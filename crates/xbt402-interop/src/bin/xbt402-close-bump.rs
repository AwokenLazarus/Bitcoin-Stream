//! AGP-067 (review C1) on regtest: a fee spike through the close margin. Run by
//! `scripts/close_bump_regtest.sh`.
//!
//! xbt402-close-bump --rpc-port R --cookie PATH --port-base PB [--report FILE]
//!
//! Four Rust providers on the node, each with a 20-block close margin: a direct provider with the
//! close bump on (`close_bump_max_fee` 10,000) and one with it off (main's behaviour), and two route
//! providers paid through a Rust hub's ch2, the same two ways. A Rust client opens a direct channel
//! to each direct provider and pays 20 calls; a Rust route payer opens ch1 to the hub and pays each
//! route provider over its ch2. All at the 1 sat/vB floor. Then, before any close margin, the fee
//! spike: the node's mempool (`maxmempool=5`, the script's bitcoin.conf) is filled with
//! transactions paying 9.5 sat/vB until its floor (`mempoolminfee`) is about 10 sat/vB, and blocks
//! take only packages paying `MARKET` (10) sat/vB or more (`generateblock` with the txids a miner would
//! pick), so the fixed 600 sat close (about 3.5 sat/vB) is refused alone and would never be mined.
//! A spike moves the dynamic floor, not `minrelaytxfee`: package relay lets a parent below
//! `mempoolminfee` in on its child's fee, never one below `minrelaytxfee`. Each block from the
//! margin to expiry every provider's watcher runs once (`close_due`):
//! * bump on, direct and ch2: the close goes in with a CPFP child from the provider's own output
//!   (`submitpackage`) and confirms in the first block after the margin, well before expiry;
//! * bump off, direct and ch2: the close is refused every block; at expiry the funding is unspent
//!   and the payer's refund, re-signed at the spike's rate, takes the whole channel back.
//!
//! Exit 0 iff every check passes.
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::adaptor::Sc;
use xbt402::client::{Client, ClientConfig, Wallet};
use xbt402::funding::{ChainBackend, FundingPolicy};
use xbt402::http::{serve_http, serve_service, UreqTransport};
use xbt402::hub::{HubConfig, RouteHub};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig, CPFP_CHILD_VSIZE};
use xbt402::route::AMSAT_PER_SAT;
use xbt402::route_client::{RoutePayer, RoutePayerConfig};
use xbt402::route_seller::RouteOffer;
use xbt402::rpc::Rpc;
use xbt402::signer::LocalSigner;
use xbt_primitives::address::segwit_address;
use xbt_primitives::hash::sha256;
use xbt_primitives::network::network_id;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

const SAT: f64 = 100_000_000.0;
const MARGIN: u32 = 20;
const FILL_SAT_VB: f64 = 9.5;
const MARKET: f64 = 10.0;
const REFUND_SAT_VB: f64 = 12.0;
const ROUTE_PRICE_SAT: u128 = 200;
const ROUTE_CALLS: usize = 30;

fn arg(name: &str) -> String {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned()).unwrap_or_else(|| panic!("{name} is required"))
}

fn opt(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

fn sk(n: u64) -> SecretKey {
    Sc::from_u64(n).secret().unwrap()
}

struct Checks(Vec<Value>);

impl Checks {
    fn check(&mut self, name: &str, ok: bool, detail: String) {
        println!("  {}  {name}{}", if ok { "PASS" } else { "FAIL" }, if detail.is_empty() { String::new() } else { format!("  ({detail})") });
        self.0.push(json!({"check": name, "ok": ok, "detail": detail}));
    }
}

/// The node wallet; a block after each funding (minConf 1).
struct MiningWallet(Rpc, String);

impl Wallet for MiningWallet {
    fn fund(&self, address: &str, sats: u64) -> xbt402::Result<(String, u32)> {
        let r = self.0.wallet("w").fund(address, sats)?;
        self.0.call("generatetoaddress", json!([1, self.1]))?;
        Ok(r)
    }
}

struct Node {
    rpc: Rpc,
    addr: String,
}

impl Node {
    fn tip(&self) -> u32 {
        self.rpc.block_count().expect("tip")
    }
    fn mine(&self, n: u32) {
        self.rpc.call("generatetoaddress", json!([n, self.addr])).expect("mine");
    }
    fn mine_to(&self, h: u32) {
        let tip = self.tip();
        if h > tip {
            self.mine(h - tip);
        }
    }
    fn confs(&self, txid: &str) -> u64 {
        self.rpc.call("getrawtransaction", json!([txid, true])).ok().and_then(|t| t["confirmations"].as_u64()).unwrap_or(0)
    }
    /// The height of the block holding `txid`, if one does.
    fn height_of(&self, txid: &str) -> Option<u32> {
        let c = self.confs(txid);
        (c > 0).then(|| self.tip() + 1 - c as u32)
    }
    fn funding_unspent(&self, chan: &str) -> bool {
        let (t, v) = chan.split_once(':').unwrap();
        matches!(self.rpc.get_tx_out(t, v.parse().unwrap(), false), Ok(Some(_)))
    }
    fn paid_to(&self, txid: &str, spk: &[u8]) -> u64 {
        let tx = self.rpc.call("getrawtransaction", json!([txid, true])).unwrap_or(Value::Null);
        let spk = hex::encode(spk);
        tx["vout"].as_array().into_iter().flatten().filter(|o| o["scriptPubKey"]["hex"] == spk.as_str())
            .map(|o| (o["value"].as_f64().unwrap_or(0.0) * SAT).round() as u64).sum()
    }
    fn floor_sat_vb(&self) -> f64 {
        self.rpc.mempool_min_fee().ok().flatten().unwrap_or(0.0)
    }
    /// The fee spike: transactions paying `FILL_SAT_VB` (1,500 outputs each, to scripts nobody
    /// spends) until the mempool is full and its floor passes `target`; (the floor, txs sent).
    fn fill_mempool(&self, target: f64) -> (f64, usize) {
        let w = self.rpc.wallet("w");
        let mut n = 0;
        for round in 0..200u32 {
            let floor = self.floor_sat_vb();
            if floor >= target {
                return (floor, n);
            }
            let outs: serde_json::Map<String, Value> = (0..1_500u32).map(|i| {
                let spk = [vec![0u8, 32], sha256(format!("filler {round} {i}").as_bytes()).to_vec()].concat();
                (segwit_address("bcrt", &spk).expect("address"), json!(0.00001))
            }).collect();
            let raw = w.call("createrawtransaction", json!([[], outs])).expect("createrawtransaction");
            let funded = w.call("fundrawtransaction", json!([raw, {"fee_rate": FILL_SAT_VB, "minconf": 1}])).expect("fundrawtransaction");
            let signed = w.call("signrawtransactionwithwallet", json!([funded["hex"]])).expect("sign");
            if self.rpc.send_raw_transaction(signed["hex"].as_str().unwrap_or("")).is_ok() {
                n += 1;
            }
        }
        (self.floor_sat_vb(), n)
    }
    /// One block of what a miner at `market` sat/vB takes: every mempool tx whose ancestor package
    /// pays `market` or more, with its ancestors (parents first).
    fn mine_market(&self, market: f64) {
        let pool = self.rpc.call("getrawmempool", json!([true])).unwrap_or(Value::Null);
        let m = pool.as_object().cloned().unwrap_or_default();
        let rate = |e: &Value| e["fees"]["ancestor"].as_f64().unwrap_or(0.0) * SAT / e["ancestorsize"].as_f64().unwrap_or(1.0);
        let mut take = std::collections::BTreeSet::new();
        let mut todo: Vec<String> = m.iter().filter(|(_, e)| rate(e) >= market).map(|(t, _)| t.clone()).collect();
        while let Some(t) = todo.pop() {
            if take.insert(t.clone()) {
                todo.extend(m[&t]["depends"].as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from));
            }
        }
        let mut txs: Vec<String> = take.into_iter().collect();
        txs.sort_by_key(|t| m[t]["ancestorcount"].as_u64().unwrap_or(0));
        self.rpc.call("generateblock", json!([self.addr, txs])).expect("generateblock");
    }
}

fn provider_cfg(net: &str, bump: bool) -> ProviderConfig {
    let mut cfg = ProviderConfig::new(net);
    cfg.close_margin = MARGIN;
    cfg.policy = FundingPolicy { min_capacity: 20_000, min_expiry_blocks: 30, max_expiry_blocks: 8_640, close_margin: MARGIN, ..FundingPolicy::default() };
    cfg.height_ttl = Duration::from_millis(100);
    cfg.close_bump_max_fee = if bump { 10_000 } else { 0 };
    cfg
}

fn provider(rpc: &Rpc, cfg: ProviderConfig, key: u64, port: u16, ledger: &Path) -> Arc<Provider> {
    let p = Provider::new(Arc::new(rpc.clone()), sk(key), cfg, Ledger::open(ledger).expect("ledger"), Box::new(|_, _| 1_000),
                          Box::new(|_, _, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], b"{\"ok\":1}".to_vec())))
        .expect("provider");
    let p = Arc::new(p);
    serve_http(p.clone(), &format!("127.0.0.1:{port}"), 4).expect("bind provider");
    p
}

/// One channel to watch through the spike.
struct Leg {
    name: &'static str,
    prov: Arc<Provider>,
    chan: String,
    expiry: u32,
    bump: bool,
}

fn main() {
    let rpc = Rpc::from_cookie(&format!("http://127.0.0.1:{}", arg("--rpc-port")), Path::new(&arg("--cookie"))).expect("cookie");
    let pb: u16 = arg("--port-base").parse().expect("--port-base");
    let net = network_id(rpc.call("getblockhash", json!([101])).expect("node").as_str().unwrap());
    let addr = rpc.wallet("w").call("getnewaddress", json!([])).unwrap().as_str().unwrap().to_string();
    let node = Node { rpc: rpc.clone(), addr: addr.clone() };
    let run = std::env::temp_dir().join(format!("xbt402-close-bump-{}", std::process::id()));
    std::fs::create_dir_all(&run).unwrap();
    let mut ck = Checks(vec![]);
    println!("== node: height {}, network {net}, mempool floor {:.2} sat/vB", node.tip(), node.floor_sat_vb());

    // --- direct channels ----------------------------------------------------------------------------
    let direct = [("direct, bump on", true, 0xD1u64, pb + 1), ("direct, bump off", false, 0xD2, pb + 2)];
    let mut legs: Vec<Leg> = vec![];
    let mut clients: Vec<(String, Client)> = vec![];
    for (name, bump, key, port) in direct {
        let prov = provider(&rpc, provider_cfg(&net, bump), key, port, &run.join(format!("direct-{key:x}.jsonl")));
        let origin = format!("http://127.0.0.1:{port}");
        let mut cc = ClientConfig::new(&net);
        cc.capacity = 100_000;
        cc.expiry_blocks = 60;
        let n = rpc.clone();
        let mut c = Client::new(cc, Box::new(UreqTransport::default()), Box::new(MiningWallet(rpc.clone(), addr.clone())), Box::new(move || n.block_count()));
        let ok = (0..20).filter(|_| c.request("GET", &format!("{origin}/v1/q"), b"").map(|r| r.status == 200).unwrap_or(false)).count();
        let p = c.channels[&origin].payer.params.clone();
        let best = prov.channel_state(&p.channel_id()).map(|s| s.best_cum).unwrap_or(0);
        // postpay: each call is paid on the next, so 20 calls leave 19 paid
        ck.check(&format!("{name}: channel open, 20 calls, 19 paid (postpay)"), ok == 20 && best == 19_000,
                 format!("{} capacity {}, expiry {}, best {best}", &p.channel_id()[..16], p.capacity, p.expiry));
        legs.push(Leg { name, prov, chan: p.channel_id(), expiry: p.expiry, bump });
        clients.push((origin, c));
    }

    // --- hub ch2s -------------------------------------------------------------------------------------
    let routed = [("hub ch2, bump on", true, 0xE1u64, pb + 3), ("hub ch2, bump off", false, 0xE2, pb + 4)];
    let mut route_provs = vec![];
    for (name, bump, key, port) in routed {
        let p = provider(&rpc, provider_cfg(&net, bump), key, port, &run.join(format!("route-{key:x}.jsonl")));
        p.offer_route(RouteOffer { window: 1.0, lock_wait: 3.0, invoice_ttl: 8.0, ..RouteOffer::new("/v1/chunk", ROUTE_PRICE_SAT * AMSAT_PER_SAT) });
        route_provs.push((name, bump, p, format!("http://127.0.0.1:{port}")));
    }
    let hcfg = HubConfig::from_json(&json!({"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20_000, "max_unguarded_lock_sat": 20_000,
        "delta": 10, "reveal_timeout": 2.0, "ch2_capacity": 60_000, "ch2_expiry_blocks": 70, "close_margin": MARGIN, "rollover_margin": 2,
        "settle_lock_multiple": 0, "refill_ahead_locks": 0, "refund_min_feerate": REFUND_SAT_VB, "refund_grace_blocks": 0,
        "policy": {"min_expiry_blocks": 30, "max_expiry_blocks": 8_640}})).expect("hub config");
    let ra = Arc::new(rpc.clone());
    let hub = Arc::new(RouteHub::new(ra.clone(), ra, Box::new(MiningWallet(rpc.clone(), addr.clone())), Box::new(UreqTransport::default()),
                                     sk(0x4B4B), &net, Some(&run.join("hub")), hcfg).expect("hub"));
    serve_service(hub.clone(), &format!("127.0.0.1:{pb}"), 8).expect("bind hub");
    for (_, _, _, u) in &route_provs {
        hub.connect(u, Some(60_000), None).expect("connect");
    }
    hub.watch_tick();
    let mut pcfg = RoutePayerConfig::new(&net);
    pcfg.capacity = 100_000;
    pcfg.expiry_blocks = 200;
    let n = rpc.clone();
    let payer = Arc::new(RoutePayer::new(&format!("http://127.0.0.1:{pb}"), pcfg, Arc::new(LocalSigner::new()),
                                         Arc::new(MiningWallet(rpc.clone(), addr.clone())), Box::new(UreqTransport::default()),
                                         Box::new(move || n.block_count())));
    payer.open().expect("open ch1");
    let hub_stop = hub.watch(Duration::from_millis(300));
    payer.start(Duration::from_millis(500));
    let shards: Vec<_> = route_provs.iter().map(|(_, _, _, u)| payer.shard(&format!("{u}/v1/chunk"), "POST").expect("shard")).collect();
    for _ in 0..ROUTE_CALLS {
        for sh in &shards {
            let _ = payer.call(sh, "POST", b"{}");
        }
        std::thread::sleep(Duration::from_millis(60));
    }
    let want = ROUTE_PRICE_SAT as u64 * ROUTE_CALLS as u64;
    let t = Instant::now();
    let routed_of = |p: &Provider| p.channel_ids().iter().filter_map(|c| p.channel_state(c)).map(|s| s.best_cum).max().unwrap_or(0);
    while route_provs.iter().any(|(_, _, p, _)| routed_of(p) < want) && t.elapsed() < Duration::from_secs(20) {
        std::thread::sleep(Duration::from_millis(250));
    }
    payer.stop();
    hub_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(400));
    for (name, bump, p, u) in &route_provs {
        let oc = hub.ch2_for(u).expect("ch2");
        let chan = oc.params.channel_id();
        let best = p.channel_state(&chan).map(|s| s.best_cum).unwrap_or(0);
        ck.check(&format!("{name}: hub-funded ch2 (payee-pays) paid through the hub"), best >= want && oc.params.close_fee_payer == xbt402::channel::FeePayer::Payee,
                 format!("{} capacity {}, expiry {}, best {best}", &chan[..16], oc.params.capacity, oc.params.expiry));
        legs.push(Leg { name, prov: p.clone(), chan, expiry: oc.params.expiry, bump: *bump });
    }

    // --- the spike ------------------------------------------------------------------------------------
    let first_margin = legs.iter().map(|l| l.expiry - MARGIN).min().unwrap();
    node.mine_to(first_margin - 1);
    let (floor, fillers) = node.fill_mempool(FILL_SAT_VB + 0.05);
    let minrelay = node.rpc.call("getmempoolinfo", json!([])).ok().and_then(|i| i["minrelaytxfee"].as_f64()).unwrap_or(0.0) * SAT / 1000.0;
    ck.check("fee spike: before any close margin the mempool is full and its floor is about 10 sat/vB (minrelaytxfee unchanged)",
             floor > FILL_SAT_VB && floor < FILL_SAT_VB + 2.0 && minrelay < 1.01 && node.tip() < first_margin,
             format!("mempoolminfee {floor:.2} sat/vB after {fillers} filler txs at {FILL_SAT_VB} sat/vB, minrelaytxfee {minrelay:.2}, height {}", node.tip()));

    let last = legs.iter().map(|l| l.expiry).max().unwrap();
    let mut confirmed_at: Vec<Option<u32>> = vec![None; legs.len()];
    while node.tip() < last {
        for l in &legs {
            let _ = l.prov.close_due();
        }
        node.mine_market(MARKET);
        for (i, l) in legs.iter().enumerate() {
            if confirmed_at[i].is_none() && !node.funding_unspent(&l.chan) {
                confirmed_at[i] = Some(node.tip());
            }
        }
    }

    // --- results --------------------------------------------------------------------------------------
    let mut report_legs = vec![];
    for (i, l) in legs.iter().enumerate() {
        let st = l.prov.channel_state(&l.chan).expect("state");
        let b = st.extra.get("close_bump").cloned().unwrap_or(Value::Null);
        if l.bump {
            let close = st.extra.get("close_hex").and_then(Value::as_str).and_then(|h| Tx::parse_hex(h).ok());
            let child = b["txid"].as_str().unwrap_or("");
            let (cv, close_fee) = close.as_ref().map(|t| (t.vsize() as u64, st.params.capacity - t.outputs.iter().map(|o| o.value as u64).sum::<u64>())).unwrap_or((0, 0));
            let own = close_fee as f64 / cv.max(1) as f64;
            let pkg = (close_fee + b["fee"].as_u64().unwrap_or(0)) as f64 / (cv + CPFP_CHILD_VSIZE) as f64;
            let at = node.height_of(&st.closed_txid);
            ck.check(&format!("{}: the close alone ({own:.2} sat/vB) is under the floor; it went in with a CPFP child at the floor", l.name),
                     own < floor && !child.is_empty() && pkg >= floor && pkg < floor + 0.5,
                     format!("close {} {cv} vB fee {close_fee}, child {} fee {}, package {pkg:.2} sat/vB{}", &st.closed_txid[..12.min(st.closed_txid.len())],
                             &child[..12.min(child.len())], b["fee"], if st.close_error.is_empty() { String::new() } else { format!("; {}", st.close_error) }));
            ck.check(&format!("{}: close and child confirmed in the first block after the margin, {} blocks before expiry", l.name,
                              at.map(|h| l.expiry.saturating_sub(h)).unwrap_or(0)),
                     at == Some(l.expiry - MARGIN + 1) && confirmed_at[i] == at && node.confs(child) >= 1,
                     format!("margin {}, confirmed at {at:?}, expiry {}", l.expiry - MARGIN, l.expiry));
            let paid = node.paid_to(&st.closed_txid, &st.params.payee_spk);
            let want = if st.params.close_fee_payer == xbt402::channel::FeePayer::Payee { st.best_cum - close_fee } else { st.best_cum };
            ck.check(&format!("{}: the close pays the provider its best state (the child's fee comes from that output)", l.name),
                     paid == want, format!("payee output {paid}, child fee {}", b["fee"]));
        } else {
            ck.check(&format!("{}: refused through the whole margin, the funding is unspent at expiry", l.name),
                     confirmed_at[i].is_none() && node.funding_unspent(&l.chan) && st.close_error.contains("fee not met"),
                     st.close_error.chars().take(80).collect());
        }
        report_legs.push(json!({"leg": l.name, "chan": l.chan, "expiry": l.expiry, "margin": l.expiry - MARGIN, "confirmed_at": confirmed_at[i],
                                "closed_txid": st.closed_txid, "close_bump": b, "close_error": st.close_error}));
    }

    // the payers' refunds win the unbumped channels
    let ctl_direct = legs.iter().find(|l| !l.bump && l.name.starts_with("direct")).unwrap();
    let (origin, c) = clients.iter().find(|(o, _)| o.ends_with(&format!(":{}", pb + 2))).unwrap();
    let ch = &c.channels[origin];
    let rv = ch.payer.refund_tx(None, Some(0)).map(|t| t.vsize() as u64).unwrap_or(150);
    let fee = (REFUND_SAT_VB * rv as f64).ceil() as u64;
    let refund = ch.payer.refund_tx(None, Some(fee)).expect("refund");
    let sent = rpc.send_raw_transaction(&refund.to_hex());
    node.mine_market(MARKET);
    let paid = node.paid_to(&refund.txid(), &refund.outputs[0].script_pubkey);
    ck.check("direct, bump off: at expiry the payer's refund, re-signed at the spike's rate, takes the whole channel back",
             sent.is_ok() && node.confs(&refund.txid()) >= 1 && paid == ch.payer.params.capacity - fee && !node.funding_unspent(&ctl_direct.chan),
             format!("refund {} pays the payer {paid} = {} - {fee}", &refund.txid()[..12], ch.payer.params.capacity));
    let ctl_hub = legs.iter().find(|l| !l.bump && l.name.starts_with("hub")).unwrap();
    let mut hub_refund = Value::Null;
    for _ in 0..6 {
        for a in hub.watch_tick() {
            if a["event"] == "ch2_refund" || a["event"] == "ch2_refund_confirmed" {
                hub_refund = a;
            }
        }
        if !node.funding_unspent(&ctl_hub.chan) {
            break;
        }
        node.mine_market(MARKET);
    }
    ck.check("hub ch2, bump off: the hub's refund takes ch2 back; the provider is paid nothing on-chain",
             !node.funding_unspent(&ctl_hub.chan) && ctl_hub.prov.channel_state(&ctl_hub.chan).map(|s| node.height_of(&s.closed_txid).is_none()).unwrap_or(false),
             format!("{hub_refund}"));

    let ok = ck.0.iter().all(|c| c["ok"] == true);
    if let Some(p) = opt("--report") {
        let rep = json!({"network": net, "mempool_floor_sat_vb": floor, "fillers": fillers, "market_sat_vb": MARKET, "close_margin": MARGIN, "legs": report_legs, "checks": ck.0});
        std::fs::write(p, serde_json::to_string_pretty(&rep).unwrap()).unwrap();
    }
    let n_ok = ck.0.iter().filter(|c| c["ok"] == true).count();
    println!("== close bump (Rust, regtest fee spike): {} ({n_ok}/{} checks)", if ok { "PASS" } else { "FAIL" }, ck.0.len());
    let _ = std::fs::remove_dir_all(&run);
    std::process::exit(if ok { 0 } else { 1 });
}
