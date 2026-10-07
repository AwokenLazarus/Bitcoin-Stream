//! AGP-044 on regtest: a hub ch2 refund that stays unconfirmed is re-signed at a higher fee and
//! replaces itself (RBF), within `refund_max_fee_sat`. Run by `scripts/refund_bump_regtest.sh`.
//!
//! xbt402-refund-bump --rpc-port R --cookie PATH --port P [--report FILE] [--provider-only]
//!
//! A Rust provider (payee-pays, short expiries) on port P and a Rust hub on the node. The hub funds
//! a ch2 nobody uses; at its expiry the watcher refunds it at the 1 sat/vB floor (no estimate on
//! regtest). Blocks mined with `generateblock ADDR []` leave the mempool out (what a fee market does
//! to a tx too cheap for it), so the refund stays unconfirmed while the chain moves:
//! * run 1 (`refund_bump_blocks` 2): the refund waits 2 blocks, is re-signed at 2x and replaces
//!   itself in the node's mempool (BIP125: it signals); the replacement confirms; on chain it pays
//!   capacity − the bumped fee to the hub's refund address, and the first version never confirms;
//! * run 2 (`refund_max_fee_sat` = 3.5x the first fee): bumped to 2x, then to the cap, then no
//!   further (`ch2_refund_bump_capped`); released, the capped version confirms at exactly the cap.
//!
//! With `--provider-only` it only serves the provider (for the Python hub's leg of the script).
//! Exit 0 iff every check passes.
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use xbt402::adaptor;
use xbt402::channel::{FeePayer, RBF_SEQUENCE};
use xbt402::client::Wallet;
use xbt402::funding::{ChainBackend, FundingPolicy};
use xbt402::http::{serve_http, UreqTransport};
use xbt402::hub::{HubConfig, RouteHub};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::rpc::Rpc;
use xbt_primitives::address::address_to_spk;
use xbt_primitives::network::network_id;
use xbt_primitives::tx::Tx;

const SAT: f64 = 100_000_000.0;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

struct Checks(Vec<Value>);

impl Checks {
    fn check(&mut self, name: &str, ok: bool, detail: String) {
        println!("  {}  {name}{}", if ok { "PASS" } else { "FAIL" }, if detail.is_empty() { String::new() } else { format!("  ({detail})") });
        self.0.push(json!({"check": name, "ok": ok, "detail": detail}));
    }
}

/// The node wallet; a block after each funding (the provider's minConf 1).
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
    fn mine(&self, n: u32) {
        self.rpc.call("generatetoaddress", json!([n, self.addr])).expect("mine");
    }

    fn tip(&self) -> u32 {
        self.rpc.block_count().expect("tip")
    }

    /// (in the mempool, its fee in sat, bip125-replaceable)
    fn mempool(&self, txid: &str) -> (bool, u64, bool) {
        match self.rpc.call("getmempoolentry", json!([txid])) {
            Ok(e) => (true, (e["fees"]["base"].as_f64().unwrap_or(0.0) * SAT).round() as u64, e["bip125-replaceable"].as_bool().unwrap_or(false)),
            Err(_) => (false, 0, false),
        }
    }

    /// `n` blocks that take nothing from the mempool (a stuck refund stays there).
    fn mine_empty(&self, n: u32) {
        for _ in 0..n {
            self.rpc.call("generateblock", json!([self.addr, []])).expect("generateblock");
        }
    }

    /// Confirmations of a tx (txindex), None if the chain and the mempool do not have it.
    fn confs(&self, txid: &str) -> Option<u64> {
        self.rpc.call("getrawtransaction", json!([txid, true])).ok().map(|t| t["confirmations"].as_u64().unwrap_or(0))
    }
}

fn provider(rpc: &Rpc, net: &str, port: u16, dir: &std::path::Path) -> Arc<Provider> {
    let mut cfg = ProviderConfig::new(net);
    cfg.close_margin = 5;
    cfg.policy = FundingPolicy { min_capacity: 20_000, min_expiry_blocks: 10, max_expiry_blocks: 8_640, close_margin: 5, ..FundingPolicy::default() };
    cfg.route_close_fee_payer = FeePayer::Payee;
    cfg.height_ttl = Duration::from_millis(200);
    let p = Provider::new(Arc::new(rpc.clone()), adaptor::random_secret(), cfg, Ledger::open(&dir.join("provider.jsonl")).expect("ledger"),
                          Box::new(|_, _| 1000), Box::new(|_, _, _| HttpResponse::new(200, vec![], b"{}".to_vec()))).expect("provider");
    let p = Arc::new(p);
    serve_http(p.clone(), &format!("127.0.0.1:{port}"), 4).expect("bind provider");
    p
}

fn hub(node: &Node, net: &str, dir: &std::path::Path, extra: Value) -> Arc<RouteHub> {
    let mut c = json!({"ch2_capacity": 50_000, "ch2_expiry_blocks": 20, "close_margin": 5, "rollover_margin": 2, "refund_min_feerate": 1.0,
                       "refund_bump_blocks": 2, "refund_max_fee_sat": 5_000});
    for (k, v) in extra.as_object().unwrap() {
        c[k] = v.clone();
    }
    let rpc = Arc::new(node.rpc.clone());
    let h = RouteHub::new(rpc.clone(), rpc, Box::new(MiningWallet(node.rpc.clone(), node.addr.clone())), Box::new(UreqTransport::default()),
                          adaptor::random_secret(), net, Some(dir), HubConfig::from_json(&c).expect("config")).expect("hub");
    let w = node.rpc.wallet("w");
    h.set_refund_to(Some(Box::new(move || Ok(w.call("getnewaddress", json!(["", "bech32"]))?.as_str().unwrap_or("").to_string()))));
    Arc::new(h)
}

fn events(h: &RouteHub, name: &str) -> Vec<Value> {
    h.events.lock().unwrap().iter().filter(|e| e["event"] == name).cloned().collect()
}

/// A ch2 funded and opened by `h`, then mined to its expiry: the watcher's first refund, held.
fn stuck_refund(ck: &mut Checks, node: &Node, h: &RouteHub, origin: &str, tag: &str) -> (String, u64, u64) {
    let oc = h.connect(origin, None, None).expect("connect");
    h.watch_tick();
    let oc = h.ch2_for(origin).filter(|c| c.state == "open").unwrap_or(oc);
    ck.check(&format!("{tag}: hub-funded ch2 open (nothing routed: its refund is due at expiry)"), oc.state == "open" && oc.signed == 0,
             format!("{} capacity {}, expiry {}", &oc.params.channel_id()[..16], oc.params.capacity, oc.params.expiry));
    let tip = node.tip();
    if oc.params.expiry > tip {
        node.mine(oc.params.expiry - tip);
    }
    h.watch_tick();
    let oc = h.ch2_for(origin).unwrap();
    let r1 = oc.refund_txid.clone();
    let (inpool, fee, rbf) = node.mempool(&r1);
    let tx = Tx::parse_hex(&oc.refund_hex).unwrap();
    ck.check(&format!("{tag}: refund at expiry at the 1 sat/vB floor, in the mempool, signalling RBF (nSequence 0xFFFFFFFD)"),
             inpool && fee == oc.refund_fee && rbf && tx.inputs[0].sequence == RBF_SEQUENCE && tx.locktime == oc.params.expiry
             && fee as usize <= tx.vsize() + 2,
             format!("{} fee {fee} sat for {} vB, bip125-replaceable {rbf}", &r1[..16], tx.vsize()));
    node.mine_empty(1);
    h.watch_tick();
    ck.check(&format!("{tag}: left out of blocks: still unconfirmed a block later, not bumped yet"),
             node.mempool(&r1).0 && h.ch2_for(origin).unwrap().refund_txid == r1 && events(h, "ch2_refund_bump").is_empty(), String::new());
    (r1, fee, oc.params.capacity)
}

fn main() {
    let rpc = Rpc::from_cookie(&format!("http://127.0.0.1:{}", arg("--rpc-port").expect("--rpc-port")),
                               std::path::Path::new(&arg("--cookie").expect("--cookie"))).expect("cookie");
    let port: u16 = arg("--port").expect("--port").parse().unwrap();
    let net = network_id(rpc.call("getblockhash", json!([101])).unwrap().as_str().unwrap());
    let addr = rpc.wallet("w").call("getnewaddress", json!([])).unwrap().as_str().unwrap().to_string();
    let node = Node { rpc: rpc.clone(), addr };
    let run = std::env::temp_dir().join(format!("xbt402-refund-bump-{}", std::process::id()));
    std::fs::create_dir_all(&run).unwrap();
    let _prov = provider(&rpc, &net, port, &run);
    let origin = format!("http://127.0.0.1:{port}");
    if std::env::args().any(|a| a == "--provider-only") {
        eprintln!("refund-bump provider on {port} ready");
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
    let mut ck = Checks(vec![]);
    println!("== node: height {}, network {net}", node.tip());

    // --- run 1: bumped once, the replacement confirms -----------------------------------------------
    println!("== run 1: a stuck refund is re-signed at a higher fee (RBF) and confirms");
    let h = hub(&node, &net, &run.join("hub1"), json!({}));
    let (r1, f1, cap) = stuck_refund(&mut ck, &node, &h, &origin, "run 1");
    node.mine_empty(1);
    h.watch_tick();
    let oc = h.ch2_for(&origin).unwrap();
    let bump = events(&h, "ch2_refund_bump");
    let r2 = oc.refund_txid.clone();
    let (in2, f2, rbf2) = node.mempool(&r2);
    ck.check("run 1: refund_bump_blocks (2) later the hub re-signed it at 2x and it replaced the first in the node's mempool",
             bump.len() == 1 && bump[0]["replaces"] == r1.as_str() && r2 != r1 && in2 && f2 == oc.refund_fee && f2 >= 2 * f1 && rbf2
             && !node.mempool(&r1).0 && oc.refund_prev == vec![json!({"txid": r1, "fee": f1})],
             format!("{} -> {} fee {f1} -> {f2} sat", &r1[..12], &r2[..12]));
    node.mine(1);
    let acts = h.watch_tick();
    let oc = h.ch2_for(&origin).unwrap();
    let conf = acts.iter().find(|a| a["event"] == "ch2_refund_confirmed").cloned().unwrap_or(Value::Null);
    let tx2 = node.rpc.call("getrawtransaction", json!([r2, true])).unwrap_or(Value::Null);
    let out2 = (tx2["vout"][0]["value"].as_f64().unwrap_or(0.0) * SAT).round() as u64;
    let spk2 = tx2["vout"][0]["scriptPubKey"]["hex"].as_str().unwrap_or("").to_string();
    let spk1 = Tx::parse_hex(&oc.refund_hex).ok().map(|t| hex::encode(&t.outputs[0].script_pubkey)).unwrap_or_default();
    let mine: bool = node.rpc.wallet("w").call("getaddressinfo", json!([xbt_primitives::address::segwit_address("bcrt", &hex::decode(&spk2).unwrap_or_default()).unwrap_or_default()]))
        .map(|i| i["ismine"].as_bool().unwrap_or(false)).unwrap_or(false);
    ck.check("run 1: the replacement confirmed; on chain it pays capacity - the bumped fee to the hub wallet's refund address",
             conf["txid"] == r2.as_str() && conf["fee"] == f2 && oc.final_ && tx2["confirmations"].as_u64().unwrap_or(0) >= 1
             && out2 == cap - f2 && spk2 == spk1 && mine && h.refund_fees_sat() == f2 && h.committed_sat() == 0,
             format!("{} conf, output {out2} = {cap} - {f2}, ours {mine}", tx2["confirmations"]));
    ck.check("run 1: the first version never confirmed (txindex has no such tx)", node.confs(&r1).is_none(), String::new());
    let spk_ok = address_to_spk(node.rpc.wallet("w").call("getnewaddress", json!(["", "bech32"])).unwrap().as_str().unwrap(), Some("bcrt")).is_ok();

    // --- run 2: capped --------------------------------------------------------------------------------
    println!("== run 2: refund_max_fee_sat caps the bumps");
    let cap_fee = f1 * 7 / 2;
    let h2 = hub(&node, &net, &run.join("hub2"), json!({"refund_max_fee_sat": cap_fee}));
    let (q1, g1, cap2) = stuck_refund(&mut ck, &node, &h2, &origin, "run 2");
    let mut fees = vec![g1];
    let mut txids = vec![q1];
    for _ in 0..8 {
        node.mine_empty(1);
        h2.watch_tick();
        let oc = h2.ch2_for(&origin).unwrap();
        if oc.refund_txid != *txids.last().unwrap() {
            fees.push(oc.refund_fee);
            txids.push(oc.refund_txid.clone());
        }
    }
    let capped = events(&h2, "ch2_refund_bump_capped");
    ck.check("run 2: bumped to 2x, then to the cap, then no further (ch2_refund_bump_capped)",
             fees == vec![g1, 2 * g1, cap_fee] && !capped.is_empty() && capped.iter().all(|c| c["fee"] == cap_fee && c["cap"] == cap_fee)
             && node.mempool(txids.last().unwrap()).0,
             format!("fees {fees:?}, cap {cap_fee}, {} capped event(s)", capped.len()));
    node.mine(1);
    h2.watch_tick();
    let oc = h2.ch2_for(&origin).unwrap();
    let tx = node.rpc.call("getrawtransaction", json!([txids.last().unwrap(), true])).unwrap_or(Value::Null);
    let out = (tx["vout"][0]["value"].as_f64().unwrap_or(0.0) * SAT).round() as u64;
    ck.check("run 2: released, the capped version confirmed at exactly the cap; the earlier ones never did",
             oc.final_ && oc.refund_fee == cap_fee && out == cap2 - cap_fee && tx["confirmations"].as_u64().unwrap_or(0) >= 1
             && txids[..txids.len() - 1].iter().all(|t| node.confs(t).is_none()) && spk_ok,
             format!("output {out} = {cap2} - {cap_fee}"));

    let ok = ck.0.iter().all(|c| c["ok"] == true);
    if let Some(p) = arg("--report") {
        let rep = json!({"network": net, "checks": ck.0, "run1": {"fees": [f1, f2], "txids": [r1, r2]}, "run2": {"fees": fees, "txids": txids, "cap": cap_fee},
                         "hub1_events": *h.events.lock().unwrap(), "hub2_events": *h2.events.lock().unwrap()});
        std::fs::write(p, serde_json::to_string_pretty(&rep).unwrap()).unwrap();
    }
    let n_ok = ck.0.iter().filter(|c| c["ok"] == true).count();
    println!("== refund bump (Rust hub, regtest): {} ({n_ok}/{} checks)", if ok { "PASS" } else { "FAIL" }, ck.0.len());
    let _ = std::fs::remove_dir_all(&run);
    std::process::exit(if ok { 0 } else { 1 });
}
