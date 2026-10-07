//! The AGP-021 demo scenarios, all Rust, on regtest (a port of B1 `scripts/demo_route.py`; run by
//! `scripts/route_interop.sh`). Real HTTP (tiny_http + ureq) between every party.
//!
//! 1 client (LocalSigner), 1 hub, 4 providers: operator 1 runs A and B under ONE payTo key (two
//! provider processes: each its own ledger, origin and sessions), C and D are separate operators. The
//! client has ONE channel (to the hub); the hub funds one ch2 per provider process itself (AGP-056: A
//! and B have one each), payee-pays (v1.2).
//!
//! * phase 1 (~10 s): the client streams to all 4 at 12 calls/s each; per-window adaptor locks pay
//!   each provider's accrued amount through the hub. A and B cost under a sat per call (amsat, B with
//!   a tail above 2^64 amsat). D settles once its net payout is 2× its own close fee, so the hub
//!   rolls D's channel over. At 5 s C stops revealing: the hub writes the lock off after its reveal
//!   timeout, stops routing to C, and neither channel pays the lock.
//! * phase 2 (~2.5 s): the hub withholds receipts (keeps t + r): the client takes its receipts from
//!   the providers' signed ROUTE-STATE.
//! * phase 3 (~10 s): the hub withholds everything: providers stop serving within window + lockWait,
//!   the client's stuck lock is voided when its invoice expires.
//! * settle: the client closes ch1 (the hub broadcasts), the hub closes every ch2 (the providers
//!   broadcast); every close and rollover is checked on chain against the ledgers.
//!
//! xbt402-route-demo --rpc-port R --cookie PATH --port-base PB [--report FILE]
//! (hub on PB, providers on PB+1..PB+4). Exit 0 iff every check passes.
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::adaptor::{PreSig, Sc};
use xbt402::client::Wallet;
use xbt402::funding::{ChainBackend, FundingPolicy};
use xbt402::http::{serve_http, serve_service, UreqTransport};
use xbt402::hub::{HubConfig, RouteHub};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route::{ceil_div, now_f, AMSAT_PER_SAT, FEE_UNITS_PER_SAT, HUB_ROUTE_PATH};
use xbt402::route_client::{RoutePayer, RoutePayerConfig, Shard};
use xbt402::route_seller::RouteOffer;
use xbt402::rpc::Rpc;
use xbt402::signer::LocalSigner;
use xbt_primitives::network::network_id;
use xbt_primitives::secp256k1::SecretKey;

const SAT: f64 = 100_000_000.0;
const WINDOW: f64 = 1.0;
const LOCK_WAIT: f64 = 3.0;
const INVOICE_TTL: f64 = 8.0;
const REVEAL_TIMEOUT: f64 = 2.0;
const RATE: f64 = 12.0;
const NAMES: [&str; 4] = ["A", "B", "C", "D"];

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

fn price(n: &str) -> u128 {
    match n {
        "A" => 370 * 10u128.pow(18),                 // 0.37 sat
        "B" => 813 * 10u128.pow(18) + 123_456_789,   // 0.813... sat with an amsat tail
        "C" => 20 * AMSAT_PER_SAT,
        _ => 40 * AMSAT_PER_SAT,
    }
}

/// Each provider's metered mount (A and B are two mounts of operator 1's one provider).
fn mount(n: &str) -> &'static str {
    if n == "B" { "/v1/chunk-b" } else { "/v1/chunk" }
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

#[derive(Clone)]
struct Chain {
    rpc: Rpc,
    w: Rpc,
    addr: String,
    lock: Arc<Mutex<()>>,
}

impl Chain {
    fn mine(&self, n: u32) {
        let _g = self.lock.lock().unwrap();
        let _ = self.rpc.call("generatetoaddress", json!([n, self.addr]));
    }

    /// (confirmations, sum of outputs paying `spk_hex`)
    fn payee_out(&self, txid: &str, spk_hex: &str) -> (u64, u64) {
        let tx = self.rpc.call("getrawtransaction", json!([txid, true])).unwrap_or(Value::Null);
        let paid = tx["vout"].as_array().into_iter().flatten().filter(|o| o["scriptPubKey"]["hex"] == spk_hex)
            .map(|o| (o["value"].as_f64().unwrap_or(0.0) * SAT).round() as u64).sum();
        (tx["confirmations"].as_u64().unwrap_or(0), paid)
    }
}

/// The wallet hook: fund, then mine a block (regtest).
struct DemoWallet(Chain);

impl Wallet for DemoWallet {
    fn fund(&self, address: &str, sats: u64) -> xbt402::Result<(String, u32)> {
        let _g = self.0.lock.lock().unwrap();
        let r = self.0.w.fund(address, sats)?;
        self.0.rpc.call("generatetoaddress", json!([1, self.0.addr]))?;
        Ok(r)
    }
}

fn pct(xs: &[f64], q: f64) -> f64 {
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    if v.is_empty() { 0.0 } else { v[((q * v.len() as f64) as usize).min(v.len() - 1)] }
}

fn main() {
    let t_start = Instant::now();
    let rpc = Rpc::from_cookie(&format!("http://127.0.0.1:{}", arg("--rpc-port").expect("--rpc-port")),
                               std::path::Path::new(&arg("--cookie").expect("--cookie"))).expect("cookie");
    let pb: u16 = arg("--port-base").expect("--port-base").parse().unwrap();
    let net = network_id(rpc.call("getblockhash", json!([101])).unwrap().as_str().unwrap());
    let w = rpc.wallet("w");
    let addr = w.call("getnewaddress", json!([])).unwrap().as_str().unwrap().to_string();
    let chain = Chain { rpc: rpc.clone(), w, addr, lock: Arc::new(Mutex::new(())) };
    let mut ck = Checks(vec![]);
    let run = std::env::temp_dir().join(format!("xbt402-route-demo-{}", std::process::id()));
    std::fs::create_dir_all(&run).unwrap();
    println!("== node: height {}, network {net}", rpc.block_count().unwrap());

    // --- providers -------------------------------------------------------------------------------
    let keys = [0xA0A0u64, 0xA0A0, 0xC0C0, 0xD0D0];
    let mut provs: HashMap<&str, Arc<Provider>> = HashMap::new();
    let mut urls: HashMap<&str, String> = HashMap::new();
    for (i, n) in NAMES.iter().enumerate() {
        urls.insert(n, format!("http://127.0.0.1:{}", pb + 1 + i as u16));
        // operator 1 runs two provider processes on one payTo key, A and B: each has its own ledger,
        // origin and sessions (AGP-056: the hub pays each on its own ch2)
        let mut cfg = ProviderConfig::new(&net);
        cfg.close_margin = 144;
        cfg.policy = FundingPolicy { min_capacity: 20_000, min_expiry_blocks: 1_008, max_expiry_blocks: 8_640, close_margin: 144, ..FundingPolicy::default() };
        cfg.settle_multiple = if *n == "D" { 2 } else { 20 };
        cfg.height_ttl = Duration::from_millis(500);
        let ledger = Ledger::open(&run.join(format!("prov-{n}.jsonl"))).unwrap();
        let name = n.to_string();
        let p = Provider::new(Arc::new(rpc.clone()), sk(keys[i]), cfg, ledger, Box::new(|_, _| 1000), Box::new(move |_, _, _| {
            HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], json!({"shard": name}).to_string())
        })).unwrap();
        p.offer_route(RouteOffer { window: WINDOW, lock_wait: LOCK_WAIT, invoice_ttl: INVOICE_TTL, ..RouteOffer::new(mount(n), price(n)) });
        let p = Arc::new(p);
        serve_http(p.clone(), &format!("127.0.0.1:{}", pb + 1 + i as u16), 8).expect("bind provider");
        provs.insert(n, p);
    }
    ck.check("operator 1 runs A and B under one payTo key", provs["A"].pay_to() == provs["B"].pay_to() && provs["A"].pay_to() != provs["C"].pay_to(),
             format!("{}...", &provs["A"].pay_to()[..18]));

    // --- hub -------------------------------------------------------------------------------------
    let cfg = HubConfig::from_json(&json!({"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500,
        "delta": 144, "reveal_timeout": REVEAL_TIMEOUT, "ch2_capacity": 150000, "ch2_expiry_blocks": 1100, "close_margin": 144})).unwrap();
    let rpc_a = Arc::new(rpc.clone());
    let hub = Arc::new(RouteHub::new(rpc_a.clone(), rpc_a, Box::new(DemoWallet(chain.clone())), Box::new(UreqTransport::default()), sk(0x4B4B),
                                     &net, Some(&run.join("hub")), cfg).unwrap());
    serve_service(hub.clone(), &format!("127.0.0.1:{pb}"), 16).expect("bind hub");
    let hub_url = format!("http://127.0.0.1:{pb}");
    println!("== hub funds one channel per provider process from its own wallet (providers open nothing)");
    let committed0 = hub.committed_sat();
    for n in NAMES {
        let cap = if n == "D" { 30_000 } else { 150_000 };
        let oc = hub.connect(&urls[n], Some(cap), None).expect("connect");
        println!("   ch2 hub->{n}: {}... capacity {}", &oc.params.channel_id()[..20], oc.params.capacity);
    }
    hub.watch_tick();
    let ch2 = |n: &str| hub.ch2_for(&urls[n]).expect("ch2");
    let opened: Vec<&str> = NAMES.iter().copied().filter(|n| ch2(n).state == "open").collect();
    ck.check("hub-funded ch2 open to all 4 providers", opened.len() == 4, opened.join(","));
    ck.check("one ch2 per provider process: A and B (one payTo key, two ledgers) have a ch2 each, 4 funded",
             ch2("A").params.channel_id() != ch2("B").params.channel_id() && hub.out_channels().len() == 4
             && hub.committed_sat() - committed0 == 150_000 * 3 + 30_000
             && provs["B"].channel_state(&ch2("B").params.channel_id()).is_some()
             && provs["A"].channel_state(&ch2("B").params.channel_id()).is_none(),
             format!("{} ch2s, {} sat committed", hub.out_channels().len(), hub.committed_sat() - committed0));
    let r402 = hub.serve("GET", HUB_ROUTE_PATH, &[], b"", "", None);
    let routing = xbt402::wire::unb64json(r402.header("PAYMENT-REQUIRED").unwrap()).unwrap()["accepts"][0]["extra"]["routing"].clone();
    let payee_all = NAMES.iter().all(|n| ch2(n).params.close_fee_payer == xbt402::channel::FeePayer::Payee);
    ck.check("v1.2: the hub advertises payee-pays ch2 (ch1 payer-pays) and every ch2 is payee-pays",
             routing["ch1CloseFeePayer"] == "payer" && routing["ch2CloseFeePayer"] == "payee" && payee_all,
             format!("ch2 minCum {}", ch2("A").params.min_amount()));

    // --- client ----------------------------------------------------------------------------------
    let signer = Arc::new(LocalSigner::new());
    let node = rpc.clone();
    let payer = Arc::new(RoutePayer::new(&hub_url, RoutePayerConfig::new(&net), signer, Arc::new(DemoWallet(chain.clone())), Box::new(UreqTransport::default()),
                                         Box::new(move || node.block_count())));
    let ch1 = payer.open().expect("open ch1");
    println!("== client (Rust LocalSigner) opened ONE channel to the hub: {}... capacity {}", &ch1["chan"].as_str().unwrap()[..20], ch1["capacity"]);
    let shards: HashMap<&str, Arc<Shard>> = NAMES.iter().map(|n| (*n, payer.shard(&format!("{}{}", urls[n], mount(n)), "POST").unwrap())).collect();

    // background: a block every 1.5 s (rollover confirmations), the hub's watcher every 0.3 s
    let stop_bg = Arc::new(AtomicBool::new(false));
    {
        let (c, s) = (chain.clone(), stop_bg.clone());
        std::thread::spawn(move || while !s.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(1500));
            c.mine(1);
        });
    }
    let hub_stop = hub.watch(Duration::from_millis(300));
    let on = Arc::new(AtomicBool::new(true));
    type Timeline = Arc<Mutex<HashMap<&'static str, Vec<(f64, u16)>>>>;
    let tl: Timeline = Arc::new(Mutex::new(NAMES.iter().map(|n| (*n, vec![])).collect()));
    let t0 = now_f();
    let streamers: Vec<_> = NAMES.iter().map(|n| {
        let (n, sh, payer, on, tl) = (*n, shards[n].clone(), payer.clone(), on.clone(), tl.clone());
        std::thread::spawn(move || {
            let mut next = Instant::now();
            while on.load(Ordering::Relaxed) {
                next += Duration::from_secs_f64(1.0 / RATE);
                let st = payer.call(&sh, "POST", br#"{"tokens":1}"#).map(|r| r.status).unwrap_or(0);
                tl.lock().unwrap().get_mut(n).unwrap().push((now_f(), st));
                if let Some(d) = next.checked_duration_since(Instant::now()) {
                    std::thread::sleep(d);
                }
            }
        })
    }).collect();
    payer.start(Duration::from_secs_f64(WINDOW / 2.0));
    println!("== phase 1: streaming to 4 providers at {RATE:.0} calls/s each, {WINDOW:.0} s windows");
    std::thread::sleep(Duration::from_secs(5));
    provs["C"].set_no_reveal(true);
    let t_c = now_f();
    println!("   t={:.1}s provider C stops revealing", t_c - t0);
    std::thread::sleep(Duration::from_secs(5));
    let t_p1 = now_f();
    let ok_until = |n: &str, t: f64| tl.lock().unwrap()[n].iter().filter(|(x, s)| *s == 200 && *x <= t).count();
    let snap1: HashMap<&str, usize> = NAMES.iter().map(|n| (*n, ok_until(n, t_p1))).collect();

    println!("== phase 2: the hub withholds receipts (t + r); the client reads t from the providers");
    let via0 = payer.stats().via_provider;
    hub.set_withhold("receipt");
    std::thread::sleep(Duration::from_millis(2500));
    let via_provider = payer.stats().via_provider - via0;

    println!("== phase 3: the hub withholds everything");
    hub.set_withhold("all");
    let t_w = now_f();
    std::thread::sleep(Duration::from_secs_f64(WINDOW + LOCK_WAIT + INVOICE_TTL - 2.0));
    on.store(false, Ordering::Relaxed);
    for s in streamers {
        let _ = s.join();
    }
    payer.stop();
    let t_end = now_f();
    hub.set_withhold("");
    stop_bg.store(true, Ordering::Relaxed);
    hub_stop.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(500));
    let pev = payer.events.lock().unwrap().clone();
    let mut kinds: std::collections::BTreeMap<String, u64> = Default::default();
    for e in &pev {
        let k = format!("{}:{}", e["event"].as_str().unwrap_or(""), e.get("via").or(e.get("why")).or(e.get("error")).and_then(Value::as_str).unwrap_or(""));
        *kinds.entry(k).or_insert(0) += 1;
    }
    println!("   client lock events: {}", json!(kinds));
    let tl = tl.lock().unwrap().clone();

    // --- phase 1 results -------------------------------------------------------------------------
    println!("== phase 1 results");
    let dur1 = t_p1 - t0;
    for n in ["A", "B", "D"] {
        let rate = snap1[n] as f64 / dur1;
        ck.check(&format!("provider {n}: >= 10 paid-route updates/s over phase 1"), rate >= 10.0, format!("{rate:.1}/s"));
    }
    let rate_c = tl["C"].iter().filter(|(t, s)| *s == 200 && *t <= t_c).count() as f64 / (t_c - t0);
    ck.check("provider C: >= 10 updates/s until it stopped revealing", rate_c >= 10.0, format!("{rate_c:.1}/s"));
    let hev = hub.events.lock().unwrap().clone();
    let rolls: Vec<Value> = hev.iter().filter(|e| e["event"] == "ch2_rollover").cloned().collect();
    let fee_d = ch2("D").params.close_fee;
    ck.check("hub rolled D's channel over at D's threshold (net payout >= 2x its own close fee)",
             !rolls.is_empty() && rolls.iter().all(|r| r["amount"].as_u64().unwrap() - fee_d >= 2 * fee_d),
             format!("{} rollover(s), amounts {:?}", rolls.len(), rolls.iter().map(|r| r["amount"].as_u64().unwrap()).collect::<Vec<_>>()));
    let archived = hub.archived();
    for r in &rolls {
        let txid = r["txid"].as_str().unwrap();
        let old = archived.iter().find(|a| a["rolled_to"] == format!("{txid}:1")).cloned().unwrap_or(Value::Null);
        let (confs, paid) = chain.payee_out(txid, old["params"]["payee_spk"].as_str().unwrap_or(""));
        let amount = r["amount"].as_u64().unwrap();
        let cap = old["params"]["capacity"].as_u64().unwrap_or(0);
        ck.check(&format!("rollover {}... confirmed, pays D {amount} less D's fee, the hub keeps the rest", &txid[..12]),
                 confs >= 1 && paid == amount - fee_d && r["nextCapacity"].as_u64() == Some(cap - amount),
                 format!("{confs} conf, payee output {paid}, next ch2 {} = {cap} - {amount}", r["nextCapacity"]));
    }
    let voids_c = hev.iter().filter(|e| e["event"] == "void" && e["provider"] == urls["C"].as_str()).count();
    let oc_c = ch2("C");
    ck.check("C never revealed: the hub wrote the lock off, stopped routing to C", voids_c > 0 && !oc_c.blocked.is_empty(),
             format!("{voids_c} lock(s) written off, blocked: {}", oc_c.blocked));
    let held: Vec<Value> = provs["C"].routes().lock().held.iter().filter(|h| xbt402::json::truthy(h.get("pre"))).cloned().collect();
    let st2c = provs["C"].channel_ids().iter().filter_map(|c| provs["C"].channel_state(c)).next().unwrap();
    let stuck = held.first().and_then(|h| h["cum"].as_u64());
    ck.check("C never revealed: its ch2 does not pay the lock", stuck.is_some_and(|s| st2c.best_cum < s),
             format!("ch2 best {} < held lock {stuck:?}", st2c.best_cum));
    if let Some(h) = held.first() {
        let pre = PreSig::from_json(&h["pre"]).unwrap();
        let p2 = &st2c.params;
        let mut tx = p2.state_tx(stuck.unwrap()).unwrap();
        let mut bogus = pre.bogus_der();
        bogus.push(0x21);
        let mine = provs["C"].payee_sign_state(&p2.channel_id(), stuck.unwrap()).unwrap();
        tx.inputs[0].witness = vec![bogus, mine, vec![1], p2.script()];
        let r = rpc.call("testmempoolaccept", json!([[tx.to_hex()]])).unwrap();
        ck.check("C cannot close with the held pre-signature (no t, no signature)", r[0]["allowed"] == false,
                 r[0]["reject-reason"].as_str().unwrap_or("").to_string());
    }
    let c_stop = tl["C"].iter().find(|(t, s)| *s == 402 && *t > t_c).map(|x| x.0);
    ck.check("C: the client stopped being served once C's locks stopped", c_stop.is_some(),
             format!("{:.1} s after C stopped revealing", c_stop.unwrap_or(t_c) - t_c));

    println!("== phase 2/3 results");
    ck.check("withheld receipts: the client took t from the providers' signed ROUTE-STATE", via_provider >= 1,
             format!("{via_provider} lock(s) settled via the provider"));
    let mut stops = serde_json::Map::new();
    for n in ["A", "B", "D"] {
        let s = provs[n].routes().lock().sessions[&shards[n].session].clone();
        let first402 = tl[n].iter().find(|(t, st)| *st == 402 && *t > t_w).map(|x| x.0);
        stops.insert(n.into(), json!(first402.map(|t| t - t_w)));
        let bound = (WINDOW + LOCK_WAIT + 1.0) * RATE * price(n) as f64; // + 1 s: the last window's lock in flight
        let owed = s.owed_amsat() as f64;
        ck.check(&format!("withholding hub: {n} stopped serving, unpaid <= window + lockWait of traffic"), first402.is_some() && owed <= bound,
                 format!("stopped {:.1} s after, unpaid {:.2} sat (bound {:.2})", first402.map(|t| t - t_w).unwrap_or(-1.0), owed / 1e21, bound / 1e21));
    }
    let cvoid: Vec<&Value> = pev.iter().filter(|e| e["event"] == "void" && e["why"].as_str().is_some_and(|w| w.contains("expired"))).collect();
    let worst = cvoid.iter().filter_map(|e| e["amount"].as_u64()).max().unwrap_or(0);
    ck.check("withholding hub: the client's stuck lock voided on invoice expiry, loss <= one lock", !cvoid.is_empty() && worst <= 20_000,
             format!("{} voided, largest {worst} sat", cvoid.len()));

    // --- metering invariants ---------------------------------------------------------------------
    println!("== metering (amsat, carry at each hop)");
    for n in NAMES {
        let (sh, s) = (shards[n].snapshot(), provs[n].routes().lock().sessions[&shards[n].session].clone());
        ck.check(&format!("{n}: provider meter == client meter (exact amsat)"), s.accrued_amsat == sh.accrued_amsat && s.accrued_amsat == sh.seen_amsat,
                 format!("{} amsat over {} calls", s.accrued_amsat, s.calls));
        ck.check(&format!("{n}: paid == sum of completed locks, never above the ceil"),
                 s.paid_sat == sh.locked_sat && s.paid_sat as u128 <= ceil_div(s.accrued_amsat, AMSAT_PER_SAT),
                 format!("paid {}, ceil {}", s.paid_sat, ceil_div(s.accrued_amsat, AMSAT_PER_SAT)));
    }
    let (routed, fee_units, fee_paid, _) = payer.counters();
    ck.check("hub fee carried exactly across every lock: fees == ceil(units / 1e9)", fee_paid as u128 == ceil_div(fee_units, FEE_UNITS_PER_SAT),
             format!("{fee_paid} sat for {fee_units} units"));
    let (la, lb) = (shards["A"].snapshot().locked_sat, shards["B"].snapshot().locked_sat);
    ck.check("one key, two processes: A's locks went over A's ch2 and B's over B's, none sent to the other",
             ch2("A").routed == la && la > 0 && ch2("B").routed == lb && lb > 0
             && !hub.stats.lock().unwrap().refused.contains_key("unknown_session"),
             format!("ch2 A routed {} = {la}, ch2 B routed {} = {lb}", ch2("A").routed, ch2("B").routed));
    let at_fwd = hub.stats.lock().unwrap().ch1_locks_at_forward.clone();
    ck.check("fan-out: at most one lock pending on ch1 at every forward", !at_fwd.is_empty() && at_fwd.iter().all(|n| *n == 1),
             format!("{} forwards", at_fwd.len()));

    // --- settlement ------------------------------------------------------------------------------
    println!("== settle: client closes ch1, hub closes every ch2; check on-chain");
    let chan1 = payer.chan().unwrap();
    let st1 = hub.ch1_state(&chan1).unwrap();
    let c1 = payer.close().expect("close ch1");
    let mut closes = vec![];
    for n in NAMES {
        if let Some(oc) = hub.ch2_for(&urls[n]).filter(|c| c.state == "open") {
            closes.push((n, hub.close_ch2(&oc, false).expect("close ch2")));
        }
    }
    chain.mine(1);
    let (confs, paid1) = chain.payee_out(c1["txid"].as_str().unwrap(), &hex::encode(&st1.params.payee_spk));
    ck.check("ch1 close confirmed, pays the hub its best state", confs >= 1 && paid1 == st1.best_cum && c1["cum"].as_str() == Some(&st1.best_cum.to_string()),
             format!("{paid1} sat = routed {routed} (+ dust floor if any)"));
    let st1 = hub.ch1_state(&chan1).unwrap();
    ck.check("client and hub agree on ch1", st1.extra["routed_sat"].as_u64() == Some(routed) && st1.extra["fee_paid"].as_u64() == Some(fee_paid),
             format!("routed {routed}, fees {fee_paid}"));
    let (mut onchain, mut total_d, mut fees_paid) = (0u64, 0u64, 0u64);
    for (n, c) in &closes {
        if c["event"] == "ch2_idle" {
            println!("   ch2 {n}: nothing signed yet (opened by a rollover): nothing to close");
            continue;
        }
        let txid = c["txid"].as_str().unwrap();
        let p = &provs[&n[..1]];
        let st2 = p.channel_ids().iter().filter_map(|x| p.channel_state(x)).find(|s| s.closed_txid == txid).unwrap();
        let (confs, paid) = chain.payee_out(txid, &hex::encode(&st2.params.payee_spk));
        let (_, change) = chain.payee_out(txid, &hex::encode(&st2.params.payer_spk));
        let routed2 = st2.extra.get("routed_sat").and_then(Value::as_u64).unwrap_or(0);
        let fee2 = st2.params.close_fee;
        onchain += paid;
        total_d += routed2;
        fees_paid += fee2;
        ck.check(&format!("ch2 {n} close confirmed, pays the provider its best state less its own close fee"),
                 confs >= 1 && paid == st2.best_cum - fee2 && change == st2.params.capacity - st2.best_cum && st2.best_cum == routed2.max(546 + fee2),
                 format!("{paid} = {} - {fee2} sat, hub change {change}, routed {routed2}", st2.best_cum));
    }
    for r in &rolls {
        onchain += r["amount"].as_u64().unwrap() - fee_d;
        fees_paid += fee_d;
        total_d += r["amount"].as_u64().unwrap();
    }
    let lock_ms: Vec<f64> = shards.values().flat_map(|s| s.snapshot().lock_ms).collect();
    let call_ms: Vec<f64> = shards.values().flat_map(|s| s.snapshot().call_ms).collect();
    let hub_ms = hub.stats.lock().unwrap().lock_ms.clone();
    let st = payer.stats();
    println!("== latency");
    println!("   data call (client -> provider, metered, signed ROUTE-STATE): p50 {:.2} ms, p95 {:.2} ms", pct(&call_ms, 0.5), pct(&call_ms, 0.95));
    println!("   routed lock (client -> hub -> provider -> hub -> client, both hops' adaptor crypto): p50 {:.1} ms, p95 {:.1} ms over {} locks",
             pct(&lock_ms, 0.5), pct(&lock_ms, 0.95), lock_ms.len());
    println!("   hub-side lock (route check + forward + completion): p50 {:.1} ms, p95 {:.1} ms", pct(&hub_ms, 0.5), pct(&hub_ms, 0.95));
    println!("   locks: {} settled ({} under the dust floor, {} receipts via the provider), {} voided", st.locks, st.floor_locks, st.via_provider, st.voided);
    println!("   client paid {routed} sat through the hub ({fee_paid} sat routing fees); providers were routed {total_d} sat and received {onchain} sat \
              on-chain after paying their own {fees_paid} sat of close fees (closes + rollovers)");
    let ok = ck.0.iter().all(|c| c["ok"] == true);
    let report = json!({"network": net, "duration_s": t_end - t0,
        "calls": NAMES.iter().map(|n| (n.to_string(), json!(tl[n].iter().filter(|x| x.1 == 200).count()))).collect::<serde_json::Map<_, _>>(),
        "phase1_rate_per_s": NAMES.iter().map(|n| (n.to_string(), json!(snap1[n] as f64 / dur1))).collect::<serde_json::Map<_, _>>(),
        "call_ms": {"n": call_ms.len(), "p50": pct(&call_ms, 0.5), "p95": pct(&call_ms, 0.95)},
        "lock_ms": {"n": lock_ms.len(), "p50": pct(&lock_ms, 0.5), "p95": pct(&lock_ms, 0.95)},
        "hub_lock_ms": {"n": hub_ms.len(), "p50": pct(&hub_ms, 0.5), "p95": pct(&hub_ms, 0.95)},
        "locks": {"settled": st.locks, "floor": st.floor_locks, "via_provider": st.via_provider, "voided": st.voided},
        "client_routed_sat": routed, "client_fee_sat": fee_paid, "hub_events": hev, "rollovers": rolls, "ch1_close": c1,
        "ch2_closes": closes.iter().map(|(n, c)| json!({"provider": n, "close": c})).collect::<Vec<_>>(),
        "stops_after_withhold_s": stops, "onchain_to_providers_sat": onchain, "routed_to_providers_sat": total_d,
        "provider_close_fees_sat": fees_paid, "checks": ck.0, "elapsed_s": t_start.elapsed().as_secs_f64()});
    if let Some(p) = arg("--report") {
        std::fs::write(p, serde_json::to_string_pretty(&report).unwrap()).unwrap();
    }
    let n_ok = ck.0.iter().filter(|c| c["ok"] == true).count();
    println!("== route demo (all Rust): {} ({n_ok}/{} checks)", if ok { "PASS" } else { "FAIL" }, ck.0.len());
    let _ = std::fs::remove_dir_all(&run);
    std::process::exit(if ok { 0 } else { 1 });
}
