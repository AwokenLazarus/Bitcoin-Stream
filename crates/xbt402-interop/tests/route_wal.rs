//! AGP-054: the provider's RouteWal (B1 `tests/security/test_agp054_route_wal.py`, same cases).
//! A routed session's meter (seq, calls, accrued) is durable before its ROUTE-STATE leaves, and its
//! sync is written ahead while the handler runs:
//! * every answered state survives a crash; a restart counts more only for a call in flight at the
//!   crash, once, at its projected charge; its seq is durable (never served twice);
//! * a charge other than the projected one is corrected before the answer leaves;
//! * a routes-file save during a call (a lock completing) covers the call's reservation;
//! * a write failure is a 500 `route_wal_failed` with no ROUTE-STATE, nothing billed;
//! * the sync overlaps the handler; concurrent calls share syncs; compaction keeps the latest;
//! * ROUTE-STATE's invoice is signed once per window.
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use xbt402::adaptor::{self, Sc};
use xbt402::funding::FundingPolicy;
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route::{call_auth, session_key, state_verify};
use xbt402::route_seller::RouteOffer;
use xbt402::wire::{b64json, request_digest, unb64json};
use xbt402_interop::memnet::MemChain;
use xbt_primitives::ecdsa;
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;

const NET: &str = "bip122:11111111111111111111111111111111";
const PATH: &str = "/v1/chunk";
const PRICE: u128 = 370 * 10u128.pow(18);

fn sk(n: u64) -> SecretKey {
    Sc::from_u64(n).secret().unwrap()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("xbt-rs-agp054-{}", hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..8])));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

type H = Arc<dyn Fn(&[u8]) -> HttpResponse + Send + Sync>;

#[derive(Clone)]
struct Opts {
    wal: bool,
    precharge: bool,
    charge: Option<u128>,
}

impl Default for Opts {
    fn default() -> Self {
        Self { wal: true, precharge: true, charge: None }
    }
}

/// A provider on disk that can be "crashed" (dropped without a save) and started again.
struct BoxP {
    dir: TempDir,
    chain: Arc<MemChain>,
    opts: Opts,
    handler: Arc<Mutex<H>>,
    p: Arc<Provider>,
}

fn ok(_: &[u8]) -> HttpResponse {
    HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], b"{\"ok\":1}".to_vec())
}

impl BoxP {
    fn new(opts: Opts, handler: H) -> Self {
        let dir = TempDir::new();
        let chain = MemChain::new(1000);
        let handler = Arc::new(Mutex::new(handler));
        let p = Self::make(&dir, &chain, &opts, &handler);
        Self { dir, chain, opts, handler, p }
    }

    fn make(dir: &TempDir, chain: &Arc<MemChain>, opts: &Opts, handler: &Arc<Mutex<H>>) -> Arc<Provider> {
        let mut cfg = ProviderConfig::new(NET);
        cfg.close_margin = 36;
        cfg.policy = FundingPolicy { min_capacity: 20_000, min_expiry_blocks: 500, max_expiry_blocks: 8_640, close_margin: 36, ..FundingPolicy::default() };
        cfg.height_ttl = Duration::ZERO;
        if opts.wal {
            cfg.route_wal = Some(dir.0.join("prov.route-wal"));
        }
        let ledger = Ledger::open(&dir.0.join("prov.jsonl")).unwrap();
        let h = handler.clone();
        let p = Provider::new(chain.clone(), sk(0x5151), cfg, ledger, Box::new(|_, _| 1000),
                              Box::new(move |_, _, b| {
                                  let f = h.lock().unwrap().clone();
                                  f(b)
                              })).unwrap();
        let charge = opts.charge;
        let precharge = opts.precharge;
        p.offer_route(RouteOffer { window: 5.0, lock_wait: 5.0,
                                   charge: charge.map(|c| Box::new(move |_: &str, _: &str, _: u16, _: &[u8]| c) as _),
                                   precharge: precharge.then(|| Box::new(|_: &str, _: &str, _: &[u8]| Some(PRICE)) as _),
                                   ..RouteOffer::new(PATH, PRICE) });
        Arc::new(p)
    }

    fn restart(&mut self) {
        self.p = Self::make(&self.dir, &self.chain, &self.opts, &self.handler);
    }

    fn set_handler(&self, h: H) {
        *self.handler.lock().unwrap() = h;
    }

    fn meter(&self, sid: &str) -> (u64, u64, u128) {
        let st = self.p.routes().lock();
        let s = &st.sessions[sid];
        (s.seq, s.calls, s.accrued_amsat)
    }

    fn wal_settle(&self) {
        let w = self.p.routes().wal().unwrap();
        w.wait(w.version(), Duration::from_secs(10)).unwrap();
    }
}

struct Client {
    session: String,
    key: [u8; 32],
    seq: u64,
    states: Vec<Value>,
}

impl Client {
    fn new(b: &BoxP) -> Self {
        let c = adaptor::random_secret();
        let r = b.p.serve("POST", PATH, &[("ROUTE-CLIENT".into(), hex::encode(ecdsa::pubkey(&c)))], b"", "", None);
        assert_eq!(r.status, 402);
        let pr = unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap();
        let session = pr["accepts"][0]["extra"]["route"]["session"].as_str().unwrap().to_string();
        let key = session_key(&c, &hex::decode(b.p.pay_to()).unwrap()).unwrap();
        Self { session, key, seq: 0, states: vec![] }
    }

    fn headers(&mut self, body: &[u8], seq: Option<u64>) -> Vec<(String, String)> {
        let seq = seq.unwrap_or_else(|| {
            self.seq += 1;
            self.seq
        });
        let auth = call_auth(&self.key, &self.session, seq, &request_digest("POST", PATH, body));
        vec![("ROUTE-AUTH".into(), b64json(&serde_json::json!({"session": self.session, "seq": seq, "auth": auth})))]
    }

    fn call_seq(&mut self, b: &BoxP, body: &[u8], seq: Option<u64>) -> HttpResponse {
        let h = self.headers(body, seq);
        let r = b.p.serve("POST", PATH, &h, body, "", None);
        if let Some(s) = r.header("ROUTE-STATE") {
            let s = unb64json(s).unwrap();
            assert!(state_verify(b.p.pay_to(), &s));
            self.states.push(s);
        }
        r
    }

    fn call(&mut self, b: &BoxP, body: &[u8]) -> HttpResponse {
        self.call_seq(b, body, None)
    }

    fn accrued(&self) -> u128 {
        self.states.last().unwrap()["accruedAmsat"].as_str().unwrap().parse().unwrap()
    }
}

#[test]
fn every_answered_state_survives_a_crash() {
    let mut b = BoxP::new(Opts::default(), Arc::new(ok));
    let mut c = Client::new(&b);
    for _ in 0..25 {
        assert_eq!(c.call(&b, b"x").status, 200);
    }
    assert_eq!(c.accrued(), 25 * PRICE);
    b.restart();
    assert_eq!(b.meter(&c.session), (25, 25, 25 * PRICE));
    let r = c.call_seq(&b, b"x", Some(25));
    assert_eq!(r.status, 402);
    assert!(String::from_utf8_lossy(&r.body).contains("bad_auth"));
    assert_eq!(c.call(&b, b"x").status, 200);
    assert_eq!(c.accrued(), 26 * PRICE);
}

#[test]
fn without_the_wal_a_crash_rewinds_the_meter() {
    let mut b = BoxP::new(Opts { wal: false, ..Opts::default() }, Arc::new(ok));
    let mut c = Client::new(&b);
    for _ in 0..5 {
        c.call(&b, b"x");
    }
    b.restart();
    assert_eq!(b.meter(&c.session), (0, 0, 0));
}

#[test]
fn a_call_in_flight_at_the_crash_counts_once_at_its_projection() {
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let (e2, r2) = (entered.clone(), release.clone());
    let mut b = BoxP::new(Opts::default(), Arc::new(move |body: &[u8]| {
        if body == b"slow" {
            e2.store(true, Ordering::SeqCst);
            while !r2.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        ok(body)
    }));
    let mut c = Client::new(&b);
    for _ in 0..3 {
        c.call(&b, b"x");
    }
    let h = c.headers(b"slow", None);
    let p = b.p.clone();
    let th = std::thread::spawn(move || p.serve("POST", PATH, &h, b"slow", "", None));
    while !entered.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(2));
    }
    b.wal_settle();
    let old = b.p.clone();
    b.restart();
    assert_eq!(b.meter(&c.session), (4, 4, 4 * PRICE));
    let r = c.call_seq(&b, b"slow", Some(4));
    assert_eq!(r.status, 402);
    release.store(true, Ordering::SeqCst);
    th.join().unwrap();
    drop(old);
}

#[test]
fn a_charge_other_than_projected_is_corrected_before_the_answer() {
    let mut b = BoxP::new(Opts::default(), Arc::new(|body: &[u8]| {
        if body == b"fail" { HttpResponse::new(503, vec![], b"busy".to_vec()) } else { ok(body) }
    }));
    let mut c = Client::new(&b);
    c.call(&b, b"x");
    assert_eq!(c.call(&b, b"fail").status, 503);
    assert_eq!(c.accrued(), PRICE);
    b.restart();
    assert_eq!(b.meter(&c.session), (2, 2, PRICE));
}

#[test]
fn a_metered_charge_below_the_precharge_is_corrected() {
    let mut b = BoxP::new(Opts { charge: Some(PRICE / 3), ..Opts::default() }, Arc::new(ok));
    let mut c = Client::new(&b);
    for _ in 0..4 {
        c.call(&b, b"x");
    }
    assert_eq!(c.accrued(), 4 * (PRICE / 3));
    b.restart();
    assert_eq!(b.meter(&c.session), (4, 4, 4 * (PRICE / 3)));
}

#[test]
fn a_routes_file_save_during_a_call_covers_it() {
    let mut b = BoxP::new(Opts::default(), Arc::new(ok));
    let mut c = Client::new(&b);
    c.call(&b, b"x");
    // what a lock completing does mid-call: save the routes file (a new session open saves it too)
    let slot: Arc<Mutex<Option<Arc<Provider>>>> = Arc::new(Mutex::new(Some(b.p.clone())));
    let s2 = slot.clone();
    b.set_handler(Arc::new(move |body: &[u8]| {
        if let Some(p) = s2.lock().unwrap().as_ref() {
            let k = adaptor::random_secret();
            p.serve("POST", PATH, &[("ROUTE-CLIENT".into(), hex::encode(ecdsa::pubkey(&k)))], b"", "", None);
        }
        ok(body)
    }));
    let w = b.p.routes().wal().unwrap().clone();
    let fs = w.fsyncs();
    assert_eq!(c.call(&b, b"x").status, 200);
    assert_eq!(w.fsyncs() - fs, 1, "the reservation only");
    *slot.lock().unwrap() = None;
    b.restart();
    assert_eq!(b.meter(&c.session), (2, 2, 2 * PRICE));
}

#[test]
fn a_wal_write_failure_is_a_500_with_nothing_billed() {
    let mut b = BoxP::new(Opts::default(), Arc::new(ok));
    let mut c = Client::new(&b);
    c.call(&b, b"x");
    let w = b.p.routes().wal().unwrap().clone();
    w.fail_writes.store(true, Ordering::SeqCst);
    let r = c.call(&b, b"x");
    w.fail_writes.store(false, Ordering::SeqCst);
    assert_eq!(r.status, 500);
    assert!(r.header("ROUTE-STATE").is_none());
    assert!(String::from_utf8_lossy(&r.body).contains("route_wal_failed"));
    assert_eq!(b.meter(&c.session), (2, 1, PRICE));
    assert_eq!(c.call(&b, b"x").status, 200);
    assert_eq!(c.accrued(), 2 * PRICE);
    b.restart();
    assert_eq!(b.meter(&c.session), (3, 2, 2 * PRICE));
}

#[test]
fn compaction_keeps_the_latest_snapshot_per_session() {
    let mut b = BoxP::new(Opts::default(), Arc::new(ok));
    b.p.routes().wal().unwrap().set_compact_bytes(400);
    let mut cs: Vec<Client> = (0..3).map(|_| Client::new(&b)).collect();
    for i in 0..40 {
        cs[i % 3].call(&b, b"x");
    }
    b.wal_settle();
    std::thread::sleep(Duration::from_millis(50));
    let size = std::fs::metadata(b.p.routes().wal().unwrap().path()).unwrap().len();
    assert!(size < 2_000, "{size}");
    b.restart();
    for c in &cs {
        let n = c.states.len() as u64;
        assert_eq!(b.meter(&c.session), (n, n, n as u128 * PRICE));
    }
}

#[test]
fn the_sync_runs_while_the_handler_computes() {
    let b = BoxP::new(Opts::default(), Arc::new(|body: &[u8]| {
        std::thread::sleep(Duration::from_millis(150));
        ok(body)
    }));
    let mut c = Client::new(&b);
    c.call(&b, b"x");
    b.p.routes().wal().unwrap().sync_delay_ms.store(150, Ordering::SeqCst);
    let t = Instant::now();
    assert_eq!(c.call(&b, b"x").status, 200);
    assert!(t.elapsed() < Duration::from_millis(270), "{:?}", t.elapsed());
}

#[test]
fn without_a_precharge_the_answer_waits_for_its_own_sync() {
    let mut b = BoxP::new(Opts { precharge: false, charge: Some(PRICE), ..Opts::default() }, Arc::new(|body: &[u8]| {
        std::thread::sleep(Duration::from_millis(150));
        ok(body)
    }));
    let mut c = Client::new(&b);
    c.call(&b, b"x");
    b.p.routes().wal().unwrap().sync_delay_ms.store(150, Ordering::SeqCst);
    let t = Instant::now();
    c.call(&b, b"x");
    assert!(t.elapsed() >= Duration::from_millis(290), "{:?}", t.elapsed());
    b.p.routes().wal().unwrap().sync_delay_ms.store(0, Ordering::SeqCst);
    b.restart();
    assert_eq!(b.meter(&c.session), (2, 2, 2 * PRICE));
}

#[test]
fn concurrent_calls_share_syncs() {
    let mut b = BoxP::new(Opts::default(), Arc::new(|body: &[u8]| {
        std::thread::sleep(Duration::from_millis(5));
        ok(body)
    }));
    let w = b.p.routes().wal().unwrap().clone();
    let cs: Vec<Client> = (0..8).map(|_| Client::new(&b)).collect();
    w.sync_delay_ms.store(20, Ordering::SeqCst);
    let fs = w.fsyncs();
    let sids: Vec<String> = cs.iter().map(|c| c.session.clone()).collect();
    let ths: Vec<_> = cs.into_iter().map(|mut c| {
        let p = b.p.clone();
        std::thread::spawn(move || {
            for _ in 0..10 {
                let h = c.headers(b"x", None);
                assert_eq!(p.serve("POST", PATH, &h, b"x", "", None).status, 200);
            }
        })
    }).collect();
    for t in ths {
        t.join().unwrap();
    }
    let used = w.fsyncs() - fs;
    w.sync_delay_ms.store(0, Ordering::SeqCst);
    assert!(used < 40, "{used} syncs for 80 calls");
    b.restart();
    for sid in sids {
        assert_eq!(b.meter(&sid), (10, 10, 10 * PRICE));
    }
}

#[test]
fn one_invoice_signature_per_window() {
    let b = BoxP::new(Opts { wal: false, ..Opts::default() }, Arc::new(ok));
    let mut c = Client::new(&b);
    c.call(&b, b"x");
    c.call(&b, b"x");
    assert_eq!(c.states[0]["invoice"], c.states[1]["invoice"]);
}

// --- AGP-054 rework 1: a ROUTE-STATE carries the session's CURRENT meter, so it may leave only once
// a snapshot covering THAT is durable, not merely the call's own reserved one (agp-lead repro
// b1 tests/security/lead_wal_race_repro.py). Each test holds the writer on the later snapshot and
// checks, at the moment a state is returned, that the durable log already covers it.

fn covered(b: &BoxP, sid: &str, st: &Value) -> bool {
    let d = b.p.routes().wal().unwrap().read()[sid].clone();
    let n = |k: &str| st[k].as_u64().unwrap();
    d.seq >= n("seq") && d.calls >= n("calls") && d.acc >= st["accruedAmsat"].as_str().unwrap().parse::<u128>().unwrap()
}

/// Run `f` in a thread while the writer is held (`hold_from` set by the caller); it must not return while held, and at its
/// return the durable log must cover the state it returned. Returns the state.
fn answer_while_held(b: &BoxP, sid: &str, f: impl FnOnce() -> Option<Value> + Send + 'static) -> Value {
    let w = b.p.routes().wal().unwrap().clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let p = b.p.clone();
    let sid2 = sid.to_string();
    let th = std::thread::spawn(move || {
        let st = f().expect("a state");
        let d = p.routes().wal().unwrap().read()[&sid2].clone();
        tx.send((st, d)).unwrap();
    });
    let early = rx.recv_timeout(Duration::from_millis(300)).ok();
    assert!(early.is_none(), "a state left while the snapshot covering it was held: {early:?}");
    w.hold_from.store(0, Ordering::SeqCst);
    let (st, d) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    th.join().unwrap();
    let n = |k: &str| st[k].as_u64().unwrap();
    assert!(d.seq >= n("seq") && d.calls >= n("calls") && d.acc >= st["accruedAmsat"].as_str().unwrap().parse::<u128>().unwrap(),
            "durable {d:?} below the state that left {st}");
    st
}

fn begin(b: &BoxP, c: &mut Client) -> String {
    let h = c.headers(b"x", None);
    let (sid, err) = b.p.routes().begin_call(PATH, &h[0].1, "POST", PATH, b"x").unwrap();
    assert!(err.is_none());
    sid
}

#[test]
fn concurrent_calls_on_one_session_wait_for_the_later_snapshot() {
    let b = BoxP::new(Opts::default(), Arc::new(ok));
    let mut c = Client::new(&b);
    let rs = b.p.routes();
    let w = rs.wal().unwrap().clone();
    let sid = begin(&b, &mut c);
    let ta = rs.reserve(&sid, PRICE).unwrap();
    w.wait(ta.v, Duration::from_secs(10)).unwrap();                  // A's snapshot v1 durable
    begin(&b, &mut c);
    w.hold_from.store(ta.v + 1, Ordering::SeqCst);
    let tb = rs.reserve(&sid, PRICE).unwrap();                         // B's snapshot v2: writer held
    let (p, s2) = (b.p.clone(), sid.clone());
    let thb = std::thread::spawn(move || p.routes().end_call_reserved(&s2, PRICE, Some(tb)).unwrap());
    std::thread::sleep(Duration::from_millis(200));                    // B metered in memory, waiting on v2
    let (p, s2) = (b.p.clone(), sid.clone());
    let st = answer_while_held(&b, &sid, move || p.routes().end_call_reserved(&s2, PRICE, Some(ta)).ok());
    thb.join().unwrap();
    assert_eq!(st["calls"], 2);
    assert_eq!(st["accruedAmsat"].as_str().unwrap(), (2 * PRICE).to_string());
}

#[test]
fn a_seq_taken_by_a_concurrent_begin_call_is_durable_before_a_state_carries_it() {
    let mut b = BoxP::new(Opts::default(), Arc::new(ok));
    let mut c = Client::new(&b);
    let w = b.p.routes().wal().unwrap().clone();
    let sid = begin(&b, &mut c);                                       // A: seq 1
    let ta = b.p.routes().reserve(&sid, PRICE).unwrap();
    w.wait(ta.v, Duration::from_secs(10)).unwrap();
    begin(&b, &mut c);                                                 // C: seq 2, authenticated, not reserved
    w.hold_from.store(ta.v + 1, Ordering::SeqCst);
    let (p, s2) = (b.p.clone(), sid.clone());
    let st = answer_while_held(&b, &sid, move || p.routes().end_call_reserved(&s2, PRICE, Some(ta)).ok());
    assert_eq!(st["seq"], 2);
    b.restart();                                                       // C's ROUTE-AUTH is not served again
    assert_eq!(b.meter(&c.session).0, 2);
}

#[test]
fn a_refusal_state_is_durable_before_the_402_carries_it() {
    let b = BoxP::new(Opts::default(), Arc::new(ok));
    let mut c = Client::new(&b);
    assert_eq!(c.call(&b, b"x").status, 200);
    let sid = begin(&b, &mut c);                                       // a refused call still takes its seq
    let w = b.p.routes().wal().unwrap().clone();
    w.hold_from.store(w.version() + 1, Ordering::SeqCst);
    let (p, s2) = (b.p.clone(), sid.clone());
    let st = answer_while_held(&b, &sid, move || p.routes().refusal_state(&s2));
    assert_eq!(st["seq"], 2);
}

#[test]
fn a_refusal_402_carries_a_covered_state() {
    let mut b = BoxP::new(Opts::default(), Arc::new(ok));
    let mut c = Client::new(&b);
    assert_eq!(c.call(&b, b"x").status, 200);
    b.p.routes().lock().sessions.get_mut(&c.session).unwrap().unpaid_since -= 60.0;   // past window + lock_wait
    let r = c.call(&b, b"x");
    assert_eq!(r.status, 402);
    let doc = unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap();
    assert_eq!(doc["routeState"]["seq"], 2);
    assert!(covered(&b, &c.session, &doc["routeState"]));
    b.restart();
    assert_eq!(b.meter(&c.session), (2, 1, PRICE));
}

#[test]
fn sequential_calls_still_answer_from_their_reserved_snapshot() {
    let b = BoxP::new(Opts::default(), Arc::new(ok));
    let mut c = Client::new(&b);
    let w = b.p.routes().wal().unwrap().clone();
    let v0 = w.version();
    for _ in 0..10 {
        assert_eq!(c.call(&b, b"x").status, 200);
    }
    assert_eq!(w.version() - v0, 10, "one snapshot per call: the overlap is kept");
}

#[test]
fn a_lost_log_does_not_restart_below_walv() {
    let mut b = BoxP::new(Opts::default(), Arc::new(ok));
    let mut c = Client::new(&b);
    for _ in 0..3 {
        c.call(&b, b"x");
    }
    b.wal_settle();
    let _other = Client::new(&b);                                      // a session open saves the routes file (walV 3)
    std::fs::remove_file(b.dir.0.join("prov.route-wal")).unwrap();
    b.restart();
    assert!(b.p.routes().wal().unwrap().version() >= 3);
    assert_eq!(c.call(&b, b"x").status, 200);
    b.restart();                                                       // the new line wins over the file
    assert_eq!(b.meter(&c.session), (4, 4, 4 * PRICE));
}

#[test]
fn a_wal_failure_is_not_taken_back_once_a_later_state_carries_it() {
    let mut b = BoxP::new(Opts::default(), Arc::new(ok));
    let mut c = Client::new(&b);
    let w = b.p.routes().wal().unwrap().clone();
    let sid = begin(&b, &mut c);
    let ta = b.p.routes().reserve(&sid, PRICE).unwrap();
    w.wait(ta.v, Duration::from_secs(10)).unwrap();
    begin(&b, &mut c);
    w.hold_from.store(ta.v + 1, Ordering::SeqCst);
    w.fail_v.store(ta.v + 1, Ordering::SeqCst);                        // v2's batch will fail
    let tb = b.p.routes().reserve(&sid, PRICE).unwrap();
    let (p, s2) = (b.p.clone(), sid.clone());
    let tha = std::thread::spawn(move || p.routes().end_call_reserved(&s2, PRICE, Some(ta)).map_err(|e| e.code));
    std::thread::sleep(Duration::from_millis(200));                    // A metered, waiting on v2
    let (p, s2) = (b.p.clone(), sid.clone());
    let thb = std::thread::spawn(move || p.routes().end_call_reserved(&s2, PRICE / 2, Some(tb)).map_err(|e| e.code));
    std::thread::sleep(Duration::from_millis(200));                    // B corrected: its own v3
    w.hold_from.store(0, Ordering::SeqCst);
    let (a, bb) = (tha.join().unwrap(), thb.join().unwrap().unwrap());
    assert_eq!(a.unwrap_err(), "route_wal_failed");
    assert_eq!(bb["calls"], 2);
    assert_eq!(bb["accruedAmsat"].as_str().unwrap(), (PRICE + PRICE / 2).to_string());
    let m = b.meter(&c.session);
    assert_eq!((m.1, m.2), (2, PRICE + PRICE / 2), "A stays billed: B's state already carries it");
    w.fail_v.store(0, Ordering::SeqCst);
    b.restart();
    assert!(b.meter(&c.session).2 >= PRICE + PRICE / 2);
}
