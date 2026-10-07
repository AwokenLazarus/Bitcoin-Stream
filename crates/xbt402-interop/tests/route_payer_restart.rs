//! AGP-044: the RoutePayer ledger seam. A routed client is killed (dropped, never closed) mid-window
//! in each state a crash can leave it in, and a new RoutePayer resumes from its [`RouteLedger`]:
//! the same ch1, the same provider sessions, the pending lock sent again, and at the end the meters
//! are exact (provider == client, to the amsat), the provider's paid == the client's locks, the
//! hub's ch1 best state == the client's signed state and every ch2's routed total == what the
//! client's locks paid that provider. The signer outlives the payer (as `xbt-signer` does), and the
//! ledger file holds no payer key, signature or refund.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::adaptor::{self, Sc};
use xbt402::channel::FeePayer;
use xbt402::client::ClientLedger;
use xbt402::error::{ChannelError, Result};
use xbt402::funding::FundingPolicy;
use xbt402::hub::{HubConfig, RouteHub};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route::{ceil_div, AMSAT_PER_SAT, FEE_UNITS_PER_SAT, HUB_ROUTE_PATH};
use xbt402::route_client::{FileRouteLedger, MemoryRouteLedger, RouteLedger, RoutePayer, RoutePayerConfig, Shard};
use xbt402::route_seller::RouteOffer;
use xbt402::signer::{LocalSigner, RouteSigner, StateSigner};
use xbt402_interop::memnet::{ChainWallet, MemChain, MemNet, NetTransport};
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;

const NET: &str = "bip122:11111111111111111111111111111111";
const HUB: &str = "http://hub.test";
const PRICE: u128 = 370 * 10u128.pow(18) * 100; // 37 sat a call: every window's lock is a new signed state

fn sk(n: u64) -> SecretKey {
    Sc::from_u64(n).secret().unwrap()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("xbt-rs-agp044r-{}", hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..8])));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn provider(chain: &Arc<MemChain>, net: &Arc<MemNet>, dir: &TempDir, origin: &str) -> Arc<Provider> {
    let mut cfg = ProviderConfig::new(NET);
    cfg.close_margin = 36;
    cfg.policy = FundingPolicy { min_capacity: 20_000, min_expiry_blocks: 500, max_expiry_blocks: 8_640, close_margin: 36, ..FundingPolicy::default() };
    cfg.height_ttl = Duration::ZERO;
    cfg.route_close_fee_payer = FeePayer::Payee;
    let name = origin.replace("http://", "").replace('.', "_");
    let ledger = Ledger::open(&dir.0.join(format!("prov-{name}.jsonl"))).unwrap();
    let p = Provider::new(chain.clone(), adaptor::random_secret(), cfg, ledger, Box::new(|_, _| 1000),
                          Box::new(|_, _, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], b"{\"ok\":1}".to_vec()))).unwrap();
    p.offer_route(RouteOffer { window: 0.3, lock_wait: 30.0, invoice_ttl: 8.0, ..RouteOffer::new("/v1/chunk", PRICE) });
    let p = Arc::new(p);
    net.add(origin, p.clone());
    p
}

/// A ledger whose saves can be made to fail (a full disk; a crash between two saves).
struct Flaky {
    inner: MemoryRouteLedger,
    fail: AtomicBool,
    saves: AtomicUsize,
}

impl ClientLedger for Flaky {
    fn load(&self) -> Result<Vec<(String, Value)>> {
        ClientLedger::load(&self.inner)
    }

    fn save(&self, records: &[(String, Value)]) -> Result<()> {
        self.saves.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(ChannelError::new("ledger_error", "disk full"));
        }
        ClientLedger::save(&self.inner, records)
    }
}

/// Shares one [`Flaky`] between payer instances (the "file" both processes open).
struct Shared(Arc<Flaky>);

impl ClientLedger for Shared {
    fn load(&self) -> Result<Vec<(String, Value)>> {
        ClientLedger::load(&*self.0)
    }

    fn save(&self, records: &[(String, Value)]) -> Result<()> {
        ClientLedger::save(&*self.0, records)
    }
}

struct W {
    chain: Arc<MemChain>,
    net: Arc<MemNet>,
    hub: Arc<RouteHub>,
    provs: Vec<(String, Arc<Provider>)>,
    signer: Arc<LocalSigner>,
    dir: TempDir,
}

impl W {
    fn new() -> Self {
        let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
        let cfg = HubConfig::from_json(&json!({"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500,
                                               "delta": 36, "reveal_timeout": 1.0, "ch2_capacity": 100000, "ch2_expiry_blocks": 1000,
                                               "close_margin": 36, "policy": {"min_capacity": 20000, "min_expiry_blocks": 500, "max_expiry_blocks": 8640}})).unwrap();
        let h = Arc::new(RouteHub::new(chain.clone(), chain.clone(), Box::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())),
                                       sk(0x4B4B), NET, Some(&dir.0.join("hub")), cfg).unwrap());
        net.add(HUB, h.clone());
        let provs: Vec<_> = (0..2).map(|i| {
            let o = format!("http://p{i}.test");
            let p = provider(&chain, &net, &dir, &o);
            h.connect(&o, None, None).unwrap();
            (o, p)
        }).collect();
        chain.confirm_all();
        h.watch_tick();
        Self { chain, net, hub: h, provs, signer: Arc::new(LocalSigner::new()), dir }
    }

    /// A payer process: the world's signer (it outlives payers), on `ledger`.
    fn payer(&self, ledger: Box<dyn RouteLedger>) -> Arc<RoutePayer> {
        let c = self.chain.clone();
        let mut pc = RoutePayerConfig::new(NET);
        pc.expiry_blocks = 8_000;
        let p = RoutePayer::new(HUB, pc, self.signer.clone(), Arc::new(ChainWallet(self.chain.clone())), Box::new(NetTransport(self.net.clone())),
                                Box::new(move || Ok(c.height())));
        Arc::new(p.with_ledger(ledger).unwrap())
    }

    fn file(&self) -> PathBuf {
        self.dir.0.join("route-payer.jsonl")
    }

    fn file_payer(&self) -> Arc<RoutePayer> {
        self.payer(Box::new(FileRouteLedger::open(&self.file()).unwrap()))
    }

    fn shards(&self, pay: &RoutePayer) -> Vec<Arc<Shard>> {
        self.provs.iter().map(|(o, _)| pay.shard(&format!("{o}/v1/chunk"), "POST").unwrap()).collect()
    }
}

fn stream(pay: &RoutePayer, sh: &Arc<Shard>, n: usize) {
    for _ in 0..n {
        let r = pay.call(sh, "POST", br#"{"tokens":1}"#).unwrap();
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    }
}

fn events(pay: &RoutePayer, name: &str) -> Vec<Value> {
    pay.events.lock().unwrap().iter().filter(|e| e["event"] == name).cloned().collect()
}

/// Pay everything due, then check every meter and total exactly.
fn finish_and_check(w: &W, pay: &RoutePayer, shards: &[Arc<Shard>]) {
    for _ in 0..40 {
        for sh in shards {
            let x = sh.snapshot();
            if sh.due_sat() > 0 && x.invoice["lockId"].as_str() == Some(x.last_locked.as_str()) {
                stream(pay, sh, 1); // an invoice is paid once: the next ROUTE-STATE brings a fresh one
            }
            let _ = pay.lock(sh).unwrap();
        }
        if pay.pending().is_none() && shards.iter().all(|s| s.due_sat() <= 0) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(pay.pending().is_none() && shards.iter().all(|s| s.due_sat() <= 0), "{:?}", pay.summary());
    let chan = pay.chan().unwrap();
    let (routed, fee_units, fee_paid, signed) = pay.counters();
    for (sh, (o, p)) in shards.iter().zip(&w.provs) {
        let x = sh.snapshot();
        let s = p.routes().lock().sessions[&sh.session].clone();
        assert_eq!((s.accrued_amsat, x.seen_amsat), (x.accrued_amsat, s.accrued_amsat), "{o}: provider meter == client meter");
        assert_eq!(s.paid_sat, x.locked_sat, "{o}: paid == the client's locks");
        assert!(s.paid_sat as u128 <= ceil_div(s.accrued_amsat, AMSAT_PER_SAT));
        assert_eq!(w.hub.out_channels()[o].routed, x.locked_sat, "{o}: ch2 routed == the client's locks to it");
    }
    assert_eq!(fee_paid as u128, ceil_div(fee_units, FEE_UNITS_PER_SAT), "fees == ceil(units / 1e9)");
    let st1 = w.hub.ch1_state(&chan).unwrap();
    assert_eq!(st1.best_cum, signed, "the hub's ch1 best state == the client's signed state");
    assert_eq!(routed - fee_paid, shards.iter().map(|s| s.snapshot().locked_sat).sum::<u64>());
    assert_eq!(w.signer.signed(&chan), signed, "the signer's signed state == the client's");
    assert!(w.signer.pending_lock(&chan).is_none());
    let close = pay.close().unwrap();
    assert_eq!(close["cum"].as_str().map(|c| c.parse::<u64>().unwrap()).or(close["cum"].as_u64()), Some(signed));
}

// --- the tests ----------------------------------------------------------------------------------------

#[test]
fn restart_mid_window_resumes_ch1_and_the_sessions_with_exact_meters() {
    let w = W::new();
    let a = w.file_payer();
    let ch = a.open().unwrap();
    let sh = w.shards(&a);
    stream(&a, &sh[0], 10);
    assert_eq!(a.lock(&sh[0]).unwrap().unwrap()["status"], "paid");
    stream(&a, &sh[0], 7); // mid-window: accrued, not locked yet
    stream(&a, &sh[1], 3);
    let before = (a.counters(), sh[0].snapshot().seen_amsat, sh[1].snapshot().seen_amsat, sh[0].session.clone());
    drop(sh);
    drop(a); // killed: no stop, no close
    let b = w.file_payer();
    let r = b.open().unwrap();
    assert_eq!((r["chan"].clone(), r["resumed"].clone()), (ch["chan"].clone(), json!(true)));
    let calls0 = w.net.count(HUB_ROUTE_PATH);
    let sh = w.shards(&b);
    assert_eq!(sh[0].session, before.3); // the same provider session, no new 402
    assert_eq!((b.counters(), sh[0].snapshot().seen_amsat, sh[1].snapshot().seen_amsat), (before.0, before.1, before.2));
    assert_eq!(w.net.count(HUB_ROUTE_PATH), calls0);
    stream(&b, &sh[0], 4);
    stream(&b, &sh[1], 9);
    assert!(events(&b, "resumed").len() == 1);
    finish_and_check(&w, &b, &sh);
}

#[test]
fn restart_with_the_lock_answer_lost_resends_it_and_takes_the_hub_s_saved_answer() {
    let w = W::new();
    let a = w.file_payer();
    a.open().unwrap();
    let sh = w.shards(&a);
    stream(&a, &sh[0], 10);
    w.net.set_drop(HUB, Some(Box::new(|_, p| p == HUB_ROUTE_PATH))); // the hub completes it; the answer is lost
    let r = a.lock(&sh[0]).unwrap().unwrap();
    assert_eq!(r["status"], "pending");
    let lock_id = a.pending().unwrap()["lockId"].clone();
    assert!(w.signer.pending_lock(&a.chan().unwrap()).is_some());
    drop(sh);
    drop(a);
    w.net.set_drop(HUB, None);
    let b = w.file_payer();
    b.open().unwrap();
    assert_eq!(b.pending().unwrap()["lockId"], lock_id);
    let sh = w.shards(&b);
    let r = b.lock(&sh[1]).unwrap().unwrap(); // the resumed lock goes first, whatever the shard
    assert_eq!((r["status"].as_str(), &r["lockId"]), (Some("paid"), &lock_id), "{r}");
    assert_eq!(events(&b, "lock_resent").len(), 1);
    assert_eq!(b.stats().locks, 1);
    stream(&b, &sh[1], 6);
    finish_and_check(&w, &b, &sh);
}

#[test]
fn restart_with_a_lock_the_hub_never_received_sends_it_now() {
    let w = W::new();
    let flaky = Arc::new(Flaky { inner: MemoryRouteLedger::default(), fail: AtomicBool::new(false), saves: AtomicUsize::new(0) });
    let a = w.payer(Box::new(Shared(flaky.clone())));
    a.open().unwrap();
    let sh = w.shards(&a);
    stream(&a, &sh[0], 10);
    // the request never reaches the hub (the process dies right after the write-ahead)
    w.net.add(HUB, Arc::new(Refuse));
    let r = a.lock(&sh[0]).unwrap().unwrap();
    assert_eq!(r["status"], "pending");
    drop(sh);
    drop(a);
    w.net.add(HUB, w.hub.clone());
    let b = w.payer(Box::new(Shared(flaky.clone())));
    let sh = w.shards(&b);
    assert_eq!(b.lock(&sh[0]).unwrap().unwrap()["status"], "paid");
    finish_and_check(&w, &b, &sh);
}

/// A hub that is not there (connection refused).
struct Refuse;

impl xbt402::http::HttpService for Refuse {
    fn body_limit(&self, _: &str) -> usize {
        1 << 20
    }

    fn serve(&self, _: &str, _: &str, _: &[(String, String)], _: &[u8], _: &str) -> HttpResponse {
        HttpResponse::new(503, vec![], b"down".to_vec())
    }
}

#[test]
fn restart_after_the_signer_resolved_but_before_the_ledger_saved_commits_on_the_secret() {
    let w = W::new();
    let flaky = Arc::new(Flaky { inner: MemoryRouteLedger::default(), fail: AtomicBool::new(false), saves: AtomicUsize::new(0) });
    let a = w.payer(Box::new(Shared(flaky.clone())));
    a.open().unwrap();
    let sh = w.shards(&a);
    stream(&a, &sh[0], 10);
    // the write-ahead lands, then every later save fails: the signer resolves, the ledger never hears
    let n0 = flaky.saves.load(Ordering::SeqCst);
    let (fail, f2) = (Arc::new(AtomicBool::new(false)), flaky.clone());
    let fl = fail.clone();
    w.net.set_drop(HUB, Some(Box::new(move |_, p| {
        if p == HUB_ROUTE_PATH && f2.saves.load(Ordering::SeqCst) > n0 {
            f2.fail.store(true, Ordering::SeqCst);
            fl.store(true, Ordering::SeqCst);
        }
        false
    })));
    assert_eq!(a.lock(&sh[0]).unwrap().unwrap()["status"], "paid");
    assert!(fail.load(Ordering::SeqCst));
    assert!(!events(&a, "ledger_error").is_empty());
    let chan = a.chan().unwrap();
    assert!(w.signer.pending_lock(&chan).is_none()); // resolved in the signer
    drop(sh);
    drop(a);
    w.net.set_drop(HUB, None);
    flaky.fail.store(false, Ordering::SeqCst);
    let b = w.payer(Box::new(Shared(flaky.clone())));
    assert!(b.pending().is_some()); // the ledger still has it pending
    let sh = w.shards(&b);
    let r = b.lock(&sh[0]).unwrap().unwrap();
    assert_eq!(r["status"], "paid", "{r}"); // the hub's saved answer; the signer has no lock left: committed on y = t + r
    assert_eq!(b.stats().locks, 1);
    stream(&b, &sh[0], 5);
    finish_and_check(&w, &b, &sh);
}

#[test]
fn restart_voids_a_presignature_the_ledger_never_recorded() {
    let w = W::new();
    let a = w.file_payer();
    a.open().unwrap();
    let sh = w.shards(&a);
    stream(&a, &sh[0], 10);
    let chan = a.chan().unwrap();
    // the process died between the signer's presign and the write-ahead
    let point = hex::decode(sh[0].snapshot().invoice["point"].as_str().unwrap()).unwrap().try_into().unwrap();
    w.signer.sign_state_adaptor(&chan, 5_000, &point, &json!({})).unwrap();
    drop(sh);
    drop(a);
    let b = w.file_payer();
    assert!(w.signer.pending_lock(&chan).is_none());
    assert_eq!(events(&b, "void").len(), 1);
    let sh = w.shards(&b);
    assert_eq!(b.lock(&sh[0]).unwrap().unwrap()["status"], "paid");
    finish_and_check(&w, &b, &sh);
}

#[test]
fn restart_adopts_calls_in_doubt_within_the_quoted_price() {
    let w = W::new();
    let a = w.file_payer();
    a.open().unwrap();
    let sh = w.shards(&a);
    stream(&a, &sh[0], 5);
    // two calls served and charged, their answers lost (the process dies with them in flight)
    let n = Arc::new(AtomicUsize::new(2));
    let n2 = n.clone();
    w.net.set_drop(&w.provs[0].0, Some(Box::new(move |_, p| p == "/v1/chunk" && n2.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |x| x.checked_sub(1)).is_ok())));
    assert!(a.call(&sh[0], "POST", b"{}").is_err());
    assert!(a.call(&sh[0], "POST", b"{}").is_err());
    w.net.set_drop(&w.provs[0].0, None);
    drop(sh);
    drop(a);
    let b = w.file_payer();
    let sh = w.shards(&b);
    assert!(sh[0].snapshot().in_doubt >= 2);
    stream(&b, &sh[0], 1);
    let ad = events(&b, "meter_adopted");
    assert_eq!(ad.len(), 1);
    assert_eq!(ad[0]["gapAmsat"], (2 * PRICE).to_string());
    stream(&b, &sh[0], 3);
    stream(&b, &sh[1], 2);
    finish_and_check(&w, &b, &sh);
}

#[test]
fn restart_a_provider_claiming_more_than_the_calls_in_doubt_is_not_adopted() {
    let w = W::new();
    let a = w.file_payer();
    a.open().unwrap();
    let sh = w.shards(&a);
    stream(&a, &sh[0], 5);
    let url = sh[0].url.clone();
    drop(sh);
    drop(a);
    // the ledger says nothing is in doubt (all reserved seqs answered)
    let recs = ClientLedger::load(&FileRouteLedger::open(&w.file()).unwrap()).unwrap();
    let mut rec = recs.iter().find(|(k, _)| *k == format!("shard {url}")).unwrap().1.clone();
    rec["seq_hi"] = rec["seq"].clone();
    rec["answered"] = rec["seq"].clone();
    ClientLedger::save(&FileRouteLedger::open(&w.file()).unwrap(), &[(format!("shard {url}"), rec)]).unwrap();
    // meanwhile the provider's meter says 3 more calls (as if it had charged calls we never made)
    {
        let mut r = w.provs[0].1.routes().lock();
        let s = r.sessions.values_mut().next().unwrap();
        s.accrued_amsat += 3 * PRICE;
    }
    let b = w.file_payer();
    let sh = w.shards(&b);
    assert_eq!(sh[0].snapshot().in_doubt, 0);
    stream(&b, &sh[0], 1);
    assert!(events(&b, "meter_adopted").is_empty());
    let x = sh[0].snapshot();
    assert_eq!(x.accrued_amsat - x.seen_amsat, 3 * PRICE); // the mismatch stays visible
}

#[test]
fn restart_the_ledger_file_holds_no_payer_key_signature_or_refund() {
    let w = W::new();
    let a = w.file_payer();
    a.open().unwrap();
    let sh = w.shards(&a);
    stream(&a, &sh[0], 10);
    assert_eq!(a.lock(&sh[0]).unwrap().unwrap()["status"], "paid");
    let chan = a.chan().unwrap();
    let raw = std::fs::read_to_string(w.file()).unwrap();
    let refund = w.signer.sign_refund(&chan).unwrap();
    assert!(!raw.contains(&refund[..120]), "the signer's refund is not in the ledger");
    let sig = hex::encode(w.signer.sign_close(&chan).unwrap());
    assert!(!raw.contains(&sig));
    for (_, v) in ClientLedger::load(&FileRouteLedger::open(&w.file()).unwrap()).unwrap() {
        for k in ["secret_key", "payer_secret", "sig", "refund_hex", "best_sig"] {
            assert!(v.get(k).is_none(), "{k} in {v}");
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(w.file()).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let _ = Path::new("");
}

#[test]
fn restart_a_ledger_of_another_hub_is_refused() {
    let w = W::new();
    let a = w.file_payer();
    a.open().unwrap();
    drop(a);
    let c = w.chain.clone();
    let p = RoutePayer::new("http://other-hub.test", RoutePayerConfig::new(NET), w.signer.clone(), Arc::new(ChainWallet(w.chain.clone())),
                            Box::new(NetTransport(w.net.clone())), Box::new(move || Ok(c.height())));
    let e = p.with_ledger(Box::new(FileRouteLedger::open(&w.file()).unwrap())).err().unwrap();
    assert_eq!(e.code, "ledger_error");
}

#[test]
fn restart_twice_under_background_locking() {
    // the payer runs its per-window lock thread beside the calls, and is killed twice mid-stream
    let w = W::new();
    let mut pay = w.file_payer();
    pay.open().unwrap();
    for round in 0..3 {
        let sh = w.shards(&pay);
        pay.start(Duration::from_millis(40));
        for _ in 0..12 {
            for s in &sh {
                let r = pay.call(s, "POST", b"{}").unwrap();
                assert!(r.status == 200 || r.status == 402, "round {round}: {}", r.status);
            }
            std::thread::sleep(Duration::from_millis(15));
        }
        if round == 2 {
            pay.stop();
            finish_and_check(&w, &pay, &sh);
            break;
        }
        pay.stop(); // the lock thread is joined; the process "dies" with whatever is pending
        drop(sh);
        drop(pay);
        pay = w.file_payer();
        assert_eq!(pay.open().unwrap()["resumed"], true);
    }
}

#[test]
fn restart_the_ledger_file_compacts_as_it_grows() {
    let dir = TempDir::new();
    let path = dir.0.join("l.jsonl");
    let l = FileRouteLedger::open(&path).unwrap();
    let pad = "x".repeat(900);
    for i in 0..3000u64 {
        RouteLedger::save(&l, &[("shard a".to_string(), json!({"seq": i, "pad": pad})), ("book".to_string(), json!({"n": i}))]).unwrap();
    }
    let size = std::fs::metadata(&path).unwrap().len();
    assert!(size < 1 << 21, "{size} bytes after 3000 saves");
    let recs: Vec<(String, Value)> = RouteLedger::load(&l).unwrap();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs.iter().find(|r| r.0 == "shard a").unwrap().1["seq"], 2999);
    drop(l);
    let again = RouteLedger::load(&FileRouteLedger::open(&path).unwrap()).unwrap();
    assert_eq!(again, recs);
}
