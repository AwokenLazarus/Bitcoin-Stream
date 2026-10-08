//! AGP-064: hub routing safety, from the external review's H1 and H2, in process ([`MemChain`] +
//! [`MemNet`]). B1 has the same tests (`tests/security/test_agp064_hub_safety.py`).
//!
//! H1: a ch1 close while a lock is in flight (route() writes the lock and lets go of ch1's ledger
//! before it forwards) would close ch1 below the lock, and the hub would pay the provider for free.
//! H2: a lock written off after its ch2 pre-signature left was superseded by the client's next
//! lock, so a `t` the provider used later (a slow honest provider, or one that answers 400 and
//! keeps the pre-signature) paid the provider and not the hub.
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::adaptor;
use xbt402::adaptor::Sc;
use xbt402::channel::FeePayer;
use xbt402::funding::FundingPolicy;
use xbt402::http::HttpService;
use xbt402::hub::{HubConfig, RouteHub};
use xbt402::ledger::{ChannelState, Ledger};
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route::ROUTE_LOCK_PATH;
use xbt402::route_client::{RoutePayer, RoutePayerConfig, Shard};
use xbt402::route_seller::RouteOffer;
use xbt402::signer::LocalSigner;
use xbt402_interop::memnet::{ChainWallet, MemChain, MemNet, NetTransport};
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;

const NET: &str = "bip122:11111111111111111111111111111111";
const HUB: &str = "http://hub.test";

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("xbt-rs-hubsafe-{}", hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..8])));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A provider as the hub sees it over the net: its answer to `/lock` can be held at a gate (the
/// provider took the lock; the hub is still waiting: a lock in flight) or replaced by a 400 (the
/// provider keeps the pre-signature).
struct Wrapped {
    inner: Arc<Provider>,
    /// (armed, entered, open)
    gate: Mutex<(bool, bool, bool)>,
    cv: Condvar,
    refuse: AtomicBool,
}

impl Wrapped {
    fn arm(&self) {
        *self.gate.lock().unwrap() = (true, false, false);
    }

    fn wait_entered(&self) {
        let g = self.gate.lock().unwrap();
        let (g, t) = self.cv.wait_timeout_while(g, Duration::from_secs(10), |g| !g.1).unwrap();
        assert!(!t.timed_out() && g.1, "the hub never reached the provider");
    }

    fn open(&self) {
        let mut g = self.gate.lock().unwrap();
        g.2 = true;
        self.cv.notify_all();
    }
}

impl HttpService for Wrapped {
    fn body_limit(&self, path: &str) -> usize {
        HttpService::body_limit(&*self.inner, path)
    }

    fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str) -> HttpResponse {
        let r = HttpService::serve(&*self.inner, method, path, headers, body, url);
        if path == ROUTE_LOCK_PATH {
            let mut g = self.gate.lock().unwrap();
            if g.0 {
                g.1 = true;
                self.cv.notify_all();
                let (mut g, _) = self.cv.wait_timeout_while(g, Duration::from_secs(10), |g| !g.2).unwrap();
                g.0 = false;
            }
        }
        if path == ROUTE_LOCK_PATH && self.refuse.load(Ordering::SeqCst) && r.status == 200 {
            return HttpResponse::new(400, vec![("Content-Type".into(), "application/json".into())], br#"{"error":"refused","detail":"no"}"#.to_vec());
        }
        r
    }
}

fn provider(chain: &Arc<MemChain>, net: &Arc<MemNet>, dir: &TempDir, origin: &str) -> Arc<Wrapped> {
    let mut cfg = ProviderConfig::new(NET);
    cfg.close_margin = 36;
    cfg.policy = FundingPolicy { min_capacity: 20_000, min_expiry_blocks: 500, max_expiry_blocks: 8_640, close_margin: 36, ..FundingPolicy::default() };
    cfg.settle_multiple = 20;
    cfg.height_ttl = Duration::ZERO;
    cfg.settle_lock_multiple = 0;
    cfg.route_close_fee_payer = FeePayer::Payee;
    let name = origin.replace("http://", "").replace('.', "_");
    let ledger = Ledger::open(&dir.0.join(format!("prov-{name}.jsonl"))).unwrap();
    let p = Provider::new(chain.clone(), adaptor::random_secret(), cfg, ledger, Box::new(|_, _| 1000),
                          Box::new(|_, _, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], b"{\"ok\":1}".to_vec()))).unwrap();
    // 300 sat a call: a lock (10 calls) is well above ch1's dust floor, so each one raises ch1's state
    p.offer_route(RouteOffer { window: 0.3, lock_wait: 0.6, invoice_ttl: 8.0, ..RouteOffer::new("/v1/chunk", 300 * 10u128.pow(21)) });
    let w = Arc::new(Wrapped { inner: Arc::new(p), gate: Mutex::new((false, false, false)), cv: Condvar::new(), refuse: AtomicBool::new(false) });
    net.add(origin, w.clone());
    w
}

fn sk(n: u64) -> SecretKey {
    Sc::from_u64(n).secret().unwrap()
}

fn hub_cfg() -> HubConfig {
    HubConfig::from_json(&json!({"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500, "delta": 36,
                                 "reveal_timeout": 0.3, "ch2_capacity": 100000, "ch2_expiry_blocks": 1000, "settle_lock_multiple": 0, "refill_ahead_locks": 0,
                                 "close_margin": 36, "policy": {"min_capacity": 20000, "min_expiry_blocks": 500, "max_expiry_blocks": 8640}})).unwrap()
}

struct W {
    chain: Arc<MemChain>,
    net: Arc<MemNet>,
    hub: Arc<RouteHub>,
    provs: Vec<(String, Arc<Wrapped>)>,
    pay: Arc<RoutePayer>,
    shards: Vec<Arc<Shard>>,
    _dir: TempDir,
}

impl W {
    fn new(n: usize) -> Self {
        Self::with_ch2_blocks(&vec![None; n])
    }

    /// One provider per entry, its ch2 open for that many blocks (None: the hub's default).
    fn with_ch2_blocks(blocks: &[Option<u32>]) -> Self {
        let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
        let hub = Arc::new(RouteHub::new(chain.clone(), chain.clone(), Box::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())), sk(0x4B4B), NET,
                                         Some(&dir.0.join("hub")), hub_cfg()).unwrap());
        net.add(HUB, hub.clone());
        let mut provs = vec![];
        for (i, b) in blocks.iter().enumerate() {
            let origin = format!("http://p{i}.test");
            provs.push((origin.clone(), provider(&chain, &net, &dir, &origin)));
            hub.connect(&origin, None, *b).unwrap();
        }
        chain.confirm_all();
        hub.watch_tick();
        let mut cfg = RoutePayerConfig::new(NET);
        cfg.expiry_blocks = 8_000;
        let c = chain.clone();
        let pay = Arc::new(RoutePayer::new(HUB, cfg, Arc::new(LocalSigner::new()), Arc::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())),
                                           Box::new(move || Ok(c.height()))));
        pay.open().unwrap();
        let shards = provs.iter().map(|(o, _)| pay.shard(&format!("{o}/v1/chunk"), "POST").unwrap()).collect();
        Self { chain, net, hub, provs, pay, shards, _dir: dir }
    }

    fn st1(&self) -> ChannelState {
        self.hub.ch1_state(&self.pay.chan().unwrap()).unwrap()
    }

    /// p`i`'s side of its ch2 (the open one, else the last one).
    fn st2(&self, i: usize) -> ChannelState {
        let p = &self.provs[i].1.inner;
        let all: Vec<ChannelState> = p.channel_ids().iter().filter_map(|c| p.channel_state(c)).collect();
        all.iter().find(|s| s.closed_txid.is_empty()).cloned().unwrap_or_else(|| all.last().unwrap().clone())
    }

    fn routed(&self) -> u64 {
        self.st1().extra.get("routed_sat").and_then(Value::as_u64).unwrap_or(0)
    }

    fn stale1(&self) -> Vec<Value> {
        self.st1().extra.get("stale_locks").and_then(Value::as_array).cloned().unwrap_or_default()
    }

    fn lock(&self, i: usize) -> Value {
        stream(&self.pay, &self.shards[i], 10);
        self.pay.lock(&self.shards[i]).unwrap().unwrap()
    }

    fn paid(&self, i: usize) {
        let r = self.lock(i);
        assert_eq!(r["status"], "paid", "{r}");
    }

    /// p`i`'s next lock, held at p`i`'s `/lock` (in flight) on another thread.
    fn lock_in_flight(&self, i: usize) -> std::thread::JoinHandle<Value> {
        stream(&self.pay, &self.shards[i], 10);
        let prov = self.provs[i].1.clone();
        prov.arm();
        let (pay, sh) = (self.pay.clone(), self.shards[i].clone());
        let t = std::thread::spawn(move || pay.lock(&sh).unwrap().unwrap());
        prov.wait_entered();
        t
    }
}

fn stream(pay: &RoutePayer, sh: &Arc<Shard>, n: usize) {
    for _ in 0..n {
        let r = pay.call(sh, "POST", br#"{"tokens":1}"#).unwrap();
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    }
}

fn d_plus_f(lock: &Value) -> u64 {
    lock["d"].as_u64().unwrap() + lock["f"].as_u64().unwrap()
}

// --- H1 ------------------------------------------------------------------------------------------------

#[test]
fn h1_close_while_a_lock_is_in_flight_is_refused_either_order() {
    // lock first: the close arrives while the hub forwards, and is refused
    let w = W::new(1);
    w.paid(0);
    let before = w.st1().best_cum;
    let t = w.lock_in_flight(0);
    assert!(xbt402::json::truthy(w.st1().extra.get("route_lock")), "the lock is written before the forward");
    let refused = w.pay.close();
    assert!(w.st1().closed_txid.is_empty(), "ch1 closed at {before} below a lock in flight");
    assert_eq!(refused.unwrap_err().code, "lock_pending");
    w.provs[0].1.open();
    let r = t.join().unwrap();
    assert_eq!(r["status"], "paid", "{r}");
    let st1 = w.st1();
    assert!(st1.best_cum > before && st1.best_cum >= w.routed(), "ch1 holds the lock now");
    let closed = w.pay.close().unwrap();
    assert_eq!(py(&closed["cum"]), st1.best_cum, "{closed}");

    // close first: the lock is refused, and nothing reaches the provider
    let w = W::new(1);
    w.paid(0);
    stream(&w.pay, &w.shards[0], 10);
    w.pay.close().unwrap();
    let (n, best2) = (w.net.count(ROUTE_LOCK_PATH), w.st2(0).best_cum);
    let r = w.pay.lock(&w.shards[0]).unwrap().unwrap();
    assert_eq!((r["status"].as_str(), r["error"].as_str()), (Some("refused"), Some("channel_closing")), "{r}");
    assert_eq!((w.net.count(ROUTE_LOCK_PATH), w.st2(0).best_cum), (n, best2));
}

#[test]
fn h1_a_lock_the_hub_never_forwarded_does_not_keep_ch1_open() {
    // a hub that wrote its ch1 lock and never forwarded it (here the withholding hook; in life a stop
    // between the two write-aheads): nothing can complete it, so the close drops it and goes ahead
    let w = W::new(1);
    w.paid(0);
    let best = w.st1().best_cum;
    w.hub.set_withhold("all");
    stream(&w.pay, &w.shards[0], 10);
    let n = w.net.count(ROUTE_LOCK_PATH);
    assert_eq!(w.pay.lock(&w.shards[0]).unwrap().unwrap()["status"], "pending");
    assert!(xbt402::json::truthy(w.st1().extra.get("route_lock")));
    assert_eq!(w.net.count(ROUTE_LOCK_PATH), n, "the lock never left the hub");
    w.hub.set_withhold("");
    let closed = w.pay.close().unwrap();
    assert_eq!(py(&closed["cum"]), best, "{closed}");
    assert!(w.hub.events.lock().unwrap().iter().any(|e| e["event"] == "orphan_lock_dropped"));
}

fn py(v: &Value) -> u64 {
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())).unwrap()
}

#[test]
fn h1_a_lock_completed_after_ch1_closed_below_it_is_not_counted() {
    // the operator's close_now does not wait: the lock still completes (the provider is paid), but
    // the hub does not record sats that are not on ch1
    let w = W::new(1);
    w.paid(0);
    let t = w.lock_in_flight(0);
    let (routed0, n0) = (w.routed(), w.hub.stats.lock().unwrap().routed);
    w.hub.inbound.close_now(&w.pay.chan().unwrap()).unwrap();
    w.provs[0].1.open();
    t.join().unwrap();
    assert_eq!(w.routed(), routed0, "a lock above the ch1 close was added to routed_sat");
    assert_eq!(w.hub.stats.lock().unwrap().routed, n0, "a lock above the ch1 close was counted as routed");
}

#[test]
fn h1_the_margin_close_lets_a_lock_in_flight_finish() {
    let w = W::new(1);
    w.paid(0);
    let t = w.lock_in_flight(0);
    let exp = w.st1().params.expiry;
    w.chain.set_height(exp - 36); // inside ch1's close margin
    assert!(w.hub.inbound.close_due().unwrap().is_empty(), "ch1 closed at its margin below a lock in flight");
    w.provs[0].1.open();
    assert_eq!(t.join().unwrap()["status"], "paid");
    assert_eq!(w.hub.inbound.close_due().unwrap().len(), 1);
    let st1 = w.st1();
    assert!(!st1.closed_txid.is_empty() && st1.best_cum >= w.routed(), "closed with the lock");
    // a lock in flight never holds the margin close past half the margin
    let w = W::new(1);
    w.paid(0);
    let t = w.lock_in_flight(0);
    w.chain.set_height(w.st1().params.expiry - 18);
    assert_eq!(w.hub.inbound.close_due().unwrap().len(), 1);
    w.provs[0].1.open();
    t.join().unwrap();
}

// --- H2 ------------------------------------------------------------------------------------------------

#[test]
fn h2_a_slow_provider_stays_in_the_base_and_a_later_route_sits_above_it() {
    // p0 completes the lock but its answer is lost: the hub writes it off at revealTimeout. The client
    // routes again (to p1); then p0 closes ch2 with t. The hub must have collected both.
    let w = W::new(2);
    let routed0 = w.routed();
    w.net.set_drop(&w.provs[0].0, Some(Box::new(|_, p| p == ROUTE_LOCK_PATH)));
    let r = w.lock(0);
    assert_eq!((r["status"].as_str(), r["error"].as_str()), (Some("refused"), Some("route_failed")), "{r}");
    let stale = w.stale1();
    assert_eq!(stale.len(), 1);
    let first = d_plus_f(&stale[0]);
    assert_eq!(w.pay.counters().0, w.routed(), "the client adopts the hold");
    let r = w.lock(1);
    assert_eq!(r["status"], "paid", "{r}");
    let second = r["amount"].as_u64().unwrap() + r["fee"].as_u64().unwrap();
    assert_eq!(w.routed(), routed0 + first + second);
    let best = w.st1().best_cum;
    assert!(best >= routed0 + first + second, "ch1's state {best} does not cover both locks");
    // p0 closes with the lock it completed: the hub reads t, and the base already counted it
    let st2 = w.st2(0);
    assert!(st2.best_cum > 0);
    w.provs[0].1.inner.close_now(&st2.params.channel_id()).unwrap();
    let acts = w.hub.watch_tick();
    assert!(acts.iter().any(|a| a["event"] == "secret_from_close"), "{acts:?}");
    assert!(w.stale1().is_empty());
    w.chain.confirm_all();
    w.hub.watch_tick();
    assert_eq!(w.routed(), routed0 + first + second, "nothing given back for a lock that was paid");
    assert_eq!(w.st1().best_cum, best);
}

#[test]
fn h2_a_refused_lock_stays_in_the_base_and_blocks_routing_and_rollover() {
    // p0 takes the lock, keeps the pre-signature and answers 400: written off with no block before.
    // The client reroutes the same amount to p1, and p0 closes ch2 later with t.
    let w = W::new(2);
    let routed0 = w.routed();
    w.provs[0].1.refuse.store(true, Ordering::SeqCst);
    let r = w.lock(0);
    assert_eq!((r["status"].as_str(), r["error"].as_str()), (Some("refused"), Some("route_failed")), "{r}");
    let first = d_plus_f(&w.stale1()[0]);
    assert_eq!(w.pay.counters().0, routed0 + first, "the client adopts the hold");
    // no lock over that ch2, and no rollover of it, until it resolves
    w.provs[0].1.refuse.store(false, Ordering::SeqCst);
    let again = w.lock(0);
    assert_eq!((again["status"].as_str(), again["error"].as_str()), (Some("refused"), Some("route_blocked")), "{again}");
    let oc = w.hub.out_channels()[&w.provs[0].0].clone();
    assert_eq!(oc.stale.len(), 1);
    assert_eq!(w.hub.rollover(&oc).unwrap_err().code, "lock_pending");
    let acts = w.hub.watch_tick();
    assert!(!acts.iter().any(|a| a["event"] == "ch2_rollover"), "{acts:?}");
    // the reroute is quoted above the held lock
    let r = w.lock(1);
    assert_eq!(r["status"], "paid", "{r}");
    let second = r["amount"].as_u64().unwrap() + r["fee"].as_u64().unwrap();
    assert!(w.st1().best_cum >= routed0 + first + second);
    w.provs[0].1.inner.close_now(&w.st2(0).params.channel_id()).unwrap();
    let acts = w.hub.watch_tick();
    assert!(acts.iter().any(|a| a["event"] == "secret_from_close"), "{acts:?}");
    assert_eq!(w.routed(), routed0 + first + second);
}

#[test]
fn h2_a_refunded_ch2_gives_the_unpaid_hold_back() {
    // the lock is written off, ch2 is never closed, the hub's refund confirms at expiry: the lock was
    // not paid, so its hold leaves the base and the client resyncs onto it (its next locks use the
    // dust floor of what it signed ahead)
    let w = W::with_ch2_blocks(&[None, Some(3_000)]); // p1's ch2 outlives p0's refund
    let routed0 = w.routed();
    w.net.set_drop(&w.provs[0].0, Some(Box::new(|_, p| p == ROUTE_LOCK_PATH)));
    assert_eq!(w.lock(0)["error"], "route_failed");
    let stale = w.stale1();
    let (lid, first) = (stale[0]["lockId"].as_str().unwrap().to_string(), d_plus_f(&stale[0]));
    let signed = w.st1().best_cum;
    let oc = w.hub.out_channels()[&w.provs[0].0].clone();
    w.chain.set_height(oc.params.expiry + 10);
    w.hub.watch_tick();
    w.chain.confirm_all();
    let acts = w.hub.watch_tick();
    assert!(acts.iter().any(|a| a["event"] == "ch2_refund_confirmed"), "{acts:?}");
    assert!(acts.iter().any(|a| a["event"] == "lock_released" && a["lockId"] == lid.as_str() && a["held"] == true), "{acts:?}");
    assert_eq!(w.routed(), routed0, "the unpaid hold left the base");
    assert!(w.stale1().is_empty());
    assert_eq!(w.st1().extra["released"], json!([lid]));
    assert_eq!(w.pay.counters().0, routed0 + first, "the client still counts it");
    // the client's next lock is refused for its amount, with the release in the view: it adopts it
    stream(&w.pay, &w.shards[1], 10);
    let r = w.pay.lock(&w.shards[1]).unwrap().unwrap();
    assert_eq!(r["status"], "resynced", "{r}");
    assert_eq!(w.pay.counters().0, routed0);
    assert_eq!(w.pay.counters().3, signed);
    let r = w.pay.lock(&w.shards[1]).unwrap().unwrap();
    assert_eq!(r["status"], "paid", "{r}");
    assert_eq!(w.pay.counters().0, w.routed());
}

#[test]
fn h2_a_void_whose_pre_signature_never_left_holds_nothing() {
    // ch2 exhausted before the pre-signature: nothing can complete the lock, so it is dropped, not held
    let w = W::new(1);
    w.paid(0);
    let routed0 = w.routed();
    w.hub.with_out(|b| {
        let c = b.chans.values_mut().next().unwrap();
        c.signed = c.params.max_amount();
        c.routed = c.params.max_amount();
    });
    let r = w.lock(0);
    assert_eq!(r["error"], "route_failed", "{r}");
    assert!(w.stale1().is_empty());
    assert_eq!((w.routed(), w.pay.counters().0), (routed0, routed0));
    assert!(w.pay.close().is_ok(), "nothing unresolved keeps ch1 open");
}
