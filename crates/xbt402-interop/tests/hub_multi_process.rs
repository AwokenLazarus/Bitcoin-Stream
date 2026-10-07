//! AGP-056 (a port of B1 `tests/security/test_agp056_multi_process.py`), in process: [`MemChain`] +
//! [`MemNet`]. Routed locks at multi-process operators, rollovers a hub's own node has not seen yet,
//! and rollovers per lock:
//!   1 ch2 identity: one operator key, several provider processes (separate ledgers and origins).
//!     Each process gets its own ch2 and is paid on it, through rollovers (AGP-044's one ch2 per payTo
//!     sent the second process's locks to the first: unknown_session, route_failed); one key is
//!     bounded (`ch2_max_per_pay_to`); a refusal says what is wrong;
//!   2 rollover relay: the provider broadcasts the rollover on ITS node; a hub whose node has not
//!     received it yet must not call it vanished (cmp R14: every child was blocked until the next block);
//!   3 settle floor: with locks larger than settleMultiple × closeFee the ch2 rolled over on every
//!     lock; the hub now waits for `settle_lock_multiple` × the largest lock, and the provider's
//!     zero-conf cap follows;
//!   4 the refusal detail reaches the client.
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::adaptor::Sc;
use xbt402::channel::FeePayer;
use xbt402::funding::{ChainBackend, FundingPolicy};
use xbt402::http::HttpService;
use xbt402::hub::{HubConfig, OutChannel, RouteHub, ROLLOVER_GONE};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route::*;
use xbt402::route_client::{RoutePayer, RoutePayerConfig, Shard};
use xbt402::route_seller::RouteOffer;
use xbt402::signer::LocalSigner;
use xbt402_interop::memnet::{ChainWallet, LagChain, MemChain, MemNet, NetTransport};
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;

const NET: &str = "bip122:11111111111111111111111111111111";
const HUB: &str = "http://hub.test";
const KEY: u64 = 0x5151;
/// 50 calls at 40 sat.
const LOCK: u64 = 2_000;

fn sk(n: u64) -> SecretKey {
    Sc::from_u64(n).secret().unwrap()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("xbt-rs-agp056-{}", hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..8])));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What a test changes: hub config keys, the providers' settle floor, price and explicit zero-conf
/// cap, whether the hub's node may lag, whether the hub connects every origin.
struct Kw {
    hub: Value,
    k: u64,
    amsat: u128,
    zc_max: Option<u64>,
    lagging: bool,
    connect: bool,
}

impl Default for Kw {
    fn default() -> Self {
        Self { hub: json!({}), k: 0, amsat: 40 * AMSAT_PER_SAT, zc_max: None, lagging: false, connect: true }
    }
}

/// One hub, one client, `n` provider processes on ONE operator key: each its own ledger and origin.
struct W {
    chain: Arc<MemChain>,
    view: Arc<LagChain>,
    net: Arc<MemNet>,
    hub: Arc<RouteHub>,
    origins: Vec<String>,
    provs: Vec<Arc<Provider>>,
    pay: Arc<RoutePayer>,
    sh: Vec<Arc<Shard>>,
    dir: TempDir,
}

fn hub_cfg(extra: &Value) -> HubConfig {
    // settle_lock_multiple 0 unless a test asks: the floor is tested on its own
    let mut c = json!({"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500, "delta": 36,
                       "reveal_timeout": 1.0, "ch2_capacity": 100000, "ch2_expiry_blocks": 1000, "close_margin": 36, "settle_lock_multiple": 0, "refill_ahead_locks": 0,
                       "policy": {"min_capacity": 20000, "min_expiry_blocks": 500, "max_expiry_blocks": 8640}});
    for (k, v) in extra.as_object().unwrap() {
        c[k] = v.clone();
    }
    HubConfig::from_json(&c).unwrap()
}

fn new_hub(w_chain: &Arc<MemChain>, view: &Arc<LagChain>, lagging: bool, net: &Arc<MemNet>, dir: &TempDir, extra: &Value) -> Arc<RouteHub> {
    let wallet = Box::new(ChainWallet(w_chain.clone()));
    let http = Box::new(NetTransport(net.clone()));
    let h = if lagging {
        RouteHub::new(view.clone(), view.clone(), wallet, http, sk(0x4B4B), NET, Some(&dir.0.join("hub")), hub_cfg(extra))
    } else {
        RouteHub::new(w_chain.clone(), w_chain.clone(), wallet, http, sk(0x4B4B), NET, Some(&dir.0.join("hub")), hub_cfg(extra))
    };
    Arc::new(h.unwrap())
}

fn world(n: usize, kw: Kw) -> W {
    let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
    let view = LagChain::new(chain.clone());
    let hub = new_hub(&chain, &view, kw.lagging, &net, &dir, &kw.hub);
    net.add(HUB, hub.clone());
    let origins: Vec<String> = (0..n).map(|i| format!("http://m{i}.test")).collect();
    let mut provs = vec![];
    for (i, o) in origins.iter().enumerate() {
        let mut cfg = ProviderConfig::new(NET);
        cfg.close_margin = 36;
        cfg.policy = FundingPolicy { min_capacity: 20_000, min_expiry_blocks: 500, max_expiry_blocks: 8_640, close_margin: 36, ..FundingPolicy::default() };
        cfg.settle_multiple = 2;
        cfg.height_ttl = Duration::ZERO;
        cfg.route_close_fee_payer = FeePayer::Payee;
        cfg.rollover_zero_conf_max = kw.zc_max;
        cfg.settle_lock_multiple = kw.k;
        let ledger = Ledger::open(&dir.0.join(format!("prov-{i}.jsonl"))).unwrap();
        let p = Arc::new(Provider::new(chain.clone(), sk(KEY), cfg, ledger, Box::new(|_, _| 1000),
                                       Box::new(|_, _, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], b"{\"ok\":1}".to_vec()))).unwrap());
        p.offer_route(RouteOffer { window: 0.3, lock_wait: 0.6, invoice_ttl: 8.0, ..RouteOffer::new("/v1/chunk", kw.amsat) });
        net.add(o, p.clone());
        provs.push(p);
    }
    if kw.connect {
        for o in &origins {
            hub.connect(o, None, None).unwrap();
        }
        chain.confirm_all();
        hub.watch_tick();
    }
    let mut pc = RoutePayerConfig::new(NET);
    pc.expiry_blocks = 8_000;
    pc.capacity = 2_000_000;
    let c = chain.clone();
    let pay = Arc::new(RoutePayer::new(HUB, pc, Arc::new(LocalSigner::new()), Arc::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())),
                                       Box::new(move || Ok(c.height()))));
    pay.open().unwrap();
    let sh = origins.iter().map(|o| pay.shard(&format!("{o}/v1/chunk"), "POST").unwrap()).collect();
    W { chain, view, net, hub, origins, provs, pay, sh, dir }
}

impl W {
    fn oc(&self, i: usize) -> OutChannel {
        self.hub.out_channels()[&self.origins[i]].clone()
    }

    fn stream(&self, i: usize, calls: usize) {
        for _ in 0..calls {
            let r = self.pay.call(&self.sh[i], "POST", br#"{"tokens":1}"#).unwrap();
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        }
    }

    fn lock_n(&self, i: usize, calls: usize) -> Value {
        self.stream(i, calls);
        self.pay.lock(&self.sh[i]).unwrap().unwrap()
    }

    fn lock(&self, i: usize) -> Value {
        self.lock_n(i, 50)
    }

    fn block(&self) -> Vec<Value> {
        self.chain.mine(1);
        for p in &self.provs {
            p.close_due().unwrap();
        }
        self.hub.watch_tick()
    }

    fn events(&self, kind: &str) -> Vec<Value> {
        self.hub.events.lock().unwrap().iter().filter(|e| e["event"] == kind).cloned().collect()
    }

    fn rollovers(&self, i: Option<usize>) -> Vec<Value> {
        self.events("ch2_rollover").into_iter().filter(|e| match i {
            Some(i) => e["provider"] == self.origins[i].as_str(),
            None => true,
        }).collect()
    }

    fn locks_to(&self, i: usize) -> usize {
        self.net.calls.lock().unwrap().iter().filter(|c| c.1 == self.origins[i] && c.2 == ROUTE_LOCK_PATH).count()
    }

    fn pay_refused(&self) -> usize {
        self.pay.stats().refused.len()
    }

    fn hub_refused(&self) -> Vec<(String, u64)> {
        self.hub.stats.lock().unwrap().refused.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }

    fn providers(&self) -> Value {
        self.hub.routing_extra().unwrap()["providers"].clone()
    }
}

fn evs(acts: &[Value]) -> Vec<String> {
    acts.iter().map(|a| a["event"].as_str().unwrap_or("").to_string()).collect()
}

fn has(acts: &[Value], kind: &str) -> bool {
    acts.iter().any(|a| a["event"] == kind)
}

// --- 1 ch2 identity ---------------------------------------------------------------------------------------

/// The repro of cmp's merchants A0..A3: locks to every process, rollovers under load, no refusal.
#[test]
fn each_process_is_paid_on_its_own_ch2_through_rollovers() {
    let w = world(3, Kw::default());
    let chans: std::collections::HashSet<String> = (0..3).map(|i| w.oc(i).params.channel_id()).collect();
    assert_eq!(chans.len(), 3);
    assert_eq!(w.providers(), json!(w.origins));
    let mut paid = [0u64; 3];
    for _ in 0..4 {
        for (i, p) in paid.iter_mut().enumerate() {
            // on the confirmed ch2: at the threshold
            let r = w.lock(i);
            assert_eq!(r["status"], "paid", "{r}");
            *p += r["amount"].as_u64().unwrap();
        }
        w.hub.watch_tick(); // every ch2 rolls over; the children open unconfirmed
        for (i, p) in paid.iter_mut().enumerate() {
            // on the unconfirmed child, no block yet
            let r = w.lock(i);
            assert_eq!(r["status"], "paid", "{r}");
            *p += r["amount"].as_u64().unwrap();
        }
        w.block(); // the children confirm and roll over in turn
        w.block();
    }
    assert_eq!((w.pay_refused(), w.hub_refused()), (0, vec![]));
    for (i, want) in paid.into_iter().enumerate() {
        assert_eq!(w.rollovers(Some(i)).len(), 8, "{i}");
        let paid_sat = w.provs[i].routes().lock().sessions[&w.sh[i].session].paid_sat;
        assert_eq!((paid_sat, w.sh[i].snapshot().locked_sat), (want, want));
        // every ch2 of this origin, the rolled ones included, is in this process's ledger and no other
        let mut mine: Vec<String> = w.hub.archived().iter().filter(|r| r["origin"] == w.origins[i].as_str())
            .map(|r| OutChannel::from_json(r).unwrap().params.channel_id()).collect();
        mine.push(w.oc(i).params.channel_id());
        for (q, prov) in w.provs.iter().enumerate() {
            for c in &mine {
                assert_eq!(prov.channel_state(c).is_some(), q == i, "ch2 {c} of {i} at {q}");
            }
        }
    }
}

#[test]
fn a_lock_is_forwarded_to_the_origin_the_client_named() {
    let w = world(2, Kw::default());
    for i in [1, 1, 0] {
        assert_eq!(w.lock_n(i, 5)["status"], "paid");
    }
    assert_eq!((w.locks_to(0), w.locks_to(1)), (1, 2));
    assert_eq!((w.oc(0).routed, w.oc(1).routed), (w.sh[0].snapshot().locked_sat, w.sh[1].snapshot().locked_sat));
}

#[test]
fn a_rollover_keeps_each_origin_on_its_own_next_ch2() {
    let w = world(2, Kw::default());
    let before = [w.oc(0).params.channel_id(), w.oc(1).params.channel_id()];
    assert_eq!(w.lock(1)["status"], "paid");
    w.hub.watch_tick();
    let rolls: Vec<Value> = w.rollovers(None).iter().map(|e| e["provider"].clone()).collect();
    assert_eq!(rolls, vec![json!(w.origins[1])]);
    assert_eq!(w.oc(0).params.channel_id(), before[0]);
    let child = w.oc(1);
    assert_eq!((child.origin.as_str(), child.rolled_from.as_str(), child.state.as_str()), (w.origins[1].as_str(), before[1].as_str(), "open"));
    assert!(w.provs[1].channel_state(&child.params.channel_id()).is_some());
    assert!(w.provs[0].channel_state(&child.params.channel_id()).is_none());
    for i in [0, 1] {
        assert_eq!(w.lock(i)["status"], "paid");
    }
}

/// An AGP-044 book: b was recorded under a's payTo and routed over a's ch2. Now its locks are refused
/// at the hub, with the cause, before anything is signed on a's ch2; connect funds b's own.
#[test]
fn an_origin_without_its_own_ch2_is_refused_with_the_reason() {
    let w = world(2, Kw { connect: false, ..Kw::default() });
    let (a, b) = (w.origins[0].clone(), w.origins[1].clone());
    w.hub.connect(&a, None, None).unwrap();
    w.chain.confirm_all();
    w.hub.watch_tick();
    let pay_to = w.oc(0).pay_to.to_lowercase();
    w.hub.with_out(|bk| {
        bk.origins.insert(b.clone(), pay_to.clone());
    });
    assert_eq!(w.providers(), json!([a]));
    let r = w.lock_n(1, 5);
    assert_eq!((r["status"].as_str(), r["error"].as_str()), (Some("refused"), Some("route_blocked")), "{r}");
    assert!(r["detail"].as_str().unwrap().contains(&format!("its payTo has a ch2 at {a}, another provider process")), "{r}");
    assert_eq!((w.locks_to(0), w.oc(0).pending.len(), w.oc(0).stale.len()), (0, 0, 0));
    let nb = w.hub.connect(&b, None, None).unwrap();
    assert_eq!(nb.origin, b);
    assert_eq!(w.hub.with_out(|bk| bk.live_keys(&pay_to).len()), 2);
    w.chain.confirm_all();
    w.hub.watch_tick();
    w.stream(1, 1);
    assert_eq!(w.lock_n(1, 5)["status"], "paid");
}

#[test]
fn one_key_is_bounded_and_the_refusal_is_clear() {
    let w = world(3, Kw { connect: false, hub: json!({"ch2_max_per_pay_to": 2}), ..Kw::default() });
    let (a, b, c) = (w.origins[0].clone(), w.origins[1].clone(), w.origins[2].clone());
    w.hub.connect(&a, None, None).unwrap();
    w.hub.connect(&b, None, None).unwrap();
    let e = w.hub.connect(&c, None, None).unwrap_err();
    assert_eq!(e.code, "pay_to_limit");
    assert!(e.to_string().contains("ch2_max_per_pay_to 2"), "{e}");
    assert_eq!(w.hub.committed_sat(), 200_000);
    assert!(!w.hub.out_channels().contains_key(&c)); // nothing written ahead, nothing funded
    // a closed one frees its place
    w.chain.confirm_all();
    w.hub.watch_tick();
    assert_eq!(w.lock_n(0, 40)["status"], "paid");
    w.hub.close_ch2(&w.oc(0), false).unwrap();
    assert_eq!(w.hub.connect(&c, None, None).unwrap().origin, c);
    assert_eq!(HubConfig::default().ch2_max_per_pay_to, 8);
    assert_eq!(HubConfig::from_json(&json!({"ch2_max_per_pay_to": 0})).unwrap().ch2_max_per_pay_to, 0);
}

#[test]
fn the_liquidity_cap_counts_every_process() {
    let w = world(2, Kw { connect: false, hub: json!({"liquidity_cap_sat": 150000}), ..Kw::default() });
    w.hub.connect(&w.origins[0], None, None).unwrap();
    assert_eq!(w.hub.connect(&w.origins[1], None, None).unwrap_err().code, "liquidity_cap");
}

#[test]
fn the_book_survives_a_restart_per_origin() {
    let w = world(2, Kw::default());
    let h2 = new_hub(&w.chain, &w.view, false, &w.net, &w.dir, &json!({}));
    assert_eq!(h2.routing_extra().unwrap()["providers"], json!(w.origins));
    assert_eq!(h2.connect(&w.origins[1], None, None).unwrap().origin, w.origins[1]);
    assert_eq!(h2.connect(&w.origins[0], None, None).unwrap().origin, w.origins[0]);
    assert_eq!(h2.committed_sat(), 200_000);
}

// --- 2 rollover relay ---------------------------------------------------------------------------------------

/// One lock at the threshold, then the hub's node falls behind and the watcher rolls the ch2 over.
fn lagging_roll(hub: Value) -> (W, OutChannel) {
    let w = world(1, Kw { lagging: true, hub, ..Kw::default() });
    assert_eq!(w.lock(0)["status"], "paid");
    w.view.lag(true); // from here the hub's node is behind
    assert!(has(&w.hub.watch_tick(), "ch2_rollover"));
    let child = w.oc(0);
    (w, child)
}

#[test]
fn a_rollover_the_hubs_node_has_not_seen_yet_is_not_vanished() {
    let (w, child) = lagging_roll(json!({}));
    let txid = child.params.funding_txid();
    assert!(w.view.get_tx_out(&txid, 1, true).unwrap().is_none()); // the hub's node: not yet
    assert!(w.chain.get_tx_out(&txid, 1, true).unwrap().is_some()); // the provider's: in its mempool
    assert_eq!((child.state.as_str(), child.fund_seen, child.zero_conf.is_empty()), ("open", false, false));
    for _ in 0..3 {
        let acts = w.hub.watch_tick();
        assert!(!evs(&acts).iter().any(|e| e.starts_with("ch2_rollover")), "{acts:?}");
    }
    assert_eq!((w.oc(0).state.as_str(), w.oc(0).blocked.as_str()), ("open", ""));
    assert_eq!(w.lock(0)["status"], "paid"); // routing never paused
    assert_eq!(w.pay_refused(), 0);
    w.view.lag(false); // relayed
    w.hub.watch_tick();
    assert!(w.oc(0).fund_seen);
    // seen and then gone is a vanished rollover, grace or not (AGP-053)
    w.chain.evict(&txid);
    assert!(has(&w.hub.watch_tick(), "ch2_rollover_vanished"));
    assert_eq!(w.oc(0).blocked, ROLLOVER_GONE);
}

#[test]
fn a_rollover_never_relayed_is_blocked_after_the_grace() {
    let (w, _) = lagging_roll(json!({"rollover_relay_grace": 0.3}));
    assert!(!has(&w.hub.watch_tick(), "ch2_rollover_vanished"));
    assert_eq!(w.oc(0).blocked, "");
    std::thread::sleep(Duration::from_millis(350));
    assert!(has(&w.hub.watch_tick(), "ch2_rollover_vanished"));
    assert_eq!(w.oc(0).blocked, ROLLOVER_GONE);
    let r = w.lock(0);
    assert_eq!((r["error"].as_str(), r["detail"].as_str()), (Some("route_blocked"), Some(ROLLOVER_GONE)), "{r}");
    w.view.lag(false); // it arrives after all
    assert!(has(&w.hub.watch_tick(), "ch2_rollover_back"));
    assert_eq!((w.oc(0).blocked.as_str(), w.oc(0).fund_seen), ("", true));
}

#[test]
fn a_hub_on_the_providers_node_sees_it_at_once() {
    let w = world(1, Kw::default());
    assert_eq!(w.lock(0)["status"], "paid");
    w.hub.watch_tick();
    let child = w.oc(0);
    assert!(child.fund_seen && child.rolled_at > 0.0);
    w.chain.evict(&child.params.funding_txid()); // no grace for a rollover it saw
    assert!(has(&w.hub.watch_tick(), "ch2_rollover_vanished"));
}

#[test]
fn a_record_without_rolled_at_gets_no_grace() {
    let (w, _) = lagging_roll(json!({}));
    let o = w.origins[0].clone();
    w.hub.with_out(|b| b.chans.get_mut(&o).unwrap().rolled_at = 0.0); // a book written before AGP-056
    assert!(has(&w.hub.watch_tick(), "ch2_rollover_vanished"));
}

// --- 3 settle floor -------------------------------------------------------------------------------------------

fn floor(k: u64, hub: Value, amsat: u128, zc_max: Option<u64>) -> W {
    let mut h = hub;
    h["settle_lock_multiple"] = k.into();
    world(1, Kw { hub: h, k, amsat, zc_max, ..Kw::default() })
}

fn run_locks(k: u64, n: usize) -> W {
    let w = floor(k, json!({}), 40 * AMSAT_PER_SAT, None);
    for _ in 0..n {
        let r = w.lock(0);
        assert_eq!(r["status"], "paid", "{r}");
        w.block(); // confirm, then roll over if due
    }
    w
}

#[test]
fn rollovers_per_lock_fall_from_one_to_one_in_k() {
    // the provider settles at 2 × 600 = 1,200 sat net; every lock is 2,000 sat
    let w0 = run_locks(0, 12);
    assert_eq!(w0.rollovers(None).len(), 12); // before: a rollover on every lock
    let w4 = run_locks(4, 12);
    assert_eq!(w4.rollovers(None).len(), 12 / 4);
    assert!(w4.rollovers(None).iter().all(|e| e["amount"] == 4 * LOCK));
    assert_eq!(w4.oc(0).max_lock, LOCK); // carried over the rollovers
    assert_eq!((w0.pay_refused(), w4.pay_refused()), (0, 0));
    assert_eq!((HubConfig::default().settle_lock_multiple, HubConfig::default().settle_idle), (4, 600.0));
}

#[test]
fn never_below_the_providers_threshold() {
    // locks of 200 sat: 4 × 200 is under the provider's 1,200 net, which stays the least it co-signs
    let w = floor(4, json!({}), 40 * AMSAT_PER_SAT, None);
    for i in 0..9 {
        assert_eq!(w.lock_n(0, 5)["status"], "paid");
        w.block();
        assert_eq!(w.rollovers(None).len(), usize::from(i >= 8), "{i}"); // 9 × 200 = 1,800 − 600 = 1,200 net
    }
    assert_eq!(w.hub_refused(), vec![]);
}

#[test]
fn an_idle_ch2_rolls_over_at_the_providers_threshold() {
    let w = floor(4, json!({"settle_idle": 0.3}), 40 * AMSAT_PER_SAT, None);
    assert_eq!(w.lock(0)["status"], "paid");
    w.block();
    assert!(w.rollovers(None).is_empty()); // due at the provider's threshold, held by the floor
    std::thread::sleep(Duration::from_millis(350));
    w.block();
    let amounts: Vec<Value> = w.rollovers(None).iter().map(|e| e["amount"].clone()).collect();
    assert_eq!(amounts, vec![json!(LOCK)]);
}

#[test]
fn never_so_late_that_the_next_lock_does_not_fit() {
    // capacity 110,000, locks of 30,000: 4 × 30,000 does not fit. After three locks a fourth would not
    // fit either, so the ch2 is due at 90,000. The 20,000 left is the provider's minimum capacity, but
    // could not take one more lock: the ch2 is closed and refilled, never left exhausted
    let w = floor(4, json!({"max_lock_sat": 50000, "ch2_capacity": 110000}), 400 * AMSAT_PER_SAT, None);
    for i in 0..3 {
        assert_eq!(w.lock_n(0, 75)["status"], "paid");
        let acts: Vec<String> = evs(&w.block()).into_iter().filter(|e| e == "ch2_rollover" || e == "ch2_close").collect();
        assert_eq!(acts, if i == 2 { vec!["ch2_close".to_string()] } else { vec![] }, "{i}");
    }
    let new = w.oc(0);
    assert_eq!((new.state.as_str(), new.params.capacity, new.rolled_from.as_str()), ("funded", 110_000, ""));
    w.block();
    assert_eq!(w.lock_n(0, 75)["status"], "paid");
    assert_eq!((w.pay_refused(), w.hub_refused()), (0, vec![]));
}

#[test]
fn a_child_too_small_for_the_next_lock_is_refilled_not_rolled() {
    // capacity 100,000, locks of 20,000, k = 2: due at 40,000 (child 60,000), again at 40,000 (child
    // 20,000: one lock fits, a rollover), and then nothing fits: close and refill
    let w = floor(2, json!({}), 400 * AMSAT_PER_SAT, None);
    let mut seen = vec![];
    for _ in 0..6 {
        assert_eq!(w.lock(0)["status"], "paid");
        seen.extend(evs(&w.block()).into_iter().filter(|e| e == "ch2_rollover" || e == "ch2_close"));
        w.block();
    }
    assert_eq!(seen, vec!["ch2_rollover", "ch2_rollover", "ch2_close"]);
    assert_eq!((w.pay_refused(), w.hub_refused()), (0, vec![]));
}

#[test]
fn the_providers_zero_conf_cap_follows_the_largest_lock() {
    // cmp R14: cap 2 × 20 × 600 = 24,000 against locks of 7k-36k: the first lock on an unconfirmed
    // child was refused. Default cap: at least 2 × 4 × the largest lock; an explicit one is kept
    let w = floor(4, json!({}), 40 * AMSAT_PER_SAT, None);
    for _ in 0..4 {
        assert_eq!(w.lock(0)["status"], "paid");
    }
    w.hub.watch_tick();
    let child = w.oc(0);
    assert_eq!((child.state.as_str(), child.zero_conf["maxCum"].clone()), ("open", json!(2 * 4 * LOCK)));
    for _ in 0..4 {
        assert_eq!(w.lock(0)["status"], "paid"); // 8,000 sat on the unconfirmed child
    }
    let st = w.provs[0].channel_state(&child.params.channel_id()).unwrap();
    assert_eq!((st.extra["max_lock"].clone(), st.extra["zero_conf"]["maxCum"].clone()), (json!(LOCK), json!(16_000)));
    let w2 = floor(4, json!({}), 40 * AMSAT_PER_SAT, Some(3_000));
    for _ in 0..4 {
        assert_eq!(w2.lock(0)["status"], "paid");
    }
    w2.hub.watch_tick();
    assert_eq!(w2.oc(0).zero_conf["maxCum"], 3_000);
}

// --- 4 refusal detail -------------------------------------------------------------------------------------------

#[test]
fn route_payer_returns_the_hubs_detail() {
    let w = world(1, Kw::default());
    let o = w.origins[0].clone();
    w.hub.with_out(|b| b.chans.get_mut(&o).unwrap().blocked = "the provider did not reveal a lock in time".into());
    let r = w.lock_n(0, 5);
    assert_eq!(r, json!({"status": "refused", "error": "route_blocked", "detail": "the provider did not reveal a lock in time"}));
}

/// What cmp's R14 saw between a rollover and the next block (its provider refused every unconfirmed
/// open): route_blocked, now with the reason.
#[test]
fn a_rollover_child_the_provider_did_not_take_unconfirmed_says_so() {
    let w = world(1, Kw { zc_max: Some(0), ..Kw::default() });
    assert_eq!(w.lock(0)["status"], "paid");
    w.hub.watch_tick();
    assert_eq!(w.oc(0).state, "funded");
    let r = w.lock_n(0, 5);
    assert_eq!(r, json!({"status": "refused", "error": "route_blocked",
                         "detail": "no open channel to that provider: its ch2 is a rollover the provider takes once it confirms"}));
    w.block();
    assert_eq!(w.lock_n(0, 5)["status"], "paid");
}

#[test]
fn a_providers_refusal_reaches_the_client_with_its_code() {
    let w = world(1, Kw::default());
    w.stream(0, 5);
    w.provs[0].routes().lock().sessions.remove(&w.sh[0].session); // the provider lost the session
    let r = w.pay.lock(&w.sh[0]).unwrap().unwrap();
    assert_eq!((r["status"].as_str(), r["error"].as_str()), (Some("refused"), Some("route_failed")), "{r}");
    assert_eq!(r["detail"], "provider refused the lock: unknown_session");
    assert_eq!(w.hub_refused(), vec![("unknown_session".to_string(), 1)]);
}

/// A provider whose /lock answers with an escape sequence and 400 bytes of detail.
struct Evil(Arc<Provider>);

impl HttpService for Evil {
    fn body_limit(&self, path: &str) -> usize {
        self.0.body_limit(path, None)
    }

    fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str) -> HttpResponse {
        if path == ROUTE_LOCK_PATH {
            let doc = format!("{{\"error\": \"bad_invoice\", \"detail\": \"x\\u001b[31m\\n{}\"}}", "y".repeat(400));
            return HttpResponse::new(400, vec![], doc.into_bytes());
        }
        self.0.serve(method, path, headers, body, url, None)
    }
}

#[test]
fn a_providers_detail_is_sanitized() {
    let w = world(1, Kw::default());
    w.net.add(&w.origins[0], Arc::new(Evil(w.provs[0].clone())));
    let r = w.lock_n(0, 5);
    assert_eq!(r["error"], "route_failed");
    let d = r["detail"].as_str().unwrap();
    assert!(d.starts_with("provider refused the lock: bad_invoice (x[31my"), "{d}");
    assert!(d.chars().all(|c| (' '..='~').contains(&c)) && d.len() < 220, "{d}");
}
