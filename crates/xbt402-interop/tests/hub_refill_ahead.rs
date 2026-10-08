//! AGP-057 (a port of B1 `tests/security/test_agp057_refill_ahead.py`), in process: [`MemChain`] +
//! [`MemNet`]. The ch2 lifecycle under load:
//!   A the zero-conf cap of a rollover child (cmp CMP-149: `cum 134687 > the provider's zero-conf cap
//!     132120`). A child's cum starts at 0: nothing the parent carried counts against the cap. The hub
//!     refused on its own `confirmed` flag, which is the watcher's last look: a child that confirmed
//!     since that tick was refused until the next one. Now the hub looks at the chain before it
//!     refuses. A child that is really unconfirmed is still refused at the provider's cap (its risk
//!     bound; sized with `rollover_zero_conf_max`).
//!   B make-before-break refill. A rollover adds no coins, so a ch2 line runs out and was then closed
//!     and refilled, and the refill opens only at minConf: a block without routing to that provider.
//!     The hub now funds the origin's NEXT ch2 while the live one still has `refill_ahead_locks` × the
//!     largest lock of room, and switches to it with the first lock the live one cannot take.
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::adaptor::Sc;
use xbt402::channel::FeePayer;
use xbt402::client::{Wallet, WalletSend};
use xbt402::error::{ChannelError, Result};
use xbt402::funding::{ChainBackend, FundingPolicy, UtxoInfo};
use xbt402::hub::{HubConfig, OutChannel, RouteHub, LIVE};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route::*;
use xbt402::route_client::{RoutePayer, RoutePayerConfig, Shard};
use xbt402::route_seller::RouteOffer;
use xbt402::signer::LocalSigner;
use xbt402_interop::memnet::{ChainWallet, MemChain, MemNet, NetTransport};
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

const NET: &str = "bip122:11111111111111111111111111111111";
const HUB: &str = "http://hub.test";
const O: &str = "http://m0.test";
/// 50 calls at 40 sat.
const LOCK: u64 = 2_000;
/// The ch2 capacity in the refill tests: 20 locks.
const CAP: u64 = 40_000;
/// The provider's minCapacity.
const MIN_CAP: u64 = 20_000;

fn sk(n: u64) -> SecretKey {
    Sc::from_u64(n).secret().unwrap()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("xbt-rs-agp057-{}", hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..8])));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A node: the chain, or one that does not answer `gettxout` while `down`. `race` (the provider's):
/// the next read of an unconfirmed output, mempool included, is followed by a block.
struct Node {
    chain: Arc<MemChain>,
    down: AtomicBool,
    race: AtomicBool,
}

impl ChainBackend for Node {
    fn block_count(&self) -> Result<u32> {
        self.chain.block_count()
    }

    fn get_tx_out(&self, txid: &str, vout: u32, mempool: bool) -> Result<Option<UtxoInfo>> {
        if self.down.load(Ordering::Relaxed) {
            return Err(ChannelError::new("rpc_error", "node down"));
        }
        let out = self.chain.get_tx_out(txid, vout, mempool)?;
        if mempool && out.as_ref().is_some_and(|u| u.confirmations == 0) && self.race.swap(false, Ordering::Relaxed) {
            self.chain.mine(1); // the block arrives right after this read
        }
        Ok(out)
    }

    fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        self.chain.send_raw_transaction(hex)
    }

    fn has_transaction(&self, txid: &str) -> Result<bool> {
        self.chain.has_transaction(txid)
    }
}

impl SpendScan for Node {
    fn find_spend(&self, txid: &str, vout: u32, from: u32) -> Result<Option<Tx>> {
        self.chain.find_spend(txid, vout, from)
    }

    fn scan_spk(&self, spk: &[u8]) -> Result<Vec<(String, u32, u64)>> {
        self.chain.scan_spk(spk)
    }

    fn fee_rate(&self, target: u32) -> Result<Option<f64>> {
        self.chain.fee_rate(target)
    }

    fn in_mempool(&self, txid: &str) -> Result<bool> {
        self.chain.in_mempool(txid)
    }
}

/// The hub's wallet: its fundings start unconfirmed (as a real wallet's do). `mode` 1: the send goes
/// out and the call fails; 2: the call fails and nothing is sent.
struct Purse {
    chain: Arc<MemChain>,
    funded: Mutex<Vec<u64>>,
    mode: AtomicU8,
}

struct PurseRef(Arc<Purse>);

impl Wallet for PurseRef {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        let mode = self.0.mode.load(Ordering::Relaxed);
        if mode == 2 {
            return Err(ChannelError::new("rpc_error", "wallet locked"));
        }
        self.0.funded.lock().unwrap().push(sats);
        let r = self.0.chain.fund_with(address, sats, 0)?;
        if mode == 1 {
            return Err(ChannelError::new("rpc_error", "wallet RPC timed out"));
        }
        Ok(r)
    }

    fn wallet_sends_to(&self, address: &str) -> Result<Vec<String>> {
        self.0.chain.wallet_sends_to(address)
    }

    fn wallet_send(&self, txid: &str, address: &str) -> Result<Option<WalletSend>> {
        self.0.chain.wallet_send(txid, address)
    }
}

/// What a test changes: hub config keys, the provider's settle floor, threshold and explicit zero-conf cap.
struct Kw {
    hub: Value,
    k: u64,
    settle_multiple: u64,
    zc_max: Option<u64>,
}

impl Default for Kw {
    fn default() -> Self {
        Self { hub: json!({}), k: 0, settle_multiple: 2, zc_max: None }
    }
}

/// The refill tests' hub: 3 locks ahead on a 20-lock ch2.
fn ahead(more: Value) -> Value {
    let mut c = json!({"refill_ahead_locks": 3, "ch2_capacity": CAP});
    for (k, v) in more.as_object().unwrap() {
        c[k] = v.clone();
    }
    c
}

/// A provider threshold above the capacity: no rollover.
fn no_rollover(hub: Value) -> Kw {
    Kw { hub, settle_multiple: 100, ..Kw::default() }
}

fn hub_cfg(extra: &Value) -> HubConfig {
    // the settle floor and the ahead refill are off unless a test asks
    let mut c = json!({"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500, "delta": 36,
                       "reveal_timeout": 1.0, "ch2_capacity": 100000, "ch2_expiry_blocks": 1000, "close_margin": 36, "settle_lock_multiple": 0,
                       "refill_ahead_locks": 0, "policy": {"min_capacity": 20000, "min_expiry_blocks": 500, "max_expiry_blocks": 8640}});
    for (k, v) in extra.as_object().unwrap() {
        c[k] = v.clone();
    }
    HubConfig::from_json(&c).unwrap()
}

/// One hub, one client, one provider; `block()` is a block and a tick of every watcher.
struct W {
    chain: Arc<MemChain>,
    node: Arc<Node>,
    /// The provider's node.
    pnode: Arc<Node>,
    net: Arc<MemNet>,
    hub: Arc<RouteHub>,
    prov: Arc<Provider>,
    pay: Arc<RoutePayer>,
    sh: Arc<Shard>,
    purse: Arc<Purse>,
    dir: TempDir,
}

fn new_hub(node: &Arc<Node>, purse: &Arc<Purse>, net: &Arc<MemNet>, dir: &TempDir, extra: &Value) -> Arc<RouteHub> {
    Arc::new(RouteHub::new(node.clone(), node.clone(), Box::new(PurseRef(purse.clone())), Box::new(NetTransport(net.clone())), sk(0x4B4B), NET,
                           Some(&dir.0.join("hub")), hub_cfg(extra)).unwrap())
}

fn world(kw: Kw) -> W {
    let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
    let node = Arc::new(Node { chain: chain.clone(), down: AtomicBool::new(false), race: AtomicBool::new(false) });
    let pnode = Arc::new(Node { chain: chain.clone(), down: AtomicBool::new(false), race: AtomicBool::new(false) });
    let purse = Arc::new(Purse { chain: chain.clone(), funded: Mutex::new(vec![]), mode: AtomicU8::new(0) });
    let hub = new_hub(&node, &purse, &net, &dir, &kw.hub);
    net.add(HUB, hub.clone());
    let mut cfg = ProviderConfig::new(NET);
    cfg.close_margin = 36;
    cfg.policy = FundingPolicy { min_capacity: MIN_CAP, min_expiry_blocks: 500, max_expiry_blocks: 8_640, close_margin: 36, ..FundingPolicy::default() };
    cfg.settle_multiple = kw.settle_multiple;
    cfg.height_ttl = Duration::ZERO;
    cfg.route_close_fee_payer = FeePayer::Payee;
    cfg.rollover_zero_conf_max = kw.zc_max;
    cfg.settle_lock_multiple = kw.k;
    let ledger = Ledger::open(&dir.0.join("prov.jsonl")).unwrap();
    let prov = Arc::new(Provider::new(pnode.clone(), sk(0x5757), cfg, ledger, Box::new(|_, _| 1000),
                                      Box::new(|_, _, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], b"{\"ok\":1}".to_vec()))).unwrap());
    prov.offer_route(RouteOffer { window: 0.3, lock_wait: 0.6, invoice_ttl: 8.0, ..RouteOffer::new("/v1/chunk", 40 * AMSAT_PER_SAT) });
    net.add(O, prov.clone());
    hub.connect(O, None, None).unwrap();
    chain.mine(1);
    hub.watch_tick();
    let mut pc = RoutePayerConfig::new(NET);
    pc.expiry_blocks = 8_000;
    pc.capacity = 2_000_000;
    let c = chain.clone();
    let pay = Arc::new(RoutePayer::new(HUB, pc, Arc::new(LocalSigner::new()), Arc::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())),
                                       Box::new(move || Ok(c.height()))));
    pay.open().unwrap();
    let sh = pay.shard(&format!("{O}/v1/chunk"), "POST").unwrap();
    W { chain, node, pnode, net, hub, prov, pay, sh, purse, dir }
}

impl W {
    fn live(&self) -> OutChannel {
        self.hub.out_channels()[O].clone()
    }

    fn nxt(&self) -> Option<OutChannel> {
        self.hub.next_channels().get(O).cloned()
    }

    fn lock(&self) -> Value {
        for _ in 0..50 {
            let r = self.pay.call(&self.sh, "POST", br#"{"tokens":1}"#).unwrap();
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        }
        self.pay.lock(&self.sh).unwrap().unwrap()
    }

    fn paid(&self, n: usize) {
        for _ in 0..n {
            let r = self.lock();
            assert_eq!(r["status"], "paid", "{r}");
        }
    }

    fn block(&self) -> Vec<Value> {
        self.chain.mine(1);
        self.prov.close_due().unwrap();
        self.hub.watch_tick()
    }

    fn events(&self, kind: &str) -> Vec<Value> {
        self.hub.events.lock().unwrap().iter().filter(|e| e["event"] == kind).cloned().collect()
    }

    fn locks_sent(&self) -> usize {
        self.net.calls.lock().unwrap().iter().filter(|c| c.1 == O && c.2 == ROUTE_LOCK_PATH).count()
    }

    /// Every ch2 record: the archive, the live ones and the next ones.
    fn records(&self) -> Vec<Value> {
        let mut r = self.hub.archived();
        r.extend(self.hub.out_channels().values().map(OutChannel::to_json));
        r.extend(self.hub.next_channels().values().map(OutChannel::to_json));
        r
    }

    fn routed(&self) -> u64 {
        self.records().iter().map(|r| r["routed"].as_u64().unwrap()).sum()
    }

    /// (refusals the client saw, refusals of the provider the hub saw).
    fn refused(&self) -> (usize, usize) {
        (self.pay.stats().refused.len(), self.hub.stats.lock().unwrap().refused.len())
    }

    fn funded(&self) -> usize {
        self.purse.funded.lock().unwrap().len()
    }
}

fn evs(acts: &[Value]) -> Vec<String> {
    acts.iter().map(|a| a["event"].as_str().unwrap_or("").to_string()).collect()
}

fn refusal(r: &Value) -> (&str, &str, &str) {
    (r["status"].as_str().unwrap_or(""), r["error"].as_str().unwrap_or(""), r["detail"].as_str().unwrap_or(""))
}

// --- A the zero-conf cap -----------------------------------------------------------------------------------

/// Settle floor on (k = 4): the ch2 rolls over after 4 locks, and the provider's cap on the child is
/// 2 × 4 × the largest lock = 8 locks.
fn capped(zc_max: Option<u64>) -> W {
    let w = world(Kw { hub: json!({"settle_lock_multiple": 4}), k: 4, zc_max, ..Kw::default() });
    w.paid(4);
    w.hub.watch_tick(); // due: rolled over, the child open unconfirmed
    assert_eq!(w.events("ch2_rollover").len(), 1);
    let c = w.live();
    assert_eq!((c.state.as_str(), c.zero_conf["maxCum"].as_u64(), c.zero_conf_pending()), ("open", Some(zc_max.unwrap_or(8 * LOCK)), true));
    w
}

#[test]
fn a_childs_cum_starts_at_zero_nothing_is_carried_into_the_cap() {
    let w = capped(None);
    let child = w.live();
    let st = w.prov.channel_state(&child.params.channel_id()).unwrap();
    assert_eq!((child.signed, child.routed, st.best_cum, st.extra.get("routed_sat").and_then(Value::as_u64).unwrap_or(0)), (0, 0, 0, 0));
    for i in 1..=8 {
        // exactly the cap's 8 locks fit, no block
        w.paid(1);
        assert_eq!((w.live().signed, w.live().routed), (i * LOCK, i * LOCK));
    }
    assert_eq!(Some(w.live().signed), w.live().zero_conf["maxCum"].as_u64());
    assert_eq!(w.refused(), (0, 0));
}

#[test]
fn a_child_that_is_unconfirmed_is_refused_at_the_cap_before_anything_is_sent() {
    let w = capped(None);
    w.paid(8);
    let sent = w.locks_sent();
    let r = w.lock();
    let (status, code, detail) = refusal(&r);
    assert_eq!((status, code), ("refused", "route_blocked"), "{r}");
    assert!(detail.contains(&format!("cum {} > the provider's zero-conf cap {}", 9 * LOCK, 8 * LOCK)), "{detail}");
    let c = w.live();
    assert_eq!((w.locks_sent(), c.signed, c.pending.is_empty(), c.stale.len()), (sent, 8 * LOCK, true, 0));
    assert_eq!(w.refused().1, 0); // the hub's own check: the provider refused nothing
}

/// cmp's refusals: the rollover is in a block, the hub's flag is still the last tick's.
#[test]
fn a_child_that_confirmed_since_the_watchers_last_tick_is_not_refused() {
    let w = capped(None);
    w.paid(8);
    w.chain.mine(1); // no watcher tick, at the hub or the provider
    assert!(w.live().zero_conf_pending());
    w.paid(1); // the 9th lock, above the cap
    assert_eq!((w.live().signed, w.live().zero_conf_pending()), (9 * LOCK, false));
    let conf: Vec<Value> = w.events("ch2_zero_conf_confirmed").iter().map(|e| e["chan"].clone()).collect();
    assert_eq!(conf, vec![json!(w.live().params.channel_id())]);
    assert_eq!(w.refused(), (0, 0));
}

#[test]
fn the_close_margin_bound_looks_at_the_chain_too() {
    let w = capped(None);
    w.paid(1);
    let tip = w.chain.height();
    // the provider's `until` is behind the tip
    w.hub.with_out(|b| b.chans.get_mut(O).unwrap().zero_conf.insert("until".into(), tip.into()));
    let r = w.lock();
    let (status, code, detail) = refusal(&r);
    assert_eq!((status, code), ("refused", "route_blocked"), "{r}");
    assert!(detail.contains("unconfirmed at the parent's close margin"), "{detail}");
    w.chain.confirm_all(); // it confirmed; no tick
    std::thread::sleep(Duration::from_millis(350)); // the refused lock's window is over
    w.paid(1);
    assert!(!w.live().zero_conf_pending());
}

#[test]
fn a_node_that_does_not_answer_leaves_the_bound_standing() {
    let w = capped(None);
    w.paid(8);
    w.chain.mine(1);
    w.node.down.store(true, Ordering::Relaxed);
    let r = w.lock();
    let (status, code, detail) = refusal(&r);
    assert_eq!((status, code), ("refused", "route_blocked"), "{r}");
    assert!(detail.contains("zero-conf cap"), "{detail}");
    let steps: Vec<Value> = w.events("ch2_watch_error").iter().map(|e| e["step"].clone()).collect();
    assert_eq!(steps, vec![json!("zero_conf")]);
    assert_eq!((w.live().signed, w.live().pending.is_empty()), (8 * LOCK, true));
}

/// The provider read the child's funding unconfirmed, then the block with the rollover came: the
/// parent is spent in a block, so the child is no zero-conf child any more, and it is confirmed. The
/// open was refused `unconfirmed` and routing waited for the hub's next tick (rollover_load cmp-lag).
#[test]
fn a_block_that_comes_while_the_provider_checks_the_child_does_not_refuse_the_open() {
    let w = world(Kw { hub: json!({"settle_lock_multiple": 4}), k: 4, ..Kw::default() });
    w.paid(4);
    w.pnode.race.store(true, Ordering::Relaxed);
    w.hub.watch_tick(); // rolled over; the open meets the block
    assert_eq!((w.events("ch2_rollover").len(), w.pnode.race.load(Ordering::Relaxed)), (1, false));
    let c = w.live();
    assert_eq!((c.state.as_str(), c.zero_conf.is_empty(), c.rolled_from.is_empty()), ("open", true, false));
    w.paid(1);
    assert_eq!(w.refused(), (0, 0));
}

/// The provider's watcher meets the block the same way (rollover_load high-nofloor: `provider refused
/// the lock: unconfirmed`): the child is left suspended although it confirmed.
#[test]
fn a_child_the_providers_watcher_left_suspended_is_looked_at_before_a_lock_is_refused() {
    let w = capped(None);
    let chan = w.live().params.channel_id();
    w.prov.with_state(&chan, |st| st.suspended = true).unwrap(); // as the racing watcher tick leaves it
    let r = w.lock(); // still unconfirmed: refused, as it must be
    assert_eq!(refusal(&r), ("refused", "route_failed", "provider refused the lock: unconfirmed"), "{r}");
    // the provider holds that lock's pre-signature, so this ch2 takes no more routes (AGP-064 H2)
    assert_eq!(refusal(&w.lock()).1, "route_blocked");
    let w = capped(None);
    let chan = w.live().params.channel_id();
    w.prov.with_state(&chan, |st| st.suspended = true).unwrap();
    w.chain.mine(1); // confirmed; no watcher tick anywhere
    std::thread::sleep(Duration::from_millis(350));
    w.paid(1);
    let st = w.prov.channel_state(&chan).unwrap();
    assert_eq!((st.suspended, st.extra["zero_conf"]["confirmed"].clone()), (false, json!(true)));
    // a plain channel whose funding left the chain stays refused: only an unconfirmed child is looked at
    w.prov.with_state(&chan, |st| st.suspended = true).unwrap();
    let r = w.lock();
    assert_eq!((refusal(&r).0, refusal(&r).2), ("refused", "provider refused the lock: unconfirmed"), "{r}");
}

#[test]
fn an_explicit_provider_cap_sizes_it_for_slow_blocks() {
    let w = capped(Some(16 * LOCK));
    w.paid(16); // no block all the while
    assert_eq!((w.live().signed, w.refused()), (16 * LOCK, (0, 0)));
}

// --- B make-before-break refill ----------------------------------------------------------------------------

/// Every lock is due at the provider's threshold, so the ch2 rolls over each block and its line
/// shrinks by a lock each time. The next ch2 is funded 3 locks before the line ends, opens at minConf,
/// and takes over when the live one is too small to roll over: 40 locks, none refused.
#[test]
fn a_line_that_runs_out_under_rollovers_never_pauses() {
    let w = world(Kw { hub: ahead(json!({})), ..Kw::default() });
    let first = w.live().params.channel_id();
    for _ in 0..40 {
        w.paid(1);
        w.block();
        assert!(w.hub.next_channels().len() <= 1);
        assert!(w.hub.committed_sat() <= 2 * CAP);
    }
    assert_eq!(w.refused(), (0, 0));
    let (ahead, switch) = (w.events("ch2_refill_ahead"), w.events("ch2_switch"));
    assert!(switch.len() >= 3, "{switch:?}");
    assert_eq!(ahead.len(), switch.len() + usize::from(w.nxt().is_some()));
    assert_ne!(ahead[0]["live"], first.as_str());
    assert_eq!((ahead[0]["maxLock"].as_u64(), ahead[0]["capacity"].as_u64()), (Some(LOCK), Some(CAP)));
    assert!(ahead[0]["room"].as_u64().unwrap() < 3 * LOCK);
    assert!(switch.iter().all(|e| e["why"] == "closed"), "{switch:?}");
    assert_eq!(w.funded(), 1 + ahead.len()); // one wallet funding per ch2, none twice
    // money: every lock is on exactly one ch2, and the provider was paid all of them
    assert_eq!(w.routed(), 40 * LOCK);
    assert_eq!(w.prov.routes().lock().sessions[&w.sh.session].paid_sat, 40 * LOCK);
    assert!(w.records().iter().all(|r| r["pending"].as_object().unwrap().is_empty() && r["stale"].as_array().unwrap().is_empty()));
}

/// The baseline (`refill_ahead_locks` 0): the same line, and a lock refused when it ends.
#[test]
fn without_it_the_refill_follows_the_close_and_routing_waits_for_a_block() {
    let w = world(Kw { hub: ahead(json!({"refill_ahead_locks": 0})), ..Kw::default() });
    let mut refused = 0;
    for _ in 0..14 {
        let r = w.lock();
        if r["status"] != "paid" {
            let (_, code, detail) = refusal(&r);
            assert_eq!(code, "route_blocked", "{r}");
            assert!(detail.contains("its ch2 is funded"), "{detail}");
            refused += 1;
        }
        w.block();
    }
    assert_eq!(refused, 1);
    assert_eq!((w.events("ch2_refill_ahead").len(), w.events("ch2_switch").len(), w.hub.next_channels().len()), (0, 0, 0));
}

#[test]
fn the_next_ch2_is_funded_at_n_locks_of_room_and_opens_only_once_confirmed() {
    let w = world(no_rollover(ahead(json!({}))));
    for i in 0..7 {
        // 14,000 used: 6,000 of room above minCapacity
        w.paid(1);
        assert_eq!(w.hub.watch_tick(), Vec::<Value>::new(), "{i}");
    }
    w.paid(1); // 16,000 used: 4,000 < 3 locks
    let acts = w.hub.watch_tick();
    assert_eq!(evs(&acts), ["ch2_refill_ahead"]);
    let (live, nxt) = (w.live(), w.nxt().unwrap());
    assert_eq!((acts[0]["room"].as_u64(), acts[0]["live"].as_str(), acts[0]["next"].as_str()),
               (Some(CAP - 8 * LOCK - MIN_CAP), Some(live.params.channel_id().as_str()), Some(nxt.params.channel_id().as_str())));
    assert_eq!((nxt.state.as_str(), nxt.params.capacity, nxt.rolled_from.as_str(), live.state.as_str()), ("funded", CAP, "", "open"));
    assert_eq!(w.hub.committed_sat(), 2 * CAP); // the liquidity accounting counts both
    assert_eq!(w.hub.with_out(|b| b.live_keys(&live.pay_to)), [O]); // one origin, counted once for its payTo
    assert_eq!(w.hub.watch_tick(), Vec::<Value>::new()); // unconfirmed: not opened, and not funded twice
    assert!(w.prov.channel_state(&nxt.params.channel_id()).is_none());
    w.paid(1); // the live one goes on meanwhile
    let acts = w.block();
    assert!(acts.contains(&json!({"event": "ch2_open", "provider": O, "next": true})), "{acts:?}");
    let nxt = w.nxt().unwrap();
    assert_eq!((nxt.state.as_str(), nxt.zero_conf.is_empty()), ("open", true));
    assert!(w.prov.channel_state(&nxt.params.channel_id()).is_some());
    assert_eq!((w.funded(), w.refused()), (2, (0, 0)));
}

/// No rollover (the provider's threshold is above the capacity): the live ch2 is used to its last
/// sat, the 21st lock switches, and the retired ch2 is closed by the watcher: the provider is paid its
/// 40,000 and the hub's accounting drops it once the close is out.
#[test]
fn the_lock_the_live_ch2_cannot_take_goes_over_the_next_one() {
    let w = world(no_rollover(ahead(json!({}))));
    w.paid(8);
    w.block(); // funded ahead
    w.block(); // open
    let (old, nxt) = (w.live().params.channel_id(), w.nxt().unwrap().params.channel_id());
    assert_eq!(w.nxt().unwrap().state, "open");
    w.paid(12);
    assert_eq!((w.live().signed, w.live().params.channel_id() == old, w.events("ch2_switch").len()), (CAP, true, 0));
    w.paid(1); // 42,000 > capacity
    let live = w.live();
    assert_eq!(live.params.channel_id(), nxt);
    assert_eq!((live.signed, live.routed, live.max_lock, w.hub.next_channels().len()), (LOCK, LOCK, LOCK, 0));
    let sw = w.events("ch2_switch");
    assert_eq!(sw.len(), 1);
    assert_eq!((sw[0]["from"].as_str(), sw[0]["to"].as_str(), sw[0]["why"].as_str()), (Some(old.as_str()), Some(nxt.as_str()), Some("exhausted")));
    let rec = w.hub.archived().pop().unwrap();
    assert_eq!((rec["state"].as_str(), rec["retired"].as_bool(), rec["signed"].as_u64()), (Some("open"), Some(true), Some(CAP)));
    assert_eq!(w.hub.committed_sat(), 2 * CAP); // still the hub's coins until its close is out
    assert_eq!(w.hub.routing_extra().unwrap()["providers"], json!([O]));
    let acts = w.hub.watch_tick();
    let close: Vec<&Value> = acts.iter().filter(|a| a["event"] == "ch2_close").collect();
    assert_eq!(close.len(), 1, "{acts:?}");
    assert_eq!((close[0]["chan"].as_str(), close[0]["amount"].as_u64(), close[0]["payeeNet"].as_u64()), (Some(old.as_str()), Some(CAP), Some(CAP - 600)));
    assert_eq!((w.hub.archived().pop().unwrap()["state"].as_str(), w.hub.committed_sat()), (Some("closing"), CAP));
    assert!(!w.prov.channel_state(&old).unwrap().closed_txid.is_empty());
    w.block();
    let rec = w.hub.archived().pop().unwrap();
    assert_eq!((rec["state"].as_str(), rec["final"].as_bool()), (Some("closed"), Some(true)));
    w.paid(3);
    assert_eq!(w.refused(), (0, 0));
    assert_eq!(w.routed(), 24 * LOCK);
}

/// N = 1: the next ch2 is funded only when the live one is at the provider's minCapacity, so it is
/// still unconfirmed when the live one is due and too small to roll over. Closing it then would pause
/// routing until the next one opens; it still takes locks, so it is kept until then.
#[test]
fn a_live_ch2_too_small_to_roll_over_is_kept_until_the_next_one_is_open() {
    let w = world(Kw { hub: ahead(json!({"refill_ahead_locks": 1, "settle_lock_multiple": 11})), ..Kw::default() });
    w.paid(10); // what a child would keep is the minCapacity
    assert_eq!(evs(&w.hub.watch_tick()), ["ch2_refill_ahead"]);
    assert_eq!((w.live().signed, w.nxt().unwrap().state.as_str()), (10 * LOCK, "funded"));
    w.paid(1);
    assert_eq!(evs(&w.hub.watch_tick()), ["ch2_wait_next"]); // due, too small to roll over, no block
    assert_eq!((w.live().state.as_str(), w.live().signed, w.nxt().unwrap().state.as_str()), ("open", 11 * LOCK, "funded"));
    w.paid(1); // the live one goes on
    w.block(); // the next one confirms and opens
    assert_eq!((w.live().signed, w.nxt().unwrap().state.as_str(), w.events("ch2_close").len()), (12 * LOCK, "open", 0));
    let acts = w.hub.watch_tick(); // now it is closed, and the next one takes over
    assert_eq!(evs(&acts), ["ch2_close"]);
    let live = w.live();
    assert_eq!((acts[0]["amount"].as_u64(), acts[0]["next"].as_str(), live.state.as_str(), live.params.capacity),
               (Some(12 * LOCK), Some(live.params.channel_id().as_str()), "open", CAP));
    w.paid(1);
    assert_eq!(w.refused(), (0, 0));
}

#[test]
fn an_exhausted_ch2_without_a_next_one_fails_as_before() {
    let w = world(no_rollover(ahead(json!({"refill_ahead_locks": 0}))));
    w.paid(20);
    let r = w.lock();
    let (status, code, detail) = refusal(&r);
    assert_eq!((status, code), ("refused", "route_failed"), "{r}");
    assert!(detail.contains("exhausted"), "{detail}");
}

#[test]
fn a_next_ch2_not_open_yet_does_not_take_the_lock() {
    let w = world(no_rollover(ahead(json!({}))));
    w.paid(8);
    w.hub.watch_tick(); // funded, unconfirmed
    assert_eq!(w.nxt().unwrap().state, "funded");
    w.paid(12);
    let r = w.lock();
    assert_eq!((refusal(&r).0, refusal(&r).1), ("refused", "route_failed"), "{r}");
    let nxt = w.nxt().unwrap();
    assert_eq!((nxt.state.as_str(), nxt.signed, w.events("ch2_switch").len()), ("funded", 0, 0));
}

/// A and B together: the child is at the provider's zero-conf cap and no block comes; the next ch2
/// (confirmed) takes the lock instead of a refusal.
#[test]
fn an_unconfirmed_rollover_child_at_its_cap_hands_over_to_an_open_next_ch2() {
    let w = world(Kw { hub: json!({"refill_ahead_locks": 40, "ch2_capacity": 100_000, "settle_lock_multiple": 4}), k: 4, ..Kw::default() });
    w.paid(1);
    w.block(); // 40 locks of room wanted: funded ahead at once
    w.block();
    assert_eq!(w.nxt().unwrap().state, "open");
    w.paid(3);
    w.hub.watch_tick(); // 4 locks: rolled over, the child unconfirmed
    let (child, nxt) = (w.live(), w.nxt().unwrap().params.channel_id());
    assert_eq!((child.zero_conf_pending(), child.zero_conf["maxCum"].as_u64()), (true, Some(8 * LOCK)));
    w.paid(8);
    w.paid(1); // the 9th: above the cap, no block
    assert_eq!(w.live().params.channel_id(), nxt);
    assert!(w.events("ch2_switch")[0]["why"].as_str().unwrap().contains("zero-conf cap"));
    assert_eq!((w.live().signed, w.refused()), (LOCK, (0, 0)));
    w.block(); // the retired child is closed on its 16,000
    let closes: Vec<(String, u64)> = w.events("ch2_close").iter().map(|e| (e["chan"].as_str().unwrap().to_string(), e["amount"].as_u64().unwrap())).collect();
    assert_eq!(closes, vec![(child.params.channel_id(), 8 * LOCK)]);
}

#[test]
fn an_idle_provider_does_not_keep_two_ch2s() {
    let w = world(no_rollover(ahead(json!({"settle_idle": 0.3}))));
    w.paid(8);
    w.block();
    w.block();
    let (old, nxt) = (w.live().params.channel_id(), w.nxt().unwrap());
    assert_eq!((nxt.state.as_str(), w.hub.committed_sat()), ("open", 2 * CAP));
    std::thread::sleep(Duration::from_millis(350));
    let acts = w.hub.watch_tick(); // no lock for settle_idle: the next one takes over
    assert!(acts.contains(&json!({"event": "ch2_switch", "provider": O, "why": "idle"})), "{acts:?}");
    assert_eq!(w.live().params.channel_id(), nxt.params.channel_id());
    let closed: Vec<&str> = acts.iter().filter(|a| a["event"] == "ch2_close").map(|a| a["chan"].as_str().unwrap()).collect();
    assert_eq!(closed, [old.as_str()]);
    assert_eq!(w.hub.committed_sat(), CAP);
    assert_eq!(w.hub.watch_tick(), Vec::<Value>::new()); // and nothing is funded ahead for an idle provider
    w.paid(1);
    assert_eq!(w.refused(), (0, 0));
}

// --- bounds --------------------------------------------------------------------------------------------------

#[test]
fn at_most_one_next_ch2_per_origin() {
    let w = world(no_rollover(ahead(json!({}))));
    assert_eq!(w.hub.connect_next("http://nobody.test", None, None).unwrap_err().code, "no_live_ch2");
    let a = w.hub.connect_next(O, None, None).unwrap();
    assert_eq!(w.hub.connect_next(O, None, None).unwrap().params.channel_id(), a.params.channel_id());
    assert_eq!((w.funded(), w.hub.next_channels().keys().cloned().collect::<Vec<_>>()), (2, vec![O.to_string()]));
    // connect still returns the live one
    assert_eq!(w.hub.connect(O, None, None).unwrap().params.channel_id(), w.live().params.channel_id());
    assert_eq!(w.funded(), 2);
}

#[test]
fn the_liquidity_cap_counts_both_and_a_refused_refill_is_tried_once_a_block() {
    let w = world(no_rollover(ahead(json!({"liquidity_cap_sat": 2 * CAP - 1}))));
    w.paid(8);
    let acts = w.hub.watch_tick();
    assert_eq!(evs(&acts), ["ch2_refill_ahead_failed"]);
    assert!(acts[0]["error"].as_str().unwrap().contains("liquidity_cap"), "{acts:?}");
    assert_eq!((w.hub.watch_tick(), w.hub.next_channels().len(), w.funded()), (vec![], 0, 1));
    w.paid(1); // the live ch2 is not disturbed
    assert_eq!(evs(&w.block()), ["ch2_refill_ahead_failed"]);
    // with room for both, it is funded
    let w = world(no_rollover(ahead(json!({"liquidity_cap_sat": 2 * CAP}))));
    w.paid(8);
    assert_eq!(evs(&w.hub.watch_tick()), ["ch2_refill_ahead"]);
    assert_eq!(w.hub.committed_sat(), 2 * CAP);
}

#[test]
fn an_embedders_own_refill_path_is_not_bypassed() {
    let w = world(no_rollover(ahead(json!({}))));
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    w.hub.set_refill(Some(Box::new(|_, _| Ok(()))));
    w.paid(8);
    // its path, lock and cap: nothing funded on our own
    assert_eq!((w.hub.watch_tick(), w.hub.next_channels().len()), (vec![], 0));
    let c = calls.clone();
    w.hub.set_refill_ahead(Some(Box::new(move |hub, origin| {
        c.lock().unwrap().push(origin.to_string());
        hub.connect_next(origin, None, None).map(|_| ())
    })));
    assert_eq!(evs(&w.hub.watch_tick()), ["ch2_refill_ahead"]);
    assert_eq!((calls.lock().unwrap().clone(), w.nxt().unwrap().state.as_str()), (vec![O.to_string()], "funded"));
}

#[test]
fn a_blocked_provider_gets_no_next_ch2_and_no_switch() {
    let w = world(no_rollover(ahead(json!({}))));
    w.paid(8);
    w.block();
    w.block();
    assert_eq!(w.nxt().unwrap().state, "open");
    let why = "the provider did not reveal a lock in time";
    w.hub.with_out(|b| b.chans.get_mut(O).unwrap().blocked = why.into());
    let r = w.lock();
    assert_eq!(refusal(&r), ("refused", "route_blocked", why), "{r}");
    assert_eq!((w.events("ch2_switch").len(), w.hub.routing_extra().unwrap()["providers"].clone()), (0, json!([])));
}

// --- lifecycle -----------------------------------------------------------------------------------------------

#[test]
fn a_fund_hook_that_fails_after_it_broadcast_is_reconciled() {
    let w = world(no_rollover(ahead(json!({}))));
    w.purse.mode.store(1, Ordering::Relaxed);
    w.paid(8);
    assert_eq!(evs(&w.hub.watch_tick()), ["ch2_refill_ahead_failed"]);
    // written ahead: the key is on disk
    assert_eq!((w.nxt().unwrap().state.as_str(), w.live().state.as_str()), ("funding", "open"));
    assert!(evs(&w.hub.watch_tick()).contains(&"ch2_funding_recovered".to_string()));
    assert_eq!(w.nxt().unwrap().state, "funded");
    w.block();
    assert_eq!(w.nxt().unwrap().state, "open");
}

#[test]
fn a_funding_that_never_appears_is_dropped_and_funded_again() {
    let w = world(no_rollover(ahead(json!({"funding_timeout_blocks": 2}))));
    w.purse.mode.store(2, Ordering::Relaxed);
    w.paid(8);
    w.hub.watch_tick();
    assert_eq!(w.nxt().unwrap().state, "funding");
    w.block();
    assert_eq!(w.nxt().unwrap().state, "funding");
    w.purse.mode.store(0, Ordering::Relaxed);
    assert_eq!(evs(&w.block()), ["ch2_funding_dropped", "ch2_refill_ahead"]);
    let rec = w.hub.archived().pop().unwrap();
    assert_eq!((w.nxt().unwrap().state.as_str(), rec["state"].as_str(), rec["final"].as_bool()), ("funded", Some("dropped"), Some(true)));
    assert_eq!(w.live().state, "open");
}

#[test]
fn the_book_keeps_the_next_ch2_over_a_restart() {
    let w = world(no_rollover(ahead(json!({}))));
    w.paid(8);
    w.block();
    w.block();
    let nxt = w.nxt().unwrap();
    let h2 = new_hub(&w.node, &w.purse, &w.net, &w.dir, &ahead(json!({})));
    let got: Vec<(String, String, String)> = h2.next_channels().iter().map(|(k, c)| (k.clone(), c.state.clone(), c.params.channel_id())).collect();
    assert_eq!(got, vec![(O.to_string(), "open".to_string(), nxt.params.channel_id())]);
    assert_eq!((h2.committed_sat(), h2.watch_tick()), (2 * CAP, vec![]));
}

#[test]
fn a_next_ch2_never_used_is_refunded_at_its_expiry_and_leaves() {
    let w = world(no_rollover(ahead(json!({}))));
    w.paid(8);
    w.block();
    w.block();
    let nxt = w.nxt().unwrap();
    assert_eq!(nxt.state, "open");
    w.chain.set_height(nxt.params.expiry); // unsigned: refunded at expiry
    w.chain.confirm_all();
    let acts = w.hub.watch_tick();
    let chan = nxt.params.channel_id();
    assert!(acts.iter().any(|a| a["event"] == "ch2_refund" && a["chan"] == chan.as_str()), "{acts:?}");
    let rec = w.hub.archived().into_iter().find(|r| OutChannel::from_json(r).unwrap().params.channel_id() == chan).unwrap();
    assert_eq!((rec["state"].as_str(), LIVE.contains(&"refunded")), (Some("refunded"), false));
    // the live ch2 still wants one: a fresh next ch2 is funded in its place, never two
    let refills: Vec<String> = evs(&acts).into_iter().filter(|e| e.starts_with("ch2_refill")).collect();
    assert_eq!(refills, ["ch2_refill_ahead"]);
    let now = w.nxt().unwrap();
    assert_eq!((now.params.channel_id() == chan, now.state.as_str(), w.hub.next_channels().len()), (false, "funded", 1));
}
