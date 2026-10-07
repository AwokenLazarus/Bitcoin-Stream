//! AGP-045: RouteHub reconcile fixes from cmp-lead's CMP-012 review (a port of B1
//! `tests/security/test_agp045_hub_reconcile.py`), in process: [`MemChain`] (chain, mempool and the
//! fund wallet) + [`MemNet`]. One section per item:
//! 1 the refill hook is looked up at call time and called with no hub lock held (it may be replaced
//!   at any time, from the hook too);
//! 2 a `funding` record is reconciled against the wallet (`gettransaction`), the mempool (`gettxout`
//!   incl. the mempool, `getmempoolentry`) and `scantxoutset`: a slow funding past
//!   `funding_timeout_blocks` is recovered or refunded, never lost; a dropped record whose send is
//!   known is watched and refunded at expiry if it confirms late; a genuinely failed send is final;
//! 3 a mempool spender makes a ch2 `closing`; only a confirmed one makes it `closed` and takes the
//!   refund fee back; the fee is booked again if the mempool close vanishes.
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::adaptor::{self, Sc};
use xbt402::channel::FeePayer;
use xbt402::client::{Wallet, WalletSend};
use xbt402::error::{ChannelError, Result};
use xbt402::funding::FundingPolicy;
use xbt402::hub::{HubConfig, OutChannel, RouteHub};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route::SpendScan;
use xbt402::route_client::{RoutePayer, RoutePayerConfig, Shard};
use xbt402::route_seller::RouteOffer;
use xbt402::signer::LocalSigner;
use xbt402_interop::memnet::{ChainWallet, MemChain, MemNet, NetTransport};
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;

const NET: &str = "bip122:11111111111111111111111111111111";
const HUB: &str = "http://hub.test";

fn sk(n: u64) -> SecretKey {
    Sc::from_u64(n).secret().unwrap()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("xbt-rs-agp045-{}", hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..8])));
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
    p.offer_route(RouteOffer { window: 0.3, lock_wait: 0.6, invoice_ttl: 8.0, ..RouteOffer::new("/v1/chunk", 370 * 10u128.pow(18)) });
    let p = Arc::new(p);
    net.add(origin, p.clone());
    p
}

fn hub_cfg() -> HubConfig {
    HubConfig::from_json(&json!({"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500, "delta": 36,
                                 "reveal_timeout": 1.0, "ch2_capacity": 100000, "ch2_expiry_blocks": 1000, "close_margin": 36,
                                 "policy": {"min_capacity": 20000, "min_expiry_blocks": 500, "max_expiry_blocks": 8640}})).unwrap()
}

fn stream(pay: &RoutePayer, sh: &Arc<Shard>, n: usize) {
    for _ in 0..n {
        let r = pay.call(sh, "POST", br#"{"tokens":1}"#).unwrap();
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    }
}

fn has(acts: &[Value], f: impl Fn(&Value) -> bool) -> bool {
    acts.iter().any(f)
}

fn find<'a>(acts: &'a [Value], event: &str) -> &'a Value {
    acts.iter().find(|a| a["event"] == event).unwrap_or_else(|| panic!("no {event} in {acts:?}"))
}

/// One provider with an open ch2, a client, 10 calls and one routed lock (ch2 carries a signed state).
struct W {
    chain: Arc<MemChain>,
    hub: Arc<RouteHub>,
    origin: String,
    prov: Arc<Provider>,
    _pay: Arc<RoutePayer>,
    _dir: TempDir,
}

impl W {
    fn new() -> Self {
        let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
        let h = Arc::new(RouteHub::new(chain.clone(), chain.clone(), Box::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())),
                                       sk(0x4B4B), NET, Some(&dir.0.join("hub")), hub_cfg()).unwrap());
        net.add(HUB, h.clone());
        let origin = "http://p0.test".to_string();
        let prov = provider(&chain, &net, &dir, &origin);
        h.connect(&origin, None, None).unwrap();
        chain.confirm_all();
        h.watch_tick();
        let c = chain.clone();
        let mut pc = RoutePayerConfig::new(NET);
        pc.expiry_blocks = 8_000;
        let pay = Arc::new(RoutePayer::new(HUB, pc, Arc::new(LocalSigner::new()), Arc::new(ChainWallet(chain.clone())),
                                           Box::new(NetTransport(net.clone())), Box::new(move || Ok(c.height()))));
        pay.open().unwrap();
        let sh = pay.shard(&format!("{origin}/v1/chunk"), "POST").unwrap();
        stream(&pay, &sh, 10);
        assert_eq!(pay.lock(&sh).unwrap().unwrap()["status"], "paid");
        let w = Self { chain, hub: h, origin, prov, _pay: pay, _dir: dir };
        assert!(w.oc().signed >= w.oc().params.min_amount());
        w
    }

    fn oc(&self) -> OutChannel {
        self.hub.out_channels()[&self.origin].clone()
    }

    fn events(&self, name: &str) -> Vec<Value> {
        self.hub.events.lock().unwrap().iter().filter(|e| e["event"] == name).cloned().collect()
    }

    /// The provider closes ch2 on its own (its best state).
    fn provider_closes(&self) -> String {
        let st = self.prov.channel_ids().iter().filter_map(|c| self.prov.channel_state(c)).find(|s| s.closed_txid.is_empty()).unwrap();
        self.prov.close_now(&st.params.channel_id()).unwrap()
    }

    /// ch2 refunded at expiry + grace (the provider never closed).
    fn refunded(&self) -> OutChannel {
        self.chain.set_height(self.oc().params.expiry + self.hub.cfg.refund_grace_blocks);
        self.hub.watch_tick();
        let oc = self.oc();
        assert_eq!(oc.state, "refunded");
        assert!(oc.refund_fee > 0);
        oc
    }
}

// --- 1 refill hook, late-bound ------------------------------------------------------------------------

type Calls = Arc<Mutex<Vec<String>>>;

fn recording(tag: &'static str, calls: &Calls) -> xbt402::hub::RefillFn {
    let c = calls.clone();
    Box::new(move |_, o| {
        c.lock().unwrap().push(format!("{tag} {o}"));
        Ok(())
    })
}

#[test]
fn refill_is_looked_up_at_call_time() {
    let w = W::new();
    let calls: Calls = Arc::default();
    w.hub.set_refill(Some(recording("first", &calls)));
    w.hub.set_refill(Some(recording("second", &calls))); // replaced after construction and after a first hook
    let ev = w.hub.close_ch2(&w.oc(), true).unwrap();
    assert_eq!(*calls.lock().unwrap(), vec![format!("second {}", w.origin)]);
    assert!(ev.get("refillError").is_none(), "{ev}");
}

#[test]
fn refill_a_hook_set_to_none_falls_back_to_connect() {
    let w = W::new();
    let calls: Calls = Arc::default();
    w.hub.set_refill(Some(recording("hook", &calls)));
    w.hub.set_refill(None); // back to the default: connect
    let old = w.oc();
    let ev = w.hub.close_ch2(&old, true).unwrap();
    assert!(ev.get("refillError").is_none(), "{ev}");
    assert!(calls.lock().unwrap().is_empty());
    let new = w.oc();
    assert_ne!(new.params.payer_pub, old.params.payer_pub);
    assert_eq!(new.state, "funded");
}

#[test]
fn refill_a_hook_may_replace_the_hook_while_it_runs() {
    // before AGP-045 the hook ran under the refill mutex: this deadlocked
    let w = W::new();
    let calls: Calls = Arc::default();
    let (c, c2) = (calls.clone(), calls.clone());
    w.hub.set_refill(Some(Box::new(move |hub: &RouteHub, o: &str| {
        c.lock().unwrap().push(format!("first {o}"));
        let c3 = c2.clone();
        hub.set_refill(Some(Box::new(move |_, o| {
            c3.lock().unwrap().push(format!("second {o}"));
            Ok(())
        })));
        Ok(())
    })));
    let (tx, rx) = mpsc::channel();
    let (hub, oc) = (w.hub.clone(), w.oc());
    std::thread::spawn(move || {
        let _ = tx.send(hub.close_ch2(&oc, true).map(|_| ()));
    });
    rx.recv_timeout(Duration::from_secs(20)).expect("close_ch2 deadlocked in the refill hook").unwrap();
    assert_eq!(*calls.lock().unwrap(), vec![format!("first {}", w.origin)]);
    // the replacement is the hook now: the provider answers a second close with the same close
    w.hub.close_ch2(&w.oc(), true).unwrap();
    assert_eq!(*calls.lock().unwrap(), vec![format!("first {}", w.origin), format!("second {}", w.origin)]);
}

// --- 2 funding reconcile ---------------------------------------------------------------------------------

/// A fund wallet over the chain whose `fund` broadcasts (with `confirmations`, or not at all), then
/// fails, as a wallet call that times out after `sendtoaddress`; the wallet view is the chain's.
struct FailingWallet {
    chain: Arc<MemChain>,
    broadcast: Option<u32>,
    sent: Arc<Mutex<Vec<(String, u32)>>>,
}

impl Wallet for FailingWallet {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        match self.broadcast {
            Some(conf) => {
                self.sent.lock().unwrap().push(self.chain.fund_with(address, sats, conf)?);
                Err(ChannelError::new("rpc_error", "gettransaction: timeout"))
            }
            None => Err(ChannelError::new("rpc_error", "Insufficient funds")),
        }
    }

    fn wallet_sends_to(&self, address: &str) -> Result<Vec<String>> {
        self.chain.wallet_sends_to(address)
    }

    fn wallet_send(&self, txid: &str, address: &str) -> Result<Option<WalletSend>> {
        self.chain.wallet_send(txid, address)
    }
}

/// The chain without `scantxoutset` (a node or backend without it).
struct NoScan(Arc<MemChain>);

impl SpendScan for NoScan {
    fn find_spend(&self, txid: &str, vout: u32, from: u32) -> Result<Option<xbt_primitives::tx::Tx>> {
        self.0.find_spend(txid, vout, from)
    }

    fn scan_spk(&self, _spk: &[u8]) -> Result<Vec<(String, u32, u64)>> {
        Err(ChannelError::new("rpc_error", "Method not found"))
    }

    fn in_mempool(&self, txid: &str) -> Result<bool> {
        self.0.in_mempool(txid)
    }
}

struct F {
    chain: Arc<MemChain>,
    net: Arc<MemNet>,
    dir: TempDir,
    origin: String,
    sent: Arc<Mutex<Vec<(String, u32)>>>,
}

fn f() -> F {
    let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
    let origin = "http://p0.test".to_string();
    provider(&chain, &net, &dir, &origin);
    F { chain, net, dir, origin, sent: Arc::default() }
}

impl F {
    fn hub_with(&self, broadcast: Option<u32>, scan: Arc<dyn SpendScan>) -> RouteHub {
        let wallet = FailingWallet { chain: self.chain.clone(), broadcast, sent: self.sent.clone() };
        RouteHub::new(self.chain.clone(), scan, Box::new(wallet), Box::new(NetTransport(self.net.clone())), sk(0x4B4B), NET,
                      Some(&self.dir.0.join("hub")), hub_cfg()).unwrap()
    }

    fn hub(&self, broadcast: Option<u32>) -> RouteHub {
        self.hub_with(broadcast, self.chain.clone())
    }

    fn funding_failed(&self, h: &RouteHub) -> OutChannel {
        assert_eq!(h.connect(&self.origin, None, None).unwrap_err().code, "fund_failed");
        h.out_channels()[&self.origin].clone()
    }

    fn txid(&self) -> String {
        self.sent.lock().unwrap()[0].0.clone()
    }

    fn last(h: &RouteHub) -> Value {
        h.archived().last().cloned().unwrap()
    }

    fn events(h: &RouteHub, name: &str) -> usize {
        h.events.lock().unwrap().iter().filter(|e| e["event"] == name).count()
    }
}

fn on_disk(dir: &Path) -> Value {
    serde_json::from_slice::<Value>(&std::fs::read(dir.join("hub").join("ch2.json")).unwrap()).unwrap()
}

#[test]
fn funding_slow_in_the_mempool_past_the_timeout_is_recovered_not_dropped() {
    // the old reconcile read scantxoutset only (confirmed outputs): a funding still in the mempool at
    // funding_timeout_blocks was dropped and never refunded
    let s = f();
    let h = s.hub(Some(0));
    s.funding_failed(&h);
    s.chain.set_height(s.chain.height() + h.cfg.funding_timeout_blocks + 3); // past the timeout, still unconfirmed
    let acts = h.watch_tick();
    assert!(has(&acts, |a| a["event"] == "ch2_funding_recovered"), "{acts:?}");
    assert_eq!(F::events(&h, "ch2_funding_dropped"), 0);
    let oc = h.out_channels()[&s.origin].clone();
    assert_eq!(((oc.params.funding_txid(), oc.params.funding_vout()), oc.state.as_str()), (s.sent.lock().unwrap()[0].clone(), "funded"));
    assert_eq!(h.committed_sat(), 100_000);
    h.watch_tick();
    assert_eq!(h.out_channels()[&s.origin].state, "funded"); // the open waits for minConf
    s.chain.mine(1);
    h.watch_tick();
    assert_eq!(h.out_channels()[&s.origin].state, "open");
}

#[test]
fn funding_slow_confirmation_after_eviction_is_watched_and_refunded_at_expiry() {
    let s = f();
    let h = s.hub(Some(0));
    let oc = s.funding_failed(&h);
    let txid = s.txid();
    s.chain.evict(&txid); // out of the mempool; the wallet still knows it
    s.chain.set_height(s.chain.height() + h.cfg.funding_timeout_blocks);
    let acts = h.watch_tick();
    assert_eq!(find(&acts, "ch2_funding_dropped")["watching"], txid.as_str());
    assert!(!h.out_channels().contains_key(&s.origin));
    let rec = F::last(&h);
    assert_eq!((rec["state"].as_str(), rec["fund_txid"].as_str(), rec["final"].as_bool()), (Some("dropped"), Some(txid.as_str()), Some(false)));
    drop(h);
    let h = s.hub(Some(0)); // a restart keeps watching it
    assert!(h.watch_tick().is_empty());
    s.chain.confirm_late(&txid);
    let acts = h.watch_tick();
    let late = find(&acts, "ch2_funding_late");
    assert_eq!((late["txid"].as_str(), late["capacity"].as_u64()), (Some(txid.as_str()), Some(100_000)));
    let rec = OutChannel::from_json(&F::last(&h)).unwrap();
    assert_eq!((rec.state.as_str(), rec.secret.as_str(), rec.params.funding_txid()), ("funded", oc.secret.as_str(), txid.clone()));
    s.chain.set_height(rec.params.expiry); // never opened: refunded at expiry
    let acts = h.watch_tick();
    let refund = find(&acts, "ch2_refund")["txid"].as_str().unwrap().to_string();
    assert_eq!(F::last(&h)["state"], "refunded");
    s.chain.mine(1);
    let acts = h.watch_tick();
    assert!(has(&acts, |a| a["event"] == "ch2_refund_confirmed" && a["txid"] == refund.as_str()), "{acts:?}");
    assert_eq!(F::last(&h)["final"], true);
    let spk = s.chain.raw(&refund).unwrap().outputs[0].script_pubkey.clone();
    assert_eq!(&spk[..2], &[0x00, 0x14]); // back to a key the hub holds
}

#[test]
fn funding_a_failed_send_is_dropped_and_final() {
    let s = f();
    let h = s.hub(None);
    s.funding_failed(&h);
    assert!(h.watch_tick().is_empty());
    s.chain.set_height(s.chain.height() + h.cfg.funding_timeout_blocks);
    let acts = h.watch_tick();
    assert!(find(&acts, "ch2_funding_dropped").get("watching").is_none());
    let rec = F::last(&h);
    assert_eq!((rec["state"].as_str(), rec["final"].as_bool()), (Some("dropped"), Some(true)));
    let n = h.events.lock().unwrap().len();
    h.watch_tick();
    assert_eq!(h.events.lock().unwrap().len(), n); // not watched
}

#[test]
fn funding_a_conflicted_send_is_dropped_and_final() {
    let s = f();
    let h = s.hub(Some(0));
    s.funding_failed(&h);
    s.chain.conflict(&s.txid()); // double-spent by a confirmed tx
    s.chain.set_height(s.chain.height() + h.cfg.funding_timeout_blocks);
    let acts = h.watch_tick();
    assert!(find(&acts, "ch2_funding_dropped").get("watching").is_none());
    assert_eq!(F::last(&h)["final"], true);
}

#[test]
fn funding_an_abandoned_dropped_send_stops_being_watched() {
    let s = f();
    let h = s.hub(Some(0));
    s.funding_failed(&h);
    let txid = s.txid();
    s.chain.evict(&txid);
    s.chain.set_height(s.chain.height() + h.cfg.funding_timeout_blocks);
    h.watch_tick();
    assert_eq!(F::last(&h)["final"], false);
    s.chain.abandon(&txid); // the operator gives up on it
    let acts = h.watch_tick();
    let ev = find(&acts, "ch2_funding_failed");
    assert_eq!((ev["txid"].as_str(), ev["why"].as_str()), (Some(txid.as_str()), Some("abandoned")));
    assert_eq!(F::last(&h)["final"], true);
    let n = h.events.lock().unwrap().len();
    h.watch_tick();
    assert_eq!(h.events.lock().unwrap().len(), n);
}

#[test]
fn funding_found_by_the_wallet_when_scantxoutset_is_missing() {
    let s = f();
    let h = s.hub_with(Some(6), Arc::new(NoScan(s.chain.clone())));
    s.funding_failed(&h);
    let acts = h.watch_tick();
    let txid = s.txid();
    assert!(has(&acts, |a| a["event"] == "ch2_funding_recovered" && a["txid"] == txid.as_str()), "{acts:?}");
}

#[test]
fn funding_mempool_entry_keeps_a_send_whose_output_is_not_visible() {
    // getmempoolentry: a send the node holds in its mempool is the one kept watching, even when the
    // wallet lists an older, evicted send to the same address first
    let s = f();
    let h = s.hub(Some(0));
    let oc = s.funding_failed(&h);
    let old = s.txid();
    s.chain.evict(&old);
    let addr = xbt_primitives::address::segwit_address("bcrt", &oc.params.spk()).unwrap();
    let (new, _) = s.chain.fund_with(&addr, 100_000, 0).unwrap();
    s.chain.hide_outputs(&new);
    s.chain.set_height(s.chain.height() + h.cfg.funding_timeout_blocks);
    let acts = h.watch_tick();
    assert_eq!(find(&acts, "ch2_funding_dropped")["watching"], new.as_str());
}

// --- 3 close on confirmed spenders only --------------------------------------------------------------------

#[test]
fn close_a_mempool_spender_is_closing_and_keeps_the_refund_fee_booked() {
    let w = W::new();
    let oc = w.refunded();
    let fee = w.hub.refund_fees_sat();
    assert_eq!(fee, oc.refund_fee);
    w.chain.evict(&oc.refund_txid);
    let close = w.provider_closes();
    let acts = w.hub.watch_tick();
    let ev = find(&acts, "ch2_closing");
    assert_eq!((ev["txid"].as_str(), ev["refundAtRisk"].as_str()), (Some(close.as_str()), Some(oc.refund_txid.as_str())));
    let c = w.oc();
    assert_eq!((c.state.as_str(), c.close_txid.as_str(), c.close_prev.as_str(), c.final_), ("closing", close.as_str(), "refunded", false));
    assert_eq!(w.hub.refund_fees_sat(), fee); // booked until the close confirms
    assert!(w.events("ch2_closed").is_empty());
    w.hub.watch_tick();
    assert_eq!(w.events("ch2_closing").len(), 1); // no repeat while it waits
    w.chain.mine(1);
    let acts = w.hub.watch_tick();
    let ev = find(&acts, "ch2_closed");
    assert_eq!((ev["txid"].as_str(), ev["refundFeeReverted"].as_u64()), (Some(close.as_str()), Some(fee)));
    let c = w.oc();
    assert_eq!((c.state.as_str(), c.final_, w.hub.refund_fees_sat()), ("closed", true, 0));
}

#[test]
fn close_a_vanished_mempool_close_rebooks_the_refund_fee() {
    let w = W::new();
    let oc = w.refunded();
    let (fee, refund) = (oc.refund_fee, oc.refund_txid.clone());
    w.chain.evict(&refund);
    let close = w.provider_closes();
    w.hub.watch_tick();
    assert_eq!(w.oc().state, "closing");
    w.chain.evict(&close); // the close leaves the mempool
    let acts = w.hub.watch_tick();
    let ev = find(&acts, "ch2_close_vanished");
    assert_eq!((ev["txid"].as_str(), ev["state"].as_str(), ev["feeRebooked"].as_u64()), (Some(close.as_str()), Some("refunded"), Some(fee)));
    assert!(has(&acts, |a| a["event"] == "ch2_refund_rebroadcast" && a["txid"] == refund.as_str()), "{acts:?}");
    let c = w.oc();
    assert_eq!((c.state.as_str(), c.close_txid.as_str(), w.hub.refund_fees_sat()), ("refunded", "", fee));
    w.chain.mine(1);
    let acts = w.hub.watch_tick();
    assert!(has(&acts, |a| a["event"] == "ch2_refund_confirmed" && a["txid"] == refund.as_str()), "{acts:?}");
    let c = w.oc();
    assert_eq!((c.state.as_str(), c.final_, w.hub.refund_fees_sat()), ("refunded", true, fee));
}

#[test]
fn close_an_unrefunded_ch2_whose_close_vanished_stays_closing_and_is_refunded_at_expiry() {
    let w = W::new();
    let close = w.provider_closes();
    w.hub.watch_tick();
    assert_eq!((w.oc().state.as_str(), w.oc().close_prev.as_str()), ("closing", "open"));
    w.chain.evict(&close);
    let acts = w.hub.watch_tick();
    assert_eq!(find(&acts, "ch2_close_vanished")["state"], "closing");
    assert_eq!((w.oc().state.as_str(), w.oc().close_txid.as_str()), ("closing", ""));
    assert_eq!(w.hub.committed_sat(), 0); // never routed or rolled over again
    w.hub.watch_tick();
    assert_eq!(w.events("ch2_close_vanished").len(), 1);
    w.chain.set_height(w.oc().params.expiry + w.hub.cfg.refund_grace_blocks);
    let acts = w.hub.watch_tick();
    assert!(has(&acts, |a| a["event"] == "ch2_refund"), "{acts:?}");
    assert_eq!(w.oc().state, "refunded");
}

#[test]
fn close_ch2_reply_is_closing_until_the_close_confirms() {
    let w = W::new();
    let ev = w.hub.close_ch2(&w.oc(), false).unwrap();
    let txid = ev["txid"].as_str().unwrap().to_string();
    let c = w.oc();
    assert_eq!((c.state.as_str(), c.close_txid.as_str(), c.close_prev.as_str()), ("closing", txid.as_str(), "open"));
    w.hub.watch_tick();
    assert_eq!((w.oc().state.as_str(), w.oc().final_), ("closing", false));
    assert!(w.events("ch2_closed").is_empty());
    w.chain.mine(1);
    let acts = w.hub.watch_tick();
    assert!(has(&acts, |a| a["event"] == "ch2_closed" && a["txid"] == txid.as_str()), "{acts:?}");
    assert_eq!((w.oc().state.as_str(), w.oc().final_), ("closed", true));
}

#[test]
fn close_a_closing_ch2_is_not_live_and_a_refill_funds_the_next() {
    let w = W::new();
    let old = w.oc();
    w.hub.close_ch2(&old, true).unwrap();
    let new = w.oc();
    assert_ne!(new.params.payer_pub, old.params.payer_pub);
    assert_eq!(new.state, "funded");
    let arch = w.hub.archived().last().cloned().unwrap();
    assert_eq!((arch["state"].as_str(), arch["params"]["funding_txid"].as_str()), (Some("closing"), Some(old.params.funding_txid().as_str())));
    w.chain.mine(1);
    w.hub.watch_tick(); // the archived one is still reconciled
    let arch = w.hub.archived().into_iter().find(|r| r["params"]["funding_txid"] == old.params.funding_txid().as_str()).unwrap();
    assert_eq!((arch["state"].as_str(), arch["final"].as_bool()), (Some("closed"), Some(true)));
}

#[test]
fn close_fields_round_trip() {
    let w = W::new();
    w.hub.close_ch2(&w.oc(), false).unwrap();
    let rec = on_disk(&w._dir.0)["chans"][&w.origin].clone();
    assert_eq!((rec["state"].as_str(), rec["close_prev"].as_str()), (Some("closing"), Some("open")));
    assert!(rec.get("fund_txid").is_some() && rec.get("fund_vout").is_some());
    let back = OutChannel::from_json(&rec).unwrap();
    assert_eq!(back.to_json(), rec);
}
