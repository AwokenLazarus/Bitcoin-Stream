//! AGP-037: RouteHub money safety (a port of B1 `tests/security/test_agp037_hub_money_safety.py`),
//! in process: [`MemChain`] + [`MemNet`]. One section per item of the task:
//! 1 write-ahead ch2 (fund hook failures, restart, drop, the rollover's next ch2); 2 every non-final
//! ch2 reconciled each tick; 3 refunds at a hub fee, watched, rebroadcast, and a provider close that
//! beats one; 4 close_ch2 checks the provider's reply; 5 hostile /terms refused before funding;
//! 6 the refill hook; 7 one failing ch2 never stops the watcher.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::adaptor::{self, Sc};
use xbt402::channel::{FeePayer, DUST};
use xbt402::client::Wallet;
use xbt402::error::{ChannelError, Result};
use xbt402::funding::{ChainBackend, FundingPolicy, UtxoInfo};
use xbt402::http::HttpService;
use xbt402::hub::{HubConfig, OutChannel, RouteHub, LIVE};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route::{SpendScan, ROLLOVER_PATH, ROUTE_LOCK_PATH, TERMS_PATH};
use xbt402::route_client::{RoutePayer, RoutePayerConfig, Shard};
use xbt402::route_seller::RouteOffer;
use xbt402::signer::LocalSigner;
use xbt402_interop::memnet::{ChainWallet, MemChain, MemNet, NetTransport};
use xbt_primitives::address::{address_to_spk, segwit_address};
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

const NET: &str = "bip122:11111111111111111111111111111111";
const HUB: &str = "http://hub.test";

fn sk(n: u64) -> SecretKey {
    Sc::from_u64(n).secret().unwrap()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("xbt-rs-agp037-{}", hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..8])));
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

type FundFn = Box<dyn Fn(&str, u64) -> Result<(String, u32)> + Send + Sync>;

/// A wallet hook: a closure over (address, sats).
struct FnWallet(FundFn);

impl Wallet for FnWallet {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        (self.0)(address, sats)
    }
}

/// The chain with `gettxout` failing for one txid (a node hiccup on one channel).
struct Flaky {
    chain: Arc<MemChain>,
    bad: Mutex<String>,
}

impl ChainBackend for Flaky {
    fn block_count(&self) -> Result<u32> {
        self.chain.block_count()
    }

    fn get_tx_out(&self, txid: &str, vout: u32, m: bool) -> Result<Option<UtxoInfo>> {
        if *self.bad.lock().unwrap() == txid {
            return Err(ChannelError::new("rpc_error", "node hiccup"));
        }
        self.chain.get_tx_out(txid, vout, m)
    }

    fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        self.chain.send_raw_transaction(hex)
    }

    fn has_transaction(&self, txid: &str) -> Result<bool> {
        self.chain.has_transaction(txid)
    }
}

impl SpendScan for Flaky {
    fn find_spend(&self, txid: &str, vout: u32, from: u32) -> Result<Option<Tx>> {
        self.chain.find_spend(txid, vout, from)
    }

    fn scan_spk(&self, spk: &[u8]) -> Result<Vec<(String, u32, u64)>> {
        self.chain.scan_spk(spk)
    }

    fn fee_rate(&self, target: u32) -> Result<Option<f64>> {
        self.chain.fee_rate(target)
    }
}

type Edit = Box<dyn Fn(&str, &str, u16, &Value) -> Option<(u16, Vec<u8>)> + Send + Sync>;

/// A provider app whose answers `edit(method, path, status, doc)` may rewrite.
struct Wrap {
    app: Arc<Provider>,
    edit: Edit,
}

impl HttpService for Wrap {
    fn body_limit(&self, path: &str) -> usize {
        HttpService::body_limit(&*self.app, path)
    }

    fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str) -> HttpResponse {
        let r = HttpService::serve(&*self.app, method, path, headers, body, url);
        let doc: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        match (self.edit)(method, path, r.status, &doc) {
            Some((st, b)) => HttpResponse::new(st, vec![("Content-Type".into(), "application/json".into())], b),
            None => r,
        }
    }
}

fn wrap(net: &MemNet, origin: &str, app: &Arc<Provider>, edit: Edit) {
    net.add(origin, Arc::new(Wrap { app: app.clone(), edit }));
}

fn terms_edit(extra: Value) -> Edit {
    Box::new(move |_, p, _, doc| {
        if p != TERMS_PATH {
            return None;
        }
        let mut d = doc.clone();
        for (k, v) in extra.as_object().unwrap() {
            d["extra"][k] = v.clone();
        }
        Some((200, serde_json::to_vec(&d).unwrap()))
    })
}

fn stream(pay: &RoutePayer, sh: &Arc<Shard>, n: usize) {
    for _ in 0..n {
        let r = pay.call(sh, "POST", br#"{"tokens":1}"#).unwrap();
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    }
}

struct W {
    chain: Arc<MemChain>,
    net: Arc<MemNet>,
    hub: Arc<RouteHub>,
    provs: Vec<(String, Arc<Provider>)>,
    pay: Arc<RoutePayer>,
    shards: Vec<Arc<Shard>>,
    flaky: Arc<Flaky>,
    _dir: TempDir,
}

impl W {
    /// `n` providers with open ch2s, a client, 10 calls to p0, and (with `lock_first`) one routed
    /// lock so p0's ch2 carries a signed state.
    fn new(n: usize, lock_first: bool) -> Self {
        let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
        let flaky = Arc::new(Flaky { chain: chain.clone(), bad: Mutex::new(String::new()) });
        let h = Arc::new(RouteHub::new(flaky.clone(), flaky.clone(), Box::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())),
                                       sk(0x4B4B), NET, Some(&dir.0.join("hub")), hub_cfg()).unwrap());
        net.add(HUB, h.clone());
        let mut provs = vec![];
        for i in 0..n {
            let origin = format!("http://p{i}.test");
            provs.push((origin.clone(), provider(&chain, &net, &dir, &origin)));
            h.connect(&origin, None, None).unwrap();
        }
        chain.confirm_all();
        h.watch_tick();
        let c = chain.clone();
        let mut pc = RoutePayerConfig::new(NET);
        pc.expiry_blocks = 8_000;
        let pay = Arc::new(RoutePayer::new(HUB, pc, Arc::new(LocalSigner::new()), Arc::new(ChainWallet(chain.clone())),
                                           Box::new(NetTransport(net.clone())), Box::new(move || Ok(c.height()))));
        pay.open().unwrap();
        let shards: Vec<_> = provs.iter().map(|(o, _)| pay.shard(&format!("{o}/v1/chunk"), "POST").unwrap()).collect();
        stream(&pay, &shards[0], 10);
        let w = Self { chain, net, hub: h, provs, pay, shards, flaky, _dir: dir };
        if lock_first {
            assert_eq!(w.pay.lock(&w.shards[0]).unwrap().unwrap()["status"], "paid");
            assert!(w.oc(0).signed >= w.oc(0).params.min_amount());
        }
        w
    }

    fn origin(&self, i: usize) -> &str {
        &self.provs[i].0
    }

    fn oc(&self, i: usize) -> OutChannel {
        self.hub.out_channels()[self.origin(i)].clone()
    }

    fn events(&self, name: &str) -> Vec<Value> {
        self.hub.events.lock().unwrap().iter().filter(|e| e["event"] == name).cloned().collect()
    }

    /// The provider closes ch2 on its own (its best state), as at expiry − closeMargin.
    fn provider_closes(&self, i: usize) -> String {
        let p = &self.provs[i].1;
        let st = p.channel_ids().iter().filter_map(|c| p.channel_state(c)).find(|s| s.closed_txid.is_empty()).unwrap();
        p.close_now(&st.params.channel_id()).unwrap()
    }
}

fn has(acts: &[Value], f: impl Fn(&Value) -> bool) -> bool {
    acts.iter().any(f)
}

// --- 1 write-ahead ch2 ------------------------------------------------------------------------------

struct Solo {
    chain: Arc<MemChain>,
    net: Arc<MemNet>,
    dir: TempDir,
    origin: String,
}

fn solo() -> Solo {
    let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
    let origin = "http://p0.test".to_string();
    provider(&chain, &net, &dir, &origin);
    Solo { chain, net, dir, origin }
}

impl Solo {
    fn hub(&self, wallet: Box<dyn Wallet>, cfg: HubConfig) -> RouteHub {
        RouteHub::new(self.chain.clone(), self.chain.clone(), wallet, Box::new(NetTransport(self.net.clone())), sk(0x4B4B), NET,
                      Some(&self.dir.0.join("hub")), cfg).unwrap()
    }

    fn on_disk(dir: &Path) -> Value {
        serde_json::from_slice::<Value>(&std::fs::read(dir.join("hub").join("ch2.json")).unwrap()).unwrap()["chans"].clone()
    }
}

#[test]
fn wa_the_key_is_on_disk_before_fund_runs() {
    let s = solo();
    let seen = Arc::new(Mutex::new(Value::Null));
    let (c, d, sn) = (s.chain.clone(), s.dir.0.clone(), seen.clone());
    let h = s.hub(Box::new(FnWallet(Box::new(move |a, sats| {
        *sn.lock().unwrap() = Solo::on_disk(&d); // what a crash inside fund() would leave
        c.fund(a, sats)
    }))), hub_cfg());
    let oc = h.connect(&s.origin, None, None).unwrap();
    let rec = seen.lock().unwrap()[&s.origin].clone();
    assert_eq!(rec["state"], "funding");
    // sealed (AGP-073 K1): it opens under the data dir's wrap key
    let wrap = xbt402::hub_keys::WrapKey::load_or_create(&s.dir.0.join("hub").join("hub-wrap-key")).unwrap();
    assert!(rec.get("secret").is_none());
    assert_eq!(wrap.open(&rec["secret_sealed"]).unwrap(), oc.secret);
    assert_eq!(rec["params"]["payer_pub"], hex::encode(oc.params.payer_pub));
    assert_eq!(oc.state, "funded");
}

#[test]
fn wa_fund_raising_after_broadcast_is_recovered_after_a_restart_and_refundable() {
    let s = solo();
    let sent = Arc::new(Mutex::new(vec![]));
    let (c, st) = (s.chain.clone(), sent.clone());
    let h = s.hub(Box::new(FnWallet(Box::new(move |a, sats| {
        st.lock().unwrap().push(c.fund(a, sats)?); // broadcast...
        Err(ChannelError::new("rpc_error", "gettransaction: timeout")) // ...then the wallet call fails
    }))), hub_cfg());
    let e = h.connect(&s.origin, None, None).unwrap_err();
    assert_eq!(e.code, "fund_failed");
    assert_eq!(sent.lock().unwrap().len(), 1);
    assert_eq!(Solo::on_disk(&s.dir.0)[&s.origin]["state"], "funding");
    assert_eq!(h.committed_sat(), 100_000); // counted while in flight
    assert_eq!(h.connect(&s.origin, None, None).unwrap_err().code, "ch2_funding");
    drop(h);
    let h2 = s.hub(Box::new(ChainWallet(s.chain.clone())), hub_cfg()); // restart
    let acts = h2.watch_tick();
    assert!(has(&acts, |a| a["event"] == "ch2_funding_recovered"), "{acts:?}");
    let oc = h2.out_channels()[&s.origin].clone();
    assert_eq!((oc.params.funding_txid(), oc.params.funding_vout()), sent.lock().unwrap()[0].clone());
    assert_eq!(oc.state, "funded");
    h2.watch_tick();
    assert_eq!(h2.out_channels()[&s.origin].state, "open");
    assert_eq!(h2.committed_sat(), 100_000);
    s.chain.set_height(oc.params.expiry); // never used: refunded at expiry
    let acts = h2.watch_tick();
    assert!(has(&acts, |a| a["event"] == "ch2_refund"), "{acts:?}");
    assert_eq!((h2.out_channels()[&s.origin].state.as_str(), h2.committed_sat()), ("refunded", 0));
}

#[test]
fn wa_fund_failing_before_broadcast_is_dropped_with_its_key_kept() {
    let s = solo();
    let h = s.hub(Box::new(FnWallet(Box::new(|_, _| Err(ChannelError::new("rpc_error", "Insufficient funds"))))), hub_cfg());
    assert!(h.connect(&s.origin, None, None).is_err());
    let secret = h.out_channels()[&s.origin].secret.clone();
    assert!(h.watch_tick().is_empty()); // not yet: it may still confirm
    s.chain.set_height(s.chain.height() + h.cfg.funding_timeout_blocks);
    let acts = h.watch_tick();
    assert!(has(&acts, |a| a["event"] == "ch2_funding_dropped"), "{acts:?}");
    assert!(!h.out_channels().contains_key(&s.origin));
    assert_eq!(h.committed_sat(), 0);
    let kept: Vec<Value> = h.archived().iter().filter(|r| r["state"] == "dropped").map(|r| r["secret"].clone()).collect();
    assert_eq!(kept, vec![Value::from(secret)]);
}

#[test]
fn wa_the_cap_check_and_the_record_are_one_step() {
    let s = solo();
    provider(&s.chain, &s.net, &s.dir, "http://p1.test");
    let mut cfg = hub_cfg();
    cfg.liquidity_cap_sat = 150_000;
    // the wallet hook connects a second provider while the first is being funded
    let slot: Arc<Mutex<Option<Arc<RouteHub>>>> = Arc::new(Mutex::new(None));
    let (c, sl, refused) = (s.chain.clone(), slot.clone(), Arc::new(AtomicUsize::new(0)));
    let rf = refused.clone();
    let h = Arc::new(s.hub(Box::new(FnWallet(Box::new(move |a, sats| {
        if let Some(h) = sl.lock().unwrap().clone() {
            if h.connect("http://p1.test", None, None).is_err_and(|e| e.code == "liquidity_cap") {
                rf.fetch_add(1, Ordering::SeqCst);
            }
        }
        c.fund(a, sats)
    }))), cfg));
    *slot.lock().unwrap() = Some(h.clone());
    h.connect(&s.origin, None, None).unwrap();
    *slot.lock().unwrap() = None;
    assert_eq!(refused.load(Ordering::SeqCst), 1);
    assert_eq!(h.committed_sat(), 100_000);
}

#[test]
fn wa_a_lost_rollover_answer_is_finished_by_the_watcher() {
    let w = W::new(1, true);
    let oc = w.oc(0);
    w.chain.set_height(oc.params.expiry - 40); // near the close margin: the provider co-signs
    w.net.set_drop(w.origin(0), Some(Box::new(|_, p| p == ROLLOVER_PATH)));
    assert!(w.hub.rollover(&oc).is_err());
    w.net.set_drop(w.origin(0), None);
    assert!(w.chain.spender(&oc.params.funding_txid(), oc.params.funding_vout()).is_some()); // it did broadcast
    let nxt = OutChannel::from_json(&Value::Object(w.oc(0).next.clone())).unwrap();
    assert!(!nxt.secret.is_empty()); // the next ch2's key survived the lost answer
    let acts = w.hub.watch_tick();
    assert!(has(&acts, |a| a["event"] == "ch2_rollover"), "{acts:?}");
    let new = w.oc(0);
    assert_eq!((new.secret.as_str(), new.params.funding_txid()), (nxt.secret.as_str(), nxt.params.funding_txid()));
    assert_eq!(w.hub.archived().last().unwrap()["state"], "rolled");
}

// --- 2 reconcile every non-final ch2 --------------------------------------------------------------

#[test]
fn rc_provider_self_close_of_a_signed_ch2_without_a_lock() {
    let w = W::new(1, true);
    let oc = w.oc(0);
    assert!(oc.pending.is_empty() && oc.stale.is_empty());
    let txid = w.provider_closes(0);
    let acts = w.hub.watch_tick(); // in the mempool: closing (AGP-045)
    assert!(has(&acts, |a| a["event"] == "ch2_closing" && a["txid"] == txid.as_str()), "{acts:?}");
    let oc = w.oc(0);
    assert_eq!((oc.state.as_str(), oc.close_txid.as_str(), oc.final_), ("closing", txid.as_str(), false));
    assert_eq!(w.hub.committed_sat(), 0);
    w.chain.mine(1);
    let acts = w.hub.watch_tick();
    assert!(has(&acts, |a| a["event"] == "ch2_closed" && a["txid"] == txid.as_str()), "{acts:?}");
    assert_eq!((w.oc(0).state.as_str(), w.oc(0).final_), ("closed", true));
    let n = w.hub.events.lock().unwrap().len();
    w.hub.watch_tick(); // final: nothing more, no retries
    assert_eq!(w.hub.events.lock().unwrap().len(), n);
}

#[test]
fn rc_close_reply_without_txid_after_the_provider_closed() {
    let w = W::new(1, true);
    wrap(&w.net, w.origin(0), &w.provs[0].1, Box::new(|_, p, st, doc| {
        (p.ends_with("/close") && st == 200).then(|| {
            let mut d = doc.clone();
            d.as_object_mut().unwrap().remove("txid");
            (200, serde_json::to_vec(&d).unwrap())
        })
    }));
    let e = w.hub.close_ch2(&w.oc(0), false).unwrap_err();
    assert_eq!(e.code, "bad_close_reply");
    assert_eq!(w.oc(0).state, "open"); // a bad reply changes nothing...
    let p = &w.provs[0].1;
    let closed: Vec<String> = p.channel_ids().iter().filter_map(|c| p.channel_state(c)).filter(|s| !s.closed_txid.is_empty()).map(|s| s.closed_txid).collect();
    assert_eq!(closed.len(), 1);
    let acts = w.hub.watch_tick(); // ...the chain does
    assert!(has(&acts, |a| a["event"] == "ch2_closing"), "{acts:?}");
    assert_eq!((w.oc(0).state.as_str(), w.oc(0).close_txid.as_str()), ("closing", closed[0].as_str()));
    w.chain.mine(1);
    w.hub.watch_tick();
    assert_eq!((w.oc(0).state.as_str(), w.oc(0).close_txid.as_str()), ("closed", closed[0].as_str()));
    assert_eq!(w.hub.committed_sat(), 0);
    w.hub.watch_tick();
    assert!(w.events("ch2_watch_error").is_empty());
}

// --- 3 refunds --------------------------------------------------------------------------------------

#[test]
fn rf_unsigned_ch2_refunded_at_expiry_at_the_hub_fee() {
    let w = W::new(2, true);
    let oc = w.oc(1);
    assert_eq!(oc.signed, 0);
    w.chain.set_fee_rate(Some(20.0));
    w.chain.set_height(oc.params.expiry - 1);
    w.hub.watch_tick();
    assert_eq!(w.oc(1).state, "open"); // not before expiry (non-final)
    w.chain.set_height(oc.params.expiry);
    let acts = w.hub.watch_tick();
    let ev = acts.iter().find(|a| a["event"] == "ch2_refund" && a["provider"] == w.origin(1)).expect("refund").clone();
    let oc = w.oc(1);
    let tx = Tx::parse_hex(&oc.refund_hex).unwrap();
    let fee = ev["fee"].as_u64().unwrap();
    assert_eq!(fee, 20 * (tx.vsize() as u64 + 1));
    assert_ne!(fee, oc.params.close_fee); // not the provider's closeFee
    assert_eq!(tx.outputs[0].value as u64, oc.params.capacity - fee);
    assert_eq!((oc.state.as_str(), oc.refund_txid.clone()), ("refunded", tx.txid()));
    assert_eq!(w.hub.committed_sat(), w.oc(0).params.capacity); // only the used ch2 is committed
    assert_eq!(w.hub.refund_fees_sat(), fee);
    w.chain.mine(1);
    let acts = w.hub.watch_tick();
    assert!(has(&acts, |a| a["event"] == "ch2_refund_confirmed"), "{acts:?}");
    assert!(w.oc(1).final_);
}

#[test]
fn rf_refund_fee_floor_without_an_estimate() {
    let w = W::new(2, true);
    w.chain.set_height(w.oc(1).params.expiry);
    w.hub.watch_tick();
    let oc = w.oc(1);
    let vsize = Tx::parse_hex(&oc.refund_hex).unwrap().vsize() as f64;
    assert_eq!(oc.refund_fee, (w.hub.cfg.refund_min_feerate * (vsize + 1.0)).ceil() as u64);
    assert!(oc.params.capacity - oc.refund_fee >= DUST);
}

#[test]
fn rf_refund_pays_the_refund_to_hook() {
    let w = W::new(2, true);
    let spk = hex::decode(format!("0014{}", "ab".repeat(20))).unwrap();
    let addr = segwit_address("bcrt", &spk).unwrap();
    let a2 = addr.clone();
    w.hub.set_refund_to(Some(Box::new(move || Ok(a2.clone()))));
    w.chain.set_height(w.oc(1).params.expiry);
    w.hub.watch_tick();
    let tx = Tx::parse_hex(&w.oc(1).refund_hex).unwrap();
    assert_eq!(tx.outputs[0].script_pubkey, address_to_spk(&addr, Some("bcrt")).unwrap());
}

/// A provider that is gone: every request fails.
struct Down;

impl HttpService for Down {
    fn body_limit(&self, _: &str) -> usize {
        1 << 20
    }

    fn serve(&self, _: &str, _: &str, _: &[(String, String)], _: &[u8], _: &str) -> HttpResponse {
        HttpResponse::new(503, vec![], b"gone".to_vec())
    }
}

#[test]
fn rf_signed_ch2_with_the_provider_gone_is_refunded_after_the_grace() {
    let w = W::new(2, true);
    let oc = w.oc(0);
    w.net.add(w.origin(0), Arc::new(Down));
    w.chain.set_height(oc.params.expiry + w.hub.cfg.refund_grace_blocks - 1);
    w.hub.watch_tick();
    assert_eq!(w.oc(0).state, "open");
    w.chain.set_height(w.chain.height() + 1);
    let acts = w.hub.watch_tick();
    assert!(has(&acts, |a| a["event"] == "ch2_refund" && a["provider"] == w.origin(0)), "{acts:?}");
    assert_eq!(w.oc(0).state, "refunded");
    assert!(!LIVE.contains(&w.oc(0).state.as_str()));
}

#[test]
fn rf_refund_that_left_the_mempool_is_rebroadcast() {
    let w = W::new(2, true);
    w.chain.set_height(w.oc(1).params.expiry);
    w.hub.watch_tick();
    let txid = w.oc(1).refund_txid;
    w.chain.evict(&txid);
    let acts = w.hub.watch_tick();
    let ev = acts.iter().find(|a| a["event"] == "ch2_refund_rebroadcast").expect("rebroadcast");
    assert_eq!(ev["txid"], txid.as_str()); // the same tx, not a new one
    assert!(w.chain.raw(&txid).is_some());
}

#[test]
fn rf_provider_close_beats_the_refund_secret_recovered_fee_reverted() {
    // the written-off lock is ch2's first (floor) state, so its adaptor signature is on the close
    let w = W::new(2, false);
    w.net.set_drop(w.origin(0), Some(Box::new(|_, p| p == ROUTE_LOCK_PATH)));
    w.hub.set_reveal_timeout(0.3);
    assert_eq!(w.pay.lock(&w.shards[0]).unwrap().unwrap()["status"], "refused");
    let oc = w.oc(0);
    assert_eq!(oc.stale.len(), 1);
    let stale_id = oc.stale[0]["lockId"].as_str().unwrap().to_string();
    w.chain.set_height(oc.params.expiry + w.hub.cfg.refund_grace_blocks);
    w.hub.watch_tick();
    assert_eq!(w.oc(0).state, "refunded");
    let refund = w.oc(0).refund_txid;
    w.chain.evict(&refund); // the provider's close replaces it
    w.net.set_drop(w.origin(0), None);
    let close = w.provider_closes(0);
    assert_eq!(w.chain.spender(&oc.params.funding_txid(), oc.params.funding_vout()), Some(close.clone()));
    let fees = w.hub.refund_fees_sat();
    let acts = w.hub.watch_tick(); // the close is in the mempool: the secret is read now
    assert!(has(&acts, |a| a["event"] == "secret_from_close" && a["lockId"] == stale_id.as_str() && a["ch1_completed"] == true), "{acts:?}");
    let oc = w.oc(0);
    assert_eq!((oc.state.as_str(), oc.close_txid.as_str(), oc.stale.len()), ("closing", close.as_str(), 0));
    assert_eq!(w.hub.refund_fees_sat(), fees); // ...but the refund fee stays booked (AGP-045)
    let st1 = w.hub.ch1_state(&w.pay.chan().unwrap()).unwrap();
    assert!(st1.extra["recovered"].as_array().unwrap().iter().any(|r| r["lockId"] == stale_id.as_str()));
    w.chain.mine(1);
    let acts = w.hub.watch_tick();
    let ev = acts.iter().find(|a| a["event"] == "ch2_closed").expect("closed");
    assert_eq!(ev["txid"], close.as_str());
    assert!(ev["refundFeeReverted"].as_u64().unwrap() > 0);
    let oc = w.oc(0);
    assert_eq!((oc.state.as_str(), oc.close_txid.as_str(), oc.final_), ("closed", close.as_str(), true));
    assert_eq!(w.hub.refund_fees_sat(), w.oc(1).refund_fee); // only the idle ch2's
}

// --- 4 close_ch2 validates the provider's reply -------------------------------------------------------

fn bad_reply(edit: fn(&Value) -> Value, why: &str) {
    let w = W::new(1, true);
    wrap(&w.net, w.origin(0), &w.provs[0].1, Box::new(move |_, p, _, doc| p.ends_with("/close").then(|| (200, serde_json::to_vec(&edit(doc)).unwrap()))));
    let e = w.hub.close_ch2(&w.oc(0), false).unwrap_err();
    assert_eq!(e.code, "bad_close_reply");
    assert!(e.to_string().contains(why), "{e}");
    assert_eq!((w.oc(0).state.as_str(), w.oc(0).close_txid.as_str()), ("open", ""));
    w.hub.watch_tick(); // the watcher survives and reconciles
    assert!(w.events("ch2_watch_error").is_empty());
    assert_eq!(w.oc(0).state, "closing"); // the provider's close, in the mempool
    w.chain.mine(1);
    w.hub.watch_tick();
    assert_eq!(w.oc(0).state, "closed");
}

#[test]
fn cr_no_txid() {
    bad_reply(|d| {
        let mut d = d.clone();
        d.as_object_mut().unwrap().remove("txid");
        d
    }, "txid");
}

#[test]
fn cr_txid_not_hex() {
    bad_reply(|d| {
        let mut d = d.clone();
        d["txid"] = "zz".repeat(32).into();
        d
    }, "txid");
}

#[test]
fn cr_cum_not_what_the_hub_signed() {
    bad_reply(|d| {
        let mut d = d.clone();
        d["cum"] = (d["cum"].as_str().unwrap().parse::<u64>().unwrap() + 1).to_string().into();
        d
    }, "cum");
}

#[test]
fn cr_payee_fee_mismatch() {
    bad_reply(|d| {
        let mut d = d.clone();
        d["payeeFee"] = "1".into();
        d
    }, "payeeFee");
}

#[test]
fn cr_not_json() {
    let w = W::new(1, true);
    wrap(&w.net, w.origin(0), &w.provs[0].1, Box::new(|_, p, _, _| p.ends_with("/close").then(|| (200, b"ok".to_vec()))));
    assert_eq!(w.hub.close_ch2(&w.oc(0), false).unwrap_err().code, "bad_close_reply");
}

#[test]
fn cr_a_good_reply_reports_gross_cum_payee_fee_and_net() {
    let w = W::new(1, true);
    let oc = w.oc(0);
    let ev = w.hub.close_ch2(&oc, false).unwrap();
    let p = &oc.params;
    assert_eq!(p.close_fee_payer, FeePayer::Payee);
    assert_eq!((ev["amount"].as_u64(), ev["payeeFee"].as_u64(), ev["payeeNet"].as_u64()), (Some(oc.signed), Some(p.close_fee), Some(oc.signed - p.close_fee)));
    assert_eq!(ev["chan"], p.channel_id().as_str());
    assert_eq!((w.oc(0).state.as_str(), w.oc(0).close_txid.as_str()), ("closing", ev["txid"].as_str().unwrap())); // closed once it confirms (AGP-045)
    w.chain.mine(1);
    w.hub.watch_tick();
    assert_eq!((w.oc(0).state.as_str(), w.oc(0).final_), ("closed", true));
}

// --- 5 bounded /terms ---------------------------------------------------------------------------------

fn hostile(extra: Value, cfg: HubConfig) -> String {
    let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
    let origin = "http://evil.test";
    let prov = provider(&chain, &net, &dir, origin);
    wrap(&net, origin, &prov, terms_edit(extra));
    let funded = Arc::new(AtomicUsize::new(0));
    let (c, f) = (chain.clone(), funded.clone());
    let h = RouteHub::new(chain.clone(), chain.clone(), Box::new(FnWallet(Box::new(move |a, s| {
        f.fetch_add(1, Ordering::SeqCst);
        c.fund(a, s)
    }))), Box::new(NetTransport(net.clone())), sk(0x4B4B), NET, Some(&dir.0.join("hub")), cfg).unwrap();
    let e = h.connect(origin, None, None).unwrap_err();
    assert_eq!(e.code, "bad_terms", "{e}");
    assert_eq!((funded.load(Ordering::SeqCst), h.out_channels().len(), h.committed_sat()), (0, 0, 0));
    e.to_string()
}

#[test]
fn ht_close_fee_19990() {
    hostile(json!({"closeFeeSat": 19_990}), hub_cfg());
}

#[test]
fn ht_close_fee_25000_over_capacity() {
    hostile(json!({"closeFeeSat": 25_000}), hub_cfg());
}

#[test]
fn ht_the_close_fee_multiple_bounds_capacity() {
    let mut cfg = hub_cfg();
    cfg.ch2_max_close_fee_sat = 10_000;
    assert!(hostile(json!({"closeFeeSat": 6_000}), cfg).contains("x closeFeeSat"));
}

#[test]
fn ht_min_expiry_5e6() {
    hostile(json!({"minExpiryBlocks": 5_000_000, "maxExpiryBlocks": 6_000_000}), hub_cfg());
}

#[test]
fn ht_min_conf_1e9() {
    hostile(json!({"minConf": 1_000_000_000u64}), hub_cfg());
}

#[test]
fn ht_min_capacity_huge() {
    hostile(json!({"minCapacity": 1_000_000_000u64}), hub_cfg());
}

#[test]
fn ht_settle_multiple_huge() {
    hostile(json!({"settleMultiple": 1_000_000_000u64}), hub_cfg());
}

#[test]
fn ht_malformed() {
    hostile(json!({"closeFeeSat": "lots"}), hub_cfg());
}

#[test]
fn ht_a_close_fee_within_both_bounds_is_funded_and_fair_expiry_clamped() {
    let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
    let origin = "http://ok.test";
    let prov = provider(&chain, &net, &dir, origin);
    wrap(&net, origin, &prov, terms_edit(json!({"closeFeeSat": 4_000})));
    let mut cfg = hub_cfg();
    cfg.ch2_max_close_fee_sat = 10_000;
    cfg.ch2_expiry_blocks = 5_000;
    cfg.ch2_max_expiry_blocks = 2_000;
    let h = RouteHub::new(chain.clone(), chain.clone(), Box::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())), sk(0x4B4B), NET,
                          Some(&dir.0.join("hub")), cfg).unwrap();
    let oc = h.connect(origin, None, None).unwrap();
    assert_eq!(oc.params.close_fee, 4_000); // 20 x 4000 <= 100000
    assert_eq!(oc.params.expiry, chain.height() + 2_000); // the hub's max, not the provider's 8640
}

// --- 6 refill hook ------------------------------------------------------------------------------------

#[test]
fn rh_refill_goes_through_the_hook() {
    let w = W::new(1, true);
    let calls = Arc::new(Mutex::new(vec![]));
    let c = calls.clone();
    w.hub.set_refill(Some(Box::new(move |_, o| {
        c.lock().unwrap().push(o.to_string());
        Ok(())
    })));
    w.hub.close_ch2(&w.oc(0), true).unwrap();
    assert_eq!(*calls.lock().unwrap(), vec![w.origin(0).to_string()]);
}

#[test]
fn rh_default_refill_is_connect_with_its_terms_checks() {
    let w = W::new(1, true);
    wrap(&w.net, w.origin(0), &w.provs[0].1, terms_edit(json!({"closeFeeSat": 25_000}))); // terms turned hostile
    let ev = w.hub.close_ch2(&w.oc(0), true).unwrap();
    assert!(ev["refillError"].as_str().unwrap().contains("bad_terms"), "{ev}");
    assert_eq!(w.oc(0).state, "closing"); // the close stands
    assert!(!w.events("ch2_refill_failed").is_empty());
}

// --- 7 watcher robustness -----------------------------------------------------------------------------

#[test]
fn wr_one_failing_ch2_never_stops_the_others() {
    let w = W::new(2, true);
    *w.flaky.bad.lock().unwrap() = w.oc(0).params.funding_txid();
    w.chain.set_height(w.oc(1).params.expiry);
    let acts = w.hub.watch_tick();
    assert!(has(&acts, |a| a["event"] == "ch2_refund" && a["provider"] == w.origin(1)), "{acts:?}");
    let errs = w.events("ch2_watch_error");
    assert!(!errs.is_empty() && errs.iter().all(|e| e["provider"] == w.origin(0)), "{errs:?}");
}

#[test]
fn wr_config_keys_round_trip() {
    let c = HubConfig::from_json(&json!({"ch2_max_close_fee_sat": 1, "ch2_max_min_conf": 2, "refund_min_feerate": 2.5,
                                          "refund_grace_blocks": 3, "funding_timeout_blocks": 4, "ch2_max_expiry_blocks": 5})).unwrap();
    assert_eq!((c.ch2_max_close_fee_sat, c.ch2_max_min_conf, c.refund_min_feerate, c.refund_grace_blocks, c.funding_timeout_blocks, c.ch2_max_expiry_blocks),
               (1, 2, 2.5, 3, 4, 5));
}
