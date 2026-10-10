//! AGP-073: the hub follow-ups AGP-063 and AGP-064 left, in process ([`MemChain`] + [`MemNet`]).
//! B1 has the same tests (`tests/security/test_agp073_hub_followups.py`).
//!
//! * K1: the hub's state file (`ch2.json`) held every ch2 payer key in plaintext.
//! * A ch2 with a written-off lock (the provider refused or timed out after the pre-signature left)
//!   was blocked for its whole life, until its close or its refund at expiry.
//! * A ch1 lock a hub crash left (written ahead, never on ch2) was dropped only on ch1's close path,
//!   and that path dropped a lock whose ch2 had already written it off (pre-signature out).
//! * The routed funders (`RoutePayer::open`, the hub's ch2 funding) broadcast before `/open`.
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use serde_json::{json, Value};
use xbt402::adaptor;
use xbt402::adaptor::Sc;
use xbt402::channel::FeePayer;
use xbt402::client::{Wallet, WalletSend};
use xbt402::error::Result;
use xbt402::funding::FundingPolicy;
use xbt402::http::HttpService;
use xbt402::hub::{HubConfig, RouteHub};
use xbt402::hub_keys::WrapKey;
use xbt402::json::truthy;
use xbt402::ledger::{ChannelState, Ledger};
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route::ROUTE_LOCK_PATH;
use xbt402::route_client::{RoutePayer, RoutePayerConfig, Shard};
use xbt402::route_seller::RouteOffer;
use xbt402::signer::LocalSigner;
use xbt402::wire::OPEN_PATH;
use xbt402_interop::memnet::{ChainWallet, MemChain, MemNet, NetTransport};
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;

const NET: &str = "bip122:11111111111111111111111111111111";
const HUB: &str = "http://hub.test";

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("xbt-rs-hub073-{}", hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..8])));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A service as the others see it over the net: `/open` can be refused (its policy changed after
/// its 402 or /terms), and a 200 to `/lock` can be turned into a 400 (the provider keeps the
/// pre-signature).
struct Svc {
    inner: Arc<dyn HttpService>,
    refuse_open: AtomicBool,
    refuse_lock: AtomicBool,
}

impl Svc {
    fn new(inner: Arc<dyn HttpService>) -> Arc<Self> {
        Arc::new(Self { inner, refuse_open: AtomicBool::new(false), refuse_lock: AtomicBool::new(false) })
    }
}

fn json_400(body: &str) -> HttpResponse {
    HttpResponse::new(400, vec![("Content-Type".into(), "application/json".into())], body.as_bytes().to_vec())
}

impl HttpService for Svc {
    fn body_limit(&self, path: &str) -> usize {
        self.inner.body_limit(path)
    }

    fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str) -> HttpResponse {
        if path == OPEN_PATH && self.refuse_open.load(Ordering::SeqCst) {
            return json_400(r#"{"error":"bad_expiry","detail":"the policy changed"}"#);
        }
        let r = self.inner.serve(method, path, headers, body, url);
        if path == ROUTE_LOCK_PATH && self.refuse_lock.load(Ordering::SeqCst) && r.status == 200 {
            return json_400(r#"{"error":"refused","detail":"no"}"#);
        }
        r
    }
}

/// The hub while it is stopped.
struct Down;

impl HttpService for Down {
    fn body_limit(&self, _path: &str) -> usize {
        1 << 16
    }

    fn serve(&self, _method: &str, _path: &str, _headers: &[(String, String)], _body: &[u8], _url: &str) -> HttpResponse {
        HttpResponse::new(503, vec![], b"down".to_vec())
    }
}

/// The chain's wallet, counting what it funds.
struct Counting(Arc<MemChain>, Arc<AtomicUsize>);

impl Wallet for Counting {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        self.1.fetch_add(1, Ordering::SeqCst);
        self.0.fund(address, sats)
    }

    fn wallet_sends_to(&self, address: &str) -> Result<Vec<String>> {
        ChainWallet(self.0.clone()).wallet_sends_to(address)
    }

    fn wallet_send(&self, txid: &str, address: &str) -> Result<Option<WalletSend>> {
        ChainWallet(self.0.clone()).wallet_send(txid, address)
    }
}

struct Prov {
    origin: String,
    svc: Arc<Svc>,
}

fn provider(chain: &Arc<MemChain>, net: &Arc<MemNet>, dir: &TempDir, origin: &str) -> Prov {
    let mut cfg = ProviderConfig::new(NET);
    cfg.close_margin = 36;
    cfg.policy = FundingPolicy { min_capacity: 20_000, min_expiry_blocks: 500, max_expiry_blocks: 8_640, close_margin: 36, ..FundingPolicy::default() };
    cfg.settle_multiple = 20;
    cfg.height_ttl = std::time::Duration::ZERO;
    cfg.settle_lock_multiple = 0;
    cfg.route_close_fee_payer = FeePayer::Payee;
    let name = origin.replace("http://", "").replace('.', "_");
    let ledger = Ledger::open(&dir.0.join(format!("prov-{name}.jsonl"))).unwrap();
    let p = Provider::new(chain.clone(), adaptor::random_secret(), cfg, ledger, Box::new(|_, _| 1000),
                          Box::new(|_, _, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], b"{\"ok\":1}".to_vec()))).unwrap();
    // 300 sat a call: a lock (10 calls) is well above ch1's dust floor, so each one raises ch1's state
    p.offer_route(RouteOffer { window: 0.3, lock_wait: 0.6, invoice_ttl: 8.0, ..RouteOffer::new("/v1/chunk", 300 * 10u128.pow(21)) });
    let svc = Svc::new(Arc::new(p));
    net.add(origin, svc.clone());
    Prov { origin: origin.into(), svc }
}

fn sk(n: u64) -> SecretKey {
    Sc::from_u64(n).secret().unwrap()
}

fn hub_cfg() -> HubConfig {
    HubConfig::from_json(&json!({"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500, "delta": 36,
                                 "reveal_timeout": 0.3, "ch2_capacity": 100000, "ch2_expiry_blocks": 1000, "settle_lock_multiple": 0, "refill_ahead_locks": 0,
                                 "close_margin": 36, "policy": {"min_capacity": 20000, "min_expiry_blocks": 500, "max_expiry_blocks": 8640}})).unwrap()
}

fn new_hub(chain: &Arc<MemChain>, net: &Arc<MemNet>, dir: &TempDir, funds: &Arc<AtomicUsize>) -> Result<Arc<RouteHub>> {
    RouteHub::new(chain.clone(), chain.clone(), Box::new(Counting(chain.clone(), funds.clone())), Box::new(NetTransport(net.clone())), sk(0x4B4B), NET,
                  Some(&dir.0.join("hub")), hub_cfg()).map(Arc::new)
}

struct W {
    chain: Arc<MemChain>,
    net: Arc<MemNet>,
    hub: Arc<RouteHub>,
    hub_svc: Arc<Svc>,
    provs: Vec<Prov>,
    pay: Arc<RoutePayer>,
    pay_funds: Arc<AtomicUsize>,
    hub_funds: Arc<AtomicUsize>,
    shards: Vec<Arc<Shard>>,
    dir: TempDir,
}

impl W {
    /// A hub, `n` providers with an open ch2 each, and a client whose ch1 to the hub is open (unless
    /// `open` is false).
    fn build(n: usize, open: bool) -> Self {
        let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
        let hub_funds = Arc::new(AtomicUsize::new(0));
        let hub = new_hub(&chain, &net, &dir, &hub_funds).unwrap();
        let hub_svc = Svc::new(hub.clone());
        net.add(HUB, hub_svc.clone());
        let mut provs = vec![];
        for i in 0..n {
            let origin = format!("http://p{i}.test");
            provs.push(provider(&chain, &net, &dir, &origin));
            hub.connect(&origin, None, None).unwrap();
        }
        chain.confirm_all();
        hub.watch_tick();
        let mut cfg = RoutePayerConfig::new(NET);
        cfg.expiry_blocks = 8_000;
        let c = chain.clone();
        let pay_funds = Arc::new(AtomicUsize::new(0));
        let pay = Arc::new(RoutePayer::new(HUB, cfg, Arc::new(LocalSigner::new()), Arc::new(Counting(chain.clone(), pay_funds.clone())),
                                           Box::new(NetTransport(net.clone())), Box::new(move || Ok(c.height()))));
        let mut shards = vec![];
        if open {
            pay.open().unwrap();
            shards = provs.iter().map(|p| pay.shard(&format!("{}/v1/chunk", p.origin), "POST").unwrap()).collect();
        }
        Self { chain, net, hub, hub_svc, provs, pay, pay_funds, hub_funds, shards, dir }
    }

    fn new(n: usize) -> Self {
        Self::build(n, true)
    }

    fn hub_dir(&self) -> PathBuf {
        self.dir.0.join("hub")
    }

    /// The hub stops (its ledger is let go) and starts again from its data dir.
    fn restart(self) -> Self {
        self.restart_after(|_, _, _| {})
    }

    /// The same, with `down(chain, net, dir)` run while it is stopped.
    fn restart_after(self, down: impl FnOnce(&Arc<MemChain>, &Arc<MemNet>, &TempDir)) -> Self {
        let W { chain, net, hub, hub_svc, provs, pay, pay_funds, hub_funds, shards, dir } = self;
        net.add(HUB, Arc::new(Down));
        drop((hub, hub_svc));
        down(&chain, &net, &dir);
        let hub = new_hub(&chain, &net, &dir, &hub_funds).unwrap();
        let hub_svc = Svc::new(hub.clone());
        net.add(HUB, hub_svc.clone());
        W { chain, net, hub, hub_svc, provs, pay, pay_funds, hub_funds, shards, dir }
    }

    fn st1(&self) -> ChannelState {
        self.hub.ch1_state(&self.pay.chan().unwrap()).unwrap()
    }

    fn routed(&self) -> u64 {
        self.st1().extra.get("routed_sat").and_then(Value::as_u64).unwrap_or(0)
    }

    fn stale1(&self) -> Vec<Value> {
        self.st1().extra.get("stale_locks").and_then(Value::as_array).cloned().unwrap_or_default()
    }

    fn chan2(&self, i: usize) -> String {
        self.hub.out_channels()[&self.provs[i].origin].params.channel_id()
    }

    fn lock(&self, i: usize) -> Value {
        stream(&self.pay, &self.shards[i], 10);
        self.pay.lock(&self.shards[i]).unwrap().unwrap()
    }

    fn paid(&self, i: usize) {
        let r = self.lock(i);
        assert_eq!(r["status"], "paid", "{r}");
    }

    /// p`i`'s next lock is written off: refused after the provider took it (`refuse`), or its answer
    /// lost until revealTimeout. Returns d + f.
    fn written_off(&self, i: usize, refuse: bool) -> u64 {
        let o = self.provs[i].origin.clone();
        if refuse {
            self.provs[i].svc.refuse_lock.store(true, Ordering::SeqCst);
        } else {
            self.net.set_drop(&o, Some(Box::new(|_, p| p == ROUTE_LOCK_PATH)));
        }
        let r = self.lock(i);
        assert_eq!((r["status"].as_str(), r["error"].as_str()), (Some("refused"), Some("route_failed")), "{r}");
        self.provs[i].svc.refuse_lock.store(false, Ordering::SeqCst);
        self.net.set_drop(&o, None);
        let s = self.stale1();
        assert_eq!(s.len(), 1, "{s:?}");
        s[0]["d"].as_u64().unwrap() + s[0]["f"].as_u64().unwrap()
    }
}

fn stream(pay: &RoutePayer, sh: &Arc<Shard>, n: usize) {
    for _ in 0..n {
        let r = pay.call(sh, "POST", br#"{"tokens":1}"#).unwrap();
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    }
}

fn has(acts: &[Value], event: &str) -> bool {
    acts.iter().any(|a| a["event"] == event)
}

fn ch2_doc(w: &W) -> Value {
    ch2_doc_at(&w.hub_dir())
}

/// Every ch2 record in a state file: the live and next ones, the archive, and a rollover's next ch2
/// written ahead inside a record.
fn records(doc: &Value) -> Vec<Value> {
    let mut out: Vec<Value> = vec![];
    for k in ["chans", "next_chans"] {
        out.extend(doc[k].as_object().into_iter().flatten().map(|(_, v)| v.clone()));
    }
    out.extend(doc["archived"].as_array().into_iter().flatten().cloned());
    let nested: Vec<Value> = out.iter().filter_map(|r| r.get("next").filter(|n| n.get("params").is_some()).cloned()).collect();
    out.extend(nested);
    out
}

/// The ch2 payer keys the hub holds (in memory).
fn hub_keys(hub: &RouteHub) -> Vec<String> {
    let mut keys: Vec<String> = hub.out_channels().values().chain(hub.next_channels().values()).map(|c| c.secret.clone()).collect();
    for r in hub.archived() {
        keys.push(r["secret"].as_str().unwrap().to_string());
    }
    for c in hub.out_channels().values() {
        if let Some(s) = c.next.get("secret").and_then(Value::as_str) {
            keys.push(s.to_string());
        }
    }
    keys
}

#[cfg(unix)]
fn mode(p: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

// --- K1: sealed ch2 keys -------------------------------------------------------------------------------

/// p0's ch2 replaced by its next one (live + archived), a next ch2 funded ahead, and a rollover's next
/// key written ahead: a key in every place a state file holds one.
fn keys_everywhere(w: &W) {
    let o = w.provs[0].origin.clone();
    w.hub.connect_next(&o, None, None).unwrap();
    w.chain.confirm_all();
    w.hub.watch_tick();
    assert_eq!(w.hub.next_channels()[&o].state, "open");
    // the live one closes (too small to roll over, say): its next one takes over at the close
    let live = w.hub.out_channels()[&o].clone();
    w.hub.close_ch2(&live, true).unwrap();
    assert_ne!(w.chan2(0), live.params.channel_id());
    w.hub.connect_next(&o, None, None).unwrap();
    let next = w.hub.next_channels()[&o].to_json();
    w.hub.with_out(|b| b.chans.get_mut(&o).unwrap().next = next.as_object().unwrap().clone());
}

#[test]
fn k1_the_state_file_holds_no_plaintext_ch2_key() {
    let w = W::new(1);
    w.paid(0);
    keys_everywhere(&w);
    let keys = hub_keys(&w.hub);
    assert!(keys.len() >= 4, "{}", keys.len());
    let raw = String::from_utf8(std::fs::read(w.hub_dir().join("ch2.json")).unwrap()).unwrap();
    for k in &keys {
        assert!(!raw.contains(k.as_str()), "a ch2 payer key is in ch2.json in plaintext");
    }
    let recs = records(&ch2_doc(&w));
    assert_eq!(recs.len(), keys.len());
    for r in &recs {
        assert!(r.get("secret").is_none(), "a record still has a secret field: {}", r["origin"]);
        let s = &r["secret_sealed"];
        assert_eq!((s["alg"].as_str(), s["aad"].as_str(), s["kdf"].as_str()), (Some("aes-256-gcm"), Some("xbt402/hub-ch2"), Some("keyfile")), "{s}");
    }
    #[cfg(unix)]
    {
        assert_eq!(mode(&w.hub_dir().join("ch2.json")), 0o600);
        assert_eq!(mode(&w.hub_dir().join("hub-wrap-key")), 0o600);
    }
    // a restart opens every key again, and routes
    let w = w.restart();
    let mut again = hub_keys(&w.hub);
    let mut before = keys.clone();
    again.sort();
    before.sort();
    assert_eq!(again, before);
    w.paid(0);
}

#[test]
fn k1_a_legacy_plaintext_state_file_is_read_once_and_rewritten_sealed() {
    let w = W::new(2);
    w.paid(0);
    let o = w.provs[0].origin.clone();
    // the file as a hub before AGP-073 wrote it: every record with its key, no wrap key
    let keys = hub_keys(&w.hub);
    let chans: serde_json::Map<String, Value> = w.hub.out_channels().iter().map(|(k, c)| (k.clone(), c.to_json())).collect();
    let origins: serde_json::Map<String, Value> = w.hub.out_channels().iter().map(|(k, c)| (k.clone(), Value::from(c.pay_to.clone()))).collect();
    let legacy = json!({"chans": chans, "archived": [], "origins": origins, "next_chans": {}});
    let _ = std::fs::remove_file(w.hub_dir().join("hub-wrap-key"));
    std::fs::write(w.hub_dir().join("ch2.json"), xbt402::json::dumps(&legacy)).unwrap();
    assert!(String::from_utf8(std::fs::read(w.hub_dir().join("ch2.json")).unwrap()).unwrap().contains(keys[0].as_str()));
    let w = w.restart();
    let raw = String::from_utf8(std::fs::read(w.hub_dir().join("ch2.json")).unwrap()).unwrap();
    for k in &keys {
        assert!(!raw.contains(k.as_str()), "the legacy plaintext key was not rewritten sealed");
    }
    let ev = w.hub.events.lock().unwrap().iter().find(|e| e["event"] == "ch2_keys_sealed").cloned();
    assert_eq!(ev.map(|e| e["count"].clone()), Some(json!(2)));
    assert_eq!(w.hub.out_channels()[&o].secret, keys.iter().find(|k| **k == w.hub.out_channels()[&o].secret).unwrap().clone());
    w.paid(0);
    w.paid(1);
}

#[test]
fn k1_a_wrong_wrap_key_or_a_swapped_blob_is_refused() {
    let w = W::new(2);
    w.paid(0);
    w.paid(1);
    let w = w.restart_after(|chain, net, dir| {
        let path = dir.0.join("hub").join("ch2.json");
        let good = std::fs::read(&path).unwrap();
        let open = |wrap: Option<WrapKey>| {
            RouteHub::new_with_wrap_key(chain.clone(), chain.clone(), Box::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())),
                                        sk(0x4B4B), NET, Some(&dir.0.join("hub")), hub_cfg(), wrap).map(|_| ())
        };
        assert_eq!(open(Some(WrapKey::from_bytes([9; 32]))).unwrap_err().code, "keystore", "another wrap key");
        // p0's sealed key moved onto p1's record (and back): each opens, neither is its record's key
        let mut doc: Value = serde_json::from_slice(&good).unwrap();
        let (a, b) = ("http://p0.test", "http://p1.test");
        let sa = doc["chans"][a]["secret_sealed"].take();
        doc["chans"][a]["secret_sealed"] = doc["chans"][b]["secret_sealed"].take();
        doc["chans"][b]["secret_sealed"] = sa;
        std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
        let e = open(None).unwrap_err();
        assert_eq!(e.code, "keystore", "{e}");
        // one byte of a blob changed
        let mut doc: Value = serde_json::from_slice(&good).unwrap();
        let ct = doc["chans"][a]["secret_sealed"]["ct"].as_str().unwrap().to_string();
        doc["chans"][a]["secret_sealed"]["ct"] = format!("{}{}", if ct.starts_with('0') { '1' } else { '0' }, &ct[1..]).into();
        std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
        assert_eq!(open(None).unwrap_err().code, "keystore");
        std::fs::write(&path, &good).unwrap();
    });
    w.paid(0);
    // a wrap key from elsewhere (a secrets mount): none is made in the data dir
    let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
    let hub = RouteHub::new_with_wrap_key(chain.clone(), chain.clone(), Box::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())),
                                          sk(0x4B4B), NET, Some(&dir.0.join("hub")), hub_cfg(), Some(WrapKey::from_bytes([5; 32]))).unwrap();
    let _p = provider(&chain, &net, &dir, "http://p0.test");
    hub.connect("http://p0.test", None, None).unwrap();
    assert!(!dir.0.join("hub").join("hub-wrap-key").exists());
    assert!(ch2_doc_at(&dir.0.join("hub"))["chans"]["http://p0.test"]["secret_sealed"].is_object());
}

fn ch2_doc_at(hub_dir: &std::path::Path) -> Value {
    serde_json::from_slice(&std::fs::read(hub_dir.join("ch2.json")).unwrap()).unwrap()
}

// --- a ch2 a written-off lock blocks -------------------------------------------------------------------

#[test]
fn written_off_a_refused_lock_ch2_is_closed_and_refilled() {
    // p0 takes the lock, keeps the pre-signature and answers 400. The hub asks p0 to close that ch2
    // at once and funds a new one; p0's close reveals t, so the hub collects what it held
    let w = W::new(2);
    let routed0 = w.routed();
    let first = w.written_off(0, true);
    assert_eq!(w.routed(), routed0 + first, "held in the base");
    let old = w.chan2(0);
    let mut acts = w.hub.watch_tick();
    assert!(acts.iter().any(|a| a["event"] == "ch2_close" && a["chan"] == old.as_str() && a["why"] == "written_off"), "{acts:?}");
    let new = w.hub.out_channels()[&w.provs[0].origin].clone();
    assert_ne!(new.params.channel_id(), old, "no refill");
    assert_eq!(new.state, "funded");
    acts.extend(w.hub.watch_tick());
    assert!(has(&acts, "secret_from_close"), "{acts:?}");
    assert!(w.stale1().is_empty());
    assert_eq!(w.routed(), routed0 + first, "the hold was paid: nothing given back, nothing counted twice");
    w.chain.confirm_all();
    w.hub.watch_tick();
    assert_eq!(w.hub.out_channels()[&w.provs[0].origin].state, "open");
    w.paid(0);
}

#[test]
fn written_off_with_a_next_ch2_the_hub_switches_and_has_the_old_one_closed() {
    let w = W::new(1);
    w.paid(0);
    let o = w.provs[0].origin.clone();
    w.hub.connect_next(&o, None, None).unwrap();
    w.chain.confirm_all();
    w.hub.watch_tick();
    let next = w.hub.next_channels()[&o].params.channel_id();
    let old = w.chan2(0);
    w.written_off(0, true);
    let mut acts = w.hub.watch_tick();
    assert!(acts.iter().any(|a| a["event"] == "ch2_switch" && a["why"] == "written_off"), "{acts:?}");
    assert_eq!(w.chan2(0), next);
    assert!(acts.iter().any(|a| a["event"] == "ch2_close" && a["chan"] == old.as_str()), "the retired ch2 is not closed: {acts:?}");
    acts.extend(w.hub.watch_tick());
    assert!(has(&acts, "secret_from_close"), "{acts:?}");
    assert!(w.stale1().is_empty());
    w.paid(0);
}

#[test]
fn written_off_on_a_timeout_the_ch2_is_closed_and_not_refilled() {
    // the provider never answered in time: the hub stops routing to it (AGP-064) and asks it to close
    // that ch2 now, so the held lock resolves; it does not fund that provider again
    let w = W::new(1);
    w.paid(0);
    let routed0 = w.routed();
    let first = w.written_off(0, false);
    let old = w.chan2(0);
    let n = w.hub_funds.load(Ordering::SeqCst);
    let mut acts = w.hub.watch_tick();
    assert!(acts.iter().any(|a| a["event"] == "ch2_close" && a["chan"] == old.as_str()), "{acts:?}");
    assert_eq!(w.hub_funds.load(Ordering::SeqCst), n, "a provider the hub stopped routing to was funded again");
    acts.extend(w.hub.watch_tick());
    assert!(has(&acts, "secret_from_close"), "{acts:?}");
    assert!(w.stale1().is_empty());
    assert_eq!(w.routed(), routed0 + first);
}

// --- crash orphans -------------------------------------------------------------------------------------

#[test]
fn orphan_a_lock_a_crash_left_is_swept_by_the_watcher() {
    // the hub wrote its ch1 lock and stopped before the ch2 one (the withholding hook leaves the same
    // state). After the restart nothing can complete it; the watcher drops it, ch1 takes locks again
    let w = W::new(1);
    w.paid(0);
    w.hub.set_withhold("all");
    assert_eq!(w.lock(0)["status"], "pending");
    let w = w.restart();
    assert!(truthy(w.st1().extra.get("route_lock")), "the lock is on disk");
    let acts = w.hub.watch_tick();
    assert!(has(&acts, "orphan_lock_dropped"), "{acts:?}");
    assert!(!truthy(w.st1().extra.get("route_lock")));
    assert!(w.stale1().is_empty());
}

#[test]
fn orphan_a_lock_its_ch2_wrote_off_before_the_crash_is_held_not_dropped() {
    // the crash came between a void's two writes: ch2 has the lock written off (its pre-signature
    // may be out), ch1 still has it as its lock. Dropping it would let ch1 close below it
    let w = W::new(1);
    w.paid(0);
    let routed0 = w.routed();
    w.hub.set_withhold("all");
    assert_eq!(w.lock(0)["status"], "pending");
    w.hub.set_withhold("");
    let rl = w.st1().extra["route_lock"].clone();
    let ch1 = w.pay.chan().unwrap();
    let o = w.provs[0].origin.clone();
    w.hub.with_out(|b| {
        b.chans.get_mut(&o).unwrap().stale.push(json!({"lockId": rl["lockId"], "cum": 5000, "pre": null, "T": rl["T"], "d": rl["d"], "ch1": ch1,
                                                        "at": 0.0, "voided": 0.0, "why": "test"}));
    });
    let refused = w.pay.close();
    assert!(w.st1().closed_txid.is_empty(), "ch1 closed below a lock whose ch2 pre-signature may be out");
    assert_eq!(refused.unwrap_err().code, "lock_pending");
    let stale = w.stale1();
    assert_eq!(stale.len(), 1, "{stale:?}");
    assert!(stale[0]["hold"].is_object());
    assert_eq!(w.routed(), routed0 + rl["d"].as_u64().unwrap() + rl["f"].as_u64().unwrap(), "held in the base");
    assert!(w.hub.events.lock().unwrap().iter().any(|e| e["event"] == "orphan_lock_held"));
}

// --- C2: preflight before the routed fundings ----------------------------------------------------------

#[test]
fn c2_the_route_payer_asks_the_hub_before_it_funds_ch1() {
    let w = W::build(1, false);
    w.hub_svc.refuse_open.store(true, Ordering::SeqCst);
    let e = w.pay.open().unwrap_err();
    assert_eq!(e.code, "bad_expiry", "{e}");
    assert_eq!(w.pay_funds.load(Ordering::SeqCst), 0, "ch1 was funded before the hub said it would open it");
    w.hub_svc.refuse_open.store(false, Ordering::SeqCst);
    let n = w.net.count(OPEN_PATH);
    w.pay.open().unwrap();
    assert_eq!((w.pay_funds.load(Ordering::SeqCst), w.net.count(OPEN_PATH) - n), (1, 2), "one preflight, one funded open");
}

#[test]
fn c2_the_hub_asks_the_provider_before_it_funds_ch2() {
    let w = W::build(0, false);
    let p = provider(&w.chain, &w.net, &w.dir, "http://p9.test");
    p.svc.refuse_open.store(true, Ordering::SeqCst);
    let e = w.hub.connect(&p.origin, None, None).unwrap_err();
    assert_eq!(e.code, "bad_expiry", "{e}");
    assert_eq!(w.hub_funds.load(Ordering::SeqCst), 0, "ch2 was funded before the provider said it would open it");
    assert!(!w.hub.out_channels().contains_key(&p.origin), "a record for a ch2 that was never funded");
    p.svc.refuse_open.store(false, Ordering::SeqCst);
    let oc = w.hub.connect(&p.origin, None, None).unwrap();
    assert_eq!((oc.state.as_str(), w.hub_funds.load(Ordering::SeqCst)), ("funded", 1));
    w.chain.confirm_all();
    w.hub.watch_tick();
    assert_eq!(w.hub.out_channels()[&p.origin].state, "open");
}
