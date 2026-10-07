//! AGP-044: the routing hub's leftovers from AGP-037 (a port of B1
//! `tests/security/test_agp044_hub_leftovers.py`), in process: [`MemChain`] + [`MemNet`].
//! 1 a stuck ch2 refund is re-signed at a higher fee (RBF), capped, and whichever version confirms
//! is the refund; 2 one live ch2 per payTo (two origins, one operator key), the cap accounting
//! unchanged.
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::adaptor::{self, Sc};
use xbt402::channel::{FeePayer, DUST, RBF_SEQUENCE};
use xbt402::client::Wallet;
use xbt402::error::Result;
use xbt402::funding::{ChainBackend, FundingPolicy};
use xbt402::hub::{HubConfig, OutChannel, RouteHub, LIVE};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route::canon_origin;
use xbt402::route_client::{RoutePayer, RoutePayerConfig};
use xbt402::route_seller::RouteOffer;
use xbt402::signer::LocalSigner;
use xbt402_interop::memnet::{ChainWallet, MemChain, MemNet, NetTransport};
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
        let p = std::env::temp_dir().join(format!("xbt-rs-agp044-{}", hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..8])));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn provider(chain: &Arc<MemChain>, net: &Arc<MemNet>, dir: &TempDir, origin: &str, key: SecretKey) -> Arc<Provider> {
    provider_settling(chain, net, dir, origin, key, 20)
}

fn provider_settling(chain: &Arc<MemChain>, net: &Arc<MemNet>, dir: &TempDir, origin: &str, key: SecretKey, settle_multiple: u64) -> Arc<Provider> {
    let mut cfg = ProviderConfig::new(NET);
    cfg.settle_multiple = settle_multiple;
    cfg.close_margin = 36;
    cfg.policy = FundingPolicy { min_capacity: 20_000, min_expiry_blocks: 500, max_expiry_blocks: 8_640, close_margin: 36, ..FundingPolicy::default() };
    cfg.height_ttl = Duration::ZERO;
    cfg.route_close_fee_payer = FeePayer::Payee;
    let name = origin.replace("http://", "").replace('.', "_");
    let ledger = Ledger::open(&dir.0.join(format!("prov-{name}.jsonl"))).unwrap();
    let p = Provider::new(chain.clone(), key, cfg, ledger, Box::new(|_, _| 1000),
                          Box::new(|_, _, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], b"{\"ok\":1}".to_vec()))).unwrap();
    p.offer_route(RouteOffer { window: 0.3, lock_wait: 0.6, invoice_ttl: 8.0, ..RouteOffer::new("/v1/chunk", 370 * 10u128.pow(18)) });
    let p = Arc::new(p);
    net.add(origin, p.clone());
    p
}

fn hub_cfg(extra: Value) -> HubConfig {
    let mut c = json!({"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500, "delta": 36,
                       "reveal_timeout": 1.0, "ch2_capacity": 100000, "ch2_expiry_blocks": 1000, "close_margin": 36,
                       "policy": {"min_capacity": 20000, "min_expiry_blocks": 500, "max_expiry_blocks": 8640}});
    for (k, v) in extra.as_object().unwrap() {
        c[k] = v.clone();
    }
    HubConfig::from_json(&c).unwrap()
}

fn has(acts: &[Value], f: impl Fn(&Value) -> bool) -> bool {
    acts.iter().any(f)
}

/// A wallet that counts its fund calls (and can be slowed down).
struct CountingWallet {
    chain: Arc<MemChain>,
    n: Arc<AtomicUsize>,
    delay: Duration,
}

impl Wallet for CountingWallet {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        self.n.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        self.chain.fund(address, sats)
    }
}

/// `net`, `pay` and `dir` are held for the world's lifetime (the per-payTo tests that read them moved to
/// hub_multi_process.rs with AGP-056).
#[allow(dead_code)]
struct W {
    chain: Arc<MemChain>,
    net: Arc<MemNet>,
    hub: Arc<RouteHub>,
    origins: Vec<String>,
    pay: Arc<RoutePayer>,
    funds: Arc<AtomicUsize>,
    dir: TempDir,
}

impl W {
    /// A hub (`cfg`) and a client; `keys[i]` is the operator key of provider i. Providers with the
    /// same key share one backend (one Provider served at both origins) when `shared`.
    fn new(keys: &[u64], shared: bool, cfg: HubConfig) -> Self {
        Self::settling(keys, shared, cfg, 20)
    }

    fn settling(keys: &[u64], shared: bool, cfg: HubConfig, settle_multiple: u64) -> Self {
        let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
        let funds = Arc::new(AtomicUsize::new(0));
        let h = Arc::new(RouteHub::new(chain.clone(), chain.clone(), Box::new(CountingWallet { chain: chain.clone(), n: funds.clone(), delay: Duration::ZERO }),
                                       Box::new(NetTransport(net.clone())), sk(0x4B4B), NET, Some(&dir.0.join("hub")), cfg).unwrap());
        net.add(HUB, h.clone());
        let mut origins = vec![];
        let mut by_key: Vec<(u64, Arc<Provider>)> = vec![];
        for (i, k) in keys.iter().enumerate() {
            let origin = format!("http://p{i}.test");
            match by_key.iter().find(|(kk, _)| kk == k).filter(|_| shared) {
                Some((_, p)) => net.add(&origin, p.clone()),
                None => by_key.push((*k, provider_settling(&chain, &net, &dir, &origin, sk(*k), settle_multiple))),
            }
            origins.push(origin);
        }
        let c = chain.clone();
        let mut pc = RoutePayerConfig::new(NET);
        pc.expiry_blocks = 8_000;
        let pay = Arc::new(RoutePayer::new(HUB, pc, Arc::new(LocalSigner::new()), Arc::new(ChainWallet(chain.clone())),
                                           Box::new(NetTransport(net.clone())), Box::new(move || Ok(c.height()))));
        pay.open().unwrap();
        Self { chain, net, hub: h, origins, pay, funds, dir }
    }

    fn connect_all(&self) {
        for o in &self.origins {
            self.hub.connect(o, None, None).unwrap();
        }
        self.chain.confirm_all();
        self.hub.watch_tick();
    }

    fn oc(&self, key: &str) -> OutChannel {
        self.hub.out_channels()[key].clone()
    }

    fn events(&self, name: &str) -> Vec<Value> {
        self.hub.events.lock().unwrap().iter().filter(|e| e["event"] == name).cloned().collect()
    }
}

// --- 1 stuck refund bump (RBF) ----------------------------------------------------------------------

/// One unsigned ch2 at its expiry, a refund at 1 sat/vB, blocks that take only >= `block_min` sat/vB.
fn stuck(block_min: f64, cfg: Value) -> W {
    let w = W::new(&[0xA1], false, hub_cfg(cfg));
    w.connect_all();
    w.chain.set_fee_rate(Some(1.0));
    w.chain.set_block_min_feerate(block_min);
    w.chain.set_height(w.oc(&w.origins[0]).params.expiry);
    let acts = w.hub.watch_tick();
    assert!(has(&acts, |a| a["event"] == "ch2_refund"), "{acts:?}");
    w
}

fn blocks(w: &W, n: u32) -> Vec<Value> {
    let mut acts = vec![];
    for _ in 0..n {
        w.chain.mine(1);
        acts.extend(w.hub.watch_tick());
    }
    acts
}

#[test]
fn bump_the_hub_refund_signals_rbf_and_keeps_its_locktime() {
    let w = stuck(0.0, json!({}));
    let oc = w.oc(&w.origins[0]);
    let tx = Tx::parse_hex(&oc.refund_hex).unwrap();
    assert_eq!(tx.inputs[0].sequence, RBF_SEQUENCE);
    assert_eq!(tx.locktime, oc.params.expiry);
    assert_eq!(oc.refund_at, oc.params.expiry);
}

#[test]
fn bump_a_stuck_refund_is_replaced_at_a_higher_fee_until_it_confirms() {
    let w = stuck(5.0, json!({}));
    let o = w.origins[0].clone();
    let first = w.oc(&o);
    let (f1, v) = w.chain.fee_of(&first.refund_txid).unwrap();
    assert_eq!(f1, first.refund_fee);
    assert!((f1 as f64) < 5.0 * v as f64); // below what blocks take
    // not before refund_bump_blocks (3)
    let acts = blocks(&w, 2);
    assert!(!has(&acts, |a| a["event"] == "ch2_refund_bump"), "{acts:?}");
    assert_eq!(w.oc(&o).refund_txid, first.refund_txid);
    let mut fees = vec![f1];
    let mut txids = vec![first.refund_txid.clone()];
    for _ in 0..8 {
        let acts = blocks(&w, 1);
        if let Some(b) = acts.iter().find(|a| a["event"] == "ch2_refund_bump") {
            let f = b["fee"].as_u64().unwrap();
            let prev = *fees.last().unwrap();
            assert_eq!(b["replaces"], txids.last().unwrap().as_str());
            assert_eq!(b["feeFrom"], prev);
            assert!(f >= 2 * prev && f >= prev + v, "{f} after {prev}");
            assert!(!w.chain.has_transaction(txids.last().unwrap()).unwrap()); // replaced in the mempool
            fees.push(f);
            txids.push(b["txid"].as_str().unwrap().to_string());
        }
        if w.oc(&o).final_ {
            break;
        }
    }
    let oc = w.oc(&o);
    assert!(oc.final_, "{:?}", w.events("ch2_refund_bump"));
    assert_eq!(oc.state, "refunded");
    assert!(fees.len() >= 3, "{fees:?}"); // 1 -> 2 -> 4 -> 8 sat/vB: two bumps stay stuck, the third confirms
    assert_eq!((oc.refund_txid.clone(), oc.refund_fee), (txids.last().unwrap().clone(), *fees.last().unwrap()));
    assert_eq!(oc.refund_prev.len(), fees.len() - 1);
    assert!(w.chain.confirmed(&oc.refund_txid));
    let out = w.chain.raw(&oc.refund_txid).unwrap().outputs[0].value as u64;
    assert_eq!(out, oc.params.capacity - oc.refund_fee);
    assert_eq!(w.hub.refund_fees_sat(), oc.refund_fee);
    let conf = w.events("ch2_refund_confirmed");
    assert_eq!((conf.len(), conf[0]["txid"].as_str().unwrap(), conf[0]["versions"].as_u64().unwrap()),
               (1, oc.refund_txid.as_str(), fees.len() as u64));
    assert_eq!(w.hub.committed_sat(), 0);
}

#[test]
fn bump_the_fee_spent_is_capped_by_refund_max_fee_sat() {
    let w = stuck(1000.0, json!({"refund_max_fee_sat": 700}));
    let o = w.origins[0].clone();
    blocks(&w, 30);
    let oc = w.oc(&o);
    assert!(!oc.final_);
    assert_eq!(oc.refund_fee, 700);
    let bumps = w.events("ch2_refund_bump");
    assert!(bumps.iter().all(|b| b["fee"].as_u64().unwrap() <= 700), "{bumps:?}");
    let capped = w.events("ch2_refund_bump_capped");
    assert!(!capped.is_empty() && capped.iter().all(|c| c["cap"] == 700 && c["fee"] == 700), "{capped:?}");
    // at the cap it is still sent (and watched), never re-signed higher
    assert!(w.chain.has_transaction(&oc.refund_txid).unwrap());
    assert!(oc.params.capacity - oc.refund_fee >= DUST);
}

#[test]
fn bump_an_earlier_version_that_confirms_is_the_refund() {
    let w = stuck(5.0, json!({}));
    let o = w.origins[0].clone();
    let old = w.oc(&o);
    blocks(&w, 3);
    let new = w.oc(&o);
    assert_ne!(new.refund_txid, old.refund_txid);
    assert_eq!(new.refund_prev, vec![json!({"txid": old.refund_txid, "fee": old.refund_fee})]);
    // a miner that had only the first version mines it
    w.chain.evict(&new.refund_txid);
    w.chain.send_raw_transaction(&old.refund_hex).unwrap();
    w.chain.set_block_min_feerate(0.0);
    let acts = blocks(&w, 1);
    let c = acts.iter().find(|a| a["event"] == "ch2_refund_confirmed").expect("confirmed");
    assert_eq!((c["txid"].as_str().unwrap(), c["fee"].as_u64().unwrap()), (old.refund_txid.as_str(), old.refund_fee));
    let oc = w.oc(&o);
    assert!(oc.final_);
    assert_eq!((oc.refund_txid, oc.refund_fee), (old.refund_txid.clone(), old.refund_fee));
    assert_eq!(w.hub.refund_fees_sat(), old.refund_fee);
}

#[test]
fn bump_a_refund_that_left_the_mempool_goes_back_bumped_once_due() {
    let w = stuck(0.0, json!({}));
    let o = w.origins[0].clone();
    let first = w.oc(&o);
    w.chain.evict(&first.refund_txid);
    let acts = w.hub.watch_tick();
    assert!(has(&acts, |a| a["event"] == "ch2_refund_rebroadcast" && a["txid"] == first.refund_txid.as_str()), "{acts:?}");
    w.chain.evict(&first.refund_txid);
    w.chain.set_height(first.refund_at + 3);
    let acts = w.hub.watch_tick();
    let b = acts.iter().find(|a| a["event"] == "ch2_refund_bump").expect("bump");
    assert_ne!(b["txid"], first.refund_txid.as_str());
    assert!(w.chain.has_transaction(b["txid"].as_str().unwrap()).unwrap());
}

#[test]
fn bump_pays_the_same_destination_as_the_version_it_replaces() {
    let (w, n) = (stuck(5.0, json!({})), Arc::new(AtomicUsize::new(0)));
    let n2 = n.clone();
    // a refund_to hook that hands out a new address per call (a wallet's getnewaddress)
    w.hub.set_refund_to(Some(Box::new(move || {
        let i = n2.fetch_add(1, Ordering::SeqCst) as u8;
        Ok(xbt_primitives::address::segwit_address("bcrt", &[&[0u8, 20][..], &[i + 1; 20][..]].concat()).unwrap())
    })));
    let o = w.origins[0].clone();
    let spk0 = Tx::parse_hex(&w.oc(&o).refund_hex).unwrap().outputs[0].script_pubkey.clone();
    blocks(&w, 3);
    let oc = w.oc(&o);
    assert_eq!(oc.refund_prev.len(), 1);
    assert_eq!(Tx::parse_hex(&oc.refund_hex).unwrap().outputs[0].script_pubkey, spk0);
    assert_eq!(n.load(Ordering::SeqCst), 0);
}

#[test]
fn bump_off_with_refund_bump_blocks_zero() {
    let w = stuck(5.0, json!({"refund_bump_blocks": 0}));
    let o = w.origins[0].clone();
    let first = w.oc(&o);
    blocks(&w, 10);
    assert!(w.events("ch2_refund_bump").is_empty());
    assert_eq!(w.oc(&o).refund_txid, first.refund_txid);
}

#[test]
fn bump_a_refused_replacement_keeps_both_versions_tracked() {
    let w = stuck(5.0, json!({}));
    let o = w.origins[0].clone();
    let old = w.oc(&o);
    // an AGP-037 refund (no RBF signal) already in the mempool: the node refuses its replacement
    w.chain.evict(&old.refund_txid);
    let key = xbt402::adaptor::Sc::from_hex64(&old.secret).unwrap().secret().unwrap();
    let legacy = old.params.refund_tx(&key, None, Some(old.refund_fee)).unwrap();
    w.chain.send_raw_transaction(&legacy.to_hex()).unwrap();
    w.hub.with_out(|b| {
        let c = b.chans.get_mut(&o).unwrap();
        c.refund_hex = legacy.to_hex();
        c.refund_txid = legacy.txid();
    });
    let acts = blocks(&w, 3);
    let f = acts.iter().find(|a| a["event"] == "ch2_refund_bump_failed").expect("refused");
    assert!(f["error"].as_str().unwrap().contains("conflict"));
    let oc = w.oc(&o);
    assert_eq!(oc.refund_prev[0]["txid"], legacy.txid().as_str());
    // the legacy version confirms after all: it is the refund
    w.chain.set_block_min_feerate(0.0);
    blocks(&w, 1);
    let oc = w.oc(&o);
    assert!(oc.final_);
    assert_eq!(oc.refund_txid, legacy.txid());
}

#[test]
fn bump_config_keys_round_trip() {
    let c = HubConfig::from_json(&json!({"refund_bump_blocks": 7, "refund_max_fee_sat": 1234})).unwrap();
    assert_eq!((c.refund_bump_blocks, c.refund_max_fee_sat), (7, 1234));
    let d = HubConfig::default();
    assert_eq!((d.refund_bump_blocks, d.refund_max_fee_sat), (3, 5000));
}

// --- 2 one live ch2 per origin -----------------------------------------------------------------------
// AGP-044 kept one live ch2 per payTo and routed a second origin of that key over it. That broke
// operators who run several provider processes on one key (each has its own ledger): AGP-056 keys the
// ch2 by origin again. What is left of item 2 here is the guard on ONE origin; the rest is in
// hub_multi_process.rs.

#[test]
fn payto_a_second_connect_to_the_same_origin_funds_nothing() {
    let w = W::new(&[0xA1], false, hub_cfg(json!({})));
    let o = w.origins[0].clone();
    let c1 = w.hub.connect(&o, None, None).unwrap();
    w.chain.confirm_all();
    w.hub.watch_tick();
    let c2 = w.hub.connect(&format!("{}/", o.to_uppercase().replace("HTTP://", "http://")), None, None).unwrap();
    assert_eq!(c1.params.channel_id(), c2.params.channel_id());
    assert_eq!((w.funds.load(Ordering::SeqCst), w.hub.archived().len()), (1, 0));
    assert_eq!(w.oc(&o).state, "open");
}

#[test]
fn payto_while_funding_the_same_origin_is_refused_not_funded() {
    let w = W::new(&[0xA1], false, hub_cfg(json!({})));
    let a = w.origins[0].clone();
    w.hub.connect(&a, None, None).unwrap();
    w.hub.with_out(|bk| bk.chans.get_mut(&a).unwrap().state = "funding".into()); // the wallet call still out
    let e = w.hub.connect(&format!("{a}/"), None, None).unwrap_err();
    assert_eq!(e.code, "ch2_funding");
    assert_eq!(w.funds.load(Ordering::SeqCst), 1);
}

#[test]
fn payto_racing_connects_to_one_origin_fund_one_ch2() {
    let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
    let funds = Arc::new(AtomicUsize::new(0));
    let hub = Arc::new(RouteHub::new(chain.clone(), chain.clone(),
                                     Box::new(CountingWallet { chain: chain.clone(), n: funds.clone(), delay: Duration::from_millis(150) }),
                                     Box::new(NetTransport(net.clone())), sk(0x4B4B), NET, Some(&dir.0.join("hub")), hub_cfg(json!({}))).unwrap());
    provider(&chain, &net, &dir, "http://a.test", sk(0xA1));
    let ths: Vec<_> = ["http://a.test", "http://a.test/"].into_iter().map(|o| {
        let h = hub.clone();
        std::thread::spawn(move || h.connect(o, None, None).map(|c| c.params.channel_id()).map_err(|e| e.code))
    }).collect();
    let res: Vec<_> = ths.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(funds.load(Ordering::SeqCst), 1, "{res:?}");
    assert!(res.iter().any(|r| r.is_ok()), "{res:?}");
    assert!(res.iter().all(|r| r.is_ok() || r.as_ref().err().map(String::as_str) == Some("ch2_funding")), "{res:?}");
    assert_eq!(hub.out_channels().values().filter(|c| LIVE.contains(&c.state.as_str())).count(), 1);
}

#[test]
fn payto_canonical_origins() {
    for (i, o) in [("HTTP://Host.Test:80/", "http://host.test"), ("https://h.test:443", "https://h.test"), ("http://h.test:8080//", "http://h.test:8080"),
                   ("http://h.test/Path/", "http://h.test/Path"), ("http://[::1]:80", "http://[::1]"), ("https://h.test:80", "https://h.test:80")] {
        assert_eq!(canon_origin(i), o, "{i}");
    }
    let _ = adaptor::random_secret();
}
