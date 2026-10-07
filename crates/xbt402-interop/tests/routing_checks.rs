//! Hub routing, security tests (a port of B1 `tests/security/test_agp021_route_checks.py` and the
//! hub parts of `test_agp023_close_fee_payer.py`), in process: [`MemChain`] + [`MemNet`].
//!
//! Hub, POST /x402/route, one test per check in the order the hub runs them; each refusal is
//! checked to leave nothing behind (no ch1 lock written, no ch2 state pre-signed, nothing sent to
//! the provider). Provider, POST /x402/xbt-channel/lock: the hub cannot reprice or redirect a lock,
//! invoices are fresh and expire, only the bound hub's channel, write-ahead and idempotent answers.
//! cmp-lead's M2 constraints 1–7 that a unit test can show (route_interop.sh shows the rest).
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::adaptor::{self, Sc};
use xbt402::channel::{channel_auth_key, FeePayer, DUST};
use xbt402::client::Transport;
use xbt402::error::Result;
use xbt402::funding::FundingPolicy;
use xbt402::hub::{HubConfig, RouteHub};
use xbt402::json::dumps;
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route::*;
use xbt402::route_client::{RoutePayer, RoutePayerConfig, Shard};
use xbt402::route_seller::RouteOffer;
use xbt402::signer::{AdaptorLock, LocalSigner, RouteSigner, StateSigner};
use xbt402::wire::{b64json, request_auth, request_digest};
use xbt402_interop::memnet::{ChainWallet, MemChain, MemNet, NetTransport};
use xbt_primitives::ecdsa;
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

const NET: &str = "bip122:11111111111111111111111111111111";
const HUB: &str = "http://hub.test";

fn pt33(h: &str) -> ecdsa::PubkeyBytes {
    hex::decode(h).unwrap().try_into().unwrap()
}

fn sk(n: u64) -> SecretKey {
    Sc::from_u64(n).secret().unwrap()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("xbt-rs-route-{}", hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..8])));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct PKw {
    amsat: u128,
    settle_multiple: u64,
    route_fee_payer: FeePayer,
}

impl Default for PKw {
    fn default() -> Self {
        Self { amsat: 370 * 10u128.pow(18), settle_multiple: 20, route_fee_payer: FeePayer::Payee }
    }
}

fn provider(chain: &Arc<MemChain>, net: &Arc<MemNet>, dir: &TempDir, origin: &str, secret: SecretKey, kw: &PKw) -> Arc<Provider> {
    let mut cfg = ProviderConfig::new(NET);
    cfg.close_margin = 36;
    cfg.policy = FundingPolicy { min_capacity: 20_000, min_expiry_blocks: 500, max_expiry_blocks: 8_640, close_margin: 36, ..FundingPolicy::default() };
    cfg.settle_multiple = kw.settle_multiple;
    cfg.height_ttl = Duration::ZERO;
    cfg.route_close_fee_payer = kw.route_fee_payer;
    let name = origin.replace("http://", "").replace('.', "_");
    let ledger = Ledger::open(&dir.0.join(format!("prov-{name}.jsonl"))).unwrap();
    let p = Provider::new(chain.clone(), secret, cfg, ledger, Box::new(|_, _| 1000),
                          Box::new(|_, _, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], b"{\"ok\":1}".to_vec()))).unwrap();
    p.offer_route(RouteOffer { window: 0.3, lock_wait: 0.6, invoice_ttl: 8.0, ..RouteOffer::new("/v1/chunk", kw.amsat) });
    let p = Arc::new(p);
    net.add(origin, p.clone());
    p
}

fn hub_cfg() -> HubConfig {
    HubConfig::from_json(&json!({"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500, "delta": 36,
                                 "reveal_timeout": 1.0, "ch2_capacity": 100000, "ch2_expiry_blocks": 1000, "close_margin": 36,
                                 "policy": {"min_capacity": 20000, "min_expiry_blocks": 500, "max_expiry_blocks": 8640}})).unwrap()
}

fn hub_with(chain: &Arc<MemChain>, net: &Arc<MemNet>, dir: &std::path::Path, secret: SecretKey, cfg: HubConfig) -> RouteHub {
    RouteHub::new(chain.clone(), chain.clone(), Box::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())), secret, NET, Some(dir), cfg).unwrap()
}

fn hub(chain: &Arc<MemChain>, net: &Arc<MemNet>, dir: &TempDir) -> Arc<RouteHub> {
    let h = Arc::new(hub_with(chain, net, &dir.0.join("hub"), sk(0x4B4B), hub_cfg()));
    net.add(HUB, h.clone());
    h
}

fn payer_with(chain: &Arc<MemChain>, net: &Arc<MemNet>, signer: Arc<dyn RouteSigner>, expiry_blocks: u32) -> Arc<RoutePayer> {
    let mut cfg = RoutePayerConfig::new(NET);
    cfg.expiry_blocks = expiry_blocks;
    let c = chain.clone();
    Arc::new(RoutePayer::new(HUB, cfg, signer, Arc::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())), Box::new(move || Ok(c.height()))))
}

fn payer(chain: &Arc<MemChain>, net: &Arc<MemNet>) -> Arc<RoutePayer> {
    payer_with(chain, net, Arc::new(LocalSigner::new()), 8_000)
}

struct W {
    chain: Arc<MemChain>,
    net: Arc<MemNet>,
    hub: Arc<RouteHub>,
    provs: Vec<(String, Arc<Provider>)>,
    pay: Arc<RoutePayer>,
    shards: Vec<Arc<Shard>>,
    dir: TempDir,
}

impl W {
    fn new(n: usize, kw: PKw) -> Self {
        let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
        let h = hub(&chain, &net, &dir);
        let mut provs = vec![];
        for i in 0..n {
            let origin = format!("http://p{i}.test");
            provs.push((origin.clone(), provider(&chain, &net, &dir, &origin, adaptor::random_secret(), &kw)));
            h.connect(&origin, None, None).unwrap();
        }
        chain.confirm_all();
        h.watch_tick();
        let pay = payer(&chain, &net);
        pay.open().unwrap();
        let shards = provs.iter().map(|(o, _)| pay.shard(&format!("{o}/v1/chunk"), "POST").unwrap()).collect();
        let w = Self { chain, net, hub: h, provs, pay, shards, dir };
        stream(&w.pay, &w.shards[0], 10);
        w
    }

    fn origin(&self) -> &str {
        &self.provs[0].0
    }

    fn prov(&self) -> &Arc<Provider> {
        &self.provs[0].1
    }

    fn sh(&self) -> &Arc<Shard> {
        &self.shards[0]
    }

    fn st1(&self) -> xbt402::ledger::ChannelState {
        self.hub.ch1_state(&self.pay.chan().unwrap()).unwrap()
    }

    fn st2_of(&self, p: &Provider) -> xbt402::ledger::ChannelState {
        p.channel_ids().iter().filter_map(|c| p.channel_state(c)).find(|s| s.closed_txid.is_empty()).unwrap()
    }

    fn st2(&self) -> xbt402::ledger::ChannelState {
        self.st2_of(self.prov())
    }

    fn oc(&self) -> xbt402::hub::OutChannel {
        self.hub.out_channels()[self.origin()].clone()
    }

    /// Refused with `code`, and nothing written or pre-signed for ch2.
    fn refused_clean(&self, tamper: Option<&Tamper>, code: &str) -> Value {
        let oc = self.oc();
        let (seq2, best2, n_lock) = (oc.seq, self.st2().best_cum, self.net.count(ROUTE_LOCK_PATH));
        let (st, doc) = route_request(&self.net, &self.pay, self.sh(), tamper);
        assert_eq!(doc["error"], code, "{doc}");
        assert!(st >= 400);
        assert!(!xbt402::json::truthy(self.st1().extra.get("route_lock")), "a refused lock was written on ch1");
        let oc = self.oc();
        assert!(oc.pending.is_empty(), "ch2 was pre-signed for a refused lock");
        assert_eq!((oc.seq, self.net.count(ROUTE_LOCK_PATH), self.st2().best_cum), (seq2, n_lock, best2));
        doc
    }
}

fn stream(pay: &RoutePayer, sh: &Arc<Shard>, n: usize) {
    for _ in 0..n {
        let r = pay.call(sh, "POST", br#"{"tokens":1}"#).unwrap();
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    }
}

enum Mode {
    Normal,
    NoAuth,
    Seq(u64),
}

type Tamper = dyn Fn(&RoutePayer, &mut Value, &mut Value) -> Mode;

/// The client's POST /x402/route built exactly as RoutePayer::lock does, edited by `tamper`.
fn route_request(net: &Arc<MemNet>, pay: &RoutePayer, sh: &Arc<Shard>, tamper: Option<&Tamper>) -> (u16, Value) {
    let inv = sh.snapshot().invoice;
    let d = sh.due_sat().max(1) as u64;
    let q = pay.quote().unwrap();
    let (routed, units, paid, _) = pay.counters();
    let (f, _) = fee_due(&q, d, units, paid);
    let cum = next_cum(routed, d + f, pay.ch1_params().unwrap().min_amount());
    let chan = pay.chan().unwrap();
    let point = inv["point"].as_str().unwrap().to_string();
    let lock_id = inv["lockId"].as_str().unwrap().to_string();
    let sa = pay.signer().sign_state_adaptor(&chan, cum, &pt33(&point), &json!({})).unwrap();
    let mut route = json!({"provider": sh.origin, "payTo": sh.pay_to, "network": NET, "amount": d, "point": point, "fee": f,
                           "feeQuote": q.to_json(), "invoice": inv, "session": sh.session, "lockId": lock_id,
                           "lockAuth": lock_auth(&sh.session_key(), &sh.session, &lock_id, d as i128, &point, &pay.hub_pay_to()),
                           "tweak": hex::encode(sa.tweak)});
    let mut pl = json!({"chan": chan, "seq": 0, "cum": cum.to_string(), "adaptor": sa.pre.to_json(), "point": hex::encode(sa.point)});
    let mode = tamper.map(|t| t(pay, &mut pl, &mut route)).unwrap_or(Mode::Normal);
    let (mut seq, accepted) = pay.next_seq().unwrap();
    if let Mode::Seq(s) = mode {
        seq = s;
    }
    pl["seq"] = seq.into();
    let body = dumps(&json!({"route": route}));
    pl["auth"] = pay.signer().request_auth(&chan, Some(&pl["seq"]), Some(&pl["cum"]), None, &request_digest("POST", HUB_ROUTE_PATH, body.as_bytes())).unwrap().into();
    if let Mode::NoAuth = mode {
        pl["auth"] = "00".repeat(32).into();
    }
    let hdr = b64json(&json!({"x402Version": 2, "accepted": accepted, "payload": pl}));
    let r = NetTransport(net.clone()).request("POST", &format!("{HUB}{HUB_ROUTE_PATH}"), body.as_bytes(), &[("PAYMENT-SIGNATURE".into(), hdr)]).unwrap();
    pay.signer().void_lock(&chan).unwrap();
    (r.status, xbt402::json::parse_slice(&r.body).unwrap_or(Value::Null))
}

fn world(n: usize, kw: PKw) -> W {
    W::new(n, kw)
}

fn relock(pay: &RoutePayer, pl: &mut Value, rt: &mut Value, cum: u64) {
    let chan = pay.chan().unwrap();
    pay.signer().void_lock(&chan).unwrap();
    let sa: AdaptorLock = pay.signer().sign_state_adaptor(&chan, cum, &pt33(rt["point"].as_str().unwrap()), &json!({})).unwrap();
    pl["cum"] = cum.to_string().into();
    pl["adaptor"] = sa.pre.to_json();
    pl["point"] = hex::encode(sa.point).into();
    rt["tweak"] = hex::encode(sa.tweak).into();
}

// --- the hub's checks, in order ------------------------------------------------------------------------

#[test]
fn hub_0_a_valid_lock_goes_through_and_a_retry_gets_the_same_answer() {
    let w = world(1, PKw::default());
    let (st, doc) = route_request(&w.net, &w.pay, w.sh(), None);
    assert_eq!(st, 200, "{doc}");
    // first ch2 lock: the channel's floor (dust + closeFee on a payee-pays ch2)
    assert_eq!(w.st2().best_cum, w.st2().params.min_amount());
    assert_eq!(w.st2().params.close_fee_payer, FeePayer::Payee);
    let done = &w.st1().extra["route_done"][doc["lockId"].as_str().unwrap()];
    assert_eq!(done["secret"], doc["secret"]);
}

#[test]
fn hub_1_auth() {
    let w = world(1, PKw::default());
    w.refused_clean(Some(&|_, _, _| Mode::NoAuth), "bad_auth");
    w.refused_clean(Some(&|_, _, _| Mode::Seq(0)), "bad_auth");
}

#[test]
fn hub_2_point_must_be_t_plus_rg() {
    let w = world(1, PKw::default());
    w.refused_clean(Some(&|_, _, rt| {
        rt["point"] = hex::encode(adaptor::enc(&adaptor::point_of(&adaptor::random_secret()))).into();
        Mode::Normal
    }), "bad_point");
    w.refused_clean(Some(&|_, _, rt| {
        rt["tweak"] = hex::encode(adaptor::random_secret().secret_bytes()).into();
        Mode::Normal
    }), "bad_point");
}

#[test]
fn hub_3_amount() {
    let w = world(1, PKw::default());
    w.refused_clean(Some(&|_, pl, _| {
        pl["cum"] = (pl["cum"].as_str().unwrap().parse::<u64>().unwrap() + 1).to_string().into();
        Mode::Normal
    }), "bad_amount");
    w.refused_clean(Some(&|_, _, rt| { rt["amount"] = 20_001.into(); Mode::Normal }), "bad_amount");
    w.refused_clean(Some(&|_, _, rt| { rt["amount"] = 0.into(); Mode::Normal }), "bad_amount");
}

#[test]
fn hub_4_preverify_against_the_exact_state() {
    let w = world(1, PKw::default());
    w.refused_clean(Some(&|pay, pl, _| {
        let p = pay.ch1_params().unwrap();
        let t1 = adaptor::dec_hex(pl["point"].as_str().unwrap()).unwrap();
        let cum = pl["cum"].as_str().unwrap().parse().unwrap();
        pl["adaptor"] = adaptor::presign(&sk(0xBAD), &p.sighash(&p.state_tx(cum).unwrap()).unwrap(), &t1).unwrap().to_json(); // not the payer
        Mode::Normal
    }), "bad_adaptor");
    w.refused_clean(Some(&|pay, pl, _| {
        // the payer's own pre-signature, under another point
        let chan = pay.chan().unwrap();
        pay.signer().void_lock(&chan).unwrap();
        let other = adaptor::enc(&adaptor::point_of(&sk(12345)));
        let sa = pay.signer().sign_state_adaptor(&chan, pl["cum"].as_str().unwrap().parse().unwrap(), &other, &json!({})).unwrap();
        pl["adaptor"] = sa.pre.to_json();
        Mode::Normal
    }), "bad_adaptor");
}

#[test]
fn hub_5_fee_quote_signed_live_and_paid() {
    let w = world(1, PKw::default());
    let q = w.pay.quote().unwrap();
    assert!(fee_due(&q, w.sh().due_sat().max(1) as u64, 0, 0).0 >= 1);
    let doc = w.refused_clean(Some(&|pay, pl, rt| {
        // a consistent lock that pays less fee than due
        let f = rt["fee"].as_u64().unwrap() - 1;
        rt["fee"] = f.into();
        let cum = next_cum(pay.counters().0, rt["amount"].as_u64().unwrap() + f, DUST);
        relock(pay, pl, rt, cum);
        Mode::Normal
    }), "route_fee");
    assert!(doc.get("feeDue").is_some());
    let mut forged = q.clone();
    (forged.fee_ppm, forged.fee_base_msat) = (0, 0);
    let forged = forged.sign(&sk(0xF00)); // not the hub
    w.refused_clean(Some(&move |_, _, rt| { rt["feeQuote"] = forged.to_json(); Mode::Normal }), "route_fee");
    let mut expired = q.clone();
    expired.valid_until = now_i() - 1;
    let expired = expired.sign(&sk(0x4B4B)); // the hub's, old
    w.refused_clean(Some(&move |_, _, rt| { rt["feeQuote"] = expired.to_json(); Mode::Normal }), "route_fee");
}

#[test]
fn hub_7_one_lock_per_channel() {
    let w = world(1, PKw::default());
    w.hub.set_withhold("all"); // the first lock stays pending at the hub
    let (_, doc) = route_request(&w.net, &w.pay, w.sh(), None);
    assert_eq!(doc["error"], "route_pending");
    w.hub.set_withhold("");
    assert!(xbt402::json::truthy(w.st1().extra.get("route_lock")));
    let (_, doc) = route_request(&w.net, &w.pay, w.sh(), None);
    assert_eq!(doc["error"], "lock_outstanding");
}

#[test]
fn hub_7_one_lock_per_ch2_across_clients() {
    let w = world(1, PKw::default());
    let o = w.origin().to_string();
    w.hub.with_out(|b| {
        b.chans.get_mut(&o).unwrap().pending = json!({"lockId": "other-client", "cum": 999, "d": 1, "T": "", "ch1": "x", "at": now_f()})
            .as_object().unwrap().clone()
    });
    let (_, doc) = route_request(&w.net, &w.pay, w.sh(), None);
    assert_eq!(doc["error"], "lock_outstanding");
    assert!(!xbt402::json::truthy(w.st1().extra.get("route_lock")));
    w.hub.with_out(|b| b.chans.get_mut(&o).unwrap().pending.clear());
}

#[test]
fn hub_order_the_first_failing_check_answers() {
    let w = world(1, PKw::default());
    w.refused_clean(Some(&|_, _, rt| { rt["point"] = format!("02{}01", "00".repeat(31)).into(); Mode::NoAuth }), "bad_auth");
    w.refused_clean(Some(&|_, pl, rt| { rt["tweak"] = "11".repeat(32).into(); pl["cum"] = "1".into(); Mode::Normal }), "bad_point");
    w.refused_clean(Some(&|_, pl, rt| {
        pl["cum"] = (pl["cum"].as_str().unwrap().parse::<u64>().unwrap() + 1).to_string().into();
        rt["feeQuote"] = json!({});
        Mode::Normal
    }), "bad_amount");
    w.refused_clean(Some(&|_, pl, rt| { pl["adaptor"]["s1"] = "11".repeat(32).into(); rt["feeQuote"] = json!({}); Mode::Normal }), "bad_adaptor");
}

#[test]
fn hub_6_route_ok_or_the_unguarded_cap() {
    let w = world(1, PKw { amsat: 60 * AMSAT_PER_SAT, ..PKw::default() });
    // a client channel that ends before the hub's channel to the provider (+ delta): route_ok fails
    let pay = payer_with(&w.chain, &w.net, Arc::new(LocalSigner::new()), 600);
    pay.open().unwrap();
    let sh = pay.shard(&format!("{}/v1/chunk", w.origin()), "POST").unwrap();
    stream(&pay, &sh, 10);
    let (p1, p2) = (pay.ch1_params().unwrap(), w.oc().params);
    assert!(!route_ok(w.chain.height(), p1.expiry, p2.expiry, 36, 36));
    assert!(sh.due_sat() > 500); // 600 sat accrued
    let (st, doc) = route_request(&w.net, &pay, &sh, None);
    assert_eq!((st, doc["error"].as_str()), (400, Some("route_expiry")), "{doc}");
    // at or under maxUnguardedLockSat it is forwarded anyway (a bounded, unprofitable attack)
    let shk = (sh.session_key(), sh.session.clone());
    let small = move |pay: &RoutePayer, pl: &mut Value, rt: &mut Value| {
        rt["amount"] = 400.into();
        let (f, _) = fee_due(&pay.quote().unwrap(), 400, 0, 0);
        rt["fee"] = f.into();
        relock(pay, pl, rt, next_cum(0, 400 + f, DUST));
        rt["lockAuth"] = lock_auth(&shk.0, &shk.1, rt["lockId"].as_str().unwrap(), 400, rt["point"].as_str().unwrap(), &pay.hub_pay_to()).into();
        Mode::Normal
    };
    let (st, doc) = route_request(&w.net, &pay, &sh, Some(&small));
    assert_eq!(st, 200, "{doc}");
}

// --- the provider's lock endpoint ----------------------------------------------------------------------

/// A ch2 lock sent to the provider as the hub would, with edits.
fn hub_lock(w: &W, route_over: Value, pl_over: Value) -> (u16, Value) {
    let oc = w.oc();
    let p2 = &oc.params;
    let inv = w.sh().snapshot().invoice;
    let point = inv["point"].as_str().unwrap().to_string();
    let lock_id = inv["lockId"].as_str().unwrap().to_string();
    let d = 3u64;
    let cum = next_cum(oc.routed, d, p2.min_amount());
    let secret = Sc::from_hex64(&oc.secret).unwrap().secret().unwrap();
    let pre = adaptor::presign(&secret, &p2.sighash(&p2.state_tx(cum).unwrap()).unwrap(), &adaptor::dec_hex(&point).unwrap()).unwrap();
    let mut route = json!({"session": w.sh().session, "lockId": lock_id, "amount": d, "hub": w.hub.pay_to(),
                           "lockAuth": lock_auth(&w.sh().session_key(), &w.sh().session, &lock_id, d as i128, &point, w.hub.pay_to())});
    for (k, v) in route_over.as_object().unwrap() {
        route[k] = v.clone();
    }
    let o = w.origin().to_string();
    let seq = w.hub.with_out(|b| {
        let c = b.chans.get_mut(&o).unwrap();
        c.seq += 1;
        c.seq
    });
    let mut pl = json!({"chan": p2.channel_id(), "seq": seq, "cum": cum.to_string(), "point": point, "adaptor": pre.to_json()});
    for (k, v) in pl_over.as_object().unwrap() {
        pl[k] = v.clone();
    }
    let body = dumps(&json!({"route": route}));
    let key = channel_auth_key(&secret, &p2.payee_pub).unwrap();
    pl["auth"] = request_auth(&key, &p2.channel_id(), pl.get("seq"), pl.get("cum"), None, &request_digest("POST", ROUTE_LOCK_PATH, body.as_bytes())).into();
    let r = NetTransport(w.net.clone()).request("POST", &format!("{o}{ROUTE_LOCK_PATH}"), body.as_bytes(),
                                                  &[("PAYMENT-SIGNATURE".into(), b64json(&json!({"x402Version": 2, "accepted": {}, "payload": pl})))]).unwrap();
    (r.status, xbt402::json::parse_slice(&r.body).unwrap())
}

#[test]
fn provider_valid_lock_reveals_t_for_the_invoice_point() {
    let w = world(1, PKw::default());
    let t = adaptor::dec_hex(w.sh().snapshot().invoice["point"].as_str().unwrap()).unwrap();
    let (st, doc) = hub_lock(&w, json!({}), json!({}));
    assert_eq!(st, 200, "{doc}");
    assert_eq!(adaptor::point_of(&Sc::from_hex64(doc["secret"].as_str().unwrap()).unwrap().secret().unwrap()), t);
}

#[test]
fn provider_hub_cannot_reprice_a_lock() {
    // the hub locks less on ch2 than the client authorised: refused, and t stays secret
    let w = world(1, PKw::default());
    let (_, doc) = hub_lock(&w, json!({"amount": 2}), json!({}));
    assert_eq!(doc["error"], "bad_auth");
    assert!(doc.get("secret").is_none());
}

#[test]
fn provider_lock_for_another_hub_or_an_unbound_channel() {
    let w = world(1, PKw::default());
    let (_, doc) = hub_lock(&w, json!({"hub": hex::encode(ecdsa::pubkey(&sk(0x999)))}), json!({}));
    assert_eq!(doc["error"], "route_blocked");
}

#[test]
fn provider_invoice_fresh_and_expiring() {
    let w = world(1, PKw::default());
    let (_, doc) = hub_lock(&w, json!({"lockId": "00".repeat(12)}), json!({}));
    assert_eq!(doc["error"], "bad_invoice");
    w.prov().routes().lock().sessions.get_mut(&w.sh().session).unwrap().valid_until = now_f() - 1.0;
    let (_, doc) = hub_lock(&w, json!({}), json!({}));
    assert_eq!(doc["error"], "bad_invoice");
}

#[test]
fn provider_amount_and_adaptor() {
    let w = world(1, PKw::default());
    let p2 = w.oc().params;
    let (_, doc) = hub_lock(&w, json!({}), json!({"cum": (p2.min_amount() + 1).to_string()}));
    assert_eq!(doc["error"], "bad_amount");
    let secret = Sc::from_hex64(&w.oc().secret).unwrap().secret().unwrap();
    let bad = adaptor::presign(&secret, &p2.sighash(&p2.state_tx(p2.min_amount()).unwrap()).unwrap(), &adaptor::point_of(&sk(7))).unwrap();
    let (_, doc) = hub_lock(&w, json!({}), json!({"adaptor": bad.to_json()}));
    assert_eq!(doc["error"], "bad_adaptor");
}

#[test]
fn provider_write_ahead_then_the_same_answer_again() {
    // saved (with t) before answering; a hub that lost the answer asks again and gets the same t,
    // and the session is credited once
    let w = world(1, PKw::default());
    let (_, first) = hub_lock(&w, json!({}), json!({}));
    let st2 = w.st2();
    let lid = first["lockId"].as_str().unwrap();
    assert_eq!((st2.best_cum, &st2.extra["route_locks"][lid]["secret"]), (st2.params.min_amount(), &first["secret"]));
    let name = w.origin().replace("http://", "").replace('.', "_");
    let reloaded = Ledger::open(&w.dir.0.join(format!("prov-{name}.jsonl"))).unwrap(); // on disk
    assert_eq!(reloaded.channels[&st2.params.channel_id()].extra["route_locks"][lid]["secret"], first["secret"]);
    let paid = w.prov().routes().lock().sessions[&w.sh().session].paid_sat;
    let t = Sc::from_hex64(first["secret"].as_str().unwrap()).unwrap().secret().unwrap();
    let (st, again) = hub_lock(&w, json!({"lockId": lid}), json!({"point": hex::encode(adaptor::enc(&adaptor::point_of(&t)))}));
    assert_eq!((st, &again["secret"]), (200, &first["secret"]));
    assert_eq!(w.prov().routes().lock().sessions[&w.sh().session].paid_sat, paid);
}

#[test]
fn provider_lost_answer_is_retried_and_settles_once() {
    let w = world(1, PKw::default());
    let n = Arc::new(AtomicUsize::new(1));
    let n2 = n.clone();
    w.net.set_drop(w.origin(), Some(Box::new(move |_, path| path == ROUTE_LOCK_PATH && n2.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |x| x.checked_sub(1)).is_ok())));
    let r = w.pay.lock(w.sh()).unwrap().unwrap();
    assert_eq!(r["status"], "paid", "{r}");
    assert_eq!(w.oc().routed, w.prov().routes().lock().sessions[&w.sh().session].paid_sat);
}

// --- cmp-lead's constraints --------------------------------------------------------------------------

#[test]
fn c1_rate_and_locks_off_the_data_path() {
    // >= 10 metered calls/s per provider on 4 providers while the per-window locks run beside them
    let w = world(4, PKw::default());
    let stop = Arc::new(AtomicBool::new(false));
    w.pay.start(Duration::from_millis(150));
    let t0 = Instant::now();
    let ths: Vec<_> = w.shards.iter().cloned().map(|sh| {
        let (pay, stop) = (w.pay.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut n = 0;
            while !stop.load(Ordering::Relaxed) {
                n += (pay.call(&sh, "POST", b"x").unwrap().status == 200) as u32;
                std::thread::sleep(Duration::from_millis(1000 / 15));
            }
            n
        })
    }).collect();
    std::thread::sleep(Duration::from_secs(2));
    stop.store(true, Ordering::Relaxed);
    let counts: Vec<u32> = ths.into_iter().map(|t| t.join().unwrap()).collect();
    w.pay.stop();
    let dt = t0.elapsed().as_secs_f64();
    for n in counts {
        assert!(n as f64 / dt >= 10.0, "{n} calls in {dt}");
    }
    let s = w.pay.stats();
    assert!(s.locks >= 4, "{s:?}");
    assert_eq!(s.voided, 0, "{:?}", w.pay.events.lock().unwrap());
}

#[test]
fn c2_amsat_meter_and_carry_at_each_hop() {
    // 0.37 sat per call: meters agree to the amsat; after the last lock paid == ceil(total); the hub
    // fee is carried the same way: fees == ceil(sum of exact fees)
    let w = world(1, PKw::default());
    let sh = w.sh();
    let mut exact = 0u128;
    for _ in 0..12 {
        stream(&w.pay, sh, 7);
        let d = sh.due_sat() as u64;
        let before = w.pay.counters().1;
        let r = w.pay.lock(sh).unwrap().unwrap();
        assert_eq!(r["status"], "paid", "{r}");
        let q = w.pay.quote().unwrap();
        exact += q.units(d);
        assert_eq!(w.pay.counters().1 - before, q.units(d));
    }
    let s = w.prov().routes().lock().sessions[&sh.session].clone();
    let c = sh.snapshot();
    assert_eq!(s.accrued_amsat, c.accrued_amsat);
    assert_eq!(s.accrued_amsat, c.seen_amsat);
    assert_eq!(s.accrued_amsat, (10 + 12 * 7) * 370 * 10u128.pow(18));
    assert_eq!(s.paid_sat as u128, ceil_div(s.accrued_amsat, AMSAT_PER_SAT));
    let (routed, _, fee_paid, _) = w.pay.counters();
    assert_eq!(fee_paid as u128, ceil_div(exact, FEE_UNITS_PER_SAT));
    let st1 = w.st1();
    assert_eq!(st1.extra["routed_sat"].as_u64().unwrap(), routed);
    assert_eq!(st1.best_cum, routed.max(DUST));
}

#[test]
fn c3_fan_out_one_client_channel_serial_locks() {
    // one ch1 pays 4 providers; locks are serial, so at most one lock is ever at risk on ch1
    let w = world(4, PKw::default());
    for sh in &w.shards {
        stream(&w.pay, sh, 20);
    }
    for sh in &w.shards {
        assert_eq!(w.pay.lock(sh).unwrap().unwrap()["status"], "paid");
    }
    assert_eq!(w.hub.stats.lock().unwrap().ch1_locks_at_forward, vec![1, 1, 1, 1]);
    assert_eq!(w.hub.inbound.channel_ids().len(), 1);
    let ids: std::collections::HashSet<String> = w.hub.out_channels().values().map(|c| c.params.channel_id()).collect();
    assert_eq!(ids.len(), 4);
}

#[test]
fn c4_signed_quotes_end_to_end() {
    // a per-call charge above the provider's signed quote is refused
    let w = world(4, PKw::default());
    assert!(w.sh().quote.verify() && w.pay.quote().unwrap().verify());
    w.prov().routes().lock().offers.get_mut("/v1/chunk").unwrap().amsat_per_call *= 2; // the provider overcharges
    assert_eq!(w.pay.call(w.sh(), "POST", b"x").unwrap_err().code, "bad_receipt");
}

#[test]
fn c7_one_payee_key_for_two_origins_one_ch2() {
    // AGP-044: one live ch2 per payTo. One operator key behind two origins (CMP-023: one paid
    // provider per operator) gets ONE hub-funded ch2; both origins route over it.
    let w = world(1, PKw::default());
    let op = sk(0xA0A0);
    let a = provider(&w.chain, &w.net, &w.dir, "http://dev-a.test", op, &PKw::default());
    w.net.add("http://dev-b.test", a.clone());
    let cap0 = w.hub.committed_sat();
    let oa = w.hub.connect("http://dev-a.test", None, None).unwrap();
    let ob = w.hub.connect("http://DEV-B.test:80/", None, None).unwrap(); // canonicalized
    assert_eq!(oa.params.channel_id(), ob.params.channel_id());
    assert_eq!(w.hub.committed_sat(), cap0 + oa.params.capacity);
    w.chain.confirm_all();
    w.hub.watch_tick();
    let sa = w.pay.shard("http://dev-a.test/v1/chunk", "POST").unwrap();
    let sb = w.pay.shard("http://dev-b.test/v1/chunk", "POST").unwrap();
    assert_eq!(sa.pay_to, sb.pay_to);
    for sh in [&sa, &sb] {
        stream(&w.pay, sh, 5);
        assert_eq!(w.pay.lock(sh).unwrap().unwrap()["status"], "paid");
    }
    let oc = w.hub.out_channels();
    assert!(!oc.contains_key("http://dev-b.test"));
    assert_eq!(oc["http://dev-a.test"].routed, sa.snapshot().locked_sat + sb.snapshot().locked_sat);
}

// --- withholding ---------------------------------------------------------------------------------------

#[test]
fn c6_hub_stops_forwarding_provider_stops_client_loses_one_lock() {
    let w = world(2, PKw::default());
    w.hub.set_withhold("all");
    stream(&w.pay, &w.shards[1], 5);
    let r = w.pay.lock(w.sh()).unwrap().unwrap();
    assert_eq!(r["status"], "pending");
    let stuck = w.pay.pending().unwrap();
    // while one lock is out on ch1 nothing else is signed: the client's exposure is that one lock
    assert!(w.pay.lock(&w.shards[1]).unwrap().is_none());
    // the provider serves on credit for window + lockWait, then stops
    let t0 = Instant::now();
    let mut st = 0;
    while t0.elapsed().as_secs_f64() < 0.3 + 0.6 + 1.0 {
        st = w.pay.call(w.sh(), "POST", b"x").unwrap().status;
        if st == 402 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(st, 402);
    assert_eq!(w.sh().snapshot().stopped, "route_credit");
    assert!(t0.elapsed().as_secs_f64() <= 0.3 + 0.6 + 0.5);
    // the stuck lock is voided when its invoice expires unanswered; it is the only loss exposure
    w.pay.expire_pending();
    assert!(w.pay.pending().is_none());
    assert_eq!(w.pay.stats().voided, 1);
    assert!(stuck["d"].as_u64().unwrap() + stuck["f"].as_u64().unwrap() <= 20_000);
}

#[test]
fn receipt_withheld_client_reads_t_from_the_provider() {
    let w = world(2, PKw::default());
    w.hub.set_withhold("receipt");
    assert_eq!(w.pay.lock(w.sh()).unwrap().unwrap()["status"], "pending");
    w.pay.call(w.sh(), "POST", b"x").unwrap(); // the provider's ROUTE-STATE carries t
    assert!(w.pay.pending().is_none());
    assert_eq!(w.pay.stats().via_provider, 1);
    assert_eq!(w.pay.counters().0, w.st1().extra["routed_sat"].as_u64().unwrap());
}

#[test]
fn stale_answer_to_a_given_up_lock_then_resync() {
    let w = world(2, PKw::default());
    w.hub.set_withhold("receipt");
    assert_eq!(w.pay.lock(w.sh()).unwrap().unwrap()["status"], "pending");
    w.hub.set_withhold("");
    w.pay.expire_pending(); // given up; no ROUTE-STATE seen since
    assert_eq!(w.pay.stats().voided, 1);
    assert_eq!(w.pay.lock(w.sh()).unwrap().unwrap(), json!({"status": "refused", "error": "stale_answer", "detail": "hub answer does not open this lock"}));
    stream(&w.pay, w.sh(), 3); // a fresh invoice (and lastLock) arrives
    assert_eq!(w.pay.lock(w.sh()).unwrap().unwrap()["status"], "resynced");
    stream(&w.pay, w.sh(), 3);
    assert_eq!(w.pay.lock(w.sh()).unwrap().unwrap()["status"], "paid");
    let (routed, _, _, signed) = w.pay.counters();
    assert_eq!(routed, w.st1().extra["routed_sat"].as_u64().unwrap());
    assert_eq!(signed, w.st1().best_cum);
}

#[test]
fn provider_never_reveals_hub_writes_off_and_blocks() {
    let w = world(2, PKw::default());
    w.prov().set_no_reveal(true);
    stream(&w.pay, w.sh(), 30);
    w.hub.set_reveal_timeout(0.3);
    let (b1, b2) = (w.st1().best_cum, w.st2().best_cum);
    let refused = w.pay.lock(w.sh()).unwrap().unwrap();
    assert_eq!((refused["status"].as_str(), refused["error"].as_str()), (Some("refused"), Some("route_failed")), "{refused}");
    assert_eq!((w.st1().best_cum, w.st2().best_cum), (b1, b2));
    let oc = w.oc();
    assert!(!oc.blocked.is_empty());
    assert_eq!(oc.stale.len(), 1); // kept for on-chain recovery
    let (_, doc) = route_request(&w.net, &w.pay, w.sh(), None);
    assert_eq!(doc["error"], "route_blocked");
}

/// A signer that keeps its locks when told to give them up (the client that recovers from chain).
struct KeepLocks(Arc<LocalSigner>);

impl StateSigner for KeepLocks {
    fn new_key(&self, o: &str) -> Result<ecdsa::PubkeyBytes> { self.0.new_key(o) }
    fn attach(&self, o: &str, p: &xbt402::channel::ChannelParams) -> Result<String> { self.0.attach(o, p) }
    fn sign_state(&self, c: &str, a: u64) -> Result<Vec<u8>> { self.0.sign_state(c, a) }
    fn sign_state_a3(&self, c: &str, a: u64) -> Result<Vec<u8>> { self.0.sign_state_a3(c, a) }
    fn sign_rollover(&self, c: &str, a: u64, spk: &[u8], cap: u64) -> Result<Vec<u8>> { self.0.sign_rollover(c, a, spk, cap) }
    fn sign_close(&self, c: &str) -> Result<Vec<u8>> { self.0.sign_close(c) }
    fn sign_refund(&self, c: &str) -> Result<String> { self.0.sign_refund(c) }
    fn request_auth(&self, c: &str, s: Option<&Value>, cum: Option<&Value>, sig: Option<&str>, req: &str) -> Result<String> { self.0.request_auth(c, s, cum, sig, req) }
    fn sign_conditional(&self, c: &str, u: u64, cond: &xbt402::conditional::ConditionalParams) -> Result<Vec<u8>> { self.0.sign_conditional(c, u, cond) }
}

impl RouteSigner for KeepLocks {
    fn sign_state_adaptor(&self, c: &str, cum: u64, p: &ecdsa::PubkeyBytes, r: &Value) -> Result<AdaptorLock> { self.0.sign_state_adaptor(c, cum, p, r) }
    fn resolve_lock(&self, c: &str, s: &[u8; 32]) -> Result<[u8; 32]> { self.0.resolve_lock(c, s) }
    fn void_lock(&self, _c: &str) -> Result<bool> { Ok(false) }
    fn adopt_lock(&self, c: &str, cum: u64) -> Result<()> { self.0.adopt_lock(c, cum) }
    fn recover_lock(&self, c: &str, tx: &Tx) -> Result<[u8; 32]> { self.0.recover_lock(c, tx) }
}

#[test]
fn watcher_t_from_a_ch2_close_completes_ch1_even_after_a_hub_restart() {
    // the provider completes the lock but its answers never reach the hub; the hub writes the lock
    // off (kept), restarts, reads t off the provider's ch2 close and completes ch1; the client, which
    // never heard back, reads t + r off the hub's ch1 close
    let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
    let h = hub(&chain, &net, &dir);
    let origin = "http://p0.test";
    let prov = provider(&chain, &net, &dir, origin, adaptor::random_secret(), &PKw::default());
    h.connect(origin, None, None).unwrap();
    chain.confirm_all();
    h.watch_tick();
    let local = Arc::new(LocalSigner::new());
    let pay = payer_with(&chain, &net, Arc::new(KeepLocks(local.clone())), 8_000);
    pay.open().unwrap();
    let sh = pay.shard(&format!("{origin}/v1/chunk"), "POST").unwrap();
    stream(&pay, &sh, 20);
    net.set_drop(origin, Some(Box::new(|_, p| p == ROUTE_LOCK_PATH)));
    h.set_reveal_timeout(0.3);
    assert_eq!(pay.lock(&sh).unwrap().unwrap()["status"], "refused");
    let chan = pay.chan().unwrap();
    let pend = local.pending_lock(&chan).expect("the client kept its lock");
    let st2 = prov.channel_ids().iter().filter_map(|c| prov.channel_state(c)).next().unwrap();
    assert_eq!(st2.best_cum, st2.params.min_amount()); // the provider did complete it
    let hub2 = hub_with(&chain, &net, &dir.0.join("hub"), sk(0x4B4B), hub_cfg());
    assert_eq!(hub2.out_channels()[origin].stale.len(), 1);
    prov.close_now(&st2.params.channel_id()).unwrap();
    let acts = hub2.watch_tick();
    assert!(acts.iter().any(|a| a["event"] == "secret_from_close" && a["ch1_completed"] == true), "{acts:?}");
    assert_eq!(hub2.ch1_state(&chan).unwrap().best_cum, pend.cum);
    let close1 = hub2.inbound.close_now(&chan).unwrap();
    let t = local.recover_lock(&chan, &chain.raw(&close1).unwrap()).unwrap();
    let tp = adaptor::point_of(&Sc::strict(&t).unwrap().secret().unwrap());
    assert_eq!(adaptor::enc(&tp), pend.t);
}

#[test]
fn resync_client_adopts_only_a_lock_it_gave_up() {
    let w = world(2, PKw::default());
    w.net.set_drop(w.origin(), Some(Box::new(|_, p| p == ROUTE_LOCK_PATH)));
    w.hub.set_reveal_timeout(0.3);
    assert_eq!(w.pay.lock(w.sh()).unwrap().unwrap()["status"], "refused");
    let gone = w.pay.last_given_up().unwrap();
    w.prov().close_now(&w.st2().params.channel_id()).unwrap();
    let acts = w.hub.watch_tick();
    assert!(acts.iter().any(|a| a["event"] == "secret_from_close"), "{acts:?}");
    assert_eq!(w.st1().best_cum, gone);
    stream(&w.pay, &w.shards[1], 5);
    assert_eq!(w.pay.lock(&w.shards[1]).unwrap().unwrap()["status"], "resynced");
    assert_eq!(w.pay.counters().3, gone);
    assert_eq!(w.pay.lock(&w.shards[1]).unwrap().unwrap()["status"], "paid");
    assert_eq!(w.pay.counters().0, w.st1().extra["routed_sat"].as_u64().unwrap());
    // a hub view that is not one of our given-up locks is never adopted
    assert!(!w.pay.try_resync(&json!({"bestCum": 1_000_000, "routedSat": 1, "feeUnits": 0, "feePaid": 0})));
    assert!(w.pay.signer().adopt_lock(&w.pay.chan().unwrap(), 1_000_000).is_err());
}

// --- config, rollover, v1.2 ------------------------------------------------------------------------------

#[test]
fn hub_config_liquidity_cap_and_fee_strategies() {
    let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
    provider(&chain, &net, &dir, "http://a.test", adaptor::random_secret(), &PKw::default());
    provider(&chain, &net, &dir, "http://b.test", adaptor::random_secret(), &PKw::default());
    let mut cfg = hub_cfg();
    cfg.liquidity_cap_sat = 150_000;
    cfg.fee_strategy = json!({"kind": "utilization", "ppm_min": 1000, "ppm_max": 9000, "base_msat": 0});
    let h = hub_with(&chain, &net, &dir.0.join("hub"), sk(0x4B4B), cfg);
    let q0 = h.fee_quote().unwrap();
    assert_eq!((q0.fee_base_msat, q0.fee_ppm), (0, 1000));
    h.connect("http://a.test", None, None).unwrap();
    let q1 = h.fee_quote().unwrap();
    assert_eq!(q1.fee_ppm, 1000 + (8000.0 * 100_000.0 / 150_000.0) as u64);
    assert!(q1.seq > q0.seq); // a new signed quote, the old one still live
    assert_eq!(h.connect("http://b.test", None, None).unwrap_err().code, "liquidity_cap"); // 200,000 > 150,000
    assert!(HubConfig::from_json(&json!({"fee_ppm": 1, "hub_pays_close": true})).is_err());
    let mut custom = hub_with(&chain, &net, &dir.0.join("hub2"), sk(0x77), hub_cfg());
    custom.set_fee_strategy(Box::new(|_| (5, 7)));
    let q = custom.fee_quote().unwrap();
    assert_eq!((q.fee_base_msat, q.fee_ppm), (5, 7));
}

#[test]
fn c5_hub_funds_and_rolls_ch2_at_the_providers_threshold() {
    let w = world(1, PKw { settle_multiple: 2, amsat: 40 * AMSAT_PER_SAT, ..PKw::default() });
    let first = w.oc().params.channel_id();
    stream(&w.pay, w.sh(), 40); // + 10: 2,000 sat accrued
    assert_eq!(w.pay.lock(w.sh()).unwrap().unwrap()["status"], "paid");
    let oc = w.oc();
    let fee = oc.params.close_fee;
    // the threshold counts the provider's own close fee (payee-pays ch2): net >= 2 x fee
    assert!(oc.signed - fee >= 2 * fee);
    let acts = w.hub.watch_tick();
    let roll = acts.iter().find(|a| a["event"] == "ch2_rollover").expect("rollover").clone();
    assert_eq!(roll["amount"].as_u64().unwrap(), oc.signed);
    let tx = w.chain.raw(roll["txid"].as_str().unwrap()).unwrap();
    // pays the provider its balance less its own close fee; the next ch2 takes all the hub's rest
    assert_eq!(tx.outputs[0].value as u64, oc.signed - fee);
    assert_eq!(tx.outputs[1].value as u64, oc.params.capacity - oc.signed);
    assert_eq!(format!("{}:{}", tx.inputs[0].prevout.txid_hex(), tx.inputs[0].prevout.vout), first);
    let new = w.oc();
    // make-before-break (AGP-053): the next ch2 is open at once, unconfirmed, under the provider's cap
    assert_eq!((new.state.as_str(), new.params.funding_txid()), ("open", roll["txid"].as_str().unwrap().to_string()));
    assert_eq!(new.zero_conf["confirmed"], false);
    stream(&w.pay, w.sh(), 5);
    assert_eq!(w.pay.lock(w.sh()).unwrap().unwrap()["status"], "paid"); // routing goes on over the new ch2 unconfirmed
    w.chain.confirm_all();
    w.hub.watch_tick();
    assert_eq!((w.oc().state.as_str(), w.oc().zero_conf["confirmed"].clone()), ("open", json!(true)));
    stream(&w.pay, w.sh(), 5);
    assert_eq!(w.pay.lock(w.sh()).unwrap().unwrap()["status"], "paid"); // and once it confirmed
    assert!(w.prov().channel_state(&new.params.channel_id()).unwrap().best_cum > 0);
}

#[test]
fn no_rollover_while_a_lock_is_pending() {
    let w = world(1, PKw::default());
    let o = w.origin().to_string();
    let (point, chan) = (w.sh().snapshot().invoice["point"].clone(), w.pay.chan().unwrap());
    w.hub.with_out(|b| {
        let c = b.chans.get_mut(&o).unwrap();
        c.signed = 5_000;
        c.pending = json!({"lockId": "x", "cum": 5100, "d": 100, "T": point, "ch1": chan, "at": now_f() + 60.0, "route": {}}).as_object().unwrap().clone();
    });
    w.hub.set_reveal_timeout(120.0);
    let acts = w.hub.watch_tick();
    assert!(!acts.iter().any(|a| a["event"] == "ch2_rollover"), "{acts:?}");
    w.hub.with_out(|b| b.chans.get_mut(&o).unwrap().pending.clear());
}

#[test]
fn v12_routing_extra_advertises_both_hops() {
    let w = world(1, PKw::default());
    let r = NetTransport(w.net.clone()).request("GET", &format!("{HUB}{HUB_ROUTE_PATH}"), b"", &[]).unwrap();
    assert_eq!(r.status, 402);
    let doc = xbt402::wire::unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap();
    let ex = &doc["accepts"][0]["extra"]["routing"];
    assert_eq!((ex["ch1CloseFeePayer"].as_str(), ex["ch2CloseFeePayer"].as_str()), (Some("payer"), Some("payee")));
    assert_eq!(ex["providers"], json!([w.origin()]));
    assert!(FeeQuote::from_json(&ex["quote"]).unwrap().verify());
}

#[test]
fn v12_a_v11_provider_needs_a_payer_pays_hub() {
    let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
    provider(&chain, &net, &dir, "http://old.test", adaptor::random_secret(), &PKw { route_fee_payer: FeePayer::Payer, ..PKw::default() });
    let h = hub_with(&chain, &net, &dir.0.join("hub"), sk(0x4B4B), hub_cfg());
    assert_eq!(h.connect("http://old.test", None, None).unwrap_err().code, "bad_fee_payer");
    let mut cfg = hub_cfg();
    cfg.ch2_close_fee_payer = FeePayer::Payer;
    let h = hub_with(&chain, &net, &dir.0.join("hub-v11"), sk(0x4B4C), cfg);
    let oc = h.connect("http://old.test", None, None).unwrap();
    assert_eq!(oc.params.close_fee_payer, FeePayer::Payer);
    chain.confirm_all();
    h.watch_tick();
    assert_eq!(h.out_channels()["http://old.test"].state, "open");
}

#[test]
fn v12_provider_refuses_an_early_rollover() {
    // below its net threshold and far from its margin, a payee-pays provider will not co-sign
    let w = world(1, PKw::default());
    assert_eq!(w.pay.lock(w.sh()).unwrap().unwrap()["status"], "paid");
    let oc = w.oc();
    assert!(oc.signed >= oc.params.min_amount());
    assert_eq!(w.hub.rollover(&oc).unwrap_err().code, "settle_early");
    // near the provider's close margin a small rollover is accepted
    w.chain.set_height(oc.params.expiry - 36 - 30);
    let ev = w.hub.rollover(&w.oc()).unwrap();
    assert_eq!(ev["event"], "ch2_rollover");
}

#[test]
fn a_paid_invoice_is_never_locked_again_even_a_floor_lock() {
    // regression (found by the all-Rust demo): a lock completes while the client still holds a
    // ROUTE-STATE from before it (the same invoice); locking that invoice again got the hub's saved
    // answer, which a floor lock accepted: d + f counted twice, then every lock was bad_amount
    let w = world(1, PKw::default());
    assert_eq!(w.pay.lock(w.sh()).unwrap().unwrap()["status"], "paid"); // cum 546: the floor
    stream(&w.pay, w.sh(), 4);
    let old_inv = w.sh().snapshot().invoice;
    let r = w.pay.lock(w.sh()).unwrap().unwrap();
    assert_eq!(r["status"], "paid");
    assert_eq!(w.pay.stats().floor_locks, 1);
    // the stale view: the paid invoice, and more accrued
    {
        let mut s = w.sh().state.lock().unwrap();
        s.invoice = old_inv;
        s.accrued_amsat += 3 * AMSAT_PER_SAT;
    }
    assert!(w.pay.lock(w.sh()).unwrap().is_none(), "locked a paid invoice");
    let (routed, _, fee_paid, signed) = w.pay.counters();
    assert_eq!((routed, fee_paid, signed.max(DUST)), (w.st1().extra["routed_sat"].as_u64().unwrap(), w.st1().extra["fee_paid"].as_u64().unwrap(), w.st1().best_cum));
    // the next real ROUTE-STATE brings a fresh invoice and routing goes on in step
    stream(&w.pay, w.sh(), 5);
    assert_eq!(w.pay.lock(w.sh()).unwrap().unwrap()["status"], "paid");
    assert_eq!(w.pay.counters().0, w.st1().extra["routed_sat"].as_u64().unwrap());
}

#[test]
fn hostile_routing_input_never_panics() {
    // hub /x402/route, provider /lock and routed calls with malformed headers and bodies: every answer
    // is a 4xx (or a 402 refusal), never a panic or a 5xx
    let w = world(1, PKw::default());
    let t = NetTransport(w.net.clone());
    let chan = w.pay.chan().unwrap();
    let ch2 = w.oc().params.channel_id();
    let hdrs = [String::new(), "!!".into(), b64json(&json!(null)), b64json(&json!({"payload": []})), b64json(&json!({"payload": {"chan": chan}})),
                b64json(&json!({"payload": {"chan": chan, "seq": "x", "cum": {}, "adaptor": 5, "point": "zz"}})),
                b64json(&json!({"payload": {"chan": ch2, "seq": 99, "cum": "-1", "adaptor": {"R": "00"}, "point": "02"}})),
                b64json(&json!({"session": 1, "seq": -5, "auth": null})), b64json(&json!({"session": w.sh().session, "seq": "1e999", "auth": "00"}))];
    let bodies: [&[u8]; 7] = [b"", b"{", b"[]", br#"{"route": 5}"#, br#"{"route": {"amount": "x", "fee": [], "lockId": {}, "provider": null}}"#,
                              br#"{"route": {"amount": 99999999999999999999999, "fee": -1, "lockId": "a", "provider": "http://p0.test", "point": "02", "tweak": "zz"}}"#,
                              br#"{"route": {"session": "s", "lockId": "l", "amount": -3, "lockAuth": 1, "hub": []}}"#];
    for h in &hdrs {
        for b in bodies {
            for (url, name) in [(format!("{HUB}{HUB_ROUTE_PATH}"), "PAYMENT-SIGNATURE"), (format!("{}{ROUTE_LOCK_PATH}", w.origin()), "PAYMENT-SIGNATURE"),
                                (format!("{}/v1/chunk", w.origin()), "ROUTE-AUTH"), (format!("{}/v1/chunk", w.origin()), "ROUTE-CLIENT")] {
                let r = t.request("POST", &url, b, &[(name.into(), h.clone())]).unwrap();
                assert!((400..500).contains(&r.status), "{url} {name}={h} body={} -> {}", String::from_utf8_lossy(b), r.status);
            }
        }
    }
    // and the honest path still works afterwards
    assert_eq!(w.pay.lock(w.sh()).unwrap().unwrap()["status"], "paid");
}

// --- AGP-054: the data path never resolves a lock whose POST is out --------------------------------------

type After = Box<dyn Fn(&HttpResponse) -> Option<HttpResponse> + Send + Sync>;

/// The hub, with `after` run once its answer to POST /x402/route is ready (and before it returns).
struct HubHook {
    app: Arc<RouteHub>,
    after: After,
}

impl xbt402::http::HttpService for HubHook {
    fn body_limit(&self, path: &str) -> usize {
        xbt402::http::HttpService::body_limit(&*self.app, path)
    }

    fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str) -> HttpResponse {
        let r = xbt402::http::HttpService::serve(&*self.app, method, path, headers, body, url);
        if path == HUB_ROUTE_PATH {
            if let Some(x) = (self.after)(&r) {
                return x;
            }
        }
        r
    }
}

#[test]
fn agp054_a_data_call_never_resolves_a_lock_whose_post_is_out() {
    let w = world(1, PKw::default());
    let seen: Arc<std::sync::Mutex<Option<(bool, Value)>>> = Arc::default();
    let (pay, sh, s2) = (w.pay.clone(), w.sh().clone(), seen.clone());
    w.net.add(HUB, Arc::new(HubHook { app: w.hub.clone(), after: Box::new(move |_| {
        pay.call(&sh, "POST", b"x").unwrap(); // the provider's ROUTE-STATE now shows t
        *s2.lock().unwrap() = Some((pay.pending().is_some(), sh.snapshot().last_lock));
        None
    }) }));
    let r = w.pay.lock(w.sh()).unwrap().unwrap();
    let (pending, last) = seen.lock().unwrap().clone().unwrap();
    assert!(pending, "the data call resolved the in-flight lock");
    assert!(last.get("lockId").is_some());
    assert_eq!(r["status"], "paid");
    assert_eq!(w.pay.stats().via_provider, 0);
    assert!(w.pay.pending().is_none());
}

#[test]
fn agp054_a_refusal_of_a_lock_the_provider_was_paid_for_resolves_via_the_provider() {
    let w = world(1, PKw::default());
    let (pay, sh) = (w.pay.clone(), w.sh().clone());
    w.net.add(HUB, Arc::new(HubHook { app: w.hub.clone(), after: Box::new(move |_| {
        pay.call(&sh, "POST", b"x").unwrap();
        Some(HttpResponse::new(502, vec![("Content-Type".into(), "application/json".into())], br#"{"error":"route_failed"}"#.to_vec()))
    }) }));
    let r = w.pay.lock(w.sh()).unwrap().unwrap();
    assert_eq!((r["status"].as_str(), r["via"].as_str()), (Some("paid"), Some("provider")));
    assert_eq!((w.pay.stats().voided, w.pay.stats().via_provider), (0, 1));
    assert_eq!(w.pay.counters().0, w.st1().extra["routed_sat"].as_u64().unwrap());
}
