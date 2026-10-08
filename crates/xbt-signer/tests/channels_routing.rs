//! Channel budget and unacknowledged states (mirrors B2 tests/test_channel_budget.py,
//! test_unacked_state.py, test_channel_policy.py), routing policy and adaptor locks (mirrors
//! tests/test_routing.py, with a test-double adaptor scheme and with xbt402's real one over the
//! socket as an xbt402 `RouteSigner`), and the external Rust payer over the signer socket (keys never
//! in the client).
mod common;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use common::*;
use serde_json::{json, Value};
use xbt402::client::{Client, ClientConfig};
use xbt402::adaptor;
use xbt402::signer::{RouteSigner, StateSigner};
use xbt_primitives::secp256k1::{Scalar, SecretKey};
use xbt_signer::channels::ChannelBook;
use xbt_signer::client::RemoteSigner;

#[test]
fn concurrent_increments_cannot_exceed_the_cap_and_exact_cap_is_ok() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    rig.open(); // cap 9,400, spent 500
    let book: Arc<ChannelBook> = rig.s.book.clone();
    let hs: Vec<_> = (0..16).map(|_| {
        let b = book.clone();
        std::thread::spawn(move || b.increment(PROVIDER, 1_000).is_ok())
    }).collect();
    let ok = hs.into_iter().map(|h| h.join().unwrap()).filter(|x| *x).count();
    assert_eq!(ok, 8, "500 + 8 x 1,000 = 8,500 <= 9,400; a ninth would exceed");
    let rec = book.get(PROVIDER).unwrap();
    assert_eq!(rec.spent_sats, 8_500);
    assert_eq!(book.increment(PROVIDER, 901).unwrap_err().code, "channel_cap");
    assert!(book.increment(PROVIDER, 900).is_ok(), "exactly the cap");
    // the public list has no keys
    assert!(xbt_signer::sanitize::assert_no_key_material(&json!(book.list_public())).is_ok());
    assert_eq!(book.find_dest(&rec.chan).as_deref(), Some(PROVIDER));
}

#[test]
fn a_lost_answer_resends_the_same_state_and_only_an_ack_lets_the_next_call_sign_higher() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    rig.open();
    let states = || rig.sigs().iter().filter(|x| x["kind"] == "channel_state").count();
    assert_eq!(states(), 1);
    // the provider's answer is lost after the state was signed
    rig.web.fail_paid.store(true, Ordering::SeqCst);
    assert_eq!(rig.pay()["rule"], "xbt402");
    rig.web.fail_paid.store(false, Ordering::SeqCst);
    let rec = rig.s.book.get(PROVIDER).unwrap();
    assert_eq!((rec.used_sats, rec.acked_sats), (1_000, 546));
    // the next call hands the same (cum, sig) again: it is charged and acknowledged
    let r = rig.pay();
    assert_eq!((r["cum"].as_i64(), r["charged_sats"].as_i64()), (Some(1_000), Some(500)), "{r}");
    assert_eq!(states(), 2, "no new signature for the resend");
    let r = rig.pay();
    assert_eq!(r["cum"], 1_500);
    assert_eq!(states(), 3);
    // sign_state with an already-signed cum hands back the cached signature
    let a = rig.call("sign_state", json!({"dest": PROVIDER, "cum": 2_000}));
    assert_eq!(a["verdict"], "allow", "{a}");
    let rec = rig.s.book.get(PROVIDER).unwrap();
    assert_eq!(rig.s.book.sign_state(PROVIDER, 2_000).unwrap(), hex::decode(&rec.last_sig).unwrap());
}

#[test]
fn policy_still_decides_on_channel_payments() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"daily_budget_sats": 1_200}), false);
    rig.fund_hot(1, 12_000);
    rig.open();
    let r = rig.call("xbt402_pay", json!({"url": URL, "max_sats": 400}));
    assert_eq!(r["rule"], "max_sats", "quoted 500 > max_sats 400: {r}");
    rig.pay();
    let r = rig.pay();
    assert_eq!((r["verdict"].as_str(), r["rule"].as_str()), (Some("deny"), Some("daily_budget")), "{r}");
    assert_eq!(rig.s.book.get(PROVIDER).unwrap().spent_sats, 1_000, "nothing signed after the deny");
    let r = rig.call("xbt402_pay", json!({"url": "http://evil.example/x", "max_sats": 500}));
    assert_eq!(r["rule"], "allowlist");
}

// --- routing ------------------------------------------------------------------------------------

fn routing_rig() -> Rig {
    let routing = json!({"routing": {"hubs": {PROVIDER: {"max_fee_ppm": 5000, "max_fee_base_msat": 2000}}, "max_lock_sats": 2000,
                                     "daily_budget_sats": 3000}});
    let rig = Rig::build(routing, false, "regtest", Some(Arc::new(TestAdaptor)));
    rig.fund_hot(1, 12_000);
    rig.open();
    rig
}

fn point(t: &SecretKey) -> String {
    hex::encode(xbt_primitives::secp256k1::PublicKey::from_secret_key(xbt_primitives::secp256k1::SECP256K1, t).serialize())
}

#[test]
fn routing_policy_caps_fee_lock_and_daily_budget() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = routing_rig();
    let chan = rig.s.book.get(PROVIDER).unwrap().chan;
    let t = point(&secret("t"));
    let lock = |cum: i64, amount: i64, fee: i64, hub: &str| rig.call("xbt402_sign_state_adaptor",
        json!({"chan": chan, "cum": cum, "point": t, "route": {"hub": hub, "amount": amount, "fee": fee, "lockId": "L1"}}));
    assert_eq!(lock(1_146, 590, 10, "http://other.hub")["rule"], "route_hub");
    // fee cap for 590 sat: ceil((2000 + 590*1000*5000/1e6)/1000) + 1 = 6
    assert_eq!(lock(1_146, 590, 7, PROVIDER)["rule"], "route_fee_cap");
    assert_eq!(lock(546 + 2_001, 1_990, 6, PROVIDER)["rule"], "route_lock_max");
    let r = lock(1_146, 594, 6, PROVIDER);
    assert_eq!(r["verdict"], "allow", "{r}");
    assert_eq!(lock(1_446, 594, 6, PROVIDER)["rule"], "lock_outstanding");
    let st = rig.call("routing_status", json!({}));
    assert_eq!(st["pending"][chan.as_str()]["cum"], 1_146);
    // a plain state below the lock is refused
    assert_eq!(rig.s.book.sign_state(PROVIDER, 1_000).unwrap_err().code, "lock_outstanding");
}

#[test]
fn a_lock_is_written_ahead_recovered_after_a_restart_and_resolved_once() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = routing_rig();
    let chan = rig.s.book.get(PROVIDER).unwrap().chan;
    let t = secret("t");
    let r = rig.call("xbt402_sign_state_adaptor", json!({"chan": chan, "cum": 1_146, "point": point(&t),
                                                         "route": {"hub": PROVIDER, "amount": 594, "fee": 6, "lockId": "L1"}}));
    let r_tweak = SecretKey::from_slice(&hex::decode(r["tweak"].as_str().unwrap()).unwrap()).unwrap();
    let chans: Value = serde_json::from_str(&std::fs::read_to_string(rig.root.join(".run/channels.json")).unwrap()).unwrap();
    assert_eq!(chans["channels"][PROVIDER]["pending_lock"]["cum"], 1_146, "written before the pre-signature left");
    assert!(rig.sigs().iter().any(|x| x["kind"] == "adaptor_presig" && x["rule"] == "policy:routing"));
    rig.restart().unwrap();
    // wrong secrets are refused
    assert_eq!(rig.call("xbt402_resolve_lock", json!({"chan": chan, "secret": "11".repeat(32)}))["rule"], "bad_secret");
    // the hub's close carries t + r in its witness
    let y = t.add_tweak(&Scalar::from(r_tweak)).unwrap().secret_bytes();
    let mut tx = xbt_primitives::tx::Tx::new(2, vec![xbt_primitives::tx::TxIn::new(xbt_primitives::tx::OutPoint::from_display(&"44".repeat(32), 0).unwrap(), 0)],
                                             vec![xbt_primitives::tx::TxOut::new(1000, vec![0u8; 22])], 0);
    tx.inputs[0].witness = vec![vec![1, 2, 3], y.to_vec()];
    rig.chain.st.lock().unwrap().mempool.insert(tx.txid(), json!({"txid": tx.txid(), "hex": tx.to_hex(), "vin": [], "vout": []}));
    let r = rig.call("xbt402_recover_lock", json!({"chan": chan, "txid": tx.txid()}));
    assert_eq!(r["t"], hex::encode(t.secret_bytes()), "{r}");
    let rec = rig.s.book.get(PROVIDER).unwrap();
    assert_eq!((rec.used_sats, rec.has_pending_lock()), (1_146, false));
    assert_eq!(rig.call("routing_status", json!({}))["spent_24h_sats"], 600);
    assert_eq!(rig.call("xbt402_resolve_lock", json!({"chan": chan, "secret": hex::encode(y)}))["rule"], "no_state");
    // the ordinary policy engine decides too: 1,000 is the human threshold
    let r = rig.call("xbt402_sign_state_adaptor", json!({"chan": chan, "cum": 1_146 + 1_000, "point": point(&t),
                                                         "route": {"hub": PROVIDER, "amount": 994, "fee": 6, "lockId": "L2"}}));
    assert_eq!(r["rule"], "human_threshold", "{r}");
    let r = rig.call("xbt402_sign_state_adaptor", json!({"chan": chan, "cum": 1_146 + 999, "point": point(&t),
                                                         "route": {"hub": PROVIDER, "amount": 993, "fee": 6, "lockId": "L2"}}));
    assert_eq!(r["verdict"], "allow", "{r}");
    // the daily routing budget counts resolved (600) and pending (999) locks
    let pol = &rig.s.routing.policy();
    assert!(xbt_signer::routing::check_route(pol, &rig.s.routing.spend, PROVIDER, 993, 6, 999, rig.s.routing.pending_sats(),
                                             xbt_signer::pyjson::now_f64()).is_none());
    let d = xbt_signer::routing::check_route(pol, &rig.s.routing.spend, PROVIDER, 1_395, 6, 1_402, rig.s.routing.pending_sats(),
                                             xbt_signer::pyjson::now_f64()).unwrap();
    assert_eq!(d["rule"], "route_daily_budget", "600 + 999 + 1,402 > 3,000");
    // give L2 up; adopt only a lock this wallet gave up
    rig.call("xbt402_void_lock", json!({"chan": chan}));
    assert_eq!(rig.call("xbt402_adopt_lock", json!({"chan": chan, "cum": 9_999}))["rule"], "bad_amount");
    assert_eq!(rig.call("xbt402_adopt_lock", json!({"chan": chan, "cum": 2_145}))["adopted"], true);
    assert_eq!(rig.call("routing_status", json!({}))["spent_24h_sats"], 600 + 999);
    assert_eq!(rig.s.book.get(PROVIDER).unwrap().used_sats, 2_145);
}

/// AGP-055: a lock changes no key, so the keys file (sealed, with a fresh salt on every rewrite) is
/// not rewritten by it; a restart still opens the same keys, and the lock resolves.
#[test]
fn a_lock_does_not_rewrite_the_keys_file() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = routing_rig();
    let keys = rig.root.join(".run/channel_keys.json");
    let before = std::fs::read(&keys).unwrap();
    let chan = rig.s.book.get(PROVIDER).unwrap().chan;
    let t = secret("t");
    let r = rig.call("xbt402_sign_state_adaptor", json!({"chan": chan, "cum": 1_146, "point": point(&t),
                                                         "route": {"hub": PROVIDER, "amount": 594, "fee": 6, "lockId": "L1"}}));
    assert_eq!(std::fs::read(&keys).unwrap(), before, "sign_state_adaptor rewrote the keys file");
    let r_tweak = SecretKey::from_slice(&hex::decode(r["tweak"].as_str().unwrap()).unwrap()).unwrap();
    let y = t.add_tweak(&Scalar::from(r_tweak)).unwrap().secret_bytes();
    assert_eq!(rig.call("xbt402_resolve_lock", json!({"chan": chan, "secret": hex::encode(y)}))["t"], hex::encode(t.secret_bytes()));
    assert_eq!(std::fs::read(&keys).unwrap(), before, "resolve_lock rewrote the keys file");
    rig.restart().unwrap();
    assert_eq!(std::fs::read(&keys).unwrap(), before, "a restart rewrote the keys file");
    let r = rig.call("xbt402_sign_state_adaptor", json!({"chan": chan, "cum": 1_446, "point": point(&t),
                                                         "route": {"hub": PROVIDER, "amount": 295, "fee": 5, "lockId": "L2"}}));
    assert_eq!(r["cum"], 1_446, "the restarted signer still holds the channel key: {r}");
}

#[test]
fn without_an_adaptor_implementation_routed_locks_are_refused() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"routing": {"hubs": {PROVIDER: {"max_fee_ppm": 5000, "max_fee_base_msat": 2000}}, "max_lock_sats": 2000,
                                          "daily_budget_sats": 3000}}), false);
    rig.fund_hot(1, 12_000);
    let chan = rig.open()["chan"].as_str().unwrap().to_string();
    // the signer's default scheme is xbt402's adaptor (AGP-034); a RouteSigner built without one refuses
    assert_eq!(rig.call("routing_status", json!({}))["adaptor"], "available");
    let bare = xbt_signer::routing::RouteSigner::new(rig.s.book.clone(), rig.s.routing.policy(), None, None, None).unwrap();
    let e = bare.sign_state_adaptor(&chan, 1_146, &point(&secret("t")), json!({"hub": PROVIDER, "amount": 594, "fee": 6})).unwrap_err();
    assert_eq!(e.code, "adaptor_unavailable");
    assert_eq!(bare.status()["adaptor"], "unavailable (AGP-026)");
    assert_eq!(rig.call("routing_status", json!({}))["policy"]["enabled"], true);
    let off = Rig::new(json!({}), false);
    assert_eq!(off.call("routing_status", json!({}))["policy"]["enabled"], false);
}

/// xbt402's RouteSigner over the socket with the real ECDSA adaptor: the pre-signature verifies
/// against the channel's exact state under T1 = T + r·G, t comes back from t + r (the hub) and from
/// a close's witness (recover, raw tx passed), void/adopt follow B2, and the routing policy decides
/// before anything is signed.
#[cfg(unix)]
#[test]
fn route_signer_over_the_socket_with_the_real_adaptor() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::build(json!({"routing": {"hubs": {PROVIDER: {"max_fee_ppm": 5000, "max_fee_base_msat": 2000}}, "max_lock_sats": 2000,
                                            "daily_budget_sats": 3000}}), false, "regtest", None);
    rig.fund_hot(1, 12_000);
    rig.open();
    let sock = rig.dir.path().join("signer.sock");
    let _srv = xbt_signer::server::spawn(rig.s.clone(), &sock, false).unwrap();
    let remote = RemoteSigner::new(&sock);
    let rs: &dyn RouteSigner = &remote;
    let rec = rig.s.book.get(PROVIDER).unwrap();
    let (chan, params) = (rec.chan.clone(), rec.params().unwrap());
    let route = |amount: u64, fee: u64, id: &str| json!({"hub": PROVIDER, "amount": amount, "fee": fee, "lockId": id});
    let pt = |t: &SecretKey| adaptor::enc(&adaptor::point_of(t));

    // policy first: another hub, a fee over the cap; nothing is signed
    let presigs = || rig.sigs().iter().filter(|x| x["kind"] == "adaptor_presig").count();
    let t1s = secret("t1");
    let bad = json!({"hub": "http://other.hub", "amount": 594, "fee": 6});
    assert_eq!(rs.sign_state_adaptor(&chan, 1_146, &pt(&t1s), &bad).unwrap_err().code, "route_hub");
    assert_eq!(rs.sign_state_adaptor(&chan, 1_146, &pt(&t1s), &route(594, 7, "L0")).unwrap_err().code, "route_fee_cap");
    assert_eq!(presigs(), 0);

    // lock 1: a real pre-signature of state(1146) under T + r·G, resolved by the hub's t + r
    let l1 = rs.sign_state_adaptor(&chan, 1_146, &pt(&t1s), &route(594, 6, "L1")).unwrap();
    let r1 = SecretKey::from_slice(&l1.tweak).unwrap();
    let t1_point = adaptor::add(Some(&adaptor::point_of(&t1s)), Some(&adaptor::point_of(&r1))).unwrap();
    assert_eq!(l1.point, adaptor::enc(&t1_point));
    let z = params.sighash(&params.state_tx(1_146).unwrap()).unwrap();
    assert!(adaptor::preverify(&params.payer_pub, &z, &t1_point, &l1.pre), "pre-verifies against the exact state");
    assert_eq!(rs.sign_state_adaptor(&chan, 1_446, &pt(&t1s), &route(294, 5, "Lx")).unwrap_err().code, "lock_outstanding");
    assert_eq!(rs.resolve_lock(&chan, &secret("wrong").secret_bytes()).unwrap_err().code, "bad_secret");
    let y1 = t1s.add_tweak(&Scalar::from(r1)).unwrap();
    assert_eq!(rs.resolve_lock(&chan, &y1.secret_bytes()).unwrap(), t1s.secret_bytes());
    assert_eq!(rig.s.book.get(PROVIDER).unwrap().used_sats, 1_146);
    assert_eq!(presigs(), 1);

    // lock 2: the hub's close carries the completed signature; the payer passes the raw tx
    let t2s = secret("t2");
    let l2 = rs.sign_state_adaptor(&chan, 1_446, &pt(&t2s), &route(294, 5, "L2")).unwrap();
    let y2 = t2s.add_tweak(&Scalar::from(SecretKey::from_slice(&l2.tweak).unwrap())).unwrap();
    let mut sig = adaptor::adapt(&l2.pre, &y2).unwrap();
    sig.push(0x21);
    assert!(xbt_primitives::ecdsa::verify(&params.payer_pub, &params.sighash(&params.state_tx(1_446).unwrap()).unwrap(), &sig[..sig.len() - 1]),
            "the completion is the payer's valid signature of state(1446)");
    let mut tx = params.state_tx(1_446).unwrap();
    tx.inputs[0].witness = vec![sig, vec![0u8; 71]];
    assert_eq!(rs.recover_lock(&chan, &tx).unwrap(), t2s.secret_bytes());
    assert_eq!(rig.s.book.get(PROVIDER).unwrap().used_sats, 1_446);

    // lock 3: given up, then adopted by its own cum only
    let l3 = rs.sign_state_adaptor(&chan, 1_646, &pt(&secret("t3")), &route(194, 4, "L3")).unwrap();
    assert!(rs.void_lock(&chan).unwrap());
    assert!(!rs.void_lock(&chan).unwrap());
    assert_eq!(rs.adopt_lock(&chan, 9_999).unwrap_err().code, "bad_amount");
    rs.adopt_lock(&chan, l3.cum).unwrap();
    assert_eq!(rig.s.book.get(PROVIDER).unwrap().used_sats, 1_646);
    assert_eq!(rig.call("routing_status", json!({}))["spent_24h_sats"], 600 + 300 + 200);
    assert_eq!(rig.call("signatures", json!({}))["chain_ok"], true);
}

// --- the Rust payer over the socket -------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_rust_payer_on_the_signer_socket_never_holds_a_key_and_the_signer_decides() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"hot_balance_cap_sats": 0}), true);
    rig.fund_hot(1, 30_000);
    let sock = rig.dir.path().join("signer.sock");
    let _srv = xbt_signer::server::spawn(rig.s.clone(), &sock, false).unwrap();
    assert_eq!(xbt_signer::fsx::mode_of(&sock), 0o600);
    let remote = RemoteSigner::new(&sock);
    let signer: Arc<dyn StateSigner> = Arc::new(remote.clone());
    let chain = rig.chain.clone();
    let mut cfg = ClientConfig::new(&rig.chain.network());
    cfg.capacity = 10_000;
    cfg.max_price = 500;
    // the provider checks the funding's confirmations: the test node confirms at once
    let wallet_chain = rig.chain.clone();
    struct ConfirmingWallet(RemoteSigner, Arc<FakeChain>);
    impl xbt402::client::Wallet for ConfirmingWallet {
        fn fund(&self, a: &str, s: u64) -> xbt402::Result<(String, u32)> {
            let r = self.0.fund(a, s)?;
            self.1.mine(1);
            Ok(r)
        }

        fn fund_channel(&self, o: &str, p: &xbt402::channel::ChannelParams, a: &str, s: u64) -> xbt402::Result<(String, u32)> {
            let r = self.0.fund_channel(o, p, a, s)?;
            self.1.mine(1);
            Ok(r)
        }
    }
    let mut client = Client::new(cfg, Box::new(WebRef(rig.web.clone())), Box::new(ConfirmingWallet(remote.clone(), wallet_chain)),
                                 Box::new(move || Ok(chain.height() as u32))).with_signer(signer);
    for i in 0..5 {
        let r = client.request("GET", URL, b"").unwrap_or_else(|e| panic!("call {i}: {e:?} {}", rig.call("history", json!({"limit": 40}))));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    }
    let ch = client.channels[PROVIDER].clone();
    assert!(ch.payer.secret().is_none() && ch.auth_key == [0u8; 32], "no payer secret, no ECDH key in the client");
    assert_eq!(hex::encode(&ch.payer.params.payer_spk), rig.hot_spk(), "close change comes back to the hot key");
    let sigs = rig.sigs();
    let states: Vec<&Value> = sigs.iter().filter(|x| x["kind"] == "channel_state").collect();
    assert!(!states.is_empty() && states.iter().all(|x| x["method"] == "xbt402_sign_state" && x["rule"] == "policy:ok"));
    // the signer's policy decides on every state the client asks for
    let chan = ch.payer.params.channel_id();
    let e = remote.sign_state(&chan, 9_000).unwrap_err();
    assert_eq!(e.code, "max_per_tx", "{}", e.msg);
    assert_eq!(remote.sign_state(&chan, 1).unwrap_err().code, "amount", "a lower cum is never signed (no increase)");
    assert_eq!(rig.sigs().iter().filter(|x| x["kind"] == "channel_state").count(), states.len());
    let r = client.close(PROVIDER).unwrap();
    let txid = r["txid"].as_str().unwrap().to_string();
    let m = remote.mark_closed(&ch.payer.params.channel_id(), &txid).unwrap();
    assert_eq!((m["state"].as_str(), m["close_change"].as_str()), (Some("closed"), Some("counted")), "{m}");
    assert_eq!(rig.call("signatures", json!({}))["chain_ok"], true);
}

struct WebRef(Arc<Web>);

impl xbt402::client::Transport for WebRef {
    fn request(&self, m: &str, u: &str, b: &[u8], h: &[(String, String)]) -> xbt402::Result<xbt402::provider::HttpResponse> {
        self.0.request(m, u, b, h)
    }
}
