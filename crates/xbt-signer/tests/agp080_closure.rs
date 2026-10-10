//! AGP-080 (closure audit, wallet): no signature leaves unbooked (the stream's hash-locked last
//! chunk, adaptor pre-signatures; W1), a channel leaves the refund watcher only when the chain
//! shows its funding spent (`xbt402_mark_closed`, `xbt402_attach` of `<origin>/next`, a provider's
//! close; W3), a seller's URL stays on its origin (X1), and the on-chain `pay` rail books before
//! it sends (K1).
mod common;

use std::sync::{Arc, Mutex};

use common::*;
use serde_json::{json, Value};
use xbt402::channel::{ChannelParams, FeePayer};
use xbt402::client::Transport;
use xbt402::conditional::encrypt;
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::wire::{b64json, unb64json, CLOSE_PATH, FACILITATOR_VERIFY, ROLLOVER_PATH};
use xbt_primitives::ecdsa;
use xbt_primitives::hash::sha256;
use xbt_signer::node::Node;
use xbt_signer::session::{leaf, manifest_message};
use xbt_signer::signer::{Signer, SignerOptions};

type Hook = Box<dyn Fn(&str, &str, &[u8], &[(String, String)]) -> Option<xbt402::Result<HttpResponse>> + Send + Sync>;

/// The rig's in-process web with a hook in front: every URL the signer asks for is recorded, and
/// the hook may answer instead of the provider.
struct Hooked {
    web: Arc<Web>,
    hook: Hook,
    seen: Mutex<Vec<String>>,
}

impl Transport for Hooked {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> xbt402::Result<HttpResponse> {
        self.seen.lock().unwrap().push(url.to_string());
        match (self.hook)(method, url, body, headers) {
            Some(r) => r,
            None => self.web.request(method, url, body, headers),
        }
    }
}

/// The rig's signer again, on the same root and chain, behind `hook`.
fn hooked(rig: &mut Rig, hook: Hook) -> Arc<Hooked> {
    let t = Arc::new(Hooked { web: rig.web.clone(), hook, seen: Mutex::new(vec![]) });
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(rig.chain.clone()), transport: Some(t.clone()), adaptor: rig.adaptor.clone(),
                                                   ..Default::default() }).unwrap();
    t
}

/// The policy ledger's total as the log on disk holds it now (payments, with amends applied).
fn ledger_on_disk(root: &std::path::Path) -> i64 {
    let text = std::fs::read_to_string(root.join(".run/ledger.payments.jsonl")).unwrap_or_default();
    let mut rows: Vec<(String, i64)> = vec![];
    for v in text.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()) {
        if let Some(t) = v.get("amend").and_then(Value::as_str) {
            if let Some(i) = rows.iter().rposition(|(id, _)| id == t) {
                match v["amount_sats"].as_i64() {
                    Some(n) => rows[i].1 = n,
                    None => {
                        rows.remove(i);
                    }
                }
            }
        } else if v.get("dest").is_some() {
            rows.push((v["txid"].as_str().unwrap_or("").to_string(), v["amount_sats"].as_i64().unwrap_or(0)));
        }
    }
    rows.iter().map(|(_, a)| a).sum()
}

fn ledger(rig: &Rig) -> i64 {
    rig.s.engine.store.payments().unwrap().iter().map(|e| e.amount_sats).sum()
}

fn rule(v: &Value) -> &str {
    v["rule"].as_str().unwrap_or("")
}

fn has_sig(headers: &[(String, String)]) -> Option<Value> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-SIGNATURE")).and_then(|(_, v)| unb64json(v).ok())
}

fn cum_of(payload: &Value) -> i64 {
    payload["cum"].as_str().and_then(|c| c.parse().ok()).or_else(|| payload["cum"].as_i64()).unwrap_or(0)
}

fn seller_pay_to() -> Vec<u8> {
    ecdsa::pubkey(&secret("provider payTo")).to_vec()
}

// --- W1: streams ------------------------------------------------------------------------------------

/// Above the dust floor: a hash lock for less is refused.
const PRICE: i64 = 600;

/// A two-chunk stream sold by the rig's provider key: chunk 0 in the clear, chunk 1 hash-locked.
struct Stream {
    doc: Value,
    chunk0: Value,
    cond: Value,
    key: Vec<u8>,
}

fn stream(chunk_url: &str) -> Stream {
    let (c0, c1, key) = (b"first chunk".to_vec(), b"the last chunk".to_vec(), vec![7u8; 32]);
    let ct = encrypt(&c1, &key);
    let (l0, l1) = (leaf(0, &c0), leaf(1, &c1));
    let root = sha256(&[b"node".as_slice(), &l0, &l1].concat());
    let mut m = json!({"id": "s1", "n": 2, "size": c0.len() + c1.len(), "root": hex::encode(root), "lock": hex::encode(sha256(&key)),
                       "finalCt": hex::encode(sha256(&ct)), "price": PRICE, "payTo": hex::encode(seller_pay_to()), "lastProof": [hex::encode(l0)]});
    m["sig"] = hex::encode(ecdsa::sign(&secret("provider payTo"), &manifest_message(&m))).into();
    Stream { doc: json!({"stream": "xbt402-merkle-v1", "manifest": m.clone(), "chunkUrl": chunk_url}),
             chunk0: json!({"i": 0, "data": hex::encode(&c0), "proof": [hex::encode(l1)]}),
             cond: json!({"hash": m["lock"], "amount": PRICE, "cipher": hex::encode(&ct), "csvDelta": 10}), key }
}

/// The rig's provider, answering every paid call with `doc`.
fn stream_provider(rig: &Rig, doc: Value) {
    provider_with(rig, doc, 10_000);
}

fn provider_with(rig: &Rig, doc: Value, min_capacity: u64) {
    let mut cfg = ProviderConfig::new(&rig.chain.network());
    cfg.policy.min_capacity = min_capacity;
    cfg.policy.max_capacity = 10_000;
    cfg.policy.min_expiry_blocks = 1_008;
    cfg.policy.min_conf = 1;
    let body = doc.to_string().into_bytes();
    let p = Provider::new(Arc::new(ProviderChain(rig.chain.clone())), secret("provider payTo"), cfg, Ledger::in_memory(), Box::new(|_, _| PRICE as u64),
                          Box::new(move |_, _, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], body.clone()))).unwrap();
    rig.web.sites.lock().unwrap().insert(PROVIDER.into(), Arc::new(p));
}

/// `(what the state leaving in this request signs, the ledger on disk at that moment)`.
type Leaving = Arc<Mutex<Vec<(String, i64, i64)>>>;

/// The stream seller's chunk endpoints; `reveal`: whether the paid last chunk hands over its key.
/// Every request that carries a signed state is noted with the ledger as it stood.
fn stream_seller(rig: &mut Rig, s: &Stream, reveal: bool) -> (Arc<Hooked>, Leaving) {
    let leaving: Leaving = Arc::new(Mutex::new(vec![]));
    let (web, root, note) = (rig.web.clone(), rig.root.clone(), leaving.clone());
    let (chunk0, cond, key) = (s.chunk0.clone(), s.cond.clone(), s.key.clone());
    let t = hooked(rig, Box::new(move |method, url, body, headers| {
        let paid = has_sig(headers);
        if let Some(p) = &paid {
            let pl = &p["payload"];
            if pl.get("sig").is_some() {
                let locked = if pl.get("hashlock").is_some() { PRICE } else { 0 };
                note.lock().unwrap().push((url.to_string(), cum_of(pl) + locked, ledger_on_disk(&root)));
            }
        }
        if url.ends_with(FACILITATOR_VERIFY) {
            let v: Value = serde_json::from_slice(body).unwrap();
            note.lock().unwrap().push((url.to_string(), cum_of(&v["paymentPayload"]["payload"]), ledger_on_disk(&root)));
            return None;
        }
        let json_ok = |v: Value| Some(Ok(HttpResponse::new(200, vec![], v.to_string().into_bytes())));
        if url.ends_with("/chunk/0") {
            return json_ok(chunk0.clone());
        }
        if url.ends_with("/chunk/1") {
            if paid.is_some() {
                return if reveal { json_ok(json!({"preimage": hex::encode(&key)})) } else { Some(Ok(HttpResponse::new(500, vec![], b"".to_vec()))) };
            }
            // the provider's own offer, with the hash lock on it
            let r = web.request(method, URL, b"", &[]).unwrap();
            let mut pr = unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap();
            pr["accepts"][0]["extra"]["conditional"] = cond.clone();
            return Some(Ok(HttpResponse::new(402, vec![("PAYMENT-REQUIRED".into(), b64json(&pr))], b"".to_vec())));
        }
        None
    }));
    (t, leaving)
}

fn buy_stream(rig: &Rig) -> Value {
    let call = || rig.call("xbt402_pay", json!({"url": URL, "method": "GET", "body": "", "max_sats": 2_000}));
    assert_eq!(call()["verdict"], "pending");
    rig.chain.mine(1);
    call()
}

const ROOMY: &str = r#"{"max_per_tx_sats": 5000, "human_threshold_sats": 5000}"#;

fn roomy() -> Value {
    serde_json::from_str(ROOMY).unwrap()
}

/// The seller takes the hash-locked state for the last chunk and never hands over the key. It
/// holds a signature worth the plain amount plus the chunk: the ledger must hold that much, from
/// before the state left.
#[test]
fn w1_the_streams_hash_locked_last_chunk_is_booked_before_it_is_signed() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(roomy(), false);
    rig.fund_hot(1, 12_000);
    let s = stream("/chunk/{i}");
    stream_provider(&rig, s.doc.clone());
    let (_t, leaving) = stream_seller(&mut rig, &s, false);
    let r = buy_stream(&rig);
    assert_eq!(r["stream"]["ok"], false, "{r}");
    let rec = rig.s.book.get(PROVIDER).unwrap();
    assert_eq!(rec.used_sats, 1_200, "the manifest call and chunk 0, as plain states");
    let locked: Vec<_> = leaving.lock().unwrap().iter().filter(|(u, ..)| u.ends_with("/chunk/1")).cloned().collect();
    assert_eq!(locked.len(), 1, "one hash-locked state left: {locked:?}");
    assert_eq!(locked[0].1, 1_800);
    assert!(locked[0].2 >= 1_800, "the hash-locked state left with the ledger at {} of the {} it signs", locked[0].2, locked[0].1);
    assert_eq!(ledger(&rig), 1_800, "the seller holds a signature for 1,800 sat; nothing releases it");
    assert_eq!(r["booked_sats"], 1_800, "{r}");
}

/// xbt402_pay, a stream's chunks and its last chunk: at every request that carries a signed
/// state, the ledger already holds what that state signs.
#[test]
fn w1_every_state_the_session_sends_is_in_the_ledger_before_it_leaves() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(roomy(), false);
    rig.fund_hot(1, 12_000);
    let s = stream("/chunk/{i}");
    stream_provider(&rig, s.doc.clone());
    let (_t, leaving) = stream_seller(&mut rig, &s, true);
    let r = buy_stream(&rig);
    assert_eq!(r["stream"]["ok"], true, "{r}");
    let seen = leaving.lock().unwrap().clone();
    assert!(seen.len() >= 4, "the first state, chunk 0, the hash lock, the folded state: {seen:?}");
    for (url, signs, held) in &seen {
        assert!(held >= signs, "{url}: a state signing {signs} sat left with the ledger at {held}");
    }
    assert_eq!((rig.s.book.get(PROVIDER).unwrap().used_sats, ledger(&rig)), (1_800, 1_800), "the folded lock is not booked twice");
}

// --- W1: the socket's signing methods -------------------------------------------------------------

fn point(t: &xbt_primitives::secp256k1::SecretKey) -> String {
    hex::encode(xbt_primitives::secp256k1::PublicKey::from_secret_key(xbt_primitives::secp256k1::SECP256K1, t).serialize())
}

fn routing(daily: i64) -> Value {
    json!({"routing": {"hubs": {PROVIDER: {"max_fee_ppm": 5000, "max_fee_base_msat": 2000}}, "max_lock_sats": 2000, "daily_budget_sats": daily},
           "max_per_tx_sats": 5000, "human_threshold_sats": 5000})
}

fn lock(rig: &Rig, chan: &str, cum: i64, amount: i64, t: &str) -> Value {
    rig.call("xbt402_sign_state_adaptor", json!({"chan": chan, "cum": cum, "point": t,
                                                 "route": {"hub": PROVIDER, "amount": amount, "fee": 6, "lockId": format!("L{cum}")}}))
}

fn next_params(rig: &Rig, cur: &ChannelParams, origin: &str) -> ChannelParams {
    let key = hex::decode(rig.call("xbt402_new_key", json!({"origin": format!("{origin}/next")}))["pub"].as_str().unwrap()).unwrap();
    ChannelParams::derive(&seller_pay_to(), &key, (rig.chain.height() + 1_014) as u32, cur.close_fee, Some(hex::decode(rig.hot_spk()).unwrap()),
                          &rig.chain.network(), cur.close_fee_payer).unwrap()
}

/// sign_state, 0xA3, conditional, rollover and adaptor: when the method answers with a signature,
/// the ledger holds the amount that signature commits the channel to.
#[test]
fn w1_every_socket_signing_method_has_booked_what_it_signs_when_it_answers() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::build(routing(3_000), false, "regtest", Some(Arc::new(TestAdaptor)));
    rig.fund_hot(1, 12_000);
    let chan = rig.open()["chan"].as_str().unwrap().to_string();
    assert_eq!(ledger(&rig), 546);
    let r = rig.call("xbt402_sign_state", json!({"chan": chan, "cum": 1_000}));
    assert!(r["sig"].is_string() && ledger(&rig) == 1_000, "sign_state: {r}, ledger {}", ledger(&rig));
    let r = rig.call("xbt402_sign_state_a3", json!({"chan": chan, "amount": 1_500}));
    assert!(r["sig"].is_string() && ledger(&rig) == 1_500, "0xA3: {r}, ledger {}", ledger(&rig));
    let r = rig.call("xbt402_sign_conditional", json!({"chan": chan, "uncond": 1_500, "amount": 600, "hash": "ab".repeat(32)}));
    assert!(r["sig"].is_string() && ledger(&rig) == 2_100, "conditional: {r}, ledger {}", ledger(&rig));
    let r = lock(&rig, &chan, 2_500, 994, &point(&secret("t")));
    assert!(r["adaptor"].is_object() && ledger(&rig) == 2_500, "adaptor: {r}, ledger {}", ledger(&rig));
    assert_eq!(rig.call("xbt402_void_lock", json!({"chan": chan}))["voided"], true);
    let rec = rig.s.book.get(PROVIDER).unwrap();
    let cur = rec.params().unwrap();
    let next = next_params(&rig, &cur, &rec.origin);
    let r = rig.call("xbt402_sign_rollover", json!({"chan": chan, "amount": 2_700, "next_spk": hex::encode(next.spk()),
                                                    "next_capacity": cur.rollover_next_capacity(2_700), "next": next.to_json()}));
    assert!(r["sig"].is_string() && ledger(&rig) == 2_700, "rollover: {r}, ledger {}", ledger(&rig));
}

/// A hub that refuses every lock keeps each pre-signature (it completes one whenever it learns t).
/// Each must be booked when it leaves; giving the lock up releases nothing; a later lock up to the
/// same amount rides on that booking, since one close can claim only one state.
#[test]
fn w1_an_adaptor_pre_signature_is_booked_before_it_leaves_and_a_void_does_not_release_it() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::build(routing(1_500), false, "regtest", Some(Arc::new(TestAdaptor)));
    rig.fund_hot(1, 12_000);
    let chan = rig.open()["chan"].as_str().unwrap().to_string();
    let t = secret("t");
    let void = || assert_eq!(rig.call("xbt402_void_lock", json!({"chan": chan}))["voided"], true);
    let r = lock(&rig, &chan, 1_146, 594, &point(&t));
    assert_eq!(r["verdict"], "allow", "{r}");
    assert_eq!(ledger(&rig), 1_146, "the pre-signature is in the ledger when it leaves");
    assert_eq!(rig.call("routing_status", json!({}))["spent_24h_sats"], 600, "and in the routing budget");
    void();
    assert_eq!(ledger(&rig), 1_146, "a void releases nothing: the hub still holds the pre-signature");
    let r = lock(&rig, &chan, 1_746, 1_194, &point(&t));
    assert_eq!(r["verdict"], "allow", "{r}");
    assert_eq!(ledger(&rig), 1_746);
    void();
    let r = lock(&rig, &chan, 2_346, 1_794, &point(&t));
    assert_eq!(rule(&r), "route_daily_budget", "the third pre-signature is past the routing budget of 1,500: {r}");
    assert_eq!(ledger(&rig), 1_746, "and nothing was booked for it");
    // a lock inside what is already booked books nothing more, and resolving it does not book it again
    let r = lock(&rig, &chan, 1_746, 1_194, &point(&t));
    assert_eq!(r["verdict"], "allow", "a re-lock at a voided amount rides on its booking: {r}");
    assert_eq!(ledger(&rig), 1_746);
    let r = rig.call("xbt402_resolve_lock", json!({"chan": chan, "secret": hex::encode(t.secret_bytes())}));
    assert_eq!(r["t"], hex::encode(t.secret_bytes()), "{r}");
    assert_eq!((rig.s.book.get(PROVIDER).unwrap().used_sats, ledger(&rig)), (1_746, 1_746));
    assert_eq!(rig.call("routing_status", json!({}))["spent_24h_sats"], 1_200);
}

// --- W3: a channel leaves the refund watcher only by the chain ---------------------------------------

fn refunds(actions: &[Value]) -> Vec<&Value> {
    actions.iter().filter(|a| a["rule"] == "refund").collect()
}

/// The audit's loop: `xbt402_new_key`, `fund`, `xbt402_mark_closed`. The funding is unspent, so the
/// channel is not closed, and the watcher refunds it at expiry.
#[test]
fn w3_mark_closed_needs_the_close_on_chain() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    let key = hex::decode(rig.call("xbt402_new_key", json!({"origin": PROVIDER}))["pub"].as_str().unwrap()).unwrap();
    let p = ChannelParams::derive(&seller_pay_to(), &key, (rig.chain.height() + 1_014) as u32, 300, Some(hex::decode(rig.hot_spk()).unwrap()),
                                  &rig.chain.network(), FeePayer::Payer).unwrap();
    let f = rig.call("fund", json!({"origin": PROVIDER, "params": p.to_json(), "sats": 9_000}));
    let chan = f["chan"].as_str().unwrap().to_string();
    rig.chain.mine(1);
    let r = rig.call("xbt402_mark_closed", json!({"chan": chan, "txid": "ab".repeat(32)}));
    assert_eq!((r["verdict"].as_str(), rule(&r)), (Some("deny"), "close_unproven"), "{r}");
    assert_eq!(rig.channel(&chan)["state"], "pending", "the caller's word closes nothing");
    let k2 = hex::decode(rig.call("xbt402_new_key", json!({"origin": PROVIDER}))["pub"].as_str().unwrap()).unwrap();
    let p2 = ChannelParams::derive(&seller_pay_to(), &k2, (rig.chain.height() + 1_014) as u32, 300, Some(hex::decode(rig.hot_spk()).unwrap()),
                                   &rig.chain.network(), FeePayer::Payer).unwrap();
    let again = rig.call("fund", json!({"origin": PROVIDER, "params": p2.to_json(), "sats": 2_000}));
    assert_eq!(rule(&again), "channel_pending", "so the loop cannot fund a second channel: {again}");
    rig.chain.mine_to(p.expiry as u64);
    let acts = rig.s.watch_tick();
    assert_eq!(refunds(&acts).len(), 1, "the watcher refunds it at expiry: {acts:?}");
    assert_eq!(rig.channel(&chan)["state"], "refunded");
}

/// A provider answers 200 to /close and broadcasts nothing. The channel is reported closed, but it
/// stays with the watcher, which refunds it at expiry; no second channel replaces it meanwhile.
#[test]
fn w3_a_close_the_chain_never_saw_is_refunded_at_expiry() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({"hot_balance_cap_sats": 100_000}), false);
    rig.fund_hot(1, 30_000);
    let t = hooked(&mut rig, Box::new(|_, url, _, _| {
        url.ends_with(CLOSE_PATH).then(|| Ok(HttpResponse::new(200, vec![], json!({"txid": "cd".repeat(32), "cum": "546", "unpaidMsat": "0"}).to_string().into_bytes())))
    }));
    let chan = rig.open()["chan"].as_str().unwrap().to_string();
    let expiry = rig.s.book.get(PROVIDER).unwrap().expiry as u64;
    let c = rig.call("close_channel", json!({"counterparty": PROVIDER}));
    assert_eq!(c["verdict"], "allow", "{c}");
    assert_eq!(c["close_proven"], false, "the wallet says the close is only the provider's word: {c}");
    let r = rig.pay();
    assert_eq!((r["verdict"].as_str(), rule(&r)), (Some("deny"), "close_unproven"), "no new channel while the old one may need its refund: {r}");
    assert!(rig.call("channels", json!({}))["channels"].as_array().unwrap().iter().any(|c| c["chan"] == chan.as_str()), "the record is still watched");
    rig.chain.mine_to(expiry);
    let acts = rig.s.watch_tick();
    assert_eq!(refunds(&acts).len(), 1, "refunded at expiry: {acts:?}");
    assert_eq!(rig.channel(&chan)["state"], "refunded");
    drop(t);
}

/// The honest case: the provider's close is on our node, so the channel is closed and proven, and
/// the next call opens a new channel.
#[test]
fn w3_a_close_on_chain_is_proven_and_the_channel_is_replaced() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"hot_balance_cap_sats": 100_000}), false);
    rig.fund_hot(1, 30_000);
    let chan = rig.open()["chan"].as_str().unwrap().to_string();
    let c = rig.call("close_channel", json!({"counterparty": PROVIDER}));
    assert_eq!((c["verdict"].as_str(), c["close_proven"].as_bool()), (Some("allow"), Some(true)), "{c}");
    rig.chain.mine(1);
    rig.s.watch_tick();
    let r = rig.pay();
    assert_eq!(r["verdict"], "pending", "a new channel is funded: {r}");
    assert_ne!(r["chan"].as_str(), Some(chan.as_str()));
}

/// `xbt402_attach` of `<origin>/next` with a made-up outpoint must not replace the live channel:
/// the next channel is attached only once our node shows the rollover that funds it.
#[test]
fn w3_attach_next_needs_the_rollover_on_chain() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"max_per_tx_sats": 5000, "human_threshold_sats": 5000}), false);
    provider_with(&rig, json!({"ok": true}), 5_000); // a rollover's next channel is smaller than the first
    rig.fund_hot(1, 12_000);
    assert_eq!(rig.call("xbt402_pay", json!({"url": URL, "max_sats": 1_000}))["verdict"], "pending");
    rig.chain.mine(1);
    let chan = rig.call("xbt402_pay", json!({"url": URL, "max_sats": 1_000}))["chan"].as_str().unwrap().to_string();
    let rec = rig.s.book.get(PROVIDER).unwrap();
    let cur = rec.params().unwrap();
    let next = next_params(&rig, &cur, &rec.origin);
    let amount = rec.used_sats as u64;
    let next_cap = cur.rollover_next_capacity(amount);
    let made_up = next.clone().with_funding(&"ee".repeat(32), 1, next_cap).unwrap();
    let a = rig.call("xbt402_attach", json!({"origin": format!("{}/next", rec.origin), "params": made_up.to_json()}));
    assert_eq!((a["verdict"].as_str(), rule(&a)), (Some("deny"), "rollover_unproven"), "{a}");
    let live = rig.s.book.get(PROVIDER).unwrap();
    assert_eq!((live.chan.as_str(), live.state.as_str()), (chan.as_str(), "open"), "the live channel's record is untouched");
    // the real rollover: signed here, co-signed and broadcast by the provider
    let sig = rig.call("xbt402_sign_rollover", json!({"chan": chan, "amount": amount, "next_spk": hex::encode(next.spk()), "next_capacity": next_cap,
                                                      "next": next.to_json()}));
    let body = json!({"chan": chan, "amount": amount, "sig": sig["sig"],
                      "next": {"payerPub": hex::encode(next.payer_pub), "expiry": next.expiry, "payerSpk": hex::encode(&next.payer_spk)}});
    let resp = rig.web.request("POST", &format!("{PROVIDER}{ROLLOVER_PATH}"), body.to_string().as_bytes(), &[("Content-Type".into(), "application/json".into())]).unwrap();
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    let reply: Value = serde_json::from_slice(&resp.body).unwrap();
    let real = next.with_funding(reply["txid"].as_str().unwrap(), 1, next_cap).unwrap();
    let a = rig.call("xbt402_attach", json!({"origin": format!("{}/next", rec.origin), "params": real.to_json()}));
    assert_eq!(a["chan"], real.channel_id(), "{a}");
    let now = rig.s.book.get(PROVIDER).unwrap();
    assert_eq!((now.chan, now.state.as_str()), (real.channel_id(), "open"));
}

// --- X1: the seller's URLs stay on its origin ------------------------------------------------------------

fn off_origin(seen: &Hooked) -> Vec<String> {
    seen.seen.lock().unwrap().iter().filter(|u| !u.starts_with(&format!("{PROVIDER}/"))).cloned().collect()
}

/// `openUrl` and `chunkUrl` come from the seller. `@evil.example/open` appended to the origin is
/// another host; nothing may be sent there.
#[test]
fn x1_a_seller_url_off_the_origin_is_refused() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    for bad in ["@evil.example/open", "//evil.example/open", ".evil.example/open", "http://evil.example/open", "/open\\@evil.example", "/a b"] {
        let mut rig = Rig::new(json!({}), false);
        rig.fund_hot(1, 12_000);
        let (web, bad_url) = (rig.web.clone(), bad.to_string());
        let t = hooked(&mut rig, Box::new(move |method, url, body, headers| {
            if url != URL || has_sig(headers).is_some() {
                return None;
            }
            let r = web.request(method, url, body, headers).unwrap();
            let mut pr = unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap();
            pr["accepts"][0]["extra"]["openUrl"] = bad_url.clone().into();
            Some(Ok(HttpResponse::new(402, vec![("PAYMENT-REQUIRED".into(), b64json(&pr))], b"".to_vec())))
        }));
        let before = rig.hot_sats();
        let r = rig.pay();
        assert_eq!((r["verdict"].as_str(), rule(&r)), (Some("deny"), "seller_url"), "{bad}: {r}");
        assert_eq!(off_origin(&t), Vec::<String>::new(), "{bad}: a request left the allowlisted origin");
        assert_eq!(rig.hot_sats(), before, "{bad}: nothing was funded");
    }
    // a stream's chunkUrl
    let mut rig = Rig::new(roomy(), false);
    rig.fund_hot(1, 12_000);
    let s = stream("@evil.example/chunk/{i}");
    stream_provider(&rig, s.doc.clone());
    let (t, _) = stream_seller(&mut rig, &s, true);
    let r = buy_stream(&rig);
    assert_eq!(r["stream"]["ok"], false, "{r}");
    assert!(r["stream"]["refused"].as_str().unwrap_or("").contains("chunkUrl"), "{r}");
    assert_eq!(off_origin(&t), Vec::<String>::new(), "a chunk request left the allowlisted origin");
    // a path on the origin, and the origin spelled out, are fine
    for good in ["/x402/xbt-channel/open", "http://127.0.0.1:33210/x402/xbt-channel/open"] {
        assert_eq!(xbt402::wire::seller_url(PROVIDER, good).unwrap(), format!("{PROVIDER}/x402/xbt-channel/open"));
    }
}

// --- K1: the on-chain pay rail books before it sends -------------------------------------------------------

/// The rig's node, with a wallet that answers `sendtoaddress`.
struct PayNode {
    chain: Arc<FakeChain>,
    root: std::path::PathBuf,
    /// The ledger on disk at each `sendtoaddress`.
    held: Mutex<Vec<i64>>,
    answer: Mutex<xbt402::Result<Value>>,
}

impl Node for PayNode {
    fn call(&self, method: &str, p: Value) -> xbt402::Result<Value> {
        if method == "sendtoaddress" {
            self.held.lock().unwrap().push(ledger_on_disk(&self.root));
            return self.answer.lock().unwrap().clone();
        }
        self.chain.call(method, p)
    }
    fn set_allow_generate(&self, allow: bool) {
        self.chain.set_allow_generate(allow);
    }
    fn wallet(&self) -> String {
        self.chain.wallet()
    }
}

const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

#[test]
fn k1_the_onchain_pay_rail_books_before_it_sends() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({"allowlist": [ADDR]}), false);
    let node = Arc::new(PayNode { chain: rig.chain.clone(), root: rig.root.clone(), held: Mutex::new(vec![]), answer: Mutex::new(Ok(json!("5a".repeat(32)))) });
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(node.clone()), transport: Some(rig.web.clone()), ..Default::default() }).unwrap();
    let r = rig.call("pay", json!({"to": ADDR, "amount_sats": 400, "memo": "m"}));
    assert_eq!((r["verdict"].as_str(), r["rail"].as_str(), r["txid"].as_str()), (Some("allow"), Some("onchain"), Some("5a".repeat(32).as_str())), "{r}");
    assert_eq!(*node.held.lock().unwrap(), vec![400], "the payment was in the ledger when sendtoaddress was called");
    let rows = rig.s.engine.store.payments().unwrap();
    assert_eq!(rows.iter().map(|e| (e.amount_sats, e.txid.as_str())).collect::<Vec<_>>(), vec![(400, "5a".repeat(32).as_str())], "booked once, under the txid");
    // the node refuses: the booking is taken back
    *node.answer.lock().unwrap() = Err(xbt402::ChannelError::new("rpc_refused", r#"{"code":-6,"message":"Insufficient funds"}"#));
    assert!(rig.s.handle("pay", &json!({"to": ADDR, "amount_sats": 300, "memo": "n"})).is_err());
    assert_eq!(ledger(&rig), 400, "a payment the node refused is not booked");
    // the node does not answer: the payment may have gone out, so it stays booked
    *node.answer.lock().unwrap() = Err(xbt402::ChannelError::new("rpc_error", "timed out reading response"));
    assert!(rig.s.handle("pay", &json!({"to": ADDR, "amount_sats": 200, "memo": "o"})).is_err());
    assert_eq!(ledger(&rig), 600, "a payment whose fate is unknown stays booked");
}
