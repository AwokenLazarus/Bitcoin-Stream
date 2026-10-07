//! The Rust emitter: B1 `check_vectors.generate()` rebuilt on the Rust crates. Every value comes
//! from `xbt-primitives` / `xbt402`; the round trips are served by the Rust [`Provider`] against
//! the same stub node, so the output is byte-identical to the published file exactly when the
//! implementations agree.
use std::sync::Arc;

use serde_json::{json, Value};
use xbt402::channel::*;
use xbt402::conditional::{decrypt, preimage_from_tx, ConditionalParams};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::wire::*;
use xbt_primitives::address::segwit_address;
use xbt_primitives::ecdsa::{self, scalar_mod_n};
use xbt_primitives::hash::{sha256, tagged_hash};
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::sighash::{SIGHASH_ALL, SIGHASH_ALL_UNIFIED};
use xbt_primitives::tx::Tx;

use crate::stub::StubNode;

pub const NETWORK: &str = XBT_MAINNET;
pub const OTHER_NETWORKS: [&str; 2] = ["bip122:11111111111111111111111111111111", "bip122:000000000933ea01ad0ee984209779ba"];
pub const TIP: u32 = 1_000;
pub const EXPIRY: u32 = TIP + 1_014;
pub const CAPACITY: u64 = 200_000;
pub const CLOSE_FEE: u64 = 600;
pub const PRICE: u64 = 150;
pub const COND_PLAIN: &[u8] = b"the deliverable: a report sold under a hash lock\n";
pub const COND_PRICE: u64 = 1_000;
pub const COND_PATH: &str = "/v1/report";

/// `int(sha256(label)) % n` as a secret key.
pub fn test_secret(label: &[u8]) -> SecretKey {
    SecretKey::from_slice(&scalar_mod_n(&sha256(label)).to_be_bytes()).expect("test key")
}

pub fn payto_secret() -> SecretKey {
    test_secret(b"xbt402 test vector: payTo secret")
}

pub fn payer_secret(i: u32) -> SecretKey {
    test_secret(format!("xbt402 test vector: payer secret {i}").as_bytes())
}

pub fn hub_secret() -> SecretKey {
    test_secret(b"xbt402 test vector: hub payTo secret")
}

pub fn cond_k() -> [u8; 32] {
    sha256(b"xbt402 test vector: conditional k")
}

pub fn funding_txid() -> String {
    hex::encode(sha256(b"xbt402 test vector: funding tx"))
}

pub fn pubhex(s: &SecretKey) -> String {
    hex::encode(ecdsa::pubkey(s))
}

fn sechex(s: &SecretKey) -> String {
    hex::encode(s.secret_bytes())
}

pub fn params(a: &SecretKey, expiry: u32, capacity: u64, vout: u32, fee_payer: FeePayer) -> ChannelParams {
    ChannelParams::derive(&ecdsa::pubkey(&payto_secret()), &ecdsa::pubkey(a), expiry, CLOSE_FEE, None, NETWORK, fee_payer)
        .and_then(|p| p.with_funding(&funding_txid(), vout, capacity))
        .expect("test params")
}

fn lax_der(der: &[u8]) -> Vec<u8> {
    let rl = der[3] as usize;
    let (r, s) = (&der[4..4 + rl], &der[6 + rl..]);
    let mut body = vec![0x02, (r.len() + 1) as u8, 0x00];
    body.extend_from_slice(r);
    body.extend_from_slice(s);
    let mut out = vec![0x30, body.len() as u8];
    out.extend(body);
    out
}

fn v10_payee_pub(pay_to: &[u8], payer: &[u8], expiry: u32) -> String {
    let mut m = pay_to.to_vec();
    m.extend_from_slice(payer);
    m.extend_from_slice(&expiry.to_le_bytes());
    let t = scalar_mod_n(&tagged_hash("xbt-channel/payee", &m));
    pubhex(&payto_secret().add_tweak(&t).expect("tweak"))
}

// --- 1. payee key derivation ----------------------------------------------------------------------
pub fn gen_derivation() -> Value {
    let mut cases = vec![(NETWORK, payer_secret(0), EXPIRY), (NETWORK, payer_secret(0), EXPIRY + 1), (NETWORK, payer_secret(1), 961_640 + 8_000)];
    for n in OTHER_NETWORKS {
        cases.push((n, payer_secret(0), EXPIRY));
    }
    let pay_to = ecdsa::pubkey(&payto_secret());
    Value::Array(cases.into_iter().map(|(network, a, expiry)| {
        let payer = ecdsa::pubkey(&a);
        let p = ChannelParams::derive(&pay_to, &payer, expiry, CLOSE_FEE, None, network, FeePayer::Payer).expect("derive");
        json!({
            "network": network, "payTo": hex::encode(pay_to), "payerPub": hex::encode(payer), "expiry": expiry,
            "expiryLE32": hex::encode(expiry.to_le_bytes()),
            "tweakPreimage": hex::encode(payee_tweak_preimage(network, &pay_to, &payer, expiry).expect("preimage")),
            "t": hex::encode(payee_tweak(network, &pay_to, &payer, expiry).expect("tweak")),
            "payeePub": hex::encode(channel_payee_pub(network, &pay_to, &payer, expiry).expect("P")),
            "redeemScript": hex::encode(p.script()), "fundingSpk": hex::encode(p.spk()),
            "fundingAddressMainnet": segwit_address("bc", &p.spk()).expect("address"),
            "payeeSpk": hex::encode(&p.payee_spk), "payerSpk": hex::encode(&p.payer_spk),
            "_payeePubV10": v10_payee_pub(&pay_to, &payer, expiry),
        })
    }).collect())
}

// --- 2. request-authentication key and payload.auth -----------------------------------------------
pub fn gen_auth() -> Value {
    let a = payer_secret(0);
    let p = params(&a, EXPIRY, CAPACITY, 0, FeePayer::Payer);
    let payee_secret = channel_payee_secret(NETWORK, &payto_secret(), &p.payer_pub, p.expiry).expect("p");
    let k_payer = channel_auth_key(&a, &p.payee_pub).expect("K");
    let k_payee = channel_auth_key(&payee_secret, &p.payer_pub).expect("K");
    let shared = ecdsa::ecdh_x(&a, &ecdsa::public_key(&p.payee_pub).expect("P"));
    let sig546 = hex::encode(Payer::new(p.clone(), a).expect("payer").sign_state(546).expect("sig"));
    let chan = p.channel_id();
    type Case<'a> = (&'a str, &'a str, &'a [u8], u64, &'a str, Option<&'a str>);
    let rows: [Case; 3] = [
        ("GET", "/v1/quote?pair=XBT-USD", b"", 1, "0", None),
        ("POST", "/v1/infer", br#"{"prompt":"hello"}"#, 2, "546", Some(sig546.as_str())),
        ("POST", "/v1/a%20b?x=1", b"\x00\x01binary", 7, "1200", None),
    ];
    let cases: Vec<Value> = rows.iter().map(|(method, path, body, seq, cum, sig)| {
        let req = request_digest(method, path, body);
        json!({"method": method, "path": path, "bodyHex": hex::encode(body), "req": req, "chan": chan, "seq": seq, "cum": cum,
               "sig": sig.unwrap_or(""), "message": auth_message(&chan, &seq.to_string(), cum, sig.unwrap_or(""), &req),
               "auth": request_auth(&k_payer, &chan, Some(&json!(seq)), Some(&json!(cum)), *sig, &req)})
    }).collect();
    json!({"payerSecret": sechex(&a), "payTo": pubhex(&payto_secret()), "payerPub": hex::encode(p.payer_pub), "expiry": p.expiry,
           "payeePub": hex::encode(p.payee_pub), "ecdhX": hex::encode(shared), "K": hex::encode(k_payer),
           "_K_payee_side": hex::encode(k_payee), "cases": cases})
}

// --- 3. states, close, refund ---------------------------------------------------------------------
pub fn gen_states() -> Value {
    let a = payer_secret(0);
    let p = params(&a, EXPIRY, CAPACITY, 0, FeePayer::Payer);
    let payee_secret = channel_payee_secret(NETWORK, &payto_secret(), &p.payer_pub, p.expiry).expect("p");
    let mut states = vec![];
    let mut sigs = vec![];
    for cum in [546, 150_000, p.max_amount() - 545, p.max_amount()] {
        let tx = p.state_tx(cum).expect("state");
        let sig = Payer::new(p.clone(), a).expect("payer").sign_state(cum).expect("sig");
        sigs.push(sig.clone());
        states.push(json!({"cum": cum, "unsignedTx": tx.to_hex(), "outputs": tx.outputs.len(),
                           "sighash": hex::encode(p.sighash(&tx).expect("sighash")), "payerSig": hex::encode(&sig)}));
    }
    let mut payee = Payee::new(p.clone(), payee_secret).expect("payee");
    payee.accept(150_000, &sigs[1]).expect("accept");
    let close = payee.close_tx().expect("close");
    let refund = p.refund_tx(&a, None, None).expect("refund");
    let s = &sigs[1];
    let mut lax = lax_der(&s[..s.len() - 1]);
    lax.push(s[s.len() - 1]);
    let mut relabel = s[..s.len() - 1].to_vec();
    relabel.push(SIGHASH_ALL);
    json!({"payerSecret": sechex(&a), "payToSecret": sechex(&payto_secret()), "payeeSecret": sechex(&payee_secret),
           "params": p.to_json(), "chan": p.channel_id(), "maxCum": p.max_amount(), "states": states,
           "closeTx": {"cum": 150_000, "hex": close.to_hex(), "txid": close.txid(), "vsize": close.vsize()},
           "refundTx": {"hex": refund.to_hex(), "txid": refund.txid(), "nLockTime": refund.locktime},
           "invalid": [
               {"why": "non-strict DER (0x00 before r): consensus-invalid in segwit v0", "cum": 150_000, "payerSig": hex::encode(lax), "error": "bad_sig"},
               {"why": "SIGHASH_ALL (0x01) instead of ALL|UNIFIED (0x21)", "cum": 150_000, "payerSig": hex::encode(relabel), "error": "bad_sighash"},
               {"why": "valid signature relabelled with a higher cum", "cum": 150_001, "payerSig": hex::encode(s), "error": "bad_sig"},
           ]})
}

fn provider(node: Arc<StubNode>, handler_body: &'static [u8], ctype: bool) -> Provider {
    let cfg = ProviderConfig::new(NETWORK);
    Provider::new(node, payto_secret(), cfg, Ledger::in_memory(), Box::new(|_, _| PRICE),
                  Box::new(move |_, _, _| {
                      let h = if ctype { vec![("Content-Type".to_string(), "application/json".to_string())] } else { vec![] };
                      HttpResponse::new(200, h, handler_body.to_vec())
                  }))
        .expect("provider")
}

fn body_json(r: &HttpResponse) -> Value {
    xbt402::json::parse_slice(&r.body).unwrap_or(Value::Null)
}

fn hdr(r: &HttpResponse, k: &str) -> String {
    r.header(k).unwrap_or("").to_string()
}

fn sig_hdr(v: &str) -> Vec<(String, String)> {
    vec![("PAYMENT-SIGNATURE".to_string(), v.to_string())]
}

fn open_request(p: &ChannelParams) -> Value {
    json!({"x402Version": 2, "network": NETWORK, "channel": {
        "txid": p.funding_txid(), "vout": p.funding_vout(), "capacity": p.capacity, "expiry": p.expiry,
        "payerPub": hex::encode(p.payer_pub), "payerSpk": hex::encode(&p.payer_spk), "redeemScript": hex::encode(p.script())}})
}

// --- 4. PAYMENT-REQUIRED / open / PAYMENT-SIGNATURE / PAYMENT-RESPONSE / close ---------------------
pub fn gen_roundtrip() -> Value {
    let a = payer_secret(0);
    let p = params(&a, EXPIRY, CAPACITY, 0, FeePayer::Payer);
    let node = Arc::new(StubNode::new(p.clone(), TIP));
    let handler_body: &'static [u8] = br#"{"result":"ok"}"#;
    let prov = provider(node.clone(), handler_body, true);
    let url = "https://api.example.com/v1/infer?model=small";
    let (method, path, body) = ("POST", "/v1/infer?model=small", br#"{"prompt":"hello"}"#.as_slice());
    let mut steps = vec![];

    let r = prov.serve(method, path, &[], body, url, None);
    let pr = hdr(&r, "PAYMENT-REQUIRED");
    let decoded = unb64json(&pr).expect("402");
    steps.push(json!({"step": "unpaid request", "request": {"method": method, "path": path, "bodyHex": hex::encode(body)},
                      "status": r.status, "PAYMENT-REQUIRED": pr, "decoded": decoded}));
    let accepted = decoded["accepts"][0].clone();
    let open_url = accepted["extra"]["openUrl"].as_str().unwrap_or("").to_string();
    let open_req = open_request(&p);
    let r = prov.serve("POST", &open_url, &[], xbt402::json::dumps(&open_req).as_bytes(), "", None);
    steps.push(json!({"step": "open", "path": open_url, "request": open_req, "status": r.status, "response": body_json(&r)}));

    let mut payer = Payer::new(p.clone(), a).expect("payer");
    let k = channel_auth_key(&a, &p.payee_pub).expect("K");
    let (mut spent_msat, mut seq, mut headers) = (0u64, 0u64, vec![]);
    let chan = p.channel_id();
    for n in 0..5 {
        let need = spent_msat.div_ceil(1000);
        let cum = need.max(payer.signed).max(if need > 0 { 546 } else { 0 });
        seq += 1;
        let mut pl = json!({"chan": chan, "seq": seq, "cum": cum.to_string()});
        if cum > payer.signed {
            pl["sig"] = hex::encode(payer.sign_state(cum).expect("sig")).into();
        }
        let sig = pl.get("sig").and_then(Value::as_str).map(str::to_string);
        pl["auth"] = request_auth(&k, &chan, Some(&json!(seq)), pl.get("cum"), sig.as_deref(), &request_digest(method, path, body)).into();
        let h = b64json(&payment_payload(&accepted, &pl));
        headers.push(h.clone());
        let r = prov.serve(method, path, &sig_hdr(&h), body, url, None);
        let resp_h = hdr(&r, "PAYMENT-RESPONSE");
        let resp = unb64json(&resp_h).expect("PAYMENT-RESPONSE");
        let receipt = receipt_of(&resp).expect("receipt").clone();
        spent_msat = receipt["spentMsat"].as_str().and_then(|s| s.parse().ok()).expect("spentMsat");
        steps.push(json!({"step": format!("paid call {}", n + 1), "PAYMENT-SIGNATURE": h, "payload": pl, "status": r.status,
                          "bodyHex": hex::encode(&r.body), "PAYMENT-RESPONSE": resp_h, "settlementResponse": resp, "receipt": receipt}));
    }
    let last = headers.last().cloned().unwrap_or_default();
    let r = prov.serve(method, path, &sig_hdr(&last), body, url, None);
    let b = body_json(&r);
    steps.push(json!({"step": "replay of paid call 5", "PAYMENT-SIGNATURE": last, "status": r.status, "error": b["error"],
                      "hasChannelDetails": b.get("channel").is_some()}));
    let r = prov.serve("GET", FACILITATOR_SUPPORTED, &[], b"", "", None);
    steps.push(json!({"step": "facilitator supported", "path": FACILITATOR_SUPPORTED, "status": r.status, "response": body_json(&r)}));
    let last_sig = steps.iter().rev().find_map(|s| s.get("payload").and_then(|p| p.get("sig")).cloned()).unwrap_or(Value::Null);
    let signed = json!({"chan": chan, "cum": payer.signed.to_string(), "sig": last_sig});
    let mut relabelled = signed.clone();
    relabelled["cum"] = (payer.signed + 1).to_string().into();
    for (what, pl) in [("facilitator verify", signed), ("facilitator verify, cum relabelled", relabelled)] {
        let req = facilitator_request(&accepted, &pl);
        let r = prov.serve("POST", FACILITATOR_VERIFY, &[], xbt402::json::dumps(&req).as_bytes(), "", None);
        steps.push(json!({"step": what, "path": FACILITATOR_VERIFY, "request": req, "status": r.status, "response": body_json(&r)}));
    }
    let fin = spent_msat.div_ceil(1000).max(payer.signed);
    seq += 1;
    let mut pl = json!({"chan": chan, "seq": seq, "cum": fin.to_string()});
    if fin > payer.signed {
        pl["sig"] = hex::encode(payer.sign_state(fin).expect("sig")).into();
    }
    let sig = pl.get("sig").and_then(Value::as_str).map(str::to_string);
    pl["auth"] = request_auth(&k, &chan, Some(&json!(seq)), pl.get("cum"), sig.as_deref(), &request_digest("", "", b"")).into();
    let close_req = json!({"chan": chan, "sig": hex::encode(ecdsa::sign(&a, &close_message(&chan))), "payload": pl});
    let close_url = accepted["extra"]["closeUrl"].as_str().unwrap_or("").to_string();
    let r = prov.serve("POST", &close_url, &[], xbt402::json::dumps(&close_req).as_bytes(), "", None);
    steps.push(json!({"step": "cooperative close", "path": close_url, "request": close_req, "status": r.status, "response": body_json(&r),
                      "closeTx": node.sent().last().cloned().unwrap_or_default()}));
    let req = facilitator_request(&accepted, &close_req);
    let r = prov.serve("POST", FACILITATOR_SETTLE, &[], xbt402::json::dumps(&req).as_bytes(), "", None);
    steps.push(json!({"step": "facilitator settle (same close)", "path": FACILITATOR_SETTLE, "request": req, "status": r.status,
                      "response": body_json(&r)}));
    json!({"network": NETWORK, "tip": TIP, "payToSecret": sechex(&payto_secret()), "payerSecret": sechex(&a), "url": url, "price": PRICE,
           "billing": "postpay", "handlerBodyHex": hex::encode(handler_body), "steps": steps})
}

// --- 5. hash-locked conditional call --------------------------------------------------------------
pub fn gen_conditional() -> Value {
    let a = payer_secret(1);
    let p = params(&a, EXPIRY, CAPACITY, 0, FeePayer::Payer);
    let node = Arc::new(StubNode::new(p.clone(), TIP));
    let prov = provider(node.clone(), br#"{"result":"ok"}"#, false);
    let (h, cipher, _) = prov.offer_conditional(COND_PATH, COND_PRICE, COND_PLAIN, Some(cond_k()));
    let origin = "https://api.example.com";
    let mut steps = vec![];
    let r = prov.serve("GET", COND_PATH, &[], b"", &format!("{origin}{COND_PATH}"), None);
    let prh = hdr(&r, "PAYMENT-REQUIRED");
    let offer = unb64json(&prh).expect("402");
    steps.push(json!({"step": "conditional offer", "status": r.status, "PAYMENT-REQUIRED": prh, "decoded": offer}));
    let accepted = offer["accepts"][0].clone();
    let csv = accepted["extra"]["conditional"]["csvDelta"].as_u64().unwrap_or(10) as u32;
    let open_url = accepted["extra"]["openUrl"].as_str().unwrap_or("").to_string();
    prov.serve("POST", &open_url, &[], xbt402::json::dumps(&open_request(&p)).as_bytes(), "", None);
    let mut payer = Payer::new(p.clone(), a).expect("payer");
    let kauth = channel_auth_key(&a, &p.payee_pub).expect("K");
    let chan = p.channel_id();
    let paid = |path: &str, fields: Value, seq: u64| {
        let mut pl = json!({"chan": chan, "seq": seq});
        for (k, v) in fields.as_object().expect("object") {
            pl[k] = v.clone();
        }
        let sig = pl.get("sig").and_then(Value::as_str).map(str::to_string);
        pl["auth"] = request_auth(&kauth, &chan, Some(&json!(seq)), pl.get("cum"), sig.as_deref(), &request_digest("GET", path, b"")).into();
        let h = b64json(&payment_payload(&accepted, &pl));
        let r = prov.serve("GET", path, &sig_hdr(&h), b"", &format!("{origin}{path}"), None);
        (pl, h, r)
    };
    let uncond = 546u64;
    let (pl, _, r) = paid("/v1/x", json!({"cum": uncond.to_string(), "sig": hex::encode(payer.sign_state(uncond).expect("sig"))}), 1);
    steps.push(json!({"step": "plain paid call", "payload": pl, "status": r.status}));
    let cp = ConditionalParams::new(p.clone(), h, COND_PRICE, csv).expect("cond");
    let tx = cp.state_tx(uncond).expect("cond state");
    let mut csig = ecdsa::sign(&a, &cp.sighash(&tx).expect("sighash"));
    csig.push(SIGHASH_ALL_UNIFIED);
    let (pl, h2, r) = paid(COND_PATH, json!({"cum": uncond.to_string(), "hashlock": hex::encode(h), "sig": hex::encode(&csig)}), 2);
    let resp_h = hdr(&r, "PAYMENT-RESPONSE");
    let resp = unb64json(&resp_h).expect("PAYMENT-RESPONSE");
    let receipt = receipt_of(&resp).expect("receipt").clone();
    steps.push(json!({"step": "conditional paid call", "PAYMENT-SIGNATURE": h2, "payload": pl, "status": r.status, "body": body_json(&r),
                      "PAYMENT-RESPONSE": resp_h, "settlementResponse": resp, "receipt": receipt}));
    node.set_tip(p.expiry - prov.cfg.close_margin);     // the payer never folded: the watcher closes
    prov.close_due().expect("watcher");
    let sent = node.sent();
    let (close, claim) = (sent[0].clone(), sent[1].clone());
    let (ctx, cltx) = (Tx::parse_hex(&close).expect("close"), Tx::parse_hex(&claim).expect("claim"));
    let claim_vout = cltx.inputs[0].prevout.vout;
    steps.push(json!({"step": "conditional close", "closeTx": close, "txid": ctx.txid(), "vsize": ctx.vsize(),
                      "hashlockVout": ctx.outputs.iter().position(|o| o.script_pubkey == cp.spk)}));
    let k = preimage_from_tx(&cltx, &h).unwrap_or_default();
    steps.push(json!({"step": "claim", "claimTx": claim, "txid": cltx.txid(), "vsize": cltx.vsize(),
                      "spends": format!("{}:{claim_vout}", ctx.txid()), "fee": COND_PRICE as i64 - cltx.outputs[0].value,
                      "preimageFromTx": hex::encode(&k), "recoveredPlaintextHex": hex::encode(decrypt(&cipher, &k))}));
    json!({"network": NETWORK, "payerSecret": sechex(&a), "payToSecret": sechex(&payto_secret()), "params": p.to_json(), "chan": chan,
           "k": hex::encode(cond_k()), "H": hex::encode(h), "plaintextHex": hex::encode(COND_PLAIN), "cipher": hex::encode(&cipher),
           "condAmount": COND_PRICE, "csvDelta": cp.csv_delta, "hashlockScript": hex::encode(&cp.script), "hashlockSpk": hex::encode(&cp.spk),
           "state": {"uncond": uncond, "unsignedTx": tx.to_hex(), "outputs": tx.outputs.len(), "sighash": hex::encode(cp.sighash(&tx).expect("sighash")),
                     "payerSig": hex::encode(&csig)},
           "steps": steps})
}

// --- 6. v1.2 payee-pays ---------------------------------------------------------------------------
pub fn gen_payee_pays() -> Value {
    let a = payer_secret(2);
    let p = params(&a, EXPIRY, CAPACITY, 0, FeePayer::Payee);
    let payee_secret = channel_payee_secret(NETWORK, &payto_secret(), &p.payer_pub, p.expiry).expect("p");
    let mut states = vec![];
    let mut sigs = vec![];
    for cum in [p.min_amount(), 150_000, p.capacity - DUST, p.capacity - DUST + 1, p.capacity] {
        let tx = p.state_tx(cum).expect("state");
        let sig = Payer::new(p.clone(), a).expect("payer").sign_state(cum).expect("sig");
        sigs.push(sig.clone());
        let outs: Vec<Value> = tx.outputs.iter().map(|o| json!([o.value, hex::encode(&o.script_pubkey)])).collect();
        states.push(json!({"cum": cum, "unsignedTx": tx.to_hex(), "outputs": outs, "sighash": hex::encode(p.sighash(&tx).expect("sighash")),
                           "payerSig": hex::encode(&sig)}));
    }
    let mut payee = Payee::new(p.clone(), payee_secret).expect("payee");
    payee.accept(150_000, &sigs[1]).expect("accept");
    let close = payee.close_tx().expect("close");
    let a3 = p.state_tx_a3(150_000).expect("a3");
    let pay_to = ecdsa::pubkey(&payto_secret());
    let nxt = ChannelParams::derive(&pay_to, &ecdsa::pubkey(&a), EXPIRY + 1_000, CLOSE_FEE, None, NETWORK, FeePayer::Payee).expect("next");
    let cap2 = p.rollover_next_capacity(150_000);
    let roll = p.rollover_tx(150_000, &nxt.spk(), cap2).expect("rollover");
    let cp = ConditionalParams::new(p.clone(), sha256(&cond_k()), COND_PRICE, 10).expect("cond");
    let ctx = cp.state_tx(p.min_amount()).expect("cond state");
    let v11 = Payer::new(params(&a, EXPIRY, CAPACITY, 0, FeePayer::Payer), a).expect("payer").sign_state(150_000).expect("sig");
    let sign21 = |d: [u8; 32]| { let mut s = ecdsa::sign(&a, &d); s.push(SIGHASH_ALL_UNIFIED); hex::encode(s) };
    let node = Arc::new(StubNode::new(p.clone(), TIP));
    let prov = provider(node.clone(), b"{}", false);
    let terms = prov.terms();
    let mut req = open_request(&p);
    req["channel"]["closeFeePayer"] = "payee".into();
    req["hub"] = json!({"payTo": pubhex(&hub_secret()), "sig": hex::encode(ecdsa::sign(&hub_secret(), &hub_channel_message(&p.channel_id())))});
    let open_url = terms["extra"]["openUrl"].as_str().unwrap_or("").to_string();
    let r = prov.serve("POST", &open_url, &[], xbt402::json::dumps(&req).as_bytes(), "", None);
    let close_section = payee_pays_close(&prov, &node, &p, &a);
    json!({"payerSecret": sechex(&a), "payeeSecret": sechex(&payee_secret), "params": p.to_json(), "chan": p.channel_id(),
           "minCum": p.min_amount(), "maxCum": p.max_amount(), "states": states,
           "closeTx": {"cum": 150_000, "hex": close.to_hex(), "txid": close.txid()},
           "a3State": {"cum": 150_000, "unsignedTx": a3.to_hex(), "sighash": hex::encode(p.sighash_a3(&a3).expect("a3 sighash")),
                       "payerSig": hex::encode(Payer::new(p.clone(), a).expect("payer").sign_state_a3(150_000).expect("a3 sig"))},
           "rollover": {"amount": 150_000, "nextExpiry": nxt.expiry, "nextSpk": hex::encode(nxt.spk()), "nextCapacity": cap2,
                        "unsignedTx": roll.to_hex(), "sighash": hex::encode(p.sighash(&roll).expect("sighash")),
                        "payerSig": sign21(p.sighash(&roll).expect("sighash"))},
           "conditional": {"H": hex::encode(cp.h), "condAmount": COND_PRICE, "csvDelta": 10, "uncond": p.min_amount(),
                           "hashlockSpk": hex::encode(&cp.spk), "unsignedTx": ctx.to_hex(), "sighash": hex::encode(cp.sighash(&ctx).expect("sighash")),
                           "payerSig": sign21(cp.sighash(&ctx).expect("sighash"))},
           "invalid": [
               {"why": "a payer-pays (v1.1) signature for the same cum: the signature commits to who pays the fee",
                "cum": 150_000, "payerSig": hex::encode(&v11), "error": "bad_sig"},
               {"why": "below the least state: the payee output would be dust after its close fee",
                "cum": p.min_amount() - 1, "payerSig": hex::encode(&sigs[0]), "error": "bad_amount"},
           ],
           "terms": terms, "open": {"request": req, "status": r.status, "response": body_json(&r)},
           "close": close_section})
}

/// AGP-029: ten 150-sat postpay calls, a close whose final state pays the 1,500 owed, and the same
/// close through /x402/settle. Both report the gross cum (what the payer paid) with payeeFee and
/// payeeNet; unpaidMsat is spent - gross (0), never the provider's own close fee.
fn payee_pays_close(prov: &Provider, node: &StubNode, p: &ChannelParams, a: &SecretKey) -> Value {
    let acc = prov.requirements(PRICE);
    let mut payer = Payer::new(p.clone(), *a).expect("payer");
    let k = channel_auth_key(a, &p.payee_pub).expect("K");
    let chan = p.channel_id();
    let (mut spent_msat, mut seq) = (0u64, 0u64);
    for _ in 0..10 {                        // postpay: each call pays for the calls before it
        let need = spent_msat.div_ceil(1000);
        let cum = need.max(payer.signed).max(if need > 0 { p.min_amount() } else { 0 });
        seq += 1;
        let mut pl = json!({"chan": chan, "seq": seq, "cum": cum.to_string()});
        if cum > payer.signed {
            pl["sig"] = hex::encode(payer.sign_state(cum).expect("sig")).into();
        }
        let sig = pl.get("sig").and_then(Value::as_str).map(str::to_string);
        pl["auth"] = request_auth(&k, &chan, Some(&json!(seq)), pl.get("cum"), sig.as_deref(), &request_digest("GET", "/v1/x", b"")).into();
        let r = prov.serve("GET", "/v1/x", &sig_hdr(&b64json(&payment_payload(&acc, &pl))), b"", "", None);
        let resp = unb64json(&hdr(&r, "PAYMENT-RESPONSE")).expect("PAYMENT-RESPONSE");
        spent_msat = receipt_of(&resp).expect("receipt")["spentMsat"].as_str().and_then(|s| s.parse().ok()).expect("spentMsat");
    }
    let fin = spent_msat.div_ceil(1000).max(payer.signed);
    let pl = json!({"chan": chan, "cum": fin.to_string(), "sig": hex::encode(payer.sign_state(fin).expect("sig"))});
    let req = json!({"chan": chan, "sig": hex::encode(ecdsa::sign(a, &close_message(&chan))), "payload": pl});
    let close_url = acc["extra"]["closeUrl"].as_str().unwrap_or("").to_string();
    let r = prov.serve("POST", &close_url, &[], xbt402::json::dumps(&req).as_bytes(), "", None);
    let mut out = json!({"calls": 10, "price": PRICE, "spentMsat": spent_msat, "request": req, "status": r.status,
                         "response": body_json(&r), "closeTx": node.sent().last().cloned().unwrap_or_default()});
    let sreq = facilitator_request(&acc, &req);
    let r = prov.serve("POST", FACILITATOR_SETTLE, &[], xbt402::json::dumps(&sreq).as_bytes(), "", None);
    out["settle"] = json!({"request": sreq, "status": r.status, "response": body_json(&r)});
    out
}

/// The whole vector file, as `check_vectors.py --write` writes it.
pub fn generate() -> Value {
    json!({
        "title": "x402 batch-settlement (XBT channel) test vectors",
        "version": format!("1.2-draft (payee derivation {DERIVATION}, x402 v2 SettlementResponse and facilitator shapes, closeFeePayer)"),
        "generator": "docs/x402/check_vectors.py --write, reference library xbt402 v1.2",
        "notes": ["All keys are test keys derived from sha256 of fixed strings. Never fund them.",
                  "Hex is lowercase. Integers are JSON numbers unless the wire format uses decimal strings.",
                  "Signatures are RFC 6979 deterministic with low S, so every value is byte-exact.",
                  "Fields starting with '_' are cross-checks, not wire values.",
                  "Sections derivation..conditional are v1.1 and unchanged in v1.2 (payer-pays, closeFeePayer absent); section payeePays is the v1.2 closeFeePayer \"payee\" state format."],
        "constants": {"network": NETWORK, "dust": DUST, "closeFeeSat": CLOSE_FEE, "capacity": CAPACITY, "sighashAllUnified": SIGHASH_ALL_UNIFIED,
                      "derivation": DERIVATION, "tags": [PAYEE_TAG, "xbt402/auth-key", "xbt402/receipt", "xbt402/close", "UnifiedSighash"]},
        "derivation": gen_derivation(),
        "auth": gen_auth(),
        "state": gen_states(),
        "roundtrip": gen_roundtrip(),
        "conditional": gen_conditional(),
        "payeePays": gen_payee_pays(),
    })
}
