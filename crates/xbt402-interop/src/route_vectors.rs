//! The xbt402 routing vectors (AGP-026), both directions:
//!
//! * [`generate`] rebuilds `vectors/xbt402_routing_vectors.json` with the Rust crates. The file is
//!   the reference's (`scripts/route_vectors.py gen`, B1 agp-023 as the library); they must be
//!   byte-identical, and `route_vectors.py check` re-verifies the Rust-emitted one with B1.
//! * [`check`] re-verifies a vector file (the published one) with the Rust crates: every
//!   pre-signature pre-verifies, completes into a valid signature and gives y back; quotes,
//!   invoices and ROUTE-STATEs verify; the fee carry, auths and tables recompute; the two-hop lock
//!   completes on both channels and t reads back off ch2's close.
//!
//! Every random input is fixed (keys are sha256(tag) mod n; adaptor nonces are injected).
use serde_json::{json, Value};
use xbt402::adaptor::{self, PreSig, Sc, Secp256k1Dleq};
use xbt402::channel::{channel_auth_key, channel_payee_secret, ChannelParams, FeePayer, Payee};
use xbt402::json::dumps;
use xbt402::route::*;
use xbt402::wire::{hub_channel_message, request_auth, request_digest_v2};
use xbt_primitives::ecdsa;
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::{PublicKey, SecretKey};
use xbt_primitives::tx::Tx;

pub const NET: &str = "bip122:0000000000000000000000000000beef";

fn key(tag: &str) -> SecretKey {
    Sc::reduce(&sha256(tag.as_bytes())).secret().expect("nonzero")
}

fn h32(tag: &str) -> [u8; 32] {
    sha256(tag.as_bytes())
}

fn pubh(x: &SecretKey) -> String {
    hex::encode(ecdsa::pubkey(x))
}

fn sh(x: &SecretKey) -> String {
    hex::encode(x.secret_bytes())
}

fn pt(p: &PublicKey) -> String {
    hex::encode(adaptor::enc(p))
}

fn presign_fixed(x: &SecretKey, z: &[u8; 32], y: &PublicKey, k: &str, w: &str) -> PreSig {
    Secp256k1Dleq.presign_with_nonces(x, z, y, &key(k), &key(w)).expect("nonces give a pre-signature")
}

fn with_type(mut s: Vec<u8>) -> Vec<u8> {
    s.push(0x21);
    s
}

fn adaptor_section() -> Value {
    let mut out = vec![];
    for i in 0..5 {
        let (x, y) = (key(&format!("adaptor/x/{i}")), key(&format!("adaptor/y/{i}")));
        let z = h32(&format!("adaptor/z/{i}"));
        let yp = adaptor::point_of(&y);
        let pre = presign_fixed(&x, &z, &yp, &format!("adaptor/k/{i}"), &format!("adaptor/w/{i}"));
        let xp = ecdsa::pubkey(&x);
        let sig = adaptor::adapt(&pre, &y).expect("adapt");
        let ext = adaptor::extract(&pre, &with_type(sig.clone()), &yp).map(|s| sh(&s)).unwrap_or_default();
        out.push(json!({"x": sh(&x), "X": pubh(&x), "z": hex::encode(z), "y": sh(&y), "Y": pt(&yp),
                        "k": sh(&key(&format!("adaptor/k/{i}"))), "w": sh(&key(&format!("adaptor/w/{i}"))),
                        "presig": pre.to_json(), "preverify": adaptor::preverify(&xp, &z, &yp, &pre),
                        "preverifyOtherDigest": adaptor::preverify(&xp, &h32("other"), &yp, &pre),
                        "preverifyOtherPoint": adaptor::preverify(&xp, &z, &adaptor::point_of(&key("other")), &pre),
                        "sig": hex::encode(&sig), "sigVerifies": ecdsa::verify(&xp, &z, &sig), "extracted": ext,
                        "bogusDer": hex::encode(pre.bogus_der()), "bogusVerifies": ecdsa::verify(&xp, &z, &pre.bogus_der())}));
    }
    Value::Array(out)
}

fn fee_quote(hub: &SecretKey) -> FeeQuote {
    FeeQuote { hub: pubh(hub), network: NET.into(), fee_base_msat: 100, fee_ppm: 2000, max_lock_sat: 20000, max_unguarded_lock_sat: 500,
               min_in_expiry_delta: 144, reveal_timeout_sec: 2, seq: 1727500001, issued_at: 1727500000, valid_until: 1727500600,
               sig: String::new() }.sign(hub)
}

fn num(x: f64) -> Value {
    Value::Number(serde_json::Number::from_f64(x).expect("finite"))
}

fn route_section() -> Value {
    let (hub, prov, client) = (key("route/hub"), key("route/provider"), key("route/client"));
    let q = fee_quote(&hub);
    let (mut carry, mut units, mut paid) = (vec![], 0u128, 0u64);
    for d in [3u64, 3, 3, 1, 250, 20000, 7, 1, 1, 999] {
        let (f, u) = fee_due(&q, d, units, paid);
        units = u;
        paid += f;
        carry.push(json!({"d": d, "fee": f, "units": units.to_string(), "paid": paid}));
    }
    let price = 813 * 10u128.pow(18) + 123_456_789;
    let pq = PriceQuote { pay_to: pubh(&prov), network: NET.into(), path: "/v1/chunk".into(), amsat_per_call: price, unit: "call".into(),
                          seq: 1727500002, issued_at: 1727500000, valid_until: 1727503600, sig: String::new() }.sign(&prov);
    let inv = |sess: &str, lid: &str, t: &str, vu: f64, hubs: Value| {
        Invoice { pay_to: pubh(&prov), network: NET.into(), session: sess.into(), lock_id: lid.into(), point: pubh(&key(t)),
                  valid_until: num(vu), hubs, sig: String::new() }.sign(&prov)
    };
    let s16 = "0f".repeat(16);
    let inv_any = inv(&s16, &"ab".repeat(12), "route/t", 1727500015.125, "any".into());
    let inv_hubs = inv(&s16, &"cd".repeat(12), "route/t2", 1727500016.5, json!([pubh(&hub)]));
    let st = json!({"session": s16, "seq": 12, "calls": 12, "chargeAmsat": price.to_string(), "accruedAmsat": (12 * price).to_string(),
                    "paidSat": 9, "quote": pq.quote_id(),
                    "lastLock": {"lockId": "ab".repeat(12), "amount": 9, "secret": sh(&key("route/t"))},
                    "invoice": inv_hubs.to_json()});
    let signed = state_sign(&prov, &st);
    let skey = session_key(&client, &ecdsa::pubkey(&prov)).expect("key");
    assert_eq!(skey, session_key(&prov, &ecdsa::pubkey(&client)).expect("key"));
    let req = request_digest_v2("POST", "https://provider.example/v1/chunk", br#"{"tokens":1}"#);
    let tpt = pubh(&key("route/t")).to_uppercase();
    let chan = format!("{}:1", "22".repeat(32));
    let rok: Vec<Value> = [(100, 9000, 5000, 144, 144), (100, 5000, 5000, 144, 144), (4857, 9000, 5000, 144, 144),
                           (4856, 9000, 5000, 144, 144), (100, 5288, 5000, 144, 144), (100, 5287, 5000, 144, 144)]
        .iter().map(|&(t, i, o, m, d)| json!([t, i, o, m, d, route_ok(t, i, o, m, d)])).collect();
    let nc: Vec<Value> = [(0u64, 5u64, 546u64), (0, 5, 1146), (2000, 37, 1146), (540, 6, 546)]
        .iter().map(|&(r, a, f)| json!([r, a, f, next_cum(r, a, f)])).collect();
    json!({
        "hub": pubh(&hub), "provider": pubh(&prov), "client": pubh(&client),
        "feeQuote": q.to_json(), "feeQuoteVerifies": q.verify(), "feeCarry": carry,
        "priceQuote": pq.to_json(), "priceQuoteId": pq.quote_id(), "priceQuoteVerifies": pq.verify(),
        "invoiceAny": inv_any.to_json(), "invoiceHubs": inv_hubs.to_json(),
        "routeState": signed, "routeStateVerifies": state_verify(&pubh(&prov), &signed),
        "sessionKey": hex::encode(skey),
        "callAuth": {"session": s16, "seq": 7, "req": req, "auth": call_auth(&skey, &s16, 7, &req)},
        "lockAuth": {"session": s16, "lockId": "ab".repeat(12), "amount": 37, "point": tpt, "hub": pubh(&hub),
                     "auth": lock_auth(&skey, &s16, &"ab".repeat(12), 37, &tpt, &pubh(&hub))},
        "hubBinding": {"chan": chan, "sig": hex::encode(ecdsa::sign(&hub, &hub_channel_message(&chan)))},
        "routeOk": rok, "nextCum": nc,
    })
}

fn params(pay_to: &SecretKey, payer: &SecretKey, expiry: u32, fp: FeePayer, txid: &str, vout: u32, cap: u64) -> ChannelParams {
    ChannelParams::derive(&ecdsa::pubkey(pay_to), &ecdsa::pubkey(payer), expiry, 600, None, NET, fp)
        .and_then(|p| p.with_funding(txid, vout, cap)).expect("params")
}

fn lock_section() -> Value {
    let (client, hub, prov, ch2key) = (key("lock/client"), key("lock/hub"), key("lock/provider"), key("lock/hub-ch2"));
    let (t, r) = (key("lock/t"), key("lock/r"));
    let tp = adaptor::point_of(&t);
    let t1 = adaptor::add(Some(&tp), Some(&adaptor::point_of(&r))).expect("T1");
    let p1 = params(&hub, &client, 9000, FeePayer::Payer, &"11".repeat(32), 0, 200000);
    let p2 = params(&prov, &ch2key, 8000, FeePayer::Payee, &"22".repeat(32), 1, 150000);
    let q = fee_quote(&hub);
    let d = 37u64;
    let (f, units) = fee_due(&q, d, 0, 0);
    let (routed1, routed2) = (1000u64, 2000u64);
    let cum1 = next_cum(routed1, d + f, p1.min_amount());
    let cum2 = next_cum(routed2, d, p2.min_amount());
    let z1 = p1.sighash(&p1.state_tx(cum1).expect("state")).expect("sighash");
    let z2 = p2.sighash(&p2.state_tx(cum2).expect("state")).expect("sighash");
    let pre1 = presign_fixed(&client, &z1, &t1, "lock/k1", "lock/w1");
    let pre2 = presign_fixed(&ch2key, &z2, &tp, "lock/k2", "lock/w2");
    let (session, lock_id) = ("5e".repeat(16), "1d".repeat(12));
    let skey = session_key(&key("lock/route-client"), &ecdsa::pubkey(&prov)).expect("key");
    let inv = Invoice { pay_to: pubh(&prov), network: NET.into(), session: session.clone(), lock_id: lock_id.clone(), point: pt(&tp),
                        valid_until: num(1727500015.125), hubs: "any".into(), sig: String::new() }.sign(&prov);
    let la = lock_auth(&skey, &session, &lock_id, d as i128, &pt(&tp), &pubh(&hub));
    let route = json!({"provider": "http://127.0.0.1:33111", "payTo": pubh(&prov), "network": NET, "amount": d, "point": pt(&tp),
                       "fee": f, "feeQuote": q.to_json(), "invoice": inv.to_json(), "session": session, "lockId": lock_id,
                       "lockAuth": la, "tweak": sh(&r)});
    let body1 = dumps(&json!({"route": route}));
    let mut pl1 = json!({"chan": p1.channel_id(), "seq": 5, "cum": cum1.to_string(), "adaptor": pre1.to_json(), "point": pt(&t1)});
    let k1 = channel_auth_key(&client, &p1.payee_pub).expect("key");
    pl1["auth"] = request_auth(&k1, &p1.channel_id(), pl1.get("seq"), pl1.get("cum"), None, &request_digest_v2("POST", &format!("https://hub.example{HUB_ROUTE_PATH}"), body1.as_bytes())).into();
    let rt2 = json!({"session": session, "lockId": lock_id, "amount": d, "lockAuth": la, "hub": pubh(&hub)});
    let body2 = dumps(&json!({"route": rt2}));
    let mut pl2 = json!({"chan": p2.channel_id(), "seq": 3, "cum": cum2.to_string(), "point": pt(&tp), "adaptor": pre2.to_json()});
    let k2 = channel_auth_key(&ch2key, &p2.payee_pub).expect("key");
    pl2["auth"] = request_auth(&k2, &p2.channel_id(), pl2.get("seq"), pl2.get("cum"), None, &request_digest_v2("POST", &format!("https://provider.example{ROUTE_LOCK_PATH}"), body2.as_bytes())).into();
    let sig2 = with_type(adaptor::adapt(&pre2, &t).expect("adapt"));
    let mut payee2 = Payee::new(p2.clone(), channel_payee_secret(NET, &prov, &p2.payer_pub, p2.expiry).expect("secret")).expect("payee");
    payee2.accept(cum2, &sig2).expect("ch2 completion is a valid state");
    let close2 = payee2.close_tx().expect("close");
    let t_back = adaptor::secret_from_witness(&pre2, &close2.inputs[0].witness, &tp).map(|s| sh(&s)).unwrap_or_default();
    let s1 = Sc::from_secret(&t).add(&Sc::from_secret(&r));
    let sig1 = with_type(adaptor::adapt(&pre1, &s1.secret().expect("t + r")).expect("adapt"));
    let mut payee1 = Payee::new(p1.clone(), channel_payee_secret(NET, &hub, &p1.payer_pub, p1.expiry).expect("secret")).expect("payee");
    payee1.accept(cum1, &sig1).expect("ch1 completion is a valid state");
    let answer = json!({"lockId": lock_id, "secret": sh(&t), "cum": cum2.to_string(), "chan": p2.channel_id(), "routedSat": routed2 + d,
                        "session": state_sign(&prov, &json!({"session": session, "lockId": lock_id, "amount": d, "paidSat": 9}))});
    let mut v11 = p2.clone();
    v11.close_fee_payer = FeePayer::Payer;
    let zv11 = v11.sighash(&v11.state_tx(cum2).expect("state")).expect("sighash");
    json!({
        "ch1": p1.to_json(), "ch1Id": p1.channel_id(), "ch2": p2.to_json(), "ch2Id": p2.channel_id(),
        "ch1MinCum": p1.min_amount(), "ch2MinCum": p2.min_amount(),
        "t": sh(&t), "T": pt(&tp), "r": sh(&r), "T1": pt(&t1),
        "d": d, "fee": f, "feeUnits": units.to_string(), "routed1": routed1, "routed2": routed2, "cum1": cum1, "cum2": cum2,
        "ch1Sighash": hex::encode(z1), "ch2Sighash": hex::encode(z2),
        "routeBody": body1, "routePayload": pl1, "lockBody": body2, "lockPayload": pl2,
        "ch2Completed": hex::encode(&sig2), "ch2Close": close2.to_hex(), "tFromCh2Close": t_back,
        "hubSecret": s1.hex(), "ch1Completed": hex::encode(&sig1), "clientReceipt": s1.sub(&Sc::from_secret(&r)).hex(),
        "providerAnswer": answer,
        "ch1PreverifyUnderT": adaptor::preverify(&p1.payer_pub, &z1, &tp, &pre1),
        "ch2PreverifyV11State": adaptor::preverify(&p2.payer_pub, &zv11, &tp, &pre2),
    })
}

/// The routing vector file, rebuilt by the Rust crates.
pub fn generate() -> Value {
    json!({"about": "xbt402 hub routing vectors (AGP-026): generated by scripts/route_vectors.py from B1 agp-023 xbt402/adaptor.py + route.py; the Rust emitter xbt402-route-vectors must match byte for byte",
           "network": NET, "adaptor": adaptor_section(), "route": route_section(), "lock": lock_section()})
}

fn write_indent(out: &mut String, v: &Value, level: usize) {
    let pad = |n: usize| " ".repeat(n);
    match v {
        Value::Array(a) if !a.is_empty() => {
            out.push_str("[\n");
            for (i, x) in a.iter().enumerate() {
                out.push_str(&pad(level + 1));
                write_indent(out, x, level + 1);
                out.push_str(if i + 1 < a.len() { ",\n" } else { "\n" });
            }
            out.push_str(&pad(level));
            out.push(']');
        }
        Value::Object(m) if !m.is_empty() && xbt402::json::as_big_int(v).is_none() => {
            out.push_str("{\n");
            for (i, (k, x)) in m.iter().enumerate() {
                out.push_str(&pad(level + 1));
                out.push_str(&dumps(&Value::String(k.clone())));
                out.push_str(": ");
                write_indent(out, x, level + 1);
                out.push_str(if i + 1 < m.len() { ",\n" } else { "\n" });
            }
            out.push_str(&pad(level));
            out.push('}');
        }
        x => out.push_str(&dumps(x)),
    }
}

/// `json.dumps(v, indent=1) + "\n"`.
pub fn dump_indent1(v: &Value) -> String {
    let mut s = String::new();
    write_indent(&mut s, v, 0);
    s.push('\n');
    s
}

// --- independent checks ------------------------------------------------------------------------------

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn u(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or(u64::MAX)
}

fn hx(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(s(v, k)).unwrap_or_default()
}

fn scalar(v: &Value, k: &str) -> Option<SecretKey> {
    Sc::from_hex64(s(v, k)).and_then(|x| x.secret())
}

/// Re-verify a routing vector file with the Rust crates. Returns the names of the checks that fail.
pub fn check(doc: &Value) -> Vec<String> {
    let mut bad = vec![];
    let mut ok = |name: String, c: bool| {
        if !c {
            bad.push(name);
        }
    };
    for (i, a) in doc["adaptor"].as_array().into_iter().flatten().enumerate() {
        let pre = PreSig::from_json(&a["presig"]);
        let (Ok(pre), Some(x), Some(y), Ok(yp)) = (pre, scalar(a, "x"), scalar(a, "y"), adaptor::dec_hex(s(a, "Y"))) else {
            ok(format!("adaptor[{i}] parses"), false);
            continue;
        };
        let (xp, z) = (hx(a, "X"), <[u8; 32]>::try_from(hx(a, "z")).unwrap_or_default());
        ok(format!("adaptor[{i}] X = x*G"), pubh(&x) == s(a, "X"));
        ok(format!("adaptor[{i}] preverify"), adaptor::preverify(&xp, &z, &yp, &pre) && a["preverify"] == true);
        ok(format!("adaptor[{i}] refusals"), a["preverifyOtherDigest"] == false && a["preverifyOtherPoint"] == false
            && !adaptor::preverify(&xp, &h32("other"), &yp, &pre));
        let sig = hx(a, "sig");
        ok(format!("adaptor[{i}] completion verifies"), ecdsa::verify(&xp, &z, &sig) && a["sigVerifies"] == true);
        ok(format!("adaptor[{i}] completion = adapt(pre, y)"), adaptor::adapt(&pre, &y).ok() == Some(sig.clone()));
        ok(format!("adaptor[{i}] extract"), adaptor::extract(&pre, &sig, &yp) == Some(y) && scalar(a, "extracted") == Some(y));
        ok(format!("adaptor[{i}] bogus DER refused"), !ecdsa::verify(&xp, &z, &hx(a, "bogusDer")) && a["bogusVerifies"] == false);
    }
    let r = &doc["route"];
    match FeeQuote::from_json(&r["feeQuote"]) {
        Ok(q) => {
            ok("route feeQuote verifies".into(), q.verify() && q.hub == s(r, "hub"));
            let (mut units, mut paid) = (0u128, 0u64);
            for c in r["feeCarry"].as_array().into_iter().flatten() {
                let (f, un) = fee_due(&q, u(c, "d"), units, paid);
                units = un;
                paid += f;
                ok(format!("route feeCarry d={}", u(c, "d")), f == u(c, "fee") && units.to_string() == s(c, "units") && paid == u(c, "paid"));
            }
        }
        Err(_) => ok("route feeQuote parses".into(), false),
    }
    match PriceQuote::from_json(&r["priceQuote"]) {
        Ok(pq) => ok("route priceQuote verifies".into(), pq.verify() && pq.quote_id() == s(r, "priceQuoteId") && pq.amsat_per_call > u64::MAX as u128),
        Err(_) => ok("route priceQuote parses".into(), false),
    }
    for k in ["invoiceAny", "invoiceHubs"] {
        ok(format!("route {k} verifies"), Invoice::from_json(&r[k]).is_ok_and(|i| i.verify()));
    }
    ok("route ROUTE-STATE verifies".into(), state_verify(s(r, "provider"), &r["routeState"]));
    let skey = <[u8; 32]>::try_from(hx(r, "sessionKey")).unwrap_or_default();
    let ca = &r["callAuth"];
    ok("route callAuth".into(), call_auth(&skey, s(ca, "session"), u(ca, "seq"), s(ca, "req")) == s(ca, "auth"));
    let la = &r["lockAuth"];
    ok("route lockAuth".into(), lock_auth(&skey, s(la, "session"), s(la, "lockId"), u(la, "amount") as i128, s(la, "point"), s(la, "hub")) == s(la, "auth"));
    let hb = &r["hubBinding"];
    ok("route hub binding".into(), ecdsa::verify(&hx(r, "hub"), &hub_channel_message(s(hb, "chan")), &hx(hb, "sig")));
    for row in r["routeOk"].as_array().into_iter().flatten() {
        let n = |i: usize| row[i].as_u64().unwrap_or(0) as u32;
        ok(format!("route route_ok {row}"), Value::Bool(route_ok(n(0), n(1), n(2), n(3), n(4))) == row[5]);
    }
    for row in r["nextCum"].as_array().into_iter().flatten() {
        let n = |i: usize| row[i].as_u64().unwrap_or(0);
        ok(format!("route next_cum {row}"), next_cum(n(0), n(1), n(2)) == n(3));
    }
    let lk = &doc["lock"];
    let (Ok(p1), Ok(p2)) = (ChannelParams::from_json(&lk["ch1"]), ChannelParams::from_json(&lk["ch2"])) else {
        ok("lock params parse".into(), false);
        return bad;
    };
    let (Ok(tp), Ok(t1), Some(t), Some(rr)) = (adaptor::dec_hex(s(lk, "T")), adaptor::dec_hex(s(lk, "T1")), scalar(lk, "t"), scalar(lk, "r")) else {
        ok("lock points parse".into(), false);
        return bad;
    };
    ok("lock T = t*G, T1 = T + r*G".into(), adaptor::point_of(&t) == tp && adaptor::add(Some(&tp), Some(&adaptor::point_of(&rr))) == Some(t1));
    let (cum1, cum2) = (u(lk, "cum1"), u(lk, "cum2"));
    ok("lock cum1/cum2".into(), cum1 == next_cum(u(lk, "routed1"), u(lk, "d") + u(lk, "fee"), p1.min_amount())
        && cum2 == next_cum(u(lk, "routed2"), u(lk, "d"), p2.min_amount()) && p2.min_amount() == 1146);
    let (Ok(pre1), Ok(pre2)) = (PreSig::from_json(&lk["routePayload"]["adaptor"]), PreSig::from_json(&lk["lockPayload"]["adaptor"])) else {
        ok("lock pre-signatures parse".into(), false);
        return bad;
    };
    let z1 = p1.state_tx(cum1).and_then(|tx| p1.sighash(&tx)).unwrap_or_default();
    let z2 = p2.state_tx(cum2).and_then(|tx| p2.sighash(&tx)).unwrap_or_default();
    ok("lock sighashes".into(), hex::encode(z1) == s(lk, "ch1Sighash") && hex::encode(z2) == s(lk, "ch2Sighash"));
    ok("lock ch1 pre-verifies under T1 (the hub's check 4)".into(), adaptor::preverify(&p1.payer_pub, &z1, &t1, &pre1));
    ok("lock ch1 does not pre-verify under T".into(), !adaptor::preverify(&p1.payer_pub, &z1, &tp, &pre1) && lk["ch1PreverifyUnderT"] == false);
    ok("lock ch2 pre-verifies under T (the provider's check)".into(), adaptor::preverify(&p2.payer_pub, &z2, &tp, &pre2));
    ok("lock ch2 pre-signature is for the payee-pays state only".into(), lk["ch2PreverifyV11State"] == false);
    let rp = &lk["routePayload"];
    let k1 = channel_auth_key(&key("lock/client"), &p1.payee_pub).unwrap_or_default();
    ok("lock route payload auth".into(), s(rp, "auth") == request_auth(&k1, &p1.channel_id(), rp.get("seq"), rp.get("cum"), None,
                                                                      &request_digest_v2("POST", &format!("https://hub.example{HUB_ROUTE_PATH}"), s(lk, "routeBody").as_bytes())));
    let lp = &lk["lockPayload"];
    let k2 = channel_auth_key(&key("lock/hub-ch2"), &p2.payee_pub).unwrap_or_default();
    ok("lock hub payload auth".into(), s(lp, "auth") == request_auth(&k2, &p2.channel_id(), lp.get("seq"), lp.get("cum"), None,
                                                                    &request_digest_v2("POST", &format!("https://provider.example{ROUTE_LOCK_PATH}"), s(lk, "lockBody").as_bytes())));
    let sig2 = hx(lk, "ch2Completed");
    ok("lock ch2 completion is a valid 0x21 state".into(), sig2.last() == Some(&0x21) && ecdsa::verify(&p2.payer_pub, &z2, &sig2[..sig2.len() - 1]));
    match Tx::parse_hex(s(lk, "ch2Close")) {
        Ok(close2) => {
            ok("lock t read back off ch2's close".into(), adaptor::secret_from_witness(&pre2, &close2.inputs[0].witness, &tp) == Some(t)
                && scalar(lk, "tFromCh2Close") == Some(t));
            ok("lock ch2 close pays the provider cum2 - its fee".into(), close2.outputs[0].value as u64 == cum2 - 600
                && close2.outputs[1].value as u64 == p2.capacity - cum2);
        }
        Err(_) => ok("lock ch2 close parses".into(), false),
    }
    let sig1 = hx(lk, "ch1Completed");
    let s1 = Sc::from_secret(&t).add(&Sc::from_secret(&rr));
    ok("lock ch1 completion (t + r) is a valid 0x21 state".into(), sig1.last() == Some(&0x21) && ecdsa::verify(&p1.payer_pub, &z1, &sig1[..sig1.len() - 1])
        && Sc::from_hex64(s(lk, "hubSecret")) == Some(s1) && scalar(lk, "clientReceipt") == Some(t));
    ok("lock provider answer signed".into(), state_verify(&pubh(&key("lock/provider")), &lk["providerAnswer"]["session"]));
    let rb: Value = xbt402::json::parse(s(lk, "routeBody")).unwrap_or(Value::Null);
    ok("lock the invoice and fee quote in the route body verify".into(),
       Invoice::from_json(&rb["route"]["invoice"]).is_ok_and(|i| i.verify()) && FeeQuote::from_json(&rb["route"]["feeQuote"]).is_ok_and(|q| q.verify()));
    bad
}

/// Number of checks [`check`] runs on a well-formed file with `n` adaptor cases (for the table).
pub fn check_count(doc: &Value) -> usize {
    let n = doc["adaptor"].as_array().map(Vec::len).unwrap_or(0);
    let carry = doc["route"]["feeCarry"].as_array().map(Vec::len).unwrap_or(0);
    let rok = doc["route"]["routeOk"].as_array().map(Vec::len).unwrap_or(0);
    let nc = doc["route"]["nextCum"].as_array().map(Vec::len).unwrap_or(0);
    n * 7 + 1 + carry + 1 + 2 + 1 + 2 + 1 + rok + nc + 16
}
