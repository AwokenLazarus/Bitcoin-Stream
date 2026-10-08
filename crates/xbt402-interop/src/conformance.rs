//! The conformance suite: every published vector recomputed by the Rust crates and compared byte
//! for byte, plus the behaviour the vectors record (what must be refused, and with which code;
//! which key signed what). Each group reports N/N.
//!
//! * xbt402 (B1 `agp-029` `docs/x402/vectors.json`, 50 vectors, counted as `check_vectors.py`
//!   counts them): the Rust emitter ([`crate::vectors::generate`]) rebuilds the whole file and every
//!   difference is charged to the vector it belongs to; then the independent checks of
//!   `check_vectors.py` run in Rust against the published values.
//! * UnifiedSighash (B1 `tests/data/unified_sighash.json`, the 166 Knots reference vectors).
//! * BLAKE2b header v2 (B2 `tests/vectors/block_header_v2.json`: every stage of 5 headers).
//! * BLAKE2b regtest chain (B2 `tests/vectors/blake2b_regtest.json`: 24 headers across the v1/v2
//!   boundary, their blocks' merkle roots, and a header chain built from the first v2 header).
use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;
use xbt402::channel::{ChannelParams, Payee, FeePayer, DUST};
use xbt402::wire::{close_message, receipt_message, unb64json};
use xbt_primitives::ecdsa::{self, is_strict_der, scalar_mod_n};
use xbt_primitives::hash::{sha256, tagged_hash};
use xbt_primitives::header::{self, HeaderChain};
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::sighash::{unified_sighash, ScriptType, SIGHASH_ALL_UNIFIED, SIGHASH_SINGLE_ACP_UNIFIED};
use xbt_primitives::tx::{Tx, TxOut};

use crate::vectors;

/// One vector group's result.
#[derive(Debug, Clone)]
pub struct Group {
    pub name: String,
    pub source: String,
    pub total: usize,
    pub passed: usize,
    pub failures: Vec<String>,
}

impl Group {
    pub fn ok(&self) -> bool {
        self.passed == self.total && self.failures.is_empty()
    }
}

/// `check_vectors.diff`: every path where `got` differs from `want`.
pub fn diff(want: &Value, got: &Value, path: &str, out: &mut Vec<String>) {
    use Value::*;
    let kind = |v: &Value| match v {
        Null => 0,
        Bool(_) => 1,
        Number(n) if n.is_f64() => 2,
        Number(_) => 3,
        String(_) => 4,
        Array(_) => 5,
        Object(_) => 6,
    };
    if kind(want) != kind(got) {
        out.push(format!("{path}: type differs"));
        return;
    }
    match (want, got) {
        (Object(w), Object(g)) => {
            for k in w.keys().filter(|k| !g.contains_key(*k)) {
                out.push(format!("{path}.{k}: missing"));
            }
            for k in g.keys().filter(|k| !w.contains_key(*k)) {
                out.push(format!("{path}.{k}: unexpected"));
            }
            for (k, wv) in w {
                if let Some(gv) = g.get(k) {
                    diff(wv, gv, &format!("{path}.{k}"), out);
                }
            }
        }
        (Array(w), Array(g)) => {
            if w.len() != g.len() {
                out.push(format!("{path}: length {} != {}", w.len(), g.len()));
                return;
            }
            for (i, (a, b)) in w.iter().zip(g).enumerate() {
                diff(a, b, &format!("{path}[{i}]"), out);
            }
        }
        _ => {
            if want != got {
                out.push(format!("{path}: {} != {}", short(want), short(got)));
            }
        }
    }
}

fn short(v: &Value) -> String {
    let s = v.to_string();
    s.chars().take(60).collect()
}

/// RFC 2104 over SHA-256, written out so the check does not share the library's HMAC.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let pad = |b: u8| k.iter().map(|x| x ^ b).collect::<Vec<u8>>();
    let mut inner = pad(0x36);
    inner.extend_from_slice(msg);
    let mut outer = pad(0x5c);
    outer.extend_from_slice(&sha256(&inner));
    sha256(&outer)
}

fn h(v: &Value) -> Vec<u8> {
    v.as_str().and_then(|s| hex::decode(s).ok()).unwrap_or_default()
}

fn h32(v: &Value) -> [u8; 32] {
    h(v).try_into().unwrap_or([0; 32])
}

fn secret(v: &Value) -> SecretKey {
    SecretKey::from_slice(&h(v)).unwrap_or_else(|_| SecretKey::from_slice(&[1; 32]).expect("one"))
}

fn u(v: &Value) -> u64 {
    v.as_u64().unwrap_or(u64::MAX)
}

/// The xbt402 vector units, keyed as `check_vectors.py` counts them (50 for the v1.2 file with AGP-029's payeePays.close).
fn units(v: &Value) -> Vec<String> {
    let n = |p: &str| v.pointer(p).and_then(Value::as_array).map(Vec::len).unwrap_or(0);
    let mut out = vec![];
    for i in 0..n("/derivation") { out.push(format!("derivation[{i}]")); }
    for i in 0..n("/auth/cases") { out.push(format!("auth.cases[{i}]")); }
    for i in 0..n("/state/states") { out.push(format!("state.states[{i}]")); }
    for i in 0..n("/state/invalid") { out.push(format!("state.invalid[{i}]")); }
    out.push("state.closeTx".into());
    out.push("state.refundTx".into());
    for i in 0..n("/roundtrip/steps") { out.push(format!("roundtrip.steps[{i}]")); }
    out.push("conditional".into());
    for i in 0..n("/conditional/steps") { out.push(format!("conditional.steps[{i}]")); }
    for i in 0..n("/payeePays/states") { out.push(format!("payeePays.states[{i}]")); }
    for i in 0..n("/payeePays/invalid") { out.push(format!("payeePays.invalid[{i}]")); }
    for k in ["closeTx", "a3State", "rollover", "conditional", "terms", "open"] { out.push(format!("payeePays.{k}")); }
    if v.pointer("/payeePays/close").is_some() { out.push("payeePays.close".into()); }
    out
}

/// Which units a failing path (`$.a.b[1].c` or a check label) belongs to.
fn charge(path: &str, all: &[String]) -> Vec<String> {
    let p = path.trim_start_matches("$.");
    let hit: Vec<String> = all.iter().filter(|u| p == u.as_str() || p.starts_with(&format!("{u}.")) || p.starts_with(&format!("{u}["))
                                              || p.starts_with(&format!("{u}:"))).cloned().collect();
    if !hit.is_empty() {
        return hit;
    }
    // a section-level field (params, secrets, K...) is shared by every vector of that section
    let section = p.split(['.', '[', ':']).next().unwrap_or("");
    let shared: Vec<String> = all.iter().filter(|u| u.split(['.', '[']).next() == Some(section)).cloned().collect();
    if shared.is_empty() { all.to_vec() } else { shared }
}

/// `check_vectors.independent_checks`, in Rust, over the published values.
pub fn independent_checks(v: &Value) -> Vec<String> {
    let mut errs = vec![];
    let mut need = |ok: bool, what: String| if !ok { errs.push(what) };
    let payto = vectors::payto_secret();
    for (i, d) in v["derivation"].as_array().into_iter().flatten().enumerate() {
        let net = d["network"].as_str().unwrap_or("").as_bytes();
        let mut pre = vec![net.len() as u8];
        pre.extend_from_slice(net);
        pre.extend(h(&d["payTo"]));
        pre.extend(h(&d["payerPub"]));
        pre.extend(h(&d["expiryLE32"]));
        need(h(&d["tweakPreimage"]) == pre, format!("derivation[{i}]: preimage layout"));
        let t = scalar_mod_n(&tagged_hash("xbt-channel/payee/v2", &h(&d["tweakPreimage"])));
        need(t.to_be_bytes() == h32(&d["t"]), format!("derivation[{i}]: t != tagged_hash mod n"));
        let p = payto.add_tweak(&t).map(|s| hex::encode(ecdsa::pubkey(&s))).unwrap_or_default();
        need(p == d["payeePub"].as_str().unwrap_or(""), format!("derivation[{i}]: (payTo_secret + t)G != P"));
        need(d["payeePub"] != d["_payeePubV10"], format!("derivation[{i}]: v1.1 key equals the v1.0 key"));
    }
    let au = &v["auth"];
    need(au["K"] == au["_K_payee_side"], "auth.cases[0]: payer and payee disagree on K".into());
    need(hex::encode(tagged_hash("xbt402/auth-key", &h(&au["ecdhX"]))) == au["K"].as_str().unwrap_or(""), "auth.cases[0]: K != tagged_hash(x)".into());
    let cases = au["cases"].as_array().cloned().unwrap_or_default();
    for (i, c) in cases.iter().enumerate() {
        // v1.3 request binding, from the split fields alone: LE64(len) ‖ field, tagged "xbt402/req/v2"
        let mut pre = Vec::new();
        for f in [c["method"].as_str(), c["scheme"].as_str(), c["host"].as_str(), c["port"].as_str(), c["target"].as_str()] {
            let f = f.unwrap_or("").as_bytes();
            pre.extend((f.len() as u64).to_le_bytes());
            pre.extend(f);
        }
        let body = h(&c["bodyHex"]);
        pre.extend((body.len() as u64).to_le_bytes());
        pre.extend(&body);
        need(pre == h(&c["reqPreimageHex"]), format!("auth.cases[{i}]: req preimage is not the length-prefixed fields"));
        need(hex::encode(tagged_hash("xbt402/req/v2", &pre)) == c["req"].as_str().unwrap_or(""), format!("auth.cases[{i}]: req != tagged_hash(preimage)"));
        need(hex::encode(hmac_sha256(&h(&au["K"]), c["message"].as_str().unwrap_or("").as_bytes())) == c["auth"].as_str().unwrap_or(""),
             format!("auth.cases[{i}]: auth != HMAC(K, message)"));
    }
    let reqs: std::collections::BTreeSet<&str> = cases.iter().filter_map(|c| c["req"].as_str()).collect();
    need(reqs.len() == cases.len(), "auth.cases[0]: two requests share a req".into());
    let st = &v["state"];
    let p = ChannelParams::from_json(&st["params"]);
    match p {
        Err(e) => need(false, format!("state: params: {e}")),
        Ok(p) => {
            for (i, s) in st["states"].as_array().into_iter().flatten().enumerate() {
                let sig = h(&s["payerSig"]);
                need(sig.last() == Some(&SIGHASH_ALL_UNIFIED) && is_strict_der(&sig[..sig.len().saturating_sub(1)])
                     && ecdsa::verify(&p.payer_pub, &h32(&s["sighash"]), &sig[..sig.len().saturating_sub(1)]),
                     format!("state.states[{i}]: payer signature"));
            }
            match Payee::new(p.clone(), secret(&st["payeeSecret"])) {
                Err(e) => need(false, format!("state: payee key {e}")),
                Ok(payee) => {
                    for (i, bad) in st["invalid"].as_array().into_iter().flatten().enumerate() {
                        match payee.verify_state(u(&bad["cum"]), &h(&bad["payerSig"])) {
                            Ok(()) => need(false, format!("state.invalid[{i}]: accepted")),
                            Err(e) => need(e.code == bad["error"].as_str().unwrap_or(""), format!("state.invalid[{i}]: got {}", e.code)),
                        }
                    }
                }
            }
        }
    }
    let rt = &v["roundtrip"];
    let payee_pub = h(&v["derivation"][0]["payeePub"]);
    let payer_pub = v["derivation"][0]["payerPub"].clone();
    let steps: Vec<Value> = rt["steps"].as_array().cloned().unwrap_or_default();
    for (i, s) in steps.iter().enumerate() {
        let name = s["step"].as_str().unwrap_or("");
        let at = format!("roundtrip.steps[{i}]");
        if let Some(r) = s.get("receipt") {
            let resp = &s["settlementResponse"];
            need(ecdsa::verify(&payee_pub, &receipt_message(r), &h(&r["sig"])), format!("{at}: receipt not signed by P"));
            if s.get("bodyHex").is_some() {
                need(r["status"] == s["status"] && r["bodyHash"].as_str() == Some(hex::encode(sha256(&h(&s["bodyHex"]))).as_str()),
                     format!("{at}: receipt status/bodyHash is not the answer's"));
            }
            need(unb64json(s["PAYMENT-RESPONSE"].as_str().unwrap_or("")).ok().as_ref() == Some(resp), format!("{at}: header != response"));
            let keys: Vec<&str> = resp.as_object().map(|m| m.keys().map(String::as_str).collect()).unwrap_or_default();
            need(keys == ["success", "transaction", "network", "payer", "amount", "extra"] && resp["transaction"] == "" && resp["network"] == rt["network"]
                 && resp["payer"] == payer_pub && resp["extra"]["receipt"] == *r && resp["extra"]["chargedAmount"] == r["charged"],
                 format!("{at}: not the SettlementResponse around the receipt"));
        }
        if name == "facilitator verify" {
            need(s["response"]["isValid"] == Value::Bool(true), format!("{at}: a signed state must be valid"));
        }
        if name.starts_with("facilitator verify,") {
            need(s["response"] == serde_json::json!({"isValid": false, "invalidReason": "invalid_batch_settlement_xbt_signature"}), format!("{at}: relabelled cum"));
        }
        if name.starts_with("facilitator settle") {
            let close = steps.iter().find(|c| c["step"] == "cooperative close").cloned().unwrap_or_default();
            let ctxid = Tx::parse_hex(close["closeTx"].as_str().unwrap_or("")).map(|t| t.txid()).unwrap_or_default();
            need(s["response"]["success"] == Value::Bool(true) && s["response"]["transaction"] == close["response"]["txid"]
                 && close["response"]["txid"].as_str() == Some(ctxid.as_str()), format!("{at}: settle txid"));
        }
        if name.starts_with("replay") {
            need(s["status"] == 402 && s["error"] == "bad_auth" && s["hasChannelDetails"] == Value::Bool(false), format!("{at}: replay"));
        }
        if name == "cooperative close" {
            need(ecdsa::verify(&h(&payer_pub), &close_message(s["request"]["chan"].as_str().unwrap_or("")), &h(&s["request"]["sig"])),
                 format!("{at}: close request signature"));
        }
    }
    errs.extend(conditional_checks(v));
    errs.extend(payee_pays_checks(v));
    errs
}

fn conditional_checks(v: &Value) -> Vec<String> {
    let mut errs = vec![];
    let mut need = |ok: bool, what: &str| if !ok { errs.push(format!("conditional: {what}")) };
    let c = &v["conditional"];
    let (k, hh, plain, cipher) = (h(&c["k"]), h(&c["H"]), h(&c["plaintextHex"]), h(&c["cipher"]));
    need(sha256(&k).to_vec() == hh, "H != sha256(k)");
    let mut stream = vec![];
    for i in 0..plain.len().div_ceil(32) {
        let mut b = k.clone();
        b.extend_from_slice(&(i as u32).to_be_bytes());
        stream.extend(sha256(&b));
    }
    need(cipher == plain.iter().zip(&stream).map(|(a, b)| a ^ b).collect::<Vec<u8>>(), "keystream");
    let Ok(p) = ChannelParams::from_json(&c["params"]) else { return vec!["conditional: params".into()] };
    let csv = u(&c["csvDelta"]) as u8;
    let mut want = vec![0x63, 0xa8, 0x20];
    want.extend(&hh);
    want.extend([0x88, 0x21]);
    want.extend(p.payee_pub);
    want.extend([0xac, 0x67]);
    if (1..=16).contains(&csv) { want.push(0x50 + csv) } else { want.extend([1, csv]) }
    want.extend([0xb2, 0x75, 0x21]);
    want.extend(p.payer_pub);
    want.extend([0xac, 0x68]);
    need(h(&c["hashlockScript"]) == want, "script layout");
    need(c["hashlockSpk"].as_str() == Some(format!("0020{}", hex::encode(sha256(&want))).as_str()), "P2WSH(script)");
    let s = &c["state"];
    let sig = h(&s["payerSig"]);
    need(sig.last() == Some(&SIGHASH_ALL_UNIFIED) && ecdsa::verify(&p.payer_pub, &h32(&s["sighash"]), &sig[..sig.len().saturating_sub(1)]), "state signature");
    let outs: Vec<(i64, String)> = Tx::parse_hex(s["unsignedTx"].as_str().unwrap_or("")).map(|t| t.outputs.iter().map(|o| (o.value, hex::encode(&o.script_pubkey))).collect()).unwrap_or_default();
    let uncond = u(&s["uncond"]) as i64;
    need(outs.len() == 3 && outs[0] == (uncond, hex::encode(&p.payee_spk)) && outs[1] == (u(&c["condAmount"]) as i64, c["hashlockSpk"].as_str().unwrap_or("").to_string())
         && outs[2] == (p.capacity as i64 - uncond - u(&c["condAmount"]) as i64 - p.close_fee as i64, hex::encode(&p.payer_spk)), "state outputs");
    let steps: BTreeMap<String, Value> = c["steps"].as_array().into_iter().flatten().map(|x| (x["step"].as_str().unwrap_or("").to_string(), x.clone())).collect();
    let ce = &steps.get("conditional offer").cloned().unwrap_or_default()["decoded"]["accepts"][0]["extra"]["conditional"];
    need(*ce == serde_json::json!({"hash": c["H"], "amount": u(&c["condAmount"]).to_string(), "csvDelta": c["csvDelta"], "cipher": c["cipher"]}), "offer");
    let paid = steps.get("conditional paid call").cloned().unwrap_or_default();
    need(paid["payload"]["hashlock"] == c["H"] && paid["payload"]["sig"] == s["payerSig"] && paid["body"] == serde_json::json!({"cipher": c["cipher"], "preimage": c["k"], "hash": c["H"]}), "paid call");
    need(ecdsa::verify(&p.payee_pub, &receipt_message(&paid["receipt"]), &h(&paid["receipt"]["sig"])) && paid["receipt"]["charged"].as_str() == Some(u(&c["condAmount"]).to_string().as_str()), "receipt");
    let close = Tx::parse_hex(steps.get("conditional close").map(|x| x["closeTx"].as_str().unwrap_or("")).unwrap_or("")).ok();
    let claim = Tx::parse_hex(steps.get("claim").map(|x| x["claimTx"].as_str().unwrap_or("")).unwrap_or("")).ok();
    match (close, claim) {
        (Some(close), Some(claim)) => {
            let w = &close.inputs[0].witness;
            need(w.len() == 4 && w[0] == sig && w[2] == [1] && w[3] == p.script(), "close witness");
            let cw = &claim.inputs[0].witness;
            need(claim.inputs[0].prevout.txid_hex() == close.txid() && cw.len() == 4 && cw[1] == k && cw[2] == [1] && cw[3] == want
                 && cw[0].last() == Some(&SIGHASH_ALL_UNIFIED), "claim witness");
            let hv = claim.inputs[0].prevout.vout as usize;
            need(close.outputs.get(hv).map(|o| hex::encode(&o.script_pubkey)).as_deref() == c["hashlockSpk"].as_str(), "claim spends the hash lock");
        }
        _ => need(false, "close/claim parse"),
    }
    errs
}

fn payee_pays_checks(v: &Value) -> Vec<String> {
    let mut errs = vec![];
    let mut need = |ok: bool, what: &str| if !ok { errs.push(format!("payeePays.{what}")) };
    let pp = &v["payeePays"];
    let Ok(p) = ChannelParams::from_json(&pp["params"]) else { return vec!["payeePays: params".into()] };
    let (cap, fee) = (p.capacity as i64, p.close_fee as i64);
    need(p.close_fee_payer == FeePayer::Payee && u(&pp["minCum"]) == DUST + p.close_fee && u(&pp["maxCum"]) == p.capacity, "params: fee payer, min, max");
    for (i, s) in pp["states"].as_array().into_iter().flatten().enumerate() {
        let cum = u(&s["cum"]) as i64;
        let mut want = vec![serde_json::json!([cum - fee, hex::encode(&p.payee_spk)])];
        if cap - cum >= DUST as i64 {
            want.push(serde_json::json!([cap - cum, hex::encode(&p.payer_spk)]));
        }
        need(s["outputs"] == Value::Array(want), &format!("states[{i}]: outputs"));
        let sig = h(&s["payerSig"]);
        need(sig.last() == Some(&SIGHASH_ALL_UNIFIED) && ecdsa::verify(&p.payer_pub, &h32(&s["sighash"]), &sig[..sig.len().saturating_sub(1)]), &format!("states[{i}]: sig"));
    }
    if let Ok(payee) = Payee::new(p.clone(), secret(&pp["payeeSecret"])) {
        for (i, bad) in pp["invalid"].as_array().into_iter().flatten().enumerate() {
            match payee.verify_state(u(&bad["cum"]), &h(&bad["payerSig"])) {
                Ok(()) => need(false, &format!("invalid[{i}]: accepted")),
                Err(e) => need(e.code == bad["error"].as_str().unwrap_or(""), &format!("invalid[{i}]: got {}", e.code)),
            }
        }
    } else {
        need(false, "params: payee key");
    }
    let a3 = Tx::parse_hex(pp["a3State"]["unsignedTx"].as_str().unwrap_or("")).ok();
    let sig = h(&pp["a3State"]["payerSig"]);
    need(a3.is_some_and(|a3| a3.outputs[0].value == cap - 150_000 && a3.outputs[0].script_pubkey == p.payer_spk && a3.outputs[1].value == 150_000 - fee)
         && sig.last() == Some(&SIGHASH_SINGLE_ACP_UNIFIED) && ecdsa::verify(&p.payer_pub, &h32(&pp["a3State"]["sighash"]), &sig[..sig.len().saturating_sub(1)]), "a3State: output 0 / 0xA3 signature");
    let r = &pp["rollover"];
    let rt = Tx::parse_hex(r["unsignedTx"].as_str().unwrap_or("")).ok();
    let amount = u(&r["amount"]) as i64;
    need(rt.is_some_and(|t| t.outputs.len() == 2 && t.outputs[0].value == amount - fee && t.outputs[1].value == cap - amount
                        && hex::encode(&t.outputs[1].script_pubkey) == r["nextSpk"].as_str().unwrap_or(""))
         && u(&r["nextCapacity"]) as i64 == cap - amount, "rollover: outputs");
    let c = &pp["conditional"];
    let ct = Tx::parse_hex(c["unsignedTx"].as_str().unwrap_or("")).ok();
    let uncond = u(&c["uncond"]) as i64;
    need(ct.is_some_and(|t| t.outputs.len() == 3 && t.outputs[0].value == uncond - fee && t.outputs[1].value == u(&c["condAmount"]) as i64
                        && t.outputs[2].value == cap - uncond - u(&c["condAmount"]) as i64) && uncond >= DUST as i64 + fee, "conditional: fee from the payee's output");
    need(pp["terms"]["extra"]["closeFeePayer"] == "payee" && pp["terms"]["extra"].get("settleMultiple").is_some(), "terms: closeFeePayer/settleMultiple");
    let o = &pp["open"];
    need(o["status"] == 200 && o["response"]["closeFeePayer"] == "payee" && o["response"]["minCum"].as_str() == Some((DUST + p.close_fee).to_string().as_str())
         && o["response"]["chan"].as_str() == Some(p.channel_id().as_str()), "open: echoes closeFeePayer and minCum");
    // AGP-029: the close answer and /x402/settle report the gross cum with payeeFee and payeeNet
    let c = &pp["close"];
    if c.is_null() {
        need(false, "close: missing");
        return errs;
    }
    let cum = c["request"]["payload"]["cum"].as_str().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let spent = u(&c["spentMsat"]);
    let (r, sr) = (&c["response"], &c["settle"]["response"]);
    let ctx = Tx::parse_hex(c["closeTx"].as_str().unwrap_or("")).ok();
    need(cum == spent.div_ceil(1000) && cum == u(&c["calls"]).saturating_mul(u(&c["price"])), "close: the final state is not what is owed");
    need(ctx.as_ref().is_some_and(|t| t.outputs.len() == 2 && t.outputs[0].value == cum as i64 - fee && t.outputs[0].script_pubkey == p.payee_spk
                                  && t.outputs[1].value == cap - cum as i64 && t.outputs[1].script_pubkey == p.payer_spk
                                  && r["txid"].as_str() == Some(t.txid().as_str())
                                  && t.inputs[0].witness.first().map(hex::encode).as_deref() == c["request"]["payload"]["sig"].as_str()),
         "close: the tx is not the final state [cum - closeFee to P, capacity - cum to A]");
    let txid = ctx.map(|t| t.txid()).unwrap_or_default();
    let want = serde_json::json!({"chan": p.channel_id(), "txid": txid, "cum": cum.to_string(),
                                  "unpaidMsat": spent.saturating_sub(cum * 1000).to_string(),
                                  "payeeFee": fee.to_string(), "payeeNet": (cum as i64 - fee).to_string()});
    need(c["status"] == 200 && *r == want, "close: the answer must report the gross cum, payeeFee, payeeNet and unpaidMsat = spent - gross");
    let want_extra = serde_json::json!({"chan": r["chan"], "unpaidMsat": r["unpaidMsat"], "payeeFee": r["payeeFee"], "payeeNet": r["payeeNet"]});
    need(c["settle"]["status"] == 200 && sr["success"] == true && sr["transaction"].as_str() == Some(txid.as_str())
         && sr["amount"].as_str() == Some(cum.to_string().as_str()) && sr["payer"].as_str() == Some(hex::encode(p.payer_pub).as_str())
         && sr["extra"] == want_extra, "close: settle amount must be the gross cum, extra must carry unpaidMsat, payeeFee and payeeNet");
    errs
}

fn read_json(path: &Path) -> Result<Value, String> {
    let s = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    xbt402::json::parse(&s).map_err(|e| format!("{}: {e}", path.display()))
}

/// The 50 xbt402 vectors.
pub fn xbt402_group(path: &Path) -> Group {
    let mut g = Group { name: "xbt402 (v1.1 to v1.3)".into(), source: path.display().to_string(), total: 0, passed: 0, failures: vec![] };
    match read_json(path) {
        Ok(want) => xbt402_check(&want, &g.source),
        Err(e) => {
            g.failures.push(e);
            g
        }
    }
}

/// [`xbt402_group`] over an already-loaded vector file.
pub fn xbt402_check(want: &Value, source: &str) -> Group {
    let mut g = Group { name: "xbt402 (v1.1 to v1.3)".into(), source: source.into(), total: 0, passed: 0, failures: vec![] };
    let want = want.clone();
    let all = units(&want);
    g.total = all.len();
    let got = vectors::generate();
    let mut problems = vec![];
    diff(&want, &got, "$", &mut problems);
    let mut failed: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for pth in problems {
        for u in charge(&pth, &all) {
            failed.entry(u).or_default().push(format!("byte mismatch {pth}"));
        }
    }
    for e in independent_checks(&want) {
        for u in charge(&e, &all) {
            failed.entry(u).or_default().push(e.clone());
        }
    }
    g.passed = all.iter().filter(|u| !failed.contains_key(*u)).count();
    g.failures = failed.into_iter().map(|(u, e)| format!("{u}: {}", e.join("; "))).collect();
    g
}

/// The 166 Knots UnifiedSighash reference vectors.
pub fn sighash_group(path: &Path) -> Group {
    let mut g = Group { name: "UnifiedSighash (Knots)".into(), source: path.display().to_string(), total: 0, passed: 0, failures: vec![] };
    let rows = match read_json(path) {
        Ok(Value::Array(r)) => r,
        Ok(_) => { g.failures.push("not an array".into()); return g; }
        Err(e) => { g.failures.push(e); return g; }
    };
    for (n, row) in rows.iter().skip(1).enumerate() {
        g.total += 1;
        let r = (|| -> Result<bool, String> {
            let script = h(&row[0]);
            let tx = Tx::parse_hex(row[1].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
            let prevouts: Vec<TxOut> = row[5].as_array().into_iter().flatten()
                .map(|p| TxOut::new(p[0].as_i64().unwrap_or(0), h(&p[1]))).collect();
            let st = ScriptType::from_u8(row[4].as_u64().unwrap_or(9) as u8).ok_or("script type")?;
            let mut leaf_in = vec![0xc0];
            xbt_primitives::encode::write_varbytes(&mut leaf_in, &script);
            let leaf = tagged_hash("TapLeaf", &leaf_in);
            let got = unified_sighash(&tx, &prevouts, row[2].as_u64().unwrap_or(0) as usize, st, &script,
                                      (row[3].as_i64().unwrap_or(0) & 0xFF) as u8, (st == ScriptType::Tapscript).then_some(&leaf))
                .map_err(|e| e.to_string())?;
            Ok(hex::encode(got) == row[6].as_str().unwrap_or(""))
        })();
        match r {
            Ok(true) => g.passed += 1,
            Ok(false) => g.failures.push(format!("vector {n}: sighash differs")),
            Err(e) => g.failures.push(format!("vector {n}: {e}")),
        }
    }
    g
}

fn put_u32(b: &mut Vec<u8>, v: &Value) {
    b.extend((u(v) as u32).to_le_bytes());
}

/// The 5 staged BLAKE2b header v2 vectors: fields -> serialization -> every stage.
pub fn header_v2_group(path: &Path) -> Group {
    let mut g = Group { name: "BLAKE2b header v2 stages".into(), source: path.display().to_string(), total: 0, passed: 0, failures: vec![] };
    let v = match read_json(path) { Ok(v) => v, Err(e) => { g.failures.push(e); return g; } };
    for hv in v["headers"].as_array().into_iter().flatten() {
        g.total += 1;
        let name = hv["name"].as_str().unwrap_or("?");
        let f = &hv["fields"];
        let mut b = Vec::with_capacity(164);
        b.extend(((u(&f["nVersion"]) as u32) | header::V2_FLAG).to_le_bytes());
        let mut prev = h(&f["hashPrevBlock"]);
        prev.reverse();
        b.extend(prev);
        let mut mr = h(&f["hashMerkleRoot"]);
        mr.reverse();
        b.extend(mr);
        // the wire carries nTime - offset when the time-offset flag is set
        let flags = u(&f["m_flags"]) as u8;
        let t = u(&f["nTime"]) as u32;
        let off = u(&f["m_time_offset"]) as u32;
        b.extend((if flags & header::FLAG_USE_TIME_OFFSET != 0 { t.wrapping_sub(off) } else { t }).to_le_bytes());
        put_u32(&mut b, &f["nBits"]);
        put_u32(&mut b, &f["nNonce"]);
        put_u32(&mut b, &f["m_nonce2"]);
        put_u32(&mut b, &f["m_nonce3"]);
        // extranonce, xor key and the reserved slot are uint128/uint256: given in display order
        let rev = |k: &str| { let mut x = h(&f[k]); x.reverse(); x };
        b.extend(rev("m_extranonce"));
        b.extend(off.to_le_bytes());
        b.extend((u(&f["m_txcount"]) as u16).to_le_bytes());
        b.push(flags);
        b.push(u(&f["m_xor_key_mask_clear_bits"]) as u8);
        b.extend(rev("m_xor_key"));
        put_u32(&mut b, &f["m_height"]);
        b.extend(rev("m_mm_rhs"));
        let mut fails = vec![];
        if hex::encode(&b) != hv["serialized"].as_str().unwrap_or("") {
            fails.push("serialization".to_string());
        }
        match header::v2_stages(&h(&hv["serialized"])) {
            Err(e) => fails.push(e.to_string()),
            Ok(s) => {
                for (k, got) in [("xor_key_hash", s.xor_key_hash.to_vec()), ("h1", s.h1.to_vec()), ("h2", s.h2.to_vec()),
                                 ("blake2b_1", s.blake2b_1.to_vec()), ("blake2b_2", s.blake2b_2.to_vec()), ("mask", s.mask.to_vec()),
                                 ("block_hash", s.block_hash.to_vec()), ("asic_input", s.asic_input.clone())] {
                    if hex::encode(&got) != hv[k].as_str().unwrap_or("") {
                        fails.push(k.to_string());
                    }
                }
                if u(&hv["asic_profile"]) != (flags & 3) as u64 {
                    fails.push("asic_profile".into());
                }
                if let Ok(hd) = header::parse_header(&b) {
                    if hd.time != t || hd.height != u(&f["m_height"]) as u32 {
                        fails.push("parsed time/height".into());
                    }
                }
            }
        }
        if fails.is_empty() { g.passed += 1 } else { g.failures.push(format!("{name}: {}", fails.join(", "))) }
    }
    g
}

/// The Knots regtest capture: 24 headers across the v1/v2 boundary (hash, committed height),
/// every captured block's merkle root, and a HeaderChain from the first v2 header.
pub fn regtest_chain_group(path: &Path) -> Group {
    let mut g = Group { name: "BLAKE2b regtest chain (Knots capture)".into(), source: path.display().to_string(), total: 0, passed: 0, failures: vec![] };
    let v = match read_json(path) { Ok(v) => v, Err(e) => { g.failures.push(e); return g; } };
    let hdrs: Vec<Value> = v["headers"].as_array().cloned().unwrap_or_default();
    let mut v2_raw: Vec<Vec<u8>> = vec![];
    let mut first_v2: Option<(u32, String)> = None;
    for hv in &hdrs {
        g.total += 1;
        let raw = h(&hv["header"]);
        let height = u(&hv["height"]) as u32;
        let want = hv["hash"].as_str().unwrap_or("");
        let r = match header::header_size(&raw) {
            Ok(header::V2_SIZE) => header::parse_header(&raw).map(|p| {
                if first_v2.is_none() { first_v2 = Some((height, want.to_string())); }
                v2_raw.push(raw.clone());
                p.hash_hex() == want && p.height == height && p.check_pow_regtest()
            }),
            Ok(_) => header::v1_hash(&raw).map(|x| hex::encode(x) == want),
            Err(e) => Err(e),
        };
        match r {
            Ok(true) => g.passed += 1,
            Ok(false) => g.failures.push(format!("height {height}: hash/height/PoW")),
            Err(e) => g.failures.push(format!("height {height}: {e}")),
        }
    }
    for (height, b) in v["blocks"].as_object().into_iter().flatten() {
        g.total += 1;
        let r = (|| -> Result<bool, String> {
            let raw = h(&b["raw"]);
            let (hdr, txs) = header::parse_block(&raw).map_err(|e| e.to_string())?;
            let ids: Vec<[u8; 32]> = txs.iter().map(Tx::txid_bytes).collect();
            let mut root = [0u8; 32];
            root.copy_from_slice(&hdr[36..68]);
            let hash = if hdr.len() == header::V2_SIZE { header::parse_header(&hdr).map_err(|e| e.to_string())?.hash_hex() }
                       else { hex::encode(header::v1_hash(&hdr).map_err(|e| e.to_string())?) };
            Ok(header::merkle_root(&ids) == root && txs.len() as u64 == u(&b["ntx"]) && hash == b["hash"].as_str().unwrap_or(""))
        })();
        match r {
            Ok(true) => g.passed += 1,
            Ok(false) => g.failures.push(format!("block {height}: merkle root / tx count / hash")),
            Err(e) => g.failures.push(format!("block {height}: {e}")),
        }
    }
    // the chain: checkpoint at the first v2 header, then connect the rest under regtest rules
    g.total += 1;
    let chain_ok = (|| -> Result<(), String> {
        let (cp_h, cp_hash) = first_v2.clone().ok_or("no v2 header")?;
        let mut c = HeaderChain::new("regtest", (cp_h, &cp_hash), None, Box::new(|| u64::MAX / 2)).map_err(|e| e.to_string())?;
        c.set_checkpoint(&v2_raw[0]).map_err(|e| e.to_string())?;
        let r = c.connect(cp_h, &v2_raw[1..]).map_err(|e| e.to_string())?;
        if !r.adopted || r.tip != cp_h + v2_raw.len() as u32 - 1 {
            return Err(format!("chain tip {} not adopted", r.tip));
        }
        // a broken link is refused
        let mut bad = v2_raw[2].clone();
        bad[4] ^= 1;
        if c.connect(cp_h + 1, &[bad]).is_ok() {
            return Err("a header that does not link was accepted".into());
        }
        Ok(())
    })();
    match chain_ok {
        Ok(()) => g.passed += 1,
        Err(e) => g.failures.push(format!("header chain: {e}")),
    }
    g
}

trait PowRegtest {
    fn check_pow_regtest(&self) -> bool;
}

impl PowRegtest for header::Header {
    fn check_pow_regtest(&self) -> bool {
        header::check_pow(self, &header::ChainRules::regtest()).is_ok()
    }
}

/// Every group, from the workspace's pinned vector copies.
pub fn run_all(dir: &Path) -> Vec<Group> {
    vec![
        xbt402_group(&dir.join("xbt402_vectors.json")),
        sighash_group(&dir.join("unified_sighash.json")),
        header_v2_group(&dir.join("block_header_v2.json")),
        regtest_chain_group(&dir.join("blake2b_regtest.json")),
    ]
}
