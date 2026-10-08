//! The `xbt-work` v1 vector file, rebuilt by this crate ([`generate`]), and the Rust side of the
//! conformance check ([`check`]).
//!
//! [`generate`] is XBT-053 `check_work_vectors.py` `build()` step for step, computed by the Rust
//! implementation (receipts, the provider book, pricing, auth, the audit and its fraud proofs, NTA,
//! the relay), and [`to_file`] writes it exactly as Python's `json.dump(v, f, indent=1)` does, so
//! the Rust-emitted file is byte-identical to the published one and XBT-053's own checker can
//! check it. [`check`] recomputes every section of a published file, compares byte for byte, and
//! re-runs the generator-independent checks (signatures, grammars, the exact pricing bound, the
//! fraud proofs, BIP86/BIP341 published values, BIP340, the relay).
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use xbt402::json::{as_big_int, big_uint, dumps, dumps_compact};
use xbt_primitives::secp256k1::{PublicKey, Scalar, SecretKey, SECP256K1};

use crate::audit::{audit_block, check_fraud_proof, AuditBounds, Deferral, SignedDeferral, SignedWindow, WindowStatement};
use crate::auth::{auth_tag, request_digest};
use crate::book::ReceiptBook;
use crate::chain::ChainBlock;
use crate::grammar::{new_invoice, parse_username, usernames};
use crate::nta;
use crate::pricing::{bits_to_target, diff1_target, difficulty, value_sats, work_units_for_price};
use crate::receipt::{pubkey_from_hex, verify, PrimeKey, Signed, WorkReceipt};
use crate::relay;

pub const PROV: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
pub const PRIME_ID: u32 = 70;
pub const BIP86_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
pub const BIP86_PATH: &str = "m/86'/0'/0'/0/0";
/// Published values: BIP86's first receiving address of the mnemonic, BIP341 keyPathSpending[0].
pub const BIP86_PUBLISHED: (&str, &str, &str) = ("cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
                                                  "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
                                                  "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
pub const BIP341_KEYPATH: (&str, &str) = ("6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa",
                                          "2405b971772ad26915c8dcdf10f238753a9b837e5f8e6a86fd7c0cce5b7296d9");

/// The vectors have no chain: the block is the one the statement names. With
/// [`AuditBounds::STATEMENT_ONLY`] nothing reads the difficulty.
fn statement_block(w: &WindowStatement, value_sats: u64, paid_sats: u64) -> ChainBlock {
    ChainBlock { height: w.height, hash: w.block_hash.clone(), value_sats, paid_sats, bits: 0, prev_bits: 0 }
}

/// The block a fraud proof names (an unreadable proof gets a block nothing matches).
fn proof_block(proof: &Value, value_sats: u64, paid_sats: u64) -> ChainBlock {
    match SignedWindow::from_doc(&proof["window"]) {
        Ok(sw) => statement_block(&sw.stmt, value_sats, paid_sats),
        Err(_) => ChainBlock { height: 0, hash: String::new(), value_sats, paid_sats, bits: 0, prev_bits: 0 },
    }
}

const ABOUT: &str = "xbt-work v1 draft test vectors. Keys are derived from public seeds: never use them.";
const RULE_INJECTION: &str = "The Prime MUST refuse to sign (queried invoice fails the grammar); the provider MUST refuse the presented document (difficulty is not an integer). Only a verifier that rebuilds the line from unchecked strings reads the signature as valid.";
const RULE_CARRY: &str = "A block that carries an unattested provider passes the audit on the Prime's signed deferral line; without the line it is a fraud proof; a line for another block counts for nothing.";
const RULE_BIP86: &str = "NTA signs with the output key K = P + t*G, t = TaggedHash(\"TapTweak\", x(P)); its secret is d + t, d negated first if d*G has odd y. The internal secret d does not verify.";
const RULE_P2WPKH: &str = "Not OP_1 <32 bytes>: after activation a coinbase paying it is bad-nta-payee, and it has no key to attest with. A Prime can only carry its share.";

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub fn prime_seed() -> [u8; 32] {
    sha(b"xbt-work/v1 test vector prime key")
}

pub fn other_seed() -> [u8; 32] {
    sha(b"xbt-work/v1 test vector other key")
}

fn dev_rand(label: &str) -> [u8; 32] {
    sha(format!("xbt-work/v1 vector rand|{label}").as_bytes())
}

fn rand16(label: &str) -> [u8; 16] {
    dev_rand(label)[..16].try_into().expect("16")
}

fn receipt(invoice: &str, seq: u64, cum: u64, shares: u64, first: u32, last: u32, diff: u64) -> WorkReceipt {
    WorkReceipt { prime_id: PRIME_ID, identity: PROV.into(), invoice: invoice.into(), seq, cum_work: cum, shares, first_height: first,
                  last_height: last, difficulty: diff }
}

fn sig_hex(k: &PrimeKey, r: &WorkReceipt) -> String {
    hex::encode(k.sign_raw(r.message().expect("in grammar").as_bytes()))
}

fn signed(k: &PrimeKey, r: &WorkReceipt) -> Signed {
    k.sign(r).expect("in grammar")
}

// --- BIP39 / BIP32, only to rebuild the BIP86 wallet vector -------------------------------------

fn hmac512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut m = Hmac::<Sha512>::new_from_slice(key).expect("any key");
    m.update(msg);
    m.finalize().into_bytes().into()
}

/// PBKDF2-HMAC-SHA512, 2048 rounds, salt "mnemonic" + passphrase: the BIP39 seed.
pub fn bip39_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let mut salt = format!("mnemonic{passphrase}").into_bytes();
    salt.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac512(mnemonic.as_bytes(), &salt);
    let mut out = u;
    for _ in 1..2048 {
        u = hmac512(mnemonic.as_bytes(), &u);
        out.iter_mut().zip(u.iter()).for_each(|(o, x)| *o ^= x);
    }
    out
}

/// The BIP32 secret key at `path` ("m/86'/0'/0'/0/0") from a seed.
pub fn bip32_derive(seed: &[u8], path: &str) -> [u8; 32] {
    let i = hmac512(b"Bitcoin seed", seed);
    let (mut k, mut c) = (SecretKey::from_slice(&i[..32]).expect("master key"), i[32..].to_vec());
    for part in path.split('/').skip(1) {
        let hard = part.ends_with('\'');
        let idx = part.trim_end_matches('\'').parse::<u32>().expect("index") + if hard { 0x8000_0000 } else { 0 };
        let mut data = if hard {
            let mut d = vec![0u8];
            d.extend_from_slice(&k.secret_bytes());
            d
        } else {
            PublicKey::from_secret_key(SECP256K1, &k).serialize().to_vec()
        };
        data.extend_from_slice(&idx.to_be_bytes());
        let i = hmac512(&c, &data);
        k = k.add_tweak(&Scalar::from_be_bytes(i[..32].try_into().expect("32")).expect("tweak")).expect("child");
        c = i[32..].to_vec();
    }
    k.secret_bytes()
}

// --- the vector file ----------------------------------------------------------------------------

/// Rebuild every section of XBT-053's `vectors.json` with the Rust implementation.
pub fn generate() -> Value {
    let prime = PrimeKey::from_seed(PRIME_ID, &prime_seed());
    let other = PrimeKey::from_seed(PRIME_ID, &other_seed());
    let mut v = json!({"about": ABOUT,
                       "prime": {"seed": hex::encode(prime_seed()), "pubkey": prime.pubkey_hex(), "primeId": PRIME_ID},
                       "otherKey": {"seed": hex::encode(other_seed()), "pubkey": other.pubkey_hex()}});

    // 1. invoice encoding and usernames
    let (inv_a, inv_b) = (new_invoice(&rand16("invoice a")), new_invoice(&rand16("invoice b")));
    let invoices: Vec<Value> = ["invoice a", "invoice b"].iter().map(|label| {
        let i = new_invoice(&rand16(label));
        let (primary, alt) = usernames(PROV, &i, "rig1").expect("grammar");
        json!({"random": hex::encode(rand16(label)), "invoice": i, "username": format!("{alt}.rig1"), "usernameAlt": primary})
    }).collect();
    v["invoices"] = invoices.into();
    let cases = [format!("{PROV}.pw-{inv_a}.rig1"), format!("{PROV}.pw-{inv_a}"), format!("{PROV}~{inv_a}.rig1"), format!("{PROV}~{inv_a}"),
                 format!("{}.pw-{inv_a}.RIG", PROV.to_uppercase()), format!("{PROV}.rig1"), PROV.to_string(), format!("{PROV}.rig1.pw-{inv_a}"),
                 format!("{PROV}~short.rig1"), format!("{PROV}.pw-{inv_a}|9|9"), format!("  {PROV}~{inv_b}.x.y  ")];
    v["usernames"] = cases.iter().map(|u| {
        let p = parse_username(u);
        json!({"username": u, "identity": p.identity, "invoice": p.invoice, "worker": p.worker})
    }).collect::<Vec<_>>().into();

    // 2. receipts: signing and verification
    let rs = [receipt(&inv_a, 0, 0, 0, 0, 0, 0), receipt(&inv_a, 3, 12, 3, 101, 102, 4), receipt(&inv_a, 7, 28, 7, 101, 104, 4),
              receipt(&inv_b, 1, 16384, 1, 975000, 975000, 16384),
              WorkReceipt { prime_id: u32::MAX, ..receipt(&inv_b, u64::MAX, u64::MAX, u64::MAX, u32::MAX, u32::MAX, u64::MAX) }];
    v["receipts"] = rs.iter().map(|r| json!({"doc": r.to_doc(), "message": r.message().expect("grammar"), "sig": sig_hex(&prime, r)}))
        .collect::<Vec<_>>().into();
    let good = &rs[1];
    let tampered = WorkReceipt { cum_work: 13, ..good.clone() };
    v["receiptVerification"] = json!([
        {"why": "valid", "message": good.message().expect("g"), "sig": sig_hex(&prime, good), "pubkey": prime.pubkey_hex(), "valid": true},
        {"why": "cum_work edited after signing", "message": tampered.message().expect("g"), "sig": sig_hex(&prime, good),
         "pubkey": prime.pubkey_hex(), "valid": false},
        {"why": "signed by another key", "message": good.message().expect("g"), "sig": sig_hex(&other, good), "pubkey": prime.pubkey_hex(), "valid": false},
    ]);
    let base = good.to_doc();
    let bad: [(&str, &[&str], Value); 10] = [
        ("seq as a float", &["receipt", "seq"], json!(3.0)), ("seq negative", &["receipt", "seq"], json!(-1)),
        ("seq with a leading zero", &["receipt", "seq"], json!("03")), ("seq as a boolean", &["receipt", "seq"], json!(true)),
        ("cum_work above 2^64-1", &["receipt", "cum_work"], big_uint(1u128 << 64)),
        ("last_height above 2^32-1", &["receipt", "last_height"], json!(1u64 << 32)),
        ("`|` smuggled into difficulty", &["receipt", "difficulty"], json!("4|0|0")),
        ("invoice too short", &["invoice"], json!("inv1234")), ("invoice carries `|`", &["invoice"], json!(format!("{inv_a}|999|999999"))),
        ("identity carries `|`", &["identity"], json!(format!("{PROV}|x"))),
    ];
    v["malformedReceipts"] = bad.into_iter().map(|(why, path, val)| {
        let mut d = base.clone();
        match path {
            [k] => d[*k] = val,
            [a, b] => d[*a][*b] = val,
            _ => unreachable!(),
        }
        json!({"why": why, "doc": d})
    }).collect::<Vec<_>>().into();

    // field injection: what a Prime that signs any queried invoice would hand out, and why it fails
    let evil = format!("xbt-work-receipt/1|{PRIME_ID}|{PROV}|{inv_a}|999|999999|1|1|1|1|0|0|0|0|0|0");
    v["fieldInjection"] = json!({
        "queriedInvoice": format!("{inv_a}|999|999999|1|1|1|1"), "signedLine": evil, "sig": hex::encode(prime.sign_raw(evil.as_bytes())),
        "presentedDoc": {"prime_id": PRIME_ID, "identity": PROV, "invoice": inv_a,
                         "receipt": {"seq": 999, "cum_work": 999999, "shares": 1, "first_height": 1, "last_height": 1, "difficulty": "1|0|0|0|0|0|0"}},
        "rule": RULE_INJECTION});

    // 3. provider credit sequence: deltas, replays, equivocation
    let mut book = ReceiptBook::new(PROV, prime.pubkey(), PRIME_ID);
    let mut steps = vec![];
    for (label, r) in [("r(seq 3)", &rs[1]), ("r(seq 7)", &rs[2]), ("replay r(seq 3)", &rs[1]), ("replay r(seq 7)", &rs[2])] {
        let credited = book.accept(&signed(&prime, r), &inv_a).expect("credit");
        steps.push(json!({"present": label, "doc": r.to_doc(), "sig": sig_hex(&prime, r), "credited": credited}));
    }
    let twin = WorkReceipt { cum_work: 56, ..rs[2].clone() };
    let eq = match book.accept(&signed(&prime, &twin), &inv_a) {
        Ok(_) => "accepted".to_string(),
        Err(e) => e.code,
    };
    steps.push(json!({"present": "same seq 7, cum_work 56", "doc": twin.to_doc(), "sig": sig_hex(&prime, &twin), "result": eq}));
    let f = &book.fraud[0];
    v["creditSequence"] = json!({"invoice": inv_a, "steps": steps, "fraudProof": {"why": f.why, "a": f.a.line_doc(), "b": f.b.line_doc()}});

    // 4. work-unit arithmetic
    v["pricing"] = [(150u64, 0x1901_41C5u32, 312_500_000u64, 0u32, 1000u32), (150, 0x1901_41C5, 312_500_000, 0, 0),
                    (10_000, 0x1901_41C5, 312_500_000, 2500, 1000), (1, 0x1901_41C5, 312_500_000, 0, 1000),
                    (1, 0x207F_FFFF, 5_000_000_000, 0, 0), (500, 0x1A0F_FFFF, 312_500_000, 0, 500)]
        .into_iter().map(|(price, bits, value, fee, haircut)| {
            let units = work_units_for_price(price, bits, value, fee, haircut).expect("pricing");
            json!({"priceSats": price, "bits": format!("{bits:08x}"), "blockValueSats": value, "feeBps": fee, "haircutBps": haircut,
                   "difficulty": format!("{:.6}", difficulty(bits).expect("bits")), "workUnits": units,
                   "valueOfWorkUnitsSats": value_sats(units, bits, value, fee).expect("value")})
        }).collect::<Vec<_>>().into();

    // 5. request binding
    let key = dev_rand("auth key");
    v["auth"] = [(1u64, "GET", "/v1/share-change?window=7d", ""), (2, "GET", "/v1/pools?window=7d", ""), (3, "POST", "/v1/report", "{\"window\":\"7d\"}")]
        .into_iter().map(|(n, method, target, body)| {
            let r = &rs[2];
            let req = request_digest(method, target, body.as_bytes());
            json!({"authKey": hex::encode(key), "invoice": inv_a, "n": n, "seq": r.seq, "cum_work": r.cum_work, "method": method,
                   "target": target, "body": body, "req": req, "auth": auth_tag(&key, &inv_a, n, r.seq, r.cum_work, &req).expect("auth")})
        }).collect::<Vec<_>>().into();

    // 6. coinbase audit: a pass and a fraud proof
    let d = 1_000_000u64;
    let w = 8 * d;
    let ph = [(1000u32, 1003u32, 400_000u64), (1003, 1010, 600_000), (1010, 1012, 200_000)];
    let mut ap = ReceiptBook::new(PROV, prime.pubkey(), PRIME_ID);
    let (mut cum, mut seq, mut audit_receipts) = (0u64, 0u64, vec![]);
    for (_, hi, wk) in ph {
        cum += wk;
        seq += wk / 4096 + 1;
        let r = receipt(&inv_b, seq, cum, seq, ph[0].0, hi, 4096);
        ap.accept(&signed(&prime, &r), &inv_b).expect("credit");
        audit_receipts.push(json!({"doc": r.to_doc(), "sig": sig_hex(&prime, &r)}));
    }
    let (height, value) = (1013u32, 5_000_000_000u64);
    let stmt = |hash: [u8; 32], fee: u32| WindowStatement { prime_id: PRIME_ID, height, block_hash: hex::encode(hash), window_start: height - 32,
                                                           window_work: w, min_payout: 546, fee_bps: fee };
    let sw = prime.sign_window(&stmt(sha(b"vector block 1012"), 0)).expect("window");
    let aud = |sw: &SignedWindow, paid, def: &[SignedDeferral]| {
        audit_block(&ap, sw, &statement_block(&sw.stmt, value, paid), &AuditBounds::STATEMENT_ONLY, def).expect("audit")
    };
    let exp = aud(&sw, 0, &[]).expected_sats;
    let pass = aud(&sw, exp, &[]);
    let fraud = aud(&sw, exp / 2, &[]);
    v["audit"] = json!({"receipts": audit_receipts, "intervals": ap.intervals.iter().map(|(lo, hi, w)| json!([lo, hi, w])).collect::<Vec<_>>(),
                        "window": sw.line_doc(), "coinbaseValueSats": value, "difficulty": d,
                        "pass": {"paidSats": exp, "ok": pass.ok, "expectedSats": pass.expected_sats},
                        "fraud": {"paidSats": exp / 2, "ok": fraud.ok, "expectedSats": fraud.expected_sats, "proof": fraud.proof},
                        "belowFloor": {"minPayout": exp + 1, "paidSats": 0, "ok": true}});

    // 6b. the same audit under XBT-NTA: the unattested provider is carried on a signed deferral line
    let nh = sha(b"vector block 1012 nta");
    let nw = prime.sign_window(&stmt(nh, 5000)).expect("window");
    let owed = aud(&nw, 0, &[]).expected_sats;
    let deferral = |hash: [u8; 32]| prime.sign_deferral(&Deferral { prime_id: PRIME_ID, height, block_hash: hex::encode(hash), identity: PROV.into(),
                                                                    sats: owed, reason: "unattested".into() }).expect("deferral");
    let dl = deferral(nh);
    let carried = aud(&nw, 0, std::slice::from_ref(&dl));
    let bare = aud(&nw, 0, &[]);
    let other_block = deferral(sha(b"another block"));
    let ok_other = aud(&nw, 0, std::slice::from_ref(&other_block)).ok;
    let ob = other_block.line_doc();
    v["auditNtaCarry"] = json!({
        "window": nw.line_doc(), "coinbaseValueSats": value, "expectedSats": owed, "deferral": dl.line_doc(),
        "carried": {"paidSats": 0, "deferred": ["deferral"], "ok": carried.ok},
        "noDeferral": {"paidSats": 0, "deferred": [], "ok": bare.ok, "proof": bare.proof},
        "deferralForAnotherBlock": {"message": ob["message"], "sig": ob["sig"], "paidSats": 0, "ok": ok_other},
        "rule": RULE_CARRY});

    // 6c. XBT-NTA v1: the provider identity from a BIP86 wallet, and one tip's attestation
    let dsec = bip32_derive(&bip39_seed(BIP86_MNEMONIC, ""), BIP86_PATH);
    let k = nta::bip86_output_secret(&dsec).expect("tweak");
    let kx = nta::xonly_pub(&k).expect("key");
    let prev = hex::encode(sha(b"xbt-work/v1 vector nta tip"));
    let (th, tbits) = (975_001i32, 0x1901_41C5u32);
    let script = nta::p2tr_script(&kx).expect("script");
    let body = nta::attest(&k, th, tbits, &prev).expect("attest");
    let digest = nta::attestation_digest(&script, th, tbits, &prev).expect("digest");
    let sig: [u8; 64] = hex::decode(body["sig"].as_str().expect("sig")).expect("hex").try_into().expect("64");
    let wrong_prev = hex::encode(sha(b"xbt-work/v1 vector nta other tip"));
    let mut other_body = body.clone();
    other_body["prev"] = wrong_prev.clone().into();
    let bip341: [u8; 32] = hex::decode(BIP341_KEYPATH.0).expect("hex").try_into().expect("32");
    v["nta"] = json!({
        "bip86": {"mnemonic": BIP86_MNEMONIC, "path": BIP86_PATH, "internalSecret": hex::encode(dsec),
                  "internalKey": hex::encode(nta::xonly_pub(&dsec).expect("key")),
                  "tweak": hex::encode(nta::tagged_hash(b"TapTweak", &nta::xonly_pub(&dsec).expect("key"))),
                  "outputSecret": hex::encode(k), "outputKey": hex::encode(kx),
                  "address": nta::p2tr_address(&kx, "bc").expect("addr"), "regtestAddress": nta::p2tr_address(&kx, "bcrt").expect("addr"),
                  "rule": RULE_BIP86},
        "bip341KeyPath": {"internalSecret": BIP341_KEYPATH.0, "outputSecret": hex::encode(nta::bip86_output_secret(&bip341).expect("tweak"))},
        "attestation": {"identity": nta::p2tr_address(&kx, "bc").expect("addr"), "payee_script": hex::encode(&script), "payee_key": hex::encode(kx),
                        "height": th, "nBits": format!("{tbits:08x}"), "hashPrevBlock": prev,
                        "preimage": hex::encode(nta::attestation_preimage(&script, th, tbits, &prev).expect("preimage")),
                        "digest": hex::encode(digest), "sig": body["sig"], "attestationOutput": hex::encode(nta::attestation_output(&sig)),
                        "attestBody": body,
                        "signedWithInternalSecret": hex::encode(nta::schnorr_sign(&digest, &dsec, &[0u8; 32]).expect("sign")),
                        "otherTip": {"hashPrevBlock": wrong_prev, "verifies": nta::check_attest_body(&other_body)}},
        "p2wpkhIdentity": {"identity": PROV, "scriptPubKey": "0014751e76e8199196d454941c45d1b3a323f1433bd6", "payee": false, "rule": RULE_P2WPKH}});

    // 7. blinded relay (§11.1): lookup, key, and a padded sealed blob from a fixed nonce
    let nonce: [u8; 12] = sha(b"xbt-work/v1 vector relay nonce")[..12].try_into().expect("12");
    let rdoc = dumps_compact(&json!({"message": v["receipts"][1]["message"], "sig": v["receipts"][1]["sig"]}));
    let blob = relay::seal(rdoc.as_bytes(), PROV, &inv_a, Some(nonce)).expect("seal");
    v["relay"] = json!({"identity": PROV, "invoice": inv_a, "lookup": relay::lookup(PROV, &inv_a), "key": hex::encode(relay::key(PROV, &inv_a)),
                        "nonce": hex::encode(nonce), "document": rdoc, "blob": hex::encode(blob), "pad": relay::PAD});
    v
}

/// Python's `json.dump(v, f, indent=1)` followed by a newline.
pub fn to_file(v: &Value) -> String {
    fn go(out: &mut String, v: &Value, level: usize) {
        let pad = |n: usize| " ".repeat(n);
        match v {
            Value::Array(a) if !a.is_empty() => {
                out.push('[');
                for (i, x) in a.iter().enumerate() {
                    out.push_str(if i == 0 { "\n" } else { ",\n" });
                    out.push_str(&pad(level + 1));
                    go(out, x, level + 1);
                }
                out.push('\n');
                out.push_str(&pad(level));
                out.push(']');
            }
            Value::Object(m) if !m.is_empty() && as_big_int(v).is_none() => {
                out.push('{');
                for (i, (k, x)) in m.iter().enumerate() {
                    out.push_str(if i == 0 { "\n" } else { ",\n" });
                    out.push_str(&pad(level + 1));
                    out.push_str(&dumps(&Value::String(k.clone())));
                    out.push_str(": ");
                    go(out, x, level + 1);
                }
                out.push('\n');
                out.push_str(&pad(level));
                out.push('}');
            }
            _ => out.push_str(&dumps(v)),
        }
    }
    let mut s = String::new();
    go(&mut s, v, 0);
    s.push('\n');
    s
}

/// One line of the conformance table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub section: String,
    pub checks: usize,
    pub failures: Vec<String>,
}

/// Check a published vector file: every section recomputed byte for byte, then the checks that do
/// not trust any generator. Returns one row per section.
pub fn check(stored: &Value) -> Vec<Row> {
    let fresh = generate();
    let mut rows: Vec<Row> = vec![];
    let mut row = |section: &str, checks: usize, failures: Vec<String>| rows.push(Row { section: section.into(), checks, failures });
    // byte-identical, section by section (key order included)
    let mut same = vec![];
    for (k, f) in fresh.as_object().expect("object") {
        if stored.get(k).map(to_file) != Some(to_file(f)) {
            same.push(format!("section {k:?} differs from the Rust recomputation"));
        }
    }
    if stored.as_object().map(|o| o.len()) != fresh.as_object().map(|o| o.len()) {
        same.push("sections differ in number".into());
    }
    row("sections recomputed byte for byte", fresh.as_object().map(|o| o.len()).unwrap_or(0), same);

    let Ok(pk) = pubkey_from_hex(stored["prime"]["pubkey"].as_str().unwrap_or("")) else {
        row("prime key", 1, vec!["prime.pubkey is not a key".into()]);
        return rows;
    };
    let (mut n, mut fails) = (0, vec![]);
    let mut ck = |ok: bool, what: String| {
        n += 1;
        if !ok {
            fails.push(what);
        }
    };
    // receipts: documents parse (strictly) back to the lines, signatures verify
    for r in stored["receipts"].as_array().into_iter().flatten() {
        let w = WorkReceipt::from_doc(&r["doc"]);
        ck(w.as_ref().ok().and_then(|w| w.message().ok()).as_deref() == r["message"].as_str(), format!("line {}", r["message"]));
        let sig: Option<[u8; 64]> = r["sig"].as_str().and_then(|s| hex::decode(s).ok()).and_then(|b| b.try_into().ok());
        ck(w.is_ok_and(|w| sig.is_some_and(|sig| Signed { receipt: w, sig }.verify(&pk))), format!("signature {}", r["message"]));
    }
    for c in stored["receiptVerification"].as_array().into_iter().flatten() {
        let got = pubkey_from_hex(c["pubkey"].as_str().unwrap_or("")).ok().zip(c["sig"].as_str().and_then(|s| hex::decode(s).ok())
            .and_then(|b| <[u8; 64]>::try_from(b).ok())).is_some_and(|(k, s)| verify(&k, c["message"].as_str().unwrap_or(""), &s));
        ck(Some(got) == c["valid"].as_bool(), format!("verification: {}", c["why"]));
    }
    row("receipts, signatures", n, std::mem::take(&mut fails));
    rows_push_grammar(stored, &pk, &mut rows);
    rows_push_rest(stored, &pk, &mut rows);
    rows
}

fn rows_push_grammar(stored: &Value, pk: &ed25519_dalek::VerifyingKey, rows: &mut Vec<Row>) {
    let (mut n, mut fails) = (0usize, vec![]);
    let mut ck = |ok: bool, what: String| {
        n += 1;
        if !ok {
            fails.push(what);
        }
    };
    for m in stored["malformedReceipts"].as_array().into_iter().flatten() {
        ck(WorkReceipt::from_doc(&m["doc"]).is_err(), format!("malformed receipt accepted: {}", m["why"]));
    }
    let fi = &stored["fieldInjection"];
    let line = fi["signedLine"].as_str().unwrap_or("");
    let sig: Option<[u8; 64]> = fi["sig"].as_str().and_then(|s| hex::decode(s).ok()).and_then(|b| b.try_into().ok());
    ck(sig.is_some_and(|s| verify(pk, line, &s)), "field injection: the oracle signature is real".into());
    ck(PrimeKey::from_seed(PRIME_ID, &prime_seed()).sign(&WorkReceipt::zero(PRIME_ID, PROV, fi["queriedInvoice"].as_str().unwrap_or(""))).is_err(),
       "a Prime signed an out-of-grammar invoice".into());
    ck(WorkReceipt::from_doc(&fi["presentedDoc"]).is_err(), "field-injection document accepted".into());
    let d = &fi["presentedDoc"];
    let s = |v: &Value| xbt402::json::py_str(Some(v));
    let naive = ["seq", "cum_work", "shares", "first_height", "last_height", "difficulty"].iter()
        .fold(format!("xbt-work-receipt/1|{}|{}|{}", s(&d["prime_id"]), s(&d["identity"]), s(&d["invoice"])), |a, k| format!("{a}|{}", s(&d["receipt"][*k])));
    ck(naive == line, "field-injection vector no longer demonstrates the attack".into());
    for u in stored["usernames"].as_array().into_iter().flatten() {
        let p = parse_username(u["username"].as_str().unwrap_or(""));
        ck(json!([p.identity, p.invoice, p.worker]) == json!([u["identity"], u["invoice"], u["worker"]]), format!("username parse: {}", u["username"]));
    }
    for i in stored["invoices"].as_array().into_iter().flatten() {
        let raw: Option<[u8; 16]> = i["random"].as_str().and_then(|h| hex::decode(h).ok()).and_then(|b| b.try_into().ok());
        ck(raw.map(|r| new_invoice(&r)).as_deref() == i["invoice"].as_str(), format!("invoice encoding {}", i["invoice"]));
    }
    rows.push(Row { section: "grammar: malformed, field injection, usernames, invoices".into(), checks: n, failures: fails });
}

fn rows_push_rest(stored: &Value, pk: &ed25519_dalek::VerifyingKey, rows: &mut Vec<Row>) {
    let (mut n, mut fails) = (0usize, vec![]);
    let mut ck = |ok: bool, what: String| {
        n += 1;
        if !ok {
            fails.push(what);
        }
    };
    // pricing: the exact rational bound, independent of the formula: u covers the price, u-1 not
    use ruint::aliases::U512;
    for p in stored["pricing"].as_array().into_iter().flatten() {
        let g = |k: &str| U512::from(p[k].as_u64().unwrap_or(0));
        let bits = u32::from_str_radix(p["bits"].as_str().unwrap_or(""), 16).unwrap_or(0);
        let ok = bits_to_target(bits).is_ok_and(|t| {
            let (u, need) = (g("workUnits"), g("priceSats") * diff1_target() * U512::from(100_000_000u64));
            let per = g("blockValueSats") * (U512::from(10_000u64) - g("feeBps")) * (U512::from(10_000u64) - g("haircutBps")) * t;
            u * per >= need && (u <= U512::from(1u64) || (u - U512::from(1u64)) * per < need)
        });
        ck(ok, format!("pricing: {} is not the least that covers {}", p["workUnits"], p["priceSats"]));
    }
    for a in stored["auth"].as_array().into_iter().flatten() {
        let req = hex::encode(Sha256::digest(format!("{}|{}|{}", a["method"].as_str().unwrap_or(""), a["target"].as_str().unwrap_or(""),
                                                     a["body"].as_str().unwrap_or("")).as_bytes()));
        ck(Some(req.as_str()) == a["req"].as_str(), format!("req digest n={}", a["n"]));
        let key = hex::decode(a["authKey"].as_str().unwrap_or("")).unwrap_or_default();
        let mut m = Hmac::<Sha256>::new_from_slice(&key).expect("key");
        m.update(format!("xbt-work/auth|{}|{}|{}|{}|{}", a["invoice"].as_str().unwrap_or(""), a["n"], a["seq"], a["cum_work"], req).as_bytes());
        ck(Some(hex::encode(m.finalize().into_bytes()).as_str()) == a["auth"].as_str(), format!("auth n={}", a["n"]));
    }
    // the credit sequence's fraud proof convicts on its own
    let fp = &stored["creditSequence"]["fraudProof"];
    let line = |d: &Value| -> Option<Signed> {
        Some(Signed { receipt: WorkReceipt::parse_line(d["message"].as_str()?).ok()?, sig: hex::decode(d["sig"].as_str()?).ok()?.try_into().ok()? })
    };
    ck(line(&fp["a"]).zip(line(&fp["b"])).is_some_and(|(a, b)| crate::book::Equivocation { a, b, why: String::new() }.check(pk)),
       "equivocation proof does not check".into());
    // coinbase audit fraud proofs, from their signed contents alone
    let a = &stored["audit"];
    let val = a["coinbaseValueSats"].as_u64().unwrap_or(0);
    let fraud = |proof: &Value, v: u64, paid: u64| check_fraud_proof(proof, pk, &proof_block(proof, v, paid), &AuditBounds::STATEMENT_ONLY);
    ck(fraud(&a["fraud"]["proof"], val, a["fraud"]["paidSats"].as_u64().unwrap_or(0)), "fraud proof does not check".into());
    ck(!fraud(&a["fraud"]["proof"], val, a["pass"]["paidSats"].as_u64().unwrap_or(0)), "fraud proof checks against an honest coinbase".into());
    let c = &stored["auditNtaCarry"];
    let dl = &c["deferral"];
    ck(dl["sig"].as_str().and_then(|s| hex::decode(s).ok()).and_then(|b| <[u8; 64]>::try_from(b).ok())
        .is_some_and(|s| verify(pk, dl["message"].as_str().unwrap_or(""), &s)), "NTA deferral line signature".into());
    let d = Deferral::parse(dl["message"].as_str().unwrap_or(""));
    ck(d.is_ok_and(|d| (d.identity.as_str(), Some(d.sats), d.reason.as_str()) == (PROV, c["expectedSats"].as_u64(), "unattested")),
       "NTA deferral line does not defer the expected share".into());
    ck(c["carried"]["ok"] == json!(true) && c["noDeferral"]["ok"] == json!(false) && c["deferralForAnotherBlock"]["ok"] == json!(false),
       "NTA carry verdicts".into());
    let cv = c["coinbaseValueSats"].as_u64().unwrap_or(0);
    ck(fraud(&c["noDeferral"]["proof"], cv, 0), "NTA: the no-deferral fraud proof does not check".into());
    let mut withline = c["noDeferral"]["proof"].clone();
    withline["deferred"] = json!([dl]);
    ck(!fraud(&withline, cv, 0), "NTA: a fraud proof survives the Prime's deferral line".into());
    // NTA: BIP86 against the published values, the attestation by BIP340
    let t = &stored["nta"];
    let b = &t["bip86"];
    ck((b["internalKey"].as_str(), b["outputKey"].as_str(), b["address"].as_str())
           == (Some(BIP86_PUBLISHED.0), Some(BIP86_PUBLISHED.1), Some(BIP86_PUBLISHED.2)), "BIP86 wallet vector differs from the published one".into());
    let h32 = |v: &Value| -> Option<[u8; 32]> { hex::decode(v.as_str()?).ok()?.try_into().ok() };
    ck(h32(&b["outputSecret"]).and_then(|s| nta::xonly_pub(&s).ok()).map(hex::encode).as_deref() == b["outputKey"].as_str()
           && h32(&b["internalKey"]).and_then(|k| nta::bip86_output_key(&k).ok()).map(hex::encode).as_deref() == b["outputKey"].as_str(),
       "BIP86 output secret does not give the output key".into());
    ck(t["bip341KeyPath"]["outputSecret"].as_str() == Some(BIP341_KEYPATH.1), "BIP341 keyPathSpending tweak".into());
    let at = &t["attestation"];
    let script = hex::decode(at["payee_script"].as_str().unwrap_or("")).unwrap_or_default();
    let nb = u32::from_str_radix(at["nBits"].as_str().unwrap_or(""), 16).unwrap_or(0);
    let mut pre = vec![script.len() as u8];
    pre.extend_from_slice(&script);
    pre.extend_from_slice(&(at["height"].as_i64().unwrap_or(0) as i32).to_le_bytes());
    pre.extend_from_slice(&nb.to_le_bytes());
    pre.extend(hex::decode(at["hashPrevBlock"].as_str().unwrap_or("")).unwrap_or_default().into_iter().rev());
    let tag = Sha256::digest(b"XBT-NTA/attestation");
    let dig = Sha256::digest([&tag[..], &tag[..], &pre[..]].concat());
    ck(Some(hex::encode(&pre).as_str()) == at["preimage"].as_str() && pre.len() == 75 && Some(hex::encode(dig).as_str()) == at["digest"].as_str(),
       "NTA preimage/digest".into());
    let digest = h32(&at["digest"]).unwrap_or_default();
    let key = hex::decode(at["payee_key"].as_str().unwrap_or("")).unwrap_or_default();
    let hx = |v: &Value| hex::decode(v.as_str().unwrap_or("")).unwrap_or_default();
    ck(nta::schnorr_verify(&digest, &key, &hx(&at["sig"])), "NTA attestation does not verify under K".into());
    ck(!nta::schnorr_verify(&digest, &key, &hx(&at["signedWithInternalSecret"])), "a signature by the BIP86 internal secret verifies under K".into());
    let ab = &at["attestBody"];
    let mut other = ab.clone();
    other["prev"] = at["otherTip"]["hashPrevBlock"].clone();
    ck(nta::check_attest_body(ab) && at["otherTip"]["verifies"] == json!(false) && !nta::check_attest_body(&other),
       "attest body: verifies for its tip and only its tip".into());
    ck(json!([ab["key"], ab["height"], ab["nbits"], ab["prev"], ab["sig"]]) == json!([at["payee_key"], at["height"], at["nBits"], at["hashPrevBlock"], at["sig"]]),
       "attest body fields".into());
    ck(at["attestationOutput"].as_str() == Some(format!("6a444e544102{}", at["sig"].as_str().unwrap_or("")).as_str()) && at["identity"] == b["address"],
       "attestation output / identity".into());
    ck(!nta::is_payee_script(&hx(&t["p2wpkhIdentity"]["scriptPubKey"])) && t["p2wpkhIdentity"]["payee"] == json!(false),
       "P2WPKH identity must not be an NTA payee".into());
    // relay
    let rel = &stored["relay"];
    let (ri, rv) = (rel["identity"].as_str().unwrap_or(""), rel["invoice"].as_str().unwrap_or(""));
    ck(Some(relay::lookup(ri, rv).as_str()) == rel["lookup"].as_str(), "relay lookup".into());
    ck(!rel["lookup"].as_str().unwrap_or("").contains(ri) && rel["lookup"].as_str() != Some(rv), "relay lookup leaks identity".into());
    let nonce: Option<[u8; 12]> = hex::decode(rel["nonce"].as_str().unwrap_or("")).ok().and_then(|b| b.try_into().ok());
    ck(relay::seal(rel["document"].as_str().unwrap_or("").as_bytes(), ri, rv, nonce).ok().map(hex::encode).as_deref() == rel["blob"].as_str(),
       "relay seal".into());
    let blob = hx(&rel["blob"]);
    ck(relay::open(&blob, ri, rv).ok().as_deref().map(|b| b.trim_ascii_end()) == Some(rel["document"].as_str().unwrap_or("").as_bytes()),
       "relay open".into());
    let mut bad = blob.clone();
    if bad.len() > 20 {
        bad[20] ^= 1;
    }
    ck(relay::open(&bad, ri, rv).is_err(), "relay accepted a tampered blob".into());
    rows.push(Row { section: "pricing, auth, audit, fraud proofs, NTA, relay".into(), checks: n, failures: fails });
}
