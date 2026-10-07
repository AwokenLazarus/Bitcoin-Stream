//! Format compatibility with B2 (Python) custody files, `vectors/b2_custody.json` (made by B2's own
//! code): the Rust signer opens B2's sealed blobs (key file and scrypt passphrase), hot.json with a
//! retired key, the sealed UTXO set, the sealed channel keys and channels.json, and checks B2's
//! signature log against B2's witness store, then extends both; and (AGP-055) B2's routed wallet: its
//! spend log, ledger and payments log. The reverse direction (B2 opening Rust-written files) runs in
//! scripts/signer_interop.sh (scripts/interop/signer_runbook.py) and, for the routed wallet, in b2's
//! tests/test_agp055_rust_wallet.py over `vectors/rust_routed_wallet.json`.
mod common;

use std::sync::Arc;

use common::*;
use serde_json::{json, Value};
use xbt_signer::anchor::AnchorStore;
use xbt_signer::channels::ChannelBook;
use xbt_signer::hot::HotWallet;
use xbt_signer::keystore::KeyStore;
use xbt_signer::sigaudit::{check_chain, SigAudit};

fn vectors() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/b2_custody.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn keyfile(v: &Value) -> KeyStore {
    KeyStore::with_key(hex::decode(v["keyfile_hex"].as_str().unwrap()).unwrap().try_into().unwrap())
}

#[test]
fn opens_b2_sealed_blobs() {
    let v = vectors();
    assert_eq!(keyfile(&v).open(&v["blobs"]["keyfile"], "b2/test").unwrap(), b"hello rust");
    let kp = KeyStore::with_passphrase(v["passphrase"].as_str().unwrap().as_bytes());
    assert_eq!(kp.open(&v["blobs"]["passphrase"], "b2/test").unwrap(), b"hello rust");
    assert!(KeyStore::with_passphrase(b"wrong").open(&v["blobs"]["passphrase"], "b2/test").is_err());
    assert!(keyfile(&v).open(&v["blobs"]["keyfile"], "b2/hot-key").is_err(), "the AAD binds the blob to its file");
}

#[test]
fn opens_b2_hot_wallet_and_channel_book() {
    let v = vectors();
    let d = tempfile::tempdir().unwrap();
    let w = |name: &str, x: &Value| std::fs::write(d.path().join(name), x.to_string()).unwrap();
    w("hot.json", &v["hot"]["hot.json"]);
    w("hot_utxos.json", &v["hot"]["hot_utxos.json"]);
    w("channels.json", &v["channels"]["channels.json"]);
    w("channel_keys.json", &v["channels"]["channel_keys.json"]);
    let ks = Arc::new(keyfile(&v));
    let chain = FakeChain::new("regtest", 6_720);
    let hot = HotWallet::open(&d.path().join("hot.json"), chain.clone(), "bcrt", Some(ks.clone()), None, 0).unwrap();
    assert_eq!(hot.address(), v["hot"]["current_address"].as_str().unwrap());
    assert_eq!(hot.balance_sats(), v["hot"]["hot_sats"].as_i64().unwrap());
    let st = hot.status();
    assert_eq!((st["hot_retired_keys"].as_i64(), st["hot_retired_sats"].as_i64()), (Some(1), Some(700)));
    assert!(hot.key_spks().len() == 2);
    // a wrong wrapping key cannot open it
    assert!(HotWallet::open(&d.path().join("hot.json"), chain.clone(), "bcrt", Some(Arc::new(KeyStore::with_key([1; 32]))), None, 0).is_err());

    let book = ChannelBook::open(&d.path().join("channels.json"), &d.path().join("channel_keys.json"), Some(ks.clone()), None).unwrap();
    let dest = "http://127.0.0.1:33210";
    let rec = book.get(dest).unwrap();
    assert_eq!(rec.chan, v["channels"]["chan"].as_str().unwrap());
    assert_eq!((rec.state.as_str(), rec.used_sats, rec.spent_sats, rec.cap_sats), ("open", 546, 500, 9400));
    assert_eq!(rec.params().unwrap().channel_id(), rec.chan, "params rebuilt byte for byte");
    // B2's payer key signs here: the next state verifies under the recorded payer pubkey
    let sig = book.sign_state(dest, 1_000).unwrap();
    let p = rec.params().unwrap();
    let z = p.sighash(&p.state_tx(1_000).unwrap()).unwrap();
    let pk = hex::decode(v["channels"]["payer_pub"].as_str().unwrap()).unwrap();
    assert!(xbt_primitives::ecdsa::verify(&pk, &z, &sig[..sig.len() - 1]));
    assert_eq!(book.sign_state(dest, 900).unwrap_err().code, "stale_amount");
    // the Rust book re-seals the keys file in the same format
    let keys: Value = serde_json::from_str(&std::fs::read_to_string(d.path().join("channel_keys.json")).unwrap()).unwrap();
    assert_eq!(keys["sealed"]["aad"], "b2/channel-keys");
    let inner: Value = serde_json::from_slice(&ks.open(&keys["sealed"], "b2/channel-keys").unwrap()).unwrap();
    assert!(inner["secrets"][rec.chan.as_str()].is_string());
    let chans: Value = serde_json::from_str(&std::fs::read_to_string(d.path().join("channels.json")).unwrap()).unwrap();
    let fields: Vec<&String> = chans["channels"][dest].as_object().unwrap().keys().collect();
    let b2_fields: Vec<&String> = v["channels"]["channels.json"]["channels"][dest].as_object().unwrap().keys().collect();
    assert_eq!(fields, b2_fields, "the same ChannelRecord fields as B2 (B2 loads it with ChannelRecord(**rec))");
}

#[test]
fn checks_and_extends_b2_signature_log_and_witness_store() {
    let v = vectors();
    let d = tempfile::tempdir().unwrap();
    let log = d.path().join("signatures.jsonl");
    std::fs::write(&log, v["log"]["signatures.jsonl"].as_str().unwrap()).unwrap();
    std::fs::create_dir_all(d.path().join("anchor")).unwrap();
    std::fs::write(d.path().join("anchor/anchors.jsonl"), v["log"]["anchors.jsonl"].as_str().unwrap()).unwrap();
    let store = AnchorStore::open(&d.path().join("anchor")).unwrap();
    let latest = store.latest();
    assert_eq!(latest["n"], 2);
    let c = check_chain(&log, Some(&latest));
    assert_eq!((c["ok"].as_bool(), c["lines"].as_i64(), c["unanchored_lines"].as_i64()), (Some(true), Some(3), Some(1)), "{c}");
    // the Rust signer appends to B2's log and anchors the new lines with the same store
    let a = SigAudit::open(&log).unwrap();
    a.record("refund", b"sig", "c:0", "", json!({"rule": "watcher:auto_refund"})).unwrap();
    let lines = a.raw_lines();
    let new: Vec<String> = lines[2..].iter().map(|l| String::from_utf8(l.clone()).unwrap()).collect();
    let head = xbt_signer::sigaudit::sha256_hex(lines.last().unwrap());
    let r = store.submit(4, &head, &new, "rust");
    assert_eq!((r["ok"].as_bool(), r["n"].as_i64()), (Some(true), Some(4)), "{r}");
    assert_eq!(check_chain(&log, Some(&store.latest()))["ok"], true);
    // a line of B2's log edited afterwards fails both checks
    let text = std::fs::read_to_string(&log).unwrap().replacen("channel_state", "channel_statf", 1);
    std::fs::write(&log, text).unwrap();
    assert_eq!(check_chain(&log, Some(&store.latest()))["ok"], false);
}

// --- AGP-055: the routed wallet (spend log, ledger + payments log, records), both directions ------

use xbt_signer::policy::{AuditLog, LedgerEntry, PolicyConfig, PolicyEngine, PolicyStore};
use xbt_signer::routing::{RoutePolicy, RouteSigner, Xbt402Adaptor};

/// A wallet directory's route signer, opened from its files (a start).
fn route_signer(dir: &std::path::Path, ks: &Arc<KeyStore>, hub: &str, routing: &Value) -> (Arc<ChannelBook>, Arc<PolicyEngine>, RouteSigner) {
    let book = Arc::new(ChannelBook::open(&dir.join("channels.json"), &dir.join("channel_keys.json"), Some(ks.clone()), None).unwrap());
    let cfg = PolicyConfig::from_value(&json!({"allowlist": [hub], "velocity_max": 100})).unwrap();
    let engine = Arc::new(PolicyEngine::new(cfg, PolicyStore::open(&dir.join("ledger.json")).unwrap(),
                                            AuditLog::open(&dir.join("audit.jsonl")).unwrap(), None));
    let rs = RouteSigner::new(book.clone(), RoutePolicy::from_value(routing.as_object().unwrap()), Some(&dir.join("routing.json")),
                              Some(engine.clone()), Some(Arc::new(Xbt402Adaptor))).unwrap();
    (book, engine, rs)
}

fn lock_txids(e: &PolicyEngine) -> Vec<(String, i64)> {
    e.store.payments().unwrap().into_iter().filter(|p| p.txid.starts_with("lock:")).map(|p| (p.txid, p.amount_sats)).collect()
}

/// B2 wrote this directory: L1 resolved and booked, L2 resolved in the record but not booked (B2
/// died between the two), L3 pending. The Rust signer opens every file, books L2 once (and not
/// again at the next start), resolves L3, and only ever appends to B2's logs.
#[test]
fn opens_a_b2_routed_wallet_books_its_unbooked_lock_once_and_resolves_its_pending_one() {
    let v = vectors();
    let r = &v["routed"];
    let d = tempfile::tempdir().unwrap();
    for f in ["channels.json", "channel_keys.json", "ledger.json"] {
        std::fs::write(d.path().join(f), r[f].to_string()).unwrap();
    }
    for f in ["routing.json", "ledger.payments.jsonl"] {
        std::fs::write(d.path().join(f), r[f].as_str().unwrap()).unwrap();
    }
    let (ks, hub, chan) = (Arc::new(keyfile(&v)), r["hub"].as_str().unwrap(), r["chan"].as_str().unwrap());
    let key = |k: &str| (r[k]["key"].as_str().unwrap().to_string(), r[k]["amount"].as_i64().unwrap());

    let (book, engine, rs) = route_signer(d.path(), &ks, hub, &r["routing_policy"]);
    assert_eq!(rs.recovered_bookings, 1, "L2: resolved on disk, booked by this start");
    assert_eq!(rs.spend.since(0.0), 1_500);
    assert_eq!(lock_txids(&engine), [key("booked"), key("unbooked")]);
    let rec = book.get(hub).unwrap();
    assert_eq!((rec.used_sats, rec.pending_lock["cum"].as_i64(), rec.resolved.len()), (1_500, Some(1_800), 2));
    assert_eq!(rec.pending_lock["pre"], r["pending"]["adaptor"]);
    drop((book, engine, rs));

    let (book, engine, rs) = route_signer(d.path(), &ks, hub, &r["routing_policy"]);
    assert_eq!((rs.recovered_bookings, rs.spend.since(0.0), lock_txids(&engine).len()), (0, 1_500, 2), "a second start books nothing more");
    assert_eq!(rs.resolve_lock(chan, r["pending"]["secret"].as_str().unwrap()).unwrap(), r["pending"]["t"].as_str().unwrap());
    assert_eq!((rs.spend.since(0.0), book.get(hub).unwrap().used_sats), (1_800, 1_800));
    assert_eq!(lock_txids(&engine).last().unwrap(), &(format!("lock:{chan}:1800"), 300));
    // append-only: what B2 wrote is still the head of both logs, and Rust's lines have B2's fields
    for f in ["routing.json", "ledger.payments.jsonl"] {
        let (now, b2) = (std::fs::read_to_string(d.path().join(f)).unwrap(), r[f].as_str().unwrap());
        assert!(now.starts_with(b2) && now.len() > b2.len(), "{f}");
        let fields = |line: &str| serde_json::from_str::<Value>(line).unwrap().as_object().unwrap().keys().cloned().collect::<Vec<_>>();
        assert_eq!(fields(now.lines().last().unwrap()), fields(b2.lines().nth(1).unwrap()), "{f}: the same row fields as B2");
    }
    let (rust, b2) = (std::fs::read_to_string(d.path().join("channels.json")).unwrap(), &r["channels.json"]["channels"][hub]);
    let rust: Value = serde_json::from_str(&rust).unwrap();
    assert_eq!(rust["channels"][hub].as_object().unwrap().keys().collect::<Vec<_>>(), b2.as_object().unwrap().keys().collect::<Vec<_>>());
    assert_eq!(rust["channels"][hub]["resolved"][0], b2["resolved"][0], "B2's booking record is kept as written");
}

/// The reverse: the Rust signer writes the same kind of directory (plus the ledger lines only it
/// writes: a Lightning booking amended, and one dropped), and `vectors/rust_routed_wallet.json`
/// holds it for B2 (b2 `tests/test_agp055_rust_wallet.py` opens a copy). `XBT_GEN_VECTORS=1`
/// rewrites the vector; without it the same steps run and are checked here.
#[test]
fn writes_a_routed_wallet_for_b2() {
    let v = vectors();
    let d = tempfile::tempdir().unwrap();
    let (ks, hub) = (Arc::new(keyfile(&v)), "http://127.0.0.1:33212");
    let routing = json!({"hubs": {hub: {"max_fee_ppm": 5000, "max_fee_base_msat": 2000}}, "max_lock_sats": 20_000, "daily_budget_sats": 50_000});
    // B2's own channel record and payer key, moved to this hub: the Rust book signs for it
    let b2 = &v["routed"];
    let mut rec = b2["channels.json"]["channels"][b2["hub"].as_str().unwrap()].clone();
    for (k, val) in [("dest", json!(hub)), ("origin", json!(hub)), ("used_sats", json!(0)), ("spent_sats", json!(0)), ("acked_sats", json!(0)),
                     ("pending_lock", json!({})), ("resolved", json!([])), ("last_sig", json!(""))] {
        rec[k] = val;
    }
    std::fs::write(d.path().join("channels.json"), json!({"channels": {hub: rec}}).to_string()).unwrap();
    std::fs::write(d.path().join("channel_keys.json"), b2["channel_keys.json"].to_string()).unwrap();
    let chan = b2["chan"].as_str().unwrap();
    let t = |n: u8| secret(&format!("agp055-t{n}"));
    let pt = |s: &xbt_primitives::secp256k1::SecretKey| hex::encode(xbt402::adaptor::enc(&xbt402::adaptor::point_of(s)));
    let y = |s: &xbt_primitives::secp256k1::SecretKey, out: &Value| {
        let r = xbt_primitives::secp256k1::SecretKey::from_slice(&hex::decode(out["tweak"].as_str().unwrap()).unwrap()).unwrap();
        hex::encode(s.add_tweak(&xbt_primitives::secp256k1::Scalar::from(r)).unwrap().secret_bytes())
    };
    let route = |amount: i64, id: &str| json!({"hub": hub, "amount": amount, "fee": 1, "lockId": id});

    let (book, engine, rs) = route_signer(d.path(), &ks, hub, &routing);
    let o1 = rs.sign_state_adaptor(chan, 1_000, &pt(&t(1)), route(999, "L1")).unwrap();
    rs.resolve_lock(chan, &y(&t(1), &o1)).unwrap();
    let now = xbt_signer::pyjson::now_f64();
    for (txid, settle) in [("ln:aa", Some(7)), ("ln:bb", None)] {
        engine.store.commit(&LedgerEntry { dest: "ln:02ab".into(), amount_sats: 50, ts: now, txid: txid.into(), memo: "ln".into() }).unwrap();
        assert!(engine.store.amend(txid, settle).unwrap());
    }
    let o2 = rs.sign_state_adaptor(chan, 1_500, &pt(&t(2)), route(499, "L2")).unwrap();
    book.resolve_lock(hub, &y(&t(2), &o2)).unwrap(); // on disk, and the process dies before its rows
    let o3 = rs.sign_state_adaptor(chan, 1_800, &pt(&t(3)), route(299, "L3")).unwrap();
    assert_eq!((rs.spend.since(0.0), lock_txids(&engine).len(), book.get(hub).unwrap().resolved.len()), (1_000, 1, 2));
    let read = |f: &str| std::fs::read_to_string(d.path().join(f)).unwrap();
    let doc = json!({
        "generator": "cargo test -p xbt-signer --test custody_compat writes_a_routed_wallet_for_b2 (XBT_GEN_VECTORS=1)",
        "created": now, "keyfile_hex": v["keyfile_hex"], "hub": hub, "chan": chan, "routing_policy": routing,
        "channels.json": serde_json::from_str::<Value>(&read("channels.json")).unwrap(),
        "channel_keys.json": serde_json::from_str::<Value>(&read("channel_keys.json")).unwrap(),
        "routing.json": read("routing.json"), "ledger.json": serde_json::from_str::<Value>(&read("ledger.json")).unwrap(),
        "ledger.payments.jsonl": read("ledger.payments.jsonl"),
        "booked": {"key": format!("lock:{chan}:1000"), "amount": 1000}, "unbooked": {"key": format!("lock:{chan}:1500"), "amount": 500},
        "ln": {"txid": "ln:aa", "amount": 7, "dropped": "ln:bb"},
        "pending": {"cum": 1800, "amount": 300, "adaptor": o3["adaptor"], "secret": y(&t(3), &o3), "t": hex::encode(t(3).secret_bytes())},
    });
    assert!(doc["ledger.payments.jsonl"].as_str().unwrap().contains("{\"amend\":\"ln:bb\",\"amount_sats\":null}\n"));
    if std::env::var("XBT_GEN_VECTORS").is_ok_and(|x| x == "1") {
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/rust_routed_wallet.json");
        std::fs::write(p, xbt_signer::pyjson::dumps_indent(&doc, 1, true) + "\n").unwrap();
    }
}
