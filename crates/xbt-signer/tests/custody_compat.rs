//! Format compatibility with B2 (Python) custody files, `vectors/b2_custody.json` (made by B2's own
//! code): the Rust signer opens B2's sealed blobs (key file and scrypt passphrase), hot.json with a
//! retired key, the sealed UTXO set, the sealed channel keys and channels.json, and checks B2's
//! signature log against B2's witness store, then extends both. The reverse direction (B2 opening
//! Rust-written files) runs in scripts/signer_interop.sh (scripts/interop/py_open_rust_files.py).
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
