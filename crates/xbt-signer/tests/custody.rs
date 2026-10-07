//! Custody (mirrors B2 tests/test_hot_custody.py and test_hot_persist.py): sealed keys and coins,
//! the wrapping key's rules, rotation, the balance cap, restart and reconcile.
mod common;

use common::*;
use serde_json::{json, Value};

fn read(p: &std::path::Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn hot_key_channel_keys_and_coins_are_sealed_at_rest() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    let r = rig.open();
    let run = rig.root.join(".run");
    let hot = read(&run.join("hot.json"));
    assert_eq!(hot["encrypted"], true);
    assert!(hot["current"]["sealed"]["ct"].is_string() && hot["current"].get("secret").is_none());
    let keys = read(&run.join("channel_keys.json"));
    assert!(keys.get("sealed").is_some() && keys.get("secrets").is_none());
    let utx = read(&run.join("hot_utxos.json"));
    assert!(utx.get("sealed").is_some() && utx.get("utxos").is_none());
    for f in ["hot.json", "channel_keys.json", "hot_utxos.json", "channels.json"] {
        assert_eq!(xbt_signer::fsx::mode_of(&run.join(f)), 0o600, "{f}");
        let text = std::fs::read_to_string(run.join(f)).unwrap();
        assert!(!text.contains("\"secret\""), "{f} names no plaintext secret");
    }
    // nothing the signer returns carries key material
    for m in ["balance", "channels", "hot_address", "signatures", "routing_status", "anchor_status"] {
        assert!(xbt_signer::sanitize::assert_no_key_material(&rig.call(m, json!({}))).is_ok(), "{m}");
    }
    assert!(xbt_signer::sanitize::assert_no_key_material(&r).is_ok());
}

#[test]
fn wrong_wrapping_key_tampered_file_and_missing_key_refused() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    // another key file
    std::env::set_var("B2_HOT_KEYFILE", rig.dir.path().join("other.key"));
    assert!(rig.restart().unwrap_err().msg.contains("wrong wrapping key or tampered"));
    // no key at all
    std::env::remove_var("B2_HOT_KEYFILE");
    assert!(rig.restart().unwrap_err().msg.contains("must be encrypted at rest"));
    // the right key, a tampered hot.json
    std::env::set_var("B2_HOT_KEYFILE", rig.dir.path().join("keys/hot.key"));
    let p = rig.root.join(".run/hot.json");
    let mut h = read(&p);
    let ct = h["current"]["sealed"]["ct"].as_str().unwrap().to_string();
    h["current"]["sealed"]["ct"] = format!("{}{}", if ct.starts_with('0') { "1" } else { "0" }, &ct[1..]).into();
    std::fs::write(&p, h.to_string()).unwrap();
    assert!(rig.restart().is_err());
}

#[test]
fn keyfile_inside_the_run_dir_is_refused_and_a_passphrase_is_consumed() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({}), false);
    std::env::set_var("B2_HOT_KEYFILE", rig.root.join(".run/hot.key"));
    assert!(rig.restart().unwrap_err().msg.contains("must not live inside the signer run dir"));
    // a passphrase opens nothing sealed with a key file, and it is removed from the environment
    std::env::remove_var("B2_HOT_KEYFILE");
    std::env::set_var("B2_HOT_PASSPHRASE", "pw");
    assert!(rig.restart().unwrap_err().msg.contains("sealed with keyfile"));
    assert!(std::env::var("B2_HOT_PASSPHRASE").is_err(), "the passphrase is consumed");
    // a new wallet under a passphrase: scrypt blobs
    let d = tempfile::tempdir().unwrap();
    std::env::set_var("B2_HOT_PASSPHRASE", "pw");
    let root = root_with(d.path(), &runbook_policy(json!({})));
    let s = signer(&root, &rig.chain, &rig.web, None).unwrap();
    assert_eq!(read(&root.join(".run/hot.json"))["current"]["sealed"]["kdf"], "scrypt");
    drop(s);
    std::env::set_var("B2_HOT_PASSPHRASE", "pw");
    assert!(signer(&root, &rig.chain, &rig.web, None).is_ok(), "the same passphrase reopens it");
}

#[test]
fn plaintext_files_from_an_older_run_are_resealed() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let d = tempfile::tempdir().unwrap();
    env_for(d.path());
    std::env::remove_var("B2_HOT_KEYFILE");
    std::env::set_var("B2_HOT_ALLOW_PLAINTEXT", "1");
    let chain = FakeChain::new("regtest", 6_720);
    let web = std::sync::Arc::new(Web::default());
    let root = root_with(d.path(), &runbook_policy(json!({})));
    let s = signer(&root, &chain, &web, None).unwrap();
    let addr = call(&s, "hot_address", json!({}))["hot_address"].clone();
    assert!(read(&root.join(".run/hot.json"))["current"]["secret"].is_string(), "plaintext only when explicitly allowed");
    drop(s);
    std::env::remove_var("B2_HOT_ALLOW_PLAINTEXT");
    std::env::set_var("B2_HOT_KEYFILE", d.path().join("keys/hot.key"));
    let s = signer(&root, &chain, &web, None).unwrap();
    assert_eq!(call(&s, "hot_address", json!({}))["hot_address"], addr, "the same key");
    let h = read(&root.join(".run/hot.json"));
    assert!(h["current"].get("sealed").is_some() && h["current"].get("secret").is_none());
}

#[test]
fn rotation_sweeps_old_coins_keeps_the_old_key_sealed_and_later_coins_are_swept() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), true);
    let old_spk = rig.hot_spk();
    rig.fund_hot(1, 5_000);
    rig.fund_hot(2, 3_000);
    let r = rig.call("rotate_hot_key", json!({}));
    let sweep = rig.chain.tx(r["sweep"]["txid"].as_str().unwrap());
    assert_eq!(sweep.inputs.len(), 2);
    assert_eq!(sweep.outputs[0].value, 8_000 - 200 - 2 * 100);
    assert_ne!(rig.hot_spk(), old_spk);
    assert_eq!(rig.hot_sats(), 7_600);
    let h = read(&rig.root.join(".run/hot.json"));
    assert_eq!(h["retired"].as_array().unwrap().len(), 1);
    assert!(h["retired"][0]["sealed"].is_object() && h["retired"][0]["retired_at"].is_f64());
    // a coin that later reaches the retired address (a close's change) is swept by the watcher
    rig.chain.credit(&"cc".repeat(32), 0, 2_000, &old_spk, true);
    rig.call("notice_hot_txid", json!({"txid": "cc".repeat(32)}));
    assert_eq!(rig.call("hot_address", json!({}))["hot_retired_sats"], 2_000);
    let acts = rig.call("watch_tick", json!({}))["actions"].clone();
    assert!(acts.to_string().contains("retired_sweep"), "{acts}");
    assert_eq!(rig.call("hot_address", json!({}))["hot_retired_sats"], 0);
    let kinds: Vec<String> = rig.sigs().iter().map(|x| format!("{}/{}", x["kind"].as_str().unwrap(), x["rule"].as_str().unwrap())).collect();
    assert!(kinds.contains(&"rotation_sweep/operator:rotate_hot_key".to_string()), "{kinds:?}");
    assert!(kinds.contains(&"retired_sweep/watcher:retired_sweep".to_string()), "{kinds:?}");
}

#[test]
fn over_the_cap_no_new_channel_until_a_human_sweeps() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"hot_balance_cap_sats": 15_000}), false);
    rig.fund_hot(1, 20_000);
    let r = rig.pay();
    assert_eq!((r["verdict"].as_str(), r["rule"].as_str(), r["action"].as_str()), (Some("deny"), Some("hot_balance_cap"), Some("human_sweep")), "{r}");
    assert_eq!((r["hot_sats"].as_i64(), r["cap_sats"].as_i64()), (Some(20_000), Some(15_000)));
    assert!(rig.chain.mempool().is_empty(), "nothing was funded");
    let hot = rig.call("hot_address", json!({}))["hot_address"].as_str().unwrap().to_string();
    let exp = xbt_signer::pyjson::now_f64() as i64 + 600;
    let to = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let sig = sign_human(&xbt_signer::approval::sweep_message(&hot, to, 8_000, exp));
    let s = rig.call("sweep_hot", json!({"to": to, "amount_sats": 8_000, "expiry": exp, "signature": sig}));
    assert_eq!(s["ok"], true, "{s}");
    assert_eq!(rig.pay()["verdict"], "pending", "under the cap again: the channel is funded");
}

#[test]
fn every_signature_is_logged_with_channel_rule_and_chain() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    let r = rig.open();
    rig.pay();
    rig.call("close_channel", json!({"counterparty": PROVIDER}));
    let sigs = rig.sigs();
    let kinds: Vec<&str> = sigs.iter().map(|x| x["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds, vec!["funding", "channel_state", "channel_state", "close_auth"]);
    for x in &sigs {
        assert_eq!(x["sig_sha256"].as_str().unwrap().len(), 64);
        assert!(!x["rule"].as_str().unwrap().is_empty() && x["rule"] != "unattributed");
    }
    assert_eq!(sigs[1]["chan"], r["chan"]);
    assert_eq!(sigs[1]["cum"], 546);
    assert_eq!(rig.call("signatures", json!({}))["chain_ok"], true);
}

#[test]
fn restart_keeps_coins_reconcile_marks_stale_restores_and_finds_unknown_coins() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({}), false);
    let spk = rig.hot_spk();
    rig.fund_hot(1, 4_000);
    rig.fund_hot(2, 5_000);
    // coin 1 is spent behind our back; a coin the file never heard of arrives while we are down
    rig.chain.st.lock().unwrap().utxos.remove(&(hex::encode([1u8; 32]), 0));
    rig.chain.credit(&"dd".repeat(32), 0, 3_000, &spk, true);
    rig.restart().unwrap();
    let rec = rig.call("hot_reconcile", json!({"last": true}));
    assert_eq!((rec["kept"].as_i64(), rec["stale"].as_i64(), rec["found"].as_i64()), (Some(1), Some(1), Some(1)), "{rec}");
    assert_eq!(rig.hot_sats(), 8_000);
    assert_eq!(rig.call("hot_address", json!({}))["hot_stale_utxos"], 1);
    // the stale coin comes back if the node has it again
    rig.chain.st.lock().unwrap().utxos.insert((hex::encode([1u8; 32]), 0), (4_000, spk.clone()));
    let rec = rig.call("hot_reconcile", json!({"scan": false}));
    assert_eq!(rec["restored"], 1, "{rec}");
    assert_eq!(rig.hot_sats(), 12_000);
    // a coin whose value disagrees with the node is dropped (the node wins)
    rig.chain.st.lock().unwrap().utxos.insert((hex::encode([2u8; 32]), 0), (4_999, spk.clone()));
    assert_eq!(rig.call("hot_reconcile", json!({"scan": false}))["dropped"], 1);
    // an unreachable node leaves the set unverified, and the signer still starts
    rig.chain.st.lock().unwrap().down = true;
    assert!(rig.restart().is_err(), "without B2_CHAIN the chain cannot be learned");
    std::env::set_var("B2_CHAIN", "regtest");
    rig.restart().unwrap();
    std::env::remove_var("B2_CHAIN");
    let rec = rig.call("hot_reconcile", json!({"last": true}));
    assert!(rec["reason"].as_str().unwrap().contains("node unreachable"), "{rec}");
    rig.chain.st.lock().unwrap().down = false;
    // a tampered coin file stops the signer; moved aside, the next start rebuilds from the scan
    let p = rig.root.join(".run/hot_utxos.json");
    let mut u = read(&p);
    u["sealed"]["ct"] = "00".repeat(40).into();
    std::fs::write(&p, u.to_string()).unwrap();
    assert!(rig.restart().unwrap_err().msg.contains("Move it aside"));
    std::fs::rename(&p, rig.root.join(".run/hot_utxos.json.bad")).unwrap();
    rig.restart().unwrap();
    assert_eq!(rig.hot_sats(), 4_000 + 3_000 + 4_999);
}
