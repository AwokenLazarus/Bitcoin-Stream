//! The anchored signature log on the signer (mirrors B2 tests/test_sig_anchor.py) and the human
//! approval attacks (mirrors tests/test_approval_attacks.py).
mod common;

use common::*;
use serde_json::{json, Value};
use xbt_signer::approval::canonical_message;
use xbt_signer::sigaudit::SigAudit;

#[test]
fn anchored_at_start_close_refund_rotation_and_a_rewritten_log_refuses_start() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({"anchor_interval_s": 0}), true);
    let w = rig.witness.as_ref().unwrap();
    assert_eq!(w.store.latest()["n"], 0, "start: the empty log is anchored (unchanged)");
    rig.fund_hot(1, 12_000);
    rig.open();
    rig.call("close_channel", json!({"counterparty": PROVIDER}));
    let lines = rig.s.sigaudit.raw_lines().len() as i64;
    assert_eq!(rig.witness.as_ref().unwrap().store.latest()["n"], lines, "anchored after the close");
    rig.call("rotate_hot_key", json!({}));
    let lines = rig.s.sigaudit.raw_lines().len() as i64;
    assert_eq!(rig.witness.as_ref().unwrap().store.latest()["n"], lines, "anchored after the rotation");
    let st = rig.call("anchor_status", json!({}));
    assert_eq!((st["enabled"].as_bool(), st["unanchored_lines"].as_i64()), (Some(true), Some(0)));
    // a whole-file rewrite with a fresh, self-consistent chain
    let log = rig.root.join(".run/signatures.jsonl");
    std::fs::remove_file(&log).unwrap();
    let fake = SigAudit::open(&log).unwrap();
    for _ in 0..lines {
        fake.record("funding", b"x", "", "", json!({})).unwrap();
    }
    let sg = rig.call("signatures", json!({}));
    assert_eq!(sg["chain_ok"], false, "the running signer sees the rewrite");
    let e = rig.restart().unwrap_err();
    assert!(e.msg.contains("fails its anchor check"), "{}", e.msg);
    // truncation too
    std::fs::write(&log, "").unwrap();
    assert!(rig.restart().unwrap_err().msg.contains("anchored"));
}

#[test]
fn anchor_required_needs_a_witness_and_without_one_anchoring_is_off() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let d = tempfile::tempdir().unwrap();
    env_for(d.path());
    let chain = FakeChain::new("regtest", 6_720);
    let web = std::sync::Arc::new(Web::default());
    let root = root_with(d.path(), &runbook_policy(json!({"anchor_required": true})));
    assert!(signer(&root, &chain, &web, None).unwrap_err().msg.contains("anchor_required"));
    std::env::set_var("B2_ANCHOR_SOCK", d.path().join("nobody.sock"));
    assert!(signer(&root, &chain, &web, None).unwrap_err().msg.contains("anchor witness unreachable"));
    std::env::remove_var("B2_ANCHOR_SOCK");
    let d2 = tempfile::tempdir().unwrap();
    let root2 = root_with(d2.path(), &runbook_policy(json!({})));
    let s = signer(&root2, &chain, &web, None).unwrap();
    let sg = call(&s, "signatures", json!({}));
    assert_eq!((sg["chain_ok"].as_bool(), sg["anchor"]["enabled"].as_bool()), (Some(true), Some(false)));
    assert_eq!(call(&s, "anchor_now", json!({}))["result"]["ok"], false);
}

#[test]
fn periodic_anchor_on_the_watcher_tick() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"anchor_interval_s": 1}), true);
    rig.fund_hot(1, 12_000);
    rig.pay(); // a funding signature, not anchored by itself
    let n = rig.s.sigaudit.raw_lines().len() as i64;
    assert!(rig.witness.as_ref().unwrap().store.latest()["n"].as_i64().unwrap() < n);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let acts = rig.call("watch_tick", json!({}))["actions"].clone();
    assert!(acts.to_string().contains("\"anchor\""), "{acts}");
    assert_eq!(rig.witness.as_ref().unwrap().store.latest()["n"], n);
}

fn approval_rig() -> Rig {
    let payto = hex::encode(xbt_primitives::ecdsa::pubkey(&secret("provider payTo")));
    let rig = Rig::new(json!({"counterparties": {PROVIDER: {"pay_to": payto}}, "split_window_s": 0}), false);
    rig.fund_hot(1, 12_000);
    rig
}

fn needs_human(rig: &Rig) -> (String, i64) {
    let r = rig.call("pay", json!({"to": PROVIDER, "amount_sats": 1000, "memo": "big"}));
    assert_eq!((r["verdict"].as_str(), r["rule"].as_str()), (Some("needs_human"), Some("human_threshold")), "{r}");
    (r["approval_token"].as_str().unwrap().to_string(), r["approval_expires"].as_i64().unwrap())
}

#[test]
fn approvals_need_the_humans_signature_over_exactly_the_pending_payment_once() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = approval_rig();
    let (tok, exp) = needs_human(&rig);
    // a boolean "human" is never a capability
    let r = rig.call("pay", json!({"to": PROVIDER, "amount_sats": 1000, "human": true}));
    assert_eq!(r["verdict"], "needs_human");
    // no signature, a bad one, one by another key
    for sig in [String::new(), "zz".into(), "00".repeat(64),
                hex::encode(ed25519_dalek::Signer::sign(&ed25519_dalek::SigningKey::from_bytes(&[1; 32]), &canonical_message(&tok, PROVIDER, 1000, exp)).to_bytes())] {
        let r = rig.call("approve", json!({"token": tok, "dest": PROVIDER, "amount_sats": 1000, "expiry": exp, "signature": sig}));
        assert_eq!(r["rule"], "approval_sig", "{r}");
    }
    // a valid signature over other fields than the pending payment
    let sig = sign_human(&canonical_message(&tok, PROVIDER, 999, exp));
    let r = rig.call("approve", json!({"token": tok, "dest": PROVIDER, "amount_sats": 999, "expiry": exp, "signature": sig}));
    assert_eq!(r["rule"], "approval_bind", "{r}");
    // the right one pays, once
    let sig = sign_human(&canonical_message(&tok, PROVIDER, 1000, exp));
    let ok = json!({"token": tok, "dest": PROVIDER, "amount_sats": 1000, "expiry": exp, "signature": sig});
    let r = rig.call("approve", ok.clone());
    assert_eq!((r["verdict"].as_str(), r["approved"].as_bool(), r["rail"].as_str()), (Some("allow"), Some(true), Some("channel")), "{r}");
    assert_eq!(r["cum"], 1000);
    assert!(rig.sigs().iter().any(|x| x["rule"] == "human:approval_signature"));
    assert_eq!(rig.call("approve", ok)["rule"], "approval", "replay: the token is gone");
}

#[test]
fn an_expired_approval_is_refused_and_forgotten() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = approval_rig();
    let (tok, _) = needs_human(&rig);
    let exp = 1_000;
    let sig = sign_human(&canonical_message(&tok, PROVIDER, 1000, exp));
    let r = rig.call("approve", json!({"token": tok, "dest": PROVIDER, "amount_sats": 1000, "expiry": exp, "signature": sig}));
    assert_eq!(r["rule"], "approval_expired");
    let ledger: Value = serde_json::from_str(&std::fs::read_to_string(rig.root.join(".run/ledger.json")).unwrap()).unwrap();
    assert!(ledger["approvals"].get(&tok).is_none());
}

#[test]
fn not_ported_methods_answer_so_and_unknown_methods_fail() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    for m in ["recover_vault", "fund_treasury", "recover_treasury"] {
        assert_eq!(rig.call(m, json!({}))["ok"], false);
    }
    assert_eq!(rig.call("forward_status", json!({}))["ported"], false);
    assert_eq!(rig.call("forward_recover", json!({"txid": "00"}))["rule"], "forward_disabled");
    assert!(rig.s.handle("dumpprivkey", &json!({})).is_err());
    let b = rig.call("balance", json!({}));
    assert!(b["hot"]["hot_address"].is_string() && b["not_ported"].is_array());
}
