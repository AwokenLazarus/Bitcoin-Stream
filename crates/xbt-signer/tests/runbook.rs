//! The AGP-017 runbook (G2-G7 and both rollbacks) in process: the Rust signer, the Rust provider,
//! a fake pruned node without txindex, and the anchor witness. Same numbers as the regtest
//! rehearsal: 12,000 sat to the hot key, a 10,000 sat funding, 10 calls of 500, closeFee 600.
mod common;

use std::sync::Arc;

use common::*;
use serde_json::{json, Value};
use xbt402::ledger::Ledger;
use xbt_signer::anchor::{serve_witness, AnchorClient};
use xbt_signer::approval::sweep_message;
use xbt_signer::sigaudit::check_chain;

fn outs(tx: &xbt_primitives::tx::Tx) -> Vec<(String, i64)> {
    tx.outputs.iter().map(|o| (hex::encode(&o.script_pubkey), o.value)).collect()
}

fn receipt(r: &Value) -> Value {
    r["untrusted_provider_response"]["receipt"]["extra"]["receipt"].clone()
}

fn sweep(s: &xbt_signer::signer::Signer, to: &str, amount: i64) -> Value {
    let hot = call(s, "hot_address", json!({}))["hot_address"].as_str().unwrap().to_string();
    let expiry = xbt_signer::pyjson::now_f64() as i64 + 900;
    let sig = sign_human(&sweep_message(&hot, to, amount, expiry));
    call(s, "sweep_hot", json!({"to": to, "amount_sats": amount, "expiry": expiry, "signature": sig}))
}

const MIKE: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

#[test]
fn runbook_g1_to_g7_and_both_rollbacks() {
    let _env = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let d = tempfile::tempdir().unwrap();
    env_for(d.path());
    let chain = FakeChain::new("regtest", 6_720);
    let web = Arc::new(Web::default());
    let prov = runbook_provider(&chain, Ledger::open(&d.path().join("provider.jsonl")).unwrap());
    web.sites.lock().unwrap().insert(PROVIDER.into(), prov.clone());
    let witness = serve_witness(&d.path().join("anchor"), &d.path().join("anchor").join("w.sock"), 0o600).unwrap();
    let ac = || Some(AnchorClient::new(&witness.sock_path));
    // AGP-063: the first state on a channel signs the dust floor (546), not the 500-sat price.
    // Twelve calls book 6092, which is above the rehearsal weekly budget of 6000.
    let root = root_with(d.path(), &runbook_policy(json!({"anchor_required": true, "daily_budget_sats": 6500, "weekly_budget_sats": 6500})));
    let s = signer(&root, &chain, &web, ac()).unwrap();

    // G1
    let h = call(&s, "health", json!({}));
    assert_eq!((h["chain"].as_str(), h["mining"].as_bool()), (Some("regtest"), Some(false)));
    let hot = call(&s, "hot_address", json!({}));
    let (hot_addr, hot_spk) = (hot["hot_address"].as_str().unwrap().to_string(), hot["hot_spk"].as_str().unwrap().to_string());
    assert!(hot_addr.starts_with("bcrt1q") && hot_spk.starts_with("0014"));
    assert_eq!(xbt_signer::fsx::mode_of(&d.path().join("keys/hot.key")), 0o600);
    let hj: Value = serde_json::from_str(&std::fs::read_to_string(root.join(".run/hot.json")).unwrap()).unwrap();
    assert!(hj["current"].get("sealed").is_some() && hj["current"].get("secret").is_none());
    let sg = call(&s, "signatures", json!({}));
    assert_eq!(sg["chain_ok"], true);
    assert_eq!(sg["signatures"], json!([]));
    assert_eq!(sg["anchor"]["enabled"], true);

    // G2
    chain.credit(&"a1".repeat(32), 1, 12_000, &hot_spk, true);
    let n = call(&s, "notice_hot_txid", json!({"txid": "a1".repeat(32)}));
    assert_eq!((n["noticed"].as_i64(), n["hot_sats"].as_i64()), (Some(1), Some(12_000)));

    // G3: the funding waits for 1 confirmation (P2), then the open and the first call
    let r = call(&s, "xbt402_pay", json!({"url": URL, "method": "GET", "body": "", "max_sats": 500}));
    assert_eq!((r["verdict"].as_str(), r["rule"].as_str()), (Some("pending"), Some("funding_unconfirmed")), "{r}");
    let fund = r["funding_txid"].as_str().unwrap().to_string();
    assert_eq!(chain.mempool(), vec![fund.clone()]);
    assert!(call(&s, "channels", json!({}))["channels"][0]["state"] == "pending");
    let open_block = chain.height() + 1;
    chain.mine(1);
    let r = call(&s, "xbt402_pay", json!({"url": URL, "method": "GET", "body": "", "max_sats": 500}));
    assert_eq!(r["verdict"], "allow", "{r}");
    assert_eq!((r["charged_sats"].as_i64(), r["cum"].as_i64()), (Some(500), Some(546)));
    assert_eq!(r["opened"]["state"], "open");
    assert_eq!(receipt(&r)["charged"], "500");
    let chan = r["chan"].as_str().unwrap().to_string();
    let ftx = chain.tx(&fund);
    let fo = outs(&ftx);
    assert!(fo[0].0.starts_with("0020") && fo[0].0.len() == 68 && fo[0].1 == 10_000, "{fo:?}");
    assert_eq!(fo[1], (hot_spk.clone(), 1_400));
    assert_eq!(*ftx.inputs[0].witness[0].last().unwrap(), 0x21);
    // the offer's minExpiryBlocks 1,008 + minConf 1 + closeMarginBlocks 144 (AGP-076)
    assert_eq!(r["opened"]["expiry"].as_i64().unwrap(), (open_block - 1) as i64 + 1_153);
    let mut receipts = vec![receipt(&r)];

    // G4: nine more calls; nothing broadcast
    let tip = chain.height();
    for _ in 0..9 {
        let r = call(&s, "xbt402_pay", json!({"url": URL, "method": "GET", "body": "", "max_sats": 500}));
        assert_eq!((r["verdict"].as_str(), r["charged_sats"].as_i64()), (Some("allow"), Some(500)), "{r}");
        receipts.push(receipt(&r));
    }
    let spent: Vec<i64> = receipts.iter().map(|x| x["spentMsat"].as_str().unwrap().parse().unwrap()).collect();
    assert_eq!(spent, (1..=10).map(|i| 500_000 * i).collect::<Vec<_>>());
    assert_eq!(receipts[9]["cum"], "5000");
    assert!(chain.mempool().is_empty() && chain.height() == tip);
    let sg = call(&s, "signatures", json!({"limit": 100}));
    let states: Vec<&Value> = sg["signatures"].as_array().unwrap().iter().filter(|x| x["kind"] == "channel_state").collect();
    assert_eq!(states.len(), 10);
    assert!(states.iter().all(|x| x["rule"] == "policy:ok" && x["method"] == "xbt402_pay"));
    assert_eq!(sg["chain_ok"], true);

    // G5: cooperative close; the change is counted at once
    let r = call(&s, "close_channel", json!({"counterparty": PROVIDER}));
    assert_eq!((r["verdict"].as_str(), r["cum"].as_i64()), (Some("allow"), Some(5_000)), "{r}");
    let close = r["txid"].as_str().unwrap().to_string();
    assert_eq!(r["close_change"], "counted");
    chain.mine(1);
    let ctx = chain.tx(&close);
    let co = outs(&ctx);
    let payee: Vec<&(String, i64)> = co.iter().filter(|(spk, _)| *spk != hot_spk).collect();
    assert_eq!(payee.len(), 1);
    assert!(payee[0].0.starts_with("0014") && payee[0].1 == 5_000);
    assert!(co.contains(&(hot_spk.clone(), 4_400)));
    assert_eq!(10_000 - co.iter().map(|x| x.1).sum::<i64>(), 600);
    let w = &ctx.inputs[0].witness;
    assert_eq!(w.len(), 4);
    assert_eq!((*w[0].last().unwrap(), *w[1].last().unwrap(), w[2].clone()), (0x21, 0x21, vec![1u8]));
    assert_eq!(w[3].len(), 78);
    let ch = call(&s, "channels", json!({}))["channels"][0].clone();
    assert_eq!((ch["state"].as_str(), ch["closed_txid"].as_str()), (Some("closed"), Some(close.as_str())));
    assert_eq!(prov.channel_state(&chan).unwrap().best_cum, 5_000);
    assert_eq!(call(&s, "hot_address", json!({}))["hot_sats"], 5_800);

    // G7: human-signed sweep, zero change
    let r = sweep(&s, MIKE, 5_200);
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["change_sats"], 0);
    let stx = chain.tx(r["txid"].as_str().unwrap());
    assert_eq!(stx.outputs.len(), 1);
    assert_eq!(stx.outputs[0].value, 5_200);
    chain.mine(1);
    assert_eq!(chain.unspent_to(&hot_spk), 0);
    assert_eq!(call(&s, "hot_address", json!({}))["hot_sats"], 0);
    // a sweep with a wrong signature, a replayed expiry-less one, or to another network is refused
    chain.credit(&"a2".repeat(32), 0, 12_000, &hot_spk, true);
    call(&s, "notice_hot_txid", json!({"txid": "a2".repeat(32)}));
    let bad = call(&s, "sweep_hot", json!({"to": MIKE, "amount_sats": 1000, "expiry": 9_999_999_999i64, "signature": "00".repeat(64)}));
    assert_eq!(bad["ok"], false);
    let r = sweep(&s, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 1_000);
    assert_eq!(r["ok"], false, "another network's address is refused (P5)");
    let sg = call(&s, "signatures", json!({"limit": 500}));
    assert!(sg["signatures"].as_array().unwrap().iter().any(|x| x["rule"] == "human:sweep_signature"));
    assert!(sg["signatures"].as_array().unwrap().iter().all(|x| x["rule"].as_str().is_some_and(|r| !r.is_empty())));

    // rollback A: the signer dies after the funding broadcast; the provider is gone; refund at expiry
    let r = call(&s, "xbt402_pay", json!({"url": URL, "method": "GET", "body": "", "max_sats": 500}));
    assert_eq!(r["verdict"], "pending", "{r}");
    let pend_chan = r["chan"].as_str().unwrap().to_string();
    drop(s);
    web.down.store(true, std::sync::atomic::Ordering::SeqCst);
    chain.mine(1);
    let s = signer(&root, &chain, &web, ac()).unwrap();
    let ch = call(&s, "channels", json!({}))["channels"].as_array().unwrap().iter().find(|c| c["chan"] == pend_chan.as_str()).cloned().unwrap();
    assert_eq!(ch["state"], "pending");
    assert_eq!(call(&s, "hot_address", json!({}))["hot_sats"], 1_400, "the funding's change survived the restart");
    let acts = call(&s, "watch_tick", json!({}))["actions"].clone();
    assert!(acts.to_string().contains("unreachable"), "{acts}");
    let ch = call(&s, "channels", json!({}))["channels"].as_array().unwrap().iter().find(|c| c["chan"] == pend_chan.as_str()).cloned().unwrap();
    assert!(ch["open_error"].as_str().unwrap().contains("unreachable"));
    let expiry = ch["expiry"].as_u64().unwrap();
    chain.mine_to(expiry - 1);
    call(&s, "watch_tick", json!({}));
    let early = call(&s, "xbt402_refund", json!({"counterparty": pend_chan}));
    assert_eq!(early["rule"], "refund_early");
    assert!(chain.mempool().is_empty());
    chain.mine_to(expiry);
    call(&s, "watch_tick", json!({}));
    let ch = call(&s, "channels", json!({}))["channels"].as_array().unwrap().iter().find(|c| c["chan"] == pend_chan.as_str()).cloned().unwrap();
    assert_eq!(ch["state"], "refunded");
    let rtx = chain.tx(ch["refund_txid"].as_str().unwrap());
    assert_eq!(rtx.locktime as u64, expiry);
    assert_eq!(outs(&rtx), vec![(hot_spk.clone(), 9_400)]);
    let sg = call(&s, "signatures", json!({"limit": 500}));
    assert!(sg["signatures"].as_array().unwrap().iter().any(|x| x["kind"] == "refund" && x["rule"] == "watcher:auto_refund"));
    assert_eq!(call(&s, "hot_address", json!({}))["hot_sats"], 1_400 + 9_400);
    // idempotent: a second refund reports the first
    let again = call(&s, "xbt402_refund", json!({"counterparty": pend_chan}));
    assert_eq!((again["already"].as_bool(), again["txid"].as_str()), (Some(true), ch["refund_txid"].as_str()));
    chain.mine(1);
    let r = sweep(&s, MIKE, 10_200);
    assert_eq!((r["ok"].as_bool(), r["change_sats"].as_i64()), (Some(true), Some(0)), "{r}");
    chain.mine(1);

    // rollback B: no cooperative close; the provider closes at expiry - 144; B2 finds it by scanning blocks
    web.down.store(false, std::sync::atomic::Ordering::SeqCst);
    chain.credit(&"b2".repeat(32), 0, 12_000, &hot_spk, true);
    call(&s, "notice_hot_txid", json!({"txid": "b2".repeat(32)}));
    assert_eq!(call(&s, "xbt402_pay", json!({"url": URL, "max_sats": 500}))["verdict"], "pending");
    chain.mine(1);
    let r = call(&s, "xbt402_pay", json!({"url": URL, "max_sats": 500}));
    assert_eq!(r["charged_sats"], 500, "{r}");
    let r2 = call(&s, "xbt402_pay", json!({"url": URL, "max_sats": 500}));
    assert_eq!((r2["charged_sats"].as_i64(), r2["cum"].as_i64()), (Some(500), Some(1_000)));
    let (bchan, bexp) = (r["chan"].as_str().unwrap().to_string(), r["opened"]["expiry"].as_u64().unwrap());
    chain.mine_to(bexp - 144);
    let closed = prov.close_due().unwrap();
    assert_eq!(closed.len(), 1);
    let pclose = prov.channel_state(&bchan).unwrap().closed_txid;
    chain.mine(1);
    let o = outs(&chain.tx(&pclose));
    assert!(o.contains(&(hot_spk.clone(), 8_400)) && o.iter().any(|x| x.1 == 1_000), "{o:?}");
    chain.mine(3);
    chain.mine_to(bexp);
    call(&s, "watch_tick", json!({}));
    let ch = call(&s, "channels", json!({}))["channels"].as_array().unwrap().iter().find(|c| c["chan"] == bchan.as_str()).cloned().unwrap();
    assert_eq!((ch["state"].as_str(), ch["closed_txid"].as_str()), (Some("closed"), Some(pclose.as_str())), "{ch}");
    assert!(ch["refund_txid"].is_null());
    assert_eq!(call(&s, "hot_address", json!({}))["hot_sats"], 1_400 + 8_400);
    let r = sweep(&s, MIKE, 9_200);
    assert_eq!((r["ok"].as_bool(), r["change_sats"].as_i64()), (Some(true), Some(0)), "{r}");

    // AGP-016: the log still holds the witness's latest anchor; the witness saw no alert
    call(&s, "anchor_now", json!({}));
    let latest = witness.store.latest();
    assert_eq!(check_chain(&root.join(".run/signatures.jsonl"), Some(&latest))["ok"], true);
    assert!(latest["n"].as_i64().unwrap() > 20);
    assert!(witness.store.alerts().is_empty());
    assert!(call(&s, "anchor_status", json!({}))["last_error"].as_str().unwrap().is_empty());
}
