//! AGP-017 mainnet readiness P1-P6 (mirrors B2 tests/test_mainnet_readiness.py).
mod common;

use std::sync::{Arc, Mutex};

use common::*;
use serde_json::{json, Value};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt_signer::node::Node;
use xbt_signer::signer::{Signer, SignerOptions};

/// A node that, at the moment of a broadcast, records what is on the signer's disk.
struct Spy {
    inner: Arc<FakeChain>,
    run: std::path::PathBuf,
    seen: Mutex<Vec<(Value, Value)>>,
}

impl Node for Spy {
    fn call(&self, m: &str, p: Value) -> xbt402::Result<Value> {
        if m == "sendrawtransaction" {
            let r = |f: &str| std::fs::read_to_string(self.run.join(f)).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
            self.seen.lock().unwrap().push((r("channels.json"), r("channel_keys.json")));
        }
        self.inner.call(m, p)
    }
    fn set_allow_generate(&self, a: bool) {
        self.inner.set_allow_generate(a)
    }
}

#[test]
fn p1_channel_and_sealed_key_are_on_disk_before_the_funding_is_broadcast() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    let spy = Arc::new(Spy { inner: rig.chain.clone(), run: rig.root.join(".run"), seen: Mutex::new(vec![]) });
    let s = Signer::new(&rig.root, SignerOptions { node: Some(spy.clone()), transport: Some(rig.web.clone()), ..Default::default() }).unwrap();
    rig.fund_hot(1, 12_000);
    call(&s, "hot_reconcile", json!({}));
    let r = call(&s, "xbt402_pay", json!({"url": URL, "max_sats": 500}));
    assert_eq!(r["verdict"], "pending", "{r}");
    let seen = spy.seen.lock().unwrap();
    let (chans, keys) = &seen[0];
    let rec = &chans["channels"][PROVIDER];
    assert_eq!((rec["state"].as_str(), rec["chan"].as_str()), (Some("pending"), r["chan"].as_str()));
    assert!(rec["funding_hex"].as_str().unwrap().len() > 100, "the signed funding is kept for a re-send");
    assert!(keys["sealed"].is_object(), "the payer key was sealed before the broadcast");
}

#[test]
fn p1_a_failed_broadcast_forgets_the_pending_channel_and_keeps_the_coin() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    rig.chain.st.lock().unwrap().reject = Some("insufficient fee".into());
    let r = rig.pay();
    assert_eq!((r["verdict"].as_str(), r["rule"].as_str()), (Some("deny"), Some("xbt402")), "{r}");
    rig.chain.st.lock().unwrap().reject = None;
    assert_eq!(rig.call("channels", json!({}))["channels"], json!([]));
    assert_eq!(rig.hot_sats(), 12_000);
    assert_eq!(rig.pay()["verdict"], "pending", "the next call funds again");
}

#[test]
fn p2_open_waits_for_min_conf_then_the_watcher_or_a_call_finishes_it() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    let r = rig.pay();
    assert_eq!((r["rule"].as_str(), r["charged_sats"].as_i64(), r["min_conf"].as_i64()), (Some("funding_unconfirmed"), Some(0), Some(1)));
    // AGP-067 (C2): the one /open so far is the preflight sent before funding
    assert_eq!(rig.web.requests.lock().unwrap().iter().filter(|(_, u)| u.ends_with("/open")).count(), 1, "no open before the confirmation");
    assert_eq!(rig.call("watch_tick", json!({}))["actions"], json!([]), "still unconfirmed: nothing to do");
    rig.chain.mine(1);
    let acts = rig.call("watch_tick", json!({}))["actions"].clone();
    assert_eq!(acts[0]["open_retry"]["state"], "open", "{acts}");
    let r = rig.pay();
    assert_eq!((r["charged_sats"].as_i64(), r["cum"].as_i64()), (Some(500), Some(546)));
    assert!(r["opened"].is_null(), "opened by the watcher, not by this call");
}

#[test]
fn p1_duplicate_channel_counts_as_opened() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    rig.pay();
    rig.chain.mine(1);
    // the provider already has the channel (our first open's answer was lost)
    let rec = rig.s.book.get(PROVIDER).unwrap();
    let p = rec.params().unwrap();
    let body = json!({"x402Version": 2, "network": rec.network, "channel": {"txid": rec.funding_txid, "vout": 0, "capacity": rec.funding_sats,
                      "expiry": rec.expiry, "payerPub": rec.payer_pub, "payerSpk": rec.payer_spk, "redeemScript": hex::encode(p.script())}});
    let r = rig.prov.serve("POST", "/x402/xbt-channel/open", &[], body.to_string().as_bytes(), &format!("{PROVIDER}/x402/xbt-channel/open"), None);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let r = rig.pay();
    assert_eq!((r["verdict"].as_str(), r["charged_sats"].as_i64()), (Some("allow"), Some(500)), "{r}");
}

#[test]
fn p1_a_refused_open_stays_pending_and_is_refunded_at_expiry() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    let chan = rig.pay()["chan"].as_str().unwrap().to_string();
    // the provider changed its payTo key: it refuses our channel
    let other = {
        let mut cfg = ProviderConfig::new(&rig.chain.network());
        cfg.policy.min_capacity = 10_000;
        cfg.policy.max_capacity = 10_000;
        cfg.policy.min_expiry_blocks = 1_008;
        Arc::new(Provider::new(Arc::new(ProviderChain(rig.chain.clone())), secret("another payTo"), cfg, Ledger::in_memory(),
                               Box::new(|_, _| 500), Box::new(|_, _, _| HttpResponse::new(200, vec![], b"x".to_vec()))).unwrap())
    };
    rig.web.sites.lock().unwrap().insert(PROVIDER.into(), other);
    rig.chain.mine(1);
    let r = rig.pay();
    assert_eq!(r["verdict"], "deny", "{r}");
    assert!(r["reason"].as_str().unwrap().contains("open failed: HTTP 4"), "{r}");
    let ch = rig.channel(&chan);
    assert_eq!(ch["state"], "pending");
    assert!(ch["open_error"].as_str().unwrap().starts_with("open refused: HTTP 4"), "{ch}");
    rig.chain.mine_to(ch["expiry"].as_u64().unwrap());
    rig.call("watch_tick", json!({}));
    let ch = rig.channel(&chan);
    assert_eq!(ch["state"], "refunded");
    assert_eq!(rig.chain.tx(ch["refund_txid"].as_str().unwrap()).outputs[0].value, 9_400);
}

#[test]
fn ten_calls_sign_exactly_5000_and_the_default_split_window_stops_the_second_call() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    rig.open();
    for _ in 0..9 {
        rig.pay();
    }
    let rec = rig.s.book.get(PROVIDER).unwrap();
    assert_eq!((rec.used_sats, rec.spent_sats), (5_000, 5_000));
    drop(rig);
    let rig = Rig::new(json!({"split_window_s": 600}), false);
    rig.fund_hot(1, 12_000);
    rig.open();
    let r = rig.pay();
    assert_eq!((r["verdict"].as_str(), r["rule"].as_str()), (Some("deny"), Some("split_bypass")), "{r}");
}

#[test]
fn a_close_fee_above_the_wallet_cap_is_refused_before_funding() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"close_fee_max_sats": 500}), false);
    rig.fund_hot(1, 12_000);
    let r = rig.pay();
    assert_eq!(r["rule"], "xbt402");
    assert!(r["reason"].as_str().unwrap().contains("closeFeeSat 600 is above this wallet's cap 500"), "{r}");
    assert!(rig.chain.mempool().is_empty());
    assert!(rig.sigs().is_empty(), "nothing signed");
}

#[test]
fn p3_p4_p5_mainnet_never_mines_uses_961640_and_bc_addresses() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::build(json!({"regtest_mine": null}), false, "main", None);
    let h = rig.call("health", json!({}));
    assert_eq!((h["chain"].as_str(), h["hrp"].as_str(), h["mining"].as_bool()), (Some("main"), Some("bc"), Some(false)));
    assert!(rig.call("hot_address", json!({}))["hot_address"].as_str().unwrap().starts_with("bc1q"));
    assert_eq!(rig.s.session.network().unwrap(), xbt402::wire::XBT_MAINNET);
    assert!(!rig.chain.allow_generate.load(std::sync::atomic::Ordering::SeqCst), "the RPC guard stays closed");
    // a sweep to another network's address is refused; one to bc1 is accepted
    rig.fund_hot(1, 3_000);
    let hot = rig.call("hot_address", json!({}))["hot_address"].as_str().unwrap().to_string();
    let exp = xbt_signer::pyjson::now_f64() as i64 + 600;
    for (to, ok) in [("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", false), ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", true)] {
        let sig = sign_human(&xbt_signer::approval::sweep_message(&hot, to, 2_400, exp));
        let r = rig.call("sweep_hot", json!({"to": to, "amount_sats": 2_400, "expiry": exp, "signature": sig}));
        assert_eq!(r["ok"], ok, "{to}: {r}");
    }
    drop(rig);
    // a mining policy on mainnet refuses to start
    let d = tempfile::tempdir().unwrap();
    env_for(d.path());
    let chain = FakeChain::new("main", 962_000);
    let root = root_with(d.path(), &runbook_policy(json!({"regtest_mine": true})));
    let e = signer(&root, &chain, &Arc::new(Web::default()), None).unwrap_err();
    assert!(e.msg.contains("refusing to start (only regtest may mine)"), "{}", e.msg);
    // a mining hook off regtest is refused by the session
    let s2 = signer(&root_with(tempfile::tempdir().unwrap().path(), &runbook_policy(json!({}))), &chain, &Arc::new(Web::default()), None).unwrap();
    let hook: xbt_signer::session::MineFn = Arc::new(|_| Ok(()));
    assert!(xbt_signer::session::Session::new(s2.book.clone(), s2.hot.clone(), s2.node.clone(), Arc::new(Web::default()), "main", Some(hook), 0.0, 0, 6).is_err());
    // the RPC client refuses generate until the chain is known to be regtest (before any network I/O)
    let rpc = xbt_signer::node::KnotsRpc::new(d.path(), "agent");
    assert!(rpc.call("generatetoaddress", json!([1, "x"])).unwrap_err().msg.contains("mining is for regtest only"));
    assert!(rpc.call("dumpprivkey", json!(["x"])).unwrap_err().msg.contains("refuses"));
}

#[test]
fn p3_regtest_mines_only_when_the_policy_lets_it_and_keeps_block_101() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"regtest_mine": null}), false);
    assert_eq!(rig.call("health", json!({}))["mining"], true);
    assert_eq!(rig.s.session.network().unwrap(), rig.chain.network());
    rig.fund_hot(1, 12_000);
    // with mining on, the signer confirms its own funding (regtest demos) and pays at once
    let r = rig.pay();
    assert_eq!(r["verdict"], "allow", "{r}");
    assert!(rig.chain.st.lock().unwrap().mined_by_signer >= 1);
}

#[test]
fn b2_chain_must_agree_with_the_node() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let d = tempfile::tempdir().unwrap();
    env_for(d.path());
    std::env::set_var("B2_CHAIN", "main");
    let chain = FakeChain::new("regtest", 6_720);
    let e = signer(&root_with(d.path(), &runbook_policy(json!({}))), &chain, &Arc::new(Web::default()), None).unwrap_err();
    std::env::remove_var("B2_CHAIN");
    assert!(e.msg.contains("B2_CHAIN"), "{}", e.msg);
}

#[test]
fn p6_the_signer_never_asks_for_txindex() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    rig.open();
    rig.pay();
    rig.call("close_channel", json!({"counterparty": PROVIDER}));
    rig.chain.mine(2);
    rig.call("watch_tick", json!({}));
    // every getrawtransaction call either hit the mempool or named a block
    let calls = rig.chain.st.lock().unwrap().calls.clone();
    assert!(!calls.iter().any(|c| c == "getrawtransaction_txindex"));
    assert!(calls.iter().all(|c| ["getblockchaininfo", "getblockcount", "getblockhash", "getblockheader", "getblock", "sendrawtransaction", "gettxout",
                                  "getrawtransaction", "gettxspendingprevout", "scantxoutset", "getbalances", "estimatesmartfee"].contains(&c.as_str())),
            "{calls:?}");
}
