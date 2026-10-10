//! review E M1 (AGP-069; B2 tests/test_review_e.py): a coinbase coin in the hot wallet waits for the
//! coinbase maturity the node reports, and waits for good when the node cannot say.
mod common;

use std::sync::Arc;

use common::*;
use serde_json::json;
use xbt_signer::hot::HotWallet;

const DEST: &str = "0014aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CB: &str = "cbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcb";

fn long_rule(depth: u32) -> serde_json::Value {
    json!({"deployments": {"long_coinbase_maturity": {"type": "flagday", "active": true, "height": 150, "height_end": 900_000,
           "coinbase_start_height": 150, "maturity": depth}}})
}

fn wallet(chain: &Arc<FakeChain>, d: &tempfile::TempDir) -> HotWallet {
    HotWallet::open(
        &d.path().join("hot.json"),
        chain.clone(),
        "bcrt",
        None,
        None,
        0,
    )
    .unwrap()
}

fn dest() -> Vec<u8> {
    hex::decode(DEST).unwrap()
}

#[test]
fn m1_coinbase_waits_for_the_node_maturity() {
    let chain = FakeChain::new("regtest", 200);
    chain.st.lock().unwrap().deployments = Some(long_rule(150));
    let d = tempfile::tempdir().unwrap();
    let hot = wallet(&chain, &d);
    chain.credit_coinbase(CB, 0, 50_000, &hot.spk_hex());
    let r = hot.reconcile(true);
    assert_eq!(hot.balance_sats(), 50_000, "{r}");
    assert_eq!(hot.status()["hot_coinbase_sats"], 50_000);

    let e = hot.prepare_fund(&dest(), 10_000, 500).unwrap_err();
    assert!(
        e.to_string().contains("50000 of it immature coinbase"),
        "{e}"
    );
    // past the ordinary 100 blocks, short of the node's 150
    chain.mine_to(200 + 100);
    assert!(hot.prepare_fund(&dest(), 10_000, 500).is_err());
    assert!(hot
        .sweep_to(&dest(), 10_000, 500)
        .unwrap_err()
        .to_string()
        .contains("immature coinbase"));
    assert!(
        hot.rotate().unwrap()["sweep"].is_null(),
        "rotation leaves the coin on the retired key"
    );
    assert_eq!(hot.sweep_retired().unwrap(), None);
    // the spend relays in block 350 = 200 + 150
    chain.mine_to(200 + 150 - 1);
    let swept = hot.sweep_retired().unwrap().expect("mature now");
    assert_eq!(swept["inputs"], 1);
    assert!(chain
        .mempool()
        .contains(&swept["txid"].as_str().unwrap().to_string()));
}

#[test]
fn m1_coinbase_waits_when_the_node_cannot_say() {
    let chain = FakeChain::new("regtest", 200);
    let d = tempfile::tempdir().unwrap();
    let hot = wallet(&chain, &d);
    chain.credit_coinbase(CB, 0, 50_000, &hot.spk_hex());
    chain.credit(&"ab".repeat(32), 0, 20_000, &hot.spk_hex(), true);
    hot.reconcile(true);
    chain.mine(10_000);
    let e = hot.prepare_fund(&dest(), 30_000, 500).unwrap_err();
    assert!(
        e.to_string().contains("immature coinbase"),
        "no getdeploymentinfo: the coinbase waits ({e})"
    );
    hot.prepare_fund(&dest(), 10_000, 500)
        .expect("an ordinary coin still spends");
    // a node that answers with no long rule: the ordinary depth
    chain.st.lock().unwrap().deployments = Some(json!({"deployments": {}}));
    hot.prepare_fund(&dest(), 30_000, 500).expect("100 deep");
}

#[test]
fn m1_coinbase_flag_from_gettxout_and_the_transaction() {
    let chain = FakeChain::new("regtest", 200);
    chain.st.lock().unwrap().deployments = Some(json!({"deployments": {}}));
    let d = tempfile::tempdir().unwrap();
    let hot = wallet(&chain, &d);
    chain.credit_coinbase(CB, 0, 50_000, &hot.spk_hex());
    // learnt without the flag, then reconciled: gettxout says coinbase, its height from confirmations
    hot.notice_utxo(CB, 0, 50_000, "").unwrap();
    chain.mine(98);
    hot.reconcile(false);
    assert!(
        hot.prepare_fund(&dest(), 10_000, 500).is_err(),
        "block 299 cannot spend a block-200 coinbase"
    );
    chain.mine(1);
    hot.prepare_fund(&dest(), 10_000, 500)
        .expect("block 300 can");

    let d2 = tempfile::tempdir().unwrap();
    let hot2 = wallet(&chain, &d2);
    let cb2 = "cd".repeat(32);
    chain.credit_coinbase(&cb2, 1, 40_000, &hot2.spk_hex());
    let bh = FakeChain::bhash("regtest", chain.height());
    assert_eq!(hot2.scan_from_txid(&cb2, false, &bh).unwrap(), 1);
    assert!(
        hot2.prepare_fund(&dest(), 10_000, 500).is_err(),
        "scanned from the transaction: vin[0] is a coinbase"
    );
    // the flag survives a restart
    drop(hot2);
    let hot2 = wallet(&chain, &d2);
    assert_eq!(hot2.status()["hot_coinbase_sats"], 40_000);
    chain.mine(99);
    hot2.prepare_fund(&dest(), 10_000, 500).expect("mature");
}
