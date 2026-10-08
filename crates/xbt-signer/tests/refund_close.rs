//! Refund custody (mirrors B2 tests/test_refund.py) and the AGP-022 close-change retry (mirrors
//! tests/test_close_change.py).
mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use common::*;
use serde_json::json;
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};

fn opened(rig: &Rig) -> (String, u64) {
    rig.fund_hot(1, 12_000);
    let r = rig.open();
    (r["chan"].as_str().unwrap().to_string(), r["opened"]["expiry"].as_u64().unwrap())
}

#[test]
fn refund_before_expiry_is_refused_and_nothing_is_signed() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    let (chan, expiry) = opened(&rig);
    let n = rig.sigs().len();
    rig.chain.mine_to(expiry - 1);
    let r = rig.call("xbt402_refund", json!({"counterparty": PROVIDER}));
    assert_eq!((r["rule"].as_str(), r["height"].as_u64()), (Some("refund_early"), Some(expiry - 1)));
    assert_eq!(rig.sigs().len(), n, "no refund signature before expiry");
    // in the margin no new state is signed either
    let r = rig.pay();
    assert_eq!(r["rule"], "channel_expiring", "{r}");
    assert_eq!(rig.channel(&chan)["state"], "open");
}

#[test]
fn refund_at_expiry_pays_the_hot_key_once_and_the_destination_cannot_be_chosen() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"hot_balance_cap_sats": 0}), false);
    let (chan, expiry) = opened(&rig);
    rig.chain.mine_to(expiry);
    let r = rig.call("xbt402_refund", json!({"counterparty": chan, "to": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"}));
    assert_eq!((r["verdict"].as_str(), r["sats"].as_i64(), r["auto"].as_bool()), (Some("allow"), Some(9_400), Some(false)), "{r}");
    let tx = rig.chain.tx(r["txid"].as_str().unwrap());
    assert_eq!(hex::encode(&tx.outputs[0].script_pubkey), rig.hot_spk(), "always the hot key");
    assert_eq!(tx.locktime as u64, expiry);
    assert_eq!(rig.hot_sats(), 1_400 + 9_400);
    let again = rig.call("xbt402_refund", json!({"counterparty": PROVIDER}));
    assert_eq!((again["already"].as_bool(), again["txid"].clone()), (Some(true), r["txid"].clone()));
    assert_eq!(rig.sigs().iter().filter(|x| x["kind"] == "refund").count(), 1, "never a second refund signature");
    // the next payment replaces the refunded channel with a new one (a funding spends one coin)
    rig.chain.mine(1);
    rig.fund_hot(2, 12_000);
    let r = rig.pay();
    assert_eq!(r["verdict"], "pending", "{r}");
}

#[test]
fn refused_by_policy_for_unknown_channels_and_after_a_node_rejection_the_channel_stays_open() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"refund_enabled": false}), false);
    assert_eq!(rig.call("xbt402_refund", json!({"counterparty": PROVIDER}))["rule"], "refund_disabled");
    drop(rig);
    let rig = Rig::new(json!({}), false);
    assert_eq!(rig.call("xbt402_refund", json!({"counterparty": "http://nobody"}))["rule"], "unknown_channel");
    let (chan, expiry) = opened(&rig);
    rig.chain.mine_to(expiry);
    rig.chain.st.lock().unwrap().reject = Some("mempool full".into());
    let r = rig.call("refund_channel", json!({"chan": chan}));
    assert_eq!(r["rule"], "refund_rejected");
    rig.chain.st.lock().unwrap().reject = None;
    assert_eq!(rig.channel(&chan)["state"], "open");
    let acts = rig.call("watch_tick", json!({}))["actions"].clone();
    assert_eq!(acts[0]["rule"], "refund", "{acts}");
}

#[test]
fn watcher_refunds_at_expiry_only_and_after_rotation_pays_the_new_hot_key() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    let (chan, expiry) = opened(&rig);
    rig.rotate_hot_key();
    let new_spk = rig.hot_spk();
    rig.chain.mine_to(expiry - 1);
    assert!(!rig.call("watch_tick", json!({}))["actions"].to_string().contains("refund"));
    rig.chain.mine_to(expiry);
    let acts = rig.call("watch_tick", json!({}))["actions"].clone();
    assert_eq!((acts[0]["chan"].as_str(), acts[0]["rule"].as_str()), (Some(chan.as_str()), Some("refund")), "{acts}");
    let tx = rig.chain.tx(acts[0]["txid"].as_str().unwrap());
    assert_eq!(hex::encode(&tx.outputs[0].script_pubkey), new_spk);
}

#[test]
fn no_refund_after_a_close_and_the_close_is_found_on_a_pruned_node() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    let (chan, expiry) = opened(&rig);
    rig.call("close_channel", json!({"counterparty": PROVIDER}));
    rig.chain.mine(1);
    rig.chain.mine_to(expiry);
    let r = rig.call("xbt402_refund", json!({"counterparty": chan}));
    assert_eq!(r["rule"], "channel_closed");
    assert!(!rig.sigs().iter().any(|x| x["kind"] == "refund"));
}

/// The provider's node: its broadcasts reach the payer's node only when released (P2P lag).
struct LagChain {
    node: Arc<FakeChain>,
    hold: AtomicBool,
    queue: Mutex<Vec<String>>,
}

impl LagChain {
    fn release(&self) {
        self.hold.store(false, Ordering::SeqCst);
        for h in self.queue.lock().unwrap().drain(..) {
            ProviderChain(self.node.clone()).send_raw_transaction(&h).unwrap();
        }
    }
}

impl ChainBackend for LagChain {
    fn block_count(&self) -> xbt402::Result<u32> {
        ProviderChain(self.node.clone()).block_count()
    }
    fn get_tx_out(&self, t: &str, v: u32, m: bool) -> xbt402::Result<Option<UtxoInfo>> {
        ProviderChain(self.node.clone()).get_tx_out(t, v, m)
    }
    fn send_raw_transaction(&self, hex: &str) -> xbt402::Result<String> {
        if self.hold.load(Ordering::SeqCst) {
            self.queue.lock().unwrap().push(hex.into());
            return Ok(xbt_primitives::tx::Tx::parse_hex(hex).unwrap().txid());
        }
        ProviderChain(self.node.clone()).send_raw_transaction(hex)
    }
    fn has_transaction(&self, t: &str) -> xbt402::Result<bool> {
        ProviderChain(self.node.clone()).has_transaction(t)
    }
}

fn lagging(rig: &Rig) -> Arc<LagChain> {
    let lag = Arc::new(LagChain { node: rig.chain.clone(), hold: AtomicBool::new(false), queue: Mutex::new(vec![]) });
    let mut cfg = ProviderConfig::new(&rig.chain.network());
    cfg.policy.min_capacity = 10_000;
    cfg.policy.max_capacity = 10_000;
    cfg.policy.min_expiry_blocks = 1_008;
    let p = Arc::new(Provider::new(lag.clone(), secret("provider payTo"), cfg, Ledger::in_memory(), Box::new(|_, _| 500),
                                   Box::new(|_, _, _| HttpResponse::new(200, vec![], b"{}".to_vec()))).unwrap());
    rig.web.sites.lock().unwrap().insert(PROVIDER.into(), p);
    lag
}

#[test]
fn a_close_not_yet_on_our_node_is_counted_on_a_later_tick_or_read_and_only_once() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({}), false);
    let lag = lagging(&rig);
    rig.fund_hot(1, 12_000);
    rig.open();
    lag.hold.store(true, Ordering::SeqCst);
    let r = rig.call("close_channel", json!({"counterparty": PROVIDER}));
    assert_eq!(r["close_change"], "pending", "{r}");
    let close = r["txid"].as_str().unwrap().to_string();
    let hot = rig.call("hot_address", json!({}));
    assert_eq!((hot["hot_sats"].as_i64(), hot["hot_pending_close_change"][0].as_str()), (Some(1_400), Some(close.as_str())));
    assert_eq!(rig.call("watch_tick", json!({}))["actions"], json!([]), "still pending: nothing to report");
    lag.release();
    // the next balance read settles it first
    let hot = rig.call("hot_address", json!({}));
    assert_eq!(hot["hot_sats"], 1_400 + 10_000 - 600 - 546, "{hot}");
    assert_eq!(hot["hot_pending_close_change"], json!([]));
    // never counted twice: ticks, restart, reconcile
    rig.call("watch_tick", json!({}));
    rig.restart().unwrap();
    rig.call("hot_reconcile", json!({}));
    rig.call("watch_tick", json!({}));
    assert_eq!(rig.hot_sats(), 1_400 + 8_854);
    assert_eq!(rig.channel(&r["chan"].as_str().unwrap().to_string())["close_change"], "counted");
}

#[test]
fn a_close_confirmed_before_it_is_ever_in_our_mempool_is_found_by_gettxout() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    let lag = lagging(&rig);
    rig.fund_hot(1, 12_000);
    rig.open();
    rig.pay();
    lag.hold.store(true, Ordering::SeqCst);
    let r = rig.call("close_channel", json!({"counterparty": PROVIDER}));
    assert_eq!(r["close_change"], "pending");
    lag.release();
    rig.chain.mine(1);
    let acts = rig.call("watch_tick", json!({}))["actions"].clone();
    assert_eq!(acts[0]["close_change"], "counted", "{acts}");
    assert_eq!(rig.hot_sats(), 1_400 + 10_000 - 600 - 1_000);
}

#[test]
fn a_change_already_spent_is_final_and_never_counted() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    let lag = lagging(&rig);
    rig.fund_hot(1, 12_000);
    rig.open();
    let hot_spk = rig.hot_spk();
    lag.hold.store(true, Ordering::SeqCst);
    let r = rig.call("close_channel", json!({"counterparty": PROVIDER}));
    lag.release();
    // someone spends the change before we count it (a swept copy of the key, a test double)
    let close = r["txid"].as_str().unwrap().to_string();
    let n = rig.chain.tx(&close).outputs.iter().position(|o| hex::encode(&o.script_pubkey) == hot_spk).unwrap() as u32;
    rig.chain.st.lock().unwrap().utxos.remove(&(close.clone(), n));
    rig.call("watch_tick", json!({}));
    assert_eq!(rig.channel(&r["chan"].as_str().unwrap().to_string())["close_change"], "spent");
    assert_eq!(rig.hot_sats(), 1_400);
}
