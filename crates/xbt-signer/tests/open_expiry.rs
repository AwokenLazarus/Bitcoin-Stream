//! AGP-076: the signer opens with `minExpiryBlocks + minConf + closeMarginBlocks` blocks to expiry
//! at least, every term from the offer (`xbt402::funding::open_expiry_blocks`; B2
//! `tests/test_agp076_open_expiry.py` has the same flows).
//!
//! The provider compares the blocks left with `min_expiry_blocks` at its own tip when the funded
//! open reaches it (`xbt402::funding::check_funding`), so every block between choosing the expiry
//! and that open comes off the payer's slack. AGP-074 answered a refusal with `minExpiryBlocks +
//! 36`, a number that mirrored one provider default and that no provider check reads.
mod common;

use common::*;
use serde_json::json;

// the runbook provider's offer
const MIN_EXPIRY: i64 = 1_008;
const MIN_CONF: i64 = 1;
const CLOSE_MARGIN: i64 = 144;

fn pending(rig: &Rig) -> (i64, i64) {
    rig.fund_hot(0xa1, 12_000);
    let h = rig.chain.height() as i64;
    let r = rig.pay();
    assert_eq!(r["verdict"], "pending", "{r}");
    let expiry = rig.call("channels", json!({}))["channels"][0]["expiry"].as_i64().unwrap();
    (h, expiry)
}

#[test]
fn the_signer_opens_at_the_offers_floor() {
    let _env = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    let (h, expiry) = pending(&rig);
    assert_eq!(expiry - h, MIN_EXPIRY + MIN_CONF + CLOSE_MARGIN);
}

/// The slack is all used: `closeMarginBlocks` pass before the funding's block, and the provider
/// sees exactly minExpiryBlocks left. At minExpiryBlocks + 36 (or + 6) it refuses `bad_expiry` on
/// every retry and the coins stay locked until the refund.
#[test]
fn a_funding_that_confirms_a_close_margin_late_still_opens() {
    let _env = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    let (_, expiry) = pending(&rig);
    rig.chain.mine((MIN_CONF + CLOSE_MARGIN) as u64);
    assert_eq!(expiry - rig.chain.height() as i64, MIN_EXPIRY);
    let r = rig.pay();
    assert_eq!((r["verdict"].as_str(), r["charged_sats"].as_i64()), (Some("allow"), Some(500)), "{r}");
    assert_eq!(r["opened"]["state"], "open");
}

/// The allowance ends where the rule says: one block more and the provider's own check refuses.
#[test]
fn one_block_later_the_provider_refuses() {
    let _env = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    pending(&rig);
    rig.chain.mine((MIN_CONF + CLOSE_MARGIN + 1) as u64);
    let r = rig.pay();
    assert_eq!(r["verdict"], "deny", "{r}");
    assert!(r["reason"].as_str().unwrap().contains("HTTP 400 bad_expiry"), "{r}");
    let c = rig.call("channels", json!({}))["channels"][0].clone();
    assert_eq!((c["state"].as_str(), c["open_error"].as_str()), (Some("pending"), Some("open refused: HTTP 400 bad_expiry")));
}
