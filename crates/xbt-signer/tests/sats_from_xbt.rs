//! AGP-036: sats_from_xbt parses sub-0.0001 XBT exactly; quote_payment for 0.00001 works.
mod common;

use common::*;
use serde_json::{json, Value};
use xbt_signer::signer::{
    sats_from_xbt, ERR_NEGATIVE, ERR_NOT_DECIMAL, ERR_NOT_FINITE, ERR_PRECISION,
};

fn n(v: Value) -> std::result::Result<i64, &'static str> {
    sats_from_xbt(Some(&v))
}

#[test]
fn tiny_amounts_are_exact() {
    assert_eq!(n(json!(0.00001)), Ok(1000));
    assert_eq!(n(json!(1e-5)), Ok(1000));
    assert_eq!(n(json!("1e-05")), Ok(1000));
    assert_eq!(n(json!(0.00000001)), Ok(1));
    assert_eq!(n(json!("0.00000001")), Ok(1));
}

#[test]
fn max_supply_and_ordinary_values() {
    assert_eq!(n(json!(21e6)), Ok(2_100_000_000_000_000));
    assert_eq!(n(json!("21e6")), Ok(2_100_000_000_000_000));
    assert_eq!(n(json!(0)), Ok(0));
    assert_eq!(n(json!("0")), Ok(0));
    assert_eq!(n(json!(1)), Ok(100_000_000));
    assert_eq!(n(json!(0.5)), Ok(50_000_000));
    assert_eq!(n(json!(".5")), Ok(50_000_000));
    assert_eq!(n(json!("0.00000546")), Ok(546));
    assert_eq!(n(json!(2.00000001)), Ok(200_000_001));
    assert_eq!(sats_from_xbt(None), Ok(0));
}

#[test]
fn ninth_place_is_refused_not_truncated() {
    assert_eq!(n(json!(0.000000001)), Err(ERR_PRECISION));
    assert_eq!(n(json!("0.000000001")), Err(ERR_PRECISION));
    assert_eq!(n(json!("0.123456789")), Err(ERR_PRECISION));
}

#[test]
fn negatives_nan_inf_and_garbage() {
    assert_eq!(n(json!(-1)), Err(ERR_NEGATIVE));
    assert_eq!(n(json!("-1")), Err(ERR_NEGATIVE));
    assert_eq!(n(json!(-0.00001)), Err(ERR_NEGATIVE));
    assert_eq!(n(json!("nan")), Err(ERR_NOT_FINITE));
    assert_eq!(n(json!("NaN")), Err(ERR_NOT_FINITE));
    assert_eq!(n(json!("inf")), Err(ERR_NOT_FINITE));
    assert_eq!(n(json!("Infinity")), Err(ERR_NOT_FINITE));
    assert_eq!(n(json!("-Infinity")), Err(ERR_NOT_FINITE));
    assert_eq!(n(json!("abc")), Err(ERR_NOT_DECIMAL));
    assert_eq!(n(json!("1.x")), Err(ERR_NOT_DECIMAL));
    assert_eq!(n(json!(true)), Err(ERR_NOT_DECIMAL));
}

#[test]
fn quote_payment_for_1e_5_xbt() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"allowlist": [PROVIDER], "max_per_tx_sats": 10_000_000, "human_threshold_sats": 10_000_000}), false);
    let out = rig.call("quote_payment", json!({"to": PROVIDER, "amount_xbt": 0.00001, "memo": "agp-036"}));
    assert_eq!(out["amount_sats"], 1000, "{out}");
    assert_eq!(out["dest"], PROVIDER);
    assert_eq!(out["verdict"], "allow", "{out}");
    assert_eq!(out["fee_estimate"]["feerate"], 0.00001);

    let again = rig.call("quote_payment", json!({"to": PROVIDER, "amount_xbt": "1e-05"}));
    assert_eq!(again["amount_sats"], 1000, "{again}");

    let err = rig.s.handle("quote_payment", &json!({"to": PROVIDER, "amount_xbt": -1})).unwrap_err();
    assert_eq!(err.code, "bad_request");
    assert_eq!(err.msg, ERR_NEGATIVE);
}
