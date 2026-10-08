//! AGP-063 (Guida W): the seller does not decide the budget (W1), minCapacity cannot raise the cap
//! (W2), a process on the agent socket cannot send coins anywhere but the seller's verified terms
//! nor refuse or rotate for the human (W3), nor enrol its own approval key (W4); the library payer
//! never signs below its watermark.
mod common;

use std::sync::Arc;

use common::*;
use serde_json::{json, Value};
use xbt402::channel::{ChannelParams, FeePayer, Payer};
use xbt402::conditional::ConditionalParams;
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::wire::{body_hash, receipt_message, request_digest_v2, settlement_response, SCHEME};
use xbt_primitives::ecdsa;
use xbt_signer::channels::ChannelRecord;
use xbt_signer::session::Session;

fn ledger_sum(rig: &Rig) -> i64 {
    let path = rig.root.join(".run/ledger.payments.jsonl");
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    text.lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v.get("dest").is_some())
        .map(|v| v["amount_sats"].as_i64().unwrap_or(0))
        .sum()
}

fn provider(chain: &Arc<FakeChain>, min_capacity: u64, charge: i64) -> Arc<Provider> {
    let mut cfg = ProviderConfig::new(&chain.network());
    cfg.policy.min_capacity = min_capacity;
    cfg.policy.max_capacity = min_capacity;
    cfg.policy.min_expiry_blocks = 1_008;
    cfg.policy.min_conf = 1;
    Arc::new(Provider::new(Arc::new(ProviderChain(chain.clone())), secret("provider payTo"), cfg, Ledger::in_memory(),
                           Box::new(|_, _| 500),
                           Box::new(|_, p, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())],
                                                                  json!({"echo": p}).to_string().into_bytes()))).unwrap()
        .with_charge(Box::new(move |_, _, _, _| charge)))
}

#[test]
fn w1_a_seller_reporting_zero_still_books_the_signed_delta() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    let hostile = provider(&rig.chain, 10_000, 0);
    rig.web.sites.lock().unwrap().insert(PROVIDER.into(), hostile);
    rig.fund_hot(1, 12_000);
    let r = rig.open();
    assert_eq!(r["verdict"], "allow", "{r}");
    assert_eq!(r["charged_sats"], 0, "the seller's receipt said nothing was charged: {r}");
    let booked = r["booked_sats"].as_i64().unwrap();
    let cum = r["cum"].as_i64().unwrap();
    assert!(booked > 0 && booked == cum, "the wallet books what it signed ({cum}), not the receipt: {r}");
    assert_eq!(ledger_sum(&rig), booked, "the policy ledger holds the signed delta");
}

#[test]
fn w1_w2_a_huge_min_capacity_and_a_zero_receipt_are_stopped_by_the_owners_cap() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    let hostile = provider(&rig.chain, 1_000_000_000, 0);
    rig.web.sites.lock().unwrap().insert(PROVIDER.into(), hostile);
    rig.fund_hot(1, 12_000);
    let before = rig.hot_sats();
    let r = rig.pay();
    assert_eq!((r["verdict"].as_str(), r["rule"].as_str()), (Some("deny"), Some("min_capacity")), "{r}");
    assert!(r["reason"].as_str().unwrap_or("").contains("minCapacity"), "{r}");
    assert_eq!(ledger_sum(&rig), 0, "nothing was booked");
    assert_eq!(rig.hot_sats(), before, "the inflated channel was not funded");
    assert!(rig.call("channels", json!({}))["channels"].as_array().unwrap().is_empty());
}

#[test]
fn w1_a_negative_or_oversized_charged_is_refused() {
    let sk = secret("payee");
    let pk = ecdsa::pubkey(&sk);
    let rec = ChannelRecord { chan: "chan".into(), payee_pub: hex::encode(pk), used_sats: 546, ..Default::default() };
    let url = URL;
    let req = request_digest_v2("GET", url, b"");
    let resp = |charged: &str| {
        let mut r = json!({"scheme": SCHEME, "chan": "chan", "seq": "1", "cum": "546", "charged": charged, "spentMsat": "0", "req": req,
                           "status": 200, "bodyHash": body_hash(b"ok")});
        r["sig"] = hex::encode(ecdsa::sign(&sk, &receipt_message(&r))).into();
        settlement_response(&r, "net", &hex::encode(pk), true)
    };
    let neg = Session::check_seller_receipt(&rec, &resp("-5"), "GET", url, b"", (200, b"ok"), 500).unwrap_err();
    assert_eq!(neg.code, "bad_receipt");
    assert!(neg.msg.contains("negative"), "{}", neg.msg);
    let over = Session::check_seller_receipt(&rec, &resp("9000"), "GET", url, b"", (200, b"ok"), 500).unwrap_err();
    assert!(over.msg.contains("exceeds"), "{}", over.msg);
    assert_eq!(Session::check_seller_receipt(&rec, &resp("0"), "GET", url, b"", (200, b"ok"), 500).unwrap(), 0);
}

/// W1/K1: a policy payment over a channel books what the wallet signs, before it signs: the dust
/// floor on the first state, nothing for a later charge the floor already covers.
#[test]
fn w1_a_channel_payment_books_the_signed_delta_ahead_of_the_signature() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"counterparties": {PROVIDER: {"pay_to": hex::encode(seller_pay_to())}}, "split_window_s": 0}), false);
    rig.fund_hot(1, 12_000);
    let r = rig.call("pay", json!({"to": PROVIDER, "amount_sats": 100, "memo": "a"}));
    assert_eq!((r["verdict"].as_str(), r["rail"].as_str()), (Some("allow"), Some("channel")), "{r}");
    let floor = r["cum"].as_i64().unwrap();
    assert!(floor > 100, "the first state is the dust floor: {r}");
    assert_eq!(ledger_sum(&rig), floor, "the ledger holds the signed floor, not the 100 asked: {r}");
    let r = rig.call("pay", json!({"to": PROVIDER, "amount_sats": 100, "memo": "b"}));
    assert_eq!((r["verdict"].as_str(), r["cum"].as_i64()), (Some("allow"), Some(floor)), "{r}");
    assert_eq!(ledger_sum(&rig), floor, "a charge inside the signed floor books nothing new");
    let r = rig.call("pay", json!({"to": PROVIDER, "amount_sats": 400, "memo": "c"}));
    let cum = r["cum"].as_i64().unwrap();
    assert_eq!(cum, 600, "{r}");
    assert_eq!(ledger_sum(&rig), cum);
    let rows = std::fs::read_to_string(rig.root.join(".run/ledger.payments.jsonl")).unwrap();
    assert!(rows.contains(&format!("xbt402:{}:{cum}", r["chan"].as_str().unwrap())), "booked under the signed state's id");
}

/// W1: on an open channel the budget is held to the increase the call signs, so a call that
/// fits exactly is paid even though max_sats alone would not fit.
#[test]
fn w1_the_budget_is_checked_on_the_signed_increase_not_max_sats() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"daily_budget_sats": 1_000, "weekly_budget_sats": 1_000}), false);
    rig.fund_hot(1, 12_000);
    let r = rig.open();
    assert_eq!(r["cum"], 546, "{r}");
    let r = rig.pay();
    assert_eq!((r["verdict"].as_str(), r["cum"].as_i64(), r["booked_sats"].as_i64()), (Some("allow"), Some(1_000), Some(454)), "{r}");
    assert_eq!(ledger_sum(&rig), 1_000);
    let r = rig.pay();
    assert_eq!((r["verdict"].as_str(), rule(&r)), (Some("deny"), "daily_budget"), "{r}");
    assert_eq!(ledger_sum(&rig), 1_000);
}

/// W1: a channel's first state signs the dust floor even for a smaller price; that floor must
/// fit the budget too, on both rails, or nothing is signed or booked.
#[test]
fn w1_a_dust_floor_above_the_remaining_budget_is_refused() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"daily_budget_sats": 520, "weekly_budget_sats": 520}), false);
    rig.fund_hot(1, 12_000);
    assert_eq!(rig.pay()["verdict"], "pending");
    rig.chain.mine(1);
    let r = rig.pay();
    assert_eq!((r["verdict"].as_str(), rule(&r)), (Some("deny"), "daily_budget"), "{r}");
    assert!(r["reason"].as_str().unwrap_or("").contains("dust floor"), "{r}");
    assert_eq!(ledger_sum(&rig), 0, "the floor was neither booked nor signed");
}

#[test]
fn w1_the_dust_floor_on_the_pay_rail_is_held_to_the_budget() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"counterparties": {PROVIDER: {"pay_to": hex::encode(seller_pay_to())}}, "split_window_s": 0,
                              "daily_budget_sats": 300, "weekly_budget_sats": 300}), false);
    rig.fund_hot(1, 12_000);
    let r = rig.call("pay", json!({"to": PROVIDER, "amount_sats": 100, "memo": "a"}));
    assert_eq!((r["verdict"].as_str(), rule(&r)), (Some("deny"), "daily_budget"), "{r}");
    assert_eq!(ledger_sum(&rig), 0);
    let chans = rig.call("channels", json!({}));
    assert!(chans["channels"].as_array().unwrap().iter().all(|c| c["used_sats"] == 0), "nothing signed: {chans}");
}

fn rule(v: &Value) -> &str {
    v["rule"].as_str().unwrap_or("")
}

fn issued(rig: &Rig, origin: &str) -> Vec<u8> {
    hex::decode(rig.call("xbt402_new_key", json!({"origin": origin}))["pub"].as_str().unwrap()).unwrap()
}

/// The channel an external client derives for `payer_pub` (unfunded).
fn client_params(rig: &Rig, pay_to: &[u8], payer_pub: &[u8], blocks: u64, payer_spk: Vec<u8>) -> ChannelParams {
    ChannelParams::derive(pay_to, payer_pub, (rig.chain.height() + blocks) as u32, 300, Some(payer_spk), &rig.chain.network(), FeePayer::Payer).unwrap()
}

fn seller_pay_to() -> Vec<u8> {
    ecdsa::pubkey(&secret("provider payTo")).to_vec()
}

fn attacker() -> Vec<u8> {
    ecdsa::pubkey(&secret("attacker")).to_vec()
}

fn fund(rig: &Rig, origin: &str, p: &ChannelParams, sats: i64) -> Value {
    rig.call("fund", json!({"origin": origin, "params": p.to_json(), "sats": sats}))
}

#[test]
fn w3_fund_pays_only_a_channel_for_an_issued_key_to_the_sellers_verified_terms() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    let before = rig.hot_sats();
    let hot = hex::decode(rig.hot_spk()).unwrap();
    assert_eq!(rule(&rig.call("fund", json!({"address": "bcrt1qattacker", "sats": 5_000}))), "fund_unbound");
    let key = issued(&rig, PROVIDER);
    assert_eq!(rule(&fund(&rig, PROVIDER, &client_params(&rig, &attacker(), &key, 1_014, hot.clone()), 5_000)), "pay_to", "a payee not from the seller's terms");
    assert_eq!(rule(&fund(&rig, PROVIDER, &client_params(&rig, &seller_pay_to(), &key, 1_014, vec![0; 22]), 5_000)), "payer_spk");
    assert_eq!(rule(&fund(&rig, PROVIDER, &client_params(&rig, &seller_pay_to(), &attacker(), 1_014, hot.clone()), 5_000)), "bad_key");
    assert_eq!(rule(&fund(&rig, PROVIDER, &client_params(&rig, &seller_pay_to(), &key, 100_000, hot.clone()), 5_000)), "expiry");
    let good = client_params(&rig, &seller_pay_to(), &key, 1_014, hot.clone());
    assert_eq!(rule(&fund(&rig, PROVIDER, &good, 50_000)), "channel_cap", "above per_counterparty_cap_sats");
    let elsewhere = "http://127.0.0.1:1";
    let k2 = issued(&rig, elsewhere);
    assert_eq!(rule(&fund(&rig, elsewhere, &client_params(&rig, &seller_pay_to(), &k2, 1_014, hot.clone()), 5_000)), "allowlist");
    assert_eq!(rig.hot_sats(), before, "nothing was paid");
    // the client's own channel: funded, written ahead as pending (refunded at expiry), opened by attach
    let r = fund(&rig, PROVIDER, &good, 9_000);
    assert!(r["txid"].is_string(), "{r}");
    assert_eq!(rule(&fund(&rig, PROVIDER, &good, 9_000)), "bad_key", "an issued key funds one channel");
    let k3 = issued(&rig, PROVIDER);
    assert_eq!(rule(&fund(&rig, PROVIDER, &client_params(&rig, &seller_pay_to(), &k3, 1_014, hot.clone()), 9_000)), "channel_pending");
    let funded = good.clone().with_funding(r["txid"].as_str().unwrap(), 0, 9_000).unwrap();
    let foreign = client_params(&rig, &seller_pay_to(), &attacker(), 1_014, hot.clone()).with_funding(&"ee".repeat(32), 0, 9_000).unwrap();
    assert_eq!(rule(&rig.call("xbt402_attach", json!({"origin": PROVIDER, "params": foreign.to_json()}))), "unknown_channel");
    let a = rig.call("xbt402_attach", json!({"origin": PROVIDER, "params": funded.to_json()}));
    assert_eq!(a["chan"], funded.channel_id(), "{a}");
    assert_eq!(rig.channel(&funded.channel_id())["state"], "open");
}

#[test]
fn w3_open_channel_takes_pay_to_only_from_the_policy() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"counterparties": {PROVIDER: {"pay_to": hex::encode(seller_pay_to())}}}), false);
    rig.fund_hot(1, 12_000);
    let before = rig.hot_sats();
    assert_eq!(rule(&rig.call("open_channel", json!({"dest": PROVIDER, "pay_to": hex::encode(attacker())}))), "pay_to");
    assert_eq!(rule(&rig.call("open_channel", json!({"dest": PROVIDER, "cap_sats": 50_000}))), "channel_cap");
    assert_eq!(rule(&rig.call("open_channel", json!({"dest": PROVIDER, "expiry_blocks": 100_000}))), "expiry");
    assert_eq!(rule(&rig.call("open_channel", json!({"dest": "http://127.0.0.1:1"}))), "allowlist");
    assert_eq!(rig.hot_sats(), before);
}

#[test]
fn w3_a_rollover_goes_only_into_the_channels_own_next_channel() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    let r = rig.open();
    let chan = r["chan"].as_str().unwrap().to_string();
    let rec = rig.s.book.get(&xbt_signer::policy::normalize_dest(PROVIDER)).unwrap();
    let cur = rec.params().unwrap();
    let amount = rec.used_sats as u64;
    let hot = hex::decode(rig.hot_spk()).unwrap();
    let next_origin = format!("{}/next", rec.origin);
    let key = issued(&rig, &next_origin);
    let next_cap = cur.rollover_next_capacity(amount);
    let roll = |next: Option<&ChannelParams>, spk: &[u8], cap: u64| {
        let mut p = json!({"chan": chan, "amount": amount, "next_spk": hex::encode(spk), "next_capacity": cap});
        if let Some(n) = next {
            p["next"] = n.to_json();
        }
        rig.call("xbt402_sign_rollover", p)
    };
    let theirs = vec![0x00, 0x14].into_iter().chain([7u8; 20]).collect::<Vec<u8>>();
    assert_eq!(rule(&roll(None, &theirs, next_cap)), "rollover_unbound", "a bare script is anyone's");
    let mk = |pay_to: &[u8], fee: u64| ChannelParams::derive(pay_to, &key, (rig.chain.height() + 1_014) as u32, fee, Some(hot.clone()), &rig.chain.network(), cur.close_fee_payer).unwrap();
    let wrong_payee = mk(&attacker(), cur.close_fee);
    assert_eq!(rule(&roll(Some(&wrong_payee), &wrong_payee.spk(), next_cap)), "pay_to");
    let good = mk(&seller_pay_to(), cur.close_fee);
    assert_eq!(rule(&roll(Some(&good), &theirs, next_cap)), "bad_rollover", "next_spk must be next's script");
    assert_eq!(rule(&roll(Some(&good), &good.spk(), next_cap - 1_000)), "bad_rollover", "the rest may not go to the fee");
    assert_eq!(rule(&roll(Some(&mk(&seller_pay_to(), cur.close_fee + 1)), &good.spk(), next_cap)), "bad_rollover");
    let ok = roll(Some(&good), &good.spk(), next_cap);
    assert!(ok["sig"].is_string(), "the channel's own next channel still rolls over: {ok}");
}

#[test]
fn w3_rotate_hot_key_and_deny_approval_need_the_human_signature() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    let hot = rig.hot_spk();
    assert_eq!(rule(&rig.call("rotate_hot_key", json!({}))), "human_sig");
    assert_eq!(rig.hot_spk(), hot, "not rotated");
    let r = rig.call("xbt402_pay", json!({"url": URL, "method": "GET", "body": "", "max_sats": 1000}));
    assert_eq!(r["verdict"], "needs_human", "{r}");
    let tok = r["approval_token"].as_str().unwrap().to_string();
    assert_eq!(rule(&rig.call("deny_approval", json!({"token": tok}))), "human_sig");
    assert_eq!(rig.call("approval_status", json!({"token": tok}))["state"], "pending", "the agent cannot refuse for the human");
    let exp = xbt_signer::pyjson::now_f64() as i64 + 300;
    let d = rig.call("deny_approval", json!({"token": tok, "expiry": exp, "signature": sign_human(&xbt_signer::approval::deny_message(&tok, exp))}));
    assert_eq!(d["state"], "denied", "{d}");
    assert_ne!(rig.rotate_hot_key()["new_address"], Value::Null);
    assert_ne!(rig.hot_spk(), hot);
}

#[test]
fn w4_the_first_human_key_needs_the_one_time_code() {
    use std::os::unix::fs::PermissionsExt;
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"human_pubkey": ""}), false);
    let f = rig.root.join(".run/enroll-code");
    assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
    let first = std::fs::read_to_string(&f).unwrap().trim().to_string();
    let pubhex = hex::encode(human().verifying_key().to_bytes());
    assert_eq!(rule(&rig.call("human_key_enroll", json!({"pubkey": pubhex}))), "enroll_code", "trust on first use is gone");
    for _ in 1..xbt_signer::admin::ENROLL_CODE_TRIES {
        assert_eq!(rule(&rig.call("human_key_enroll", json!({"pubkey": pubhex, "code": "0000-0000-0000"}))), "enroll_code");
    }
    let second = std::fs::read_to_string(&f).unwrap().trim().to_string();
    assert_ne!(first, second, "a new code after the tries run out");
    assert_eq!(rule(&rig.call("human_key_enroll", json!({"pubkey": pubhex, "code": first}))), "enroll_code", "the old code is dead");
    let r = rig.call("human_key_enroll", json!({"pubkey": pubhex, "code": second.to_lowercase().replace('-', "")}));
    assert_eq!(r["ok"], true, "{r}");
    assert!(!f.exists());
}

#[test]
fn wm_the_payer_never_signs_a3_or_conditional_states_below_its_watermark() {
    let a = secret("payer");
    let p = ChannelParams::derive(&seller_pay_to(), &ecdsa::pubkey(&a), 7_000, 300, None, "regtest", FeePayer::Payer).unwrap()
        .with_funding(&"ab".repeat(32), 0, 10_000).unwrap();
    let mut payer = Payer::new(p.clone(), a).unwrap();
    payer.sign_state(2_000).unwrap();
    assert_eq!(payer.sign_state_a3(1_000).unwrap_err().code, "stale_amount");
    payer.sign_state_a3(3_000).unwrap();
    assert_eq!(payer.signed, 3_000, "an 0xA3 state advances the watermark");
    let cond = ConditionalParams::new(p, [5u8; 32], 600, 10).unwrap();
    assert_eq!(payer.sign_conditional(2_500, &cond).unwrap_err().code, "stale_amount");
    payer.sign_conditional(3_000, &cond).unwrap();
    assert_eq!(payer.sign_state(2_999).unwrap_err().code, "stale_amount");
}
