//! AGP-084: AGP-079's stated limit, "an unpaid block with no statement leaves no verdict". It
//! still leaves none: the provider cannot tell the Prime's unpaid block from another pool's, and
//! most blocks of a chain are another pool's. What changed is that such blocks are counted while
//! credit is unpaid (the run since a coinbase last paid for any), that an operator can stop new
//! credit after N of them, and that a statement the Prime itself signed for an unpaid block, which
//! the audit refuses, is a failed audit: the Prime's signature says the block is its own.
//!
//! Every provider here runs `WorkConfig::shipped`, as in `agp077_closure_audit.rs`.
use serde_json::json;
use xbt_work::audit::{PrimeTerms, WindowStatement};
use xbt_work::chain::ChainBlock;
use xbt_work::provider::{Statement, WorkConfig, WorkProvider};
use xbt_work::receipt::{PrimeKey, WorkReceipt};

const NET: &str = "bip122:00000000000000000000000000000001";
const PROV: &str = "bcrt1q76vavszzsq657n375vk6updhxm0tfay7k28cc3";
const V: u64 = 5_000_000_000;
const TERMS: PrimeTerms = PrimeTerms { window: 8, window_min_work: 8000, window_tolerance_bps: 500, fee_bps: 0, max_min_payout: 546 };
const REGTEST_BITS: u32 = 0x207f_ffff;

fn config(k: &PrimeKey) -> WorkConfig {
    WorkConfig { terms: TERMS, ..WorkConfig::new(NET, PROV, 70, &k.pubkey_hex(), "http://prime.test/receipt") }.shipped(REGTEST_BITS, V, 150)
}
fn world() -> (PrimeKey, WorkProvider) {
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let wp = WorkProvider::new(config(&k)).unwrap();
    (k, wp)
}
fn inv(wp: &WorkProvider) -> String { wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string() }
fn credit(k: &PrimeKey, wp: &WorkProvider, inv: &str, seq: u64, cum: u64, first: u32, last: u32) -> u64 {
    let r = WorkReceipt { seq, cum_work: cum, shares: seq, first_height: first, last_height: last, difficulty: 1, ..WorkReceipt::zero(70, PROV, inv) };
    wp.accept(&k.sign(&r).unwrap()).unwrap()
}
fn hash(h: u32) -> String { format!("{h:064x}") }
fn stmt(height: u32, ws: u32, ww: u64) -> WindowStatement {
    WindowStatement { prime_id: 70, height, block_hash: hash(height), window_start: ws, window_work: ww, min_payout: 546, fee_bps: 0 }
}
fn block(height: u32, paid: u64) -> ChainBlock {
    ChainBlock { height, hash: hash(height), value_sats: V, paid_sats: paid, bits: REGTEST_BITS, prev_bits: REGTEST_BITS }
}
fn unpaid(wp: &WorkProvider) -> serde_json::Value { wp.report()["unpaidBlocks"].clone() }
fn missing(wp: &WorkProvider, heights: std::ops::RangeInclusive<u32>) {
    for h in heights {
        assert!(wp.audit_chain(&block(h, 0), Statement::Missing).unwrap().is_none(), "an unpaid block with no statement has no verdict");
    }
}

#[test]
fn p4_unpaid_blocks_with_no_statement_are_recorded_while_credit_is_unpaid() {
    let (k, wp) = world();
    // nothing is owed yet: an unpaid block is nobody's debt and is not counted
    missing(&wp, 100..=100);
    assert!(unpaid(&wp).is_null());
    let i = inv(&wp);
    credit(&k, &wp, &i, 1, 100, 101, 102);
    missing(&wp, 103..=109);
    assert_eq!(unpaid(&wp), json!({"from": 103, "to": 109, "count": 7, "refused": 0}),
               "seven blocks paid the identity nothing and had no statement while 100 units were unpaid: nothing was recorded");
    // walked again (the admin audit, a pass repeated after a node error): each block counts once
    missing(&wp, 103..=109);
    assert_eq!(unpaid(&wp)["count"], json!(7));
    // still no verdict: no audit record, no distrust, no freeze, and nothing covered
    let r = wp.report();
    assert_eq!((wp.exposure().0, r["audits"].as_array().unwrap().len()), (100, 0));
    assert!(r["distrust"].is_null() && r["credit"]["frozen"].is_null(), "{r}");
    // a coinbase pays for credit: the run ends, and the next unpaid block starts another
    assert!(wp.audit(&k.sign_window(&stmt(110, 100, 8400)).unwrap(), &[], &block(110, V * 100 / 8400)).unwrap().ok);
    assert!(unpaid(&wp).is_null());
    missing(&wp, 111..=111);
    assert_eq!(unpaid(&wp), json!({"from": 111, "to": 111, "count": 1, "refused": 0}));
}

#[test]
fn p4_a_statement_that_does_not_bind_the_prime_to_an_unpaid_block_is_no_statement() {
    // another key's signature, or the Prime's statement for another block: neither says this block
    // is the Prime's. No verdict; counted with the unpaid blocks, as refused
    let other = PrimeKey::from_seed(70, &[7u8; 32]);
    for why in ["another block", "wrong key"] {
        let (k, wp) = world();
        let i = inv(&wp);
        credit(&k, &wp, &i, 1, 100, 101, 102);
        let sw = match why {
            "another block" => k.sign_window(&WindowStatement { block_hash: hash(111), ..stmt(110, 100, 8000) }).unwrap(),
            _ => other.sign_window(&stmt(110, 100, 8000)).unwrap(),
        };
        assert!(wp.audit_chain(&block(110, 0), Statement::Found(&sw, &[])).unwrap().is_none(), "{why}");
        let r = wp.report();
        assert!(r["distrust"].is_null() && r["audits"].as_array().unwrap().is_empty(), "{why}: {r}");
        assert_eq!(unpaid(&wp), json!({"from": 110, "to": 110, "count": 1, "refused": 1}), "{why}");
        assert_eq!(wp.exposure().0, 100);
    }
}

#[test]
fn p4_a_statement_the_prime_signed_for_an_unpaid_block_and_the_audit_refuses_is_a_failed_audit() {
    // signed by the pinned key for this very block: the Prime says the block is its own, and gives
    // a statement no audit can run on. On a paid block that already failed (AGP-079); on an unpaid
    // one it left no verdict, so signed garbage was treated more gently than an honest statement
    for why in ["window_work 0", "regressed start"] {
        let (k, wp) = world();
        let i = inv(&wp);
        credit(&k, &wp, &i, 1, 100, 101, 102);
        wp.audit(&k.sign_window(&stmt(105, 104, 8000)).unwrap(), &[], &block(105, 0)).unwrap();
        let sw = match why {
            "window_work 0" => k.sign_window(&stmt(110, 104, 0)).unwrap(),
            _ => k.sign_window(&stmt(110, 100, 8000)).unwrap(),
        };
        let o = wp.audit_chain(&block(110, 0), Statement::Found(&sw, &[])).unwrap();
        let r = wp.report();
        assert!(o.is_some_and(|o| !o.ok), "{why}: no verdict for a block the Prime signed a refused statement for");
        assert_eq!(r["distrust"]["code"], json!("refused_statement"), "{why}: {r}");
        assert!(r["audits"].as_array().unwrap().iter().any(|a| a["height"] == json!(110) && a["ok"] == json!(false) && a["paidSats"] == json!(0)), "{why}: {r}");
        assert_eq!(wp.exposure().0, 100, "{why}: it covers nothing");
    }
}

#[test]
fn p4_unpaid_blocks_alone_never_distrust_or_stop_credit_under_the_shipped_defaults() {
    // they are every other pool's blocks too: two thousand of them say nothing about the Prime
    let (k, wp) = world();
    let i = inv(&wp);
    credit(&k, &wp, &i, 1, 50, 101, 102);
    missing(&wp, 103..=2102);
    let r = wp.report();
    assert_eq!(unpaid(&wp)["count"], json!(2000));
    assert!(r["distrust"].is_null() && r["credit"]["frozen"].is_null(), "{r}");
    assert_eq!(credit(&k, &wp, &i, 2, 80, 2103, 2104), 30, "credit goes on inside the caps");
}

#[test]
fn p4_an_operator_can_stop_new_credit_after_n_unpaid_blocks() {
    // --max-unpaid-blocks: for a provider that knows how often its Prime's pool finds a block
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let wp = WorkProvider::new(WorkConfig { max_unpaid_blocks: Some(6), ..config(&k) }).unwrap();
    let i = inv(&wp);
    credit(&k, &wp, &i, 1, 50, 101, 102);
    missing(&wp, 103..=107);
    assert!(wp.report()["credit"]["frozen"].is_null(), "five of six");
    assert_eq!(credit(&k, &wp, &i, 2, 60, 106, 107), 10);
    missing(&wp, 108..=108);
    let r = wp.report();
    assert_eq!(r["credit"]["frozen"], json!("unpaid_blocks"), "{r}");
    assert!(r["distrust"].is_null(), "a stop that a payment lifts, not a verdict: {r}");
    assert_eq!((credit(&k, &wp, &i, 3, 80, 108, 109), wp.exposure()), (0, (60, 20)), "new work is held, not credited");
    // a coinbase pays: credit goes on, and the held work is credited as far as the caps allow
    assert!(wp.audit(&k.sign_window(&stmt(110, 100, 8400)).unwrap(), &[], &block(110, V * 80 / 8400)).unwrap().ok);
    let r = wp.report();
    assert!(r["credit"]["frozen"].is_null() && unpaid(&wp).is_null(), "{r}");
    assert_eq!(wp.exposure().1, 0, "{r}");
}

#[test]
fn the_run_of_unpaid_blocks_survives_a_restart() {
    let dir = std::env::temp_dir().join(format!("xbt-work-agp084-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("work.json");
    let _ = std::fs::remove_file(&path);
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let cfg = WorkConfig { state_path: Some(path.clone()), max_unpaid_blocks: Some(3), ..config(&k) };
    let wp = WorkProvider::new(cfg.clone()).unwrap();
    let i = inv(&wp);
    credit(&k, &wp, &i, 1, 50, 101, 102);
    missing(&wp, 103..=105);
    drop(wp);
    let again = WorkProvider::new(cfg).unwrap();
    assert_eq!(unpaid(&again), json!({"from": 103, "to": 105, "count": 3, "refused": 0}));
    assert_eq!(again.report()["credit"]["frozen"], json!("unpaid_blocks"), "the stop is in force again after the restart");
    let _ = std::fs::remove_dir_all(&dir);
}
