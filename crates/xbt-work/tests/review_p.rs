//! external review (AGP-065): the pay-with-work audit independent of the Prime. P1-P4 were written
//! against the AGP-043 API first and failed there; they keep their names. AGP-079: a pass covers
//! what the coinbase paid for, so the tests that release credit now pay for it.
use std::sync::Arc;

use serde_json::json;
use xbt_work::audit::{check_fraud_proof, AuditBounds, PrimeTerms, WindowStatement};
use xbt_work::book::CreditCaps;
use xbt_work::chain::{ChainBlock, LongMaturity, Maturity};
use xbt_work::payer::check_gateway_config;
use xbt_work::provider::{window_statement, Amount, Caps, Statement, WorkConfig, WorkProvider};
use xbt_work::receipt::{PrimeKey, WorkReceipt};

const NET: &str = "bip122:00000000000000000000000000000001";
const PROV: &str = "bcrt1q76vavszzsq657n375vk6updhxm0tfay7k28cc3";
const V: u64 = 5_000_000_000;
/// The Prime's regtest floor: the window holds 8000 work units, so the bound is 8400.
const TERMS: PrimeTerms = PrimeTerms { window: 8, window_min_work: 8000, window_tolerance_bps: 500, fee_bps: 0, max_min_payout: 546 };

/// A call costs one work unit and 5,000,000 sats: what a unit earns over the eight blocks of an
/// 8000-unit window that each pay `V / 8000` for it.
fn config(k: &PrimeKey) -> WorkConfig {
    WorkConfig { terms: TERMS, invoice_price_sats: 5_000_000, ..WorkConfig::new(NET, PROV, 70, &k.pubkey_hex(), "http://prime.test/receipt") }
}

fn world() -> (PrimeKey, WorkProvider, String) {
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let wp = WorkProvider::new(config(&k)).unwrap();
    let inv = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
    (k, wp, inv)
}

fn credit(k: &PrimeKey, wp: &WorkProvider, inv: &str, seq: u64, cum: u64, first: u32, last: u32) -> u64 {
    let r = WorkReceipt { seq, cum_work: cum, shares: seq, first_height: first, last_height: last, difficulty: 1, ..WorkReceipt::zero(70, PROV, inv) };
    wp.accept(&k.sign(&r).unwrap()).unwrap()
}

fn hash(height: u32) -> String {
    format!("{height:064x}")
}

fn stmt(height: u32, window_start: u32, window_work: u64, min_payout: u64, fee_bps: u32) -> WindowStatement {
    WindowStatement { prime_id: 70, height, block_hash: hash(height), window_start, window_work, min_payout, fee_bps }
}

/// The block at `height` as the provider's node has it (regtest difficulty).
fn block(height: u32, paid_sats: u64) -> ChainBlock {
    ChainBlock { height, hash: hash(height), value_sats: V, paid_sats, bits: 0x207f_ffff, prev_bits: 0x207f_ffff }
}

/// P1: a Prime colluding with a payer receipts 1000 units nobody mined, then signs statements that
/// drive `expected` to nothing. The coinbase pays the provider 0. The provider's bounds fail the
/// audit, and a third party holding the same terms convicts from the proof alone.
#[test]
fn p1_colluding_prime_statements_fail_the_audit() {
    for (why, s) in [("window_work inflated", stmt(110, 100, u64::MAX, 546, 0)),
                     ("fee_bps 10000", stmt(110, 100, 8000, 546, 10_000)),
                     ("min_payout above expected", stmt(110, 100, 8000, u64::MAX, 0))] {
        let (k, wp, inv) = world();
        assert_eq!(credit(&k, &wp, &inv, 4, 1000, 101, 103), 1000);
        let b = block(110, 0);
        let o = wp.audit(&k.sign_window(&s).unwrap(), &[], &b).unwrap();
        assert!(!o.ok && o.bounded, "{why}: the audit passed a coinbase that paid nothing");
        let proof = o.proof.as_ref().unwrap();
        assert!(check_fraud_proof(proof, &k.pubkey(), &b, &TERMS.bounds(&b).unwrap()), "{why}: the proof does not convict");
        assert!(!check_fraud_proof(proof, &k.pubkey(), &b, &AuditBounds::STATEMENT_ONLY), "{why}: convicts without the bounds");
        assert_eq!(proof["bounds"]["maxWindowWork"], json!(8400));
    }
}

/// P1: an honest statement inside the bounds is used as it is.
#[test]
fn p1_an_honest_statement_is_not_bounded() {
    let (k, wp, inv) = world();
    credit(&k, &wp, &inv, 4, 1000, 101, 103);
    let s = stmt(110, 100, 8350, 546, 0);
    let expected = V * 1000 / 8350;
    let o = wp.audit(&k.sign_window(&s).unwrap(), &[], &block(110, expected)).unwrap();
    assert!(o.ok && !o.bounded && o.window_work == 8350, "{o:?}");
    // AGP-079: the pass covers what the coinbase paid for (598.8M sats: 119 units), not the whole span
    assert_eq!(wp.exposure().0, 1000 - 119);
}

/// P1: window starts must not go backwards between audited blocks. The refused statement records
/// nothing and covers nothing.
#[test]
fn p1_window_start_is_monotonic() {
    let (k, wp, inv) = world();
    credit(&k, &wp, &inv, 4, 1000, 101, 103);
    let o = wp.audit(&k.sign_window(&stmt(110, 102, 8000, 546, 0)).unwrap(), &[], &block(110, 0)).unwrap();
    assert!(o.ok, "nothing proven, nothing owed");
    let e = wp.audit(&k.sign_window(&stmt(120, 100, 8000, 546, 0)).unwrap(), &[], &block(120, V / 8)).unwrap_err();
    assert_eq!(e.code, "window_start_regressed");
    assert_eq!((wp.exposure().0, wp.report()["audits"].as_array().unwrap().len()), (1000, 1));
}

/// P1: a pass under the min_payout clause owes what it did not pay, as the Prime's window does.
#[test]
fn p1_a_below_min_pass_is_owed_carry() {
    let (k, wp, inv) = world();
    credit(&k, &wp, &inv, 4, 1, 101, 103);
    let small = ChainBlock { value_sats: 1_000_000, ..block(110, 0) };
    let o = wp.audit(&k.sign_window(&stmt(110, 100, 8000, 546, 0)).unwrap(), &[], &small).unwrap();
    assert!(o.ok && o.expected_sats == 125, "{o:?}");
    assert_eq!((o.below_min_sats, wp.carry().owed()), (o.expected_sats, o.expected_sats));
}

/// P2: a pass releases only the credit its bound covered. window_start = 102 leaves [101,103]
/// outside the bound (L = 0), so the pass says nothing about it.
#[test]
fn p2_a_pass_releases_only_covered_credit() {
    let (k, wp, inv) = world();
    credit(&k, &wp, &inv, 4, 1000, 101, 103);
    let o = wp.audit(&k.sign_window(&stmt(110, 102, 8000, 546, 0)).unwrap(), &[], &block(110, 0)).unwrap();
    assert_eq!(o.proven_work, 0);
    assert_eq!(wp.exposure().0, 1000, "credit outside the audited bound was released");
    assert_eq!(wp.book().paid_work(), 0);
}

/// P4: a Prime that answers anything but 200 or 404 for a statement must not make the block
/// look like one it never stated.
#[test]
fn p4_a_statement_error_is_not_a_missing_statement() {
    use xbt402::client::Transport;
    use xbt402::provider::HttpResponse;
    struct Down(u16);
    impl Transport for Down {
        fn request(&self, _: &str, _: &str, _: &[u8], _: &[(String, String)]) -> xbt402::error::Result<HttpResponse> {
            Ok(HttpResponse::new(self.0, vec![], b"".to_vec()))
        }
    }
    assert!(window_statement(&Down(500), "http://prime.test/window", 110).is_err(), "a 500 read as no statement");
    assert!(window_statement(&Down(404), "http://prime.test/window", 110).unwrap().is_none());
}

/// P4: a missing statement is audited too: a coinbase that paid the identity with no statement
/// fails (and distrusts the Prime); one that paid nothing records nothing and covers nothing.
#[test]
fn p4_a_missing_statement_fails_or_holds() {
    let (k, wp, inv) = world();
    credit(&k, &wp, &inv, 4, 1000, 101, 103);
    assert!(wp.audit_chain(&block(110, 0), Statement::Missing).unwrap().is_none());
    assert_eq!(wp.exposure().0, 1000);
    let o = wp.audit_chain(&block(111, 600), Statement::Missing).unwrap().unwrap();
    assert!(!o.ok);
    assert_eq!(wp.report()["distrust"]["code"], json!("missing_statement"));
    assert_eq!(wp.exposure().0, 1000);
}

/// P3: a statement with the real block's hash but another height. height = u32::MAX with
/// window_start = u32::MAX - 1 has an empty bound and (on main) clears every unaudited credit.
#[test]
fn p3_statement_height_must_be_the_blocks() {
    let (k, wp, inv) = world();
    credit(&k, &wp, &inv, 4, 1000, 101, 103);
    let mut s = stmt(110, u32::MAX - 1, 8000, 546, 0);
    s.height = u32::MAX;
    let e = wp.audit(&k.sign_window(&s).unwrap(), &[], &block(110, 0)).unwrap_err();
    assert_eq!(e.code, "wrong_block");
    assert_eq!(wp.exposure().0, 1000, "a statement for height u32::MAX released credit");
    // and the right height with another block's hash
    let mut s = stmt(110, 100, 8000, 546, 0);
    s.block_hash = hash(111);
    assert_eq!(wp.audit(&k.sign_window(&s).unwrap(), &[], &block(110, V / 8)).unwrap_err().code, "wrong_block");
    // height = window_start + 1: the right block and an empty bound. It passes with nothing proven
    // and releases nothing.
    let o = wp.audit(&k.sign_window(&stmt(110, 109, 8000, 546, 0)).unwrap(), &[], &block(110, 0)).unwrap();
    assert!(o.ok && o.proven_work == 0, "{o:?}");
    assert_eq!(wp.exposure().0, 1000, "a statement with height = window_start + 1 released credit");
}

/// P6: a reorg undoes what the orphaned block's audit released.
#[test]
fn p6_a_reorg_rolls_back_released_credit() {
    let (k, wp, inv) = world();
    credit(&k, &wp, &inv, 4, 1000, 101, 103);
    // the coinbase pays the whole price of the credit at once (its share and the carry before it)
    let o = wp.audit(&k.sign_window(&stmt(110, 100, 8000, 546, 0)).unwrap(), &[], &block(110, V)).unwrap();
    assert!(o.ok);
    assert_eq!(wp.exposure().0, 0);
    assert_eq!(wp.audited_blocks(), vec![(110, hash(110))]);
    assert_eq!(wp.orphaned(110).unwrap(), Some(1000));
    assert_eq!((wp.exposure().0, wp.audited_blocks().len()), (1000, 0));
    assert_eq!(wp.orphaned(110).unwrap(), None);
}

/// P6: an unfunded invoice past its TTL stays dormant for the grace: work mined on it just before
/// expiry is still accepted and credited. Past the grace it is gone.
#[test]
fn p6_an_invoice_with_work_outlives_its_ttl() {
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let wp = WorkProvider::new(WorkConfig { invoice_ttl_secs: 0, ..config(&k) }).unwrap();
    let inv = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert!(wp.invoices().contains(&inv), "dormant invoices are still pulled");
    assert_eq!(credit(&k, &wp, &inv, 4, 1000, 101, 103), 1000);
    let gone = WorkProvider::new(WorkConfig { invoice_ttl_secs: 0, invoice_grace_secs: 0, ..config(&k) }).unwrap();
    let inv = gone.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    gone.issue_invoice().unwrap();
    assert!(!gone.invoices().contains(&inv));
}

/// P6: one client cannot take every unfunded invoice slot; dormant invoices give way to new ones.
#[test]
fn p6_issuance_is_limited_per_client() {
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let wp = WorkProvider::new(WorkConfig { max_unfunded_per_client: Some(2), ..config(&k) }).unwrap();
    wp.issue_invoice_for(Some("10.0.0.1")).unwrap();
    wp.issue_invoice_for(Some("10.0.0.1")).unwrap();
    assert_eq!(wp.issue_invoice_for(Some("10.0.0.1")).unwrap_err().code, "too_many_invoices");
    wp.issue_invoice_for(Some("10.0.0.2")).unwrap();
    let full = WorkProvider::new(WorkConfig { max_unfunded: 1, invoice_ttl_secs: 0, ..config(&k) }).unwrap();
    full.issue_invoice().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    full.issue_invoice().expect("the dormant invoice gives way");
}

/// P6: state is written outside the state lock; concurrent writers never leave an older snapshot
/// on disk.
#[test]
fn p6_concurrent_writes_keep_the_newest_state() {
    let dir = std::env::temp_dir().join(format!("xbt-work-review-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("state.json");
    let _ = std::fs::remove_file(&path);
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let wp = Arc::new(WorkProvider::new(WorkConfig { state_path: Some(path.clone()), ..config(&k) }).unwrap());
    let hs: Vec<_> = (0..8).map(|_| {
        let wp = wp.clone();
        std::thread::spawn(move || (0..20).map(|_| wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string()).collect::<Vec<_>>())
    }).collect();
    let issued: Vec<String> = hs.into_iter().flat_map(|h| h.join().unwrap()).collect();
    let again = WorkProvider::new(WorkConfig { state_path: Some(path.clone()), ..config(&k) }).unwrap();
    let mut live = again.invoices();
    live.sort();
    let mut want = issued;
    want.sort();
    assert_eq!(live, want);
    let _ = std::fs::remove_dir_all(&dir);
}

/// P2/P6: credit the Prime's window moved past before any coinbase paid for it counts against the
/// total cap for good; none of it is forgiven (AGP-079).
#[test]
fn p2_credit_the_window_moved_past_fills_the_total_cap() {
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let caps = CreditCaps { per_invoice: Some(1000), total: Some(1500) };
    let wp = WorkProvider::new(WorkConfig { caps, ..config(&k) }).unwrap();
    let inv = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
    assert_eq!(credit(&k, &wp, &inv, 4, 1000, 101, 103), 1000);
    assert!(wp.audit(&k.sign_window(&stmt(110, 103, 8000, 546, 0)).unwrap(), &[], &block(110, 0)).unwrap().ok);
    // all 1000 still count; a second invoice gets 500 of its 1000
    assert_eq!(wp.exposure().0, 1000);
    let inv2 = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
    assert_eq!(credit(&k, &wp, &inv2, 4, 1000, 104, 106), 500);
}

/// review P5: with no flag the binary caps unaudited credit and owed carry, on mainnet and on
/// regtest, and prices work exactly (`WorkConfig::shipped` is what `xbt-work-provider` starts from).
#[test]
fn p5_the_binary_ships_non_zero_caps() {
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    for (bits, v) in [(0x1702_3a6e_u32, 312_500_000u64), (0x207f_ffff, 5_000_000_000)] {
        let c = Caps::SHIPPED.at(bits, v, 150);
        let (inv, tot) = (c.per_invoice.expect("per-invoice cap"), c.total.expect("total cap"));
        assert!(inv > 0 && tot >= inv, "{bits:08x}: {c:?}");
        let cfg = config(&k).shipped(bits, v, 150);
        assert_eq!((cfg.caps, cfg.max_owed_carry_sats), (c, Some(150_000)));
        assert!(matches!(cfg.amount, Amount::Priced(_)));
    }
    assert_eq!(xbt_work::provider::Cap::Off.units(0x207f_ffff, 1, 1).unwrap(), None);
    let unconvertible = Caps { invoice: xbt_work::provider::Cap::Sats(150), total: xbt_work::provider::Cap::Off };
    assert_eq!(unconvertible.at(0, 1, 1), CreditCaps { per_invoice: Some(0), total: None }, "an unconvertible cap holds everything");
}

/// DATUM: the payer refuses a gateway that would not pass the username to the Prime.
#[test]
fn datum_gateway_must_pass_full_usernames() {
    assert!(check_gateway_config(&json!({"datum": {"pool_pass_full_users": true}})).is_ok());
    assert!(check_gateway_config(&json!({"datum": {}})).is_ok(), "the gateway's default is true");
    assert_eq!(check_gateway_config(&json!({"datum": {"pool_pass_full_users": false}})).unwrap_err().code, "gateway_config");
    assert!(check_gateway_config(&json!({"datum": {"pool_pass_full_users": "yes"}})).is_err());
}

/// M1: payouts are split by the node's coinbase maturity, never a hard-coded 100.
#[test]
fn m1_locked_payouts_are_paid_but_illiquid() {
    let (k, wp, inv) = world();
    credit(&k, &wp, &inv, 4, 1000, 101, 103);
    wp.audit(&k.sign_window(&stmt(110, 100, 8000, 546, 0)).unwrap(), &[], &block(110, V / 8)).unwrap();
    let ordinary = Maturity { long: None };
    assert_eq!(wp.payouts(208, &ordinary), (0, V / 8));
    assert_eq!(wp.payouts(209, &ordinary), (V / 8, 0));
    let long = Maturity { long: Some(LongMaturity { coinbase_start: 0, enforce: 0, end: 10_000, depth: 6480 }) };
    assert_eq!(wp.payouts(209, &long), (0, V / 8), "the node's long maturity locks it");
    assert_eq!(wp.payouts(6589, &long), (V / 8, 0));
}
