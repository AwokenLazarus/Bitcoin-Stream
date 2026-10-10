//! AGP-077 closure audit, fixed by AGP-079: what the audit found open on main e1c71cc in the coinbase
//! audit (the review's P1 "the Prime controls the audit's inputs", P4). Each test states the outcome
//! the review asked for; all of them failed before AGP-079.
//!
//! Every provider here runs `WorkConfig::shipped`, the settings `xbt-work-provider` starts with when
//! no flag is set: no test passes because of a flag.
use serde_json::json;
use xbt_work::audit::{Deferral, PrimeTerms, WindowStatement};
use xbt_work::chain::ChainBlock;
use xbt_work::provider::{Statement, WorkConfig, WorkProvider};
use xbt_work::receipt::{PrimeKey, WorkReceipt};

const NET: &str = "bip122:00000000000000000000000000000001";
const PROV: &str = "bcrt1q76vavszzsq657n375vk6updhxm0tfay7k28cc3";
const V: u64 = 5_000_000_000;
const TERMS: PrimeTerms = PrimeTerms { window: 8, window_min_work: 8000, window_tolerance_bps: 500, fee_bps: 0, max_min_payout: 546 };
/// regtest: a 150-sat call costs one work unit, so the shipped caps are 100 units per invoice and 1000 in total
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
fn total_credited(wp: &WorkProvider) -> u64 { wp.book().credited.values().sum() }

/// P1: a Prime colluding with a payer signs receipts for work nobody mined, honest-looking
/// statements, and a deferral line for the whole expected payout. Every coinbase pays 0. The
/// credit must stay inside the total cap.
#[test]
fn p1_deferral_lines_do_not_release_credit_no_coinbase_paid_for() {
    let (k, wp) = world();
    let mut h = 100u32;
    for _round in 0..50 {
        let i = inv(&wp);
        let r = WorkReceipt { seq: 1, cum_work: 100, shares: 1, first_height: h + 1, last_height: h + 2, difficulty: 1, ..WorkReceipt::zero(70, PROV, &i) };
        if wp.accept(&k.sign(&r).unwrap()).is_err() {
            break; // refused: the caps bind
        }
        let s = stmt(h + 3, h, 8000);
        let d = Deferral { prime_id: 70, height: h + 3, block_hash: hash(h + 3), identity: PROV.into(), sats: V * 100 / 8000, reason: "over-budget".into() };
        let _ = wp.audit(&k.sign_window(&s).unwrap(), &[k.sign_deferral(&d).unwrap()], &block(h + 3, 0));
        h += 3;
    }
    assert!(total_credited(&wp) <= 1000, "{} units credited over a total cap of 1000 while every coinbase paid 0 (owed carry {} sats, frozen {})",
            total_credited(&wp), wp.carry().owed(), wp.report()["credit"]["frozen"]);
    // none of it is covered, and the shipped cap on owed carry stopped new credit after the first line
    assert_eq!((wp.exposure().0, total_credited(&wp)), (100, 100));
    assert_eq!(wp.report()["credit"]["frozen"], json!("carry_cap"));
}

/// P1: the same with the carry cap switched off (`--max-carry-sats off`): the deferral lines still
/// release nothing, so the cap on unaudited credit binds.
#[test]
fn p1_deferral_lines_release_nothing_even_without_a_carry_cap() {
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let wp = WorkProvider::new(WorkConfig { max_owed_carry_sats: None, ..config(&k) }).unwrap();
    for round in 0..50u32 {
        let h = 100 + 3 * round;
        let i = inv(&wp);
        credit(&k, &wp, &i, 1, 100, h + 1, h + 2);
        let d = Deferral { prime_id: 70, height: h + 3, block_hash: hash(h + 3), identity: PROV.into(), sats: V * 100 / 8000, reason: "over-budget".into() };
        assert!(wp.audit(&k.sign_window(&stmt(h + 3, h, 8000)).unwrap(), &[k.sign_deferral(&d).unwrap()], &block(h + 3, 0)).unwrap().ok);
    }
    assert_eq!((total_credited(&wp), wp.exposure()), (1000, (1000, 4000)));
}

/// P4: "a Prime can underpay a block and then 404 its statement". Seven pool blocks pay the
/// identity nothing and have no statement; one later block pays one block's share. The credit was
/// paid in one block of its window, not eight: it must not all be released.
#[test]
fn p4_unpaid_blocks_with_no_statement_do_not_vanish_from_the_audit() {
    let (k, wp) = world();
    let i = inv(&wp);
    credit(&k, &wp, &i, 1, 100, 101, 102);
    for h in 103..=109 {
        let _ = wp.audit_chain(&block(h, 0), Statement::Missing);
    }
    let _ = wp.audit(&k.sign_window(&stmt(110, 100, 8400)).unwrap(), &[], &block(110, V * 100 / 8400));
    assert!(wp.exposure().0 > 0 || !wp.report()["distrust"].is_null(),
            "100 units released (unaudited 0, no distrust) after 7 of 8 pool blocks paid nothing and published no statement");
    // the unpaid blocks left no verdict and covered nothing; the one that paid covers what it paid for
    assert_eq!((wp.exposure().0, wp.report()["audits"].as_array().unwrap().len()), (99, 1));
}

/// P4: a statement the audit refuses, on a block that underpaid the identity, is treated more
/// gently than no statement at all: no verdict, no distrust, and the next pass covers the credit.
#[test]
fn p4_a_refused_statement_on_an_underpaid_block_is_a_failed_audit() {
    let (k, wp) = world();
    let i = inv(&wp);
    credit(&k, &wp, &i, 1, 100, 101, 102);
    let sw = k.sign_window(&stmt(110, 100, 0)).unwrap(); // window_work 0: refused as bad_window
    let _ = wp.audit_chain(&block(110, 5), Statement::Found(&sw, &[]));
    assert!(!wp.report()["distrust"].is_null(), "a block that paid 5 sats with a refused statement left no failed audit and no distrust");
    // control: the same block with no statement does fail
    let (_k2, wp2) = world();
    assert!(!wp2.audit_chain(&block(110, 5), Statement::Missing).unwrap().unwrap().ok);
    // and the refused one is a failed audit that covers nothing
    assert_eq!(wp.report()["distrust"]["code"], json!("refused_statement"));
    assert_eq!(wp.exposure().0, 100);
}

/// P4: a refused statement on a block that paid the identity nothing covers nothing. Since
/// AGP-084 this one, which the Prime signed for the block, is also a failed audit (it was no
/// verdict); one that does not bind the Prime to the block still has none
/// (`agp084_unpaid_blocks.rs`).
#[test]
fn p4_a_refused_statement_on_an_unpaid_block_covers_nothing() {
    let (k, wp) = world();
    let i = inv(&wp);
    credit(&k, &wp, &i, 1, 100, 101, 102);
    let sw = k.sign_window(&stmt(110, 100, 0)).unwrap();
    assert!(wp.audit_chain(&block(110, 0), Statement::Found(&sw, &[])).unwrap().is_some_and(|o| !o.ok));
    assert_eq!((wp.exposure().0, wp.report()["audits"].as_array().unwrap().len()), (100, 1));
    assert_eq!(wp.report()["distrust"]["code"], json!("refused_statement"));
}

/// P4: every kind of statement the audit refuses (no window, another block, a window start that went
/// backwards, another key), on a block that paid the identity, counts as that block having no statement.
#[test]
fn p4_every_refused_statement_on_a_paid_block_distrusts_the_prime() {
    let other = PrimeKey::from_seed(70, &[7u8; 32]);
    for why in ["window_work 0", "another block", "regressed start", "wrong key"] {
        let (k, wp) = world();
        let i = inv(&wp);
        credit(&k, &wp, &i, 1, 100, 101, 102);
        // an audited block below, so a lower window start at 110 is a regression
        wp.audit(&k.sign_window(&stmt(105, 104, 8000)).unwrap(), &[], &block(105, 0)).unwrap();
        let sw = match why {
            "window_work 0" => k.sign_window(&stmt(110, 104, 0)).unwrap(),
            "another block" => k.sign_window(&WindowStatement { block_hash: hash(111), ..stmt(110, 104, 8000) }).unwrap(),
            "regressed start" => k.sign_window(&stmt(110, 100, 8000)).unwrap(),
            _ => other.sign_window(&stmt(110, 104, 8000)).unwrap(),
        };
        let _ = wp.audit_chain(&block(110, 5), Statement::Found(&sw, &[]));
        assert!(!wp.report()["distrust"].is_null(), "{why}: a paid block with a refused statement left no distrust");
        assert!(wp.report()["audits"].as_array().unwrap().iter().any(|a| a["height"] == json!(110) && a["ok"] == json!(false)), "{why}: no failed audit recorded");
    }
}

/// P1: the `min_payout` excuse. Each round's share of a small coinbase is below `min_payout`, so the
/// audit passes with nothing paid. The credit must stay inside the total cap.
#[test]
fn p1_the_min_payout_excuse_does_not_release_credit() {
    let (k, wp) = world();
    let mut h = 100u32;
    for _round in 0..500 {
        let i = inv(&wp);
        let r = WorkReceipt { seq: 1, cum_work: 4, shares: 1, first_height: h + 1, last_height: h + 2, difficulty: 1, ..WorkReceipt::zero(70, PROV, &i) };
        if wp.accept(&k.sign(&r).unwrap()).is_err() {
            break;
        }
        // V = 1,000,000: expected = 500 sats, under the 546 the terms allow
        let small = ChainBlock { value_sats: 1_000_000, ..block(h + 3, 0) };
        let o = wp.audit(&k.sign_window(&stmt(h + 3, h, 8000)).unwrap(), &[], &small).unwrap();
        assert!(o.ok && o.paid_sats == 0, "{o:?}");
        h += 3;
    }
    assert!(total_credited(&wp) <= 1000, "{} units credited over a total cap of 1000 while every coinbase paid 0", total_credited(&wp));
}

/// P1: `window_start` moved forward. One coinbase pays one block's share of the credit (an eighth
/// of what an honest window pays over its eight blocks); the next statements start their window
/// above the credit, so nothing more is ever expected. The credit must not all be released.
#[test]
fn p1_a_window_start_moved_forward_does_not_release_unpaid_credit() {
    let (k, wp) = world();
    let i = inv(&wp);
    credit(&k, &wp, &i, 1, 100, 101, 102);
    assert!(wp.audit(&k.sign_window(&stmt(110, 100, 8400)).unwrap(), &[], &block(110, V * 100 / 8400)).unwrap().ok);
    for h in 111..=117 {
        assert!(wp.audit(&k.sign_window(&stmt(h, h - 1, 8400)).unwrap(), &[], &block(h, 0)).unwrap().ok);
    }
    assert!(wp.exposure().0 > 0, "100 units released after one of eight blocks' shares was paid and the window start jumped over the credit");
}

/// Mainnet-shaped numbers under the shipped defaults: difficulty `1a00f0b5`, a 3.125 XBT coinbase, a
/// 150-sat call. A payer mines 80 calls' worth and the Prime's window is 8 x D.
struct Mainnet {
    k: PrimeKey,
    wp: WorkProvider,
    /// work units of one call, and of the 80 calls mined
    call: u64,
    mined: u64,
    window_work: u64,
}

const MAIN_BITS: u32 = 0x1a00_f0b5;
const MAIN_V: u64 = 312_500_000;

impl Mainnet {
    fn new() -> Self {
        let k = PrimeKey::from_seed(70, &[9u8; 32]);
        let terms = PrimeTerms::default();
        let cfg = WorkConfig { terms, ..WorkConfig::new(NET, PROV, 70, &k.pubkey_hex(), "http://prime.test/receipt") }.shipped(MAIN_BITS, MAIN_V, 150);
        let wp = WorkProvider::new(cfg).unwrap();
        let call = wp.amount(150).unwrap();
        let i = inv(&wp);
        assert_eq!(credit(&k, &wp, &i, 1, 80 * call, 101, 102), 80 * call);
        Self { k, wp, call, mined: 80 * call, window_work: terms.window_target(MAIN_BITS).unwrap() }
    }

    fn block(&self, height: u32, paid: u64) -> ChainBlock {
        ChainBlock { height, hash: hash(height), value_sats: MAIN_V, paid_sats: paid, bits: MAIN_BITS, prev_bits: MAIN_BITS }
    }

    /// One pool block's share of the mined work.
    fn share(&self) -> u64 {
        (u128::from(MAIN_V) * u128::from(self.mined) / u128::from(self.window_work)) as u64
    }

    fn audit(&self, height: u32, window_start: u32, paid: u64) -> bool {
        let s = WindowStatement { prime_id: 70, height, block_hash: hash(height), window_start, window_work: self.window_work, min_payout: 546, fee_bps: 0 };
        self.wp.audit(&self.k.sign_window(&s).unwrap(), &[], &self.block(height, paid)).unwrap().ok
    }
}

/// The honest case the fix must keep: the eight pool blocks of the window each pay the share, and
/// by the last one all the credit is paid for. After one block, an eighth of it is.
#[test]
fn an_honest_window_pays_for_all_the_credit_under_the_shipped_defaults() {
    let m = Mainnet::new();
    assert_eq!(m.wp.exposure().0, m.mined);
    assert!(m.audit(110, 100, m.share()));
    let after_one = m.wp.exposure().0;
    // 1/8 of the price, in work at a 10% haircut: 13.9% of the credit, 14% once rounded up to a unit
    assert!(after_one >= m.mined * 86 / 100 && after_one < m.mined * 87 / 100, "{after_one} of {} still unpaid after one block", m.mined);
    for h in 111..=117 {
        assert!(m.audit(h, 100, m.share()));
    }
    assert_eq!(m.wp.exposure().0, 0, "eight blocks' shares did not pay for the credit");
}

/// P1, `window_start` moved forward, in sats: the Prime pays one block's share (an eighth of the
/// price), then starts every window above the credit. Seven eighths of it stay unpaid for good.
#[test]
fn p1_one_block_of_eight_pays_for_an_eighth_under_the_shipped_defaults() {
    let m = Mainnet::new();
    assert!(m.audit(110, 100, m.share()));
    for h in 111..=130 {
        assert!(m.audit(h, h - 1, 0), "an empty window owes nothing");
    }
    let unpaid = m.wp.exposure().0;
    assert!(unpaid >= m.mined * 86 / 100, "{unpaid} of {} unpaid", m.mined);
    // new work is credited only inside the caps: one invoice's cap, then what the total cap leaves
    let (per_invoice, total) = (m.wp.cfg.caps.per_invoice.unwrap(), m.wp.cfg.caps.total.unwrap());
    let i2 = inv(&m.wp);
    assert_eq!(credit(&m.k, &m.wp, &i2, 1, 200 * m.call, 131, 132), per_invoice);
    for _ in 0..12 {
        let i = inv(&m.wp);
        credit(&m.k, &m.wp, &i, 1, 200 * m.call, 131, 132);
    }
    assert_eq!(m.wp.exposure().0, total, "unpaid credit went over the total cap");
}

/// A restart keeps the unpaid credit and the payments (state version 3): the caps bind as before.
#[test]
fn unpaid_credit_and_payments_survive_a_restart() {
    let dir = std::env::temp_dir().join(format!("xbt-work-agp079-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("work.json");
    let _ = std::fs::remove_file(&path);
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let cfg = WorkConfig { state_path: Some(path.clone()), ..config(&k) };
    let wp = WorkProvider::new(cfg.clone()).unwrap();
    let i = inv(&wp);
    credit(&k, &wp, &i, 1, 150, 101, 102);
    assert!(wp.audit(&k.sign_window(&stmt(110, 100, 8400)).unwrap(), &[], &block(110, V * 150 / 8400)).unwrap().ok);
    // the block paid for one unit, and one held unit took its place under the invoice's cap
    assert_eq!(wp.exposure(), (100, 49));
    drop(wp);
    let again = WorkProvider::new(cfg).unwrap();
    assert_eq!((again.exposure(), again.book().paid_work()), ((100, 49), 1));
    // the block is reorged out after the restart: its payment goes with it
    assert_eq!(again.orphaned(110).unwrap(), Some(1));
    assert_eq!(again.exposure(), (101, 49));
    let _ = std::fs::remove_dir_all(&dir);
}

/// State written before AGP-079 (version 2, spans): open credit loads as unpaid, and the blocks its
/// audits already resolved are not paid for a second time when the audit loop walks them again.
#[test]
fn state_from_before_agp079_does_not_count_old_payments_twice() {
    let dir = std::env::temp_dir().join(format!("xbt-work-agp079-v2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("work.json");
    let _ = std::fs::remove_file(&path);
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let cfg = WorkConfig { state_path: Some(path.clone()), ..config(&k) };
    let wp = WorkProvider::new(cfg.clone()).unwrap();
    let i = inv(&wp);
    credit(&k, &wp, &i, 1, 100, 101, 102);
    let paid = block(110, V * 100 / 8400);
    assert!(wp.audit(&k.sign_window(&stmt(110, 100, 8400)).unwrap(), &[], &paid).unwrap().ok);
    drop(wp);
    // the same state as AGP-065 wrote it: the span still open under the audit at 110
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    v["version"] = json!(2);
    let book = v["book"].as_object_mut().unwrap();
    for key in ["credits", "cover", "coverSettled", "settledThrough"] {
        book.remove(key);
    }
    book.insert("spans".into(), json!([[i, 101, 102, 100, 100, "open", 0]]));
    book.insert("settledSkipped".into(), json!(0));
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    let again = WorkProvider::new(cfg).unwrap();
    assert_eq!(again.exposure(), (100, 0));
    assert!(again.audit(&k.sign_window(&stmt(110, 100, 8400)).unwrap(), &[], &paid).unwrap().ok);
    assert_eq!(again.exposure().0, 100, "a block audited before the upgrade was paid for again");
    assert!(again.audit(&k.sign_window(&stmt(111, 100, 8400)).unwrap(), &[], &block(111, V * 100 / 8400)).unwrap().ok);
    assert_eq!(again.exposure().0, 99);
    let _ = std::fs::remove_dir_all(&dir);
}
