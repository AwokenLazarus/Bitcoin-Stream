//! The CPU cost of the AGP-065 audit on the target itself (scripts: none; run it under the target's
//! emulator or on the device): the independent bounds, one block audit, the per-call credit walk and
//! a fraud-proof check, over a book of `INVOICES × RECEIPTS` live spans. Prints one JSON line.
use std::time::Instant;

use xbt_work::audit::{audit_block, check_fraud_proof, PrimeTerms, WindowStatement};
use xbt_work::book::ReceiptBook;
use xbt_work::chain::ChainBlock;
use xbt_work::receipt::{PrimeKey, WorkReceipt};

const PROV: &str = "bcrt1q76vavszzsq657n375vk6updhxm0tfay7k28cc3";
const INVOICES: u64 = 100;
const RECEIPTS: u64 = 10;
const TERMS: PrimeTerms = PrimeTerms { window: 8, window_min_work: 8000, window_tolerance_bps: 500, fee_bps: 0, max_min_payout: 546 };

/// Median microseconds per call of `f` over `n` calls, in 5 rounds.
fn micros(n: u32, mut f: impl FnMut()) -> f64 {
    let mut rounds: Vec<f64> = (0..5).map(|_| {
        let t = Instant::now();
        for _ in 0..n {
            f();
        }
        t.elapsed().as_secs_f64() * 1e6 / n as f64
    }).collect();
    rounds.sort_by(f64::total_cmp);
    rounds[2]
}

/// A 26-character base32 invoice id (§4.1) numbered `i`.
fn invoice(i: u64) -> String {
    let a = b"abcdefghijklmnopqrstuvwxyz234567";
    (0..26).map(|d| a[((i >> (5 * (d % 12))) & 31) as usize] as char).collect()
}

fn book(k: &PrimeKey, invoices: u64) -> ReceiptBook {
    let mut b = ReceiptBook::new(PROV, k.pubkey(), 70);
    for i in 0..invoices {
        let inv = invoice(i);
        for j in 1..=RECEIPTS {
            let h = 101 + (i * RECEIPTS + j) as u32;
            let r = WorkReceipt { seq: j, cum_work: j, shares: j, first_height: h, last_height: h, difficulty: 1, ..WorkReceipt::zero(70, PROV, &inv) };
            b.accept(&k.sign(&r).expect("sign"), &inv).expect("accept");
        }
    }
    b
}

fn main() {
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let height = 101 + (INVOICES * RECEIPTS) as u32 + 1;
    let block = ChainBlock { height, hash: format!("{height:064x}"), value_sats: 5_000_000_000, paid_sats: 0, bits: 0x1703_0ecd, prev_bits: 0x1703_0ecd };
    let s = WindowStatement { prime_id: 70, height, block_hash: block.hash.clone(), window_start: 100, window_work: 8000, min_payout: 546, fee_bps: 0 };
    let sw = k.sign_window(&s).expect("sign window");
    let mut out = serde_json::Map::new();
    for invoices in [1, INVOICES] {
        let b = book(&k, invoices);
        let bounds = TERMS.bounds(&block).expect("bounds");
        let proof = audit_block(&b, &sw, &block, &bounds, &[]).expect("audit").proof.expect("an unpaid block fails");
        let inv = &invoice(0);
        out.insert(format!("spans_{}", b.spans.len()), serde_json::json!({
            "bounds_us": micros(2000, || { std::hint::black_box(TERMS.bounds(std::hint::black_box(&block)).expect("bounds")); }),
            "audit_block_us": micros(20, || { std::hint::black_box(audit_block(&b, &sw, &block, &bounds, &[]).expect("audit")); }),
            "room_us": micros(200, || { std::hint::black_box(b.room(std::hint::black_box(inv))); }),
            "check_fraud_proof_us": micros(5, || { assert!(check_fraud_proof(&proof, &k.pubkey(), &block, &bounds)); }),
        }));
    }
    println!("{}", serde_json::json!({"arch": std::env::consts::ARCH, "cost": out}));
}
