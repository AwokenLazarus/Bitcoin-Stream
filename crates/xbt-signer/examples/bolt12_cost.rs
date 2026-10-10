//! AGP-082 pass line 6: the CPU of decode-and-check of a 1 KB BOLT 12 offer and its invoice, as `ln_pay`
//! does it: the offer string to its fields and id, its checks, the invoice string to its fields with the
//! Merkle root and the BIP-340 signature verified, and the invoice's checks against the offer. Median and
//! slowest of 5 rounds. `cargo run --release -p xbt-signer --example bolt12_cost`; for armv7, build with
//! `--target armv7-unknown-linux-musleabihf` and run the binary under `qemu-arm-static`.
use std::time::Instant;

use xbt_primitives::secp256k1::SecretKey;
use xbt_signer::bolt12::{self, encode, InvoiceTerms};

const NOW: u64 = 1_790_000_000;

fn main() {
    let key = |b: u8| SecretKey::from_slice(&[b; 32]).expect("a test key");
    let (issuer, payer, hop) = (key(0x41), key(0x51), encode::pubkey(&key(0x71)));
    let genesis = [0x22u8; 32];
    // an offer of 1,024 bytes: two blinded paths of three hops, an amount, an expiry, and a description
    // that fills the rest
    let fields = |desc: usize| {
        vec![(2u64, genesis.to_vec()), (8, encode::tu(250_000)), (10, vec![b'a'; desc]), (12, encode::features(&[512])), (14, encode::tu(NOW + 86_400)),
             (16, [encode::path(&hop, &hop, 3), encode::path(&hop, &hop, 3)].concat()), (18, b"Alice's coffee".to_vec()),
             (22, encode::pubkey(&issuer).to_vec())]
    };
    let desc = 1024 - (encode::stream(fields(300)).len() - 300);
    let offer = encode::offer(fields(desc));
    let o = bolt12::decode_offer(&offer).expect("the offer decodes");
    assert_eq!(o.tlv.len(), 1024);
    let invoice = encode::invoice(&encode::InvoiceSpec { offer_tlv: &o.tlv, chain: Some(genesis), payer_key: &payer, created_at: NOW - 10,
                                                         relative_expiry: Some(3600), payment_hash: [9; 32], amount_msat: 250_000,
                                                         features: &[17, 512], key: &issuer, node_id: None, cltv_expiry_delta: 40, extra: vec![] });
    let terms = InvoiceTerms { amount_msat: 250_000, genesis: &genesis, now: NOW as f64, min_expiry_s: 60, max_cltv_blocks: 1008 };
    let run = || {
        let o = bolt12::decode_offer(std::hint::black_box(&offer)).expect("offer");
        bolt12::check_offer(&o, &genesis, NOW as f64).expect("offer checks");
        let amount = bolt12::offer_amount_msat(&o, None).expect("amount");
        let inv = bolt12::decode_invoice(std::hint::black_box(&invoice)).expect("invoice");
        bolt12::check_invoice(&o, &inv, &InvoiceTerms { amount_msat: amount, ..terms }).expect("invoice checks");
        std::hint::black_box(inv.payment_hash);
    };
    run();
    let n: u32 = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(200);
    let mut worst = 0f64;
    let mut rounds: Vec<f64> = (0..5)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..n {
                let one = Instant::now();
                run();
                worst = worst.max(one.elapsed().as_secs_f64() * 1e3);
            }
            t.elapsed().as_secs_f64() * 1e3 / f64::from(n)
        })
        .collect();
    rounds.sort_by(f64::total_cmp);
    println!("{{\"offer_tlv_bytes\": {}, \"offer_chars\": {}, \"invoice_chars\": {}, \"decode_and_check_ms_median\": {:.4}, \"decode_and_check_ms_worst\": {:.4}, \"iterations\": {}}}",
             o.tlv.len(), offer.len(), invoice.len(), rounds[2], worst, 5 * n);
}
