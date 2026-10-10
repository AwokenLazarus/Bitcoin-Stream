//! AGP-066 L5: the CPU the funding proof spends reading which signatures each input's script checks
//! (`ln_funding::checked_sighashes`), for one funding transaction of 10 inputs: P2WPKH, 2-of-3 P2WSH,
//! P2SH-P2WPKH and P2TR key path. Median of 5 rounds. `cargo run --release -p xbt-signer --example ln_funding_cost`.
use std::time::Instant;

use sha2::{Digest, Sha256};
use xbt_primitives::tx::{OutPoint, TxIn};
use xbt_signer::ln_funding::checked_sighashes;

fn der() -> Vec<u8> {
    [vec![0x30, 0x45, 0x02, 0x21, 0x00], vec![1u8; 32], vec![0x02, 0x20], vec![2u8; 32], vec![0x21]].concat()
}

fn input(witness: Vec<Vec<u8>>, script_sig: Vec<u8>) -> TxIn {
    let mut i = TxIn::new(OutPoint::new([3; 32], 0), 0xffff_fffd);
    i.witness = witness;
    i.script_sig = script_sig;
    i
}

fn main() {
    let ms = [vec![0x52, 0x21], vec![2; 33], vec![0x21], vec![3; 33], vec![0x21], vec![4; 33], vec![0x53, 0xae]].concat();
    let wsh = [vec![0u8, 0x20], Sha256::digest(&ms).to_vec()].concat();
    let wpkh = [vec![0u8, 0x14], vec![5; 20]].concat();
    let p2sh = [vec![0xa9, 0x14], vec![6; 20], vec![0x87]].concat();
    let tr = [vec![0x51u8, 0x20], vec![7; 32]].concat();
    let kinds = [
        (input(vec![der(), vec![2; 33]], vec![]), wpkh.clone()),
        (input(vec![vec![], der(), der(), ms.clone()], vec![]), wsh),
        (input(vec![der(), vec![2; 33]], [vec![22u8], wpkh].concat()), p2sh),
        (input(vec![[vec![8; 64], vec![0x21]].concat()], vec![]), tr),
    ];
    let tx: Vec<&(TxIn, Vec<u8>)> = kinds.iter().cycle().take(10).collect();
    let n = 20_000u32;
    let mut rounds: Vec<f64> = (0..5)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..n {
                for (inp, spk) in &tx {
                    std::hint::black_box(checked_sighashes(std::hint::black_box(inp), spk).is_ok());
                }
            }
            t.elapsed().as_secs_f64() * 1e6 / n as f64
        })
        .collect();
    rounds.sort_by(f64::total_cmp);
    println!("{{\"checked_sighashes_10_inputs_us\": {:.2}}}", rounds[2]);
}
