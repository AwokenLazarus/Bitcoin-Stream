//! The CPU cost of light-client header validation (the AGP-069 pass line in the README): a
//! 4x2016-header catch-up through `connect` and through a streamed `Branch`, the checkpoint with
//! its priors, starting a branch, the plausibility check, and the real mainnet headers from 961640.
//!
//! `cargo run --release -p xbt-primitives --example header_cost`
use std::hint::black_box;
use std::time::Instant;
use xbt_primitives::header::{self, parse_header, v1_hash, ChainRules, HeaderChain, U512, V2_FLAG};

const REGTEST_BITS: u32 = 0x207F_FFFF;
const T0: u32 = 1_800_000_000;
const CHUNK: usize = 2016;
const CHUNKS: usize = 4;

fn mine(prev_display: [u8; 32], height: u32, time: u32) -> Vec<u8> {
    let rules = ChainRules::regtest();
    for nonce in 0u32.. {
        let mut b = Vec::with_capacity(164);
        b.extend((0x2000_0000u32 | V2_FLAG).to_le_bytes());
        let mut prev = prev_display;
        prev.reverse();
        b.extend(prev);
        b.extend([7u8; 32]);
        b.extend(time.to_le_bytes());
        b.extend(REGTEST_BITS.to_le_bytes());
        b.extend(nonce.to_le_bytes());
        b.extend([0u8; 28]);
        b.extend(1u16.to_le_bytes());
        b.extend([0u8; 18]);
        b.extend(height.to_le_bytes());
        b.extend([0u8; 32]);
        if header::check_pow(&parse_header(&b).expect("164 bytes"), &rules).is_ok() {
            return b;
        }
    }
    unreachable!()
}

fn v1(prev_display: [u8; 32], time: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(80);
    b.extend(0x2000_0000u32.to_le_bytes());
    let mut prev = prev_display;
    prev.reverse();
    b.extend(prev);
    b.extend([0x5Au8; 32]);
    b.extend(time.to_le_bytes());
    b.extend(REGTEST_BITS.to_le_bytes());
    b.extend(0u32.to_le_bytes());
    b
}

/// Seconds per run, the best of `runs`.
fn best(runs: usize, mut f: impl FnMut()) -> f64 {
    (0..runs)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_secs_f64()
        })
        .fold(f64::MAX, f64::min)
}

fn main() {
    let mut prior = vec![];
    let mut prev = [3u8; 32];
    for i in 0..10 {
        let raw = v1(prev, T0 - 100 + i);
        prev = v1_hash(&raw).expect("80 bytes");
        prior.push(raw);
    }
    let cp = mine(prev, 101, T0);
    let cp_hex = parse_header(&cp).expect("cp").hash_hex();
    let mut raws = vec![];
    let mut p = parse_header(&cp).expect("cp");
    for i in 0..(CHUNK * CHUNKS) as u32 {
        let raw = mine(p.hash, p.height + 1, T0 + 1 + i);
        p = parse_header(&raw).expect("mined");
        raws.push(raw);
    }
    let n = raws.len() as f64;
    let now = (T0 as u64) + raws.len() as u64 + 100;
    let fresh = || {
        let mut c = HeaderChain::new("regtest", (101, &cp_hex), None, move || now).expect("chain");
        c.set_checkpoint(&cp, &prior).expect("checkpoint");
        c
    };

    let rules = ChainRules::regtest();
    let pow = best(5, || {
        for r in &raws {
            header::check_pow(&black_box(parse_header(r)).expect("mined"), &rules).expect("pow");
        }
    });
    println!(
        "parse (BLAKE2b) + PoW alone  {:8.0} ns/header",
        pow / n * 1e9
    );

    let connect = best(5, || {
        let mut c = fresh();
        for (k, chunk) in raws.chunks(CHUNK).enumerate() {
            assert!(
                c.connect(101 + (k * CHUNK) as u32, chunk)
                    .expect("connect")
                    .adopted
            );
        }
    });
    println!(
        "connect, 4 x 2016 headers    {:8.0} ns/header  ({:.1} ms total)",
        connect / n * 1e9,
        connect * 1e3
    );

    let streamed = best(5, || {
        let mut c = fresh();
        let mut b = c.branch(101).expect("branch");
        for chunk in raws.chunks(CHUNK) {
            b.extend(chunk).expect("extend");
        }
        assert!(c.adopt(b).expect("adopt").adopted);
    });
    println!(
        "streamed Branch + adopt      {:8.0} ns/header  ({:.1} ms total)",
        streamed / n * 1e9,
        streamed * 1e3
    );

    let no_walk = best(5, || {
        let mut c = fresh();
        c.rules.allow_min_difficulty = false;
        for (k, chunk) in raws.chunks(CHUNK).enumerate() {
            assert!(
                c.connect(101 + (k * CHUNK) as u32, chunk)
                    .expect("connect")
                    .adopted
            );
        }
    });
    println!(
        "connect, mainnet's path      {:8.0} ns/header  ({:.1} ms total, no min-difficulty walk)",
        no_walk / n * 1e9,
        no_walk * 1e3
    );

    let cp_cost = best(50, || {
        black_box(fresh());
    });
    println!("checkpoint with 10 priors    {:8.1} us", cp_cost * 1e6);

    let mut full = fresh();
    for (k, chunk) in raws.chunks(CHUNK).enumerate() {
        full.connect(101 + (k * CHUNK) as u32, chunk)
            .expect("connect");
    }
    let tip = full.tip_height().expect("tip");
    let br = best(50, || {
        black_box(full.branch(tip).expect("branch"));
    });
    println!(
        "branch() at the tip          {:8.1} us (per sync round)",
        br * 1e6
    );

    const CALLS: u32 = 1_000_000;
    let imp = best(5, || {
        for _ in 0..CALLS {
            assert!(black_box(full.implausible(U512::ZERO, Some((600, 2016)))).is_none());
        }
    });
    println!(
        "implausible() per answer     {:8.1} ns",
        imp / CALLS as f64 * 1e9
    );

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/mainnet_headers_961630.json"
    );
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("vector")).expect("json");
    let main: Vec<Vec<u8>> = v["headers"]
        .as_array()
        .expect("headers")
        .iter()
        .map(|h| hex::decode(h.as_str().expect("hex")).expect("hex"))
        .collect();
    let above = main.len() - 11;
    let mainnet = best(20, || {
        let mut c = HeaderChain::with_system_clock(
            "main",
            (header::MAINNET_CHECKPOINT.0, header::MAINNET_CHECKPOINT.1),
            None,
        )
        .expect("chain");
        c.set_checkpoint(&main[10], &main[..10])
            .expect("checkpoint");
        assert!(
            c.connect(header::MAINNET_CHECKPOINT.0, &main[11..])
                .expect("connect")
                .adopted
        );
    });
    println!(
        "mainnet 961640 + {above} real     {:8.1} us total ({:.0} ns/header incl. checkpoint)",
        mainnet * 1e6,
        mainnet / above as f64 * 1e9
    );
}
