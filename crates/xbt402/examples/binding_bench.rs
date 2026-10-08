//! AGP-068 per-call hashing against the receipt signature (release build):
//! `cargo run --release -p xbt402 --example binding_bench`.
use std::hint::black_box;
use std::time::Instant;

use serde_json::json;
use xbt402::wire::{body_hash, receipt_message, request_digest_v1, request_digest_v2};
use xbt_primitives::ecdsa;
use xbt_primitives::hash::{sha256, tagged_hash};
use xbt_primitives::secp256k1::SecretKey;

fn per_op(n: u32, mut f: impl FnMut()) -> f64 {
    let t = Instant::now();
    for _ in 0..n {
        f();
    }
    t.elapsed().as_secs_f64() * 1e9 / n as f64
}

fn main() {
    let n = 20_000;
    let url = "https://api.example.com/v1/quote?pair=XBT-USD";
    let body = br#"{"prompt":"hello"}"#;
    let answer = vec![7u8; 4096];
    let r = json!({"chan": format!("{}:0", "ab".repeat(32)), "seq": 12, "cum": "1800", "charged": "150",
                   "spentMsat": "1800000", "req": "cd".repeat(32), "status": 200, "bodyHash": "ef".repeat(32)});
    let v1_receipt = || {
        let parts: Vec<String> = ["chan", "seq", "cum", "charged", "spentMsat", "req"]
            .iter()
            .map(|k| xbt402::json::py_str(r.get(*k)))
            .collect();
        tagged_hash("xbt402/receipt", parts.join("|").as_bytes())
    };
    let d1 = per_op(n, || {
        black_box(request_digest_v1("POST", "/v1/quote?pair=XBT-USD", body));
    });
    let d2 = per_op(n, || {
        black_box(request_digest_v2("POST", url, body));
    });
    let r1 = per_op(n, || {
        black_box(v1_receipt());
    });
    let r2 = per_op(n, || {
        black_box(receipt_message(&r));
    });
    let bh = per_op(n, || {
        black_box(body_hash(&answer));
    });
    let sk = SecretKey::from_slice(&sha256(b"binding_bench")).expect("key");
    let msg = receipt_message(&r);
    let sign = per_op(n / 10, || {
        black_box(ecdsa::sign(&sk, &msg));
    });
    let mib = vec![1u8; 1 << 20];
    let sha_ns = per_op(50, || {
        black_box(sha256(&mib));
    });
    // a paid call computes the request digest twice on the server (auth, receipt) and once more on
    // the client to check the receipt; the server frames one receipt and hashes the answer once
    let fixed = 2.0 * (d2 - d1) + (r2 - r1);
    println!("ns per op ({n} ops): digest v1 {d1:.0}, v2 {d2:.0}; receipt v1 {r1:.0}, v2 {r2:.0}; bodyHash 4 KiB {bh:.0}; \
              ECDSA sign {sign:.0}");
    println!("added per paid call (server): framing {fixed:.0} ns ({:.1}% of a sign), with a 4 KiB bodyHash {:.0} ns ({:.1}%)",
             100.0 * fixed / sign, fixed + bh, 100.0 * (fixed + bh) / sign);
    println!(
        "sha256 {:.0} MB/s ({:.2} ns/byte)",
        1e3 * (1 << 20) as f64 / sha_ns,
        sha_ns / (1 << 20) as f64
    );
}
