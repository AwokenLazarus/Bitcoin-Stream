//! AGP-063 K1: the time of one scrypt derivation (r=8, p=1, as the keystore runs it) for each
//! log_n, best of three. `cargo run --release -p xbt-signer --example kdf_cost [log_n...]`.
use std::time::Instant;

fn main() {
    let ns: Vec<u8> = std::env::args().skip(1).filter_map(|a| a.parse().ok()).collect();
    for log_n in if ns.is_empty() { vec![15, 16, 17, 18] } else { ns } {
        let Ok(params) = scrypt::Params::new(log_n, 8, 1, 32) else { continue };
        let mut best = f64::MAX;
        for _ in 0..3 {
            let mut out = [0u8; 32];
            let t = Instant::now();
            if scrypt::scrypt(b"correct horse battery staple", &[7u8; 16], &params, &mut out).is_err() {
                break;
            }
            best = best.min(t.elapsed().as_secs_f64() * 1e3);
        }
        println!("scrypt log_n={log_n} r=8 p=1 mem={} MiB: {best:.0} ms", ((128u64 * 8) << log_n) >> 20);
    }
}
