//! Offline self-test for the build matrix (scripts/work_matrix.sh): on the target itself, rebuild
//! XBT-053's xbt-work vector file with this crate (byte-identical to the published copy embedded
//! here) and run every conformance check over it. No network, no files.
use xbt_work::vectors::{check, generate, to_file};

const PINNED: &str = include_str!("../../../vectors/xbt_work_vectors.json");

fn main() {
    let same = to_file(&generate()) == PINNED;
    let rows = check(&xbt402::json::parse(PINNED).expect("pinned vectors parse"));
    let n: usize = rows.iter().map(|r| r.checks).sum();
    let f: usize = rows.iter().map(|r| r.failures.len()).sum();
    for r in rows.iter().filter(|r| !r.failures.is_empty()) {
        eprintln!("FAIL {}: {:?}", r.section, r.failures);
    }
    if same && f == 0 {
        println!("xbt-work selftest OK ({}): vectors byte-identical, {}/{} checks", std::env::consts::ARCH, n - f, n);
    } else {
        println!("xbt-work selftest FAIL ({}): byte-identical {same}, {}/{} checks", std::env::consts::ARCH, n - f, n);
        std::process::exit(1);
    }
}
