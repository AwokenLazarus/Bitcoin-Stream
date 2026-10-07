//! The xbt-work vector emitter and the Rust conformance table.
//!
//! xbt-work-vectors OUT.json          rebuild XBT-053's vectors.json with the Rust crate (byte-identical)
//! xbt-work-vectors --check FILE      recompute every section of FILE byte for byte, run the
//!                                    generator-independent checks, print the N/N table (exit 1 on any failure)
use xbt_work::vectors::{check, generate, to_file};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("--check") => {
            let path = a.get(2).expect("--check FILE");
            let raw = std::fs::read_to_string(path).expect("read");
            let stored = xbt402::json::parse(&raw).expect("JSON");
            let rows = check(&stored);
            let (mut n, mut f) = (0, 0);
            println!("{:<58} {:>7}", "xbt-work v1 vectors (Rust)", "result");
            for r in &rows {
                let ok = r.checks - r.failures.len();
                println!("{:<58} {:>3}/{:<3}", r.section, ok, r.checks);
                for x in &r.failures {
                    println!("  FAIL {x}");
                }
                n += r.checks;
                f += r.failures.len();
            }
            let same = to_file(&generate()) == raw;
            println!("{:<58} {:>7}", "whole file byte-identical to the Rust emitter", if same { "yes" } else { "NO" });
            println!("total {}/{} ({f} failures) against {path}", n - f, n);
            std::process::exit(if f == 0 && same { 0 } else { 1 });
        }
        Some(out) => {
            std::fs::write(out, to_file(&generate())).expect("write");
            eprintln!("wrote {out}");
        }
        None => {
            eprintln!("usage: xbt-work-vectors OUT.json | --check FILE");
            std::process::exit(2);
        }
    }
}
