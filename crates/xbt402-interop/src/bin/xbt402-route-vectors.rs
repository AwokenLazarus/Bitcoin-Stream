//! The routing vector emitter and checker (AGP-026).
//!
//! `xbt402-route-vectors [OUT]` writes the routing vector file rebuilt by the Rust crates (the
//! reference's `json.dumps(indent=1)` layout); `xbt402-route-vectors --check FILE` re-verifies a
//! vector file (the Python-published one) with the Rust crates.
use xbt402_interop::route_vectors::{check, check_count, dump_indent1, generate};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--check") {
        let path = args.get(1).expect("--check FILE");
        let doc: serde_json::Value = xbt402::json::parse(&std::fs::read_to_string(path).expect("read")).expect("json");
        let bad = check(&doc);
        let n = check_count(&doc);
        if bad.is_empty() {
            println!("route vectors (Rust): {path}: OK ({n}/{n} checks)");
        } else {
            println!("route vectors (Rust): {path}: FAIL {}/{n}: {bad:?}", n - bad.len());
            std::process::exit(1);
        }
        return;
    }
    let s = dump_indent1(&generate());
    match args.first() {
        Some(path) => std::fs::write(path, s).expect("write"),
        None => print!("{s}"),
    }
}
