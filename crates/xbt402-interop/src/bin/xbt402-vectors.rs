//! The Rust emitter: prints the xbt402 vector file rebuilt by the Rust crates (JSON, indent 1 like
//! the reference's `--write`). `xbt402-vectors [OUT]`.
fn main() {
    let v = xbt402_interop::vectors::generate();
    let s = serde_json::to_string_pretty(&v).expect("json") + "\n";
    match std::env::args().nth(1) {
        Some(path) => std::fs::write(&path, s).expect("write"),
        None => print!("{s}"),
    }
}
