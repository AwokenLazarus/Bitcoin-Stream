//! Conformance suite and interop tools for `xbt-primitives` and `xbt402` (not published).
//!
//! * [`vectors::generate`]: the Rust emitter. It rebuilds the whole xbt402 vector file
//!   (`docs/x402/vectors.json` of B1) with the Rust crates, the Rust provider serving the round
//!   trips, so the Python `check_vectors.py` can check Rust-produced values.
//! * [`conformance`]: every published vector recomputed by Rust and compared byte for byte, plus
//!   the behaviour the vectors record (refusals, signatures, receipts).
//! * `bin/`: `xbt-conformance` (the N/N table), `xbt402-vectors` (the emitter), and the regtest
//!   cross-implementation tools `xbt402-rust-provider` and `xbt402-rust-payer`.
pub mod conformance;
pub mod memnet;
pub mod route_vectors;
pub mod stub;
pub mod vectors;

use std::path::PathBuf;

/// The workspace's `vectors/` directory (pinned copies of the published vector files).
pub fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}
