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

use std::path::{Path, PathBuf};

/// The workspace's `vectors/` directory (pinned copies of the published vector files).
pub fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

/// A crash, in one test process: `from` (a file, or a directory tree) copied to `to` as it is on
/// disk now, without the `.lock` sidecars. A ledger takes one opener (AGP-067), so the next
/// "process" opens the copy while the old instance, still alive in the test, keeps its own files,
/// as a dead process's later writes never reach its successor.
pub fn crash_copy(from: &Path, to: &Path) -> std::io::Result<()> {
    if from.is_file() {
        std::fs::copy(from, to).map(|_| ())
    } else {
        std::fs::create_dir_all(to)?;
        for e in std::fs::read_dir(from)? {
            let p = e?.path();
            if p.extension().is_none_or(|x| x != "lock") {
                crash_copy(&p, &to.join(p.file_name().unwrap_or_default()))?;
            }
        }
        Ok(())
    }
}
