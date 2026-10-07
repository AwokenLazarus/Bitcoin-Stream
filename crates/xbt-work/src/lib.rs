//! xbt-work: pay-with-work, the x402 v2 scheme `xbt-work` (v1 draft), in Rust.
//!
//! A client that owns hashrate pays an API by mining: it takes an invoice from the provider,
//! mines through its own DATUM gateway as `<identity>.pw-<invoice>` so the Prime credits the
//! shares to the provider's payout identity, and presents the Prime's signed cumulative receipt
//! with each request. The provider credits only the increase over the best receipt it holds, and
//! audits each pool coinbase against the receipts, turning any shortfall into a fraud proof.
//!
//! A port of the Python reference (XBT-053 `receipts.py`, `nta.py`, `relay/`, and the xbt-070
//! coinbase audit), byte-identical to it: the conformance suite rebuilds all of XBT-053's
//! `vectors.json` and XBT-053's own `check_work_vectors.py` checks the Rust-emitted file.
//!
//! * [`grammar`]: field grammars, invoices (§4.1), identities (§4.2), usernames (§4.3).
//! * [`receipt`]: the signed receipt line and document (§5), the Prime key.
//! * [`book`]: the provider's receipt book: delta credit, equivocation proofs, audit intervals (§9.1).
//! * [`pricing`]: work units and exact pricing per nBits epoch (§6).
//! * [`auth`]: the request binding (§8.2).
//! * [`audit`]: window statements, deferral lines (NTA carry), the audit rule, fraud proofs, the
//!   carry ledger (§10).
//! * [`relay`]: the blinded relay client, ChaCha20-Poly1305 (§11.1).
//! * [`nta`]: payee attestation (XBT-NTA v1, §13.8).
//! * [`provider`]: the `xbt-work` offer beside `xbt-channel` in the xbt402 Provider (§7, §9).
//! * [`payer`]: the `xbt-work` payer for the xbt402 Client (§8, §9.3).
//! * [`vectors`]: the vector emitter and conformance checks.
//!
//! Portable: pure Rust (ed25519-dalek, chacha20poly1305) plus libsecp256k1 through
//! xbt-primitives; no platform-specific dependencies.

pub mod audit;
pub mod auth;
pub mod book;
pub mod error;
mod fsx;
pub mod grammar;
pub mod nta;
pub mod payer;
pub mod pricing;
pub mod provider;
pub mod receipt;
pub mod relay;
#[cfg(feature = "tools")]
pub mod tools;
pub mod vectors;

pub use error::{GrammarError, Result, WorkError};

pub const SCHEME: &str = "xbt-work";
/// `amount` is in difficulty-1 work units (2^32 expected hashes).
pub const ASSET: &str = "XBT:work-diff1";
/// Invoice issuance, relative to the resource origin (§7 `extra.invoiceUrl`).
pub const INVOICE_PATH: &str = "/x402/xbt-work/invoice";
