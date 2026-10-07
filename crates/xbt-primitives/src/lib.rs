//! Chain primitives for XBT (Bitcoin with BLAKE2b proof of work), shared by the xbt402 rails and
//! any other project that needs them.
//!
//! Everything here is byte-identical to the Python references it ports: B1 `xbt402/tx.py` and
//! `xbt402/ecc.py` (transactions, scripts, bech32, the Knots `UnifiedSighash`, strict-DER low-S
//! ECDSA) and B2 `agentwallet/headers.py` (BLAKE2b v2 headers, proof of work, the Knots retarget,
//! most-work header chains). The conformance suite in this workspace checks that against the
//! published vectors.
//!
//! Nothing here panics on untrusted bytes: parsers return [`Error`].

pub mod address;
pub mod amount;
pub mod ecdsa;
pub mod encode;
pub mod error;
pub mod hash;
pub mod header;
pub mod network;
pub mod script;
pub mod sighash;
pub mod tx;

pub use error::Error;

/// Re-export of the `secp256k1` crate this library signs with, so callers use the same version.
pub use secp256k1;
