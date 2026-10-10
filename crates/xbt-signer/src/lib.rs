//! xbt-signer: B2's agent-wallet signer in Rust (AGP-027).
//!
//! A signer process holds every payer key; the model-facing process (B2's Python MCP, or the
//! Rust payer through [`client::RemoteSigner`]) only calls its Unix socket. It carries B2's
//! policy engine, sealed hot and channel keys, the write-ahead channel open, refund custody at
//! expiry (the watcher), the pending close-change retry and the anchored signature log, with
//! B2's socket protocol (`docs/B2_SIGNER_API.md`) and on-disk formats.
//!
//! * [`applog`], [`fsx`]: the append-only logs (AGP-055) and the durable-write steps under every file.
//! * [`keystore`]: AES-256-GCM sealing (keyfile or scrypt passphrase), B2's blob format.
//! * [`sigaudit`], [`anchor`]: the hash-chained signature log and the witness protocol.
//! * [`policy`], [`approval`]: B2's policy engine and the ed25519 human approvals.
//! * [`node`]: the node RPC (cookie auth, P3 mining guard) and B2's pruned-node lookups (P6).
//! * [`hot`]: the hot key, its sealed UTXO set, rotation, the balance cap, sweeps.
//! * [`channels`]: the channel book (per-counterparty Spillman channels as the budget).
//! * [`session`]: `xbt402_pay` inside the signer (open, minConf wait, paid calls, close).
//! * [`routing`]: the routing policy and adaptor-lock book operations (AGP-021).
//! * [`bolt11`], [`ln`]: `rail=ln` (AGP-048): XBT Lightning invoices paid through an LND node under the
//!   same policy, with the chain-identity, bit-512, taproot and pre-split guards.
//! * [`signer`]: the request handler and the watcher; [`server`]: the socket.
//! * [`admin`]: the web UI's methods (AGP-039): the approval queue, human-signed policy changes, key
//!   enrolment and rotation, backups.
//! * [`client`]: the socket client and [`client::RemoteSigner`], an xbt402 `StateSigner`/`Wallet`.
pub mod admin;
pub mod anchor;
pub mod applog;
pub mod client;
pub mod approval;
pub mod bolt11;
pub mod bolt12;
pub mod channels;
pub mod fsx;
pub mod hot;
pub mod ipc;
pub mod keystore;
pub mod ln;
pub mod ln_funding;
pub mod ln_offer;
pub mod macaroon;
pub mod node;
pub mod policy;
pub mod pyjson;
pub mod sanitize;
pub mod server;
pub mod session;
pub mod signer;
pub mod routing;
pub mod sigaudit;

pub use xbt402::{ChannelError as Error, Result};

/// An error with a wire code and a message.
pub fn err(code: &str, msg: impl Into<String>) -> Error {
    Error::new(code, msg)
}
