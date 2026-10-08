//! xbt402: HTTP 402 payments over XBT Spillman channels, the x402 v2 XBT binding of
//! `batch-settlement` (`extra.assetTransferMethod: "channel"`; `xbt-channel` accepted as an alias)
//! (spec v1.1 + the v1.2 `closeFeePayer` additions), in Rust.
//!
//! A port of the Python reference (B1 `xbt402/`), byte-identical to it: the conformance suite in
//! this workspace checks every published vector (`docs/x402/vectors.json`) and the Python checker
//! verifies this crate's own output.
//!
//! * [`channel`]: channel parameters, the payee key tweak v2, funding script, 0x21/0xA3 states,
//!   close, rollover, refund, [`channel::Payer`] and [`channel::Payee`].
//! * [`conditional`]: hash-locked conditional states and claims (M6/M7).
//! * [`wire`]: the 402 / PAYMENT-SIGNATURE / PAYMENT-RESPONSE messages, request auth, receipts,
//!   facilitator bodies.
//! * [`provider`]: the resource-server verifier ([`provider::Provider::serve`]).
//! * [`client`]: the payer SDK ([`client::Client`]), transport-agnostic.
//! * [`signer`]: the [`signer::StateSigner`] seam, so the payer's keys can live in another
//!   process (B2's signer, `xbt-signer`); [`signer::LocalSigner`] keeps them in memory.
//! * [`funding`]: funding checks against a [`funding::ChainBackend`].
//! * [`scheme`]: the seam for a second x402 scheme beside the channel binding (`xbt-work`, AGP-032).
//!
//! Optional features: `http-client` (ureq transport), `http-server` (std::net around the
//! provider), `rpc` (bitcoind JSON-RPC backend and wallet).

pub mod adaptor;
pub mod channel;
pub mod client;
pub mod conditional;
pub mod error;
pub mod funding;
pub mod hub;
pub mod json;
pub mod ledger;
pub mod provider;
pub mod route;
pub mod route_client;
pub mod route_seller;
pub mod scheme;
pub mod signer;
pub mod wire;
#[cfg(feature = "rpc")]
pub mod rpc;
#[cfg(any(feature = "http-client", feature = "http-server"))]
pub mod http;

pub use error::{ChannelError, Result};
pub use xbt_primitives;
