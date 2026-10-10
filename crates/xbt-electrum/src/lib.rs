//! A light chain backend for XBT: Electrum servers, checked against our own BLAKE2b header chain.
//! The xbt402 client and wallet run on it with no node, on any hardware (AGP-028, a port of B2's
//! `agentwallet/electrum.py`, AGP-024).
//!
//! [`ElectrumBackend`] implements [`xbt402::funding::ChainBackend`], has a typed API
//! ([`ElectrumBackend::tx_out`], [`ElectrumBackend::transaction`], [`ElectrumBackend::spending_tx`],
//! [`ElectrumBackend::unspent`], [`ElectrumBackend::broadcast`], [`ElectrumBackend::watch`], ...), and
//! answers the node RPCs of the client path the way the node does ([`ElectrumBackend::call`]).
//!
//! Trust (the same rules as the Python backend; threat model in `docs/B2_CHAIN_BACKEND.md`):
//!
//! * **Headers**: our own chain from a pinned post-fork checkpoint ([`xbt_primitives::header::HeaderChain`]):
//!   each header's BLAKE2b PoW, nBits (Knots' retarget), linkage, committed height and time are
//!   checked, and the most-work chain any server shows wins. A server cannot move us to a chain with
//!   less work, or below the checkpoint. Servers that answer but cannot serve the checkpoint are the
//!   wrong chain ([`Kind::CheckpointMismatch`]). Knots' header rules hold from the first header
//!   (the ten below the checkpoint are fetched and hash-linked for the median), chunks are checked as
//!   they arrive, and a claimed tip is believed only up to what the time since our tip allows.
//! * **A believable chain** (mainnet, [`Plausibility`]): until the chain reaches the pinned block
//!   964264 (Knots' assumevalid), carries Knots' nMinimumChainWork and is not implausibly short for its
//!   age, every chain answer fails with [`Kind::Implausible`]. Mainnet servers need TLS (`ssl://`),
//!   except on a loopback host.
//! * **Transactions**: a raw tx is accepted only if it re-serializes byte for byte and hashes to the
//!   txid asked for. It counts as confirmed only with a Merkle proof into one of our headers whose
//!   committed transaction count fits the proof (depth `ceil(log2(txcount))`, position below the
//!   count: no 64-byte inner-node forgeries).
//! * **Several servers**: histories and unspent lists are the union over every reachable server
//!   (proofs stop fabrication; the union means one honest server defeats hiding), headers are
//!   cross-checked, broadcasts go to all of them, the fee estimate is their median.
//! * **Mempool facts cannot be proven.** A spend seen only in a mempool never makes an output count
//!   as spent, so a lying server cannot talk the wallet out of a refund.
//!
//! What a malicious server can still do: hide a transaction until another server or a block shows
//! it, withhold new blocks (the tip lags: `status()["tip_age_s"]`), delay or drop us, lie about fees
//! (unverifiable, reported as such), and learn which scripts we watch.
pub mod backend;
pub mod conn;
pub mod error;
#[cfg(feature = "sim")]
pub mod sim;

pub use backend::{is_loopback_host, parse_checkpoint, scripthash, Config, ElectrumBackend, FeeEstimate, Flag, Plausibility, TxOutInfo,
                  TxStatus, Utxo};
pub use conn::{parse_server, tls_config, Connection, ServerAddr};
pub use error::{ElectrumError, Kind, Result};
