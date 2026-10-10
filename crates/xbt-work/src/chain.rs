//! What the provider reads from its own node about a pool block, never from the Prime (AGP-065):
//! the block's height, hash, coinbase value and payout, the epoch's difficulty (the audit's bound
//! on `window_work`), and when the payout becomes spendable under the node's coinbase maturity
//! ([`Maturity`], now in `xbt402::maturity` so the hot wallet reads the same rule).
pub use xbt402::maturity::{LongMaturity, Maturity, ORDINARY_MATURITY};

/// One block of the provider's chain, as its node reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBlock {
    pub height: u32,
    /// 64 lowercase hex, display order.
    pub hash: String,
    /// `V`: the sum of the coinbase outputs.
    pub value_sats: u64,
    /// What the coinbase pays the provider's identity.
    pub paid_sats: u64,
    /// nBits of this block and of its parent: the window target a Prime sizes from either.
    pub bits: u32,
    pub prev_bits: u32,
}
