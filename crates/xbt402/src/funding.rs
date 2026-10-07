//! Payee-side funding checks before a channel is credited, against any [`ChainBackend`].
use xbt_primitives::amount::Amount;

use crate::channel::ChannelParams;
use crate::error::{fail, ChannelError, Result};

/// An unspent output as `gettxout` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoInfo {
    pub confirmations: u32,
    /// Sats.
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    pub coinbase: bool,
}

/// The node calls the provider and the payer SDK need. The `rpc` feature implements it over
/// bitcoind JSON-RPC; a light client or a test stub can implement it too.
pub trait ChainBackend: Send + Sync {
    fn block_count(&self) -> Result<u32>;
    /// `gettxout txid vout include_mempool`: None when unknown or spent.
    fn get_tx_out(&self, txid: &str, vout: u32, include_mempool: bool) -> Result<Option<UtxoInfo>>;
    /// Broadcast; returns the txid.
    fn send_raw_transaction(&self, hex: &str) -> Result<String>;
    /// Does the node know this transaction (mempool, or txindex)?
    fn has_transaction(&self, txid: &str) -> Result<bool>;
}

/// What a payee accepts as funding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingPolicy {
    pub min_capacity: u64,
    pub max_capacity: u64,
    /// ~1 day left at open.
    pub min_expiry_blocks: u32,
    /// ~60 days: bounds how long the payee's key is hot.
    pub max_expiry_blocks: u32,
    /// The payee closes this many blocks before expiry.
    pub close_margin: u32,
    pub min_conf: u32,
    /// Accept unconfirmed funding up to this capacity (0 = never).
    pub zero_conf_max: u64,
    /// Above this a funding reorg is worth more to an attacker...
    pub large_capacity: u64,
    /// ...so wait for more confirmations.
    pub large_min_conf: u32,
}

impl Default for FundingPolicy {
    fn default() -> Self {
        Self {
            min_capacity: 20_000,
            max_capacity: 10_000_000,
            min_expiry_blocks: 144,
            max_expiry_blocks: 8_640,
            close_margin: 36,
            min_conf: 1,
            zero_conf_max: 0,
            large_capacity: 1_000_000,
            large_min_conf: 3,
        }
    }
}

impl FundingPolicy {
    pub fn conf_for(&self, capacity: u64) -> u32 {
        if capacity > self.large_capacity { self.min_conf.max(self.large_min_conf) } else { self.min_conf }
    }
}

/// Err unless the funding output is acceptable; its confirmations otherwise. Coinbase fundings
/// are refused outright (#419 maturity would outlast the channel).
pub fn check_funding(chain: &dyn ChainBackend, p: &ChannelParams, pol: &FundingPolicy) -> Result<u32> {
    let out = chain
        .get_tx_out(&p.funding_txid(), p.funding_vout(), true)
        .map_err(|e| ChannelError::new("unknown_funding", e.to_string()))?
        .ok_or_else(|| ChannelError::new("unknown_funding", "no such unspent output (unknown, or already spent)"))?;
    if out.coinbase {
        return fail("coinbase_funding", "coinbase outputs cannot fund a channel (maturity)");
    }
    if out.script_pubkey != p.spk() {
        return fail("bad_funding", "output is not this channel's script");
    }
    if out.value != p.capacity {
        return fail("bad_funding", "capacity mismatch");
    }
    if !(pol.min_capacity..=pol.max_capacity).contains(&p.capacity) {
        return fail("bad_capacity", format!("capacity outside [{}, {}]", pol.min_capacity, pol.max_capacity));
    }
    let left = p.expiry as i64 - chain.block_count()? as i64;
    if left < pol.min_expiry_blocks as i64 || left > pol.max_expiry_blocks as i64 {
        return fail("bad_expiry", format!("{left} blocks to expiry, need [{}, {}]", pol.min_expiry_blocks, pol.max_expiry_blocks));
    }
    let need = pol.conf_for(p.capacity);
    if out.confirmations < need && p.capacity > pol.zero_conf_max {
        return fail("unconfirmed", format!("{} confirmations, need {need}", out.confirmations));
    }
    let _ = Amount::from_sat(p.capacity).map_err(|_| ChannelError::new("bad_capacity", "above MAX_MONEY"))?;
    Ok(out.confirmations)
}
