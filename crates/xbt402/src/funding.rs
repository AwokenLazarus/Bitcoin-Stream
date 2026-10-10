//! Payee-side funding checks before a channel is credited, against any [`ChainBackend`].
use serde_json::Value;
use xbt_primitives::amount::Amount;

use crate::channel::ChannelParams;
use crate::error::{fail, ChannelError, Result};
use crate::json::py_u64;

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

    /// `estimatesmartfee target` in sat/vB; None without an estimate (AGP-067: the close bump).
    fn estimate_fee_rate(&self, _target: u32) -> Result<Option<f64>> {
        Ok(None)
    }

    /// The least feerate this node's mempool takes now, in sat/vB (`getmempoolinfo`: the larger
    /// of `mempoolminfee` and `minrelaytxfee`); None when unknown.
    fn mempool_min_fee(&self) -> Result<Option<f64>> {
        Ok(None)
    }

    /// Submit a parent and the child that pays for it as one package (`submitpackage`), so a
    /// parent below the mempool's floor gets in on the child's fee. Default: each in order, a
    /// refusal of the parent left to show as the child's missing input.
    fn submit_package(&self, hexes: &[String]) -> Result<()> {
        for (i, h) in hexes.iter().enumerate() {
            match self.send_raw_transaction(h) {
                Err(e) if i + 1 == hexes.len() => return Err(e),
                _ => {}
            }
        }
        Ok(())
    }
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

/// The fewest blocks to expiry a payer asks for when it opens on an offer: `minExpiryBlocks +
/// minConf + closeMarginBlocks`, all three from that offer (AGP-076).
///
/// [`check_funding`] compares the blocks left with `min_expiry_blocks` at the provider's tip when
/// the funded open reaches it, not at the payer's tip when the payer chose the expiry. In between
/// the funding has to get `minConf` confirmations, and it may wait for the first one. So the
/// payer adds `minConf`, plus the time the provider itself allows a transaction to confirm on this
/// chain: `closeMarginBlocks`, how long before expiry it broadcasts its close. A funding that takes
/// longer than that would be refused `bad_expiry` on every retry, with the coins locked until the
/// refund. No provider check reads the margin; it is only the payer's allowance.
pub fn open_expiry_floor(min_expiry: u64, min_conf: u64, close_margin: u64) -> u64 {
    min_expiry.saturating_add(min_conf).saturating_add(close_margin)
}

/// Blocks to expiry for a new channel: what the payer wants, at least [`open_expiry_floor`], at
/// most `maxExpiryBlocks - 1`. An offer whose window is narrower than the floor gets the top of
/// its window: the open preflight answers that before anything is funded.
pub fn open_expiry_blocks(want: u64, min_expiry: u64, max_expiry: u64, min_conf: u64, close_margin: u64) -> u64 {
    want.max(open_expiry_floor(min_expiry, min_conf, close_margin)).min(max_expiry.saturating_sub(1))
}

/// [`open_expiry_blocks`] for an offer's `extra`. `minConf` absent is 1, as everywhere on this
/// wire; the three others have no default, so an offer without one is refused `bad_offer`.
pub fn offer_expiry_blocks(extra: &Value, want: u64) -> Result<u64> {
    let need = |k: &str| py_u64(extra.get(k)).ok_or_else(|| ChannelError::new("bad_offer", format!("extra.{k} missing")));
    let min_conf = if extra.get("minConf").is_some() { need("minConf")? } else { 1 };
    Ok(open_expiry_blocks(want, need("minExpiryBlocks")?, need("maxExpiryBlocks")?, min_conf, need("closeMarginBlocks")?))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn floor_is_min_expiry_plus_min_conf_plus_close_margin() {
        // three margins, three answers: a slack that mirrors one provider's default fails two of them
        assert_eq!(open_expiry_blocks(1_008, 1_008, 8_640, 1, 144), 1_153);
        assert_eq!(open_expiry_blocks(1_008, 1_008, 8_640, 1, 36), 1_045);
        assert_eq!(open_expiry_blocks(1_008, 1_008, 8_640, 3, 5), 1_016);
        assert_eq!(open_expiry_blocks(1_008, 1_008, 8_640, 0, 0), 1_008);
    }

    #[test]
    fn want_above_the_floor_is_kept_and_the_offer_max_bounds_both() {
        assert_eq!(open_expiry_blocks(2_016, 1_008, 8_640, 1, 144), 2_016);
        assert_eq!(open_expiry_blocks(9_000, 1_008, 8_640, 1, 144), 8_639);
        assert_eq!(open_expiry_blocks(100, 1_008, 1_100, 1, 144), 1_099);
        assert_eq!(open_expiry_blocks(100, u64::MAX, u64::MAX, u64::MAX, u64::MAX), u64::MAX - 1);
        assert_eq!(open_expiry_blocks(100, 10, 0, 1, 5), 0);
    }

    #[test]
    fn offer_fields_have_no_default_but_min_conf() {
        let ex = json!({"minExpiryBlocks": 1_008, "maxExpiryBlocks": 8_640, "closeMarginBlocks": 144, "minConf": 3});
        assert_eq!(offer_expiry_blocks(&ex, 1_008).unwrap(), 1_155);
        let mut no_conf = ex.clone();
        no_conf.as_object_mut().unwrap().remove("minConf");
        assert_eq!(offer_expiry_blocks(&no_conf, 1_008).unwrap(), 1_153);
        for k in ["minExpiryBlocks", "maxExpiryBlocks", "closeMarginBlocks"] {
            let mut e = ex.clone();
            e.as_object_mut().unwrap().remove(k);
            let err = offer_expiry_blocks(&e, 1_008).unwrap_err();
            assert_eq!(err.code, "bad_offer", "{k}");
            e[k] = json!(-1);
            assert_eq!(offer_expiry_blocks(&e, 1_008).unwrap_err().code, "bad_offer", "{k} negative");
        }
        let mut e = ex.clone();
        e["minConf"] = json!("x");
        assert_eq!(offer_expiry_blocks(&e, 1_008).unwrap_err().code, "bad_offer");
    }
}
