//! Satoshi amounts.
use crate::error::{Error, Result};

/// Satoshis per coin.
pub const SAT_PER_COIN: u64 = 100_000_000;
/// No more than this many satoshis can ever exist (21M coins).
pub const MAX_MONEY: u64 = 21_000_000 * SAT_PER_COIN;

/// A non-negative amount of satoshis, at most [`MAX_MONEY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Amount(u64);

impl Amount {
    pub const ZERO: Amount = Amount(0);

    pub fn from_sat(sat: u64) -> Result<Self> {
        if sat > MAX_MONEY {
            return Err(Error::Amount("above MAX_MONEY"));
        }
        Ok(Amount(sat))
    }

    pub fn to_sat(self) -> u64 {
        self.0
    }

    pub fn checked_add(self, o: Amount) -> Option<Amount> {
        self.0.checked_add(o.0).filter(|s| *s <= MAX_MONEY).map(Amount)
    }

    pub fn checked_sub(self, o: Amount) -> Option<Amount> {
        self.0.checked_sub(o.0).map(Amount)
    }

    /// From a JSON-RPC coin value (bitcoind prints 8 decimals), rounded like Python's
    /// `round(value * 1e8)`.
    pub fn from_btc_f64(btc: f64) -> Result<Self> {
        if !btc.is_finite() || btc < 0.0 {
            return Err(Error::Amount("not a finite non-negative value"));
        }
        let sat = (btc * SAT_PER_COIN as f64).round_ties_even();
        if sat > MAX_MONEY as f64 {
            return Err(Error::Amount("above MAX_MONEY"));
        }
        Ok(Amount(sat as u64))
    }

    /// Exact decimal coin string ("0.00200000") for RPCs such as `sendtoaddress`.
    pub fn to_btc_string(self) -> String {
        format!("{}.{:08}", self.0 / SAT_PER_COIN, self.0 % SAT_PER_COIN)
    }
}

impl std::fmt::Display for Amount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} sat", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn btc_conversions() {
        assert_eq!(Amount::from_btc_f64(0.002).unwrap().to_sat(), 200_000);
        assert_eq!(Amount::from_btc_f64(20999999.9769).unwrap().to_sat(), 2_099_999_997_690_000);
        assert_eq!(Amount::from_sat(200_000).unwrap().to_btc_string(), "0.00200000");
        assert!(Amount::from_sat(MAX_MONEY + 1).is_err());
        assert!(Amount::from_btc_f64(f64::NAN).is_err());
    }
}
