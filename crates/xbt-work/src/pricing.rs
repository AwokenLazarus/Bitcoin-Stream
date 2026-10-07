//! Work units and pricing (spec §6), in exact integers from the epoch's compact target, so every
//! implementation quotes the same `amount`:
//!
//! ```text
//! amount = max(1, ⌈ priceSats · T₁ · 10⁸ / (T(bits) · V · (10⁴ − feeBps) · (10⁴ − haircutBps)) ⌉)
//! value_sats(w) = ⌊ w · V · (10⁴ − feeBps) · T(bits) / (T₁ · 10⁴) ⌋
//! ```
//! `T₁` is the difficulty-1 target (`0x1d00ffff`). Products reach ~2^400, so the arithmetic is
//! 512-bit.
use ruint::aliases::U512;
use serde_json::Value;
use xbt402::json::obj;

use crate::error::{fail, Result};

pub const DIFF1_BITS: u32 = 0x1D00_FFFF;

/// The block target a compact `bits` encodes. Negative, zero and above-2^256 targets are refused.
pub fn bits_to_target(bits: u32) -> Result<U512> {
    let (exp, mant) = (bits >> 24, bits & 0x007F_FFFF);
    if bits & 0x0080_0000 != 0 || mant == 0 {
        return fail("bad_bits", "negative or zero target");
    }
    if exp > 32 {
        return fail("bad_bits", "target above 2^256");
    }
    let m = U512::from(mant);
    Ok(if exp <= 3 { m >> (8 * (3 - exp) as usize) } else { m << (8 * (exp - 3) as usize) })
}

pub fn diff1_target() -> U512 {
    bits_to_target(DIFF1_BITS).expect("diff1")
}

fn check_bps(name: &str, bps: u32) -> Result<U512> {
    if bps >= 10_000 {
        return fail("bad_pricing", format!("{name} must be below 10000"));
    }
    Ok(U512::from(10_000 - bps))
}

/// §6.2: the least number of work units that pays `price_sats` net of fee and haircut (at least 1).
pub fn work_units_for_price(price_sats: u64, bits: u32, block_value_sats: u64, fee_bps: u32, haircut_bps: u32) -> Result<u64> {
    if block_value_sats == 0 {
        return fail("bad_pricing", "block value is zero");
    }
    let num = U512::from(price_sats) * diff1_target() * U512::from(100_000_000u64);
    let den = bits_to_target(bits)? * U512::from(block_value_sats) * check_bps("feeBps", fee_bps)? * check_bps("haircutBps", haircut_bps)?;
    let q = num.div_ceil(den);
    u64::try_from(q.max(U512::from(1u64))).or_else(|_| fail("bad_pricing", "amount above 2^64-1"))
}

/// §6.1: expected sats of `work` credited at `bits` on a path with `fee_bps` (floor).
pub fn value_sats(work: u64, bits: u32, block_value_sats: u64, fee_bps: u32) -> Result<u64> {
    let num = U512::from(work) * U512::from(block_value_sats) * check_bps("feeBps", fee_bps)? * bits_to_target(bits)?;
    let q = num / (diff1_target() * U512::from(10_000u64));
    u64::try_from(q).or_else(|_| fail("bad_pricing", "value above 2^64-1"))
}

/// D = T₁ / T(bits) as the nearest f64 (both targets are exact in f64: 16- and 23-bit mantissas).
pub fn difficulty(bits: u32) -> Result<f64> {
    bits_to_target(bits)?;
    let (exp, mant) = ((bits >> 24) as i32, (bits & 0x007F_FFFF) as f64);
    let t = if exp <= 3 { ((bits & 0x007F_FFFF) >> (8 * (3 - exp))) as f64 } else { mant * 2f64.powi(8 * (exp - 3)) };
    Ok(65535.0 * 2f64.powi(208) / t)
}

/// Provider pricing inputs (§6.5): what `extra.pricing` publishes, and the quote they give.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pricing {
    pub price_sats: u64,
    pub bits: u32,
    pub block_value_sats: u64,
    pub fee_bps: u32,
    pub haircut_bps: u32,
}

impl Pricing {
    pub fn amount(&self) -> Result<u64> {
        work_units_for_price(self.price_sats, self.bits, self.block_value_sats, self.fee_bps, self.haircut_bps)
    }

    /// `{"priceSats":"150","bits":"190141c5","blockValueSats":"312500000","feeBps":0,"haircutBps":1000}`.
    pub fn to_json(&self) -> Value {
        obj([("priceSats", self.price_sats.to_string().into()), ("bits", format!("{:08x}", self.bits).into()),
             ("blockValueSats", self.block_value_sats.to_string().into()), ("feeBps", self.fee_bps.into()),
             ("haircutBps", self.haircut_bps.into())])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_economics() {
        // §6.4: a 150-sat request with a 10% haircut costs 1,823 work units
        assert_eq!(work_units_for_price(150, 0x1901_41C5, 312_500_000, 0, 1000).unwrap(), 1823);
        assert_eq!(work_units_for_price(1, 0x207F_FFFF, 5_000_000_000, 0, 0).unwrap(), 1);
        assert_eq!(format!("{:.6}", difficulty(DIFF1_BITS).unwrap()), "1.000000");
        assert!(bits_to_target(0x0180_0000).is_err());
        assert!(bits_to_target(0x2100_0001).is_err());
        assert!(work_units_for_price(1, DIFF1_BITS, 1, 10_000, 0).is_err());
        assert_eq!(value_sats(1823, 0x1901_41C5, 312_500_000, 0).unwrap(), 166);
    }
}
