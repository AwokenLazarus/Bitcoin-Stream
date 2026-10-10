//! Coinbase maturity as the node enforces it (AGP-065, shared by the provider audit in `xbt-work`
//! and the hot wallet in `xbt-signer`, AGP-069): read from `getdeploymentinfo`, never hard-coded.
use serde_json::Value;

use crate::error::{ChannelError, Result};

/// `COINBASE_MATURITY` of the Bitcoin consensus code: the depth when the node reports no long rule.
pub const ORDINARY_MATURITY: u32 = 100;

/// The node's long coinbase maturity rule (Knots `long_coinbase_maturity`, a flag-day deployment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongMaturity {
    /// `coinbase_start_height`: coinbases from here are covered.
    pub coinbase_start: u32,
    /// `height`: spends in blocks from here are held to it by consensus...
    pub enforce: u32,
    /// ...until `height_end` (inclusive).
    pub end: u32,
    /// `maturity`: the depth required.
    pub depth: u32,
}

/// The coinbase maturity in force on the node's chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Maturity {
    pub long: Option<LongMaturity>,
}

impl Maturity {
    /// From `getdeploymentinfo` (`deployments.long_coinbase_maturity`). A node that lists no such
    /// deployment has only the ordinary depth; a listed one with a missing field is an error.
    pub fn from_deployments(info: &Value) -> Result<Self> {
        let Some(d) = info.get("deployments").filter(|d| d.is_object()) else {
            return Err(ChannelError::new(
                "node",
                "getdeploymentinfo has no deployments",
            ));
        };
        let Some(l) = d.get("long_coinbase_maturity") else {
            return Ok(Self { long: None });
        };
        let f = |k: &str| {
            l.get(k)
                .and_then(Value::as_u64)
                .and_then(|v| u32::try_from(v).ok())
        };
        match (
            f("coinbase_start_height"),
            f("height"),
            f("height_end"),
            f("maturity"),
        ) {
            (Some(coinbase_start), Some(enforce), Some(end), Some(depth)) => Ok(Self {
                long: Some(LongMaturity {
                    coinbase_start,
                    enforce,
                    end,
                    depth,
                }),
            }),
            _ => Err(ChannelError::new(
                "node",
                "long_coinbase_maturity: a field is missing or out of range",
            )),
        }
    }

    /// The first height at which a spend of the coinbase at `height` relays. Knots' mempool holds
    /// every coinbase spend to the long depth whatever its height (policy start height 0), so this
    /// is when a wallet can actually move it.
    pub fn relay_at(&self, height: u32) -> u32 {
        height.saturating_add(
            self.long
                .map_or(ORDINARY_MATURITY, |l| l.depth.max(ORDINARY_MATURITY)),
        )
    }

    /// The first height at which a block may include a spend of the coinbase at `height`.
    pub fn consensus_at(&self, height: u32) -> u32 {
        let ordinary = height.saturating_add(ORDINARY_MATURITY);
        let Some(l) = self.long else { return ordinary };
        if height < l.coinbase_start {
            return ordinary;
        }
        let long = height.saturating_add(l.depth);
        // a spend at s needs the long depth while enforce <= s <= end, the ordinary one otherwise
        if ordinary < l.enforce || ordinary > l.end {
            ordinary
        } else {
            long.min(l.end.saturating_add(1))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maturity_from_the_node() {
        // Knots mainnet: coinbases from 973440, enforced 973440..=979919, depth 6480
        let main = json!({"deployments": {"long_coinbase_maturity": {"type": "flagday", "height": 973440, "height_end": 979919,
                                                                      "coinbase_start_height": 973440, "maturity": 6480, "active": true}}});
        let m = Maturity::from_deployments(&main).unwrap();
        assert_eq!(m.relay_at(975000), 981480);
        assert_eq!(
            m.relay_at(900000),
            906480,
            "policy holds every coinbase to the long depth"
        );
        assert_eq!(
            m.consensus_at(900000),
            900100,
            "before coinbase_start: the ordinary depth"
        );
        assert_eq!(
            m.consensus_at(975000),
            979920,
            "the rule ends after height_end"
        );
        assert_eq!(m.consensus_at(973440), 979920);
        assert_eq!(
            m.consensus_at(979900),
            980000,
            "the ordinary depth already ends past height_end"
        );
        // regtest without the rule
        let reg = Maturity::from_deployments(&json!({"deployments": {"segwit": {}}})).unwrap();
        assert_eq!((reg.relay_at(110), reg.consensus_at(110)), (210, 210));
        assert!(Maturity::from_deployments(&json!({})).is_err());
        let bad = json!({"deployments": {"long_coinbase_maturity": {"height": 1}}});
        assert!(Maturity::from_deployments(&bad).is_err());
    }
}
