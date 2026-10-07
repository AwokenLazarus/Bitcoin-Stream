//! Chains, their bech32 prefixes, and the CAIP-2 network id xbt402 uses.
use crate::error::{Error, Result};

/// The first BLAKE2b block on XBT mainnet: the anchor of the mainnet network id.
pub const MAINNET_ANCHOR_HEIGHT: u32 = 961_640;
/// Its hash (display hex).
pub const MAINNET_ANCHOR_HASH: &str = "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb";
/// On regtest the rigs switch to BLAKE2b at block 101 (`-testactivationheight=blake2b@101`); the
/// network id is that block's hash.
pub const REGTEST_ANCHOR_HEIGHT: u32 = 101;
/// `network_id(block 961640)`, the xbt402 mainnet network string.
pub const XBT_MAINNET: &str = "bip122:0000000000000050c1e5f69672f45929";

/// A chain as `getblockchaininfo.chain` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Chain {
    Main,
    Test,
    Testnet4,
    Signet,
    Regtest,
}

impl Chain {
    pub fn from_name(name: &str) -> Result<Self> {
        Ok(match name {
            "main" => Chain::Main,
            "test" => Chain::Test,
            "testnet4" => Chain::Testnet4,
            "signet" => Chain::Signet,
            "regtest" => Chain::Regtest,
            _ => return Err(Error::BadAddress(format!("unknown chain {name:?}"))),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Chain::Main => "main",
            Chain::Test => "test",
            Chain::Testnet4 => "testnet4",
            Chain::Signet => "signet",
            Chain::Regtest => "regtest",
        }
    }

    /// The bech32 human-readable part.
    pub fn hrp(self) -> &'static str {
        match self {
            Chain::Main => "bc",
            Chain::Test | Chain::Testnet4 | Chain::Signet => "tb",
            Chain::Regtest => "bcrt",
        }
    }

    /// The block whose hash names the network (mainnet 961640, regtest 101). None elsewhere.
    pub fn anchor_height(self) -> Option<u32> {
        match self {
            Chain::Main => Some(MAINNET_ANCHOR_HEIGHT),
            Chain::Regtest => Some(REGTEST_ANCHOR_HEIGHT),
            _ => None,
        }
    }
}

/// CAIP-2 `bip122:<first 32 hex characters of the anchor block hash>`.
pub fn network_id(anchor_block_hash_hex: &str) -> String {
    let h: String = anchor_block_hash_hex.chars().take(32).collect();
    format!("bip122:{h}")
}

/// The network id for `chain` from its anchor block hash; on mainnet it must be [`XBT_MAINNET`].
pub fn network_for(chain: Chain, anchor_block_hash_hex: &str) -> Result<String> {
    let id = network_id(anchor_block_hash_hex);
    if chain == Chain::Main && id != XBT_MAINNET {
        return Err(Error::Header(format!("block {MAINNET_ANCHOR_HEIGHT} gives {id}, not {XBT_MAINNET}")));
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_id() {
        assert_eq!(network_id(MAINNET_ANCHOR_HASH), XBT_MAINNET);
        assert!(network_for(Chain::Main, &"11".repeat(32)).is_err());
        assert_eq!(Chain::Regtest.hrp(), "bcrt");
        assert_eq!(Chain::from_name("main").unwrap().hrp(), "bc");
    }
}
