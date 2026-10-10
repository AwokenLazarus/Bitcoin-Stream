//! BLAKE2b block headers (v2, 164 bytes), proof of work, the Knots retarget and a most-work
//! header chain from a pinned checkpoint. A port of B2 `agentwallet/headers.py` (AGP-024), which
//! ports electrs' `headerv2.rs`.
//!
//! A header is accepted by [`HeaderChain`] only when:
//! * it is a v2 header (164 bytes, bit 31 of the version set) whose committed height is its height;
//! * it links to its parent by hash;
//! * the top two bits of its flags are clear (Knots `bad-flags-highbits`) and its version without
//!   bit 31 is at least 4 (Knots `bad-version`, BIP34/65/66 are buried far below any checkpoint);
//! * at a pinned height ([`ChainRules::pins`], mainnet: Knots' assumevalid block 964264) its hash is
//!   the pinned one (Knots `checkpoint-mismatch`);
//! * its BLAKE2b block hash meets the target its nBits encode, within powLimit;
//! * its nBits follow Knots' `pow.cpp` `GetNextWorkRequired`: unchanged inside a 2016-block period
//!   and, at a period boundary, exactly `CalculateNextWorkRequired` when the period's first header
//!   is known, else within `PermittedDifficultyTransition`'s 4x bounds; on a min-difficulty chain
//!   (regtest) powLimit after a 20-minute gap, else the walk back to the last block that was not a
//!   min-difficulty block;
//! * its time is above the median of the 11 before it (the 10 headers below the checkpoint are
//!   fetched, hash-linked back from it, so this holds from the first header) and at most 2 h in
//!   the future.
//!
//! Of competing branches the one with the most work wins (first seen wins a tie). Testnet3,
//! testnet4 (BIP94, XBT Blake2bHeight 150308) and signet have no rules here: [`ChainRules::for_chain`]
//! refuses them, so a light client on those chains fails closed at construction.
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use ruint::aliases::{U256, U512};

use crate::encode::Reader;
use crate::error::{Error, Result};
use crate::hash::{blake2b256, dsha256, tagged_hash};
use crate::tx::Tx;

pub const V2_FLAG: u32 = 0x8000_0000;
pub const V1_SIZE: usize = 80;
pub const V2_SIZE: usize = 164;
pub const FLAG_USE_TIME_OFFSET: u8 = 0x04;
pub const MEDIAN_SPAN: usize = 11;
pub const MAX_FUTURE_S: u64 = 2 * 60 * 60;
/// Knots `bad-flags-highbits`: the top two flag bits are reserved for a future hard fork.
pub const FLAGS_RESERVED: u8 = 0xC0;
/// Knots `bad-version`: below 4 is refused once BIP34/66/65 are active (far below 961640).
pub const MIN_VERSION: u32 = 4;
/// Headers below the checkpoint a chain holds (hash-linked back from it), so the median-time rule
/// applies from the first header above it.
pub const PRIOR_HEADERS: u32 = MEDIAN_SPAN as u32 - 1;
/// Mainnet's trust anchor: the first BLAKE2b block, also the xbt402 network anchor
/// ([`crate::network::MAINNET_ANCHOR_HASH`]).
pub const MAINNET_CHECKPOINT: (u32, &str) =
    (961_640, "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb");
/// Chainwork from genesis at [`MAINNET_CHECKPOINT`] (Knots `getblockheader`, 2026-10-08).
pub const MAINNET_CHECKPOINT_CHAINWORK: &str = "00000000000000000000000000000000000000013e002762b0a1ae991b033e89";
/// Knots mainnet `nMinimumChainWork` (`src/kernel/chainparams.cpp:149`, v29.4.2.knots20260508). It
/// is exactly the chainwork of block 964264, Knots' `defaultAssumeValid` (`getblockheader`).
pub const MAINNET_MIN_CHAIN_WORK: &str = "00000000000000000000000000000000000000013e00277374c9f9eeadc70200";
/// Hashes every mainnet chain must have at these heights: Knots mainnet `defaultAssumeValid`
/// (`src/kernel/chainparams.cpp:150`, block 964264). Moved forward with each release.
pub const MAINNET_PINS: &[(u32, &str)] = &[(964_264, "0000000000000078ed1e20cac1acf78df6d1060c78059fb6331e17141c881fc8")];

/// A 256-bit chainwork as `getblockheader` prints it (64 hex digits).
pub fn parse_chainwork(hex64: &str) -> Result<U512> {
    let v = U256::from_str_radix(hex64, 16).map_err(|_| herr(format!("chainwork {hex64:?} is not hex")))?;
    Ok(U512::from(v))
}

/// The work a mainnet chain must show above the checkpoint `cp`: Knots' `nMinimumChainWork` minus
/// the chainwork at `cp`. Zero for an anchor at or above the last pin (it is past the minimum
/// already); None for an older anchor whose chainwork this release does not know.
pub fn mainnet_min_work_above(cp: (u32, &[u8; 32])) -> Option<U512> {
    let min = parse_chainwork(MAINNET_MIN_CHAIN_WORK).ok()?;
    if cp.0 == MAINNET_CHECKPOINT.0 && hex::encode(cp.1) == MAINNET_CHECKPOINT.1 {
        return Some(min.saturating_sub(parse_chainwork(MAINNET_CHECKPOINT_CHAINWORK).ok()?));
    }
    let last_pin = MAINNET_PINS.iter().map(|p| p.0).max().unwrap_or(0);
    (cp.0 >= last_pin).then_some(U512::ZERO)
}

fn herr(s: impl Into<String>) -> Error {
    Error::Header(s.into())
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

// --- compact targets (arith_uint256 SetCompact / GetCompact) ------------------------------------

/// `SetCompact`, refusing a negative or overflowing encoding (Knots `DeriveTarget` refuses both).
pub fn bits_to_target(bits: u32) -> Result<U256> {
    let size = bits >> 24;
    let word = bits & 0x007F_FFFF;
    if word != 0 && bits & 0x0080_0000 != 0 {
        return Err(herr(format!("nBits {bits:08x} is negative")));
    }
    if word != 0 && (size > 34 || (word > 0xFF && size > 33) || (word > 0xFFFF && size > 32)) {
        return Err(herr(format!("nBits {bits:08x} overflows")));
    }
    if word == 0 {
        return Ok(U256::ZERO);
    }
    let w = U256::from(word);
    Ok(if size <= 3 { w >> (8 * (3 - size) as usize) } else { w << (8 * (size - 3) as usize) })
}

/// `GetCompact`.
pub fn target_to_bits(target: U256) -> u32 {
    let mut size = target.bit_len().div_ceil(8) as u32;
    let mut compact: u32 = if size <= 3 {
        (target << (8 * (3 - size) as usize)).to::<u64>() as u32
    } else {
        (target >> (8 * (size - 3) as usize)).to::<u64>() as u32
    };
    if compact & 0x0080_0000 != 0 {
        compact >>= 8;
        size += 1;
    }
    compact | (size << 24)
}

/// `GetBlockProof`: 2^256 / (target + 1).
pub fn work_of(bits: u32) -> Result<U512> {
    let t = U512::from(bits_to_target(bits)?);
    Ok((U512::from(1u8) << 256) / (t + U512::from(1u8)))
}

/// A 32-byte big-endian value (a block hash as Knots prints it) as an integer.
pub fn hash_as_u256(h: &[u8; 32]) -> U256 {
    U256::from_be_bytes(*h)
}

// --- header v2 ------------------------------------------------------------------------------

/// The intermediate values of `CBlockHeader::GetHash()` for a v2 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Stages {
    pub xor_key_hash: [u8; 32],
    pub mask: [u8; 32],
    pub h1: [u8; 32],
    pub h2: [u8; 32],
    pub blake2b_1: [u8; 32],
    pub asic_input: Vec<u8>,
    pub blake2b_2: [u8; 32],
    pub block_hash: [u8; 32],
}

/// Is this raw header (by its version field) v2?
pub fn header_size(b: &[u8]) -> Result<usize> {
    if b.len() < 4 {
        return Err(herr("need 4 bytes to read the version field"));
    }
    Ok(if u32_at(b, 0) & V2_FLAG != 0 { V2_SIZE } else { V1_SIZE })
}

/// The staged BLAKE2b hash of a v2 header.
pub fn v2_stages(b: &[u8]) -> Result<V2Stages> {
    if b.len() != V2_SIZE {
        return Err(herr(format!("a v2 header is {V2_SIZE} bytes, got {}", b.len())));
    }
    let version = u32_at(b, 0);
    if version & V2_FLAG == 0 {
        return Err(herr("not a v2 header: bit 31 of the version field is clear"));
    }
    let merkle = &b[36..68];
    let (time_on_wire, bits, nonce, nonce2, nonce3) = (u32_at(b, 68), u32_at(b, 72), u32_at(b, 76), u32_at(b, 80), u32_at(b, 84));
    let extranonce = &b[88..104];
    let time_offset = u32_at(b, 104);
    let txcount = u16::from_le_bytes([b[108], b[109]]) as u32;
    let (flags, clear_bits) = (b[110], b[111]);
    let xor_key = &b[112..128];
    let height = u32_at(b, 128);
    let mm_rhs = &b[132..164];

    let xor_key_hash = tagged_hash("Bitcoin block hash PoW XOR key", xor_key);
    let mut mask = [0u8; 32];
    if xor_key.iter().any(|&x| x != 0) {
        mask = tagged_hash("Bitcoin block hash PoW XOR mask", xor_key);
        let clear = (clear_bits / 8) as usize;
        for m in mask.iter_mut().take(clear) {
            *m = 0;
        }
        if clear < 32 {
            mask[clear] &= 0xFF >> (clear_bits % 8);
        }
    }
    let mut prev_sane = [0u8; 32];
    prev_sane.copy_from_slice(&b[4..36]);
    prev_sane.reverse();
    let mut prev_hidden = tagged_hash("Bitcoin prevblock header, hashed", &prev_sane);

    let mut h1p = Vec::with_capacity(119);
    h1p.extend_from_slice(&version.to_le_bytes());
    h1p.extend_from_slice(&prev_sane);
    h1p.extend_from_slice(&height.to_le_bytes());
    h1p.extend_from_slice(merkle);
    h1p.extend_from_slice(&time_on_wire.to_le_bytes());
    h1p.push(0);
    h1p.extend_from_slice(&bits.to_le_bytes());
    h1p.extend_from_slice(&txcount.to_le_bytes());
    h1p.extend_from_slice(&[flags, clear_bits]);
    h1p.extend_from_slice(&xor_key_hash);
    let h1 = tagged_hash("Bitcoin block header 1", &h1p);
    let mut h2p = Vec::with_capacity(96);
    h2p.extend_from_slice(&h1);
    h2p.extend_from_slice(&[0u8; 32]);
    h2p.extend_from_slice(mm_rhs);
    let h2 = tagged_hash("Merge-mining hook", &h2p);
    let mut b1p = Vec::with_capacity(52);
    b1p.extend_from_slice(&[0u8; 4]);
    b1p.extend_from_slice(&h2);
    b1p.extend_from_slice(extranonce);
    let blake2b_1 = blake2b256(&b1p);

    let le = |n: u32| n.to_le_bytes();
    let mut asic = Vec::with_capacity(160);
    match flags & 3 {
        0 => {
            prev_hidden[..6].fill(0);
            asic.extend_from_slice(&prev_hidden);
            asic.extend_from_slice(&le(nonce));
            asic.extend_from_slice(&le(nonce2));
            asic.extend_from_slice(&le(time_offset));
            asic.extend_from_slice(&le(nonce3));
            asic.extend_from_slice(&blake2b_1);
        }
        1 => {
            asic.extend_from_slice(&le(nonce));
            asic.extend_from_slice(&le(nonce2));
            asic.extend_from_slice(&le(nonce3));
            asic.extend_from_slice(&le(time_offset));
            asic.extend_from_slice(&blake2b_1);
            asic.extend_from_slice(&h2);
        }
        p => {
            if p == 3 {
                asic.extend_from_slice(&[0u8; 32]);
            }
            asic.extend_from_slice(&[0u8; 48]);
            asic.extend_from_slice(&h2);
            asic.extend_from_slice(&le(nonce));
            asic.extend_from_slice(&le(nonce2));
            asic.extend_from_slice(&le(time_offset));
            asic.extend_from_slice(&le(nonce3));
            asic.extend_from_slice(&blake2b_1);
        }
    }
    let blake2b_2 = blake2b256(&asic);
    let mut block_hash = [0u8; 32];
    for i in 0..32 {
        block_hash[i] = blake2b_2[i] ^ mask[i];
    }
    Ok(V2Stages { xor_key_hash, mask, h1, h2, blake2b_1, asic_input: asic, blake2b_2, block_hash })
}

/// A parsed v2 header (or, below a checkpoint, a v1 header: see [`parse_prior`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Header {
    pub raw: Vec<u8>,
    /// The version field as on the wire (bit 31 set on a v2 header).
    pub version: u32,
    /// The v2 flags byte (0 on a v1 header).
    pub flags: u8,
    /// Block hash, big-endian (display order, as Knots prints it).
    pub hash: [u8; 32],
    /// Parent hash, display order.
    pub prev: [u8; 32],
    /// Merkle root, internal byte order.
    pub merkle_root: [u8; 32],
    /// Block time (the wire time plus the time offset when the header's flag says so).
    pub time: u32,
    pub bits: u32,
    /// Committed height.
    pub height: u32,
    /// Committed transaction count.
    pub txcount: u16,
}

impl Header {
    pub fn target(&self) -> Result<U256> {
        bits_to_target(self.bits)
    }

    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash)
    }

    pub fn prev_hex(&self) -> String {
        hex::encode(self.prev)
    }
}

/// Parse a v2 header and compute its hash.
pub fn parse_header(b: &[u8]) -> Result<Header> {
    let st = v2_stages(b)?;
    let flags = b[110];
    let (time_on_wire, offset) = (u32_at(b, 68), u32_at(b, 104));
    let time = if flags & FLAG_USE_TIME_OFFSET != 0 { time_on_wire.wrapping_add(offset) } else { time_on_wire };
    let mut prev = [0u8; 32];
    prev.copy_from_slice(&b[4..36]);
    prev.reverse();
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&b[36..68]);
    Ok(Header {
        raw: b.to_vec(),
        version: u32_at(b, 0),
        flags,
        hash: st.block_hash,
        prev,
        merkle_root,
        time,
        bits: u32_at(b, 72),
        height: u32_at(b, 128),
        txcount: u16::from_le_bytes([b[108], b[109]]),
    })
}

/// A header below a checkpoint, at `height`: v2 (its committed height must be `height`) or v1
/// (80 bytes, SHA-256d, no committed height). Nothing but its link and time matter: it is trusted
/// because it hashes to the parent the checkpoint (or the header above it) names.
pub fn parse_prior(b: &[u8], height: u32) -> Result<Header> {
    if header_size(b)? == V2_SIZE {
        let h = parse_header(b)?;
        if h.height != height {
            return Err(herr(format!("header {height} commits height {}", h.height)));
        }
        return Ok(h);
    }
    if b.len() != V1_SIZE {
        return Err(herr(format!("a v1 header is {V1_SIZE} bytes, got {}", b.len())));
    }
    let mut prev = [0u8; 32];
    prev.copy_from_slice(&b[4..36]);
    prev.reverse();
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&b[36..68]);
    Ok(Header { raw: b.to_vec(), version: u32_at(b, 0), flags: 0, hash: v1_hash(b)?, prev, merkle_root,
                time: u32_at(b, 68), bits: u32_at(b, 72), height, txcount: 0 })
}

/// The SHA-256d hash (display order) of a v1 (80-byte) header.
pub fn v1_hash(b: &[u8]) -> Result<[u8; 32]> {
    if b.len() < V1_SIZE {
        return Err(herr("a v1 header is 80 bytes"));
    }
    let mut h = dsha256(&b[..V1_SIZE]);
    h.reverse();
    Ok(h)
}

/// A run of headers of either size, walked by each one's version field.
pub fn split_headers(blob: &[u8]) -> Result<Vec<&[u8]>> {
    let (mut out, mut i) = (Vec::new(), 0usize);
    while i < blob.len() {
        let n = header_size(&blob[i..])?;
        if blob.len() - i < n {
            return Err(herr(format!("trailing {} bytes, need {n} for the next header", blob.len() - i)));
        }
        out.push(&blob[i..i + n]);
        i += n;
    }
    Ok(out)
}

/// A whole block (either header version): its header and transactions.
pub fn parse_block(raw: &[u8]) -> Result<(Vec<u8>, Vec<Tx>)> {
    let n = header_size(raw)?;
    if raw.len() < n {
        return Err(herr("block shorter than its header"));
    }
    let mut r = Reader::new(&raw[n..]);
    let count = r.varint()?;
    let mut txs = Vec::new();
    let body = &raw[n..];
    let mut pos = body.len() - r.remaining();
    for _ in 0..count {
        // find each transaction's end by parsing progressively larger prefixes is quadratic;
        // instead parse from the cursor and re-serialize to learn its length
        let tx = parse_tx_prefix(&body[pos..])?;
        pos += tx.serialize().len();
        txs.push(tx);
    }
    if pos != body.len() {
        return Err(herr("trailing bytes after the block's transactions"));
    }
    Ok((raw[..n].to_vec(), txs))
}

fn parse_tx_prefix(b: &[u8]) -> Result<Tx> {
    // A transaction's length is not prefixed: walk it with the same rules as Tx::parse.
    let mut r = Reader::new(b);
    r.take(4)?;
    let mut n_in = r.varint()?;
    let seg = n_in == 0;
    if seg {
        r.u8()?;
        n_in = r.varint()?;
    }
    for _ in 0..n_in {
        r.take(36)?;
        r.varbytes()?;
        r.take(4)?;
    }
    let n_out = r.varint()?;
    for _ in 0..n_out {
        r.take(8)?;
        r.varbytes()?;
    }
    if seg {
        for _ in 0..n_in {
            let k = r.varint()?;
            for _ in 0..k {
                r.varbytes()?;
            }
        }
    }
    r.take(4)?;
    let used = b.len() - r.remaining();
    Tx::parse(&b[..used])
}

// --- chain rules ----------------------------------------------------------------------------

/// What a child's nBits may be: a set of exact values, or a (min, max) target range when the
/// period's first header is below the checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Allowed {
    Exact(Vec<u32>),
    Range(U256, U256),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainRules {
    pub name: &'static str,
    pub pow_limit: U256,
    pub interval: u32,
    pub timespan: u64,
    /// `nPowTargetSpacing`.
    pub spacing: u64,
    pub allow_min_difficulty: bool,
    pub no_retargeting: bool,
    /// (height, display-order hash) every accepted chain has (Knots' checkpoint lock-in).
    pub pins: Vec<(u32, [u8; 32])>,
}

impl ChainRules {
    pub fn main() -> Self {
        Self {
            name: "main",
            pow_limit: U256::from(0xFFFF_u64) << 208,
            interval: 2016,
            timespan: 14 * 24 * 60 * 60,
            spacing: 10 * 60,
            allow_min_difficulty: false,
            no_retargeting: false,
            pins: MAINNET_PINS.iter()
                .map(|(h, x)| (*h, crate::hash::hex32(x).expect("MAINNET_PINS are 64-hex constants")))
                .collect(),
        }
    }

    pub fn regtest() -> Self {
        Self {
            name: "regtest",
            pow_limit: U256::from(0x7F_FFFF_u64) << 232,
            interval: 2016,
            timespan: 14 * 24 * 60 * 60,
            spacing: 10 * 60,
            allow_min_difficulty: true,
            no_retargeting: true,
            pins: Vec::new(),
        }
    }

    /// Main and regtest. Testnet3, testnet4 (BIP94) and signet are refused: fail closed.
    pub fn for_chain(chain: &str) -> Result<Self> {
        match chain {
            "main" => Ok(Self::main()),
            "regtest" => Ok(Self::regtest()),
            other => Err(herr(format!("header rules are known for main and regtest, not {other:?}"))),
        }
    }

    /// Knots `GetNextWorkRequired` for the child of `parent` with time `child_time`. `ancestor(h)`
    /// returns our header at height `h` when we hold it. Where the walk back on a min-difficulty
    /// chain runs past what we hold, the earliest header held stands in for Knots' genesis stop;
    /// on regtest (genesis at powLimit, no retargeting) every block is powLimit either way.
    pub fn next_bits_with<'a>(&self, parent: &'a Header, child_time: u32,
                              ancestor: impl Fn(u32) -> Option<&'a Header>) -> Result<Allowed> {
        let pl_bits = target_to_bits(self.pow_limit);
        let boundary = (parent.height as u64 + 1).is_multiple_of(self.interval as u64);
        if !boundary && self.allow_min_difficulty {
            if child_time as u64 > parent.time as u64 + 2 * self.spacing {
                return Ok(Allowed::Exact(vec![pl_bits]));
            }
            let mut p = parent;
            while !p.height.is_multiple_of(self.interval) && p.bits == pl_bits {
                match p.height.checked_sub(1).and_then(&ancestor) {
                    Some(a) => p = a,
                    None => break,
                }
            }
            return Ok(Allowed::Exact(vec![p.bits]));
        }
        if self.no_retargeting {
            return Ok(Allowed::Exact(vec![parent.bits]));
        }
        let first_time = if boundary {
            (parent.height + 1).checked_sub(self.interval).and_then(&ancestor).map(|f| f.time)
        } else {
            None
        };
        self.next_bits(parent, first_time)
    }

    fn scaled(&self, target: U256, span: u64) -> U256 {
        let t = U512::from(target) * U512::from(span) / U512::from(self.timespan);
        let pl = U512::from(self.pow_limit);
        U256::from(if t < pl { t } else { pl })
    }

    /// The nBits a child of `parent` may carry on a retargeting chain (`first_time`: the time of the
    /// period's first header, when it is known). On a min-difficulty chain this is only the loose
    /// bound {parent, powLimit}; [`Self::next_bits_with`] is the exact rule validation uses.
    pub fn next_bits(&self, parent: &Header, first_time: Option<u32>) -> Result<Allowed> {
        let pl_bits = target_to_bits(self.pow_limit);
        if self.allow_min_difficulty || self.no_retargeting {
            return Ok(Allowed::Exact(vec![parent.bits, pl_bits]));
        }
        if !(parent.height as u64 + 1).is_multiple_of(self.interval as u64) {
            return Ok(Allowed::Exact(vec![parent.bits]));
        }
        let pt = bits_to_target(parent.bits)?;
        if let Some(ft) = first_time {
            let span = (parent.time as i64 - ft as i64).clamp((self.timespan / 4) as i64, (self.timespan * 4) as i64) as u64;
            return Ok(Allowed::Exact(vec![target_to_bits(self.scaled(pt, span))]));
        }
        let lo = bits_to_target(target_to_bits(self.scaled(pt, self.timespan / 4)))?;
        let hi = bits_to_target(target_to_bits(self.scaled(pt, self.timespan * 4)))?;
        Ok(Allowed::Range(lo, hi))
    }
}

/// The hash meets the header's own target, and that target is within powLimit.
pub fn check_pow(h: &Header, rules: &ChainRules) -> Result<()> {
    let target = h.target()?;
    if target.is_zero() || target > rules.pow_limit {
        return Err(herr(format!("block {}: nBits {:08x} outside powLimit", h.height, h.bits)));
    }
    if hash_as_u256(&h.hash) > target {
        return Err(herr(format!("block {}: hash {} does not meet its target {:08x}", h.height, h.hash_hex(), h.bits)));
    }
    Ok(())
}

// --- merkle proofs --------------------------------------------------------------------------

pub fn merkle_depth(txcount: u32) -> u32 {
    if txcount <= 1 {
        0
    } else {
        32 - (txcount - 1).leading_zeros()
    }
}

/// The root (internal byte order) an Electrum merkle branch proves for `txid` (display hex) at
/// `pos`. With the header's committed `txcount`, a branch of the wrong depth or a position past
/// the end is refused (no CVE-2017-12842 64-byte inner-node forgeries).
pub fn merkle_root_from_proof(txid: &[u8; 32], branch: &[[u8; 32]], pos: u64, txcount: Option<u32>) -> Result<[u8; 32]> {
    if let Some(n) = txcount {
        if n < 1 || pos >= n as u64 {
            return Err(herr(format!("merkle position {pos} is outside the block's {n} transactions")));
        }
        if branch.len() as u32 != merkle_depth(n) {
            return Err(herr(format!("merkle branch of {} for a block of {n} transactions", branch.len())));
        }
    }
    let mut h = *txid;
    h.reverse();
    let mut idx = pos;
    for sib_display in branch {
        let mut sib = *sib_display;
        sib.reverse();
        let mut cat = [0u8; 64];
        if idx & 1 == 1 {
            cat[..32].copy_from_slice(&sib);
            cat[32..].copy_from_slice(&h);
        } else {
            cat[..32].copy_from_slice(&h);
            cat[32..].copy_from_slice(&sib);
        }
        h = dsha256(&cat);
        idx >>= 1;
    }
    if idx != 0 {
        return Err(herr("merkle position does not fit the branch"));
    }
    Ok(h)
}

/// Bitcoin merkle root over txids in internal byte order.
pub fn merkle_root(txids: &[[u8; 32]]) -> [u8; 32] {
    if txids.is_empty() {
        return [0; 32];
    }
    let mut level = txids.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(level[level.len() - 1]);
        }
        level = level
            .chunks(2)
            .map(|c| {
                let mut cat = [0u8; 64];
                cat[..32].copy_from_slice(&c[0]);
                cat[32..].copy_from_slice(&c[1]);
                dsha256(&cat)
            })
            .collect();
    }
    level[0]
}

// --- the header chain -----------------------------------------------------------------------

/// Result of [`HeaderChain::connect`] and [`HeaderChain::adopt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectResult {
    pub adopted: bool,
    pub tip: u32,
    pub reorg: u32,
}

/// The current unix time (the 2 h future rule).
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Headers from a pinned checkpoint to the most-work tip seen, each one verified. Optionally
/// persisted (the raw headers, re-verified on load).
pub struct HeaderChain {
    pub rules: ChainRules,
    pub chain: String,
    cp_height: u32,
    cp_hash: [u8; 32],
    path: Option<PathBuf>,
    clock: Clock,
    /// The headers below the checkpoint ([`PRIOR_HEADERS`], fewer only near genesis), oldest first.
    prior: Vec<Header>,
    headers: Vec<Header>,
    work: Vec<U512>,
}

/// Headers validated on top of one of ours without holding the chain: made by
/// [`HeaderChain::branch`], grown by [`Branch::extend`] as each chunk arrives, applied by
/// [`HeaderChain::adopt`].
pub struct Branch {
    rules: ChainRules,
    clock: Clock,
    /// Our headers up to the fork point (contiguous, as far back as the rules look), then the new ones.
    known: Vec<Header>,
    base_len: usize,
    /// (height, hash) of the fork point.
    base: (u32, [u8; 32]),
    /// Work above the checkpoint at the branch tip.
    work: U512,
}

impl Branch {
    pub fn fork_height(&self) -> u32 {
        self.base.0
    }

    pub fn len(&self) -> usize {
        self.known.len() - self.base_len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn tip_height(&self) -> u32 {
        self.base.0 + self.len() as u32
    }

    /// Work above the checkpoint at the branch tip.
    pub fn work(&self) -> U512 {
        self.work
    }

    fn at(&self, height: u32) -> Option<&Header> {
        let first = self.known.first()?.height;
        self.known.get(height.checked_sub(first)? as usize).filter(|h| h.height == height)
    }

    /// Validate `raws` in order on top of the branch. The first invalid header stops it: the
    /// headers before it stay (they carry real work), it and the rest are dropped, and its reason
    /// is the error.
    pub fn extend<R: AsRef<[u8]>>(&mut self, raws: &[R]) -> Result<()> {
        for raw in raws {
            let raw = raw.as_ref();
            if header_size(raw)? != V2_SIZE {
                return Err(herr(format!("block {} is a v1 header above the BLAKE2b checkpoint", self.tip_height() as u64 + 1)));
            }
            let h = parse_header(raw)?;
            self.validate(&h)?;
            self.work += work_of(h.bits)?;
            self.known.push(h);
        }
        Ok(())
    }

    fn validate(&self, h: &Header) -> Result<()> {
        let parent = self.known.last().ok_or_else(|| herr("a branch has its fork point"))?;
        let n = parent.height as u64 + 1;
        if h.prev != parent.hash {
            return Err(herr(format!("block {n} does not link to {}", parent.hash_hex())));
        }
        if h.height as u64 != n {
            return Err(herr(format!("block {n} commits height {}", h.height)));
        }
        if h.flags & FLAGS_RESERVED != 0 {
            return Err(herr(format!("block {n}: bad-flags-highbits (flags {:02x})", h.flags)));
        }
        if h.version & !V2_FLAG < MIN_VERSION {
            return Err(herr(format!("block {n}: bad-version ({:08x})", h.version)));
        }
        if let Some((_, pin)) = self.rules.pins.iter().find(|p| p.0 == h.height) {
            if &h.hash != pin {
                return Err(herr(format!("block {n}: checkpoint-mismatch, {} is pinned", hex::encode(pin))));
            }
        }
        check_pow(h, &self.rules)?;
        match self.rules.next_bits_with(parent, h.time, |x| self.at(x))? {
            Allowed::Exact(v) => {
                if !v.contains(&h.bits) {
                    return Err(herr(format!("block {n}: nBits {:08x}, expected {:?}", h.bits,
                                            v.iter().map(|b| format!("{b:08x}")).collect::<Vec<_>>())));
                }
            }
            Allowed::Range(lo, hi) => {
                let t = h.target()?;
                if t < lo || t > hi {
                    return Err(herr(format!("block {n}: nBits {:08x} outside the permitted retarget", h.bits)));
                }
            }
        }
        // GetMedianTimePast: the 11 before it, fewer only near genesis
        let prior = &self.known[self.known.len().saturating_sub(MEDIAN_SPAN)..];
        let mut times: Vec<u32> = prior.iter().map(|x| x.time).collect();
        times.sort_unstable();
        let mtp = times[times.len() / 2];
        if h.time <= mtp {
            return Err(herr(format!("block {n}: time {} not above the median {mtp}", h.time)));
        }
        if h.time as u64 > (self.clock)() + MAX_FUTURE_S {
            return Err(herr(format!("block {n}: time {} is more than 2 h in the future", h.time)));
        }
        Ok(())
    }
}

impl HeaderChain {
    /// `checkpoint` = (height, display hex hash). `path` persists the chain; `clock` gives the
    /// current unix time (the 2 h future rule).
    pub fn new(chain: &str, checkpoint: (u32, &str), path: Option<&Path>,
               clock: impl Fn() -> u64 + Send + Sync + 'static) -> Result<Self> {
        Self::with_clock(chain, checkpoint, path, Arc::new(clock))
    }

    pub fn with_clock(chain: &str, checkpoint: (u32, &str), path: Option<&Path>, clock: Clock) -> Result<Self> {
        let mut c = Self {
            rules: ChainRules::for_chain(chain)?,
            chain: chain.to_string(),
            cp_height: checkpoint.0,
            cp_hash: crate::hash::hex32(checkpoint.1)?,
            path: path.map(Path::to_path_buf),
            clock,
            prior: Vec::new(),
            headers: Vec::new(),
            work: Vec::new(),
        };
        c.load();
        Ok(c)
    }

    /// A chain with the system clock.
    pub fn with_system_clock(chain: &str, checkpoint: (u32, &str), path: Option<&Path>) -> Result<Self> {
        Self::new(chain, checkpoint, path, || {
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
        })
    }

    pub fn checkpoint(&self) -> (u32, [u8; 32]) {
        (self.cp_height, self.cp_hash)
    }

    /// How many headers below the checkpoint [`Self::set_checkpoint`] needs.
    pub fn prior_needed(&self) -> u32 {
        PRIOR_HEADERS.min(self.cp_height)
    }

    pub fn ready(&self) -> bool {
        !self.headers.is_empty()
    }

    pub fn tip_height(&self) -> Result<u32> {
        if self.headers.is_empty() {
            return Err(herr("no verified headers yet (checkpoint not fetched)"));
        }
        Ok(self.cp_height + self.headers.len() as u32 - 1)
    }

    pub fn tip(&self) -> Option<&Header> {
        self.headers.last()
    }

    pub fn at(&self, height: u32) -> Option<&Header> {
        height.checked_sub(self.cp_height).and_then(|i| self.headers.get(i as usize))
    }

    pub fn height_of(&self, hash: &[u8; 32]) -> Option<u32> {
        self.headers.iter().rposition(|h| &h.hash == hash).map(|i| self.cp_height + i as u32)
    }

    /// Cumulative work above the checkpoint.
    pub fn total_work(&self) -> U512 {
        self.work.last().copied().unwrap_or(U512::ZERO)
    }

    /// Why this chain is not believable yet, or None: it must reach every pinned height above the
    /// checkpoint, carry `min_work_above` the checkpoint, and with `floor = (spacing_s, slack)` its
    /// tip may not trail the newest pinned block it holds (or the checkpoint) by more than `slack`
    /// blocks at one block per `spacing_s` since that block's time.
    pub fn implausible(&self, min_work_above: U512, floor: Option<(u64, u32)>) -> Option<String> {
        let Some(tip) = self.tip() else { return Some("no verified headers yet".into()) };
        let tip_h = tip.height;
        if let Some((h, _)) = self.rules.pins.iter().find(|(h, _)| *h > self.cp_height && tip_h < *h) {
            return Some(format!("tip {tip_h} is below the pinned block {h}"));
        }
        let work = self.total_work();
        if work < min_work_above {
            return Some(format!("work above the checkpoint {work:#x} is below the minimum {min_work_above:#x}"));
        }
        let (spacing, slack) = floor?;
        let base = self.rules.pins.iter().filter_map(|(h, _)| self.at(*h)).max_by_key(|h| h.height).or_else(|| self.headers.first())?;
        let expected = base.height as u64 + ((self.clock)().saturating_sub(base.time as u64)) / spacing.max(1);
        ((tip_h as u64 + slack as u64) < expected).then(|| {
            format!("tip {tip_h} is implausibly low: block {expected} expected by now at one per {spacing} s from block {}", base.height)
        })
    }

    /// The checkpoint header, whose hash must be the pinned one, and the [`Self::prior_needed`]
    /// headers below it (oldest first), each hash-linked to the one above it.
    pub fn set_checkpoint<R: AsRef<[u8]>>(&mut self, raw: &[u8], prior: &[R]) -> Result<()> {
        let h = parse_header(raw)?;
        if h.hash != self.cp_hash {
            return Err(herr(format!("checkpoint {} hashes to {}, not the pinned {}", self.cp_height, h.hash_hex(), hex::encode(self.cp_hash))));
        }
        if h.height != self.cp_height {
            return Err(herr(format!("checkpoint commits height {}, not {}", h.height, self.cp_height)));
        }
        check_pow(&h, &self.rules)?;
        let want = self.prior_needed() as usize;
        if prior.len() != want {
            return Err(herr(format!("the checkpoint needs the {want} headers below it, got {}", prior.len())));
        }
        let mut below = Vec::with_capacity(want);
        let mut child = h.prev;
        for (i, r) in prior.iter().enumerate().rev() {
            let height = self.cp_height - (want - i) as u32;
            let p = parse_prior(r.as_ref(), height)?;
            if p.hash != child {
                return Err(herr(format!("header {height} is not the parent of header {}", height + 1)));
            }
            child = p.prev;
            below.push(p);
        }
        below.reverse();
        if self.headers.is_empty() {
            self.prior = below;
            self.headers = vec![h];
            self.work = vec![U512::ZERO];
            self.save();
        }
        Ok(())
    }

    /// A branch to grow on our header at `fork_height` (see [`Branch`]).
    pub fn branch(&self, fork_height: u32) -> Result<Branch> {
        let i0 = fork_height.checked_sub(self.cp_height).map(|i| i as usize).filter(|&i| i < self.headers.len())
            .ok_or_else(|| herr(format!("no header of ours at {fork_height} to build on")))?;
        // back far enough for a retarget's first header, the min-difficulty walk and the median
        let back = (self.rules.interval as usize).max(MEDIAN_SPAN);
        let start = (i0 + 1).saturating_sub(back);
        let mut known = Vec::with_capacity(back);
        if start == 0 {
            let more = back - (i0 + 1);
            known.extend_from_slice(&self.prior[self.prior.len().saturating_sub(more)..]);
        }
        known.extend_from_slice(&self.headers[start..=i0]);
        Ok(Branch { rules: self.rules.clone(), clock: self.clock.clone(), base_len: known.len(), known,
                    base: (fork_height, self.headers[i0].hash), work: self.work[i0] })
    }

    /// Apply a branch: it replaces ours above its fork point only if it has more work and the fork
    /// point is still ours (if another branch moved our chain under it, the next sync redoes it).
    pub fn adopt(&mut self, b: Branch) -> Result<ConnectResult> {
        let tip = self.tip_height()?;
        let still_ours = self.at(b.base.0).map(|h| h.hash) == Some(b.base.1);
        if b.is_empty() || !still_ours || b.work <= self.total_work() {
            return Ok(ConnectResult { adopted: false, tip, reorg: 0 });
        }
        let i0 = (b.base.0 - self.cp_height) as usize;
        let reorg = (self.headers.len() - 1 - i0) as u32;
        let branch = &b.known[b.base_len..];
        let mut cum = self.work[i0];
        let mut works = Vec::with_capacity(branch.len());
        for h in branch {
            cum += work_of(h.bits)?;
            works.push(cum);
        }
        self.headers.truncate(i0 + 1);
        self.headers.extend_from_slice(branch);
        self.work.truncate(i0 + 1);
        self.work.extend(works);
        self.save();
        Ok(ConnectResult { adopted: true, tip: self.tip_height()?, reorg })
    }

    /// Headers `fork_height+1..` that build on our header at `fork_height`, all or nothing. The
    /// branch replaces ours above `fork_height` only if it has more work.
    pub fn connect<R: AsRef<[u8]>>(&mut self, fork_height: u32, raws: &[R]) -> Result<ConnectResult> {
        let mut b = self.branch(fork_height)?;
        b.extend(raws)?;
        self.adopt(b)
    }

    fn meta_path(&self) -> Option<PathBuf> {
        self.path.as_ref().map(|p| p.with_extension("json"))
    }

    fn save(&self) {
        let (Some(p), Some(meta)) = (self.path.as_ref(), self.meta_path()) else { return };
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let tmp = p.with_extension("tmp");
        let blob: Vec<u8> = self.prior.iter().chain(&self.headers).flat_map(|h| h.raw.iter().copied()).collect();
        if std::fs::write(&tmp, blob).and_then(|_| std::fs::rename(&tmp, p)).is_ok() {
            let tip = self.cp_height + self.headers.len() as u32 - 1;
            let _ = std::fs::write(meta, format!(
                "{{\"chain\": \"{}\", \"checkpoint\": [{}, \"{}\"], \"prior\": {}, \"tip\": {}}}",
                self.chain, self.cp_height, hex::encode(self.cp_hash), self.prior.len(), tip));
        }
    }

    /// A store without the headers below the checkpoint (older releases) is ignored: the chain is
    /// fetched again.
    fn load(&mut self) {
        let (Some(p), Some(meta)) = (self.path.clone(), self.meta_path()) else { return };
        let (Ok(blob), Ok(m)) = (std::fs::read(&p), std::fs::read_to_string(&meta)) else { return };
        let want = format!("\"checkpoint\": [{}, \"{}\"], \"prior\": {}, ", self.cp_height, hex::encode(self.cp_hash), self.prior_needed());
        if !m.contains(&format!("\"chain\": \"{}\"", self.chain)) || !m.contains(&want) {
            return;
        }
        let n = self.prior_needed() as usize;
        let ok = (|| -> Result<()> {
            let raws = split_headers(&blob)?;
            if raws.len() <= n {
                return Ok(());
            }
            self.set_checkpoint(raws[n], &raws[..n])?;
            self.connect(self.cp_height, &raws[n + 1..])?;
            Ok(())
        })();
        if ok.is_err() {
            self.prior.clear();
            self.headers.clear();
            self.work.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_round_trips() {
        for bits in [0x1D00_FFFFu32, 0x207F_FFFF, 0x1B04_864C, 0x1703_4219] {
            assert_eq!(target_to_bits(bits_to_target(bits).unwrap()), bits);
        }
        assert!(bits_to_target(0x0480_0001).is_err());
        assert!(bits_to_target(0xFF12_3456).is_err());
        assert_eq!(bits_to_target(0x0100_0000).unwrap(), U256::ZERO);
        assert_eq!(work_of(0x1D00_FFFF).unwrap(), U512::from(0x1_0001_0001_u64));
    }

    #[test]
    fn mainnet_minimum_work() {
        let cp = crate::hash::hex32(MAINNET_CHECKPOINT.1).unwrap();
        // nMinimumChainWork (= chainwork of 964264) minus the chainwork of 961640
        let above = mainnet_min_work_above((MAINNET_CHECKPOINT.0, &cp)).unwrap();
        assert_eq!(above, U512::from(0x0010_c428_4b55_92c3_c377_u128));
        assert_eq!(mainnet_min_work_above((964_264, &[0; 32])), Some(U512::ZERO));
        assert_eq!(mainnet_min_work_above((962_000, &[0; 32])), None, "an older anchor of unknown chainwork");
        assert!(parse_chainwork("zz").is_err());
        assert_eq!(ChainRules::main().pins.len(), MAINNET_PINS.len());
    }

    #[test]
    fn merkle_helpers() {
        assert_eq!(merkle_depth(1), 0);
        assert_eq!(merkle_depth(2), 1);
        assert_eq!(merkle_depth(5), 3);
        let ids: Vec<[u8; 32]> = (0u8..5).map(|i| [i; 32]).collect();
        let root = merkle_root(&ids);
        // branch for position 3, built by hand
        let l1: Vec<[u8; 32]> = vec![ids[0], ids[1], ids[2], ids[3], ids[4], ids[4]];
        let pair = |a: &[u8; 32], b: &[u8; 32]| { let mut c = [0u8; 64]; c[..32].copy_from_slice(a); c[32..].copy_from_slice(b); dsha256(&c) };
        let l2 = [pair(&l1[0], &l1[1]), pair(&l1[2], &l1[3]), pair(&l1[4], &l1[5]), pair(&l1[4], &l1[5])];
        let disp = |x: &[u8; 32]| { let mut y = *x; y.reverse(); y };
        let branch = [disp(&ids[2]), disp(&l2[0]), disp(&pair(&l2[2], &l2[3]))];
        assert_eq!(merkle_root_from_proof(&disp(&ids[3]), &branch, 3, Some(5)).unwrap(), root);
        assert!(merkle_root_from_proof(&disp(&ids[3]), &branch, 3, Some(9)).is_err());
        assert!(merkle_root_from_proof(&disp(&ids[3]), &branch, 5, Some(5)).is_err());
    }
}
