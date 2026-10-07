//! BLAKE2b block headers (v2, 164 bytes), proof of work, the Knots retarget and a most-work
//! header chain from a pinned checkpoint. A port of B2 `agentwallet/headers.py` (AGP-024), which
//! ports electrs' `headerv2.rs`.
//!
//! A header is accepted by [`HeaderChain`] only when:
//! * it is a v2 header (164 bytes, bit 31 of the version set) whose committed height is its height;
//! * it links to its parent by hash;
//! * its BLAKE2b block hash meets the target its nBits encode, within powLimit;
//! * its nBits follow Knots' `pow.cpp`: unchanged inside a 2016-block period and, at a period
//!   boundary, exactly `CalculateNextWorkRequired` when the period's first header is known, else
//!   within `PermittedDifficultyTransition`'s 4x bounds; regtest allows the parent's nBits or
//!   powLimit;
//! * its time is above the median of the 11 before it and at most 2 h in the future.
//!
//! Of competing branches the one with the most work wins (first seen wins a tie).
use std::path::{Path, PathBuf};

use ruint::aliases::{U256, U512};

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
/// Mainnet's pinned checkpoint: the first BLAKE2b block.
pub const MAINNET_CHECKPOINT: (u32, &str) =
    (961_640, "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb");

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

/// A parsed v2 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub raw: Vec<u8>,
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
        hash: st.block_hash,
        prev,
        merkle_root,
        time,
        bits: u32_at(b, 72),
        height: u32_at(b, 128),
        txcount: u16::from_le_bytes([b[108], b[109]]),
    })
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
    pub allow_min_difficulty: bool,
    pub no_retargeting: bool,
}

impl ChainRules {
    pub fn main() -> Self {
        Self {
            name: "main",
            pow_limit: U256::from(0xFFFF_u64) << 208,
            interval: 2016,
            timespan: 14 * 24 * 60 * 60,
            allow_min_difficulty: false,
            no_retargeting: false,
        }
    }

    pub fn regtest() -> Self {
        Self {
            name: "regtest",
            pow_limit: U256::from(0x7F_FFFF_u64) << 232,
            interval: 2016,
            timespan: 14 * 24 * 60 * 60,
            allow_min_difficulty: true,
            no_retargeting: true,
        }
    }

    pub fn for_chain(chain: &str) -> Result<Self> {
        match chain {
            "main" => Ok(Self::main()),
            "regtest" => Ok(Self::regtest()),
            other => Err(herr(format!("header rules are known for main and regtest, not {other:?}"))),
        }
    }

    fn scaled(&self, target: U256, span: u64) -> U256 {
        let t = U512::from(target) * U512::from(span) / U512::from(self.timespan);
        let pl = U512::from(self.pow_limit);
        U256::from(if t < pl { t } else { pl })
    }

    /// The nBits a child of `parent` may carry (`first_time`: the time of the period's first
    /// header, when it is known).
    pub fn next_bits(&self, parent: &Header, first_time: Option<u32>) -> Result<Allowed> {
        let pl_bits = target_to_bits(self.pow_limit);
        if self.allow_min_difficulty || self.no_retargeting {
            return Ok(Allowed::Exact(vec![parent.bits, pl_bits]));
        }
        if (parent.height as u64 + 1) % self.interval as u64 != 0 {
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

/// Result of [`HeaderChain::connect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectResult {
    pub adopted: bool,
    pub tip: u32,
    pub reorg: u32,
}

/// Headers from a pinned checkpoint to the most-work tip seen, each one verified. Optionally
/// persisted (the raw headers, re-verified on load).
pub struct HeaderChain {
    pub rules: ChainRules,
    pub chain: String,
    cp_height: u32,
    cp_hash: [u8; 32],
    path: Option<PathBuf>,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
    headers: Vec<Header>,
    work: Vec<U512>,
}

impl HeaderChain {
    /// `checkpoint` = (height, display hex hash). `path` persists the chain; `clock` gives the
    /// current unix time (the 2 h future rule).
    pub fn new(chain: &str, checkpoint: (u32, &str), path: Option<&Path>,
               clock: Box<dyn Fn() -> u64 + Send + Sync>) -> Result<Self> {
        let mut c = Self {
            rules: ChainRules::for_chain(chain)?,
            chain: chain.to_string(),
            cp_height: checkpoint.0,
            cp_hash: crate::hash::hex32(checkpoint.1)?,
            path: path.map(Path::to_path_buf),
            clock,
            headers: Vec::new(),
            work: Vec::new(),
        };
        c.load();
        Ok(c)
    }

    /// A chain with the system clock.
    pub fn with_system_clock(chain: &str, checkpoint: (u32, &str), path: Option<&Path>) -> Result<Self> {
        Self::new(chain, checkpoint, path, Box::new(|| {
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
        }))
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

    /// The checkpoint header itself: its hash must be the pinned one.
    pub fn set_checkpoint(&mut self, raw: &[u8]) -> Result<()> {
        let h = parse_header(raw)?;
        if h.hash != self.cp_hash {
            return Err(herr(format!("checkpoint {} hashes to {}, not the pinned {}", self.cp_height, h.hash_hex(), hex::encode(self.cp_hash))));
        }
        if h.height != self.cp_height {
            return Err(herr(format!("checkpoint commits height {}, not {}", h.height, self.cp_height)));
        }
        check_pow(&h, &self.rules)?;
        if self.headers.is_empty() {
            self.headers = vec![h];
            self.work = vec![U512::ZERO];
            self.save();
        }
        Ok(())
    }

    fn ancestor<'a>(&'a self, height: u32, ancestors: &'a [Header]) -> Option<&'a Header> {
        ancestors.iter().rev().find(|a| a.height == height).or_else(|| if height >= self.cp_height { self.at(height) } else { None })
    }

    fn validate(&self, parent: &Header, h: &Header, ancestors: &[Header]) -> Result<()> {
        if h.prev != parent.hash {
            return Err(herr(format!("block {} does not link to {}", parent.height as u64 + 1, parent.hash_hex())));
        }
        if h.height as u64 != parent.height as u64 + 1 {
            return Err(herr(format!("block {} commits height {}", parent.height as u64 + 1, h.height)));
        }
        check_pow(h, &self.rules)?;
        let mut first_time = None;
        if !(self.rules.allow_min_difficulty || self.rules.no_retargeting) && h.height % self.rules.interval == 0 {
            if let Some(first) = h.height.checked_sub(self.rules.interval) {
                first_time = self.ancestor(first, ancestors).map(|f| f.time);
            }
        }
        match self.rules.next_bits(parent, first_time)? {
            Allowed::Exact(v) => {
                if !v.contains(&h.bits) {
                    return Err(herr(format!("block {}: nBits {:08x}, expected {:?}", h.height, h.bits,
                                            v.iter().map(|b| format!("{b:08x}")).collect::<Vec<_>>())));
                }
            }
            Allowed::Range(lo, hi) => {
                let t = h.target()?;
                if t < lo || t > hi {
                    return Err(herr(format!("block {}: nBits {:08x} outside the permitted retarget", h.height, h.bits)));
                }
            }
        }
        let prior = &ancestors[ancestors.len().saturating_sub(MEDIAN_SPAN)..];
        if prior.len() == MEDIAN_SPAN {
            let mut times: Vec<u32> = prior.iter().map(|x| x.time).collect();
            times.sort_unstable();
            let mtp = times[MEDIAN_SPAN / 2];
            if h.time <= mtp {
                return Err(herr(format!("block {}: time {} not above the median {mtp}", h.height, h.time)));
            }
        }
        if h.time as u64 > (self.clock)() + MAX_FUTURE_S {
            return Err(herr(format!("block {}: time {} is more than 2 h in the future", h.height, h.time)));
        }
        Ok(())
    }

    /// Headers `fork_height+1..` that build on our header at `fork_height`. The branch replaces
    /// ours above `fork_height` only if it has more work.
    pub fn connect<R: AsRef<[u8]>>(&mut self, fork_height: u32, raws: &[R]) -> Result<ConnectResult> {
        let base = self.at(fork_height).cloned().ok_or_else(|| herr(format!("no header of ours at {fork_height} to build on")))?;
        let i0 = (fork_height - self.cp_height) as usize;
        let start = (i0 + 1).saturating_sub(self.rules.interval as usize);
        let mut ancestors: Vec<Header> = self.headers[start..=i0].to_vec();
        let base_len = ancestors.len();
        let mut work = self.work[i0];
        let mut parent = base;
        for raw in raws {
            let raw = raw.as_ref();
            if header_size(raw)? != V2_SIZE {
                return Err(herr(format!("block {} is a v1 header above the BLAKE2b checkpoint", parent.height as u64 + 1)));
            }
            let h = parse_header(raw)?;
            self.validate(&parent, &h, &ancestors)?;
            work += work_of(h.bits)?;
            ancestors.push(h.clone());
            parent = h;
        }
        let branch = ancestors.split_off(base_len);
        let tip = self.tip_height()?;
        if branch.is_empty() || work <= self.total_work() {
            return Ok(ConnectResult { adopted: false, tip, reorg: 0 });
        }
        let reorg = (self.headers.len() - 1 - i0) as u32;
        let mut cum = self.work[i0];
        let mut works = Vec::with_capacity(branch.len());
        for h in &branch {
            cum += work_of(h.bits)?;
            works.push(cum);
        }
        self.headers.truncate(i0 + 1);
        self.headers.extend(branch);
        self.work.truncate(i0 + 1);
        self.work.extend(works);
        self.save();
        Ok(ConnectResult { adopted: true, tip: self.tip_height()?, reorg })
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
        let blob: Vec<u8> = self.headers.iter().flat_map(|h| h.raw.iter().copied()).collect();
        if std::fs::write(&tmp, blob).and_then(|_| std::fs::rename(&tmp, p)).is_ok() {
            let tip = self.cp_height + self.headers.len() as u32 - 1;
            let _ = std::fs::write(meta, format!(
                "{{\"chain\": \"{}\", \"checkpoint\": [{}, \"{}\"], \"tip\": {}}}",
                self.chain, self.cp_height, hex::encode(self.cp_hash), tip));
        }
    }

    fn load(&mut self) {
        let (Some(p), Some(meta)) = (self.path.clone(), self.meta_path()) else { return };
        let (Ok(blob), Ok(m)) = (std::fs::read(&p), std::fs::read_to_string(&meta)) else { return };
        let want = format!("\"checkpoint\": [{}, \"{}\"]", self.cp_height, hex::encode(self.cp_hash));
        if !m.contains(&format!("\"chain\": \"{}\"", self.chain)) || !m.contains(&want) {
            return;
        }
        let ok = (|| -> Result<()> {
            let raws = split_headers(&blob)?;
            let Some((first, rest)) = raws.split_first() else { return Ok(()) };
            self.set_checkpoint(first)?;
            self.connect(self.cp_height, rest)?;
            Ok(())
        })();
        if ok.is_err() {
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
