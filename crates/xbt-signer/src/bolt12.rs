//! BOLT 12 offers and invoices, read and checked here (AGP-082), not taken from the Lightning node.
//!
//! The `rail=ln` payer reads an offer (`lno1...`) itself: its id, the chains it names, its amount, its
//! expiry, its issuer and its feature bits. It then reads the invoice (`lni1...`) the node fetched for
//! it, verifies the issuer's signature over the invoice's Merkle root, and checks the invoice against
//! the offer ([`check_invoice`]), so the policy decision never rests on what the LN node says either
//! of them means. The node's own summary of the invoice is then compared field by field
//! ([`crate::ln_offer`]). Only the fields those checks use are read; this is not an offer stack, and
//! nothing here writes an invoice request (the node does that).
//!
//! XBT Lightning keeps Bitcoin's genesis chain hash, and BOLT 12 reads an offer that names no chain as
//! Bitcoin mainnet, so on mainnet a chain-less offer names this chain and SHA-256 Bitcoin alike. What
//! separates the two is the compulsory feature bit 512 (`option_blake2b`), as on BOLT 11
//! ([`crate::bolt11::FEATURE_BLAKE2B`]): [`check_offer`] and [`check_invoice`] refuse without it.
//!
//! Every length and count comes off the wire, so each is bounded before it is used: a string is at
//! most [`MAX_LEN`] characters, a stream at most [`MAX_RECORDS`] records, a paths field at most
//! [`MAX_PATHS`] paths, and a field's length is checked against the bytes left before it is sliced.
//! Nothing is allocated from a length the input names. The reader is checked against the
//! specification's test vectors (`tests/data/bolt12`) and against truncated and mutated input.
use sha2::{Digest, Sha256};
use xbt_primitives::secp256k1::{schnorr, Message, PublicKey, Secp256k1};

use crate::bolt11::FEATURE_BLAKE2B;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// A BOLT 12 string longer than this, once its `+` joins are removed, is refused before any work
/// (the specification sets no limit; an offer with blinded paths is about 1,000 characters).
pub const MAX_LEN: usize = 16_384;
/// The most TLV records a stream may hold (an invoice from Lightning Fork has about twenty).
pub const MAX_RECORDS: usize = 64;
/// The most blinded paths a paths field may hold.
pub const MAX_PATHS: usize = 16;
/// The chain BOLT 12 means when a message names none: Bitcoin's genesis block hash, in wire order.
/// XBT mainnet shares it.
pub const BITCOIN_GENESIS: [u8; 32] = [0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f, 0x93, 0x1e,
                                       0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00];
/// `invoice_relative_expiry` when the invoice omits it.
pub const DEFAULT_RELATIVE_EXPIRY_S: u64 = 7200;

/// A refusal: `(rule, reason)`, as [`crate::ln::check_invoice`] gives them.
pub type Refusal = (String, String);

/// A blinded path, as far as the checks need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedPath {
    pub hops: usize,
    /// The last hop's blinded node id: the key that signs the invoice of an offer with no issuer id.
    pub last_blinded_node: [u8; 33],
}

/// One `blinded_payinfo` of an invoice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayInfo {
    pub fee_base_msat: u32,
    pub fee_proportional_millionths: u32,
    pub cltv_expiry_delta: u16,
    pub htlc_minimum_msat: u64,
    pub htlc_maximum_msat: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// SHA-256 of the offer's TLV stream: Core Lightning's offer id, which Lightning Fork reports too.
    pub id: [u8; 32],
    /// The TLV stream: an invoice for this offer repeats it byte for byte.
    pub tlv: Vec<u8>,
    /// `offer_chains`; `None`: the offer names no chain, which BOLT 12 reads as Bitcoin mainnet.
    pub chains: Option<Vec<[u8; 32]>>,
    pub currency: Option<String>,
    /// `offer_amount`, in msat when there is no currency; `None`: the payer chooses.
    pub amount: Option<u64>,
    pub description: Option<String>,
    /// `offer_features`, as on the wire (big-endian).
    pub features: Vec<u8>,
    pub absolute_expiry: Option<u64>,
    pub paths: Vec<BlindedPath>,
    pub issuer: Option<String>,
    pub quantity_max: Option<u64>,
    pub issuer_id: Option<[u8; 33]>,
    /// Whether it carries fields in the experimental range (1,000,000,000 and up).
    pub experimental: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invoice {
    /// The offer fields it repeats (types 1 to 79), and their SHA-256: the id of the offer it answers.
    pub offer_tlv: Vec<u8>,
    pub offer_id: [u8; 32],
    /// `invreq_chain`; `None`: Bitcoin mainnet's.
    pub chain: Option<[u8; 32]>,
    pub invreq_amount: Option<u64>,
    pub quantity: Option<u64>,
    /// `invreq_payer_id`: the key the node signed its request with. Lightning Fork draws a new one for
    /// every request, so it identifies one payment, not a payer.
    pub payer_id: [u8; 33],
    pub paths: Vec<BlindedPath>,
    pub payinfo: Vec<PayInfo>,
    pub created_at: u64,
    pub relative_expiry: u64,
    pub payment_hash: [u8; 32],
    pub amount_msat: u64,
    pub features: Vec<u8>,
    /// `invoice_node_id`: the key whose signature over the invoice was verified.
    pub node_id: [u8; 33],
}

impl Offer {
    pub fn id_hex(&self) -> String {
        hex::encode(self.id)
    }

    pub fn has_feature(&self, bit: usize) -> bool {
        feature_set(&self.features, bit)
    }

    /// The chains the offer is for, with the specification's default.
    pub fn names_chain(&self, chain: &[u8; 32]) -> bool {
        match &self.chains {
            Some(c) => c.contains(chain),
            None => *chain == BITCOIN_GENESIS,
        }
    }
}

impl Invoice {
    pub fn has_feature(&self, bit: usize) -> bool {
        feature_set(&self.features, bit)
    }

    pub fn payment_hash_hex(&self) -> String {
        hex::encode(self.payment_hash)
    }

    /// The amount in whole sats, rounded up (as [`crate::bolt11::Invoice::amount_sats_ceil`]).
    pub fn amount_sats_ceil(&self) -> u64 {
        self.amount_msat.div_ceil(1000)
    }

    /// When the invoice stops being payable (unix seconds).
    pub fn expires_at(&self) -> u64 {
        self.created_at.saturating_add(self.relative_expiry)
    }
}

/// Whether `bit` is set in a feature vector (big-endian bytes).
pub fn feature_set(features: &[u8], bit: usize) -> bool {
    features.len().checked_sub(1 + bit / 8).is_some_and(|i| (features[i] >> (bit % 8)) & 1 == 1)
}

// --- the string ---------------------------------------------------------------------------------------

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// A BOLT 12 string: bech32 without a checksum, `+` (and whitespace after it) joining its parts:
/// `(prefix, TLV bytes)`.
pub fn bech32_decode(s: &str) -> Result<(String, Vec<u8>), String> {
    let raw = s.as_bytes();
    if raw.len() > 2 * MAX_LEN {
        return Err(format!("the string is {} characters (limit {})", raw.len(), 2 * MAX_LEN));
    }
    let mut clean = Vec::with_capacity(raw.len().min(MAX_LEN));
    let mut i = 0;
    while i < raw.len() {
        let c = raw[i];
        if c == b'+' {
            // a join stands between two characters that are neither whitespace nor a join
            let mut j = i + 1;
            while j < raw.len() && is_space(raw[j]) {
                j += 1;
            }
            if i == 0 || raw[i - 1] == b'+' || is_space(raw[i - 1]) || j >= raw.len() || raw[j] == b'+' {
                return Err("a + must join two parts of the string".into());
            }
            i = j;
            continue;
        }
        if !(33..=126).contains(&c) {
            return Err("a character outside printable ASCII".into());
        }
        if clean.len() == MAX_LEN {
            return Err(format!("the string is longer than {MAX_LEN} characters"));
        }
        clean.push(c);
        i += 1;
    }
    if clean.iter().any(u8::is_ascii_lowercase) && clean.iter().any(u8::is_ascii_uppercase) {
        return Err("mixed-case string".into());
    }
    clean.make_ascii_lowercase();
    let pos = clean.iter().rposition(|c| *c == b'1').filter(|p| *p >= 1 && p + 1 < clean.len()).ok_or("no bech32 separator")?;
    let hrp = std::str::from_utf8(&clean[..pos]).map_err(|_| "bad prefix".to_string())?.to_string();
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::with_capacity((clean.len() - pos) * 5 / 8));
    for c in &clean[pos + 1..] {
        let v = CHARSET.iter().position(|x| x == c).ok_or_else(|| format!("bad bech32 character {:?}", *c as char))?;
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // what is left is padding: under five bits, all zero
    if bits >= 5 || acc != 0 {
        return Err("bad bech32 padding".into());
    }
    Ok((hrp, out))
}

// --- the TLV stream -----------------------------------------------------------------------------------

/// A cursor over bytes: every read is checked against what is left.
struct Rd<'a> {
    b: &'a [u8],
}

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if n > self.b.len() {
            return Err("truncated".into());
        }
        let (head, rest) = self.b.split_at(n);
        self.b = rest;
        Ok(head)
    }

    fn uint(&mut self, n: usize) -> Result<u64, String> {
        Ok(self.take(n)?.iter().fold(0u64, |a, x| (a << 8) | u64::from(*x)))
    }

    /// A BigSize, minimally encoded.
    fn bigsize(&mut self) -> Result<u64, String> {
        let (v, min) = match self.uint(1)? {
            0xfd => (self.uint(2)?, 0xfd),
            0xfe => (self.uint(4)?, 0x1_0000),
            0xff => (self.uint(8)?, 0x1_0000_0000),
            v => (v, 0),
        };
        if v < min {
            return Err("a number is not minimally encoded".into());
        }
        Ok(v)
    }

    /// A compressed public key, on the curve.
    fn point(&mut self) -> Result<[u8; 33], String> {
        point(self.take(33)?)
    }
}

fn point(b: &[u8]) -> Result<[u8; 33], String> {
    let k = <[u8; 33]>::try_from(b).map_err(|_| "a public key is not 33 bytes".to_string())?;
    PublicKey::from_slice(&k).map_err(|_| "not a public key".to_string())?;
    Ok(k)
}

/// One TLV record: its type, the whole record (type, length and value) and the value.
#[derive(Debug, Clone, Copy)]
struct Record<'a> {
    typ: u64,
    raw: &'a [u8],
    value: &'a [u8],
}

/// The records of a TLV stream: at least one, at most [`MAX_RECORDS`], types strictly ascending.
fn records(data: &[u8]) -> Result<Vec<Record<'_>>, String> {
    if data.is_empty() {
        return Err("empty".into());
    }
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        if out.len() == MAX_RECORDS {
            return Err(format!("more than {MAX_RECORDS} fields"));
        }
        let mut r = Rd { b: rest };
        let typ = r.bigsize()?;
        let len = usize::try_from(r.bigsize()?).ok().filter(|l| *l <= r.b.len()).ok_or("a field runs past the end")?;
        let value = r.take(len)?;
        if out.last().is_some_and(|p: &Record| typ <= p.typ) {
            return Err("fields out of order".into());
        }
        out.push(Record { typ, raw: &rest[..rest.len() - r.b.len()], value });
        rest = r.b;
    }
    Ok(out)
}

/// A truncated integer of at most `max` bytes, without leading zero bytes.
fn tu(v: &[u8], max: usize) -> Result<u64, String> {
    if v.len() > max || v.first() == Some(&0) {
        return Err("a truncated integer is not minimal".into());
    }
    Ok(v.iter().fold(0u64, |a, x| (a << 8) | u64::from(*x)))
}

fn utf8(v: &[u8], what: &str) -> Result<String, String> {
    std::str::from_utf8(v).map(str::to_string).map_err(|_| format!("{what} is not UTF-8"))
}

fn arr32(v: &[u8], what: &str) -> Result<[u8; 32], String> {
    <[u8; 32]>::try_from(v).map_err(|_| format!("{what} is not 32 bytes"))
}

/// A feature vector: minimal, and no even bit but 512 (an even bit the reader does not know means
/// "do not proceed"; 512 is the one this rail knows).
fn features(v: &[u8]) -> Result<Vec<u8>, String> {
    if v.first() == Some(&0) {
        return Err("a feature vector is not minimal".into());
    }
    for (i, byte) in v.iter().rev().enumerate() {
        for b in (0..8).step_by(2) {
            if (byte >> b) & 1 == 1 && i * 8 + b != FEATURE_BLAKE2B {
                return Err(format!("unknown even feature bit {}", i * 8 + b));
            }
        }
    }
    Ok(v.to_vec())
}

/// `blinded_path`s back to back: at least one, each with at least one hop.
fn paths(v: &[u8]) -> Result<Vec<BlindedPath>, String> {
    let mut r = Rd { b: v };
    let mut out = Vec::new();
    while !r.b.is_empty() {
        if out.len() == MAX_PATHS {
            return Err(format!("more than {MAX_PATHS} blinded paths"));
        }
        // first_node_id: a node id, or a channel and a direction (0 or 1, then the short channel id)
        match r.b[0] {
            0 | 1 => {
                r.take(9)?;
            }
            _ => {
                r.point()?;
            }
        }
        r.point()?;
        let hops = r.uint(1)? as usize;
        if hops == 0 {
            return Err("a blinded path with no hops".into());
        }
        let mut last = [0u8; 33];
        for _ in 0..hops {
            last = r.point()?;
            let enclen = r.uint(2)? as usize;
            r.take(enclen)?;
        }
        out.push(BlindedPath { hops, last_blinded_node: last });
    }
    if out.is_empty() {
        return Err("an empty paths field".into());
    }
    Ok(out)
}

/// `blinded_payinfo`s back to back.
fn payinfos(v: &[u8]) -> Result<Vec<PayInfo>, String> {
    let mut r = Rd { b: v };
    let mut out = Vec::new();
    while !r.b.is_empty() {
        if out.len() == MAX_PATHS {
            return Err(format!("more than {MAX_PATHS} payment paths"));
        }
        let p = PayInfo { fee_base_msat: r.uint(4)? as u32, fee_proportional_millionths: r.uint(4)? as u32, cltv_expiry_delta: r.uint(2)? as u16,
                          htlc_minimum_msat: r.uint(8)?, htlc_maximum_msat: r.uint(8)? };
        let flen = r.uint(2)? as usize;
        r.take(flen)?;
        out.push(p);
    }
    Ok(out)
}

/// Whether a field outside the ones read here may be skipped: an odd type in one of `ranges`.
fn skippable(typ: u64, ranges: &[std::ops::RangeInclusive<u64>], what: &str) -> Result<(), String> {
    if !ranges.iter().any(|r| r.contains(&typ)) {
        return Err(format!("field {typ} is outside {what}'s ranges"));
    }
    if typ.is_multiple_of(2) {
        return Err(format!("unknown even field {typ}"));
    }
    Ok(())
}

const EXPERIMENTAL: u64 = 1_000_000_000;

// --- the offer ----------------------------------------------------------------------------------------

/// Decode an offer string. Any malformed part is an error; unknown odd fields are skipped, as BOLT 12
/// says. Whether the rail will pay it is [`check_offer`]'s to say.
pub fn decode_offer(offer: &str) -> Result<Offer, String> {
    let (hrp, data) = bech32_decode(offer.trim())?;
    if hrp != "lno" {
        return Err(format!("not an offer (prefix {hrp:?}, not lno)"));
    }
    offer_from_tlv(&data)
}

/// An offer from its TLV stream.
pub fn offer_from_tlv(data: &[u8]) -> Result<Offer, String> {
    let mut o = Offer { id: Sha256::digest(data).into(), tlv: data.to_vec(), chains: None, currency: None, amount: None, description: None,
                        features: vec![], absolute_expiry: None, paths: vec![], issuer: None, quantity_max: None, issuer_id: None,
                        experimental: false };
    for r in records(data)? {
        let v = r.value;
        match r.typ {
            2 => {
                if v.is_empty() || v.len() % 32 != 0 {
                    return Err("offer_chains is not a list of chain hashes".into());
                }
                o.chains = Some(v.as_chunks::<32>().0.to_vec());
            }
            4 => {}
            6 => {
                if v.len() != 3 {
                    return Err("offer_currency is not a three-letter code".into());
                }
                o.currency = Some(utf8(v, "offer_currency")?);
            }
            8 => {
                let a = tu(v, 8)?;
                if a == 0 {
                    return Err("zero offer_amount".into());
                }
                o.amount = Some(a);
            }
            10 => o.description = Some(utf8(v, "offer_description")?),
            12 => o.features = features(v)?,
            14 => o.absolute_expiry = Some(tu(v, 8)?),
            16 => o.paths = paths(v)?,
            18 => o.issuer = Some(utf8(v, "offer_issuer")?),
            20 => o.quantity_max = Some(tu(v, 8)?),
            22 => o.issuer_id = Some(point(v)?),
            t => {
                skippable(t, &[1..=79, EXPERIMENTAL..=1_999_999_999], "an offer")?;
                o.experimental |= t >= EXPERIMENTAL;
            }
        }
    }
    if o.amount.is_some() && o.description.is_none() {
        return Err("an offer with an amount needs a description".into());
    }
    if o.currency.is_some() && o.amount.is_none() {
        return Err("an offer with a currency needs an amount".into());
    }
    if o.issuer_id.is_none() && o.paths.is_empty() {
        return Err("the offer names neither an issuer nor a path to one".into());
    }
    Ok(o)
}

/// The offer's checks that need no node: bit 512, the chain (`genesis`: the block 0 hash of the chain
/// the signer's own node follows, in wire order), the expiry, and the kinds of offer this rail pays.
pub fn check_offer(o: &Offer, genesis: &[u8; 32], now: f64) -> Result<(), Refusal> {
    let e = |r: &str, m: String| Err((r.to_string(), m));
    if !o.has_feature(FEATURE_BLAKE2B) {
        return e("ln_feature_512", "the offer lacks feature bit 512 (option_blake2b): it is not an XBT Lightning offer".into());
    }
    if !o.names_chain(genesis) {
        let named = match &o.chains {
            Some(c) => c.iter().map(hex::encode).collect::<Vec<_>>().join(", "),
            None => "no chain, which BOLT 12 reads as Bitcoin mainnet".into(),
        };
        return e("ln_network", format!("the offer is for another chain ({named}), not this node's {}", hex::encode(genesis)));
    }
    if o.experimental {
        return e("ln_offer", "the offer carries experimental-range fields: refused, implementations disagree on such an offer's id".into());
    }
    if let Some(c) = &o.currency {
        return e("ln_offer", format!("the offer is priced in {c:?}, not in this chain's coin: refused"));
    }
    if o.quantity_max.is_some() {
        return e("ln_offer", "the offer sells by quantity, which this wallet does not ask for: refused".into());
    }
    if o.absolute_expiry.is_some_and(|x| (x as f64) < now) {
        return e("ln_expired", "the offer has expired".into());
    }
    Ok(())
}

/// What an invoice for the offer must be for, in msat: the offer's amount, or `amount_msat` (the
/// caller's) when the offer leaves the amount to the payer.
pub fn offer_amount_msat(o: &Offer, amount_msat: Option<u64>) -> Result<u64, Refusal> {
    let e = |m: String| Err(("ln_amount".to_string(), m));
    match (o.amount, amount_msat) {
        (Some(a), None) => Ok(a),
        (Some(a), Some(g)) if a == g => Ok(a),
        (Some(a), Some(g)) => e(format!("the offer asks for {a} msat; amount_sats ({g} msat) must be left out or equal it")),
        (None, Some(g)) if g > 0 => Ok(g),
        (None, _) => e("the offer names no amount: pass amount_sats, the amount to pay".into()),
    }
}

// --- the invoice --------------------------------------------------------------------------------------

/// BIP-340's tagged hash, the tag given as its SHA-256.
fn tagged(tag_hash: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(tag_hash).chain_update(tag_hash).chain_update(msg).finalize().into()
}

fn tag(t: &[u8]) -> [u8; 32] {
    Sha256::digest(t).into()
}

fn bigsize_bytes(n: u64) -> Vec<u8> {
    match n {
        0..=0xfc => vec![n as u8],
        0xfd..=0xffff => [vec![0xfd], (n as u16).to_be_bytes().to_vec()].concat(),
        0x1_0000..=0xffff_ffff => [vec![0xfe], (n as u32).to_be_bytes().to_vec()].concat(),
        _ => [vec![0xff], n.to_be_bytes().to_vec()].concat(),
    }
}

/// BOLT 12's Merkle root over every record but the signature range (240 to 1000): a leaf per record
/// (`LnLeaf` over the record) paired with a nonce leaf (`LnNonce` and the first record, over the
/// record's type), pairs then joined in order, the lesser hash first. `None`: nothing to sign.
fn merkle_root(recs: &[Record<'_>]) -> Option<[u8; 32]> {
    let signed: Vec<&Record> = recs.iter().filter(|r| !(240..=1000).contains(&r.typ)).collect();
    let first = signed.first()?;
    let (leaf, branch, nonce) = (tag(b"LnLeaf"), tag(b"LnBranch"), tag(&[b"LnNonce".as_slice(), first.raw].concat()));
    let join = |a: [u8; 32], b: [u8; 32]| {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        tagged(&branch, &[lo, hi].concat())
    };
    let mut level: Vec<[u8; 32]> = signed.iter().map(|r| join(tagged(&leaf, r.raw), tagged(&nonce, &bigsize_bytes(r.typ)))).collect();
    while level.len() > 1 {
        level = level.chunks(2).map(|c| if c.len() == 2 { join(c[0], c[1]) } else { c[0] }).collect();
    }
    level.first().copied()
}

/// Verify the BIP-340 signature of a BOLT 12 message (`name`: `invoice` or `invoice_request`) by `key`.
fn verify(recs: &[Record<'_>], name: &str, sig: &[u8], key: &[u8; 33]) -> Result<(), String> {
    let root = merkle_root(recs).ok_or("nothing is signed")?;
    let digest = tagged(&tag(format!("lightning{name}signature").as_bytes()), &root);
    let sig = schnorr::Signature::from_slice(sig).map_err(|_| "bad signature".to_string())?;
    let (xonly, _) = PublicKey::from_slice(key).map_err(|_| "not a public key".to_string())?.x_only_public_key();
    Secp256k1::verification_only().verify_schnorr(&sig, &Message::from_digest(digest), &xonly)
        .map_err(|_| format!("the {name} is not signed by its key"))
}

/// Decode an invoice string and verify its signature by `invoice_node_id`. Any malformed part is an
/// error. Whether it answers an offer is [`check_invoice`]'s to say.
pub fn decode_invoice(invoice: &str) -> Result<Invoice, String> {
    let (hrp, data) = bech32_decode(invoice.trim())?;
    if hrp != "lni" {
        return Err(format!("not an invoice (prefix {hrp:?}, not lni)"));
    }
    invoice_from_tlv(&data)
}

/// An invoice from its TLV stream, its signature verified.
pub fn invoice_from_tlv(data: &[u8]) -> Result<Invoice, String> {
    let recs = records(data)?;
    let mut offer_tlv = Vec::new();
    let (mut chain, mut invreq_amount, mut quantity, mut payer_id) = (None, None, None, None);
    let (mut inv_paths, mut payinfo, mut created_at, mut relative_expiry) = (None, None, None, None);
    let (mut payment_hash, mut amount_msat, mut feats, mut node_id, mut sig) = (None, None, vec![], None, None);
    for r in &recs {
        let v = r.value;
        match r.typ {
            // the offer it answers, repeated: compared with the offer byte for byte, not read again
            1..=79 => offer_tlv.extend_from_slice(r.raw),
            0 | 84 | 89 | 90 | 91 | 172 => {}
            80 => chain = Some(arr32(v, "invreq_chain")?),
            82 => invreq_amount = Some(tu(v, 8)?),
            86 => quantity = Some(tu(v, 8)?),
            88 => payer_id = Some(point(v)?),
            160 => inv_paths = Some(paths(v)?),
            162 => payinfo = Some(payinfos(v)?),
            164 => created_at = Some(tu(v, 8)?),
            166 => relative_expiry = Some(tu(v, 4)?),
            168 => payment_hash = Some(arr32(v, "invoice_payment_hash")?),
            170 => amount_msat = Some(tu(v, 8)?),
            174 => feats = features(v)?,
            176 => node_id = Some(point(v)?),
            240 => sig = Some(<[u8; 64]>::try_from(v).map_err(|_| "the signature is not 64 bytes".to_string())?),
            t => skippable(t, &[0..=1000, EXPERIMENTAL..=3_999_999_999], "an invoice")?,
        }
    }
    let node_id = node_id.ok_or("the invoice has no invoice_node_id")?;
    verify(&recs, "invoice", &sig.ok_or("the invoice has no signature")?, &node_id)?;
    let paths = inv_paths.ok_or("the invoice has no payment paths")?;
    let payinfo = payinfo.ok_or("the invoice has no invoice_blindedpay")?;
    if paths.len() != payinfo.len() {
        return Err("the invoice's paths and their payment info do not pair".into());
    }
    if offer_tlv.is_empty() {
        return Err("the invoice answers no offer".into());
    }
    Ok(Invoice { offer_id: Sha256::digest(&offer_tlv).into(), offer_tlv, chain, invreq_amount, quantity,
                 payer_id: payer_id.ok_or("the invoice has no invreq_payer_id")?, paths, payinfo,
                 created_at: created_at.ok_or("the invoice has no invoice_created_at")?,
                 relative_expiry: relative_expiry.unwrap_or(DEFAULT_RELATIVE_EXPIRY_S),
                 payment_hash: payment_hash.ok_or("the invoice has no invoice_payment_hash")?,
                 amount_msat: amount_msat.ok_or("the invoice has no invoice_amount")?, features: feats, node_id })
}

/// What an invoice must satisfy besides answering its offer.
#[derive(Debug, Clone, Copy)]
pub struct InvoiceTerms<'a> {
    /// The amount asked for ([`offer_amount_msat`]).
    pub amount_msat: u64,
    /// The signer's own node's block 0 hash, in wire order.
    pub genesis: &'a [u8; 32],
    pub now: f64,
    /// It must stay payable at least this long.
    pub min_expiry_s: i64,
    pub max_cltv_blocks: i64,
}

/// A fetched invoice against the offer it was fetched for, with no node: bit 512, the chain, that it
/// repeats this offer, that the offer's issuer signed it, the amount asked, the expiry, the time
/// locks of its payment paths.
pub fn check_invoice(o: &Offer, inv: &Invoice, t: &InvoiceTerms) -> Result<(), Refusal> {
    let e = |r: &str, m: String| Err((r.to_string(), m));
    if !inv.has_feature(FEATURE_BLAKE2B) {
        return e("ln_feature_512", "the invoice lacks feature bit 512 (option_blake2b): it is not an XBT Lightning invoice".into());
    }
    if inv.chain.unwrap_or(BITCOIN_GENESIS) != *t.genesis {
        return e("ln_network", "the invoice is for another chain than this node's".into());
    }
    if inv.offer_tlv != o.tlv {
        return e("ln_offer_mismatch", format!("the invoice answers offer {}, not {}", hex::encode(inv.offer_id), o.id_hex()));
    }
    // the issuer: the offer's issuer id, or (an offer with none) the last blinded node of one of its paths
    let issuer_ok = match &o.issuer_id {
        Some(k) => *k == inv.node_id,
        None => o.paths.iter().any(|p| p.last_blinded_node == inv.node_id),
    };
    if !issuer_ok {
        return e("ln_offer_mismatch", format!("the invoice is signed by {}, which the offer does not name as its issuer", hex::encode(inv.node_id)));
    }
    if inv.amount_msat != t.amount_msat || inv.invreq_amount.is_some_and(|a| a != t.amount_msat) {
        return e("ln_amount", format!("the invoice is for {} msat, not the {} msat asked for", inv.amount_msat, t.amount_msat));
    }
    if inv.quantity.is_some() {
        return e("ln_offer_mismatch", "the invoice names a quantity, which was not asked for".into());
    }
    let left = inv.expires_at() as f64 - t.now;
    if left < t.min_expiry_s as f64 {
        return e("ln_expired", format!("the invoice expires in {left:.0} s (at least {} s required)", t.min_expiry_s));
    }
    if inv.created_at as f64 > t.now + 600.0 {
        return e("ln_invoice", "the invoice is dated in the future".into());
    }
    if let Some(p) = inv.payinfo.iter().find(|p| i64::from(p.cltv_expiry_delta) > t.max_cltv_blocks) {
        return e("ln_cltv", format!("a payment path's cltv_expiry_delta {} is above max_cltv_blocks {}", p.cltv_expiry_delta, t.max_cltv_blocks));
    }
    Ok(())
}

/// Test support: build offers and signed invoices (the encoder the reader is checked against).
#[doc(hidden)]
pub mod encode {
    use super::*;
    use xbt_primitives::secp256k1::{Keypair, SecretKey};

    pub fn tlv(typ: u64, value: &[u8]) -> Vec<u8> {
        [bigsize_bytes(typ), bigsize_bytes(value.len() as u64), value.to_vec()].concat()
    }

    /// A truncated integer.
    pub fn tu(n: u64) -> Vec<u8> {
        n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect()
    }

    /// A feature vector with these bits.
    pub fn features(bits: &[usize]) -> Vec<u8> {
        let mut v = vec![0u8; bits.iter().max().map_or(0, |m| m / 8 + 1)];
        let n = v.len();
        for b in bits {
            v[n - 1 - b / 8] |= 1 << (b % 8);
        }
        v
    }

    pub fn pubkey(key: &SecretKey) -> [u8; 33] {
        PublicKey::from_secret_key(&Secp256k1::new(), key).serialize()
    }

    /// A blinded path of `hops` hops from `first` whose last blinded node is `last`.
    pub fn path(first: &[u8; 33], last: &[u8; 33], hops: u8) -> Vec<u8> {
        let mut p = [first.to_vec(), first.to_vec(), vec![hops]].concat();
        for i in 0..hops {
            p.extend(if i + 1 == hops { last } else { first });
            p.extend([0, 4, 1, 2, 3, 4]);
        }
        p
    }

    /// A payment path's `blinded_payinfo`.
    pub fn payinfo(cltv_expiry_delta: u16) -> Vec<u8> {
        [1000u32.to_be_bytes().to_vec(), 100u32.to_be_bytes().to_vec(), cltv_expiry_delta.to_be_bytes().to_vec(), 1u64.to_be_bytes().to_vec(),
         21_000_000_000u64.to_be_bytes().to_vec(), vec![0, 0]].concat()
    }

    pub fn string(hrp: &str, data: &[u8]) -> String {
        let (mut acc, mut bits, mut s) = (0u32, 0u32, format!("{hrp}1"));
        for x in data {
            acc = (acc << 8) | u32::from(*x);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                s.push(CHARSET[((acc >> bits) & 31) as usize] as char);
            }
            acc &= (1 << bits) - 1;
        }
        if bits > 0 {
            s.push(CHARSET[((acc << (5 - bits)) & 31) as usize] as char);
        }
        s
    }

    /// A TLV stream from `(type, value)` fields, in type order.
    pub fn stream(mut fields: Vec<(u64, Vec<u8>)>) -> Vec<u8> {
        fields.sort_by_key(|f| f.0);
        fields.iter().flat_map(|(t, v)| tlv(*t, v)).collect()
    }

    /// An offer string from its fields.
    pub fn offer(fields: Vec<(u64, Vec<u8>)>) -> String {
        string("lno", &stream(fields))
    }

    /// Sign a BOLT 12 message's fields (`name`: `invoice`) with `key` and return its TLV stream.
    pub fn signed(fields: Vec<(u64, Vec<u8>)>, name: &str, key: &SecretKey) -> Vec<u8> {
        let mut data = stream(fields);
        let root = records(&data).ok().and_then(|r| merkle_root(&r)).unwrap_or_default();
        let digest = tagged(&tag(format!("lightning{name}signature").as_bytes()), &root);
        let secp = Secp256k1::new();
        let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &Keypair::from_secret_key(&secp, key));
        data.extend(tlv(240, sig.as_ref()));
        data
    }

    /// What to put in a test invoice for an offer.
    pub struct InvoiceSpec<'a> {
        /// The offer's TLV stream ([`Offer::tlv`]), repeated in the invoice.
        pub offer_tlv: &'a [u8],
        pub chain: Option<[u8; 32]>,
        pub payer_key: &'a SecretKey,
        pub created_at: u64,
        pub relative_expiry: Option<u32>,
        pub payment_hash: [u8; 32],
        pub amount_msat: u64,
        pub features: &'a [usize],
        /// The key that signs, and the `invoice_node_id` (the signer's own unless given).
        pub key: &'a SecretKey,
        pub node_id: Option<[u8; 33]>,
        pub cltv_expiry_delta: u16,
        /// Fields added or (same type) put in place of the above.
        pub extra: Vec<(u64, Vec<u8>)>,
    }

    /// The fields of a test invoice, unsigned.
    pub fn invoice_fields(s: &InvoiceSpec) -> Vec<(u64, Vec<u8>)> {
        let node = s.node_id.unwrap_or_else(|| pubkey(s.key));
        let mut f: Vec<(u64, Vec<u8>)> = records(s.offer_tlv).unwrap_or_default().iter().map(|r| (r.typ, r.value.to_vec())).collect();
        f.push((0, s.payment_hash[..16].to_vec()));
        if let Some(c) = s.chain {
            f.push((80, c.to_vec()));
        }
        f.push((82, tu(s.amount_msat)));
        f.push((88, pubkey(s.payer_key).to_vec()));
        f.push((160, path(&node, &node, 2)));
        f.push((162, payinfo(s.cltv_expiry_delta)));
        f.push((164, tu(s.created_at)));
        if let Some(x) = s.relative_expiry {
            f.push((166, tu(u64::from(x))));
        }
        f.push((168, s.payment_hash.to_vec()));
        f.push((170, tu(s.amount_msat)));
        if !s.features.is_empty() {
            f.push((174, features(s.features)));
        }
        f.push((176, node.to_vec()));
        for (t, v) in &s.extra {
            f.retain(|x| x.0 != *t);
            f.push((*t, v.clone()));
        }
        f
    }

    /// A signed invoice string.
    pub fn invoice(s: &InvoiceSpec) -> String {
        string("lni", &signed(invoice_fields(s), "invoice", s.key))
    }
}

#[cfg(test)]
mod tests {
    use super::encode::{self, InvoiceSpec};
    use super::*;
    use serde_json::Value;
    use xbt_primitives::secp256k1::SecretKey;

    const REGTEST: [u8; 32] = [0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf, 0x28, 0xc3, 0x4f, 0x3a,
                               0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f];
    const NOW: u64 = 1_790_000_000;

    fn vectors(name: &str) -> Vec<Value> {
        let text = match name {
            "format" => include_str!("../tests/data/bolt12/format-string-test.json"),
            "offers" => include_str!("../tests/data/bolt12/offers-test.json"),
            _ => include_str!("../tests/data/bolt12/signature-test.json"),
        };
        serde_json::from_str(text).unwrap()
    }

    fn key(b: u8) -> SecretKey {
        SecretKey::from_slice(&[b; 32]).unwrap()
    }

    fn issuer() -> [u8; 33] {
        encode::pubkey(&key(0x41))
    }

    /// An XBT offer on regtest from the issuer, with these fields added or put in place.
    fn offer(extra: Vec<(u64, Vec<u8>)>) -> String {
        let mut f = vec![(2, REGTEST.to_vec()), (10, b"coffee".to_vec()), (12, encode::features(&[512])), (22, issuer().to_vec())];
        for (t, v) in extra {
            f.retain(|x| x.0 != t);
            f.push((t, v));
        }
        encode::offer(f)
    }

    fn spec<'a>(o: &'a Offer, payer: &'a SecretKey, signer: &'a SecretKey) -> InvoiceSpec<'a> {
        InvoiceSpec { offer_tlv: &o.tlv, chain: Some(REGTEST), payer_key: payer, created_at: NOW - 10, relative_expiry: Some(3600),
                      payment_hash: [9; 32], amount_msat: 250_000, features: &[512], key: signer, node_id: None, cltv_expiry_delta: 40,
                      extra: vec![] }
    }

    fn terms(amount_msat: u64) -> InvoiceTerms<'static> {
        InvoiceTerms { amount_msat, genesis: &REGTEST, now: NOW as f64, min_expiry_s: 60, max_cltv_blocks: 1008 }
    }

    #[test]
    fn the_specifications_format_vectors() {
        for v in vectors("format") {
            let ok = decode_offer(v["string"].as_str().unwrap()).is_ok();
            assert_eq!(ok, v["valid"].as_bool().unwrap(), "{}", v["comment"]);
        }
    }

    #[test]
    fn the_specifications_offer_vectors() {
        let all = vectors("offers");
        assert_eq!(all.len(), 53);
        for v in all {
            let d = decode_offer(v["bolt12"].as_str().unwrap());
            assert_eq!(d.is_ok(), v["valid"].as_bool().unwrap(), "{}: {:?}", v["description"], d.as_ref().err());
            let Ok(o) = d else { continue };
            // each field the reader holds is the vector's
            for f in v["fields"].as_array().unwrap() {
                let (t, val) = (f["type"].as_u64().unwrap(), hex::decode(f["hex"].as_str().unwrap()).unwrap());
                match t {
                    2 => assert_eq!(o.chains.as_ref().unwrap().concat(), val),
                    8 => assert_eq!(encode::tu(o.amount.unwrap()), val),
                    10 => assert_eq!(o.description.as_deref().unwrap().as_bytes(), val),
                    12 => assert_eq!(o.features, val),
                    14 => assert_eq!(encode::tu(o.absolute_expiry.unwrap()), val),
                    18 => assert_eq!(o.issuer.as_deref().unwrap().as_bytes(), val),
                    20 => assert_eq!(encode::tu(o.quantity_max.unwrap()), val),
                    22 => assert_eq!(o.issuer_id.unwrap().to_vec(), val),
                    _ => {}
                }
            }
            assert_eq!(o.id, <[u8; 32]>::from(Sha256::digest(&o.tlv)));
            // none of them is an XBT offer: no bit 512
            assert_eq!(check_offer(&o, &BITCOIN_GENESIS, 0.0).unwrap_err().0, "ln_feature_512", "{}", v["description"]);
        }
    }

    #[test]
    fn the_specifications_merkle_and_signature_vectors() {
        let all = vectors("signature");
        assert_eq!(all.len(), 4);
        for v in &all {
            // the stream is the records named in the leaves, in order
            let data: Vec<u8> = v["leaves"].as_array().unwrap().iter().flat_map(|l| {
                let k = l.as_object().unwrap().keys().find(|k| k.starts_with("H(`LnLeaf`,")).unwrap().clone();
                hex::decode(k.trim_start_matches("H(`LnLeaf`,").trim_end_matches(')')).unwrap()
            }).collect();
            let recs = records(&data).unwrap();
            assert_eq!(hex::encode(merkle_root(&recs).unwrap()), v["merkle"].as_str().unwrap(), "{}", v["comment"]);
        }
        // the invoice_request vector: signed by Bob (0x42...), over the string's own records
        let v = &all[3];
        let (hrp, data) = bech32_decode(v["bolt12"].as_str().unwrap()).unwrap();
        assert_eq!(hrp, "lnr");
        let recs = records(&data).unwrap();
        assert_eq!(hex::encode(merkle_root(&recs).unwrap()), v["merkle"].as_str().unwrap());
        let sig = recs.iter().find(|r| r.typ == 240).unwrap().value;
        assert_eq!(hex::encode(sig), v["signature"].as_str().unwrap());
        let bob = encode::pubkey(&key(0x42));
        verify(&recs, "invoice_request", sig, &bob).unwrap();
        assert!(verify(&recs, "invoice", sig, &bob).is_err(), "the tag names the message");
        assert!(verify(&recs, "invoice_request", sig, &issuer()).is_err());
        // and our own signer makes the vector's signature (BIP-340 with no auxiliary randomness)
        let fields: Vec<(u64, Vec<u8>)> = recs.iter().filter(|r| r.typ != 240).map(|r| (r.typ, r.value.to_vec())).collect();
        assert_eq!(encode::signed(fields, "invoice_request", &key(0x42)), data);
    }

    #[test]
    fn an_offer_round_trips_and_its_id_is_the_hash_of_its_fields() {
        let s = offer(vec![(8, encode::tu(250_000)), (14, encode::tu(NOW + 100))]);
        let o = decode_offer(&s).unwrap();
        assert_eq!((o.amount, o.description.as_deref(), o.absolute_expiry, o.issuer_id), (Some(250_000), Some("coffee"), Some(NOW + 100), Some(issuer())));
        assert_eq!(o.chains, Some(vec![REGTEST]));
        assert!(o.has_feature(512) && !o.has_feature(513) && !o.has_feature(511) && !o.has_feature(100_000));
        assert_eq!(o.id_hex(), hex::encode(Sha256::digest(&o.tlv)));
        check_offer(&o, &REGTEST, NOW as f64).unwrap();
        // uppercase, whitespace around it and a + join decode the same
        assert_eq!(decode_offer(&format!("  {}\n", s.to_uppercase())).unwrap(), o);
        assert_eq!(decode_offer(&format!("{}+\n  {}", &s[..20], &s[20..])).unwrap(), o);
        assert_eq!(check_offer(&o, &REGTEST, (NOW + 101) as f64).unwrap_err().0, "ln_expired");
        assert_eq!(offer_amount_msat(&o, None), Ok(250_000));
        assert_eq!(offer_amount_msat(&o, Some(250_000)), Ok(250_000));
        assert_eq!(offer_amount_msat(&o, Some(300_000)).unwrap_err().0, "ln_amount");
        let open = decode_offer(&offer(vec![])).unwrap();
        assert_eq!(offer_amount_msat(&open, Some(7_000)), Ok(7_000));
        assert_eq!(offer_amount_msat(&open, None).unwrap_err().0, "ln_amount");
        assert_eq!(offer_amount_msat(&open, Some(0)).unwrap_err().0, "ln_amount");
    }

    /// Pass line 2: on a chain whose genesis is Bitcoin's (mainnet), an offer that names no chain is this
    /// chain's by BOLT 12, and bit 512 alone says whether it is XBT's.
    #[test]
    fn a_chainless_offer_is_payable_with_bit_512_and_refused_without() {
        let chainless = |bits: &[usize]| {
            let mut f = vec![(10, b"coffee".to_vec()), (22, issuer().to_vec())];
            if !bits.is_empty() {
                f.push((12, encode::features(bits)));
            }
            decode_offer(&encode::offer(f)).unwrap()
        };
        let with = chainless(&[512]);
        assert_eq!(with.chains, None);
        assert_eq!(check_offer(&with, &BITCOIN_GENESIS, NOW as f64), Ok(()));
        assert_eq!(check_offer(&chainless(&[]), &BITCOIN_GENESIS, NOW as f64).unwrap_err().0, "ln_feature_512");
        assert_eq!(check_offer(&chainless(&[513]), &BITCOIN_GENESIS, NOW as f64).unwrap_err().0, "ln_feature_512", "the odd form is not enough");
        assert_eq!(check_offer(&chainless(&[99]), &BITCOIN_GENESIS, NOW as f64).unwrap_err().0, "ln_feature_512");
        // off mainnet a chain-less offer names another chain
        assert_eq!(check_offer(&with, &REGTEST, NOW as f64).unwrap_err().0, "ln_network");
        // naming Bitcoin's genesis outright is the same offer for the same chain
        let named = decode_offer(&offer(vec![(2, BITCOIN_GENESIS.to_vec())])).unwrap();
        assert_eq!(check_offer(&named, &BITCOIN_GENESIS, NOW as f64), Ok(()));
        assert_eq!(check_offer(&named, &REGTEST, NOW as f64).unwrap_err().0, "ln_network");
        // one of several chains is enough; none of them is not
        let both = decode_offer(&offer(vec![(2, [[7u8; 32], REGTEST].concat())])).unwrap();
        assert_eq!(check_offer(&both, &REGTEST, NOW as f64), Ok(()));
        assert_eq!(check_offer(&both, &BITCOIN_GENESIS, NOW as f64).unwrap_err().0, "ln_network");
    }

    #[test]
    fn offers_this_rail_does_not_pay_are_refused() {
        let refused = |extra: Vec<(u64, Vec<u8>)>| check_offer(&decode_offer(&offer(extra)).unwrap(), &REGTEST, NOW as f64).unwrap_err().0;
        assert_eq!(refused(vec![(6, b"USD".to_vec()), (8, encode::tu(100))]), "ln_offer");
        assert_eq!(refused(vec![(20, encode::tu(5))]), "ln_offer");
        assert_eq!(refused(vec![(1_000_000_033, vec![1, 2])]), "ln_offer");
        assert_eq!(refused(vec![(12, vec![])]), "ln_feature_512");
        // malformed, not merely unpayable
        for bad in [vec![(12u64, encode::features(&[512, 122]))], vec![(12, [vec![0], encode::features(&[512])].concat())], vec![(8, vec![0, 5])],
                    vec![(8, vec![1; 9])], vec![(22, [vec![2], vec![0xff; 32]].concat())], vec![(22, vec![])], vec![(2, vec![1; 31])], vec![(78, vec![])],
                    vec![(80, vec![])], vec![(16, vec![])], vec![(16, encode::path(&issuer(), &issuer(), 0))]] {
            assert!(decode_offer(&offer(bad.clone())).is_err(), "{bad:?}");
        }
        assert!(decode_offer("lni1qqqq").is_err());
        assert!(decode_offer(&"q".repeat(3 * MAX_LEN)).is_err());
        assert!(decode_offer(&format!("lno1{}", "q".repeat(MAX_LEN))).is_err());
    }

    #[test]
    fn an_invoice_is_checked_against_its_offer() {
        let o = decode_offer(&offer(vec![(8, encode::tu(250_000))])).unwrap();
        let (payer, alice, mallory) = (key(0x51), key(0x41), key(0x66));
        let good = spec(&o, &payer, &alice);
        let inv = decode_invoice(&encode::invoice(&good)).unwrap();
        assert_eq!((inv.offer_id, inv.node_id, inv.amount_msat, inv.payment_hash), (o.id, issuer(), 250_000, [9; 32]));
        assert_eq!((inv.payer_id, inv.expires_at(), inv.amount_sats_ceil()), (encode::pubkey(&payer), NOW - 10 + 3600, 250));
        assert_eq!(check_invoice(&o, &inv, &terms(250_000)), Ok(()));
        let rule = |s: &InvoiceSpec, t: &InvoiceTerms| check_invoice(&o, &decode_invoice(&encode::invoice(s)).unwrap(), t).unwrap_err().0;
        // no bit 512; another chain; no chain off mainnet
        assert_eq!(rule(&InvoiceSpec { features: &[], ..spec(&o, &payer, &alice) }, &terms(250_000)), "ln_feature_512");
        assert_eq!(rule(&InvoiceSpec { features: &[513], ..spec(&o, &payer, &alice) }, &terms(250_000)), "ln_feature_512");
        assert_eq!(rule(&InvoiceSpec { chain: Some([7; 32]), ..spec(&o, &payer, &alice) }, &terms(250_000)), "ln_network");
        assert_eq!(rule(&InvoiceSpec { chain: None, ..spec(&o, &payer, &alice) }, &terms(250_000)), "ln_network");
        // signed, validly, by a key the offer does not name
        assert_eq!(rule(&spec(&o, &payer, &mallory), &terms(250_000)), "ln_offer_mismatch");
        // an invoice for another offer of the same issuer
        let other = decode_offer(&offer(vec![(8, encode::tu(250_000)), (10, b"tea".to_vec())])).unwrap();
        assert_eq!(rule(&spec(&other, &payer, &alice), &terms(250_000)), "ln_offer_mismatch");
        // another amount than was asked; a quantity; expiring; from the future; a long time lock
        assert_eq!(rule(&InvoiceSpec { amount_msat: 250_001, ..spec(&o, &payer, &alice) }, &terms(250_000)), "ln_amount");
        assert_eq!(rule(&InvoiceSpec { extra: vec![(82, encode::tu(9))], ..spec(&o, &payer, &alice) }, &terms(250_000)), "ln_amount");
        assert_eq!(rule(&InvoiceSpec { extra: vec![(86, encode::tu(2))], ..spec(&o, &payer, &alice) }, &terms(250_000)), "ln_offer_mismatch");
        assert_eq!(rule(&InvoiceSpec { relative_expiry: Some(60), ..spec(&o, &payer, &alice) }, &terms(250_000)), "ln_expired");
        assert_eq!(rule(&InvoiceSpec { created_at: NOW + 700, ..spec(&o, &payer, &alice) }, &terms(250_000)), "ln_invoice");
        assert_eq!(rule(&InvoiceSpec { cltv_expiry_delta: 1009, ..spec(&o, &payer, &alice) }, &terms(250_000)), "ln_cltv");
        // the default expiry is two hours
        let d = decode_invoice(&encode::invoice(&InvoiceSpec { relative_expiry: None, ..spec(&o, &payer, &alice) })).unwrap();
        assert_eq!(d.relative_expiry, 7200);
        // an offer with no issuer id: the invoice is signed by the last blinded node of one of its paths
        let (intro, last) = (encode::pubkey(&key(0x71)), encode::pubkey(&key(0x72)));
        let blind = decode_offer(&encode::offer(vec![(2, REGTEST.to_vec()), (10, b"coffee".to_vec()), (12, encode::features(&[512])),
                                                    (16, [encode::path(&intro, &intro, 1), encode::path(&intro, &last, 3)].concat())])).unwrap();
        assert_eq!((blind.paths.len(), blind.paths[1].hops, blind.paths[1].last_blinded_node), (2, 3, last));
        let by = |k: &SecretKey| check_invoice(&blind, &decode_invoice(&encode::invoice(&spec(&blind, &payer, k))).unwrap(), &terms(250_000));
        assert_eq!(by(&key(0x72)), Ok(()));
        assert_eq!(by(&key(0x71)), Ok(()));
        assert_eq!(by(&alice).unwrap_err().0, "ln_offer_mismatch");
    }

    #[test]
    fn an_invoice_that_is_not_signed_by_its_node_id_does_not_decode() {
        let o = decode_offer(&offer(vec![(8, encode::tu(250_000))])).unwrap();
        let (payer, alice, mallory) = (key(0x51), key(0x41), key(0x66));
        // invoice_node_id says the issuer; the signature is another key's
        let forged = encode::invoice(&InvoiceSpec { node_id: Some(issuer()), ..spec(&o, &payer, &mallory) });
        assert!(decode_invoice(&forged).unwrap_err().contains("not signed"));
        // every required field
        for missing in [88u64, 160, 162, 164, 168, 170, 176] {
            let mut f = encode::invoice_fields(&spec(&o, &payer, &alice));
            f.retain(|x| x.0 != missing);
            assert!(decode_invoice(&encode::string("lni", &encode::signed(f, "invoice", &alice))).is_err(), "{missing}");
        }
        let unsigned = encode::string("lni", &encode::stream(encode::invoice_fields(&spec(&o, &payer, &alice))));
        assert!(decode_invoice(&unsigned).unwrap_err().contains("no signature"));
        // paths and payment info that do not pair; an unknown even field; an offer string
        let two = [encode::payinfo(40), encode::payinfo(40)].concat();
        assert!(decode_invoice(&encode::invoice(&InvoiceSpec { extra: vec![(162, two)], ..spec(&o, &payer, &alice) })).is_err());
        assert!(decode_invoice(&encode::invoice(&InvoiceSpec { extra: vec![(178, vec![1])], ..spec(&o, &payer, &alice) })).is_err());
        assert!(decode_invoice(&encode::invoice(&InvoiceSpec { extra: vec![(179, vec![1])], ..spec(&o, &payer, &alice) })).is_ok());
        assert!(decode_invoice(&offer(vec![])).is_err());
    }

    /// The reference implementation: offers and invoices written by Lightning Fork's own codec at
    /// v0.21.3-beta-blake2b.17, with its reader's and its payer's verdicts (`scripts/ln_rail/agp082vec.go`).
    /// This reader holds the same fields and reaches the same verdict on each, on regtest and on mainnet.
    /// Pass line 2 is in here in the fork's own words: no chain and bit 512 is payable on mainnet, no
    /// chain and no bit 512 is not.
    #[test]
    fn lightning_forks_own_offers_and_invoices() {
        let v: Value = serde_json::from_str(include_str!("../tests/data/bolt12/lightning-fork-17.json")).unwrap();
        let now = v["now"].as_f64().unwrap();
        let genesis = |name: &str| <[u8; 32]>::try_from(hex::decode(v["chains"][name].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!((genesis("mainnet"), genesis("regtest")), (BITCOIN_GENESIS, REGTEST));
        let mut offers = std::collections::HashMap::new();
        for o in v["offers"].as_array().unwrap() {
            let name = o["name"].as_str().unwrap();
            let d = decode_offer(o["bolt12"].as_str().unwrap()).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(hex::encode(&d.tlv), o["tlv"].as_str().unwrap(), "{name}");
            assert_eq!(d.id_hex(), o["offer_id"].as_str().unwrap(), "{name}: the offer id is the fork's");
            assert_eq!(d.amount.unwrap_or(0), o["amount_msat"].as_u64().unwrap(), "{name}");
            assert_eq!(d.description.as_deref(), o["description"].as_str(), "{name}");
            assert_eq!(d.issuer_id.map(hex::encode), o["issuer_id"].as_str().map(str::to_string), "{name}");
            assert_eq!(d.paths.len() as u64, o["num_paths"].as_u64().unwrap(), "{name}");
            let named: Vec<String> = o["chains"].as_array().into_iter().flatten().map(|c| c.as_str().unwrap().to_string()).collect();
            assert_eq!(d.chains.clone().unwrap_or_default().iter().map(hex::encode).collect::<Vec<_>>(), named, "{name}");
            for chain in ["regtest", "mainnet"] {
                let ours = check_offer(&d, &genesis(chain), now);
                assert_eq!(ours.is_ok(), o["lightning_fork"][chain]["payable"].as_bool().unwrap(), "{name} on {chain}: {ours:?}");
            }
            offers.insert(name.to_string(), d);
        }
        assert_eq!(offers.len(), 9);
        // the chain-less pair, by name
        assert_eq!(check_offer(&offers["no chain (mainnet), option_blake2b"], &BITCOIN_GENESIS, now), Ok(()));
        assert_eq!(check_offer(&offers["no chain, no option_blake2b"], &BITCOIN_GENESIS, now).unwrap_err().0, "ln_feature_512");
        assert_eq!(check_offer(&offers["no chain (mainnet), option_blake2b"], &REGTEST, now).unwrap_err().0, "ln_network");
        let mut payers = vec![];
        for i in v["invoices"].as_array().unwrap() {
            let (name, o) = (i["name"].as_str().unwrap(), &offers[i["offer"].as_str().unwrap()]);
            let accepts = i["lightning_fork"]["payer_accepts"].as_bool().unwrap();
            let terms = InvoiceTerms { amount_msat: i["amount_msat"].as_u64().unwrap(), genesis: &genesis(i["chain"].as_str().unwrap()), now,
                                       min_expiry_s: 60, max_cltv_blocks: 1008 };
            let d = match decode_invoice(i["bolt12"].as_str().unwrap()) {
                Ok(d) => d,
                Err(e) => {
                    assert!(!accepts && e.contains("not signed"), "{name}: {e}");
                    continue;
                }
            };
            assert_eq!(hex::encode(d.offer_id), i["offer_id"].as_str().unwrap(), "{name}");
            assert_eq!(d.payment_hash_hex(), i["payment_hash"].as_str().unwrap(), "{name}");
            assert_eq!(hex::encode(Sha256::digest(hex::decode(i["preimage"].as_str().unwrap()).unwrap())), d.payment_hash_hex());
            assert_eq!((d.amount_msat, d.created_at, d.relative_expiry),
                       (i["amount_msat"].as_u64().unwrap(), i["created_at"].as_u64().unwrap(), i["relative_expiry"].as_u64().unwrap()), "{name}");
            assert_eq!((hex::encode(d.node_id), hex::encode(d.payer_id)), (i["node_id"].as_str().unwrap().into(), i["payer_id"].as_str().unwrap().into()), "{name}");
            assert_eq!((d.paths.len(), d.payinfo[0].cltv_expiry_delta, d.has_feature(17)), (1, 40, true), "{name}");
            let ours = check_invoice(o, &d, &terms);
            assert_eq!(ours.is_ok(), accepts, "{name}: {ours:?}");
            if accepts && i["offer"] == "regtest, 250000 msat, issuer id" {
                payers.push(d.payer_id);
            }
        }
        // pass line 5: two invoices for one offer, two payer ids
        assert_eq!(payers.len(), 2);
        assert_ne!(payers[0], payers[1]);
        assert_eq!(v["invoices"].as_array().unwrap().len(), 8);
    }

    /// xorshift64: the same inputs every run.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// The reader against truncation, overlong fields and mutation: it never panics, and it accepts no
    /// invoice but the one that was signed.
    #[test]
    fn truncated_overlong_and_mutated_input_is_refused() {
        let (intro, payer, alice) = (encode::pubkey(&key(0x71)), key(0x51), key(0x41));
        let o = decode_offer(&offer(vec![(8, encode::tu(250_000)), (16, encode::path(&intro, &intro, 2)), (18, b"Alice".to_vec())])).unwrap();
        let inv = encode::signed(encode::invoice_fields(&spec(&o, &payer, &alice)), "invoice", &alice);
        assert!(invoice_from_tlv(&inv).is_ok());
        // every truncation of the invoice, and of the offer (an offer cut at a field boundary may still
        // be an offer, but never this one)
        for n in 0..inv.len() {
            assert!(invoice_from_tlv(&inv[..n]).is_err(), "invoice cut at {n}");
        }
        for n in 0..o.tlv.len() {
            assert!(offer_from_tlv(&o.tlv[..n]).map_or(true, |x| x.id != o.id), "offer cut at {n}");
        }
        // every single-bit flip of the invoice: the signature covers every byte
        for i in 0..inv.len() * 8 {
            let mut m = inv.clone();
            m[i / 8] ^= 1 << (i % 8);
            assert!(invoice_from_tlv(&m).is_err(), "bit {i}");
        }
        // lengths that run past the end, in every width, at every field
        let lens: [&[u8]; 6] = [&[0xfc], &[0xfd, 0xff, 0xff], &[0xfe, 0xff, 0xff, 0xff, 0xff], &[0xff; 9], &[0xfd, 0x00, 0x05], &[0xff, 0, 0, 0, 0, 0, 0, 0, 9]];
        for base in [&o.tlv, &inv] {
            let mut at = 0;
            for r in records(base).unwrap() {
                let tlen = bigsize_bytes(r.typ).len();
                for l in lens {
                    let m = [&base[..at + tlen], l, &base[at + tlen + bigsize_bytes(r.value.len() as u64).len()..]].concat();
                    assert!(offer_from_tlv(&m).is_err() && invoice_from_tlv(&m).is_err(), "field {} length {l:?}", r.typ);
                }
                at += r.raw.len();
            }
        }
        // counts that promise more than is there: hops, paths, records
        assert!(paths(&[intro.to_vec(), intro.to_vec(), vec![255], intro.to_vec(), vec![0, 0]].concat()).is_err());
        assert!(paths(&[intro.to_vec(), intro.to_vec(), vec![1], intro.to_vec(), vec![0xff, 0xff]].concat()).is_err());
        assert!(paths(&encode::path(&intro, &intro, 1).repeat(MAX_PATHS)).is_ok());
        assert!(paths(&encode::path(&intro, &intro, 1).repeat(MAX_PATHS + 1)).is_err());
        assert!(payinfos(&encode::payinfo(1).repeat(MAX_PATHS + 1)).is_err());
        assert!(payinfos(&encode::payinfo(1)[..25]).is_err());
        let many: Vec<u8> = (0..MAX_RECORDS as u64 + 1).flat_map(|i| encode::tlv(2 * i + 1, &[])).collect();
        assert!(records(&many).unwrap_err().contains("more than"));
        assert_eq!(records(&many[..2 * MAX_RECORDS]).unwrap().len(), MAX_RECORDS);
        // random bytes, random mutations of a real offer and invoice, random strings: no panic, and
        // nothing mutated passes for the signed invoice
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for i in 0..20_000 {
            let base = if i % 2 == 0 { &o.tlv } else { &inv };
            let mut m = base.clone();
            for _ in 0..1 + rng.next() % 4 {
                let at = rng.next() as usize % m.len();
                match rng.next() % 3 {
                    0 => m[at] = rng.next() as u8,
                    1 => {
                        m.insert(at, rng.next() as u8);
                    }
                    _ => {
                        m.remove(at);
                    }
                }
                if m.is_empty() {
                    break;
                }
            }
            let _ = offer_from_tlv(&m);
            assert!(m == inv || invoice_from_tlv(&m).is_err());
            let junk: Vec<u8> = (0..rng.next() % 200).map(|_| rng.next() as u8).collect();
            let _ = (offer_from_tlv(&junk), invoice_from_tlv(&junk), paths(&junk), payinfos(&junk));
            let text: String = junk.iter().map(|b| (b"lnoi1+ qpzry9x8gf2tvdw0s3jn54khce6mua7lQ\n"[*b as usize % 41]) as char).collect();
            let _ = (decode_offer(&text), decode_invoice(&text), bech32_decode(&text));
        }
    }
}
