//! Receipts (spec §5): the signed line `xbt-work-receipt/1|...`, the receipt document, and
//! Ed25519 signatures under the Prime key.
//!
//! A verifier parses and type-checks every field of a received document ([`WorkReceipt::from_doc`])
//! and rebuilds the line itself ([`WorkReceipt::message`]); it never verifies a `message` string
//! supplied by anyone (§5.1, §12.1).
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::Value;
use xbt402::json::obj;

use crate::error::{GResult, GrammarError};
use crate::grammar::{check_identity, check_invoice, text, uint, uint_text, U32, U64};

pub const RECEIPT_TAG: &str = "xbt-work-receipt/1";

/// One Prime receipt: "identity has been credited cum_work under invoice" (§5.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkReceipt {
    pub prime_id: u32,
    /// Canonical identity credited (the provider's payout address).
    pub identity: String,
    pub invoice: String,
    /// Per (identity, invoice): 0 before any credit, then strictly increasing.
    pub seq: u64,
    pub cum_work: u64,
    pub shares: u64,
    pub first_height: u32,
    pub last_height: u32,
    /// Share difficulty of the latest credited share (informational).
    pub difficulty: u64,
}

impl WorkReceipt {
    /// The zero receipt a Prime signs for a pair it never credited (§5.3 rule 5).
    pub fn zero(prime_id: u32, identity: &str, invoice: &str) -> Self {
        Self { prime_id, identity: identity.into(), invoice: invoice.into(), seq: 0, cum_work: 0, shares: 0,
               first_height: 0, last_height: 0, difficulty: 0 }
    }

    /// The exact ASCII line a Prime signs. Refuses an identity or invoice outside the grammar.
    pub fn message(&self) -> GResult<String> {
        check_identity(&self.identity)?;
        check_invoice(&self.invoice)?;
        Ok(format!("{RECEIPT_TAG}|{}|{}|{}|{}|{}|{}|{}|{}|{}", self.prime_id, self.identity, self.invoice, self.seq,
                   self.cum_work, self.shares, self.first_height, self.last_height, self.difficulty))
    }

    /// The receipt document a Prime serves and a payer forwards verbatim (§5.2), without `sig`.
    pub fn to_doc(&self) -> Value {
        obj([("prime_id", self.prime_id.into()), ("identity", self.identity.clone().into()),
             ("invoice", self.invoice.clone().into()),
             ("receipt", obj([("seq", self.seq.into()), ("cum_work", self.cum_work.into()), ("shares", self.shares.into()),
                              ("first_height", self.first_height.into()), ("last_height", self.last_height.into()),
                              ("difficulty", self.difficulty.into())]))])
    }

    /// Strict parse of a receipt document: every field against its grammar (§5.1). Numbers may be
    /// JSON integers or canonical decimal strings; extra keys (`message`, `pubkey`, `sig`) are ignored.
    pub fn from_doc(d: &Value) -> GResult<Self> {
        let r = d.get("receipt").filter(|r| r.is_object()).filter(|_| d.is_object())
            .ok_or_else(|| GrammarError::new("receipt document"))?;
        Ok(Self {
            prime_id: uint(d.get("prime_id"), U32, "prime_id")? as u32,
            identity: text(d.get("identity"), check_identity)?.into(),
            invoice: text(d.get("invoice"), check_invoice)?.into(),
            seq: uint(r.get("seq"), U64, "seq")?,
            cum_work: uint(r.get("cum_work"), U64, "cum_work")?,
            shares: uint(r.get("shares"), U64, "shares")?,
            first_height: uint(r.get("first_height"), U32, "first_height")? as u32,
            last_height: uint(r.get("last_height"), U32, "last_height")? as u32,
            difficulty: uint(r.get("difficulty"), U64, "difficulty")?,
        })
    }

    /// Parse a signed line back (a fraud proof carries lines): exactly ten fields, each in its
    /// grammar, and the line must be the canonical one for its values.
    pub fn parse_line(line: &str) -> GResult<Self> {
        let f: Vec<&str> = line.split('|').collect();
        if f.len() != 10 || f[0] != RECEIPT_TAG {
            return Err(GrammarError::new("receipt line"));
        }
        let r = Self {
            prime_id: uint_text(f[1], U32, "prime_id")? as u32,
            identity: check_identity(f[2])?.into(),
            invoice: check_invoice(f[3])?.into(),
            seq: uint_text(f[4], U64, "seq")?,
            cum_work: uint_text(f[5], U64, "cum_work")?,
            shares: uint_text(f[6], U64, "shares")?,
            first_height: uint_text(f[7], U32, "first_height")? as u32,
            last_height: uint_text(f[8], U32, "last_height")? as u32,
            difficulty: uint_text(f[9], U64, "difficulty")?,
        };
        if r.message()? != line {
            return Err(GrammarError::new("receipt line is not canonical"));
        }
        Ok(r)
    }

    /// The cumulative state the equivocation rules compare (everything but the key fields).
    pub fn state(&self) -> (u64, u64, u32, u32, u64) {
        (self.cum_work, self.shares, self.first_height, self.last_height, self.difficulty)
    }
}

/// A receipt with the Prime's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub receipt: WorkReceipt,
    pub sig: [u8; 64],
}

impl Signed {
    /// `{"message": <line>, "sig": <hex>}`, as fraud proofs carry receipts.
    pub fn line_doc(&self) -> Value {
        obj([("message", self.receipt.message().unwrap_or_default().into()), ("sig", hex::encode(self.sig).into())])
    }

    /// The Prime's document with `sig` (§5.2).
    pub fn to_doc(&self) -> Value {
        let mut d = self.receipt.to_doc();
        d["sig"] = hex::encode(self.sig).into();
        d
    }

    /// A served document with its `sig` field: strict (§5.1), sig is 64 bytes of hex.
    pub fn from_doc(d: &Value) -> GResult<Self> {
        Ok(Self { receipt: WorkReceipt::from_doc(d)?, sig: sig64(d.get("sig"))? })
    }

    pub fn verify(&self, pubkey: &VerifyingKey) -> bool {
        self.receipt.message().is_ok_and(|m| verify(pubkey, &m, &self.sig))
    }
}

/// 64 bytes of hex (lower or upper case), as `sig` must be (§9.1 step 2).
pub fn sig64(v: Option<&Value>) -> GResult<[u8; 64]> {
    v.and_then(Value::as_str).and_then(|s| hex::decode(s).ok()).and_then(|b| <[u8; 64]>::try_from(b).ok())
        .ok_or_else(|| GrammarError::new("sig: 64 bytes of hex"))
}

/// Ed25519 (RFC 8032, pure) verification of `msg`. Strict: non-canonical signatures and weak keys
/// are refused.
pub fn verify(pubkey: &VerifyingKey, msg: &str, sig: &[u8; 64]) -> bool {
    pubkey.verify_strict(msg.as_bytes(), &Signature::from_bytes(sig)).is_ok()
}

/// The Prime key from hex. `primed pubkey` prints the Ed25519 key followed by its X25519 key
/// (64 bytes); the first 32 bytes are the signing key.
pub fn pubkey_from_hex(h: &str) -> GResult<VerifyingKey> {
    let b = hex::decode(h.get(..64).unwrap_or(h)).map_err(|_| GrammarError::new("primePubkey: hex"))?;
    let b: [u8; 32] = b.try_into().map_err(|_| GrammarError::new("primePubkey: 32 bytes"))?;
    VerifyingKey::from_bytes(&b).map_err(|_| GrammarError::new("primePubkey: not a point"))
}

/// A Prime signing key (tests, vectors, and anyone running a Prime in Rust). Signs only lines of
/// this scheme's grammar.
pub struct PrimeKey {
    pub prime_id: u32,
    key: SigningKey,
}

impl PrimeKey {
    /// From the 32-byte RFC 8032 seed.
    pub fn from_seed(prime_id: u32, seed: &[u8; 32]) -> Self {
        Self { prime_id, key: SigningKey::from_bytes(seed) }
    }

    pub fn pubkey(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.pubkey().as_bytes())
    }

    /// Sign any bytes (the field-injection vector needs the raw oracle signature).
    pub fn sign_raw(&self, msg: &[u8]) -> [u8; 64] {
        self.key.sign(msg).to_bytes()
    }

    /// Sign a receipt; refuses one outside the grammar (§5.3 rule 4).
    pub fn sign(&self, r: &WorkReceipt) -> GResult<Signed> {
        Ok(Signed { receipt: r.clone(), sig: self.sign_raw(r.message()?.as_bytes()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn line_and_doc_round_trip() {
        let k = PrimeKey::from_seed(70, &[7u8; 32]);
        let r = WorkReceipt { seq: 3, cum_work: 12, shares: 3, first_height: 101, last_height: 102, difficulty: 4,
                              ..WorkReceipt::zero(70, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "vfer2e5e75t4tv7in42lakx6i4") };
        let s = k.sign(&r).unwrap();
        assert!(s.verify(&k.pubkey()));
        assert_eq!(WorkReceipt::from_doc(&r.to_doc()).unwrap(), r);
        assert_eq!(Signed::from_doc(&s.to_doc()).unwrap(), s);
        assert_eq!(WorkReceipt::parse_line(&r.message().unwrap()).unwrap(), r);
        let mut t = r.clone();
        t.cum_work = 13;
        assert!(!Signed { receipt: t, sig: s.sig }.verify(&k.pubkey()));
        assert!(WorkReceipt::parse_line("xbt-work-receipt/1|70|a|abcdefgh|01|0|0|0|0|0").is_err());
        let mut d = r.to_doc();
        d["receipt"]["difficulty"] = json!("4|0|0");
        assert!(WorkReceipt::from_doc(&d).is_err());
        assert!(k.sign(&WorkReceipt::zero(70, "bc1q", "inv|999|999999")).is_err());
    }
}
