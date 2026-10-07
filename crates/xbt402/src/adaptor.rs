//! ECDSA adaptor signatures for adaptor-locked xbt402 states (hub routing, AGP-021/026).
//!
//! A payer pre-signs its next channel state under a point Y. The pre-signature is not a valid
//! ECDSA signature: whoever knows y (Y = y·G) completes it into one, and whoever holds the
//! pre-signature and sees the completed signature learns y. The completed signature is an
//! ordinary 0x21 state signature, so [`crate::channel::Payee`], close and the watcher take it
//! unchanged.
//!
//! ```text
//! pre-sign(x, z, Y):  k random; R' = k·G; R = k·Y; r = R.x mod n; s' = k⁻¹ (z + r·x)
//!                     π = DLEQ proof that log_G(R') = log_Y(R)
//! pre-verify:         π holds and s'⁻¹ (z·G + r·X) == R'
//! adapt(y):           s = s' · y⁻¹, low S          -> (r, s) is a valid ECDSA signature
//! extract(s):         y = ±(s' · s⁻¹), the sign fixed by y·G == Y
//! ```
//!
//! The construction and the wire encoding are B1's `xbt402/adaptor.py` (AGP-008/014, reviewed in
//! AGP-021): `{R, R1, s1, c, z}` with 33-byte compressed points and 64-hex scalars, and the DLEQ
//! challenge `tagged_hash("b5/adaptor/dleq", X‖z‖Y‖R'‖R‖A1‖A2) mod n`. A pre-signature made here
//! verifies there and the other way round (the routing vectors and `route_interop.sh` check it).
//!
//! **Constant time.** Every operation on a secret (the key x, the nonces k and w, the adaptor
//! secret y) runs in libsecp256k1: point multiplications through `secp256k1_ec_pubkey_create` /
//! `_tweak_mul`, scalar products and sums through `secp256k1_ec_seckey_tweak_mul` / `_tweak_add`,
//! and inversions as a fixed square-and-multiply ladder over the public exponent n − 2 built from
//! those. The Python reference still does s' = k⁻¹(z + r·x) and the DLEQ response in bigints
//! (blinded); this port has no such remainder. Public work (pre-verify, extract) needs no
//! constant time and uses the same primitives.
//!
//! **zkp seam.** [`AdaptorBackend`] is the whole surface the routing code uses (through the free
//! functions below, which call [`default_backend`]). A libsecp256k1-zkp `ecdsa_adaptor` backend
//! can implement it later; its encoding differs, so both ends of a hop must switch together.
use serde_json::{json, Value};
use xbt_primitives::ecdsa::{self, CURVE_ORDER};
use xbt_primitives::hash::tagged_hash;
use xbt_primitives::secp256k1::{PublicKey, Scalar, SecretKey, SECP256K1};

use crate::error::{fail, ChannelError, Result};

/// The DLEQ proof's tagged-hash tag (the B1/b5 wire).
pub const DLEQ_TAG: &str = "b5/adaptor/dleq";

// --- scalars mod n ---------------------------------------------------------------------------

/// A scalar mod n, big-endian, always reduced. Zero is representable (a public value may be).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Sc(pub [u8; 32]);

fn sub_n(v: &mut [u8; 32]) {
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = v[i] as i16 - CURVE_ORDER[i] as i16 - borrow;
        borrow = if d < 0 { 1 } else { 0 };
        v[i] = (d + 256 * borrow) as u8;
    }
}

impl Sc {
    pub const ZERO: Sc = Sc([0; 32]);

    /// `b mod n` for any 32 bytes (b < 2^256 < 2n: at most one subtraction).
    pub fn reduce(b: &[u8; 32]) -> Sc {
        let mut v = *b;
        if v >= CURVE_ORDER {
            sub_n(&mut v);
        }
        Sc(v)
    }

    /// A scalar that must already be below n (a wire value): None otherwise.
    pub fn strict(b: &[u8; 32]) -> Option<Sc> {
        (*b < CURVE_ORDER).then_some(Sc(*b))
    }

    pub fn from_secret(s: &SecretKey) -> Sc {
        Sc(s.secret_bytes())
    }

    pub fn from_u64(n: u64) -> Sc {
        let mut b = [0u8; 32];
        b[24..].copy_from_slice(&n.to_be_bytes());
        Sc(b)
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 32]
    }

    /// As a secret key (None for zero).
    pub fn secret(&self) -> Option<SecretKey> {
        SecretKey::from_slice(&self.0).ok()
    }

    fn tweak(&self) -> Scalar {
        // cannot fail: reduced
        Scalar::from_be_bytes(self.0).unwrap_or(Scalar::ZERO)
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// 64 hex digits (the wire form), strictly below n.
    pub fn from_hex64(s: &str) -> Option<Sc> {
        if s.len() != 64 {
            return None;
        }
        let v: [u8; 32] = hex::decode(s).ok()?.try_into().ok()?;
        Sc::strict(&v)
    }

    /// Python `int(s, 16) % N` for a hex string of any length up to 64 digits.
    pub fn from_hex_mod_n(s: &str) -> Option<Sc> {
        let s = s.trim();
        if s.is_empty() || s.len() > 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let padded = format!("{s:0>64}");
        let v: [u8; 32] = hex::decode(padded).ok()?.try_into().ok()?;
        Some(Sc::reduce(&v))
    }

    /// `a · b mod n` (constant time in libsecp256k1 for nonzero operands).
    pub fn mul(&self, b: &Sc) -> Sc {
        match (self.secret(), b.is_zero()) {
            (Some(a), false) => a.mul_tweak(&b.tweak()).map(|s| Sc::from_secret(&s)).unwrap_or(Sc::ZERO),
            _ => Sc::ZERO,
        }
    }

    /// `a + b mod n`.
    pub fn add(&self, b: &Sc) -> Sc {
        match self.secret() {
            None => *b,
            // Err only when the sum is zero
            Some(a) => a.add_tweak(&b.tweak()).map(|s| Sc::from_secret(&s)).unwrap_or(Sc::ZERO),
        }
    }

    /// `−a mod n`.
    pub fn neg(&self) -> Sc {
        self.secret().map(|a| Sc::from_secret(&a.negate())).unwrap_or(Sc::ZERO)
    }

    pub fn sub(&self, b: &Sc) -> Sc {
        self.add(&b.neg())
    }

    /// `a⁻¹ mod n` = a^(n−2): a fixed ladder over the public exponent (256 squarings and one
    /// multiplication per set bit, the same sequence for every a). None for zero.
    pub fn inv(&self) -> Option<Sc> {
        let a = self.secret()?;
        let mut e = CURVE_ORDER;
        // n - 2 (n is odd and its low byte is 0x41, so no borrow)
        e[31] -= 2;
        let at = Scalar::from(a);
        let mut acc: Option<SecretKey> = None;
        for byte in e {
            for bit in (0..8).rev() {
                if let Some(x) = acc {
                    acc = x.mul_tweak(&Scalar::from(x)).ok();
                }
                if (byte >> bit) & 1 == 1 {
                    acc = Some(match acc {
                        None => a,
                        Some(x) => x.mul_tweak(&at).ok()?,
                    });
                }
            }
        }
        acc.map(|s| Sc::from_secret(&s))
    }

    /// `a⁻¹` blinded as B1 does: a⁻¹ = b·(a·b)⁻¹ for a fresh b, so the ladder never runs on `a`.
    pub fn inv_blinded(&self) -> Option<Sc> {
        let b = Sc::from_secret(&random_secret());
        Some(b.mul(&self.mul(&b).inv()?))
    }

    /// `a > n/2`.
    pub fn is_high(&self) -> bool {
        // n/2 = floor(n / 2): compare 2a > n <=> a > (n-1)/2
        let mut half = [0u8; 32];
        let mut carry = 0u8;
        for (i, b) in CURVE_ORDER.iter().enumerate() {
            half[i] = (b >> 1) | (carry << 7);
            carry = b & 1;
        }
        self.0 > half
    }
}

/// A fresh random secret key (the OS RNG).
pub use crate::signer::random_secret;

// --- points ------------------------------------------------------------------------------------

/// A compressed point (`enc` in the reference).
pub fn enc(p: &PublicKey) -> [u8; 33] {
    p.serialize()
}

/// A compressed point from hex or bytes; Err for anything that is not on the curve.
pub fn dec(b: &[u8]) -> Result<PublicKey> {
    if b.len() != 33 {
        return fail("bad_point", "points must be 33-byte compressed");
    }
    PublicKey::from_slice(b).map_err(|_| ChannelError::new("bad_point", "not a point on secp256k1"))
}

pub fn dec_hex(s: &str) -> Result<PublicKey> {
    dec(&hex::decode(s.trim()).map_err(|_| ChannelError::new("bad_point", "not hex"))?)
}

/// `y·G` for a secret y (a route's t or t + r).
pub fn point_of(y: &SecretKey) -> PublicKey {
    y.public_key(SECP256K1)
}

/// `k·P` (or `k·G` when `p` is None); None at infinity (k = 0).
pub fn mul(k: &Sc, p: Option<&PublicKey>) -> Option<PublicKey> {
    let s = k.secret()?;
    match p {
        None => Some(s.public_key(SECP256K1)),
        Some(p) => p.mul_tweak(SECP256K1, &k.tweak()).ok(),
    }
}

/// `a + b`; None is the point at infinity.
pub fn add(a: Option<&PublicKey>, b: Option<&PublicKey>) -> Option<PublicKey> {
    match (a, b) {
        (None, b) => b.copied(),
        (a, None) => a.copied(),
        (Some(a), Some(b)) => a.combine(b).ok(),
    }
}

fn neg(p: Option<PublicKey>) -> Option<PublicKey> {
    p.map(|p| p.negate(SECP256K1))
}

/// `R.x mod n`.
pub fn x_mod_n(p: &PublicKey) -> Sc {
    let s = p.serialize();
    let mut x = [0u8; 32];
    x.copy_from_slice(&s[1..]);
    Sc::reduce(&x)
}

// --- the pre-signature -------------------------------------------------------------------------

/// A pre-signature `{R, R1, s1, c, z}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreSig {
    /// k·Y: r = R.x mod n is the r of the completed signature.
    pub big_r: [u8; 33],
    /// k·G.
    pub r1: [u8; 33],
    /// s' = k⁻¹ (z + r·x).
    pub s1: Sc,
    /// DLEQ challenge.
    pub c: Sc,
    /// DLEQ response.
    pub zz: Sc,
}

impl PreSig {
    /// The r of the completed signature, or None if R is not a point.
    pub fn r(&self) -> Option<Sc> {
        dec(&self.big_r).ok().map(|p| x_mod_n(&p))
    }

    /// The wire form, key order as B1's `to_json`.
    pub fn to_json(&self) -> Value {
        json!({"R": hex::encode(self.big_r), "R1": hex::encode(self.r1), "s1": self.s1.hex(), "c": self.c.hex(), "z": self.zz.hex()})
    }

    /// Parse the wire form. Err (`bad_adaptor`) on anything malformed. Like the reference, the
    /// points are only checked for length here (pre-verify decodes them) and each scalar must be
    /// 64 hex digits.
    pub fn from_json(d: &Value) -> Result<Self> {
        let bad = |m: &str| ChannelError::new("bad_adaptor", m.to_string());
        let o = d.as_object().ok_or_else(|| bad("adaptor must be an object"))?;
        let pt = |k: &str| -> Result<[u8; 33]> {
            let s = o.get(k).and_then(Value::as_str).ok_or_else(|| bad(k))?;
            hex::decode(s).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| bad("adaptor points are 33-byte compressed"))
        };
        let (big_r, r1) = (pt("R")?, pt("R1")?);
        let sc = |k: &str| -> Result<Sc> {
            let s = o.get(k).and_then(Value::as_str).filter(|s| s.len() == 64).ok_or_else(|| bad(&format!("adaptor {k} is 64 hex")))?;
            let v: [u8; 32] = hex::decode(s).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| bad(&format!("adaptor {k} is 64 hex")))?;
            // the reference keeps int(s, 16) as is; values >= n fail pre-verify there, and here
            Ok(Sc(v))
        };
        Ok(Self { big_r, r1, s1: sc("s1")?, c: sc("c")?, zz: sc("z")? })
    }

    /// `(r, s')` as if it were a signature: what a payee that never learns y could try to close
    /// with (the node refuses it).
    pub fn bogus_der(&self) -> Vec<u8> {
        let r = self.r().unwrap_or_default();
        let s = if self.s1.is_high() { self.s1.neg() } else { self.s1 };
        der(&r, &s)
    }
}

fn der_int(v: &[u8; 32]) -> Vec<u8> {
    let mut b: Vec<u8> = v.iter().copied().skip_while(|x| *x == 0).collect();
    if b.is_empty() {
        b.push(0);
    }
    if b[0] & 0x80 != 0 {
        b.insert(0, 0);
    }
    let mut out = vec![0x02, b.len() as u8];
    out.extend(b);
    out
}

/// Minimal DER of `(r, s)` (the reference's `der`), no hash-type byte.
pub fn der(r: &Sc, s: &Sc) -> Vec<u8> {
    let body = [der_int(&r.0), der_int(&s.0)].concat();
    let mut out = vec![0x30, body.len() as u8];
    out.extend(body);
    out
}

/// The reference's lenient `parse_der`: `(r, s)` as big-endian byte strings (any length), or
/// None where Python raises.
fn parse_der(sig: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if sig.len() < 8 || sig[0] != 0x30 || sig[1] as usize != sig.len() - 2 || sig[2] != 0x02 {
        return None;
    }
    let lr = sig[3] as usize;
    if *sig.get(4 + lr)? != 0x02 {
        return None;
    }
    let ls = *sig.get(5 + lr)? as usize;
    // Python slices past the end truncate
    let r = sig[4.min(sig.len())..(4 + lr).min(sig.len())].to_vec();
    let s0 = (6 + lr).min(sig.len());
    let s = sig[s0..(6 + lr + ls).min(sig.len())].to_vec();
    Some((r, s))
}

/// A big-endian byte string of any length as a scalar, if its value is below n.
fn int_below_n(b: &[u8]) -> Option<Sc> {
    let t: Vec<u8> = b.iter().copied().skip_while(|x| *x == 0).collect();
    if t.len() > 32 {
        return None;
    }
    let mut v = [0u8; 32];
    v[32 - t.len()..].copy_from_slice(&t);
    Sc::strict(&v)
}

fn challenge(x: &[u8], z: &[u8; 32], y: &PublicKey, r1: &PublicKey, r: &PublicKey, a1: &PublicKey, a2: &PublicKey) -> Sc {
    let mut m = Vec::with_capacity(33 * 6 + 32);
    m.extend_from_slice(x);
    m.extend_from_slice(z);
    for p in [y, r1, r, a1, a2] {
        m.extend_from_slice(&enc(p));
    }
    Sc::reduce(&tagged_hash(DLEQ_TAG, &m))
}

// --- the backend seam --------------------------------------------------------------------------

/// Everything the routing code needs from an adaptor-signature scheme. [`Secp256k1Dleq`] is the
/// B1-compatible one; a libsecp256k1-zkp backend can implement this later.
pub trait AdaptorBackend: Send + Sync {
    /// Pre-sign digest `z` with key `x` under point `y` (secret-key operation).
    fn presign(&self, x: &SecretKey, z: &[u8; 32], y: &PublicKey) -> Result<PreSig>;
    /// True iff completing `pre` with log_G(y) gives a valid ECDSA signature by `x_pub` over `z`.
    fn preverify(&self, x_pub: &[u8], z: &[u8; 32], y: &PublicKey, pre: &PreSig) -> bool;
    /// The completed low-S strict-DER signature (no hash-type byte).
    fn adapt(&self, pre: &PreSig, y: &SecretKey) -> Result<Vec<u8>>;
    /// y from a completed signature (with or without its hash-type byte), or None if `sig` is not
    /// a completion of `pre`.
    fn extract(&self, pre: &PreSig, sig: &[u8], y: &PublicKey) -> Option<SecretKey>;
}

/// The ECDSA adaptor with a DLEQ proof, wire-compatible with B1 `xbt402/adaptor.py`.
#[derive(Debug, Default, Clone, Copy)]
pub struct Secp256k1Dleq;

impl Secp256k1Dleq {
    /// Pre-sign with given nonces `k` and `w` (None if they make r or s' zero). For test vectors
    /// only: a reused k leaks x.
    #[doc(hidden)]
    pub fn presign_with_nonces(&self, x: &SecretKey, z: &[u8; 32], y: &PublicKey, k: &SecretKey, w: &SecretKey) -> Option<PreSig> {
        let xp = ecdsa::pubkey(x);
        let r1 = point_of(k);
        let big_r = y.mul_tweak(SECP256K1, &Scalar::from(*k)).ok()?;
        let r = x_mod_n(&big_r);
        let (ks, xs) = (Sc::from_secret(k), Sc::from_secret(x));
        // s' = k⁻¹ (z + r·x), every step in libsecp256k1
        let s1 = ks.inv_blinded()?.mul(&Sc::reduce(z).add(&r.mul(&xs)));
        if r.is_zero() || s1.is_zero() {
            return None;
        }
        let a1 = point_of(w);
        let a2 = y.mul_tweak(SECP256K1, &Scalar::from(*w)).ok()?;
        let c = challenge(&xp, z, y, &r1, &big_r, &a1, &a2);
        let zz = Sc::from_secret(w).add(&c.mul(&ks));
        Some(PreSig { big_r: enc(&big_r), r1: enc(&r1), s1, c, zz })
    }
}

impl AdaptorBackend for Secp256k1Dleq {
    fn presign(&self, x: &SecretKey, z: &[u8; 32], y: &PublicKey) -> Result<PreSig> {
        for _ in 0..64 {
            if let Some(p) = self.presign_with_nonces(x, z, y, &random_secret(), &random_secret()) {
                return Ok(p);
            }
        }
        fail("bad_adaptor", "could not pre-sign")
    }

    fn preverify(&self, x_pub: &[u8], z: &[u8; 32], y: &PublicKey, pre: &PreSig) -> bool {
        let (Ok(big_r), Ok(r1), Ok(xp)) = (dec(&pre.big_r), dec(&pre.r1), dec(x_pub)) else { return false };
        // 0 <= c < n, 0 < z < n, 0 < s1 < n
        let (Some(c), Some(zz), Some(s1)) = (Sc::strict(&pre.c.0), Sc::strict(&pre.zz.0), Sc::strict(&pre.s1.0)) else { return false };
        if zz.is_zero() || s1.is_zero() {
            return false;
        }
        let a1 = add(mul(&zz, None).as_ref(), neg(mul(&c, Some(&r1))).as_ref());
        let a2 = add(mul(&zz, Some(y)).as_ref(), neg(mul(&c, Some(&big_r))).as_ref());
        let (Some(a1), Some(a2)) = (a1, a2) else { return false };
        if c != challenge(&xp.serialize(), z, y, &r1, &big_r, &a1, &a2) {
            return false;
        }
        let r = x_mod_n(&big_r);
        if r.is_zero() {
            return false;
        }
        let Some(si) = s1.inv() else { return false };
        let lhs = add(mul(&Sc::reduce(z).mul(&si), None).as_ref(), mul(&r.mul(&si), Some(&xp)).as_ref());
        lhs == Some(r1)
    }

    fn adapt(&self, pre: &PreSig, y: &SecretKey) -> Result<Vec<u8>> {
        let r = pre.r().ok_or_else(|| ChannelError::new("bad_adaptor", "R is not a point"))?;
        let yi = Sc::from_secret(y).inv_blinded().ok_or_else(|| ChannelError::new("bad_secret", "zero adaptor secret"))?;
        let s = Sc::reduce(&pre.s1.0).mul(&yi);
        if s.is_zero() || r.is_zero() {
            return fail("bad_adaptor", "degenerate pre-signature");
        }
        let s = if s.is_high() { s.neg() } else { s };
        Ok(der(&r, &s))
    }

    fn extract(&self, pre: &PreSig, sig: &[u8], y: &PublicKey) -> Option<SecretKey> {
        let sig = if sig.len() >= 2 && sig.len() == sig[1] as usize + 3 { &sig[..sig.len() - 1] } else { sig };
        let (rb, sb) = parse_der(sig)?;
        let r = int_below_n(&rb)?;
        if Some(r) != pre.r() {
            return None;
        }
        let s = int_below_n(&sb)?;
        let yv = Sc::reduce(&pre.s1.0).mul(&s.inv()?);
        [yv, yv.neg()].into_iter().filter_map(|c| c.secret()).find(|c| point_of(c) == *y)
    }
}

static DEFAULT: Secp256k1Dleq = Secp256k1Dleq;

/// The backend the free functions use.
pub fn default_backend() -> &'static dyn AdaptorBackend {
    &DEFAULT
}

pub fn presign(x: &SecretKey, z: &[u8; 32], y: &PublicKey) -> Result<PreSig> {
    default_backend().presign(x, z, y)
}

pub fn preverify(x_pub: &[u8], z: &[u8; 32], y: &PublicKey, pre: &PreSig) -> bool {
    default_backend().preverify(x_pub, z, y, pre)
}

pub fn adapt(pre: &PreSig, y: &SecretKey) -> Result<Vec<u8>> {
    default_backend().adapt(pre, y)
}

pub fn extract(pre: &PreSig, sig: &[u8], y: &PublicKey) -> Option<SecretKey> {
    default_backend().extract(pre, sig, y)
}

/// y from a close's input witness: any item that is a completion of `pre` (the payer signature is
/// witness[0] on the pay path).
pub fn secret_from_witness(pre: &PreSig, witness: &[Vec<u8>], y: &PublicKey) -> Option<SecretKey> {
    witness.iter().find_map(|item| extract(pre, item, y))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xbt_primitives::hash::sha256;

    fn sk(tag: &[u8]) -> SecretKey {
        SecretKey::from_slice(&sha256(tag)).unwrap()
    }

    #[test]
    fn scalar_ops() {
        let a = Sc::from_secret(&sk(b"a"));
        let ai = a.inv().unwrap();
        assert_eq!(a.mul(&ai), Sc::from_u64(1));
        assert_eq!(a.inv_blinded().unwrap(), ai);
        assert_eq!(a.add(&a.neg()), Sc::ZERO);
        assert_eq!(Sc::from_u64(7).mul(&Sc::from_u64(6)), Sc::from_u64(42));
        assert_eq!(Sc::from_u64(7).sub(&Sc::from_u64(9)), Sc::from_u64(2).neg());
        assert!(Sc::ZERO.inv().is_none());
        assert!(Sc::from_u64(1).neg().is_high() && !Sc::from_u64(1).is_high());
        assert_eq!(Sc::from_hex_mod_n("ff").unwrap(), Sc::from_u64(255));
    }

    #[test]
    fn presign_adapt_extract() {
        let x = sk(b"x");
        let z = sha256(b"state");
        let y = sk(b"y");
        let yp = point_of(&y);
        let pre = presign(&x, &z, &yp).unwrap();
        let xp = ecdsa::pubkey(&x);
        assert!(preverify(&xp, &z, &yp, &pre));
        assert!(!preverify(&xp, &sha256(b"other"), &yp, &pre));
        assert!(!preverify(&xp, &z, &point_of(&sk(b"y2")), &pre));
        let sig = adapt(&pre, &y).unwrap();
        assert!(ecdsa::verify(&xp, &z, &sig), "a completed pre-signature is a valid low-S strict-DER signature");
        assert_eq!(extract(&pre, &sig, &yp), Some(y));
        let mut with_type = sig.clone();
        with_type.push(0x21);
        assert_eq!(secret_from_witness(&pre, &[vec![], with_type], &yp), Some(y));
        assert!(!ecdsa::verify(&xp, &z, &pre.bogus_der()));
        let j = pre.to_json();
        assert_eq!(PreSig::from_json(&j).unwrap(), pre);
        let mut bad = pre.clone();
        bad.zz = bad.zz.add(&Sc::from_u64(1));
        assert!(!preverify(&xp, &z, &yp, &bad));
    }

    #[test]
    fn hostile_wire() {
        for v in [json!(null), json!({}), json!({"R": "00", "R1": "00", "s1": "0", "c": "0", "z": "0"}), json!([1])] {
            assert!(PreSig::from_json(&v).is_err());
        }
        let pre = PreSig { big_r: [2; 33], r1: [3; 33], s1: Sc([0xff; 32]), c: Sc::ZERO, zz: Sc::ZERO };
        assert!(!preverify(&[2; 33], &[0; 32], &point_of(&sk(b"y")), &pre));
        assert!(extract(&pre, &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01], &point_of(&sk(b"y"))).is_none());
        assert!(extract(&pre, &[], &point_of(&sk(b"y"))).is_none());
        assert!(extract(&pre, &[0x30, 0xff, 0x02, 0x70, 0, 0, 0, 0], &point_of(&sk(b"y"))).is_none());
    }
}
