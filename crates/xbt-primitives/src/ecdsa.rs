//! secp256k1 through libsecp256k1: RFC 6979 low-S ECDSA with BIP66 strict-DER checking, ECDH,
//! and the additive key tweaks xbt402's per-channel keys use.
use secp256k1::{ecdh, ecdsa::Signature, Message, PublicKey, Scalar, SecretKey, SECP256K1};

use crate::error::{Error, Result};

/// The curve order n, big-endian.
pub const CURVE_ORDER: [u8; 32] = secp256k1::constants::CURVE_ORDER;

/// A 33-byte compressed SEC1 public key.
pub type PubkeyBytes = [u8; 33];

/// BIP66 strict DER (Bitcoin Core `IsValidSignatureEncoding`) for a signature *without* its
/// hash-type byte. Segwit v0 consensus refuses any other encoding, so a state that only parses
/// loosely is one the payee can never close with.
pub fn is_strict_der(der: &[u8]) -> bool {
    let n = der.len();
    if !(8..=72).contains(&n) || der[0] != 0x30 || der[1] as usize != n - 2 || der[2] != 0x02 {
        return false;
    }
    let lr = der[3] as usize;
    if lr == 0 || 5 + lr >= n || der[4] & 0x80 != 0 || (lr > 1 && der[4] == 0 && der[5] & 0x80 == 0) {
        return false;
    }
    if der[4 + lr] != 0x02 {
        return false;
    }
    let ls = der[5 + lr] as usize;
    if ls == 0 || 6 + lr + ls != n || der[6 + lr] & 0x80 != 0 || (ls > 1 && der[6 + lr] == 0 && der[7 + lr] & 0x80 == 0) {
        return false;
    }
    true
}

pub fn secret_key(b: &[u8; 32]) -> Result<SecretKey> {
    SecretKey::from_slice(b).map_err(|_| Error::BadKey("secret key is zero or not below n"))
}

pub fn public_key(b: &[u8]) -> Result<PublicKey> {
    PublicKey::from_slice(b).map_err(|_| Error::BadKey("not a point on secp256k1"))
}

/// Compressed public key of `sk`.
pub fn pubkey(sk: &SecretKey) -> PubkeyBytes {
    PublicKey::from_secret_key(SECP256K1, sk).serialize()
}

/// DER signature (low S, RFC 6979 nonce) over a 32-byte digest, without the hash-type byte. The
/// same bytes coincurve and B1's pure-Python fallback produce.
pub fn sign(sk: &SecretKey, msg32: &[u8; 32]) -> Vec<u8> {
    SECP256K1.sign_ecdsa(&Message::from_digest(*msg32), sk).serialize_der().to_vec()
}

/// Verify a strict-DER, low-S signature: exactly what the node accepts in a segwit v0 witness.
/// Never panics; any malformed key or signature is `false`.
pub fn verify(pubkey: &[u8], msg32: &[u8; 32], der: &[u8]) -> bool {
    if !is_strict_der(der) {
        return false;
    }
    let (Ok(pk), Ok(sig)) = (PublicKey::from_slice(pubkey), Signature::from_der(der)) else {
        return false;
    };
    // libsecp256k1 refuses a high-S signature in verify, as the node's policy does
    SECP256K1.verify_ecdsa(&Message::from_digest(*msg32), &sig, &pk).is_ok()
}

/// x coordinate of `sk * pubkey` (32 bytes): a secret both channel parties can compute.
pub fn ecdh_x(sk: &SecretKey, pubkey: &PublicKey) -> [u8; 32] {
    let pt = ecdh::shared_secret_point(pubkey, sk);
    let mut x = [0u8; 32];
    x.copy_from_slice(&pt[..32]);
    x
}

/// `h mod n` as a scalar, for a 32-byte hash read big-endian (h < 2^256 < 2n, so at most one
/// subtraction).
pub fn scalar_mod_n(h: &[u8; 32]) -> Scalar {
    let mut v = *h;
    if v >= CURVE_ORDER {
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = v[i] as i16 - CURVE_ORDER[i] as i16 - borrow;
            borrow = if d < 0 { 1 } else { 0 };
            v[i] = (d + 256 * borrow) as u8;
        }
    }
    // cannot fail: v < n now
    Scalar::from_be_bytes(v).unwrap_or(Scalar::ZERO)
}

/// `P + t·G`.
pub fn tweak_add_pub(p: &PublicKey, t: &Scalar) -> Result<PublicKey> {
    p.add_exp_tweak(SECP256K1, t).map_err(|_| Error::BadKey("tweaked key is the point at infinity"))
}

/// `(s + t) mod n`.
pub fn tweak_add_secret(s: &SecretKey, t: &Scalar) -> Result<SecretKey> {
    s.add_tweak(t).map_err(|_| Error::BadKey("tweaked secret is zero"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;

    #[test]
    fn sign_verify_and_der_rules() {
        let sk = secret_key(&sha256(b"k")).unwrap();
        let msg = sha256(b"m");
        let sig = sign(&sk, &msg);
        let pk = pubkey(&sk);
        assert!(is_strict_der(&sig));
        assert!(verify(&pk, &msg, &sig));
        assert!(!verify(&pk, &sha256(b"other"), &sig));
        assert!(!verify(&[2; 33], &msg, &sig));
        assert!(!verify(&pk, &msg, &sig[..sig.len() - 1]));
        // a high-S twin of the same signature is refused
        let mut s = Signature::from_der(&sig).unwrap().serialize_compact();
        let mut hs = [0u8; 32];
        let n = CURVE_ORDER;
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = n[i] as i16 - s[32 + i] as i16 - borrow;
            borrow = if d < 0 { 1 } else { 0 };
            hs[i] = (d + 256 * borrow) as u8;
        }
        s[32..].copy_from_slice(&hs);
        let high = Signature::from_compact(&s).unwrap().serialize_der();
        assert!(!verify(&pk, &msg, &high));
    }

    #[test]
    fn scalar_reduction() {
        let big = [0xFF; 32];
        let s = scalar_mod_n(&big);
        // 2^256 - 1 - n
        let want = hex::decode("000000000000000000000000000000014551231950b75fc4402da1732fc9bebe").unwrap();
        assert_eq!(s.to_be_bytes().to_vec(), want);
    }
}
