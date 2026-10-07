//! Hash functions: SHA-256, SHA-256d, BIP340-style tagged hashes, HASH160 and BLAKE2b-256.
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest as _};
use ripemd::Ripemd160;
use sha2::Sha256;

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub fn dsha256(b: &[u8]) -> [u8; 32] {
    sha256(&sha256(b))
}

/// `sha256(sha256(tag) || sha256(tag) || msg)`.
pub fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let t = sha256(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h.update(msg);
    h.finalize().into()
}

/// RIPEMD160(SHA256(b)).
pub fn hash160(b: &[u8]) -> [u8; 20] {
    Ripemd160::digest(sha256(b)).into()
}

/// BLAKE2b with a 32-byte digest. The digest size is part of BLAKE2b's parameter block, so this
/// is not a truncated BLAKE2b-512.
pub fn blake2b256(b: &[u8]) -> [u8; 32] {
    Blake2b::<U32>::digest(b).into()
}

/// Lowercase hex of `b` reversed: how txids and block hashes are displayed.
pub fn display_hex(b: &[u8; 32]) -> String {
    let mut r = *b;
    r.reverse();
    hex::encode(r)
}

/// The inverse of [`display_hex`]: 64 hex characters to internal byte order.
pub fn from_display_hex(s: &str) -> crate::error::Result<[u8; 32]> {
    let mut b = hex32(s)?;
    b.reverse();
    Ok(b)
}

/// Exactly 32 bytes of hex (either case).
pub fn hex32(s: &str) -> crate::error::Result<[u8; 32]> {
    let v = hex::decode(s).map_err(|e| crate::Error::BadHex(e.to_string()))?;
    v.try_into().map_err(|_| crate::Error::BadHex("expected 32 bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        assert_eq!(hex::encode(sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex::encode(blake2b256(b"")), "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
        assert_eq!(hex::encode(hash160(b"")), "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb");
    }
}
