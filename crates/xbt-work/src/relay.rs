//! The blinded receipt relay, client side (spec §11.1). For each (identity, invoice):
//!
//! ```text
//! lookup = hex(SHA256("xbt-work/relay-id|"  ‖ identity ‖ "|" ‖ invoice))
//! key    =      SHA256("xbt-work/relay-key|" ‖ identity ‖ "|" ‖ invoice)
//! blob   = nonce(12) ‖ ChaCha20-Poly1305(key, nonce, pad₁₀₂₄(receipt document), aad = lookup)
//! ```
//! The relay sees only 256-bit lookups and constant-size blobs; it can neither read nor forge a
//! receipt (the Prime's signature is inside), only withhold or serve a stale one.
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde_json::Value;
use sha2::{Digest, Sha256};
use xbt402::client::Transport;

use crate::error::{fail, Result};

pub const PAD: usize = 1024;

pub fn lookup(identity: &str, invoice: &str) -> String {
    hex::encode(Sha256::digest(format!("xbt-work/relay-id|{identity}|{invoice}").as_bytes()))
}

pub fn key(identity: &str, invoice: &str) -> [u8; 32] {
    Sha256::digest(format!("xbt-work/relay-key|{identity}|{invoice}").as_bytes()).into()
}

/// Seal a receipt document (a Prime pushes these). `nonce` None: 12 random bytes.
pub fn seal(doc: &[u8], identity: &str, invoice: &str, nonce: Option<[u8; 12]>) -> Result<Vec<u8>> {
    if doc.len() > PAD {
        return fail("relay", "receipt document larger than pad_1024");
    }
    let n = nonce.unwrap_or_else(|| {
        let mut b = [0u8; 12];
        getrandom::getrandom(&mut b).expect("OS randomness");
        b
    });
    let mut padded = doc.to_vec();
    padded.resize(PAD, b' ');
    let lk = lookup(identity, invoice);
    let ct = ChaCha20Poly1305::new(Key::from_slice(&key(identity, invoice)))
        .encrypt(Nonce::from_slice(&n), Payload { msg: &padded, aad: lk.as_bytes() })
        .map_err(|_| crate::error::WorkError::new("relay", "seal"))?;
    let mut out = n.to_vec();
    out.extend(ct);
    Ok(out)
}

/// Open a blob: the padded document (trailing spaces kept). Tampering or the wrong pair fails.
pub fn open(blob: &[u8], identity: &str, invoice: &str) -> Result<Vec<u8>> {
    if blob.len() < 28 {
        return fail("relay", "blob too short");
    }
    let lk = lookup(identity, invoice);
    ChaCha20Poly1305::new(Key::from_slice(&key(identity, invoice)))
        .decrypt(Nonce::from_slice(&blob[..12]), Payload { msg: &blob[12..], aad: lk.as_bytes() })
        .or_else(|_| fail("relay", "tampered or wrong key"))
}

/// `GET <relay>/<lookup>`, open, parse: the Prime's receipt document for the pair, or None when
/// the relay has no entry (404). The document is still unverified: verify its signature.
pub fn fetch(t: &dyn Transport, relay_url: &str, identity: &str, invoice: &str) -> Result<Option<Value>> {
    let r = t.request("GET", &format!("{}/{}", relay_url.trim_end_matches('/'), lookup(identity, invoice)), b"", &[])?;
    match r.status {
        404 => Ok(None),
        200 => {
            let raw = open(&r.body, identity, invoice)?;
            let text = std::str::from_utf8(&raw).map_err(|_| crate::error::WorkError::new("relay", "not UTF-8"))?;
            let doc = xbt402::json::parse(text.trim_end_matches(' ')).map_err(|_| crate::error::WorkError::new("relay", "not JSON"))?;
            Ok(Some(doc))
        }
        s => fail("relay", format!("relay answered HTTP {s}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_tamper() {
        let (i, v) = ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "vfer2e5e75t4tv7in42lakx6i4");
        let b = seal(b"{\"a\":1}", i, v, Some([3u8; 12])).unwrap();
        assert_eq!(b.len(), 12 + PAD + 16);
        assert_eq!(open(&b, i, v).unwrap().trim_ascii_end(), b"{\"a\":1}");
        let mut t = b.clone();
        t[20] ^= 1;
        assert!(open(&t, i, v).is_err());
        assert!(open(&b, i, "vfer2e5e75t4tv7in42lakx6i5").is_err());
        assert!(!lookup(i, v).contains(i));
    }
}
