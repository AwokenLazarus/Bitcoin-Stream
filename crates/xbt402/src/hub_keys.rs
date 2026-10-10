//! AGP-073 K1: the hub's ch2 payer keys sealed at rest.
//!
//! The hub is the payer of every ch2 and holds each one's key in its state file (`ch2.json`). Each
//! key is sealed on its own with AES-256-GCM under the hub's wrap key, aad [`HUB_CH2_AAD`], in the
//! B2 keystore blob format (`xbt-signer` `keystore`):
//! `{"v":1,"alg":"aes-256-gcm","kdf":"keyfile","salt":"","nonce","ct","aad"}`, hex fields, the tag
//! at the end of `ct`. The rest of the record stays readable (operators and the watcher's tools
//! read it), and a key is sealed once and its blob reused by every later save.
//!
//! The wrap key is 32 bytes (raw, or 64 hex) in a file of its own: `hub-wrap-key`, 0600, refused
//! when group or others have any bit. The blob does not name its record: the book checks that each
//! key it opens is the record's `payerPub`, so a blob moved to another record is refused.
use std::io::Write;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::error::{ChannelError, Result};

/// The aad of a sealed ch2 key.
pub const HUB_CH2_AAD: &str = "xbt402/hub-ch2";
/// The wrap key's default file name (in the hub's data dir) and its secret name in `xbt402-hub`.
pub const WRAP_KEY_FILE: &str = "hub-wrap-key";

fn err(msg: impl Into<String>) -> ChannelError {
    ChannelError::new("keystore", msg)
}

/// The key that seals the hub's ch2 keys. Zeroed on drop; never printed.
pub struct WrapKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for WrapKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WrapKey(..)")
    }
}

impl WrapKey {
    pub fn from_bytes(k: [u8; 32]) -> Self {
        Self(Zeroizing::new(k))
    }

    /// 32 raw bytes, or 64 hex characters (surrounding whitespace ignored).
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() == 32 {
            let mut k = Zeroizing::new([0u8; 32]);
            k.copy_from_slice(raw);
            return Ok(Self(k));
        }
        let txt = Zeroizing::new(String::from_utf8_lossy(raw).trim().to_string());
        let mut k = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(txt.as_bytes(), &mut k[..]).map_err(|_| err("a wrap key is 32 bytes (raw or 64 hex characters)"))?;
        Ok(Self(k))
    }

    /// The wrap key in `path`, created (32 random bytes, 0600, never over an existing file) when it
    /// does not exist. Refused: not a regular file, or any bit for group or others.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        let at = |e: std::io::Error| err(format!("{}: {e}", path.display()));
        if !path.exists() {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent).map_err(at)?;
            }
            match create_new_private(path) {
                Ok(mut f) => {
                    let mut k = Zeroizing::new([0u8; 32]);
                    getrandom::getrandom(&mut k[..]).map_err(|e| err(format!("OS randomness: {e}")))?;
                    f.write_all(&k[..]).map_err(at)?;
                    f.sync_all().map_err(at)?;
                    sync_dir(path).map_err(at)?;
                }
                // another process made it first: read theirs
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(at(e)),
            }
        }
        let md = std::fs::metadata(path).map_err(at)?;
        if !md.file_type().is_file() {
            return Err(err(format!("{} is not a regular file", path.display())));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = md.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(err(format!("{} is mode {mode:o}: chmod 600 it", path.display())));
            }
        }
        let raw = Zeroizing::new(std::fs::read(path).map_err(at)?);
        Self::parse(&raw).map_err(|e| err(format!("{}: {}", path.display(), e.msg)))
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new((&*self.0).into())
    }

    /// Seal one ch2 key (64 hex characters).
    pub fn seal(&self, secret_hex: &str) -> Result<Value> {
        let mut pt = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(secret_hex, &mut pt[..]).map_err(|_| err("a ch2 key is 64 hex characters"))?;
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|e| err(format!("OS randomness: {e}")))?;
        let ct = self.cipher().encrypt(Nonce::from_slice(&nonce), Payload { msg: &pt[..], aad: HUB_CH2_AAD.as_bytes() })
            .map_err(|_| err("seal failed"))?;
        Ok(json!({"v": 1, "alg": "aes-256-gcm", "kdf": "keyfile", "salt": "", "nonce": hex::encode(nonce), "ct": hex::encode(ct),
                  "aad": HUB_CH2_AAD}))
    }

    /// Open a sealed ch2 key: its 64 hex characters. Refused: another format, aad or kdf, a wrong
    /// wrap key, or a blob changed in any byte.
    pub fn open(&self, blob: &Value) -> Result<String> {
        let s = |k: &str| blob.get(k).and_then(Value::as_str).unwrap_or("");
        if blob.get("v").and_then(Value::as_u64) != Some(1) || s("alg") != "aes-256-gcm" || s("kdf") != "keyfile" {
            return Err(err("not a v1 aes-256-gcm keyfile blob"));
        }
        if s("aad") != HUB_CH2_AAD {
            return Err(err(format!("sealed blob is for {:?}, not {HUB_CH2_AAD:?}", s("aad"))));
        }
        let nonce = hex::decode(s("nonce")).ok().filter(|n| n.len() == 12).ok_or_else(|| err("nonce"))?;
        let ct = hex::decode(s("ct")).map_err(|_| err("ct"))?;
        let pt = Zeroizing::new(self.cipher().decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad: HUB_CH2_AAD.as_bytes() })
            .map_err(|_| err("a sealed ch2 key does not open: another wrap key, or the state file was changed"))?);
        if pt.len() != 32 {
            return Err(err("a sealed ch2 key is not 32 bytes"));
        }
        Ok(hex::encode(&pt[..]))
    }
}

/// A new file, 0600 from its first byte (O_EXCL).
fn create_new_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// Create or truncate `path`, 0600 (also when it existed with other bits).
pub(crate) fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let f = o.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(f)
}

/// fsync the directory holding `path`, so a create or rename in it is durable (a no-op off Unix).
pub(crate) fn sync_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        std::fs::File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: &str = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";

    #[test]
    fn seal_open_roundtrip_and_refusals() {
        let w = WrapKey::from_bytes([7; 32]);
        let b = w.seal(K).unwrap();
        assert_eq!((b["aad"].as_str(), b["kdf"].as_str(), b["salt"].as_str()), (Some(HUB_CH2_AAD), Some("keyfile"), Some("")));
        assert!(!b.to_string().contains(K));
        assert_eq!(w.open(&b).unwrap(), K);
        assert_ne!(w.seal(K).unwrap()["nonce"], b["nonce"], "a fresh nonce every seal");
        assert_eq!(WrapKey::from_bytes([8; 32]).open(&b).unwrap_err().code, "keystore");
        let mut t = b.clone();
        let ct = t["ct"].as_str().unwrap().to_string();
        t["ct"] = format!("{}{}", if ct.starts_with('0') { "1" } else { "0" }, &ct[1..]).into();
        assert_eq!(w.open(&t).unwrap_err().code, "keystore");
        let mut a = b.clone();
        a["aad"] = "xbt-signer/keys".into();
        assert!(w.open(&a).is_err());
        assert!(w.seal("zz").is_err());
    }

    #[test]
    fn parse_takes_raw_or_hex() {
        assert_eq!(WrapKey::parse(&[3; 32]).unwrap().0[..], [3; 32]);
        let h = format!("{}\n", hex::encode([4u8; 32]));
        assert_eq!(WrapKey::parse(h.as_bytes()).unwrap().0[..], [4; 32]);
        assert!(WrapKey::parse(b"short").is_err());
        assert_eq!(format!("{:?}", WrapKey::from_bytes([1; 32])), "WrapKey(..)");
    }

    #[cfg(unix)]
    #[test]
    fn a_wrap_key_file_is_made_0600_and_one_open_to_others_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("xbt402-wrapkey-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&d);
        let p = d.join(WRAP_KEY_FILE);
        let k1 = WrapKey::load_or_create(&p).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(WrapKey::load_or_create(&p).unwrap().0[..], k1.0[..], "the same key again");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(WrapKey::load_or_create(&p).unwrap_err().code, "keystore");
        std::fs::remove_file(&p).unwrap();
        std::fs::create_dir(&p).unwrap();
        assert!(WrapKey::load_or_create(&p).is_err(), "a directory");
        let _ = std::fs::remove_dir_all(&d);
    }
}
