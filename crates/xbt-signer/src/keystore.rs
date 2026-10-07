//! At-rest encryption for the signer's keys (B2 `keystore.py`, AGP-013), format-compatible.
//!
//! The hot key (`hot.json`), the per-channel payer keys (`channel_keys.json`) and the hot UTXO set
//! are sealed with AES-256-GCM. The 32-byte wrapping key comes from the signer's environment only:
//!
//! * `B2_HOT_KEYFILE=/path` — 32 random bytes (raw or 64 hex chars), created 0600 if missing, refused
//!   inside the signer's run directory;
//! * `B2_HOT_PASSPHRASE=...` — scrypt(N=2^15, r=8, p=1) with a per-blob salt; removed from the
//!   environment once read.
//!
//! A sealed blob is `{"v":1,"alg":"aes-256-gcm","kdf":"keyfile"|"scrypt","salt","nonce","ct","aad"}`
//! (hex fields; `ct` includes the 16-byte tag), exactly as B2 writes it, so either signer opens
//! the other's files.
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde_json::{json, Value};

use crate::{err, Result};

pub const ENV_KEYFILE: &str = "B2_HOT_KEYFILE";
pub const ENV_PASSPHRASE: &str = "B2_HOT_PASSPHRASE";
pub const ENV_ALLOW_PLAINTEXT: &str = "B2_HOT_ALLOW_PLAINTEXT";
const SCRYPT_LOG_N: u8 = 15;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

/// OS randomness.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS randomness");
    b
}

enum Source {
    Key([u8; 32]),
    Passphrase(Vec<u8>),
}

/// Seals and opens small secrets.
pub struct KeyStore {
    src: Source,
    kdf_cache: Mutex<HashMap<Vec<u8>, [u8; 32]>>,
}

impl std::fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyStore({})", self.kind())
    }
}

impl KeyStore {
    pub fn with_key(key: [u8; 32]) -> Self {
        Self { src: Source::Key(key), kdf_cache: Mutex::new(HashMap::new()) }
    }

    pub fn with_passphrase(pw: &[u8]) -> Self {
        Self { src: Source::Passphrase(pw.to_vec()), kdf_cache: Mutex::new(HashMap::new()) }
    }

    /// "keyfile" or "scrypt" (the blob's `kdf`).
    pub fn kind(&self) -> &'static str {
        match self.src {
            Source::Key(_) => "keyfile",
            Source::Passphrase(_) => "scrypt",
        }
    }

    /// The signer's key source from the environment, or `None` when it names none. The
    /// passphrase is removed from the environment once read (`pop`).
    pub fn from_env(run_dir: Option<&Path>, pop: bool) -> Result<Option<Self>> {
        let pw = std::env::var(ENV_PASSPHRASE).ok().filter(|p| !p.is_empty());
        if pop && pw.is_some() {
            std::env::remove_var(ENV_PASSPHRASE);
        }
        let path = std::env::var(ENV_KEYFILE).unwrap_or_default().trim().to_string();
        if pw.is_some() && !path.is_empty() {
            return Err(err("keystore", format!("set only one of {ENV_KEYFILE} / {ENV_PASSPHRASE}")));
        }
        if let Some(pw) = pw {
            return Ok(Some(Self::with_passphrase(pw.as_bytes())));
        }
        if !path.is_empty() {
            return Ok(Some(Self::with_key(load_or_create_keyfile(Path::new(&path), run_dir)?)));
        }
        Ok(None)
    }

    /// The wrapping secret itself (the 32-byte key, or the passphrase): only for the human-signed
    /// backup export (AGP-039), which seals it under the backup passphrase before it leaves.
    pub(crate) fn wrapping_secret(&self) -> Vec<u8> {
        match &self.src {
            Source::Key(k) => k.to_vec(),
            Source::Passphrase(pw) => pw.clone(),
        }
    }

    pub fn plaintext_allowed() -> bool {
        std::env::var(ENV_ALLOW_PLAINTEXT).map(|v| v == "1").unwrap_or(false)
    }

    fn wrap_key(&self, salt: &[u8]) -> Result<[u8; 32]> {
        match &self.src {
            Source::Key(k) => Ok(*k),
            Source::Passphrase(pw) => {
                let mut cache = self.kdf_cache.lock().map_err(|_| err("keystore", "poisoned"))?;
                if let Some(k) = cache.get(salt) {
                    return Ok(*k);
                }
                let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 32).map_err(|e| err("keystore", e.to_string()))?;
                let mut out = [0u8; 32];
                scrypt::scrypt(pw, salt, &params, &mut out).map_err(|e| err("keystore", e.to_string()))?;
                cache.insert(salt.to_vec(), out);
                Ok(out)
            }
        }
    }

    /// Seal `plaintext` under `aad`. `salt` lets a file that is re-sealed often (the hot UTXO
    /// set) reuse one scrypt derivation; every seal still gets a fresh random nonce.
    pub fn seal(&self, plaintext: &[u8], aad: &str, salt: Option<&[u8]>) -> Result<Value> {
        let salt = salt.map(<[u8]>::to_vec).unwrap_or_else(|| random_bytes::<16>().to_vec());
        let nonce = random_bytes::<12>();
        let cipher = Aes256Gcm::new_from_slice(&self.wrap_key(&salt)?).map_err(|_| err("keystore", "key length"))?;
        let ct = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: aad.as_bytes() })
            .map_err(|_| err("keystore", "encryption failed"))?;
        Ok(json!({"v": 1, "alg": "aes-256-gcm", "kdf": self.kind(), "salt": hex::encode(&salt), "nonce": hex::encode(nonce),
                  "ct": hex::encode(ct), "aad": aad}))
    }

    /// Open a sealed blob; refuses another format, another `aad`, another kdf, a wrong key or a
    /// tampered blob.
    pub fn open(&self, blob: &Value, aad: &str) -> Result<Vec<u8>> {
        if blob.get("v").and_then(Value::as_i64) != Some(1) || blob.get("alg").and_then(Value::as_str) != Some("aes-256-gcm") {
            return Err(err("keystore", "unknown sealed-key format"));
        }
        let got_aad = blob.get("aad").and_then(Value::as_str).unwrap_or("");
        if got_aad != aad {
            return Err(err("keystore", format!("sealed blob is for {got_aad:?}, not {aad:?}")));
        }
        let kdf = blob.get("kdf").and_then(Value::as_str).unwrap_or("");
        if kdf != self.kind() {
            return Err(err("keystore", format!("key sealed with {kdf}, signer has a {}", self.kind())));
        }
        let h = |k: &str| blob.get(k).and_then(Value::as_str).and_then(|x| hex::decode(x).ok());
        let (salt, nonce, ct) = match (h("salt"), h("nonce"), h("ct")) {
            (Some(s), Some(n), Some(c)) if n.len() == 12 => (s, n, c),
            _ => return Err(err("keystore", "cannot open sealed key: wrong wrapping key or tampered file")),
        };
        let cipher = Aes256Gcm::new_from_slice(&self.wrap_key(&salt)?).map_err(|_| err("keystore", "key length"))?;
        cipher.decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad: aad.as_bytes() })
            .map_err(|_| err("keystore", "cannot open sealed key: wrong wrapping key or tampered file"))
    }
}

/// The 32-byte wrapping key in `path` (raw or hex), created 0600 (O_EXCL) if missing. Refused
/// inside the signer's run directory.
pub fn load_or_create_keyfile(path: &Path, run_dir: Option<&Path>) -> Result<[u8; 32]> {
    let path = absolute(&expand_home(path));
    if let Some(rd) = run_dir {
        let rd = absolute(rd);
        if path == rd || path.starts_with(&rd) {
            return Err(err("keystore", format!("{ENV_KEYFILE} must not live inside the signer run dir {}", rd.display())));
        }
    }
    if !path.exists() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| err("keystore", e.to_string()))?;
        }
        let mut f = crate::fsx::create_new(&path, 0o600)
            .map_err(|e| err("keystore", format!("{}: {e}", path.display())))?;
        f.write_all(&random_bytes::<32>()).map_err(|e| err("keystore", e.to_string()))?;
        f.sync_all().ok();
    }
    let raw = fs::read(&path).map_err(|e| err("keystore", format!("{}: {e}", path.display())))?;
    if raw.len() == 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(&raw);
        return Ok(k);
    }
    let txt = String::from_utf8_lossy(&raw).trim().to_string();
    match hex::decode(&txt) {
        Ok(k) if k.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&k);
            Ok(out)
        }
        _ => Err(err("keystore", format!("{ENV_KEYFILE} must hold 32 bytes (raw or 64 hex chars)"))),
    }
}

fn expand_home(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(h) = std::env::var("HOME") {
            return Path::new(&h).join(rest);
        }
    }
    p.to_path_buf()
}

/// An absolute, symlink-resolved path (the parent is resolved when the file does not exist yet).
pub fn absolute(p: &Path) -> PathBuf {
    if let Ok(c) = fs::canonicalize(p) {
        return c;
    }
    let base = if p.is_absolute() { p.to_path_buf() } else { std::env::current_dir().unwrap_or_default().join(p) };
    match (base.parent(), base.file_name()) {
        (Some(parent), Some(name)) => fs::canonicalize(parent).map(|c| c.join(name)).unwrap_or(base.clone()),
        _ => base,
    }
}

/// Atomic 0600 write: the temp file is 0600 before any byte lands, fsynced, then renamed.
pub fn write_private(path: &Path, text: &str) -> Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut f = crate::fsx::create_truncate(&tmp, 0o600)
            .map_err(|e| err("io", format!("{}: {e}", tmp.display())))?;
        f.write_all(text.as_bytes()).map_err(|e| err("io", e.to_string()))?;
        f.sync_all().map_err(|e| err("io", e.to_string()))?;
    }
    fs::rename(&tmp, path).map_err(|e| err("io", format!("{}: {e}", path.display())))?;
    crate::fsx::set_mode(path, 0o600).map_err(|e| err("io", e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_and_refusals() {
        let ks = KeyStore::with_key([7u8; 32]);
        let blob = ks.seal(b"secret", "b2/hot-key", None).unwrap();
        assert_eq!(ks.open(&blob, "b2/hot-key").unwrap(), b"secret");
        assert!(ks.open(&blob, "b2/channel-keys").is_err());
        assert!(KeyStore::with_key([8u8; 32]).open(&blob, "b2/hot-key").is_err());
        let mut bad = blob.clone();
        let ct = bad["ct"].as_str().unwrap().to_string();
        bad["ct"] = format!("{}{}", if &ct[..1] == "0" { "1" } else { "0" }, &ct[1..]).into();
        assert!(ks.open(&bad, "b2/hot-key").is_err());
        assert!(KeyStore::with_passphrase(b"pw").open(&blob, "b2/hot-key").unwrap_err().msg.contains("sealed with keyfile"));
    }

    #[test]
    fn passphrase_seal() {
        let ks = KeyStore::with_passphrase(b"correct horse");
        let blob = ks.seal(b"x", "a", None).unwrap();
        assert_eq!(blob["kdf"], "scrypt");
        assert_eq!(KeyStore::with_passphrase(b"correct horse").open(&blob, "a").unwrap(), b"x");
        assert!(KeyStore::with_passphrase(b"wrong").open(&blob, "a").is_err());
    }
}
