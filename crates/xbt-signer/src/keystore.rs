//! At-rest encryption for the signer's keys (B2 `keystore.py`, AGP-013), format-compatible.
//!
//! The hot key (`hot.json`), the per-channel payer keys (`channel_keys.json`) and the hot UTXO set
//! are sealed with AES-256-GCM. The 32-byte wrapping key comes from the signer's environment only:
//!
//! * `B2_HOT_KEYFILE=/path` — 32 random bytes (raw or 64 hex chars), created 0600 if missing, refused
//!   inside the signer's run directory;
//! * `B2_HOT_PASSPHRASE=...` — scrypt(N=2^17, r=8, p=1) with a per-blob salt; removed from the
//!   environment once read. AGP-063 K1: the blob records `log_n`; one without it is an older
//!   blob at N=2^15, opened as before and re-sealed at 2^17 on its next write.
//!
//! A sealed blob is `{"v":1,"alg":"aes-256-gcm","kdf":"keyfile"|"scrypt","salt","nonce","ct","aad"}`
//! plus `"log_n"` for scrypt (hex fields; `ct` includes the 16-byte tag), exactly as B2 writes it,
//! so either signer opens the other's files. Secrets are zeroized when the store drops.
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::{err, Result};

pub const ENV_KEYFILE: &str = "B2_HOT_KEYFILE";
pub const ENV_PASSPHRASE: &str = "B2_HOT_PASSPHRASE";
pub const ENV_ALLOW_PLAINTEXT: &str = "B2_HOT_ALLOW_PLAINTEXT";
/// New seals (AGP-063 K1: 170 ms on the build host, about 1 s on armv7, 128 MiB). A blob may name
/// 15..=SCRYPT_LOG_N_MAX; a larger one is refused (it would allocate 128 * 8 * 2^log_n bytes).
pub const SCRYPT_LOG_N: u8 = 17;
const SCRYPT_LOG_N_LEGACY: u8 = 15;
const SCRYPT_LOG_N_MAX: u8 = 18;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

/// OS randomness.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS randomness");
    b
}

enum Source {
    Key(Zeroizing<[u8; 32]>),
    Passphrase(Zeroizing<Vec<u8>>),
}

/// Derived wrapping keys by (scrypt log_n, salt).
type KdfCache = HashMap<(u8, Vec<u8>), Zeroizing<[u8; 32]>>;

/// Seals and opens small secrets.
pub struct KeyStore {
    src: Source,
    kdf_cache: Mutex<KdfCache>,
}

impl std::fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyStore({})", self.kind())
    }
}

impl KeyStore {
    pub fn with_key(key: [u8; 32]) -> Self {
        Self { src: Source::Key(Zeroizing::new(key)), kdf_cache: Mutex::new(HashMap::new()) }
    }

    pub fn with_passphrase(pw: &[u8]) -> Self {
        Self { src: Source::Passphrase(Zeroizing::new(pw.to_vec())), kdf_cache: Mutex::new(HashMap::new()) }
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
        let pw = std::env::var(ENV_PASSPHRASE).ok().filter(|p| !p.is_empty()).map(Zeroizing::new);
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
    pub(crate) fn wrapping_secret(&self) -> Zeroizing<Vec<u8>> {
        match &self.src {
            Source::Key(k) => Zeroizing::new(k.to_vec()),
            Source::Passphrase(pw) => pw.clone(),
        }
    }

    pub fn plaintext_allowed() -> bool {
        std::env::var(ENV_ALLOW_PLAINTEXT).map(|v| v == "1").unwrap_or(false)
    }

    fn wrap_key(&self, salt: &[u8], log_n: u8) -> Result<Zeroizing<[u8; 32]>> {
        match &self.src {
            Source::Key(k) => Ok(k.clone()),
            Source::Passphrase(pw) => {
                let mut cache = self.kdf_cache.lock().map_err(|_| err("keystore", "poisoned"))?;
                if let Some(k) = cache.get(&(log_n, salt.to_vec())) {
                    return Ok(k.clone());
                }
                let params = scrypt::Params::new(log_n, SCRYPT_R, SCRYPT_P, 32).map_err(|e| err("keystore", e.to_string()))?;
                let mut out = Zeroizing::new([0u8; 32]);
                scrypt::scrypt(pw, salt, &params, &mut *out).map_err(|e| err("keystore", e.to_string()))?;
                cache.insert((log_n, salt.to_vec()), out.clone());
                Ok(out)
            }
        }
    }

    /// Seal `plaintext` under `aad`. `salt` lets a file that is re-sealed often (the hot UTXO
    /// set) reuse one scrypt derivation; every seal still gets a fresh random nonce.
    pub fn seal(&self, plaintext: &[u8], aad: &str, salt: Option<&[u8]>) -> Result<Value> {
        let salt = salt.map(<[u8]>::to_vec).unwrap_or_else(|| random_bytes::<16>().to_vec());
        let nonce = random_bytes::<12>();
        let cipher = Aes256Gcm::new_from_slice(&*self.wrap_key(&salt, SCRYPT_LOG_N)?).map_err(|_| err("keystore", "key length"))?;
        let ct = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: aad.as_bytes() })
            .map_err(|_| err("keystore", "encryption failed"))?;
        let mut blob = json!({"v": 1, "alg": "aes-256-gcm", "kdf": self.kind(), "salt": hex::encode(&salt), "nonce": hex::encode(nonce),
                              "ct": hex::encode(ct), "aad": aad});
        if matches!(self.src, Source::Passphrase(_)) {
            blob["log_n"] = SCRYPT_LOG_N.into();
        }
        Ok(blob)
    }

    /// Open a sealed blob; refuses another format, another `aad`, another kdf, a wrong key or a
    /// tampered blob.
    /// The plaintext is wiped when the caller drops it (AGP-080 K1).
    pub fn open(&self, blob: &Value, aad: &str) -> Result<Zeroizing<Vec<u8>>> {
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
        let log_n = match blob.get("log_n") {
            None => SCRYPT_LOG_N_LEGACY,
            Some(v) => v.as_u64().filter(|n| (SCRYPT_LOG_N_LEGACY as u64..=SCRYPT_LOG_N_MAX as u64).contains(n))
                .ok_or_else(|| err("keystore", format!("sealed blob log_n must be {SCRYPT_LOG_N_LEGACY}..={SCRYPT_LOG_N_MAX}")))? as u8,
        };
        let cipher = Aes256Gcm::new_from_slice(&*self.wrap_key(&salt, log_n)?).map_err(|_| err("keystore", "key length"))?;
        cipher.decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad: aad.as_bytes() }).map(Zeroizing::new)
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
    check_keyfile(&path)?;
    let raw = Zeroizing::new(fs::read(&path).map_err(|e| err("keystore", format!("{}: {e}", path.display())))?);
    if raw.len() == 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(&raw);
        return Ok(k);
    }
    let txt = Zeroizing::new(String::from_utf8_lossy(&raw).trim().to_string());
    match hex::decode(&*txt).map(Zeroizing::new) {
        Ok(k) if k.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&k);
            Ok(out)
        }
        _ => Err(err("keystore", format!("{ENV_KEYFILE} must hold 32 bytes (raw or 64 hex chars)"))),
    }
}

/// AGP-063 K1: the keyfile (its path already resolved by `absolute`) must be a regular file with
/// no bits for group or others, as the signer creates it.
fn check_keyfile(path: &Path) -> Result<()> {
    let md = fs::metadata(path).map_err(|e| err("keystore", format!("{}: {e}", path.display())))?;
    if !md.file_type().is_file() {
        return Err(err("keystore", format!("{ENV_KEYFILE} {} is not a regular file", path.display())));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = md.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(err("keystore", format!("{ENV_KEYFILE} {} is mode {mode:o}: chmod 600 it", path.display())));
        }
    }
    Ok(())
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

/// Atomic, durable 0600 write: the temp file is 0600 before any byte lands, fsynced, renamed, and
/// the directory fsynced (AGP-055: the rename itself must be durable before the caller goes on, since
/// a lock is written ahead of its pre-signature; without it the rename waits for the next journal commit).
pub fn write_private(path: &Path, text: &str) -> Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut f = crate::fsx::create_truncate(&tmp, 0o600)
            .map_err(|e| err("io", format!("{}: {e}", tmp.display())))?;
        crate::fsx::write_all(&mut f, text.as_bytes()).map_err(|e| err("io", e.to_string()))?;
        crate::fsx::sync(&f).map_err(|e| err("io", e.to_string()))?;
    }
    crate::fsx::rename(&tmp, path).map_err(|e| err("io", format!("{}: {e}", path.display())))?;
    crate::fsx::sync_dir(crate::fsx::parent_of(path)).map_err(|e| err("io", format!("{}: {e}", path.display())))?;
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
        assert_eq!(ks.open(&blob, "b2/hot-key").unwrap().as_slice(), b"secret");
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
        assert_eq!(KeyStore::with_passphrase(b"correct horse").open(&blob, "a").unwrap().as_slice(), b"x");
        assert!(KeyStore::with_passphrase(b"wrong").open(&blob, "a").is_err());
    }

    /// AGP-063 K1: new passphrase blobs record scrypt N=2^17; a blob without `log_n` (B2 and
    /// pre-AGP-063 Rust) still opens at 2^15; a `log_n` outside 15..=18 is refused before any work.
    #[test]
    fn k1_scrypt_cost_is_recorded_per_blob() {
        let ks = KeyStore::with_passphrase(b"pw");
        let blob = ks.seal(b"x", "a", None).unwrap();
        assert_eq!(blob["log_n"], SCRYPT_LOG_N as u64);
        assert_eq!(SCRYPT_LOG_N, 17);
        let mut legacy = blob.clone();
        legacy.as_object_mut().unwrap().remove("log_n");
        assert!(KeyStore::with_passphrase(b"pw").open(&legacy, "a").is_err(), "a 2^17 blob read as 2^15 must not open");
        let salt = hex::decode(blob["salt"].as_str().unwrap()).unwrap();
        let k15 = ks.wrap_key(&salt, SCRYPT_LOG_N_LEGACY).unwrap();
        let old = KeyStore::with_key(*k15).seal(b"old", "a", Some(&salt)).unwrap();
        let mut old = old;
        old["kdf"] = "scrypt".into();
        assert_eq!(KeyStore::with_passphrase(b"pw").open(&old, "a").unwrap().as_slice(), b"old");
        for bad in [14u64, 19, 30, 255] {
            let mut b = blob.clone();
            b["log_n"] = bad.into();
            assert!(KeyStore::with_passphrase(b"pw").open(&b, "a").unwrap_err().msg.contains("log_n"));
        }
        assert!(KeyStore::with_key([1; 32]).seal(b"x", "a", None).unwrap().get("log_n").is_none());
    }

    /// AGP-063 K1: a keyfile readable by group or others, or one that is not a regular file, is
    /// refused, also through a symlink (the path is resolved first).
    #[cfg(unix)]
    #[test]
    fn k1_a_keyfile_open_to_others_or_a_symlink_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("k/hot.key");
        let k = load_or_create_keyfile(&p, None).unwrap();
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(load_or_create_keyfile(&p, None).unwrap(), k);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_or_create_keyfile(&p, None).unwrap_err().msg.contains("mode 644"));
        fs::set_permissions(&p, fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(load_or_create_keyfile(&p, None).unwrap(), k);
        let link = d.path().join("link.key");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert_eq!(load_or_create_keyfile(&link, None).unwrap(), k);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_or_create_keyfile(&link, None).unwrap_err().msg.contains("mode 640"));
        assert!(load_or_create_keyfile(d.path(), None).unwrap_err().msg.contains("not a regular file"));
    }
}
