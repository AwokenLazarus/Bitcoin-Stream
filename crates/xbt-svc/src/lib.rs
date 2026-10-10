//! xbt-svc: what makes an XBT service binary container-ready (AGP-038, cmp CONTRACT §U), shared by
//! `xbt-signer`, `xbt-anchor-witness`, `xbt-wallet-mcp` and `xbt402-hub`. std only, no async runtime.
//!
//! * [`DataDir`]: one relocatable data dir (`XBT_DATA_DIR`), one sub-dir per component, sockets under
//!   `run/<component>/`, the witness store on its own mount (`XBT_WITNESS_DIR`). See `docs/CONTAINER.md`.
//! * [`Secrets`]: a secret by name from an explicit file (`XBT_SECRET_<NAME>_FILE`), systemd's
//!   `$CREDENTIALS_DIRECTORY/<name>`, or `<component>/secrets/<name>` in the data dir (generated 0600
//!   on first run); a plain env value only in dev mode ([`Mode`]).
//! * [`health`]: node sync status, the readiness file of a socket-only service, freshness checks.
//! * [`proxy`]: base-path stripping and the public URL behind Umbrel `app_proxy`, StartOS and Tor.
//! * [`probe`]: a minimal HTTP GET for `healthcheck` subcommands (images have no shell or curl).
//! * [`http`]: the bounded HTTP/1.1 server every service listens with: header caps, head and body
//!   deadlines, a connection limit, a fixed worker pool (review T1; AGP-068, AGP-072).
//! * [`layout`]: the data dir's owners and modes, and `xbt-init`, which makes a bind mount or a
//!   root-owned volume match them (Umbrel, StartOS; AGP-040).
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub mod http;
pub mod layout;

/// A non-empty, trimmed environment variable.
pub fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// `1`, `true`, `yes`, `on` (any case) are true; anything else, or unset, is `default`.
pub fn env_bool(name: &str, default: bool) -> bool {
    match env(name) {
        Some(v) => matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        None => default,
    }
}

/// How strict secret handling is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Secrets only from files (explicit path, `$CREDENTIALS_DIRECTORY`, the data dir); plain env
    /// values holding a secret are refused. The images set `XBT_MODE=production`.
    Production,
    /// Also plain env values (`XBT_SECRET_<NAME>`, and the older `B2_HOT_PASSPHRASE`,
    /// `XBT_MCP_HTTP_TOKEN`): tests and the pre-AGP-038 bare-metal behaviour.
    Dev,
}

impl Mode {
    /// `XBT_MODE=production|dev`; unset: production when `XBT_DATA_DIR` is set, dev otherwise (so a
    /// bare-metal install configured the old way keeps working).
    pub fn from_env() -> Result<Self, String> {
        match env("XBT_MODE").map(|m| m.to_ascii_lowercase()).as_deref() {
            Some("production" | "prod") => Ok(Mode::Production),
            Some("dev" | "development" | "test") => Ok(Mode::Dev),
            Some(o) => Err(format!("XBT_MODE={o}: expected production or dev")),
            None => Ok(if env("XBT_DATA_DIR").is_some() { Mode::Production } else { Mode::Dev }),
        }
    }

    pub fn is_production(self) -> bool {
        self == Mode::Production
    }
}

pub const SIGNER: &str = "signer";
pub const WITNESS: &str = "witness";
pub const MCP: &str = "mcp";
pub const HUB: &str = "hub";
/// The wallet's web UI (AGP-039): its login hash, setup code and secrets.
pub const UI: &str = "ui";
/// The xbt-work blinded receipt relay (AGP-043): its blob store and push token.
pub const RELAY: &str = "relay";
/// The socket directory of the signer (`signer.sock`, `ready.json`) and of the witness (`anchor.sock`).
pub const RUN_SIGNER: &str = "signer";
pub const RUN_ANCHOR: &str = "anchor";
/// The UI's shared dir (AGP-042): `mcp-http-token`, which the UI writes and the MCP only reads (group).
pub const RUN_UI: &str = "ui";
/// The MCP bearer token's name, in `run/ui/` on a box (AGP-042) or `mcp/secrets/` without a UI.
pub const MCP_TOKEN: &str = "mcp-http-token";

/// The data dir: `$XBT_DATA_DIR/<component>/` for state, `$XBT_DATA_DIR/run/<component>/` for sockets
/// and readiness files (override `XBT_RUN_DIR`), the witness store at `$XBT_WITNESS_DIR` (default
/// `$XBT_DATA_DIR/witness`) so it can be another mount with another owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataDir {
    pub root: PathBuf,
}

impl DataDir {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// From `XBT_DATA_DIR`, or `None` when it is unset (the binary then keeps its older defaults).
    pub fn from_env() -> Option<Self> {
        env("XBT_DATA_DIR").map(Self::new)
    }

    /// A component's state directory (not created).
    pub fn component(&self, name: &str) -> PathBuf {
        if name == WITNESS {
            if let Some(w) = env("XBT_WITNESS_DIR") {
                return PathBuf::from(w);
            }
        }
        self.root.join(name)
    }

    /// The socket directory of `name` (not created).
    pub fn run(&self, name: &str) -> PathBuf {
        env("XBT_RUN_DIR").map(PathBuf::from).unwrap_or_else(|| self.root.join("run")).join(name)
    }

    /// The signer's socket.
    pub fn signer_sock(&self) -> PathBuf {
        self.run(RUN_SIGNER).join("signer.sock")
    }

    /// The signer's readiness file.
    pub fn signer_ready(&self) -> PathBuf {
        self.run(RUN_SIGNER).join("ready.json")
    }

    /// The anchor witness's socket.
    pub fn anchor_sock(&self) -> PathBuf {
        self.run(RUN_ANCHOR).join("anchor.sock")
    }

    /// The MCP bearer token the UI owns and the MCP reads (AGP-042): `run/ui/mcp-http-token`.
    pub fn mcp_token(&self) -> PathBuf {
        self.run(RUN_UI).join(MCP_TOKEN)
    }
}

/// Create `dir` (and its parents) if missing; a directory this call creates gets `mode`. An existing
/// one keeps the mode its operator chose.
pub fn ensure_dir(dir: &Path, mode: u32) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(dir)?;
    set_mode(dir, mode)
}

/// chmod on Unix; a no-op elsewhere.
pub fn set_mode(path: &Path, _mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(_mode))?;
    }
    Ok(())
}

/// The permission bits (0 where the platform has none).
pub fn mode_of(path: &Path) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        return std::fs::metadata(path).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
    }
    #[allow(unreachable_code)]
    {
        let _ = path;
        0
    }
}

/// Write `bytes` to `path` atomically: a 0600 temp file (created before any byte lands), fsync,
/// rename, then `mode`.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".tmp{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    {
        let mut f = open_private(&tmp, false)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    set_mode(path, mode)
}

/// Replace a secret file atomically (AGP-042: the rotated MCP token). A temp file with a random name
/// is created exclusively in the same directory, mode 0600 (never through a planted symlink), written
/// and fsynced; only then does it get `mode` (0600 or 0640, never a bit for others) and is renamed over
/// `path`, and the directory is fsynced. Readers see the old value or the new one, never a partial one,
/// and nobody outside the owner (and, with 0640, its group) can read it at any moment.
pub fn replace_secret_file(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    if mode & 0o137 != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("secret mode {mode:o}: at most 0640")));
    }
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = path.file_name().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let tmp = dir.join(format!(".{}.{}.tmp", name.to_string_lossy(), to_hex(&random_bytes(8))));
    let res = (|| {
        let mut f = open_private(&tmp, true)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(mode))?;
            f.sync_all()?;
        }
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

fn open_private(path: &Path, exclusive: bool) -> io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true);
    if exclusive {
        o.create_new(true);
    } else {
        o.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// OS randomness.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).expect("OS randomness");
    b
}

/// Lower-case hex.
pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Where a secret came from (never its value).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    /// `XBT_SECRET_<NAME>_FILE`: an explicit path (StartOS config, compose/Docker secrets).
    File(PathBuf),
    /// `$CREDENTIALS_DIRECTORY/<name>` (systemd `LoadCredential=`).
    Credentials(PathBuf),
    /// `<component>/secrets/<name>` in the data dir.
    DataDir(PathBuf),
    /// Generated just now into the data dir (first run).
    Generated(PathBuf),
    /// `XBT_SECRET_<NAME>` (dev mode only).
    Env(String),
}

impl Origin {
    /// The file behind the secret, if it has one.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Origin::File(p) | Origin::Credentials(p) | Origin::DataDir(p) | Origin::Generated(p) => Some(p),
            Origin::Env(_) => None,
        }
    }
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Origin::File(p) => write!(f, "file {}", p.display()),
            Origin::Credentials(p) => write!(f, "credential {}", p.display()),
            Origin::DataDir(p) => write!(f, "data dir {}", p.display()),
            Origin::Generated(p) => write!(f, "generated {}", p.display()),
            Origin::Env(n) => write!(f, "env {n}"),
        }
    }
}

/// A secret's bytes and origin. `Debug` never prints the bytes.
pub struct Secret {
    pub bytes: Vec<u8>,
    pub origin: Origin,
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret({} bytes from {})", self.bytes.len(), self.origin)
    }
}

impl Secret {
    /// The bytes as trimmed UTF-8 text (tokens, passphrases, `user:password`).
    pub fn text(&self) -> Result<String, String> {
        std::str::from_utf8(&self.bytes).map(|s| s.trim().to_string()).map_err(|_| format!("secret from {} is not UTF-8 text", self.origin))
    }
}

/// `node-rpc-auth` → `XBT_SECRET_NODE_RPC_AUTH`.
pub fn secret_env_name(name: &str) -> String {
    format!("XBT_SECRET_{}", name.to_ascii_uppercase().replace(['-', '.'], "_"))
}

/// A pluggable secret source: the same lookup order for every secret name.
///
/// 1. `XBT_SECRET_<NAME>_FILE`: an explicit path (StartOS writes config secrets to files; compose
///    and Docker secrets mount files);
/// 2. `$CREDENTIALS_DIRECTORY/<name>` (systemd `LoadCredential=`);
/// 3. `<dir>/<name>`, where `dir` is `XBT_SECRETS_DIR` or `$XBT_DATA_DIR/<component>/secrets`
///    (production refuses one readable by group or others);
/// 4. `XBT_SECRET_<NAME>` as a plain value: dev mode only; production refuses it.
#[derive(Clone, Debug)]
pub struct Secrets {
    pub dir: Option<PathBuf>,
    pub mode: Mode,
}

impl Secrets {
    pub fn new(dir: Option<PathBuf>, mode: Mode) -> Self {
        Self { dir, mode }
    }

    /// `XBT_SECRETS_DIR`, else `<data>/<component>/secrets` when there is a data dir.
    pub fn for_component(data: Option<&DataDir>, component: &str, mode: Mode) -> Self {
        let dir = env("XBT_SECRETS_DIR").map(PathBuf::from).or_else(|| data.map(|d| d.component(component).join("secrets")));
        Self::new(dir, mode)
    }

    /// Look `name` up; `Ok(None)` when no source has it.
    pub fn get(&self, name: &str) -> Result<Option<Secret>, String> {
        let var = secret_env_name(name);
        if std::env::var_os(&var).is_some() && self.mode.is_production() {
            return Err(format!("{var} holds a secret as a plain env value, refused in production mode: \
                                use {var}_FILE, $CREDENTIALS_DIRECTORY/{name} or the data dir (XBT_MODE=dev allows it for tests)"));
        }
        if let Some(p) = env(&format!("{var}_FILE")) {
            let p = PathBuf::from(p);
            return read(&p).map(|b| Some(Secret { bytes: b, origin: Origin::File(p) }));
        }
        if let Some(cd) = env("CREDENTIALS_DIRECTORY") {
            let p = Path::new(&cd).join(name);
            if p.exists() {
                return read(&p).map(|b| Some(Secret { bytes: b, origin: Origin::Credentials(p) }));
            }
        }
        if let Some(dir) = &self.dir {
            let p = dir.join(name);
            if p.exists() {
                self.check_private(&p)?;
                return read(&p).map(|b| Some(Secret { bytes: b, origin: Origin::DataDir(p) }));
            }
        }
        if let Some(v) = std::env::var_os(&var) {
            return Ok(Some(Secret { bytes: v.to_string_lossy().into_owned().into_bytes(), origin: Origin::Env(var) }));
        }
        Ok(None)
    }

    /// [`Self::get`], or on first run a new secret from `generate` written to the data dir: the
    /// directory 0700, the file 0600 and created exclusively (two processes racing both end up
    /// with the one that won).
    pub fn get_or_create(&self, name: &str, generate: impl FnOnce() -> Vec<u8>) -> Result<Secret, String> {
        if let Some(s) = self.get(name)? {
            return Ok(s);
        }
        let dir = self.dir.as_ref().ok_or_else(|| {
            format!("secret {name}: none found and nowhere to create one (set XBT_DATA_DIR, XBT_SECRETS_DIR or {}_FILE)", secret_env_name(name))
        })?;
        ensure_dir(dir, 0o700).map_err(|e| format!("{}: {e}", dir.display()))?;
        let p = dir.join(name);
        match open_private(&p, true) {
            Ok(mut f) => {
                let bytes = generate();
                f.write_all(&bytes).and_then(|_| f.sync_all()).map_err(|e| format!("{}: {e}", p.display()))?;
                if let Ok(d) = std::fs::File::open(dir) {
                    let _ = d.sync_all();
                }
                Ok(Secret { bytes, origin: Origin::Generated(p) })
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                read(&p).map(|b| Secret { bytes: b, origin: Origin::DataDir(p) })
            }
            Err(e) => Err(format!("{}: {e}", p.display())),
        }
    }

    fn check_private(&self, p: &Path) -> Result<(), String> {
        let m = mode_of(p);
        if self.mode.is_production() && cfg!(unix) && m & 0o077 != 0 {
            return Err(format!("{}: mode {m:o} lets group or others read a secret; chmod 600 it", p.display()));
        }
        Ok(())
    }
}

fn read(p: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))
}

pub mod health {
    //! Readiness: the node's sync status, and the readiness file a socket-only service writes.
    use std::path::Path;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use serde_json::{json, Value};

    pub fn now() -> f64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
    }

    /// A node's status from `getblockchaininfo`: reachable, synced (not in IBD and blocks =
    /// headers) and sync % (`verificationprogress`).
    pub fn node_status(info: Result<Value, String>) -> Value {
        match info {
            Err(e) => json!({"reachable": false, "synced": false, "sync_pct": 0.0, "error": e}),
            Ok(i) => {
                let blocks = i.get("blocks").and_then(Value::as_u64).unwrap_or(0);
                let headers = i.get("headers").and_then(Value::as_u64).unwrap_or(0);
                let ibd = i.get("initialblockdownload").and_then(Value::as_bool).unwrap_or(true);
                let pct = (i.get("verificationprogress").and_then(Value::as_f64).unwrap_or(0.0) * 10_000.0).round() / 100.0;
                json!({"reachable": true, "synced": !ibd && blocks >= headers, "sync_pct": pct, "blocks": blocks, "headers": headers,
                       "chain": i.get("chain").cloned().unwrap_or(Value::Null), "initialblockdownload": ibd})
            }
        }
    }

    /// Write a readiness document (`ts` added) atomically, mode 0640 (the group is the service's
    /// clients).
    pub fn write_ready(path: &Path, doc: &Value) -> std::io::Result<()> {
        let mut d = doc.clone();
        d["ts"] = json!(now());
        crate::write_atomic(path, format!("{d}\n").as_bytes(), 0o640)
    }

    /// Read a readiness document; an error when it is missing, unreadable or older than `max_age`
    /// (the writer is gone or wedged).
    pub fn read_ready(path: &Path, max_age: Duration) -> Result<Value, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let v: Value = serde_json::from_str(raw.trim()).map_err(|e| format!("{}: {e}", path.display()))?;
        let age = now() - v.get("ts").and_then(Value::as_f64).unwrap_or(0.0);
        if age > max_age.as_secs_f64() {
            return Err(format!("{}: stale ({age:.0}s old)", path.display()));
        }
        Ok(v)
    }
}

pub mod proxy {
    //! Serving behind Umbrel `app_proxy`, StartOS interfaces and Tor: a configurable base path, and
    //! the public URL from `XBT_PUBLIC_URL` or (when trusted) `X-Forwarded-*`, never a hard-coded
    //! self-URL.

    /// `""` for none, else `/a/b` (leading slash, no trailing one).
    pub fn normalize_base(base: &str) -> String {
        let b = base.trim().trim_matches('/');
        if b.is_empty() { String::new() } else { format!("/{b}") }
    }

    /// `path` (with any query) with the base path removed; `None` when it is outside the base.
    pub fn strip_base(path: &str, base: &str) -> Option<String> {
        let base = normalize_base(base);
        if base.is_empty() {
            return Some(path.to_string());
        }
        let rest = path.strip_prefix(&base)?;
        match rest.chars().next() {
            None => Some("/".into()),
            Some('/') => Some(rest.to_string()),
            Some('?') => Some(format!("/{rest}")),
            Some(_) => None,
        }
    }

    fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    fn first(v: &str) -> &str {
        v.split(',').next().unwrap_or("").trim()
    }

    fn clean_host(h: &str) -> Option<&str> {
        (!h.is_empty() && h.bytes().all(|b| b.is_ascii_alphanumeric() || b"-.:[]_".contains(&b))).then_some(h)
    }

    /// The absolute URL a client used for `path_q` (the path the service saw, base path included):
    /// `public_base` + the path below the base when configured; else, with `trust_forwarded`, the
    /// proxy's `X-Forwarded-Proto`/`-Host`/`-Prefix`; else `http://<Host>`.
    pub fn public_url(headers: &[(String, String)], path_q: &str, base: &str, public_base: Option<&str>, trust_forwarded: bool) -> String {
        let below = strip_base(path_q, base).unwrap_or_else(|| path_q.to_string());
        if let Some(pb) = public_base {
            return format!("{}{below}", pb.trim_end_matches('/'));
        }
        let host = header(headers, "Host").and_then(clean_host).unwrap_or("localhost");
        if trust_forwarded {
            let proto = header(headers, "X-Forwarded-Proto").map(first).filter(|p| matches!(*p, "http" | "https")).unwrap_or("http");
            let fhost = header(headers, "X-Forwarded-Host").map(first).and_then(clean_host).unwrap_or(host);
            let prefix = header(headers, "X-Forwarded-Prefix").map(first).map(normalize_base).unwrap_or_default();
            return format!("{proto}://{fhost}{prefix}{path_q}");
        }
        format!("http://{host}{path_q}")
    }
}

pub mod probe {
    //! A minimal HTTP/1.0 GET for the images' `healthcheck` subcommands.
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    /// The address to probe a listener bound to `bind` from inside its own container: a wildcard
    /// host becomes loopback.
    pub fn local_addr(bind: &str) -> String {
        match bind.rsplit_once(':') {
            Some(("0.0.0.0" | "" | "*", port)) => format!("127.0.0.1:{port}"),
            Some(("[::]", port)) => format!("[::1]:{port}"),
            _ => bind.to_string(),
        }
    }

    /// `GET path` on `addr`: the status code and the body.
    pub fn get(addr: &str, path: &str, timeout: Duration) -> Result<(u16, String), String> {
        let sa = addr.to_socket_addrs().map_err(|e| format!("{addr}: {e}"))?.next().ok_or_else(|| format!("{addr}: no address"))?;
        let mut s = TcpStream::connect_timeout(&sa, timeout).map_err(|e| format!("{addr}: {e}"))?;
        let _ = s.set_read_timeout(Some(timeout));
        let _ = s.set_write_timeout(Some(timeout));
        write!(s, "GET {path} HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n").map_err(|e| format!("{addr}: {e}"))?;
        let mut buf = Vec::new();
        s.take(1 << 20).read_to_end(&mut buf).map_err(|e| format!("{addr}: {e}"))?;
        let text = String::from_utf8_lossy(&buf);
        let status = text.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or_else(|| format!("{addr}: not HTTP"))?;
        let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
        Ok((status, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // the tests below change the process environment
    static ENV: Mutex<()> = Mutex::new(());

    fn clear() {
        for k in ["XBT_MODE", "XBT_DATA_DIR", "XBT_SECRETS_DIR", "CREDENTIALS_DIRECTORY", "XBT_SECRET_T_ONE", "XBT_SECRET_T_ONE_FILE",
                  "XBT_WITNESS_DIR", "XBT_RUN_DIR"] {
            std::env::remove_var(k);
        }
    }

    #[test]
    fn lookup_order_and_production_refusals() {
        let _g = ENV.lock().unwrap_or_else(|p| p.into_inner());
        clear();
        let d = tempfile::tempdir().unwrap();
        let data = DataDir::new(d.path());
        let s = Secrets::for_component(Some(&data), SIGNER, Mode::Production);
        assert_eq!(s.dir.as_deref(), Some(d.path().join("signer/secrets").as_path()));
        assert!(s.get("t-one").unwrap().is_none());
        // first run: generated, 0600 in a 0700 dir, then read back unchanged
        let g = s.get_or_create("t-one", || b"abc".to_vec()).unwrap();
        assert!(matches!(g.origin, Origin::Generated(_)));
        let p = d.path().join("signer/secrets/t-one");
        #[cfg(unix)]
        {
            assert_eq!(mode_of(&p), 0o600);
            assert_eq!(mode_of(&d.path().join("signer/secrets")), 0o700);
        }
        let again = s.get_or_create("t-one", || b"zzz".to_vec()).unwrap();
        assert_eq!((again.bytes.as_slice(), &again.origin), (b"abc".as_slice(), &Origin::DataDir(p.clone())));
        // a group-readable secret file is refused in production, read in dev
        #[cfg(unix)]
        {
            set_mode(&p, 0o640).unwrap();
            assert!(s.get("t-one").unwrap_err().contains("chmod 600"));
            assert!(Secrets::new(s.dir.clone(), Mode::Dev).get("t-one").unwrap().is_some());
            set_mode(&p, 0o600).unwrap();
        }
        // $CREDENTIALS_DIRECTORY beats the data dir; an explicit _FILE beats both
        let cd = tempfile::tempdir().unwrap();
        std::fs::write(cd.path().join("t-one"), b"cred").unwrap();
        std::env::set_var("CREDENTIALS_DIRECTORY", cd.path());
        let c = s.get("t-one").unwrap().unwrap();
        assert_eq!((c.bytes.as_slice(), matches!(c.origin, Origin::Credentials(_))), (b"cred".as_slice(), true));
        let f = d.path().join("explicit");
        std::fs::write(&f, b"file\n").unwrap();
        std::env::set_var("XBT_SECRET_T_ONE_FILE", &f);
        assert_eq!(s.get("t-one").unwrap().unwrap().text().unwrap(), "file");
        // a plain env value: refused in production even with files around, used in dev
        std::env::set_var("XBT_SECRET_T_ONE", "plain");
        assert!(s.get("t-one").unwrap_err().contains("refused in production"));
        std::env::remove_var("XBT_SECRET_T_ONE_FILE");
        std::env::remove_var("CREDENTIALS_DIRECTORY");
        std::fs::remove_file(&p).unwrap();
        let dev = Secrets::new(s.dir.clone(), Mode::Dev);
        assert_eq!(dev.get("t-one").unwrap().unwrap().origin, Origin::Env("XBT_SECRET_T_ONE".into()));
        assert!(format!("{:?}", dev.get("t-one").unwrap().unwrap()).contains("5 bytes"));
        clear();
        assert!(Secrets::new(None, Mode::Production).get_or_create("t-one", Vec::new).unwrap_err().contains("nowhere to create"));
    }

    #[test]
    fn mode_and_layout() {
        let _g = ENV.lock().unwrap_or_else(|p| p.into_inner());
        clear();
        assert_eq!(Mode::from_env().unwrap(), Mode::Dev);
        std::env::set_var("XBT_DATA_DIR", "/data");
        assert_eq!(Mode::from_env().unwrap(), Mode::Production);
        std::env::set_var("XBT_MODE", "dev");
        assert_eq!(Mode::from_env().unwrap(), Mode::Dev);
        std::env::set_var("XBT_MODE", "nope");
        assert!(Mode::from_env().is_err());
        let d = DataDir::from_env().unwrap();
        assert_eq!(d.component(SIGNER), PathBuf::from("/data/signer"));
        assert_eq!(d.component(WITNESS), PathBuf::from("/data/witness"));
        assert_eq!(d.signer_sock(), PathBuf::from("/data/run/signer/signer.sock"));
        assert_eq!(d.anchor_sock(), PathBuf::from("/data/run/anchor/anchor.sock"));
        std::env::set_var("XBT_WITNESS_DIR", "/witness");
        std::env::set_var("XBT_RUN_DIR", "/run/xbt");
        assert_eq!(d.component(WITNESS), PathBuf::from("/witness"));
        assert_eq!(d.signer_ready(), PathBuf::from("/run/xbt/signer/ready.json"));
        clear();
    }

    #[test]
    fn proxy_urls() {
        use proxy::*;
        assert_eq!(normalize_base("/app/"), "/app");
        assert_eq!(normalize_base("/"), "");
        assert_eq!(strip_base("/app/mcp", "/app").as_deref(), Some("/mcp"));
        assert_eq!(strip_base("/app", "/app/").as_deref(), Some("/"));
        assert_eq!(strip_base("/app?x=1", "app").as_deref(), Some("/?x=1"));
        assert_eq!(strip_base("/apple", "/app"), None);
        assert_eq!(strip_base("/mcp", ""), Some("/mcp".into()));
        let h = |v: &[(&str, &str)]| v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect::<Vec<_>>();
        let onion = h(&[("Host", "abc.onion"), ("X-Forwarded-Proto", "https, http"), ("X-Forwarded-Host", "pay.example"),
                        ("X-Forwarded-Prefix", "/hub/")]);
        assert_eq!(proxy::public_url(&onion, "/v1/x?q", "", None, false), "http://abc.onion/v1/x?q");
        assert_eq!(proxy::public_url(&onion, "/v1/x?q", "", None, true), "https://pay.example/hub/v1/x?q");
        assert_eq!(proxy::public_url(&onion, "/b/v1/x", "/b", Some("http://x.onion/"), true), "http://x.onion/v1/x");
        assert_eq!(proxy::public_url(&h(&[("Host", "evil host/")]), "/p", "", None, false), "http://localhost/p");
    }

    #[test]
    fn readiness_file_freshness() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ready.json");
        health::write_ready(&p, &serde_json::json!({"ok": true})).unwrap();
        assert_eq!(health::read_ready(&p, std::time::Duration::from_secs(5)).unwrap()["ok"], true);
        #[cfg(unix)]
        assert_eq!(mode_of(&p), 0o640);
        std::fs::write(&p, r#"{"ok": true, "ts": 1}"#).unwrap();
        assert!(health::read_ready(&p, std::time::Duration::from_secs(5)).unwrap_err().contains("stale"));
        let st = health::node_status(Ok(serde_json::json!({"blocks": 5, "headers": 5, "initialblockdownload": false,
                                                           "verificationprogress": 0.9999, "chain": "regtest"})));
        assert_eq!((st["synced"].clone(), st["sync_pct"].clone()), (serde_json::json!(true), serde_json::json!(99.99)));
        assert_eq!(health::node_status(Err("down".into()))["reachable"], false);
        assert_eq!(probe::local_addr("0.0.0.0:80"), "127.0.0.1:80");
        assert_eq!(probe::local_addr("[::]:80"), "[::1]:80");
    }

    /// AGP-042: the rotated MCP token is replaced atomically and is never readable by others.
    #[cfg(unix)]
    #[test]
    fn replace_secret_file_is_atomic_and_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        let p = d.path().join(MCP_TOKEN);
        // the temp file is 0600 from its creation, before a byte is written (umask cannot widen it)
        let t = d.path().join("t");
        let f = open_private(&t, true).unwrap();
        assert_eq!(f.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        drop(f);
        assert!(open_private(&t, true).is_err(), "exclusive: an existing (or planted) temp path is refused");
        std::fs::remove_file(&t).unwrap();
        replace_secret_file(&p, b"old", 0o640).unwrap();
        assert_eq!(mode_of(&p), 0o640);
        // a reader holding the old file keeps reading the old inode; the path flips to the new value
        let held = std::fs::File::open(&p).unwrap();
        replace_secret_file(&p, b"new", 0o600).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"new");
        assert_eq!(mode_of(&p), 0o600);
        assert_eq!(std::io::read_to_string(held).unwrap(), "old");
        let left: Vec<_> = std::fs::read_dir(d.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(left, vec![std::ffi::OsString::from(MCP_TOKEN)], "no temp file left behind");
        for bad in [0o644, 0o604, 0o660, 0o700] {
            assert!(replace_secret_file(&p, b"x", bad).is_err(), "{bad:o}");
        }
        assert_eq!(std::fs::read(&p).unwrap(), b"new");
        // a symlink at the target is replaced, not followed
        let victim = d.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        replace_secret_file(&link, b"tok", 0o640).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_file());
    }
}
