//! The xbt-work blinded receipt relay (spec §11.1), server side: a keyless store of sealed receipt
//! blobs. The Prime pushes `(lookup, blob)` whenever a receipt changes; payers and providers
//! `GET <relay>/<lookup>` and open the blob with a key only a holder of the invoice can derive
//! (`xbt_work::relay`). The relay:
//!
//! * holds **no key** and parses nothing: a blob is 12 + 1024 + 16 = [`BLOB_LEN`] opaque bytes;
//! * accepts only **padded blobs**: exactly [`BLOB_LEN`] bytes (`pad₁₀₂₄`), so every entry has one size;
//! * keeps **no index that can be enumerated**: `GET /` and anything that is not a 64-hex lookup is
//!   `404`; there is no listing route, and it logs no lookup;
//! * sends `Cache-Control: no-store` on every response;
//! * **rate-limits by client** (a token bucket per IP; behind a trusted proxy, the address it adds to
//!   `X-Forwarded-For`);
//! * takes pushes on a **separate listener** (the spec's "authenticated internal channel"), with an
//!   optional bearer token; the public listener is read-only;
//! * bounds its store (a maximum entry count, and entries not refreshed for `ttl` expire).
//!
//! The store is either memory (tests, a throwaway relay) or a directory of one file per lookup
//! (`<dir>/<lookup[..2]>/<lookup>`, 0600), which survives a restart and needs no in-memory index.
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

/// `pad₁₀₂₄`: every receipt document is padded with spaces to this many bytes before sealing.
pub const PAD: usize = 1024;
/// nonce(12) ‖ ciphertext(PAD) ‖ tag(16): the one size of every blob.
pub const BLOB_LEN: usize = 12 + PAD + 16;
/// The path prefix the Python reference relay also serves lookups under.
pub const PREFIX: &str = "/work-receipts/v1/";
pub const SERVICE: &str = "xbt-work-relay";

/// A lookup: `hex(SHA256("xbt-work/relay-id|" ‖ identity ‖ "|" ‖ invoice))`, 64 lowercase hex.
pub fn valid_lookup(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// --- the store -------------------------------------------------------------------------------------

/// Why a push was not stored.
#[derive(Debug, PartialEq, Eq)]
pub enum PutError {
    /// The store holds `max_entries` and this lookup is new.
    Full,
    Io(String),
}

enum Backend {
    Memory(Mutex<HashMap<String, (Vec<u8>, u64)>>),
    Disk { dir: PathBuf, count: AtomicUsize },
}

/// Blobs by lookup, bounded in count and age.
pub struct Store {
    backend: Backend,
    pub max_entries: usize,
    /// Entries not pushed again for this long are gone (0: never).
    pub ttl_secs: u64,
    tmp_seq: AtomicU64,
}

impl Store {
    pub fn memory(max_entries: usize, ttl_secs: u64) -> Self {
        Self { backend: Backend::Memory(Mutex::new(HashMap::new())), max_entries, ttl_secs, tmp_seq: AtomicU64::new(0) }
    }

    /// A directory store (created 0700 if missing). Counts the entries already there.
    pub fn disk(dir: impl Into<PathBuf>, max_entries: usize, ttl_secs: u64) -> io::Result<Self> {
        let dir = dir.into();
        xbt_svc::ensure_dir(&dir, 0o700)?;
        let mut n = 0;
        for shard in std::fs::read_dir(&dir)? {
            let shard = shard?;
            if shard.file_type()?.is_dir() {
                n += std::fs::read_dir(shard.path())?.filter_map(|e| e.ok()).filter(|e| valid_lookup(&e.file_name().to_string_lossy())).count();
            }
        }
        Ok(Self { backend: Backend::Disk { dir, count: AtomicUsize::new(n) }, max_entries, ttl_secs, tmp_seq: AtomicU64::new(0) })
    }

    pub fn kind(&self) -> &'static str {
        match self.backend {
            Backend::Memory(_) => "memory",
            Backend::Disk { .. } => "disk",
        }
    }

    fn path(dir: &Path, lookup: &str) -> PathBuf {
        dir.join(&lookup[..2]).join(lookup)
    }

    fn expired(&self, stored_at: u64, now: u64) -> bool {
        self.ttl_secs > 0 && now.saturating_sub(stored_at) > self.ttl_secs
    }

    pub fn len(&self) -> usize {
        match &self.backend {
            Backend::Memory(m) => m.lock().unwrap_or_else(|p| p.into_inner()).len(),
            Backend::Disk { count, .. } => count.load(Ordering::Relaxed),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The blob for `lookup` (an expired one is gone). `lookup` must be valid.
    pub fn get(&self, lookup: &str) -> io::Result<Option<Vec<u8>>> {
        debug_assert!(valid_lookup(lookup));
        let now = unix_now();
        match &self.backend {
            Backend::Memory(m) => {
                let m = m.lock().unwrap_or_else(|p| p.into_inner());
                Ok(m.get(lookup).filter(|(_, t)| !self.expired(*t, now)).map(|(b, _)| b.clone()))
            }
            Backend::Disk { dir, .. } => {
                let p = Self::path(dir, lookup);
                let f = match std::fs::File::open(&p) {
                    Ok(f) => f,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                    Err(e) => return Err(e),
                };
                let t = f.metadata()?.modified().ok().and_then(|m| m.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
                if self.expired(t, now) {
                    return Ok(None);
                }
                let mut b = Vec::with_capacity(BLOB_LEN);
                f.take(BLOB_LEN as u64 + 1).read_to_end(&mut b)?;
                Ok((b.len() == BLOB_LEN).then_some(b))
            }
        }
    }

    /// Store (or replace) the blob for `lookup`. Both must be valid.
    pub fn put(&self, lookup: &str, blob: &[u8]) -> Result<(), PutError> {
        debug_assert!(valid_lookup(lookup) && blob.len() == BLOB_LEN);
        let now = unix_now();
        match &self.backend {
            Backend::Memory(m) => {
                let mut m = m.lock().unwrap_or_else(|p| p.into_inner());
                if !m.contains_key(lookup) && m.len() >= self.max_entries {
                    return Err(PutError::Full);
                }
                m.insert(lookup.to_string(), (blob.to_vec(), now));
                Ok(())
            }
            Backend::Disk { dir, count } => {
                let p = Self::path(dir, lookup);
                let fresh = !p.exists();
                if fresh && count.load(Ordering::Relaxed) >= self.max_entries {
                    return Err(PutError::Full);
                }
                let io = |e: io::Error| PutError::Io(e.to_string());
                xbt_svc::ensure_dir(p.parent().expect("sharded"), 0o700).map_err(io)?;
                // a temp name per write: two pushes of one lookup never share a temp file
                let tmp = p.with_extension(format!("tmp{}-{}", std::process::id(), self.tmp_seq.fetch_add(1, Ordering::Relaxed)));
                let w = (|| -> io::Result<()> {
                    let mut o = std::fs::OpenOptions::new();
                    o.write(true).create_new(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        o.mode(0o600);
                    }
                    let mut f = o.open(&tmp)?;
                    f.write_all(blob)?;
                    f.sync_all()?;
                    std::fs::rename(&tmp, &p)
                })();
                if let Err(e) = w {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(io(e));
                }
                if fresh {
                    count.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            }
        }
    }

    /// Remove an entry (the Prime retiring an invoice). True when there was one.
    pub fn delete(&self, lookup: &str) -> io::Result<bool> {
        match &self.backend {
            Backend::Memory(m) => Ok(m.lock().unwrap_or_else(|p| p.into_inner()).remove(lookup).is_some()),
            Backend::Disk { dir, count } => match std::fs::remove_file(Self::path(dir, lookup)) {
                Ok(()) => {
                    count.fetch_sub(1, Ordering::Relaxed);
                    Ok(true)
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(e),
            },
        }
    }

    /// Drop expired entries (and stale temp files); returns how many entries went.
    pub fn sweep(&self) -> usize {
        if self.ttl_secs == 0 {
            return 0;
        }
        let now = unix_now();
        match &self.backend {
            Backend::Memory(m) => {
                let mut m = m.lock().unwrap_or_else(|p| p.into_inner());
                let before = m.len();
                m.retain(|_, (_, t)| !self.expired(*t, now));
                before - m.len()
            }
            Backend::Disk { dir, count } => {
                let mut gone = 0;
                for shard in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                    for e in std::fs::read_dir(shard.path()).into_iter().flatten().flatten() {
                        let name = e.file_name().to_string_lossy().to_string();
                        let t = e.metadata().ok().and_then(|m| m.modified().ok()).and_then(|m| m.duration_since(UNIX_EPOCH).ok())
                            .map(|d| d.as_secs()).unwrap_or(0);
                        if valid_lookup(&name) {
                            if self.expired(t, now) && std::fs::remove_file(e.path()).is_ok() {
                                count.fetch_sub(1, Ordering::Relaxed);
                                gone += 1;
                            }
                        } else if name.contains(".tmp") && now.saturating_sub(t) > 3600 {
                            let _ = std::fs::remove_file(e.path());
                        }
                    }
                }
                gone
            }
        }
    }

    /// Whether the store can take a write (the readiness check).
    pub fn writable(&self) -> bool {
        match &self.backend {
            Backend::Memory(_) => true,
            Backend::Disk { dir, .. } => {
                let p = dir.join(format!(".probe{}", std::process::id()));
                let ok = std::fs::write(&p, b"").is_ok();
                let _ = std::fs::remove_file(&p);
                ok
            }
        }
    }
}

// --- rate limiting ---------------------------------------------------------------------------------

/// A token bucket per client address: `rate` requests per second, bursts up to `burst`.
pub struct RateLimit {
    rate: f64,
    burst: f64,
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
}

/// Clients tracked before idle (full) buckets are dropped.
const MAX_CLIENTS: usize = 65_536;

impl RateLimit {
    /// `rate` 0: no limit.
    pub fn new(rate: f64, burst: u32) -> Self {
        Self { rate, burst: f64::from(burst.max(1)), buckets: Mutex::new(HashMap::new()) }
    }

    pub fn allow(&self, ip: IpAddr) -> bool {
        if self.rate <= 0.0 {
            return true;
        }
        let now = Instant::now();
        let mut b = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        if b.len() >= MAX_CLIENTS && !b.contains_key(&ip) {
            let (rate, burst) = (self.rate, self.burst);
            b.retain(|_, (tokens, at)| *tokens + now.duration_since(*at).as_secs_f64() * rate < burst);
        }
        let e = b.entry(ip).or_insert((self.burst, now));
        e.0 = (e.0 + now.duration_since(e.1).as_secs_f64() * self.rate).min(self.burst);
        e.1 = now;
        if e.0 >= 1.0 {
            e.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

// --- HTTP ------------------------------------------------------------------------------------------

/// Relay settings.
#[derive(Clone, Debug)]
pub struct Config {
    /// GETs per second per client (0: unlimited) and the burst.
    pub rate: f64,
    pub burst: u32,
    /// When set, a push must carry `Authorization: Bearer <token>`.
    pub push_token: Option<String>,
    /// Take the client address from the last `X-Forwarded-For` hop (only behind a proxy that sets it).
    pub trust_forwarded: bool,
    /// `XBT_BASE_PATH`: lookups answer at `<base>/<lookup>` and at `/<lookup>`.
    pub base: String,
}

impl Default for Config {
    fn default() -> Self {
        Self { rate: 10.0, burst: 40, push_token: None, trust_forwarded: false, base: String::new() }
    }
}

/// An HTTP answer.
#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Resp {
    fn text(status: u16, t: &str) -> Self {
        Self { status, content_type: "text/plain", body: t.as_bytes().to_vec() }
    }

    fn json(status: u16, v: &Value) -> Self {
        Self { status, content_type: "application/json", body: serde_json::to_vec(v).unwrap_or_default() }
    }
}

/// Counters for the log (never a lookup).
#[derive(Default)]
pub struct Counters {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub limited: AtomicU64,
    pub pushes: AtomicU64,
    pub refused: AtomicU64,
}

pub struct Relay {
    pub cfg: Config,
    pub store: Store,
    limiter: RateLimit,
    pub counters: Counters,
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// Constant-time equality of two byte strings (the push token).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Relay {
    pub fn new(cfg: Config, store: Store) -> Self {
        let limiter = RateLimit::new(cfg.rate, cfg.burst);
        Self { cfg, store, limiter, counters: Counters::default() }
    }

    /// The path below the base (query dropped); a path outside the base is taken as is (a proxy
    /// that strips the prefix).
    fn inner(&self, url: &str) -> Option<String> {
        let path = url.split(['?', '#']).next().unwrap_or("");
        Some(xbt_svc::proxy::strip_base(path, &self.cfg.base).unwrap_or_else(|| path.to_string()))
    }

    /// The lookup a path names: `/<lookup>` or `/work-receipts/v1/<lookup>`.
    fn lookup_of(inner: &str) -> Option<&str> {
        let l = inner.strip_prefix(PREFIX).or_else(|| inner.strip_prefix('/'))?;
        valid_lookup(l).then_some(l)
    }

    /// The client a GET is counted against.
    pub fn client(&self, headers: &[(String, String)], peer: Option<IpAddr>) -> Option<IpAddr> {
        if self.cfg.trust_forwarded {
            if let Some(ip) = header(headers, "X-Forwarded-For").and_then(|v| v.rsplit(',').next()).and_then(|v| v.trim().parse().ok()) {
                return Some(ip);
            }
        }
        peer
    }

    fn health(&self, inner: &str) -> Option<Resp> {
        match inner {
            "/healthz" => Some(Resp::json(200, &json!({"ok": true, "service": SERVICE}))),
            "/readyz" => {
                let ok = self.store.writable();
                Some(Resp::json(if ok { 200 } else { 503 }, &json!({"ok": ok, "service": SERVICE, "store": self.store.kind()})))
            }
            // the Python reference relay's probe (scripts that wait for it keep working)
            "/health" => Some(Resp::text(200, "ok\n")),
            _ => None,
        }
    }

    /// The public, read-only listener: `GET <base>/<lookup>`.
    pub fn public(&self, method: &str, url: &str, headers: &[(String, String)], peer: Option<IpAddr>) -> Resp {
        let Some(inner) = self.inner(url) else { return Resp::text(404, "not found\n") };
        if method == "GET" || method == "HEAD" {
            if let Some(r) = self.health(&inner) {
                return r;
            }
        }
        let Some(lookup) = Self::lookup_of(&inner) else { return Resp::text(404, "not found\n") };
        if method != "GET" && method != "HEAD" {
            // pushes go to the push listener; the public one is read-only
            return Resp::text(405, "method not allowed\n");
        }
        if let Some(ip) = self.client(headers, peer) {
            if !self.limiter.allow(ip) {
                self.counters.limited.fetch_add(1, Ordering::Relaxed);
                return Resp::text(429, "rate limited\n");
            }
        }
        match self.store.get(lookup) {
            Ok(Some(b)) => {
                self.counters.hits.fetch_add(1, Ordering::Relaxed);
                Resp { status: 200, content_type: "application/octet-stream", body: b }
            }
            Ok(None) => {
                self.counters.misses.fetch_add(1, Ordering::Relaxed);
                Resp::text(404, "not found\n")
            }
            Err(_) => Resp::text(503, "store unavailable\n"),
        }
    }

    /// The push listener (the Prime's side): `PUT|POST <base>/<lookup>` with the blob, `DELETE` to
    /// retire an entry.
    pub fn push(&self, method: &str, url: &str, headers: &[(String, String)], body: &[u8]) -> Resp {
        let Some(inner) = self.inner(url) else { return Resp::text(404, "not found\n") };
        if method == "GET" || method == "HEAD" {
            if let Some(r) = self.health(&inner) {
                return r;
            }
            return Resp::text(404, "not found\n");
        }
        if let Some(tok) = &self.cfg.push_token {
            let got = header(headers, "Authorization").and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
            if !ct_eq(got.trim().as_bytes(), tok.as_bytes()) {
                self.counters.refused.fetch_add(1, Ordering::Relaxed);
                return Resp::text(401, "push token required\n");
            }
        }
        let Some(lookup) = Self::lookup_of(&inner) else {
            self.counters.refused.fetch_add(1, Ordering::Relaxed);
            return Resp::text(400, "bad lookup\n");
        };
        match method {
            "PUT" | "POST" => {
                if body.len() != BLOB_LEN {
                    self.counters.refused.fetch_add(1, Ordering::Relaxed);
                    return Resp::text(400, "bad length: a blob is nonce(12) + pad_1024 + tag(16) = 1052 bytes\n");
                }
                match self.store.put(lookup, body) {
                    Ok(()) => {
                        self.counters.pushes.fetch_add(1, Ordering::Relaxed);
                        Resp { status: 204, content_type: "text/plain", body: vec![] }
                    }
                    Err(PutError::Full) => Resp::text(507, "relay full\n"),
                    Err(PutError::Io(_)) => Resp::text(503, "store unavailable\n"),
                }
            }
            "DELETE" => match self.store.delete(lookup) {
                Ok(_) => Resp { status: 204, content_type: "text/plain", body: vec![] },
                Err(_) => Resp::text(503, "store unavailable\n"),
            },
            _ => Resp::text(405, "method not allowed\n"),
        }
    }
}

impl From<Resp> for xbt_svc::http::Response {
    fn from(r: Resp) -> Self {
        let headers = [("Content-Type", r.content_type), ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff")];
        Self::new(r.status, headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), r.body)
    }
}

/// The read-only listener. A body is read only up to a blob, so a misdirected push still gets its 405.
struct Public(Arc<Relay>);

impl xbt_svc::http::Handler for Public {
    fn body_limit(&self, _method: &str, _target: &str) -> usize {
        BLOB_LEN
    }

    fn handle(&self, req: xbt_svc::http::Request) -> xbt_svc::http::Response {
        self.0.public(&req.method, &req.target, &req.headers, req.peer.map(|a| a.ip())).into()
    }
}

struct Push(Arc<Relay>);

impl xbt_svc::http::Handler for Push {
    fn body_limit(&self, _method: &str, _target: &str) -> usize {
        BLOB_LEN
    }

    fn handle(&self, req: xbt_svc::http::Request) -> xbt_svc::http::Response {
        self.0.push(&req.method, &req.target, &req.headers, &req.body).into()
    }
}

/// The running listeners.
pub struct Running {
    pub public: SocketAddr,
    pub push: Option<SocketAddr>,
    pub threads: Vec<JoinHandle<()>>,
}

fn listen(addr: &str) -> io::Result<TcpListener> {
    TcpListener::bind(addr).map_err(|e| io::Error::new(e.kind(), format!("{addr}: {e}")))
}

/// Serve `relay` on `public` (GET) and, unless None, `push` (PUT/POST/DELETE), on
/// [`xbt_svc::http`] with `threads` handlers at once (at most 4 for pushes); also sweeps expired entries
/// every `sweep` (when the store has a TTL).
pub fn serve(relay: Arc<Relay>, public: &str, push: Option<&str>, threads: usize, sweep: Duration) -> io::Result<Running> {
    let p = xbt_svc::http::serve(Arc::new(Public(relay.clone())), listen(public)?, threads.max(1))?;
    let mut out = Running { public: p.addr, push: None, threads: p.threads };
    if let Some(addr) = push {
        let q = xbt_svc::http::serve(Arc::new(Push(relay.clone())), listen(addr)?, threads.clamp(1, 4))?;
        out.push = Some(q.addr);
        out.threads.extend(q.threads);
    }
    if relay.store.ttl_secs > 0 {
        let r = relay.clone();
        out.threads.push(std::thread::spawn(move || loop {
            std::thread::sleep(sweep);
            let gone = r.store.sweep();
            if gone > 0 {
                eprintln!("{SERVICE}: {gone} expired entries removed");
            }
        }));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const L: &str = "3f1c0d7e5a2b4c6d8e9f00112233445566778899aabbccddeeff001122334455";

    fn blob(b: u8) -> Vec<u8> {
        vec![b; BLOB_LEN]
    }

    #[test]
    fn lookups_and_sizes() {
        assert!(valid_lookup(L));
        assert!(!valid_lookup(&L.to_uppercase()));
        assert!(!valid_lookup(&L[1..]));
        assert!(!valid_lookup(&format!("{}/", &L[..63])));
        let r = Relay::new(Config::default(), Store::memory(10, 0));
        assert_eq!(r.push("PUT", &format!("/{L}"), &[], &blob(1)[1..]).status, 400);
        assert_eq!(r.push("PUT", &format!("/{L}"), &[], &[blob(1), vec![0]].concat()).status, 400);
        assert_eq!(r.push("PUT", "/nope", &[], &blob(1)).status, 400);
        assert_eq!(r.push("PUT", &format!("/{L}"), &[], &blob(1)).status, 204);
        let g = r.public("GET", &format!("/{L}?x=1"), &[], None);
        assert_eq!((g.status, g.body), (200, blob(1)));
        assert_eq!(r.public("GET", &format!("{PREFIX}{L}"), &[], None).status, 200);
        // no listing, no push on the public side, nothing else
        for p in ["/", "/work-receipts/v1", "/work-receipts/v1/", "/index", "/..", &format!("/{L}/x")] {
            assert_eq!(r.public("GET", p, &[], None).status, 404, "{p}");
        }
        assert_eq!(r.public("PUT", &format!("/{L}"), &[], None).status, 405);
        assert_eq!(r.push("GET", &format!("/{L}"), &[], &[]).status, 404);
        assert_eq!(r.push("DELETE", &format!("/{L}"), &[], &[]).status, 204);
        assert_eq!(r.public("GET", &format!("/{L}"), &[], None).status, 404);
    }

    #[test]
    fn token_base_and_rate() {
        let cfg = Config { rate: 1.0, burst: 3, push_token: Some("s3cret".into()), trust_forwarded: true, base: "/relay".into() };
        let r = Relay::new(cfg, Store::memory(10, 0));
        assert_eq!(r.push("PUT", &format!("/relay/{L}"), &[], &blob(2)).status, 401);
        let bad = vec![("Authorization".to_string(), "Bearer s3cre7".to_string())];
        assert_eq!(r.push("PUT", &format!("/relay/{L}"), &bad, &blob(2)).status, 401);
        let good = vec![("Authorization".to_string(), "Bearer s3cret".to_string())];
        assert_eq!(r.push("PUT", &format!("/relay/{L}"), &good, &blob(2)).status, 204);
        assert_eq!(r.public("GET", &format!("/other/{L}"), &[], None).status, 404);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let st: Vec<u16> = (0..5).map(|_| r.public("GET", &format!("/relay/{L}"), &[], Some(a)).status).collect();
        assert_eq!(st, vec![200, 200, 200, 429, 429]);
        // another client has its own bucket; behind a trusted proxy the last X-Forwarded-For hop counts
        let fwd = vec![("X-Forwarded-For".to_string(), "10.0.0.1, 192.0.2.7".to_string())];
        assert_eq!(r.public("GET", &format!("/relay/{L}"), &fwd, Some(a)).status, 200);
        assert_eq!(r.client(&fwd, Some(a)), Some("192.0.2.7".parse().unwrap()));
        // health is never rate limited
        assert_eq!(r.public("GET", "/relay/healthz", &[], Some(a)).status, 200);
        assert!(!r.limiter.allow(a));
    }

    #[test]
    fn disk_store_bounds_persists_and_expires() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::disk(d.path().join("blobs"), 2, 0).unwrap();
        let (l2, l3) = (L.replace('3', "4"), L.replace('3', "5"));
        s.put(L, &blob(1)).unwrap();
        s.put(&l2, &blob(2)).unwrap();
        s.put(L, &blob(3)).unwrap();
        assert_eq!(s.put(&l3, &blob(4)), Err(PutError::Full));
        assert_eq!(s.get(L).unwrap(), Some(blob(3)));
        assert_eq!(s.get(&l3).unwrap(), None);
        #[cfg(unix)]
        assert_eq!(xbt_svc::mode_of(&d.path().join("blobs").join(&L[..2]).join(L)), 0o600);
        // a restart counts what is there
        let s2 = Store::disk(d.path().join("blobs"), 2, 1).unwrap();
        assert_eq!(s2.len(), 2);
        assert_eq!(s2.get(&l2).unwrap(), Some(blob(2)));
        // backdate one entry past the TTL: it reads as missing and the sweep removes it
        let p = d.path().join("blobs").join(&l2[..2]).join(&l2);
        let old = std::fs::File::options().write(true).open(&p).unwrap();
        old.set_modified(SystemTime::now() - Duration::from_secs(100)).unwrap();
        assert_eq!(s2.get(&l2).unwrap(), None);
        assert_eq!(s2.sweep(), 1);
        assert_eq!(s2.len(), 1);
        s2.put(&l3, &blob(5)).unwrap();
        assert!(s2.delete(L).unwrap());
        assert_eq!(s2.len(), 1);
        assert!(s2.writable());
    }
}
