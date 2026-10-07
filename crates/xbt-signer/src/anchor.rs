//! Anchoring the signature log's head outside the signer's reach (B2 `anchor.py`, AGP-016).
//!
//! The signer's Unix user could rewrite the whole hash-chained log with a fresh, self-consistent
//! chain. So the head is published to a **witness** process that runs as its own user and keeps an
//! append-only store the signer cannot write. On each submission the witness receives the log lines
//! added since its last anchor and accepts the new head only if they chain from the one it holds; a
//! rewind, a fork or a head mismatch is refused and written to its `alerts.jsonl`.
//!
//! This module has the signer side ([`AnchorClient`], [`Anchorer`]) and a port of the witness
//! ([`AnchorStore`], [`serve_witness`]). Both speak B2's protocol (newline-delimited JSON over a
//! Unix socket: `latest`, `submit {n, head, lines, reason}`, `alerts`) and use its store format, so
//! a Rust signer anchors with B2's Python witness and the reverse.
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use crate::ipc::{Listener, Stream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use crate::pyjson::{dumps, dumps_sorted_compact, now_f64, now_ts, py_int};
use crate::sigaudit::{check_chain, sha256_hex, SigAudit, GENESIS};
use crate::{err, Result};

pub const ENV_SOCK: &str = "B2_ANCHOR_SOCK";
pub const MAX_LINES: usize = 100_000;

/// The signer side of the witness socket.
#[derive(Debug, Clone)]
pub struct AnchorClient {
    pub sock_path: PathBuf,
    pub timeout: Duration,
}

impl AnchorClient {
    pub fn new(sock: &Path) -> Self {
        Self { sock_path: sock.to_path_buf(), timeout: Duration::from_secs(10) }
    }

    pub fn from_env() -> Option<Self> {
        let p = std::env::var(ENV_SOCK).unwrap_or_default();
        let p = p.trim();
        (!p.is_empty()).then(|| Self::new(Path::new(p)))
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let unreachable = |e: std::io::Error| err("anchor", format!("anchor witness unreachable at {}: {e}", self.sock_path.display()));
        let mut s = Stream::connect(&self.sock_path).map_err(unreachable)?;
        s.set_timeouts(Some(self.timeout));
        let req = json!({"id": 1, "method": method, "params": params});
        s.write_all(format!("{}\n", dumps(&req)).as_bytes()).map_err(unreachable)?;
        let mut line = String::new();
        BufReader::new(s).read_line(&mut line).map_err(unreachable)?;
        let resp: Value = serde_json::from_str(line.trim()).unwrap_or(json!({}));
        if let Some(e) = resp.get("error").filter(|e| !e.is_null()) {
            return Err(err("anchor", e.get("message").and_then(Value::as_str).unwrap_or("witness error").to_string()));
        }
        resp.get("result").cloned().ok_or_else(|| err("anchor", "empty reply from the anchor witness"))
    }

    pub fn latest(&self) -> Result<Value> {
        self.call("latest", json!({}))
    }

    pub fn submit(&self, n: usize, head: &str, lines: &[String], reason: &str) -> Result<Value> {
        self.call("submit", json!({"n": n, "head": head, "lines": lines, "reason": reason}))
    }
}

struct AnchorerState {
    last: Value,
    last_error: String,
    last_at: f64,
}

/// Sends the log's new lines and head to the witness, one anchor at a time.
pub struct Anchorer {
    audit: Arc<SigAudit>,
    client: Option<AnchorClient>,
    pub interval_s: f64,
    st: Mutex<AnchorerState>,
}

impl Anchorer {
    pub fn new(audit: Arc<SigAudit>, client: Option<AnchorClient>, interval_s: f64) -> Self {
        Self { audit, client, interval_s, st: Mutex::new(AnchorerState { last: json!({}), last_error: String::new(), last_at: 0.0 }) }
    }

    pub fn enabled(&self) -> bool {
        self.client.is_some()
    }

    /// The local log against the witness's latest anchor.
    pub fn check(&self) -> Result<Value> {
        match &self.client {
            None => {
                let mut c = check_chain(&self.audit.path, None);
                c["anchor"] = Value::Null;
                Ok(c)
            }
            Some(cl) => {
                let latest = cl.latest()?;
                let mut c = check_chain(&self.audit.path, Some(&latest));
                c["anchor"] = latest;
                Ok(c)
            }
        }
    }

    pub fn set_error(&self, e: &str) {
        if let Ok(mut st) = self.st.lock() {
            st.last_error = e.chars().take(300).collect();
        }
    }

    /// Anchor the log's current head. Never fails the operation that triggered it: problems are
    /// returned as `{"ok": false, ...}` and kept as `last_error`.
    pub fn anchor(&self, reason: &str) -> Value {
        let Some(cl) = &self.client else {
            return json!({"ok": false, "reason": "anchoring is off (no B2_ANCHOR_SOCK)"});
        };
        let mut st = match self.st.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let attempt = || -> Result<Value> {
            let latest = cl.latest()?;
            let an = py_int(latest.get("n")).unwrap_or(0).max(0) as usize;
            let lines = self.audit.raw_lines();
            if lines.len() < an {
                return Err(err("anchor", format!("the signature log has {} lines, fewer than the {an} anchored", lines.len())));
            }
            let new: Vec<String> = lines[an..].iter().map(|l| String::from_utf8_lossy(l).into_owned()).collect();
            let head = lines.last().map(|l| sha256_hex(l)).unwrap_or_else(|| GENESIS.into());
            cl.submit(lines.len(), &head, &new, reason)
        };
        match attempt() {
            Err(e) => {
                st.last_error = e.msg.chars().take(300).collect();
                json!({"ok": false, "reason": st.last_error})
            }
            Ok(r) => {
                if r.get("ok") == Some(&Value::Bool(true)) {
                    st.last = r.clone();
                    st.last_error.clear();
                    st.last_at = now_f64();
                } else {
                    st.last_error = format!("witness refused: {}", r.get("alert").map(|a| a.as_str().map(str::to_string).unwrap_or_else(|| a.to_string())).unwrap_or_else(|| "None".into()));
                }
                r
            }
        }
    }

    pub fn due(&self) -> bool {
        let last_at = self.st.lock().map(|s| s.last_at).unwrap_or(0.0);
        self.enabled() && self.interval_s > 0.0 && now_f64() - last_at >= self.interval_s
    }

    pub fn last_error(&self) -> String {
        self.st.lock().map(|s| s.last_error.clone()).unwrap_or_default()
    }

    pub fn status(&self) -> Value {
        let n = self.audit.raw_lines().len();
        let st = self.st.lock().map(|s| (s.last.clone(), s.last_error.clone())).unwrap_or((json!({}), String::new()));
        let anchored_n = py_int(st.0.get("n")).unwrap_or(0).max(0) as usize;
        json!({"enabled": self.enabled(), "interval_s": self.interval_s,
               "anchored_n": st.0.get("n").cloned().unwrap_or(Value::Null),
               "anchored_head": st.0.get("head").cloned().unwrap_or(Value::Null),
               "anchored_at": st.0.get("ts").cloned().unwrap_or(Value::Null), "log_lines": n,
               "unanchored_lines": if self.enabled() { json!(n as i64 - anchored_n as i64) } else { Value::Null },
               "error": if st.1.is_empty() { Value::Null } else { st.1.into() }})
    }
}

// --- the witness -----------------------------------------------------------------------------------

struct StoreState {
    rows: Vec<Value>,
    last_line_hash: String,
}

/// The witness's append-only record of `(n lines, head)` for one signature log (`anchors.jsonl`,
/// hash-chained, O_APPEND + fsync) and its `alerts.jsonl`.
pub struct AnchorStore {
    pub dir: PathBuf,
    pub path: PathBuf,
    pub alerts_path: PathBuf,
    st: Mutex<StoreState>,
}

fn append_line(path: &Path, row: &Value) -> Result<String> {
    let line = dumps_sorted_compact(row);
    let mut f = crate::fsx::append(path, 0o640)
        .map_err(|e| err("anchor", format!("{}: {e}", path.display())))?;
    f.write_all(format!("{line}\n").as_bytes()).map_err(|e| err("anchor", e.to_string()))?;
    f.sync_all().map_err(|e| err("anchor", e.to_string()))?;
    Ok(line)
}

impl AnchorStore {
    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir).map_err(|e| err("anchor", e.to_string()))?;
        let path = dir.join("anchors.jsonl");
        let mut rows = vec![];
        let mut prev = GENESIS.to_string();
        if let Ok(b) = fs::read(&path) {
            for raw in b.split(|c| *c == b'\n').filter(|l| !l.iter().all(u8::is_ascii_whitespace)) {
                let row: Value = serde_json::from_slice(raw).map_err(|e| err("anchor", e.to_string()))?;
                if row.get("prev").and_then(Value::as_str) != Some(prev.as_str()) {
                    return Err(err("anchor", format!("witness store {} is not a valid chain", path.display())));
                }
                prev = sha256_hex(raw);
                rows.push(row);
            }
        }
        Ok(Self { dir: dir.into(), alerts_path: dir.join("alerts.jsonl"), path, st: Mutex::new(StoreState { rows, last_line_hash: prev }) })
    }

    fn genesis_row() -> Value {
        json!({"n": 0, "head": GENESIS, "seq": 0})
    }

    pub fn latest(&self) -> Value {
        self.st.lock().ok().and_then(|s| s.rows.last().cloned()).unwrap_or_else(Self::genesis_row)
    }

    fn alert(&self, kind: &str, detail: Value) -> Value {
        let mut row = json!({"ts": now_ts(), "alert": kind});
        let mut out = json!({"ok": false, "alert": kind});
        if let Value::Object(m) = detail {
            for (k, v) in m {
                row[&k] = v.clone();
                out[&k] = v;
            }
        }
        let _ = append_line(&self.alerts_path, &row);
        out
    }

    pub fn alerts(&self) -> Vec<Value> {
        fs::read_to_string(&self.alerts_path).map(|t| t.lines().filter(|l| !l.trim().is_empty()).filter_map(|l| serde_json::from_str(l).ok()).collect())
            .unwrap_or_default()
    }

    /// Accept `(n, head)` only if `lines` are exactly the log lines after the last anchor and chain
    /// from its head to `head`.
    pub fn submit(&self, n: i64, head: &str, lines: &[String], reason: &str) -> Value {
        let mut st = match self.st.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let last = st.rows.last().cloned().unwrap_or_else(Self::genesis_row);
        let (ln, lhead, lseq) = (py_int(last.get("n")).unwrap_or(0), last["head"].as_str().unwrap_or(GENESIS).to_string(), py_int(last.get("seq")).unwrap_or(0));
        if n < ln {
            if st.rows.iter().any(|r| py_int(r.get("n")) == Some(n) && r["head"].as_str() == Some(head)) {
                return json!({"ok": true, "n": ln, "head": lhead, "seq": lseq, "stale": true});
            }
            drop(st);
            return self.alert("rewind", json!({"n": n, "head": head, "anchored_n": ln, "reason": reason}));
        }
        if lines.len() as i64 != n - ln || lines.len() > MAX_LINES {
            drop(st);
            return self.alert("bad_submission", json!({"n": n, "lines": lines.len(), "anchored_n": ln}));
        }
        let mut prev = lhead.clone();
        for (i, raw) in lines.iter().enumerate() {
            let link = serde_json::from_str::<Value>(raw).ok().and_then(|v| v.get("prev").and_then(Value::as_str).map(str::to_string));
            if link.as_deref() != Some(prev.as_str()) {
                drop(st);
                return self.alert("fork", json!({"n": n, "head": head, "anchored_n": ln, "at_line": ln + i as i64 + 1, "reason": reason}));
            }
            prev = sha256_hex(raw.as_bytes());
        }
        if prev != head {
            drop(st);
            return self.alert("head_mismatch", json!({"n": n, "head": head, "computed": prev}));
        }
        if n == ln {
            return json!({"ok": true, "n": ln, "head": lhead, "seq": lseq, "unchanged": true});
        }
        let row = json!({"seq": lseq + 1, "n": n, "head": head, "ts": now_ts(), "reason": reason, "prev": st.last_line_hash});
        match append_line(&self.path, &row) {
            Ok(line) => {
                st.last_line_hash = sha256_hex(line.as_bytes());
                st.rows.push(row.clone());
                json!({"ok": true, "seq": row["seq"], "n": row["n"], "head": row["head"], "ts": row["ts"]})
            }
            Err(e) => json!({"ok": false, "alert": "store_error", "reason": e.msg}),
        }
    }

    pub fn handle(&self, req: &Value) -> Result<Value> {
        let p = req.get("params").cloned().unwrap_or(json!({}));
        match req.get("method").and_then(Value::as_str) {
            Some("latest") => Ok(self.latest()),
            Some("submit") => {
                let lines: Vec<String> = p.get("lines").and_then(Value::as_array).map(|a| a.iter().map(|x| x.as_str().unwrap_or("").to_string()).collect()).unwrap_or_default();
                Ok(self.submit(py_int(p.get("n")).unwrap_or(0), p.get("head").and_then(Value::as_str).unwrap_or(""), &lines,
                               p.get("reason").and_then(Value::as_str).unwrap_or("")))
            }
            Some("alerts") => Ok(json!({"alerts": self.alerts()})),
            m => Err(err("anchor", format!("unknown method {}", m.unwrap_or("None")))),
        }
    }
}

/// A running witness (tests and the `xbt-anchor-witness` binary). Stops when dropped.
pub struct Witness {
    pub store: Arc<AnchorStore>,
    pub sock_path: PathBuf,
    stop: Arc<AtomicBool>,
}

impl Drop for Witness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = Stream::connect(&self.sock_path);
    }
}

/// Bind the witness socket (mode `sock_mode`) and serve it on a background thread.
pub fn serve_witness(store_dir: &Path, sock_path: &Path, sock_mode: u32) -> Result<Witness> {
    let store = Arc::new(AnchorStore::open(store_dir)?);
    let listener = Listener::bind(sock_path, sock_mode).map_err(|e| err("anchor", format!("{}: {e}", sock_path.display())))?;
    let stop = Arc::new(AtomicBool::new(false));
    let (st2, stop2) = (store.clone(), stop.clone());
    std::thread::Builder::new().name("anchor-witness".into()).spawn(move || {
        loop {
            let conn = listener.accept();
            if stop2.load(Ordering::SeqCst) {
                break;
            }
            if let Ok(conn) = conn {
                let st = st2.clone();
                std::thread::spawn(move || serve_conn(conn, |req| st.handle(req)));
            }
        }
    }).map_err(|e| err("anchor", e.to_string()))?;
    Ok(Witness { store, sock_path: sock_path.into(), stop })
}

/// Newline-delimited JSON request/response loop over one connection.
pub fn serve_conn(conn: Stream, handle: impl Fn(&Value) -> Result<Value>) {
    let mut w = match conn.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut reader = BufReader::new(conn.take(u64::MAX));
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(line.trim()) {
            Ok(v) => v,
            Err(_) => break,
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let resp = match handle(&req) {
            Ok(r) => json!({"id": id, "result": r}),
            Err(e) => json!({"id": id, "error": {"message": e.msg}}),
        };
        if w.write_all(format!("{}\n", dumps(&resp)).as_bytes()).is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_accepts_extensions_and_refuses_rewrites() {
        let d = tempfile::tempdir().unwrap();
        let w = serve_witness(&d.path().join("store"), &d.path().join("w.sock"), 0o600).unwrap();
        let log = Arc::new(SigAudit::open(&d.path().join("signatures.jsonl")).unwrap());
        let an = Anchorer::new(log.clone(), Some(AnchorClient::new(&w.sock_path)), 60.0);
        assert_eq!(an.anchor("start")["unchanged"], true);
        log.record("funding", b"a", "", "", json!({})).unwrap();
        log.record("channel_state", b"b", "c", "", json!({})).unwrap();
        let r = an.anchor("close");
        assert_eq!(r["ok"], true);
        assert_eq!(r["n"], 2);
        assert_eq!(an.check().unwrap()["ok"], true);
        // rewrite the whole log with a fresh chain: the anchor check fails and the witness refuses it
        fs::remove_file(&log.path).unwrap();
        let fake = Arc::new(SigAudit::open(&d.path().join("signatures.jsonl")).unwrap());
        fake.record("funding", b"x", "", "", json!({})).unwrap();
        fake.record("funding", b"y", "", "", json!({})).unwrap();
        fake.record("funding", b"z", "", "", json!({})).unwrap();
        let an2 = Anchorer::new(fake, Some(AnchorClient::new(&w.sock_path)), 60.0);
        assert_eq!(an2.check().unwrap()["ok"], false);
        let r = an2.anchor("periodic");
        assert_eq!(r["ok"], false);
        assert_eq!(r["alert"], "fork");
        assert_eq!(w.store.alerts().len(), 1);
    }
}
