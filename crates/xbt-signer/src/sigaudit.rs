//! Append-only log of every signature the signer makes (B2 `sigaudit.py`, AGP-013/016).
//!
//! One JSON line per signature: what was signed (`kind`), for which channel / destination, the
//! amount, the SHA-256 of the signature bytes, the signer method that asked for it and the policy
//! rule that allowed it. Lines are hash-chained (`prev` = SHA-256 of the previous line as written),
//! O_APPEND and fsynced, so a removed or edited line breaks [`check_chain`]; with the witness's
//! latest anchor (`anchor.rs`) a whole-file rewrite is detected too. The line format is B2's
//! (`json.dumps(entry, sort_keys=True, separators=(",", ":"))`), so either implementation checks
//! the other's log.
//!
//! The method and rule come from a per-thread context the signer sets while it handles a request
//! ([`context`], [`set_rule`]), so the low-level signing code does not need to know which policy
//! decision is behind it.
use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::pyjson::{dumps_sorted_compact, now_ts};
use crate::{err, Result};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

thread_local! {
    static CTX: RefCell<Option<Map<String, Value>>> = const { RefCell::new(None) };
}

/// Restores the previous context when dropped.
pub struct ContextGuard {
    prev: Option<Map<String, Value>>,
}

impl Drop for ContextGuard {
    fn drop(&mut self) {
        let prev = self.prev.take();
        CTX.with(|c| *c.borrow_mut() = prev);
    }
}

/// Set the method / rule the next signatures on this thread are made under (merged over the
/// current context, restored when the guard drops).
pub fn context(method: Option<&str>, rule: Option<&str>) -> ContextGuard {
    CTX.with(|c| {
        let prev = c.borrow().clone();
        let mut m = prev.clone().unwrap_or_default();
        if let Some(x) = method {
            m.insert("method".into(), x.into());
        }
        if let Some(x) = rule {
            m.insert("rule".into(), x.into());
        }
        *c.borrow_mut() = Some(m);
        ContextGuard { prev }
    })
}

/// Record the policy rule that allowed the current request (inside a [`context`]).
pub fn set_rule(rule: &str) {
    CTX.with(|c| {
        if let Some(m) = c.borrow_mut().as_mut() {
            m.insert("rule".into(), rule.into());
        }
    });
}

/// The current context's fields.
pub fn current() -> Map<String, Value> {
    CTX.with(|c| c.borrow().clone().unwrap_or_default())
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// The signature log.
pub struct SigAudit {
    pub path: PathBuf,
    last: Mutex<String>,
}

impl SigAudit {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).map_err(|e| err("io", e.to_string()))?;
        }
        // AGP-055: a crash mid-append leaves a line without its newline. That signature never left
        // (it is logged before it is returned), and the next line must not be glued onto it.
        crate::applog::cut_torn_tail(path)?;
        let last = tail_hash(path);
        Ok(Self { path: path.to_path_buf(), last: Mutex::new(last) })
    }

    /// Append one line: `kind`, `chan`, `dest`, `sig_sha256` (of `sig`), the context's method and
    /// rule (`extra["rule"]` overrides), `extra`, `ts` and `prev`.
    pub fn record(&self, kind: &str, sig: &[u8], chan: &str, dest: &str, extra: Value) -> Result<Value> {
        let ctx = current();
        let mut extra = match extra {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        let rule = extra.remove("rule").filter(|r| r.as_str().is_some_and(|s| !s.is_empty()))
            .or_else(|| ctx.get("rule").cloned().filter(|r| r.as_str().is_some_and(|s| !s.is_empty())))
            .unwrap_or_else(|| "unattributed".into());
        let mut last = self.last.lock().map_err(|_| err("sigaudit", "poisoned"))?;
        let mut entry = Map::new();
        entry.insert("ts".into(), now_ts());
        entry.insert("kind".into(), kind.into());
        entry.insert("chan".into(), chan.into());
        entry.insert("dest".into(), dest.into());
        entry.insert("sig_sha256".into(), if sig.is_empty() { "".into() } else { sha256_hex(sig).into() });
        entry.insert("method".into(), ctx.get("method").cloned().unwrap_or_else(|| "".into()));
        entry.insert("rule".into(), rule);
        for (k, v) in extra {
            entry.insert(k, v);
        }
        entry.insert("prev".into(), last.clone().into());
        let entry = Value::Object(entry);
        let line = dumps_sorted_compact(&entry);
        let mut f = crate::fsx::append(&self.path, 0o600)
            .map_err(|e| err("sigaudit", format!("{}: {e}", self.path.display())))?;
        let mut buf = line.clone().into_bytes();
        buf.push(b'\n');
        crate::fsx::write_all(&mut f, &buf).map_err(|e| err("sigaudit", e.to_string()))?;
        crate::fsx::sync(&f).map_err(|e| err("sigaudit", e.to_string()))?;
        *last = sha256_hex(line.as_bytes());
        Ok(entry)
    }

    /// The log's non-empty lines as written (what the chain hashes), read under the append lock.
    pub fn raw_lines(&self) -> Vec<Vec<u8>> {
        let _g = self.last.lock();
        read_lines(&self.path)
    }

    /// The last `limit` entries (all with 0).
    pub fn read(&self, limit: usize) -> Vec<Value> {
        let rows: Vec<Value> = read_lines(&self.path).iter().filter_map(|l| serde_json::from_slice(l).ok()).collect();
        if limit > 0 && rows.len() > limit {
            rows[rows.len() - limit..].to_vec()
        } else {
            rows
        }
    }
}

fn read_lines(path: &Path) -> Vec<Vec<u8>> {
    fs::read(path).map(|b| b.split(|c| *c == b'\n').filter(|l| !l.iter().all(u8::is_ascii_whitespace)).map(<[u8]>::to_vec).collect())
        .unwrap_or_default()
}

fn strip_cr(l: &[u8]) -> &[u8] {
    l.strip_suffix(b"\r").unwrap_or(l)
}

fn tail_hash(path: &Path) -> String {
    read_lines(path).last().map(|l| sha256_hex(strip_cr(l))).unwrap_or_else(|| GENESIS.into())
}

/// Walk the chain; with `anchor` (`{"n", "head"}` from the witness) also require that line `n`
/// still hashes to the anchored head (a log rewritten from scratch fails). B2's `check_chain`.
pub fn check_chain(path: &Path, anchor: Option<&Value>) -> Value {
    let mut prev = GENESIS.to_string();
    let mut heads = vec![GENESIS.to_string()];
    let (mut n, mut bad) = (0usize, String::new());
    for raw in read_lines(path) {
        let raw = strip_cr(&raw);
        let link = serde_json::from_slice::<Value>(raw).ok().and_then(|v| v.get("prev").and_then(Value::as_str).map(str::to_string));
        if link.as_deref() != Some(prev.as_str()) {
            bad = format!("line {} does not chain from line {n}", n + 1);
            break;
        }
        prev = sha256_hex(raw);
        heads.push(prev.clone());
        n += 1;
    }
    let mut out = json!({"ok": bad.is_empty(), "lines": n, "head": prev, "reason": bad});
    if let (Some(a), true) = (anchor, bad.is_empty()) {
        let an = crate::pyjson::py_int(a.get("n")).unwrap_or(0).max(0) as usize;
        let ah = a.get("head").and_then(Value::as_str).unwrap_or(GENESIS).to_string();
        out["anchored_n"] = an.into();
        if n < an {
            out["ok"] = false.into();
            out["reason"] = format!("the log has {n} lines but {an} were anchored (truncated or rewritten)").into();
        } else if heads[an] != ah {
            out["ok"] = false.into();
            out["reason"] = format!("line {an} does not hash to the anchored head (the log was rewritten)").into();
        } else {
            out["unanchored_lines"] = (n - an).into();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_detects_edits_and_rewrites() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("signatures.jsonl");
        let a = SigAudit::open(&p).unwrap();
        {
            let _g = context(Some("xbt402_pay"), Some("method:xbt402_pay"));
            set_rule("policy:ok");
            a.record("channel_state", b"sig1", "c:0", "http://x", json!({"cum": 546})).unwrap();
            a.record("refund", b"sig2", "c:0", "http://x", json!({"rule": "watcher:auto_refund"})).unwrap();
        }
        let rows = a.read(0);
        assert_eq!(rows[0]["rule"], "policy:ok");
        assert_eq!(rows[0]["method"], "xbt402_pay");
        assert_eq!(rows[1]["rule"], "watcher:auto_refund");
        assert_eq!(check_chain(&p, None)["ok"], true);
        let anchor = json!({"n": 2, "head": check_chain(&p, None)["head"]});
        assert_eq!(check_chain(&p, Some(&anchor))["ok"], true);
        // an edited line breaks the chain
        let text = fs::read_to_string(&p).unwrap().replace("546", "547");
        fs::write(&p, &text).unwrap();
        assert_eq!(check_chain(&p, None)["ok"], false);
        // a self-consistent rewrite passes the chain but fails the anchor
        fs::remove_file(&p).unwrap();
        let b = SigAudit::open(&p).unwrap();
        b.record("channel_state", b"x", "c:0", "", json!({})).unwrap();
        b.record("channel_state", b"y", "c:0", "", json!({})).unwrap();
        assert_eq!(check_chain(&p, None)["ok"], true);
        assert_eq!(check_chain(&p, Some(&anchor))["ok"], false);
        // outside any context a signature is unattributed
        assert_eq!(b.record("x", b"", "", "", json!({})).unwrap()["rule"], "unattributed");
    }
}
