//! Append-only JSON-lines log with one fsync per row (AGP-055; B2 `applog.py`, same files).
//!
//! The routed-spend rows and the payment ledger used to be rewritten whole on every lock. Here a
//! row is one line appended to an open file and fsynced: the cost of a row no longer depends on
//! how many rows came before it.
//!
//! File: a header line `{"kind":"<kind>","v":1}`, then one JSON object per line.
//!
//! Torn last line: a row counts once its line ends in a newline. A crash in the middle of an
//! append leaves bytes after the last newline; `append` had not returned for that row, so nothing
//! was built on it. Opening the log cuts those bytes off (and fsyncs) before anything is appended
//! after them. Any complete line that does not parse is damage, not a crash: opening fails, it
//! never reads as a shorter log.
//!
//! Compaction: [`AppendLog::compact`] writes the header and the rows to a temp file, fsyncs it,
//! renames it over the log and fsyncs the directory. A crash leaves the old log or the new one.
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::pyjson::dumps_sorted_compact;
use crate::{err, fsx, Result};

pub const VERSION: i64 = 1;

fn io(path: &Path, e: std::io::Error) -> crate::Error {
    err("io", format!("{}: {e}", path.display()))
}

/// One row as its line: `json.dumps(row, sort_keys=True, separators=(",", ":"))` and a newline.
pub fn line(row: &Value) -> Vec<u8> {
    let mut b = dumps_sorted_compact(row).into_bytes();
    b.push(b'\n');
    b
}

/// The header line of a `kind` log.
pub fn header(kind: &str) -> Vec<u8> {
    line(&json!({"kind": kind, "v": VERSION}))
}

fn tmp_of(path: &Path) -> PathBuf {
    let mut t = path.as_os_str().to_owned();
    t.push(".tmp");
    PathBuf::from(t)
}

/// Cut the bytes after the last newline off an append-only file (a crash mid-append), fsync, and
/// return how many were cut. A missing file has no tail.
pub fn cut_torn_tail(path: &Path) -> Result<usize> {
    if !path.exists() {
        return Ok(0);
    }
    let data = std::fs::read(path).map_err(|e| io(path, e))?;
    let good = data.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    if good == data.len() {
        return Ok(0);
    }
    let f = std::fs::OpenOptions::new().write(true).open(path).map_err(|e| io(path, e))?;
    fsx::truncate(&f, good as u64).map_err(|e| io(path, e))?;
    fsx::sync(&f).map_err(|e| io(path, e))?;
    Ok(data.len() - good)
}

/// Write a whole log (header + rows) to a temp file, fsync, rename over `path`, fsync the directory.
pub fn replace_log(path: &Path, kind: &str, rows: &[Value]) -> Result<()> {
    let tmp = tmp_of(path);
    let mut body = header(kind);
    for r in rows {
        body.extend_from_slice(&line(r));
    }
    {
        let mut f = fsx::create_truncate(&tmp, 0o600).map_err(|e| io(&tmp, e))?;
        fsx::write_all(&mut f, &body).map_err(|e| io(&tmp, e))?;
        fsx::sync(&f).map_err(|e| io(&tmp, e))?;
    }
    fsx::rename(&tmp, path).map_err(|e| io(path, e))?;
    fsx::sync_dir(fsx::parent_of(path)).map_err(|e| io(path, e))
}

/// An open log. The owner keeps the rows: [`AppendLog::open`] hands over what the file held, and
/// `file_rows` counts the lines since. Not `Sync`: the owner serializes calls.
pub struct AppendLog {
    pub path: PathBuf,
    kind: String,
    file: File,
    /// Row lines in the file (the header is not one).
    pub file_rows: usize,
    /// Bytes of a torn last line cut off at open.
    pub torn_bytes: usize,
}

impl AppendLog {
    /// Open (or create) the `kind` log at `path`; returns it and the rows it holds, in order.
    pub fn open(path: &Path, kind: &str) -> Result<(Self, Vec<Value>)> {
        let dir = fsx::parent_of(path);
        std::fs::create_dir_all(dir).map_err(|e| io(dir, e))?;
        let created = !path.exists();
        let mut file = fsx::with_mode_rw_append(path, 0o600).map_err(|e| io(path, e))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data).map_err(|e| io(path, e))?;
        let good = data.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
        let torn_bytes = data.len() - good;
        if torn_bytes > 0 {
            // a torn last line: never acknowledged, cut it off
            fsx::truncate(&file, good as u64).map_err(|e| io(path, e))?;
            fsx::sync(&file).map_err(|e| io(path, e))?;
            data.truncate(good);
        }
        let head = header(kind);
        if data.is_empty() {
            fsx::write_all(&mut file, &head).map_err(|e| io(path, e))?;
            fsx::sync(&file).map_err(|e| io(path, e))?;
            data = head.clone();
        }
        let mut lines = data[..data.len() - 1].split(|&b| b == b'\n');
        let first = lines.next().unwrap_or(&[]);
        if first != &head[..head.len() - 1] {
            return Err(err("log", format!("{}: not a v{VERSION} {kind} log (first line {:?})", path.display(),
                                          String::from_utf8_lossy(&first[..first.len().min(80)]))));
        }
        let mut rows = Vec::new();
        for (n, raw) in lines.enumerate() {
            let row: Value = serde_json::from_slice(raw)
                .map_err(|e| err("log", format!("{}: line {} is damaged ({e}); the log is not read past it", path.display(), n + 2)))?;
            if !row.is_object() {
                return Err(err("log", format!("{}: line {} is not an object", path.display(), n + 2)));
            }
            rows.push(row);
        }
        if created {
            fsx::sync_dir(dir).map_err(|e| io(dir, e))?;
        }
        Ok((Self { path: path.into(), kind: kind.into(), file, file_rows: rows.len(), torn_bytes }, rows))
    }

    /// One write and one fsync; returns once the row is durable.
    pub fn append(&mut self, row: &Value) -> Result<()> {
        fsx::write_all(&mut self.file, &line(row)).map_err(|e| io(&self.path, e))?;
        fsx::sync(&self.file).map_err(|e| io(&self.path, e))?;
        self.file_rows += 1;
        Ok(())
    }

    /// Replace the log's rows with `rows`, atomically.
    pub fn compact(&mut self, rows: &[Value]) -> Result<()> {
        replace_log(&self.path, &self.kind, rows)?;
        self.file = fsx::with_mode_rw_append(&self.path, 0o600).map_err(|e| io(&self.path, e))?;
        self.file_rows = rows.len();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsx::probe;

    fn rows_of(path: &Path) -> Result<Vec<Value>> {
        AppendLog::open(path, "k").map(|(_, r)| r)
    }

    /// Run `f` with a crash armed at `step`; `None` when it died there.
    fn crashing<T>(step: u64, torn: bool, f: impl FnOnce() -> T) -> Option<T> {
        probe::crash_at(step, torn);
        let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        probe::reset();
        match out {
            Ok(v) => Some(v),
            Err(e) if e.is::<probe::Crash>() => None,
            Err(e) => std::panic::resume_unwind(e),
        }
    }

    #[test]
    fn lines_are_python_json_dumps_sorted_compact() {
        assert_eq!(header("payments"), b"{\"kind\":\"payments\",\"v\":1}\n");
        assert_eq!(line(&json!({"ts": 1.5, "dest": "d", "amount_sats": 7, "memo": "é"})),
                   b"{\"amount_sats\":7,\"dest\":\"d\",\"memo\":\"\\u00e9\",\"ts\":1.5}\n");
    }

    #[test]
    fn a_torn_last_line_is_cut_at_every_length_and_the_next_row_lands_clean() {
        let torn = line(&json!({"at": 1.5, "amount": 7}));
        for cut in 1..torn.len() {
            let d = tempfile::tempdir().unwrap();
            let p = d.path().join("x.jsonl");
            let (mut a, _) = AppendLog::open(&p, "k").unwrap();
            a.append(&json!({"at": 1.0, "amount": 1})).unwrap();
            drop(a);
            let mut bytes = std::fs::read(&p).unwrap();
            bytes.extend_from_slice(&torn[..cut]); // a crash mid-append: no newline yet
            std::fs::write(&p, &bytes).unwrap();
            let (mut b, rows) = AppendLog::open(&p, "k").unwrap();
            assert_eq!((rows, b.torn_bytes), (vec![json!({"at": 1.0, "amount": 1})], cut));
            b.append(&json!({"at": 2.0, "amount": 2})).unwrap();
            drop(b);
            assert_eq!(rows_of(&p).unwrap(), vec![json!({"at": 1.0, "amount": 1}), json!({"at": 2.0, "amount": 2})]);
        }
    }

    #[test]
    fn a_damaged_complete_line_or_another_header_refuses_to_load() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.jsonl");
        let (mut a, _) = AppendLog::open(&p, "k").unwrap();
        a.append(&json!({"n": 1})).unwrap();
        drop(a);
        let good = std::fs::read(&p).unwrap();
        let with = |tail: &[u8]| [good.as_slice(), tail].concat();
        std::fs::write(&p, with(b"{\"n\": 2\n{\"n\":3}\n")).unwrap();
        assert_eq!(rows_of(&p).unwrap_err().code, "log", "never the rows before the damage");
        std::fs::write(&p, with(b"[1]\n")).unwrap();
        assert_eq!(rows_of(&p).unwrap_err().code, "log");
        std::fs::write(&p, &good).unwrap();
        assert_eq!(AppendLog::open(&p, "other").err().map(|e| e.code), Some("log".to_string()));
        std::fs::write(&p, b"{\"resolved\": []}\n").unwrap();
        assert_eq!(rows_of(&p).unwrap_err().code, "log");
    }

    #[test]
    fn a_crash_at_every_step_of_create_and_compact_leaves_a_whole_log() {
        for torn in [false, true] {
            let mut step = 0;
            loop {
                let d = tempfile::tempdir().unwrap();
                let p = d.path().join("x.jsonl");
                if crashing(step, torn, || drop(AppendLog::open(&p, "k").unwrap())).is_some() {
                    break;
                }
                assert_eq!(rows_of(&p).unwrap(), Vec::<Value>::new(), "create step {step} torn={torn}");
                step += 1;
            }
            let old: Vec<Value> = (0..5).map(|n| json!({"n": n})).collect();
            let new = vec![json!({"n": 3}), json!({"n": 4})];
            let mut step = 0;
            loop {
                let d = tempfile::tempdir().unwrap();
                let p = d.path().join("x.jsonl");
                let (mut a, _) = AppendLog::open(&p, "k").unwrap();
                for r in &old {
                    a.append(r).unwrap();
                }
                if crashing(step, torn, || a.compact(&new).unwrap()).is_some() {
                    assert_eq!(rows_of(&p).unwrap(), new);
                    break;
                }
                let got = rows_of(&p).unwrap();
                assert!(got == old || got == new, "compact step {step} torn={torn}: {got:?}");
                step += 1;
            }
            assert!(step > 2);
        }
    }
}
