//! The provider's per-channel state, persisted before a call is served.
//!
//! The Python reference keeps it in SQLite (WAL, synchronous=FULL). This crate uses an append-only
//! JSON-lines log: `save` appends the changed rows and fsyncs, so a paid call costs O(1) writes
//! whatever the number of channels; `open` replays the log (the last row per channel wins) and
//! compacts it. A torn last line (a crash mid-write) is ignored: that row was never acknowledged.
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use serde_json::{Map, Value};

use crate::channel::ChannelParams;
use crate::error::{ChannelError, Result};

/// `extra` key of the reservations of metered calls in flight: `{"<seq>": msat}` (AGP-059).
const RESV: &str = "resv";

/// One channel as the provider sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct ChannelState {
    pub params: ChannelParams,
    pub best_cum: u64,
    /// Hex of the payer's best 0x21 signature.
    pub best_sig: String,
    pub seq: u64,
    pub spent_msat: u64,
    pub closed_txid: String,
    pub best_sig_a3: String,
    pub cond_hash: String,
    pub cond_amount: u64,
    pub cond_sig: String,
    pub extra: Map<String, Value>,
    /// The watcher saw the funding leave the chain (reorg): serve nothing.
    pub suspended: bool,
    /// Last watcher error for this channel, retried every tick.
    pub close_error: String,
}

impl ChannelState {
    pub fn new(params: ChannelParams) -> Self {
        Self {
            params,
            best_cum: 0,
            best_sig: String::new(),
            seq: 0,
            spent_msat: 0,
            closed_txid: String::new(),
            best_sig_a3: String::new(),
            cond_hash: String::new(),
            cond_amount: 0,
            cond_sig: String::new(),
            extra: Map::new(),
            suspended: false,
            close_error: String::new(),
        }
    }

    /// AGP-059: record that `spent_msat` holds `msat` reserved for the metered call `seq`, whose
    /// charge is not known yet (`extra.resv`). The call's settlement releases it; one still recorded
    /// when a provider starts was never charged (a crash mid-call) and is refunded.
    pub fn reserve(&mut self, seq: u64, msat: u64) {
        let mut resv = self.extra.get(RESV).and_then(Value::as_object).cloned().unwrap_or_default();
        resv.insert(seq.to_string(), msat.into());
        self.extra.insert(RESV.into(), Value::Object(resv));
    }

    /// Forget the reservation of call `seq`: the msat it held (0 if none was recorded).
    pub fn release(&mut self, seq: u64) -> u64 {
        let Some(mut resv) = self.extra.get(RESV).and_then(Value::as_object).cloned() else { return 0 };
        let msat = resv.remove(&seq.to_string()).and_then(|v| v.as_u64()).unwrap_or(0);
        if resv.is_empty() {
            self.extra.remove(RESV);
        } else {
            self.extra.insert(RESV.into(), Value::Object(resv));
        }
        msat
    }

    /// Msat of `spent_msat` that are reservations of calls not settled yet.
    pub fn reserved_msat(&self) -> u64 {
        self.extra.get(RESV).and_then(Value::as_object).into_iter().flatten()
            .fold(0u64, |a, (_, v)| a.saturating_add(v.as_u64().unwrap_or(0)))
    }

    /// Refund every recorded reservation (provider start): `spent_msat` is what was charged again.
    /// Returns the msat refunded.
    pub fn refund_reservations(&mut self) -> u64 {
        let msat = self.reserved_msat();
        self.spent_msat = self.spent_msat.saturating_sub(msat);
        self.extra.remove(RESV);
        msat
    }

    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "chan": self.params.channel_id(), "params": self.params.to_json(), "best_cum": self.best_cum,
            "best_sig": self.best_sig, "seq": self.seq, "spent_msat": self.spent_msat,
            "closed_txid": self.closed_txid, "best_sig_a3": self.best_sig_a3, "cond_hash": self.cond_hash,
            "cond_amount": self.cond_amount, "cond_sig": self.cond_sig, "extra": self.extra,
            "suspended": self.suspended, "close_error": self.close_error,
        })
    }

    pub fn from_json(v: &Value) -> Result<Self> {
        let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let n = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
        Ok(Self {
            params: ChannelParams::from_json(v.get("params").unwrap_or(&Value::Null))?,
            best_cum: n("best_cum"),
            best_sig: s("best_sig"),
            seq: n("seq"),
            spent_msat: n("spent_msat"),
            closed_txid: s("closed_txid"),
            best_sig_a3: s("best_sig_a3"),
            cond_hash: s("cond_hash"),
            cond_amount: n("cond_amount"),
            cond_sig: s("cond_sig"),
            extra: v.get("extra").and_then(Value::as_object).cloned().unwrap_or_default(),
            suspended: v.get("suspended").and_then(Value::as_bool).unwrap_or(false),
            close_error: s("close_error"),
        })
    }
}

/// Latest state per channel (insertion order kept), optionally persisted.
#[derive(Debug, Default)]
pub struct Ledger {
    path: Option<PathBuf>,
    file: Option<File>,
    pub channels: IndexMap<String, ChannelState>,
}

fn io_err(e: std::io::Error) -> ChannelError {
    ChannelError::new("ledger_error", e.to_string())
}

impl Ledger {
    /// A ledger that lives only in memory (tests, vector generation).
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Where this ledger lives (None in memory).
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Replay and compact the log at `path` (created if missing).
    pub fn open(path: &Path) -> Result<Self> {
        let mut channels = IndexMap::new();
        if path.exists() {
            let f = File::open(path).map_err(io_err)?;
            for line in BufReader::new(f).lines() {
                let Ok(line) = line else { break };
                let Ok(v) = crate::json::parse(&line) else { continue };
                let st = ChannelState::from_json(&v)?;
                channels.insert(st.params.channel_id(), st);
            }
        }
        let mut l = Self { path: Some(path.to_path_buf()), file: None, channels };
        l.compact()?;
        Ok(l)
    }

    fn compact(&mut self) -> Result<()> {
        let Some(path) = self.path.clone() else { return Ok(()) };
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d).map_err(io_err)?;
        }
        let tmp = path.with_extension("tmp");
        {
            let mut f = File::create(&tmp).map_err(io_err)?;
            for st in self.channels.values() {
                writeln!(f, "{}", st.to_json()).map_err(io_err)?;
            }
            f.sync_all().map_err(io_err)?;
        }
        std::fs::rename(&tmp, &path).map_err(io_err)?;
        if let Some(d) = path.parent() {
            if let Ok(dir) = File::open(d) {
                let _ = dir.sync_all();
            }
        }
        self.file = Some(OpenOptions::new().append(true).open(&path).map_err(io_err)?);
        Ok(())
    }

    /// Persist the given channels (every channel if `chans` is empty) and fsync.
    pub fn save(&mut self, chans: &[&str]) -> Result<()> {
        let Some(f) = self.file.as_mut() else { return Ok(()) };
        let mut buf = String::new();
        let rows: Vec<&ChannelState> = if chans.is_empty() {
            self.channels.values().collect()
        } else {
            chans.iter().filter_map(|c| self.channels.get(*c)).collect()
        };
        for st in rows {
            buf.push_str(&st.to_json().to_string());
            buf.push('\n');
        }
        f.write_all(buf.as_bytes()).map_err(io_err)?;
        f.sync_data().map_err(io_err)?;
        Ok(())
    }
}
