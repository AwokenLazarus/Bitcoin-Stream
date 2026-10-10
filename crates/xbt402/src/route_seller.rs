//! The provider side of hub routing (B1 `RouteSeller` and the provider's routing endpoints,
//! AGP-021/023): route offers with a signed price quote, metered sessions in amsat, a fresh lock
//! point T per window in a payTo-signed invoice, ROUTE-AUTH / ROUTE-STATE on every routed call,
//! and `POST /x402/xbt-channel/lock`, which completes a hub's adaptor-locked ch2 state with the
//! window's t, saves it write-ahead and only then returns t.
//!
//! Serving rule (cmp constraint 6): a session is served while its unpaid charges are younger than
//! `window + lock_wait` (and under `credit_msat` if set). When the hub stops forwarding, the lock
//! never arrives and the provider stops within one window: its loss is at most one window of that
//! session's traffic, the client's at most one lock per provider.
//!
//! One deliberate difference from the reference: a channel keeps the answers to its last 256
//! completed locks (B1 keeps all of them). A hub retries only its one pending lock, and a replay of
//! an older lockId is refused as `bad_invoice` (it is not the session's open invoice).
//!
//! AGP-054: an optional [`RouteWal`] makes each session's meter durable before its ROUTE-STATE
//! leaves, written ahead while the handler runs (B1 `RouteWal`, same file format and rules).
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};
use xbt_primitives::ecdsa;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::sighash::SIGHASH_ALL_UNIFIED;

use crate::adaptor::{self, PreSig, Sc};
use crate::error::{fail, ChannelError, Result};
use crate::json::{dumps, py_int, py_str, py_u64};
use crate::ledger::{ChannelState, Ledger};
use crate::provider::{HttpResponse, Provider};
use crate::route::*;
use crate::wire::*;

/// Most completed-lock answers a channel keeps for idempotent retries.
pub const ROUTE_LOCKS_KEPT: usize = 256;

/// `charge(method, path, status, body) -> amsat` for a metered routed path.
pub type RouteChargeFn = Box<dyn Fn(&str, &str, u16, &[u8]) -> u128 + Send + Sync>;

/// `precharge(method, path, body) -> amsat` the call will bill, known before it runs (AGP-054): with
/// a [`RouteWal`] its session's meter is written ahead while the handler runs. None: no overlap.
pub type RoutePrechargeFn = Box<dyn Fn(&str, &str, &[u8]) -> Option<u128> + Send + Sync>;

/// A routed path on sale.
pub struct RouteOffer {
    pub path: String,
    /// Seconds per lock window.
    pub window: f64,
    /// Grace after a window for its lock to arrive.
    pub lock_wait: f64,
    /// A window's invoice is completed only until then.
    pub invoice_ttl: f64,
    /// `"any"` or `["<hub payTo>", ...]`.
    pub hubs: Value,
    pub amsat_per_call: u128,
    pub unit: String,
    /// Optional hard cap on unpaid credit, msat (0: time-based only).
    pub credit_msat: u128,
    pub charge: Option<RouteChargeFn>,
    /// AGP-054: the charge a call will bill, before it runs (a flat path needs none).
    pub precharge: Option<RoutePrechargeFn>,
}

impl RouteOffer {
    pub fn new(path: &str, amsat_per_call: u128) -> Self {
        Self { path: path.into(), window: 1.0, lock_wait: 2.0, invoice_ttl: 15.0, hubs: "any".into(), amsat_per_call,
               unit: "call".into(), credit_msat: 0, charge: None, precharge: None }
    }

    /// What a call is expected to bill before it runs: the precharge, else the flat price of a path
    /// without a metered charge, else unknown.
    fn expect(&self, method: &str, path: &str, body: &[u8]) -> Option<u128> {
        match (&self.precharge, &self.charge) {
            (Some(f), _) => f(method, path, body),
            (None, None) => Some(self.amsat_per_call),
            (None, Some(_)) => None,
        }
    }
}

/// One client's metered session on a routed path.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteSession {
    pub session: String,
    pub client_pub: String,
    pub path: String,
    pub created: f64,
    pub seq: u64,
    pub accrued_amsat: u128,
    pub paid_sat: u64,
    pub calls: u64,
    /// Time of the oldest charge not covered by paid_sat (0: none).
    pub unpaid_since: f64,
    pub lock_id: String,
    /// The current window's secret (hex); never leaves until its lock completes.
    pub t: String,
    pub point: String,
    pub valid_until: f64,
    /// `{lockId, amount, secret}`: the client's receipt.
    pub last_lock: Value,
    pub locks: u64,
}

impl RouteSession {
    pub fn owed_amsat(&self) -> i128 {
        self.accrued_amsat as i128 - self.paid_sat as i128 * AMSAT_PER_SAT as i128
    }

    fn to_json(&self) -> Value {
        json!({"session": self.session, "client_pub": self.client_pub, "path": self.path, "created": self.created,
               "seq": self.seq, "accrued_amsat": int_value(self.accrued_amsat), "paid_sat": self.paid_sat, "calls": self.calls,
               "unpaid_since": self.unpaid_since, "lock_id": self.lock_id, "t": self.t, "point": self.point,
               "valid_until": self.valid_until, "last_lock": self.last_lock, "locks": self.locks})
    }

    fn from_json(v: &Value) -> Option<Self> {
        let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let f = |k: &str| v.get(k).and_then(Value::as_f64).unwrap_or(0.0);
        let n = |k: &str| py_u64(v.get(k)).unwrap_or(0);
        Some(Self { session: s("session"), client_pub: s("client_pub"), path: s("path"), created: f("created"), seq: n("seq"),
                    accrued_amsat: u128_of(v.get("accrued_amsat")).unwrap_or(0), paid_sat: n("paid_sat"), calls: n("calls"),
                    unpaid_since: f("unpaid_since"), lock_id: s("lock_id"), t: s("t"), point: s("point"),
                    valid_until: f("valid_until"), last_lock: v.get("last_lock").cloned().unwrap_or(json!({})), locks: n("locks") })
    }
}

/// A routed session's meter (seq, calls, accruedAmsat, unpaid_since) made durable before the
/// ROUTE-STATE that carries it leaves, without an fsync on the call's critical path (B1 `RouteWal`).
///
/// Every line is a snapshot of one session's meter projected over its calls in flight (each at the
/// charge reserved for it before it runs), versioned by `v`. One writer thread appends whatever is
/// queued and syncs it (group commit), so the sync runs while the handler computes. A call whose
/// charge differs from its projection writes a corrected snapshot and waits for that one.
///
/// * every ROUTE-STATE that left is covered by a durable snapshot;
/// * a restart can count more only for calls in flight at the crash, each at its projected charge
///   (the in-doubt chunk a client already accounts for);
/// * a seq is durable before its handler runs: no ROUTE-AUTH is served twice across a crash.
///
/// Replay: the highest-`v` snapshot per session wins over the routes file when its `v` is above
/// the file's `walV`. The log is rewritten as one snapshot per session past `compact_bytes`.
pub struct RouteWal {
    path: PathBuf,
    compact_bytes: AtomicU64,
    inner: Mutex<WalInner>,
    cv: Condvar,
    fsyncs: AtomicU64,
    #[doc(hidden)]
    pub fail_writes: AtomicBool,
    #[doc(hidden)]
    pub sync_delay_ms: AtomicU64,
    /// Tests: a batch holding any version >= this (0: off) waits until it is cleared.
    #[doc(hidden)]
    pub hold_from: AtomicU64,
    /// Tests: a batch holding this version (0: off) fails.
    #[doc(hidden)]
    pub fail_v: AtomicU64,
}

#[derive(Default)]
struct WalInner {
    v: u64,
    queue: Vec<(u64, String, Vec<u8>)>,
    durable: u64,
    failed: Vec<(u64, u64)>,
    latest: HashMap<String, Vec<u8>>,
    error: String,
    started: bool,
}

/// One replayed snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct WalRecord {
    pub v: u64,
    pub seq: u64,
    pub calls: u64,
    pub acc: u128,
    pub us: f64,
}

fn wal_line(sid: &str, v: u64, seq: u64, calls: u64, acc: u128, us: f64) -> Vec<u8> {
    let mut l = dumps(&json!({"acc": acc.to_string(), "calls": calls, "s": sid, "seq": seq, "us": round3(us), "v": v}));
    l.push('\n');
    l.into_bytes()
}

fn fsync_dir(path: &Path) {
    if let Some(d) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        if let Ok(f) = std::fs::File::open(d) {
            let _ = f.sync_all();
        }
    }
}

impl RouteWal {
    pub fn open(path: impl Into<PathBuf>) -> Arc<Self> {
        let wal = Arc::new(Self { path: path.into(), compact_bytes: AtomicU64::new(1 << 20), inner: Mutex::new(WalInner::default()),
                                  cv: Condvar::new(), fsyncs: AtomicU64::new(0), fail_writes: AtomicBool::new(false),
                                  sync_delay_ms: AtomicU64::new(0), hold_from: AtomicU64::new(0), fail_v: AtomicU64::new(0) });
        let recs = wal.read();
        {
            let mut g = wal.guard();
            for (sid, r) in recs {
                g.v = g.v.max(r.v);
                g.latest.insert(sid.clone(), wal_line(&sid, r.v, r.seq, r.calls, r.acc, r.us));
            }
            g.durable = g.v;
        }
        wal
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, WalInner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The last version handed out.
    pub fn version(&self) -> u64 {
        self.guard().v
    }

    /// At open: versions continue above `v` (the routes file's walV). A log that lost its lines
    /// (deleted, replaced) must not restart below it, or replay would take the routes file over
    /// every snapshot written since.
    pub fn resume_above(&self, v: u64) {
        let mut g = self.guard();
        if g.v < v {
            g.v = v;
            g.durable = g.durable.max(v);
        }
    }

    /// How many batches were synced.
    pub fn fsyncs(&self) -> u64 {
        self.fsyncs.load(Ordering::Relaxed)
    }

    pub fn set_compact_bytes(&self, n: u64) {
        self.compact_bytes.store(n, Ordering::Relaxed);
    }

    /// The highest-`v` snapshot per session, from every whole line (a torn last line was never
    /// acknowledged: its call was never answered).
    pub fn read(&self) -> HashMap<String, WalRecord> {
        let mut out: HashMap<String, WalRecord> = HashMap::new();
        let Ok(raw) = std::fs::read(&self.path) else { return out };
        for line in raw.split(|b| *b == b'\n') {
            let Ok(r) = crate::json::parse_slice(line) else { continue };
            let (Some(sid), Some(v), Some(seq), Some(calls), Some(acc)) =
                (r.get("s").and_then(Value::as_str), py_u64(r.get("v")), py_u64(r.get("seq")), py_u64(r.get("calls")), u128_of(r.get("acc")))
            else {
                continue;
            };
            let rec = WalRecord { v, seq, calls, acc, us: r.get("us").and_then(Value::as_f64).unwrap_or(0.0) };
            if out.get(sid).is_none_or(|o| v > o.v) {
                out.insert(sid.to_string(), rec);
            }
        }
        out
    }

    /// Queue one snapshot; returns its version (the ticket to `wait` for). Never blocks on I/O.
    pub fn submit(self: &Arc<Self>, sid: &str, seq: u64, calls: u64, acc: u128, us: f64) -> u64 {
        let mut g = self.guard();
        g.v += 1;
        let v = g.v;
        g.queue.push((v, sid.to_string(), wal_line(sid, v, seq, calls, acc, us)));
        if !g.started {
            g.started = true;
            let me = Arc::clone(self);
            std::thread::Builder::new().name("route-wal".into()).spawn(move || RouteWal::run(me)).expect("route-wal thread");
        }
        self.cv.notify_all();
        v
    }

    /// Return once snapshot `v` is durable; an error if its write failed (or timed out).
    pub fn wait(&self, v: u64, timeout: Duration) -> Result<()> {
        let end = Instant::now() + timeout;
        let mut g = self.guard();
        loop {
            if g.failed.iter().any(|(lo, hi)| (*lo..=*hi).contains(&v)) {
                let e = if g.error.is_empty() { "write failed".to_string() } else { g.error.clone() };
                return fail("route_wal_failed", format!("route wal {}: {e}", self.path.display()));
            }
            if g.durable >= v {
                return Ok(());
            }
            let now = Instant::now();
            if now >= end {
                return fail("route_wal_failed", format!("route wal {}: not durable after {timeout:?}", self.path.display()));
            }
            g = self.cv.wait_timeout(g, end - now).map(|(g, _)| g).unwrap_or_else(|p| p.into_inner().0);
        }
    }

    /// A pruned session: left out of the next compaction.
    pub fn forget(&self, sid: &str) {
        self.guard().latest.remove(sid);
    }

    /// The writer thread. It ends once it holds the last reference (the provider is gone).
    fn run(self: Arc<Self>) {
        let mut file: Option<std::fs::File> = None;
        loop {
            let batch = {
                let mut g = self.guard();
                while g.queue.is_empty() {
                    if Arc::strong_count(&self) == 1 {
                        return;
                    }
                    g = self.cv.wait_timeout(g, Duration::from_secs(1)).map(|(g, _)| g).unwrap_or_else(|p| p.into_inner().0);
                }
                std::mem::take(&mut g.queue)
            };
            let (lo, hi) = (batch[0].0, batch[batch.len() - 1].0);
            match self.write(&mut file, &batch) {
                Err(e) => {
                    let mut g = self.guard();
                    g.error = e.to_string();
                    g.failed.push((lo, hi));
                    let n = g.failed.len();
                    if n > 64 {
                        g.failed.drain(..n - 64);
                    }
                    g.durable = g.durable.max(hi);
                    self.cv.notify_all();
                }
                Ok(size) => {
                    {
                        let mut g = self.guard();
                        g.durable = hi;
                        for (_, sid, line) in batch {
                            g.latest.insert(sid, line);
                        }
                        self.cv.notify_all();
                    }
                    if size > self.compact_bytes.load(Ordering::Relaxed) {
                        let _ = self.compact(&mut file);
                    }
                }
            }
        }
    }

    fn write(&self, file: &mut Option<std::fs::File>, batch: &[(u64, String, Vec<u8>)]) -> std::io::Result<u64> {
        let mut created = false;
        if file.is_none() {
            created = !self.path.exists();
            *file = Some(std::fs::OpenOptions::new().create(true).append(true).open(&self.path)?);
        }
        let f = file.as_mut().expect("opened");
        let start = f.metadata()?.len();
        let data: Vec<u8> = batch.iter().flat_map(|(_, _, l)| l.iter().copied()).collect();
        let res = (|| {
            let hold = self.hold_from.load(Ordering::Relaxed);
            if hold > 0 && batch.iter().any(|(v, _, _)| *v >= hold) {
                let end = Instant::now() + Duration::from_secs(10);
                while self.hold_from.load(Ordering::Relaxed) > 0 && Instant::now() < end {
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
            let fv = self.fail_v.load(Ordering::Relaxed);
            if self.fail_writes.load(Ordering::Relaxed) || (fv > 0 && batch.iter().any(|(v, _, _)| *v == fv)) {
                return Err(std::io::Error::other("EIO (test)"));
            }
            f.write_all(&data)?;
            let d = self.sync_delay_ms.load(Ordering::Relaxed);
            if d > 0 {
                std::thread::sleep(Duration::from_millis(d));
            }
            f.sync_data()?;
            self.fsyncs.fetch_add(1, Ordering::Relaxed);
            if created {
                fsync_dir(&self.path);
            }
            f.metadata().map(|m| m.len())
        })();
        if res.is_err() && f.set_len(start).is_err() {
            *file = None;
        }
        res
    }

    /// In the writer thread: one snapshot per live session, synced, renamed over the log.
    fn compact(&self, file: &mut Option<std::fs::File>) -> std::io::Result<()> {
        let lines: Vec<u8> = self.guard().latest.values().flat_map(|l| l.iter().copied()).collect();
        let tmp = self.path.with_extension("wal-tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&lines)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        fsync_dir(&self.path);
        *file = Some(std::fs::OpenOptions::new().append(true).open(&self.path)?);
        Ok(())
    }
}

/// A reservation made before a routed call's handler runs: its snapshot version and expected charge.
#[derive(Debug, Clone, Copy)]
pub struct WalTicket {
    pub v: u64,
    pub expect: u128,
}

/// How long an answer waits for its snapshot at most.
const WAL_WAIT: Duration = Duration::from_secs(30);

fn token_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).expect("OS randomness");
    hex::encode(b)
}

/// A client's lock answer or ROUTE-STATE, and the held locks of a non-revealing provider.
#[derive(Default)]
pub struct SellerState {
    pub offers: HashMap<String, RouteOffer>,
    pub sessions: HashMap<String, RouteSession>,
    quotes: HashMap<String, PriceQuote>,
    quote_seq: i64,
    keys: HashMap<String, [u8; 32]>,
    /// Tests/demo: take locks, never reveal t (a withholding provider).
    pub no_reveal: bool,
    pub held: Vec<Value>,
    /// session -> (window key, signed invoice): one signature per window (AGP-054).
    invoices: HashMap<String, (String, Value)>,
    /// session -> (calls, amsat) reserved and not yet ended (AGP-054).
    inflight: HashMap<String, (u64, u128)>,
    /// RouteWal version at the routes file's last save (its `walV`).
    saved_v: u64,
    /// session -> (v, seq, calls, accrued): the meter its latest snapshot holds, v 0 for a completed
    /// routes-file save (durable already). An answer waits for a snapshot that covers it (AGP-054 rework 1).
    snap: HashMap<String, (u64, u64, u64, u128)>,
    /// session -> ROUTE-STATEs built so far (a failed call's take-back guard).
    states: HashMap<String, u64>,
}

/// The provider's routing book: offers, sessions (persisted next to the ledger) and the rest.
pub struct RouteSeller {
    pub state: Mutex<SellerState>,
    path: Option<PathBuf>,
    secret: SecretKey,
    pay_to: String,
    network: String,
    settle_multiple: u64,
    wal: Option<Arc<RouteWal>>,
}

impl RouteSeller {
    pub(crate) fn new(ledger: &Ledger, secret: SecretKey, network: &str, settle_multiple: u64, wal: Option<&Path>) -> Self {
        let path = ledger.path().map(|p| {
            let s = p.to_string_lossy().to_string();
            PathBuf::from(format!("{}.routes.json", s.strip_suffix(".json").unwrap_or(&s)))
        });
        let mut st = SellerState { quote_seq: now_i(), ..Default::default() };
        if let Some(raw) = path.as_ref().and_then(|p| std::fs::read(p).ok()).and_then(|b| crate::json::parse_slice(&b).ok()) {
            for (k, v) in raw.get("sessions").and_then(Value::as_object).into_iter().flatten() {
                if let Some(s) = RouteSession::from_json(v) {
                    st.sessions.insert(k.clone(), s);
                }
            }
            st.saved_v = py_u64(raw.get("walV")).unwrap_or(0);
        }
        let wal = wal.map(RouteWal::open);
        if let Some(w) = &wal {
            w.resume_above(st.saved_v);
        }
        let me = Self { state: Mutex::new(st), path, pay_to: hex::encode(ecdsa::pubkey(&secret)), secret, network: network.into(),
                        settle_multiple, wal };
        me.replay();
        me
    }

    /// The RouteWal, when the provider has one.
    pub fn wal(&self) -> Option<&Arc<RouteWal>> {
        self.wal.as_ref()
    }

    /// At start: a session's meter from the RouteWal where its snapshot is newer than the routes
    /// file (v above walV), then one save, so the routes file carries it.
    fn replay(&self) {
        let Some(wal) = &self.wal else { return };
        let mut st = self.lock();
        let mut changed = false;
        for (sid, r) in wal.read() {
            let saved = st.saved_v;
            let Some(s) = st.sessions.get_mut(&sid) else { continue };
            if r.v <= saved {
                continue;
            }
            s.seq = s.seq.max(r.seq);
            s.calls = r.calls;
            s.accrued_amsat = r.acc;
            s.unpaid_since = r.us;
            changed = true;
        }
        if changed {
            let _ = self.save(&mut st);
        }
    }

    /// (seq, calls, accrued, unpaid_since) with the calls in flight counted at their reserved
    /// charges: what a restart may bill.
    fn projected(st: &SellerState, s: &RouteSession) -> (u64, u64, u128, f64) {
        let (n, amt) = st.inflight.get(&s.session).copied().unwrap_or((0, 0));
        let us = if amt > 0 && s.owed_amsat() <= 0 { now_f() } else { s.unpaid_since };
        (s.seq, s.calls + n, s.accrued_amsat + amt, us)
    }

    fn submit(&self, st: &mut SellerState, sid: &str) -> Option<u64> {
        let wal = self.wal.as_ref()?;
        let s = st.sessions.get(sid)?;
        let (seq, calls, acc, us) = Self::projected(st, s);
        let v = wal.submit(sid, seq, calls, acc, us);
        st.snap.insert(sid.to_string(), (v, seq, calls, acc));
        Some(v)
    }

    /// As a state is built from the session's meter: the version of a snapshot that covers it (seq,
    /// calls and accrued each >= the state's), queuing a fresh one if the latest does not. The state
    /// carries the session's CURRENT meter, which may already hold a concurrent call metered in
    /// memory whose own snapshot is still queued, or a seq taken by begin_call and not reserved yet:
    /// waiting only for the call's own reserved snapshot could let a state leave that a crash would
    /// take back (AGP-054 rework 1).
    fn covering(&self, st: &mut SellerState, sid: &str) -> Option<u64> {
        let s = st.sessions.get(sid)?;
        match st.snap.get(sid) {
            Some(&(v, seq, calls, acc)) if seq >= s.seq && calls >= s.calls && acc >= s.accrued_amsat => Some(v),
            _ => self.submit(st, sid),
        }
    }

    /// Before the handler runs: count the call in flight at `expect` and queue its session's
    /// projected meter, so the sync overlaps the handler. None without a RouteWal.
    pub fn reserve(&self, sid: &str, expect: u128) -> Option<WalTicket> {
        self.wal.as_ref()?;
        let mut st = self.lock();
        if !st.sessions.contains_key(sid) {
            return None;
        }
        let e = st.inflight.entry(sid.to_string()).or_insert((0, 0));
        e.0 += 1;
        e.1 += expect;
        self.submit(&mut st, sid).map(|v| WalTicket { v, expect })
    }

    fn unreserve(st: &mut SellerState, sid: &str, t: Option<WalTicket>) {
        let Some(t) = t else { return };
        if let Some(e) = st.inflight.get_mut(sid) {
            e.0 = e.0.saturating_sub(1);
            e.1 = e.1.saturating_sub(t.expect);
            if e.0 == 0 {
                st.inflight.remove(sid);
            }
        }
    }

    /// The call billed nothing and no answer leaves: its projection is corrected (not waited for).
    pub fn cancel(&self, sid: &str, t: Option<WalTicket>) {
        if t.is_none() {
            return;
        }
        let mut st = self.lock();
        Self::unreserve(&mut st, sid, t);
        self.submit(&mut st, sid);
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, SellerState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Save the routes file. A session is kept with its meter projected over its calls in flight
    /// (the same snapshot a RouteWal line holds), so a save supersedes no reservation (AGP-054).
    fn save(&self, st: &mut SellerState) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        if let Some(w) = &self.wal {
            st.saved_v = w.version();
        }
        let sessions: Map<String, Value> = st.sessions.iter().map(|(k, v)| {
            let mut j = v.to_json();
            if st.inflight.contains_key(k) {
                let (seq, calls, acc, us) = Self::projected(st, v);
                j["seq"] = seq.into();
                j["calls"] = calls.into();
                j["accrued_amsat"] = int_value(acc);
                j["unpaid_since"] = us.into();
            }
            (k.clone(), j)
        }).collect();
        let tmp = path.with_extension("tmp");
        let io = |e: std::io::Error| ChannelError::new("ledger_error", e.to_string());
        {
            let mut f = std::fs::File::create(&tmp).map_err(io)?;
            f.write_all(dumps(&json!({"sessions": sessions, "walV": st.saved_v})).as_bytes()).map_err(io)?;
            f.sync_all().map_err(io)?;
        }
        std::fs::rename(&tmp, path).map_err(io)?;
        if self.wal.is_some() {
            // the caller holds the seller lock: the file is durable and covers each session as it is now
            let snaps: Vec<(String, (u64, u64, u64, u128))> = st.sessions.iter().map(|(k, s)| {
                let (seq, calls, acc, _) = Self::projected(st, s);
                (k.clone(), (0, seq, calls, acc))
            }).collect();
            st.snap.extend(snaps);
        }
        Ok(())
    }

    pub fn has_offer(&self, path: &str) -> bool {
        self.lock().offers.contains_key(path)
    }

    pub fn offer_paths(&self) -> Vec<String> {
        let mut v: Vec<String> = self.lock().offers.keys().cloned().collect();
        v.sort();
        v
    }

    fn price_quote(&self, st: &mut SellerState, path: &str) -> Result<PriceQuote> {
        let now = now_i();
        if let Some(q) = st.quotes.get(path) {
            if q.valid_until - now >= 60 {
                return Ok(q.clone());
            }
        }
        let o = st.offers.get(path).ok_or_else(|| ChannelError::code("unknown_route"))?;
        st.quote_seq += 1;
        let q = PriceQuote { pay_to: self.pay_to.clone(), network: self.network.clone(), path: path.into(), amsat_per_call: o.amsat_per_call,
                             unit: o.unit.clone(), seq: st.quote_seq, issued_at: now, valid_until: now + 3600, sig: String::new() }
            .sign(&self.secret);
        st.quotes.insert(path.into(), q.clone());
        Ok(q)
    }

    fn key(&self, st: &mut SellerState, sid: &str) -> Result<[u8; 32]> {
        if let Some(k) = st.keys.get(sid) {
            return Ok(*k);
        }
        let s = st.sessions.get(sid).ok_or_else(|| ChannelError::code("unknown_session"))?;
        let k = session_key(&self.secret, &hex::decode(&s.client_pub).unwrap_or_default())?;
        st.keys.insert(sid.to_string(), k);
        Ok(k)
    }

    /// A fresh (t, T) per window.
    fn new_window(s: &mut RouteSession, ttl: f64) {
        let t = adaptor::random_secret();
        s.t = hex::encode(t.secret_bytes());
        s.point = hex::encode(adaptor::enc(&adaptor::point_of(&t)));
        s.lock_id = token_hex(12);
        s.valid_until = now_f() + ttl;
    }

    /// The window's signed invoice. It only changes with the window (and ECDSA signing is
    /// deterministic), so it is signed once per window, not on every ROUTE-STATE (AGP-054).
    fn invoice(&self, st: &mut SellerState, s: &RouteSession) -> Value {
        let hubs = st.offers.get(&s.path).map(|o| o.hubs.clone()).unwrap_or_else(|| "any".into());
        let key = format!("{}|{}|{}|{}", s.lock_id, s.point, round3(s.valid_until), dumps(&hubs));
        if let Some((k, inv)) = st.invoices.get(&s.session) {
            if *k == key {
                return inv.clone();
            }
        }
        let inv = Invoice { pay_to: self.pay_to.clone(), network: self.network.clone(), session: s.session.clone(), lock_id: s.lock_id.clone(),
                            point: s.point.clone(), valid_until: round3(s.valid_until), hubs, sig: String::new() }
            .sign(&self.secret).to_json();
        st.invoices.insert(s.session.clone(), (key, inv.clone()));
        inv
    }

    fn open_session(&self, st: &mut SellerState, path: &str, client_pub_hex: &str) -> Result<String> {
        let pubk = hex::decode(client_pub_hex.trim()).map_err(|_| ChannelError::new("bad_key", "not hex"))?;
        ecdsa::public_key(&pubk).map_err(|_| ChannelError::new("bad_key", "not a point"))?;
        let ttl = st.offers.get(path).map(|o| o.invoice_ttl).unwrap_or(15.0);
        let mut s = RouteSession { session: token_hex(16), client_pub: hex::encode(&pubk), path: path.into(), created: now_f(), seq: 0,
                                   accrued_amsat: 0, paid_sat: 0, calls: 0, unpaid_since: 0.0, lock_id: String::new(), t: String::new(),
                                   point: String::new(), valid_until: 0.0, last_lock: json!({}), locks: 0 };
        Self::new_window(&mut s, ttl);
        let sid = s.session.clone();
        st.sessions.insert(sid.clone(), s);
        self.save(st)?;
        Ok(sid)
    }

    /// `PaymentRequirements.extra.route` for a routed path: the offer, the signed price quote and,
    /// when the request named a client route key (ROUTE-CLIENT), a new session and its first
    /// invoice.
    pub fn route_extra(&self, path: &str, client_pub_hex: &str) -> Result<Value> {
        let mut st = self.lock();
        let q = self.price_quote(&mut st, path)?;
        let o = &st.offers[path];
        let mut out = json!({"window": o.window, "lockWait": o.lock_wait, "invoiceTtl": o.invoice_ttl, "hubs": o.hubs,
                             "creditMsat": o.credit_msat.to_string(), "quote": q.to_json(), "lockUrl": ROUTE_LOCK_PATH,
                             "settleMultiple": self.settle_multiple});
        if !client_pub_hex.is_empty() {
            let sid = self.open_session(&mut st, path, client_pub_hex)?;
            let s = st.sessions[&sid].clone();
            let inv = self.invoice(&mut st, &s);
            out["session"] = sid.into();
            out["invoice"] = inv;
        }
        Ok(out)
    }

    fn serving(st: &SellerState, s: &RouteSession, now: f64) -> Option<&'static str> {
        let o = st.offers.get(&s.path)?;
        if s.owed_amsat() <= 0 {
            return None;
        }
        if s.unpaid_since > 0.0 && now - s.unpaid_since > o.window + o.lock_wait {
            return Some("route_credit");
        }
        if o.credit_msat > 0 && s.owed_amsat() > (o.credit_msat * AMSAT_PER_MSAT) as i128 {
            return Some("route_credit");
        }
        None
    }

    /// ROUTE-STATE: the signed running meter and the open invoice (and the last completed lock's t,
    /// so the client has its receipt even from a hub that withholds it).
    fn state_locked(&self, st: &mut SellerState, sid: &str, charge: u128) -> Result<Value> {
        let q = {
            let path = st.sessions.get(sid).map(|s| s.path.clone()).ok_or_else(|| ChannelError::code("unknown_session"))?;
            self.price_quote(st, &path)?
        };
        let ttl = st.sessions.get(sid).and_then(|s| st.offers.get(&s.path)).map(|o| o.invoice_ttl).unwrap_or(15.0);
        let s = st.sessions.get_mut(sid).ok_or_else(|| ChannelError::code("unknown_session"))?;
        if now_f() > s.valid_until - 1.0 {
            // an expired invoice: nobody can complete it now, issue a fresh T
            Self::new_window(s, ttl);
        }
        let s = st.sessions[sid].clone();
        let body = json!({"session": s.session, "seq": s.seq, "calls": s.calls, "chargeAmsat": charge.to_string(),
                          "accruedAmsat": s.accrued_amsat.to_string(), "paidSat": s.paid_sat, "quote": q.quote_id(),
                          "lastLock": s.last_lock, "invoice": self.invoice(st, &s)});
        Ok(state_sign(&self.secret, &body))
    }

    /// The session's current ROUTE-STATE (no charge).
    pub fn state(&self, sid: &str) -> Result<Value> {
        let mut st = self.lock();
        self.state_locked(&mut st, sid, 0)
    }

    /// Authenticate a routed call. `Ok((session, None))` to serve, `Ok((session, Some(error)))` or
    /// `Err(error)` (no session) to refuse.
    /// `bind` is the request's URL as [`request_digest_v2`] binds it.
    pub fn begin_call(&self, path: &str, hdr: &str, method: &str, bind: &str, body: &[u8]) -> std::result::Result<(String, Option<&'static str>), &'static str> {
        let h = unb64json(hdr).map_err(|_| "bad_payload")?;
        let (Some(sid), Some(seq), Some(auth)) = (h.get("session"), py_int(h.get("seq")), h.get("auth")) else { return Err("bad_payload") };
        let (sid, auth) = (py_str(Some(sid)), py_str(Some(auth)));
        let mut st = self.lock();
        if !st.sessions.get(&sid).is_some_and(|s| s.path == path) {
            return Err("unknown_session");
        }
        let key = self.key(&mut st, &sid).map_err(|_| "bad_auth")?;
        let s = st.sessions.get(&sid).ok_or("unknown_session")?;
        if seq <= s.seq as i128 {
            return Err("bad_auth");
        }
        let seq = u64::try_from(seq).map_err(|_| "bad_auth")?;
        if !auth_eq(&call_auth(&key, &sid, seq, &request_digest_v2(method, bind, body)), &auth) {
            return Err("bad_auth");
        }
        let s = st.sessions.get_mut(&sid).ok_or("unknown_session")?;
        s.seq = seq;
        let s = s.clone();
        let err = Self::serving(&st, &s, now_f());
        Ok((sid, err))
    }

    pub fn end_call(&self, sid: &str, charge_amsat: u128) -> Result<Value> {
        self.end_call_reserved(sid, charge_amsat, None)
    }

    /// Meter the call and return its ROUTE-STATE. With a RouteWal the state is returned only once a
    /// snapshot covering it is durable: the reserved one when the charge is what was projected, else
    /// a fresh one. On a write failure the call is taken back (nothing billed) and the error is
    /// `route_wal_failed`: no state may leave.
    pub fn end_call_reserved(&self, sid: &str, charge_amsat: u128, ticket: Option<WalTicket>) -> Result<Value> {
        let (state, v) = {
            let mut st = self.lock();
            Self::unreserve(&mut st, sid, ticket);
            let s = st.sessions.get_mut(sid).ok_or_else(|| ChannelError::code("unknown_session"))?;
            if charge_amsat > 0 {
                if s.owed_amsat() <= 0 {
                    s.unpaid_since = now_f();
                }
                s.accrued_amsat += charge_amsat;
            }
            s.calls += 1;
            let state = self.state_locked(&mut st, sid, charge_amsat)?;
            if self.wal.is_none() {
                return Ok(state);
            }
            let gen = st.states.entry(sid.to_string()).or_insert(0);
            *gen += 1;
            let gen = *gen;
            let v = match ticket {
                // the session's latest snapshot, not only this call's own: the state carries the
                // session's meter as it is now (sequentially, that is the reserved one)
                Some(t) if t.expect == charge_amsat => self.covering(&mut st, sid),
                // the durable meter must not keep a projection the call did not bill
                _ => self.submit(&mut st, sid),
            };
            (state, v.map(|v| (v, gen)))
        };
        let (Some((v, gen)), Some(wal)) = (v, &self.wal) else { return Ok(state) };
        if let Err(e) = wal.wait(v, WAL_WAIT) {
            let mut st = self.lock();
            // taken back only while no later state carries it (a later answer's snapshot may be
            // durable and hold it: taking it back would make the next state go backwards); it then
            // stays billed, like a call in flight at a crash
            if st.states.get(sid) == Some(&gen) {
                if let Some(s) = st.sessions.get_mut(sid) {
                    s.accrued_amsat -= charge_amsat;
                    s.calls = s.calls.saturating_sub(1);
                    if s.owed_amsat() <= 0 {
                        s.unpaid_since = 0.0;
                    }
                }
            }
            return Err(e);
        }
        Ok(state)
    }

    /// The ROUTE-STATE a refused call's 402 carries, once a snapshot covering it is durable (the
    /// refused call's seq was taken, and a concurrent call may be metered in memory). None when the
    /// RouteWal cannot make it durable: the 402 then carries no state.
    pub fn refusal_state(&self, sid: &str) -> Option<Value> {
        let (state, v) = {
            let mut st = self.lock();
            let state = self.state_locked(&mut st, sid, 0).ok()?;
            if self.wal.is_none() {
                return Some(state);
            }
            *st.states.entry(sid.to_string()).or_insert(0) += 1;
            (state, self.covering(&mut st, sid))
        };
        match (v, &self.wal) {
            (Some(v), Some(wal)) => wal.wait(v, WAL_WAIT).ok().map(|_| state),
            _ => Some(state),
        }
    }

    fn lock_answer(&self, st: &SellerState, chan: &str, routed: u64, lock_id: &str, rec: &Value) -> Value {
        let sid = py_str(rec.get("session"));
        let paid = st.sessions.get(&sid).map(|s| Value::from(s.paid_sat)).unwrap_or(Value::Null);
        json!({"lockId": lock_id, "secret": rec["secret"], "cum": py_str(rec.get("cum")), "chan": chan, "routedSat": routed,
               "session": state_sign(&self.secret, &json!({"session": sid, "lockId": lock_id, "amount": rec["amount"], "paidSat": paid}))})
    }
}

// --- the provider's routing endpoints --------------------------------------------------------------

fn err_json(status: u16, code: &str, detail: &str) -> HttpResponse {
    HttpResponse::new(status, vec![("Content-Type".into(), "application/json".into())], dumps(&json!({"error": code, "detail": detail})))
}

impl Provider {
    /// Sell `path` through hubs. Its 402 carries `extra.route` (the signed price quote and, for a
    /// client that names its route key in `ROUTE-CLIENT`, a session with a fresh lock point T per
    /// window). Calls carry ROUTE-AUTH and are metered in amsat; each window's accrued amount is
    /// paid by one adaptor-locked ch2 state from a hub.
    pub fn offer_route(&self, offer: RouteOffer) {
        let mut st = self.routes.lock();
        st.quotes.remove(&offer.path);
        st.offers.insert(offer.path.clone(), offer);
    }

    /// Tests/demo: stop revealing t (take locks and hold them), or resume.
    pub fn set_no_reveal(&self, on: bool) {
        self.routes.lock().no_reveal = on;
    }

    /// Close `chan` now with its best state (an operator's unilateral close; the watcher does the
    /// same at the close margin). Returns the close txid.
    pub fn close_now(&self, chan: &str) -> Result<String> {
        let cid = crate::channel::canonical_chan(chan)?;
        let mut l = self.ledger_lock();
        let mut st = l.channels.get(&cid).cloned().ok_or_else(|| ChannelError::code("unknown_channel"))?;
        let r = self.close_locked(&mut l, &mut st);
        l.channels.insert(cid, st);
        r
    }

    /// The payee's own 0x21 signature for `chan`'s state paying `cum` (the provider can always
    /// sign its half; tests use it to show a held pre-signature cannot complete a close).
    #[doc(hidden)]
    pub fn payee_sign_state(&self, chan: &str, cum: u64) -> Result<Vec<u8>> {
        let st = self.channel_state(chan).ok_or_else(|| ChannelError::code("unknown_channel"))?;
        let tx = st.params.state_tx(cum)?;
        Ok(crate::channel::sign_with_type(&self.chan_secret(&st.params)?, &st.params.sighash(&tx)?, SIGHASH_ALL_UNIFIED))
    }

    /// The routing book (sessions, held locks).
    pub fn routes(&self) -> &RouteSeller {
        &self.routes
    }

    /// Complete one adaptor-locked ch2 state (the ledger lock is held by the caller, and the hub's
    /// channel auth has passed). Checks the lock, completes it with the window's t, saves the plain
    /// state write-ahead, and only then credits the session and returns t.
    ///
    /// ch2's cumulative amount is `next_cum(routed, d, min_amount)`: the routed total with the
    /// channel's floor, which the hub pre-pays once per channel and later locks use up. A lock the
    /// floor covers needs no new state (and carries no adaptor). A lockId completed before is
    /// answered again with the same t.
    pub(crate) fn complete_lock(&self, l: &mut Ledger, st: &mut ChannelState, pl: &Value, route: &Value) -> Result<Value> {
        let bad = |m: &str| ChannelError::new("bad_payload", m.to_string());
        let sid = route.get("session").map(|v| py_str(Some(v))).ok_or_else(|| bad("'session'"))?;
        let lock_id = route.get("lockId").map(|v| py_str(Some(v))).ok_or_else(|| bad("'lockId'"))?;
        let amount = py_int(route.get("amount")).ok_or_else(|| bad("'amount'"))?;
        let point = pl.get("point").map(|v| py_str(Some(v)).to_lowercase()).ok_or_else(|| bad("'point'"))?;
        let auth = route.get("lockAuth").map(|v| py_str(Some(v))).ok_or_else(|| bad("'lockAuth'"))?;
        let hub = route.get("hub").map(|v| py_str(Some(v))).ok_or_else(|| bad("'hub'"))?;
        let cum = py_int(pl.get("cum")).ok_or_else(|| bad("'cum'"))?;
        let chan = st.params.channel_id();
        let mut locks = st.extra.get("route_locks").and_then(Value::as_object).cloned().unwrap_or_default();
        let routes = &self.routes;
        let mut rs = routes.lock();
        if let Some(done) = locks.get(&lock_id) {
            // idempotent: the same answer again
            if py_str(done.get("session")) != sid || py_int(done.get("amount")) != Some(amount) {
                return fail("bad_invoice", "lockId already completed with other terms");
            }
            let routed = py_u64(st.extra.get("routed_sat")).unwrap_or(0);
            return Ok(routes.lock_answer(&rs, &chan, routed, &lock_id, done));
        }
        let s = rs.sessions.get(&sid).cloned().ok_or_else(|| ChannelError::code("unknown_session"))?;
        let o = rs.offers.get(&s.path).ok_or_else(|| ChannelError::code("unknown_session"))?;
        let (hubs, ttl) = (o.hubs.clone(), o.invoice_ttl);
        if lock_id != s.lock_id || point != s.point {
            return fail("bad_invoice", "not this session's open invoice");
        }
        if now_f() > s.valid_until {
            return fail("bad_invoice", "invoice expired: a fresh point is in the next ROUTE-STATE");
        }
        if st.extra.get("hub").map(|v| py_str(Some(v))).unwrap_or_default() != hub {
            return fail("route_blocked", "this channel is not that hub's");
        }
        if !hubs_accept(&hubs, &hub) {
            return fail("route_blocked", "hub not accepted by this provider");
        }
        let key = routes.key(&mut rs, &sid)?;
        if !auth_eq(&lock_auth(&key, &sid, &lock_id, amount, &point, &hub), &auth) {
            return fail("bad_auth", "the client did not authorise this amount for this invoice");
        }
        if amount < 1 {
            return fail("bad_amount", "lock amount must be >= 1 sat");
        }
        let amount = u64::try_from(amount).map_err(|_| ChannelError::new("bad_amount", "lock amount out of range"))?;
        if rs.no_reveal {
            rs.held.push(json!({"lockId": lock_id, "cum": cum.to_string().parse::<u64>().ok(), "pre": pl.get("adaptor"), "chan": chan}));
            return Ok(json!({"held": lock_id}));
        }
        let routed = py_u64(st.extra.get("routed_sat")).unwrap_or(0);
        let need = next_cum(routed, amount, st.params.min_amount());
        let mut sig = Vec::new();
        if need <= st.best_cum {
            if cum != st.best_cum as i128 || pl.get("adaptor").is_some_and(|a| crate::json::truthy(Some(a))) {
                return fail("bad_amount", format!("the dust floor covers this lock: cum {}, no adaptor", st.best_cum));
            }
        } else {
            if cum != need as i128 {
                return fail("bad_amount", format!("lock pays {cum}, expected {need}"));
            }
            if need > st.params.max_amount() {
                return fail("channel_exhausted", "");
            }
            let pre = PreSig::from_json(pl.get("adaptor").unwrap_or(&Value::Null))?;
            let z = st.params.sighash(&st.params.state_tx(need)?)?;
            if !adaptor::preverify(&st.params.payer_pub, &z, &adaptor::dec_hex(&point)?, &pre) {
                return fail("bad_adaptor", "pre-signature does not verify under the invoice point");
            }
            let t = Sc::from_hex64(&s.t).and_then(|t| t.secret()).ok_or_else(|| ChannelError::new("bad_state", "window secret"))?;
            sig = adaptor::adapt(&pre, &t)?;
            sig.push(SIGHASH_ALL_UNIFIED);
            // an ordinary 0x21 state from here on
            self.payee(st)?.accept(need, &sig)?;
        }
        // write-ahead (M8): the plain state and the lock record are on disk before t leaves
        let rec = json!({"session": sid, "amount": amount, "cum": need.max(st.best_cum), "secret": s.t, "at": round3(now_f())});
        locks.insert(lock_id.clone(), rec.clone());
        while locks.len() > ROUTE_LOCKS_KEPT {
            let first = locks.keys().next().cloned().unwrap_or_default();
            locks.remove(&first);
        }
        if !sig.is_empty() {
            st.best_cum = need;
            st.best_sig = hex::encode(&sig);
        }
        st.extra.insert("route_locks".into(), Value::Object(locks));
        st.extra.insert("routed_sat".into(), (routed + amount).into());
        st.extra.insert("max_lock".into(), py_u64(st.extra.get("max_lock")).unwrap_or(0).max(amount).into());
        self.save_state(l, st)?;
        let sess = rs.sessions.get_mut(&sid).ok_or_else(|| ChannelError::code("unknown_session"))?;
        sess.paid_sat += amount;
        sess.locks += 1;
        sess.last_lock = json!({"lockId": lock_id, "amount": amount, "secret": s.t});
        sess.unpaid_since = if sess.owed_amsat() > 0 { now_f() } else { 0.0 };
        RouteSeller::new_window(sess, ttl);
        routes.save(&mut rs)?;
        Ok(routes.lock_answer(&rs, &chan, routed + amount, &lock_id, &rec))
    }

    /// POST /x402/xbt-channel/lock: a hub's adaptor-locked state on its ch2 to us, authenticated
    /// like a paid call (the hub's channel HMAC covers the JSON body with the route terms).
    pub(crate) fn route_lock(&self, method: &str, bind: &str, headers: &[(String, String)], body: &[u8]) -> HttpResponse {
        let hdr = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-SIGNATURE")).map(|(_, v)| v.as_str()).unwrap_or("");
        let parsed = (|| -> Option<(Value, Value)> {
            let pl = unb64json(hdr).ok()?.get("payload")?.clone();
            let route = crate::json::parse_slice(body).ok()?.get("route")?.clone();
            (pl.is_object() && route.is_object()).then_some((pl, route))
        })();
        let Some((pl, route)) = parsed else { return err_json(400, "bad_payload", "") };
        let mut l = self.ledger_lock();
        let cid = pl.get("chan").and_then(Value::as_str).and_then(|c| crate::channel::canonical_chan(c).ok()).filter(|c| l.channels.contains_key(c));
        let Some(cid) = cid else { return err_json(400, "unknown_channel", "") };
        let mut st = l.channels[&cid].clone();
        if !self.authentic(&st, &pl, method, bind, body) {
            return err_json(401, "bad_auth", "");
        }
        st.seq = py_u64(pl.get("seq")).unwrap_or(st.seq);
        l.channels.insert(cid.clone(), st.clone());
        let height = match self.height() {
            Ok(h) => h,
            Err(e) => return err_json(500, "node_error", &e.to_string()),
        };
        if !st.closed_txid.is_empty() || height as i64 >= st.params.expiry as i64 - self.cfg.close_margin as i64 {
            return err_json(400, "channel_closing", "");
        }
        if st.suspended {
            // AGP-057: `suspended` is the watcher's last look, and a block that came during that look
            // leaves a rollover child suspended although it confirmed (the parent was then spent in a
            // block, so it was no zero-conf child either). A hub looks at the chain itself before it
            // sends a lock: so do we before refusing one on an unconfirmed child
            let pending = st.extra.get("zero_conf").is_some_and(|z| z.is_object() && !crate::json::truthy(z.get("confirmed")));
            if !(pending && matches!(self.zc_confirmed(&mut st, true), Ok(true))) {
                return err_json(400, "unconfirmed", "");
            }
            st.suspended = false;
            let _ = self.save_state(&mut l, &st);
        }
        if let Some(zc) = st.extra.get("zero_conf").filter(|z| z.is_object() && !crate::json::truthy(z.get("confirmed"))).cloned() {
            // AGP-053: an unconfirmed rollover child, taken up to its cap and before the parent's margin
            let Some(cum) = crate::json::py_int(pl.get("cum")) else { return err_json(400, "bad_payload", "") };
            let until = py_u64(zc.get("until")).unwrap_or(0);
            let max = py_u64(zc.get("maxCum")).unwrap_or(0);
            // past a bound: look at the chain first (it may have confirmed since the watcher's tick)
            if height as u64 >= until || cum > max as i128 {
                match self.zc_confirmed(&mut st, true) {
                    Ok(true) => {
                        let _ = self.save_state(&mut l, &st);
                    }
                    Ok(false) if height as u64 >= until => return err_json(400, "unconfirmed", "rollover unconfirmed at the parent's close margin"),
                    Ok(false) => return err_json(400, "zero_conf_cap", &format!("cum {cum} > {max} while the rollover is unconfirmed")),
                    Err(e) => return err_json(500, "node_error", &e.to_string()),
                }
            }
        }
        match self.complete_lock(&mut l, &mut st, &pl, &route) {
            Ok(out) => {
                l.channels.insert(cid, st);
                let status = if out.get("held").is_some() { 202 } else { 200 };
                HttpResponse::new(status, vec![("Content-Type".into(), "application/json".into())], dumps(&out))
            }
            Err(e) => {
                let _ = self.save_state(&mut l, &st);
                err_json(400, &e.code, &e.to_string())
            }
        }
    }

    /// A metered call on a routed path (ROUTE-AUTH, no PAYMENT-SIGNATURE).
    pub(crate) fn routed_call(&self, method: &str, path: &str, pk: &str, hdr: &str, body: &[u8], url: &str) -> HttpResponse {
        let refuse = |error: &str, sid: Option<&str>| {
            let mut doc = self.payment_required_doc(url, (self.price)(method, path), error, None);
            if let Ok(extra) = self.routes.route_extra(pk, "") {
                doc["accepts"][0]["extra"]["route"] = extra;
            }
            if let Some(s) = sid.and_then(|sid| self.routes.refusal_state(sid)) {
                doc["routeState"] = s;
            }
            self.required_response(&doc)
        };
        let sid = match self.routes.begin_call(pk, hdr, method, &crate::provider::binding_url(url, path), body) {
            Err(e) => return refuse(e, None),
            Ok((sid, Some(e))) => return refuse(e, Some(&sid)),
            Ok((sid, None)) => sid,
        };
        // AGP-054: with a RouteWal, the call's projected meter is written ahead while the handler runs
        let ticket = if self.routes.wal().is_some() {
            let expect = self.routes.lock().offers.get(pk).and_then(|o| o.expect(method, path, body));
            expect.and_then(|e| self.routes.reserve(&sid, e))
        } else {
            None
        };
        let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.handler)(method, path, body)));
        let mut resp = match run {
            Ok(r) => r,
            Err(p) => {
                self.routes.cancel(&sid, ticket);
                std::panic::resume_unwind(p);
            }
        };
        if resp.headers.iter().any(|(k, v)| k.contains(['\r', '\n', '\0']) || v.contains(['\r', '\n', '\0'])) {
            resp = HttpResponse::new(500, vec![], b"handler returned a header with CR/LF".to_vec());
        }
        let charge = {
            let rs = self.routes.lock();
            match rs.offers.get(pk) {
                Some(o) => match &o.charge {
                    Some(f) => f(method, path, resp.status, &resp.body),
                    None => o.amsat_per_call,
                },
                None => 0,
            }
        };
        let charge = if resp.status >= 500 { 0 } else { charge };
        match self.routes.end_call_reserved(&sid, charge, ticket) {
            Ok(state) => resp.headers.push(("ROUTE-STATE".into(), b64json(&state))),
            Err(e) if e.code == "route_wal_failed" => {
                return err_json(500, "route_wal_failed", "the route meter is not durable: this call is not billed")
            }
            Err(e) => return err_json(500, &e.code, &e.to_string()),
        }
        resp
    }

    /// The 402 for a routed path without ROUTE-AUTH: `extra.route`, with a new session when the
    /// request carries ROUTE-CLIENT.
    pub(crate) fn route_offer_402(&self, method: &str, path: &str, pk: &str, client: &str, url: &str) -> HttpResponse {
        let mut doc = self.payment_required_doc(url, (self.price)(method, path), "payment_required", None);
        match self.routes.route_extra(pk, client) {
            Ok(extra) => doc["accepts"][0]["extra"]["route"] = extra,
            Err(_) => return HttpResponse::new(400, vec![], b"bad ROUTE-CLIENT key".to_vec()),
        }
        self.required_response(&doc)
    }
}

/// A lock answer's `secret` opens `point` (t·G == T)?
pub fn secret_opens(secret_hex: &str, point_hex: &str) -> Option<SecretKey> {
    let y = Sc::from_hex_mod_n(secret_hex)?.secret()?;
    let p = adaptor::dec_hex(point_hex).ok()?;
    (adaptor::point_of(&y) == p).then_some(y)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_json_round_trip() {
        let mut s = RouteSession { session: "s".into(), client_pub: "02".into(), path: "/p".into(), created: 1.5, seq: 3,
                                   accrued_amsat: 813_000_000_000_123_456_789 * 1000, paid_sat: 9, calls: 4, unpaid_since: 0.0,
                                   lock_id: "l".into(), t: "00".into(), point: "02".into(), valid_until: 7.25, last_lock: json!({}), locks: 1 };
        let v: Value = crate::json::parse(&dumps(&s.to_json())).unwrap();
        assert_eq!(RouteSession::from_json(&v).unwrap(), s);
        s.paid_sat = 10_000_000_000;
        assert!(s.owed_amsat() < 0);
    }
}
