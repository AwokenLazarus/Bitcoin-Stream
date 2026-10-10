//! Routed xbt402 payments (B2 `routing.py`, AGP-021): adaptor-locked channel states through a hub,
//! under the routing policy and the ordinary policy engine.
//!
//! policy.json `"routing": {"hubs": {"http://hub:port": {"max_fee_ppm", "max_fee_base_msat"}},
//! "max_lock_sats", "daily_budget_sats"}`. No section, or no hubs, means routing is off.
//!
//! Before an adaptor pre-signature: the hub is allowed, its fee is within that hub's caps (plus 1 sat
//! of carried remainder), the lock is within `max_lock_sats`, and the 24 h routed spend (resolved
//! locks plus pending ones) stays within `daily_budget_sats`; then the policy engine decides on the
//! increase as a payment to the hub. The crypto is the [`AdaptorScheme`] seam; [`Xbt402Adaptor`] is
//! xbt402's ECDSA adaptor (AGP-026, wire-compatible with B1 `adaptor.py`) and the signer's default.
use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value};

use xbt402::adaptor::{self, PreSig};
use xbt_primitives::secp256k1::{PublicKey, SecretKey};

use crate::applog::{replace_log, AppendLog};
use crate::channels::{AdaptorScheme, ChannelBook};
use crate::policy::{normalize_dest, Payment, PolicyEngine};
use crate::pyjson::{now_f64, py_int};
use crate::{err, Result};

pub const DAY_S: f64 = 86_400.0;

/// xbt402's ECDSA adaptor (DLEQ-proven pre-signatures in libsecp256k1, AGP-026): what B2 gets from
/// B1's `xbt402/adaptor.py`.
#[derive(Debug, Default, Clone, Copy)]
pub struct Xbt402Adaptor;

impl AdaptorScheme for Xbt402Adaptor {
    fn presign(&self, secret: &SecretKey, z: &[u8; 32], t1: &PublicKey) -> Result<Value> {
        Ok(adaptor::presign(secret, z, t1)?.to_json())
    }

    fn extract(&self, pre: &Value, sig: &[u8], t1: &PublicKey) -> Option<[u8; 32]> {
        adaptor::extract(&PreSig::from_json(pre).ok()?, sig, t1).map(|y| y.secret_bytes())
    }
}

#[derive(Debug, Clone, Default)]
pub struct RoutePolicy {
    /// normalized hub origin -> (max_fee_ppm, max_fee_base_msat)
    pub hubs: Vec<(String, i64, i64)>,
    pub max_lock_sats: i64,
    pub daily_budget_sats: i64,
}

impl RoutePolicy {
    pub fn from_value(raw: &Map<String, Value>) -> Self {
        let mut hubs = vec![];
        for (h, v) in raw.get("hubs").and_then(Value::as_object).into_iter().flatten() {
            let d = normalize_dest(h);
            if !d.is_empty() {
                hubs.push((d, py_int(v.get("max_fee_ppm")).unwrap_or(0), py_int(v.get("max_fee_base_msat")).unwrap_or(0)));
            }
        }
        Self { hubs, max_lock_sats: py_int(raw.get("max_lock_sats")).unwrap_or(0), daily_budget_sats: py_int(raw.get("daily_budget_sats")).unwrap_or(0) }
    }

    pub fn enabled(&self) -> bool {
        !self.hubs.is_empty() && self.max_lock_sats > 0 && self.daily_budget_sats > 0
    }

    fn hub(&self, hub: &str) -> Option<(i64, i64)> {
        let d = normalize_dest(hub);
        self.hubs.iter().find(|(h, _, _)| *h == d).map(|(_, p, b)| (*p, *b))
    }

    pub fn public(&self) -> Value {
        let hubs: Map<String, Value> = self.hubs.iter().map(|(h, p, b)| (h.clone(), json!({"max_fee_ppm": p, "max_fee_base_msat": b}))).collect();
        json!({"enabled": self.enabled(), "hubs": hubs, "max_lock_sats": self.max_lock_sats, "daily_budget_sats": self.daily_budget_sats})
    }

    /// The most this hub may charge for a lock of `amount` sat: its caps on the exact fee, plus
    /// 1 sat for the carried remainder.
    pub fn fee_cap_sat(&self, hub: &str, amount: i64) -> i64 {
        let (ppm, base) = self.hub(hub).unwrap_or((0, 0));
        let exact_msat = base + amount * 1000 * ppm / 1_000_000;
        (exact_msat + 999).div_euclid(1000) + 1
    }
}

/// Rows older than this are never read (the budget looks back 24 h).
pub const RETAIN_S: f64 = 7.0 * DAY_S;
/// Rows added between two prunes: a prune is O(rows), so it is not per lock.
pub const PRUNE_EVERY: usize = 1024;

struct Spend {
    rows: Vec<Value>,
    keys: HashSet<String>,
    log: Option<AppendLog>,
    unpruned: usize,
    prune_every: usize,
}

fn row_at(r: &Value) -> f64 {
    r.get("at").and_then(Value::as_f64).unwrap_or(0.0)
}

impl Spend {
    fn prune(&mut self, now: f64) -> Result<()> {
        self.unpruned = 0;
        self.rows.retain(|r| row_at(r) >= now - RETAIN_S);
        self.keys = self.rows.iter().filter_map(|r| r.get("key").and_then(Value::as_str)).filter(|k| !k.is_empty()).map(String::from).collect();
        if let Some(log) = &mut self.log {
            if log.file_rows > 2 * self.rows.len() + self.prune_every {
                log.compact(&self.rows)?;
            }
        }
        Ok(())
    }
}

/// Resolved routed spend, for the 24 h routing budget.
///
/// AGP-055 (as B2 `routing.py`, same file): an append-only log ([`crate::applog`]), one line and
/// one fsync per resolved lock; it used to be seven days of rows rewritten on every lock. Rows
/// older than [`RETAIN_S`] leave memory at a prune, and the file is compacted to the rows still in
/// memory once it holds over twice as many (plus [`PRUNE_EVERY`]). A file in the old format
/// (`{"resolved": [...]}`) is converted at open, in one rename.
pub struct RouteSpend {
    inner: Mutex<Spend>,
}

impl RouteSpend {
    /// Open the log at `path` (`None`: memory only). A file that cannot be read is an error, never
    /// an empty budget.
    pub fn open(path: Option<&Path>) -> Result<Self> {
        let mut spend = Spend { rows: vec![], keys: HashSet::new(), log: None, unpruned: 0, prune_every: PRUNE_EVERY };
        if let Some(p) = path {
            if let Some(old) = Self::legacy_rows(p)? {
                replace_log(p, "route-spend", &old)?;
            }
            let (log, rows) = AppendLog::open(p, "route-spend")?;
            for (i, r) in rows.iter().enumerate() {
                if r.get("at").and_then(Value::as_f64).is_none() || py_int(r.get("amount")).is_none() {
                    return Err(err("log", format!("{}: line {} is not a spend row", p.display(), i + 2)));
                }
            }
            (spend.log, spend.rows) = (Some(log), rows);
            spend.prune(now_f64())?;
        }
        Ok(Self { inner: Mutex::new(spend) })
    }

    /// The rows of a pre-AGP-055 file, or `None` when the file is absent or already a log.
    fn legacy_rows(p: &Path) -> Result<Option<Vec<Value>>> {
        if !p.exists() {
            return Ok(None);
        }
        let text = std::fs::read(p).map_err(|e| err("io", format!("{}: {e}", p.display())))?;
        // not one JSON document: the append-only log (opened strictly next)
        Ok(serde_json::from_slice::<Value>(&text).ok().and_then(|v| v.get("resolved").and_then(Value::as_array).cloned()))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Spend> {
        match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// Book a row. A row with a `"key"` this log already holds is not booked again (`false`).
    pub fn add(&self, row: Value) -> Result<bool> {
        let mut g = self.lock();
        let key = row.get("key").and_then(Value::as_str).filter(|k| !k.is_empty()).map(String::from);
        if key.as_ref().is_some_and(|k| g.keys.contains(k)) {
            return Ok(false);
        }
        if let Some(log) = &mut g.log {
            log.append(&row)?; // durable before it counts
        }
        g.rows.push(row);
        if let Some(k) = key {
            g.keys.insert(k);
        }
        g.unpruned += 1;
        if g.unpruned >= g.prune_every {
            g.prune(now_f64())?;
        }
        Ok(true)
    }

    pub fn since(&self, t: f64) -> i64 {
        self.lock().rows.iter().filter(|x| row_at(x) >= t).map(|x| py_int(x.get("amount")).unwrap_or(0)).sum()
    }

    /// Rows in memory (the retained window).
    pub fn len(&self) -> usize {
        self.lock().rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn deny(rule: &str, reason: String) -> Value {
    json!({"verdict": "deny", "rule": rule, "reason": reason})
}

/// `None` if the routing policy allows this lock, else a deny.
#[allow(clippy::too_many_arguments)] // public API: bundling the figures would change its signature
pub fn check_route(policy: &RoutePolicy, spend: &RouteSpend, hub: &str, amount: i64, fee: i64, increase: i64, pending: i64, now: f64) -> Option<Value> {
    if !policy.enabled() {
        return Some(deny("routing_disabled", "routing is off in this policy".into()));
    }
    if policy.hub(hub).is_none() {
        return Some(deny("route_hub", format!("{hub} is not an allowed hub")));
    }
    if amount < 1 || fee < 0 || increase < 1 {
        return Some(deny("route_amount", "a lock pays at least 1 sat".into()));
    }
    let cap = policy.fee_cap_sat(hub, amount);
    if fee > cap {
        return Some(deny("route_fee_cap", format!("fee {fee} sat > this hub's cap {cap} for {amount} sat")));
    }
    if increase > policy.max_lock_sats {
        return Some(deny("route_lock_max", format!("lock {increase} sat > max_lock_sats {}", policy.max_lock_sats)));
    }
    let spent = spend.since(now - DAY_S);
    if spent + pending + increase > policy.daily_budget_sats {
        return Some(deny("route_daily_budget", format!("routed spend {spent} + {increase} > daily_budget_sats {}", policy.daily_budget_sats)));
    }
    None
}

/// B2's `RouteSigner`: the routing policy on every adaptor lock, over the channel book.
pub struct RouteSigner {
    pub book: Arc<ChannelBook>,
    /// Live: a human-signed `policy_set` (AGP-039) swaps it. Read with [`RouteSigner::policy`].
    policy: std::sync::RwLock<RoutePolicy>,
    pub spend: RouteSpend,
    pub engine: Option<Arc<PolicyEngine>>,
    pub adaptor: Option<Arc<dyn AdaptorScheme>>,
    pub denials: Mutex<Vec<Value>>,
    /// AGP-055: resolved locks booked at start because a crash had left them unbooked.
    pub recovered_bookings: usize,
}

impl RouteSigner {
    /// Opens the spend log, then books every resolved lock the book still remembers that has no
    /// row yet: a crash between a resolve reaching disk and its rows left the budgets short.
    pub fn new(book: Arc<ChannelBook>, policy: RoutePolicy, state_path: Option<&Path>, engine: Option<Arc<PolicyEngine>>,
               adaptor: Option<Arc<dyn AdaptorScheme>>) -> Result<Self> {
        let mut s = Self { book, policy: std::sync::RwLock::new(policy), spend: RouteSpend::open(state_path)?, engine, adaptor,
                           denials: Mutex::new(vec![]), recovered_bookings: 0 };
        let cutoff = now_f64() - RETAIN_S;
        let in_ledger: HashSet<String> = match &s.engine {
            Some(e) => e.store.payments()?.into_iter().map(|p| p.txid).collect(),
            None => HashSet::new(),
        };
        for (chan, b) in s.book.resolved_bookings() {
            if b.get("at").and_then(Value::as_f64).unwrap_or(0.0) >= cutoff && s.book_lock(&chan, &b, None, Some(&in_ledger))? {
                s.recovered_bookings += 1;
            }
        }
        Ok(s)
    }

    /// Book a resolved lock in the 24 h routing budget and the policy ledger, under its key. A lock
    /// resolves once, so a live call (`in_ledger` `None`) always writes both rows. At start the
    /// record's remembered locks come through here again: the spend log skips a key it holds, and
    /// `in_ledger` (the ledger's txids) skips a payment it holds. `true` if anything was written.
    fn book_lock(&self, chan: &str, b: &Value, how: Option<&str>, in_ledger: Option<&HashSet<String>>) -> Result<bool> {
        let key = b.get("key").and_then(Value::as_str).unwrap_or("");
        let (amount, at) = (py_int(b.get("amount")).unwrap_or(0), b.get("at").and_then(Value::as_f64).unwrap_or(0.0));
        if key.is_empty() {
            return Err(err("io", "a resolved lock without its booking key"));
        }
        let mut row = json!({"at": b.get("at").cloned().unwrap_or(Value::Null), "amount": amount, "chan": chan,
                             "lockId": b.get("lockId").cloned().unwrap_or("".into()), "key": key});
        if let Some(h) = how {
            row[h] = true.into();
        }
        let mut wrote = self.spend.add(row)?;
        if let Some(engine) = &self.engine {
            if !in_ledger.is_some_and(|l| l.contains(key)) {
                let hub = b.get("hub").and_then(Value::as_str).filter(|h| !h.is_empty()).unwrap_or(chan);
                let mut p = Payment::new(&normalize_dest(hub), amount, "routed lock");
                p.ts = at;
                engine.commit(&p, key)?;
                wrote = true;
            }
        }
        Ok(wrote)
    }

    pub fn policy(&self) -> RoutePolicy {
        self.policy.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn set_policy(&self, p: RoutePolicy) {
        *self.policy.write().unwrap_or_else(|e| e.into_inner()) = p;
    }

    fn dest(&self, chan: &str) -> Result<String> {
        self.book.find_dest(chan).ok_or_else(|| err("unknown_channel", chan.to_string()))
    }

    fn scheme(&self) -> Result<Arc<dyn AdaptorScheme>> {
        self.adaptor.clone().ok_or_else(|| err("adaptor_unavailable",
            "this signer has no ECDSA adaptor implementation (xbt402 routing, AGP-026): routed locks are refused"))
    }

    /// Pending routed amount on every channel of the book.
    pub fn pending_sats(&self) -> i64 {
        self.book.unsettled_records().iter().filter(|r| r.has_pending_lock())
            .map(|r| py_int(r.pending_lock.get("cum")).unwrap_or(0) - py_int(r.pending_lock.get("prev_used")).unwrap_or(0)).sum()
    }

    pub fn sign_state_adaptor(&self, chan: &str, cum: i64, point: &str, route: Value) -> Result<Value> {
        let mut route = match route {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        let dest = self.dest(chan)?;
        let rec = self.book.get(&dest).ok_or_else(|| err("unknown_channel", chan.to_string()))?;
        let hub = route.get("hub").and_then(Value::as_str).filter(|h| !h.is_empty()).map(str::to_string)
            .unwrap_or_else(|| if rec.origin.is_empty() { dest.clone() } else { rec.origin.clone() });
        let increase = cum - rec.used_sats;
        let mut denied = check_route(&self.policy(), &self.spend, &hub, py_int(route.get("amount")).unwrap_or(0),
                                     py_int(route.get("fee")).unwrap_or(0), increase, self.pending_sats(), now_f64());
        if denied.is_none() {
            if let Some(engine) = &self.engine {
                let lock_id = route.get("lockId").and_then(Value::as_str).unwrap_or("").to_string();
                let d = engine.evaluate(&Payment::new(&normalize_dest(&hub), increase, &format!("routed lock {lock_id}")), false)?;
                if !d.allowed() {
                    denied = Some(d.as_value());
                }
            }
        }
        if let Some(d) = denied {
            if let Ok(mut v) = self.denials.lock() {
                v.push(d.clone());
            }
            return Err(err(d["rule"].as_str().unwrap_or("deny"), d["reason"].as_str().unwrap_or("").to_string()));
        }
        let scheme = self.scheme()?;
        route.insert("hub".into(), hub.into());
        self.book.sign_state_adaptor(&dest, cum, point, Value::Object(route), &*scheme)
    }

    pub fn resolve_lock(&self, chan: &str, secret: &str) -> Result<String> {
        let res = self.book.resolve_lock(&self.dest(chan)?, secret)?;
        self.book_lock(chan, &res["booking"], None, None)?;
        Ok(res["t"].as_str().unwrap_or("").to_string())
    }

    pub fn void_lock(&self, chan: &str) -> Result<Value> {
        self.book.void_lock(&self.dest(chan)?)
    }

    pub fn adopt_lock(&self, chan: &str, cum: i64) -> Result<()> {
        let res = self.book.adopt_lock(&self.dest(chan)?, cum)?;
        let amount = py_int(res.get("amount")).unwrap_or(0);
        if amount != 0 {
            self.book_lock(chan, &res["booking"], Some("adopted"), None)?;
        }
        Ok(())
    }

    pub fn recover_lock(&self, chan: &str, witness: &[Vec<u8>]) -> Result<String> {
        let scheme = self.scheme()?;
        let res = self.book.recover_lock(&self.dest(chan)?, witness, &*scheme)?;
        self.book_lock(chan, &res["booking"], Some("recovered"), None)?;
        Ok(res["t"].as_str().unwrap_or("").to_string())
    }

    pub fn status(&self) -> Value {
        let pending: Map<String, Value> = self.book.unsettled_records().into_iter().filter(|r| r.has_pending_lock())
            .map(|r| (r.chan.clone(), json!({"cum": r.pending_lock["cum"], "route": r.pending_lock.get("route")}))).collect();
        json!({"policy": self.policy().public(), "spent_24h_sats": self.spend.since(now_f64() - DAY_S), "pending": pending,
               "adaptor": if self.adaptor.is_some() { "available" } else { "unavailable (AGP-026)" }})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsx::probe;

    fn crashing<T>(step: u64, f: impl FnOnce() -> T) -> Option<T> {
        probe::crash_at(step, true);
        let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        probe::reset();
        match out {
            Ok(v) => Some(v),
            Err(e) if e.is::<probe::Crash>() => None,
            Err(e) => std::panic::resume_unwind(e),
        }
    }

    #[test]
    fn add_appends_one_line_with_one_fsync_and_no_rename_and_a_key_books_once() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("routing.json");
        let s = RouteSpend::open(Some(&p)).unwrap();
        let now = now_f64();
        assert!(s.add(json!({"at": now, "amount": 5, "chan": "c", "key": "lock:c:5"})).unwrap());
        let size = std::fs::metadata(&p).unwrap().len() as usize;
        probe::reset();
        assert!(s.add(json!({"at": now, "amount": 6, "chan": "c", "key": "lock:c:11"})).unwrap());
        let c = probe::counts();
        assert_eq!((c.writes, c.syncs, c.renames), (1, 1, 0));
        assert!(!s.add(json!({"at": now, "amount": 6, "chan": "c", "key": "lock:c:11"})).unwrap(), "the same key again");
        assert_eq!(probe::counts(), c, "nothing written for it");
        assert_eq!(std::fs::read(&p).unwrap()[size..], crate::applog::line(&json!({"at": now, "amount": 6, "chan": "c", "key": "lock:c:11"})));
        drop(s);
        let again = RouteSpend::open(Some(&p)).unwrap();
        assert_eq!(again.since(now - 1.0), 11);
        assert!(!again.add(json!({"at": now, "amount": 5, "chan": "c", "key": "lock:c:5"})).unwrap(), "keys survive a restart");
    }

    #[test]
    fn old_format_is_converted_once_and_a_crash_in_between_keeps_every_row() {
        let now = now_f64();
        let old = json!({"resolved": [{"at": now - 10.0, "amount": 3, "chan": "c"}, {"at": now - 5.0, "amount": 4, "chan": "c"}]});
        let mut step = 0;
        loop {
            let d = tempfile::tempdir().unwrap();
            let p = d.path().join("routing.json");
            std::fs::write(&p, crate::pyjson::dumps(&old)).unwrap();
            let done = crashing(step, || drop(RouteSpend::open(Some(&p)).unwrap())).is_some();
            assert_eq!(RouteSpend::open(Some(&p)).unwrap().since(now - DAY_S), 7, "step {step}");
            if done {
                assert!(std::fs::read(&p).unwrap().starts_with(&crate::applog::header("route-spend")));
                break;
            }
            step += 1;
        }
        assert!(step > 2);
    }

    #[test]
    fn a_file_that_cannot_be_read_is_an_error_not_an_empty_budget() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("routing.json");
        for bad in ["{\"kind\":\"route-spend\",\"v\":1}\n{\"at\": 1\n{\"at\":2.0,\"amount\":1}\n", "{\"kind\":\"route-spend\",\"v\":1}\n{\"amount\":1}\n", "not json\n"] {
            std::fs::write(&p, bad).unwrap();
            assert_eq!(RouteSpend::open(Some(&p)).err().map(|e| e.code), Some("log".to_string()), "{bad:?}");
        }
    }

    #[test]
    fn the_window_is_bounded_and_the_file_is_compacted() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("routing.json");
        let now = now_f64();
        let s = RouteSpend::open(Some(&p)).unwrap();
        s.lock().prune_every = 8;
        for _ in 0..40 {
            s.add(json!({"at": now - 8.0 * DAY_S, "amount": 1, "chan": "old"})).unwrap(); // outside the 7 day window
        }
        for _ in 0..12 {
            s.add(json!({"at": now, "amount": 10, "chan": "new"})).unwrap();
        }
        assert_eq!(s.len(), 12, "memory: the window only");
        let lines = std::fs::read_to_string(&p).unwrap().lines().count() - 1;
        assert!((12..=2 * 12 + 8).contains(&lines), "file: compacted, at most 2 x live + the prune interval ({lines})");
        drop(s);
        std::fs::write(&p, [std::fs::read(&p).unwrap().as_slice(), b"{\"at\": 1"].concat()).unwrap(); // a torn row
        assert_eq!(RouteSpend::open(Some(&p)).unwrap().since(now - DAY_S), 120);
    }
}
