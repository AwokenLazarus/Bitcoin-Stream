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
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value};

use xbt402::adaptor::{self, PreSig};
use xbt_primitives::secp256k1::{PublicKey, SecretKey};

use crate::channels::{AdaptorScheme, ChannelBook};
use crate::policy::{normalize_dest, Payment, PolicyEngine};
use crate::pyjson::{dumps, now_f64, py_int, ts_value};
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

/// Resolved routed spend (fsynced JSON `{"resolved": [...]}`), for the 24 h routing budget.
pub struct RouteSpend {
    path: Option<PathBuf>,
    rows: Mutex<Vec<Value>>,
}

impl RouteSpend {
    pub fn open(path: Option<&Path>) -> Self {
        let rows = path.and_then(|p| std::fs::read_to_string(p).ok()).and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|v| v.get("resolved").and_then(Value::as_array).cloned()).unwrap_or_default();
        Self { path: path.map(Path::to_path_buf), rows: Mutex::new(rows) }
    }

    pub fn add(&self, row: Value) {
        let mut rows = match self.rows.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        rows.push(row);
        let cutoff = now_f64() - 7.0 * DAY_S;
        rows.retain(|r| r.get("at").and_then(Value::as_f64).unwrap_or(0.0) >= cutoff);
        if let Some(p) = &self.path {
            let tmp = p.with_extension("tmp");
            if std::fs::write(&tmp, dumps(&json!({"resolved": *rows}))).is_ok() {
                if let Ok(f) = std::fs::File::open(&tmp) {
                    let _ = f.sync_all();
                }
                let _ = std::fs::rename(&tmp, p);
            }
        }
    }

    pub fn since(&self, t: f64) -> i64 {
        self.rows.lock().map(|r| r.iter().filter(|x| x.get("at").and_then(Value::as_f64).unwrap_or(0.0) >= t)
            .map(|x| py_int(x.get("amount")).unwrap_or(0)).sum()).unwrap_or(0)
    }
}

fn deny(rule: &str, reason: String) -> Value {
    json!({"verdict": "deny", "rule": rule, "reason": reason})
}

/// `None` if the routing policy allows this lock, else a deny.
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
}

impl RouteSigner {
    pub fn new(book: Arc<ChannelBook>, policy: RoutePolicy, state_path: Option<&Path>, engine: Option<Arc<PolicyEngine>>,
               adaptor: Option<Arc<dyn AdaptorScheme>>) -> Self {
        Self { book, policy: std::sync::RwLock::new(policy), spend: RouteSpend::open(state_path), engine, adaptor, denials: Mutex::new(vec![]) }
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
        let amount = py_int(res.get("amount")).unwrap_or(0);
        let route = res.get("route").cloned().unwrap_or(json!({}));
        self.spend.add(json!({"at": ts_value(now_f64()), "amount": amount, "chan": chan, "lockId": route.get("lockId").cloned().unwrap_or("".into())}));
        if let Some(engine) = &self.engine {
            let hub = route.get("hub").and_then(Value::as_str).filter(|h| !h.is_empty()).unwrap_or(chan);
            engine.commit(&Payment::new(&normalize_dest(hub), amount, "routed lock"), chan)?;
        }
        Ok(res["t"].as_str().unwrap_or("").to_string())
    }

    pub fn void_lock(&self, chan: &str) -> Result<Value> {
        self.book.void_lock(&self.dest(chan)?)
    }

    pub fn adopt_lock(&self, chan: &str, cum: i64) -> Result<()> {
        let res = self.book.adopt_lock(&self.dest(chan)?, cum)?;
        let amount = py_int(res.get("amount")).unwrap_or(0);
        if amount != 0 {
            self.spend.add(json!({"at": ts_value(now_f64()), "amount": amount, "chan": chan, "adopted": true}));
        }
        Ok(())
    }

    pub fn recover_lock(&self, chan: &str, witness: &[Vec<u8>]) -> Result<String> {
        let scheme = self.scheme()?;
        let res = self.book.recover_lock(&self.dest(chan)?, witness, &*scheme)?;
        self.spend.add(json!({"at": ts_value(now_f64()), "amount": res["amount"], "chan": chan, "recovered": true}));
        Ok(res["t"].as_str().unwrap_or("").to_string())
    }

    pub fn status(&self) -> Value {
        let pending: Map<String, Value> = self.book.unsettled_records().into_iter().filter(|r| r.has_pending_lock())
            .map(|r| (r.chan.clone(), json!({"cum": r.pending_lock["cum"], "route": r.pending_lock.get("route")}))).collect();
        json!({"policy": self.policy().public(), "spent_24h_sats": self.spend.since(now_f64() - DAY_S), "pending": pending,
               "adaptor": if self.adaptor.is_some() { "available" } else { "unavailable (AGP-026)" }})
    }
}
