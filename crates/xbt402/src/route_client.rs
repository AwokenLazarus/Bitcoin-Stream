//! `RoutePayer`: pay many xbt402 providers through one hub channel (a port of B1
//! `xbt402/route_client.py`, AGP-021).
//!
//! ```text
//! let payer = Arc::new(RoutePayer::new(hub_url, cfg, signer, wallet, transport, height));
//! payer.open()?;                                  // one ch1 to the hub, whatever the number of shards
//! let a = payer.shard("http://shard-a:port/forward", "POST")?;   // signed price quote + first invoice
//! payer.start(window / 2);                        // per-window locks, serial on ch1, off the data path
//! let r = payer.call(&a, "POST", chunk)?;         // data calls go straight to the provider
//! payer.stop(); payer.close()?;                   // cooperative close of ch1 (the hub closes it)
//! ```
//!
//! Data calls carry ROUTE-AUTH (an HMAC under a client ↔ provider ECDH key the hub never sees) and
//! come back with a provider-signed ROUTE-STATE: the running meter in amsat, what the provider has
//! been paid, the open invoice (a fresh lock point T per window) and the last lock's t. So the
//! client:
//! * never waits on routing per chunk: chunks run on the provider's credit window;
//! * pays each window's accrued amount as the ceil of the running total minus what is already paid
//!   (the carry) with one adaptor lock per provider, one after another on ch1;
//! * gets its receipt from the hub (t + r) or, if the hub withholds it, from the provider (t);
//! * gives a lock up when the hub refuses it, or when its invoice expires unanswered: the lock can
//!   then cost at most its own amount (one window of one provider), and a later state dominates it.
//!
//! Keys stay behind [`RouteSigner`] (the [`crate::signer::StateSigner`] seam plus the adaptor lock
//! methods): [`crate::signer::LocalSigner`] in process, or `xbt-signer`'s `RemoteSigner` (the B2
//! signer and its routing policy, keys never in the client). ch1 is funded by a [`Wallet`].
//!
//! Restarts (AGP-044): with a [`RouteLedger`] ([`RoutePayer::with_ledger`]) the payer keeps ch1, its
//! counters, the given-up locks, the pending lock and every shard session in the ledger, and a new
//! process resumes mid-stream from it: the same ch1, the same sessions (the providers' meters go on),
//! the pending lock sent again (the hub answers a lock it completed with its saved answer). The
//! ledger holds no payer key, signature or refund: those stay in the signer (`xbt-signer`, or the
//! caller's [`crate::signer::LocalSigner`] that outlives the payer). It does hold each session's
//! call-auth key (the client ↔ provider HMAC key, as [`crate::client::FileClientLedger`] holds a
//! channel's `auth_key`): it can make metered calls on that session, never sign a state.
//! * write-ahead: a lock (with its seq) before its request leaves; a block of call seqs
//!   ([`SEQ_RESERVE`]) before the first of them leaves;
//! * a shard's meters are saved after every `persist_every` answered calls; calls a crash left
//!   unanswered (at most the reserved seqs not answered) are *in doubt*: the provider's next signed
//!   running total may exceed our meter by at most their count × the quoted price, and that gap is
//!   adopted (event `meter_adopted`), so the meters end exact;
//! * a presigned lock the ledger never recorded never left: [`RoutePayer::with_ledger`] voids it in
//!   the signer; a lock the signer resolved just before a crash is committed on its secret alone.
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use indexmap::IndexMap;
use serde_json::{json, Value};
use xbt_primitives::address::segwit_address;
use xbt_primitives::ecdsa;

use crate::adaptor::{self, Sc};
use crate::channel::{ChannelParams, FeePayer, DERIVATION};
use crate::client::{split_url, ClientLedger, HeightFn, Transport, Wallet};
use crate::error::{fail, ChannelError, Result};
use crate::json::{dumps, py_str, py_u64, truthy};
use crate::provider::HttpResponse;
use crate::route::*;
use crate::signer::RouteSigner;
use crate::wire::*;

fn lk<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Where a [`RoutePayer`] keeps its state across restarts (AGP-044): records under string keys,
/// `"ch1"`, `"book"`, `"pending"` and `"shard <url>"`, `null` removing a key. The same store as a
/// [`ClientLedger`] (every `ClientLedger` is a `RouteLedger`): [`FileRouteLedger`] and
/// [`MemoryRouteLedger`] are provided.
pub trait RouteLedger: Send + Sync {
    /// The latest record per key (no `null`s).
    fn load(&self) -> Result<Vec<(String, Value)>>;
    /// Save these records together, durably before returning.
    fn save(&self, records: &[(String, Value)]) -> Result<()>;
}

impl<T: ClientLedger + ?Sized> RouteLedger for T {
    fn load(&self) -> Result<Vec<(String, Value)>> {
        ClientLedger::load(self)
    }

    fn save(&self, records: &[(String, Value)]) -> Result<()> {
        ClientLedger::save(self, records)
    }
}

/// A [`RouteLedger`] file (JSON lines, fsynced, compacted; mode 0600).
pub type FileRouteLedger = crate::client::FileClientLedger;
/// A [`RouteLedger`] in memory (tests; a caller that persists elsewhere).
pub type MemoryRouteLedger = crate::client::MemoryClientLedger;

/// Call seqs reserved (written ahead) per ledger save: a restarted payer starts past them.
pub const SEQ_RESERVE: u64 = 16;

/// RoutePayer settings (the reference's keywords).
#[derive(Debug, Clone)]
pub struct RoutePayerConfig {
    pub network: String,
    pub capacity: u64,
    pub expiry_blocks: u32,
    pub max_fee_ppm: u64,
    pub max_fee_base_msat: u64,
    pub max_lock_sat: u64,
    pub max_close_fee: u64,
    /// Seconds past an invoice's validUntil before its unanswered lock is given up.
    pub void_grace: f64,
    /// With a ledger: save a shard's meters every this many answered calls (1: every call; the
    /// calls in doubt after a crash grow with it).
    pub persist_every: u64,
}

impl RoutePayerConfig {
    pub fn new(network: &str) -> Self {
        Self { network: network.into(), capacity: 200_000, expiry_blocks: 8_000, max_fee_ppm: 10_000, max_fee_base_msat: 10_000,
               max_lock_sat: 50_000, max_close_fee: 2_000, void_grace: 1.0, persist_every: 1 }
    }
}

/// The mutable part of a shard session.
#[derive(Debug, Clone, Default)]
pub struct ShardState {
    pub seq: u64,
    pub invoice: Value,
    /// The provider's signed running total.
    pub accrued_amsat: u128,
    /// The sum of the per-call charges we were shown.
    pub seen_amsat: u128,
    /// What the provider says it has been paid (signed).
    pub paid_sat: u64,
    /// What our completed locks paid it.
    pub locked_sat: u64,
    pub calls: u64,
    pub last_lock: Value,
    /// The lockId of the last lock we completed: an invoice is paid once. A ROUTE-STATE produced
    /// before that lock completed can still carry its invoice; locking it again would be answered
    /// with the hub's saved answer, which a floor lock (no T1 to check) would count twice.
    pub last_locked: String,
    /// Why the provider stopped serving us ("" while it serves).
    pub stopped: String,
    /// Calls that came back (a response, whatever its status).
    pub answered: u64,
    /// Call seqs written ahead in the ledger: a restart goes on after them.
    pub seq_hi: u64,
    /// After a restart: calls that may have been charged unseen (see the module doc).
    pub in_doubt: u64,
    pub call_ms: Vec<f64>,
    pub lock_ms: Vec<f64>,
}

/// One metered session on a routed path.
#[derive(Debug)]
pub struct Shard {
    pub url: String,
    pub origin: String,
    pub path: String,
    pub pay_to: String,
    pub session: String,
    key: [u8; 32],
    pub quote: PriceQuote,
    pub window: f64,
    pub lock_wait: f64,
    pub state: Mutex<ShardState>,
}

impl Shard {
    /// The client ↔ provider session key (ECDH; the hub never has it).
    #[doc(hidden)]
    pub fn session_key(&self) -> [u8; 32] {
        self.key
    }

    /// `ceil(accrued) − max(paid, locked)`: what the next lock pays.
    pub fn due_sat(&self) -> i128 {
        let s = lk(&self.state);
        ceil_div(s.accrued_amsat, AMSAT_PER_SAT) as i128 - s.paid_sat.max(s.locked_sat) as i128
    }

    pub fn snapshot(&self) -> ShardState {
        lk(&self.state).clone()
    }

    /// The ledger record (`key` is the session's call-auth key).
    fn to_json(&self) -> Value {
        let s = lk(&self.state);
        json!({"url": self.url, "origin": self.origin, "path": self.path, "pay_to": self.pay_to, "session": self.session,
               "key": hex::encode(self.key), "quote": self.quote.to_json(), "window": self.window, "lock_wait": self.lock_wait,
               "seq": s.seq, "seq_hi": s.seq_hi, "answered": s.answered, "invoice": s.invoice, "accrued_amsat": s.accrued_amsat.to_string(),
               "seen_amsat": s.seen_amsat.to_string(), "paid_sat": s.paid_sat, "locked_sat": s.locked_sat, "calls": s.calls,
               "last_lock": s.last_lock, "last_locked": s.last_locked, "stopped": s.stopped})
    }

    /// A shard back from its record: its next call goes after every seq written ahead, and the
    /// reserved seqs not answered are in doubt.
    fn from_json(v: &Value) -> Result<Self> {
        let bad = |k: &str| ChannelError::new("ledger_error", format!("shard record: {k}"));
        let st = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string).ok_or_else(|| bad(k));
        let n = |k: &str| py_u64(v.get(k)).ok_or_else(|| bad(k));
        let big = |k: &str| u128_of(v.get(k)).ok_or_else(|| bad(k));
        let key: [u8; 32] = hex::decode(st("key")?).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| bad("key"))?;
        let (seq_hi, answered) = (n("seq_hi")?.max(n("seq")?), n("answered")?);
        let state = ShardState { seq: seq_hi, invoice: v.get("invoice").cloned().unwrap_or(json!({})), accrued_amsat: big("accrued_amsat")?,
                                 seen_amsat: big("seen_amsat")?, paid_sat: n("paid_sat")?, locked_sat: n("locked_sat")?, calls: n("calls")?,
                                 last_lock: v.get("last_lock").cloned().unwrap_or(json!({})), last_locked: st("last_locked")?, stopped: st("stopped")?,
                                 answered, seq_hi, in_doubt: seq_hi.saturating_sub(answered), ..Default::default() };
        Ok(Self { url: st("url")?, origin: st("origin")?, path: st("path")?, pay_to: st("pay_to")?, session: st("session")?, key,
                  quote: PriceQuote::from_json(v.get("quote").ok_or_else(|| bad("quote"))?)?,
                  window: v.get("window").and_then(Value::as_f64).unwrap_or(1.0), lock_wait: v.get("lock_wait").and_then(Value::as_f64).unwrap_or(1.0),
                  state: Mutex::new(state) })
    }
}

struct Pending {
    id: u64,
    shard: Arc<Shard>,
    lock_id: String,
    d: u64,
    f: u64,
    units: u128,
    cum: u64,
    floor: bool,
    t: String,
    t1: String,
    until: f64,
    t0: Instant,
    inflight: bool,
    /// r (hex), the payer's tweak (T1 = T + r·G).
    tweak: String,
    /// The request as sent, without seq and auth: a restarted payer sends it again.
    pl: Value,
    body: String,
    /// Loaded from the ledger (a restart): the signer may have resolved it already.
    resumed: bool,
}

impl Pending {
    fn to_json(&self) -> Value {
        json!({"shard": self.shard.url, "lockId": self.lock_id, "d": self.d, "f": self.f, "units": self.units.to_string(), "cum": self.cum,
               "floor": self.floor, "T": self.t, "T1": self.t1, "until": self.until, "tweak": self.tweak, "pl": self.pl, "body": self.body})
    }
}

struct GivenUp {
    cum: u64,
    lock_id: String,
    after: (u64, u128, u64),
}

impl GivenUp {
    fn to_json(&self) -> Value {
        json!({"cum": self.cum, "lockId": self.lock_id, "after": [self.after.0, self.after.1.to_string(), self.after.2]})
    }

    fn from_json(v: &Value) -> Option<Self> {
        let a = v.get("after")?.as_array()?;
        Some(Self { cum: py_u64(v.get("cum"))?, lock_id: py_str(v.get("lockId")),
                    after: (py_u64(a.first())?, u128_of(a.get(1))?, py_u64(a.get(2))?) })
    }
}

/// Counters (`stats` in the reference).
#[derive(Debug, Clone, Default)]
pub struct PayerStats {
    pub locks: u64,
    pub floor_locks: u64,
    pub voided: u64,
    pub via_provider: u64,
    pub refused: IndexMap<String, u64>,
}

struct Ch1 {
    params: ChannelParams,
    accepted: Value,
    seq: u64,
    /// The hub answered our open (false: funded and attached, the open not confirmed yet).
    opened: bool,
}

#[derive(Default)]
struct PState {
    ch: Option<Ch1>,
    quote: Option<FeeQuote>,
    hub_pay_to: String,
    routed: u64,
    fee_units: u128,
    fee_paid: u64,
    signed: u64,
    pending: Option<Pending>,
    given_up: Vec<GivenUp>,
    stats: PayerStats,
}

/// The routed-payment client.
pub struct RoutePayer {
    pub hub_url: String,
    pub cfg: RoutePayerConfig,
    signer: Arc<dyn RouteSigner>,
    wallet: Arc<dyn Wallet>,
    http: Box<dyn Transport>,
    height: HeightFn,
    st: Mutex<PState>,
    shards: Mutex<IndexMap<String, Arc<Shard>>>,
    ledger: Option<Box<dyn RouteLedger>>,
    stop: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
    ids: AtomicU64,
    pub events: Mutex<Vec<Value>>,
}

fn hdr_json(r: &HttpResponse, name: &str) -> Option<Value> {
    r.header(name).and_then(|h| unb64json(h).ok())
}

impl RoutePayer {
    pub fn new(hub_url: &str, cfg: RoutePayerConfig, signer: Arc<dyn RouteSigner>, wallet: Arc<dyn Wallet>, http: Box<dyn Transport>,
               height: HeightFn) -> Self {
        Self { hub_url: hub_url.trim_end_matches('/').to_string(), cfg, signer, wallet, http, height, st: Mutex::new(PState::default()),
               shards: Mutex::new(IndexMap::new()), ledger: None, stop: Arc::new(AtomicBool::new(false)), thread: Mutex::new(None),
               ids: AtomicU64::new(1), events: Mutex::new(vec![]) }
    }

    /// Keep this payer's state in `ledger`, and resume from what it holds (AGP-044): ch1, the
    /// counters, the given-up locks, the pending lock (sent again by the next [`lock`](Self::lock))
    /// and the shard sessions ([`shard`](Self::shard) returns a resumed one). Call before `open`.
    /// The signer must be the one that holds ch1's key (the same `xbt-signer`, or the same
    /// `LocalSigner`). A lock the signer pre-signed but the ledger never recorded never left: it is
    /// voided in the signer here.
    pub fn with_ledger(mut self, ledger: Box<dyn RouteLedger>) -> Result<Self> {
        let recs: IndexMap<String, Value> = ledger.load()?.into_iter().collect();
        let bad = |k: &str| ChannelError::new("ledger_error", format!("route ledger: {k}"));
        {
            let mut st = lk(&self.st);
            if let Some(c) = recs.get("ch1") {
                if c.get("hub_url").and_then(Value::as_str) != Some(self.hub_url.as_str()) {
                    return fail("ledger_error", "the route ledger belongs to another hub");
                }
                st.ch = Some(Ch1 { params: ChannelParams::from_json(c.get("params").ok_or_else(|| bad("params"))?)?,
                                   accepted: c.get("accepted").cloned().unwrap_or(Value::Null), seq: py_u64(c.get("seq")).ok_or_else(|| bad("seq"))?,
                                   opened: c.get("opened").and_then(Value::as_bool).unwrap_or(false) });
                st.hub_pay_to = py_str(c.get("hub_pay_to"));
            }
            if let Some(b) = recs.get("book") {
                let n = |k: &str| py_u64(b.get(k)).ok_or_else(|| bad(k));
                (st.routed, st.fee_paid, st.signed) = (n("routed")?, n("fee_paid")?, n("signed")?);
                st.fee_units = u128_of(b.get("fee_units")).ok_or_else(|| bad("fee_units"))?;
                st.given_up = b.get("given_up").and_then(Value::as_array).into_iter().flatten().filter_map(GivenUp::from_json).collect();
                st.quote = b.get("quote").and_then(|q| FeeQuote::from_json(q).ok());
                let s = b.get("stats").cloned().unwrap_or(Value::Null);
                let sn = |k: &str| py_u64(s.get(k)).unwrap_or(0);
                st.stats = PayerStats { locks: sn("locks"), floor_locks: sn("floor_locks"), voided: sn("voided"), via_provider: sn("via_provider"),
                                        refused: s.get("refused").and_then(Value::as_object).into_iter().flatten()
                                            .map(|(k, v)| (k.clone(), py_u64(Some(v)).unwrap_or(0))).collect() };
            }
        }
        {
            let mut shards = lk(&self.shards);
            for (k, v) in &recs {
                if let Some(url) = k.strip_prefix("shard ") {
                    shards.insert(url.to_string(), Arc::new(Shard::from_json(v)?));
                }
            }
        }
        let chan = self.chan();
        let pending = recs.get("pending").filter(|p| !p.is_null());
        match (pending, &chan) {
            (Some(p), _) => {
                let url = py_str(p.get("shard"));
                let shard = lk(&self.shards).get(&url).cloned().ok_or_else(|| bad("pending lock's shard"))?;
                let n = |k: &str| py_u64(p.get(k)).ok_or_else(|| bad(k));
                let pend = Pending { id: self.ids.fetch_add(1, Ordering::Relaxed), shard, lock_id: py_str(p.get("lockId")), d: n("d")?, f: n("f")?,
                                     units: u128_of(p.get("units")).ok_or_else(|| bad("units"))?, cum: n("cum")?,
                                     floor: p.get("floor").and_then(Value::as_bool).unwrap_or(false), t: py_str(p.get("T")), t1: py_str(p.get("T1")),
                                     until: p.get("until").and_then(Value::as_f64).unwrap_or(0.0), t0: Instant::now(), inflight: false,
                                     tweak: py_str(p.get("tweak")), pl: p.get("pl").cloned().unwrap_or(Value::Null), body: py_str(p.get("body")),
                                     resumed: true };
                lk(&self.st).pending = Some(pend);
            }
            // a presignature the ledger never recorded never left: give it up in the signer
            (None, Some(c)) if self.signer.void_lock(c).unwrap_or(false) => {
                self.event(json!({"event": "void", "why": "presigned, never sent (restart)"}));
            }
            _ => {}
        }
        self.ledger = Some(ledger);
        if chan.is_some() {
            self.event(json!({"event": "resumed", "chan": chan, "shards": lk(&self.shards).len(), "pending": lk(&self.st).pending.is_some()}));
        }
        Ok(self)
    }

    fn book_json(st: &PState) -> Value {
        let s = &st.stats;
        json!({"routed": st.routed, "fee_units": st.fee_units.to_string(), "fee_paid": st.fee_paid, "signed": st.signed,
               "given_up": st.given_up.iter().map(GivenUp::to_json).collect::<Vec<_>>(), "quote": st.quote.as_ref().map(FeeQuote::to_json),
               "stats": {"locks": s.locks, "floor_locks": s.floor_locks, "voided": s.voided, "via_provider": s.via_provider,
                         "refused": s.refused.iter().map(|(k, v)| (k.clone(), Value::from(*v))).collect::<serde_json::Map<String, Value>>()}})
    }

    fn ch1_json(&self, st: &PState) -> Value {
        st.ch.as_ref().map(|c| json!({"hub_url": self.hub_url, "params": c.params.to_json(), "accepted": c.accepted, "seq": c.seq,
                                     "opened": c.opened, "hub_pay_to": st.hub_pay_to})).unwrap_or(Value::Null)
    }

    fn persist(&self, recs: &[(String, Value)]) -> Result<()> {
        match &self.ledger {
            Some(l) => l.save(recs),
            None => Ok(()),
        }
    }

    /// Save after a change that already happened (a failed save is an event: the next restart
    /// resolves from an older record, which every path above tolerates).
    fn persist_quiet(&self, recs: &[(String, Value)]) {
        if let Err(e) = self.persist(recs) {
            self.event(json!({"event": "ledger_error", "error": e.to_string()}));
        }
    }

    /// The book, the pending lock and (after a lock) its shard, as one save.
    fn persist_lock_state(&self, st: &PState, shard: Option<&Arc<Shard>>) {
        if self.ledger.is_none() {
            return;
        }
        let mut recs = vec![("book".to_string(), Self::book_json(st)), ("pending".to_string(), st.pending.as_ref().map(Pending::to_json).unwrap_or(Value::Null))];
        if let Some(sh) = shard {
            recs.push((format!("shard {}", sh.url), sh.to_json()));
        }
        self.persist_quiet(&recs);
    }

    fn event(&self, e: Value) {
        lk(&self.events).push(e);
    }

    /// The ch1 channel id.
    pub fn chan(&self) -> Option<String> {
        lk(&self.st).ch.as_ref().map(|c| c.params.channel_id())
    }

    fn pick(&self, pr: &Value) -> Result<Value> {
        for acc in pr.get("accepts").and_then(Value::as_array).into_iter().flatten() {
            if scheme_accepted(acc.get("scheme").and_then(Value::as_str)) && acc.get("network").and_then(Value::as_str) == Some(&self.cfg.network) {
                let ex = acc.get("extra").cloned().unwrap_or(Value::Null);
                if !py_u64(ex.get("closeFeeSat")).is_some_and(|f| f <= self.cfg.max_close_fee) {
                    return fail("bad_offer", "closeFeeSat above our cap");
                }
                if let Some(fp) = ex.get("closeFeePayer") {
                    FeePayer::parse(fp.as_str().unwrap_or("")).map_err(|_| ChannelError::new("bad_offer", "unknown closeFeePayer"))?;
                }
                if ex.get("derivation").and_then(Value::as_str) != Some(DERIVATION) {
                    return fail("bad_offer", "payee key derivation is not v2 (xbt402 v1.1)");
                }
                return Ok(acc.clone());
            }
        }
        fail("no_scheme", format!("no {SCHEME} offer on {}", self.cfg.network))
    }

    fn refresh_quote(&self, st: &mut PState, routing: &Value) -> Result<()> {
        let q = FeeQuote::from_json(routing.get("quote").unwrap_or(&Value::Null))?;
        if q.hub != st.hub_pay_to || q.network != self.cfg.network || !q.verify() || !q.live(now_f()) {
            return fail("route_fee", "hub fee quote not signed by the hub's payTo, or not live");
        }
        if q.fee_ppm > self.cfg.max_fee_ppm || q.fee_base_msat > self.cfg.max_fee_base_msat {
            return fail("route_fee", format!("hub fee {} msat + {} ppm above our caps", q.fee_base_msat, q.fee_ppm));
        }
        st.quote = Some(q);
        Ok(())
    }

    fn hub_offer(&self) -> Result<Value> {
        let r = self.http.request("GET", &format!("{}{HUB_ROUTE_PATH}", self.hub_url), b"", &[])?;
        if r.status != 402 {
            return fail("bad_offer", format!("hub answered {}, expected 402", r.status));
        }
        self.pick(&hdr_json(&r, "PAYMENT-REQUIRED").ok_or_else(|| ChannelError::new("bad_offer", "402 without PAYMENT-REQUIRED"))?)
    }

    fn post(&self, url: &str, v: &Value) -> Result<Value> {
        let r = self.http.request("POST", url, dumps(v).as_bytes(), &[("Content-Type".into(), "application/json".into())])?;
        let data: Value = crate::json::parse_slice(&r.body).map_err(|_| ChannelError::new("provider_error", format!("HTTP {} non-JSON", r.status)))?;
        if r.status != 200 {
            let code = data.get("error").and_then(Value::as_str).filter(|c| safe_code(c)).unwrap_or("provider_error");
            return fail(code, py_str(data.get("detail")));
        }
        Ok(data)
    }

    /// Open ch1 to the hub from its 402 (x402 v2, xbt-channel, `extra.routing`). Returns
    /// `{chan, capacity, expiry}`.
    pub fn open(&self) -> Result<Value> {
        let resumed = {
            let st = lk(&self.st);
            st.ch.as_ref().map(|c| (c.opened, c.params.clone(), c.accepted.clone()))
        };
        if let Some((opened, p, acc)) = resumed {
            if !opened {
                // funded and attached before a restart, the hub's answer to our open not seen
                self.post_open(&p, &acc)?;
                if let Some(c) = lk(&self.st).ch.as_mut() {
                    c.opened = true;
                }
                let rec = self.ch1_json(&lk(&self.st));
                self.persist(&[("ch1".into(), rec)])?;
            }
            return Ok(json!({"chan": p.channel_id(), "capacity": p.capacity, "expiry": p.expiry, "resumed": true}));
        }
        let acc = self.hub_offer()?;
        {
            let mut st = lk(&self.st);
            st.hub_pay_to = py_str(acc.get("payTo"));
            self.refresh_quote(&mut st, acc.get("extra").and_then(|e| e.get("routing")).unwrap_or(&Value::Null))?;
        }
        let ex = acc.get("extra").cloned().unwrap_or(Value::Null);
        let fee_payer = FeePayer::parse(ex.get("closeFeePayer").and_then(Value::as_str).unwrap_or("payer"))?;
        let cap = self.cfg.capacity.max(py_u64(ex.get("minCapacity")).unwrap_or(0));
        if cap > py_u64(ex.get("maxCapacity")).unwrap_or(cap) {
            return fail("budget", "channel capacity outside the hub's range");
        }
        let pubk = self.signer.new_key(&self.hub_url)?;
        let payer_spk = self.signer.payer_spk()?;
        let lo = py_u64(ex.get("minExpiryBlocks")).unwrap_or(0) + 6;
        let hi = py_u64(ex.get("maxExpiryBlocks")).unwrap_or(u64::MAX).saturating_sub(1);
        let expiry = (self.height)()? + (self.cfg.expiry_blocks as u64).max(lo).min(hi) as u32;
        let pay_to = hex::decode(py_str(acc.get("payTo"))).map_err(|_| ChannelError::new("bad_offer", "payTo"))?;
        let p = ChannelParams::derive(&pay_to, &pubk, expiry, py_u64(ex.get("closeFeeSat")).unwrap_or(0), payer_spk, &self.cfg.network, fee_payer)?;
        let hrp = if self.cfg.network == XBT_MAINNET { "bc" } else { "bcrt" };
        let (txid, vout) = self.wallet.fund(&segwit_address(hrp, &p.spk())?, cap)?;
        let p = p.with_funding(&txid, vout, cap)?;
        self.signer.attach(&self.hub_url, &p)?;
        self.signer.sign_refund(&p.channel_id())?;
        if self.ledger.is_some() {
            // write-ahead: a restart finds the funded ch1 (and posts the open again)
            let mut st = lk(&self.st);
            st.ch = Some(Ch1 { params: p.clone(), accepted: acc.clone(), seq: 0, opened: false });
            let recs = [("ch1".to_string(), self.ch1_json(&st)), ("book".to_string(), Self::book_json(&st))];
            drop(st);
            self.persist(&recs)?;
        }
        self.post_open(&p, &acc)?;
        let out = json!({"chan": p.channel_id(), "capacity": p.capacity, "expiry": p.expiry});
        let mut st = lk(&self.st);
        let seq = st.ch.as_ref().map(|c| c.seq).unwrap_or(0);
        st.ch = Some(Ch1 { params: p, accepted: acc, seq, opened: true });
        let rec = self.ch1_json(&st);
        drop(st);
        self.persist(&[("ch1".into(), rec)])?;
        Ok(out)
    }

    fn post_open(&self, p: &ChannelParams, acc: &Value) -> Result<()> {
        let ex = acc.get("extra").cloned().unwrap_or(Value::Null);
        let mut c = json!({"txid": p.funding_txid(), "vout": p.funding_vout(), "capacity": p.capacity, "expiry": p.expiry,
                           "payerPub": hex::encode(p.payer_pub), "payerSpk": hex::encode(&p.payer_spk), "redeemScript": hex::encode(p.script())});
        if p.close_fee_payer != FeePayer::Payer {
            c["closeFeePayer"] = p.close_fee_payer.as_str().into();
        }
        let open_url = format!("{}{}", self.hub_url, ex.get("openUrl").and_then(Value::as_str).unwrap_or(OPEN_PATH));
        let r = self.post(&open_url, &json!({"x402Version": 2, "network": self.cfg.network, "channel": c}))?;
        if r.get("closeFeePayer").and_then(Value::as_str).unwrap_or("payer") != p.close_fee_payer.as_str() {
            return fail("bad_fee_payer", "the hub opened the channel with another closeFeePayer");
        }
        Ok(())
    }

    /// Re-read the hub's 402 for a fresh fee quote.
    pub fn refresh_hub(&self) -> Result<()> {
        let acc = self.hub_offer()?;
        let mut st = lk(&self.st);
        if py_str(acc.get("payTo")) != st.hub_pay_to {
            return fail("bad_offer", "the hub's payTo changed");
        }
        self.refresh_quote(&mut st, acc.get("extra").and_then(|e| e.get("routing")).unwrap_or(&Value::Null))
    }

    /// Start a metered session on a routed path: verify the provider's signed price quote and first
    /// invoice (the hub never touches either).
    /// With a ledger, a session it holds for `url` is resumed instead (no new 402).
    pub fn shard(&self, url: &str, method: &str) -> Result<Arc<Shard>> {
        if let Some(sh) = lk(&self.shards).get(url).cloned() {
            if self.ledger.is_some() {
                return Ok(sh);
            }
        }
        let c = adaptor::random_secret();
        let r = self.http.request(method, url, b"", &[("ROUTE-CLIENT".into(), hex::encode(ecdsa::pubkey(&c)))])?;
        if r.status != 402 {
            return fail("bad_offer", format!("expected a 402 with extra.route, got {}", r.status));
        }
        let acc = self.pick(&hdr_json(&r, "PAYMENT-REQUIRED").ok_or_else(|| ChannelError::new("bad_offer", "no PAYMENT-REQUIRED"))?)?;
        let rt = acc.get("extra").and_then(|e| e.get("route")).cloned().unwrap_or(json!({}));
        let pay_to = py_str(acc.get("payTo"));
        let q = PriceQuote::from_json(rt.get("quote").unwrap_or(&Value::Null))?;
        let inv = Invoice::from_json(rt.get("invoice").unwrap_or(&Value::Null))?;
        if q.pay_to != pay_to || q.network != self.cfg.network || !q.verify() {
            return fail("bad_offer", "price quote not signed by the provider's payTo");
        }
        let session = py_str(rt.get("session"));
        if inv.pay_to != pay_to || inv.session != session || !inv.verify() {
            return fail("bad_invoice", "invoice not signed by the provider's payTo");
        }
        let hub = lk(&self.st).hub_pay_to.clone();
        if !inv.accepts_hub(&hub) {
            return fail("route_blocked", "the provider does not take locks from our hub");
        }
        let (origin, path) = split_url(url);
        let key = session_key(&c, &hex::decode(&pay_to).unwrap_or_default())?;
        let f = |k: &str| rt.get(k).and_then(Value::as_f64).unwrap_or(1.0);
        let sh = Arc::new(Shard { url: url.into(), origin, path, pay_to, session, key, quote: q, window: f("window"), lock_wait: f("lockWait"),
                                  state: Mutex::new(ShardState { invoice: inv.to_json(), last_lock: json!({}), ..Default::default() }) });
        self.persist(&[(format!("shard {url}"), sh.to_json())])?;
        lk(&self.shards).insert(url.to_string(), sh.clone());
        Ok(sh)
    }

    pub fn shards(&self) -> Vec<Arc<Shard>> {
        lk(&self.shards).values().cloned().collect()
    }

    // --- data path -------------------------------------------------------------------------------

    /// One metered call straight to the provider. A 402 with `error: route_credit` means the
    /// provider stopped serving us (its credit window ran out). Err only for a ROUTE-STATE that
    /// is not the provider's (`bad_receipt`) or a transport failure.
    pub fn call(&self, sh: &Arc<Shard>, method: &str, body: &[u8]) -> Result<HttpResponse> {
        let (seq, reserve) = {
            let mut s = lk(&sh.state);
            s.seq += 1;
            let reserve = self.ledger.is_some() && s.seq > s.seq_hi;
            if reserve {
                s.seq_hi = s.seq + SEQ_RESERVE - 1;
            }
            (s.seq, reserve)
        };
        if reserve {
            // write-ahead: a restart starts past every seq that may have left
            self.persist(&[(format!("shard {}", sh.url), sh.to_json())])?;
        }
        let auth = call_auth(&sh.key, &sh.session, seq, &request_digest(method, &sh.path, body));
        let hdr = b64json(&json!({"session": sh.session, "seq": seq, "auth": auth}));
        let t0 = Instant::now();
        let r = self.http.request(method, &sh.url, body, &[("ROUTE-AUTH".into(), hdr)])?;
        {
            let mut s = lk(&sh.state);
            s.call_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
            s.answered += 1;
        }
        let mut state = hdr_json(&r, "ROUTE-STATE");
        if state.is_none() && r.status == 402 {
            let doc: Value = crate::json::parse_slice(&r.body).unwrap_or(Value::Null);
            state = doc.get("routeState").cloned();
            lk(&sh.state).stopped = doc.get("error").and_then(Value::as_str).unwrap_or("refused").to_string();
        }
        if let Some(state) = state {
            self.apply_state(sh, &state)?;
        }
        let answered = {
            let mut s = lk(&sh.state);
            if r.status < 400 {
                s.calls += 1;
            }
            s.answered
        };
        if self.ledger.is_some() && answered % self.cfg.persist_every.max(1) == 0 {
            self.persist_quiet(&[(format!("shard {}", sh.url), sh.to_json())]);
        }
        Ok(r)
    }

    fn apply_state(&self, sh: &Arc<Shard>, state: &Value) -> Result<()> {
        if !state_verify(&sh.pay_to, state) || state.get("session").and_then(Value::as_str) != Some(sh.session.as_str()) {
            return fail("bad_receipt", "ROUTE-STATE not signed by the provider for this session");
        }
        let charge = u128_of(state.get("chargeAmsat")).unwrap_or(0);
        if sh.quote.amsat_per_call > 0 && charge > sh.quote.amsat_per_call {
            return fail("bad_receipt", "charged above the signed price quote");
        }
        {
            let mut s = lk(&sh.state);
            s.seen_amsat += charge;
            let acc = u128_of(state.get("accruedAmsat")).unwrap_or(0);
            if s.in_doubt > 0 {
                // the first state after a restart: calls a crash left unanswered may have been charged
                let gap = acc.saturating_sub(s.seen_amsat);
                let bound = s.in_doubt as u128 * sh.quote.amsat_per_call;
                if gap > 0 && gap <= bound {
                    s.seen_amsat += gap;
                    self.event(json!({"event": "meter_adopted", "provider": sh.origin, "gapAmsat": gap.to_string(), "inDoubt": s.in_doubt}));
                } else if gap > bound {
                    self.event(json!({"event": "meter_gap", "provider": sh.origin, "gapAmsat": gap.to_string(), "boundAmsat": bound.to_string()}));
                }
                s.in_doubt = 0;
            }
            s.accrued_amsat = s.accrued_amsat.max(acc);
            s.paid_sat = s.paid_sat.max(py_u64(state.get("paidSat")).unwrap_or(0));
            let inv = state.get("invoice").cloned().unwrap_or(json!({}));
            if truthy(inv.get("lockId")) && inv.get("lockId") != s.invoice.get("lockId") {
                if let Ok(i) = Invoice::from_json(&inv) {
                    if i.verify() && i.pay_to == sh.pay_to && i.session == sh.session {
                        s.invoice = inv;
                    }
                }
            }
            if truthy(state.get("lastLock")) {
                s.last_lock = state["lastLock"].clone();
            }
        }
        self.check_pending(Some(sh));
        Ok(())
    }

    // --- locks (serial on ch1) -------------------------------------------------------------------

    fn commit(&self, st: &mut PState, p: &Pending, t_hex: &str, via: &str) {
        st.routed += p.d + p.f;
        st.fee_units = p.units;
        st.fee_paid += p.f;
        st.signed = st.signed.max(p.cum);
        {
            let mut s = lk(&p.shard.state);
            s.locked_sat += p.d;
            s.last_locked = p.lock_id.clone();
            s.lock_ms.push(p.t0.elapsed().as_secs_f64() * 1000.0);
        }
        st.stats.locks += 1;
        if p.floor {
            st.stats.floor_locks += 1;
        }
        if via == "provider" {
            st.stats.via_provider += 1;
        }
        self.event(json!({"event": "lock", "provider": p.shard.origin, "lockId": p.lock_id, "amount": p.d, "fee": p.f, "cum1": p.cum,
                          "via": via, "t": &t_hex[..16.min(t_hex.len())]}));
    }

    fn chan_of(st: &PState) -> String {
        st.ch.as_ref().map(|c| c.params.channel_id()).unwrap_or_default()
    }

    /// The provider's signed ROUTE-STATE says the pending lock was paid: its t is our receipt even if
    /// the hub keeps t + r. Resolves the lock and returns true.
    fn via_provider(&self, st: &mut PState) -> bool {
        let Some(p) = st.pending.as_ref() else { return false };
        let ll = lk(&p.shard.state).last_lock.clone();
        if ll.get("lockId").and_then(Value::as_str) != Some(p.lock_id.as_str()) {
            return false;
        }
        let Some(t) = Sc::from_hex_mod_n(&py_str(ll.get("secret"))).and_then(|s| s.secret()) else { return false };
        if hex::encode(adaptor::enc(&adaptor::point_of(&t))) != p.t.to_lowercase() {
            return false;
        }
        let chan = Self::chan_of(st);
        // resumed: the signer may have resolved it just before the crash (t opens T: it was paid)
        if !p.floor && self.signer.resolve_lock(&chan, &t.secret_bytes()).is_err() && !p.resumed {
            return false;
        }
        let p = st.pending.take().expect("checked");
        self.commit(st, &p, &hex::encode(t.secret_bytes()), "provider");
        self.persist_lock_state(st, Some(&p.shard));
        true
    }

    fn check_pending(&self, from: Option<&Arc<Shard>>) {
        let mut st = lk(&self.st);
        let Some(p) = st.pending.as_ref() else { return };
        if from.is_some_and(|f| !Arc::ptr_eq(f, &p.shard) || p.inflight) {
            // a data call never resolves a lock whose POST is still out (AGP-054): the hub's answer is
            // on its way and settles it off the data path (the signer's and the ledger's write-ahead
            // are fsyncs); a lost or refused answer leaves it to the next check (the provider's t)
            return;
        }
        if self.via_provider(&mut st) {
            return;
        }
        let Some(p) = st.pending.as_ref() else { return };
        if now_f() > p.until && !p.inflight {
            // never while our request is out: the hub may still complete it
            let p = st.pending.take().expect("checked");
            self.void(&mut st, &p, "invoice expired unanswered");
            self.persist_lock_state(&st, Some(&p.shard));
        }
    }

    fn void(&self, st: &mut PState, p: &Pending, why: &str) {
        if !p.floor {
            let _ = self.signer.void_lock(&Self::chan_of(st));
            let after = (st.routed + p.d + p.f, p.units, st.fee_paid + p.f);
            st.given_up.push(GivenUp { cum: p.cum, lock_id: p.lock_id.clone(), after });
            if st.given_up.len() > 16 {
                st.given_up.remove(0);
            }
        }
        st.stats.voided += 1;
        self.event(json!({"event": "void", "provider": p.shard.origin, "lockId": p.lock_id, "amount": p.d, "why": why}));
    }

    /// The hub completed a lock we had given up (it read t off the provider's ch2 close). Adopt its
    /// view only if its best state is one of those locks, with the counters it implied.
    fn resync(&self, st: &mut PState, doc: &Value) -> bool {
        let (Some(best), Some(r), Some(u), Some(pd)) = (py_u64(doc.get("bestCum")), py_u64(doc.get("routedSat")), u128_of(doc.get("feeUnits")),
                                                        py_u64(doc.get("feePaid"))) else { return false };
        let Some(i) = st.given_up.iter().position(|g| g.cum == best && g.after == (r, u, pd)) else { return false };
        if best <= st.signed {
            return false;
        }
        // the refused lock goes first: a signer adopts only with no lock pending (B2's book, xbt-signer)
        let chan = Self::chan_of(st);
        let _ = self.signer.void_lock(&chan);
        if self.signer.adopt_lock(&chan, best).is_err() {
            return false;
        }
        (st.routed, st.fee_units, st.fee_paid, st.signed) = (r, u, pd, best);
        let g = st.given_up.remove(i);
        self.event(json!({"event": "resync", "lockId": g.lock_id, "cum1": best}));
        true
    }

    /// Pay `sh`'s accrued amount through the hub with one adaptor lock. `Ok(None)` if nothing is
    /// due or a lock is still pending on ch1; otherwise `{status: paid|refused|resynced|pending...}`.
    /// A lock resumed from the ledger is sent again first (whatever `sh`).
    pub fn lock(&self, sh: &Arc<Shard>) -> Result<Option<Value>> {
        self.check_pending(None);
        if let Some(r) = self.resend_pending()? {
            return Ok(Some(r));
        }
        let (id, pl, body, accepted, d, f, floor) = {
            let mut st = lk(&self.st);
            if st.pending.is_some() || st.ch.is_none() {
                return Ok(None);
            }
            let due = sh.due_sat();
            let inv = lk(&sh.state).invoice.clone();
            let vu = inv.get("validUntil").and_then(Value::as_f64).unwrap_or(0.0);
            let rts = st.quote.as_ref().map(|q| q.reveal_timeout_sec).unwrap_or(10) as f64;
            // the hub may wait revealTimeoutSec for the provider: lock only with that much invoice left;
            // and never an invoice already paid (wait for the fresh one in the next ROUTE-STATE)
            let paid_already = inv.get("lockId").and_then(Value::as_str) == Some(sh.snapshot().last_locked.as_str());
            if due < 1 || vu < now_f() + 1.0 + rts || paid_already {
                return Ok(None);
            }
            if !st.quote.as_ref().is_some_and(|q| q.live(now_f() + 30.0)) {
                drop(st);
                self.refresh_hub()?;
                return Ok(None);
            }
            let q = st.quote.clone().expect("live");
            let d = (due as u64).min(self.cfg.max_lock_sat).min(q.max_lock_sat);
            let (f, units) = fee_due(&q, d, st.fee_units, st.fee_paid);
            let ch = st.ch.as_ref().expect("open");
            let (chan, min_amount) = (ch.params.channel_id(), ch.params.min_amount());
            let cum = next_cum(st.routed, d + f, min_amount);
            let floor = cum <= st.signed;
            let lock_id = py_str(inv.get("lockId"));
            let point = py_str(inv.get("point"));
            let mut route = json!({"provider": sh.origin, "payTo": sh.pay_to, "network": self.cfg.network, "amount": d, "point": point,
                                   "fee": f, "feeQuote": q.to_json(), "invoice": inv, "session": sh.session, "lockId": lock_id,
                                   "lockAuth": lock_auth(&sh.key, &sh.session, &lock_id, d as i128, &point, &st.hub_pay_to)});
            let id = self.ids.fetch_add(1, Ordering::Relaxed);
            let mut p = Pending { id, shard: sh.clone(), lock_id: lock_id.clone(), d, f, units, cum: cum.max(st.signed), floor, t: point.clone(),
                                  t1: String::new(), until: vu + self.cfg.void_grace, t0: Instant::now(), inflight: true, tweak: "00".repeat(32),
                                  pl: Value::Null, body: String::new(), resumed: false };
            let pl = if floor {
                route["tweak"] = "00".repeat(32).into();
                json!({"chan": chan, "seq": 0, "cum": st.signed.to_string()})
            } else {
                let tp: ecdsa::PubkeyBytes = hex::decode(&point).ok().and_then(|b| b.try_into().ok())
                    .ok_or_else(|| ChannelError::new("bad_invoice", "invoice point"))?;
                let sa = self.signer.sign_state_adaptor(&chan, cum, &tp, &json!({"hub": self.hub_url, "provider": sh.origin, "lockId": lock_id,
                                                                                     "amount": d, "fee": f}))?;
                route["tweak"] = hex::encode(sa.tweak).into();
                p.tweak = hex::encode(sa.tweak);
                p.t1 = hex::encode(sa.point);
                json!({"chan": chan, "seq": 0, "cum": cum.to_string(), "adaptor": sa.pre.to_json(), "point": p.t1.clone()})
            };
            let body = dumps(&json!({"route": route}));
            (p.pl, p.body) = (pl.clone(), body.clone());
            let accepted = st.ch.as_ref().expect("open").accepted.clone();
            let pl = match self.signed_payload(&mut st, &pl, &body) {
                Ok(x) => x,
                Err(e) => {
                    if !floor {
                        let _ = self.signer.void_lock(&chan);
                    }
                    return Err(e);
                }
            };
            st.pending = Some(p);
            if self.ledger.is_some() {
                // write-ahead: the lock and its seq before the request leaves
                let recs = [("ch1".to_string(), self.ch1_json(&st)), ("pending".to_string(), st.pending.as_ref().map(Pending::to_json).unwrap_or_default())];
                if let Err(e) = self.persist(&recs) {
                    st.pending = None;
                    if !floor {
                        let _ = self.signer.void_lock(&chan);
                    }
                    return Err(e);
                }
            }
            (id, pl, body, accepted, d, f, floor)
        };
        self.send_lock(id, &pl, &body, &accepted, d, f, floor)
    }

    /// `pl` with a fresh ch1 seq and its auth.
    fn signed_payload(&self, st: &mut PState, pl: &Value, body: &str) -> Result<Value> {
        let ch = st.ch.as_mut().ok_or_else(|| ChannelError::code("no_channel"))?;
        ch.seq += 1;
        let mut pl = pl.clone();
        pl["seq"] = ch.seq.into();
        let chan = ch.params.channel_id();
        pl["auth"] = self.signer.request_auth(&chan, Some(&pl["seq"]), Some(&pl["cum"]), None, &request_digest("POST", HUB_ROUTE_PATH, body.as_bytes()))?.into();
        Ok(pl)
    }

    /// A lock resumed from the ledger: send the same request again (a fresh seq and auth). The hub
    /// answers a lock it completed with its saved answer; one it never saw it takes now; a refusal
    /// voids it as usual. None if there is no such lock (or it is out already).
    fn resend_pending(&self) -> Result<Option<Value>> {
        let (id, pl, body, accepted, d, f, floor) = {
            let mut st = lk(&self.st);
            let Some(p) = st.pending.as_ref().filter(|p| p.resumed && !p.inflight) else { return Ok(None) };
            let (id, pl0, body, d, f, floor) = (p.id, p.pl.clone(), p.body.clone(), p.d, p.f, p.floor);
            let accepted = st.ch.as_ref().map(|c| c.accepted.clone()).unwrap_or(Value::Null);
            let pl = self.signed_payload(&mut st, &pl0, &body)?;
            self.persist(&[("ch1".to_string(), self.ch1_json(&st))])?;
            if let Some(p) = st.pending.as_mut() {
                p.inflight = true;
            }
            (id, pl, body, accepted, d, f, floor)
        };
        self.event(json!({"event": "lock_resent", "lockId": lk(&self.st).pending.as_ref().map(|p| p.lock_id.clone())}));
        self.send_lock(id, &pl, &body, &accepted, d, f, floor)
    }

    #[allow(clippy::too_many_arguments)]
    fn send_lock(&self, id: u64, pl: &Value, body: &str, accepted: &Value, d: u64, f: u64, floor: bool) -> Result<Option<Value>> {
        let r = self.http.request("POST", &format!("{}{HUB_ROUTE_PATH}", self.hub_url), body.as_bytes(),
                                  &[("PAYMENT-SIGNATURE".into(), b64json(&json!({"x402Version": 2, "accepted": accepted, "payload": pl}))),
                                    ("Content-Type".into(), "application/json".into())]);
        let (status, doc) = match r {
            Ok(r) => (r.status, crate::json::parse_slice(&r.body).unwrap_or(Value::Null)),
            Err(_) => (0, Value::Null),
        };
        let mut st = lk(&self.st);
        match st.pending.as_mut() {
            Some(p) if p.id == id => p.inflight = false,
            _ => return Ok(Some(json!({"status": "resolved_elsewhere"}))),
        }
        let chan = Self::chan_of(&st);
        if status == 200 && truthy(doc.get("secret")) {
            let Some(y) = Sc::from_hex_mod_n(&py_str(doc.get("secret"))).and_then(|s| s.secret()) else {
                return Ok(Some(json!({"status": "pending", "why": "bad secret"})));
            };
            let yp = hex::encode(adaptor::enc(&adaptor::point_of(&y)));
            let p = st.pending.as_ref().expect("ours");
            let t = if floor {
                if yp != p.t.to_lowercase() {
                    return Ok(Some(json!({"status": "pending", "why": "bad secret"})));
                }
                hex::encode(y.secret_bytes())
            } else {
                // the answer must open OUR T1: a hub replaying its answer to an earlier attempt at this
                // invoice (whose lock we gave up) is refused here, and resynced on the next lock
                if doc.get("lockId").and_then(Value::as_str) != Some(p.lock_id.as_str()) || yp != p.t1 {
                    let p = st.pending.take().expect("ours");
                    self.void(&mut st, &p, "hub answer does not open this lock");
                    self.event(json!({"event": "stale_answer", "lockId": p.lock_id, "cum1": doc.get("cum")}));
                    self.persist_lock_state(&st, Some(&p.shard));
                    return Ok(Some(json!({"status": "refused", "error": "stale_answer", "detail": "hub answer does not open this lock"})));
                }
                match self.signer.resolve_lock(&chan, &y.secret_bytes()) {
                    Ok(t) => hex::encode(t),
                    // resumed: the signer resolved it before the crash; y opens our T1, so t = y − r
                    Err(_) if p.resumed => Sc::from_secret(&y).sub(&Sc::from_hex_mod_n(&p.tweak).unwrap_or(Sc::from_u64(0))).hex(),
                    Err(e) => return Ok(Some(json!({"status": "pending", "why": e.to_string()}))),
                }
            };
            let p = st.pending.take().expect("ours");
            self.commit(&mut st, &p, &t, "hub");
            self.persist_lock_state(&st, Some(&p.shard));
            return Ok(Some(json!({"status": "paid", "amount": d, "fee": f, "lockId": p.lock_id})));
        }
        let code = doc.get("error").and_then(Value::as_str).map(str::to_string);
        if code.as_deref() == Some("bad_amount") && self.resync(&mut st, &doc) {
            let shard = st.pending.take().map(|p| {
                self.void(&mut st, &p, "hub: resynced");
                p.shard
            });
            self.persist_lock_state(&st, shard.as_ref());
            return Ok(Some(json!({"status": "resynced"})));
        }
        if [400, 401, 402, 502].contains(&status) {
            if let Some(code) = code {
                if code == "lock_outstanding" && st.pending.as_ref().is_some_and(|p| p.resumed) {
                    // the hub is still forwarding the lock we sent before the restart
                    return Ok(Some(json!({"status": "pending", "why": "lock_outstanding"})));
                }
                // the hub refused (or the provider did, through it): nothing was completed with t,
                // unless the provider's signed ROUTE-STATE already says it was paid
                let lock_id = st.pending.as_ref().map(|p| p.lock_id.clone()).unwrap_or_default();
                if self.via_provider(&mut st) {
                    return Ok(Some(json!({"status": "paid", "amount": d, "fee": f, "lockId": lock_id, "via": "provider"})));
                }
                *st.stats.refused.entry(code.clone()).or_insert(0) += 1;
                let detail = doc.get("detail").and_then(Value::as_str).unwrap_or("").to_string();
                let shard = st.pending.take().map(|p| {
                    self.void(&mut st, &p, &format!("hub: {code}"));
                    p.shard
                });
                self.persist_lock_state(&st, shard.as_ref());
                return Ok(Some(json!({"status": "refused", "error": code, "detail": detail})));
            }
        }
        Ok(Some(json!({"status": "pending", "http": status})))
    }

    // --- background locking ----------------------------------------------------------------------

    /// One pass: try a lock for every shard.
    pub fn tick(&self) {
        for sh in self.shards() {
            if self.stop.load(Ordering::Relaxed) {
                return;
            }
            if let Err(e) = self.lock(&sh) {
                self.event(json!({"event": "lock_error", "provider": sh.origin, "error": e.code}));
            }
        }
    }

    /// Run [`RoutePayer::tick`] every `interval` on a background thread.
    pub fn start(self: &Arc<Self>, interval: Duration) {
        self.stop.store(false, Ordering::Relaxed);
        let me = self.clone();
        let h = std::thread::Builder::new().name("route-payer".into()).spawn(move || {
            let mut next = Instant::now();
            while !me.stop.load(Ordering::Relaxed) {
                next += interval;
                me.tick();
                let now = Instant::now();
                if next > now {
                    std::thread::sleep(next - now);
                }
            }
        }).expect("spawn");
        *lk(&self.thread) = Some(h);
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = lk(&self.thread).take() {
            let _ = h.join();
        }
    }

    /// Cooperative close of ch1: the hub closes with the best state it holds (every completed lock
    /// is already a plain state there, so no final state is needed).
    pub fn close(&self) -> Result<Value> {
        let (chan, url) = {
            let st = lk(&self.st);
            let ch = st.ch.as_ref().ok_or_else(|| ChannelError::code("no_channel"))?;
            let cu = ch.accepted.get("extra").and_then(|e| e.get("closeUrl")).and_then(Value::as_str).unwrap_or(CLOSE_PATH).to_string();
            (ch.params.channel_id(), format!("{}{cu}", self.hub_url))
        };
        let sig = hex::encode(self.signer.sign_close(&chan)?);
        self.post(&url, &json!({"chan": chan, "sig": sig}))
    }

    /// Meters, locks and counters.
    pub fn summary(&self) -> Value {
        let st = lk(&self.st);
        let shards: serde_json::Map<String, Value> = lk(&self.shards).iter().map(|(u, s)| {
            let x = s.snapshot();
            (u.clone(), json!({"accrued_amsat": x.accrued_amsat.to_string(), "seen_amsat": x.seen_amsat.to_string(), "paid_sat": x.paid_sat,
                               "locked_sat": x.locked_sat, "calls": x.calls, "stopped": x.stopped, "pay_to": s.pay_to, "session": s.session}))
        }).collect();
        json!({"chan": st.ch.as_ref().map(|c| c.params.channel_id()), "routed_sat": st.routed, "fee_paid_sat": st.fee_paid,
               "fee_units": st.fee_units.to_string(), "signed": st.signed, "locks": st.stats.locks, "floor_locks": st.stats.floor_locks,
               "voided": st.stats.voided, "via_provider": st.stats.via_provider,
               "refused": st.stats.refused.iter().map(|(k, v)| (k.clone(), Value::from(*v))).collect::<serde_json::Map<String, Value>>(), "shards": shards})
    }

    pub fn stats(&self) -> PayerStats {
        lk(&self.st).stats.clone()
    }

    /// (routed, fee_paid, signed) on ch1.
    pub fn totals(&self) -> (u64, u64, u64) {
        let st = lk(&self.st);
        (st.routed, st.fee_paid, st.signed)
    }

    /// The hub's live fee quote as last seen.
    pub fn quote(&self) -> Option<FeeQuote> {
        lk(&self.st).quote.clone()
    }

    /// (routed, fee units, fee paid, signed) on ch1.
    pub fn counters(&self) -> (u64, u128, u64, u64) {
        let st = lk(&self.st);
        (st.routed, st.fee_units, st.fee_paid, st.signed)
    }

    pub fn hub_pay_to(&self) -> String {
        lk(&self.st).hub_pay_to.clone()
    }

    pub fn signer(&self) -> &Arc<dyn RouteSigner> {
        &self.signer
    }

    /// ch1's accepted requirements and a fresh request seq (to build a request by hand: tests,
    /// tools).
    #[doc(hidden)]
    pub fn next_seq(&self) -> Option<(u64, Value)> {
        let mut st = lk(&self.st);
        let ch = st.ch.as_mut()?;
        ch.seq += 1;
        Some((ch.seq, ch.accepted.clone()))
    }

    /// Rewind ch1's request seq (tests: a stale seq).
    #[doc(hidden)]
    pub fn set_seq(&self, seq: u64) {
        if let Some(ch) = lk(&self.st).ch.as_mut() {
            ch.seq = seq;
        }
    }

    /// The pending lock, if any: `{lockId, d, f, cum, floor, until}`.
    pub fn pending(&self) -> Option<Value> {
        lk(&self.st).pending.as_ref().map(|p| json!({"lockId": p.lock_id, "d": p.d, "f": p.f, "cum": p.cum, "floor": p.floor, "until": p.until}))
    }

    /// Treat the pending lock's invoice as expired now and re-check it (tests).
    #[doc(hidden)]
    pub fn expire_pending(&self) {
        if let Some(p) = lk(&self.st).pending.as_mut() {
            p.until = now_f() - 1.0;
        }
        self.check_pending(None);
    }

    /// The cum of the last lock given up.
    pub fn last_given_up(&self) -> Option<u64> {
        lk(&self.st).given_up.last().map(|g| g.cum)
    }

    /// Adopt a hub view (`{bestCum, routedSat, feeUnits, feePaid}`) if it is a lock we gave up.
    #[doc(hidden)]
    pub fn try_resync(&self, doc: &Value) -> bool {
        let mut st = lk(&self.st);
        self.resync(&mut st, doc)
    }

    /// ch1's parameters.
    pub fn ch1_params(&self) -> Option<ChannelParams> {
        lk(&self.st).ch.as_ref().map(|c| c.params.clone())
    }
}
