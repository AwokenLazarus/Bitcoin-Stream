//! The provider (resource server) side: a facilitator-less x402 `batch-settlement` (XBT channel) verifier around an
//! application handler. A port of B1 `XbtChannelProvider` (v1.1 + v1.2): the 402 challenge, open,
//! paid calls with request auth and signed receipts, postpay/prepay billing, metered charges,
//! hash-locked conditional sales, cooperative close, rollover, the facilitator endpoints and the
//! expiry watcher. Hub routing (route offers, routed sessions, `/x402/xbt-channel/lock`) lives in
//! [`crate::route_seller`] (AGP-026).
//!
//! [`Provider::serve`] is transport-independent: give it the method, path, headers and body of a
//! request and send back what it returns. The `http-server` feature serves it on std::net.
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt_primitives::ecdsa;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::sighash::SIGHASH_ALL_UNIFIED;
use xbt_primitives::tx::{OutPoint, Tx, TxIn, TxOut};

use crate::channel::{canonical_chan, channel_auth_key, channel_payee_secret, check_payout_spk, settle_due,
                     cpfp_child, sign_p2wpkh, sign_with_type, ChannelParams, FeePayer, Payee, DERIVATION, DUST};
use crate::conditional::{encrypt, ConditionalParams, CSV_DELTA};
use crate::error::{fail, ChannelError, Result};
use crate::funding::{check_funding, ChainBackend, FundingPolicy};
use crate::json::{dumps, py_int, py_str, py_u64, truthy};
use crate::ledger::{ChannelState, Ledger};
use crate::wire::*;

/// vsize of a CPFP child (one P2WPKH input, one P2WPKH output: 109.25 vB, rounded up).
pub const CPFP_CHILD_VSIZE: u64 = 110;

/// The header the HTTP server sets to the TCP peer's IP address. A client-sent header of this name
/// never reaches the service.
pub const PEER_HEADER: &str = "X-Xbt402-Peer";

/// A response for the transport to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status: u16, headers: Vec<(String, String)>, body: impl Into<Vec<u8>>) -> Self {
        Self { status, headers, body: body.into() }
    }

    fn json(status: u16, v: &Value) -> Self {
        Self::new(status, vec![("Content-Type".into(), "application/json".into())], dumps(v))
    }

    fn text(status: u16, s: &str) -> Self {
        Self::new(status, vec![], s.as_bytes().to_vec())
    }

    /// The first header named `name` (any case).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// `handler(method, path, body)`: the paid API itself.
pub type Handler = Box<dyn Fn(&str, &str, &[u8]) -> HttpResponse + Send + Sync>;
/// `price(method, path)`: the per-call maximum in sats.
pub type PriceFn = Box<dyn Fn(&str, &str) -> u64 + Send + Sync>;
/// `charge(method, path, status, body)`: what the call actually costs (metered), clamped to the price.
pub type ChargeFn = Box<dyn Fn(&str, &str, u16, &[u8]) -> i64 + Send + Sync>;

/// Provider settings (the reference's constructor keywords).
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    /// CAIP-2 network id (`bip122:...`).
    pub network: String,
    /// "postpay" or "prepay".
    pub billing: String,
    pub close_fee: u64,
    pub close_margin: u32,
    pub policy: FundingPolicy,
    /// Bitcoind height cache.
    pub height_ttl: Duration,
    /// Sats the hash-lock claim pays out of condAmount.
    pub claim_fee: u64,
    pub max_body: usize,
    pub route_max_body: HashMap<String, usize>,
    /// Settle once the net payout is at least this many close fees.
    pub settle_multiple: u64,
    /// Plain channels (v1.1 default: payer).
    pub close_fee_payer: FeePayer,
    /// Hub-funded channels (v1.2 default: payee).
    pub route_close_fee_payer: FeePayer,
    /// Blocks before the close margin a rollover is due anyway.
    pub rollover_grace: u32,
    /// AGP-053 make-before-break: a hub-bound channel's rollover child is taken unconfirmed (its parent
    /// is our own confirmed channel, and only we can sign a conflicting spend of it before its expiry),
    /// up to this cum while it stays unconfirmed. None: two settlements' worth (2 × settle_multiple ×
    /// close_fee); 0: never (the hub opens it at minConf).
    pub rollover_zero_conf_max: Option<u64>,
    /// AGP-056: a hub rolls a ch2 over at `settle_lock_multiple` × the largest lock when that is above
    /// our threshold (locks larger than settle_multiple × close_fee), so the default zero-conf cap
    /// follows it: at least 2 × this × the largest lock the parent's line took. An explicit
    /// `rollover_zero_conf_max` is used as it is.
    pub settle_lock_multiple: u64,
    /// AGP-054: a path makes each routed session's meter (seq, calls, accrued) durable before its
    /// ROUTE-STATE leaves, written ahead while the handler runs (`RouteOffer::precharge`). None: off.
    pub route_wal: Option<std::path::PathBuf>,
    /// AGP-067 (review C1): most sats a CPFP child of one close may pay. The watcher bumps a close
    /// still unconfirmed before expiry with a child spending this provider's own close output (never
    /// more than that output less dust). 0: never bump.
    pub close_bump_max_fee: u64,
    /// sat/vB floor of a close's package feerate (below any estimate or mempool floor).
    pub close_min_feerate: f64,
    /// A close unconfirmed this many blocks after its last send, with half the close margin or less
    /// left to expiry, has its package feerate at least doubled whatever the estimate says.
    pub close_bump_blocks: u32,
}

impl ProviderConfig {
    pub fn new(network: &str) -> Self {
        let close_margin = 144;
        Self {
            network: network.to_string(),
            billing: "postpay".into(),
            close_fee: 600,
            close_margin,
            policy: FundingPolicy { min_expiry_blocks: 1_008, close_margin, ..FundingPolicy::default() },
            height_ttl: Duration::from_secs(2),
            claim_fee: 300,
            max_body: MAX_BODY,
            route_max_body: HashMap::new(),
            settle_multiple: 20,
            close_fee_payer: FeePayer::Payer,
            route_close_fee_payer: FeePayer::Payee,
            rollover_grace: 36,
            rollover_zero_conf_max: None,
            settle_lock_multiple: 4,
            route_wal: None,
            close_bump_max_fee: 10_000,
            close_min_feerate: 1.0,
            close_bump_blocks: 3,
        }
    }

    /// The effective zero-conf rollover cap (AGP-053), whatever the locks.
    pub fn zero_conf_max(&self) -> u64 {
        self.rollover_zero_conf_max.unwrap_or_else(|| self.settle_multiple.saturating_mul(2).saturating_mul(self.close_fee))
    }

    /// The most a rollover child takes while unconfirmed when the largest lock its parent's line took
    /// is `max_lock`: `rollover_zero_conf_max`, and by default (AGP-056) at least 2 ×
    /// `settle_lock_multiple` × that lock, so a provider paid in locks larger than its settle
    /// threshold is not capped below one lock.
    pub fn zero_conf_max_for(&self, max_lock: u64) -> u64 {
        match self.rollover_zero_conf_max {
            Some(m) => m,
            None => self.zero_conf_max().max(self.settle_lock_multiple.saturating_mul(2).saturating_mul(max_lock)),
        }
    }
}

struct CondOffer {
    k: Vec<u8>,
    h: [u8; 32],
    price: u64,
    cipher: Vec<u8>,
    plain: Vec<u8>,
}

/// The facilitator-less `batch-settlement` (XBT channel) resource server.
pub struct Provider {
    pub cfg: ProviderConfig,
    chain: Arc<dyn ChainBackend>,
    secret: SecretKey,
    pay_to: String,
    ledger: Mutex<Ledger>,
    payees: Mutex<HashMap<String, Payee>>,
    auth_keys: Mutex<HashMap<String, [u8; 32]>>,
    height: Mutex<Option<(u32, Instant)>>,
    cond: Mutex<HashMap<String, CondOffer>>,
    pub(crate) price: PriceFn,
    pub(crate) handler: Handler,
    charge: Option<ChargeFn>,
    pub(crate) routes: crate::route_seller::RouteSeller,
    /// AGP-032: other schemes offered beside the channel binding (xbt-work).
    schemes: Vec<Arc<dyn crate::scheme::ProviderScheme>>,
    /// AGP-059: direct calls between their reservation and their settlement, per channel.
    in_call: Mutex<HashMap<String, u32>>,
    /// AGP-059: (channel, msat) of the reservations refunded when this provider started.
    recovered: Vec<(String, u64)>,
}

/// A hub's ch1 holds a routed lock that its best state does not cover (AGP-064): the one in flight
/// (`route_lock`), or one written off (`stale_locks`) above the best state, which the hub may still
/// have to pay on its ch2. Closing ch1 now would close below it, and so would rolling it over: both
/// spend its funding (AGP-078).
fn locks_open(st: &ChannelState) -> bool {
    truthy(st.extra.get("route_lock"))
        || st.extra.get("stale_locks").and_then(Value::as_array).is_some_and(|s| {
            s.iter().any(|x| py_u64(x.get("cum")).is_none_or(|c| c > st.best_cum))
        })
}

/// A close or rollover of this channel was signed and written ahead (`close_intent`, M8) and is not
/// recorded as its close yet: the node answered the broadcast with an error, or we stopped before
/// its answer. That transaction is complete and can still confirm, so the channel takes no state
/// above it (AGP-084): no paid call, no routed lock. It ends when the node shows the spend
/// ([`Provider::adopt_intent`]), when the watcher gets a close through, or when the client rolls
/// over or closes again.
pub(crate) fn intent_open(st: &ChannelState) -> bool {
    st.closed_txid.is_empty() && truthy(st.extra.get("close_intent"))
}

/// The channel is closed, or a spend of it may be on its way (see [`intent_open`]).
pub(crate) fn closing(st: &ChannelState) -> bool {
    !st.closed_txid.is_empty() || intent_open(st)
}

/// A direct call between its reservation and its settlement (AGP-059). Dropped unsettled (the
/// handler or the charge panicked), it refunds the reservation: nothing was charged.
struct InCall<'a> {
    prov: &'a Provider,
    cid: String,
    seq: u64,
    msat: u64,
    settled: bool,
}

impl<'a> InCall<'a> {
    fn new(prov: &'a Provider, cid: &str, seq: u64, msat: u64) -> Self {
        *lock(&prov.in_call).entry(cid.to_string()).or_insert(0) += 1;
        Self { prov, cid: cid.to_string(), seq, msat, settled: false }
    }
}

impl Drop for InCall<'_> {
    fn drop(&mut self) {
        {
            let mut n = lock(&self.prov.in_call);
            if let Some(c) = n.get_mut(&self.cid) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    n.remove(&self.cid);
                }
            }
        }
        if self.settled {
            return;
        }
        let mut l = lock(&self.prov.ledger);
        if let Some(mut st) = l.channels.get(&self.cid).cloned() {
            st.release(self.seq);
            st.spent_msat = st.spent_msat.saturating_sub(self.msat);
            let _ = self.prov.save_state(&mut l, &st);
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn path_key(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
}

/// The URL a request's payment binds: the origin of `url` (where the server was reached) and the
/// target it routes on. A `url` without an origin binds the target alone.
pub(crate) fn binding_url(url: &str, path: &str) -> String {
    format!("{}{path}", url_origin(url))
}

/// The provider's payTo secret kept in `path` (review C4): read it, or create it (64 hex chars,
/// mode 0600 on Unix, never overwritten). Every channel key derives from it, so a provider that
/// starts with a new one can no longer close a single channel it holds states for. On Unix a file
/// readable by group or others is refused.
pub fn load_or_create_secret(path: &Path) -> Result<SecretKey> {
    let bad = |m: String| ChannelError::new("key_file", format!("{}: {m}", path.display()));
    if let Some(d) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(d).map_err(|e| bad(e.to_string()))?;
    }
    if !path.exists() {
        // written whole under a private name, then linked into place: never a torn key, never an
        // overwrite of a key another starter linked first
        let mut name = path.as_os_str().to_owned();
        name.push(format!(".new.{}", std::process::id()));
        let tmp = std::path::PathBuf::from(name);
        let sk = SecretKey::from_slice(&random32()).map_err(|e| bad(e.to_string()))?;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let written = o.open(&tmp).and_then(|mut f| {
            use std::io::Write as _;
            writeln!(f, "{}", hex::encode(sk.secret_bytes()))?;
            f.sync_all()
        });
        let linked = written.and_then(|_| std::fs::hard_link(&tmp, path));
        let _ = std::fs::remove_file(&tmp);
        match linked {
            Ok(()) => {
                let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
                std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(|e| bad(e.to_string()))?;
                return Ok(sk);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(bad(e.to_string())),
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path).map_err(|e| bad(e.to_string()))?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(bad(format!("mode {:o} lets others read the payTo key: chmod 600", mode & 0o777)));
        }
    }
    let text = std::fs::read_to_string(path).map_err(|e| bad(e.to_string()))?;
    let raw = hex::decode(text.trim()).map_err(|_| bad("not a hex secret".into()))?;
    SecretKey::from_slice(&raw).map_err(|_| bad("not a secp256k1 secret".into()))
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("OS randomness");
    b
}

fn hexs(v: Option<&Value>) -> Result<Vec<u8>> {
    let s = v.and_then(Value::as_str).ok_or_else(|| ChannelError::new("bad_request", "hex string expected"))?;
    hex::decode(s).map_err(|_| ChannelError::new("bad_request", "not hex"))
}

fn field<'a>(v: &'a Value, k: &str) -> Result<&'a Value> {
    v.get(k).ok_or_else(|| ChannelError::new("bad_request", format!("'{k}'")))
}

impl Provider {
    pub fn new(chain: Arc<dyn ChainBackend>, pay_to_secret: SecretKey, cfg: ProviderConfig, ledger: Ledger,
               price: PriceFn, handler: Handler) -> Result<Self> {
        if cfg.billing != "postpay" && cfg.billing != "prepay" {
            return fail("bad_config", "billing is postpay or prepay");
        }
        if cfg.max_body < 1 {
            return fail("bad_config", "max_body must be >= 1");
        }
        let mut ledger = ledger;
        // AGP-059: a reservation still recorded was never settled (a crash mid-call): not charged
        let mut recovered = Vec::new();
        for (cid, st) in ledger.channels.iter_mut() {
            let msat = st.refund_reservations();
            if msat > 0 {
                recovered.push((cid.clone(), msat));
            }
        }
        if !recovered.is_empty() {
            let ids: Vec<&str> = recovered.iter().map(|(c, _)| c.as_str()).collect();
            ledger.save(&ids)?;
        }
        let routes = crate::route_seller::RouteSeller::new(&ledger, pay_to_secret, &cfg.network, cfg.settle_multiple,
                                                           cfg.route_wal.as_deref());
        Ok(Self {
            pay_to: hex::encode(ecdsa::pubkey(&pay_to_secret)),
            cfg,
            chain,
            secret: pay_to_secret,
            ledger: Mutex::new(ledger),
            payees: Mutex::new(HashMap::new()),
            auth_keys: Mutex::new(HashMap::new()),
            height: Mutex::new(None),
            cond: Mutex::new(HashMap::new()),
            price,
            handler,
            charge: None,
            routes,
            schemes: vec![],
            in_call: Mutex::new(HashMap::new()),
            recovered,
        })
    }

    /// Meter calls: the charge may lower (never raise) the price after serving.
    pub fn with_charge(mut self, charge: ChargeFn) -> Self {
        self.charge = Some(charge);
        self
    }

    /// Offer another scheme beside the channel binding (AGP-032): its requirements follow the channel's in
    /// every unpaid 402, its control endpoints are served, and a PAYMENT-SIGNATURE whose
    /// `accepted.scheme` is its scheme is verified and settled by it.
    pub fn with_scheme(mut self, s: Arc<dyn crate::scheme::ProviderScheme>) -> Self {
        self.schemes.push(s);
        self
    }

    /// The compressed payTo key (hex).
    pub fn pay_to(&self) -> &str {
        &self.pay_to
    }

    /// The reservations refunded when this provider started (AGP-059): `(channel, msat)` of metered
    /// calls that were in flight when the last process stopped. They were never charged.
    pub fn recovered_reservations(&self) -> &[(String, u64)] {
        &self.recovered
    }

    /// The ledger, locked (the hub's ch1 book and the routing endpoints work under it).
    pub(crate) fn ledger_lock(&self) -> MutexGuard<'_, Ledger> {
        lock(&self.ledger)
    }

    /// A snapshot of one channel's state.
    pub fn channel_state(&self, chan: &str) -> Option<ChannelState> {
        let c = canonical_chan(chan).ok()?;
        lock(&self.ledger).channels.get(&c).cloned()
    }

    /// Edit a channel's state and save it (tests).
    #[doc(hidden)]
    pub fn with_state<R>(&self, chan: &str, f: impl FnOnce(&mut ChannelState) -> R) -> Result<R> {
        let mut l = lock(&self.ledger);
        let mut st = l.channels.get(chan).cloned().ok_or_else(|| ChannelError::code("unknown_channel"))?;
        let r = f(&mut st);
        self.save_state(&mut l, &st)?;
        Ok(r)
    }

    /// This provider's best close of a channel as a signed tx (tests: a close that replaces a rollover).
    #[doc(hidden)]
    pub fn best_close_hex(&self, chan: &str) -> Result<String> {
        let st = self.channel_state(chan).ok_or_else(|| ChannelError::code("unknown_channel"))?;
        Ok(self.close_tx(&st)?.0.to_hex())
    }

    pub fn channel_ids(&self) -> Vec<String> {
        lock(&self.ledger).channels.keys().cloned().collect()
    }

    /// Chain tip, cached for `height_ttl` so a paid call costs no RPC.
    pub fn height(&self) -> Result<u32> {
        let mut h = lock(&self.height);
        if let Some((n, at)) = *h {
            if at.elapsed() <= self.cfg.height_ttl {
                return Ok(n);
            }
        }
        let n = self.chain.block_count()?;
        *h = Some((n, Instant::now()));
        Ok(n)
    }

    /// Request-body bound for this path: `max_body` wins, then a route option, then the default.
    pub fn body_limit(&self, path: &str, max_body: Option<usize>) -> usize {
        if let Some(n) = max_body {
            return n.max(1);
        }
        self.cfg.route_max_body.get(path_key(path)).copied().unwrap_or(self.cfg.max_body)
    }

    /// The PaymentRequirements this provider offers at `price` sats per call.
    pub fn requirements(&self, price: u64) -> Value {
        let p = &self.cfg.policy;
        let mut req = json!({
            "scheme": SCHEME, "network": self.cfg.network, "amount": price.to_string(), "asset": "XBT:sat",
            "payTo": self.pay_to, "maxTimeoutSeconds": 30,
            "extra": {"minCapacity": p.min_capacity.to_string(), "maxCapacity": p.max_capacity.to_string(),
                      "minExpiryBlocks": p.min_expiry_blocks, "maxExpiryBlocks": p.max_expiry_blocks,
                      "closeMarginBlocks": self.cfg.close_margin, "minConf": p.min_conf,
                      "closeFeeSat": self.cfg.close_fee.to_string(), "openUrl": OPEN_PATH,
                      "closeUrl": CLOSE_PATH, "billing": self.cfg.billing, "derivation": DERIVATION,
                      "assetTransferMethod": ASSET_TRANSFER_METHOD}});
        if self.cfg.close_fee_payer != FeePayer::Payer {
            req["extra"]["closeFeePayer"] = self.cfg.close_fee_payer.as_str().into();
        }
        req
    }

    /// GET /x402/xbt-channel/terms: what a hub needs to open a hub-funded channel here.
    pub fn terms(&self) -> Value {
        let mut req = self.requirements(0);
        let ex = &mut req["extra"];
        ex["settleMultiple"] = self.cfg.settle_multiple.into();
        ex["closeFeePayer"] = self.cfg.route_close_fee_payer.as_str().into();
        ex["rolloverGraceBlocks"] = self.cfg.rollover_grace.into();
        ex["routes"] = json!(self.routes.offer_paths());
        req
    }

    pub fn supported(&self) -> Value {
        json!({"kinds": [{"x402Version": 2, "scheme": SCHEME, "network": self.cfg.network}], "extensions": [], "signers": {}})
    }

    fn payment_required(&self, url: &str, price: u64, error: &str, st: Option<&ChannelState>) -> HttpResponse {
        let body = self.payment_required_doc(url, price, error, st);
        self.required_response(&body)
    }

    /// The PaymentRequired document of a 402.
    pub(crate) fn payment_required_doc(&self, url: &str, price: u64, error: &str, st: Option<&ChannelState>) -> Value {
        let mut body = json!({"x402Version": 2, "error": error, "resource": {"url": url}, "accepts": [self.requirements(price)]});
        if let Some(st) = st {
            body["channel"] = json!({"chan": st.params.channel_id(), "cum": st.best_cum.to_string(), "seq": st.seq,
                                     "spentMsat": st.spent_msat.to_string()});
        }
        body
    }

    pub(crate) fn required_response(&self, body: &Value) -> HttpResponse {
        HttpResponse::new(402, vec![("PAYMENT-REQUIRED".into(), b64json(body)), ("Content-Type".into(), "application/json".into())],
                          dumps(body))
    }

    // --- per-channel keys ------------------------------------------------------------------

    /// The channel's Payee (no state), derived once per channel.
    fn channel_payee(&self, p: &ChannelParams) -> Result<Payee> {
        let id = p.channel_id();
        if let Some(pe) = lock(&self.payees).get(&id) {
            return Ok(pe.clone());
        }
        let secret = channel_payee_secret(&self.cfg.network, &self.secret, &p.payer_pub, p.expiry)?;
        let pe = Payee::new(p.clone(), secret)?;
        lock(&self.payees).insert(id, pe.clone());
        Ok(pe)
    }

    pub(crate) fn payee(&self, st: &ChannelState) -> Result<Payee> {
        let mut pe = self.channel_payee(&st.params)?;
        pe.best_amount = st.best_cum;
        pe.best_sig = hex::decode(&st.best_sig).unwrap_or_default();
        Ok(pe)
    }

    pub(crate) fn chan_secret(&self, p: &ChannelParams) -> Result<SecretKey> {
        Ok(*self.channel_payee(p)?.secret())
    }

    /// payload.auth is the channel's HMAC over this request and a seq above every earlier one.
    /// `bind` is the request's URL as [`request_digest_v2`] binds it ([`binding_url`]).
    pub(crate) fn authentic(&self, st: &ChannelState, pl: &Value, method: &str, bind: &str, body: &[u8]) -> bool {
        let Some(seq) = py_int(pl.get("seq")) else { return false };
        if seq <= st.seq as i128 {
            return false;
        }
        let cid = st.params.channel_id();
        let key = {
            let cached = lock(&self.auth_keys).get(&cid).copied();
            match cached {
                Some(k) => k,
                None => {
                    let Ok(secret) = self.chan_secret(&st.params) else { return false };
                    let Ok(k) = channel_auth_key(&secret, &st.params.payer_pub) else { return false };
                    lock(&self.auth_keys).insert(cid.clone(), k);
                    k
                }
            }
        };
        let sig = if truthy(pl.get("sig")) { py_str(pl.get("sig")) } else { String::new() };
        let want = request_auth(&key, &cid, Some(&Value::String(seq.to_string())), pl.get("cum"),
                                Some(&sig), &request_digest_v2(method, bind, body));
        let got = match pl.get("auth") {
            None => String::new(),
            v => py_str(v),
        };
        auth_eq(&want, &got)
    }

    /// Apply a payload's state. At most one ECDSA verify. Parse problems are `bad_payload`.
    fn apply(&self, st: &mut ChannelState, pl: &Value) -> Result<()> {
        let cum = py_int(pl.get("cum")).ok_or_else(|| ChannelError::new("bad_payload", "cum"))?;
        if cum > st.best_cum as i128 {
            if pl.get("sig").is_none() {
                return fail("bad_sig", "a higher cum needs a signature");
            }
            let cum = u64::try_from(cum).map_err(|_| ChannelError::new("bad_amount", "cum out of range"))?;
            let sig = pl.get("sig").and_then(Value::as_str).and_then(|s| hex::decode(s).ok())
                .ok_or_else(|| ChannelError::new("bad_payload", "sig"))?;
            let mut payee = self.payee(st)?;
            payee.accept(cum, &sig)?;
            st.best_cum = cum;
            st.best_sig = hex::encode(&sig);
        } else if cum < st.best_cum as i128 {
            return fail("stale_amount", format!("have {}, got {cum}", st.best_cum));
        } else if truthy(pl.get("sig")) {
            let sig = pl.get("sig").and_then(Value::as_str).and_then(|s| hex::decode(s).ok())
                .ok_or_else(|| ChannelError::new("bad_payload", "sig"))?;
            if sig != hex::decode(&st.best_sig).unwrap_or_default() {
                return fail("bad_sig", "signature differs from the stored state for this cum");
            }
        }
        Ok(())
    }

    // --- control endpoints -----------------------------------------------------------------

    /// POST /x402/xbt-channel/open. With `"preflight": true` and no outpoint (review C2) it answers
    /// whether it would open a channel on exactly these terms, before the payer funds it: every
    /// check that does not need the funding output, nothing recorded.
    pub fn open(&self, req: &Value) -> Result<Value> {
        let (p, hub_req) = self.open_terms(req)?;
        let c = field(req, "channel")?;
        if truthy(req.get("preflight")) {
            return self.open_preflight(p, c);
        }
        self.open_funded(p, hub_req, c)
    }

    /// The preflight's checks past [`open_terms`](Self::open_terms): the capacity and the blocks to
    /// expiry against the funding policy, as `check_funding` will apply them.
    fn open_preflight(&self, mut p: ChannelParams, c: &Value) -> Result<Value> {
        let pol = &self.cfg.policy;
        p.capacity = py_u64(c.get("capacity")).ok_or_else(|| ChannelError::new("bad_request", "capacity"))?;
        if !(pol.min_capacity..=pol.max_capacity).contains(&p.capacity) {
            return fail("bad_capacity", format!("capacity outside [{}, {}]", pol.min_capacity, pol.max_capacity));
        }
        let left = p.expiry as i64 - self.height()? as i64;
        if left < pol.min_expiry_blocks as i64 || left > pol.max_expiry_blocks as i64 {
            return fail("bad_expiry", format!("{left} blocks to expiry, need [{}, {}]", pol.min_expiry_blocks, pol.max_expiry_blocks));
        }
        let mut out = json!({"preflight": true, "expiry": p.expiry, "maxCum": p.max_amount().to_string(), "minConf": pol.conf_for(p.capacity)});
        if p.close_fee_payer != FeePayer::Payer {
            out["closeFeePayer"] = p.close_fee_payer.as_str().into();
            out["minCum"] = p.min_amount().to_string().into();
        }
        Ok(out)
    }

    /// The channel terms of an open request (no outpoint yet), checked: the network, the keys, the
    /// close-fee payer and the redeem script this provider would derive.
    fn open_terms<'a>(&self, req: &'a Value) -> Result<(ChannelParams, Option<&'a Value>)> {
        if req.get("network").and_then(Value::as_str) != Some(self.cfg.network.as_str()) {
            return fail("wrong_network", format!("this provider is on {}", self.cfg.network));
        }
        let c = field(req, "channel")?;
        let payer_pub = hexs(c.get("payerPub"))?;
        ecdsa::public_key(&payer_pub).map_err(|e| ChannelError::new("bad_request", e.to_string()))?;
        let payer_spk = match c.get("payerSpk") {
            Some(v) if truthy(Some(v)) => Some(check_payout_spk(v.as_str().unwrap_or("-"))?),
            _ => None,
        };
        let fee_payer = match c.get("closeFeePayer") {
            None => FeePayer::Payer,
            Some(v) => FeePayer::parse(v.as_str().unwrap_or(""))
                .map_err(|_| ChannelError::new("bad_fee_payer", format!("closeFeePayer {v} not offered for this channel")))?,
        };
        let hub_req = req.get("hub").filter(|h| truthy(Some(h)));
        let offered = if hub_req.is_some() { self.cfg.route_close_fee_payer } else { self.cfg.close_fee_payer };
        if fee_payer != FeePayer::Payer && fee_payer != offered {
            return fail("bad_fee_payer", format!("closeFeePayer {:?} not offered for this channel", fee_payer.as_str()));
        }
        let expiry = py_u64(c.get("expiry")).and_then(|e| u32::try_from(e).ok())
            .ok_or_else(|| ChannelError::new("bad_request", "expiry"))?;
        let pay_to = hex::decode(&self.pay_to).unwrap_or_default();
        let p = ChannelParams::derive(&pay_to, &payer_pub, expiry, self.cfg.close_fee, payer_spk, &self.cfg.network, fee_payer)?;
        let redeem = field(c, "redeemScript")?.as_str().ok_or_else(|| ChannelError::new("bad_request", "redeemScript"))?;
        if redeem.to_ascii_lowercase() != hex::encode(p.script()) {
            return fail("bad_funding", "redeemScript does not match payTo/payerPub/expiry");
        }
        Ok((p, hub_req))
    }

    fn open_funded(&self, mut p: ChannelParams, hub_req: Option<&Value>, c: &Value) -> Result<Value> {
        let vout = py_u64(c.get("vout")).ok_or_else(|| ChannelError::new("bad_request", "vout"))?;
        let txid = field(c, "txid")?.as_str().ok_or_else(|| ChannelError::new("unknown_channel", "chan must be txid:vout"))?;
        let chan = canonical_chan(&format!("{txid}:{vout}"))?;
        let vout = u32::try_from(vout).map_err(|_| ChannelError::new("unknown_channel", "vout out of range"))?;
        let capacity = py_u64(c.get("capacity")).ok_or_else(|| ChannelError::new("bad_request", "capacity"))?;
        p = p.with_funding(chan.split(':').next().unwrap_or(""), vout, capacity)?;
        let mut hub = String::new();
        if let Some(h) = hub_req {
            hub = h.get("payTo").map(|v| py_str(Some(v))).unwrap_or_default();
            let hub_pub = hex::decode(&hub).map_err(|_| ChannelError::new("bad_request", "hub payTo is not hex"))?;
            let sig = hexs(h.get("sig"))?;
            if !ecdsa::verify(&hub_pub, &hub_channel_message(&p.channel_id()), &sig) {
                return fail("bad_sig", "hub binding not signed by the hub's payTo");
            }
        }
        let cid = p.channel_id();
        let (confs, zc) = {
            let mut l = lock(&self.ledger);
            if l.channels.contains_key(&cid) {
                return fail("duplicate_channel", "");
            }
            let (confs, zc) = match check_funding(self.chain.as_ref(), &p, &self.cfg.policy) {
                Ok(c) => (c, None),
                Err(e) if e.code == "unconfirmed" => match self.zero_conf_child(&l, &p, &hub)? {
                    Some(zc) => {
                        let pol = FundingPolicy { zero_conf_max: p.capacity, ..self.cfg.policy.clone() };
                        (check_funding(self.chain.as_ref(), &p, &pol)?, Some(zc))
                    }
                    // AGP-057: not a child we take unconfirmed. A block that came while we looked makes
                    // it neither: the funding read above had no confirmation yet, and the parent is now
                    // spent in that block. Look at the funding once more (still unconfirmed: the same refusal)
                    None if !hub.is_empty() => (check_funding(self.chain.as_ref(), &p, &self.cfg.policy)?, None),
                    None => return Err(e),
                },
                Err(e) => return Err(e),
            };
            let mut st = ChannelState::new(p.clone());
            if !hub.is_empty() {
                st.extra.insert("hub".into(), hub.as_str().into());
                // a rollover child carries its line's largest lock on (AGP-056: the next child's cap)
                let big = l.channels.values()
                    .filter(|s| s.extra.get("rollover_to").and_then(Value::as_str) == Some(cid.as_str())
                            && s.extra.get("hub").and_then(Value::as_str) == Some(hub.as_str()))
                    .map(|s| py_u64(s.extra.get("max_lock")).unwrap_or(0)).max().unwrap_or(0);
                if big > 0 {
                    st.extra.insert("max_lock".into(), big.into());
                }
            }
            if let Some(zc) = &zc {
                st.extra.insert("zero_conf".into(), zc.clone());
            }
            l.channels.insert(cid.clone(), st);
            l.save(&[&cid])?;
            (confs, zc)
        };
        let mut out = json!({"chan": cid, "expiry": p.expiry, "maxCum": p.max_amount().to_string(), "confirmations": confs});
        if p.close_fee_payer != FeePayer::Payer {
            out["closeFeePayer"] = p.close_fee_payer.as_str().into();
            out["minCum"] = p.min_amount().to_string().into();
        }
        if let Some(zc) = zc {
            out["zeroConf"] = json!({"parent": zc["parent"], "maxCum": py_u64(zc.get("maxCum")).unwrap_or(0).to_string(), "until": zc["until"]});
        }
        Ok(out)
    }

    /// AGP-053: the unconfirmed channel `p` is the rollover child of one of our hub-bound channels (the
    /// tx we co-signed and broadcast, `rollover_to`), bound to the same hub, whose own funding is
    /// confirmed (conf_for) and which is before its close margin: take it now, bounded (`zero_conf` on
    /// the child). Before the parent's expiry only this provider can sign a spend of the parent other
    /// than that rollover, so the child exists unless we replace it ourselves, or the rollover is still
    /// unconfirmed at the parent's expiry (the payer's refund): locks are taken until `until` only.
    fn zero_conf_child(&self, l: &Ledger, p: &ChannelParams, hub: &str) -> Result<Option<Value>> {
        let cap = self.cfg.zero_conf_max();
        if hub.is_empty() || cap == 0 {
            return Ok(None);
        }
        let cid = p.channel_id();
        let parent = l.channels.values().find(|s| {
            s.extra.get("rollover_to").and_then(Value::as_str) == Some(cid.as_str()) && s.extra.get("hub").and_then(Value::as_str) == Some(hub)
        });
        let Some(parent) = parent else { return Ok(None) };
        let pp = &parent.params;
        let need = self.cfg.policy.conf_for(pp.capacity);
        let until = pp.expiry.saturating_sub(self.cfg.close_margin);
        if self.height()? >= until || !self.confirmed(&pp.funding_txid(), pp.funding_vout(), need)? {
            return Ok(None);
        }
        if self.chain.get_tx_out(&p.funding_txid(), p.funding_vout(), true)?.is_none() {
            return Ok(None);
        }
        let cap = self.cfg.zero_conf_max_for(py_u64(parent.extra.get("max_lock")).unwrap_or(0));
        Ok(Some(json!({"parent": pp.channel_id(), "need": need, "maxCum": cap, "until": until, "confirmed": false})))
    }

    /// The output is in a block with `need` confirmations (spent in the mempool or not).
    fn confirmed(&self, txid: &str, vout: u32, need: u32) -> Result<bool> {
        Ok(self.chain.get_tx_out(txid, vout, false)?.is_some_and(|u| u.confirmations >= need))
    }

    /// An unconfirmed rollover child (AGP-053) is served while it is in the mempool, its parent still
    /// has its confirmations (a reorg of the parent ends it), and before the parent's margin.
    fn zero_conf_ok(&self, st: &ChannelState, h: u32) -> Result<bool> {
        let Some(zc) = st.extra.get("zero_conf").filter(|z| z.is_object()) else { return Ok(false) };
        if h as u64 >= py_u64(zc.get("until")).unwrap_or(0) {
            return Ok(false);
        }
        let p = &st.params;
        if self.chain.get_tx_out(&p.funding_txid(), p.funding_vout(), true)?.is_none() {
            return Ok(false);
        }
        let parent = zc.get("parent").and_then(Value::as_str).unwrap_or("");
        let Some((ptxid, pvout)) = parent.split_once(':') else { return Ok(false) };
        let need = py_u64(zc.get("need")).unwrap_or(1) as u32;
        self.confirmed(ptxid, pvout.parse().unwrap_or(u32::MAX), need)
    }

    /// Not an unconfirmed rollover child (AGP-053): a plain channel, or a child that confirmed (as the
    /// watcher last saw it, or `live` from the node now, recorded in `st`).
    pub(crate) fn zc_confirmed(&self, st: &mut ChannelState, live: bool) -> Result<bool> {
        let Some(zc) = st.extra.get("zero_conf").filter(|z| z.is_object()).cloned() else { return Ok(true) };
        if truthy(zc.get("confirmed")) {
            return Ok(true);
        }
        let p = &st.params;
        if live && self.confirmed(&p.funding_txid(), p.funding_vout(), self.cfg.policy.conf_for(p.capacity))? {
            let mut z = zc;
            z["confirmed"] = true.into();
            st.extra.insert("zero_conf".into(), z);
            return Ok(true);
        }
        Ok(false)
    }

    /// This provider's settlement policy: the net payout is at least settle_multiple × closeFee,
    /// or the channel is within `margin` blocks of its close margin at `tip`.
    pub fn settle_due(&self, p: &ChannelParams, cum: u64, tip: Option<u32>, margin: u32) -> bool {
        if settle_due(p, cum, self.cfg.settle_multiple) {
            return true;
        }
        tip.is_some_and(|t| t as i64 >= p.expiry as i64 - self.cfg.close_margin as i64 - margin as i64)
    }

    fn channel_id_of(&self, chan: Option<&Value>) -> Result<String> {
        let c = chan.and_then(Value::as_str).ok_or_else(|| ChannelError::new("unknown_channel", "chan must be txid:vout"))?;
        let c = canonical_chan(c)?;
        if !lock(&self.ledger).channels.contains_key(&c) {
            return fail("unknown_channel", "");
        }
        Ok(c)
    }

    /// POST /x402/xbt-channel/close: `{chan, sig, payload?}`, sig = the payer's over
    /// `tagged_hash("xbt402/close", chan)`; payload = a final state (postpay).
    pub fn close(&self, req: &Value) -> Result<Value> {
        let cid = self.channel_id_of(Some(field(req, "chan")?))?;
        let payer_pub = lock(&self.ledger).channels[&cid].params.payer_pub;
        let sig = hexs(req.get("sig"))?;
        if !ecdsa::verify(&payer_pub, &close_message(&cid), &sig) {
            return fail("bad_sig", "close request not signed by the payer");
        }
        let mut l = lock(&self.ledger);
        let mut st = l.channels[&cid].clone();
        // AGP-064 (H1): route() writes its lock and lets go of the ledger before it forwards, so a
        // close here could otherwise land between the two
        if st.closed_txid.is_empty() && locks_open(&st) {
            return fail("lock_pending", "a routed lock is open on this channel");
        }
        // AGP-084: an earlier spend the node has after all is this channel's close, before a new
        // close replaces its intent
        if let Err(e) = self.adopt_intent(&mut l, &mut st) {
            l.channels.insert(cid.clone(), st);
            return Err(e);
        }
        if truthy(req.get("payload")) && st.closed_txid.is_empty() {
            let r = self.apply(&mut st, &req["payload"]);
            if let Err(e) = r {
                return Err(if e.code == "bad_payload" { ChannelError::new("bad_request", e.msg) } else { e });
            }
        }
        let r = self.close_locked(&mut l, &mut st);
        l.channels.insert(cid.clone(), st.clone());
        let txid = r?;
        let mut out = json!({"chan": cid, "txid": txid});
        if let (Some(o), Value::Object(rep)) = (out.as_object_mut(), self.close_report(&st)?) {
            o.extend(rep);
        }
        Ok(out)
    }

    /// Close one channel now with the best signed state (AGP-059), exactly as the watcher does at the
    /// close margin: the write-ahead close intent, the broadcast, the record, the hash-lock claim of a
    /// conditional close. Returns the cooperative close's answer (`chan`, `txid`, `cum`, `unpaidMsat`,
    /// and `payeeFee`/`payeeNet` under payee-pays).
    ///
    /// Refused, with nothing changed: `unknown_channel`; `channel_closed` (already closed or rolled
    /// over); `lock_pending` (a routed lock is open on it); `hub_channel` (a hub-funded ch2: its hub
    /// rolls it over or closes it, and the margin close still protects it); `call_in_flight` (a paid
    /// call is being served: the best state does not cover it yet); `no_state` (nothing signed).
    pub fn close_channel(&self, chan: &str) -> Result<Value> {
        let cid = canonical_chan(chan)?;
        let mut l = lock(&self.ledger);
        let mut st = l.channels.get(&cid).cloned().ok_or_else(|| ChannelError::code("unknown_channel"))?;
        if !st.closed_txid.is_empty() {
            return fail("channel_closed", format!("closed by {}", st.closed_txid));
        }
        if locks_open(&st) {
            return fail("lock_pending", "a routed lock is open on this channel");
        }
        if st.extra.get("hub").is_some_and(|h| truthy(Some(h))) {
            return fail("hub_channel", "a hub-funded channel is rolled over or closed by its hub");
        }
        if lock(&self.in_call).get(&cid).copied().unwrap_or(0) > 0 {
            return fail("call_in_flight", "a paid call is being served on this channel");
        }
        if st.best_sig.is_empty() && st.cond_sig.is_empty() {
            return fail("no_state", "the payer has signed no state to close with");
        }
        let r = match self.adopt_intent(&mut l, &mut st) {
            Ok(true) => Ok(st.closed_txid.clone()),
            Ok(false) => self.close_locked(&mut l, &mut st),
            Err(e) => Err(e),
        };
        l.channels.insert(cid.clone(), st.clone());
        let txid = r?;
        let mut out = json!({"chan": cid, "txid": txid});
        if let (Some(o), Value::Object(rep)) = (out.as_object_mut(), self.close_report(&st)?) {
            o.extend(rep);
        }
        Ok(out)
    }

    /// A close this provider sent and never recorded (M8: the intent is written ahead): record it.
    /// True when the channel is now closed by it.
    fn adopt_intent(&self, l: &mut Ledger, st: &mut ChannelState) -> Result<bool> {
        let Some(intent) = st.extra.get("close_intent").cloned().filter(|i| truthy(Some(i))) else { return Ok(false) };
        let hx = intent.get("hex").and_then(Value::as_str).unwrap_or("").to_string();
        let txid = intent.get("txid").and_then(Value::as_str).unwrap_or("").to_string();
        if !self.tx_known(&txid, &Tx::parse_hex(&hx)?) {
            return Ok(false);
        }
        self.closed(l, st, &hx, &txid, truthy(intent.get("cond")))?;
        if let Some(next) = intent.get("next").filter(|n| truthy(Some(n))) {
            // a rollover (AGP-084): the next channel is the one this tx funds
            st.extra.insert("rollover_to".into(), next.clone());
            self.save_state(l, st)?;
        }
        Ok(true)
    }

    // hash-locked conditional state (M6) --------------------------------------------------

    fn cond_state(&self, st: &ChannelState) -> Result<Option<(ConditionalParams, u64, Vec<u8>)>> {
        let Some(c) = st.extra.get("cond").filter(|c| truthy(Some(c))) else { return Ok(None) };
        if st.cond_sig.is_empty() {
            return Ok(None);
        }
        let h: [u8; 32] = hex::decode(&st.cond_hash).ok().and_then(|v| v.try_into().ok())
            .ok_or_else(|| ChannelError::new("bad_state", "cond_hash"))?;
        let csv = py_u64(c.get("csv")).unwrap_or(CSV_DELTA as u64) as u32;
        let cp = ConditionalParams::new(st.params.clone(), h, st.cond_amount, csv)?;
        let uncond = py_u64(c.get("uncond")).unwrap_or(0);
        let k = hexs(c.get("k"))?;
        Ok(Some((cp, uncond, k)))
    }

    fn cond_value(&self, st: &ChannelState) -> Result<u64> {
        Ok(match self.cond_state(st)? {
            Some((cp, uncond, _)) if cp.cond_amount >= self.cfg.claim_fee + DUST => uncond + cp.cond_amount - self.cfg.claim_fee,
            _ => 0,
        })
    }

    fn cond_outstanding(&self, st: &ChannelState) -> Result<bool> {
        Ok(match self.cond_state(st)? {
            Some((cp, uncond, _)) => st.best_cum < uncond + cp.cond_amount,
            None => false,
        })
    }

    /// The payee's best close: the conditional state when it pays more than the best plain one.
    fn close_tx(&self, st: &ChannelState) -> Result<(Tx, bool)> {
        if self.cond_value(st)? > st.best_cum {
            if let Some((cp, uncond, _)) = self.cond_state(st)? {
                let mut tx = cp.state_tx(uncond)?;
                let mine = sign_with_type(&self.chan_secret(&st.params)?, &cp.sighash(&tx)?, SIGHASH_ALL_UNIFIED);
                tx.inputs[0].witness = vec![hex::decode(&st.cond_sig).unwrap_or_default(), mine, vec![0x01], st.params.script()];
                return Ok((tx, true));
            }
        }
        Ok((self.payee(st)?.close_tx()?, false))
    }

    fn claim_tx(&self, st: &ChannelState, fee: u64) -> Result<(Tx, u32)> {
        let (cp, _, k) = self.cond_state(st)?.ok_or_else(|| ChannelError::new("no_state", "no conditional state"))?;
        let close_hex = st.extra.get("close_hex").and_then(Value::as_str).unwrap_or("");
        let close = Tx::parse_hex(close_hex)?;
        let vout = close.outputs.iter().position(|o| o.script_pubkey == cp.spk)
            .ok_or_else(|| ChannelError::new("no_state", "close has no hash-lock output"))? as u32;
        let tx = cp.claim_tx(&st.closed_txid, vout, &k, &self.chan_secret(&st.params)?, &st.params.payee_spk, fee)?;
        Ok((tx, vout))
    }

    /// Broadcast the hash-lock claim unless its output is already spent; bump a claim stuck while
    /// the close gets buried (the payer's CSV branch opens at csvDelta).
    fn claim(&self, st: &mut ChannelState) -> Result<()> {
        let mut fee = st.extra.get("claim_fee").and_then(Value::as_u64).unwrap_or(self.cfg.claim_fee);
        let (mut tx, vout) = self.claim_tx(st, fee)?;
        if self.chain.get_tx_out(&st.closed_txid, vout, true)?.is_none() {
            let Some(chain) = self.chain.get_tx_out(&st.closed_txid, vout, false)? else { return Ok(()) };
            let depth = chain.confirmations.min(32);
            let cond_amount = self.cond_state(st)?.map(|c| c.0.cond_amount).unwrap_or(0);
            let shifted = if self.cfg.claim_fee.leading_zeros() >= depth { self.cfg.claim_fee << depth } else { u64::MAX };
            let bumped = shifted.min(cond_amount.saturating_sub(DUST));
            if bumped <= fee {
                return Ok(());
            }
            fee = bumped;
            tx = self.claim_tx(st, fee)?.0;
        }
        match self.chain.send_raw_transaction(&tx.to_hex()) {
            Ok(txid) => {
                st.extra.insert("claim_txid".into(), txid.into());
                st.extra.insert("claim_fee".into(), fee.into());
                Ok(())
            }
            Err(e) => fail("claim_failed", e.to_string()),
        }
    }

    fn tx_known(&self, txid: &str, tx: &Tx) -> bool {
        if self.chain.has_transaction(txid).unwrap_or(false) {
            return true;
        }
        (0..tx.outputs.len() as u32).any(|n| matches!(self.chain.get_tx_out(txid, n, true), Ok(Some(_))))
    }

    pub(crate) fn close_locked(&self, l: &mut Ledger, st: &mut ChannelState) -> Result<String> {
        if st.closed_txid.is_empty() {
            let (tx, conditional) = self.close_tx(st)?;
            let txid = tx.txid();
            // write-ahead (M8): a close the node took but we never recorded would never be claimed
            st.extra.insert("close_intent".into(), json!({"hex": tx.to_hex(), "txid": txid, "cond": conditional}));
            self.save_state(l, st)?;
            if let Err(e) = self.chain.send_raw_transaction(&tx.to_hex()) {
                // AGP-067 (C1): refused alone (below the mempool's floor), it goes in with a child
                let bump = if self.cfg.close_bump_max_fee > 0 { Some(self.height().and_then(|h| self.bump_close(st, h, &txid, &tx, true))) } else { None };
                if !matches!(bump, Some(Ok(()))) && !self.tx_known(&txid, &tx) {
                    let why = match bump {
                        Some(Err(b)) => format!("{e}; bump: {b}"),
                        _ => e.to_string(),
                    };
                    return fail("close_failed", why);
                }
            }
            self.closed(l, st, &tx.to_hex(), &txid, conditional)?;
        }
        Ok(st.closed_txid.clone())
    }

    /// The package feerate (sat/vB) a close needs at `tip`: the estimate for confirming within a
    /// quarter of the blocks left to expiry, the mempool's floor and `close_min_feerate`, whichever
    /// is highest; doubled from the last send once `close_bump_blocks` passed without a
    /// confirmation in the second half of the close margin (an estimate that lags the market).
    fn close_rate_wanted(&self, p: &ChannelParams, tip: u32, last: Option<&Value>) -> f64 {
        let left = p.expiry.saturating_sub(tip);
        let mut want = self.cfg.close_min_feerate;
        if let Ok(Some(r)) = self.chain.estimate_fee_rate((left / 4).clamp(1, 1008)) {
            want = want.max(r);
        }
        if let Ok(Some(r)) = self.chain.mempool_min_fee() {
            want = want.max(r);
        }
        if let Some(b) = last {
            let at = py_u64(b.get("at")).unwrap_or(0);
            if tip as u64 >= at + self.cfg.close_bump_blocks as u64 && left <= self.cfg.close_margin / 2 {
                want = want.max(b.get("rate").and_then(Value::as_f64).unwrap_or(0.0) * 2.0);
            }
        }
        want
    }

    /// review C1: get the close `txid` confirmed before the payer's refund is valid. Each block (each
    /// call while it is not in the mempool) the close goes out alone if its own fee meets
    /// [`close_rate_wanted`](Self::close_rate_wanted), else with a CPFP child that spends this
    /// provider's close output back to the same key and pays the difference, replacing the last
    /// child (BIP125: the new one pays at least the old fee plus its own vsize). The child's fee is
    /// capped at `close_bump_max_fee` and at the output less dust. Recorded in `extra.close_bump`
    /// (`at` the last send, `rate`, `fee`, the child's `txid`/`hex`, `capped`, `replaced`).
    /// `refused_alone`: the node just refused the close alone, so it is not sent alone again.
    fn bump_close(&self, st: &mut ChannelState, tip: u32, txid: &str, close: &Tx, refused_alone: bool) -> Result<()> {
        let p = st.params.clone();
        if self.chain.get_tx_out(&p.funding_txid(), p.funding_vout(), false)?.is_none() {
            return Ok(());      // spent in a block: the close confirmed, or the channel is gone
        }
        let last = st.extra.get("close_bump").cloned().filter(Value::is_object);
        let field_u64 = |k: &str| last.as_ref().and_then(|b| py_u64(b.get(k))).unwrap_or(0);
        let child_txid = last.as_ref().and_then(|b| b.get("txid")).and_then(Value::as_str).unwrap_or("").to_string();
        // a node may still answer for an evicted close's txid: in the pool only while the funding is spent there
        let in_pool = self.tx_known(txid, close)
            && matches!(self.chain.get_tx_out(&p.funding_txid(), p.funding_vout(), true), Ok(None));
        let child_in_pool = !child_txid.is_empty() && self.chain.has_transaction(&child_txid).unwrap_or(false);
        if in_pool && (child_txid.is_empty() || child_in_pool) && field_u64("seen") == tip as u64 && last.is_some() {
            return Ok(());      // looked at this block already
        }
        let close_hex = close.to_hex();
        let close_fee = (p.capacity as i64 - close.outputs.iter().map(|o| o.value).sum::<i64>()).max(0) as u64;
        let cv = close.vsize() as u64;
        let want = self.close_rate_wanted(&p, tip, last.as_ref());
        let (have_fee, have_vs) = if child_in_pool { (close_fee + field_u64("fee"), cv + CPFP_CHILD_VSIZE) } else { (close_fee, cv) };
        let mut rec = last.clone().unwrap_or_else(|| json!({"at": tip, "rate": close_fee as f64 / cv as f64, "fee": 0}));
        rec["seen"] = tip.into();
        if in_pool && have_fee as f64 >= want * have_vs as f64 {
            st.extra.insert("close_bump".into(), rec);
            return Ok(());
        }
        let send_alone = |rec: &mut Value| -> Result<()> {
            if refused_alone {
                return fail("close_failed", "the node refused the close alone");
            }
            if let Err(e) = self.chain.send_raw_transaction(&close_hex) {
                if !self.tx_known(txid, close) {
                    return fail("close_failed", e.to_string());
                }
            }
            rec["at"] = tip.into();
            Ok(())
        };
        let payee_out = close.outputs.iter().position(|o| o.script_pubkey == p.payee_spk);
        let swept = st.extra.contains_key("payee_sweep") || st.extra.contains_key("payee_sweep_intent");
        let (Some(vout), false) = (payee_out, swept) else {
            // nothing of ours to spend (or a sweep spends it already): the close alone, as before
            let r = send_alone(&mut rec);
            st.extra.insert("close_bump".into(), rec);
            return r;
        };
        if close_fee as f64 >= want * cv as f64 {
            let r = send_alone(&mut rec);
            st.extra.insert("close_bump".into(), rec);
            return r;
        }
        let value = close.outputs[vout].value as u64;
        let mut fee = ((want * (cv + CPFP_CHILD_VSIZE) as f64).ceil() as u64).saturating_sub(close_fee);
        let last_fee = field_u64("fee");
        if last_fee > 0 {
            fee = fee.max(last_fee + CPFP_CHILD_VSIZE);
        }
        let cap = self.cfg.close_bump_max_fee.min(value.saturating_sub(DUST));
        let capped = fee > cap;
        fee = fee.min(cap);
        let (child_hex, child_id) = if last_fee > 0 && fee <= last_fee {
            // at the cap: nothing higher to sign; the last child again
            (rec.get("hex").and_then(Value::as_str).unwrap_or("").to_string(), child_txid.clone())
        } else {
            let child = cpfp_child(txid, vout as u32, value, &p.payee_spk, &self.chan_secret(&p)?, fee)?;
            (child.to_hex(), child.txid())
        };
        if child_hex.is_empty() || fee == 0 {
            let r = send_alone(&mut rec);
            st.extra.insert("close_bump".into(), rec);
            return r;
        }
        let sent = self.chain.submit_package(&[close_hex.clone(), child_hex.clone()]);
        if let Err(e) = sent {
            st.extra.insert("close_bump".into(), rec);
            return fail("close_bump_failed", e.to_string());
        }
        if child_id != child_txid && !child_txid.is_empty() {
            let mut replaced = rec.get("replaced").and_then(Value::as_array).cloned().unwrap_or_default();
            replaced.push(json!([child_txid, last_fee]));
            rec["replaced"] = replaced.into();
        }
        let fee = if child_id == child_txid { last_fee } else { fee };
        rec["at"] = tip.into();
        rec["rate"] = ((close_fee + fee) as f64 / (cv + CPFP_CHILD_VSIZE) as f64).into();
        rec["fee"] = fee.into();
        rec["txid"] = child_id.into();
        rec["hex"] = child_hex.into();
        rec["capped"] = capped.into();
        st.extra.insert("close_bump".into(), rec);
        Ok(())
    }

    pub(crate) fn save_state(&self, l: &mut Ledger, st: &ChannelState) -> Result<()> {
        let cid = st.params.channel_id();
        l.channels.insert(cid.clone(), st.clone());
        l.save(&[&cid])
    }

    /// Record the close the node has, then claim the hash lock of a conditional one.
    fn closed(&self, l: &mut Ledger, st: &mut ChannelState, close_hex: &str, txid: &str, conditional: bool) -> Result<()> {
        st.closed_txid = txid.to_string();
        let mut mine = vec![st.params.payee_spk.clone()];
        if conditional {
            if let Some((cp, _, _)) = self.cond_state(st)? {
                mine.push(cp.spk);
            }
        }
        let paid: i64 = Tx::parse_hex(close_hex)?.outputs.iter().filter(|o| mine.contains(&o.script_pubkey)).map(|o| o.value).sum();
        st.extra.insert("close_hex".into(), close_hex.into());
        st.extra.insert("cond_close".into(), conditional.into());
        st.extra.insert("close_paid".into(), paid.into());
        self.save_state(l, st)?;
        if conditional {
            if let Err(e) = self.claim(st) {
                st.close_error = e.to_string();
            }
            self.save_state(l, st)?;
        }
        Ok(())
    }

    /// Sat the payer paid by the recorded close: its gross state (a conditional close: uncond +
    /// condAmount, before the claim fee). Under v1.2 payee-pays the provider's outputs hold this less
    /// payeeFee (AGP-029): the fee is the provider's cost, never an amount the payer still owes.
    pub(crate) fn close_paid(&self, st: &ChannelState) -> Result<u64> {
        if let Some(p) = st.extra.get("close_paid").and_then(Value::as_u64) {
            return Ok(p + st.params.payee_fee());     // the provider's outputs of the close actually sent
        }
        if truthy(st.extra.get("cond_close")) {
            if let Some((cp, uncond, _)) = self.cond_state(st)? {
                return Ok(uncond + cp.cond_amount);
            }
        }
        Ok(st.best_cum)
    }

    /// The close answer's amounts: `cum` gross and `unpaidMsat` = spent - gross. A payee-pays channel
    /// adds `payeeFee` and `payeeNet` (what the provider's outputs hold); a payer-pays (v1.1) answer is
    /// unchanged byte for byte.
    fn close_report(&self, st: &ChannelState) -> Result<Value> {
        let paid = self.close_paid(st)?;
        let owed = st.spent_msat as i128 - paid as i128 * 1000;
        let mut out = json!({"cum": paid.to_string(), "unpaidMsat": owed.max(0).to_string()});
        let fee = st.params.payee_fee();
        if fee > 0 {
            out["payeeFee"] = fee.to_string().into();
            out["payeeNet"] = paid.saturating_sub(fee).to_string().into();
        }
        Ok(out)
    }

    fn watch_one(&self, l: &mut Ledger, st: &mut ChannelState, h: u32, out: &mut Vec<String>) -> Result<()> {
        let p = st.params.clone();
        if !st.closed_txid.is_empty() {
            let close = match st.extra.get("close_hex").and_then(Value::as_str) {
                Some(h) => Tx::parse_hex(h)?,
                None => self.close_tx(st)?.0,
            };
            if self.cfg.close_bump_max_fee > 0 {
                let txid = st.closed_txid.clone();
                self.bump_close(st, h, &txid, &close, false)?;
            } else if self.chain.get_tx_out(&p.funding_txid(), p.funding_vout(), true)?.is_some() {
                // funding still unspent even counting the mempool: the close was evicted, send it again
                self.chain.send_raw_transaction(&close.to_hex())?;
            }
            if truthy(st.extra.get("cond_close")) {
                self.claim(st)?;
            }
            return Ok(());
        }
        if self.adopt_intent(l, st)? {
            out.push(st.closed_txid.clone());
            if truthy(st.extra.get("cond_close")) {
                self.claim(st)?;
            }
            return Ok(());
        }
        // AGP-084: a close the node answered with an error is sent again every tick. The channel
        // takes no state until then, so it is the same close. Never a rollover: its client was
        // told it failed and may no longer hold the next channel's key
        if intent_open(st) && !truthy(st.extra.get("close_intent").and_then(|i| i.get("next"))) && !locks_open(st) {
            out.push(self.close_locked(l, st)?);
            if truthy(st.extra.get("cond_close")) {
                self.claim(st)?;
            }
            return Ok(());
        }
        let utxo = self.chain.get_tx_out(&p.funding_txid(), p.funding_vout(), false)?;
        st.suspended = utxo.map(|u| u.confirmations < self.cfg.policy.conf_for(p.capacity)).unwrap_or(true);
        if let Some(mut zc) = st.extra.get("zero_conf").filter(|z| z.is_object()).cloned() {
            // AGP-053: confirmed (again, after a reorg) or not; unconfirmed, it is served under its rules
            zc["confirmed"] = (!st.suspended).into();
            st.extra.insert("zero_conf".into(), zc);
            if st.suspended && self.zero_conf_ok(st, h)? {
                st.suspended = false;
            }
        }
        if (!st.best_sig.is_empty() || !st.cond_sig.is_empty()) && h as i64 >= p.expiry as i64 - self.cfg.close_margin as i64 {
            // AGP-064: a lock in flight (seconds: the hub's revealTimeout) is let finish, in the first
            // half of the margin only. Never for a written-off lock: a skipped margin close lets the
            // payer refund the whole channel at expiry.
            if truthy(st.extra.get("route_lock")) && (h as i64) < p.expiry as i64 - (self.cfg.close_margin as i64 + 1) / 2 {
                return Ok(());
            }
            out.push(self.close_locked(l, st)?);
            if truthy(st.extra.get("cond_close")) {
                self.claim(st)?;
            }
        }
        Ok(())
    }

    /// Watcher tick (every block), channel by channel so one failing channel never stops the
    /// rest: suspend channels whose funding left the chain, close channels at expiry -
    /// closeMarginBlocks, rebroadcast closes that fell out of the mempool, claim hash locks.
    /// Returns the txids of closes made this tick.
    pub fn close_due(&self) -> Result<Vec<String>> {
        let h = self.chain.block_count()?;
        let mut out = Vec::new();
        let mut l = lock(&self.ledger);
        let ids: Vec<String> = l.channels.keys().cloned().collect();
        for cid in ids {
            let mut st = l.channels[&cid].clone();
            match self.watch_one(&mut l, &mut st, h, &mut out) {
                Ok(()) => st.close_error.clear(),
                Err(e) => st.close_error = e.to_string(),
            }
            l.channels.insert(cid, st);
        }
        l.save(&[])?;
        Ok(out)
    }

    /// Move this channel's payee close output to `dest_spk` (witness v0), signed 0x21 with the
    /// channel secret, which is never returned. Idempotent.
    pub fn sweep_payee(&self, chan: &str, dest_spk: &[u8], fee: u64) -> Result<Value> {
        if !((dest_spk.len() == 22 || dest_spk.len() == 34) && dest_spk[0] == 0 && dest_spk[1] as usize == dest_spk.len() - 2) {
            return fail("bad_dest", "sweep destination must be a witness v0 script (P2WPKH or P2WSH)");
        }
        let cid = canonical_chan(chan)?;
        let mut l = lock(&self.ledger);
        let mut st = l.channels.get(&cid).cloned().ok_or_else(|| ChannelError::code("unknown_channel"))?;
        if let Some(done) = st.extra.get("payee_sweep") {
            let mut d = done.clone();
            d["already"] = true.into();
            return Ok(d);
        }
        let close_hex = st.extra.get("close_hex").and_then(Value::as_str).map(str::to_string);
        let (true, Some(close_hex)) = (!st.closed_txid.is_empty(), close_hex) else {
            return fail("not_closed", "the channel has no recorded close to sweep");
        };
        let close = Tx::parse_hex(&close_hex)?;
        let vout = close.outputs.iter().position(|o| o.script_pubkey == st.params.payee_spk)
            .ok_or_else(|| ChannelError::new("no_payee_output", "the close pays nothing to the payee key"))?;
        // AGP-067: a CPFP child (the latest, or one it replaced) moved the output to the same key
        let base = close.outputs[vout].value as u64;
        let mut found = (st.closed_txid.clone(), vout as u32, base);
        if let Some(b) = st.extra.get("close_bump").filter(|b| py_u64(b.get("fee")).unwrap_or(0) > 0) {
            let mut kids = vec![(py_str(b.get("txid")), py_u64(b.get("fee")).unwrap_or(0))];
            for r in b.get("replaced").and_then(Value::as_array).into_iter().flatten() {
                kids.push((py_str(r.get(0)), py_u64(r.get(1)).unwrap_or(0)));
            }
            for (txid, kfee) in kids.into_iter().rev().filter(|(t, _)| !t.is_empty()) {
                if self.chain.get_tx_out(&txid, 0, true)?.is_some() {
                    found = (txid, 0, base.saturating_sub(kfee));
                }
            }
        }
        let (from_txid, vout, value) = found;
        if value < fee + DUST {
            return fail("bad_amount", format!("fee {fee} leaves dust from {value}"));
        }
        if self.chain.get_tx_out(&from_txid, vout, true)?.is_none() {
            return fail("payee_spent", "the payee output is spent or its close is not on this node");
        }
        let op = OutPoint::from_display(&from_txid, vout)?;
        let mut tx = Tx::new(2, vec![TxIn::new(op, 0xFFFF_FFFD)], vec![TxOut::new((value - fee) as i64, dest_spk.to_vec())], 0);
        sign_p2wpkh(&self.chan_secret(&st.params)?, &mut tx, &[TxOut::new(value as i64, st.params.payee_spk.clone())], 0)?;
        let txid = tx.txid();
        let rec = json!({"txid": txid, "outpoint": format!("{from_txid}:{vout}"), "value": value, "fee": fee,
                         "swept": value - fee, "dest_spk": hex::encode(dest_spk)});
        let mut intent = rec.clone();
        intent["hex"] = tx.to_hex().into();
        st.extra.insert("payee_sweep_intent".into(), intent);
        self.save_state(&mut l, &st)?;
        if let Err(e) = self.chain.send_raw_transaction(&tx.to_hex()) {
            if !self.tx_known(&txid, &tx) {
                return fail("sweep_failed", e.to_string());
            }
        }
        st.extra.insert("payee_sweep".into(), rec.clone());
        self.save_state(&mut l, &st)?;
        Ok(rec)
    }

    fn facilitator_payload<'a>(&self, req: &'a Value) -> Result<&'a Value> {
        if req.get("x402Version").and_then(Value::as_u64) != Some(2) {
            return fail("bad_payload", "x402Version 2 facilitator body expected");
        }
        let (pp, want) = (req.get("paymentPayload"), req.get("paymentRequirements"));
        let ok = matches!((pp, want), (Some(pp), Some(w)) if pp.is_object() && w.is_object()
                          && pp.get("accepted").is_some_and(Value::is_object) && pp.get("payload").is_some_and(Value::is_object)
                          && pp.get("x402Version").and_then(Value::as_u64) == Some(2));
        if !ok {
            return fail("bad_payload", "paymentPayload {x402Version, accepted, payload} and paymentRequirements expected");
        }
        let pp = pp.unwrap_or(&Value::Null);
        for acc in [want.unwrap_or(&Value::Null), &pp["accepted"]] {
            if !scheme_accepted(acc.get("scheme").and_then(Value::as_str))
                || acc.get("network").and_then(Value::as_str) != Some(self.cfg.network.as_str())
                || acc.get("payTo").and_then(Value::as_str) != Some(self.pay_to.as_str())
            {
                return fail("unsupported_scheme_or_network", "");
            }
        }
        Ok(&pp["payload"])
    }

    /// POST /x402/verify: an x402 VerifyResponse for a signed state, kept if higher. Needs a payer
    /// signature for exactly the cum it names; never moves seq.
    pub fn facilitator_verify(&self, req: &Value) -> Value {
        let r = (|| -> Result<(String, String, u64)> {
            let pl = self.facilitator_payload(req)?;
            let cid = self.channel_id_of(pl.get("chan"))?;
            let cum = py_int(pl.get("cum")).ok_or_else(|| ChannelError::code("bad_payload"))?;
            if !truthy(pl.get("sig")) {
                return fail("bad_sig", "verify needs a signed state");
            }
            let sig_hex = pl.get("sig").and_then(Value::as_str).ok_or_else(|| ChannelError::code("bad_payload"))?;
            let sig = hex::decode(sig_hex).map_err(|_| ChannelError::code("bad_payload"))?;
            let params = lock(&self.ledger).channels[&cid].params.clone();
            let cum = u64::try_from(cum).map_err(|_| ChannelError::code("bad_amount"))?;
            // the only work a stranger can make us do, outside the ledger lock
            self.channel_payee(&params)?.verify_state(cum, &sig)?;
            let height = self.height()?;
            let mut l = lock(&self.ledger);
            let mut st = l.channels[&cid].clone();
            if cum > st.best_cum && st.closed_txid.is_empty() {
                st.best_cum = cum;
                st.best_sig = sig_hex.to_string();
                self.save_state(&mut l, &st)?;
            }
            if closing(&st) || height as i64 >= st.params.expiry as i64 - self.cfg.close_margin as i64 {
                return fail("channel_closing", "");
            }
            if st.suspended {
                return fail("unconfirmed", "");
            }
            Ok((hex::encode(st.params.payer_pub), cid, cum))
        })();
        match r {
            Ok((payer, cid, cum)) => json!({"isValid": true, "payer": payer, "extra": {"chan": cid, "cum": cum.to_string()}}),
            Err(e) => json!({"isValid": false, "invalidReason": upstream_code(&e.code)}),
        }
    }

    /// POST /x402/settle: a SettlementResponse for a close request.
    pub fn facilitator_settle(&self, req: &Value) -> Value {
        let r = (|| -> Result<Value> {
            let pl = self.facilitator_payload(req)?;
            let r = self.close(pl)?;
            let cid = r["chan"].as_str().unwrap_or("").to_string();
            let st = lock(&self.ledger).channels.get(&cid).cloned().ok_or_else(|| ChannelError::code("unknown_channel"))?;
            let mut extra = json!({"chan": cid, "unpaidMsat": r["unpaidMsat"]});
            if r.get("payeeFee").is_some() {
                extra["payeeFee"] = r["payeeFee"].clone();
                extra["payeeNet"] = r["payeeNet"].clone();
            }
            Ok(json!({"success": true, "transaction": r["txid"], "network": self.cfg.network,
                      "payer": hex::encode(st.params.payer_pub), "amount": r["cum"], "extra": extra}))
        })();
        r.unwrap_or_else(|e| {
            let code = if e.code == "bad_request" { "bad_payload" } else { e.code.as_str() };
            json!({"success": false, "errorReason": upstream_code(code), "transaction": "", "network": self.cfg.network})
        })
    }

    /// POST /x402/xbt-channel/rollover: co-sign and broadcast the payer's rollover, one tx that
    /// pays this provider `amount` (at least its best state) and funds the next channel. Refused
    /// `lock_pending`, as a close is, while a routed lock is open on the channel, whatever `amount`.
    pub fn rollover(&self, req: &Value) -> Result<Value> {
        let cid = self.channel_id_of(Some(field(req, "chan")?))?;
        {
            let mut l = lock(&self.ledger);
            let mut st = l.channels[&cid].clone();
            if !self.zc_confirmed(&mut st, true)? {
                return fail("unconfirmed", "the channel's funding (a rollover) is not confirmed yet");
            }
            if st.extra != l.channels[&cid].extra {
                self.save_state(&mut l, &st)?;
            }
        }
        let p = lock(&self.ledger).channels[&cid].params.clone();
        let amount = py_u64(req.get("amount")).ok_or_else(|| ChannelError::new("bad_request", "amount"))?;
        let nxt = field(req, "next")?;
        let payer_pub = hexs(nxt.get("payerPub"))?;
        ecdsa::public_key(&payer_pub).map_err(|e| ChannelError::new("bad_request", e.to_string()))?;
        let expiry = py_u64(nxt.get("expiry")).and_then(|e| u32::try_from(e).ok()).ok_or_else(|| ChannelError::new("bad_request", "expiry"))?;
        let h = self.height()?;
        let pol = &self.cfg.policy;
        if (expiry as u64) < h as u64 + pol.min_expiry_blocks as u64 || expiry as u64 > h as u64 + pol.max_expiry_blocks as u64 {
            return fail("bad_expiry", "next channel expiry outside this provider's policy");
        }
        let payer_spk = match nxt.get("payerSpk") {
            Some(v) if truthy(Some(v)) => Some(check_payout_spk(v.as_str().unwrap_or("-"))?),
            _ => None,
        };
        let pay_to = hex::decode(&self.pay_to).unwrap_or_default();
        let nparams = ChannelParams::derive(&pay_to, &payer_pub, expiry, p.close_fee, payer_spk, &self.cfg.network, p.close_fee_payer)?;
        let next_cap = p.rollover_next_capacity(amount);
        if next_cap < pol.min_capacity {
            return fail("bad_amount", "rollover leaves less than the minimum channel capacity");
        }
        if p.payee_fee() > 0 && !self.settle_due(&p, amount, Some(h), self.cfg.rollover_grace) {
            return fail("settle_early", format!("net payout {} < {} x closeFee {}, and the channel is not near its margin",
                                                p.payee_value(amount), self.cfg.settle_multiple, p.close_fee));
        }
        let mut tx = p.rollover_tx(amount, &nparams.spk(), next_cap)?;
        let sig = hexs(req.get("sig"))?;
        let digest = p.sighash(&tx)?;
        if sig.last() != Some(&SIGHASH_ALL_UNIFIED) || !ecdsa::verify(&p.payer_pub, &digest, &sig[..sig.len() - 1]) {
            return fail("bad_sig", "payer signature does not verify for this rollover");
        }
        tx.inputs[0].witness = vec![sig, sign_with_type(&self.chan_secret(&p)?, &digest, SIGHASH_ALL_UNIFIED), vec![0x01], p.script()];
        let mut l = lock(&self.ledger);
        let mut st = l.channels[&cid].clone();
        // AGP-084: an earlier spend the node has after all is this channel's close, before this
        // rollover replaces its intent
        if let Err(e) = self.adopt_intent(&mut l, &mut st) {
            l.channels.insert(cid.clone(), st);
            return Err(e);
        }
        if !st.closed_txid.is_empty() {
            return fail("channel_closing", "already settled");
        }
        // AGP-078 (H1, H2): a rollover spends the funding as a close does. Checked here, under the
        // ledger lock that is held until the rollover is sent: route() writes its lock under it too
        if locks_open(&st) {
            return fail("lock_pending", "a routed lock is open on this channel");
        }
        if amount < st.best_cum {
            return fail("bad_amount", format!("a rollover pays at least the best state {}", st.best_cum));
        }
        let txid = tx.txid();
        st.extra.insert("close_intent".into(), json!({"hex": tx.to_hex(), "txid": txid, "cond": false, "next": format!("{txid}:1")}));
        self.save_state(&mut l, &st)?;
        if let Err(e) = self.chain.send_raw_transaction(&tx.to_hex()) {
            if !self.tx_known(&txid, &tx) {
                return fail("close_failed", e.to_string());
            }
        }
        self.closed(&mut l, &mut st, &tx.to_hex(), &txid, false)?;
        st.extra.insert("rollover_to".into(), format!("{txid}:1").into());
        self.save_state(&mut l, &st)?;
        Ok(json!({"chan": cid, "txid": txid, "amount": amount, "nextChan": format!("{txid}:1"), "nextCapacity": next_cap}))
    }

    /// Offer a hash-locked deliverable at `path`: the 402 carries H and the ciphertext; each sale
    /// reveals k, so after a sale the path is offered again under a fresh k. `k` fixes the first
    /// key (test vectors only). Returns (H, ciphertext, k).
    pub fn offer_conditional(&self, path: &str, price: u64, plaintext: &[u8], k: Option<[u8; 32]>) -> ([u8; 32], Vec<u8>, Vec<u8>) {
        let k = k.unwrap_or_else(random32).to_vec();
        let h = xbt_primitives::hash::sha256(&k);
        let cipher = encrypt(plaintext, &k);
        lock(&self.cond).insert(path.to_string(), CondOffer { k: k.clone(), h, price, cipher: cipher.clone(), plain: plaintext.to_vec() });
        (h, cipher, k)
    }

    // --- paid requests ---------------------------------------------------------------------

    /// Serve one HTTP request. `url` is the absolute URL for the 402's `resource.url` (defaults
    /// to the path); `max_body` overrides the configured body bound.
    pub fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str,
                 max_body: Option<usize>) -> HttpResponse {
        if body.len() > self.body_limit(path, max_body) {
            return HttpResponse::text(400, "bad request framing or body over MAX_BODY");
        }
        if crate::wire::no_fragment(path).is_err() {
            // before anything is authenticated or routed (AGP-081, review T2)
            return HttpResponse::text(400, "request target with a # fragment");
        }
        let pk = path_key(path);
        if [FACILITATOR_SUPPORTED, FACILITATOR_VERIFY, FACILITATOR_SETTLE].contains(&pk) {
            let parsed = || crate::json::parse_slice(body).map_err(|e| ChannelError::new("bad_request", e.to_string()));
            let r = match (method, pk) {
                ("GET", FACILITATOR_SUPPORTED) => Ok(self.supported()),
                ("POST", FACILITATOR_VERIFY) => parsed().map(|v| self.facilitator_verify(&v)),
                ("POST", FACILITATOR_SETTLE) => parsed().map(|v| self.facilitator_settle(&v)),
                _ => return HttpResponse::text(405, "method not allowed"),
            };
            return match r {
                Ok(v) => HttpResponse::json(200, &v),
                Err(e) => HttpResponse::json(400, &json!({"error": e.code, "detail": e.to_string()})),
            };
        }
        let bind = binding_url(url, path);
        if path == LOCK_PATH {
            if method != "POST" {
                return HttpResponse::text(405, "method not allowed");
            }
            return self.route_lock(method, &bind, headers, body);
        }
        if path == TERMS_PATH && method == "GET" {
            return HttpResponse::json(200, &self.terms());
        }
        for s in &self.schemes {
            if let Some(r) = s.control(method, path, headers, body) {
                return r;
            }
        }
        if path.starts_with("/x402/xbt-channel/") {
            let action: Option<fn(&Self, &Value) -> Result<Value>> = match path {
                OPEN_PATH => Some(Self::open),
                CLOSE_PATH => Some(Self::close),
                ROLLOVER_PATH => Some(Self::rollover),
                _ => None,
            };
            let Some(action) = action.filter(|_| method == "POST") else { return HttpResponse::text(404, "not found") };
            let r = crate::json::parse_slice(body).map_err(|e| ChannelError::new("bad_request", e.to_string())).and_then(|v| action(self, &v));
            return match r {
                Ok(v) => HttpResponse::json(200, &v),
                Err(e) => HttpResponse::json(400, &json!({"error": e.code, "detail": e.to_string()})),
            };
        }
        let url = if url.is_empty() { path } else { url };
        let hdr = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-SIGNATURE")).map(|(_, v)| v.clone());
        let hval = |name: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty());
        let routed = self.routes.has_offer(pk);
        if routed && !hdr.as_deref().is_some_and(|h| !h.is_empty()) {
            if let Some(ra) = hval("ROUTE-AUTH") {
                return self.routed_call(method, path, pk, ra, body, url);
            }
            return self.route_offer_402(method, path, pk, hval("ROUTE-CLIENT").unwrap_or(""), url);
        }
        let price = (self.price)(method, path);
        let Some(hdr) = hdr else {
            let cond = lock(&self.cond);
            if let Some(offer) = cond.get(pk) {
                // the ciphertext goes out before the payer signs (M7)
                let mut body = json!({"x402Version": 2, "error": "payment_required", "resource": {"url": url},
                                      "accepts": [self.requirements(price)]});
                body["accepts"][0]["extra"]["conditional"] = json!({"hash": hex::encode(offer.h), "amount": offer.price.to_string(),
                                                                    "csvDelta": CSV_DELTA, "cipher": hex::encode(&offer.cipher)});
                return self.required_response(&body);
            }
            let mut body = self.payment_required_doc(url, price, "payment_required", None);
            if let Some(a) = body.get_mut("accepts").and_then(Value::as_array_mut) {
                a.extend(self.schemes.iter().filter_map(|s| s.requirements(method, path, price)));
            }
            return self.required_response(&body);
        };
        let (acc, pl) = match unb64json(&hdr) {
            Ok(pp) => {
                let (Some(acc), Some(pl)) = (pp.get("accepted").filter(|a| a.is_object()), pp.get("payload").filter(|p| p.is_object())) else {
                    return self.payment_required(url, price, "bad_payload", None);
                };
                let other = acc.get("scheme").and_then(Value::as_str).and_then(|sc| self.schemes.iter().find(|s| s.scheme() == sc));
                if let Some(s) = other {
                    return self.serve_other(s.as_ref(), &pp, method, path, body, price, url);
                }
                if pp.get("x402Version").and_then(Value::as_u64) != Some(2) || !scheme_accepted(acc.get("scheme").and_then(Value::as_str))
                    || acc.get("network").and_then(Value::as_str) != Some(self.cfg.network.as_str())
                    || acc.get("payTo").and_then(Value::as_str) != Some(self.pay_to.as_str())
                {
                    return self.payment_required(url, price, "unsupported_scheme_or_network", None);
                }
                (acc.clone(), pl.clone())
            }
            Err(_) => return self.payment_required(url, price, "bad_payload", None),
        };
        let _ = acc;
        let hashlock = truthy(pl.get("hashlock"));
        let metered = self.charge.is_some();
        let (cid, price, cond_sale, mut call, numbers) = {
            let mut l = lock(&self.ledger);
            let cid = pl.get("chan").and_then(Value::as_str).and_then(|c| canonical_chan(c).ok()).filter(|c| l.channels.contains_key(c));
            let Some(cid) = cid else { return self.payment_required(url, price, "unknown_channel", None) };
            let mut st = l.channels[&cid].clone();
            if !self.authentic(&st, &pl, method, &bind, body) {
                return self.payment_required(url, price, "bad_auth", None);
            }
            st.seq = py_u64(pl.get("seq")).unwrap_or(st.seq);        // spent, whatever happens next
            // every refusal from here on is durable: the seq it spent, and a higher state that
            // still does not cover this call (review T4: a seq kept only in memory came back after a
            // restart, and the refused header with it)
            let refuse = |l: &mut Ledger, st: &ChannelState, error: &str, price: u64| {
                if let Err(e) = self.save_state(l, st) {
                    return HttpResponse::json(500, &json!({"error": e.code, "detail": e.to_string()}));
                }
                self.payment_required(url, price, error, Some(st))
            };
            let height = match self.height() {
                Ok(h) => h,
                Err(e) => {
                    let _ = self.save_state(&mut l, &st);
                    return HttpResponse::json(500, &json!({"error": "node_error", "detail": e.to_string()}));
                }
            };
            if closing(&st) || height as i64 >= st.params.expiry as i64 - self.cfg.close_margin as i64 {
                return refuse(&mut l, &st, "channel_closing", price);
            }
            if st.suspended {
                return refuse(&mut l, &st, "unconfirmed", price);
            }
            if !hashlock {
                if let Err(e) = self.apply(&mut st, &pl) {
                    return refuse(&mut l, &st, &e.code, price);
                }
            }
            let mut price = price;
            let mut cond_sale = false;
            let cond = lock(&self.cond);
            if let (true, Some(offer)) = (hashlock, cond.get(pk)) {
                match self.cond_outstanding(&st) {
                    Ok(true) => return refuse(&mut l, &st, "conditional_outstanding", price),
                    Err(e) => return refuse(&mut l, &st, &e.code, price),
                    Ok(false) => {}
                }
                if pl.get("hashlock").and_then(Value::as_str).and_then(|h| hex::decode(h).ok()).as_deref() != Some(&offer.h[..]) {
                    return refuse(&mut l, &st, "bad_hashlock", price);
                }
                let checked = (|| -> Result<(ConditionalParams, Tx, Vec<u8>)> {
                    let cp = ConditionalParams::new(st.params.clone(), offer.h, offer.price, CSV_DELTA)?;
                    let tx = cp.state_tx(st.best_cum)?;
                    let sig = pl.get("sig").and_then(Value::as_str).and_then(|s| hex::decode(s).ok())
                        .ok_or_else(|| ChannelError::code("bad_payload"))?;
                    Ok((cp, tx, sig))
                })();
                let (cp, tx, sig) = match checked {
                    Ok(x) => x,
                    Err(e) => return refuse(&mut l, &st, &e.code, price),
                };
                let ok = sig.last() == Some(&0x21) && cp.sighash(&tx).is_ok_and(|d| ecdsa::verify(&st.params.payer_pub, &d, &sig[..sig.len() - 1]));
                if !ok {
                    return refuse(&mut l, &st, "bad_sig", price);
                }
                st.cond_hash = hex::encode(offer.h);
                st.cond_amount = offer.price;
                st.cond_sig = hex::encode(&sig);
                // enough to close with this state and claim it after a restart
                st.extra.insert("cond".into(), json!({"uncond": st.best_cum, "csv": CSV_DELTA, "k": hex::encode(&offer.k)}));
                price = offer.price;
                cond_sale = true;
            } else {
                let paid = st.best_cum as u128 * 1000;
                let need = st.spent_msat as u128 + if self.cfg.billing == "prepay" { price as u128 * 1000 } else { 0 };
                if paid < need {
                    return refuse(&mut l, &st, "insufficient_payment", price);
                }
            }
            drop(cond);
            if st.spent_msat as u128 + price as u128 * 1000 > st.params.max_amount() as u128 * 1000 {
                return refuse(&mut l, &st, "channel_exhausted", price);
            }
            let reserved = price.saturating_mul(1000);
            st.spent_msat = st.spent_msat.saturating_add(reserved);   // reserve the max; refunded below if metered lower
            if metered {
                // AGP-059: the charge is not known yet. Recorded, so a restart refunds a call that
                // never settled; an unmetered call's reservation is its exact charge already
                st.reserve(st.seq, reserved);
            }
            if let Err(e) = self.save_state(&mut l, &st) {
                return HttpResponse::json(500, &json!({"error": e.code, "detail": e.to_string()}));
            }
            let call = InCall::new(self, &cid, st.seq, reserved);
            (cid, price, cond_sale, call, (st.best_cum, st.spent_msat))
        };
        let mut resp = (self.handler)(method, path, body);
        if resp.headers.iter().any(|(k, v)| k.contains(['\r', '\n', '\0']) || v.contains(['\r', '\n', '\0'])) {
            resp = HttpResponse::text(500, "handler returned a header with CR/LF");
        }
        if cond_sale {
            let mut cond = lock(&self.cond);
            if let Some(offer) = cond.remove(pk) {
                resp = HttpResponse::json(200, &json!({"cipher": hex::encode(&offer.cipher), "preimage": hex::encode(&offer.k),
                                                        "hash": hex::encode(offer.h)}));
                drop(cond);
                // one k per sale: the next payer gets a new k (M7)
                self.offer_conditional(pk, offer.price, &offer.plain, None);
            }
        }
        let mut charged = price;
        if let Some(charge) = &self.charge {
            charged = charge(method, path, resp.status, &resp.body).clamp(0, price as i64) as u64;
        }
        let (receipt, secret, payer) = {
            let mut l = lock(&self.ledger);
            let Some(mut st) = l.channels.get(&cid).cloned() else { return HttpResponse::text(500, "channel vanished") };
            call.settled = true;
            st.release(call.seq);
            let mut refund = (price - charged).saturating_mul(1000);
            if resp.status >= 500 {
                // don't bill failed calls
                refund = price.saturating_mul(1000);
                charged = 0;
            }
            st.spent_msat = st.spent_msat.saturating_sub(refund);
            if metered || charged != price {
                // a metered call's charge is durable before its answer leaves: the row on disk held
                // the reservation, which a restart refunds (AGP-059)
                if let Err(e) = self.save_state(&mut l, &st) {
                    st.spent_msat = st.spent_msat.saturating_sub(charged.saturating_mul(1000));
                    l.channels.insert(cid.clone(), st);
                    return HttpResponse::json(500, &json!({"error": e.code, "detail": e.to_string()}));
                }
            } else {
                l.channels.insert(cid.clone(), st.clone());
            }
            // the numbers of this call's own reservation (review T4): calls running beside it move the
            // channel, not this receipt. Calls reserved before it count at what they reserved.
            let (cum, spent) = (numbers.0, numbers.1.saturating_sub(refund));
            let r = json!({"scheme": SCHEME, "chan": cid, "seq": call.seq, "cum": cum.to_string(), "charged": charged.to_string(),
                           "spentMsat": spent.to_string(),
                           "owedMsat": spent.saturating_sub(cum * 1000).to_string(),
                           "creditMsat": (cum * 1000).saturating_sub(spent).to_string(), "expiry": st.params.expiry,
                           "req": request_digest_v2(method, &bind, body), "status": resp.status, "bodyHash": body_hash(&resp.body)});
            (r, self.chan_secret(&st.params), hex::encode(st.params.payer_pub))
        };
        let Ok(secret) = secret else { return HttpResponse::text(500, "channel key") };
        let mut receipt = receipt;
        receipt["sig"] = hex::encode(ecdsa::sign(&secret, &receipt_message(&receipt))).into();
        let sr = settlement_response(&receipt, &self.cfg.network, &payer, resp.status < 400);
        resp.headers.push(("PAYMENT-RESPONSE".into(), b64json(&sr)));
        resp
    }

    /// A call paid with another scheme: it verifies and debits, the handler runs, it settles.
    #[allow(clippy::too_many_arguments)]
    fn serve_other(&self, s: &dyn crate::scheme::ProviderScheme, pp: &Value, method: &str, path: &str, body: &[u8], price: u64,
                   url: &str) -> HttpResponse {
        let charge = match s.authorize(pp, method, path, body, price, url) {
            Ok(c) => c,
            Err(doc) => return self.required_response(&doc),
        };
        let mut resp = (self.handler)(method, path, body);
        if resp.headers.iter().any(|(k, v)| k.contains(['\r', '\n', '\0']) || v.contains(['\r', '\n', '\0'])) {
            resp = HttpResponse::text(500, "handler returned a header with CR/LF");
        }
        let sr = charge.settle(resp.status);
        resp.headers.push(("PAYMENT-RESPONSE".into(), b64json(&sr)));
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_keys() {
        assert_eq!(path_key("/a?b=1"), "/a");
        assert_eq!(path_key("/a"), "/a");
    }
}
