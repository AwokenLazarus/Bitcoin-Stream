//! The signer: owns the node connection, the keys and the policy; the model-facing process talks
//! only to its socket (B2 `signer.py`, method for method; `docs/B2_SIGNER_API.md`).
//!
//! Human approval is cryptographic: the signer holds only an ed25519 public key; `approve`,
//! `sweep_hot` and the recoveries need a signature by it. A boolean `human` in a request is never
//! a capability.
//!
//! AGP-013/016/017/022 custody: sealed keys, the signature log anchored with a witness (the signer
//! refuses to start when its log fails the anchor check), write-ahead opens with the minConf wait,
//! no mining off regtest, per-chain hrp, pruned-node lookups, refund custody at expiry (the
//! watcher), the pending close-change retry, rotation, the balance cap and the human sweep.
//!
//! Not ported (see the crate README): the forward rail, the treasury, the presigned vault and the
//! Electrum light backend; their methods answer that they are unavailable.
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Duration;

use serde_json::{json, Value};
use xbt402::client::Transport;
use xbt_primitives::tx::Tx;

use crate::anchor::{AnchorClient, Anchorer};
use crate::approval::{recover_message, sweep_message, verify, verify_approval, x2b};
use crate::channels::{AdaptorScheme, ChannelBook};
use crate::hot::{HotWallet, DEFAULT_FEE};
use crate::keystore::KeyStore;
use crate::ln::{LnBackend, LnBook, LndRest};
use crate::node::{self, KnotsRpc, Node};
use crate::policy::{normalize_dest, AuditLog, Clock, Payment, PolicyConfig, PolicyEngine, PolicyStore};
use crate::pyjson::{now_f64, py_int, str_or_empty, truthy, ts_value};
use crate::routing::{RoutePolicy, RouteSigner};
use crate::sanitize::sanitize;
use crate::session::{origin_of, MineFn, Session};
use crate::sigaudit::{self, check_chain, SigAudit};
use crate::{err, Result};

pub const XBT_SATS: i64 = 100_000_000;

/// Same texts as B2 `sats_from_xbt` (`agentwallet/signer.py`).
pub const ERR_NOT_DECIMAL: &str = "amount_xbt is not a decimal number";
pub const ERR_NOT_FINITE: &str = "amount_xbt must be a finite number";
pub const ERR_NEGATIVE: &str = "amount_xbt must not be negative";
pub const ERR_PRECISION: &str = "amount_xbt has more than 8 decimal places";

/// Exact XBT → sats (B2 `sats_from_xbt`): at most 8 decimal places; refuse negatives, NaN and inf.
/// Scientific notation (`1e-05`) is accepted. Extra precision is an error, never truncated.
pub fn sats_from_xbt(v: Option<&Value>) -> std::result::Result<i64, &'static str> {
    let s = match v {
        None | Some(Value::Null) => "0".to_string(),
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() { i.to_string() } else { crate::pyjson::py_float(n.as_f64().unwrap_or(0.0)) }
        }
        Some(Value::Bool(false)) => "0".to_string(),
        Some(Value::Bool(true)) => "True".to_string(),
        Some(other) => other.to_string(),
    };
    parse_xbt_decimal(&s)
}

fn parse_xbt_decimal(s: &str) -> std::result::Result<i64, &'static str> {
    let s = s.trim();
    if is_non_finite_token(s) {
        return Err(ERR_NOT_FINITE);
    }
    let (neg, rest) = if let Some(r) = s.strip_prefix('-') {
        (true, r)
    } else if let Some(r) = s.strip_prefix('+') {
        (false, r)
    } else {
        (false, s)
    };
    if is_non_finite_token(rest) {
        return Err(ERR_NOT_FINITE);
    }
    let (mant, exp) = match rest.find(['e', 'E']) {
        Some(i) => {
            let e: i32 = rest[i + 1..].parse().map_err(|_| ERR_NOT_DECIMAL)?;
            (&rest[..i], e)
        }
        None => (rest, 0),
    };
    if mant.is_empty() {
        return Err(ERR_NOT_DECIMAL);
    }
    let (whole, frac) = match mant.split_once('.') {
        Some((w, f)) => (w, f),
        None => (mant, ""),
    };
    if !whole.bytes().all(|c| c.is_ascii_digit()) || !frac.bytes().all(|c| c.is_ascii_digit()) {
        return Err(ERR_NOT_DECIMAL);
    }
    if whole.is_empty() && frac.is_empty() {
        return Err(ERR_NOT_DECIMAL);
    }
    let mut digits = String::with_capacity(whole.len() + frac.len() + 1);
    digits.push_str(if whole.is_empty() { "0" } else { whole });
    digits.push_str(frac);
    let power = exp
        .checked_sub(frac.len() as i32)
        .and_then(|p| p.checked_add(8))
        .ok_or(ERR_NOT_DECIMAL)?;
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Ok(0);
    }
    if neg {
        return Err(ERR_NEGATIVE);
    }
    let n: i128 = digits.parse().map_err(|_| ERR_NOT_DECIMAL)?;
    let sats = if power >= 0 {
        let mut v = n;
        for _ in 0..power {
            v = v.checked_mul(10).ok_or(ERR_NOT_DECIMAL)?;
        }
        v
    } else {
        let places = u32::try_from(-power).map_err(|_| ERR_NOT_DECIMAL)?;
        if places > 38 {
            return Err(ERR_PRECISION);
        }
        let div = 10i128.checked_pow(places).ok_or(ERR_PRECISION)?;
        if n % div != 0 {
            return Err(ERR_PRECISION);
        }
        n / div
    };
    i64::try_from(sats).map_err(|_| ERR_NOT_DECIMAL)
}

fn is_non_finite_token(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "nan" | "+nan" | "-nan" | "inf" | "+inf" | "-inf" | "infinity" | "+infinity" | "-infinity"
    )
}

pub fn deny(rule: &str, reason: impl Into<String>) -> Value {
    json!({"verdict": "deny", "rule": rule, "reason": reason.into()})
}

pub(crate) fn with(mut v: Value, extra: Value) -> Value {
    if let (Value::Object(a), Value::Object(b)) = (&mut v, extra) {
        for (k, x) in b {
            a.insert(k, x);
        }
    }
    v
}

fn trunc(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Codes that are B2 RuntimeErrors (reported as `deny/xbt402`), not xbt402 `ChannelError` codes.
const INTERNAL: [&str; 10] = ["xbt402", "rpc_error", "transport_error", "io", "keystore", "hot", "sigaudit", "chain", "poisoned", "anchor"];

/// A witness-v0 address of this chain's hrp (B1 `address_to_spk(addr, hrp)`, P5).
pub fn address_to_spk(addr: &str, hrp: &str) -> Result<Vec<u8>> {
    let spk = xbt_primitives::address::address_to_spk(addr, Some(hrp)).map_err(|e| err("bad_address", e.to_string()))?;
    if spk.first() != Some(&0) {
        return Err(err("bad_address", "only witness v0"));
    }
    Ok(spk)
}

/// How to build a signer (tests inject a node, a transport, a clock, an adaptor scheme; the default
/// scheme is [`crate::routing::Xbt402Adaptor`]).
#[derive(Default)]
pub struct SignerOptions {
    pub node: Option<Arc<dyn Node>>,
    pub transport: Option<Arc<dyn Transport>>,
    pub clock: Option<Clock>,
    pub adaptor: Option<Arc<dyn AdaptorScheme>>,
    /// Overrides `B2_ANCHOR_SOCK`.
    pub anchor: Option<AnchorClient>,
    /// Overrides `B2_HOT_KEYFILE` / `B2_HOT_PASSPHRASE` (the container entry point's secret source, AGP-038).
    pub keystore: Option<Arc<KeyStore>>,
    /// AGP-048: the LN node `rail=ln` pays through (default: `B2_LN_REST` / `B2_LN_MACAROON` / `B2_LN_TLS_CERT`).
    pub ln: Option<Arc<dyn LnBackend>>,
}

pub struct Signer {
    pub root: PathBuf,
    pub run: PathBuf,
    /// Live (AGP-039 `policy_set`): read with [`Signer::config`].
    config: RwLock<PolicyConfig>,
    pub engine: Arc<PolicyEngine>,
    pub node: Arc<dyn Node>,
    pub chain: String,
    pub hrp: String,
    pub mining: bool,
    pub sock_path: PathBuf,
    human_pubkey: RwLock<Vec<u8>>,
    pub(crate) spend: Mutex<()>,
    /// AGP-039: what became of an approval token that left the ledger (denied, used, expired).
    pub(crate) approval_outcomes: Mutex<HashMap<String, Value>>,
    /// policy.json as this process read it at start (restart-only keys are compared with it).
    pub(crate) boot_policy: Value,
    pub keystore: Option<Arc<KeyStore>>,
    pub sigaudit: Arc<SigAudit>,
    pub anchor: Anchorer,
    pub hot: Arc<HotWallet>,
    pub book: Arc<ChannelBook>,
    pub session: Session,
    pub routing: RouteSigner,
    open_tried: Mutex<HashMap<String, f64>>,
    pub watch_interval: f64,
    /// AGP-048 `rail=ln`: the LN node (None: not configured), a configuration error that keeps the
    /// rail shut, and the write-ahead payment book.
    pub ln: Option<Arc<dyn LnBackend>>,
    pub ln_error: Option<String>,
    pub ln_book: LnBook,
    /// AGP-049: channel funding verdicts from our own node, per funding outpoint (final ones only).
    pub(crate) ln_funding: Mutex<HashMap<String, crate::ln_funding::Funding>>,
}

impl Signer {
    /// B2's `Signer(root)`: `root/policy.json`, state in `root/.run`, environment as B2 reads it.
    pub fn new(root: &Path, opts: SignerOptions) -> Result<Arc<Self>> {
        let run = root.join(".run");
        std::fs::create_dir_all(&run).map_err(|e| err("io", format!("{}: {e}", run.display())))?;
        let raw: Value = serde_json::from_str(&std::fs::read_to_string(root.join("policy.json"))
            .map_err(|e| err("io", format!("{}: {e}", root.join("policy.json").display())))?)
            .map_err(|e| err("policy", format!("policy.json: {e}")))?;
        let config = PolicyConfig::from_value(&raw)?;
        let engine = Arc::new(PolicyEngine::new(config.clone(), PolicyStore::open(&run.join("ledger.json"))?,
                                                AuditLog::open(&run.join("audit.jsonl"))?, opts.clock.clone()));
        let backend = std::env::var("B2_CHAIN_BACKEND").unwrap_or_default().trim().to_lowercase();
        if backend == "electrum" && opts.node.is_none() {
            return Err(err("chain", "B2_CHAIN_BACKEND=electrum: the Electrum light backend is not ported to the Rust signer (AGP-028); use the node RPC"));
        }
        let datadir = std::env::var("B2_DATADIR").map(PathBuf::from).unwrap_or_else(|_| root.join(".regtest"));
        let wallet = std::env::var("B2_WALLET").unwrap_or_else(|_| "agent".into());
        let node: Arc<dyn Node> = opts.node.clone().unwrap_or_else(|| Arc::new(KnotsRpc::new(&datadir, &wallet)));
        // P3/P5: the chain decides the hrp and whether this process may ever mine
        let chain = node::detect_chain(&*node)?;
        if config.regtest_mine == Some(true) && !node::mining_allowed(&chain) {
            return Err(err("chain", format!("policy regtest_mine is set but the node is on {chain:?}: refusing to start (only regtest may mine)")));
        }
        let mining = node::mining_allowed(&chain) && config.regtest_mine != Some(false);
        node.set_allow_generate(mining);
        let hrp = node::hrp(&chain)?.to_string();
        let sock_path = std::env::var("B2_SIGNER_SOCK").map(PathBuf::from).unwrap_or_else(|_| run.join("signer.sock"));
        let pub_hex = raw.get("human_pubkey").and_then(Value::as_str).unwrap_or("").trim().to_string();
        let human_pubkey = if pub_hex.is_empty() { vec![] } else { x2b(&pub_hex).ok_or_else(|| err("policy", "human_pubkey is not hex"))? };
        let keystore = match opts.keystore.clone() {
            Some(k) => Some(k),
            None => KeyStore::from_env(Some(&run), true)?.map(Arc::new),
        };
        if keystore.is_none() && !KeyStore::plaintext_allowed() {
            return Err(err("keystore", "the signer's hot key must be encrypted at rest: set B2_HOT_KEYFILE (a 32-byte key file outside the run dir) \
                                        or B2_HOT_PASSPHRASE (B2_HOT_ALLOW_PLAINTEXT=1 for tests)"));
        }
        let sigaudit = Arc::new(SigAudit::open(&run.join("signatures.jsonl"))?);
        let anchor = Anchorer::new(sigaudit.clone(), opts.anchor.clone().or_else(AnchorClient::from_env), config.anchor_interval_s as f64);
        Self::check_anchor_at_start(&anchor, &config)?;
        let hot = Arc::new(HotWallet::open(&run.join("hot.json"), node.clone(), &hrp, keystore.clone(), Some(sigaudit.clone()),
                                           config.hot_balance_cap_sats)?);
        hot.reconcile(std::env::var("B2_HOT_SCAN").map(|v| v != "0").unwrap_or(true));
        let book = Arc::new(ChannelBook::open(&run.join("channels.json"), &run.join("channel_keys.json"), keystore.clone(), Some(sigaudit.clone()))?);
        let n2 = node.clone();
        book.set_expiry_guard(Arc::new(move || node::height(&*n2)), config.refund_margin_blocks);
        let transport = opts.transport.clone().unwrap_or_else(|| Arc::new(xbt402::http::UreqTransport::default()));
        let mine: Option<MineFn> = if mining {
            let n3 = node.clone();
            Some(Arc::new(move |k: u64| mine_blocks(&*n3, k)))
        } else {
            None
        };
        let session = Session::new(book.clone(), hot.clone(), node.clone(), transport, &chain, mine, config.open_wait_s as f64,
                                   config.close_fee_max_sats, config.refund_margin_blocks)?;
        let routing = RouteSigner::new(book.clone(), RoutePolicy::from_value(&config.routing), Some(&run.join("routing.json")),
                                       Some(engine.clone()), Some(opts.adaptor.clone().unwrap_or_else(|| Arc::new(crate::routing::Xbt402Adaptor))))?;
        let watch_interval = std::env::var("B2_WATCH_INTERVAL").ok().and_then(|v| v.parse().ok()).unwrap_or(10.0);
        // an LN misconfiguration shuts only the LN rail (every ln_pay is refused with it)
        let (ln, ln_error) = match opts.ln.clone() {
            Some(b) => (Some(b), None),
            None => match LndRest::from_env() {
                Ok(b) => (b.map(|b| Arc::new(b) as Arc<dyn LnBackend>), None),
                Err(e) => (None, Some(e.msg)),
            },
        };
        let ln_book = LnBook::open(&run.join("ln_payments.json"))?;
        Ok(Arc::new(Self { root: root.into(), run, config: RwLock::new(config), engine, node, chain, hrp, mining, sock_path,
                           human_pubkey: RwLock::new(human_pubkey), spend: Mutex::new(()), approval_outcomes: Mutex::new(HashMap::new()), boot_policy: raw,
                           keystore, sigaudit, anchor, hot, book, session, routing, open_tried: Mutex::new(HashMap::new()), watch_interval,
                           ln, ln_error, ln_book, ln_funding: Mutex::new(HashMap::new()) }))
    }

    /// Fail closed if the signature log no longer holds the witness's latest anchor.
    fn check_anchor_at_start(anchor: &Anchorer, config: &PolicyConfig) -> Result<()> {
        if !anchor.enabled() {
            if config.anchor_required {
                return Err(err("sigaudit", format!("policy anchor_required: set {} to the anchor witness socket", crate::anchor::ENV_SOCK)));
            }
            return Ok(());
        }
        let chk = match anchor.check() {
            Ok(c) => c,
            Err(e) => {
                if config.anchor_required {
                    return Err(err("sigaudit", format!("policy anchor_required: {}", e.msg)));
                }
                anchor.set_error(&e.msg);
                return Ok(());
            }
        };
        if chk["ok"] != Value::Bool(true) {
            return Err(err("sigaudit", format!("signature log fails its anchor check ({}): refusing to start. \
                                                Keep the log and the witness store as evidence and ask a human.", chk["reason"].as_str().unwrap_or(""))));
        }
        anchor.anchor("signer_start");
        Ok(())
    }

    /// The policy in force now.
    pub fn config(&self) -> PolicyConfig {
        self.config.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub(crate) fn set_config_live(&self, c: PolicyConfig) {
        *self.config.write().unwrap_or_else(|p| p.into_inner()) = c;
    }

    /// The human's ed25519 public key (empty: none enrolled).
    pub fn human_key(&self) -> Vec<u8> {
        self.human_pubkey.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub(crate) fn set_human_key(&self, k: Vec<u8>) {
        *self.human_pubkey.write().unwrap_or_else(|p| p.into_inner()) = k;
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, ()> {
        match self.spend.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// Anchor after a close, refund or sweep. Never fails the operation that triggered it.
    pub(crate) fn anchor_after(&self, reason: &str) {
        if self.anchor.enabled() {
            self.anchor.anchor(reason);
        }
    }

    fn now(&self) -> f64 {
        self.engine.now()
    }

    fn height(&self) -> Result<i64> {
        node::height(&*self.node).map(|h| h as i64)
    }

    pub(crate) fn height_safe(&self) -> i64 {
        self.height().unwrap_or(0)
    }

    fn mine_safe(&self) {
        if self.mining {
            let _ = mine_blocks(&*self.node, 1);
        }
    }

    /// Handle one request; every signature made meanwhile is logged under its method.
    pub fn handle(&self, method: &str, params: &Value) -> Result<Value> {
        let _ctx = sigaudit::context(Some(method), Some(&format!("method:{method}")));
        let empty = json!({});
        let p = if params.is_object() { params } else { &empty };
        self.dispatch(method, p)
    }

    fn dispatch(&self, method: &str, p: &Value) -> Result<Value> {
        let s = |k: &str| str_or_empty(p.get(k));
        Ok(match method {
            "balance" => {
                let bals = self.node.call("getbalances", json!([])).unwrap_or(json!({}));
                let mine = bals.get("mine").cloned().unwrap_or(json!({}));
                sanitize(json!({"trusted_sats": node::sats(mine.get("trusted")), "untrusted_pending_sats": node::sats(mine.get("untrusted_pending")),
                                "immature_sats": node::sats(mine.get("immature")), "vault": null, "treasury": null,
                                "not_ported": ["vault", "treasury", "forward"], "hot": self.hot_status(false), "channels": self.book.list_public()}))
            }
            "quote_payment" => {
                let d = self.engine.quote(&self.payment(p)?)?;
                let mut out = d.as_value();
                out["fee_estimate"] = self.node.call("estimatesmartfee", json!([1])).unwrap_or(Value::Null);
                sanitize(out)
            }
            "pay" => {
                let _g = self.lock();
                sanitize(self.pay_locked(p, false)?)
            }
            "approve" => sanitize(self.approve_signed(p)?),
            "history" => sanitize(json!({"events": self.engine.audit.read(py_int(p.get("limit")).filter(|l| *l > 0).unwrap_or(50) as usize)})),
            "recover_vault" | "fund_treasury" | "recover_treasury" => {
                json!({"ok": false, "reason": format!("{method}: the presigned vault and the treasury are not ported to the Rust signer")})
            }
            "health" => json!({"ok": true, "wallet": self.node.wallet(), "chain": self.chain, "hrp": self.hrp, "mining": self.mining,
                               "implementation": "xbt-signer (Rust)"}),
            "chain_backend" => json!({"backend": "rpc"}),
            // read-only: an external payer waits for its funding's minConf (P2) through this
            "tx_confirmations" => {
                let r = self.node.call("gettxout", json!([s("txid"), py_int(p.get("vout")).unwrap_or(0), true]))?;
                json!({"confirmations": if r.is_null() { Value::Null } else { r.get("confirmations").cloned().unwrap_or(0.into()) },
                       "height": self.height_safe()})
            }
            "channels" => sanitize(json!({"channels": self.book.list_public(), "height": self.height_safe()})),
            "hot_address" => sanitize(self.hot_status(false)),
            "notice_hot_txid" => {
                let n = self.hot.scan_from_txid(&s("txid"), false, "")?;
                sanitize(with(self.hot.status(), json!({"noticed": n})))
            }
            "fund" => {
                let sats = py_int(p.get("sats")).filter(|v| *v != 0).or_else(|| py_int(p.get("amount_sats"))).unwrap_or(0);
                let addr = if s("address").is_empty() { s("to") } else { s("address") };
                let (txid, vout) = self.hot.fund(&address_to_spk(&addr, &self.hrp)?, sats, DEFAULT_FEE)?;
                sanitize(json!({"txid": txid, "vout": vout, "sats": sats, "sighash": "0x21"}))
            }
            "open_channel" => {
                let _g = self.lock();
                sanitize(self.open_channel_locked(p)?)
            }
            "sign_state" | "xbt402_sign_state" => sanitize(self.sign_state(p)?),
            "xbt402_pay" => {
                let _g = self.lock();
                sanitize(self.xbt402_pay_locked(p))
            }
            "xbt402_request_auth" => {
                let chan = s("chan");
                let sig = p.get("sig").and_then(Value::as_str).filter(|x| !x.is_empty());
                match self.book.request_auth(&chan, p.get("seq"), p.get("cum"), sig, &s("req")) {
                    Ok(a) => json!({"auth": a}),
                    Err(e) => deny("xbt402_request_auth", e.msg),
                }
            }
            "xbt402_sign_state_a3" => {
                let _g = self.lock();
                sanitize(self.sign_a3(p))
            }
            "xbt402_sign_rollover" => {
                let _g = self.lock();
                sanitize(self.sign_rollover(p))
            }
            "xbt402_new_key" => {
                let origin = s("origin");
                if origin.is_empty() {
                    return Ok(deny("dest", "origin required"));
                }
                json!({"pub": self.book.issue_key(&origin)?})
            }
            "xbt402_attach" => {
                let _g = self.lock();
                sanitize(self.attach(p))
            }
            "xbt402_sign_close" => match self.book.find_dest(&s("chan")) {
                None => deny("unknown_channel", format!("no channel for {}", s("chan"))),
                Some(d) => {
                    sigaudit::set_rule("client:close");
                    match self.book.sign_close(&d) {
                        Ok(sig) => json!({"sig": sig}),
                        Err(e) => deny(&e.code, e.msg),
                    }
                }
            },
            "xbt402_sign_refund" => sanitize(self.sign_refund(p)),
            "xbt402_sign_conditional" => {
                let _g = self.lock();
                sanitize(self.sign_conditional(p))
            }
            "xbt402_mark_closed" => {
                let _g = self.lock();
                sanitize(self.mark_closed(p))
            }
            "xbt402_sign_state_adaptor" => {
                let _g = self.lock();
                sigaudit::set_rule("policy:routing");
                let route = p.get("route").filter(|r| r.is_object()).cloned().unwrap_or(json!({}));
                match self.routing.sign_state_adaptor(&s("chan"), py_int(p.get("cum")).unwrap_or(0), &s("point"), route) {
                    Ok(out) => sanitize(with(json!({"verdict": "allow"}), out)),
                    Err(e) => deny(&e.code, e.msg),
                }
            }
            "xbt402_resolve_lock" => {
                let _g = self.lock();
                match self.routing.resolve_lock(&s("chan"), &s("secret")) {
                    Ok(t) => json!({"t": t}),
                    Err(e) => deny(&e.code, e.msg),
                }
            }
            "xbt402_void_lock" => {
                let _g = self.lock();
                match self.routing.void_lock(&s("chan")) {
                    Ok(v) => json!({"voided": truthy(Some(&v))}),
                    Err(e) => deny(&e.code, e.msg),
                }
            }
            "xbt402_adopt_lock" => {
                let _g = self.lock();
                match self.routing.adopt_lock(&s("chan"), py_int(p.get("cum")).unwrap_or(0)) {
                    Ok(()) => json!({"adopted": true}),
                    Err(e) => deny(&e.code, e.msg),
                }
            }
            "xbt402_recover_lock" => {
                let _g = self.lock();
                sanitize(self.recover_lock(p))
            }
            "routing_status" => sanitize(self.routing.status()),
            // AGP-048 rail=ln
            "ln_pay" => {
                let _g = self.lock();
                sanitize(self.ln_pay_locked(p))
            }
            "ln_status" => {
                let _g = self.lock();
                sanitize(self.ln_status_locked())
            }
            "close_channel" => {
                let _g = self.lock();
                sanitize(self.close_channel_locked(p))
            }
            "xbt402_refund" | "refund_channel" => {
                let _g = self.lock();
                let key = ["counterparty", "dest", "chan"].iter().map(|k| s(k)).find(|v| !v.is_empty()).unwrap_or_default();
                sanitize(self.refund_locked(&key, false)?)
            }
            "watch_tick" => sanitize(json!({"actions": self.watch_tick()})),
            "forward_status" => json!({"enabled": false, "ported": false, "reason": "the forward rail is not ported to the Rust signer",
                                       "pending": [], "delivered": []}),
            "forward_pending" => json!({"pending": []}),
            "forward_transfers" => json!({"delivered": []}),
            "forward_recover" => deny("forward_disabled", "the forward rail is not ported to the Rust signer"),
            "rotate_hot_key" => {
                let _g = self.lock();
                self.rotate_locked("operator:rotate_hot_key")?
            }
            "sweep_hot" => {
                let _g = self.lock();
                sanitize(self.sweep_hot_signed(p))
            }
            "signatures" => {
                let chk = match self.anchor.check() {
                    Ok(c) => c,
                    Err(e) => with(check_chain(&self.sigaudit.path, None), json!({"anchor_error": trunc(&e.msg, 200)})),
                };
                let limit = py_int(p.get("limit")).filter(|l| *l > 0).unwrap_or(50) as usize;
                sanitize(json!({"signatures": self.sigaudit.read(limit), "chain_ok": chk["ok"], "chain": chk, "anchor": self.anchor.status()}))
            }
            "anchor_now" => {
                let reason = if s("reason").is_empty() { "operator".to_string() } else { s("reason") };
                sanitize(json!({"result": self.anchor.anchor(&reason), "anchor": self.anchor.status()}))
            }
            "anchor_status" => sanitize(with(self.anchor.status(), json!({"last_error": self.anchor.last_error()}))),
            "hot_reconcile" => {
                if truthy(p.get("last")) {
                    return Ok(sanitize(with(self.hot.last_reconcile(), self.hot.status())));
                }
                let _g = self.lock();
                let scan = p.get("scan").map(|v| truthy(Some(v))).unwrap_or(true);
                sanitize(with(self.hot.reconcile(scan), self.hot_status(true)))
            }
            other => match self.admin_dispatch(other, p) {
                Some(r) => r?,
                None => return Err(err("unknown_method", format!("unknown method {other}"))),
            },
        })
    }

    /// Rotate the hot key (the caller holds the spend lock); `rule` names who asked in the signature log.
    pub(crate) fn rotate_locked(&self, rule: &str) -> Result<Value> {
        sigaudit::set_rule(rule);
        let out = self.hot.rotate()?;
        self.engine.audit.append(json!({"type": "hot_rotation", "ts": ts_value(self.now()), "old_address": out["old_address"],
                                        "new_address": out["new_address"], "sweep_txid": out["sweep"].get("txid")}));
        if !out["sweep"].is_null() {
            self.mine_safe();
        }
        self.anchor_after("rotation");
        Ok(sanitize(with(out, self.hot.status())))
    }

    fn payment(&self, p: &Value) -> Result<Payment> {
        let amount = match p.get("amount_sats").filter(|v| !v.is_null()) {
            Some(v) => py_int(Some(v)).ok_or_else(|| err("bad_request", "amount_sats is not an integer"))?,
            None => sats_from_xbt(p.get("amount_xbt")).map_err(|m| err("bad_request", m))?,
        };
        let to = str_or_empty(p.get("to"));
        let to = if to.is_empty() { str_or_empty(p.get("dest")) } else { to };
        Ok(Payment::new(&to, amount, &str_or_empty(p.get("memo"))))
    }

    // --- refund custody, the watcher, the human sweep --------------------------------------------------

    /// Broadcast the payer's CLTV refund of a channel the provider did not close. The refund always
    /// pays the current hot key: nothing the caller passes can redirect it.
    pub fn refund_locked(&self, key: &str, auto: bool) -> Result<Value> {
        if !self.config().refund_enabled {
            return Ok(deny("refund_disabled", "refunds are off in this policy"));
        }
        let dest = if key.is_empty() { None } else { self.book.find_dest(key) };
        let Some((dest, rec)) = dest.and_then(|d| self.book.get(&d).map(|r| (d, r))) else {
            return Ok(deny("unknown_channel", format!("no channel for {key}")));
        };
        let base = json!({"dest": dest, "chan": rec.chan, "expiry": rec.expiry});
        if rec.state == "refunded" {
            // idempotent: report the refund already made, never a second one
            return Ok(with(json!({"verdict": "allow", "rule": "already_refunded", "already": true}),
                           with(base, json!({"txid": rec.refund_txid, "sats": rec.funding_sats - rec.close_fee}))));
        }
        if rec.state == "closed" {
            self.notice_close_change(&dest);
            return Ok(with(with(deny("channel_closed", "the channel was closed; there is nothing to refund"), base),
                           json!({"closed_txid": if rec.closed_txid.is_empty() { Value::Null } else { rec.closed_txid.clone().into() }})));
        }
        let h = self.height()?;
        if h < rec.expiry {
            return Ok(with(with(deny("refund_early", format!("height {h}: the refund is valid from the block after {}", rec.expiry)), base),
                           json!({"height": h})));
        }
        let utxo = match self.node.call("gettxout", json!([rec.funding_txid, rec.funding_vout, true])) {
            Ok(u) => u,
            Err(e) => return Ok(deny("refund_rpc", trunc(&e.msg, 200))),
        };
        if utxo.is_null() {
            // P6: no txindex. The spend is found in the mempool or by scanning blocks from the funding's
            // block; the funding counts as known once seen confirmed or in the mempool.
            let start = if rec.funding_height != 0 { rec.funding_height } else { rec.open_height };
            let spender = node::find_spender(&*self.node, &rec.funding_txid, rec.funding_vout as u32, start.max(0) as u64, node::SPENDER_SCAN_MAX);
            let known = spender.is_some() || rec.funding_height != 0 || node::get_tx(&*self.node, &rec.funding_txid, "").is_some();
            if known {
                // AGP-022: the change first, then the state: a reader that sees "closed" sees the change
                let sp = spender.clone().unwrap_or_default();
                let change = self.session.learn_close_change(&rec, &sp, start, "");
                self.book.mark_closed(&dest, &sp, Some(&change), "")?;
                let closed = spender.or_else(|| change.get("txid").and_then(Value::as_str).filter(|t| !t.is_empty()).map(str::to_string));
                return Ok(with(with(deny("channel_closed", "the funding output is already spent (the provider closed)"), base),
                               json!({"closed_txid": closed})));
            }
            return Ok(with(deny("funding_unknown", "the funding output is not on this node"), base));
        }
        sigaudit::set_rule(if auto { "watcher:auto_refund" } else { "policy:refund_enabled" });
        let (tx, _) = self.book.refund_tx(&dest, &self.hot.spk(), Some(rec.close_fee.max(0) as u64))?;
        let txid = match self.node.call("sendrawtransaction", json!([tx.to_hex()])) {
            Ok(t) => t.as_str().map(str::to_string).unwrap_or_else(|| tx.txid()),
            Err(e) => return Ok(with(deny("refund_rejected", trunc(&e.msg, 200)), base)),
        };
        self.book.mark_refunded(&dest, &txid)?;
        let sats = tx.outputs[0].value;
        self.hot.notice_utxo(&txid, 0, sats, "")?;
        self.engine.audit.append(json!({"type": "refund", "dest": dest, "chan": rec.chan, "txid": txid, "sats": sats, "auto": auto,
                                        "ts": ts_value(self.now())}));
        self.anchor_after("refund");
        Ok(with(json!({"verdict": "allow", "rule": "refund"}), with(base, json!({"txid": txid, "sats": sats, "to": self.hot.address(), "auto": auto}))))
    }

    /// AGP-016/022: learn a closed channel's still-unspent change once; a final answer is never
    /// looked up again, so a coin is never counted twice.
    fn notice_close_change(&self, dest: &str) -> String {
        let Some(rec) = self.book.get(dest).filter(|r| r.state == "closed") else { return String::new() };
        if !rec.close_change.is_empty() && rec.close_change != "pending" {
            return rec.close_change;
        }
        let change = self.session.learn_close_change(&rec, &rec.closed_txid, 0, &rec.close_hex);
        let _ = self.book.note_close_change(dest, &change);
        change["status"].as_str().unwrap_or("pending").to_string()
    }

    /// Retry every closed channel whose change is still pending. The caller holds the spend lock.
    fn settle_close_changes(&self) -> Vec<Value> {
        let mut out = vec![];
        for rec in self.book.pending_close_records() {
            let st = self.notice_close_change(&rec.dest);
            if st != "pending" {
                let closed = self.book.get(&rec.dest).map(|r| r.closed_txid).unwrap_or(rec.closed_txid.clone());
                out.push(json!({"dest": rec.dest, "chan": rec.chan, "close_change": st, "closed_txid": closed}));
            }
        }
        out
    }

    /// The hot status once pending close changes had their chance (a read after a close sees its
    /// change, or is told which closes are still pending).
    fn hot_status(&self, locked: bool) -> Value {
        if !self.book.pending_close_records().is_empty() {
            if locked {
                self.settle_close_changes();
            } else {
                let _g = self.lock();
                self.settle_close_changes();
            }
        }
        let pend: Vec<Value> = self.book.pending_close_records().into_iter()
            .map(|r| (if r.closed_txid.is_empty() { r.chan } else { r.closed_txid }).into()).collect();
        with(self.hot.status(), json!({"hot_pending_close_change": pend}))
    }

    /// One watcher pass: finish pending opens, refund every open channel at or past its expiry,
    /// retry pending close changes, sweep coins that reached a retired key, anchor when due.
    pub fn watch_tick(&self) -> Vec<Value> {
        let mut actions = vec![];
        let Ok(h) = self.height() else { return actions };
        for rec in self.book.pending_records() {
            // P1/P2: finish opens a crash or a wait left behind
            if h >= rec.expiry - self.config().refund_margin_blocks {
                continue;
            }
            {
                let mut tried = self.open_tried.lock().unwrap_or_else(|p| p.into_inner());
                if now_f64() - tried.get(&rec.dest).copied().unwrap_or(0.0) < self.config().open_retry_s as f64 {
                    continue;
                }
                tried.insert(rec.dest.clone(), now_f64());
            }
            let act = {
                let _g = self.lock();
                let _c = sigaudit::context(Some("watcher"), Some("watcher:open_retry"));
                match self.session.complete_open(&rec.dest, 0.0) {
                    Ok(r) => json!({"state": r.get("state"), "confirmations": r.get("confirmations")}),
                    Err(e) => json!({"state": "pending", "error": trunc(&e.msg, 160)}),
                }
            };
            if act["state"] == "open" || act.get("error").is_some() {
                actions.push(json!({"dest": rec.dest, "chan": rec.chan, "height": h, "open_retry": act}));
            }
        }
        for rec in self.book.unsettled_records() {
            if h >= rec.expiry {
                let r = {
                    let _g = self.lock();
                    let _c = sigaudit::context(Some("watcher"), None);
                    self.refund_locked(&rec.dest, true).unwrap_or_else(|e| deny("refund_error", e.msg))
                };
                let mut a = json!({"dest": rec.dest, "chan": rec.chan, "height": h});
                for k in ["verdict", "rule", "txid", "sats", "reason"] {
                    a[k] = r.get(k).cloned().unwrap_or(Value::Null);
                }
                actions.push(a);
            }
        }
        if !self.book.pending_close_records().is_empty() {
            // AGP-022: a close's change not yet counted
            let _g = self.lock();
            let _c = sigaudit::context(Some("watcher"), None);
            for a in self.settle_close_changes() {
                actions.push(with(a, json!({"height": h})));
            }
        }
        let sw = {
            let _g = self.lock();
            let _c = sigaudit::context(Some("watcher"), Some("watcher:retired_sweep"));
            match self.hot.sweep_retired() {
                Ok(v) => v,
                Err(e) => Some(json!({"error": trunc(&e.msg, 200)})),
            }
        };
        if let Some(sw) = sw {
            let swept = sw.get("txid").is_some();
            actions.push(json!({"retired_sweep": sw}));
            if swept {
                self.anchor_after("retired_sweep");
            }
        }
        if self.anchor.due() {
            let r = self.anchor.anchor("periodic");
            if r.get("ok") != Some(&Value::Bool(true)) || !truthy(r.get("unchanged")) {
                let mut a = json!({});
                for k in ["ok", "n", "seq", "alert", "reason"] {
                    a[k] = r.get(k).cloned().unwrap_or(Value::Null);
                }
                actions.push(json!({"anchor": a}));
            }
        }
        // AGP-048: a Lightning payment a crash or a timeout left in flight (AGP-049: or one released as
        // never sent, which the node may still record late)
        if self.ln.is_some() && (!self.ln_book.in_flight().is_empty() || !self.ln_book.watched(self.engine.now()).is_empty()) {
            let _g = self.lock();
            let _c = sigaudit::context(Some("watcher"), Some("watcher:ln_reconcile"));
            for r in self.ln_reconcile_locked() {
                actions.push(json!({"ln_reconcile": r}));
            }
        }
        actions
    }

    fn sweep_hot_signed(&self, p: &Value) -> Value {
        let to = { let t = str_or_empty(p.get("to")); if t.is_empty() { str_or_empty(p.get("address")) } else { t } }.trim().to_string();
        let (Some(amount), Some(expiry), Some(sig)) = (py_int(p.get("amount_sats")).or(Some(0)), py_int(p.get("expiry")).or(Some(0)),
                                                        x2b(&str_or_empty(p.get("signature")))) else {
            return json!({"ok": false, "reason": "bad amount, expiry or signature"});
        };
        if self.human_key().is_empty() || sig.is_empty() || !verify(&self.human_key(), &sweep_message(&self.hot.address(), &to, amount, expiry), &sig) {
            return json!({"ok": false, "reason": "sweep_hot requires a valid human signature"});
        }
        if (expiry as f64) < self.now() {
            return json!({"ok": false, "reason": "sweep signature expired"});
        }
        sigaudit::set_rule("human:sweep_signature");
        self.settle_close_changes(); // AGP-022: a pending close change is counted before the sweep
        let out = match address_to_spk(&to, &self.hrp).and_then(|spk| self.hot.sweep_to(&spk, amount, DEFAULT_FEE)) {
            Ok(o) => o,
            Err(e) => return json!({"ok": false, "reason": trunc(&e.msg, 200)}),
        };
        self.engine.audit.append(json!({"type": "hot_sweep", "to": to, "sats": amount, "txid": out["txid"], "ts": ts_value(self.now())}));
        self.anchor_after("human_sweep");
        self.mine_safe();
        with(with(json!({"ok": true, "to": to}), out), self.hot.status())
    }

    // --- payments ---------------------------------------------------------------------------------------

    fn uses_channel(&self, dest: &str) -> bool {
        let dest = normalize_dest(dest);
        self.book.has(&dest) || !self.config().pay_to_for(&dest).is_empty() || dest.starts_with("http://") || dest.starts_with("https://")
    }

    fn pay_locked(&self, p: &Value, human: bool) -> Result<Value> {
        let pay = self.payment(p)?;
        let d = self.engine.evaluate(&pay, human)?;
        if !d.allowed() {
            return Ok(d.as_value());
        }
        sigaudit::set_rule(&if human { "human:approval_signature".to_string() } else { format!("policy:{}", d.rule) });
        let dest = pay.normalized(self.now()).dest;
        if self.uses_channel(&dest) {
            return self.channel_pay(&pay, &dest, d.as_value());
        }
        let xbt = format!("{:.8}", pay.amount_sats as f64 / XBT_SATS as f64);
        let txid = self.node.call("sendtoaddress", json!([pay.dest, xbt, pay.memo, "", false]))?;
        let txid = txid.as_str().unwrap_or("").to_string();
        self.engine.commit(&pay, &txid)?;
        Ok(with(d.as_value(), json!({"txid": txid, "rail": "onchain"})))
    }

    fn channel_pay(&self, pay: &Payment, dest: &str, d: Value) -> Result<Value> {
        if self.book.get(dest).is_none_or(|r| r.state != "open") {
            let opened = self.open_channel_locked(&json!({"dest": dest}))?;
            if opened["verdict"] == "deny" {
                return Ok(opened);
            }
        }
        let rec = match self.book.increment(dest, pay.amount_sats) {
            Ok((rec, _)) => rec,
            Err(e) => return Ok(deny(&e.code, e.msg)),
        };
        self.engine.commit(pay, &rec.chan)?;
        Ok(with(d, json!({"rail": "channel", "chan": rec.chan, "cum": rec.used_sats, "seq": rec.seq, "cap_sats": rec.cap_sats,
                          "used_sats": rec.used_sats})))
    }

    fn open_channel_locked(&self, p: &Value) -> Result<Value> {
        let raw = { let d = str_or_empty(p.get("dest")); if d.is_empty() { str_or_empty(p.get("to")) } else { d } };
        let dest = normalize_dest(&raw);
        if dest.is_empty() {
            return Ok(deny("dest", "destination required"));
        }
        if let Some(existing) = self.book.get(&dest).filter(|r| r.state == "open") {
            return Ok(with(json!({"verdict": "allow", "already": true}), existing.public()));
        }
        let pay_to = { let v = str_or_empty(p.get("pay_to")); if v.trim().is_empty() { self.config().pay_to_for(&dest) } else { v.trim().to_string() } };
        if pay_to.is_empty() {
            return Ok(deny("pay_to", format!("no payTo pubkey registered for {dest}")));
        }
        let cap = py_int(p.get("cap_sats")).filter(|v| *v != 0).unwrap_or(self.config().per_counterparty_cap_sats);
        let expiry_blocks = py_int(p.get("expiry_blocks")).filter(|v| *v != 0).unwrap_or(self.config().channel_expiry_blocks);
        let close_fee = py_int(p.get("close_fee")).filter(|v| *v != 0).unwrap_or(600);
        if let Err(e) = self.hot.check_channel_funding() {
            return Ok(with(deny("hot_balance_cap", e.msg), json!({"action": "human_sweep", "hot_sats": self.hot.balance_sats(), "cap_sats": self.hot.cap_sats()})));
        }
        let (secret, payer_pub) = self.book.new_payer_key();
        let open_height = self.height()?;
        let expiry = open_height + expiry_blocks;
        let params = xbt402::channel::ChannelParams::derive(&hex::decode(&pay_to).map_err(|_| err("pay_to", "payTo is not hex"))?,
                                                            &hex::decode(&payer_pub).unwrap_or_default(), expiry as u32, close_fee as u64,
                                                            Some(self.hot.spk()), &self.session.network()?, xbt402::channel::FeePayer::Payer)?;
        let funded = cap + close_fee;
        let prep = self.hot.prepare_fund(&params.spk(), funded, DEFAULT_FEE)?;
        let params = params.with_funding(&prep.txid, 0, funded as u64)?;
        // P1 write-ahead: this rail has no provider open, so the channel is open once the funding is sent
        self.book.add_pending(&dest, secret, &params, "", Some(cap), open_height, "", "", 0, &prep.hex)?;
        if let Err(e) = self.hot.broadcast(&prep) {
            self.book.drop_pending(&dest, &params.channel_id())?;
            return Err(e);
        }
        self.hot.commit(&prep)?;
        let rec = self.book.mark_open(&dest)?;
        self.mine_safe();
        Ok(with(json!({"verdict": "allow", "rail": "channel"}), with(rec.public(), json!({"funding_sighash": "0x21"}))))
    }

    /// B2's error → deny mapping for `xbt402_pay`.
    fn pay_deny(&self, e: &crate::Error) -> Value {
        match e.code.as_str() {
            "channel_cap" => deny("channel_cap", e.msg.clone()),
            "hot_balance_cap" => with(deny("hot_balance_cap", e.msg.clone()),
                                      json!({"action": "human_sweep", "hot_sats": self.hot.balance_sats(), "cap_sats": self.hot.cap_sats()})),
            c if INTERNAL.contains(&c) => deny("xbt402", e.msg.clone()),
            c => deny(c, e.msg.clone()),
        }
    }

    fn xbt402_pay_locked(&self, p: &Value) -> Value {
        let url = str_or_empty(p.get("url"));
        let method = { let m = str_or_empty(p.get("method")).to_uppercase(); if m.is_empty() { "GET".to_string() } else { m } };
        let raw: Vec<u8> = match p.get("body") {
            Some(Value::String(s)) => s.clone().into_bytes(),
            Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_u64().map(|b| b as u8)).collect(),
            _ => vec![],
        };
        let max_sats = match p.get("max_sats").filter(|v| !v.is_null()) {
            None => 0,
            Some(v) => match py_int(Some(v)) {
                Some(n) => n,
                None => return deny("amount", "max_sats must be an integer"),
            },
        };
        let dest = match origin_of(&url) {
            Ok(d) => d,
            Err(e) => return deny("dest", e.msg),
        };
        if max_sats < 0 {
            return deny("amount", "max_sats must be >= 0");
        }
        let (exp, cap) = (self.config().channel_expiry_blocks, self.config().per_counterparty_cap_sats);
        if max_sats == 0 {
            // free-only: allowlisted dest, no channel open or update; a >0 price is refused in pay_once
            if !self.engine.allowlist().contains(&dest) {
                return deny("allowlist", format!("destination not on allowlist: {dest}"));
            }
            return match self.session.pay_once(&url, &method, &raw, 0, exp, cap) {
                Err(e) => deny("xbt402", e.msg),
                Ok(r) if r["verdict"] == "deny" => r,
                Ok(r) => with(with(json!({"verdict": "allow", "rule": "free"}), r), json!({"rail": "xbt402"})),
            };
        }
        let pay = Payment::new(&dest, max_sats, &format!("xbt402 {method} {url}"));
        // AGP-039: a human-approved grant for exactly this call pays as B2's approve does (human = true)
        let grant = self.find_xbt402_grant(&dest, max_sats, &url, &method);
        let d = match self.engine.evaluate(&pay, grant.is_some()) {
            Ok(d) => d,
            Err(e) => return deny("xbt402", e.msg),
        };
        if d.verdict == crate::policy::Verdict::NeedsHuman {
            if let Some(t) = &d.approval_token {
                let _ = self.engine.store.update_approval(t, &json!({"kind": "xbt402", "url": url, "method": method}));
            }
        }
        if !d.allowed() {
            return d.as_value();
        }
        sigaudit::set_rule(&if grant.is_some() { "human:approval_signature".to_string() } else { format!("policy:{}", d.rule) });
        let result = match self.session.pay_once(&url, &method, &raw, max_sats, exp, cap) {
            Ok(r) => r,
            Err(e) => return self.pay_deny(&e),
        };
        if result["verdict"] == "deny" || result["verdict"] == "pending" {
            return result;
        }
        let charged = py_int(result.get("charged_sats")).unwrap_or(0);
        if charged != 0 {
            let chan = str_or_empty(result.get("chan"));
            if let Err(e) = self.engine.commit(&Payment::new(&dest, charged, &pay.memo), &chan) {
                return deny("xbt402", e.msg);
            }
        }
        if let Some(t) = &grant {
            self.use_xbt402_grant(t, charged);
            return with(with(d.as_value(), result), json!({"rail": "xbt402", "approved": true, "approval_token": t}));
        }
        with(with(d.as_value(), result), json!({"rail": "xbt402"}))
    }

    /// `sign_state` (B2) and `xbt402_sign_state` (the external client): a policy-checked state.
    fn sign_state(&self, p: &Value) -> Result<Value> {
        let _g = self.lock();
        let key = ["dest", "to", "chan"].iter().map(|k| str_or_empty(p.get(*k))).find(|v| !v.is_empty()).unwrap_or_default();
        let dest = self.book.find_dest(&key).unwrap_or_else(|| normalize_dest(&key));
        let cum = py_int(p.get("cum")).filter(|v| *v != 0).or_else(|| py_int(p.get("amount"))).unwrap_or(0);
        let used = self.book.get(&dest).map(|r| r.used_sats).unwrap_or(0);
        let pay = Payment::new(&dest, (cum - used).max(0), "");
        let d = self.engine.evaluate(&pay, false)?;
        if !d.allowed() {
            return Ok(d.as_value());
        }
        sigaudit::set_rule(&format!("policy:{}", d.rule));
        let sig = self.book.sign_state(&dest, cum)?;
        let chan = self.book.get(&dest).map(|r| r.chan).unwrap_or_default();
        self.engine.commit(&pay, &chan)?;
        Ok(json!({"verdict": "allow", "chan": chan, "cum": cum, "sig": hex::encode(sig)}))
    }

    /// Policy on an increase of the signed amount (a3, rollover, conditional): `None` = allowed.
    fn policy_on_increase(&self, dest: &str, increase: i64, memo: &str) -> Result<Option<Value>> {
        if increase <= 0 {
            sigaudit::set_rule("policy:no_increase");
            return Ok(None);
        }
        let origin = self.book.get(dest).map(|r| if r.origin.is_empty() { dest.to_string() } else { r.origin }).unwrap_or(dest.into());
        let pay = Payment::new(&origin, increase, memo);
        let d = self.engine.evaluate(&pay, false)?;
        if !d.allowed() {
            return Ok(Some(d.as_value()));
        }
        sigaudit::set_rule(&format!("policy:{}", d.rule));
        self.engine.commit(&pay, &self.book.get(dest).map(|r| r.chan).unwrap_or_default())?;
        Ok(None)
    }

    fn sign_a3(&self, p: &Value) -> Value {
        let chan = str_or_empty(p.get("chan"));
        let dest = self.book.find_dest(&chan).unwrap_or(chan.clone());
        let amount = py_int(p.get("amount")).unwrap_or(0);
        let used = self.book.get(&dest).map(|r| r.used_sats).unwrap_or(0);
        match self.policy_on_increase(&dest, amount - used, "xbt402 0xA3 state") {
            Ok(Some(d)) => return d,
            Err(e) => return deny("xbt402_sign_state_a3", e.msg),
            Ok(None) => {}
        }
        match self.book.sign_state_a3(&dest, amount) {
            Ok(sig) => json!({"sig": hex::encode(sig)}),
            Err(e) => deny("xbt402_sign_state_a3", e.msg),
        }
    }

    fn sign_rollover(&self, p: &Value) -> Value {
        let chan = str_or_empty(p.get("chan"));
        let Some(dest) = self.book.find_dest(&chan) else { return deny("unknown_channel", format!("no channel for {chan}")) };
        let amount = py_int(p.get("amount")).unwrap_or(0);
        let Some(next_spk) = x2b(&str_or_empty(p.get("next_spk"))) else { return deny("bad_request", "next_spk is not hex") };
        let next_cap = py_int(p.get("next_capacity")).unwrap_or(0).max(0) as u64;
        let used = self.book.get(&dest).map(|r| r.used_sats).unwrap_or(0);
        match self.policy_on_increase(&dest, amount - used, "xbt402 rollover") {
            Ok(Some(d)) => return d,
            Err(e) => return deny("xbt402", e.msg),
            Ok(None) => {}
        }
        match self.book.sign_rollover(&dest, amount, &next_spk, next_cap) {
            Ok(sig) => json!({"sig": hex::encode(sig)}),
            Err(e) => deny(&e.code, e.msg),
        }
    }

    fn sign_conditional(&self, p: &Value) -> Value {
        let chan = str_or_empty(p.get("chan"));
        let Some(dest) = self.book.find_dest(&chan) else { return deny("unknown_channel", format!("no channel for {chan}")) };
        let uncond = py_int(p.get("uncond")).unwrap_or(0);
        let amount = py_int(p.get("amount")).unwrap_or(0);
        let csv = py_int(p.get("csv_delta")).unwrap_or(10).max(0) as u32;
        let Some(hash) = x2b(&str_or_empty(p.get("hash"))).and_then(|v| <[u8; 32]>::try_from(v).ok()) else {
            return deny("bad_request", "hash must be 32 bytes of hex");
        };
        let used = self.book.get(&dest).map(|r| r.used_sats).unwrap_or(0);
        match self.policy_on_increase(&dest, uncond + amount - used, "xbt402 conditional state") {
            Ok(Some(d)) => return d,
            Err(e) => return deny("xbt402", e.msg),
            Ok(None) => {}
        }
        match self.book.sign_conditional(&dest, uncond, hash, amount.max(0) as u64, csv, None) {
            Ok((_, sig)) => json!({"sig": hex::encode(sig)}),
            Err(e) => deny(&e.code, e.msg),
        }
    }

    /// The external client's funded channel: bind the key issued for `origin` (B1 `attach`).
    fn attach(&self, p: &Value) -> Value {
        let origin = str_or_empty(p.get("origin"));
        let params = match p.get("params").map(xbt402::channel::ChannelParams::from_json) {
            Some(Ok(pp)) => pp,
            _ => return deny("bad_params", "params must be ChannelParams.to_dict()"),
        };
        if params.funding.is_none() {
            return deny("bad_params", "attach a funded channel");
        }
        let secret = match self.book.take_issued(&origin) {
            Ok(s) => s,
            Err(e) => return deny(&e.code, e.msg),
        };
        if xbt_primitives::ecdsa::pubkey(&secret) != params.payer_pub {
            return deny("bad_key", "attached params do not match the issued key");
        }
        // a rolled-over channel ("<origin>/next") replaces the one it spends, at the same origin
        let base = origin.strip_suffix("/next").unwrap_or(&origin).to_string();
        let dest = normalize_dest(&base);
        let open_height = self.height_safe();
        match self.book.add_funded(&dest, secret, &params, &base, Some(params.max_amount() as i64), open_height) {
            Ok(rec) => json!({"chan": rec.chan, "dest": dest}),
            Err(e) => deny(&e.code, e.msg),
        }
    }

    fn sign_refund(&self, p: &Value) -> Value {
        let chan = str_or_empty(p.get("chan"));
        let Some(dest) = self.book.find_dest(&chan) else { return deny("unknown_channel", format!("no channel for {chan}")) };
        let fee = self.book.get(&dest).map(|r| r.close_fee.max(0) as u64);
        sigaudit::set_rule("client:refund_custody");
        match self.book.refund_tx(&dest, &self.hot.spk(), fee) {
            Ok((tx, expiry)) => json!({"hex": tx.to_hex(), "expiry": expiry, "to": self.hot.address()}),
            Err(e) => deny(&e.code, e.msg),
        }
    }

    /// The external client closed a channel: learn its change, then mark it closed.
    fn mark_closed(&self, p: &Value) -> Value {
        let chan = str_or_empty(p.get("chan"));
        let Some(dest) = self.book.find_dest(&chan) else { return deny("unknown_channel", format!("no channel for {chan}")) };
        let Some(rec) = self.book.get(&dest) else { return deny("unknown_channel", chan) };
        let txid = str_or_empty(p.get("txid"));
        let txid = if txid.len() == 64 && txid.bytes().all(|c| c.is_ascii_hexdigit()) { txid.to_lowercase() } else { String::new() };
        let change = self.session.learn_close_change(&rec, &txid, py_int(p.get("scan_from")).unwrap_or(0), "");
        if let Err(e) = self.book.mark_closed(&dest, &txid, Some(&change), "") {
            return deny(&e.code, e.msg);
        }
        self.anchor_after("close");
        with(self.book.get(&dest).map(|r| r.public()).unwrap_or(json!({})), json!({"verdict": "allow"}))
    }

    /// t + r off the hub's ch1 close: by txid (blockhash on a pruned node), as B2. Extension: the
    /// caller may pass the raw close as `hex` (a payer that already holds it, and a node without the
    /// tx); only its witness is read, and a secret counts only if it opens the stored T1.
    fn recover_lock(&self, p: &Value) -> Value {
        let given = str_or_empty(p.get("hex"));
        let raw = if !given.is_empty() {
            Some(given)
        } else {
            node::get_tx(&*self.node, &str_or_empty(p.get("txid")), &str_or_empty(p.get("blockhash")))
                .and_then(|v| v.get("hex").and_then(Value::as_str).map(str::to_string))
        };
        let Some(raw) = raw else { return deny("unknown_tx", "close transaction not found") };
        let Ok(tx) = Tx::parse_hex(&raw) else { return deny("unknown_tx", "close transaction does not parse") };
        let wit = tx.inputs.first().map(|i| i.witness.clone()).unwrap_or_default();
        match self.routing.recover_lock(&str_or_empty(p.get("chan")), &wit) {
            Ok(t) => json!({"t": t}),
            Err(e) => deny(&e.code, e.msg),
        }
    }

    fn close_channel_locked(&self, p: &Value) -> Value {
        let raw = ["counterparty", "dest", "to"].iter().map(|k| str_or_empty(p.get(*k))).find(|v| !v.is_empty()).unwrap_or_default();
        let found = self.book.find_dest(&raw);
        let dest = found.clone().unwrap_or_else(|| normalize_dest(&raw));
        if dest.is_empty() {
            return deny("dest", "counterparty required");
        }
        if !self.book.has(&dest) && found.is_none() {
            return deny("unknown_channel", format!("no channel for {raw}"));
        }
        let out = match self.session.close_channel(&dest) {
            Ok(v) => v,
            Err(e) => deny("close_channel", e.msg),
        };
        self.save_close_report(&out);
        self.anchor_after("close");
        out
    }

    fn approve_signed(&self, p: &Value) -> Result<Value> {
        let token = str_or_empty(p.get("token"));
        let mut dest = { let d = str_or_empty(p.get("dest")); if d.is_empty() { str_or_empty(p.get("to")) } else { d } }.trim().to_string();
        let low = dest.to_lowercase();
        if low.starts_with("bc1") || low.starts_with("bcrt1") || low.starts_with("tb1") {
            dest = low;
        }
        let amount = match p.get("amount_sats").filter(|v| !v.is_null()) {
            Some(v) => py_int(Some(v)).unwrap_or(0),
            None => sats_from_xbt(p.get("amount_xbt")).map_err(|m| err("bad_request", m))?,
        };
        let expiry = py_int(p.get("expiry")).unwrap_or(0);
        let sig_hex = { let s = str_or_empty(p.get("signature")); if s.is_empty() { str_or_empty(p.get("sig")) } else { s } };
        let Some(signature) = x2b(&sig_hex) else { return Ok(deny("approval_sig", "signature is not valid hex")) };
        let human_pubkey = self.human_key();
        if human_pubkey.is_empty() {
            return Ok(deny("approval_sig", "signer has no human public key configured"));
        }
        let now = self.now();
        if signature.is_empty() || !verify_approval(&human_pubkey, &token, &dest, amount, expiry, &signature) {
            self.engine.audit.append(json!({"type": "decision", "verdict": "deny", "rule": "approval_sig", "reason": "missing or invalid human signature",
                                            "dest": dest, "amount_sats": amount, "ts": ts_value(now)}));
            return Ok(deny("approval_sig", "missing or invalid human signature over (token, dest, amount, expiry)"));
        }
        let Some(payload) = self.engine.store.get_approval(&token)? else {
            self.engine.audit.append(json!({"type": "approval_miss", "token": token, "ts": ts_value(now)}));
            return Ok(deny("approval", "unknown or already-used approval token"));
        };
        if truthy(payload.get("used")) {
            return Ok(deny("approval_replay", "approval token already used"));
        }
        let stored_exp = py_int(payload.get("expires")).unwrap_or(0);
        if (stored_exp as f64) < now || (expiry as f64) < now {
            self.engine.store.pop_approval(&token)?;
            self.note_expired(&token);
            self.engine.audit.append(json!({"type": "approval_expired", "token": token, "ts": ts_value(now)}));
            return Ok(deny("approval_expired", "approval token expired"));
        }
        if dest != str_or_empty(payload.get("dest")) || amount != py_int(payload.get("amount_sats")).unwrap_or(0) || expiry != stored_exp {
            self.engine.audit.append(json!({"type": "decision", "verdict": "deny", "rule": "approval_bind",
                                            "reason": "signature fields do not match pending approval", "dest": dest, "amount_sats": amount, "ts": ts_value(now)}));
            return Ok(deny("approval_bind", "signature fields do not match the pending approval"));
        }
        if matches!(payload.get("kind").and_then(Value::as_str), Some("xbt402") | Some("ln")) {
            return self.grant_xbt402(&token, &payload);
        }
        let Some(pay) = self.engine.consume_approval(&token)? else { return Ok(deny("approval", "unknown or expired approval token")) };
        self.note_used(&token);
        let _g = self.lock();
        let mut settled = self.pay_locked(&json!({"to": pay.dest, "amount_sats": pay.amount_sats, "memo": pay.memo}), true)?;
        if settled["verdict"] == "allow" {
            settled["approved"] = true.into();
        }
        Ok(settled)
    }

    /// Unused in the Rust signer (no vault), kept for the message format.
    pub fn recover_message_for(&self, addr: &str, expiry: i64) -> Vec<u8> {
        recover_message(addr, expiry)
    }
}

/// Regtest only (P3): refused unless the node is still regtest.
pub fn mine_blocks(node: &dyn Node, n: u64) -> Result<()> {
    let info = node.call("getblockchaininfo", json!([]))?;
    if info.get("chain").and_then(Value::as_str).unwrap_or("regtest") != "regtest" {
        return Err(err("chain", "the node is no longer regtest: refusing to mine"));
    }
    let addr = node.call("getnewaddress", json!(["mine", "bech32"]))?;
    node.call("generatetoaddress", json!([n, addr]))?;
    Ok(())
}

impl Signer {
    /// Sleep until the next watcher tick; `true` when stopping.
    pub fn watch_loop(self: &Arc<Self>, stop: Arc<std::sync::atomic::AtomicBool>) {
        use std::sync::atomic::Ordering;
        loop {
            let steps = ((self.watch_interval * 10.0) as u64).max(1);
            for _ in 0..steps {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            for a in self.watch_tick() {
                println!("watcher: {}", crate::pyjson::dumps_sorted_compact(&a));
            }
        }
    }
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer").field("root", &self.root).field("chain", &self.chain).field("mining", &self.mining).finish_non_exhaustive()
    }
}
