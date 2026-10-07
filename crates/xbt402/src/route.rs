//! xbt402 hub routing, the parts the three roles share (a port of B1 `xbt402/route.py`,
//! AGP-021/023; design: AGP-019).
//!
//! A routed payment goes client → hub → provider over two ordinary xbt402 channels, ch1 (client
//! pays hub) and ch2 (hub pays provider), as an adaptor-locked state on each hop
//! ([`crate::adaptor`]):
//!
//! ```text
//! provider: t per window, T = t·G in its signed invoice      client: tweak r, T1 = T + r·G
//! ch1: client pre-signs cum1 + d + f under T1  ->  hub pre-verifies, then pre-signs ch2 cum2 + d under T
//! provider completes ch2 with t (a plain 0x21 state), saves it, returns t
//! hub completes ch1 with t + r, returns t + r; the client's receipt is t = (t + r) − r
//! ```
//!
//! This module holds [`route_ok`] (the expiry rule), [`FeeQuote`] (the hub's signed, expiring fee
//! offer) with [`fee_due`] (the carry), the provider's [`PriceQuote`] and [`Invoice`], the
//! ROUTE-STATE signature, the client ↔ provider authenticators (an ECDH key the hub never sees),
//! [`next_cum`] and the [`SpendScan`] chain hook the hub's watcher reads t with.
//!
//! Units: amsat = 1e-18 msat, so 1 sat = 10^21 amsat; meters are `u128`. Whole sats appear only
//! in lock amounts, as the ceil of the running total minus what is already paid.
//!
//! Every signed body is `json.dumps(body, sort_keys=True, separators=(",", ":"))` as the reference
//! writes it ([`canon`]), and every value keeps the JSON type the reference gives it, so quotes,
//! invoices and ROUTE-STATEs signed by either implementation verify in the other.
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde_json::{json, Map, Number, Value};
use sha2::{Digest, Sha256};
use xbt_primitives::ecdsa;
use xbt_primitives::hash::tagged_hash;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

use crate::channel::DUST;
use crate::error::{fail, ChannelError, Result};
use crate::json::{dumps_compact, int_text, py_str};

pub const AMSAT_PER_SAT: u128 = 1_000_000_000_000_000_000_000;
pub const AMSAT_PER_MSAT: u128 = 1_000_000_000_000_000_000;
/// The fee carry unit: 1e-6 msat (feePpm × msat, exact).
pub const FEE_UNITS_PER_SAT: u128 = 1_000_000_000;
pub use crate::wire::{LOCK_PATH as ROUTE_LOCK_PATH, ROLLOVER_PATH, TERMS_PATH};
pub const HUB_ROUTE_PATH: &str = "/x402/route";
pub const ROUTE_ERRORS: [&str; 11] = ["bad_auth", "bad_point", "bad_amount", "bad_adaptor", "route_fee", "route_expiry",
                                      "lock_outstanding", "bad_secret", "route_failed", "route_blocked", "bad_invoice"];

pub const FEE_QUOTE_TAG: &str = "xbt402/route/fee-quote";
pub const PRICE_QUOTE_TAG: &str = "xbt402/route/price-quote";
pub const INVOICE_TAG: &str = "xbt402/route/invoice";
pub const STATE_TAG: &str = "xbt402/route/state";

/// Seconds since the epoch, as Python's `time.time()`.
pub fn now_f() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// `int(time.time())`.
pub fn now_i() -> i64 {
    now_f() as i64
}

/// Python's `round(x, 3)` as a JSON number (what invoices carry as `validUntil`).
pub fn round3(x: f64) -> Value {
    Number::from_f64((x * 1000.0).round() / 1000.0).map(Value::Number).unwrap_or(Value::Null)
}

pub fn ceil_div(a: u128, b: u128) -> u128 {
    a.div_ceil(b)
}

/// A provider origin as the hub keys it (AGP-044, B1 `route.canon_origin`): scheme and host
/// lowercased, the default port (`:80` for http, `:443` for https) and trailing `/`s dropped.
pub fn canon_origin(origin: &str) -> String {
    let o = origin.trim().trim_end_matches('/');
    let Some(i) = o.find("://") else { return o.to_string() };
    let (scheme, rest) = (o[..i].to_ascii_lowercase(), &o[i + 3..]);
    let (host, path) = rest.find('/').map_or((rest, ""), |k| (&rest[..k], &rest[k..]));
    let mut host = host.to_ascii_lowercase();
    if (scheme == "http" && host.ends_with(":80")) || (scheme == "https" && host.ends_with(":443")) {
        host.truncate(host.rfind(':').unwrap_or(host.len()));
    }
    format!("{scheme}://{host}{path}")
}

/// May the hub forward a lock from the channel expiring at `in_expiry` into the one expiring at
/// `out_expiry`? The provider can complete and close ch2 until ch2's close margin, and its close
/// can confirm as late as `out_expiry`; the hub then needs `delta` blocks to learn t and get ch1's
/// close confirmed before ch1's margin.
pub fn route_ok(tip: u32, in_expiry: u32, out_expiry: u32, close_margin: u32, delta: u32) -> bool {
    let (tip, i, o, m, d) = (tip as i64, in_expiry as i64, out_expiry as i64, close_margin as i64, delta as i64);
    tip < o - m && o + d <= i - m
}

/// A routed channel's next cumulative state: the routed total plus this lock, floored at the
/// channel's least state (`ChannelParams::min_amount`: dust, plus the close fee under payee-pays).
pub fn next_cum(routed: u64, amount: u64, floor: u64) -> u64 {
    routed.saturating_add(amount).max(floor)
}

pub fn next_cum_dust(routed: u64, amount: u64) -> u64 {
    next_cum(routed, amount, DUST)
}

fn sorted(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for k in keys {
                out.insert(k.clone(), sorted(&m[k]));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
        x => x.clone(),
    }
}

/// `json.dumps(v, sort_keys=True, separators=(",", ":"))`.
pub fn canon(v: &Value) -> String {
    dumps_compact(&sorted(v))
}

/// DER hex of payTo's signature over `tagged_hash(tag, canon(body))`.
pub fn sign_body(secret: &SecretKey, tag: &str, body: &Value) -> String {
    hex::encode(ecdsa::sign(secret, &tagged_hash(tag, canon(body).as_bytes())))
}

pub fn verify_body(pub_hex: &str, tag: &str, body: &Value, sig_hex: &str) -> bool {
    let (Ok(p), Ok(s)) = (hex::decode(pub_hex), hex::decode(sig_hex)) else { return false };
    ecdsa::verify(&p, &tagged_hash(tag, canon(body).as_bytes()), &s)
}

fn get_i(d: &Map<String, Value>, k: &str, code: &str) -> Result<i128> {
    match d.get(k) {
        Some(v @ (Value::Number(_) | Value::Object(_))) => int_text(v).and_then(|t| t.parse::<i128>().ok())
            .ok_or_else(|| ChannelError::new(code, format!("{k} is not an integer"))),
        _ => fail(code, format!("'{k}'")),
    }
}

fn get_s(d: &Map<String, Value>, k: &str, code: &str) -> Result<String> {
    d.get(k).and_then(Value::as_str).map(str::to_string).ok_or_else(|| ChannelError::new(code, format!("'{k}'")))
}

fn obj<'a>(d: &'a Value, code: &str, what: &str) -> Result<&'a Map<String, Value>> {
    d.as_object().ok_or_else(|| ChannelError::new(code, format!("{what} must be an object")))
}

/// A JSON integer of any size (amsat).
pub fn int_value(n: u128) -> Value {
    crate::json::big_uint(n)
}

/// A JSON integer or decimal string as u128 (`int(x)` on the reference's amsat fields).
pub fn u128_of(v: Option<&Value>) -> Option<u128> {
    match v? {
        Value::String(s) => {
            let t = s.trim();
            (!t.is_empty() && t.len() <= 39 && t.bytes().all(|c| c.is_ascii_digit())).then(|| t.parse().ok()).flatten()
        }
        v => int_text(v)?.parse().ok(),
    }
}

// --- hub fee quotes ------------------------------------------------------------------------------

/// A hub's signed, expiring routing-fee offer. Fee for a lock of d sat: `feeBaseMsat + d × 1000 ×
/// feePpm / 1e6` msat, accrued exactly (1e-6 msat units) per ch1 and charged as the ceil of the
/// running total: never rounded per lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeQuote {
    /// The hub's payTo (33-byte compressed hex): who signs.
    pub hub: String,
    pub network: String,
    pub fee_base_msat: u64,
    pub fee_ppm: u64,
    pub max_lock_sat: u64,
    pub max_unguarded_lock_sat: u64,
    /// The delta in [`route_ok`].
    pub min_in_expiry_delta: u64,
    pub reveal_timeout_sec: u64,
    pub seq: i64,
    pub issued_at: i64,
    pub valid_until: i64,
    pub sig: String,
}

impl FeeQuote {
    /// The signed fields, in the reference's field order.
    pub fn body(&self) -> Value {
        json!({"hub": self.hub, "network": self.network, "feeBaseMsat": self.fee_base_msat, "feePpm": self.fee_ppm,
               "maxLockSat": self.max_lock_sat, "maxUnguardedLockSat": self.max_unguarded_lock_sat,
               "minInExpiryDelta": self.min_in_expiry_delta, "revealTimeoutSec": self.reveal_timeout_sec,
               "seq": self.seq, "issuedAt": self.issued_at, "validUntil": self.valid_until})
    }

    /// `asdict(quote)`: the body plus `sig`.
    pub fn to_json(&self) -> Value {
        let mut v = self.body();
        v["sig"] = self.sig.clone().into();
        v
    }

    pub fn sign(mut self, secret: &SecretKey) -> Self {
        self.sig = sign_body(secret, FEE_QUOTE_TAG, &self.body());
        self
    }

    pub fn verify(&self) -> bool {
        verify_body(&self.hub, FEE_QUOTE_TAG, &self.body(), &self.sig)
    }

    pub fn live(&self, now: f64) -> bool {
        self.issued_at as f64 <= now + 5.0 && now <= self.valid_until as f64
    }

    /// This lock's fee in 1e-6 msat (exact).
    pub fn units(&self, d_sat: u64) -> u128 {
        self.fee_base_msat as u128 * 1_000_000 + d_sat as u128 * 1000 * self.fee_ppm as u128
    }

    /// Parse; any missing or ill-typed field is `route_fee`.
    pub fn from_json(d: &Value) -> Result<Self> {
        let c = "route_fee";
        let d = obj(d, c, "fee quote")?;
        let u = |k: &str| -> Result<u64> { u64::try_from(get_i(d, k, c)?).map_err(|_| ChannelError::new(c, format!("{k} out of range"))) };
        let i = |k: &str| -> Result<i64> { i64::try_from(get_i(d, k, c)?).map_err(|_| ChannelError::new(c, format!("{k} out of range"))) };
        Ok(Self {
            hub: get_s(d, "hub", c)?,
            network: get_s(d, "network", c)?,
            fee_base_msat: u("feeBaseMsat")?,
            fee_ppm: u("feePpm")?,
            max_lock_sat: u("maxLockSat")?,
            max_unguarded_lock_sat: u("maxUnguardedLockSat")?,
            min_in_expiry_delta: u("minInExpiryDelta")?,
            reveal_timeout_sec: u("revealTimeoutSec")?,
            seq: i("seq")?,
            issued_at: i("issuedAt")?,
            valid_until: i("validUntil")?,
            sig: d.get("sig").map(|v| py_str(Some(v))).unwrap_or_default(),
        })
    }
}

/// (fee in sat for this lock, new running total in units): the carry at the hub hop.
pub fn fee_due(q: &FeeQuote, d_sat: u64, units_total: u128, paid_sat: u64) -> (u64, u128) {
    let total = units_total + q.units(d_sat);
    let due = ceil_div(total, FEE_UNITS_PER_SAT).saturating_sub(paid_sat as u128);
    (u64::try_from(due).unwrap_or(u64::MAX), total)
}

// --- provider price quotes and invoices ----------------------------------------------------------

/// The provider's signed price for a routed path, verifiable end to end: every charge in a
/// ROUTE-STATE names the quote it was billed under, so a hub in the middle cannot reprice it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceQuote {
    pub pay_to: String,
    pub network: String,
    pub path: String,
    /// A flat price per call; a metered path reports `chargeAmsat` per call.
    pub amsat_per_call: u128,
    pub unit: String,
    pub seq: i64,
    pub issued_at: i64,
    pub valid_until: i64,
    pub sig: String,
}

impl PriceQuote {
    pub fn body(&self) -> Value {
        json!({"payTo": self.pay_to, "network": self.network, "path": self.path, "amsatPerCall": int_value(self.amsat_per_call),
               "unit": self.unit, "seq": self.seq, "issuedAt": self.issued_at, "validUntil": self.valid_until})
    }

    pub fn to_json(&self) -> Value {
        let mut v = self.body();
        v["sig"] = self.sig.clone().into();
        v
    }

    /// `sha256(canon(body))` hex: how a ROUTE-STATE names its quote.
    pub fn quote_id(&self) -> String {
        hex::encode(Sha256::digest(canon(&self.body()).as_bytes()))
    }

    pub fn sign(mut self, secret: &SecretKey) -> Self {
        self.sig = sign_body(secret, PRICE_QUOTE_TAG, &self.body());
        self
    }

    pub fn verify(&self) -> bool {
        verify_body(&self.pay_to, PRICE_QUOTE_TAG, &self.body(), &self.sig)
    }

    pub fn from_json(d: &Value) -> Result<Self> {
        let c = "bad_offer";
        let d = obj(d, c, "price quote")?;
        let i = |k: &str| -> Result<i64> { i64::try_from(get_i(d, k, c)?).map_err(|_| ChannelError::new(c, format!("{k} out of range"))) };
        Ok(Self {
            pay_to: get_s(d, "payTo", c)?,
            network: get_s(d, "network", c)?,
            path: get_s(d, "path", c)?,
            amsat_per_call: u128::try_from(get_i(d, "amsatPerCall", c)?).map_err(|_| ChannelError::new(c, "amsatPerCall"))?,
            unit: get_s(d, "unit", c)?,
            seq: i("seq")?,
            issued_at: i("issuedAt")?,
            valid_until: i("validUntil")?,
            sig: d.get("sig").map(|v| py_str(Some(v))).unwrap_or_default(),
        })
    }
}

/// One window's lock point T = t·G, fresh per window, signed by the provider's payTo.
#[derive(Debug, Clone, PartialEq)]
pub struct Invoice {
    pub pay_to: String,
    pub network: String,
    pub session: String,
    pub lock_id: String,
    /// T, compressed hex.
    pub point: String,
    /// A JSON number (the reference writes `round(time, 3)`, a float): kept as received so the
    /// signature verifies byte for byte.
    pub valid_until: Value,
    /// `["<hub payTo>", ...]` or `"any"`.
    pub hubs: Value,
    pub sig: String,
}

impl Invoice {
    pub fn body(&self) -> Value {
        json!({"payTo": self.pay_to, "network": self.network, "session": self.session, "lockId": self.lock_id,
               "point": self.point, "validUntil": self.valid_until, "hubs": self.hubs})
    }

    pub fn to_json(&self) -> Value {
        let mut v = self.body();
        v["sig"] = self.sig.clone().into();
        v
    }

    pub fn sign(mut self, secret: &SecretKey) -> Self {
        self.sig = sign_body(secret, INVOICE_TAG, &self.body());
        self
    }

    pub fn verify(&self) -> bool {
        verify_body(&self.pay_to, INVOICE_TAG, &self.body(), &self.sig)
    }

    pub fn valid_until_f(&self) -> f64 {
        self.valid_until.as_f64().unwrap_or(0.0)
    }

    /// Does this invoice take locks from `hub` (a payTo hex)?
    pub fn accepts_hub(&self, hub: &str) -> bool {
        hubs_accept(&self.hubs, hub)
    }

    pub fn from_json(d: &Value) -> Result<Self> {
        let c = "bad_invoice";
        let d = obj(d, c, "invoice")?;
        let vu = d.get("validUntil").filter(|v| v.is_number()).cloned().ok_or_else(|| ChannelError::new(c, "'validUntil'"))?;
        let hubs = d.get("hubs").cloned().ok_or_else(|| ChannelError::new(c, "'hubs'"))?;
        Ok(Self {
            pay_to: get_s(d, "payTo", c)?,
            network: get_s(d, "network", c)?,
            session: get_s(d, "session", c)?,
            lock_id: get_s(d, "lockId", c)?,
            point: get_s(d, "point", c)?,
            valid_until: vu,
            hubs,
            sig: d.get("sig").map(|v| py_str(Some(v))).unwrap_or_default(),
        })
    }
}

/// `hubs == "any" or hub in hubs`.
pub fn hubs_accept(hubs: &Value, hub: &str) -> bool {
    match hubs {
        Value::String(s) => s == "any",
        Value::Array(a) => a.iter().any(|h| h.as_str() == Some(hub)),
        _ => false,
    }
}

/// A ROUTE-STATE (or lock answer) with payTo's signature appended as `sig`.
pub fn state_sign(secret: &SecretKey, st: &Value) -> Value {
    let mut out = st.clone();
    out["sig"] = sign_body(secret, STATE_TAG, st).into();
    out
}

pub fn state_verify(pay_to: &str, st: &Value) -> bool {
    let Some(m) = st.as_object() else { return false };
    let mut body = m.clone();
    let sig = body.remove("sig").map(|v| py_str(Some(&v))).unwrap_or_default();
    verify_body(pay_to, STATE_TAG, &Value::Object(body), &sig)
}

// --- client <-> provider authenticators ------------------------------------------------------------

/// ECDH(client route key, provider payTo): both ends compute it, the hub cannot.
pub fn session_key(secret: &SecretKey, other_pub: &[u8]) -> Result<[u8; 32]> {
    let pk = ecdsa::public_key(other_pub).map_err(|_| ChannelError::new("bad_key", "not a point"))?;
    Ok(tagged_hash("xbt402/route/session-key", &ecdsa::ecdh_x(secret, &pk)))
}

fn hmac_hex(key: &[u8; 32], msg: &str) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(msg.as_bytes());
    hex::encode(m.finalize().into_bytes())
}

/// ROUTE-AUTH's MAC over one routed call.
pub fn call_auth(key: &[u8; 32], session: &str, seq: u64, req: &str) -> String {
    hmac_hex(key, &["xbt402/route/call", session, &seq.to_string(), req].join("|"))
}

/// The client authorises exactly this amount for this invoice via this hub. The provider refuses
/// a ch2 lock whose amount or point differs, so the hub can relay but not reprice or redirect.
pub fn lock_auth(key: &[u8; 32], session: &str, lock_id: &str, amount: i128, point: &str, hub: &str) -> String {
    hmac_hex(key, &["xbt402/route/lock", session, lock_id, &amount.to_string(), &point.to_lowercase(), &hub.to_lowercase()].join("|"))
}

// --- the chain hook for the hub's watcher ---------------------------------------------------------

/// Find the transaction spending an outpoint without a txindex (the hub's node may be pruned):
/// the mempool first, then blocks from `from_height` up.
pub trait SpendScan: Send + Sync {
    fn find_spend(&self, txid: &str, vout: u32, from_height: u32) -> Result<Option<Tx>>;

    /// Confirmed unspent outputs paying `spk` as (display txid, vout, sats) (`scantxoutset`, no
    /// wallet or txindex needed): how the hub finds a funding its wallet call lost (AGP-037).
    fn scan_spk(&self, _spk: &[u8]) -> Result<Vec<(String, u32, u64)>> {
        Ok(vec![])
    }

    /// `estimatesmartfee target` in sat/vB; None without an estimate (the refund fee's floor applies).
    fn fee_rate(&self, _target: u32) -> Result<Option<f64>> {
        Ok(None)
    }

    /// `getmempoolentry txid`: is the tx in this node's mempool (AGP-045)? Default: unknown (false).
    fn in_mempool(&self, _txid: &str) -> Result<bool> {
        Ok(false)
    }
}

#[cfg(feature = "rpc")]
impl SpendScan for crate::rpc::Rpc {
    fn find_spend(&self, txid: &str, vout: u32, from_height: u32) -> Result<Option<Tx>> {
        use crate::funding::ChainBackend;
        if let Ok(r) = self.call("gettxspendingprevout", json!([[{"txid": txid, "vout": vout}]])) {
            if let Some(sp) = r.get(0).and_then(|e| e.get("spendingtxid")).and_then(Value::as_str) {
                let raw = self.call("getrawtransaction", json!([sp, false]))?;
                return Ok(Some(Tx::parse_hex(raw.as_str().unwrap_or(""))?));
            }
        }
        let tip = self.block_count()?;
        for h in from_height..=tip {
            let hash = self.call("getblockhash", json!([h]))?;
            let blk = self.call("getblock", json!([hash, 2]))?;
            for tx in blk.get("tx").and_then(Value::as_array).into_iter().flatten() {
                let spends = tx.get("vin").and_then(Value::as_array).into_iter().flatten()
                    .any(|i| i.get("txid").and_then(Value::as_str) == Some(txid) && i.get("vout").and_then(Value::as_u64) == Some(vout as u64));
                if spends {
                    return Ok(Some(Tx::parse_hex(tx.get("hex").and_then(Value::as_str).unwrap_or(""))?));
                }
            }
        }
        Ok(None)
    }

    fn scan_spk(&self, spk: &[u8]) -> Result<Vec<(String, u32, u64)>> {
        let r = self.call("scantxoutset", json!(["start", [format!("raw({})", hex::encode(spk))]]))?;
        Ok(r.get("unspents").and_then(Value::as_array).into_iter().flatten().filter_map(|u| {
            let sats = xbt_primitives::amount::Amount::from_btc_f64(u.get("amount")?.as_f64()?).ok()?.to_sat();
            Some((u.get("txid")?.as_str()?.to_string(), u32::try_from(u.get("vout")?.as_u64()?).ok()?, sats))
        }).collect())
    }

    fn fee_rate(&self, target: u32) -> Result<Option<f64>> {
        let r = self.call("estimatesmartfee", json!([target]))?;
        Ok(r.get("feerate").and_then(Value::as_f64).filter(|f| *f > 0.0).map(|f| f * 1e8 / 1000.0))
    }

    fn in_mempool(&self, txid: &str) -> Result<bool> {
        Ok(self.call("getmempoolentry", json!([txid])).is_ok_and(|v| !v.is_null()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xbt_primitives::hash::sha256;

    #[test]
    fn canon_sorts_every_level() {
        let v = json!({"b": 1, "a": {"d": [{"z": 1, "y": 2}], "c": "x"}});
        assert_eq!(canon(&v), r#"{"a":{"c":"x","d":[{"y":2,"z":1}]},"b":1}"#);
    }

    #[test]
    fn quotes_sign_verify_and_carry() {
        let sk = SecretKey::from_slice(&sha256(b"hub")).unwrap();
        let q = FeeQuote { hub: hex::encode(ecdsa::pubkey(&sk)), network: "bip122:x".into(), fee_base_msat: 100, fee_ppm: 2000,
                           max_lock_sat: 20_000, max_unguarded_lock_sat: 500, min_in_expiry_delta: 144, reveal_timeout_sec: 2,
                           seq: 7, issued_at: 1_000, valid_until: 2_000, sig: String::new() }.sign(&sk);
        assert!(q.verify());
        let back = FeeQuote::from_json(&q.to_json()).unwrap();
        assert_eq!(back, q);
        let mut bad = q.clone();
        bad.fee_ppm = 1;
        assert!(!bad.verify());
        // 1,000 locks of 3 sat at 100 msat + 2,000 ppm cost exactly 106 sat (AGP-021 FeeCarryUnit)
        let (mut units, mut paid) = (0u128, 0u64);
        for _ in 0..1000 {
            let (f, u) = fee_due(&q, 3, units, paid);
            units = u;
            paid += f;
        }
        assert_eq!(paid, 106);
        assert!(route_ok(100, 9000, 5000, 144, 144) && !route_ok(100, 5000, 5000, 144, 144));
        assert_eq!(next_cum(10, 5, 1146), 1146);
        assert_eq!(next_cum(2000, 5, 1146), 2005);
    }

    #[test]
    fn big_amsat_round_trip() {
        let sk = SecretKey::from_slice(&sha256(b"p")).unwrap();
        let pq = PriceQuote { pay_to: hex::encode(ecdsa::pubkey(&sk)), network: "n".into(), path: "/v1".into(),
                              amsat_per_call: 813 * 10u128.pow(18) + 123_456_789, unit: "call".into(), seq: 1, issued_at: 1, valid_until: 2,
                              sig: String::new() }.sign(&sk);
        let wire: Value = crate::json::parse(&crate::json::dumps(&pq.to_json())).unwrap();
        let back = PriceQuote::from_json(&wire).unwrap();
        assert!(back.verify());
        assert_eq!(back.amsat_per_call, 813_000_000_000_123_456_789);
        assert!(crate::json::dumps(&pq.to_json()).contains("\"amsatPerCall\": 813000000000123456789"));
    }
}
