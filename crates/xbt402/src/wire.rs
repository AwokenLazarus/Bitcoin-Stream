//! The x402 v2 `batch-settlement` wire (XBT channel binding; `xbt-channel` accepted as an alias): PAYMENT-REQUIRED / PAYMENT-SIGNATURE / PAYMENT-RESPONSE,
//! request authentication, receipts, and the `/x402/verify|settle|supported` facilitator bodies.
//!
//! ```text
//! 402 + PAYMENT-REQUIRED: base64(PaymentRequired)      (the same JSON in the body)
//! PaymentRequired = {x402Version: 2, error?, resource: {url}, accepts: [PaymentRequirements]}
//! pay:    PAYMENT-SIGNATURE: base64({x402Version: 2, accepted, payload: {chan, seq, cum, sig?, auth}})
//!         auth = HMAC-SHA256(K, "xbt402/auth|chan|seq|cum|sig|sha256(method|path|body)")
//! result: PAYMENT-RESPONSE: base64(SettlementResponse {success, transaction: "", network, payer,
//!         amount: "", extra: {chargedAmount, receipt}})
//! ```
//!
//! Values that are signed or MACed are formatted exactly as the Python reference does, and every
//! header is built with [`crate::json`], so they are byte-identical to it. The typed structs
//! below are for applications; the protocol code works on `serde_json::Value` so a message's
//! unknown fields and key order survive a round trip.
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use xbt_primitives::hash::tagged_hash;

use crate::error::{fail, ChannelError, Result};
use crate::json::{dumps_compact, py_str};

/// x402 scheme id: the XBT network binding of upstream `batch-settlement`.
pub const SCHEME: &str = "batch-settlement";
/// One-release input alias. Servers and clients accept this on the wire; they emit [`SCHEME`].
pub const SCHEME_ALIAS: &str = "xbt-channel";
/// Reserved x402 extra key: this binding's transfer method.
pub const ASSET_TRANSFER_METHOD: &str = "channel";
pub const X402_VERSION: u64 = 2;

/// True for the canonical scheme or the one-release `xbt-channel` alias.
pub fn scheme_accepted(s: Option<&str>) -> bool {
    matches!(s, Some(SCHEME) | Some(SCHEME_ALIAS))
}
/// Default request-body bound.
pub const MAX_BODY: usize = 1 << 20;
pub const FACILITATOR_VERIFY: &str = "/x402/verify";
pub const FACILITATOR_SETTLE: &str = "/x402/settle";
pub const FACILITATOR_SUPPORTED: &str = "/x402/supported";
pub const OPEN_PATH: &str = "/x402/xbt-channel/open";
pub const CLOSE_PATH: &str = "/x402/xbt-channel/close";
pub const ROLLOVER_PATH: &str = "/x402/xbt-channel/rollover";
pub const TERMS_PATH: &str = "/x402/xbt-channel/terms";
pub const LOCK_PATH: &str = "/x402/xbt-channel/lock";
pub use xbt_primitives::network::{network_id, XBT_MAINNET};

/// `base64(json.dumps(obj, separators=(",", ":")))`.
pub fn b64json(v: &Value) -> String {
    B64.encode(dumps_compact(v))
}

/// Inverse of [`b64json`].
pub fn unb64json(s: &str) -> Result<Value> {
    let raw = B64.decode(s.trim()).map_err(|_| ChannelError::new("bad_payload", "not base64"))?;
    crate::json::parse_slice(&raw).map_err(|_| ChannelError::new("bad_payload", "not JSON"))
}

/// `sha256(method | path | body)` hex: which request a payment or receipt is for.
pub fn request_digest(method: &str, path: &str, body: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(method.as_bytes());
    h.update(b"|");
    h.update(path.as_bytes());
    h.update(b"|");
    h.update(body);
    hex::encode(h.finalize())
}

/// The message `payload.auth` MACs.
pub fn auth_message(chan: &str, seq: &str, cum: &str, sig: &str, req: &str) -> String {
    ["xbt402/auth", chan, seq, cum, sig, req].join("|")
}

/// `payload.auth`: binds one paid request to the channel, a fresh seq and the state it carries.
/// `seq` and `cum` are formatted as Python's `str()` does (so a JSON number and its decimal
/// string MAC the same); `sig` None is the empty string.
pub fn request_auth(key: &[u8; 32], chan: &str, seq: Option<&Value>, cum: Option<&Value>, sig: Option<&str>, req: &str) -> String {
    let msg = auth_message(chan, &py_str(seq), &py_str(cum), sig.unwrap_or(""), req);
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(msg.as_bytes());
    hex::encode(m.finalize().into_bytes())
}

/// Constant-time comparison of two MACs.
pub fn auth_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `tagged_hash("xbt402/receipt", "chan|seq|cum|charged|spentMsat|req")`.
pub fn receipt_message(r: &Value) -> [u8; 32] {
    let parts: Vec<String> = ["chan", "seq", "cum", "charged", "spentMsat", "req"].iter().map(|k| py_str(r.get(*k))).collect();
    tagged_hash("xbt402/receipt", parts.join("|").as_bytes())
}

/// What the payer signs to close: `tagged_hash("xbt402/close", chan)`.
pub fn close_message(chan: &str) -> [u8; 32] {
    tagged_hash("xbt402/close", chan.as_bytes())
}

/// What a hub's payTo signs to bind a hub-funded channel to itself at open (AGP-021).
pub fn hub_channel_message(chan: &str) -> [u8; 32] {
    tagged_hash("xbt402/route/hub-channel", chan.as_bytes())
}

/// x402 facilitator reasons for the protocol's own codes.
pub fn upstream_code(code: &str) -> String {
    match code {
        "unsupported_scheme_or_network" => "invalid_batch_settlement_xbt_scheme_or_network".into(),
        "bad_payload" => "invalid_batch_settlement_xbt_payload".into(),
        "bad_auth" => "invalid_batch_settlement_xbt_auth".into(),
        "channel_closing" => "invalid_batch_settlement_xbt_closing".into(),
        "bad_sig" => "invalid_batch_settlement_xbt_signature".into(),
        "wrong_network" => "invalid_network".into(),
        "close_failed" => "unexpected_settle_error".into(),
        "" => "invalid_batch_settlement_xbt_payload".into(),
        other => format!("invalid_batch_settlement_xbt_{other}"),
    }
}

/// A short snake_case identifier: the only provider-chosen string an error code may be.
pub fn safe_code(code: &str) -> bool {
    !code.is_empty() && code.len() <= 40 && code.bytes().all(|c| c == b'_' || c.is_ascii_lowercase())
        && code.bytes().any(|c| c.is_ascii_lowercase())
}

/// PAYMENT-RESPONSE as an x402 v2 SettlementResponse around a signed receipt.
pub fn settlement_response(receipt: &Value, network: &str, payer: &str, success: bool) -> Value {
    let mut extra = Map::new();
    extra.insert("chargedAmount".into(), receipt.get("charged").cloned().unwrap_or(Value::Null));
    extra.insert("receipt".into(), receipt.clone());
    let mut m = Map::new();
    m.insert("success".into(), success.into());
    m.insert("transaction".into(), "".into());
    m.insert("network".into(), network.into());
    m.insert("payer".into(), payer.into());
    m.insert("amount".into(), "".into());
    m.insert("extra".into(), Value::Object(extra));
    Value::Object(m)
}

/// The signed channel receipt inside a PAYMENT-RESPONSE SettlementResponse.
pub fn receipt_of(resp: &Value) -> Result<&Value> {
    let r = resp.get("extra").and_then(|e| e.get("receipt")).filter(|r| r.is_object());
    let r = match r {
        Some(r) if scheme_accepted(r.get("scheme").and_then(Value::as_str)) => r,
        _ => return fail("bad_receipt", "PAYMENT-RESPONSE carries no batch-settlement receipt in extra.receipt"),
    };
    if py_str(resp["extra"].get("chargedAmount")) != py_str(r.get("charged")) {
        return fail("bad_receipt", "extra.chargedAmount differs from the signed receipt");
    }
    Ok(r)
}

/// Body of POST /x402/verify and /x402/settle.
pub fn facilitator_request(accepted: &Value, payload: &Value) -> Value {
    let mut pp = Map::new();
    pp.insert("x402Version".into(), X402_VERSION.into());
    pp.insert("accepted".into(), accepted.clone());
    pp.insert("payload".into(), payload.clone());
    let mut m = Map::new();
    m.insert("x402Version".into(), X402_VERSION.into());
    m.insert("paymentPayload".into(), Value::Object(pp));
    m.insert("paymentRequirements".into(), accepted.clone());
    Value::Object(m)
}

/// `{x402Version: 2, accepted, payload}`: what PAYMENT-SIGNATURE carries (base64).
pub fn payment_payload(accepted: &Value, payload: &Value) -> Value {
    let mut m = Map::new();
    m.insert("x402Version".into(), X402_VERSION.into());
    m.insert("accepted".into(), accepted.clone());
    m.insert("payload".into(), payload.clone());
    Value::Object(m)
}

// --- typed views for applications ---------------------------------------------------------------

/// `PaymentRequirements.extra` for the XBT `batch-settlement` channel binding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelExtra {
    pub min_capacity: String,
    pub max_capacity: String,
    pub min_expiry_blocks: u32,
    pub max_expiry_blocks: u32,
    pub close_margin_blocks: u32,
    pub min_conf: u32,
    pub close_fee_sat: String,
    pub open_url: String,
    pub close_url: String,
    pub billing: String,
    pub derivation: String,
    /// v1.2: absent means "payer".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_fee_payer: Option<String>,
    /// Anything else (conditional offers, route terms, /terms fields), kept in order.
    #[serde(flatten)]
    pub other: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    pub amount: String,
    pub asset: String,
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    pub extra: ChannelExtra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequired {
    pub x402_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub resource: Resource,
    pub accepts: Vec<PaymentRequirements>,
    /// The provider's view of an existing channel (on refusals).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<Value>,
}

/// `payload` of PAYMENT-SIGNATURE.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchemePayload {
    pub chan: String,
    pub seq: u64,
    pub cum: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashlock: Option<String>,
    pub auth: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub scheme: String,
    pub chan: String,
    pub seq: u64,
    pub cum: String,
    pub charged: String,
    pub spent_msat: String,
    pub owed_msat: String,
    pub credit_msat: String,
    pub expiry: u32,
    pub req: String,
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlementResponse {
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    pub transaction: String,
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub is_valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalid_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedKind {
    pub x402_version: u64,
    pub scheme: String,
    pub network: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SupportedResponse {
    pub kinds: Vec<SupportedKind>,
    pub extensions: Vec<Value>,
    pub signers: Map<String, Value>,
}

/// `channel` of an open request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenChannel {
    pub txid: String,
    pub vout: u32,
    pub capacity: u64,
    pub expiry: u32,
    pub payer_pub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer_spk: Option<String>,
    pub redeem_script: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_fee_payer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenResponse {
    pub chan: String,
    pub expiry: u32,
    pub max_cum: String,
    pub confirmations: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_fee_payer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_cum: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseResponse {
    pub chan: String,
    pub txid: String,
    pub cum: String,
    pub unpaid_msat: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn codes_and_digests() {
        assert_eq!(upstream_code("bad_sig"), "invalid_batch_settlement_xbt_signature");
        assert_eq!(upstream_code("stale_amount"), "invalid_batch_settlement_xbt_stale_amount");
        assert!(scheme_accepted(Some(SCHEME)) && scheme_accepted(Some(SCHEME_ALIAS)));
        assert!(!scheme_accepted(Some("exact")));
        assert!(safe_code("bad_sig") && !safe_code("Bad") && !safe_code("a b") && !safe_code("__"));
        assert_eq!(request_digest("", "", b""), hex::encode(Sha256::digest(b"||")));
        let v = json!({"a": 1});
        assert_eq!(unb64json(&b64json(&v)).unwrap(), v);
        let r = json!({"chan": "c", "seq": 3, "cum": "5", "charged": "1", "spentMsat": "2", "req": "r"});
        assert_eq!(receipt_message(&r), tagged_hash("xbt402/receipt", b"c|3|5|1|2|r"));
    }
}
