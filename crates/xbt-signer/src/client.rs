//! The signer socket's client, and [`RemoteSigner`]: an xbt402 [`StateSigner`], [`RouteSigner`] and
//! [`Wallet`] whose keys live in the signer process, so a Rust payer (`xbt402::client::Client::with_signer`,
//! `xbt402::route_client::RoutePayer`) never holds a payer secret. Every state it asks for goes
//! through the signer's policy engine, and every adaptor lock through its routing policy first.
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};
use xbt402::channel::ChannelParams;
use xbt402::client::Wallet;
use xbt402::conditional::ConditionalParams;
use xbt402::adaptor::PreSig;
use xbt402::signer::{AdaptorLock, RouteSigner, StateSigner};
use xbt_primitives::ecdsa::PubkeyBytes;
use xbt_primitives::tx::Tx;

use crate::ipc::Stream;
use crate::pyjson::dumps;
use crate::{err, Result};

/// One request per connection, like B2's `SignerClient`.
#[derive(Debug, Clone)]
pub struct SignerClient {
    pub sock_path: PathBuf,
    pub timeout: Duration,
}

impl SignerClient {
    pub fn new(sock: &Path) -> Self {
        let t = std::env::var("B2_SIGNER_TIMEOUT").ok().and_then(|v| v.parse::<f64>().ok()).unwrap_or(60.0);
        Self { sock_path: sock.into(), timeout: Duration::from_secs_f64(t) }
    }

    /// The raw result, or `signer_error` with the signer's message.
    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let io = |e: std::io::Error| err("signer_unreachable", format!("{}: {e}", self.sock_path.display()));
        let mut s = Stream::connect(&self.sock_path).map_err(io)?;
        s.set_timeouts(Some(self.timeout));
        s.write_all(format!("{}\n", dumps(&json!({"id": 1, "method": method, "params": params}))).as_bytes()).map_err(io)?;
        let mut line = String::new();
        BufReader::new(s).read_line(&mut line).map_err(io)?;
        let resp: Value = serde_json::from_str(line.trim()).map_err(|e| err("signer_error", e.to_string()))?;
        if let Some(e) = resp.get("error").filter(|e| !e.is_null()) {
            return Err(err("signer_error", e.get("message").and_then(Value::as_str).unwrap_or("error").to_string()));
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }
}

/// A deny from the signer becomes an error with the deny's rule as the code.
fn checked(v: Value) -> Result<Value> {
    if matches!(v.get("verdict").and_then(Value::as_str), Some("deny") | Some("needs_human")) {
        return Err(err(v.get("rule").and_then(Value::as_str).unwrap_or("deny"), v.get("reason").and_then(Value::as_str).unwrap_or("").to_string()));
    }
    Ok(v)
}

fn hex_field(v: &Value, k: &str) -> Result<Vec<u8>> {
    v.get(k).and_then(Value::as_str).and_then(|x| hex::decode(x).ok()).ok_or_else(|| err("signer_error", format!("no {k} in the signer's answer")))
}

fn hex_n<const N: usize>(v: &Value, k: &str) -> Result<[u8; N]> {
    hex_field(v, k)?.try_into().map_err(|_| err("signer_error", format!("{k} in the signer's answer is not {N} bytes")))
}

/// xbt402's signer seam over the B2 socket.
#[derive(Debug, Clone)]
pub struct RemoteSigner {
    pub client: SignerClient,
}

impl RemoteSigner {
    pub fn new(sock: &Path) -> Self {
        Self { client: SignerClient::new(sock) }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value> {
        checked(self.client.call(method, params)?)
    }

    /// Tell the signer a channel was closed cooperatively (it learns the change, marks it closed).
    pub fn mark_closed(&self, chan: &str, txid: &str) -> Result<Value> {
        self.call("xbt402_mark_closed", json!({"chan": chan, "txid": txid}))
    }
}

impl StateSigner for RemoteSigner {
    fn new_key(&self, origin: &str) -> xbt402::Result<PubkeyBytes> {
        let v = self.call("xbt402_new_key", json!({"origin": origin}))?;
        hex_field(&v, "pub")?.try_into().map_err(|_| err("bad_key", "the signer's key is not 33 bytes"))
    }

    fn attach(&self, origin: &str, params: &ChannelParams) -> xbt402::Result<String> {
        let v = self.call("xbt402_attach", json!({"origin": origin, "params": params.to_json()}))?;
        Ok(v.get("chan").and_then(Value::as_str).unwrap_or("").to_string())
    }

    fn payer_spk(&self) -> xbt402::Result<Option<Vec<u8>>> {
        Ok(Some(hex_field(&self.call("hot_address", json!({}))?, "hot_spk")?))
    }

    fn sign_state(&self, chan: &str, amount: u64) -> xbt402::Result<Vec<u8>> {
        hex_field(&self.call("xbt402_sign_state", json!({"chan": chan, "cum": amount}))?, "sig")
    }

    fn sign_state_a3(&self, chan: &str, amount: u64) -> xbt402::Result<Vec<u8>> {
        hex_field(&self.call("xbt402_sign_state_a3", json!({"chan": chan, "amount": amount}))?, "sig")
    }

    fn sign_rollover(&self, chan: &str, amount: u64, next_spk: &[u8], next_capacity: u64) -> xbt402::Result<Vec<u8>> {
        hex_field(&self.call("xbt402_sign_rollover", json!({"chan": chan, "amount": amount, "next_spk": hex::encode(next_spk),
                                                             "next_capacity": next_capacity}))?, "sig")
    }

    fn sign_rollover_next(&self, chan: &str, amount: u64, next: &ChannelParams, next_capacity: u64) -> xbt402::Result<Vec<u8>> {
        hex_field(&self.call("xbt402_sign_rollover", json!({"chan": chan, "amount": amount, "next_spk": hex::encode(next.spk()),
                                                             "next_capacity": next_capacity, "next": next.to_json()}))?, "sig")
    }

    fn sign_close(&self, chan: &str) -> xbt402::Result<Vec<u8>> {
        hex_field(&self.call("xbt402_sign_close", json!({"chan": chan}))?, "sig")
    }

    fn sign_refund(&self, chan: &str) -> xbt402::Result<String> {
        Ok(self.call("xbt402_sign_refund", json!({"chan": chan}))?.get("hex").and_then(Value::as_str).unwrap_or("").to_string())
    }

    fn request_auth(&self, chan: &str, seq: Option<&Value>, cum: Option<&Value>, sig: Option<&str>, req: &str) -> xbt402::Result<String> {
        let v = self.call("xbt402_request_auth", json!({"chan": chan, "seq": seq, "cum": cum, "sig": sig, "req": req}))?;
        v.get("auth").and_then(Value::as_str).map(str::to_string).ok_or_else(|| err("bad_auth", "no auth from the signer"))
    }

    fn sign_conditional(&self, chan: &str, uncond: u64, cond: &ConditionalParams) -> xbt402::Result<Vec<u8>> {
        hex_field(&self.call("xbt402_sign_conditional", json!({"chan": chan, "uncond": uncond, "hash": hex::encode(cond.h),
                                                                "amount": cond.cond_amount, "csv_delta": cond.csv_delta}))?, "sig")
    }
}

/// B2's `xbt402_*` lock methods; the signer applies its routing policy (hub allowlist, fee cap,
/// `max_lock_sats`, the 24 h routed budget) and then the policy engine before it pre-signs.
impl RouteSigner for RemoteSigner {
    fn sign_state_adaptor(&self, chan: &str, cum: u64, point: &PubkeyBytes, route: &Value) -> xbt402::Result<AdaptorLock> {
        let v = self.call("xbt402_sign_state_adaptor", json!({"chan": chan, "cum": cum, "point": hex::encode(point), "route": route}))?;
        let pre = PreSig::from_json(v.get("adaptor").unwrap_or(&Value::Null)).map_err(|e| err("signer_error", e.msg))?;
        let got = v.get("cum").and_then(Value::as_u64).unwrap_or(0);
        if got != cum {
            return Err(err("signer_error", format!("the signer locked {got}, not {cum}")));
        }
        Ok(AdaptorLock { pre, point: hex_n(&v, "point")?, tweak: hex_n(&v, "tweak")?, cum })
    }

    fn resolve_lock(&self, chan: &str, secret: &[u8; 32]) -> xbt402::Result<[u8; 32]> {
        hex_n(&self.call("xbt402_resolve_lock", json!({"chan": chan, "secret": hex::encode(secret)}))?, "t")
    }

    fn void_lock(&self, chan: &str) -> xbt402::Result<bool> {
        Ok(self.call("xbt402_void_lock", json!({"chan": chan}))?.get("voided").and_then(Value::as_bool).unwrap_or(false))
    }

    fn adopt_lock(&self, chan: &str, cum: u64) -> xbt402::Result<()> {
        self.call("xbt402_adopt_lock", json!({"chan": chan, "cum": cum})).map(|_| ())
    }

    fn recover_lock(&self, chan: &str, close_tx: &Tx) -> xbt402::Result<[u8; 32]> {
        hex_n(&self.call("xbt402_recover_lock", json!({"chan": chan, "txid": close_tx.txid(), "hex": close_tx.to_hex()}))?, "t")
    }
}

impl Wallet for RemoteSigner {
    /// The signer funds only channels for keys it issued (AGP-063 W3): see [`Wallet::fund_channel`].
    fn fund(&self, address: &str, sats: u64) -> xbt402::Result<(String, u32)> {
        let v = self.call("fund", json!({"address": address, "sats": sats}))?;
        Ok((v.get("txid").and_then(Value::as_str).unwrap_or("").to_string(), v.get("vout").and_then(Value::as_u64).unwrap_or(0) as u32))
    }

    /// The signer's `fund` of the channel for the key it issued for `origin` (a 0x21 funding from
    /// its hot key); it checks the channel against the seller's verified terms and its policy first.
    fn fund_channel(&self, origin: &str, params: &ChannelParams, address: &str, sats: u64) -> xbt402::Result<(String, u32)> {
        let v = self.call("fund", json!({"origin": origin, "params": params.to_json(), "address": address, "sats": sats}))?;
        Ok((v.get("txid").and_then(Value::as_str).unwrap_or("").to_string(), v.get("vout").and_then(Value::as_u64).unwrap_or(0) as u32))
    }
}
