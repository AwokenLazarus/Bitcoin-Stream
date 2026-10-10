//! bitcoind JSON-RPC (feature `rpc`): a [`ChainBackend`] for the provider and a [`Wallet`] for the
//! payer, over blocking HTTP with basic auth (user/password or the node's `.cookie`).
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::{json, Value};
use xbt_primitives::amount::Amount;

use crate::client::{Wallet, WalletSend};
use crate::error::{fail, ChannelError, Result};
use crate::funding::{ChainBackend, UtxoInfo};
use crate::json::py_str;

/// A JSON-RPC connection to one node (optionally one of its wallets).
#[derive(Clone)]
pub struct Rpc {
    url: String,
    auth: String,
    agent: ureq::Agent,
}

impl Rpc {
    pub fn new(url: &str, user: &str, password: &str) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            auth: format!("Basic {}", B64.encode(format!("{user}:{password}"))),
            agent: ureq::AgentBuilder::new().timeout(Duration::from_secs(60)).build(),
        }
    }

    /// Credentials from a node's cookie file (`<datadir>/regtest/.cookie`).
    pub fn from_cookie(url: &str, cookie_path: &std::path::Path) -> Result<Self> {
        let c = std::fs::read_to_string(cookie_path).map_err(|e| ChannelError::new("rpc_error", format!("cookie: {e}")))?;
        let (u, p) = c.trim().split_once(':').ok_or_else(|| ChannelError::new("rpc_error", "bad cookie"))?;
        Ok(Self::new(url, u, p))
    }

    /// The same node, addressing wallet `name`.
    pub fn wallet(&self, name: &str) -> Self {
        let base = self.url.split("/wallet/").next().unwrap_or(&self.url);
        Self { url: format!("{base}/wallet/{name}"), auth: self.auth.clone(), agent: self.agent.clone() }
    }

    /// Call `method`; an RPC error becomes `rpc_error` with the node's message.
    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc": "1.0", "id": "xbt402", "method": method, "params": params});
        let resp = match self.agent.post(&self.url).set("Authorization", &self.auth).set("Content-Type", "application/json")
            .send_string(&body.to_string())
        {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return fail("rpc_error", e.to_string()),
        };
        let text = resp.into_string().map_err(|e| ChannelError::new("rpc_error", e.to_string()))?;
        let v: Value = crate::json::parse(&text).map_err(|e| ChannelError::new("rpc_error", e.to_string()))?;
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            return fail("rpc_error", err.get("message").and_then(Value::as_str).unwrap_or("error").to_string());
        }
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    }
}

impl ChainBackend for Rpc {
    fn block_count(&self) -> Result<u32> {
        self.call("getblockcount", json!([]))?.as_u64().and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| ChannelError::new("rpc_error", "getblockcount"))
    }

    fn get_tx_out(&self, txid: &str, vout: u32, include_mempool: bool) -> Result<Option<UtxoInfo>> {
        let v = self.call("gettxout", json!([txid, vout, include_mempool]))?;
        if v.is_null() {
            return Ok(None);
        }
        let value = Amount::from_btc_f64(v.get("value").and_then(Value::as_f64).unwrap_or(-1.0))
            .map_err(|e| ChannelError::new("rpc_error", e.to_string()))?;
        let spk = v.get("scriptPubKey").and_then(|s| s.get("hex")).and_then(Value::as_str).unwrap_or("");
        Ok(Some(UtxoInfo {
            confirmations: v.get("confirmations").and_then(Value::as_u64).unwrap_or(0) as u32,
            value: value.to_sat(),
            script_pubkey: hex::decode(spk).map_err(|_| ChannelError::new("rpc_error", "scriptPubKey hex"))?,
            coinbase: v.get("coinbase").and_then(Value::as_bool).unwrap_or(false),
        }))
    }

    fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        self.call("sendrawtransaction", json!([hex]))?.as_str().map(str::to_string)
            .ok_or_else(|| ChannelError::new("rpc_error", "sendrawtransaction"))
    }

    fn has_transaction(&self, txid: &str) -> Result<bool> {
        Ok(self.call("getrawtransaction", json!([txid])).map(|v| !v.is_null()).unwrap_or(false))
    }

    fn estimate_fee_rate(&self, target: u32) -> Result<Option<f64>> {
        let r = self.call("estimatesmartfee", json!([target]))?;
        Ok(r.get("feerate").and_then(Value::as_f64).filter(|f| *f > 0.0).map(|f| f * 1e8 / 1000.0))
    }

    fn mempool_min_fee(&self) -> Result<Option<f64>> {
        let r = self.call("getmempoolinfo", json!([]))?;
        let rate = |k: &str| r.get(k).and_then(Value::as_f64).unwrap_or(0.0) * 1e8 / 1000.0;
        Ok(Some(rate("mempoolminfee").max(rate("minrelaytxfee"))).filter(|f| *f > 0.0))
    }

    /// `submitpackage`: Ok when every tx of the package is in the mempool (or was already).
    fn submit_package(&self, hexes: &[String]) -> Result<()> {
        let r = self.call("submitpackage", json!([hexes]))?;
        if r.get("package_msg").and_then(Value::as_str) == Some("success") {
            return Ok(());
        }
        let errs: Vec<String> = r.get("tx-results").and_then(Value::as_object).into_iter().flatten()
            .filter_map(|(_, t)| t.get("error").and_then(Value::as_str).map(str::to_string)).collect();
        fail("rpc_error", format!("submitpackage: {} {}", py_str(r.get("package_msg")), errs.join("; ")))
    }
}

impl Wallet for Rpc {
    /// `sendtoaddress`, then the wallet's own view of the tx for the vout (no txindex needed).
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        let amt = Amount::from_sat(sats).map_err(|e| ChannelError::new("bad_amount", e.to_string()))?;
        let txid = self.call("sendtoaddress", json!([address, amt.to_btc_string().parse::<f64>().unwrap_or(0.0)]))?
            .as_str().map(str::to_string).ok_or_else(|| ChannelError::new("rpc_error", "sendtoaddress"))?;
        let tx = self.call("gettransaction", json!([txid, true, true]))?;
        let vout = tx.get("decoded").and_then(|d| d.get("vout")).and_then(Value::as_array).and_then(|outs| {
            outs.iter().find(|o| o.get("scriptPubKey").and_then(|s| s.get("address")).and_then(Value::as_str) == Some(address))
                .and_then(|o| o.get("n")).and_then(Value::as_u64)
        }).ok_or_else(|| ChannelError::new("rpc_error", "funding output not found"))?;
        Ok((txid, vout as u32))
    }

    fn wallet_sends_to(&self, address: &str) -> Result<Vec<String>> {
        let r = self.call("listtransactions", json!(["*", 1000, 0, true]))?;
        let mut out: Vec<String> = vec![];
        for t in r.as_array().into_iter().flatten() {
            if t.get("category").and_then(Value::as_str) == Some("send") && t.get("address").and_then(Value::as_str) == Some(address) {
                if let Some(id) = t.get("txid").and_then(Value::as_str).filter(|id| !out.iter().any(|o| o == id)) {
                    out.push(id.to_string());
                }
            }
        }
        Ok(out)
    }

    fn wallet_send(&self, txid: &str, address: &str) -> Result<Option<WalletSend>> {
        let Ok(tx) = self.call("gettransaction", json!([txid, true, true])) else { return Ok(None) };
        let out = tx.get("decoded").and_then(|d| d.get("vout")).and_then(Value::as_array).and_then(|outs| {
            outs.iter().find(|o| o.get("scriptPubKey").and_then(|s| s.get("address")).and_then(Value::as_str) == Some(address))
        });
        let Some(o) = out else { return Ok(None) };
        let sats = o.get("value").and_then(Value::as_f64).and_then(|v| Amount::from_btc_f64(v).ok()).map(|a| a.to_sat()).unwrap_or(0);
        Ok(Some(WalletSend {
            txid: txid.to_string(),
            vout: o.get("n").and_then(Value::as_u64).unwrap_or(0) as u32,
            sats,
            confirmations: tx.get("confirmations").and_then(Value::as_i64).unwrap_or(0),
            abandoned: tx.get("details").and_then(Value::as_array).into_iter().flatten()
                .any(|d| d.get("abandoned").and_then(Value::as_bool).unwrap_or(false)),
        }))
    }
}
