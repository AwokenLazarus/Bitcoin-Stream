//! The signer's node (B2 `rpc.py`, `netparams.py`, AGP-017).
//!
//! [`Node`] is every chain call the signer makes, as bitcoind JSON-RPC. [`KnotsRpc`] talks to a
//! Knots node with cookie auth, refuses key-dumping RPCs, and refuses block generation unless the
//! signer confirmed the node is regtest (P3). The free functions are B2's `netparams`: the chain
//! and what follows from it (hrp P5, network id P4, mining P3), and the lookups a pruned node
//! without txindex needs (P6): [`get_tx`], [`block_of`], [`find_spender`].
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::{json, Value};

use crate::{err, Result};

pub const ENV_CHAIN: &str = "B2_CHAIN";
pub const MAINNET_ANCHOR: u64 = 961_640;
pub const REGTEST_ANCHOR: u64 = 101;
pub const SPENDER_SCAN_MAX: u64 = 4_032;
pub const XBT_SATS: f64 = 100_000_000.0;

/// A chain backend: bitcoind JSON-RPC semantics. Errors carry code `rpc_error`.
pub trait Node: Send + Sync {
    fn call(&self, method: &str, params: Value) -> Result<Value>;
    /// P3: whether block-generating calls are allowed (set once the chain is known to be regtest).
    fn set_allow_generate(&self, _allow: bool) {}
    /// The wallet name (for `health`).
    fn wallet(&self) -> String {
        String::new()
    }
}

/// BTC float (as JSON) to sats: `int(round(float(v) * 1e8))`.
pub fn sats(v: Option<&Value>) -> i64 {
    let f = match v {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) => s.parse().unwrap_or(0.0),
        _ => 0.0,
    };
    (f * XBT_SATS).round() as i64
}

const FORBIDDEN: [&str; 9] = ["dumpprivkey", "dumpwallet", "dumpmasterprivkey", "listdescriptors", "getdescriptorinfo",
                              "importdescriptors", "importprivkey", "sethdseed", "backupwallet"];
const GENERATE: [&str; 4] = ["generatetoaddress", "generatetodescriptor", "generateblock", "generate"];

/// Knots JSON-RPC over cookie auth, addressing one wallet (`/wallet/<name>`).
pub struct KnotsRpc {
    pub datadir: PathBuf,
    pub wallet_name: String,
    pub port: String,
    pub host: String,
    pub auth_file: Option<PathBuf>,
    allow_generate: AtomicBool,
    agent: ureq::Agent,
}

impl KnotsRpc {
    /// `B2_RPCPORT` (default 19443) on `B2_RPCHOST` (default 127.0.0.1; a container reaches its node
    /// by service name). Credentials: `B2_RPCCOOKIE` (a file holding `user:password`, cookie format:
    /// a node's cookie on a shared volume, or rpcauth credentials) or the cookie in `datadir`.
    pub fn new(datadir: &Path, wallet: &str) -> Self {
        let env = |k: &str| std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        Self { datadir: datadir.into(), wallet_name: wallet.into(), port: env("B2_RPCPORT").unwrap_or_else(|| "19443".into()),
               host: env("B2_RPCHOST").unwrap_or_else(|| "127.0.0.1".into()), auth_file: env("B2_RPCCOOKIE").map(PathBuf::from),
               allow_generate: AtomicBool::new(false), agent: ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).build() }
    }

    fn cookie(&self) -> Result<String> {
        if let Some(f) = &self.auth_file {
            return std::fs::read_to_string(f).map(|t| t.trim().to_string())
                .map_err(|e| err("rpc_error", format!("RPC credentials {}: {e}", f.display())));
        }
        for c in [self.datadir.join("regtest").join(".cookie"), self.datadir.join(".cookie")] {
            if let Ok(t) = std::fs::read_to_string(&c) {
                return Ok(t.trim().to_string());
            }
        }
        Err(err("rpc_error", format!("RPC cookie not found under {}", self.datadir.display())))
    }
}

/// The node answered the call with a JSON-RPC error: it did not do what was asked. Every other
/// failure is `rpc_error`: the call may or may not have run (AGP-080: `pay` keeps its booking then).
pub const REFUSED: &str = "rpc_refused";

impl Node for KnotsRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let m = method.to_lowercase();
        if FORBIDDEN.contains(&m.as_str()) {
            return Err(err("rpc_error", format!("signer refuses RPC method {method}")));
        }
        if GENERATE.contains(&m.as_str()) && !self.allow_generate.load(Ordering::SeqCst) {
            return Err(err("rpc_error", format!("signer refuses {method}: mining is for regtest only")));
        }
        let auth = format!("Basic {}", B64.encode(self.cookie()?));
        let url = format!("http://{}:{}/wallet/{}", self.host, self.port, self.wallet_name);
        let body = json!({"jsonrpc": "1.0", "id": "b2", "method": method, "params": params});
        let resp = match self.agent.post(&url).set("Authorization", &auth).set("Content-Type", "application/json").send_string(&body.to_string()) {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                let raw = r.into_string().unwrap_or_default();
                // a JSON-RPC error comes back with HTTP 500 and a body; report the node's error
                if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                    if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
                        return Err(err(REFUSED, e.to_string()));
                    }
                }
                return Err(err("rpc_error", format!("RPC HTTP {code}: {}", raw.chars().take(400).collect::<String>())));
            }
            Err(e) => return Err(err("rpc_error", e.to_string())),
        };
        let v: Value = serde_json::from_str(&resp.into_string().map_err(|e| err("rpc_error", e.to_string()))?)
            .map_err(|e| err("rpc_error", e.to_string()))?;
        if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
            return Err(err(REFUSED, e.to_string()));
        }
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    }

    fn set_allow_generate(&self, allow: bool) {
        self.allow_generate.store(allow, Ordering::SeqCst);
    }

    fn wallet(&self) -> String {
        self.wallet_name.clone()
    }
}

// --- netparams ------------------------------------------------------------------------------------

pub fn hrp(chain: &str) -> Result<&'static str> {
    Ok(match chain {
        "main" => "bc",
        "test" | "testnet4" | "signet" => "tb",
        "regtest" => "bcrt",
        other => return Err(err("chain", format!("unknown chain {other:?}"))),
    })
}

pub fn mining_allowed(chain: &str) -> bool {
    chain == "regtest"
}

/// The node's chain, checked against `B2_CHAIN`; with the node unreachable, `B2_CHAIN` alone.
pub fn detect_chain(node: &dyn Node) -> Result<String> {
    let want = std::env::var(ENV_CHAIN).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let info = match node.call("getblockchaininfo", json!([])) {
        Ok(i) => i,
        Err(e) => {
            return match want {
                Some(w) => hrp(&w).map(|_| w),
                None => Err(err("chain", format!("cannot reach the node to learn its chain ({}); set {ENV_CHAIN}",
                                                 e.msg.chars().take(120).collect::<String>()))),
            };
        }
    };
    let got = info.get("chain").and_then(Value::as_str).map(str::to_string).or(want.clone()).unwrap_or_else(|| "regtest".into());
    if let Some(w) = want {
        if got != w {
            return Err(err("chain", format!("the node is on {got:?} but {ENV_CHAIN}={w:?}")));
        }
    }
    hrp(&got)?;
    Ok(got)
}

fn u64_of(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

/// Block count.
pub fn height(node: &dyn Node) -> Result<u64> {
    u64_of(&node.call("getblockcount", json!([]))?).ok_or_else(|| err("rpc_error", "getblockcount"))
}

pub fn block_hash(node: &dyn Node, h: u64) -> Result<String> {
    node.call("getblockhash", json!([h]))?.as_str().map(str::to_string).ok_or_else(|| err("rpc_error", "getblockhash"))
}

/// The xbt402 network id for this chain (P4): block 961640 on mainnet (it must be the spec's
/// `XBT_MAINNET`), block 101 on regtest and the test chains.
pub fn network(node: &dyn Node, chain: &str, tip: Option<u64>) -> Result<String> {
    if chain == "main" {
        let net = xbt_primitives::network::network_id(&block_hash(node, MAINNET_ANCHOR)?);
        if net != xbt402::wire::XBT_MAINNET {
            return Err(err("chain", format!("block {MAINNET_ANCHOR} gives {net}, not the spec's {}", xbt402::wire::XBT_MAINNET)));
        }
        return Ok(net);
    }
    let tip = match tip {
        Some(t) => t,
        None => height(node)?,
    };
    if tip < REGTEST_ANCHOR {
        return Err(err("chain", format!("the chain has no block {REGTEST_ANCHOR} yet (tip {tip})")));
    }
    Ok(xbt_primitives::network::network_id(&block_hash(node, REGTEST_ANCHOR)?))
}

/// A verbose transaction without txindex: the mempool (or txindex), then the block it is known to
/// be in. `None` when neither has it.
pub fn get_tx(node: &dyn Node, txid: &str, blockhash: &str) -> Option<Value> {
    if let Ok(v) = node.call("getrawtransaction", json!([txid, true])) {
        if !v.is_null() {
            return Some(v);
        }
    }
    if !blockhash.is_empty() {
        if let Ok(v) = node.call("getrawtransaction", json!([txid, true, blockhash])) {
            if !v.is_null() {
                return Some(v);
            }
        }
    }
    None
}

/// `(height, blockhash)` of a confirmed, still unspent output, from gettxout alone.
pub fn block_of(node: &dyn Node, txid: &str, vout: u32) -> Option<(u64, String)> {
    let r = node.call("gettxout", json!([txid, vout, false])).ok()?;
    let confs = r.get("confirmations").and_then(u64_of).unwrap_or(0);
    if confs < 1 {
        return None;
    }
    let tip = r.get("bestblock").and_then(Value::as_str)
        .and_then(|b| node.call("getblockheader", json!([b])).ok())
        .and_then(|h| h.get("height").and_then(u64_of))
        .or_else(|| height(node).ok())?;
    let h = tip + 1 - confs;
    Some((h, block_hash(node, h).ok()?))
}

fn spends(tx: &Value, txid: &str, vout: u32) -> bool {
    tx.get("vin").and_then(Value::as_array).is_some_and(|vin| vin.iter().any(|v| {
        v.get("txid").and_then(Value::as_str) == Some(txid) && v.get("vout").and_then(u64_of) == Some(vout as u64)
    }))
}

/// The txid spending `(txid, vout)`: the mempool first (gettxspendingprevout), then the blocks
/// from `from_height` on (at most `limit`, newest last). `None` if not found.
pub fn find_spender(node: &dyn Node, txid: &str, vout: u32, from_height: u64, limit: u64) -> Option<String> {
    if let Ok(r) = node.call("gettxspendingprevout", json!([[{"txid": txid, "vout": vout}]])) {
        if let Some(sp) = r.get(0).and_then(|x| x.get("spendingtxid")).and_then(Value::as_str) {
            return Some(sp.to_string());
        }
    }
    if from_height == 0 {
        return None;
    }
    let tip = height(node).ok()?;
    let start = from_height.max((tip + 1).saturating_sub(limit));
    for h in start..=tip {
        let Ok(bh) = block_hash(node, h) else { continue };
        let Ok(blk) = node.call("getblock", json!([bh, 2])) else { continue };
        for tx in blk.get("tx").and_then(Value::as_array).into_iter().flatten() {
            if spends(tx, txid, vout) {
                return tx.get("txid").and_then(Value::as_str).map(str::to_string);
            }
        }
    }
    None
}

/// Whether `tx` (verbose) spends `(txid, vout)`.
pub fn tx_spends(tx: &Value, txid: &str, vout: u32) -> bool {
    spends(tx, txid, vout)
}
