//! The wallet behind the tools: B2's signer socket, and nothing else. This process never holds a key
//! (B2's signer, Python or Rust, holds them all) and never reads the hot key's wrapping key.
//!
//! * [`Wallet::call_tool`] forwards a validated tool call to the signer method of the same name,
//!   exactly as B2's `mcp_server.py` does, and packs the answer the way B2 packs it ([`pack`]).
//! * With `XBT_MCP_PAYER=local`, `xbt402_pay` and `close_channel` instead run xbt402's own payer SDK
//!   ([`xbt402::client::Client`]) in this process with the signer as its `StateSigner` and `Wallet`
//!   ([`xbt_signer::client::RemoteSigner`]), so every key, state and policy check still lives in
//!   the signer. That path needs the Rust signer (the Python signer has no external-payer methods).
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Map, Value};
use xbt402::client::{split_url, Client, ClientConfig, FileClientLedger};
use xbt402::http::UreqTransport;
use xbt402::json::{as_big_int, parse, py_float};
use xbt402::signer::StateSigner;
use xbt_signer::client::RemoteSigner;
use xbt_signer::ipc::Stream;
use xbt_signer::sanitize::{assert_no_key_material, sanitize, untrusted, UNTRUSTED_KEY};

// --- JSON as Python writes it -----------------------------------------------------------------

fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7E => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write(out: &mut String, v: &Value, indent: Option<usize>, sort: bool, level: usize) {
    let (item, key) = if indent.is_some() { (",", ": ") } else { (", ", ": ") };
    let nl = |out: &mut String, l: usize| {
        if let Some(n) = indent {
            out.push('\n');
            out.push_str(&" ".repeat(n * l));
        }
    };
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) if n.is_f64() => out.push_str(&py_float(n.as_f64().unwrap_or(0.0))),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) if s.starts_with(NONFINITE) => out.push_str(&s[NONFINITE.len()..]),
        Value::String(s) => write_str(out, s),
        Value::Object(_) if as_big_int(v).is_some() => out.push_str(as_big_int(v).unwrap_or("0")),
        Value::Array(a) if a.is_empty() => out.push_str("[]"),
        Value::Object(m) if m.is_empty() => out.push_str("{}"),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(item);
                }
                nl(out, level + 1);
                write(out, x, indent, sort, level + 1);
            }
            nl(out, level);
            out.push(']');
        }
        Value::Object(m) => {
            let mut kv: Vec<_> = m.iter().collect();
            if sort {
                kv.sort_by(|a, b| a.0.cmp(b.0)); // UTF-8 byte order is code-point order, as Python sorts
            }
            out.push('{');
            for (i, (k, x)) in kv.into_iter().enumerate() {
                if i > 0 {
                    out.push_str(item);
                }
                nl(out, level + 1);
                write_str(out, k);
                out.push_str(key);
                write(out, x, indent, sort, level + 1);
            }
            nl(out, level);
            out.push('}');
        }
    }
}

/// `json.dumps(v, indent=2, sort_keys=True)`, integers of any size kept.
pub fn dumps_pretty(v: &Value) -> String {
    let mut s = String::new();
    write(&mut s, v, Some(2), true, 0);
    s
}

/// `json.dumps(v)`, integers of any size kept.
pub fn dumps(v: &Value) -> String {
    let mut s = String::new();
    write(&mut s, v, None, false, 0);
    s
}

/// B2's `_pack`: drop key-named fields and redact key-shaped strings (outside the untrusted provider
/// subtree), refuse anything key-like that is left, and print as B2 prints. Err: the refusal.
pub fn pack(result: Value) -> Result<String, String> {
    let clean = sanitize(result);
    assert_no_key_material(&clean)?;
    Ok(dumps_pretty(&clean))
}

// --- the signer socket --------------------------------------------------------------------------

/// A float Python's `json` reads and writes that JSON has no token for (`NaN`, `Infinity`,
/// `-Infinity`), carried through as a marked string and written back bare.
const NONFINITE: &str = "\u{0}xbt-mcp-nonfinite:";

/// [`parse`], plus Python's `NaN` / `Infinity` / `-Infinity` tokens outside strings.
pub fn parse_py(s: &str) -> serde_json::Result<Value> {
    if !(s.contains("NaN") || s.contains("Infinity")) {
        return parse(s);
    }
    let (mut out, mut in_str, mut esc, mut i) = (Vec::with_capacity(s.len()), false, false, 0);
    let b = s.as_bytes();
    while i < b.len() {
        let c = b[i];
        if in_str {
            in_str = !(c == b'"' && !esc);
            esc = c == b'\\' && !esc;
        } else if c == b'"' {
            in_str = true;
        } else if let Some(t) = ["-Infinity", "Infinity", "NaN"].into_iter().find(|t| b[i..].starts_with(t.as_bytes())) {
            out.extend(format!("\"{}{t}\"", NONFINITE.replace('\u{0}', "\\u0000")).bytes());
            i += t.len();
            continue;
        }
        out.push(c);
        i += 1;
    }
    xbt402::json::parse_slice(&out)
}

/// B2's `SignerClient.call`: one request per connection, `{"id": 1, "method", "params"}` + newline,
/// one line back. Big integers survive both ways (`xbt402::json::parse`).
pub fn signer_call(sock: &Path, timeout: Duration, method: &str, params: &Value) -> Result<Value, String> {
    let io = |e: std::io::Error| format!("signer socket {}: {e}", sock.display());
    let mut s = Stream::connect(sock).map_err(io)?;
    s.set_timeouts(Some(timeout));
    let mut req = Map::new();
    req.insert("id".into(), 1.into());
    req.insert("method".into(), method.into());
    req.insert("params".into(), params.clone());
    s.write_all(format!("{}\n", dumps(&Value::Object(req))).as_bytes()).map_err(io)?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).map_err(io)?;
    let resp = parse_py(line.trim()).map_err(|e| format!("signer answer: {e}"))?;
    if let Some(e) = resp.get("error").filter(|e| !e.is_null()) {
        return Err(format!("signer error: {}", e.get("message").and_then(Value::as_str).unwrap_or("error")));
    }
    Ok(resp.get("result").cloned().unwrap_or(Value::Null))
}

/// Where B2 looks for the socket: `B2_SIGNER_SOCK`, else `$B2_ROOT/.run/signer.sock`.
pub fn default_sock() -> PathBuf {
    if let Ok(s) = std::env::var("B2_SIGNER_SOCK") {
        return s.into();
    }
    let root = std::env::var("B2_ROOT").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."));
    root.join(".run").join("signer.sock")
}

fn default_timeout() -> Duration {
    Duration::from_secs_f64(std::env::var("B2_SIGNER_TIMEOUT").ok().and_then(|v| v.parse::<f64>().ok()).unwrap_or(60.0))
}

// --- the local payer (XBT_MCP_PAYER=local) ------------------------------------------------------

/// Settings of the in-process payer. Every key stays in the signer.
#[derive(Clone, Debug)]
pub struct LocalConfig {
    /// The xbt402 network id (`xbt:...`) the payer accepts offers on.
    pub network: String,
    pub capacity: u64,
    pub expiry_blocks: u32,
    pub budget_sats: u64,
    pub min_conf: u64,
    /// Where the channel book is kept across restarts (xbt402 `FileClientLedger`); `None`: memory.
    pub ledger: Option<PathBuf>,
}

impl LocalConfig {
    /// From `XBT_MCP_NETWORK` (required), `XBT_MCP_CAPACITY`, `XBT_MCP_EXPIRY_BLOCKS`,
    /// `XBT_MCP_BUDGET_SATS`, `XBT_MCP_MIN_CONF` and `XBT_MCP_LEDGER` (default
    /// `$B2_ROOT/.run/mcp-payer.jsonl`; `-` for memory only).
    pub fn from_env() -> Result<Self, String> {
        let n = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
        let network = std::env::var("XBT_MCP_NETWORK").map_err(|_| "XBT_MCP_PAYER=local needs XBT_MCP_NETWORK (the xbt402 network id)".to_string())?;
        let ledger = match std::env::var("XBT_MCP_LEDGER") {
            Ok(p) if p == "-" => None,
            Ok(p) => Some(PathBuf::from(p)),
            Err(_) => Some(std::env::var("B2_ROOT").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(".")).join(".run").join("mcp-payer.jsonl")),
        };
        Ok(Self { network, capacity: n("XBT_MCP_CAPACITY", 10_000), expiry_blocks: n("XBT_MCP_EXPIRY_BLOCKS", 1_008) as u32,
                  budget_sats: n("XBT_MCP_BUDGET_SATS", 1_000_000), min_conf: n("XBT_MCP_MIN_CONF", 1), ledger })
    }
}

/// The signer's `fund`, then a wait for the funding's confirmations (the provider needs minConf).
struct Funding {
    remote: RemoteSigner,
    min_conf: u64,
}

impl Funding {
    fn confirmed(&self, txid: String, vout: u32) -> xbt402::Result<(String, u32)> {
        let deadline = std::time::Instant::now() + Duration::from_secs(180);
        loop {
            let v = self.remote.client.call("tx_confirmations", json!({"txid": txid, "vout": vout}))?;
            if v["confirmations"].as_u64().unwrap_or(0) >= self.min_conf {
                return Ok((txid, vout));
            }
            if std::time::Instant::now() > deadline {
                return Err(xbt402::ChannelError::new("funding_unconfirmed", "the funding did not confirm in time"));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

impl xbt402::client::Wallet for Funding {
    fn fund(&self, address: &str, sats: u64) -> xbt402::Result<(String, u32)> {
        let (txid, vout) = xbt402::client::Wallet::fund(&self.remote, address, sats)?;
        self.confirmed(txid, vout)
    }

    fn fund_channel(&self, origin: &str, params: &xbt402::channel::ChannelParams, address: &str, sats: u64) -> xbt402::Result<(String, u32)> {
        let (txid, vout) = self.remote.fund_channel(origin, params, address, sats)?;
        self.confirmed(txid, vout)
    }
}

struct LocalPayer {
    client: Client,
    remote: RemoteSigner,
    /// For the unpaid first request that learns this call's price (as the signer's own xbt402_pay does).
    http: UreqTransport,
    network: String,
}

fn deny(e: xbt402::ChannelError) -> Value {
    json!({"verdict": "deny", "rule": e.code, "reason": e.msg, "charged_sats": 0, "payer": LOCAL_PAYER})
}

const LOCAL_PAYER: &str = "xbt-wallet-mcp: xbt402 Client, keys in the signer";

impl LocalPayer {
    fn new(sock: &Path, cfg: &LocalConfig) -> Result<Self, String> {
        let remote = RemoteSigner::new(sock);
        let mut c = ClientConfig::new(&cfg.network);
        c.capacity = cfg.capacity;
        c.expiry_blocks = cfg.expiry_blocks;
        c.budget_sats = cfg.budget_sats;
        let h = remote.clone();
        let height: xbt402::client::HeightFn = Box::new(move || {
            let v = h.client.call("channels", json!({}))?;
            Ok(v.get("height").and_then(Value::as_u64).unwrap_or(0) as u32)
        });
        let signer: Arc<dyn StateSigner> = Arc::new(remote.clone());
        let mut client = Client::new(c, Box::new(UreqTransport::default()), Box::new(Funding { remote: remote.clone(), min_conf: cfg.min_conf }), height)
            .with_signer(signer);
        if let Some(p) = &cfg.ledger {
            if let Some(d) = p.parent() {
                let _ = std::fs::create_dir_all(d);
            }
            client = client.with_ledger(Box::new(FileClientLedger::open(p).map_err(|e| e.msg)?)).map_err(|e| e.msg)?;
        }
        Ok(Self { client, remote, http: UreqTransport::default(), network: cfg.network.clone() })
    }

    /// `origin` is on the signer's allowlist now (read on every call: the owner may change it).
    fn allowlisted(&self, origin: &str) -> xbt402::Result<()> {
        let dest = xbt_signer::policy::normalize_dest(origin);
        let v = self.remote.client.call("policy_get", json!({}))?;
        let listed = v.pointer("/policy/allowlist").and_then(Value::as_array).into_iter().flatten()
            .filter_map(Value::as_str).any(|a| xbt_signer::policy::normalize_dest(a) == dest);
        if dest.is_empty() || !listed {
            return Err(xbt402::ChannelError::new("allowlist", format!("destination not on allowlist: {dest}")));
        }
        Ok(())
    }

    /// One paid call through xbt402's `Client`. The provider's body and receipt only come back under
    /// `untrusted_provider_response`, as the signer's own `xbt402_pay` returns them.
    fn pay(&mut self, url: &str, method: &str, body: &str, max_sats: u64) -> Value {
        let (origin, _) = split_url(url);
        let cap = xbt_signer::session::body_cap();
        // AGP-063 X1: the owner's allowlist before any request, so the probe reaches no other host
        if let Err(e) = self.allowlisted(&origin) {
            return deny(e);
        }
        // This call's price, before anything is signed: an open channel pays without a 402 first, and
        // xbt402's Client checks max_price only when it opens one, so max_sats is enforced here.
        let probe = match xbt402::client::Transport::request(&self.http, method, url, body.as_bytes(), &[]) {
            Ok(r) => r,
            Err(e) => return deny(e),
        };
        if probe.status != 402 {
            let text: String = String::from_utf8_lossy(&probe.body).chars().take(cap).collect();
            return json!({"status": probe.status, "charged_sats": 0, "note": "no 402 (already free or error)", "payer": LOCAL_PAYER,
                          UNTRUSTED_KEY: untrusted(&text, Value::Null)});
        }
        let offer = probe.header("PAYMENT-REQUIRED").and_then(|h| xbt402::wire::unb64json(h).ok());
        let price = offer.as_ref().and_then(|pr| pr.get("accepts")).and_then(Value::as_array).into_iter().flatten()
            .find(|a| xbt402::wire::scheme_accepted(a.get("scheme").and_then(Value::as_str)) && a.get("network").and_then(Value::as_str) == Some(self.network.as_str()))
            .and_then(|a| xbt402::json::py_u64(a.get("amount")));
        let Some(price) = price else {
            return deny(xbt402::ChannelError::new("bad_offer", format!("no batch-settlement offer on {}", self.network)));
        };
        if price > max_sats {
            return json!({"verdict": "deny", "rule": "max_sats", "reason": format!("quoted {price} > max_sats {max_sats}"), "charged_sats": 0,
                          "payer": LOCAL_PAYER});
        }
        self.client.cfg.max_price = max_sats;
        let before = self.client.channels.get(&origin).map(|c| (c.receipts.len(), c.payer.signed));
        let opened = before.is_none();
        let r = match self.client.request(method, url, body.as_bytes()) {
            Ok(r) => r,
            Err(e) => return deny(e),
        };
        self.client.trim_receipts(64);
        let text: String = String::from_utf8_lossy(&r.body).chars().take(cap).collect();
        let Some(ch) = self.client.channels.get(&origin) else {
            return json!({"status": r.status, "charged_sats": 0, "note": "no channel was opened", "payer": LOCAL_PAYER,
                          UNTRUSTED_KEY: untrusted(&text, Value::Null)});
        };
        let (n0, _) = before.unwrap_or((0, 0));
        let receipt = if ch.receipts.len() > n0 { ch.receipts.last().cloned().unwrap_or(Value::Null) } else { Value::Null };
        let charged = if r.status < 400 { xbt402::json::py_u64(receipt.get("charged")).unwrap_or(0) } else { 0 };
        let mut out = json!({"status": r.status, "charged_sats": charged, "chan": ch.payer.params.channel_id(), "cum": ch.payer.signed,
                             "owed_sats": ch.spent_msat.div_ceil(1000), "billing": ch.accepted.get("extra").and_then(|e| e.get("billing")).cloned().unwrap_or("postpay".into()),
                             "opened": if opened { json!({"funding_txid": ch.payer.params.funding_txid(), "funding_sats": ch.payer.params.capacity}) } else { Value::Null },
                             "payer": LOCAL_PAYER, UNTRUSTED_KEY: untrusted(&text, receipt)});
        if r.body.len() > cap {
            out["bytes"] = r.body.len().into();
        }
        if parse(&String::from_utf8_lossy(&r.body)).ok().and_then(|d| d.get("stream").and_then(Value::as_str).map(str::to_string)).as_deref()
            == Some("xbt402-merkle-v1")
        {
            out["note"] = "a streamed (Merkle) result: its chunks are bought by the signer's own xbt402_pay (XBT_MCP_PAYER=signer)".into();
        }
        out
    }

    /// The origin of this payer's channel matching `counterparty` (an origin or a channel id).
    fn find(&self, counterparty: &str) -> Option<String> {
        let c = counterparty.trim_end_matches('/');
        self.client.channels.iter()
            .find(|(o, ch)| o.as_str() == c || ch.payer.params.channel_id() == counterparty)
            .map(|(o, _)| o.clone())
    }

    fn close(&mut self, origin: &str) -> Value {
        let chan = self.client.channels[origin].payer.params.channel_id();
        let r = match self.client.close(origin) {
            Ok(r) => r,
            Err(e) => return deny(e),
        };
        // the close's own state: in postpay it is the first to cover the last call
        let cum = self.client.channels.get(origin).map(|c| c.payer.signed).unwrap_or(0);
        let txid = r.get("txid").and_then(Value::as_str)
            .filter(|t| t.len() == 64 && t.bytes().all(|c| c.is_ascii_hexdigit())).map(str::to_string);
        let marked = self.remote.mark_closed(&chan, txid.as_deref().unwrap_or(""));
        self.client.channels.remove(origin);
        let _ = self.client.persist(Some(origin));
        json!({"verdict": "allow", "rail": "xbt402", "dest": origin, "txid": txid, "chan": chan, "cum": cum, "payer": LOCAL_PAYER,
               "close_change": marked.ok().and_then(|m| m.get("close_change").cloned()).unwrap_or(Value::Null),
               UNTRUSTED_KEY: untrusted(&dumps(&r), Value::Null)})
    }
}

// --- the wallet ---------------------------------------------------------------------------------

/// Which process runs `xbt402_pay`.
#[derive(Clone, Debug)]
pub enum PayerMode {
    /// The signer's own `xbt402_pay` (B2's behaviour; either signer).
    Signer,
    /// xbt402's `Client` here, keys in the (Rust) signer.
    Local(LocalConfig),
}

pub struct Wallet {
    pub sock: PathBuf,
    pub timeout: Duration,
    pub mode: PayerMode,
    /// AGP-039 `XBT_MCP_APPROVAL_WAIT_S`: how long an over-threshold `xbt402_pay` waits for the
    /// human's approval (in the wallet's web UI) before it answers `needs_human`. 0 (the default) is
    /// B2's behaviour: answer at once.
    pub approval_wait: Duration,
    /// AGP-048 `XBT_MCP_LN=1`: offer `ln_pay` and `ln_status` (the signer must have an LN node).
    pub ln_tools: bool,
    local: Mutex<Option<LocalPayer>>,
}

impl Wallet {
    pub fn new(sock: PathBuf, mode: PayerMode) -> Self {
        let wait = std::env::var("XBT_MCP_APPROVAL_WAIT_S").ok().and_then(|v| v.parse::<f64>().ok()).filter(|w| w.is_finite() && *w > 0.0).unwrap_or(0.0);
        let ln_tools = std::env::var("XBT_MCP_LN").is_ok_and(|v| matches!(v.trim(), "1" | "true" | "yes"));
        Self { sock, timeout: default_timeout(), mode, local: Mutex::new(None), approval_wait: Duration::from_secs_f64(wait.min(86_400.0)), ln_tools }
    }

    /// B2's environment: `B2_SIGNER_SOCK` / `B2_ROOT`, `B2_SIGNER_TIMEOUT`, plus `XBT_MCP_PAYER`.
    pub fn from_env() -> Result<Self, String> {
        let mode = match std::env::var("XBT_MCP_PAYER").as_deref() {
            Ok("local") => PayerMode::Local(LocalConfig::from_env()?),
            Ok("signer") | Err(_) => PayerMode::Signer,
            Ok(o) => return Err(format!("XBT_MCP_PAYER={o}: expected signer or local")),
        };
        Ok(Self::new(default_sock(), mode))
    }

    pub fn signer(&self, method: &str, params: &Value) -> Result<Value, String> {
        signer_call(&self.sock, self.timeout, method, params)
    }

    /// The signer's `xbt402_pay` (or, AGP-048, `ln_pay`); an over-threshold call waits up to
    /// `approval_wait` for the human. Once the human approved in the UI the signer holds a one-time
    /// grant for exactly this call (url, method, max_sats; or the invoice), and the same call again
    /// pays under it. A deny or expiry answers the original `needs_human` with `approval_state`. The
    /// model never sees or needs a signature.
    fn pay_waiting(&self, method: &str, params: &Map<String, Value>) -> Result<Value, String> {
        let args = Value::Object(params.clone());
        let first = self.signer(method, &args)?;
        if self.approval_wait.is_zero() || first.get("verdict").and_then(Value::as_str) != Some("needs_human") {
            return Ok(first);
        }
        let Some(token) = first.get("approval_token").and_then(Value::as_str).map(str::to_string) else { return Ok(first) };
        let until = std::time::Instant::now() + self.approval_wait;
        let mut state = String::from("pending");
        while std::time::Instant::now() < until {
            std::thread::sleep(Duration::from_millis(500));
            state = self.signer("approval_status", &json!({"token": token}))?.get("state").and_then(Value::as_str).unwrap_or("unknown").to_string();
            if state == "approved" {
                let mut paid = self.signer(method, &args)?;
                // a new channel's first call can be "pending" (funding waits for a block): the grant
                // stays until it is used, so keep calling while the wait lasts
                while paid.get("verdict").and_then(Value::as_str) == Some("pending") && std::time::Instant::now() < until {
                    std::thread::sleep(Duration::from_secs(1));
                    paid = self.signer(method, &args)?;
                }
                if let Value::Object(m) = &mut paid {
                    m.insert("waited_for_human".into(), Value::Bool(true));
                }
                return Ok(paid);
            }
            if state != "pending" {
                break;
            }
        }
        let mut out = first;
        if let Value::Object(m) = &mut out {
            m.insert("approval_state".into(), state.into());
        }
        Ok(out)
    }

    fn with_local<T>(&self, f: impl FnOnce(&mut LocalPayer) -> T) -> Result<T, String> {
        let PayerMode::Local(cfg) = &self.mode else { return Err("not in local payer mode".into()) };
        let mut g = self.local.lock().unwrap_or_else(|p| p.into_inner());
        if g.is_none() {
            *g = Some(LocalPayer::new(&self.sock, cfg)?);
        }
        Ok(f(g.as_mut().expect("set above")))
    }

    /// Run a tool whose arguments passed validation. Ok: the packed text. Err: the reason, which
    /// stays in this process's log; the model gets B2's generic "Error executing tool" line.
    pub fn call_tool(&self, name: &str, params: Map<String, Value>) -> Result<String, String> {
        let local = matches!(self.mode, PayerMode::Local(_));
        let result = match name {
            "xbt402_pay" if local => {
                let s = |k: &str| params.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                let max = params.get("max_sats").and_then(Value::as_i64).unwrap_or(1000).max(0) as u64;
                self.with_local(|p| p.pay(&s("url"), &s("method"), &s("body"), max))?
            }
            "close_channel" if local => {
                let cp = params.get("counterparty").and_then(Value::as_str).unwrap_or("").to_string();
                match self.with_local(|p| p.find(&cp).map(|o| p.close(&o)))? {
                    Some(v) => v,
                    None => self.signer(name, &Value::Object(params))?,
                }
            }
            "xbt402_pay" | "ln_pay" => self.pay_waiting(name, &params)?,
            _ => self.signer(name, &Value::Object(params))?,
        };
        pack(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dumps_like_python() {
        let v = parse(r#"{"b": [1, 2.0, {"z": null, "a": []}], "a": {}, "big": 100000000000000000000000, "u": "é"}"#).unwrap();
        assert_eq!(dumps_pretty(&v), "{\n  \"a\": {},\n  \"b\": [\n    1,\n    2.0,\n    {\n      \"a\": [],\n      \"z\": null\n    }\n  ],\n  \"big\": 100000000000000000000000,\n  \"u\": \"\\u00e9\"\n}");
        assert_eq!(dumps(&v), r#"{"b": [1, 2.0, {"z": null, "a": []}], "a": {}, "big": 100000000000000000000000, "u": "\u00e9"}"#);
    }

    #[test]
    fn pack_strips_keys_keeps_untrusted() {
        let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
        let s = pack(json!({"hot_secret": "x", "wif": wif, "n": wif, UNTRUSTED_KEY: {"body": wif, "secret": 1}})).unwrap();
        assert_eq!(s, format!("{{\n  \"n\": \"[redacted]\",\n  \"untrusted_provider_response\": {{\n    \"body\": \"{wif}\",\n    \"secret\": 1\n  }}\n}}"));
    }
}
