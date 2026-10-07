//! `xbt402_pay` inside the signer (B2 `xbt402.py` + `stream.py`): B1's wire, B2's keys.
//!
//! Channels are keyed by HTTP origin. AGP-017: the network id comes from the spec's anchor
//! (block 961640 on mainnet, P4); a mining hook is refused off regtest (P3); a channel is recorded,
//! payer key sealed, before its funding is broadcast (P1) and opened only once the funding has the
//! offer's minConf (P2). The provider's body and receipt come back only under
//! `untrusted_provider_response` (L7); the wallet's own errors never carry provider text (L12).
//!
//! Streamed results (`stream: xbt402-merkle-v1`) are bought here: signed Merkle manifest,
//! verify-then-pay per chunk, hash-locked last chunk (the ciphertext before the signature, M7).
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::channel::DERIVATION;
use xbt402::client::Transport;
use xbt402::conditional::{encrypt, preimage_from_tx};
use xbt402::json::{dumps, py_str};
use xbt402::provider::HttpResponse;
use xbt402::wire::{b64json, facilitator_request, receipt_of, request_digest, safe_code, scheme_accepted, unb64json, FACILITATOR_VERIFY};
use xbt_primitives::ecdsa;
use xbt_primitives::hash::{sha256, tagged_hash};
use xbt_primitives::tx::Tx;

use crate::channels::{ChannelBook, ChannelRecord};
use crate::hot::{HotWallet, DEFAULT_FEE};
use crate::node::{self, Node};
use crate::pyjson::{now_f64, py_int, truthy};
use crate::sanitize::{untrusted, UNTRUSTED_KEY};
use crate::{err, Result};

pub const PREVIEW_CAP: usize = 2048;
const OPEN_POLL_S: f64 = 2.0;

/// Inline preview cap (`B2_BODY_CAP`, default 12,000).
pub fn body_cap() -> usize {
    std::env::var("B2_BODY_CAP").ok().and_then(|v| v.parse().ok()).unwrap_or(12_000)
}

/// A RuntimeError in B2: reported as `deny/xbt402`.
fn rt(msg: impl Into<String>) -> crate::Error {
    err("xbt402", msg)
}

/// `scheme://netloc` of an absolute URL.
pub fn origin_of(url: &str) -> Result<String> {
    let (scheme, rest) = url.split_once("://").ok_or_else(|| err("dest", "xbt402_pay needs an absolute URL"))?;
    let netloc = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    if scheme.is_empty() || netloc.is_empty() || !scheme.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) {
        return Err(err("dest", "xbt402_pay needs an absolute URL"));
    }
    Ok(format!("{}://{netloc}", scheme.to_ascii_lowercase()))
}

/// Path + query as the provider sees it.
pub fn request_target(url: &str) -> String {
    let parts: Vec<&str> = url.splitn(4, '/').collect();
    if parts.len() > 3 { format!("/{}", parts[3]) } else { "/".into() }
}

fn pick_accept(pr: &Value, network: &str) -> Result<Value> {
    pr.get("accepts").and_then(Value::as_array).into_iter().flatten()
        .find(|a| scheme_accepted(a.get("scheme").and_then(Value::as_str)) && a.get("network").and_then(Value::as_str) == Some(network))
        .cloned().ok_or_else(|| rt("no batch-settlement offer on this network"))
}

/// Python's `int(v or default)`.
fn or_int(v: Option<&Value>, default: i64) -> Result<i64> {
    if !truthy(v) {
        return Ok(default);
    }
    py_int(v).ok_or_else(|| rt("offer field is not an integer"))
}

fn charged_of(resp: Option<&Value>, default: i64) -> i64 {
    resp.and_then(|r| receipt_of(r).ok()).and_then(|r| py_int(r.get("charged"))).unwrap_or(default)
}

fn log_call(kind: &str, fields: Value) {
    let Ok(path) = std::env::var("B2_CALLS_JSONL") else { return };
    let mut row = json!({"t": (now_f64() * 1000.0).round() / 1000.0, "kind": kind});
    if let Value::Object(m) = fields {
        for (k, v) in m {
            row[&k] = v;
        }
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).open(path) {
        use std::io::Write;
        let _ = writeln!(f, "{}", dumps(&row));
    }
}

fn ms_since(t: Instant) -> f64 {
    (t.elapsed().as_secs_f64() * 10_000.0).round() / 10.0
}

/// Persist a body; digest + path. Never truncates the stored bytes.
fn store_body(raw: &[u8], name: &str) -> Value {
    let digest = hex::encode(sha256(raw));
    let Ok(root) = std::env::var("B2_BODY_DIR") else {
        return json!({"body_digest": digest, "bytes": raw.len()});
    };
    let _ = std::fs::create_dir_all(&root);
    let safe: String = name.chars().map(|c| if c.is_alphanumeric() || "-_.".contains(c) { c } else { '_' }).take(80).collect();
    let safe = if safe.is_empty() { digest[..16].to_string() } else { safe };
    let path = Path::new(&root).join(format!("{safe}.bin"));
    let _ = std::fs::write(&path, raw);
    json!({"body_digest": digest, "saved_to": path.to_string_lossy(), "bytes": raw.len()})
}

fn preview(b: &[u8], cap: usize) -> String {
    String::from_utf8_lossy(b).chars().take(cap).collect()
}

fn merge(dst: &mut Value, src: Value) {
    if let (Value::Object(d), Value::Object(s)) = (dst, src) {
        for (k, v) in s {
            d.insert(k, v);
        }
    }
}

pub type MineFn = Arc<dyn Fn(u64) -> Result<()> + Send + Sync>;

/// One signer-owned client session.
pub struct Session {
    pub book: Arc<ChannelBook>,
    pub hot: Arc<HotWallet>,
    pub node: Arc<dyn Node>,
    pub transport: Arc<dyn Transport>,
    pub chain: String,
    pub mine: Option<MineFn>,
    pub open_wait_s: f64,
    pub close_fee_max: i64,
    pub refund_margin: i64,
    net: Mutex<Option<String>>,
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    pub fn new(book: Arc<ChannelBook>, hot: Arc<HotWallet>, node: Arc<dyn Node>, transport: Arc<dyn Transport>, chain: &str,
               mine: Option<MineFn>, open_wait_s: f64, close_fee_max: i64, refund_margin: i64) -> Result<Self> {
        if mine.is_some() && !node::mining_allowed(chain) {
            return Err(err("chain", format!("a mining hook on {chain:?}: only regtest may mine")));
        }
        Ok(Self { book, hot, node, transport, chain: chain.into(), mine, open_wait_s, close_fee_max, refund_margin, net: Mutex::new(None) })
    }

    pub fn height(&self) -> Result<u64> {
        node::height(&*self.node)
    }

    /// The xbt402 network id (P4). A wrong mainnet anchor fails: never pay on a network we can't name.
    pub fn network(&self) -> Result<String> {
        if self.chain != "regtest" {
            let mut g = self.net.lock().map_err(|_| rt("poisoned"))?;
            if g.is_none() {
                *g = Some(node::network(&*self.node, &self.chain, None)?);
            }
            return Ok(g.clone().unwrap_or_default());
        }
        Ok(self.height().and_then(|h| node::network(&*self.node, &self.chain, Some(h)))
            .unwrap_or_else(|_| xbt_primitives::network::network_id(&"0".repeat(64))))
    }

    fn http(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        self.transport.request(method, url, body, headers)
    }

    /// Fund a channel for this offer and open it. Returns the channel's public record, or one with
    /// state "pending" when the funding has not reached the offer's minConf within `open_wait_s`.
    pub fn open_from_offer(&self, dest: &str, acc: &Value, cap_sats: i64, expiry_blocks: i64) -> Result<Value> {
        let extra = acc.get("extra").cloned().unwrap_or(json!({}));
        if extra.get("derivation").and_then(Value::as_str) != Some(DERIVATION) {
            // checked before funding: a mismatch strands the coins (no provider text: L12)
            return Err(rt(format!("provider payee-key derivation is not {DERIVATION:?}; refused before funding")));
        }
        let close_fee = or_int(extra.get("closeFeeSat"), 600)?;
        if self.close_fee_max > 0 && close_fee > self.close_fee_max {
            return Err(rt(format!("offer closeFeeSat {close_fee} is above this wallet's cap {}; refused before funding", self.close_fee_max)));
        }
        let fee_payer = extra.get("closeFeePayer").map(|v| v.as_str().unwrap_or("?").to_string()).unwrap_or_else(|| "payer".into());
        if fee_payer != "payer" && fee_payer != "payee" {
            return Err(rt("offer closeFeePayer is neither payer nor payee; refused before funding"));
        }
        // payer-pays: we fund our close fee on top of the cap; payee-pays: the payee's output carries it
        let payer_fee = if fee_payer == "payer" { close_fee } else { 0 };
        // min/maxCapacity bound the funding output (cap + our close fee), as B1 checks it (AGP-017)
        let min_cap = or_int(extra.get("minCapacity"), 0)?;
        let max_cap = or_int(extra.get("maxCapacity"), cap_sats + payer_fee)?;
        let cap = cap_sats.max(min_cap - payer_fee);
        if cap + payer_fee > max_cap {
            return Err(rt(format!("channel capacity {} above provider max {max_cap}", cap + payer_fee)));
        }
        let min_exp = or_int(extra.get("minExpiryBlocks"), 1)?;
        let max_exp = or_int(extra.get("maxExpiryBlocks"), 100_000)?;
        let blocks = expiry_blocks.max(min_exp + 6).min(max_exp - 1);
        self.hot.check_channel_funding()?; // AGP-013: above the hot-balance cap, a human sweeps first
        let open_height = self.height()? as i64;
        let expiry = open_height + blocks;
        let (secret, payer_pub) = self.book.new_payer_key();
        // change at close returns to the signer's hot key, not the per-channel payer key
        let pay_to = hex::decode(acc.get("payTo").and_then(Value::as_str).unwrap_or("")).map_err(|_| rt("offer payTo is not hex"))?;
        let network = acc.get("network").and_then(Value::as_str).unwrap_or("").to_string();
        let fp = xbt402::channel::FeePayer::parse(&fee_payer)?;
        let params = xbt402::channel::ChannelParams::derive(&pay_to, &hex::decode(&payer_pub).unwrap_or_default(), expiry as u32,
                                                            close_fee as u64, Some(self.hot.spk()), &network, fp)?;
        let funded = cap + payer_fee;
        let min_conf = match extra.get("minConf") {
            None => 1,
            Some(v) => py_int(Some(v)).map(|x| x.max(0)).unwrap_or(1),
        };
        let prep = self.hot.prepare_fund(&params.spk(), funded, DEFAULT_FEE)?;
        let params = params.with_funding(&prep.txid, 0, funded as u64)?;
        // P1 write-ahead: the payer key is sealed on disk, with everything the refund needs, before
        // the funding exists anywhere but here
        let open_url = format!("{dest}{}", extra.get("openUrl").and_then(Value::as_str).unwrap_or(xbt402::wire::OPEN_PATH));
        self.book.add_pending(dest, secret, &params, dest, Some(cap), open_height, &open_url, &network, min_conf, &prep.hex)?;
        if let Err(e) = self.hot.broadcast(&prep) {
            self.book.drop_pending(dest, &params.channel_id())?;
            return Err(rt(format!("funding broadcast failed: {}", e.msg.chars().take(200).collect::<String>())));
        }
        self.hot.commit(&prep)?;
        log_call("funding", json!({"dest": dest, "chan": params.channel_id(), "txid": prep.txid, "capacity": funded, "expiry": expiry,
                                   "min_conf": min_conf}));
        self.complete_open(dest, self.open_wait_s)
    }

    /// Confirmations of a channel's funding output; `None` when the node does not have it at all.
    fn funding_confirmations(&self, rec: &ChannelRecord) -> Result<Option<i64>> {
        let r = self.node.call("gettxout", json!([rec.funding_txid, rec.funding_vout, true]))?;
        Ok((!r.is_null()).then(|| py_int(r.get("confirmations")).unwrap_or(0)))
    }

    /// P2: post a pending channel's open once its funding has `min_conf` confirmations (waiting up
    /// to `wait_s`), and mark it open when the provider accepts it (`duplicate_channel` counts).
    /// Otherwise it stays pending, and the watcher retries or refunds it.
    pub fn complete_open(&self, dest: &str, wait_s: f64) -> Result<Value> {
        let Some(rec) = self.book.get(dest) else { return Ok(json!({})) };
        if rec.state != "pending" {
            return Ok(rec.public());
        }
        let mut confs = self.funding_confirmations(&rec)?;
        if confs.is_none() && !rec.funding_hex.is_empty() && self.node.call("sendrawtransaction", json!([rec.funding_hex])).is_ok() {
            confs = Some(0); // never reached the node, or was evicted: sent again
        }
        if let (Some(c), Some(mine)) = (confs, &self.mine) {
            if c < rec.min_conf {
                mine((rec.min_conf - c) as u64)?; // regtest only (P3)
                confs = self.funding_confirmations(&rec)?;
            }
        }
        let deadline = Instant::now() + Duration::from_secs_f64(wait_s.max(0.0));
        while confs.is_none_or(|c| c < rec.min_conf) && Instant::now() < deadline {
            let left = deadline.saturating_duration_since(Instant::now()).as_secs_f64();
            std::thread::sleep(Duration::from_secs_f64(OPEN_POLL_S.min(left.max(0.05))));
            confs = self.funding_confirmations(&rec)?;
        }
        if confs.is_none_or(|c| c < rec.min_conf) {
            let mut out = rec.public();
            out["confirmations"] = confs.unwrap_or(0).into();
            out["min_conf"] = rec.min_conf.into();
            return Ok(out);
        }
        let confs = confs.unwrap_or(0);
        if confs >= 1 && rec.funding_height == 0 {
            if let Some((h, _)) = node::block_of(&*self.node, &rec.funding_txid, rec.funding_vout as u32) {
                self.book.note_pending(dest, None, Some(h as i64))?;
            }
        }
        if self.height()? as i64 >= rec.expiry - self.refund_margin {
            self.book.note_pending(dest, Some("too close to expiry to open; refunded at expiry"), None)?;
            let mut out = self.book.get(dest).map(|r| r.public()).unwrap_or(json!({}));
            out["confirmations"] = confs.into();
            out["min_conf"] = rec.min_conf.into();
            return Ok(out);
        }
        let mut ch = json!({"txid": rec.funding_txid, "vout": rec.funding_vout, "capacity": rec.funding_sats, "expiry": rec.expiry,
                            "payerPub": rec.payer_pub, "payerSpk": rec.payer_spk, "redeemScript": hex::encode(rec.params()?.script())});
        if rec.close_fee_payer != "payer" {
            ch["closeFeePayer"] = rec.close_fee_payer.clone().into();
        }
        let body = json!({"x402Version": 2, "network": rec.network, "channel": ch});
        let resp = match self.http("POST", &rec.open_url, dumps(&body).as_bytes(), &[("Content-Type".into(), "application/json".into())]) {
            Ok(r) => r,
            Err(_) => {
                self.book.note_pending(dest, Some("open unreachable: ConnectionError"), None)?;
                return Err(rt("open failed: provider unreachable (ConnectionError); the channel stays pending: retried by the watcher, \
                               refunded at expiry if never opened"));
            }
        };
        let st = resp.status;
        let reply: Option<Value> = serde_json::from_slice(&resp.body).ok();
        let mut code = String::new();
        if st != 200 {
            code = reply.as_ref().and_then(|r| r.get("error")).and_then(Value::as_str).unwrap_or("").to_string();
            if !safe_code(&code) {
                code.clear(); // no provider text in the wallet's errors (L12)
            }
        }
        if st == 200 {
            let echoed = reply.as_ref().map(|r| r.get("closeFeePayer").cloned().unwrap_or_else(|| "payer".into()));
            if echoed.as_ref().and_then(Value::as_str) != Some(rec.close_fee_payer.as_str()) {
                // the provider would refuse every state we sign: never mark it open (refunded at expiry)
                self.book.note_pending(dest, Some("open refused: provider opened another closeFeePayer"), None)?;
                return Err(rt("open failed: the provider did not take the offer's closeFeePayer; the channel stays pending and is refunded at expiry"));
            }
        }
        if st == 200 || code == "duplicate_channel" {
            let opened = self.book.mark_open(dest)?;
            log_call("opened", json!({"dest": dest, "chan": opened.chan, "confirmations": confs, "duplicate": st != 200}));
            let mut out = opened.public();
            out["confirmations"] = confs.into();
            return Ok(out);
        }
        let tail = if code.is_empty() { String::new() } else { format!(" {code}") };
        self.book.note_pending(dest, Some(&format!("open refused: HTTP {st}{tail}")), None)?;
        Err(rt(format!("open failed: HTTP {st}{tail}; the channel stays pending: retried by the watcher, refunded at expiry if never opened")))
    }

    /// H3: bind this payload to (method, path, body). The ECDH key stays in the book.
    fn with_auth(&self, payload: &mut Value, method: &str, url: &str, body: &[u8]) -> Result<()> {
        let req = request_digest(method, &request_target(url), body);
        let chan = py_str(payload.get("chan"));
        let sig = payload.get("sig").and_then(Value::as_str).map(str::to_string);
        payload["auth"] = self.book.request_auth(&chan, payload.get("seq"), payload.get("cum"), sig.as_deref(), &req)?.into();
        Ok(())
    }

    fn paid(&self, method: &str, url: &str, body: &[u8], acc: &Value, mut payload: Value) -> Result<(HttpResponse, Option<Value>)> {
        self.with_auth(&mut payload, method, url, body)?;
        let hdr = b64json(&json!({"x402Version": 2, "accepted": acc, "payload": payload}));
        let r = self.http(method, url, body, &[("PAYMENT-SIGNATURE".into(), hdr)])?;
        let receipt = r.header("PAYMENT-RESPONSE").and_then(|h| unb64json(h).ok());
        Ok((r, receipt))
    }

    /// One call. The provider's body and receipt come back only under `untrusted_provider_response`.
    pub fn pay_once(&self, url: &str, method: &str, body: &[u8], max_sats: i64, expiry_blocks: i64, cap_sats: i64) -> Result<Value> {
        let mut res = self.pay_once_inner(url, method, body, max_sats, expiry_blocks, cap_sats)?;
        if let Value::Object(m) = &mut res {
            if m.contains_key("body") || m.contains_key("receipt") {
                let b = m.remove("body").map(|b| b.as_str().unwrap_or("").to_string()).unwrap_or_default();
                let r = m.remove("receipt").unwrap_or(Value::Null);
                m.insert(UNTRUSTED_KEY.into(), untrusted(&b, r));
            }
        }
        Ok(res)
    }

    fn pay_once_inner(&self, url: &str, method: &str, body: &[u8], max_sats: i64, expiry_blocks: i64, cap_sats: i64) -> Result<Value> {
        let dest = origin_of(url)?;
        let t0 = Instant::now();
        let cap = body_cap();
        let r = self.http(method, url, body, &[])?;
        if r.status != 402 {
            let stored = if r.body.len() > cap { store_body(&r.body, &format!("free-{}", now_f64() as i64)) } else { json!({}) };
            log_call("call", json!({"url": url, "status": r.status, "ms": ms_since(t0), "chargedSat": 0, "chan": null}));
            let mut out = json!({"status": r.status, "charged_sats": 0, "body": preview(&r.body, cap), "note": "no 402 (already free or error)"});
            merge(&mut out, stored);
            return Ok(out);
        }
        let pr = unb64json(r.header("PAYMENT-REQUIRED").ok_or_else(|| rt("402 without PAYMENT-REQUIRED"))?)
            .map_err(|_| rt("402 with an unreadable PAYMENT-REQUIRED"))?;
        let acc = pick_accept(&pr, &self.network()?)?;
        if acc.get("extra").and_then(|e| e.get("forward")).is_some_and(Value::is_object) {
            // the forward rail (B2 forward.py) is not in this signer: refuse before any payment
            return Ok(json!({"verdict": "deny", "rule": "forward_disabled",
                             "reason": "the forward rail is not available in this signer (not ported to the Rust signer)"}));
        }
        let price = py_int(acc.get("amount")).ok_or_else(|| rt("offer amount is not an integer"))?;
        if price > max_sats {
            return Ok(json!({"verdict": "deny", "rule": "max_sats", "reason": format!("quoted {price} > max_sats {max_sats}")}));
        }
        if price == 0 {
            let stored = if r.body.len() > cap { store_body(&r.body, &format!("free-{}", now_f64() as i64)) } else { json!({}) };
            log_call("call", json!({"url": url, "status": r.status, "ms": ms_since(t0), "chargedSat": 0, "chan": null}));
            let mut out = json!({"status": r.status, "charged_sats": 0, "body": preview(&r.body, cap), "note": "zero-priced offer; no channel"});
            merge(&mut out, stored);
            return Ok(out);
        }
        let mut opened = Value::Null;
        let rec = self.book.get(&dest);
        if rec.as_ref().is_none_or(|r| r.state != "open") {
            // a closed or refunded channel is replaced by a new one
            let t1 = Instant::now();
            let rec_pub = if rec.as_ref().is_some_and(|r| r.state == "pending") {
                self.complete_open(&dest, self.open_wait_s)? // funded earlier, not yet open (P1, P2)
            } else {
                self.open_from_offer(&dest, &acc, cap_sats, expiry_blocks)?
            };
            let rec = self.book.get(&dest).ok_or_else(|| rt("channel vanished"))?;
            if rec.state == "pending" {
                return Ok(json!({"verdict": "pending", "rule": "funding_unconfirmed", "chan": rec.chan, "funding_txid": rec.funding_txid,
                                 "confirmations": rec_pub.get("confirmations").cloned().unwrap_or(0.into()), "min_conf": rec.min_conf,
                                 "charged_sats": 0,
                                 "reason": "channel funded; its open waits for the funding to confirm. Call again later: the watcher also \
                                            opens it, and refunds it at expiry if it never opens"}));
            }
            opened = rec_pub;
            opened["funding_txid"] = rec.funding_txid.clone().into();
            opened["funding_sats"] = rec.funding_sats.into();
            log_call("open", json!({"url": url, "chan": rec.chan, "txid": rec.funding_txid, "capacity": rec.funding_sats, "cap": rec.cap_sats,
                                    "ms": ms_since(t1)}));
        }
        let rec = self.book.get(&dest).ok_or_else(|| rt("channel vanished"))?;
        let (rec, sig) = if !rec.last_sig.is_empty() && rec.used_sats > rec.acked_sats {
            self.book.resend_state(&dest)? // same (cum, sig); do not sign a higher one (M3)
        } else {
            self.book.increment(&dest, price)?
        };
        let mut payload = json!({"chan": rec.chan, "seq": rec.seq, "cum": rec.used_sats.to_string()});
        if !sig.is_empty() {
            payload["sig"] = hex::encode(&sig).into();
        }
        let (r2, receipt) = self.paid(method, url, body, &acc, payload)?;
        if receipt.is_some() {
            self.book.ack_state(&dest, Some(rec.used_sats))?;
        }
        let charged = if r2.status < 400 { charged_of(receipt.as_ref(), price) } else { 0 };
        log_call("call", json!({"url": url, "status": r2.status, "ms": ms_since(t0), "chargedSat": charged, "chan": rec.chan,
                                "cum": rec.used_sats, "opened": !opened.is_null()}));
        let stored = if r2.body.len() > cap { store_body(&r2.body, &format!("{}-{}", &rec.chan[..rec.chan.len().min(12)], rec.seq)) } else { json!({}) };
        let mut res = json!({"status": r2.status, "charged_sats": charged, "receipt": receipt, "chan": rec.chan, "cum": rec.used_sats,
                             "opened": opened, "body": preview(&r2.body, cap)});
        merge(&mut res, stored);
        let Ok(doc) = serde_json::from_slice::<Value>(&r2.body) else { return Ok(res) };
        if r2.status == 200 && doc.get("stream").and_then(Value::as_str) == Some("xbt402-merkle-v1") {
            res["receipt_scope"] = "manifest call only; chunk payments are in stream.paid_sats".into();
            let s = self.stream(&dest, &acc, &doc, max_sats - charged);
            let sc = s.get("stream_charged").and_then(Value::as_i64).unwrap_or(0);
            merge(&mut res, s);
            if let Value::Object(m) = &mut res {
                m.remove("stream_charged");
            }
            res["charged_sats"] = (charged + sc).into();
        }
        Ok(res)
    }

    // --- streams (stream.py) -------------------------------------------------------------------------

    fn stream(&self, dest: &str, acc: &Value, doc: &Value, budget: i64) -> Value {
        let m = doc.get("manifest").cloned().unwrap_or(json!({}));
        let t0 = Instant::now();
        let pay_to = acc.get("payTo").and_then(Value::as_str).unwrap_or("");
        if let Err(e) = check_manifest(&m, pay_to) {
            return json!({"stream_charged": 0, "stream": {"ok": false, "refused": e}});
        }
        let n = py_int(m.get("n")).unwrap_or(0);
        let price = py_int(m.get("price")).unwrap_or(0);
        if n < 1 || price < 0 {
            return json!({"stream_charged": 0, "stream": {"ok": false, "refused": "manifest has no chunks"}});
        }
        if n * price > budget {
            return json!({"stream_charged": 0, "body": "",
                          "stream": {"ok": false, "refused": format!("result costs {n} x {price} sat more; max_sats leaves {budget}")}});
        }
        let chunk_url = doc.get("chunkUrl").and_then(Value::as_str).unwrap_or("");
        let mid = m.get("id").cloned().unwrap_or(Value::Null);
        let (mut parts, mut spent) = (Vec::<u8>::new(), 0i64);
        for i in 0..n - 1 {
            let url = format!("{dest}{}", chunk_url.replace("{i}", &i.to_string()));
            let t = Instant::now();
            let step = || -> std::result::Result<(Vec<u8>, i64, String), (String, i64, String)> {
                let rec = self.book.fresh_seq(dest).map_err(|e| (e.msg, 0, String::new()))?;
                let (r, receipt) = self.paid("GET", &url, b"", acc, json!({"chan": rec.chan, "seq": rec.seq, "cum": rec.used_sats.to_string()}))
                    .map_err(|e| (e.msg, 0, rec.chan.clone()))?;
                let charged = charged_of(receipt.as_ref(), 0);
                if r.status != 200 {
                    return Err((format!("chunk {i}: HTTP {}", r.status), charged, rec.chan));
                }
                let c: Value = serde_json::from_slice(&r.body).map_err(|_| (format!("chunk {i}: not JSON"), charged, rec.chan.clone()))?;
                let data = check_chunk(&m, &c).map_err(|e| (e, charged, rec.chan.clone()))?;
                Ok((data, charged, rec.chan))
            };
            match step() {
                Err((reason, charged, chan)) => {
                    log_call("refused_chunk", json!({"i": i, "reason": reason, "refusedSat": charged, "chan": chan, "url": url}));
                    return json!({"stream_charged": spent, "body": "",
                                  "stream": {"ok": false, "id": mid, "refused_chunk": i, "reason": reason, "verified_chunks": i, "paid_sats": spent,
                                             "unpaid_refused_sats": charged,
                                             "note": "the wallet never signed a state paying for the bad chunk; buying stopped"}});
                }
                Ok((data, _, _)) => {
                    parts.extend(data);
                    let paid = self.book.increment(dest, price).and_then(|(rec, sig)| {
                        self.verify_post(dest, acc, json!({"chan": rec.chan, "cum": rec.used_sats.to_string(), "sig": hex::encode(sig)}))?;
                        Ok(rec)
                    });
                    match paid {
                        Ok(rec) => {
                            spent += price;
                            log_call("chunk", json!({"i": i, "ms": ms_since(t), "chargedSat": price, "chan": rec.chan, "cum": rec.used_sats}));
                        }
                        Err(e) => {
                            return json!({"stream_charged": spent + price, "body": "",
                                          "stream": {"ok": false, "id": mid, "refused_chunk": i, "reason": e.msg, "verified_chunks": i + 1,
                                                     "paid_sats": spent + price}});
                        }
                    }
                }
            }
        }
        let (pt, final_ms) = match self.final_chunk(dest, doc, &m) {
            Ok(x) => x,
            Err(e) => {
                let chan = self.book.get(dest).map(|r| r.chan).unwrap_or_default();
                log_call("refused_chunk", json!({"i": n - 1, "reason": e, "refusedSat": 0, "chan": chan}));
                return json!({"stream_charged": spent, "body": "",
                              "stream": {"ok": false, "id": mid, "refused_chunk": n - 1, "reason": e, "verified_chunks": n - 1, "paid_sats": spent}});
            }
        };
        spent += price;
        parts.extend(pt);
        let report = parts;
        let mut stored = store_body(&report, &py_str(m.get("id")));
        let mut path = stored.get("saved_to").and_then(Value::as_str).map(str::to_string);
        if let Some(p) = path.clone().filter(|p| p.ends_with(".bin")) {
            let md = format!("{}.md", &p[..p.len() - 4]);
            if std::fs::rename(&p, &md).is_ok() {
                stored["saved_to"] = md.clone().into();
                path = Some(md);
            }
        }
        let chan = self.book.get(dest).map(|r| r.chan).unwrap_or_default();
        log_call("stream", json!({"id": mid, "n": n, "bytes": report.len(), "sats": spent, "root": m.get("root"), "ms": ms_since(t0),
                                  "final_ms": final_ms, "chan": chan}));
        let text = String::from_utf8_lossy(&report).into_owned();
        let pv: String = text.chars().take(PREVIEW_CAP).collect();
        let digest = stored["body_digest"].as_str().unwrap_or("").to_string();
        let more = format!("\n\u{2026} [{} bytes, sha256 {digest}{}]", report.len(), path.as_ref().map(|p| format!(", saved to {p}")).unwrap_or_default());
        let mut out = json!({"stream_charged": spent, "body": if text.chars().count() > PREVIEW_CAP { format!("{pv}{more}") } else { pv },
                             "stream": {"ok": true, "id": mid, "chunks": n, "bytes": report.len(), "merkle_root": m.get("root"), "paid_sats": spent,
                                        "all_chunks_verified": true, "last_chunk": "hash-locked, key checked", "body_digest": digest}});
        if let Some(p) = path {
            out["stream"]["saved_to"] = p.into();
        }
        merge(&mut out, stored);
        out
    }

    /// Hand the provider a signed state through /x402/verify.
    fn verify_post(&self, dest: &str, acc: &Value, payload: Value) -> Result<()> {
        let r = self.http("POST", &format!("{dest}{FACILITATOR_VERIFY}"), dumps(&facilitator_request(acc, &payload)).as_bytes(),
                          &[("Content-Type".into(), "application/json".into())])?;
        let valid = r.status == 200 && serde_json::from_slice::<Value>(&r.body).ok().and_then(|v| v.get("isValid").cloned()) == Some(Value::Bool(true));
        if !valid {
            return Err(rt(format!("provider refused our payment state (HTTP {})", r.status)));
        }
        Ok(())
    }

    fn final_chunk(&self, dest: &str, doc: &Value, m: &Value) -> std::result::Result<(Vec<u8>, f64), String> {
        let t = Instant::now();
        let n = py_int(m.get("n")).unwrap_or(0);
        let price = py_int(m.get("price")).unwrap_or(0);
        let url = format!("{dest}{}", doc.get("chunkUrl").and_then(Value::as_str).unwrap_or("").replace("{i}", &(n - 1).to_string()));
        let not_offered = || "last chunk is not offered under the manifest's hash lock".to_string();
        let r = self.http("GET", &url, b"", &[]).map_err(|e| e.msg)?;
        let Some(h) = r.header("PAYMENT-REQUIRED").filter(|_| r.status == 402) else { return Err(not_offered()) };
        let net = self.network().map_err(|e| e.msg)?;
        let acc = unb64json(h).ok().and_then(|pr| pick_accept(&pr, &net).ok()).ok_or_else(not_offered)?;
        let cond = acc.get("extra").and_then(|e| e.get("conditional")).cloned().unwrap_or(json!({}));
        if cond.get("hash") != m.get("lock") || py_int(cond.get("amount")).unwrap_or(0) != price {
            return Err(not_offered());
        }
        // M7: the ciphertext comes before the signature
        let cipher = cond.get("cipher").and_then(Value::as_str).and_then(|c| hex::decode(c).ok())
            .ok_or_else(|| "last chunk offer carries no ciphertext; refused before signing".to_string())?;
        if Some(hex::encode(sha256(&cipher)).as_str()) != m.get("finalCt").and_then(Value::as_str) {
            return Err("last chunk offer's ciphertext does not match the committed finalCt; refused before signing".into());
        }
        let hash: [u8; 32] = cond.get("hash").and_then(Value::as_str).and_then(|x| hex::decode(x).ok()).and_then(|v| v.try_into().ok())
            .ok_or_else(not_offered)?;
        let csv = py_int(cond.get("csvDelta")).unwrap_or(10) as u32;
        let manifest: serde_json::Map<String, Value> = ["id", "n", "root", "lock", "finalCt", "lastProof"].iter()
            .map(|k| (k.to_string(), m.get(*k).cloned().unwrap_or(Value::Null))).collect();
        let pending = json!({"hash": hex::encode(hash), "cipher": hex::encode(&cipher), "manifest": manifest});
        let (rec, sig) = self.book.sign_stream_final(dest, hash, price as u64, csv, pending).map_err(|e| e.msg)?;
        let payload = json!({"chan": rec.chan, "seq": rec.seq, "cum": rec.used_sats.to_string(), "hashlock": hex::encode(hash), "sig": hex::encode(&sig)});
        let (r, _) = self.paid("GET", &url, b"", &acc, payload).map_err(|e| e.msg)?;
        if r.status != 200 {
            return Err(format!("conditional purchase of the last chunk failed: HTTP {}; if the provider claims the hash lock, \
                                recover_conditional() opens the chunk", r.status));
        }
        let k = serde_json::from_slice::<Value>(&r.body).ok().and_then(|v| v.get("preimage").and_then(Value::as_str).and_then(|p| hex::decode(p).ok()))
            .ok_or_else(|| "paid response carries no key; if the provider claims the hash lock, recover_conditional() opens the chunk".to_string())?;
        let pt = open_final(m, &cipher, &k)?; // the offered ciphertext, never one the response substitutes
        self.book.clear_pending_cond(dest).map_err(|e| e.msg)?;
        let (rec, sig2) = self.book.increment(dest, price).map_err(|e| e.msg)?;
        self.verify_post(dest, &acc, json!({"chan": rec.chan, "cum": rec.used_sats.to_string(), "sig": hex::encode(sig2)})).map_err(|e| e.msg)?;
        let ms = ms_since(t);
        log_call("chunk", json!({"i": n - 1, "ms": ms, "chargedSat": price, "chan": rec.chan, "cum": rec.used_sats, "hashlock": hex::encode(hash)}));
        Ok((pt, ms))
    }

    /// The last chunk of a stream whose hash lock was signed but whose paid response never came,
    /// from the provider's claim transaction (which reveals k on-chain).
    pub fn recover_conditional(&self, dest: &str, claim: &Tx) -> Result<Vec<u8>> {
        let pc = self.book.get(dest).map(|r| r.pending_cond).filter(|p| truthy(Some(p)))
            .ok_or_else(|| rt("no pending conditional purchase on this channel"))?;
        let hash: [u8; 32] = hex::decode(pc["hash"].as_str().unwrap_or("")).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| rt("hash"))?;
        let k = preimage_from_tx(claim, &hash).ok_or_else(|| rt("this transaction does not reveal the hash lock's key"))?;
        let pt = open_final(&pc["manifest"], &hex::decode(pc["cipher"].as_str().unwrap_or("")).unwrap_or_default(), &k).map_err(rt)?;
        self.book.clear_pending_cond(dest)?;
        Ok(pt)
    }

    // --- close ------------------------------------------------------------------------------------------

    /// The close's raw hex, if the provider's (untrusted) reply has it: kept only when it is the
    /// reported txid and spends this channel's funding output.
    fn close_hex(reply: Option<&Value>, txid: Option<&str>, rec: &ChannelRecord) -> String {
        let h = reply.and_then(|r| r.get("hex").or_else(|| r.get("closeHex"))).and_then(Value::as_str);
        let (Some(txid), Some(h)) = (txid, h) else { return String::new() };
        if h.len() >= 20_000 {
            return String::new();
        }
        let Ok(tx) = Tx::parse_hex(h) else { return String::new() };
        let spends = tx.inputs.iter().any(|i| i.prevout.txid_hex() == rec.funding_txid && i.prevout.vout as i64 == rec.funding_vout);
        if tx.txid() == txid && spends { h.to_string() } else { String::new() }
    }

    /// AGP-022: one attempt at counting a close's change. With the close's hex, our own node is
    /// handed the tx first.
    pub fn learn_close_change(&self, rec: &ChannelRecord, txid: &str, scan_from: i64, close_hex: &str) -> Value {
        if !close_hex.is_empty() {
            let _ = self.node.call("sendrawtransaction", json!([close_hex]));
        }
        let start = [scan_from, rec.close_scan_from, rec.funding_height, rec.open_height].into_iter().find(|v| *v != 0).unwrap_or(0);
        let t = if txid.is_empty() { rec.closed_txid.as_str() } else { txid };
        match self.hot.learn_close_change(t, (&rec.funding_txid, rec.funding_vout as u32), start.max(0) as u64, crate::hot::CLOSE_SCAN_MAX) {
            Ok(v) => v,
            Err(e) => json!({"status": "pending", "txid": t, "scan_from": start, "added": 0, "error": e.msg.chars().take(160).collect::<String>()}),
        }
    }

    /// Cooperative close through the signer: payer signs `tagged_hash(xbt402/close, chan)`.
    pub fn close_channel(&self, dest: &str) -> Result<Value> {
        let (dest, rec) = match self.book.get(dest) {
            Some(r) => (dest.to_string(), r),
            None => {
                let d = self.book.find_dest(dest).unwrap_or_else(|| dest.to_string());
                let r = self.book.get(&d).ok_or_else(|| rt(format!("no channel for {d}")))?;
                (d, r)
            }
        };
        let sig = self.book.sign_close(&dest)?;
        let origin = if rec.origin.is_empty() { dest.clone() } else { rec.origin.clone() };
        let close_url = format!("{}/x402/xbt-channel/close", origin.trim_end_matches('/'));
        let payload = json!({"chan": rec.chan, "seq": rec.seq, "cum": rec.used_sats.to_string()});
        let body = json!({"chan": rec.chan, "sig": sig, "payload": payload});
        let h0 = self.height().unwrap_or(0) as i64; // AGP-022: no block before this one can hold the close
        let r = self.http("POST", &close_url, dumps(&body).as_bytes(), &[("Content-Type".into(), "application/json".into())])
            .map_err(|_| rt("close failed: provider unreachable"))?;
        if r.status != 200 {
            return Err(rt(format!("close failed: HTTP {}", r.status)));
        }
        let reply: Option<Value> = serde_json::from_slice(&r.body).ok();
        // the provider's reply is untrusted data: only a txid-shaped txid becomes the wallet's own field
        let txid = reply.as_ref().and_then(|r| r.get("txid")).and_then(Value::as_str)
            .filter(|t| t.len() == 64 && t.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))).map(str::to_string);
        let report = Self::close_report(reply.as_ref(), &rec);
        let close_hex = Self::close_hex(reply.as_ref(), txid.as_deref(), &rec);
        if let (Some(mine), Some(_)) = (&self.mine, &txid) {
            let _ = mine(1); // regtest only (P3)
        }
        // the provider broadcast the close on its node; ours may get it later (P2P) or only in a
        // block: learn the change now if we can, then mark the channel closed with the answer
        let change = self.learn_close_change(&rec, txid.as_deref().unwrap_or(""), h0, &close_hex);
        self.book.mark_closed(&dest, txid.as_deref().unwrap_or(""), Some(&change), &close_hex)?;
        let hot_spk = self.hot.spk_hex();
        log_call("close", json!({"dest": dest, "chan": rec.chan, "txid": txid, "cum": rec.used_sats, "change_spk": rec.payer_spk,
                                 "hot_spk": hot_spk, "close_change": change["status"]}));
        Ok(json!({"verdict": "allow", "rail": "xbt402", "dest": dest, "txid": txid, "chan": rec.chan, "cum": rec.used_sats,
                  "change_spk": rec.payer_spk, "hot_spk": hot_spk, "change_to_hot": rec.payer_spk == hot_spk,
                  "close_change": change["status"], "close_report": report,
                  UNTRUSTED_KEY: untrusted(&preview(&r.body, body_cap()), Value::Null)}))
    }

    /// B2 `close_report` (AGP-029, agp-next3 `6090990`): the provider's (untrusted) close amounts, as
    /// integers only, checked against our own state. xbt402 v1.2: `cum` is the gross state we paid,
    /// `unpaidMsat` = spent - cum, and a payee-pays channel adds `payeeFee` (the provider's own close
    /// fee) and `payeeNet`. status: "ok" when the report matches what we signed and owes nothing;
    /// "debt" when the provider says we still owe; "mismatch" when its numbers disagree.
    pub fn close_report(reply: Option<&Value>, rec: &ChannelRecord) -> Value {
        let num = |k: &str| -> Option<i64> {
            match reply.and_then(|r| r.get(k)) {
                Some(Value::Number(n)) => n.as_i64().filter(|v| *v >= 0),
                Some(Value::String(s)) => s.trim().parse::<i64>().ok().filter(|v| *v >= 0),
                _ => None,
            }
        };
        let (cum, unpaid, fee, net) = (num("cum"), num("unpaidMsat"), num("payeeFee"), num("payeeNet"));
        let payee_pays = rec.close_fee_payer == "payee";
        let fee_ok = if payee_pays { fee == Some(rec.close_fee) && net == Some(cum.unwrap_or(0) - rec.close_fee) } else { fee.is_none() && net.is_none() };
        let status = if unpaid.is_some_and(|u| u != 0) {
            "debt"
        } else if cum != Some(rec.used_sats) || unpaid.is_none() || !fee_ok {
            "mismatch"
        } else {
            "ok"
        };
        let mut out = json!({"status": status, "cum": cum, "unpaid_msat": unpaid});
        if payee_pays {
            out["payee_fee"] = fee.into();
            out["payee_net"] = net.into();
        }
        out
    }
}

// --- stream verification (stream.py) ------------------------------------------------------------

fn h(b: &[u8]) -> [u8; 32] {
    sha256(b)
}

pub fn leaf(i: u32, chunk: &[u8]) -> [u8; 32] {
    let mut b = b"leaf".to_vec();
    b.extend(i.to_be_bytes());
    b.extend(h(chunk));
    h(&b)
}

fn node_hash(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut v = b"node".to_vec();
    v.extend(a);
    v.extend(b);
    h(&v)
}

pub fn verify_proof(root_hex: &str, i: i64, chunk: &[u8], proof: &Value) -> bool {
    let Ok(mut i) = u32::try_from(i) else { return false };
    let mut cur = leaf(i, chunk);
    for sib in proof.as_array().into_iter().flatten() {
        let Some(s) = sib.as_str().and_then(|x| hex::decode(x).ok()) else { return false };
        cur = if i % 2 == 0 { node_hash(&cur, &s) } else { node_hash(&s, &cur) };
        i /= 2;
    }
    hex::encode(cur) == root_hex
}

pub fn manifest_message(m: &Value) -> [u8; 32] {
    let keys = ["id", "n", "size", "root", "lock", "finalCt", "price", "payTo"];
    let s: Vec<String> = keys.iter().map(|k| py_str(m.get(*k))).collect();
    tagged_hash("xbt402/stream-manifest", s.join("|").as_bytes())
}

pub fn check_manifest(m: &Value, pay_to: &str) -> std::result::Result<(), String> {
    if m.get("payTo").and_then(Value::as_str) != Some(pay_to) {
        return Err("manifest not from this provider's payTo key".into());
    }
    let good = match (hex::decode(pay_to), m.get("sig").and_then(Value::as_str).and_then(|s| hex::decode(s).ok())) {
        (Ok(pk), Some(sig)) => ecdsa::verify(&pk, &manifest_message(m), &sig),
        _ => false,
    };
    if !good {
        return Err("bad manifest signature".into());
    }
    Ok(())
}

pub fn check_chunk(m: &Value, c: &Value) -> std::result::Result<Vec<u8>, String> {
    let i = py_int(c.get("i")).ok_or("chunk has no index")?;
    let n = py_int(m.get("n")).unwrap_or(0);
    if truthy(c.get("encrypted")) {
        if i != n - 1 {
            return Err(format!("chunk {i}: only the last chunk may be encrypted"));
        }
        let ct = c.get("ct").and_then(Value::as_str).and_then(|x| hex::decode(x).ok()).ok_or(format!("chunk {i}: ct"))?;
        if Some(hex::encode(h(&ct)).as_str()) != m.get("finalCt").and_then(Value::as_str) {
            return Err(format!("chunk {i}: ciphertext does not match the committed finalCt"));
        }
        return Ok(ct);
    }
    let data = c.get("data").and_then(Value::as_str).and_then(|x| hex::decode(x).ok()).ok_or(format!("chunk {i}: data"))?;
    if !verify_proof(m.get("root").and_then(Value::as_str).unwrap_or(""), i, &data, c.get("proof").unwrap_or(&Value::Null)) {
        return Err(format!("chunk {i}: Merkle proof fails against the committed root (tampered)"));
    }
    Ok(data)
}

pub fn open_final(m: &Value, ct: &[u8], key: &[u8]) -> std::result::Result<Vec<u8>, String> {
    if Some(hex::encode(h(ct)).as_str()) != m.get("finalCt").and_then(Value::as_str) {
        return Err("last chunk ciphertext does not match the committed finalCt".into());
    }
    if Some(hex::encode(h(key)).as_str()) != m.get("lock").and_then(Value::as_str) {
        return Err("revealed key does not match the hash lock".into());
    }
    let pt = encrypt(ct, key);
    if !verify_proof(m.get("root").and_then(Value::as_str).unwrap_or(""), py_int(m.get("n")).unwrap_or(0) - 1, &pt,
                     m.get("lastProof").unwrap_or(&Value::Null)) {
        return Err("decrypted last chunk fails the Merkle proof (provably bad commitment)".into());
    }
    Ok(pt)
}
