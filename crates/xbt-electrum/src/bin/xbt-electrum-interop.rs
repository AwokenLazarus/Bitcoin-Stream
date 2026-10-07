//! Regtest interop for the light backend (feature `interop`; run by `scripts/electrum_interop.sh`).
//!
//! A **light** Rust payer: its own hot key, and every chain read and broadcast through
//! [`ElectrumBackend`] (real electrs servers, one of them behind TLS). The node is only the faucet
//! (one payment to the hot key), the miner (blocks come from `generatetoaddress`) and the oracle:
//! every answer the payer acts on is compared with the node's own RPC.
//!
//!   xbt-electrum-interop pay     --url U [--calls N]       open, N paid calls, close, the close change counted late
//!   xbt-electrum-interop refund  --url U --kill-pid P      open, calls, the provider vanishes, refund at expiry
//!   xbt-electrum-interop tls-proxy --listen A --upstream B TLS (test certificate) in front of a TCP server
//! Common: --rpc-port R --cookie PATH --servers tcp://..,ssl://.. --ca PEM [--min-servers 2]
//! Prints one JSON line; exit 0 only if every check holds.
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use xbt402::channel::sign_p2wpkh;
use xbt402::client::{Client, ClientConfig, Wallet};
use xbt402::http::UreqTransport;
use xbt402::rpc::Rpc;
use xbt402::{ChannelError, Result};
use xbt_electrum::{Config, ElectrumBackend, TxStatus};
use xbt_primitives::address::segwit_address;
use xbt_primitives::ecdsa;
use xbt_primitives::hash::sha256;
use xbt_primitives::network::network_id;
use xbt_primitives::script::p2wpkh_spk;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::{OutPoint, Tx, TxIn, TxOut};

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

fn e(msg: impl std::fmt::Display) -> ChannelError {
    ChannelError::new("interop", msg.to_string())
}

const FUND_FEE: u64 = 500;

/// Answers of the light backend next to the node's, for the report.
struct Oracle {
    node: Rpc,
    light: Arc<ElectrumBackend>,
    rows: Vec<Value>,
}

impl Oracle {
    /// Compare `method(params)`; `keys` limits the comparison to those fields of an object answer.
    fn cmp(&mut self, method: &str, params: Value, keys: Option<&[&str]>) -> bool {
        let light = self.light.call(method, &params).map_err(|e| e.to_string());
        let node = self.node.call(method, params.clone()).map_err(|e| e.to_string());
        let pick = |v: &Value| match (keys, v) {
            (Some(k), Value::Object(m)) => Value::Object(k.iter().filter_map(|k| m.get(*k).map(|x| (k.to_string(), norm(x)))).collect()),
            _ => norm(v),
        };
        let equal = match (&light, &node) {
            // the fields asked for are all present on both sides, and each one we report is the node's
            (Ok(l), Ok(n)) => {
                let (l, n) = (pick(l), pick(n));
                let same_keys = match (&l, &n) {
                    (Value::Object(a), Value::Object(b)) => a.keys().eq(b.keys()) || keys.is_none(),
                    _ => true,
                };
                same_keys && covered(&l, &n)
            }
            (Err(_), Err(_)) => true,
            _ => false,
        };
        self.rows.push(json!({"method": method, "params": params, "equal": equal,
                              "light": light.as_ref().map(&pick).unwrap_or_else(|e| json!({"error": e})),
                              "node": node.as_ref().map(&pick).unwrap_or_else(|e| json!({"error": e}))}));
        equal
    }

    fn all_equal(&self) -> bool {
        self.rows.iter().all(|r| r["equal"] == true)
    }
}

/// Every field the light backend reports equals the node's (the node prints more: asm, types,
/// normalized descriptors). A `raw(...)` descriptor we echo is not compared with the node's `addr(...)#...`.
fn covered(light: &Value, node: &Value) -> bool {
    match (light, node) {
        (Value::Object(l), Value::Object(n)) => l.iter().all(|(k, v)| {
            (k == "desc" && v.as_str().map(|d| d.starts_with("raw(")).unwrap_or(false)) || n.get(k).map(|x| covered(v, x)).unwrap_or(false)
        }),
        (Value::Array(l), Value::Array(n)) => l.len() == n.len() && l.iter().zip(n).all(|(a, b)| covered(a, b)),
        (a, b) => a == b,
    }
}

/// Numbers compared as f64 (the node prints 0.50000000, we print 0.5).
fn norm(v: &Value) -> Value {
    match v {
        Value::Number(n) => json!(n.as_f64()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), norm(x))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(norm).collect()),
        x => x.clone(),
    }
}

/// The payer's hot key: coins found and spent through Electrum only.
struct LightWallet {
    light: Arc<ElectrumBackend>,
    miner: Rpc,
    secret: SecretKey,
    spk: Vec<u8>,
}

impl LightWallet {
    fn wait_confirmed(&self, txid: &str) -> Result<u32> {
        let t0 = Instant::now();
        loop {
            if let Some((_, TxStatus::Confirmed { height, .. })) = self.light.transaction(txid)? {
                return Ok(height);
            }
            if t0.elapsed() > Duration::from_secs(60) {
                return Err(e(format!("{txid} not proven confirmed through Electrum in 60 s")));
            }
            self.light.wait_for_change(Duration::from_millis(250));
        }
    }
}

fn mine(node: &Rpc, n: u32) -> Result<()> {
    let addr = node.call("getnewaddress", json!([]))?;
    node.call("generatetoaddress", json!([n, addr]))?;
    Ok(())
}

impl Wallet for LightWallet {
    /// Spend a hot coin (found by `listunspent` over Electrum, proven) to the channel, change back
    /// to the hot key, broadcast through Electrum, then wait for the proof of its confirmation.
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        let coins = self.light.unspent(&self.spk)?;
        let coin = coins.iter().filter(|c| c.value >= sats + FUND_FEE + 1_000).max_by_key(|c| c.value)
            .ok_or_else(|| e("no hot coin large enough"))?;
        let dest = xbt_primitives::address::address_to_spk(address, Some("bcrt"))?;
        let mut tx = Tx::new(2, vec![TxIn::new(OutPoint::from_display(&coin.txid, coin.vout)?, 0xFFFF_FFFD)],
                             vec![TxOut::new(sats as i64, dest), TxOut::new((coin.value - sats - FUND_FEE) as i64, self.spk.clone())], 0);
        sign_p2wpkh(&self.secret, &mut tx, &[TxOut::new(coin.value as i64, self.spk.clone())], 0)?;
        let txid = self.light.broadcast(&tx.to_hex())?;
        mine(&self.miner, 1)?;
        self.wait_confirmed(&txid)?;
        Ok((txid, 0))
    }
}

fn random_secret() -> SecretKey {
    let n = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let seed = sha256(format!("{n}:{}", std::process::id()).as_bytes());
    SecretKey::from_slice(&seed).expect("a valid scalar")
}

struct Rig {
    node: Rpc,
    wallet_rpc: Rpc,
    light: Arc<ElectrumBackend>,
    network: String,
    /// The first header sync (checkpoint 101 to the tip), over both servers.
    sync_ms: u64,
    synced: u32,
}

fn rig() -> Result<Rig> {
    let node = Rpc::from_cookie(&format!("http://127.0.0.1:{}", arg("--rpc-port").ok_or_else(|| e("--rpc-port"))?),
                                std::path::Path::new(&arg("--cookie").ok_or_else(|| e("--cookie"))?))?;
    let wallet_rpc = node.wallet("w");
    let servers = arg("--servers").ok_or_else(|| e("--servers"))?;
    let cp_hash = node.call("getblockhash", json!([101]))?.as_str().unwrap_or("").to_string();
    let mut cfg = Config::new(&servers.split(',').collect::<Vec<_>>(), "regtest");
    cfg.checkpoint = Some((101, cp_hash.clone()));
    cfg.min_servers = arg("--min-servers").map(|m| m.parse().expect("min-servers"));
    cfg.extra_ca = arg("--ca").into_iter().map(Into::into).collect();
    cfg.timeout = Duration::from_secs(20);
    let light = Arc::new(ElectrumBackend::new(cfg)?);
    // electrs must have indexed the node's chain
    let want = node.call("getblockcount", json!([]))?.as_u64().unwrap_or(0) as u32;
    let t0 = Instant::now();
    let _ = light.block_count(); // the first sync: every header from the checkpoint, verified
    let sync_ms = t0.elapsed().as_millis() as u64;
    while light.block_count().unwrap_or(0) < want {
        if t0.elapsed() > Duration::from_secs(180) {
            return Err(e(format!("Electrum did not reach height {want}: {}", light.status())));
        }
        light.wait_for_change(Duration::from_millis(250));
    }
    Ok(Rig { node, wallet_rpc, light, network: network_id(&cp_hash), sync_ms, synced: want })
}

/// Wait until the light backend's tip is the node's.
fn settle(r: &Rig) -> Result<u32> {
    let want = r.node.call("getblockcount", json!([]))?.as_u64().unwrap_or(0) as u32;
    let t0 = Instant::now();
    loop {
        let h = r.light.block_count()?;
        if h >= want {
            return Ok(h);
        }
        if t0.elapsed() > Duration::from_secs(60) {
            return Err(e(format!("light tip {h}, node {want}")));
        }
        r.light.wait_for_change(Duration::from_millis(250));
    }
}

/// A hot key funded by the faucet (the node wallet), the coin found through Electrum.
fn hot_wallet(r: &Rig, oracle: &mut Oracle) -> Result<LightWallet> {
    let secret = random_secret();
    let spk = p2wpkh_spk(&ecdsa::pubkey(&secret));
    let addr = segwit_address("bcrt", &spk)?;
    r.light.watch(&[&spk])?;
    let ftx = r.wallet_rpc.call("sendtoaddress", json!([addr, 0.01]))?.as_str().unwrap_or("").to_string();
    mine(&r.wallet_rpc, 1)?;
    settle(r)?;
    let w = LightWallet { light: r.light.clone(), miner: r.wallet_rpc.clone(), secret, spk: spk.clone() };
    w.wait_confirmed(&ftx)?;
    oracle.cmp("scantxoutset", json!(["start", [format!("raw({})", hex::encode(&spk))]]), Some(&["success", "height", "bestblock", "unspents", "total_amount"]));
    oracle.cmp("getrawtransaction", json!([ftx, false]), None);
    Ok(w)
}

fn common_checks(r: &Rig, oracle: &mut Oracle) -> Result<()> {
    let tip = settle(r)?;
    oracle.cmp("getblockcount", json!([]), None);
    for h in [101, 102, tip / 2, tip - 1, tip] {
        oracle.cmp("getblockhash", json!([h]), None);
    }
    let th = r.node.call("getblockhash", json!([tip]))?;
    oracle.cmp("getblockheader", json!([th, true]), Some(&["hash", "height", "confirmations", "time", "bits", "nTx", "merkleroot", "previousblockhash"]));
    oracle.cmp("getblockheader", json!([th, false]), None);
    oracle.cmp("getblockchaininfo", json!([]), Some(&["chain", "blocks", "bestblockhash"]));
    Ok(())
}

fn tx_checks(oracle: &mut Oracle, txid: &str, vouts: &[u32]) {
    oracle.cmp("getrawtransaction", json!([txid, false]), None);
    oracle.cmp("getrawtransaction", json!([txid, true]), Some(&["txid", "hex", "blockhash", "confirmations", "vin", "vout"]));
    for v in vouts {
        oracle.cmp("gettxout", json!([txid, v, true]), Some(&["bestblock", "confirmations", "value", "scriptPubKey", "coinbase"]));
        oracle.cmp("gettxout", json!([txid, v, false]), Some(&["bestblock", "confirmations", "value", "scriptPubKey", "coinbase"]));
    }
}

fn client(r: &Rig, w: LightWallet, expiry_blocks: Option<u32>) -> Client {
    let mut cfg = ClientConfig::new(&r.network);
    if let Some(x) = expiry_blocks {
        cfg.expiry_blocks = x;
    }
    let l = r.light.clone();
    Client::new(cfg, Box::new(UreqTransport::default()), Box::new(w), Box::new(move || Ok(l.block_count()?)))
}

/// open, calls, close; the close is seen in the mempool first (unproven: the funding still counts
/// as unspent), then its confirmation wakes the watcher and the change is counted.
fn pay(r: &Rig) -> Result<Value> {
    let url = arg("--url").ok_or_else(|| e("--url"))?;
    let calls: u32 = arg("--calls").map(|c| c.parse().expect("calls")).unwrap_or(10);
    let mut o = Oracle { node: r.node.clone(), light: r.light.clone(), rows: vec![] };
    common_checks(r, &mut o)?;
    let w = hot_wallet(r, &mut o)?;
    let hot_spk = w.spk.clone();
    let mut c = client(r, w, None);
    let mut statuses = vec![];
    for i in 0..calls {
        statuses.push(c.request("POST", &format!("{url}/v1/infer?i={i}"), format!("{{\"q\":{i}}}").as_bytes())?.status);
    }
    let ch = c.channels[&url].clone();
    let p = ch.payer.params.clone();
    let (fund_txid, fund_vout) = (p.funding_txid(), p.funding_vout());
    tx_checks(&mut o, &fund_txid, &[fund_vout, 1]);
    // the provider's funding check on this backend: what it would accept
    let funding_ok = xbt402::funding::check_funding(r.light.as_ref(), &p, &xbt402::funding::FundingPolicy { min_expiry_blocks: 1_008, close_margin: 144, ..Default::default() });
    r.light.watch(&[&p.spk(), &p.payer_spk])?;
    let close = c.close(&url)?;
    let signed = c.channels[&url].payer.signed;
    let close_txid = close["txid"].as_str().ok_or_else(|| e("no close txid"))?.to_string();

    // before any block: the close is a mempool fact, not proof
    let t0 = Instant::now();
    let mut hint = None;
    while hint.is_none() && t0.elapsed() < Duration::from_secs(20) {
        hint = r.light.spending_tx(&fund_txid, fund_vout)?;
        if hint.is_none() {
            r.light.wait_for_change(Duration::from_millis(250));
        }
    }
    let seen_in_mempool = hint == Some((close_txid.clone(), TxStatus::Mempool));
    let funding_still_unspent = r.light.tx_out(&fund_txid, fund_vout, true)?.is_some();
    let close_tx = r.light.transaction(&close_txid)?.ok_or_else(|| e("close tx not found through Electrum"))?.0;
    let change_vout = close_tx.outputs.iter().position(|x| x.script_pubkey == p.payer_spk).map(|v| v as u32);
    let change_before = change_vout.map(|v| r.light.tx_out(&close_txid, v, true)).transpose()?.flatten().map(|x| x.confirmations);
    o.cmp("gettxspendingprevout", json!([[{"txid": fund_txid, "vout": fund_vout}]]), None);
    o.cmp("gettxout", json!([fund_txid, fund_vout, false]), Some(&["bestblock", "confirmations", "value", "scriptPubKey"]));

    // a block: the subscription wakes us, the close is proven, the change counted
    let _ = r.light.wait_for_change(Duration::from_millis(1));
    mine(&r.wallet_rpc, 1)?;
    let woke = r.light.wait_for_change(Duration::from_secs(30));
    let t0 = Instant::now();
    let mut proven = None;
    while t0.elapsed() < Duration::from_secs(60) {
        if let Some((t, TxStatus::Confirmed { height, .. })) = r.light.spending_tx(&fund_txid, fund_vout)? {
            proven = Some((t, height));
            break;
        }
        r.light.wait_for_change(Duration::from_millis(250));
    }
    settle(r)?;
    let funding_spent = r.light.tx_out(&fund_txid, fund_vout, true)?.is_none();
    let change_after = change_vout.map(|v| r.light.tx_out(&close_txid, v, true)).transpose()?.flatten();
    let to = |spk: &[u8]| close_tx.outputs.iter().filter(|x| x.script_pubkey == spk).map(|x| x.value).sum::<i64>();
    let (payee_out, payer_out) = (to(&p.payee_spk), to(&p.payer_spk));
    let want_payer = (p.capacity - p.payer_fee() - signed) as i64;
    tx_checks(&mut o, &close_txid, &change_vout.into_iter().collect::<Vec<_>>());
    o.cmp("gettxout", json!([fund_txid, fund_vout, true]), None);
    o.cmp("gettxspendingprevout", json!([[{"txid": fund_txid, "vout": fund_vout}]]), None);
    o.cmp("scantxoutset", json!(["start", [format!("raw({})", hex::encode(&hot_spk))]]), Some(&["success", "height", "bestblock", "unspents", "total_amount"]));
    common_checks(r, &mut o)?;
    let checks = json!({
        "all_calls_200": statuses.iter().all(|s| *s == 200),
        "funding_acceptable_on_light_backend": funding_ok.is_ok(),
        "close_seen_in_mempool_as_hint": seen_in_mempool,
        "mempool_close_does_not_mark_funding_spent": funding_still_unspent,
        "change_unconfirmed_before_block": change_before == Some(0),
        "subscription_woke_on_block": woke,
        "close_proven_by_merkle": proven.as_ref().map(|x| x.0 == close_txid).unwrap_or(false),
        "funding_spent_after_proof": funding_spent,
        "late_change_counted": change_after.as_ref().map(|x| x.confirmations == 1 && x.value as i64 == want_payer).unwrap_or(false),
        "payee_output_exact": payee_out == p.payee_value(signed) as i64,
        "payer_output_exact": payer_out == want_payer,
        "fee_exact": p.capacity as i64 - payee_out - payer_out == p.close_fee as i64,
        "every_answer_matches_node": o.all_equal(),
        "no_verification_failures": r.light.flags().is_empty(),
    });
    let ok = checks.as_object().unwrap().values().all(|v| v == true);
    Ok(json!({"ok": ok, "scenario": "pay", "headerSyncMs": r.sync_ms, "headersSynced": r.synced - 101, "url": url, "chan": p.channel_id(), "closeFeePayer": p.close_fee_payer.as_str(),
              "capacity": p.capacity, "calls": calls, "finalCum": signed, "closeTxid": close_txid, "payeeOut": payee_out,
              "payerOut": payer_out, "checks": checks, "comparisons": o.rows.len(),
              "mismatches": o.rows.iter().filter(|r| r["equal"] != true).cloned().collect::<Vec<_>>(),
              "flags": r.light.flags().iter().map(|f| format!("{}: {}", f.server, f.reason)).collect::<Vec<_>>(),
              "servers": r.light.status()["servers"]}))
}

/// open, calls; the provider vanishes (killed) and never closes; at expiry the payer's presigned
/// refund goes out through Electrum and is proven.
fn refund(r: &Rig) -> Result<Value> {
    let url = arg("--url").ok_or_else(|| e("--url"))?;
    let pid = arg("--kill-pid").ok_or_else(|| e("--kill-pid"))?;
    let mut o = Oracle { node: r.node.clone(), light: r.light.clone(), rows: vec![] };
    let w = hot_wallet(r, &mut o)?;
    let mut c = client(r, w, Some(1_008));
    let mut statuses = vec![];
    for i in 0..3 {
        statuses.push(c.request("POST", &format!("{url}/v1/infer?r={i}"), b"{}")?.status);
    }
    let ch = c.channels[&url].clone();
    let p = ch.payer.params.clone();
    let (fund_txid, fund_vout) = (p.funding_txid(), p.funding_vout());
    let killed = std::process::Command::new("kill").arg(&pid).status().map(|s| s.success()).unwrap_or(false);
    std::thread::sleep(Duration::from_millis(500));
    let refund_tx = Tx::parse_hex(&ch.refund_hex)?;
    let early = r.light.broadcast(&ch.refund_hex);
    let tip = settle(r)?;
    mine(&r.wallet_rpc, p.expiry - tip)?;
    let at = settle(r)?;
    let funding_unspent_at_expiry = r.light.tx_out(&fund_txid, fund_vout, true)?.is_some();
    o.cmp("gettxout", json!([fund_txid, fund_vout, true]), Some(&["bestblock", "confirmations", "value", "scriptPubKey", "coinbase"]));
    let rtxid = r.light.broadcast(&ch.refund_hex);
    mine(&r.wallet_rpc, 1)?;
    settle(r)?;
    let proven = r.light.transaction(&refund_tx.txid())?.map(|x| x.1);
    let out = r.light.tx_out(&refund_tx.txid(), 0, true)?;
    tx_checks(&mut o, &refund_tx.txid(), &[0]);
    o.cmp("gettxout", json!([fund_txid, fund_vout, true]), None);
    o.cmp("gettxspendingprevout", json!([[{"txid": fund_txid, "vout": fund_vout}]]), None);
    common_checks(r, &mut o)?;
    let want = (p.capacity - p.close_fee) as u64;
    let checks = json!({
        "calls_200": statuses.iter().all(|s| *s == 200),
        "provider_gone": killed,
        "early_refund_refused_by_the_network": early.is_err(),
        "funding_unspent_at_expiry": funding_unspent_at_expiry,
        "refund_broadcast_via_electrum": rtxid.as_deref().ok() == Some(refund_tx.txid().as_str()),
        "refund_proven_by_merkle": matches!(proven, Some(TxStatus::Confirmed { height, .. }) if height == at + 1),
        "refund_output_exact": out.as_ref().map(|x| x.value == want && x.script_pubkey == p.payer_spk && x.confirmations == 1).unwrap_or(false),
        "funding_spent": r.light.tx_out(&fund_txid, fund_vout, true)?.is_none(),
        "every_answer_matches_node": o.all_equal(),
        "no_verification_failures": r.light.flags().is_empty(),
    });
    let ok = checks.as_object().unwrap().values().all(|v| v == true);
    Ok(json!({"ok": ok, "scenario": "refund", "headerSyncMs": r.sync_ms, "headersSynced": r.synced - 101, "url": url, "chan": p.channel_id(), "expiry": p.expiry, "capacity": p.capacity,
              "refundTxid": refund_tx.txid(), "refundSats": want, "earlyError": early.err().map(|x| x.to_string()),
              "checks": checks, "comparisons": o.rows.len(),
              "mismatches": o.rows.iter().filter(|r| r["equal"] != true).cloned().collect::<Vec<_>>(),
              "flags": r.light.flags().iter().map(|f| format!("{}: {}", f.server, f.reason)).collect::<Vec<_>>()}))
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode == "tls-proxy" {
        let up = arg("--upstream").expect("--upstream").parse().expect("upstream addr");
        let p = xbt_electrum::sim::TlsProxy::start(&arg("--listen").expect("--listen"), up).expect("listen");
        eprintln!("tls-proxy ready on {} -> {up}", p.addr);
        loop {
            std::thread::park();
        }
    }
    let r = rig().and_then(|r| match mode.as_str() {
        "pay" => pay(&r),
        "refund" => refund(&r),
        m => Err(e(format!("unknown mode {m:?}"))),
    });
    match r {
        Ok(v) => {
            println!("{v}");
            std::process::exit(if v["ok"] == true { 0 } else { 1 });
        }
        Err(err) => {
            println!("{}", json!({"ok": false, "scenario": mode, "error": err.to_string()}));
            std::process::exit(1);
        }
    }
}
