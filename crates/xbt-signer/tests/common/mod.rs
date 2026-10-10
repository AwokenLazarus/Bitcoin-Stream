//! Test rig: a fake pruned node (B2 `tests/_agp017.py` `PrunedChain`: blocks, confirmations, no
//! txindex) that is both the signer's `Node` and the Rust provider's `ChainBackend`, an in-process
//! transport to `xbt402::provider::Provider`, and a signer root builder.
#![allow(dead_code)]
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{json, Value};
use xbt402::client::{split_url, Transport};
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::{ChannelError, Result};
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;
use xbt_signer::node::Node;
use xbt_signer::signer::{Signer, SignerOptions};

pub const MAIN_961640: &str = "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb";

#[derive(Default)]
pub struct State {
    pub chain: String,
    pub height: u64,
    pub mempool: HashMap<String, Value>,
    pub blocks: HashMap<u64, Vec<Value>>,
    pub conf_height: HashMap<String, u64>,
    pub utxos: HashMap<(String, u32), (i64, String)>,
    pub spent_by: HashMap<(String, u32), String>,
    pub sent: Vec<String>,
    pub calls: Vec<String>,
    pub reject: Option<String>,
    pub mined_by_signer: u64,
    pub down: bool,
    pub coinbase: std::collections::HashSet<String>,
    /// `getdeploymentinfo`; None: the node does not answer it.
    pub deployments: Option<Value>,
}

pub struct FakeChain {
    pub st: Mutex<State>,
    pub allow_generate: AtomicBool,
}

fn rpc_err(m: &str) -> ChannelError {
    ChannelError::new("rpc_error", m.to_string())
}

impl FakeChain {
    pub fn new(chain: &str, height: u64) -> Arc<Self> {
        Arc::new(Self { st: Mutex::new(State { chain: chain.into(), height, ..Default::default() }), allow_generate: AtomicBool::new(false) })
    }

    pub fn bhash(chain: &str, h: u64) -> String {
        if chain == "main" && h == 961_640 { MAIN_961640.into() } else { format!("{h:064x}") }
    }

    pub fn network(&self) -> String {
        let c = self.st.lock().unwrap().chain.clone();
        xbt_primitives::network::network_id(&Self::bhash(&c, if c == "main" { 961_640 } else { 101 }))
    }

    /// An outside coin (a faucet send) to `spk`.
    pub fn credit(&self, txid: &str, vout: u32, sats: i64, spk: &str, confirmed: bool) {
        let mut s = self.st.lock().unwrap();
        let mut outs: Vec<Value> = (0..vout).map(|n| json!({"n": n, "value": 0, "scriptPubKey": {"hex": ""}})).collect();
        outs.push(json!({"n": vout, "value": sats as f64 / 1e8, "scriptPubKey": {"hex": spk}}));
        let tx = json!({"txid": txid, "hex": "", "vin": [{"txid": "ee".repeat(32), "vout": 0}], "vout": outs});
        s.utxos.insert((txid.into(), vout), (sats, spk.into()));
        if confirmed {
            let h = s.height;
            s.blocks.entry(h).or_default().push(tx);
            s.conf_height.insert(txid.into(), h);
        } else {
            s.mempool.insert(txid.into(), tx);
        }
    }

    /// A coinbase paying `sats` to `spk`, in a block at the current height.
    pub fn credit_coinbase(&self, txid: &str, vout: u32, sats: i64, spk: &str) {
        let mut s = self.st.lock().unwrap();
        let mut outs: Vec<Value> = (0..vout).map(|n| json!({"n": n, "value": 0, "scriptPubKey": {"hex": ""}})).collect();
        outs.push(json!({"n": vout, "value": sats as f64 / 1e8, "scriptPubKey": {"hex": spk}}));
        let tx = json!({"txid": txid, "hex": "", "vin": [{"coinbase": "03c80000", "sequence": 4294967295u32}], "vout": outs});
        let h = s.height;
        s.utxos.insert((txid.into(), vout), (sats, spk.into()));
        s.blocks.entry(h).or_default().push(tx);
        s.conf_height.insert(txid.into(), h);
        s.coinbase.insert(txid.into());
    }

    pub fn mine(&self, n: u64) {
        let mut s = self.st.lock().unwrap();
        for _ in 0..n {
            s.height += 1;
            let h = s.height;
            let txs: Vec<Value> = s.mempool.drain().map(|(_, v)| v).collect();
            for t in &txs {
                let id = t["txid"].as_str().unwrap().to_string();
                s.conf_height.insert(id, h);
            }
            s.blocks.insert(h, txs);
        }
    }

    pub fn height(&self) -> u64 {
        self.st.lock().unwrap().height
    }

    pub fn mine_to(&self, h: u64) {
        let cur = self.height();
        if h > cur {
            self.mine(h - cur);
        }
    }

    pub fn mempool(&self) -> Vec<String> {
        self.st.lock().unwrap().mempool.keys().cloned().collect()
    }

    pub fn sent_txs(&self) -> Vec<Tx> {
        self.st.lock().unwrap().sent.iter().map(|h| Tx::parse_hex(h).unwrap()).collect()
    }

    pub fn tx(&self, txid: &str) -> Tx {
        self.sent_txs().into_iter().find(|t| t.txid() == txid).expect("tx sent")
    }

    pub fn unspent_to(&self, spk: &str) -> i64 {
        self.st.lock().unwrap().utxos.values().filter(|(_, s)| s == spk).map(|(v, _)| *v).sum()
    }

    fn send(&self, raw: &str) -> Result<String> {
        let mut s = self.st.lock().unwrap();
        if let Some(r) = s.reject.clone() {
            return Err(rpc_err(&r));
        }
        let tx = Tx::parse_hex(raw).map_err(|_| rpc_err("TX decode failed"))?;
        let txid = tx.txid();
        if s.mempool.contains_key(&txid) || s.conf_height.contains_key(&txid) {
            return Err(rpc_err("txn-already-known"));
        }
        if tx.locktime > 0 && tx.locktime < 500_000_000 && tx.locktime as u64 > s.height {
            return Err(rpc_err("non-final"));
        }
        for i in &tx.inputs {
            if !s.utxos.contains_key(&(i.prevout.txid_hex(), i.prevout.vout)) {
                return Err(rpc_err("bad-txns-inputs-missingorspent"));
            }
        }
        for i in &tx.inputs {
            let op = (i.prevout.txid_hex(), i.prevout.vout);
            s.utxos.remove(&op);
            s.spent_by.insert(op, txid.clone());
        }
        for (n, o) in tx.outputs.iter().enumerate() {
            s.utxos.insert((txid.clone(), n as u32), (o.value, hex::encode(&o.script_pubkey)));
        }
        let vin: Vec<Value> = tx.inputs.iter().map(|i| json!({"txid": i.prevout.txid_hex(), "vout": i.prevout.vout,
            "txinwitness": i.witness.iter().map(hex::encode).collect::<Vec<_>>()})).collect();
        let vout: Vec<Value> = tx.outputs.iter().enumerate().map(|(n, o)| json!({"n": n, "value": o.value as f64 / 1e8,
            "scriptPubKey": {"hex": hex::encode(&o.script_pubkey)}})).collect();
        s.mempool.insert(txid.clone(), json!({"txid": txid, "hex": raw, "locktime": tx.locktime, "vin": vin, "vout": vout}));
        s.sent.push(raw.into());
        Ok(txid)
    }

    fn gettxout(&self, txid: &str, vout: u32, mem: bool) -> Value {
        let s = self.st.lock().unwrap();
        let Some((v, spk)) = s.utxos.get(&(txid.into(), vout)).cloned() else { return Value::Null };
        let confs = if s.mempool.contains_key(txid) {
            if !mem {
                return Value::Null;
            }
            0
        } else {
            s.height - s.conf_height.get(txid).copied().unwrap_or(s.height) + 1
        };
        json!({"bestblock": Self::bhash(&s.chain, s.height), "confirmations": confs, "value": v as f64 / 1e8,
               "scriptPubKey": {"hex": spk}, "coinbase": s.coinbase.contains(txid)})
    }
}

fn hash_height(h: &str) -> u64 {
    if h == MAIN_961640 { 961_640 } else { u64::from_str_radix(h, 16).unwrap_or(0) }
}

impl Node for FakeChain {
    fn call(&self, method: &str, p: Value) -> Result<Value> {
        let p = p.as_array().cloned().unwrap_or_default();
        {
            let mut s = self.st.lock().unwrap();
            s.calls.push(method.into());
            if s.down {
                return Err(rpc_err("connection refused"));
            }
        }
        let chain = self.st.lock().unwrap().chain.clone();
        Ok(match method {
            "getblockchaininfo" => {
                let s = self.st.lock().unwrap();
                json!({"chain": s.chain, "blocks": s.height, "initialblockdownload": false, "pruned": true})
            }
            "getblockcount" => json!(self.height()),
            "getblockhash" => {
                let h = p[0].as_u64().unwrap_or(0);
                if h > self.height() {
                    return Err(rpc_err("Block height out of range"));
                }
                json!(Self::bhash(&chain, h))
            }
            "getblockheader" => json!({"height": hash_height(p[0].as_str().unwrap_or(""))}),
            "getblock" => {
                let h = hash_height(p[0].as_str().unwrap_or(""));
                json!({"height": h, "tx": self.st.lock().unwrap().blocks.get(&h).cloned().unwrap_or_default()})
            }
            "sendrawtransaction" => json!(self.send(p[0].as_str().unwrap_or(""))?),
            "gettxout" => self.gettxout(p[0].as_str().unwrap_or(""), p[1].as_u64().unwrap_or(0) as u32, p.get(2).and_then(Value::as_bool).unwrap_or(true)),
            "getrawtransaction" => {
                let txid = p[0].as_str().unwrap_or("");
                let s = self.st.lock().unwrap();
                if let Some(t) = s.mempool.get(txid) {
                    return Ok(t.clone());
                }
                if let Some(bh) = p.get(2).and_then(Value::as_str) {
                    if let Some(t) = s.blocks.get(&hash_height(bh)).and_then(|b| b.iter().find(|t| t["txid"] == txid)) {
                        return Ok(t.clone());
                    }
                }
                return Err(rpc_err("No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries."));
            }
            "gettxspendingprevout" => {
                let s = self.st.lock().unwrap();
                let out: Vec<Value> = p[0].as_array().cloned().unwrap_or_default().into_iter().map(|o| {
                    let op = (o["txid"].as_str().unwrap_or("").to_string(), o["vout"].as_u64().unwrap_or(0) as u32);
                    let mut r = o.clone();
                    if let Some(sp) = s.spent_by.get(&op).filter(|sp| s.mempool.contains_key(*sp)) {
                        r["spendingtxid"] = sp.clone().into();
                    }
                    r
                }).collect();
                json!(out)
            }
            "scantxoutset" => {
                let want: Vec<String> = p[1].as_array().cloned().unwrap_or_default().iter()
                    .filter_map(|d| d.as_str().and_then(|d| d.strip_prefix("raw(")).and_then(|d| d.strip_suffix(')')).map(str::to_string)).collect();
                let s = self.st.lock().unwrap();
                let u: Vec<Value> = s.utxos.iter().filter(|((t, _), (_, spk))| want.contains(spk) && !s.mempool.contains_key(t))
                    .map(|((t, v), (a, spk))| json!({"txid": t, "vout": v, "scriptPubKey": spk, "amount": *a as f64 / 1e8,
                                                     "coinbase": s.coinbase.contains(t), "height": s.conf_height.get(t)})).collect();
                json!({"success": true, "unspents": u})
            }
            "getnewaddress" => json!("bcrt1qmine"),
            "generatetoaddress" => {
                assert_eq!(chain, "regtest", "generatetoaddress off regtest");
                assert!(self.allow_generate.load(Ordering::SeqCst), "generate without the P3 guard");
                let n = p[0].as_u64().unwrap_or(1);
                self.st.lock().unwrap().mined_by_signer += n;
                self.mine(n);
                json!([])
            }
            "getbalances" => json!({"mine": {"trusted": 0, "untrusted_pending": 0, "immature": 0}}),
            "getdeploymentinfo" => {
                let d = self.st.lock().unwrap().deployments.clone();
                d.ok_or_else(|| rpc_err("Method not found"))?
            }
            "estimatesmartfee" => json!({"feerate": 0.00001}),
            other => panic!("FakeChain: unexpected {other} {p:?}"),
        })
    }

    fn set_allow_generate(&self, allow: bool) {
        self.allow_generate.store(allow, Ordering::SeqCst);
    }

    fn wallet(&self) -> String {
        "agent".into()
    }
}

/// The provider's view of the same node.
pub struct ProviderChain(pub Arc<FakeChain>);

impl ChainBackend for ProviderChain {
    fn block_count(&self) -> Result<u32> {
        Ok(self.0.height() as u32)
    }
    fn get_tx_out(&self, txid: &str, vout: u32, mem: bool) -> Result<Option<UtxoInfo>> {
        let v = self.0.gettxout(txid, vout, mem);
        if v.is_null() {
            return Ok(None);
        }
        Ok(Some(UtxoInfo { confirmations: v["confirmations"].as_u64().unwrap_or(0) as u32, value: (v["value"].as_f64().unwrap() * 1e8).round() as u64,
                           script_pubkey: hex::decode(v["scriptPubKey"]["hex"].as_str().unwrap()).unwrap(), coinbase: false }))
    }
    fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        self.0.send(hex)
    }
    fn has_transaction(&self, txid: &str) -> Result<bool> {
        let s = self.0.st.lock().unwrap();
        Ok(s.mempool.contains_key(txid) || s.conf_height.contains_key(txid))
    }
}

/// In-process HTTP to one or more providers keyed by origin; `down` makes it unreachable.
#[derive(Default)]
pub struct Web {
    pub sites: Mutex<HashMap<String, Arc<Provider>>>,
    pub down: AtomicBool,
    /// Fail paid requests (with PAYMENT-SIGNATURE) before the provider sees them.
    pub fail_paid: AtomicBool,
    pub requests: Mutex<Vec<(String, String)>>,
}

impl Transport for Web {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        if self.down.load(Ordering::SeqCst) {
            return Err(ChannelError::new("transport_error", "connection refused"));
        }
        if self.fail_paid.load(Ordering::SeqCst) && headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-SIGNATURE")) {
            return Err(ChannelError::new("transport_error", "connection reset"));
        }
        let (origin, path) = split_url(url);
        self.requests.lock().unwrap().push((method.into(), url.into()));
        let p = self.sites.lock().unwrap().get(&origin).cloned().ok_or_else(|| ChannelError::new("transport_error", "no such host"))?;
        Ok(p.serve(method, &path, headers, body, url, None))
    }
}

pub const PROVIDER: &str = "http://127.0.0.1:33210";
pub const URL: &str = "http://127.0.0.1:33210/agp015/echo";

pub fn secret(label: &str) -> SecretKey {
    SecretKey::from_slice(&sha256(label.as_bytes())).unwrap()
}

/// The runbook's provider: 500 sat per call, 10,000 sat funding only, closeFee 600, 1,008 blocks.
pub fn runbook_provider(chain: &Arc<FakeChain>, ledger: Ledger) -> Arc<Provider> {
    let mut cfg = ProviderConfig::new(&chain.network());
    cfg.policy.min_capacity = 10_000;
    cfg.policy.max_capacity = 10_000;
    cfg.policy.min_expiry_blocks = 1_008;
    cfg.policy.min_conf = 1;
    Arc::new(Provider::new(Arc::new(ProviderChain(chain.clone())), secret("provider payTo"), cfg, ledger, Box::new(|_, _| 500),
                           Box::new(|_, p, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())],
                                                                  json!({"echo": p}).to_string().into_bytes()))).unwrap())
}

/// The human's device key.
pub fn human() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

pub fn sign_human(msg: &[u8]) -> String {
    hex::encode(human().sign(msg).to_bytes())
}

/// The runbook's policy (AGP-017 rehearsal G1).
pub fn runbook_policy(extra: Value) -> Value {
    let mut p = json!({"allowlist": [PROVIDER], "max_per_tx_sats": 1000, "daily_budget_sats": 6000, "weekly_budget_sats": 6000,
                       "per_counterparty_cap_sats": 9400, "velocity_max": 20, "velocity_window_s": 3600, "human_threshold_sats": 1000,
                       "channel_expiry_blocks": 1008, "refund_enabled": true, "refund_margin_blocks": 6, "hot_balance_cap_sats": 15000,
                       "human_pubkey": hex::encode(human().verifying_key().to_bytes()), "split_window_s": 0, "regtest_mine": false,
                       "anchor_interval_s": 5, "open_wait_s": 0, "open_retry_s": 0});
    if let (Value::Object(a), Value::Object(b)) = (&mut p, extra) {
        for (k, v) in b {
            a.insert(k, v);
        }
    }
    p
}

/// A signer root with `policy`; the wrapping key file outside it.
pub fn root_with(dir: &Path, policy: &Value) -> PathBuf {
    let root = dir.join("wallet");
    std::fs::create_dir_all(root.join(".run")).unwrap();
    std::fs::write(root.join("policy.json"), policy.to_string()).unwrap();
    root
}

/// Serializes the tests that set process environment variables.
pub static ENV: Mutex<()> = Mutex::new(());

pub fn env_for(dir: &Path) {
    std::env::set_var("B2_HOT_KEYFILE", dir.join("keys").join("hot.key"));
    std::env::remove_var("B2_HOT_PASSPHRASE");
    std::env::remove_var("B2_ANCHOR_SOCK");
    std::env::remove_var("B2_CHAIN");
    std::env::remove_var("B2_HOT_ALLOW_PLAINTEXT");
    std::env::remove_var("B2_CHAIN_BACKEND");
    std::env::set_var("B2_WATCH_INTERVAL", "0");
}

pub fn signer(root: &Path, chain: &Arc<FakeChain>, web: &Arc<Web>, anchor: Option<xbt_signer::anchor::AnchorClient>) -> xbt402::Result<Arc<Signer>> {
    Signer::new(root, SignerOptions { node: Some(chain.clone()), transport: Some(web.clone()), anchor, ..Default::default() })
}

pub fn call(s: &Signer, m: &str, p: Value) -> Value {
    s.handle(m, &p).unwrap_or_else(|e| panic!("{m}: {}: {}", e.code, e.msg))
}

/// One signer with the runbook provider on a fake pruned node.
pub struct Rig {
    pub dir: tempfile::TempDir,
    pub root: PathBuf,
    pub chain: Arc<FakeChain>,
    pub web: Arc<Web>,
    pub prov: Arc<Provider>,
    pub s: Arc<Signer>,
    pub witness: Option<xbt_signer::anchor::Witness>,
    pub adaptor: Option<Arc<dyn xbt_signer::channels::AdaptorScheme>>,
}

impl Rig {
    /// Hold `ENV` for the whole test (the signer reads its environment).
    pub fn new(policy_extra: Value, with_witness: bool) -> Self {
        Self::build(policy_extra, with_witness, "regtest", None)
    }

    pub fn build(policy_extra: Value, with_witness: bool, chain_name: &str, adaptor: Option<Arc<dyn xbt_signer::channels::AdaptorScheme>>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        env_for(dir.path());
        let chain = FakeChain::new(chain_name, if chain_name == "main" { 962_000 } else { 6_720 });
        let web = Arc::new(Web::default());
        let prov = runbook_provider(&chain, Ledger::in_memory());
        web.sites.lock().unwrap().insert(PROVIDER.into(), prov.clone());
        let witness = with_witness.then(|| xbt_signer::anchor::serve_witness(&dir.path().join("anchor"), &dir.path().join("anchor/w.sock"), 0o600).unwrap());
        let root = root_with(dir.path(), &runbook_policy(policy_extra));
        let ac = witness.as_ref().map(|w| xbt_signer::anchor::AnchorClient::new(&w.sock_path));
        let s = Signer::new(&root, SignerOptions { node: Some(chain.clone()), transport: Some(web.clone()), anchor: ac, adaptor: adaptor.clone(),
                                                   ..Default::default() }).unwrap();
        Self { dir, root, chain, web, prov, s, witness, adaptor }
    }

    /// A fresh signer process on the same root (a restart).
    pub fn restart(&mut self) -> xbt402::Result<()> {
        let ac = self.witness.as_ref().map(|w| xbt_signer::anchor::AnchorClient::new(&w.sock_path));
        self.s = Signer::new(&self.root, SignerOptions { node: Some(self.chain.clone()), transport: Some(self.web.clone()), anchor: ac,
                                                         adaptor: self.adaptor.clone(), ..Default::default() })?;
        Ok(())
    }

    pub fn call(&self, m: &str, p: Value) -> Value {
        call(&self.s, m, p)
    }

    /// The hot-key rotation the human signs (AGP-063 W3: `rotate_hot_key` is never unsigned).
    pub fn rotate_hot_key(&self) -> Value {
        let old = self.call("hot_address", json!({}))["hot_address"].as_str().unwrap().to_string();
        let exp = xbt_signer::pyjson::now_f64() as i64 + 300;
        self.call("rotate_hot_key", json!({"expiry": exp, "signature": sign_human(&xbt_signer::approval::rotate_message(&old, exp))}))
    }

    pub fn hot_spk(&self) -> String {
        self.call("hot_address", json!({}))["hot_spk"].as_str().unwrap().to_string()
    }

    pub fn hot_sats(&self) -> i64 {
        self.call("hot_address", json!({}))["hot_sats"].as_i64().unwrap()
    }

    /// A confirmed coin to the hot key, noticed.
    pub fn fund_hot(&self, tag: u8, sats: i64) -> String {
        let txid = hex::encode([tag; 32]);
        self.chain.credit(&txid, 0, sats, &self.hot_spk(), true);
        self.call("notice_hot_txid", json!({"txid": txid}));
        txid
    }

    pub fn pay(&self) -> Value {
        self.call("xbt402_pay", json!({"url": URL, "method": "GET", "body": "", "max_sats": 500}))
    }

    /// Fund, confirm, open and pay the first call.
    pub fn open(&self) -> Value {
        let r = self.pay();
        assert_eq!(r["verdict"], "pending", "{r}");
        self.chain.mine(1);
        let r = self.pay();
        assert_eq!(r["verdict"], "allow", "{r}");
        r
    }

    pub fn channel(&self, chan: &str) -> Value {
        self.call("channels", json!({}))["channels"].as_array().unwrap().iter().find(|c| c["chan"] == chan).cloned().unwrap()
    }

    pub fn sigs(&self) -> Vec<Value> {
        self.call("signatures", json!({"limit": 1000}))["signatures"].as_array().unwrap().clone()
    }
}

/// A TEST DOUBLE of the ECDSA adaptor scheme (the real one is B1 adaptor.py, ported by AGP-026):
/// the "pre-signature" commits to T1, and a "completed signature" is the 32-byte secret y itself,
/// so extract works exactly when y·G = T1. It exercises the book's write-ahead, recovery and the
/// routing policy, not the cryptography.
pub struct TestAdaptor;

impl xbt_signer::channels::AdaptorScheme for TestAdaptor {
    fn presign(&self, _secret: &SecretKey, z: &[u8; 32], t1: &xbt_primitives::secp256k1::PublicKey) -> Result<Value> {
        Ok(json!({"R": hex::encode(t1.serialize()), "R1": hex::encode(t1.serialize()), "s1": hex::encode(z), "c": "00".repeat(32), "z": "00".repeat(32)}))
    }
    fn extract(&self, _pre: &Value, sig: &[u8], t1: &xbt_primitives::secp256k1::PublicKey) -> Option<[u8; 32]> {
        let y: [u8; 32] = sig.try_into().ok()?;
        (xbt_signer::channels::point_of(&y).as_ref() == Some(t1)).then_some(y)
    }
}
