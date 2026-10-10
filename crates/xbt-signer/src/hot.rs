//! The signer-owned secp256k1 hot key (B2 `hot.py`). Every spend is signed SIGHASH_ALL|UNIFIED
//! (0x21) by the signer itself.
//!
//! Custody (AGP-013/016/017), with B2's file formats:
//! * `hot.json` holds the current and retired keys, AES-256-GCM sealed (AAD `b2/hot-key`);
//! * `hot_utxos.json` holds the hot coins, sealed (AAD `b2/hot-utxos`), rewritten on every change and
//!   reconciled against the node at start (`gettxout`, `scantxoutset`);
//! * [`HotWallet::rotate`] makes a new key and sweeps the old one's coins into it; retired keys stay
//!   sealed so later coins to them are swept by the watcher;
//! * a balance cap refuses new channels until a human sweeps ([`HotWallet::sweep_to`]);
//! * [`HotWallet::prepare_fund`] / [`HotWallet::broadcast`] / [`HotWallet::commit`] split a funding
//!   so the caller can seal what it needs before the broadcast (P1);
//! * [`HotWallet::learn_close_change`] counts a close's change exactly once (AGP-022).
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use serde_json::{json, Map, Value};
use xbt_primitives::address::segwit_address;
use xbt_primitives::ecdsa::{self, PubkeyBytes};
use xbt_primitives::script::{p2wpkh_script_code, p2wpkh_spk};
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::sighash::{unified_sighash, ScriptType, SIGHASH_ALL_UNIFIED};
use xbt_primitives::tx::{OutPoint, Tx, TxIn, TxOut};

use xbt402::maturity::Maturity;

use crate::keystore::{write_private, KeyStore};
use crate::node::{self, sats, Node};
use crate::pyjson::{dumps, dumps_indent, now_f64, py_int};
use crate::sigaudit::SigAudit;
use crate::{err, Result};

pub const DEFAULT_FEE: i64 = 600;
pub const SWEEP_FEE_BASE: i64 = 200;
pub const SWEEP_FEE_PER_INPUT: i64 = 100;
pub const DUST: i64 = 546;
pub const AAD: &str = "b2/hot-key";
pub const UTXO_AAD: &str = "b2/hot-utxos";
pub const MAX_STALE: usize = 500;
pub const CLOSE_MAX_OUTPUTS: u32 = 4;
pub const CLOSE_SCAN_MAX: u64 = 144;
/// B1's default input sequence (RBF-signalling).
pub const SEQUENCE: u32 = 0xFFFF_FFFD;

#[derive(Clone)]
pub struct HotKey {
    secret: SecretKey,
    pub pubkey: PubkeyBytes,
    pub spk: Vec<u8>,
    pub address: String,
    pub retired_at: f64,
}

impl HotKey {
    pub fn new(secret: SecretKey, hrp: &str, retired_at: f64) -> Result<Self> {
        let pubkey = ecdsa::pubkey(&secret);
        let spk = p2wpkh_spk(&pubkey);
        let address = segwit_address(hrp, &spk)?;
        Ok(Self { secret, pubkey, spk, address, retired_at })
    }

    pub fn spk_hex(&self) -> String {
        hex::encode(&self.spk)
    }
}

/// One hot coin (`{"txid", "vout", "value", "spk", "why"?, "coinbase"?, "height"?}`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Coin {
    pub txid: String,
    pub vout: u32,
    pub value: i64,
    pub spk: String,
    pub why: String,
    /// A coinbase output: spendable only once the node's coinbase maturity allows ([`HotWallet::spendable`]).
    pub coinbase: bool,
    /// The block a coinbase coin is in; None when the node did not say (the coin then waits).
    pub height: Option<u32>,
}

impl Coin {
    fn from_value(u: &Value) -> Result<Self> {
        Ok(Self {
            txid: u.get("txid").and_then(Value::as_str).ok_or_else(|| err("hot", "coin txid"))?.into(),
            vout: py_int(u.get("vout")).ok_or_else(|| err("hot", "coin vout"))? as u32,
            value: py_int(u.get("value")).ok_or_else(|| err("hot", "coin value"))?,
            spk: u.get("spk").and_then(Value::as_str).unwrap_or("").into(),
            why: u.get("why").and_then(Value::as_str).unwrap_or("").into(),
            coinbase: crate::pyjson::truthy(u.get("coinbase")),
            height: py_int(u.get("height")).and_then(|h| u32::try_from(h).ok()),
        })
    }

    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("txid".into(), self.txid.clone().into());
        m.insert("vout".into(), self.vout.into());
        m.insert("value".into(), self.value.into());
        m.insert("spk".into(), self.spk.clone().into());
        if !self.why.is_empty() {
            m.insert("why".into(), self.why.clone().into());
        }
        if self.coinbase {
            m.insert("coinbase".into(), true.into());
            if let Some(h) = self.height {
                m.insert("height".into(), h.into());
            }
        }
        Value::Object(m)
    }

    fn op(&self) -> (String, u32) {
        (self.txid.clone(), self.vout)
    }
}

/// A built and 0x21-signed transaction, not yet broadcast.
#[derive(Debug, Clone)]
pub struct Prep {
    pub hex: String,
    pub txid: String,
    pub inputs: Vec<(String, u32)>,
    pub outputs: Vec<(i64, String)>,
}

struct Inner {
    current: HotKey,
    retired: Vec<HotKey>,
    utxos: Vec<Coin>,
    stale: Vec<Coin>,
    last_reconcile: Value,
}

pub struct HotWallet {
    pub path: PathBuf,
    pub utxo_path: PathBuf,
    node: Arc<dyn Node>,
    pub hrp: String,
    keystore: Option<Arc<KeyStore>>,
    audit: Option<Arc<SigAudit>>,
    /// Live: a human-signed `policy_set` (AGP-039) changes it. Read with [`HotWallet::cap_sats`].
    cap_sats: std::sync::atomic::AtomicI64,
    utxo_salt: [u8; 16],
    inner: Mutex<Inner>,
}

fn new_secret() -> SecretKey {
    xbt402::signer::random_secret()
}

fn gettxout(node: &dyn Node, txid: &str, n: u32) -> Result<Option<Value>> {
    let v = node.call("gettxout", json!([txid, n, true]))?;
    Ok((!v.is_null()).then_some(v))
}

fn spk_of(v: &Value) -> String {
    v.get("scriptPubKey").and_then(|s| s.get("hex")).and_then(Value::as_str).unwrap_or("").to_string()
}

/// The coinbase flag and block of one `scantxoutset` unspent.
fn scanned(c: &Value) -> Coin {
    let coinbase = crate::pyjson::truthy(c.get("coinbase"));
    let height = if coinbase { py_int(c.get("height")).and_then(|h| u32::try_from(h).ok()) } else { None };
    Coin { coinbase, height, ..Coin::default() }
}

impl HotWallet {
    pub fn open(path: &Path, node: Arc<dyn Node>, hrp: &str, keystore: Option<Arc<KeyStore>>, audit: Option<Arc<SigAudit>>,
                cap_sats: i64) -> Result<Self> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).map_err(|e| err("io", e.to_string()))?;
        }
        let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "hot".into());
        let utxo_path = path.with_file_name(format!("{stem}_utxos.json"));
        let placeholder = HotKey::new(new_secret(), hrp, 0.0)?;
        let w = Self { path: path.into(), utxo_path, node, hrp: hrp.into(), keystore, audit, cap_sats: std::sync::atomic::AtomicI64::new(cap_sats),
                       utxo_salt: crate::keystore::random_bytes::<16>(),
                       inner: Mutex::new(Inner { current: placeholder, retired: vec![], utxos: vec![], stale: vec![], last_reconcile: json!({}) }) };
        w.load_or_create()?;
        w.load_utxos()?;
        Ok(w)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    pub fn encrypted(&self) -> bool {
        self.keystore.is_some()
    }

    /// The hot balance cap (0 = none).
    pub fn cap_sats(&self) -> i64 {
        self.cap_sats.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn set_cap_sats(&self, v: i64) {
        self.cap_sats.store(v, std::sync::atomic::Ordering::SeqCst)
    }

    pub fn address(&self) -> String {
        self.lock().current.address.clone()
    }

    pub fn spk(&self) -> Vec<u8> {
        self.lock().current.spk.clone()
    }

    pub fn spk_hex(&self) -> String {
        self.lock().current.spk_hex()
    }

    pub fn pubkey(&self) -> PubkeyBytes {
        self.lock().current.pubkey
    }

    /// Every key's spk, current first (what a light backend watches).
    pub fn key_spks(&self) -> Vec<Vec<u8>> {
        let g = self.lock();
        std::iter::once(&g.current).chain(g.retired.iter()).map(|k| k.spk.clone()).collect()
    }

    pub fn last_reconcile(&self) -> Value {
        self.lock().last_reconcile.clone()
    }

    // --- storage ---------------------------------------------------------------------------------
    fn seal(&self, k: &HotKey) -> Result<Value> {
        let mut d = Map::new();
        d.insert("pub".into(), hex::encode(k.pubkey).into());
        if k.retired_at != 0.0 {
            d.insert("retired_at".into(), crate::pyjson::ts_value(k.retired_at));
        }
        match &self.keystore {
            None => {
                d.insert("secret".into(), hex::encode(k.secret.secret_bytes()).into());
            }
            Some(ks) => {
                d.insert("sealed".into(), ks.seal(&k.secret.secret_bytes(), AAD, None)?);
            }
        }
        Ok(Value::Object(d))
    }

    fn unseal(&self, d: &Value) -> Result<HotKey> {
        let secret = if let Some(blob) = d.get("sealed") {
            let ks = self.keystore.as_ref().ok_or_else(|| err("keystore", "hot key is encrypted: set B2_HOT_KEYFILE or B2_HOT_PASSPHRASE"))?;
            let b = ks.open(blob, AAD)?;
            SecretKey::from_slice(&b).map_err(|_| err("keystore", "hot key file: not a secret key"))?
        } else {
            let h = d.get("secret").and_then(Value::as_str).ok_or_else(|| err("keystore", "hot key file: no key"))?;
            let b = hex::decode(h).map_err(|_| err("keystore", "hot key file: secret is not hex"))?;
            let mut padded = [0u8; 32];
            if b.len() > 32 {
                return Err(err("keystore", "hot key file: secret too long"));
            }
            padded[32 - b.len()..].copy_from_slice(&b);
            SecretKey::from_slice(&padded).map_err(|_| err("keystore", "hot key file: not a secret key"))?
        };
        let retired_at = d.get("retired_at").and_then(Value::as_f64).unwrap_or(0.0);
        let k = HotKey::new(secret, &self.hrp, retired_at)?;
        if let Some(p) = d.get("pub").and_then(Value::as_str).filter(|p| !p.is_empty()) {
            if p != hex::encode(k.pubkey) {
                return Err(err("keystore", "hot key file: the key does not match its recorded pub"));
            }
        }
        Ok(k)
    }

    fn persist_keys(&self, g: &Inner) -> Result<()> {
        let retired: Vec<Value> = g.retired.iter().map(|k| self.seal(k)).collect::<Result<_>>()?;
        let doc = json!({"v": 2, "encrypted": self.encrypted(), "current": self.seal(&g.current)?, "retired": retired});
        write_private(&self.path, &dumps_indent(&doc, 2, false))
    }

    fn load_or_create(&self) -> Result<()> {
        let mut g = self.lock();
        if !self.path.exists() {
            g.current = HotKey::new(new_secret(), &self.hrp, 0.0)?;
            g.retired.clear();
            return self.persist_keys(&g);
        }
        let raw: Value = serde_json::from_str(&std::fs::read_to_string(&self.path).map_err(|e| err("io", e.to_string()))?)
            .map_err(|e| err("keystore", format!("{}: {e}", self.path.display())))?;
        let plain;
        if let Some(cur) = raw.get("current") {
            g.current = self.unseal(cur)?;
            let ret = raw.get("retired").and_then(Value::as_array).cloned().unwrap_or_default();
            g.retired = ret.iter().map(|d| self.unseal(d)).collect::<Result<_>>()?;
            plain = cur.get("secret").is_some() || ret.iter().any(|d| d.get("secret").is_some());
        } else {
            // wave-2 format: {"secret", "pub"} in the clear
            g.current = self.unseal(&raw)?;
            g.retired.clear();
            plain = true;
        }
        if plain && self.keystore.is_some() {
            self.persist_keys(&g)?; // first start with a wrapping key: re-seal the plaintext file
        }
        Ok(())
    }

    fn load_utxos(&self) -> Result<()> {
        if !self.utxo_path.exists() {
            return Ok(());
        }
        let raw: Value = serde_json::from_str(&std::fs::read_to_string(&self.utxo_path).map_err(|e| err("io", e.to_string()))?)
            .map_err(|e| err("keystore", format!("{}: {e}", self.utxo_path.display())))?;
        let name = self.utxo_path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let doc = if let Some(blob) = raw.get("sealed") {
            let ks = self.keystore.as_ref().ok_or_else(|| err("keystore", "hot UTXO set is encrypted: set B2_HOT_KEYFILE or B2_HOT_PASSPHRASE"))?;
            let pt = ks.open(blob, UTXO_AAD).map_err(|e| err("keystore", format!(
                "{name}: {}. Move it aside to rebuild the set from the node (scantxoutset at the next start)", e.msg)))?;
            serde_json::from_slice(&pt).map_err(|e| err("keystore", format!("{name}: {e}")))?
        } else {
            raw.clone()
        };
        let coins = |k: &str| -> Result<Vec<Coin>> {
            doc.get(k).and_then(Value::as_array).map(|a| a.iter().map(Coin::from_value).collect()).unwrap_or(Ok(vec![]))
        };
        let (u, s) = (coins("utxos")?, coins("stale")?);
        let mut g = self.lock();
        g.utxos = u;
        g.stale = s;
        if self.keystore.is_some() && raw.get("sealed").is_none() {
            self.persist_utxos(&g)?; // first start with a wrapping key: re-seal the plaintext set
        }
        Ok(())
    }

    fn persist_utxos(&self, g: &Inner) -> Result<()> {
        let start = g.stale.len().saturating_sub(MAX_STALE);
        let doc = json!({"v": 1, "utxos": g.utxos.iter().map(Coin::to_value).collect::<Vec<_>>(),
                         "stale": g.stale[start..].iter().map(Coin::to_value).collect::<Vec<_>>()});
        let doc = match &self.keystore {
            Some(ks) => json!({"v": 1, "encrypted": true, "sealed": ks.seal(dumps(&doc).as_bytes(), UTXO_AAD, Some(&self.utxo_salt))?}),
            None => doc,
        };
        write_private(&self.utxo_path, &dumps_indent(&doc, 1, false))
    }

    fn keys(g: &Inner) -> Vec<&HotKey> {
        std::iter::once(&g.current).chain(g.retired.iter()).collect()
    }

    fn key_for_spk<'a>(g: &'a Inner, spk_hex: &str) -> Option<&'a HotKey> {
        Self::keys(g).into_iter().find(|k| k.spk_hex() == spk_hex)
    }

    fn key_for_out<'a>(g: &'a Inner, o: &Value) -> Option<&'a HotKey> {
        let spk = o.get("scriptPubKey");
        let hexs = spk.and_then(|s| s.get("hex")).and_then(Value::as_str).unwrap_or("");
        let addr = spk.and_then(|s| s.get("address")).and_then(Value::as_str);
        Self::key_for_spk(g, hexs).or_else(|| Self::keys(g).into_iter().find(|k| addr == Some(k.address.as_str())))
    }

    /// Check the stored coins against the node; with `scan`, also find coins the file lacks.
    pub fn reconcile(&self, scan: bool) -> Value {
        let mut out = json!({"ok": false, "kept": 0, "stale": 0, "restored": 0, "dropped": 0, "found": 0, "scanned": false});
        let mut g = self.lock();
        match self.node.call("getblockchaininfo", json!([])) {
            Ok(info) if crate::pyjson::truthy(info.get("initialblockdownload")) => {
                out["reason"] = "node is in initial block download: stored coins kept unverified".into();
                g.last_reconcile = out.clone();
                return out;
            }
            Ok(_) => {}
            Err(e) => {
                out["reason"] = format!("node unreachable: {}; stored coins kept unverified", e.msg.chars().take(160).collect::<String>()).into();
                g.last_reconcile = out.clone();
                return out;
            }
        }
        let bump = |out: &mut Value, k: &str| out[k] = (out[k].as_i64().unwrap_or(0) + 1).into();
        let (mut keep, mut stale) = (vec![], vec![]);
        let all: Vec<(Coin, bool)> = g.utxos.iter().map(|u| (u.clone(), false)).chain(g.stale.iter().map(|u| (u.clone(), true))).collect();
        for (u, was_stale) in all {
            let r = match self.node.call("gettxout", json!([u.txid, u.vout, true])) {
                Ok(r) => r,
                Err(e) => {
                    out["reason"] = format!("gettxout failed: {}; stored coins kept unverified", e.msg.chars().take(160).collect::<String>()).into();
                    g.last_reconcile = out.clone();
                    return out;
                }
            };
            if r.is_null() {
                stale.push(Coin { why: "not unspent on the node".into(), ..u });
                bump(&mut out, "stale");
                continue;
            }
            let spk = spk_of(&r);
            let value = sats(r.get("value"));
            let check_spk = if spk.is_empty() { &u.spk } else { &spk };
            if (!u.spk.is_empty() && !spk.is_empty() && spk != u.spk) || value != u.value || Self::key_for_spk(&g, check_spk).is_none() {
                bump(&mut out, "dropped"); // the node disagrees with the file: the node wins
                continue;
            }
            let coinbase = crate::pyjson::truthy(r.get("coinbase"));
            let height = if coinbase { u.height.or_else(|| self.txout_height(&r)) } else { None };
            keep.push(Coin { why: String::new(), spk: check_spk.clone(), coinbase, height, ..u });
            bump(&mut out, if was_stale { "restored" } else { "kept" });
        }
        if scan {
            let descs: Vec<String> = Self::keys(&g).iter().map(|k| format!("raw({})", k.spk_hex())).collect();
            match self.node.call("scantxoutset", json!(["start", descs])) {
                Ok(res) => {
                    let mut have: Vec<(String, u32)> = keep.iter().map(Coin::op).collect();
                    for c in res.get("unspents").and_then(Value::as_array).into_iter().flatten() {
                        let op = (c.get("txid").and_then(Value::as_str).unwrap_or("").to_string(), py_int(c.get("vout")).unwrap_or(0) as u32);
                        let spk = c.get("scriptPubKey").and_then(Value::as_str).unwrap_or("");
                        if have.contains(&op) || Self::key_for_spk(&g, spk).is_none() {
                            continue;
                        }
                        keep.push(Coin { txid: op.0.clone(), vout: op.1, value: sats(c.get("amount")), spk: spk.into(), ..scanned(c) });
                        stale.retain(|x| x.op() != op);
                        have.push(op);
                        bump(&mut out, "found");
                    }
                    out["scanned"] = (!res.is_null() && res.get("success").map(|s| crate::pyjson::truthy(Some(s))).unwrap_or(true)).into();
                }
                Err(e) => out["scan_error"] = e.msg.chars().take(160).collect::<String>().into(),
            }
        }
        let start = stale.len().saturating_sub(MAX_STALE);
        g.utxos = keep;
        g.stale = stale[start..].to_vec();
        if let Err(e) = self.persist_utxos(&g) {
            out["reason"] = e.msg.into();
            return out;
        }
        out["ok"] = true.into();
        out["hot_sats"] = g.utxos.iter().map(|u| u.value).sum::<i64>().into();
        g.last_reconcile = out.clone();
        out
    }

    // --- coins -----------------------------------------------------------------------------------
    fn notice_locked(&self, g: &mut Inner, txid: &str, vout: u32, value: i64, spk: &str) -> Result<()> {
        self.notice_coin_locked(g, Coin { txid: txid.into(), vout, value, spk: spk.into(), ..Coin::default() })
    }

    fn notice_coin_locked(&self, g: &mut Inner, mut c: Coin) -> Result<()> {
        if c.spk.is_empty() {
            c.spk = g.current.spk_hex();
        }
        if !g.utxos.iter().any(|u| u.op() == c.op()) {
            g.stale.retain(|u| u.op() != c.op());
            g.utxos.push(c);
            self.persist_utxos(g)?;
        }
        Ok(())
    }

    /// A coinbase output's block from a `gettxout` answer: its confirmations counted back from the
    /// `bestblock` they were counted at.
    fn txout_height(&self, r: &Value) -> Option<u32> {
        let conf = py_int(r.get("confirmations")).filter(|c| *c > 0)?;
        let best = r.get("bestblock").and_then(Value::as_str)?;
        let tip = py_int(self.node.call("getblockheader", json!([best, true])).ok()?.get("height"))?;
        u32::try_from(tip - conf + 1).ok()
    }

    /// The block of a confirmed transaction from its verbose form (`height`, else its `blockhash`,
    /// else the block it was looked up in).
    fn tx_height(&self, raw: &Value, looked_in: &str) -> Option<u32> {
        if let Some(h) = py_int(raw.get("height")) {
            return u32::try_from(h).ok();
        }
        let bh = raw.get("blockhash").and_then(Value::as_str).or((!looked_in.is_empty()).then_some(looked_in))?;
        py_int(self.node.call("getblockheader", json!([bh, true])).ok()?.get("height")).and_then(|h| u32::try_from(h).ok())
    }

    pub fn notice_utxo(&self, txid: &str, vout: u32, value: i64, spk: &str) -> Result<()> {
        let mut g = self.lock();
        self.notice_locked(&mut g, txid, vout, value, spk)
    }

    /// Notice this tx's outputs to any hot key. `unspent_only` skips outputs the node says are
    /// spent. P6: without txindex a confirmed tx is found only with its block hash; without one,
    /// the UTXO set is scanned for this tx's unspent outputs to our keys.
    pub fn scan_from_txid(&self, txid: &str, unspent_only: bool, blockhash: &str) -> Result<usize> {
        let Some(raw) = node::get_tx(&*self.node, txid, blockhash) else {
            return self.scan_utxoset_for(txid);
        };
        let coinbase = raw.get("vin").and_then(|v| v.get(0)).map(|i| i.get("coinbase").is_some()).unwrap_or(false);
        let height = if coinbase { self.tx_height(&raw, blockhash) } else { None };
        let mut g = self.lock();
        let mut added = 0;
        for o in raw.get("vout").and_then(Value::as_array).cloned().unwrap_or_default() {
            let Some(k) = Self::key_for_out(&g, &o).map(|k| k.spk_hex()) else { continue };
            let n = py_int(o.get("n")).unwrap_or(0) as u32;
            if unspent_only && gettxout(&*self.node, txid, n)?.is_none() {
                continue;
            }
            let c = Coin { txid: txid.into(), vout: n, value: sats(o.get("value")), spk: k, coinbase, height, ..Coin::default() };
            self.notice_coin_locked(&mut g, c)?;
            added += 1;
        }
        Ok(added)
    }

    fn scan_utxoset_for(&self, txid: &str) -> Result<usize> {
        let mut g = self.lock();
        let descs: Vec<String> = Self::keys(&g).iter().map(|k| format!("raw({})", k.spk_hex())).collect();
        let res = self.node.call("scantxoutset", json!(["start", descs]))?;
        let mut added = 0;
        for c in res.get("unspents").and_then(Value::as_array).cloned().unwrap_or_default() {
            let spk = c.get("scriptPubKey").and_then(Value::as_str).unwrap_or("").to_string();
            if c.get("txid").and_then(Value::as_str) == Some(txid) && Self::key_for_spk(&g, &spk).is_some() {
                let coin = Coin { txid: txid.into(), vout: py_int(c.get("vout")).unwrap_or(0) as u32, value: sats(c.get("amount")), spk,
                                  ..scanned(&c) };
                self.notice_coin_locked(&mut g, coin)?;
                added += 1;
            }
        }
        Ok(added)
    }

    /// AGP-022: count a channel close's change to a hot key, once. Returns `{status, txid,
    /// scan_from, added}`; status "counted" | "none" | "spent" | "pending" (ask again later).
    pub fn learn_close_change(&self, txid: &str, funding: (&str, u32), scan_from: u64, limit: u64) -> Result<Value> {
        let node = &*self.node;
        let mut out = json!({"status": "pending", "txid": txid, "scan_from": scan_from, "added": 0});
        let mut txid = txid.to_string();
        if txid.is_empty() {
            // the provider's reply had no txid: find the spend
            if let Ok(r) = node.call("gettxspendingprevout", json!([[{"txid": funding.0, "vout": funding.1}]])) {
                txid = r.get(0).and_then(|x| x.get("spendingtxid")).and_then(Value::as_str).unwrap_or("").to_string();
                out["txid"] = txid.clone().into();
            }
        }
        let mut raw = if txid.is_empty() { None } else { node::get_tx(node, &txid, "") };
        if raw.is_none() && !txid.is_empty() {
            // confirmed: its unspent outputs answer gettxout
            for n in 0..CLOSE_MAX_OUTPUTS {
                if let Some(c) = gettxout(node, &txid, n)? {
                    let mine = { let g = self.lock(); Self::key_for_spk(&g, &spk_of(&c)).is_some() };
                    if mine {
                        let added = self.count_close(&txid, &[(n, c)])?;
                        out["status"] = "counted".into();
                        out["added"] = added.into();
                        return Ok(out);
                    }
                }
            }
        }
        if raw.is_none() {
            // no unspent output of ours: find the spend of the funding in a block
            raw = self.close_in_blocks(&mut out, funding, limit);
            txid = out["txid"].as_str().unwrap_or("").to_string();
        }
        let Some(raw) = raw else { return Ok(out) };
        let mine: Vec<u32> = {
            let g = self.lock();
            raw.get("vout").and_then(Value::as_array).into_iter().flatten()
                .filter(|o| Self::key_for_out(&g, o).is_some()).map(|o| py_int(o.get("n")).unwrap_or(0) as u32).collect()
        };
        if mine.is_empty() {
            out["status"] = "none".into();
            return Ok(out);
        }
        let mut live = vec![];
        for n in mine {
            if let Some(c) = gettxout(node, &txid, n)? {
                live.push((n, c));
            }
        }
        if live.is_empty() {
            out["status"] = "spent".into();
            return Ok(out);
        }
        out["added"] = self.count_close(&txid, &live)?.into();
        out["status"] = "counted".into();
        Ok(out)
    }

    fn count_close(&self, txid: &str, coins: &[(u32, Value)]) -> Result<usize> {
        let mut g = self.lock();
        let before = g.utxos.len();
        for (n, c) in coins {
            if let Some(spk) = Self::key_for_spk(&g, &spk_of(c)).map(HotKey::spk_hex) {
                self.notice_locked(&mut g, txid, *n, sats(c.get("value")), &spk)?;
            }
        }
        Ok(g.utxos.len() - before)
    }

    fn close_in_blocks(&self, out: &mut Value, funding: (&str, u32), limit: u64) -> Option<Value> {
        let tip = node::height(&*self.node).ok()?;
        let sf = out["scan_from"].as_u64().unwrap_or(0);
        let start = if sf == 0 { tip } else { sf };
        if start > tip {
            return None;
        }
        let end = tip.min(start + limit - 1);
        for h in start..=end {
            let blk = node::block_hash(&*self.node, h).and_then(|bh| self.node.call("getblock", json!([bh, 2])));
            let Ok(blk) = blk else { return None }; // keep scan_from here: retry this block next time
            for tx in blk.get("tx").and_then(Value::as_array).into_iter().flatten() {
                if node::tx_spends(tx, funding.0, funding.1) {
                    if let Some(t) = tx.get("txid").and_then(Value::as_str) {
                        out["txid"] = t.into();
                    }
                    out["scan_from"] = h.into();
                    return Some(tx.clone());
                }
            }
            out["scan_from"] = (h + 1).into();
        }
        None
    }

    pub fn balance_sats(&self) -> i64 {
        self.lock().utxos.iter().map(|u| u.value).sum()
    }

    pub fn over_cap(&self) -> bool {
        self.cap_sats() > 0 && self.balance_sats() > self.cap_sats()
    }

    /// Before a new channel is funded: above the cap, a human sweeps first (`hot_balance_cap`).
    pub fn check_channel_funding(&self) -> Result<()> {
        if self.over_cap() {
            return Err(err("hot_balance_cap", format!(
                "hot key holds {} sats, above its {} sat cap: a human must sweep it (agentwallet-approve sweep) before new channels are funded",
                self.balance_sats(), self.cap_sats())));
        }
        Ok(())
    }

    pub fn holds(&self, txid: &str, vout: u32) -> bool {
        self.lock().utxos.iter().any(|u| u.txid == txid && u.vout == vout)
    }

    pub fn status(&self) -> Value {
        let g = self.lock();
        let cur = g.current.spk_hex();
        let bal: i64 = g.utxos.iter().map(|u| u.value).sum();
        let retired: i64 = g.utxos.iter().filter(|u| !u.spk.is_empty() && u.spk != cur).map(|u| u.value).sum();
        let coinbase: i64 = g.utxos.iter().filter(|u| u.coinbase).map(|u| u.value).sum();
        json!({"hot_address": g.current.address, "hot_spk": cur, "hot_sats": bal, "hot_utxos": g.utxos.len(), "hot_coinbase_sats": coinbase,
               "hot_stale_utxos": g.stale.len(), "hot_encrypted": self.encrypted(), "hot_retired_keys": g.retired.len(),
               "hot_retired_sats": retired, "hot_cap_sats": self.cap_sats(), "hot_over_cap": self.cap_sats() > 0 && bal > self.cap_sats()})
    }

    // --- spending --------------------------------------------------------------------------------
    /// `coins` less every coinbase coin the node would not relay a spend of yet, and the sats held
    /// back. The depth is the node's (`getdeploymentinfo`, [`Maturity::relay_at`]); when the node
    /// cannot say (no deployment info, no tip, no block for the coin), the coin waits.
    pub fn spendable(&self, coins: &[Coin]) -> (Vec<Coin>, i64) {
        if !coins.iter().any(|c| c.coinbase) {
            return (coins.to_vec(), 0);
        }
        let rule = self.node.call("getdeploymentinfo", json!([])).ok().and_then(|d| Maturity::from_deployments(&d).ok());
        let tip = self.node.call("getblockcount", json!([])).ok().and_then(|v| py_int(Some(&v))).and_then(|h| u32::try_from(h).ok());
        let mut held = 0;
        let ok = coins.iter().filter(|c| {
            let mature = !c.coinbase || matches!((rule, tip, c.height), (Some(m), Some(t), Some(h)) if t.saturating_add(1) >= m.relay_at(h));
            if !mature {
                held += c.value;
            }
            mature
        }).cloned().collect();
        (ok, held)
    }

    fn prepare_locked(&self, g: &Inner, utxos: &[Coin], outs: Vec<TxOut>, kind: &str, extra: Value) -> Result<Prep> {
        let cur = g.current.spk_hex();
        let keys: Vec<HotKey> = utxos.iter().map(|u| Self::key_for_spk(g, if u.spk.is_empty() { &cur } else { &u.spk }).cloned())
            .collect::<Option<_>>().ok_or_else(|| err("hot", "hot wallet holds a coin it has no key for"))?;
        let inputs = utxos.iter().map(|u| OutPoint::from_display(&u.txid, u.vout).map(|op| TxIn::new(op, SEQUENCE)))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut tx = Tx::new(2, inputs, outs, 0);
        let prevouts: Vec<TxOut> = utxos.iter().zip(&keys).map(|(u, k)| TxOut::new(u.value, k.spk.clone())).collect();
        let mut sigs = vec![];
        for (i, k) in keys.iter().enumerate() {
            let digest = unified_sighash(&tx, &prevouts, i, ScriptType::WitnessV0, &p2wpkh_script_code(&k.pubkey), SIGHASH_ALL_UNIFIED, None)?;
            let sig = xbt402::channel::sign_with_type(&k.secret, &digest, SIGHASH_ALL_UNIFIED);
            if sig.last() != Some(&SIGHASH_ALL_UNIFIED) {
                return Err(err("hot", "hot signature is not 0x21"));
            }
            tx.inputs[i].witness = vec![sig.clone(), k.pubkey.to_vec()];
            sigs.push((k.spk_hex(), sig));
        }
        let txid = tx.txid();
        let amount: i64 = tx.outputs.iter().map(|o| o.value).sum();
        if let Some(a) = &self.audit {
            for (spk, sig) in &sigs {
                let mut e = json!({"txid": txid, "key_spk": spk, "sighash": "0x21", "amount_sats": amount});
                if let Value::Object(m) = &extra {
                    for (k, v) in m {
                        e[k] = v.clone();
                    }
                }
                a.record(kind, sig, "", "", e)?;
            }
        }
        Ok(Prep { hex: tx.to_hex(), txid, inputs: utxos.iter().map(Coin::op).collect(),
                  outputs: tx.outputs.iter().map(|o| (o.value, hex::encode(&o.script_pubkey))).collect() })
    }

    /// Send a prepared transaction. A failed send whose transaction the node already has counts
    /// as sent; anything else fails and nothing is forgotten.
    pub fn broadcast(&self, prep: &Prep) -> Result<String> {
        match self.node.call("sendrawtransaction", json!([prep.hex])) {
            Ok(v) => Ok(v.as_str().map(str::to_string).unwrap_or_else(|| prep.txid.clone())),
            Err(e) => match gettxout(&*self.node, &prep.txid, 0) {
                Ok(Some(_)) => Ok(prep.txid.clone()),
                _ => Err(e),
            },
        }
    }

    /// The prepared transaction is sent: forget its inputs, learn its outputs to our keys.
    pub fn commit(&self, prep: &Prep) -> Result<()> {
        let mut g = self.lock();
        g.utxos.retain(|u| !prep.inputs.contains(&u.op()));
        self.persist_utxos(&g)?;
        for (n, (value, spk)) in prep.outputs.iter().enumerate() {
            if Self::key_for_spk(&g, spk).is_some() && *value >= DUST {
                self.notice_locked(&mut g, &prep.txid, n as u32, *value, spk)?;
            }
        }
        self.persist_utxos(&g)
    }

    fn spend(&self, utxos: &[Coin], outs: Vec<TxOut>, kind: &str, extra: Value) -> Result<String> {
        let prep = { let g = self.lock(); self.prepare_locked(&g, utxos, outs, kind, extra)? };
        let txid = self.broadcast(&prep)?;
        self.commit(&prep)?;
        Ok(txid)
    }

    /// Build, 0x21-sign and broadcast a payment of `sats` to `dest_spk`. Returns (txid, 0).
    pub fn fund(&self, dest_spk: &[u8], sats: i64, fee: i64) -> Result<(String, u32)> {
        let prep = self.prepare_fund(dest_spk, sats, fee)?;
        let txid = self.broadcast(&prep)?;
        self.commit(&prep)?;
        Ok((txid, 0))
    }

    /// `fund` without the broadcast (P1): output 0 pays `dest_spk`, output 1 is our change.
    pub fn prepare_fund(&self, dest_spk: &[u8], sats: i64, fee: i64) -> Result<Prep> {
        if sats <= 0 {
            return Err(err("hot", "fund amount must be positive"));
        }
        let need = sats + fee;
        let g = self.lock();
        let cur = g.current.spk_hex();
        let bal: i64 = g.utxos.iter().map(|u| u.value).sum();
        let (ok, held) = self.spendable(&g.utxos);
        let immature = if held > 0 { format!(", {held} of it immature coinbase") } else { String::new() };
        let utxo = ok.into_iter().find(|u| (u.spk.is_empty() || u.spk == cur) && u.value >= need)
            .ok_or_else(|| err("hot", format!("hot wallet has no UTXO \u{2265} {need} sats (have {bal}{immature})")))?;
        let change = utxo.value - need;
        let mut outs = vec![TxOut::new(sats, dest_spk.to_vec())];
        if change >= DUST {
            outs.push(TxOut::new(change, g.current.spk.clone()));
        }
        self.prepare_locked(&g, &[utxo], outs, "funding", json!({"dest_spk": hex::encode(dest_spk)}))
    }

    fn sweep(&self, utxos: &[Coin], dest_spk: &[u8], kind: &str, extra: Value) -> Result<Value> {
        let total: i64 = utxos.iter().map(|u| u.value).sum();
        let fee = SWEEP_FEE_BASE + SWEEP_FEE_PER_INPUT * utxos.len() as i64;
        if total - fee < DUST {
            return Err(err("hot", format!("nothing to sweep ({total} sats)")));
        }
        let txid = self.spend(utxos, vec![TxOut::new(total - fee, dest_spk.to_vec())], kind, extra)?;
        Ok(json!({"txid": txid, "swept_sats": total - fee, "inputs": utxos.len(), "fee_sats": fee}))
    }

    fn retired_utxos(g: &Inner) -> Vec<Coin> {
        let cur = g.current.spk_hex();
        g.utxos.iter().filter(|u| !u.spk.is_empty() && u.spk != cur).cloned().collect()
    }

    /// New hot key; every coin of the old key(s) sweeps into it. The old key stays sealed as retired.
    pub fn rotate(&self) -> Result<Value> {
        let (old_addr, old_spk, new_addr, new_spk, coins) = {
            let mut g = self.lock();
            let mut old = g.current.clone();
            let new = HotKey::new(new_secret(), &self.hrp, 0.0)?;
            old.retired_at = (now_f64() * 1000.0).round() / 1000.0;
            g.retired.push(old.clone());
            g.current = new.clone();
            self.persist_keys(&g)?; // the new key is on disk before any coin moves to it
            (old.address.clone(), old.spk_hex(), new.address, new.spk, Self::retired_utxos(&g))
        };
        let coins = self.spendable(&coins).0;
        let mut out = json!({"old_address": old_addr, "new_address": new_addr, "sweep": null});
        if !coins.is_empty() {
            out["sweep"] = self.sweep(&coins, &new_spk, "rotation_sweep", json!({"old_key": old_spk}))?;
        }
        Ok(out)
    }

    /// Sweep coins that reached a retired key (a channel close or refund to an old address).
    pub fn sweep_retired(&self) -> Result<Option<Value>> {
        let (coins, spk) = { let g = self.lock(); (Self::retired_utxos(&g), g.current.spk.clone()) };
        let coins = self.spendable(&coins).0;
        let total: i64 = coins.iter().map(|u| u.value).sum();
        if coins.is_empty() || total - SWEEP_FEE_BASE - SWEEP_FEE_PER_INPUT * (coins.len() as i64) < DUST {
            return Ok(None);
        }
        self.sweep(&coins, &spk, "retired_sweep", json!({})).map(Some)
    }

    /// Human-approved sweep of `amount_sats` out of the hot key (the signer checks the signature).
    pub fn sweep_to(&self, dest_spk: &[u8], amount_sats: i64, fee: i64) -> Result<Value> {
        let (coins, cur_spk) = { let g = self.lock(); (g.utxos.clone(), g.current.spk.clone()) };
        let (coins, held) = self.spendable(&coins);
        let total: i64 = coins.iter().map(|u| u.value).sum();
        let mut fee = fee.max(SWEEP_FEE_BASE + SWEEP_FEE_PER_INPUT * coins.len() as i64);
        if amount_sats < DUST || amount_sats + fee > total {
            let immature = if held > 0 { format!(" (and {held} immature coinbase)") } else { String::new() };
            return Err(err("hot", format!("cannot sweep {amount_sats} sats from {total}{immature}")));
        }
        let change = total - amount_sats - fee;
        let mut outs = vec![TxOut::new(amount_sats, dest_spk.to_vec())];
        if change >= DUST {
            outs.push(TxOut::new(change, cur_spk));
        } else {
            fee += change; // zero change, or change below dust: it goes to the fee, and is reported
        }
        let n_out = outs.len();
        let txid = self.spend(&coins, outs, "human_sweep", json!({"dest_spk": hex::encode(dest_spk)}))?;
        Ok(json!({"txid": txid, "swept_sats": amount_sats, "fee_sats": fee, "change_sats": if change >= DUST { change } else { 0 },
                  "outputs": n_out, "hot_sats": self.balance_sats()}))
    }
}
