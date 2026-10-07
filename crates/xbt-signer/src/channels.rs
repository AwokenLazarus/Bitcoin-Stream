//! Per-counterparty Spillman channels used as the policy budget (B2 `channels.py`).
//!
//! The book holds every payer secret; responses list cap / used / expiry only. Payer keys are
//! sealed at rest (`channel_keys.json`, AAD `b2/channel-keys`), every signature goes to the
//! signature log, and a channel has a lifecycle: `pending` (written, key sealed, **before** its
//! funding is broadcast: P1) → `open` → `closed` | `refunded`. No new state is signed on a channel
//! that is not open or is within `refund_margin_blocks` of its CLTV expiry. `channels.json` is
//! B2's format (a record per dest with B2's field names; settled records under `archived`).
//!
//! `spent_sats` is what the calls cost; `used_sats` is the cumulative amount signed, at least the
//! dust floor (10 calls of 500 sign 5,000, not 5,046: AGP-017).
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use xbt402::channel::{channel_auth_key, sign_with_type, ChannelParams, Payer};
use xbt402::conditional::ConditionalParams;
use xbt_primitives::ecdsa;
use xbt_primitives::secp256k1::{PublicKey, Scalar, SecretKey, SECP256K1};
use xbt_primitives::sighash::SIGHASH_ALL_UNIFIED;
use xbt_primitives::tx::Tx;

use crate::keystore::{write_private, KeyStore};
use crate::policy::normalize_dest;
use crate::pyjson::{dumps_indent, now_f64, ts_value};
use crate::sigaudit::SigAudit;
use crate::{err, Result};

pub const KEYS_AAD: &str = "b2/channel-keys";

/// One channel, with B2's `ChannelRecord` fields (every one of them, so B2 loads the file).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ChannelRecord {
    pub dest: String,
    pub chan: String,
    pub cap_sats: i64,
    pub used_sats: i64,
    pub expiry: i64,
    pub payer_pub: String,
    pub payee_pub: String,
    pub close_fee: i64,
    pub payer_spk: String,
    pub payee_spk: String,
    pub funding_txid: String,
    pub funding_vout: i64,
    pub funding_sats: i64,
    pub seq: i64,
    pub origin: String,
    pub pending_cond: Value,
    pub state: String,
    pub closed_txid: String,
    pub refund_txid: String,
    pub open_height: i64,
    pub spent_sats: i64,
    pub open_url: String,
    pub network: String,
    pub min_conf: i64,
    pub funding_hex: String,
    pub funding_height: i64,
    pub open_error: String,
    pub last_sig: String,
    pub acked_sats: i64,
    pub pending_lock: Value,
    pub given_up: Vec<Value>,
    pub close_change: String,
    pub close_scan_from: i64,
    pub close_hex: String,
    pub close_fee_payer: String,
}

impl Default for ChannelRecord {
    fn default() -> Self {
        Self { dest: String::new(), chan: String::new(), cap_sats: 0, used_sats: 0, expiry: 0, payer_pub: String::new(),
               payee_pub: String::new(), close_fee: 0, payer_spk: String::new(), payee_spk: String::new(), funding_txid: String::new(),
               funding_vout: 0, funding_sats: 0, seq: 0, origin: String::new(), pending_cond: json!({}), state: "open".into(),
               closed_txid: String::new(), refund_txid: String::new(), open_height: 0, spent_sats: -1, open_url: String::new(),
               network: String::new(), min_conf: 0, funding_hex: String::new(), funding_height: 0, open_error: String::new(),
               last_sig: String::new(), acked_sats: 0, pending_lock: json!({}), given_up: vec![], close_change: String::new(),
               close_scan_from: 0, close_hex: String::new(), close_fee_payer: "payer".into() }
    }
}

fn has_lock(v: &Value) -> bool {
    v.as_object().is_some_and(|m| !m.is_empty())
}

fn lk_int(lk: &Value, k: &str) -> i64 {
    crate::pyjson::py_int(lk.get(k)).unwrap_or(0)
}

impl ChannelRecord {
    /// The channel's params, rebuilt byte for byte from this record.
    pub fn params(&self) -> Result<ChannelParams> {
        let mut d = json!({"payer_pub": self.payer_pub, "payee_pub": self.payee_pub, "expiry": self.expiry, "payer_spk": self.payer_spk,
                           "payee_spk": self.payee_spk, "close_fee": self.close_fee, "funding_txid": self.funding_txid,
                           "funding_vout": self.funding_vout, "capacity": if self.funding_sats != 0 { self.funding_sats } else { self.cap_sats }});
        if self.close_fee_payer != "payer" {
            d["close_fee_payer"] = self.close_fee_payer.clone().into();
        }
        ChannelParams::from_json(&d)
    }

    pub fn spent(&self) -> i64 {
        if self.spent_sats < 0 { self.used_sats } else { self.spent_sats }
    }

    pub fn has_pending_lock(&self) -> bool {
        has_lock(&self.pending_lock)
    }

    pub fn public(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("state".into(), self.state.clone().into());
        m.insert("funding_txid".into(), if self.funding_txid.is_empty() { Value::Null } else { self.funding_txid.clone().into() });
        m.insert("spent_sats".into(), self.spent().into());
        if !self.open_error.is_empty() && self.state == "pending" {
            m.insert("open_error".into(), self.open_error.clone().into());
        }
        m.insert("closed_txid".into(), if self.closed_txid.is_empty() { Value::Null } else { self.closed_txid.clone().into() });
        if self.state == "closed" && !self.close_change.is_empty() {
            m.insert("close_change".into(), self.close_change.clone().into());
        }
        m.insert("refund_txid".into(), if self.refund_txid.is_empty() { Value::Null } else { self.refund_txid.clone().into() });
        m.insert("dest".into(), self.dest.clone().into());
        m.insert("chan".into(), self.chan.clone().into());
        m.insert("cap_sats".into(), self.cap_sats.into());
        m.insert("used_sats".into(), self.used_sats.into());
        m.insert("expiry".into(), self.expiry.into());
        m.insert("residual_sats".into(), (self.cap_sats - self.used_sats).max(0).into());
        m.insert("seq".into(), self.seq.into());
        m.insert("origin".into(), self.origin.clone().into());
        if self.close_fee_payer != "payer" {
            m.insert("close_fee_payer".into(), self.close_fee_payer.clone().into());
        }
        if self.has_pending_lock() {
            m.insert("pending_lock_cum".into(), self.pending_lock.get("cum").cloned().unwrap_or(Value::Null));
        }
        Value::Object(m)
    }
}

/// `channel used + amount exceeds cap` (B2 `ChannelCapError`, code `channel_cap`).
pub fn cap_error(used: i64, amount: i64, cap: i64) -> crate::Error {
    err("channel_cap", format!("channel used {used} + {amount} exceeds cap {cap}"))
}

/// The ECDSA adaptor scheme behind routed (adaptor-locked) states: B1's `xbt402/adaptor.py`, which
/// AGP-026 ports to Rust. The book needs only these two operations; the point arithmetic is here.
pub trait AdaptorScheme: Send + Sync {
    /// Pre-sign digest `z` with `secret` under point `t1`; the pre-signature's wire JSON
    /// (`{"R", "R1", "s1", "c", "z"}`).
    fn presign(&self, secret: &SecretKey, z: &[u8; 32], t1: &PublicKey) -> Result<Value>;
    /// The secret `y` (with `y·G = t1`) from a completed signature, or `None`.
    fn extract(&self, pre: &Value, sig: &[u8], t1: &PublicKey) -> Option<[u8; 32]>;
}

pub type HeightFn = Arc<dyn Fn() -> Result<u64> + Send + Sync>;

struct Inner {
    records: IndexMap<String, ChannelRecord>,
    archived: Vec<Value>,
    secrets: HashMap<String, SecretKey>,
}

pub struct ChannelBook {
    pub records_path: PathBuf,
    pub keys_path: PathBuf,
    keystore: Option<Arc<KeyStore>>,
    audit: Option<Arc<SigAudit>>,
    /// `(height, margin)`: refuse new states once height >= expiry - margin.
    pub expiry_guard: Mutex<Option<(HeightFn, i64)>>,
    inner: Mutex<Inner>,
}

fn secret_hex(s: &SecretKey) -> String {
    hex::encode(s.secret_bytes())
}

fn parse_secret(h: &str) -> Result<SecretKey> {
    let b = hex::decode(h.trim()).map_err(|_| err("keystore", "channel key is not hex"))?;
    if b.len() > 32 {
        return Err(err("keystore", "channel key too long"));
    }
    let mut p = [0u8; 32];
    p[32 - b.len()..].copy_from_slice(&b);
    SecretKey::from_slice(&p).map_err(|_| err("keystore", "channel key out of range"))
}

fn audit_rec(a: &Option<Arc<SigAudit>>, kind: &str, sig: &[u8], chan: &str, dest: &str, extra: Value) -> Result<()> {
    if let Some(a) = a {
        a.record(kind, sig, chan, dest, extra)?;
    }
    Ok(())
}

/// `y·G` for a 32-byte scalar.
pub fn point_of(y: &[u8; 32]) -> Option<PublicKey> {
    SecretKey::from_slice(y).ok().map(|s| PublicKey::from_secret_key(SECP256K1, &s))
}

impl ChannelBook {
    pub fn open(records_path: &Path, keys_path: &Path, keystore: Option<Arc<KeyStore>>, audit: Option<Arc<SigAudit>>) -> Result<Self> {
        if let Some(p) = records_path.parent() {
            std::fs::create_dir_all(p).map_err(|e| err("io", e.to_string()))?;
        }
        let b = Self { records_path: records_path.into(), keys_path: keys_path.into(), keystore, audit, expiry_guard: Mutex::new(None),
                       inner: Mutex::new(Inner { records: IndexMap::new(), archived: vec![], secrets: HashMap::new() }) };
        b.load()?;
        Ok(b)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    pub fn set_expiry_guard(&self, height: HeightFn, margin: i64) {
        if let Ok(mut g) = self.expiry_guard.lock() {
            *g = Some((height, margin));
        }
    }

    fn load(&self) -> Result<()> {
        let mut g = self.lock();
        if self.records_path.exists() {
            let raw: Value = serde_json::from_str(&std::fs::read_to_string(&self.records_path).map_err(|e| err("io", e.to_string()))?)
                .map_err(|e| err("io", format!("{}: {e}", self.records_path.display())))?;
            if let Some(m) = raw.get("channels").and_then(Value::as_object) {
                for (dest, rec) in m {
                    let r: ChannelRecord = serde_json::from_value(rec.clone()).map_err(|e| err("io", format!("channel {dest}: {e}")))?;
                    g.records.insert(dest.clone(), r);
                }
            }
            g.archived = raw.get("archived").and_then(Value::as_array).cloned().unwrap_or_default();
        }
        if self.keys_path.exists() {
            let raw: Value = serde_json::from_str(&std::fs::read_to_string(&self.keys_path).map_err(|e| err("io", e.to_string()))?)
                .map_err(|e| err("io", format!("{}: {e}", self.keys_path.display())))?;
            let (doc, plain) = if let Some(blob) = raw.get("sealed") {
                let ks = self.keystore.as_ref().ok_or_else(|| err("keystore", "channel keys are encrypted: set B2_HOT_KEYFILE or B2_HOT_PASSPHRASE"))?;
                let pt = ks.open(blob, KEYS_AAD)?;
                (serde_json::from_slice::<Value>(&pt).map_err(|e| err("keystore", e.to_string()))?, false)
            } else {
                (raw, true)
            };
            for (k, v) in doc.get("secrets").and_then(Value::as_object).into_iter().flatten() {
                g.secrets.insert(k.clone(), parse_secret(v.as_str().unwrap_or(""))?);
            }
            if plain && self.keystore.is_some() && !g.secrets.is_empty() {
                self.persist(&g)?; // first start with a wrapping key: re-seal the plaintext file
            }
        }
        Ok(())
    }

    fn persist(&self, g: &Inner) -> Result<()> {
        // keys first: a record on disk never names a channel whose payer key is not on disk (P1)
        let mut secrets: Vec<(&String, String)> = g.secrets.iter().map(|(k, v)| (k, secret_hex(v))).collect();
        secrets.sort();
        let sm: serde_json::Map<String, Value> = secrets.into_iter().map(|(k, v)| (k.clone(), v.into())).collect();
        let mut doc = dumps_indent(&json!({"secrets": sm}), 2, false);
        if let Some(ks) = &self.keystore {
            doc = dumps_indent(&json!({"sealed": ks.seal(doc.as_bytes(), KEYS_AAD, None)?}), 2, false);
        }
        write_private(&self.keys_path, &doc)?;
        let chans: serde_json::Map<String, Value> = g.records.iter()
            .map(|(d, r)| (d.clone(), serde_json::to_value(r).unwrap_or(Value::Null))).collect();
        let mut body = json!({"channels": chans});
        if !g.archived.is_empty() {
            body["archived"] = g.archived.clone().into();
        }
        write_private(&self.records_path, &dumps_indent(&body, 2, true))
    }

    pub fn list_public(&self) -> Vec<Value> {
        self.lock().records.values().map(ChannelRecord::public).collect()
    }

    pub fn get(&self, dest: &str) -> Option<ChannelRecord> {
        self.lock().records.get(dest).cloned()
    }

    pub fn has(&self, dest: &str) -> bool {
        self.lock().records.contains_key(dest)
    }

    /// Resolve an origin, dest, or channel id to the book key.
    pub fn find_dest(&self, counterparty: &str) -> Option<String> {
        let dest = normalize_dest(counterparty);
        let g = self.lock();
        if g.records.contains_key(&dest) {
            return Some(dest);
        }
        if g.records.contains_key(counterparty) {
            return Some(counterparty.into());
        }
        g.records.iter().find(|(_, r)| r.chan == counterparty || r.origin == dest || r.origin == counterparty).map(|(d, _)| d.clone())
    }

    fn key_of(g: &Inner, key: &str) -> Result<String> {
        if g.records.contains_key(key) {
            return Ok(key.into());
        }
        g.records.iter().find(|(_, r)| r.chan == key || r.origin == key).map(|(d, _)| d.clone())
            .ok_or_else(|| err("unknown_channel", key.to_string()))
    }

    fn secret_of(g: &Inner, chan: &str) -> Result<SecretKey> {
        g.secrets.get(chan).copied().ok_or_else(|| err("bad_key", "signer has no key for this channel"))
    }

    /// Payer signature over `tagged_hash("xbt402/close", chan)` (DER hex). Keys stay here.
    pub fn sign_close(&self, dest: &str) -> Result<String> {
        let g = self.lock();
        let k = Self::key_of(&g, dest)?;
        let rec = &g.records[&k];
        let secret = Self::secret_of(&g, &rec.chan)?;
        if rec.state == "refunded" {
            return Err(err("channel_refunded", format!("refunded in {}", rec.refund_txid)));
        }
        let sig = ecdsa::sign(&secret, &xbt402::wire::close_message(&rec.chan));
        audit_rec(&self.audit, "close_auth", &sig, &rec.chan, &rec.dest, json!({"cum": rec.used_sats}))?;
        Ok(hex::encode(sig))
    }

    /// H3 per-request HMAC. The ECDH channel key never leaves the signer.
    pub fn request_auth(&self, chan: &str, seq: Option<&Value>, cum: Option<&Value>, sig: Option<&str>, req: &str) -> Result<String> {
        let g = self.lock();
        let k = Self::key_of(&g, chan)?;
        let rec = &g.records[&k];
        let secret = Self::secret_of(&g, &rec.chan)?;
        let payee = hex::decode(&rec.payee_pub).map_err(|_| err("bad_key", "payee_pub"))?;
        let key = channel_auth_key(&secret, &payee)?;
        Ok(xbt402::wire::request_auth(&key, &rec.chan, seq, cum, sig, req))
    }

    fn check_usable(&self, rec: &ChannelRecord) -> Result<()> {
        if rec.state != "open" {
            return Err(err(&format!("channel_{}", rec.state), format!("channel {} is {}", &rec.chan[..rec.chan.len().min(16)], rec.state)));
        }
        let guard = self.expiry_guard.lock().ok().and_then(|g| g.clone());
        if let Some((height, margin)) = guard {
            let h = height()? as i64;
            if h >= rec.expiry - margin {
                return Err(err("channel_expiring", format!("height {h} is within {margin} blocks of expiry {}: close or refund it", rec.expiry)));
            }
        }
        Ok(())
    }

    fn payer_locked(&self, g: &Inner, rec: &ChannelRecord) -> Result<Payer> {
        self.check_usable(rec)?;
        let secret = Self::secret_of(g, &rec.chan)?;
        let mut payer = Payer::new(rec.params()?, secret)?;
        payer.signed = rec.used_sats.max(0) as u64;
        Ok(payer)
    }

    /// H5: 0xA3 fee-input state. Never a lower cum.
    pub fn sign_state_a3(&self, chan: &str, amount: i64) -> Result<Vec<u8>> {
        let mut g = self.lock();
        let k = Self::key_of(&g, chan)?;
        let rec = g.records[&k].clone();
        if amount < rec.used_sats {
            return Err(err("stale_amount", format!("have {}, got {amount}", rec.used_sats)));
        }
        if amount > rec.cap_sats {
            return Err(cap_error(rec.used_sats, amount - rec.used_sats, rec.cap_sats));
        }
        let payer = self.payer_locked(&g, &rec)?;
        let sig = payer.sign_state_a3(amount as u64)?;
        audit_rec(&self.audit, "channel_state_a3", &sig, &rec.chan, &rec.dest, json!({"cum": amount, "sighash": "0xa3"}))?;
        let r = g.records.get_mut(&k).unwrap();
        r.used_sats = r.used_sats.max(amount);
        r.spent_sats = r.spent().max(amount);
        self.persist(&g)?;
        Ok(sig)
    }

    /// The payer's 0x21 signature for a rollover tx paying `amount` (CMP-003's
    /// `b2_sign_rollover`): open and expiry checks, never a stale amount or one over the cap.
    pub fn sign_rollover(&self, chan: &str, amount: i64, next_spk: &[u8], next_capacity: u64) -> Result<Vec<u8>> {
        let mut g = self.lock();
        let k = Self::key_of(&g, chan)?;
        let rec = g.records[&k].clone();
        if amount < rec.used_sats {
            return Err(err("stale_amount", format!("have {}, got {amount}", rec.used_sats)));
        }
        if amount > rec.cap_sats {
            return Err(cap_error(rec.used_sats, amount - rec.used_sats, rec.cap_sats));
        }
        let mut payer = self.payer_locked(&g, &rec)?;
        let sig = payer.sign_rollover(amount as u64, next_spk, next_capacity)?;
        audit_rec(&self.audit, "channel_rollover", &sig, &rec.chan, &rec.dest,
                  json!({"cum": amount, "sighash": "0x21", "next_spk": hex::encode(next_spk), "next_capacity": next_capacity}))?;
        let r = g.records.get_mut(&k).unwrap();
        r.used_sats = r.used_sats.max(amount);
        r.spent_sats = r.spent().max(amount);
        r.seq += 1;
        self.persist(&g)?;
        Ok(sig)
    }

    /// The 0x21 hash-locked state paying `uncond` plus the conditional amount (M6/M7). The
    /// conditional amount is not added to `used_sats` until the lock is folded into a plain state.
    pub fn sign_conditional(&self, chan: &str, uncond: i64, hash: [u8; 32], cond_amount: u64, csv_delta: u32, pending: Option<Value>) -> Result<(ChannelRecord, Vec<u8>)> {
        let mut g = self.lock();
        let k = Self::key_of(&g, chan)?;
        let rec = g.records[&k].clone();
        if uncond < rec.used_sats {
            return Err(err("stale_amount", format!("have {}, got {uncond}", rec.used_sats)));
        }
        if uncond + cond_amount as i64 > rec.cap_sats {
            return Err(cap_error(rec.used_sats, uncond + cond_amount as i64 - rec.used_sats, rec.cap_sats));
        }
        let payer = self.payer_locked(&g, &rec)?;
        let cp = ConditionalParams::new(payer.params.clone(), hash, cond_amount, csv_delta)?;
        let sig = payer.sign_conditional(uncond as u64, &cp)?;
        audit_rec(&self.audit, "conditional_state", &sig, &rec.chan, &rec.dest,
                  json!({"cum": uncond, "hashlock": hex::encode(hash), "cond_sats": cond_amount, "sighash": "0x21"}))?;
        let r = g.records.get_mut(&k).unwrap();
        r.seq += 1;
        if let Some(p) = pending {
            r.pending_cond = p;
        }
        let out = r.clone();
        self.persist(&g)?;
        Ok((out, sig))
    }

    pub fn clear_pending_cond(&self, key: &str) -> Result<()> {
        let mut g = self.lock();
        let k = Self::key_of(&g, key)?;
        g.records.get_mut(&k).unwrap().pending_cond = json!({});
        self.persist(&g)
    }

    /// Spend a seq without changing the signed cum (every paid request needs a new seq).
    pub fn fresh_seq(&self, dest: &str) -> Result<ChannelRecord> {
        let mut g = self.lock();
        let k = Self::key_of(&g, dest)?;
        let r = g.records.get_mut(&k).unwrap();
        r.seq += 1;
        let out = r.clone();
        self.persist(&g)?;
        Ok(out)
    }

    pub fn new_payer_key(&self) -> (SecretKey, String) {
        let s = xbt402::signer::random_secret();
        (s, hex::encode(ecdsa::pubkey(&s)))
    }

    /// A key for an external client's channel to `origin` (the `StateSigner` API), sealed on
    /// disk at once as `pending:<origin>`: a crash between its funding and `attach` loses nothing.
    pub fn issue_key(&self, origin: &str) -> Result<String> {
        let (s, pubk) = self.new_payer_key();
        let mut g = self.lock();
        g.secrets.insert(format!("pending:{origin}"), s);
        self.persist(&g)?;
        Ok(pubk)
    }

    /// Take the key [`issue_key`](Self::issue_key) sealed for `origin`.
    pub fn take_issued(&self, origin: &str) -> Result<SecretKey> {
        let mut g = self.lock();
        let s = g.secrets.remove(&format!("pending:{origin}")).ok_or_else(|| err("bad_key", "call new_key before attach"))?;
        self.persist(&g)?;
        Ok(s)
    }

    fn record_of(dest: &str, p: &ChannelParams, origin: &str, cap_sats: Option<i64>, open_height: i64) -> ChannelRecord {
        ChannelRecord { dest: dest.into(), chan: p.channel_id(), cap_sats: cap_sats.unwrap_or(p.max_amount() as i64), used_sats: 0,
                        expiry: p.expiry as i64, payer_pub: hex::encode(p.payer_pub), payee_pub: hex::encode(p.payee_pub),
                        close_fee: p.close_fee as i64, payer_spk: hex::encode(&p.payer_spk), payee_spk: hex::encode(&p.payee_spk),
                        funding_txid: p.funding_txid(), funding_vout: p.funding_vout() as i64, funding_sats: p.capacity as i64, seq: 0,
                        origin: origin.into(), open_height, spent_sats: 0, close_fee_payer: p.close_fee_payer.as_str().into(),
                        ..Default::default() }
    }

    /// P1: record a channel and seal its payer key before its funding is broadcast. A pending or
    /// open channel to the same dest is never replaced; a settled one is archived.
    #[allow(clippy::too_many_arguments)]
    pub fn add_pending(&self, dest: &str, secret: SecretKey, p: &ChannelParams, origin: &str, cap_sats: Option<i64>, open_height: i64,
                       open_url: &str, network: &str, min_conf: i64, funding_hex: &str) -> Result<ChannelRecord> {
        let mut g = self.lock();
        if let Some(old) = g.records.get(dest).cloned() {
            if old.state == "open" || old.state == "pending" {
                return Err(err(&format!("channel_{}", old.state), format!("{dest} already has a {} channel {}", old.state, &old.chan[..old.chan.len().min(16)])));
            }
            g.archived.push(serde_json::to_value(&old).unwrap_or(Value::Null));
        }
        let mut rec = Self::record_of(dest, p, origin, cap_sats, open_height);
        rec.state = "pending".into();
        rec.open_url = open_url.into();
        rec.network = network.into();
        rec.min_conf = min_conf;
        rec.funding_hex = funding_hex.into();
        rec.spent_sats = 0;
        g.records.insert(dest.into(), rec.clone());
        g.secrets.insert(p.channel_id(), secret);
        self.persist(&g)?;
        Ok(rec)
    }

    /// The funding of a pending channel was never broadcast: forget the record and its key.
    pub fn drop_pending(&self, dest: &str, chan: &str) -> Result<()> {
        let mut g = self.lock();
        match g.records.get(dest) {
            Some(r) if r.chan == chan && r.state == "pending" => {}
            _ => return Ok(()),
        }
        g.records.shift_remove(dest);
        g.secrets.remove(chan);
        if g.archived.last().and_then(|a| a.get("dest")).and_then(Value::as_str) == Some(dest) {
            let a = g.archived.pop().unwrap();
            if let Ok(r) = serde_json::from_value::<ChannelRecord>(a) {
                g.records.insert(dest.into(), r);
            }
        }
        self.persist(&g)
    }

    pub fn mark_open(&self, key: &str) -> Result<ChannelRecord> {
        let mut g = self.lock();
        let k = Self::key_of(&g, key)?;
        let r = g.records.get_mut(&k).unwrap();
        if r.state == "pending" {
            r.state = "open".into();
            r.open_error.clear();
            let out = r.clone();
            self.persist(&g)?;
            return Ok(out);
        }
        Ok(r.clone())
    }

    pub fn note_pending(&self, key: &str, open_error: Option<&str>, funding_height: Option<i64>) -> Result<()> {
        let mut g = self.lock();
        let k = Self::key_of(&g, key)?;
        let r = g.records.get_mut(&k).unwrap();
        if let Some(e) = open_error {
            r.open_error = e.chars().take(200).collect();
        }
        if let Some(h) = funding_height.filter(|h| *h != 0) {
            r.funding_height = h;
        }
        self.persist(&g)
    }

    /// A channel funded and opened elsewhere (the external client and routing paths): open at once.
    pub fn add_funded(&self, dest: &str, secret: SecretKey, p: &ChannelParams, origin: &str, cap_sats: Option<i64>, open_height: i64) -> Result<ChannelRecord> {
        let rec = Self::record_of(dest, p, origin, cap_sats, open_height);
        let mut g = self.lock();
        if let Some(old) = g.records.get(dest).cloned() {
            if old.state == "pending" {
                return Err(err("channel_pending", format!("{dest} has a pending channel {}", &old.chan[..old.chan.len().min(16)])));
            }
            if old.state != "open" {
                g.archived.push(serde_json::to_value(&old).unwrap_or(Value::Null));
            }
        }
        g.records.insert(dest.into(), rec.clone());
        g.secrets.insert(p.channel_id(), secret);
        self.persist(&g)?;
        Ok(rec)
    }

    /// A plain state under a pending lock would sit below it (refused); one at or above it
    /// dominates the lock, which is then no longer pending.
    fn plain_over_lock(rec: &mut ChannelRecord, cum: i64) -> Result<()> {
        if rec.has_pending_lock() {
            let lc = lk_int(&rec.pending_lock, "cum");
            if cum < lc {
                return Err(err("lock_outstanding", format!("a lock for {lc} is pending on this channel")));
            }
            rec.pending_lock = json!({});
        }
        Ok(())
    }

    /// Atomically raise the signed cumulative amount by a charge of `amount_sats`.
    pub fn increment(&self, dest: &str, amount_sats: i64) -> Result<(ChannelRecord, Vec<u8>)> {
        if amount_sats <= 0 {
            return Err(err("bad_amount", "amount must be positive"));
        }
        let mut g = self.lock();
        let mut rec = g.records.get(dest).cloned().ok_or_else(|| err("unknown_channel", dest.to_string()))?;
        let spent = rec.spent();
        if spent + amount_sats > rec.cap_sats {
            return Err(cap_error(spent, amount_sats, rec.cap_sats));
        }
        let new_spent = spent + amount_sats;
        let mut sign_cum = new_spent.max(rec.used_sats);
        let floor = rec.params()?.min_amount() as i64; // dust, + close_fee on a payee-pays channel (v1.2)
        if 0 < sign_cum && sign_cum < floor {
            if floor > rec.cap_sats {
                return Err(cap_error(spent, floor - spent, rec.cap_sats));
            }
            sign_cum = floor;
        }
        Self::plain_over_lock(&mut rec, sign_cum)?;
        let mut payer = self.payer_locked(&g, &rec)?;
        let mut sig = vec![];
        if sign_cum as u64 > payer.signed {
            if sign_cum as u64 > payer.params.max_amount() {
                return Err(cap_error(rec.used_sats, amount_sats, payer.params.max_amount() as i64));
            }
            sig = payer.sign_state(sign_cum as u64)?;
            rec.last_sig = hex::encode(&sig);
            audit_rec(&self.audit, "channel_state", &sig, &rec.chan, &rec.dest, json!({"cum": sign_cum, "sighash": "0x21"}))?;
        }
        rec.used_sats = sign_cum;
        rec.spent_sats = new_spent;
        rec.seq += 1;
        g.records.insert(dest.into(), rec.clone());
        self.persist(&g)?;
        Ok((rec, sig))
    }

    /// The caller (policy-checked) decided `cum`. Still refuses a cap breach. An already-signed
    /// cum hands back the cached signature (AGP-020).
    pub fn sign_state(&self, dest: &str, cum: i64) -> Result<Vec<u8>> {
        let mut g = self.lock();
        let k = Self::key_of(&g, dest)?;
        let mut rec = g.records[&k].clone();
        if cum > rec.cap_sats {
            return Err(cap_error(rec.used_sats, cum - rec.used_sats, rec.cap_sats));
        }
        if cum < rec.used_sats {
            return Err(err("stale_amount", format!("have {}, got {cum}", rec.used_sats)));
        }
        Self::plain_over_lock(&mut rec, cum)?;
        let mut payer = self.payer_locked(&g, &rec)?;
        let mut sig = vec![];
        if cum as u64 > payer.signed {
            sig = payer.sign_state(cum as u64)?;
            rec.last_sig = hex::encode(&sig);
            audit_rec(&self.audit, "channel_state", &sig, &rec.chan, &rec.dest, json!({"cum": cum, "sighash": "0x21"}))?;
        } else if !rec.last_sig.is_empty() {
            sig = hex::decode(&rec.last_sig).unwrap_or_default();
        }
        rec.used_sats = rec.used_sats.max(cum);
        rec.spent_sats = rec.spent().max(cum);
        rec.seq += 1;
        g.records.insert(k, rec);
        self.persist(&g)?;
        Ok(sig)
    }

    // --- AGP-021: adaptor-locked states (routed payments) -----------------------------------------

    /// Pre-sign state(cum) under `T1 = T + r·G` (`point` = T, the provider's invoice point; r fresh
    /// here). One pending lock per channel; (lock, r, T) are persisted before this returns.
    pub fn sign_state_adaptor(&self, dest: &str, cum: i64, point: &str, route: Value, a: &dyn AdaptorScheme) -> Result<Value> {
        let mut g = self.lock();
        let k = Self::key_of(&g, dest)?;
        let mut rec = g.records[&k].clone();
        if rec.has_pending_lock() {
            return Err(err("lock_outstanding", "one adaptor lock per channel at a time"));
        }
        if cum <= rec.used_sats {
            return Err(err("stale_amount", format!("a lock must raise the signed amount {}", rec.used_sats)));
        }
        if cum > rec.cap_sats {
            return Err(cap_error(rec.used_sats, cum - rec.used_sats, rec.cap_sats));
        }
        let payer = self.payer_locked(&g, &rec)?;
        if cum as u64 > payer.params.max_amount() {
            return Err(cap_error(rec.used_sats, cum - rec.used_sats, payer.params.max_amount() as i64));
        }
        let t = PublicKey::from_slice(&hex::decode(point).map_err(|_| err("bad_point", "point is not hex"))?)
            .map_err(|_| err("bad_point", "point is not on the curve"))?;
        let r = xbt402::signer::random_secret();
        let t1 = t.combine(&PublicKey::from_secret_key(SECP256K1, &r)).map_err(|_| err("bad_point", "T + rG is infinity"))?;
        let z = payer.params.sighash(&payer.params.state_tx(cum as u64)?)?;
        let secret = Self::secret_of(&g, &rec.chan)?;
        let pre = a.presign(&secret, &z, &t1)?;
        let t1_hex = hex::encode(t1.serialize());
        rec.pending_lock = json!({"cum": cum, "pre": pre, "r": secret_hex(&r), "T": point.to_lowercase(), "T1": t1_hex,
                                  "route": route, "prev_used": rec.used_sats, "at": ts_value((now_f64() * 1000.0).round() / 1000.0)});
        let mut pre_bytes = hex::decode(pre.get("R").and_then(Value::as_str).unwrap_or("")).unwrap_or_default();
        pre_bytes.extend(hex::decode(pre.get("s1").and_then(Value::as_str).unwrap_or("")).unwrap_or_default());
        audit_rec(&self.audit, "adaptor_presig", &pre_bytes, &rec.chan, &rec.dest,
                  json!({"cum": cum, "sighash": "0x21", "point": t1_hex, "route": rec.pending_lock["route"]}))?;
        g.records.insert(k, rec);
        self.persist(&g)?; // write-ahead: before the pre-signature leaves
        Ok(json!({"adaptor": pre, "point": t1_hex, "tweak": secret_hex(&r), "cum": cum}))
    }

    /// The lock was paid: `secret` is t + r (the hub's answer) or t (the provider's receipt). It
    /// must open T1 or T. The locked amount becomes the signed (and spent) amount.
    pub fn resolve_lock(&self, dest: &str, secret: &str) -> Result<Value> {
        let mut g = self.lock();
        let k = Self::key_of(&g, dest)?;
        let rec = g.records.get_mut(&k).unwrap();
        if !rec.has_pending_lock() {
            return Err(err("no_state", "no pending lock on this channel"));
        }
        let lk = rec.pending_lock.clone();
        let y: [u8; 32] = hex::decode(secret.trim()).ok().and_then(|b| {
            let mut p = [0u8; 32];
            (b.len() <= 32).then(|| { p[32 - b.len()..].copy_from_slice(&b); p })
        }).ok_or_else(|| err("bad_secret", "secret is not a 32-byte hex scalar"))?;
        let r = parse_secret(lk["r"].as_str().unwrap_or(""))?;
        let yp = point_of(&y);
        let pt = |k: &str| hex::decode(lk[k].as_str().unwrap_or("")).ok().and_then(|b| PublicKey::from_slice(&b).ok());
        let t = if yp.is_some() && yp == pt("T1") {
            // t = y - r
            let ys = SecretKey::from_slice(&y).map_err(|_| err("bad_secret", "zero"))?;
            let neg_r = r.negate();
            ys.add_tweak(&Scalar::from(neg_r)).map(|s| s.secret_bytes()).unwrap_or([0u8; 32])
        } else if yp.is_some() && yp == pt("T") {
            y
        } else {
            return Err(err("bad_secret", "the secret opens neither T1 nor T"));
        };
        let cum = lk_int(&lk, "cum");
        rec.used_sats = rec.used_sats.max(cum);
        rec.spent_sats = rec.spent().max(cum);
        rec.acked_sats = rec.used_sats; // the hub holds the completed state
        rec.last_sig.clear();
        rec.pending_lock = json!({});
        self.persist(&g)?;
        Ok(json!({"t": hex::encode(t), "cum": cum, "amount": cum - lk_int(&lk, "prev_used"), "route": lk.get("route").cloned().unwrap_or(json!({}))}))
    }

    /// Give the pending lock up (the hub refused it, or its invoice expired unanswered).
    pub fn void_lock(&self, dest: &str) -> Result<Value> {
        let mut g = self.lock();
        let k = Self::key_of(&g, dest)?;
        let rec = g.records.get_mut(&k).unwrap();
        let lk = std::mem::replace(&mut rec.pending_lock, json!({}));
        if has_lock(&lk) {
            rec.given_up.push(json!({"cum": lk_int(&lk, "cum"), "prev_used": lk_int(&lk, "prev_used"),
                                     "route": lk.get("route").cloned().unwrap_or(json!({})), "at": ts_value((now_f64() * 1000.0).round() / 1000.0)}));
            let n = rec.given_up.len();
            if n > 16 {
                rec.given_up.drain(..n - 16);
            }
            self.persist(&g)?;
        }
        Ok(lk)
    }

    /// A lock we gave up was completed after all: its amount is now signed and spent. Only the cum
    /// of a lock this book pre-signed is accepted.
    pub fn adopt_lock(&self, dest: &str, cum: i64) -> Result<Value> {
        let mut g = self.lock();
        let k = Self::key_of(&g, dest)?;
        let rec = g.records.get_mut(&k).unwrap();
        let i = rec.given_up.iter().position(|x| lk_int(x, "cum") == cum).ok_or_else(|| err("bad_amount", "not a lock this wallet pre-signed"))?;
        if rec.has_pending_lock() {
            return Err(err("lock_outstanding", "resolve or void the pending lock first"));
        }
        let gu = rec.given_up.remove(i);
        let amount = (cum - rec.used_sats).max(0);
        rec.used_sats = rec.used_sats.max(cum);
        rec.spent_sats = rec.spent().max(cum);
        rec.acked_sats = rec.used_sats;
        self.persist(&g)?;
        Ok(json!({"cum": cum, "amount": amount, "route": gu.get("route").cloned().unwrap_or(json!({}))}))
    }

    /// After a restart: the hub closed ch1 with our completed pre-signature; t + r is in it.
    pub fn recover_lock(&self, dest: &str, witness: &[Vec<u8>], a: &dyn AdaptorScheme) -> Result<Value> {
        let lk = {
            let g = self.lock();
            let k = Self::key_of(&g, dest)?;
            g.records[&k].pending_lock.clone()
        };
        if !has_lock(&lk) {
            return Err(err("no_state", "no pending lock on this channel"));
        }
        let t1 = hex::decode(lk["T1"].as_str().unwrap_or("")).ok().and_then(|b| PublicKey::from_slice(&b).ok())
            .ok_or_else(|| err("bad_point", "stored T1"))?;
        for item in witness {
            if let Some(y) = a.extract(&lk["pre"], item, &t1) {
                return self.resolve_lock(dest, &hex::encode(y));
            }
        }
        Err(err("bad_secret", "this close does not carry our lock"))
    }

    /// Re-hand the last signed-but-unacknowledged state (same cum, same sig, fresh seq).
    pub fn resend_state(&self, dest: &str) -> Result<(ChannelRecord, Vec<u8>)> {
        let mut g = self.lock();
        let rec = g.records.get_mut(dest).ok_or_else(|| err("unknown_channel", dest.to_string()))?;
        if rec.last_sig.is_empty() || rec.used_sats <= rec.acked_sats {
            return Err(err("no_unacked_state", dest.to_string()));
        }
        rec.seq += 1;
        let out = rec.clone();
        self.persist(&g)?;
        let sig = hex::decode(&out.last_sig).unwrap_or_default();
        Ok((out, sig))
    }

    /// The provider recorded this signed cum (a receipt or a PAYMENT-RESPONSE).
    pub fn ack_state(&self, dest: &str, cum: Option<i64>) -> Result<()> {
        let mut g = self.lock();
        let Some(rec) = g.records.get_mut(dest) else { return Ok(()) };
        rec.acked_sats = match cum {
            None => rec.used_sats,
            Some(c) => c.min(rec.used_sats),
        };
        self.persist(&g)
    }

    // --- lifecycle ---------------------------------------------------------------------------------
    fn filtered(&self, f: impl Fn(&ChannelRecord) -> bool) -> Vec<ChannelRecord> {
        self.lock().records.values().filter(|r| f(r)).cloned().collect()
    }

    pub fn open_records(&self) -> Vec<ChannelRecord> {
        self.filtered(|r| r.state == "open")
    }

    /// Open and pending channels: their funding output may still be ours to refund (P1).
    pub fn unsettled_records(&self) -> Vec<ChannelRecord> {
        self.filtered(|r| r.state == "open" || r.state == "pending")
    }

    pub fn pending_records(&self) -> Vec<ChannelRecord> {
        self.filtered(|r| r.state == "pending")
    }

    /// Closed channels whose change is not yet counted (AGP-022).
    pub fn pending_close_records(&self) -> Vec<ChannelRecord> {
        self.filtered(|r| r.state == "closed" && r.close_change == "pending")
    }

    fn note_change(rec: &mut ChannelRecord, change: &Value) {
        if !rec.close_change.is_empty() && rec.close_change != "pending" {
            return; // final: counted, spent or none never change again
        }
        rec.close_change = change.get("status").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or("pending").into();
        let sf = crate::pyjson::py_int(change.get("scan_from")).unwrap_or(0);
        if sf != 0 {
            rec.close_scan_from = sf;
        }
        if let Some(t) = change.get("txid").and_then(Value::as_str).filter(|t| !t.is_empty()) {
            if rec.closed_txid.is_empty() || t != rec.closed_txid {
                rec.closed_txid = t.into(); // the close that actually spent the funding
            }
        }
    }

    /// `change` is the hot wallet's `learn_close_change` answer, taken before this call: a reader
    /// that sees the channel closed also sees its change counted, or close_change "pending".
    pub fn mark_closed(&self, key: &str, txid: &str, change: Option<&Value>, close_hex: &str) -> Result<()> {
        let mut g = self.lock();
        let k = Self::key_of(&g, key)?;
        let rec = g.records.get_mut(&k).unwrap();
        if rec.state == "open" || rec.state == "pending" {
            rec.state = "closed".into();
            if !txid.is_empty() {
                rec.closed_txid = txid.into();
            }
        } else if rec.state == "closed" && !txid.is_empty() && rec.closed_txid.is_empty() {
            rec.closed_txid = txid.into();
        } else if change.is_none() {
            return Ok(());
        }
        if !close_hex.is_empty() && rec.close_hex.is_empty() {
            rec.close_hex = close_hex.into();
        }
        if let Some(c) = change {
            if rec.state == "closed" {
                Self::note_change(rec, c);
            }
        }
        self.persist(&g)
    }

    pub fn note_close_change(&self, key: &str, change: &Value) -> Result<()> {
        let mut g = self.lock();
        let k = Self::key_of(&g, key)?;
        let rec = g.records.get_mut(&k).unwrap();
        if rec.state == "closed" && (rec.close_change.is_empty() || rec.close_change == "pending") {
            Self::note_change(rec, change);
            self.persist(&g)?;
        }
        Ok(())
    }

    /// The payer's CLTV refund of the whole funding output to `dest_spk` (B1 `refund_tx`). Only
    /// for an open or pending channel.
    pub fn refund_tx(&self, key: &str, dest_spk: &[u8], fee: Option<u64>) -> Result<(Tx, i64)> {
        let g = self.lock();
        let k = Self::key_of(&g, key)?;
        let rec = &g.records[&k];
        if rec.state != "open" && rec.state != "pending" {
            return Err(err(&format!("channel_{}", rec.state), if rec.refund_txid.is_empty() { rec.closed_txid.clone() } else { rec.refund_txid.clone() }));
        }
        let secret = Self::secret_of(&g, &rec.chan)?;
        let tx = rec.params()?.refund_tx(&secret, Some(dest_spk), fee)?;
        let sig = tx.inputs[0].witness.first().cloned().unwrap_or_default();
        audit_rec(&self.audit, "refund", &sig, &rec.chan, &rec.dest, json!({"txid": tx.txid(), "amount_sats": tx.outputs[0].value,
                                                                              "locktime": rec.expiry, "sighash": "0x21"}))?;
        Ok((tx, rec.expiry))
    }

    pub fn mark_refunded(&self, key: &str, txid: &str) -> Result<()> {
        let mut g = self.lock();
        let k = Self::key_of(&g, key)?;
        let rec = g.records.get_mut(&k).unwrap();
        rec.state = "refunded".into();
        rec.refund_txid = txid.into();
        self.persist(&g)
    }

    /// The 0x21 hash-locked final-chunk state for the session's stream purchase, signed under
    /// the book's lock: (record after the seq bump, signature).
    pub fn sign_stream_final(&self, dest: &str, hash: [u8; 32], price: u64, csv: u32, pending: Value) -> Result<(ChannelRecord, Vec<u8>)> {
        let used = self.get(dest).map(|r| r.used_sats).ok_or_else(|| err("unknown_channel", dest.to_string()))?;
        self.sign_conditional(dest, used, hash, price, csv, Some(pending))
    }
}

/// `DER || 0x21` over a digest with a book-held key (tests and the stream path).
pub fn sign21(secret: &SecretKey, digest: &[u8; 32]) -> Vec<u8> {
    sign_with_type(secret, digest, SIGHASH_ALL_UNIFIED)
}
