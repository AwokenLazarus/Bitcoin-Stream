//! AGP-039: the signer methods behind the web UI (`xbt-wallet-ui`), for a box with no terminal.
//!
//! Everything that raises what the wallet may spend, or moves or exports keys, needs a signature by
//! the human's ed25519 key, exactly like `approve` and `sweep_hot`: a new policy (`policy_set`), a new
//! human key (`human_key_rotate`), a hot-key rotation (`rotate_hot_key_signed`) and the backup export
//! (`backup_export`). The socket is shared with the model-facing process, so a login to the UI is never
//! what authorises these; the signature is. AGP-063 W3: refusing an approval (`deny_approval`) and
//! the plain `rotate_hot_key` need it too. The first human key is enrolled only with the one-time
//! code this signer writes to its log and `.run/enroll-code` while none is enrolled (W4): a process on
//! the socket cannot read the console or the run dir, so it cannot enrol its own key first.
//!
//! An over-threshold `xbt402_pay` becomes a *grant* when approved: the human signs (token, origin,
//! max_sats, expiry) and the agent's next `xbt402_pay` of the same URL, method and `max_sats` pays under
//! it, once (see `Signer::xbt402_pay_locked`). Every other token keeps B2's `approve` (pay at once).
use std::path::Path;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::approval::{backup_message, deny_message, human_key_message, policy_message, rotate_message, verify, x2b};
use crate::keystore::{random_bytes, write_private};
use crate::keystore::KeyStore;
use crate::policy::{validate_policy, PolicyConfig, RESTART_KEYS};
use crate::pyjson::{dumps, dumps_indent, py_int, str_or_empty, ts_value};
use crate::routing::RoutePolicy;
use crate::sanitize::sanitize;
use crate::signer::{deny, Signer};
use crate::{err, Result};

/// How long a prepared policy change may wait for the human's signature.
pub const POLICY_SIGN_WINDOW_S: i64 = 600;
/// The shortest backup passphrase the export accepts.
pub const MIN_BACKUP_PASS: usize = 12;
/// AGP-063 W4: the enrolment code's file under `.run`, and the wrong codes one code survives.
pub const ENROLL_CODE_FILE: &str = "enroll-code";
pub const ENROLL_CODE_TRIES: u32 = 5;

/// The one-time code that enrols the first human key, and the wrong codes tried against it.
#[derive(Default)]
pub struct EnrollCode {
    code: String,
    failures: u32,
}

/// 60 random bits as `XXXX-XXXX-XXXX` (Crockford base32: no I, L, O or U to misread).
fn new_enroll_code() -> String {
    const A: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let n = u64::from_le_bytes(random_bytes::<8>());
    let c: Vec<u8> = (0..12).map(|i| A[((n >> (5 * i)) & 31) as usize]).collect();
    format!("{}-{}-{}", String::from_utf8_lossy(&c[..4]), String::from_utf8_lossy(&c[4..8]), String::from_utf8_lossy(&c[8..]))
}

fn canon_code(s: &str) -> Vec<u8> {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect::<String>().into_bytes()
}

/// Equal-length compare without an early exit.
fn same_code(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// The exact bytes a policy change writes: sorted keys, two-space indent, a final newline.
pub fn canonical_policy(v: &Value) -> String {
    format!("{}\n", dumps_indent(v, 2, true))
}

fn outcome(state: &str, extra: Value) -> Value {
    let mut v = json!({"state": state});
    for (k, x) in extra.as_object().into_iter().flatten() {
        v[k] = x.clone();
    }
    v
}

/// The values in force, defaults included (the UI shows them for keys policy.json leaves out).
pub fn effective(c: &PolicyConfig) -> Value {
    json!({"max_per_tx_sats": c.max_per_tx_sats, "daily_budget_sats": c.daily_budget_sats, "weekly_budget_sats": c.weekly_budget_sats,
           "per_counterparty_cap_sats": c.per_counterparty_cap_sats, "velocity_max": c.velocity_max, "velocity_window_s": c.velocity_window_s,
           "human_threshold_sats": c.human_threshold_sats, "split_window_s": c.split_window_s, "approval_ttl_s": c.approval_ttl_s,
           "channel_expiry_blocks": c.channel_expiry_blocks, "treasury_csv": c.treasury_csv, "refund_enabled": c.refund_enabled,
           "refund_margin_blocks": c.refund_margin_blocks, "hot_balance_cap_sats": c.hot_balance_cap_sats, "anchor_interval_s": c.anchor_interval_s,
           "anchor_required": c.anchor_required, "open_wait_s": c.open_wait_s, "open_retry_s": c.open_retry_s, "close_fee_max_sats": c.close_fee_max_sats,
           "regtest_mine": c.regtest_mine, "forward": c.forward})
}

impl Signer {
    fn policy_path(&self) -> std::path::PathBuf {
        self.root.join("policy.json")
    }

    fn policy_text(&self) -> Result<String> {
        std::fs::read_to_string(self.policy_path()).map_err(|e| err("io", format!("policy.json: {e}")))
    }

    fn policy_raw(&self) -> Result<Value> {
        serde_json::from_str(&self.policy_text()?).map_err(|e| err("policy", format!("policy.json: {e}")))
    }

    fn now_i(&self) -> i64 {
        self.engine.now() as i64
    }

    fn remember(&self, token: &str, v: Value) {
        if let Ok(mut m) = self.approval_outcomes.lock() {
            if m.len() > 1000 {
                m.clear();
            }
            m.insert(token.to_string(), v);
        }
    }

    /// Write policy.json atomically (the previous file is kept as policy.json.prev) and put it in force.
    fn write_policy(&self, text: &str) -> Result<PolicyConfig> {
        let raw: Value = serde_json::from_str(text).map_err(|e| err("policy", format!("policy.json: {e}")))?;
        let cfg = PolicyConfig::from_value(&raw)?;
        let path = self.policy_path();
        let tmp = path.with_extension("json.tmp");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp).map_err(|e| err("io", e.to_string()))?;
            f.write_all(text.as_bytes()).and_then(|_| f.sync_all()).map_err(|e| err("io", e.to_string()))?;
        }
        if path.exists() {
            let _ = std::fs::copy(&path, path.with_extension("json.prev"));
        }
        std::fs::rename(&tmp, &path).map_err(|e| err("io", e.to_string()))?;
        self.engine.set_config(cfg.clone());
        self.routing.set_policy(RoutePolicy::from_value(&cfg.routing));
        self.hot.set_cap_sats(cfg.hot_balance_cap_sats);
        self.set_config_live(cfg.clone());
        Ok(cfg)
    }

    /// Restart-only keys whose value on disk differs from the one this process started with.
    /// Compared as the values in force (defaults included), so writing a default out is no change.
    fn pending_restart(&self, raw: &Value) -> Vec<String> {
        let (Ok(now), Ok(boot)) = (PolicyConfig::from_value(raw), PolicyConfig::from_value(&self.boot_policy)) else { return vec![] };
        let (a, b) = (effective(&now), effective(&boot));
        RESTART_KEYS.iter().filter(|k| a.get(**k) != b.get(**k)).map(|k| k.to_string()).collect()
    }

    fn check_sig(&self, msg: &[u8], p: &Value, expiry: i64) -> Option<Value> {
        let human = self.human_key();
        if human.is_empty() {
            return Some(deny("human_key", "no human key is enrolled: run the setup first"));
        }
        let sig = x2b(&str_or_empty(p.get("signature"))).unwrap_or_default();
        if sig.is_empty() || !verify(&human, msg, &sig) {
            return Some(deny("human_sig", "missing or invalid human signature"));
        }
        if expiry < self.now_i() {
            return Some(deny("expired", "the signature has expired"));
        }
        None
    }

    fn approval_row(token: &str, a: &Value, now: i64) -> Value {
        let expires = py_int(a.get("expires")).unwrap_or(0);
        let approved = a.get("approved") == Some(&Value::Bool(true));
        let state = if expires < now { "expired" } else if approved { "approved" } else { "pending" };
        json!({"token": token, "dest": a.get("dest"), "amount_sats": a.get("amount_sats"), "memo": a.get("memo"), "expires": expires,
               "ts": a.get("ts"), "kind": a.get("kind").cloned().unwrap_or("pay".into()), "url": a.get("url"), "method": a.get("method"),
               "payment_hash": a.get("payment_hash"), "state": state})
    }

    /// The UI's methods; `None` for a method this module does not know.
    pub(crate) fn admin_dispatch(&self, method: &str, p: &Value) -> Option<Result<Value>> {
        Some(match method {
            "approvals" => self.approvals(),
            "approval_status" => self.approval_status(&str_or_empty(p.get("token"))),
            "deny_approval" => self.deny_approval(p),
            "policy_get" => self.policy_get(),
            "policy_validate" => {
                let (errors, warnings) = validate_policy(p.get("policy").unwrap_or(&Value::Null));
                Ok(json!({"ok": errors.is_empty(), "errors": errors, "warnings": warnings}))
            }
            "policy_prepare" => self.policy_prepare(p),
            "policy_set" => self.policy_set(p),
            "human_key_enroll" => self.human_key_enroll(p),
            "human_key_rotate" => self.human_key_rotate(p),
            "rotate_hot_key" | "rotate_hot_key_signed" => self.rotate_signed(p),
            "backup_export" => self.backup_export(p),
            "keystore_status" => self.keystore_status(),
            "channel_reports" => Ok(json!({"reports": self.close_reports(), "height": self.height_safe(),
                                           "refund_margin_blocks": self.config().refund_margin_blocks,
                                           "refund_enabled": self.config().refund_enabled})),
            _ => return None,
        })
    }

    fn approvals(&self) -> Result<Value> {
        let now = self.now_i();
        let rows: Vec<Value> = self.engine.store.approvals()?.iter().filter(|(_, a)| a.get("used") != Some(&Value::Bool(true)))
            .map(|(t, a)| Self::approval_row(t, a, now)).collect();
        Ok(sanitize(json!({"approvals": rows, "now": now, "human_key": !self.human_key().is_empty()})))
    }

    fn approval_status(&self, token: &str) -> Result<Value> {
        if let Some(a) = self.engine.store.get_approval(token)? {
            return Ok(Self::approval_row(token, &a, self.now_i()));
        }
        let known = self.approval_outcomes.lock().ok().and_then(|m| m.get(token).cloned());
        Ok(known.unwrap_or_else(|| json!({"token": token, "state": "unknown"})))
    }

    /// Refuse or revoke an approval: signed by the human (`deny_message`), since a refused grant is
    /// a payment the human wanted; an approval that has already expired may be dismissed unsigned.
    fn deny_approval(&self, p: &Value) -> Result<Value> {
        let token = str_or_empty(p.get("token"));
        let reason: String = str_or_empty(p.get("reason")).chars().take(200).collect();
        let Some(a) = self.engine.store.get_approval(&token)? else { return Ok(deny("approval", "unknown or already-used approval token")) };
        if py_int(a.get("expires")).unwrap_or(0) >= self.now_i() {
            let expiry = py_int(p.get("expiry")).unwrap_or(0);
            if let Some(d) = self.check_sig(&deny_message(&token, expiry), p, expiry) {
                return Ok(d);
            }
        }
        let Some(a) = self.engine.store.pop_approval(&token)? else { return Ok(deny("approval", "unknown or already-used approval token")) };
        self.engine.audit.append(json!({"type": "approval_denied", "token": token, "dest": a.get("dest"), "amount_sats": a.get("amount_sats"),
                                        "reason": reason, "ts": ts_value(self.engine.now())}));
        self.remember(&token, outcome("denied", json!({"token": token, "reason": reason})));
        Ok(json!({"ok": true, "token": token, "state": "denied"}))
    }

    fn policy_get(&self) -> Result<Value> {
        let text = self.policy_text()?;
        let raw: Value = serde_json::from_str(&text).map_err(|e| err("policy", format!("policy.json: {e}")))?;
        let (errors, warnings) = validate_policy(&raw);
        Ok(json!({"policy": raw, "text": text, "sha256": sha256_hex(text.as_bytes()), "human_key": hex::encode(self.human_key()),
                  "restart_keys": RESTART_KEYS, "pending_restart": self.pending_restart(&raw), "errors": errors, "warnings": warnings,
                  "routing": self.routing.policy().public(), "hot_cap_sats": self.hot.cap_sats(), "effective": effective(&self.config())}))
    }

    /// Validate a proposed policy and return the exact text and message the human signs.
    fn policy_prepare(&self, p: &Value) -> Result<Value> {
        let Some(Value::Object(proposed)) = p.get("policy") else { return Ok(json!({"ok": false, "errors": ["policy.json: not a JSON object"], "warnings": []})) };
        let mut proposed = proposed.clone();
        // the human key only changes through human_key_rotate (signed by the old key)
        let human = hex::encode(self.human_key());
        if human.is_empty() {
            proposed.remove("human_pubkey");
        } else {
            proposed.insert("human_pubkey".into(), human.clone().into());
        }
        let v = Value::Object(proposed);
        let (errors, warnings) = validate_policy(&v);
        if !errors.is_empty() {
            return Ok(json!({"ok": false, "errors": errors, "warnings": warnings}));
        }
        let text = canonical_policy(&v);
        let old = self.policy_raw().unwrap_or(json!({}));
        let prev = sha256_hex(self.policy_text()?.as_bytes());
        let expiry = self.now_i() + POLICY_SIGN_WINDOW_S;
        let mut keys: Vec<&String> = v.as_object().into_iter().flatten().map(|(k, _)| k).chain(old.as_object().into_iter().flatten().map(|(k, _)| k)).collect();
        keys.sort();
        keys.dedup();
        let diff: Vec<Value> = keys.into_iter().filter(|k| v.get(*k) != old.get(*k))
            .map(|k| json!({"key": k, "old": old.get(k), "new": v.get(k), "restart": RESTART_KEYS.contains(&k.as_str())})).collect();
        let msg = policy_message(&prev, expiry, &text);
        Ok(json!({"ok": true, "text": text, "prev_sha256": prev, "expiry": expiry, "message_hex": hex::encode(&msg), "diff": diff,
                  "warnings": warnings, "human_key": !human.is_empty()}))
    }

    fn policy_set(&self, p: &Value) -> Result<Value> {
        let _g = self.lock();
        let text = str_or_empty(p.get("text"));
        let prev = str_or_empty(p.get("prev_sha256"));
        let expiry = py_int(p.get("expiry")).unwrap_or(0);
        if let Some(d) = self.check_sig(&policy_message(&prev, expiry, &text), p, expiry) {
            self.engine.audit.append(json!({"type": "policy_refused", "rule": d["rule"], "ts": ts_value(self.engine.now())}));
            return Ok(d);
        }
        let cur = self.policy_text()?;
        if sha256_hex(cur.as_bytes()) != prev {
            return Ok(deny("policy_stale", "policy.json changed since this change was prepared: prepare and sign it again"));
        }
        let Ok(v) = serde_json::from_str::<Value>(&text) else { return Ok(deny("policy", "the signed policy is not JSON")) };
        if canonical_policy(&v) != text {
            return Ok(deny("policy", "the signed policy is not in canonical form (prepare it with policy_prepare)"));
        }
        let (errors, _) = validate_policy(&v);
        if !errors.is_empty() {
            return Ok(json!({"verdict": "deny", "rule": "policy", "reason": errors.join("; "), "errors": errors}));
        }
        if v.get("human_pubkey").and_then(Value::as_str).unwrap_or("") != hex::encode(self.human_key()) {
            return Ok(deny("human_key", "a policy change cannot change the human key (use human_key_rotate)"));
        }
        self.write_policy(&text)?;
        let sha = sha256_hex(text.as_bytes());
        self.engine.audit.append(json!({"type": "policy_change", "prev_sha256": prev, "sha256": sha, "ts": ts_value(self.engine.now())}));
        Ok(json!({"ok": true, "verdict": "allow", "sha256": sha, "pending_restart": self.pending_restart(&v)}))
    }

    fn set_human_pubkey_in_policy(&self, new_hex: &str) -> Result<String> {
        let mut raw = self.policy_raw()?;
        raw["human_pubkey"] = new_hex.into();
        let text = canonical_policy(&raw);
        self.write_policy(&text)?;
        self.set_human_key(hex::decode(new_hex).unwrap_or_default());
        Ok(sha256_hex(text.as_bytes()))
    }

    fn parse_pub(p: &Value) -> Option<String> {
        let h = str_or_empty(p.get("pubkey")).trim().to_lowercase();
        let b = hex::decode(&h).ok().filter(|b| b.len() == 32)?;
        ed25519_dalek::VerifyingKey::from_bytes(&<[u8; 32]>::try_from(b.as_slice()).ok()?).ok()?;
        Some(h)
    }

    fn human_key_enroll(&self, p: &Value) -> Result<Value> {
        let _g = self.lock();
        if !self.human_key().is_empty() {
            return Ok(deny("human_key", "a human key is already enrolled: rotate it with a signature by the current key"));
        }
        let Some(new) = Self::parse_pub(p) else { return Ok(deny("human_key", "pubkey must be a 32-byte ed25519 public key in hex")) };
        if let Some(d) = self.take_enroll_code(&str_or_empty(p.get("code")))? {
            return Ok(d);
        }
        let sha = self.set_human_pubkey_in_policy(&new)?;
        self.engine.audit.append(json!({"type": "human_key_enrolled", "human_pubkey": new, "ts": ts_value(self.engine.now())}));
        Ok(json!({"ok": true, "human_pubkey": new, "policy_sha256": sha}))
    }

    /// While no human key is enrolled: a fresh one-time code, written to the log and to
    /// `.run/enroll-code` (0600), where only the box's owner reads it (Umbrel and StartOS: the app's log).
    pub(crate) fn issue_enroll_code(&self) -> Result<()> {
        let code = new_enroll_code();
        write_private(&self.run.join(ENROLL_CODE_FILE), &format!("{code}\n"))?;
        eprintln!("xbt-signer: no human key is enrolled. One-time enrolment code: {code} (also in {})", self.run.join(ENROLL_CODE_FILE).display());
        *self.enroll.lock().unwrap_or_else(|p| p.into_inner()) = EnrollCode { code, failures: 0 };
        Ok(())
    }

    /// `None` when `given` is the current code (now spent); else the deny. After
    /// [`ENROLL_CODE_TRIES`] wrong codes a new code replaces it.
    fn take_enroll_code(&self, given: &str) -> Result<Option<Value>> {
        let mut g = self.enroll.lock().unwrap_or_else(|p| p.into_inner());
        if !g.code.is_empty() && same_code(&canon_code(given), &canon_code(&g.code)) {
            *g = EnrollCode::default();
            drop(g);
            let _ = std::fs::remove_file(self.run.join(ENROLL_CODE_FILE));
            return Ok(None);
        }
        g.failures += 1;
        let renew = g.code.is_empty() || g.failures >= ENROLL_CODE_TRIES;
        drop(g);
        self.engine.audit.append(json!({"type": "human_key_enroll_refused", "renewed": renew, "ts": ts_value(self.engine.now())}));
        if renew {
            self.issue_enroll_code()?;
        }
        Ok(Some(deny("enroll_code", format!("missing or wrong enrolment code: read it in the signer's log or {}{}",
                                             self.run.join(ENROLL_CODE_FILE).display(), if renew { " (a new code was issued)" } else { "" }))))
    }

    fn human_key_rotate(&self, p: &Value) -> Result<Value> {
        let _g = self.lock();
        let Some(new) = Self::parse_pub(p) else { return Ok(deny("human_key", "pubkey must be a 32-byte ed25519 public key in hex")) };
        let old = hex::encode(self.human_key());
        let expiry = py_int(p.get("expiry")).unwrap_or(0);
        if let Some(d) = self.check_sig(&human_key_message(&old, &new, expiry), p, expiry) {
            return Ok(d);
        }
        let sha = self.set_human_pubkey_in_policy(&new)?;
        self.engine.audit.append(json!({"type": "human_key_rotated", "old": old, "human_pubkey": new, "ts": ts_value(self.engine.now())}));
        Ok(json!({"ok": true, "human_pubkey": new, "policy_sha256": sha}))
    }

    fn rotate_signed(&self, p: &Value) -> Result<Value> {
        let _g = self.lock();
        let expiry = py_int(p.get("expiry")).unwrap_or(0);
        if let Some(d) = self.check_sig(&rotate_message(&self.hot.address(), expiry), p, expiry) {
            return Ok(d);
        }
        self.rotate_locked("human:rotate_signature")
    }

    fn backup_export(&self, p: &Value) -> Result<Value> {
        let expiry = py_int(p.get("expiry")).unwrap_or(0);
        if let Some(d) = self.check_sig(&backup_message(&self.hot.address(), expiry), p, expiry) {
            return Ok(d);
        }
        let pass = str_or_empty(p.get("backup_pass"));
        if pass.chars().count() < MIN_BACKUP_PASS {
            return Ok(deny("backup_pass", format!("the backup passphrase needs at least {MIN_BACKUP_PASS} characters")));
        }
        let Some(ks) = &self.keystore else { return Ok(deny("keystore", "the keys are not encrypted at rest (test mode): no backup export")) };
        let _g = self.lock();
        let mut files = Map::new();
        let mut add = |name: String, path: &Path| {
            if let Ok(t) = std::fs::read_to_string(path) {
                if t.len() <= 8 << 20 {
                    files.insert(name, t.into());
                }
            }
        };
        add("policy.json".into(), &self.policy_path());
        let mut names: Vec<_> = std::fs::read_dir(&self.run).map(|d| d.flatten().map(|e| e.path()).collect()).unwrap_or_else(|_| vec![]);
        names.sort();
        for path in names {
            let n = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            if (n.ends_with(".json") || n.ends_with(".jsonl")) && path.is_file() {
                add(format!(".run/{n}"), &path);
            }
        }
        let wrapped = KeyStore::with_passphrase(pass.as_bytes()).seal(&ks.wrapping_secret(), "xbt-agentwallet-backup-wrapping", None)?;
        self.engine.audit.append(json!({"type": "backup_export", "files": files.len(), "ts": ts_value(self.engine.now())}));
        let doc = json!({"format": "xbt-agentwallet-backup-v1", "created": self.now_i(), "hot_address": self.hot.address(),
                         "wrapping_kdf": ks.kind(), "wrapping_sealed": wrapped, "files": files,
                         "restore": "Put files back under the wallet root; open wrapping_sealed with the backup passphrase \
                                     (keystore scrypt blob, aad xbt-agentwallet-backup-wrapping): it is the B2_HOT_KEYFILE bytes (kdf keyfile) \
                                     or the B2_HOT_PASSPHRASE (kdf scrypt)."});
        // not sanitized: every key in it is sealed, and the file names must survive
        Ok(json!({"ok": true, "backup_json": dumps(&doc)}))
    }

    fn keystore_status(&self) -> Result<Value> {
        let keyfile = std::env::var(crate::keystore::ENV_KEYFILE).unwrap_or_default();
        let mode = if keyfile.is_empty() { Value::Null } else { format!("{:o}", crate::fsx::mode_of(Path::new(&keyfile)) & 0o777).into() };
        let policy_exists = self.policy_path().exists();
        Ok(json!({"encrypted": self.keystore.is_some(), "kdf": self.keystore.as_ref().map(|k| k.kind()).unwrap_or("none"),
                  "keyfile": if keyfile.is_empty() { Value::Null } else { keyfile.clone().into() }, "keyfile_mode": mode,
                  "human_key": !self.human_key().is_empty(), "human_pubkey": hex::encode(self.human_key()), "policy": policy_exists,
                  "hot": self.hot.status(), "chain": self.chain, "anchor": self.anchor.status()}))
    }

    fn close_reports_path(&self) -> std::path::PathBuf {
        self.run.join("close_reports.json")
    }

    pub(crate) fn close_reports(&self) -> Value {
        std::fs::read_to_string(self.close_reports_path()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(json!({}))
    }

    /// Keep a close's report (AGP-029) for the UI; B2's channels.json format is left as it is.
    pub(crate) fn save_close_report(&self, out: &Value) {
        let (Some(chan), Some(report)) = (out.get("chan").and_then(Value::as_str), out.get("close_report")) else { return };
        let mut all = self.close_reports();
        all[chan] = json!({"report": report, "txid": out.get("txid"), "cum": out.get("cum"), "dest": out.get("dest"), "ts": self.now_i()});
        let path = self.close_reports_path();
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, dumps(&all)).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }

    // --- the xbt402 grant --------------------------------------------------------------------------

    /// A human-approved, unused, unexpired xbt402 grant for exactly this call.
    pub(crate) fn find_xbt402_grant(&self, dest: &str, max_sats: i64, url: &str, method: &str) -> Option<String> {
        let now = self.now_i();
        self.engine.store.approvals().ok()?.into_iter().find(|(_, a)| {
            a.get("kind").and_then(Value::as_str) == Some("xbt402") && a.get("approved") == Some(&Value::Bool(true))
                && a.get("used") != Some(&Value::Bool(true)) && py_int(a.get("expires")).unwrap_or(0) >= now
                && a.get("dest").and_then(Value::as_str) == Some(dest) && py_int(a.get("amount_sats")) == Some(max_sats)
                && a.get("url").and_then(Value::as_str) == Some(url) && a.get("method").and_then(Value::as_str) == Some(method)
        }).map(|(t, _)| t)
    }

    /// The grant was spent: drop it and remember the outcome.
    pub(crate) fn use_xbt402_grant(&self, token: &str, charged: i64) {
        let _ = self.engine.store.pop_approval(token);
        self.engine.audit.append(json!({"type": "approval_used", "token": token, "charged_sats": charged, "ts": ts_value(self.engine.now())}));
        self.remember(token, outcome("used", json!({"token": token, "charged_sats": charged})));
    }

    /// `approve` of an xbt402 or (AGP-048) an ln token (the signature is already checked): mark it
    /// granted. The agent's same call again pays under it, once.
    pub(crate) fn grant_xbt402(&self, token: &str, payload: &Value) -> Result<Value> {
        if payload.get("approved") == Some(&Value::Bool(true)) {
            return Ok(deny("approval_replay", "approval token already approved"));
        }
        self.engine.store.update_approval(token, &json!({"approved": true, "approved_at": ts_value(self.engine.now())}))?;
        self.engine.audit.append(json!({"type": "approval_granted", "token": token, "dest": payload.get("dest"),
                                        "amount_sats": payload.get("amount_sats"), "url": payload.get("url"), "ts": ts_value(self.engine.now())}));
        if payload.get("kind").and_then(Value::as_str) == Some("ln") {
            return Ok(json!({"verdict": "allow", "approved": true, "granted": true, "rail": "ln", "token": token, "dest": payload.get("dest"),
                             "amount_sats": payload.get("amount_sats"), "payment_hash": payload.get("payment_hash"), "expires": payload.get("expires"),
                             "note": "the agent's next ln_pay of this invoice pays under this approval, once"}));
        }
        Ok(json!({"verdict": "allow", "approved": true, "granted": true, "rail": "xbt402", "token": token, "dest": payload.get("dest"),
                  "amount_sats": payload.get("amount_sats"), "url": payload.get("url"), "expires": payload.get("expires"),
                  "note": "the agent's next xbt402_pay of this url with this max_sats pays under this approval, once"}))
    }

    pub(crate) fn note_expired(&self, token: &str) {
        self.remember(token, outcome("expired", json!({"token": token})));
    }

    pub(crate) fn note_used(&self, token: &str) {
        self.remember(token, outcome("used", json!({"token": token})));
    }
}
