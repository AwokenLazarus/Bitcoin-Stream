//! AGP-067: review C2-C5 (B1 `tests/security/test_agp067_review_c.py`, same names for C2, C3, C5).
//! * C2: a seller that would refuse `/open` is asked first (`"preflight": true`, no outpoint), so
//!   the buyer funds nothing on-chain for a channel that never opens;
//! * C3: the rollover's txid is the one the payer computed from the tx it signed, never the
//!   provider's word for it;
//! * C4: the payTo key persists (0600) and a provider restarted on its data dir keeps its channels
//!   and closes them;
//! * C5: one opener per ledger file (provider and client ledgers), the lock gone with the ledger.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use xbt402::client::{split_url, Client, ClientConfig, ClientLedger, FileClientLedger, Transport, Wallet};
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt402::ledger::Ledger;
use xbt402::provider::{load_or_create_secret, HttpResponse, Provider, ProviderConfig};
use xbt402::wire::{OPEN_PATH, ROLLOVER_PATH};
use xbt402::{ChannelError, Result};
use xbt_primitives::address::address_to_spk;
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

const NET: &str = "bip122:11111111111111111111111111111111";
const O: &str = "https://api.example";

#[derive(Default)]
struct MemChain {
    tip: Mutex<u32>,
    utxos: Mutex<HashMap<(String, u32), UtxoInfo>>,
    sent: Mutex<Vec<Tx>>,
}

impl MemChain {
    fn new() -> Arc<Self> {
        let c = Self::default();
        *c.tip.lock().unwrap() = 1_000;
        Arc::new(c)
    }
}

impl ChainBackend for MemChain {
    fn block_count(&self) -> Result<u32> {
        Ok(*self.tip.lock().unwrap())
    }
    fn get_tx_out(&self, txid: &str, vout: u32, _m: bool) -> Result<Option<UtxoInfo>> {
        Ok(self.utxos.lock().unwrap().get(&(txid.to_string(), vout)).cloned())
    }
    fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        let tx = Tx::parse_hex(hex)?;
        let mut u = self.utxos.lock().unwrap();
        for i in &tx.inputs {
            if u.remove(&(i.prevout.txid_hex(), i.prevout.vout)).is_none() {
                return Err(ChannelError::new("rpc_error", "missing inputs"));
            }
        }
        for (n, o) in tx.outputs.iter().enumerate() {
            u.insert((tx.txid(), n as u32), UtxoInfo { confirmations: 1, value: o.value as u64, script_pubkey: o.script_pubkey.clone(), coinbase: false });
        }
        self.sent.lock().unwrap().push(tx.clone());
        Ok(tx.txid())
    }
    fn has_transaction(&self, txid: &str) -> Result<bool> {
        Ok(self.sent.lock().unwrap().iter().any(|t| t.txid() == txid))
    }
}

/// Counts what it funds: a refused open must leave it at zero.
struct CountingWallet(Arc<MemChain>, Arc<AtomicUsize>);

impl Wallet for CountingWallet {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        let n = self.1.fetch_add(1, Ordering::SeqCst) + 1;
        let txid = hex::encode(sha256(format!("funding {n}").as_bytes()));
        let spk = address_to_spk(address, None).map_err(|e| ChannelError::new("bad_address", e.to_string()))?;
        self.0.utxos.lock().unwrap().insert((txid.clone(), 0), UtxoInfo { confirmations: 1, value: sats, script_pubkey: spk, coinbase: false });
        Ok((txid, 0))
    }
}

/// The 402 from `offer`, `/open` (preflight or funded) to `open`: a seller restarted with another
/// payTo between its 402 and the buyer's open (C4's bug), or one that refuses on purpose.
struct Split {
    offer: Arc<Provider>,
    open: Arc<Provider>,
}

impl Transport for Split {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        let (_, path) = split_url(url);
        let p = if path == OPEN_PATH { &self.open } else { &self.offer };
        Ok(p.serve(method, &path, headers, body, url, None))
    }
}

type Rewrite = Box<dyn Fn(&str, &Value, HttpResponse) -> HttpResponse + Send + Sync>;

/// The provider, with `f` free to change each answer on the way back.
struct Edit(Arc<Provider>, Rewrite);

impl Transport for Edit {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        let (_, path) = split_url(url);
        let req: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        Ok((self.1)(&path, &req, self.0.serve(method, &path, headers, body, url, None)))
    }
}

fn secret(label: &str) -> SecretKey {
    SecretKey::from_slice(&sha256(label.as_bytes())).unwrap()
}

fn provider(chain: &Arc<MemChain>, key: SecretKey, ledger: Ledger) -> Arc<Provider> {
    Arc::new(Provider::new(chain.clone(), key, ProviderConfig::new(NET), ledger, Box::new(|_, _| 150),
                           Box::new(|_, p, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())],
                                                                  json!({"answer": p}).to_string().into_bytes()))).unwrap())
}

fn client(chain: &Arc<MemChain>, t: Box<dyn Transport>, funded: &Arc<AtomicUsize>) -> Client {
    let c = chain.clone();
    Client::new(ClientConfig::new(NET), t, Box::new(CountingWallet(chain.clone(), funded.clone())), Box::new(move || c.block_count()))
}

fn json_body(r: &HttpResponse) -> Value {
    serde_json::from_slice(&r.body).unwrap_or(Value::Null)
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("xbt-rs-agp067-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

// --- C2: no on-chain funding before the seller accepts /open ----------------------------------------

#[test]
fn c2_a_refused_open_funds_nothing() {
    let chain = MemChain::new();
    let funded = Arc::new(AtomicUsize::new(0));
    let before = provider(&chain, secret("payTo before the restart"), Ledger::in_memory());
    let after = provider(&chain, secret("payTo after the restart"), Ledger::in_memory());
    let mut c = client(&chain, Box::new(Split { offer: before, open: after.clone() }), &funded);
    let e = c.request("GET", &format!("{O}/v1/q"), b"").unwrap_err();
    assert_eq!(e.code, "bad_funding", "{e}");
    assert_eq!(funded.load(Ordering::SeqCst), 0, "the buyer funded a channel the seller refused");
    assert!(after.channel_ids().is_empty());
}

#[test]
fn c2_the_preflight_records_nothing() {
    let chain = MemChain::new();
    let funded = Arc::new(AtomicUsize::new(0));
    let prov = provider(&chain, secret("provider payTo"), Ledger::in_memory());
    let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
    let s2 = seen.clone();
    let t = Edit(prov.clone(), Box::new(move |path, req, r| {
        if path == OPEN_PATH && req.get("preflight") == Some(&Value::Bool(true)) {
            s2.lock().unwrap().push(json!({"req": req, "status": r.status, "body": json_body(&r)}));
        }
        r
    }));
    let mut c = client(&chain, Box::new(t), &funded);
    assert_eq!(c.request("GET", &format!("{O}/v1/q"), b"").unwrap().status, 200);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "one preflight before the funding");
    let (req, ans) = (&seen[0]["req"], &seen[0]["body"]);
    assert_eq!(seen[0]["status"], 200, "{ans}");
    assert_eq!(ans["preflight"], true);
    assert!(req["channel"].get("txid").is_none() && req["channel"].get("vout").is_none(), "no outpoint in a preflight: {req}");
    let p = &c.channels[O].payer.params;
    assert_eq!((ans["expiry"].as_u64(), ans["maxCum"].as_str()), (Some(p.expiry as u64), Some(p.max_amount().to_string().as_str())));
    assert_eq!(funded.load(Ordering::SeqCst), 1);
    assert_eq!(prov.channel_ids().len(), 1, "the funded open only");
    // a preflight on its own changes nothing, and refuses what the funded open would
    let mut again = req.clone();
    let r = prov.serve("POST", OPEN_PATH, &[], again.to_string().as_bytes(), &format!("{O}{OPEN_PATH}"), None);
    assert_eq!((r.status, json_body(&r)["preflight"].clone()), (200, json!(true)));
    assert_eq!(prov.channel_ids().len(), 1);
    again["channel"]["capacity"] = json!(prov.cfg.policy.max_capacity + 1);
    let r = prov.serve("POST", OPEN_PATH, &[], again.to_string().as_bytes(), &format!("{O}{OPEN_PATH}"), None);
    assert_eq!((r.status, json_body(&r)["error"].as_str()), (400, Some("bad_capacity")), "{}", String::from_utf8_lossy(&r.body));
}

#[test]
fn c2_a_provider_without_preflight_still_opens() {
    let chain = MemChain::new();
    let funded = Arc::new(AtomicUsize::new(0));
    let prov = provider(&chain, secret("provider payTo"), Ledger::in_memory());
    // a provider from before AGP-067 checks the terms, then fails on the missing vout
    let t = Edit(prov.clone(), Box::new(|path, req, r| {
        if path == OPEN_PATH && req.get("preflight") == Some(&Value::Bool(true)) {
            return HttpResponse::new(400, vec![], json!({"error": "bad_request", "detail": "vout"}).to_string().into_bytes());
        }
        r
    }));
    let mut c = client(&chain, Box::new(t), &funded);
    assert_eq!(c.request("GET", &format!("{O}/v1/q"), b"").unwrap().status, 200);
    assert_eq!((funded.load(Ordering::SeqCst), prov.channel_ids().len()), (1, 1));
}

// --- C3: the rollover txid is recomputed --------------------------------------------------------------

#[test]
fn c3_a_rollover_reply_naming_another_txid_is_refused() {
    let chain = MemChain::new();
    let funded = Arc::new(AtomicUsize::new(0));
    let prov = provider(&chain, secret("provider payTo"), Ledger::in_memory());
    let forged = hex::encode(sha256(b"a tx the payer never signed"));
    let f2 = forged.clone();
    let t = Edit(prov.clone(), Box::new(move |path, _, r| {
        if path != ROLLOVER_PATH || r.status != 200 {
            return r;
        }
        let mut b = json_body(&r);
        b["txid"] = f2.clone().into();
        b["nextChan"] = format!("{f2}:1").into();
        HttpResponse::new(200, r.headers.clone(), b.to_string().into_bytes())
    }));
    let mut c = client(&chain, Box::new(t), &funded);
    let refunds: Arc<Mutex<Vec<String>>> = Arc::default();
    let r2 = refunds.clone();
    c.on_refund = Some(Box::new(move |hx, _| r2.lock().unwrap().push(hx.to_string())));
    for _ in 0..8 {
        c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    }
    let e = c.rollover(O).unwrap_err();
    assert_eq!(e.code, "bad_rollover", "{e}");
    assert!(!e.msg.contains(&forged), "the error names the tx we signed: {e}");
    // the provider did broadcast the tx we signed: the refund of its next channel was kept
    let roll = chain.sent.lock().unwrap().last().unwrap().clone();
    let kept = Tx::parse_hex(refunds.lock().unwrap().last().expect("a refund for the next channel")).unwrap();
    assert_eq!(kept.inputs[0].prevout.txid_hex(), roll.txid());
    assert_eq!(kept.inputs[0].prevout.vout, 1);
}

// --- C4: a persistent payTo key and ledger ------------------------------------------------------------

#[test]
fn c4_the_payto_key_persists_0600_and_a_loose_file_is_refused() {
    let d = tmp("key");
    let path = d.join("sub").join("payto.key");
    let k = load_or_create_secret(&path).unwrap();
    assert_eq!(load_or_create_secret(&path).unwrap(), k, "the same key after a restart");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(load_or_create_secret(&path).unwrap_err().code, "key_file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(&path, "not a key").unwrap();
    assert_eq!(load_or_create_secret(&path).unwrap_err().code, "key_file");
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn c4_a_restarted_provider_keeps_its_key_and_channels_and_closes_them() {
    let d = tmp("restart");
    let chain = MemChain::new();
    let funded = Arc::new(AtomicUsize::new(0));
    let start = || provider(&chain, load_or_create_secret(&d.join("payto.key")).unwrap(), Ledger::open(&d.join("channels.jsonl")).unwrap());
    let prov = start();
    let pay_to = prov.pay_to().to_string();
    let mut c = client(&chain, Box::new(Edit(prov.clone(), Box::new(|_, _, r| r))), &funded);
    for _ in 0..3 {
        assert_eq!(c.request("GET", &format!("{O}/v1/q"), b"").unwrap().status, 200);
    }
    let p = c.channels[O].payer.params.clone();
    let best = prov.channel_state(&p.channel_id()).unwrap().best_cum;
    drop((c, prov));
    let prov = start();
    assert_eq!(prov.pay_to(), pay_to, "the payTo key survived the restart");
    assert_eq!(prov.channel_state(&p.channel_id()).unwrap().best_cum, best);
    *chain.tip.lock().unwrap() = p.expiry - prov.cfg.close_margin;
    assert_eq!(prov.close_due().unwrap().len(), 1, "the watcher closes the channel before the payer's refund");
    let _ = std::fs::remove_dir_all(d);
}

// --- C5: one opener per ledger file --------------------------------------------------------------------

#[test]
fn c5_a_second_provider_on_one_ledger_is_refused() {
    let d = tmp("lock");
    let path = d.join("ledger.jsonl");
    let first = Ledger::open(&path).unwrap();
    let e = Ledger::open(&path).unwrap_err();
    assert_eq!(e.code, "ledger_locked");
    assert!(e.msg.contains(&std::process::id().to_string()), "the error names the holder: {e}");
    // the lock goes with the ledger (a crash too: the OS drops it with the process)
    drop(first);
    Ledger::open(&path).unwrap();
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn c5_a_second_client_on_one_client_ledger_is_refused() {
    let d = tmp("client-lock");
    let path = d.join("client.jsonl");
    let first = FileClientLedger::open(&path).unwrap();
    assert_eq!(FileClientLedger::open(&path).unwrap_err().code, "ledger_locked");
    ClientLedger::save(&first, &[]).unwrap();
    drop(first);
    FileClientLedger::open(&path).unwrap();
    let _ = std::fs::remove_dir_all(d);
}

/// Another process holding `flock(2)` on the sidecar (util-linux `flock`, which B1's `fcntl.flock`
/// is the same call as) keeps a provider off the file.
#[cfg(target_os = "linux")]
#[test]
fn c5_another_process_holding_the_lock_is_refused() {
    let d = tmp("flock");
    let path = d.join("ledger.jsonl");
    let lock = d.join("ledger.jsonl.lock");
    std::fs::write(&lock, "").unwrap();
    // -o: flock(1) itself holds the lock, not the shell, which ends when its stdin closes
    let Ok(mut child) = std::process::Command::new("flock").args(["-o", "-n"]).arg(&lock).args(["-c", "echo held; read x || true"])
        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn() else {
        eprintln!("flock(1) not installed: the in-process cases cover the lock");
        return;
    };
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(child.stdout.take().unwrap()), &mut line).unwrap();
    assert_eq!(line.trim(), "held");
    let e = Ledger::open(&path).unwrap_err();
    assert_eq!(e.code, "ledger_locked");
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
    Ledger::open(&path).unwrap();
    let _ = std::fs::remove_dir_all(d);
}
