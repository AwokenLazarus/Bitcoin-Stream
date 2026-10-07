//! The B2 signer in Rust.
//!
//!   xbt-signer [--root DIR] [--check]       serve (or, with --check, run every start-up check and exit)
//!   xbt-signer healthcheck [--ready]        the image's HEALTHCHECK: the readiness file is fresh (and ok)
//!   xbt-signer call METHOD [PARAMS_JSON]    one socket request (operator tool), the result on stdout
//!
//! Environment as B2's signer: `B2_ROOT` (policy.json, `.run/`), `B2_DATADIR`, `B2_RPCPORT`, `B2_RPCHOST`,
//! `B2_RPCCOOKIE`, `B2_WALLET`, `B2_CHAIN`, `B2_SIGNER_SOCK` (a path, or `tcp://127.0.0.1:PORT`),
//! `B2_SIGNER_SOCK_MODE`, `B2_HOT_KEYFILE` / `B2_HOT_PASSPHRASE`, `B2_ANCHOR_SOCK`, `B2_WATCH_INTERVAL`,
//! `B2_HOT_SCAN`.
//!
//! Container mode (AGP-038, `docs/CONTAINER.md`): with `XBT_DATA_DIR` set and neither `--root` nor
//! `B2_ROOT`, the root is `$XBT_DATA_DIR/signer`; the socket is `run/signer/signer.sock` (mode 660), the
//! witness `run/anchor/anchor.sock` (`XBT_ANCHOR=off` to run without one); the policy comes from
//! `XBT_SIGNER_POLICY` (JSON) or `XBT_SIGNER_POLICY_FILE`, else the existing `policy.json`, else a
//! default that pays nobody; the node is `XBT_NODE_RPC_HOST`/`XBT_NODE_RPC_PORT`/`XBT_CHAIN` with
//! the secret `node-rpc-auth`; the wrapping key is the secret `signer-passphrase`, else
//! `signer-wrap-key` (32 bytes, generated 0600 on first run). The signer writes its readiness to
//! `run/signer/ready.json` every `XBT_READY_INTERVAL` seconds (default 5).
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use xbt_signer::anchor::AnchorClient;
use xbt_signer::client::SignerClient;
use xbt_signer::keystore::KeyStore;
use xbt_signer::signer::{Signer, SignerOptions};
use xbt_svc::{env, health, DataDir, Mode, Secrets};

fn die(code: i32, msg: impl std::fmt::Display) -> ! {
    eprintln!("xbt-signer: {msg}");
    std::process::exit(code)
}

fn set_default(k: &str, v: impl AsRef<std::ffi::OsStr>) {
    if std::env::var_os(k).is_none() {
        std::env::set_var(k, v);
    }
}

fn ready_interval() -> f64 {
    env("XBT_READY_INTERVAL").and_then(|v| v.parse().ok()).filter(|v: &f64| *v > 0.0).unwrap_or(5.0)
}

fn ready_file() -> Option<PathBuf> {
    env("XBT_SIGNER_READY_FILE").map(PathBuf::from).or_else(|| DataDir::from_env().map(|d| d.signer_ready()))
}

fn sock_path() -> PathBuf {
    env("B2_SIGNER_SOCK").map(PathBuf::from)
        .or_else(|| DataDir::from_env().map(|d| d.signer_sock()))
        .unwrap_or_else(|| PathBuf::from(env("B2_ROOT").unwrap_or_else(|| ".".into())).join(".run").join("signer.sock"))
}

/// A policy that pays nobody until the operator writes one: every limit at B2's defaults, an empty
/// allowlist, never mines.
fn default_policy(anchor_on: bool) -> Value {
    json!({"allowlist": [], "regtest_mine": false, "anchor_required": anchor_on})
}

/// Container mode: the root, the environment defaults, the keystore from the secret source.
fn container_setup(data: &DataDir, mode: Mode) -> Result<(PathBuf, Option<Arc<KeyStore>>), String> {
    let root = data.component(xbt_svc::SIGNER);
    xbt_svc::ensure_dir(&root, 0o700).map_err(|e| format!("{}: {e}", root.display()))?;
    let run = data.run(xbt_svc::RUN_SIGNER);
    xbt_svc::ensure_dir(&run, 0o750).map_err(|e| format!("{}: {e}", run.display()))?;
    set_default("B2_SIGNER_SOCK", data.signer_sock());
    set_default("B2_SIGNER_SOCK_MODE", "660");
    let anchor_on = !matches!(env("XBT_ANCHOR").map(|v| v.to_ascii_lowercase()).as_deref(), Some("off" | "0" | "false" | "no"));
    if anchor_on {
        set_default("B2_ANCHOR_SOCK", data.anchor_sock());
    }
    for (from, to) in [("XBT_NODE_RPC_HOST", "B2_RPCHOST"), ("XBT_NODE_RPC_PORT", "B2_RPCPORT"), ("XBT_CHAIN", "B2_CHAIN"),
                       ("XBT_NODE_WALLET", "B2_WALLET")] {
        if let Some(v) = env(from) {
            set_default(to, v);
        }
    }
    // the policy: env JSON (authoritative, rewritten when it changes), a file, the existing one, a default
    let policy_path = root.join("policy.json");
    let given = match (env("XBT_SIGNER_POLICY"), env("XBT_SIGNER_POLICY_FILE")) {
        (Some(j), _) => Some(j),
        (None, Some(f)) => Some(std::fs::read_to_string(&f).map_err(|e| format!("XBT_SIGNER_POLICY_FILE {f}: {e}"))?),
        (None, None) => None,
    };
    let policy = match given {
        Some(text) => {
            let v: Value = serde_json::from_str(&text).map_err(|e| format!("XBT_SIGNER_POLICY: {e}"))?;
            v.is_object().then_some(v).ok_or("XBT_SIGNER_POLICY: not a JSON object")?
        }
        None if policy_path.exists() => Value::Null,
        None => default_policy(anchor_on),
    };
    if !policy.is_null() {
        let text = serde_json::to_string_pretty(&policy).unwrap_or_default();
        if std::fs::read_to_string(&policy_path).ok().as_deref() != Some(text.as_str()) {
            xbt_svc::write_atomic(&policy_path, text.as_bytes(), 0o600).map_err(|e| format!("{}: {e}", policy_path.display()))?;
            eprintln!("xbt-signer: wrote {}", policy_path.display());
        }
    }
    let secrets = Secrets::for_component(Some(data), xbt_svc::SIGNER, mode);
    if env("B2_RPCCOOKIE").is_none() {
        if let Some(s) = secrets.get("node-rpc-auth")? {
            let p = s.origin.path().ok_or("secret node-rpc-auth must be a file (it is read on every RPC call)")?;
            std::env::set_var("B2_RPCCOOKIE", p);
        }
    }
    keystore(&secrets).map(|k| (root, k))
}

/// The wrapping key: `B2_HOT_KEYFILE` (a path) as before; else the secret `signer-passphrase`; else
/// `signer-wrap-key`, generated on first run. Production refuses a passphrase or plaintext by env.
fn keystore(secrets: &Secrets) -> Result<Option<Arc<KeyStore>>, String> {
    if env("B2_HOT_KEYFILE").is_some() || env("B2_HOT_PASSPHRASE").is_some() {
        return Ok(None);
    }
    if let Some(pw) = secrets.get("signer-passphrase")? {
        eprintln!("xbt-signer: wrapping key from the passphrase ({})", pw.origin);
        return Ok(Some(Arc::new(KeyStore::with_passphrase(pw.text()?.as_bytes()))));
    }
    let k = secrets.get_or_create("signer-wrap-key", || xbt_svc::random_bytes(32))?;
    let key: [u8; 32] = match k.bytes.len() {
        32 => k.bytes.as_slice().try_into().map_err(|_| "signer-wrap-key")?,
        _ => {
            let t = k.text()?;
            let b: Vec<u8> = (0..t.len()).step_by(2).filter_map(|i| t.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok())).collect();
            b.as_slice().try_into().ok().filter(|_| t.len() == 64)
                .ok_or_else(|| format!("signer-wrap-key ({}) must hold 32 bytes (raw or 64 hex chars)", k.origin))?
        }
    };
    eprintln!("xbt-signer: wrapping key from {}", k.origin);
    Ok(Some(Arc::new(KeyStore::with_key(key))))
}

/// The readiness document: node reachable and synced, keys unlocked, witness reachable (when
/// anchoring is on), the socket answering.
fn readiness(signer: &Signer, sock: &Path) -> Value {
    let node = health::node_status(signer.node.call("getblockchaininfo", json!([])).map_err(|e| e.msg));
    let witness = match env("B2_ANCHOR_SOCK") {
        Some(p) => match AnchorClient::new(Path::new(&p)).latest() {
            Ok(_) => json!({"enabled": true, "reachable": true}),
            Err(e) => json!({"enabled": true, "reachable": false, "error": e.msg}),
        },
        None => json!({"enabled": false, "reachable": false}),
    };
    let socket = SignerClient::new(sock).call("health", json!({})).map(|h| h["ok"] == true).unwrap_or(false);
    // the signer only starts with its keys opened (sealed hot key, channel keys)
    let unlocked = signer.keystore.is_some() || KeyStore::plaintext_allowed();
    let ok = node["reachable"] == true && node["synced"] == true && unlocked && socket
        && (witness["enabled"] == false || witness["reachable"] == true);
    json!({"ok": ok, "service": "xbt-signer", "node": node, "unlocked": unlocked,
           "keystore": signer.keystore.as_ref().map(|k| k.kind()).unwrap_or("plaintext"), "witness": witness, "socket": socket,
           "chain": signer.chain, "pid": std::process::id()})
}

fn healthcheck(args: &[String]) -> ! {
    let Some(path) = ready_file() else { die(2, "no readiness file: set XBT_DATA_DIR or XBT_SIGNER_READY_FILE") };
    match health::read_ready(&path, Duration::from_secs_f64(ready_interval() * 3.0 + 5.0)) {
        Ok(v) => {
            println!("{v}");
            let want_ready = args.iter().any(|a| a == "--ready");
            std::process::exit(if !want_ready || v["ok"] == true { 0 } else { 1 })
        }
        Err(e) => die(1, e),
    }
}

fn call(args: &[String]) -> ! {
    let Some(method) = args.first() else { die(2, "usage: xbt-signer call METHOD [PARAMS_JSON]") };
    let params: Value = match args.get(1) {
        Some(p) => serde_json::from_str(p).unwrap_or_else(|e| die(2, format!("params: {e}"))),
        None => json!({}),
    };
    match SignerClient::new(&sock_path()).call(method, params) {
        Ok(v) => {
            println!("{v}");
            std::process::exit(0)
        }
        Err(e) => die(1, format!("{}: {}", e.code, e.msg)),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("healthcheck") => healthcheck(&args[1..]),
        Some("call") => call(&args[1..]),
        _ => {}
    }
    let mut root = env("B2_ROOT").map(PathBuf::from);
    let mut check = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--root" => {
                i += 1;
                root = Some(PathBuf::from(args.get(i).cloned().unwrap_or_default()));
            }
            "--check" => check = true,
            "-h" | "--help" => {
                println!("{}", include_str!("xbt-signer.rs").lines().take_while(|l| l.starts_with("//!"))
                    .map(|l| l.trim_start_matches("//!").trim_start_matches(' ')).collect::<Vec<_>>().join("\n"));
                return;
            }
            other => die(2, format!("unknown argument {other}")),
        }
        i += 1;
    }
    let mode = Mode::from_env().unwrap_or_else(|e| die(2, e));
    if mode.is_production() {
        if env("B2_HOT_PASSPHRASE").is_some() {
            die(1, "refusing to start: B2_HOT_PASSPHRASE is a plain env secret, refused in production mode: use the secret \
                    signer-passphrase (XBT_SECRET_SIGNER_PASSPHRASE_FILE, $CREDENTIALS_DIRECTORY or the data dir)");
        }
        if KeyStore::plaintext_allowed() {
            die(1, "refusing to start: B2_HOT_ALLOW_PLAINTEXT is for tests, refused in production mode");
        }
    }
    let data = DataDir::from_env();
    let mut opts = SignerOptions::default();
    let root = match (root, &data) {
        (Some(r), _) => r,
        (None, Some(d)) => {
            let (r, ks) = container_setup(d, mode).unwrap_or_else(|e| die(1, format!("refusing to start: {e}")));
            opts.keystore = ks;
            r
        }
        (None, None) => PathBuf::from("."),
    };
    let signer = match Signer::new(&root, opts) {
        Ok(s) => s,
        Err(e) => die(1, format!("refusing to start: {}: {}", e.code, e.msg)),
    };
    if check {
        match signer.handle("health", &json!({})) {
            Ok(h) => println!("{h}"),
            Err(e) => die(1, e.msg),
        }
        return;
    }
    if let Some(path) = ready_file() {
        let (s, sock) = (signer.clone(), signer.sock_path.clone());
        let every = Duration::from_secs_f64(ready_interval());
        std::thread::Builder::new().name("readiness".into()).spawn(move || loop {
            // the socket binds right after this thread starts: give it a moment on the first round
            std::thread::sleep(Duration::from_millis(200));
            if let Err(e) = health::write_ready(&path, &readiness(&s, &sock)) {
                eprintln!("xbt-signer: readiness file {}: {e}", path.display());
            }
            std::thread::sleep(every);
        }).unwrap_or_else(|e| die(1, e));
    }
    if let Err(e) = xbt_signer::server::serve(signer) {
        die(1, e.msg);
    }
}
