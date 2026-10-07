//! `xbt-wallet-ui`: the agent wallet's web UI (AGP-039).
//!
//!   xbt-wallet-ui [serve]                       serve (configuration from the environment: see `config`)
//!   xbt-wallet-ui sign --key FILE --message-hex HEX
//!                                               sign a message shown by the UI with an approval key file
//!                                               (32 raw bytes or 64 hex; the UI's backup), on another device
//!   xbt-wallet-ui pubkey --key FILE             the key file's public key (for enrolment)
//!   xbt-wallet-ui healthcheck [--ready]         GET /healthz (or /readyz) on XBT_UI_BIND: the image's
//!                                               HEALTHCHECK (it has no shell or curl); exit 0 on 200
use std::io::Read;

fn key_from(path: &str) -> Result<[u8; 32], String> {
    let mut raw = Vec::new();
    std::fs::File::open(path).and_then(|mut f| f.read_to_end(&mut raw)).map_err(|e| format!("{path}: {e}"))?;
    if raw.len() == 32 {
        return Ok(raw.try_into().expect("32"));
    }
    let t = String::from_utf8_lossy(&raw).trim().to_string();
    hex::decode(&t).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| format!("{path}: not 32 raw bytes or 64 hex characters"))
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        None | Some("serve") => serve(),
        Some("healthcheck") => healthcheck(args.iter().any(|a| a == "--ready")),
        Some("sign") | Some("pubkey") => match offline(&args) {
            Ok(out) => {
                println!("{out}");
                0
            }
            Err(e) => {
                eprintln!("xbt-wallet-ui: {e}");
                2
            }
        },
        Some("-h") | Some("--help") => {
            println!("usage: xbt-wallet-ui [serve] | sign --key FILE --message-hex HEX | pubkey --key FILE | healthcheck [--ready]\n\
                      serve reads XBT_UI_BIND, XBT_UI_SIGNER_SOCK, XBT_UI_DATA_DIR, XBT_UI_PASSWORD_FILE, XBT_UI_BASE_PATH, ... (README)");
            0
        }
        Some(o) => {
            eprintln!("xbt-wallet-ui: unknown command {o} (try --help)");
            2
        }
    };
    std::process::exit(code);
}

fn offline(args: &[String]) -> Result<String, String> {
    let key = key_from(&arg(args, "--key").ok_or("--key FILE is required")?)?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&key);
    if args[0] == "pubkey" {
        return Ok(hex::encode(sk.verifying_key().to_bytes()));
    }
    let m = hex::decode(arg(args, "--message-hex").ok_or("--message-hex HEX is required")?.trim()).map_err(|_| "--message-hex is not hex")?;
    Ok(hex::encode(ed25519_dalek::Signer::sign(&sk, &m).to_bytes()))
}

fn healthcheck(ready: bool) -> i32 {
    let bind = std::env::var("XBT_UI_BIND").ok().filter(|b| !b.trim().is_empty()).unwrap_or_else(|| "127.0.0.1:8480".into());
    let addr = match bind.rsplit_once(':') {
        Some(("0.0.0.0", p)) => format!("127.0.0.1:{p}"),
        Some(("[::]", p)) => format!("[::1]:{p}"),
        _ => bind,
    };
    let path = if ready { "/readyz" } else { "/healthz" };
    match xbt_wallet_ui::app::http_get(&format!("http://{addr}{path}")) {
        Ok((200, _)) => 0,
        Ok((code, body)) => {
            eprintln!("xbt-wallet-ui healthcheck: {path} {code} {}", body.trim());
            1
        }
        Err(e) => {
            eprintln!("xbt-wallet-ui healthcheck: {path}: {e}");
            1
        }
    }
}

fn serve() -> i32 {
    let cfg = match xbt_wallet_ui::config::Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("xbt-wallet-ui: {e}");
            return 2;
        }
    };
    let app = match xbt_wallet_ui::app::App::new(cfg) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("xbt-wallet-ui: {e}");
            return 2;
        }
    };
    match xbt_wallet_ui::server::spawn(app.clone()) {
        Ok(r) => {
            eprintln!("xbt-wallet-ui listening on http://{}{} (signer {})", r.addr, app.cfg.base_path, app.cfg.signer_sock.display());
            loop {
                std::thread::park();
            }
        }
        Err(e) => {
            eprintln!("xbt-wallet-ui: {e}");
            2
        }
    }
}
