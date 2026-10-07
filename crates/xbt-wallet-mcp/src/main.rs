//! `xbt-wallet-mcp`: the agent wallet's MCP server.
//!
//!   xbt-wallet-mcp                      stdio (Claude Code, Hermes, OpenClaw)
//!   xbt-wallet-mcp --http 127.0.0.1:33510 [--path /mcp] [--http-allow-remote]
//!   xbt-wallet-mcp --stdio              stdio even when XBT_MCP_HTTP is set
//!   xbt-wallet-mcp --check              ask the signer for `health`, print it, exit 0 if reachable
//!   xbt-wallet-mcp --healthcheck [--ready]   GET our own /healthz (/readyz): the image's HEALTHCHECK
//!   xbt-wallet-mcp --list-tools         print the tool list (JSON) and exit
//!
//! Environment (B2's): `B2_SIGNER_SOCK` (a socket path or `tcp://127.0.0.1:PORT`) or `B2_ROOT`
//! (socket `$B2_ROOT/.run/signer.sock`), `B2_SIGNER_TIMEOUT`, `B2_BODY_CAP`. Ours: `XBT_MCP_PAYER`
//! (`signer`, the default, or `local`; see the README), `XBT_MCP_NETWORK` and the other `XBT_MCP_*`
//! payer settings, `XBT_MCP_HTTP_TOKEN` (a bearer token for HTTP; dev mode only when `XBT_MODE` is
//! production, which reads the secret `mcp-http-token` instead).
//!
//! Container-ready (AGP-038, `docs/CONTAINER.md`): `XBT_MCP_HTTP` (= `--http`), `XBT_MCP_PATH`,
//! `XBT_BASE_PATH` (a prefix the reverse proxy keeps), `XBT_MCP_HTTP_ALLOW_REMOTE`. With `XBT_DATA_DIR`
//! the signer socket defaults to `run/signer/signer.sock` and a listener on a non-loopback address
//! is allowed, always behind the bearer token: the secret `mcp-http-token` (generated 0600 into
//! `mcp/secrets/` on first run). On a box with the web UI (AGP-042) the token is the UI's file instead:
//! `XBT_MCP_HTTP_TOKEN_FILE`, default `run/ui/mcp-http-token` when it exists (xbt-init makes it, 0640,
//! group `xbt-wallet-ui`). The MCP reads it on every request and never writes it, so the owner's
//! rotation on the UI's Agents page cuts the old token off at once. `GET /healthz` is the process; `GET /readyz` is the signer answering
//! and its readiness file (node synced, keys unlocked, witness reachable) fresh and ok.
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use xbt_svc::{env, env_bool, health, probe, DataDir, Mode, Secrets};
use xbt_wallet_mcp::mcp::{tools, Server};
use xbt_wallet_mcp::transport::{read_token_file, serve_http, serve_stdio, HttpConfig, ReadyFn};
use xbt_wallet_mcp::wallet::Wallet;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn die(msg: &str) -> ! {
    eprintln!("xbt-wallet-mcp: {msg}");
    std::process::exit(2)
}

fn is_loopback(addr: &str) -> bool {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    matches!(host.trim_start_matches('[').trim_end_matches(']'), "127.0.0.1" | "localhost" | "::1")
}

/// The signer answers `health`, and its readiness file (when there is one) is fresh and ok.
fn readiness(wallet: Arc<Wallet>, ready_file: Option<PathBuf>) -> ReadyFn {
    Arc::new(move || {
        let signer = match wallet.signer("health", &json!({})) {
            Ok(v) => json!({"reachable": true, "chain": v.get("chain").cloned().unwrap_or(Value::Null)}),
            Err(e) => json!({"reachable": false, "error": e}),
        };
        let mut ok = signer["reachable"] == true;
        let file = ready_file.as_ref().map(|p| {
            let max = env("XBT_READY_INTERVAL").and_then(|v| v.parse::<f64>().ok()).unwrap_or(5.0) * 3.0 + 5.0;
            match health::read_ready(p, Duration::from_secs_f64(max)) {
                Ok(v) => {
                    ok &= v["ok"] == true;
                    v
                }
                Err(e) => {
                    ok = false;
                    json!({"ok": false, "error": e})
                }
            }
        });
        (ok, json!({"signer": signer, "signer_ready": file}))
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", include_str!("main.rs").lines().take_while(|l| l.starts_with("//!")).map(|l| l.trim_start_matches("//!").trim_start_matches(' ')).collect::<Vec<_>>().join("\n"));
        return;
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("xbt-wallet-mcp {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args.iter().any(|a| a == "--list-tools") {
        println!("{}", serde_json::to_string_pretty(&tools()).unwrap_or_default());
        return;
    }
    let addr = if args.iter().any(|a| a == "--stdio") { None } else { arg(&args, "--http").or_else(|| env("XBT_MCP_HTTP")) };
    let path = arg(&args, "--path").or_else(|| env("XBT_MCP_PATH")).unwrap_or_else(|| "/mcp".into());
    let base = env("XBT_BASE_PATH").unwrap_or_default();
    if args.iter().any(|a| a == "--healthcheck") {
        let addr = addr.unwrap_or_else(|| die("--healthcheck needs --http or XBT_MCP_HTTP"));
        let which = if args.iter().any(|a| a == "--ready") { "/readyz" } else { "/healthz" };
        match probe::get(&probe::local_addr(&addr), &format!("{}{which}", xbt_svc::proxy::normalize_base(&base)), Duration::from_secs(5)) {
            Ok((200, body)) => {
                println!("{}", body.trim());
                return;
            }
            Ok((code, body)) => {
                eprintln!("xbt-wallet-mcp: {which} {code} {}", body.trim());
                std::process::exit(1)
            }
            Err(e) => {
                eprintln!("xbt-wallet-mcp: {which}: {e}");
                std::process::exit(1)
            }
        }
    }
    let mode = Mode::from_env().unwrap_or_else(|e| die(&e));
    let data = DataDir::from_env();
    if let Some(d) = &data {
        if std::env::var_os("B2_SIGNER_SOCK").is_none() && std::env::var_os("B2_ROOT").is_none() {
            std::env::set_var("B2_SIGNER_SOCK", d.signer_sock());
        }
        if std::env::var_os("XBT_MCP_LEDGER").is_none() {
            std::env::set_var("XBT_MCP_LEDGER", d.component(xbt_svc::MCP).join("mcp-payer.jsonl"));
        }
    }
    let wallet = Arc::new(Wallet::from_env().unwrap_or_else(|e| die(&e)));
    if args.iter().any(|a| a == "--check") {
        match wallet.signer("health", &json!({})) {
            Ok(v) => {
                println!("{}", xbt_wallet_mcp::wallet::pack(v).unwrap_or_else(|e| die(&e)));
                return;
            }
            Err(e) => die(&e),
        }
    }
    let server = Arc::new(Server::new(wallet.clone()));
    let Some(addr) = addr else { return serve_stdio(server) };
    let remote = !is_loopback(&addr);
    let allow_remote = args.iter().any(|a| a == "--http-allow-remote") || env_bool("XBT_MCP_HTTP_ALLOW_REMOTE", data.is_some());
    // the token: the old env value (dev mode), else the secret; a non-loopback listener always needs one
    let secrets = Secrets::for_component(data.as_ref(), xbt_svc::MCP, mode);
    // AGP-042: the UI's token file (read-only here), when there is one
    let token_file = env("XBT_MCP_HTTP_TOKEN_FILE").map(PathBuf::from)
        .or_else(|| data.as_ref().map(DataDir::mcp_token).filter(|p| std::fs::symlink_metadata(p).is_ok()));
    if let Some(p) = &token_file {
        if env("XBT_MCP_HTTP_TOKEN").is_some() {
            die("set XBT_MCP_HTTP_TOKEN_FILE or XBT_MCP_HTTP_TOKEN, not both");
        }
        read_token_file(p).unwrap_or_else(|e| die(&format!("bearer token: {e}")));
        eprintln!("xbt-wallet-mcp: bearer token from {} (read on every request; the UI rotates it)", p.display());
    }
    let token = match env("XBT_MCP_HTTP_TOKEN") {
        _ if token_file.is_some() => None,
        Some(_) if mode.is_production() => die("XBT_MCP_HTTP_TOKEN is a plain env secret, refused in production mode: use the secret \
                                                mcp-http-token (XBT_SECRET_MCP_HTTP_TOKEN_FILE, $CREDENTIALS_DIRECTORY or the data dir)"),
        Some(t) => Some(t),
        None => {
            // generated only where it can be kept (a data dir); otherwise serve_http refuses the listener
            let found = if remote && allow_remote && secrets.dir.is_some() {
                Some(secrets.get_or_create("mcp-http-token", || xbt_svc::to_hex(&xbt_svc::random_bytes(32)).into_bytes()))
            } else {
                secrets.get("mcp-http-token").transpose()
            };
            match found.transpose().unwrap_or_else(|e| die(&e)) {
                Some(s) => {
                    eprintln!("xbt-wallet-mcp: bearer token from {}", s.origin);
                    Some(s.text().unwrap_or_else(|e| die(&e))).filter(|t| !t.is_empty())
                }
                None => None,
            }
        }
    };
    let ready_file = env("XBT_SIGNER_READY_FILE").map(PathBuf::from).or_else(|| data.as_ref().map(DataDir::signer_ready));
    let cfg = HttpConfig { addr, path, token, token_file, allow_remote, base, ready: Some(readiness(wallet, ready_file)) };
    if let Err(e) = serve_http(server, cfg) {
        die(&e);
    }
}
