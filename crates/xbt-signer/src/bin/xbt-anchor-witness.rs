//! The signature-log anchor witness (B2 `python -m agentwallet.anchor`), protocol and store compatible:
//!   xbt-anchor-witness serve --store DIR --sock PATH [--sock-mode 660]
//!   xbt-anchor-witness check --store DIR --log signatures.jsonl
//!   xbt-anchor-witness healthcheck [--sock PATH]    the image's HEALTHCHECK: `latest` answers on the socket
//! Run it as its own user, with a store directory the signer's user cannot write.
//!
//! Container mode (AGP-038): `--store` defaults to `XBT_WITNESS_DIR` (else `$XBT_DATA_DIR/witness`), and
//! `--sock` to `XBT_ANCHOR_SOCK` (else `$XBT_DATA_DIR/run/anchor/anchor.sock`); the witness has no secrets.
use std::path::{Path, PathBuf};

use xbt_signer::anchor::{serve_witness, AnchorClient, AnchorStore};
use xbt_signer::sigaudit::check_chain;
use xbt_svc::{env, DataDir};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn die(code: i32, msg: impl std::fmt::Display) -> ! {
    eprintln!("xbt-anchor-witness: {msg}");
    std::process::exit(code)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let data = DataDir::from_env();
    let store = arg(&args, "--store").map(PathBuf::from).or_else(|| data.as_ref().map(|d| d.component(xbt_svc::WITNESS)));
    let sock = arg(&args, "--sock").or_else(|| env("XBT_ANCHOR_SOCK")).map(PathBuf::from).or_else(|| data.as_ref().map(DataDir::anchor_sock));
    match (args.first().map(String::as_str), store) {
        (Some("healthcheck"), _) => {
            let sock = sock.unwrap_or_else(|| die(2, "--sock required"));
            match AnchorClient::new(&sock).latest() {
                Ok(v) => println!("{}", serde_json::json!({"ok": true, "service": "xbt-anchor-witness", "latest": v})),
                Err(e) => die(1, e.msg),
            }
        }
        (Some("serve"), Some(store)) => {
            let sock = sock.unwrap_or_else(|| die(2, "--sock required"));
            let mode = u32::from_str_radix(&arg(&args, "--sock-mode").unwrap_or_else(|| "660".into()), 8).unwrap_or(0o660);
            if data.is_some() {
                for (d, m) in [(store.as_path(), 0o700), (sock.parent().unwrap_or(Path::new(".")), 0o750)] {
                    xbt_svc::ensure_dir(d, m).unwrap_or_else(|e| die(1, format!("{}: {e}", d.display())));
                }
            }
            match serve_witness(&store, &sock, mode) {
                Ok(w) => {
                    println!("anchor witness on {}, store {}, latest {}", sock.display(), store.display(), w.store.latest());
                    loop {
                        std::thread::park();
                    }
                }
                Err(e) => die(1, e.msg),
            }
        }
        (Some("check"), Some(store)) => {
            let log = PathBuf::from(arg(&args, "--log").unwrap_or_default());
            let latest = match AnchorStore::open(&store) {
                Ok(s) => s.latest(),
                Err(e) => die(1, e.msg),
            };
            let res = check_chain(&log, Some(&latest));
            println!("{res}");
            std::process::exit(if res["ok"] == true { 0 } else { 1 });
        }
        _ => die(2, "usage: xbt-anchor-witness serve --store DIR --sock PATH | check --store DIR --log FILE | healthcheck [--sock PATH]"),
    }
}
