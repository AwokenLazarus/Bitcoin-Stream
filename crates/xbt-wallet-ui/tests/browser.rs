//! AGP-039: the UI in headless Chrome (tests/js/browser_test.mjs over the DevTools protocol) against a
//! regtest signer: the approval key is made in the browser, enrolled, and signs an approval and a
//! policy change in the page; then the agent's waiting xbt402 call is paid. Skipped (with a note) when
//! node or Chrome is missing. Screenshots and HTML snapshots: `$XBT_UI_SNAPSHOT_DIR` (default
//! `target/ui-browser`).
#[path = "../../xbt-signer/tests/common/mod.rs"]
mod common;

use common::*;
use serde_json::json;
use xbt_wallet_ui::app::App;
use xbt_wallet_ui::config::Config;

fn find(cands: &[String]) -> Option<String> {
    cands.iter().find(|c| std::process::Command::new(c).arg("--version").output().is_ok_and(|o| o.status.success())).cloned()
}

#[test]
fn the_ui_in_headless_chrome() {
    let home = std::env::var("HOME").unwrap_or_default();
    let (Some(node), Some(chrome)) = (find(&["node".into(), format!("{home}/.local/share/nodejs/bin/node")]),
                                      find(&[std::env::var("CHROME").unwrap_or_else(|_| "google-chrome".into()), "chromium".into(), "chromium-browser".into()])) else {
        return eprintln!("node or chrome not found: skipped");
    };
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"human_pubkey": ""}), true);
    rig.fund_hot(1, 12_000);
    let sock_path = rig.dir.path().join("signer.sock");
    let _sock = xbt_signer::server::spawn(rig.s.clone(), &sock_path, false).unwrap();
    let data = tempfile::tempdir().unwrap();
    let app = App::new(Config::for_test(sock_path, data.path().join("ui"), "127.0.0.1:0")).unwrap();
    let srv = xbt_wallet_ui::server::spawn(app).unwrap();
    // the agent asks for more than the threshold: it waits for the human
    let r = rig.call("xbt402_pay", json!({"url": URL, "method": "GET", "body": "", "max_sats": 1000}));
    assert_eq!(r["verdict"], "needs_human");
    let token = r["approval_token"].as_str().unwrap().to_string();
    let code = std::fs::read_to_string(data.path().join("ui/setup-code")).unwrap();
    let enroll = std::fs::read_to_string(rig.root.join(".run/enroll-code")).unwrap();
    let out = std::env::var("XBT_UI_SNAPSHOT_DIR").unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/ui-browser").into());
    let o = std::process::Command::new(node).env("CHROME", chrome)
        .args([concat!(env!("CARGO_MANIFEST_DIR"), "/tests/js/browser_test.mjs"), &format!("http://{}", srv.addr), code.trim(), &out, enroll.trim()])
        .output().unwrap();
    let text = String::from_utf8_lossy(&o.stdout);
    eprintln!("{text}");
    assert!(o.status.success(), "{text}{}", String::from_utf8_lossy(&o.stderr));
    // the browser enrolled its own key, signed the approval and the policy
    assert!(!rig.s.human_key().is_empty());
    assert_eq!(rig.call("approval_status", json!({"token": token}))["state"], "approved");
    assert_eq!(rig.s.config().max_per_tx_sats, 100_000, "the starter template the browser signed is in force");
    // the agent's retry is paid under the grant
    rig.call("xbt402_pay", json!({"url": URL, "method": "GET", "body": "", "max_sats": 1000}));
    rig.chain.mine(1);
    let paid = rig.call("xbt402_pay", json!({"url": URL, "method": "GET", "body": "", "max_sats": 1000}));
    assert_eq!((paid["verdict"].as_str(), paid["approved"].as_bool()), (Some("allow"), Some(true)), "{paid}");
}
