//! AGP-039: the browser's crypto (assets/ui.js, run under node) against the signer's: every message
//! kind ui.js signs is byte-for-byte `xbt_signer::approval`'s (and the UI's own `msg`), and its
//! signatures verify with ed25519-dalek. Skipped (with a note) when node is not installed.
use serde_json::Value;
use xbt_signer::approval;

fn node() -> Option<String> {
    let home = std::env::var("HOME").unwrap_or_default();
    ["node".to_string(), format!("{home}/.local/share/nodejs/bin/node")].into_iter()
        .find(|n| std::process::Command::new(n).arg("--version").output().is_ok_and(|o| o.status.success()))
}

fn run(args: &[&str]) -> Option<std::process::Output> {
    let n = node()?;
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/js/crypto_test.mjs");
    Some(std::process::Command::new(n).arg(script).args(args).output().unwrap())
}

#[test]
fn ui_js_vectors() {
    let Some(o) = run(&[]) else { return eprintln!("node not found: skipped") };
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{out}{}", String::from_utf8_lossy(&o.stderr));
    assert!(out.contains("vectors OK"), "{out}");
    let start = out.find("crypto_test: ").expect(&out) + "crypto_test: ".len();
    let score = out[start..].split(" vectors").next().expect(&out);
    let (got, want) = score.split_once('/').expect(&out);
    assert_eq!(got, want, "a vector failed: {out}");
    let total: u32 = want.parse().expect(score);
    assert!(total >= 25, "expected the AGP-041 vectors, got {score}: {out}");
}

#[test]
fn ui_js_signs_exactly_the_signer_s_messages() {
    let Some(o) = run(&["emit"]) else { return eprintln!("node not found: skipped") };
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    let pk = hex::decode(v["pub"].as_str().unwrap()).unwrap();
    let dalek = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]).verifying_key().to_bytes();
    assert_eq!(pk, dalek, "the same public key from the same seed");
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    for c in cases {
        let f = &c["fields"];
        let s = |k: &str| f[k].as_str().unwrap().to_string();
        let i = |k: &str| f[k].as_i64().unwrap();
        let (want, ui) = match c["kind"].as_str().unwrap() {
            "approve" => (approval::canonical_message(&s("token"), &s("dest"), i("amount_sats"), i("expiry")),
                          xbt_wallet_ui::msg::approve(&s("token"), &s("dest"), i("amount_sats"), i("expiry"))),
            "sweep" => (approval::sweep_message(&s("hot_address"), &s("to"), i("amount_sats"), i("expiry")),
                        xbt_wallet_ui::msg::sweep(&s("hot_address"), &s("to"), i("amount_sats"), i("expiry"))),
            "policy" => (approval::policy_message(&s("prev_sha256"), i("expiry"), &s("text")),
                         xbt_wallet_ui::msg::policy(&s("prev_sha256"), i("expiry"), &s("text"))),
            "human-key" => (approval::human_key_message(&s("old_pub"), &s("pubkey"), i("expiry")),
                            xbt_wallet_ui::msg::human_key(&s("old_pub"), &s("pubkey"), i("expiry"))),
            "rotate" => (approval::rotate_message(&s("hot_address"), i("expiry")), xbt_wallet_ui::msg::rotate(&s("hot_address"), i("expiry"))),
            "backup" => (approval::backup_message(&s("hot_address"), i("expiry")), xbt_wallet_ui::msg::backup(&s("hot_address"), i("expiry"))),
            k => panic!("unknown kind {k}"),
        };
        let js = hex::decode(c["msg"].as_str().unwrap()).unwrap();
        assert_eq!(js, want, "{}: ui.js builds the signer's bytes", c["kind"]);
        assert_eq!(ui, want, "{}: the UI's msg builds the signer's bytes", c["kind"]);
        let sig = hex::decode(c["sig"].as_str().unwrap()).unwrap();
        assert!(approval::verify(&pk, &want, &sig), "{}: the signer accepts ui.js's signature", c["kind"]);
    }
}

#[test]
fn the_offline_sign_helper_matches() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k");
    std::fs::write(&key, "22".repeat(32)).unwrap();
    let bin = env!("CARGO_BIN_EXE_xbt-wallet-ui");
    let m = approval::rotate_message("bcrt1qx", 99);
    let o = std::process::Command::new(bin).args(["sign", "--key", key.to_str().unwrap(), "--message-hex", &hex::encode(&m)]).output().unwrap();
    let sig = hex::decode(String::from_utf8_lossy(&o.stdout).trim()).unwrap();
    let o = std::process::Command::new(bin).args(["pubkey", "--key", key.to_str().unwrap()]).output().unwrap();
    let pk = hex::decode(String::from_utf8_lossy(&o.stdout).trim()).unwrap();
    assert!(approval::verify(&pk, &m, &sig));
}
