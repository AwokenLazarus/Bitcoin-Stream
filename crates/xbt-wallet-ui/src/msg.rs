//! The messages the human signs, byte for byte as `xbt_signer::approval` builds them and as
//! `assets/ui.js` rebuilds them in the browser (tests/crypto_js.rs checks all three agree). The UI
//! shows them in hex for a human who signs on another device.

fn join(parts: &[&str]) -> Vec<u8> {
    parts.join("\n").into_bytes()
}

pub fn approve(token: &str, dest: &str, amount_sats: i64, expiry: i64) -> Vec<u8> {
    join(&["xbt-agentwallet-approve-v1", token, dest, &amount_sats.to_string(), &expiry.to_string()])
}

pub fn sweep(hot_address: &str, to: &str, amount_sats: i64, expiry: i64) -> Vec<u8> {
    join(&["xbt-agentwallet-hot-sweep-v1", hot_address, to, &amount_sats.to_string(), &expiry.to_string()])
}

pub fn policy(prev_sha256: &str, expiry: i64, text: &str) -> Vec<u8> {
    join(&["xbt-agentwallet-policy-v1", prev_sha256, &expiry.to_string(), text])
}

pub fn human_key(old_pub: &str, new_pub: &str, expiry: i64) -> Vec<u8> {
    join(&["xbt-agentwallet-human-key-v1", old_pub, new_pub, &expiry.to_string()])
}

pub fn rotate(hot_address: &str, expiry: i64) -> Vec<u8> {
    join(&["xbt-agentwallet-hot-rotate-v1", hot_address, &expiry.to_string()])
}

pub fn backup(hot_address: &str, expiry: i64) -> Vec<u8> {
    join(&["xbt-agentwallet-backup-v1", hot_address, &expiry.to_string()])
}

pub fn deny(token: &str, expiry: i64) -> Vec<u8> {
    join(&["xbt-agentwallet-deny-v1", token, &expiry.to_string()])
}
