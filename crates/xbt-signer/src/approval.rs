//! Ed25519 human-approval messages (B2 `approval.py`). The signer holds only the public key; the
//! private key lives on the human's device (`agentwallet-approve`).
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub const DOMAIN: &[u8] = b"xbt-agentwallet-approve-v1";
pub const RECOVER_DOMAIN: &[u8] = b"xbt-agentwallet-recover-v1";
pub const SWEEP_DOMAIN: &[u8] = b"xbt-agentwallet-hot-sweep-v1";
/// AGP-039 (the web UI): a new policy.json, the human key's rotation, a hot-key rotation, a backup export.
pub const POLICY_DOMAIN: &[u8] = b"xbt-agentwallet-policy-v1";
pub const HUMAN_KEY_DOMAIN: &[u8] = b"xbt-agentwallet-human-key-v1";
pub const ROTATE_DOMAIN: &[u8] = b"xbt-agentwallet-hot-rotate-v1";
pub const BACKUP_DOMAIN: &[u8] = b"xbt-agentwallet-backup-v1";
/// AGP-063 W3: refuse (or revoke) a pending approval.
pub const DENY_DOMAIN: &[u8] = b"xbt-agentwallet-deny-v1";

fn join(parts: &[&[u8]]) -> Vec<u8> {
    parts.join(&b'\n')
}

/// `(token, dest, amount_sats, expiry)` under the approval domain.
pub fn canonical_message(token: &str, dest: &str, amount_sats: i64, expiry: i64) -> Vec<u8> {
    join(&[DOMAIN, token.as_bytes(), dest.as_bytes(), amount_sats.to_string().as_bytes(), expiry.to_string().as_bytes()])
}

pub fn recover_message(recovery_address: &str, expiry: i64) -> Vec<u8> {
    join(&[RECOVER_DOMAIN, recovery_address.as_bytes(), expiry.to_string().as_bytes()])
}

/// AGP-013: a human moves `amount_sats` out of the hot key to `dest`.
pub fn sweep_message(hot_address: &str, dest: &str, amount_sats: i64, expiry: i64) -> Vec<u8> {
    join(&[SWEEP_DOMAIN, hot_address.as_bytes(), dest.as_bytes(), amount_sats.to_string().as_bytes(), expiry.to_string().as_bytes()])
}

/// AGP-039: replace the policy whose file hashes to `prev_sha256` by exactly `policy_text` (the bytes
/// the signer writes), valid until `expiry`. Binding the previous hash stops a replay of an older change.
pub fn policy_message(prev_sha256: &str, expiry: i64, policy_text: &str) -> Vec<u8> {
    join(&[POLICY_DOMAIN, prev_sha256.as_bytes(), expiry.to_string().as_bytes(), policy_text.as_bytes()])
}

/// AGP-039: the current human key hands over to `new_pub_hex`.
pub fn human_key_message(old_pub_hex: &str, new_pub_hex: &str, expiry: i64) -> Vec<u8> {
    join(&[HUMAN_KEY_DOMAIN, old_pub_hex.as_bytes(), new_pub_hex.as_bytes(), expiry.to_string().as_bytes()])
}

/// AGP-039: rotate the hot key whose address is `hot_address` (its coins sweep to the new key).
pub fn rotate_message(hot_address: &str, expiry: i64) -> Vec<u8> {
    join(&[ROTATE_DOMAIN, hot_address.as_bytes(), expiry.to_string().as_bytes()])
}

/// AGP-039: export the wallet backup (the sealed files plus the wrapping secret sealed under a backup
/// passphrase), valid until `expiry`.
pub fn backup_message(hot_address: &str, expiry: i64) -> Vec<u8> {
    join(&[BACKUP_DOMAIN, hot_address.as_bytes(), expiry.to_string().as_bytes()])
}

/// AGP-063 W3: deny or revoke the approval `token`, valid until `expiry`.
pub fn deny_message(token: &str, expiry: i64) -> Vec<u8> {
    join(&[DENY_DOMAIN, token.as_bytes(), expiry.to_string().as_bytes()])
}

/// Ed25519 verification; any malformed key or signature is `false`.
pub fn verify(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(pk) = <[u8; 32]>::try_from(public) else { return false };
    let Ok(sig) = <[u8; 64]>::try_from(signature) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return false };
    vk.verify(message, &Signature::from_bytes(&sig)).is_ok()
}

pub fn verify_approval(public: &[u8], token: &str, dest: &str, amount_sats: i64, expiry: i64, signature: &[u8]) -> bool {
    verify(public, &canonical_message(token, dest, amount_sats, expiry), signature)
}

/// `bytes.fromhex(s.strip())`.
pub fn x2b(s: &str) -> Option<Vec<u8>> {
    hex::decode(s.trim()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn approval_binds_every_field() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let sig = sk.sign(&canonical_message("tok", "bcrt1qx", 5000, 99)).to_bytes();
        assert!(verify_approval(&pk, "tok", "bcrt1qx", 5000, 99, &sig));
        assert!(!verify_approval(&pk, "tok", "bcrt1qx", 5001, 99, &sig));
        assert!(!verify_approval(&pk, "tok2", "bcrt1qx", 5000, 99, &sig));
        assert!(!verify(&pk, &sweep_message("a", "b", 1, 2), &sig));
        assert!(!verify(&pk[..31], b"", &sig));
    }
}
