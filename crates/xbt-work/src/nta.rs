//! What an `xbt-work` provider needs on a chain with payee attestation (XBT-NTA v1, spec §13.8):
//! the attestation digest a payee key signs for each tip, the direct attest endpoint's body, the
//! attestation output a coinbase carries, and the BIP86 output-key secret (the key NTA signs with
//! is the tweaked output key `K = P + t·G`, never the wallet's internal key).
//!
//! ```text
//! digest = TaggedHash("XBT-NTA/attestation", ser(script) ‖ height (i32 LE) ‖ nBits (u32 LE) ‖ hashPrevBlock)
//! ```
//! BIP340 over libsecp256k1 (via xbt-primitives), zero aux randomness as the reference signer.
use serde_json::Value;
use sha2::{Digest, Sha256};
use xbt402::json::obj;
use xbt_primitives::secp256k1::{schnorr, Keypair, Message, Parity, Scalar, SecretKey, XOnlyPublicKey, SECP256K1};

use crate::error::{fail, Result};

pub const NTA_TAG: &[u8] = b"XBT-NTA/attestation";
/// `OP_RETURN PUSH68 "NTA" 0x02`, the prefix of a payee's zero-value attestation output.
pub const ATTESTATION_PREFIX: [u8; 6] = [0x6a, 0x44, 0x4e, 0x54, 0x41, 0x02];

pub fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let t = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h.update(msg);
    h.finalize().into()
}

fn xonly(key: &[u8]) -> Result<XOnlyPublicKey> {
    XOnlyPublicKey::from_slice(key).or_else(|_| fail("bad_key", "not a BIP340 x-only public key"))
}

fn secret(sec: &[u8; 32]) -> Result<SecretKey> {
    SecretKey::from_slice(sec).or_else(|_| fail("bad_key", "secret key out of range"))
}

/// The x-only public key of a secret.
pub fn xonly_pub(sec: &[u8; 32]) -> Result<[u8; 32]> {
    Ok(Keypair::from_secret_key(SECP256K1, &secret(sec)?).x_only_public_key().0.serialize())
}

/// `OP_1 <K>`: the only payee script NTA v1 admits.
pub fn p2tr_script(key: &[u8; 32]) -> Result<Vec<u8>> {
    xonly(key)?;
    let mut s = vec![0x51, 0x20];
    s.extend_from_slice(key);
    Ok(s)
}

/// `ser(script) ‖ h ‖ nBits ‖ hashPrevBlock`; `prev_display` is the parent hash as RPC shows it.
pub fn attestation_preimage(script: &[u8], height: i32, nbits: u32, prev_display: &str) -> Result<Vec<u8>> {
    if script.len() >= 0xFD {
        return fail("bad_script", "script too long for a one-byte CompactSize");
    }
    let mut prev = hex::decode(prev_display).or_else(|_| fail("bad_prev", "not hex"))?;
    if prev.len() != 32 {
        return fail("bad_prev", "hashPrevBlock is 32 bytes");
    }
    prev.reverse();
    let mut out = vec![script.len() as u8];
    out.extend_from_slice(script);
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&nbits.to_le_bytes());
    out.extend(prev);
    Ok(out)
}

pub fn attestation_digest(script: &[u8], height: i32, nbits: u32, prev_display: &str) -> Result<[u8; 32]> {
    Ok(tagged_hash(NTA_TAG, &attestation_preimage(script, height, nbits, prev_display)?))
}

/// BIP340 signature with 32-byte aux randomness (the reference signer uses zeros).
pub fn schnorr_sign(digest: &[u8; 32], sec: &[u8; 32], aux: &[u8; 32]) -> Result<[u8; 64]> {
    let kp = Keypair::from_secret_key(SECP256K1, &secret(sec)?);
    Ok(SECP256K1.sign_schnorr_with_aux_rand(&Message::from_digest(*digest), &kp, aux).serialize())
}

pub fn schnorr_verify(digest: &[u8; 32], key: &[u8], sig: &[u8]) -> bool {
    let (Ok(pk), Ok(s)) = (XOnlyPublicKey::from_slice(key), schnorr::Signature::from_slice(sig)) else { return false };
    SECP256K1.verify_schnorr(&s, &Message::from_digest(*digest), &pk).is_ok()
}

/// The body a provider's signer POSTs to a Prime's attest endpoint for one tip (§13.8 item 4).
pub fn attest(sec: &[u8; 32], height: i32, nbits: u32, prev_display: &str) -> Result<Value> {
    let key = xonly_pub(sec)?;
    let sig = schnorr_sign(&attestation_digest(&p2tr_script(&key)?, height, nbits, prev_display)?, sec, &[0u8; 32])?;
    Ok(obj([("version", 1.into()), ("key", hex::encode(key).into()), ("height", height.into()),
            ("nbits", format!("{nbits:08x}").into()), ("prev", prev_display.into()), ("sig", hex::encode(sig).into())]))
}

/// The zero-value coinbase output script that carries one payee's attestation.
pub fn attestation_output(sig: &[u8; 64]) -> Vec<u8> {
    let mut s = ATTESTATION_PREFIX.to_vec();
    s.extend_from_slice(sig);
    s
}

/// What a Prime checks first: `version` is 1 and the signature verifies for the claimed
/// (height, nBits, prev) under `key`. (It then checks the tuple against its own node's tip.)
pub fn check_attest_body(body: &Value) -> bool {
    (|| -> Option<bool> {
        let key: [u8; 32] = hex::decode(body.get("key")?.as_str()?).ok()?.try_into().ok()?;
        let height = i32::try_from(body.get("height")?.as_i64()?).ok()?;
        let nbits = match body.get("nbits")? {
            Value::String(s) => u32::from_str_radix(s, 16).ok()?,
            v => u32::try_from(v.as_u64()?).ok()?,
        };
        let digest = attestation_digest(&p2tr_script(&key).ok()?, height, nbits, body.get("prev")?.as_str()?).ok()?;
        let sig = hex::decode(body.get("sig")?.as_str()?).ok()?;
        Some(body.get("version").and_then(Value::as_u64) == Some(1) && schnorr_verify(&digest, &key, &sig))
    })().unwrap_or(false)
}

/// A BIP86 wallet's internal secret d → the secret of the output key K = P + t·G (d negated first
/// if P = d·G has odd y; t = TaggedHash("TapTweak", x(P)), no script tree).
pub fn bip86_output_secret(internal_sec: &[u8; 32]) -> Result<[u8; 32]> {
    let mut d = secret(internal_sec)?;
    let (p, parity) = Keypair::from_secret_key(SECP256K1, &d).x_only_public_key();
    if parity == Parity::Odd {
        d = d.negate();
    }
    let t = Scalar::from_be_bytes(tagged_hash(b"TapTweak", &p.serialize())).or_else(|_| fail("bad_key", "tweak out of range"))?;
    Ok(d.add_tweak(&t).or_else(|_| fail("bad_key", "tweaked key is zero"))?.secret_bytes())
}

/// x(P + t·G) from the internal x-only key: what a watch-only wallet shows as the address.
pub fn bip86_output_key(internal_pub: &[u8; 32]) -> Result<[u8; 32]> {
    let p = xonly(internal_pub)?;
    let t = Scalar::from_be_bytes(tagged_hash(b"TapTweak", internal_pub)).or_else(|_| fail("bad_key", "tweak out of range"))?;
    Ok(p.add_tweak(SECP256K1, &t).or_else(|_| fail("bad_key", "tweak"))?.0.serialize())
}

/// The bech32m P2TR address of an x-only key (`bc`, `bcrt`, ...).
pub fn p2tr_address(key: &[u8; 32], hrp: &str) -> Result<String> {
    Ok(xbt_primitives::address::segwit_address(hrp, &p2tr_script(key)?)?)
}

/// §13.8 item 1: whether a scriptPubKey can be an NTA payee (`OP_1 <32-byte x-only key>`).
pub fn is_payee_script(spk: &[u8]) -> bool {
    spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20 && XOnlyPublicKey::from_slice(&spk[2..]).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip341_keypath_tweak() {
        // BIP341 wallet-test-vectors keyPathSpending[0]: internal secret -> tweaked secret
        let d: [u8; 32] = hex::decode("6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa").unwrap().try_into().unwrap();
        assert_eq!(hex::encode(bip86_output_secret(&d).unwrap()), "2405b971772ad26915c8dcdf10f238753a9b837e5f8e6a86fd7c0cce5b7296d9");
        let k = bip86_output_secret(&d).unwrap();
        assert_eq!(bip86_output_key(&xonly_pub(&d).unwrap()).unwrap(), xonly_pub(&k).unwrap());
        let body = attest(&k, 975_001, 0x1901_41c5, &"11".repeat(32)).unwrap();
        assert!(check_attest_body(&body));
        let mut other = body.clone();
        other["prev"] = "22".repeat(32).into();
        assert!(!check_attest_body(&other));
        assert!(!is_payee_script(&hex::decode("0014751e76e8199196d454941c45d1b3a323f1433bd6").unwrap()));
    }
}
