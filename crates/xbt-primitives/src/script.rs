//! Script building blocks: pushes, script numbers and the standard output templates.
use crate::error::{Error, Result};
use crate::hash::{hash160, sha256};

pub const OP_0: u8 = 0x00;
pub const OP_PUSHDATA1: u8 = 0x4C;
pub const OP_1: u8 = 0x51;
pub const OP_IF: u8 = 0x63;
pub const OP_ELSE: u8 = 0x67;
pub const OP_ENDIF: u8 = 0x68;
pub const OP_DROP: u8 = 0x75;
pub const OP_DUP: u8 = 0x76;
pub const OP_EQUALVERIFY: u8 = 0x88;
pub const OP_SHA256: u8 = 0xA8;
pub const OP_HASH160: u8 = 0xA9;
pub const OP_CHECKSIG: u8 = 0xAC;
pub const OP_CHECKSIGVERIFY: u8 = 0xAD;
pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xB1;
pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xB2;

/// A minimal data push (direct push below 0x4C bytes, OP_PUSHDATA1 up to 255). Larger pushes
/// are refused: RDTS caps pushes anyway.
pub fn push(data: &[u8]) -> Result<Vec<u8>> {
    let mut v = Vec::with_capacity(data.len() + 2);
    push_into(&mut v, data)?;
    Ok(v)
}

pub fn push_into(out: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    if data.len() < OP_PUSHDATA1 as usize {
        out.push(data.len() as u8);
    } else if data.len() <= 0xFF {
        out.push(OP_PUSHDATA1);
        out.push(data.len() as u8);
    } else {
        return Err(Error::BadScript("push too large for this library (RDTS caps pushes anyway)"));
    }
    out.extend_from_slice(data);
    Ok(())
}

/// Minimal CScriptNum push of a non-negative integer.
pub fn script_num(n: u64) -> Vec<u8> {
    if n == 0 {
        return vec![OP_0];
    }
    if n <= 16 {
        return vec![OP_1 + (n as u8) - 1];
    }
    let mut b = Vec::with_capacity(9);
    let mut m = n;
    while m > 0 {
        b.push((m & 0xFF) as u8);
        m >>= 8;
    }
    if b[b.len() - 1] & 0x80 != 0 {
        b.push(0);
    }
    let mut v = Vec::with_capacity(b.len() + 1);
    v.push(b.len() as u8);
    v.extend_from_slice(&b);
    v
}

/// `OP_0 <sha256(witness_script)>`.
pub fn p2wsh_spk(witness_script: &[u8]) -> Vec<u8> {
    let mut v = vec![0x00, 0x20];
    v.extend_from_slice(&sha256(witness_script));
    v
}

/// `OP_0 <hash160(pubkey)>`.
pub fn p2wpkh_spk(pubkey: &[u8]) -> Vec<u8> {
    let mut v = vec![0x00, 0x14];
    v.extend_from_slice(&hash160(pubkey));
    v
}

/// `OP_1 <32-byte output key>`.
pub fn p2tr_spk(output_key_x: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![OP_1, 0x20];
    v.extend_from_slice(output_key_x);
    v
}

/// The BIP143 scriptCode of a P2WPKH input: `DUP HASH160 <h> EQUALVERIFY CHECKSIG`.
pub fn p2wpkh_script_code(pubkey: &[u8]) -> Vec<u8> {
    let mut v = vec![OP_DUP, OP_HASH160, 0x14];
    v.extend_from_slice(&hash160(pubkey));
    v.extend_from_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
    v
}

/// The kinds of output this library builds and recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpkKind {
    P2wpkh,
    P2wsh,
    P2tr,
}

/// P2WPKH, P2WSH or P2TR (all standard and within the RDTS 34-byte output cap), else None.
pub fn classify(spk: &[u8]) -> Option<SpkKind> {
    match (spk.len(), spk.first(), spk.get(1)) {
        (22, Some(0x00), Some(0x14)) => Some(SpkKind::P2wpkh),
        (34, Some(0x00), Some(0x20)) => Some(SpkKind::P2wsh),
        (34, Some(0x51), Some(0x20)) => Some(SpkKind::P2tr),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_numbers() {
        assert_eq!(script_num(0), vec![0x00]);
        assert_eq!(script_num(16), vec![0x60]);
        assert_eq!(script_num(17), vec![1, 17]);
        assert_eq!(script_num(128), vec![2, 0x80, 0]);
        assert_eq!(script_num(2014), vec![2, 0xDE, 0x07]);
    }

    #[test]
    fn pushes() {
        assert_eq!(push(&[1; 3]).unwrap(), vec![3, 1, 1, 1]);
        assert_eq!(push(&[0; 0x4C]).unwrap()[..2], [0x4C, 0x4C]);
        assert!(push(&[0; 256]).is_err());
    }
}
