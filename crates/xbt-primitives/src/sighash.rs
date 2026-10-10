//! The XBT unified signature hash (Knots hf-sighash-opt-in `UnifiedSighash`), and BIP143 for
//! comparison.
//!
//! A unified hash type carries the 0x20 opt-in bit. It commits to every input's amount and
//! scriptPubKey (like BIP341) for every script type, and SHA-256d Bitcoin verifies a different
//! message, so these signatures never replay there.
use crate::encode::write_varbytes;
use crate::error::{Error, Result};
use crate::hash::{dsha256, sha256, tagged_hash};
use crate::tx::{Tx, TxOut};

pub const SIGHASH_ALL: u8 = 0x01;
pub const SIGHASH_SINGLE: u8 = 0x03;
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;
pub const UNIFIED_FLAG: u8 = 0x20;
/// ALL | UNIFIED: every xbt402 channel signature.
pub const SIGHASH_ALL_UNIFIED: u8 = 0x21;
/// SINGLE | ANYONECANPAY | UNIFIED: the fee-input state variant.
pub const SIGHASH_SINGLE_ACP_UNIFIED: u8 = 0xA3;

/// `UnifiedSighash` script-type domain separator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ScriptType {
    Bare = 0,
    WitnessV0 = 1,
    Taproot = 2,
    Tapscript = 3,
}

impl ScriptType {
    pub fn from_u8(n: u8) -> Option<Self> {
        Some(match n {
            0 => ScriptType::Bare,
            1 => ScriptType::WitnessV0,
            2 => ScriptType::Taproot,
            3 => ScriptType::Tapscript,
            _ => return None,
        })
    }
}

/// The tapscript default codeseparator position: no OP_CODESEPARATOR executed.
pub const NO_CODESEP: u32 = 0xFFFF_FFFF;
/// The first byte of a taproot annex (BIP341).
pub const ANNEX_TAG: u8 = 0x50;

/// What a taproot spend commits to beyond the transaction: the annex (key and script path) and the
/// position of the last executed OP_CODESEPARATOR (tapscript). Knots' REDUCED_DATA rule refuses any
/// annex on mainnet until 2027-09-01 (interpreter.cpp:2149), so a signature over one does not verify
/// there yet; it is here so a message is never built over a spend it does not describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendExt<'a> {
    /// The whole annex, its 0x50 tag included (committed as SHA-256 of its compact-size serialization).
    pub annex: Option<&'a [u8]>,
    pub codesep_pos: u32,
}

impl Default for SpendExt<'_> {
    fn default() -> Self {
        Self { annex: None, codesep_pos: NO_CODESEP }
    }
}

/// Port of Knots `UnifiedSighash` (B1 `tx.unified_sighash`): the 32-byte message a unified
/// signature on input `index` signs, for a spend with no annex and no OP_CODESEPARATOR executed
/// (see [`unified_sighash_ext`]). `script_code` is ignored for taproot key/script paths; `leaf_hash`
/// is required for tapscript.
///
/// Script type 0 (bare and P2SH): `script_code` is the script from the last executed
/// OP_CODESEPARATOR with every push of this signature already removed (Knots still runs
/// FindAndDelete there, interpreter.cpp:345-349, and refuses the spend under CONST_SCRIPTCODE if it
/// found one). Script type 1 (witness v0) takes the script code unaltered.
pub fn unified_sighash(tx: &Tx, prevouts: &[TxOut], index: usize, script_type: ScriptType, script_code: &[u8],
                       hash_type: u8, leaf_hash: Option<&[u8; 32]>) -> Result<[u8; 32]> {
    unified_sighash_ext(tx, prevouts, index, script_type, script_code, hash_type, leaf_hash, SpendExt::default())
}

/// [`unified_sighash`] for a spend with an annex (taproot and tapscript) or an executed
/// OP_CODESEPARATOR (tapscript). Values the script type does not commit to are refused rather than
/// ignored.
#[allow(clippy::too_many_arguments)]
pub fn unified_sighash_ext(tx: &Tx, prevouts: &[TxOut], index: usize, script_type: ScriptType, script_code: &[u8],
                           hash_type: u8, leaf_hash: Option<&[u8; 32]>, ext: SpendExt<'_>) -> Result<[u8; 32]> {
    if prevouts.len() != tx.inputs.len() || index >= tx.inputs.len() {
        return Err(Error::Sighash("prevouts/inputs mismatch"));
    }
    let is_tr = matches!(script_type, ScriptType::Taproot | ScriptType::Tapscript);
    if ext.annex.is_some() && !is_tr {
        return Err(Error::Sighash("only a taproot spend has an annex"));
    }
    if ext.annex.is_some_and(|a| a.first() != Some(&ANNEX_TAG)) {
        return Err(Error::Sighash("an annex starts with 0x50"));
    }
    if ext.codesep_pos != NO_CODESEP && script_type != ScriptType::Tapscript {
        return Err(Error::Sighash("only tapscript commits to a codeseparator position"));
    }
    if hash_type & UNIFIED_FLAG == 0 {
        return Err(Error::Sighash("hash type lacks the 0x20 opt-in bit"));
    }
    let out_type = hash_type & 0x1F;
    let acp = hash_type & SIGHASH_ANYONECANPAY != 0;
    if is_tr && ((hash_type & !(0x1F | 0x80 | UNIFIED_FLAG)) != 0 || !(1..=3).contains(&out_type)) {
        return Err(Error::Sighash("undefined taproot hash type"));
    }
    let mut m = Vec::with_capacity(256);
    m.push(0x00);
    m.push(hash_type);
    m.extend_from_slice(&tx.version.to_le_bytes());
    m.extend_from_slice(&tx.locktime.to_le_bytes());
    m.push(0x00);
    if !acp {
        let mut b = Vec::with_capacity(36 * tx.inputs.len());
        for i in &tx.inputs {
            b.extend_from_slice(&i.prevout.serialize());
        }
        m.extend_from_slice(&sha256(&b));
        b.clear();
        for p in prevouts {
            b.extend_from_slice(&p.value.to_le_bytes());
        }
        m.extend_from_slice(&sha256(&b));
        b.clear();
        for p in prevouts {
            write_varbytes(&mut b, &p.script_pubkey);
        }
        m.extend_from_slice(&sha256(&b));
        b.clear();
        for i in &tx.inputs {
            b.extend_from_slice(&i.sequence.to_le_bytes());
        }
        m.extend_from_slice(&sha256(&b));
    }
    if out_type != 2 && out_type != 3 {
        let mut b = Vec::new();
        for o in &tx.outputs {
            o.serialize_into(&mut b);
        }
        m.extend_from_slice(&sha256(&b));
    }
    m.push(script_type as u8);
    if acp {
        let i = &tx.inputs[index];
        m.extend_from_slice(&i.prevout.serialize());
        m.extend_from_slice(&prevouts[index].value.to_le_bytes());
        write_varbytes(&mut m, &prevouts[index].script_pubkey);
        m.extend_from_slice(&i.sequence.to_le_bytes());
    } else {
        m.extend_from_slice(&(index as u32).to_le_bytes());
    }
    if is_tr {
        match ext.annex {
            Some(a) => {
                m.push(0x01);
                let mut s = Vec::with_capacity(a.len() + 9);
                write_varbytes(&mut s, a);
                m.extend_from_slice(&sha256(&s));
            }
            None => m.push(0x00),
        }
    } else {
        write_varbytes(&mut m, script_code);
    }
    if out_type == 3 {
        let o = tx.outputs.get(index).ok_or(Error::Sighash("SIGHASH_SINGLE without output"))?;
        m.extend_from_slice(&sha256(&o.serialize()));
    }
    if script_type == ScriptType::Tapscript {
        let leaf = leaf_hash.ok_or(Error::Sighash("tapscript needs leaf hash"))?;
        m.extend_from_slice(leaf);
        m.push(0x00);
        m.extend_from_slice(&ext.codesep_pos.to_le_bytes());
    }
    Ok(tagged_hash("UnifiedSighash", &m))
}

/// The BIP143 (SHA-256d Bitcoin, segwit v0) message for SIGHASH_ALL: what a unified signature is
/// deliberately not. Used by tests to build the replayable counterpart.
pub fn bip143_sighash(tx: &Tx, index: usize, script_code: &[u8], value: i64) -> Result<[u8; 32]> {
    let i = tx.inputs.get(index).ok_or(Error::Sighash("no such input"))?;
    let mut m = Vec::with_capacity(256);
    m.extend_from_slice(&tx.version.to_le_bytes());
    let mut b = Vec::new();
    for x in &tx.inputs {
        b.extend_from_slice(&x.prevout.serialize());
    }
    m.extend_from_slice(&dsha256(&b));
    b.clear();
    for x in &tx.inputs {
        b.extend_from_slice(&x.sequence.to_le_bytes());
    }
    m.extend_from_slice(&dsha256(&b));
    m.extend_from_slice(&i.prevout.serialize());
    write_varbytes(&mut m, script_code);
    m.extend_from_slice(&value.to_le_bytes());
    m.extend_from_slice(&i.sequence.to_le_bytes());
    b.clear();
    for o in &tx.outputs {
        o.serialize_into(&mut b);
    }
    m.extend_from_slice(&dsha256(&b));
    m.extend_from_slice(&tx.locktime.to_le_bytes());
    m.extend_from_slice(&(SIGHASH_ALL as u32).to_le_bytes());
    Ok(dsha256(&m))
}
