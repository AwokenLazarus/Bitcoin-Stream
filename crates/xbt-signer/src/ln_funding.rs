//! AGP-049: a channel's funding, proven from the funding transaction on the signer's own node rather
//! than from the LN node's `unified_sigs` flag. AGP-066 (review L5) corrected the reasoning below and
//! narrowed what counts as a signature.
//!
//! **What must hold.** A channel's commitment, HTLC and close transactions spend its funding output, so
//! they can replay on SHA-256 Bitcoin only if the funding transaction is valid there too (AGP-047 §4.2).
//! A transaction is invalid if any one input is, so it is enough that an input carries a signature its
//! script checks and SHA-256 Bitcoin cannot verify. This module asks for more: every input, and every
//! signature each input's script checks, must be such a signature.
//!
//! **Why 0x21 is such a signature.** Not because SHA-256 Bitcoin rejects the byte: its consensus
//! accepts hash type 0x21 on legacy and segwit v0 inputs (the byte is only non-standard there; taproot
//! does reject it). The protection is the digest. An XBT signer signs a 0x21 signature over the
//! unified message ([`xbt_primitives::sighash::unified_sighash`]: BIP341-shaped, committing to every
//! input's amount and scriptPubKey), while SHA-256 Bitcoin checks the same bytes against its own
//! message (legacy or BIP143 with hash type 0x21). One ECDSA signature valid for two messages under one
//! key would need the two digests to be equal modulo the group order.
//!
//! **Why reading the bytes suffices, without verifying the signatures here.** The funding transaction
//! is read from a block on the signer's own node's best chain, at the position its short channel id
//! names, so that node's consensus has verified every signature each input's script checks against
//! XBT's message for its hash type (or, below an `assumevalid` block, the network that built on it
//! has). What the bytes alone cannot tell is which pushes the script checks: a 0x21-shaped push that
//! the script never checks (`OP_DROP OP_TRUE`, a hash lock) proves nothing. So only spends whose sole
//! condition is signatures are read ([`checked_sighashes`]): P2WPKH, P2SH-P2WPKH, P2PKH, P2WSH or
//! P2SH-P2WSH with a witness script of `<key> CHECKSIG` or `m <keys> n CHECKMULTISIG`, and a taproot key
//! path. Any other input leaves the channel unproven.
//!
//! **What the height does not prove.** A coin confirmed at or above the split is not thereby XBT-only:
//! a transaction valid on both chains (a 0x01 spend of pre-split coins, broadcast on both) has the same
//! txid on each, so its outputs exist on SHA-256 Bitcoin too, however high it confirmed here. The
//! signatures are the proof. Every input's coin must still be confirmed at or above the split height,
//! as an extra, conservative rule (a channel opened after the split never needs older coins).
//!
//! The funding transaction's checks: the channel's txid, output, amount and P2WSH. Inputs are looked up
//! with `getrawtransaction` (the signer's node needs `txindex=1`); a lookup that fails leaves the
//! channel unproven, and an unproven channel carries no payment. The verdict carries the funding block's
//! hash, which the signer's cache is keyed on, so a reorg proves the channel again.
use serde_json::{json, Value};
use xbt_primitives::script::{classify, SpkKind};
use xbt_primitives::tx::{Tx, TxIn};

use crate::node::{self, Node};

/// SIGHASH_ALL | SIGHASH_UNIFIED (0x20).
pub const SIGHASH_UNIFIED_ALL: u8 = 0x21;

/// The verdict on one channel's funding.
#[derive(Debug, Clone, PartialEq)]
pub enum Funding {
    /// Every input signed 0x21 and confirmed at or above the split: the evidence.
    Proven(Value),
    /// The transaction says the channel is unsafe (or is not the channel's): why, and the evidence.
    Refused(String, Value),
    /// The signer's node could not answer (a missing txindex, the node down): not cached.
    Unknown(String),
}

impl Funding {
    /// Whether the verdict is final (cacheable per funding outpoint, for as long as its block stands).
    pub fn is_final(&self) -> bool {
        !matches!(self, Funding::Unknown(_))
    }

    /// The hash of the block the verdict was reached on, when it was reached on one.
    pub fn block_hash(&self) -> Option<&str> {
        match self {
            Funding::Proven(ev) | Funding::Refused(_, ev) => ev.get("block_hash").and_then(Value::as_str),
            Funding::Unknown(_) => None,
        }
    }
}

/// A strict (BIP 66 shaped) DER ECDSA signature followed by one sighash byte: the sighash byte.
pub fn der_sighash(item: &[u8]) -> Option<u8> {
    let n = item.len();
    if !(9..=73).contains(&n) || item[0] != 0x30 || item[1] as usize != n - 3 || item[2] != 0x02 {
        return None;
    }
    let rlen = item[3] as usize;
    if rlen == 0 || 5 + rlen >= n || item[4 + rlen] != 0x02 {
        return None;
    }
    let slen = item[5 + rlen] as usize;
    (slen > 0 && rlen + slen + 7 == n).then(|| item[n - 1])
}

/// The data pushes of a push-only script (`None` if it has any other opcode).
pub fn pushes(script: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut out = vec![];
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        i += 1;
        let n = match op {
            0x00 => 0,
            0x01..=0x4b => op as usize,
            0x4c => {
                let n = *script.get(i)? as usize;
                i += 1;
                n
            }
            0x4d => {
                let n = u16::from_le_bytes([*script.get(i)?, *script.get(i + 1)?]) as usize;
                i += 2;
                n
            }
            0x4e => {
                let b = script.get(i..i + 4)?;
                i += 4;
                u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
            }
            _ => return None,
        };
        out.push(script.get(i..i + n)?.to_vec());
        i += n;
    }
    Some(out)
}

const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKMULTISIG: u8 = 0xae;

/// `OP_1`..`OP_16` as a number.
fn small_int(op: u8) -> Option<usize> {
    (0x51..=0x60).contains(&op).then(|| (op - 0x50) as usize)
}

/// How many signatures a witness script checks, if checking them is all it does: `<key> CHECKSIG`
/// (`Some((1, false))`) or `m <keys> n CHECKMULTISIG` (`Some((m, true))`), compressed keys only.
fn sig_only_script(s: &[u8]) -> Option<(usize, bool)> {
    if s.len() == 35 && s[0] == 0x21 && s[34] == OP_CHECKSIG {
        return Some((1, false));
    }
    let (&first, rest) = s.split_first()?;
    let (&last, rest) = rest.split_last()?;
    let (&nop, keys) = rest.split_last()?;
    let (m, n) = (small_int(first)?, small_int(nop)?);
    (last == OP_CHECKMULTISIG && m <= n && keys.len() == 34 * n && keys.chunks(34).all(|k| k[0] == 0x21)).then_some((m, true))
}

/// The sighash bytes of `items`, each of which must be a DER signature.
fn der_all(items: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    items.iter().map(|i| der_sighash(i).ok_or_else(|| "a pushed signature is not a strict DER signature".to_string())).collect()
}

/// A segwit v0 spend of a 20-byte (P2WPKH) or 32-byte (P2WSH) program.
fn witness_v0(witness: &[Vec<u8>], program_len: usize) -> Result<Vec<u8>, String> {
    if program_len == 20 {
        return match witness {
            [sig, key] if key.len() == 33 => der_all(std::slice::from_ref(sig)),
            _ => Err("its P2WPKH witness is not [signature, compressed key]".into()),
        };
    }
    let (script, items) = witness.split_last().ok_or("its P2WSH witness is empty")?;
    let Some((m, multi)) = sig_only_script(script) else {
        return Err("its witness script is not `<key> CHECKSIG` or `m <keys> n CHECKMULTISIG`: its pushes may be data the script never \
                    checks, so a 0x21 byte among them proves nothing".into());
    };
    match (multi, items) {
        (false, [sig]) => der_all(std::slice::from_ref(sig)),
        (true, [dummy, sigs @ ..]) if dummy.is_empty() && sigs.len() == m => der_all(sigs),
        _ => Err(format!("its witness does not hold exactly the {m} signature(s) its script checks")),
    }
}

/// AGP-066 (review L5): the sighash bytes of exactly the signatures an input's script checks, judged by
/// the coin it spends, or why the input cannot be read: only spends whose sole condition is signatures
/// count (the module documentation says why). A taproot key path signature of 64 bytes is
/// SIGHASH_DEFAULT (0x00).
pub fn checked_sighashes(inp: &TxIn, prev_spk: &[u8]) -> Result<Vec<u8>, String> {
    match classify(prev_spk) {
        Some(SpkKind::P2wpkh) => return witness_v0(&inp.witness, 20),
        Some(SpkKind::P2wsh) => return witness_v0(&inp.witness, 32),
        Some(SpkKind::P2tr) => {
            let mut w: &[Vec<u8>] = &inp.witness;
            if w.len() >= 2 && w.last().is_some_and(|a| a.first() == Some(&0x50)) {
                w = &w[..w.len() - 1]; // the annex
            }
            return match w {
                [s] if s.len() == 64 => Ok(vec![0x00]),
                [s] if s.len() == 65 => Ok(vec![s[64]]),
                [_] => Err("its taproot key path signature is not 64 or 65 bytes".into()),
                _ => Err("a taproot script path spend: which pushes its leaf script checks is not read".into()),
            };
        }
        None => {}
    }
    let p2sh = prev_spk.len() == 23 && prev_spk[..2] == [0xa9, 0x14] && prev_spk[22] == 0x87;
    let p2pkh = prev_spk.len() == 25 && prev_spk[..3] == [0x76, 0xa9, 0x14] && prev_spk[23..] == [0x88, OP_CHECKSIG];
    let pushed = pushes(&inp.script_sig).ok_or("its scriptSig is not push-only")?;
    if p2sh {
        return match pushed.as_slice() {
            [r] if r.len() == 22 && r[..2] == [0x00, 0x14] => witness_v0(&inp.witness, 20),
            [r] if r.len() == 34 && r[..2] == [0x00, 0x20] => witness_v0(&inp.witness, 32),
            _ => Err("a P2SH spend that is not P2SH-P2WPKH or P2SH-P2WSH".into()),
        };
    }
    if p2pkh {
        return match pushed.as_slice() {
            [sig, key] if key.len() == 33 || key.len() == 65 => der_all(std::slice::from_ref(sig)),
            _ => Err("its P2PKH scriptSig is not [signature, key]".into()),
        };
    }
    Err("it spends a script the proof cannot read (not P2WPKH, P2WSH, P2TR, P2SH-wrapped segwit or P2PKH)".into())
}

fn height_of_block(node: &dyn Node, blockhash: &str) -> Option<i64> {
    node.call("getblockheader", json!([blockhash])).ok()?.get("height").and_then(Value::as_i64)
}

fn tx_hex(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string).or_else(|| v.get("hex").and_then(Value::as_str).map(str::to_string))
}

/// Prove (or refuse) one channel's funding: `channel_point` is LND's `txid:vout`, `scid` its short
/// channel id, `capacity` its size in sats.
pub fn check(node: &dyn Node, channel_point: &str, scid: u64, capacity: i64, split_height: i64) -> Funding {
    let Some((txid, vout)) = channel_point.split_once(':').and_then(|(t, v)| Some((t.to_lowercase(), v.parse::<u32>().ok()?))) else {
        return Funding::Refused(format!("channel_point {channel_point:?} is not txid:vout"), Value::Null);
    };
    let (height, pos, out) = ((scid >> 40) as i64, ((scid >> 16) & 0xff_ffff) as usize, (scid & 0xffff) as u32);
    let ev = |extra: Value| {
        let mut e = json!({"txid": txid, "vout": vout, "height": height, "tx_index": pos});
        if let (Some(o), Value::Object(x)) = (e.as_object_mut(), extra) {
            o.extend(x);
        }
        e
    };
    if out != vout {
        return Funding::Refused(format!("the short channel id's output {out} is not the channel point's {vout}"), ev(json!({})));
    }
    let bh = match node::block_hash(node, height as u64) {
        Ok(h) => h,
        Err(e) => return Funding::Unknown(format!("our node has no block {height}: {}", e.msg)),
    };
    let ev = |extra: Value| {
        let mut e = ev(extra);
        e["block_hash"] = bh.clone().into();
        e
    };
    let block = match node.call("getblock", json!([bh, 1])) {
        Ok(b) => b,
        Err(e) => return Funding::Unknown(format!("getblock {height}: {}", e.msg)),
    };
    let at = block.get("tx").and_then(Value::as_array).and_then(|t| t.get(pos))
        .and_then(|t| t.as_str().map(str::to_string).or_else(|| t.get("txid").and_then(Value::as_str).map(str::to_string)));
    if at.as_deref() != Some(txid.as_str()) {
        return Funding::Refused(format!("our node's block {height} holds {} at position {pos}, not the channel's funding",
                                        at.unwrap_or_else(|| "nothing".into())), ev(json!({})));
    }
    let raw = match node.call("getrawtransaction", json!([txid, true, bh])).ok().as_ref().and_then(tx_hex) {
        Some(h) => h,
        None => return Funding::Unknown(format!("our node cannot return the funding transaction {txid}")),
    };
    let tx = match Tx::parse_hex(&raw) {
        Ok(t) if t.txid() == txid => t,
        _ => return Funding::Refused(format!("our node's transaction {txid} does not parse to that txid"), ev(json!({}))),
    };
    let Some(o) = tx.outputs.get(vout as usize) else {
        return Funding::Refused(format!("the funding transaction has no output {vout}"), ev(json!({})));
    };
    if o.value != capacity {
        return Funding::Refused(format!("the funding output holds {} sats, the channel says {capacity}", o.value), ev(json!({})));
    }
    if classify(&o.script_pubkey) != Some(SpkKind::P2wsh) {
        return Funding::Refused("the funding output is not a P2WSH 2-of-2".into(), ev(json!({})));
    }
    let mut inputs = vec![];
    let mut bad = vec![];
    for (i, inp) in tx.inputs.iter().enumerate() {
        let prev_txid = inp.prevout.txid_hex();
        let pv = inp.prevout.vout;
        let Some(prev) = node::get_tx(node, &prev_txid, "") else {
            return Funding::Unknown(format!("our node cannot find input {i}'s transaction {prev_txid} (the signer's node needs txindex=1)"));
        };
        let spk = match prev.get("hex").and_then(Value::as_str).and_then(|h| Tx::parse_hex(h).ok()) {
            Some(t) if t.txid() == prev_txid => t.outputs.get(pv as usize).map(|o| o.script_pubkey.clone()),
            _ => None,
        };
        let Some(spk) = spk else {
            return Funding::Refused(format!("input {i}'s coin {prev_txid}:{pv} is not in our node's copy of its transaction"), ev(json!({})));
        };
        let h = prev.get("blockhash").and_then(Value::as_str).and_then(|b| height_of_block(node, b));
        let Some(h) = h else {
            return Funding::Unknown(format!("input {i}'s transaction {prev_txid} has no confirmed block on our node"));
        };
        let sh = checked_sighashes(inp, &spk);
        let shown: Vec<String> = sh.iter().flatten().map(|b| format!("0x{b:02x}")).collect();
        match &sh {
            Err(why) => bad.push(format!("input {i} ({prev_txid}:{pv}): {why}")),
            Ok(s) if s.is_empty() => bad.push(format!("input {i} ({prev_txid}:{pv}) carries no signature we can read")),
            Ok(s) if s.iter().any(|b| *b != SIGHASH_UNIFIED_ALL) => {
                bad.push(format!("input {i} ({prev_txid}:{pv}) is signed {}, not 0x21: SHA-256 Bitcoin may verify it, so the funding \
                                  may replay there", shown.join("/")));
            }
            Ok(_) => {}
        }
        if h < split_height {
            bad.push(format!("input {i} ({prev_txid}:{pv}) was confirmed at {h}, below the split {split_height}"));
        }
        inputs.push(json!({"outpoint": format!("{prev_txid}:{pv}"), "height": h, "sighash": shown}));
    }
    let evidence = ev(json!({"inputs": inputs, "source": "the signer's own node"}));
    if bad.is_empty() { Funding::Proven(evidence) } else { Funding::Refused(bad.join("; "), evidence) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der(sighash: u8) -> Vec<u8> {
        let mut s = vec![0x30, 0x44, 0x02, 0x20];
        s.extend([1u8; 32]);
        s.extend([0x02, 0x20]);
        s.extend([2u8; 32]);
        s.push(sighash);
        s
    }

    #[test]
    fn reads_sighash_bytes_by_input_kind() {
        assert_eq!(der_sighash(&der(0x21)), Some(0x21));
        assert_eq!(der_sighash(&[0x02; 33]), None, "a pubkey is not a signature");
        assert_eq!(der_sighash(&der(0x21)[..70]), None);
        let wpkh = [0u8, 0x14].iter().copied().chain([7u8; 20]).collect::<Vec<u8>>();
        let wsh = [0u8, 0x20].iter().copied().chain([7u8; 32]).collect::<Vec<u8>>();
        let tr = [0x51u8, 0x20].iter().copied().chain([7u8; 32]).collect::<Vec<u8>>();
        let mut i = TxIn::new(xbt_primitives::tx::OutPoint::new([0; 32], 0), 0);
        let read = |i: &TxIn, spk: &[u8]| checked_sighashes(i, spk);
        i.witness = vec![der(0x21), vec![0x02; 33]];
        assert_eq!(read(&i, &wpkh), Ok(vec![0x21]));
        i.witness = vec![der(0x01), vec![0x02; 33]];
        assert_eq!(read(&i, &wpkh), Ok(vec![0x01]));
        i.witness = vec![vec![0x02; 33], der(0x21)];
        assert!(read(&i, &wpkh).is_err(), "the key is not a signature");
        // 2-of-2 P2WSH: both signatures, never the script
        let ms = [vec![0x52, 0x21], vec![2; 33], vec![0x21], vec![3; 33], vec![0x52, 0xae]].concat();
        i.witness = vec![vec![], der(0x21), der(0x01), ms.clone()];
        assert_eq!(read(&i, &wsh), Ok(vec![0x21, 0x01]));
        i.witness = vec![vec![], der(0x21), ms.clone()];
        assert!(read(&i, &wsh).is_err(), "2-of-2 with one signature");
        let single = [vec![0x21], vec![2; 33], vec![0xac]].concat();
        i.witness = vec![der(0x21), single];
        assert_eq!(read(&i, &wsh), Ok(vec![0x21]));
        // AGP-066: a script that checks no signature, or not only signatures, is not read
        for script in [vec![0x75, 0x51], [vec![0xa8, 0x20], vec![1; 32], vec![0x87]].concat(), [ms.clone(), vec![0x75]].concat()] {
            i.witness = vec![der(0x21), script];
            assert!(read(&i, &wsh).unwrap_err().contains("CHECKSIG"));
        }
        // taproot key path: 64 bytes is SIGHASH_DEFAULT; a script path is not read
        i.witness = vec![vec![5; 64]];
        assert_eq!(read(&i, &tr), Ok(vec![0x00]));
        i.witness = vec![[vec![5; 64], vec![0x21]].concat()];
        assert_eq!(read(&i, &tr), Ok(vec![0x21]));
        i.witness = vec![[vec![5; 64], vec![0x21]].concat(), vec![0x50, 1]];
        assert_eq!(read(&i, &tr), Ok(vec![0x21]), "the annex is not a script path");
        i.witness = vec![[vec![5; 64], vec![0x21]].concat(), vec![0x51], vec![0xc0; 33]];
        assert!(read(&i, &tr).unwrap_err().contains("script path"));
        // legacy P2PKH: the scriptSig's pushes
        i.witness = vec![];
        let sig = der(0x21);
        let p2pkh = [vec![0x76, 0xa9, 0x14], vec![4; 20], vec![0x88, 0xac]].concat();
        i.script_sig = [vec![sig.len() as u8], sig.clone(), vec![33], vec![0x02; 33]].concat();
        assert_eq!(read(&i, &p2pkh), Ok(vec![0x21]));
        assert!(read(&i, &[0x76, 0xa9]).is_err(), "not a script the proof reads");
        // P2SH-P2WPKH: the redeem script pushed, the signature in the witness
        let p2sh = [vec![0xa9, 0x14], vec![1; 20], vec![0x87]].concat();
        i.script_sig = [vec![22u8, 0x00, 0x14], vec![9; 20]].concat();
        i.witness = vec![der(0x21), vec![0x02; 33]];
        assert_eq!(read(&i, &p2sh), Ok(vec![0x21]));
        i.script_sig = [vec![sig.len() as u8], sig].concat();
        assert!(read(&i, &p2sh).is_err(), "legacy P2SH is not read");
    }

    /// Property: whatever the witness, a P2WSH input is read only when its script is a key check, and
    /// then yields exactly the signatures that script checks.
    #[test]
    fn only_signature_only_scripts_are_read() {
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let wsh = [vec![0u8, 0x20], vec![7u8; 32]].concat();
        let mut i = TxIn::new(xbt_primitives::tx::OutPoint::new([0; 32], 0), 0);
        for _ in 0..2_000 {
            let n = (next() % 4) as usize;
            let script: Vec<u8> = (0..(next() % 40) as usize).map(|_| [0x51, 0x52, 0x21, 0xac, 0xae, 0x75, 0x87, 0x02][(next() % 8) as usize]).collect();
            i.witness = (0..n).map(|_| if next() % 2 == 0 { der(0x21) } else { vec![] }).chain([script.clone()]).collect();
            if let Ok(sh) = checked_sighashes(&i, &wsh) {
                let (m, _) = sig_only_script(&script).expect("read only a key-check script");
                assert_eq!(sh.len(), m);
            }
        }
    }
}
