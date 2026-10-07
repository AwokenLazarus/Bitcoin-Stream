//! AGP-049: a channel's funding, proven from the funding transaction on the signer's own node rather
//! than from the LN node's `unified_sigs` flag.
//!
//! A channel's commitment, HTLC and close transactions spend its funding output, so they can replay on
//! SHA-256 Bitcoin only if the funding transaction itself replayed; that needs every input to exist on
//! both chains (confirmed below the split) and every signature to be 0x01 / DEFAULT (AGP-047 §4.2).
//! This module fetches the funding transaction at the position its short channel id names, checks it is
//! the channel's (txid, output, amount, P2WSH), and requires, for every input:
//!
//! - every signature in its witness (or scriptSig) to carry the unified sighash byte **0x21**
//!   (SIGHASH_ALL | SIGHASH_UNIFIED), which SHA-256 consensus rejects;
//! - its coin to be confirmed at or above the split height.
//!
//! Inputs are looked up with `getrawtransaction` (the signer's node needs `txindex=1`); a lookup that
//! fails leaves the channel unproven, and an unproven channel carries no payment.
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
    /// Whether the verdict is final (cacheable per funding outpoint).
    pub fn is_final(&self) -> bool {
        !matches!(self, Funding::Unknown(_))
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

/// The sighash bytes of every signature an input carries, judged by the coin it spends. A taproot key
/// path signature of 64 bytes is SIGHASH_DEFAULT (0x00).
pub fn input_sighashes(inp: &TxIn, prev_spk: &[u8]) -> Vec<u8> {
    if classify(prev_spk) == Some(SpkKind::P2tr) {
        let mut w: Vec<&Vec<u8>> = inp.witness.iter().collect();
        if w.len() >= 2 && w.last().is_some_and(|a| a.first() == Some(&0x50)) {
            w.pop(); // the annex
        }
        let sigs: Vec<&Vec<u8>> = if w.len() == 1 { w } else { w[..w.len().saturating_sub(2)].to_vec() };
        return sigs.iter().filter_map(|s| match s.len() {
            64 => Some(0x00),
            65 => Some(s[64]),
            _ => None,
        }).collect();
    }
    let items: Vec<Vec<u8>> = if !inp.witness.is_empty() {
        // P2WSH: the last item is the witness script, never a signature
        let n = if classify(prev_spk) == Some(SpkKind::P2wsh) || inp.witness.len() > 2 { inp.witness.len() - 1 } else { inp.witness.len() };
        inp.witness[..n].to_vec()
    } else {
        pushes(&inp.script_sig).unwrap_or_default()
    };
    items.iter().filter_map(|i| der_sighash(i)).collect()
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
        let sh = input_sighashes(inp, &spk);
        let shown: Vec<String> = sh.iter().map(|b| format!("0x{b:02x}")).collect();
        if sh.is_empty() {
            bad.push(format!("input {i} ({prev_txid}:{pv}) carries no signature we can read"));
        } else if sh.iter().any(|b| *b != SIGHASH_UNIFIED_ALL) {
            bad.push(format!("input {i} ({prev_txid}:{pv}) is signed {}, not 0x21: the funding can replay on SHA-256 Bitcoin",
                             shown.join("/")));
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
        i.witness = vec![der(0x21), vec![0x02; 33]];
        assert_eq!(input_sighashes(&i, &wpkh), vec![0x21]);
        i.witness = vec![der(0x01), vec![0x02; 33]];
        assert_eq!(input_sighashes(&i, &wpkh), vec![0x01]);
        // 2-of-2 P2WSH: both signatures, never the script
        i.witness = vec![vec![], der(0x21), der(0x01), vec![0x52, 0x21]];
        assert_eq!(input_sighashes(&i, &wsh), vec![0x21, 0x01]);
        // taproot key path: 64 bytes is SIGHASH_DEFAULT
        i.witness = vec![vec![5; 64]];
        assert_eq!(input_sighashes(&i, &tr), vec![0x00]);
        i.witness = vec![[vec![5; 64], vec![0x21]].concat()];
        assert_eq!(input_sighashes(&i, &tr), vec![0x21]);
        // legacy P2PKH: the scriptSig's pushes
        i.witness = vec![];
        let sig = der(0x21);
        i.script_sig = [vec![sig.len() as u8], sig, vec![33], vec![0x02; 33]].concat();
        assert_eq!(input_sighashes(&i, &[0x76, 0xa9]), vec![0x21]);
    }
}
