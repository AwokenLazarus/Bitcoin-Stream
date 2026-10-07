//! Hash-locked conditional increments (M6/M7): a state that pays `uncond` to the payee plus
//! `cond` to a P2WSH hash lock
//!
//! ```text
//! OP_IF    OP_SHA256 <H> OP_EQUALVERIFY <P> OP_CHECKSIG
//! OP_ELSE  <csvDelta> OP_CSV OP_DROP <A> OP_CHECKSIG
//! OP_ENDIF
//! ```
//!
//! The seller claims with k (sha256(k) = H), which publishes k; the buyer takes the increment
//! back after `csv_delta` blocks if k never arrives. A port of B1 `xbt402/conditional.py`.
use xbt_primitives::hash::sha256;
use xbt_primitives::script::{self, p2wsh_spk, push_into, script_num};
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::sighash::{unified_sighash, ScriptType, SIGHASH_ALL_UNIFIED};
use xbt_primitives::tx::{OutPoint, Tx, TxIn, TxOut};

use crate::channel::{sign_with_type, ChannelParams, FeePayer, DUST};
use crate::error::{fail, ChannelError, Result};

pub const CSV_DELTA: u32 = 10;

pub fn hashlock_script(payee_pub: &[u8], payer_pub: &[u8], h: &[u8], csv_delta: u32) -> Result<Vec<u8>> {
    if h.len() != 32 {
        return fail("bad_hashlock", "H must be 32 bytes");
    }
    let mut s = vec![script::OP_IF, script::OP_SHA256];
    push_into(&mut s, h)?;
    s.push(script::OP_EQUALVERIFY);
    push_into(&mut s, payee_pub)?;
    s.extend_from_slice(&[script::OP_CHECKSIG, script::OP_ELSE]);
    s.extend(script_num(csv_delta as u64));
    s.extend_from_slice(&[script::OP_CHECKSEQUENCEVERIFY, script::OP_DROP]);
    push_into(&mut s, payer_pub)?;
    s.extend_from_slice(&[script::OP_CHECKSIG, script::OP_ENDIF]);
    Ok(s)
}

/// The `sha256(k || BE32(i))` keystream.
pub fn xor_stream(key: &[u8], n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 32);
    let mut i: u32 = 0;
    while out.len() < n {
        let mut b = key.to_vec();
        b.extend_from_slice(&i.to_be_bytes());
        out.extend_from_slice(&sha256(&b));
        i = i.wrapping_add(1);
    }
    out.truncate(n);
    out
}

/// plaintext XOR keystream(k). Its own inverse.
pub fn encrypt(plaintext: &[u8], k: &[u8]) -> Vec<u8> {
    plaintext.iter().zip(xor_stream(k, plaintext.len())).map(|(a, b)| a ^ b).collect()
}

pub fn decrypt(cipher: &[u8], k: &[u8]) -> Vec<u8> {
    encrypt(cipher, k)
}

/// k from a hash-lock claim (any witness item whose SHA-256 is H), or None. The claim that pays
/// the provider publishes k, so a payer holding the ciphertext always gets the deliverable.
pub fn preimage_from_tx(tx: &Tx, h: &[u8; 32]) -> Option<Vec<u8>> {
    tx.inputs.iter().flat_map(|i| i.witness.iter()).find(|w| &sha256(w) == h).cloned()
}

/// A conditional increment on a channel.
#[derive(Debug, Clone)]
pub struct ConditionalParams {
    pub channel: ChannelParams,
    pub h: [u8; 32],
    pub cond_amount: u64,
    pub csv_delta: u32,
    pub script: Vec<u8>,
    pub spk: Vec<u8>,
}

impl ConditionalParams {
    pub fn new(channel: ChannelParams, h: [u8; 32], cond_amount: u64, csv_delta: u32) -> Result<Self> {
        if cond_amount < DUST {
            return fail("bad_amount", "conditional increment below dust");
        }
        let script = hashlock_script(&channel.payee_pub, &channel.payer_pub, &h, csv_delta)?;
        let spk = p2wsh_spk(&script);
        Ok(Self { channel, h, cond_amount, csv_delta, script, spk })
    }

    /// `uncond` to the payee, `cond` to the hash lock, the rest to the payer, the close fee out of
    /// close_fee_payer's side. Under payee-pays the fee comes out of the payee's unconditional
    /// output (which must then clear dust after it) and the hash-lock output stays cond_amount.
    pub fn state_tx(&self, uncond: u64) -> Result<Tx> {
        let p = &self.channel;
        if (uncond > 0 || p.close_fee_payer == FeePayer::Payee && p.close_fee > 0)
            && !(p.min_amount() <= uncond && uncond <= p.max_amount())
        {
            return fail("bad_amount", format!("uncond {uncond} out of range [{}, {}]", p.min_amount(), p.max_amount()));
        }
        let total = uncond as u128 + self.cond_amount as u128 + p.payer_fee() as u128;
        if total > p.capacity as u128 {
            return fail("channel_exhausted", "conditional increment does not fit");
        }
        let mut outs = Vec::with_capacity(3);
        if uncond > 0 {
            outs.push(TxOut::new(p.payee_value(uncond) as i64, p.payee_spk.clone()));
        }
        outs.push(TxOut::new(self.cond_amount as i64, self.spk.clone()));
        let change = p.capacity - total as u64;
        if change >= DUST {
            outs.push(TxOut::new(change as i64, p.payer_spk.clone()));
        }
        let op = p.funding.ok_or_else(|| ChannelError::new("no_funding", "channel has no funding outpoint"))?;
        Ok(Tx::new(2, vec![TxIn::new(op, 0xFFFF_FFFD)], outs, 0))
    }

    pub fn sighash(&self, tx: &Tx) -> Result<[u8; 32]> {
        self.channel.sighash(tx)
    }

    /// Spend the hash-lock output of a conditional close with k, to `dest`.
    pub fn claim_tx(&self, close_txid: &str, vout: u32, k: &[u8], payee_secret: &SecretKey, dest: &[u8], fee: u64) -> Result<Tx> {
        if sha256(k) != self.h {
            return fail("bad_preimage", "sha256(k) != H");
        }
        let value = self.cond_amount.checked_sub(fee).ok_or_else(|| ChannelError::new("bad_amount", "claim fee exceeds the hash lock"))?;
        let op = OutPoint::from_display(close_txid, vout).map_err(|_| ChannelError::new("bad_request", "bad txid"))?;
        let mut tx = Tx::new(2, vec![TxIn::new(op, 0xFFFF_FFFD)], vec![TxOut::new(value as i64, dest.to_vec())], 0);
        let prev = TxOut::new(self.cond_amount as i64, self.spk.clone());
        let h = unified_sighash(&tx, &[prev], 0, ScriptType::WitnessV0, &self.script, SIGHASH_ALL_UNIFIED, None)?;
        tx.inputs[0].witness = vec![sign_with_type(payee_secret, &h, SIGHASH_ALL_UNIFIED), k.to_vec(), vec![0x01], self.script.clone()];
        Ok(tx)
    }
}
