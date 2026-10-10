//! Spillman-style unidirectional channels: the funding script, state (commitment) txs, the payee's
//! close and the payer's refund. Every channel signature is SIGHASH_ALL|UNIFIED (0x21), except the
//! 0xA3 fee-input state variant. A port of B1 `xbt402/channel.py`.
//!
//! The funding output is P2WSH of
//!
//! ```text
//! OP_IF
//!     <payee_pub> OP_CHECKSIGVERIFY
//! OP_ELSE
//!     <expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP
//! OP_ENDIF
//! <payer_pub> OP_CHECKSIG
//! ```
//!
//! - pay path (any time): witness `[payer_sig, payee_sig, 0x01, script]`
//! - refund (height >= expiry): witness `[payer_sig, <empty>, script]`, nLockTime = expiry
use serde_json::{Map, Value};
use xbt_primitives::ecdsa::{self, PubkeyBytes};
use xbt_primitives::hash::tagged_hash;
use xbt_primitives::script::{self, classify, p2wpkh_script_code, p2wpkh_spk, p2wsh_spk, push_into, script_num};
use xbt_primitives::secp256k1::{PublicKey, SecretKey};
use xbt_primitives::sighash::{unified_sighash, ScriptType, SIGHASH_ALL_UNIFIED, SIGHASH_SINGLE_ACP_UNIFIED};
use xbt_primitives::tx::{OutPoint, Tx, TxIn, TxOut};

use crate::error::{fail, ChannelError, Result};

/// Conservative dust floor for any output xbt402 creates.
pub const DUST: u64 = 546;
/// nSequence of a refund that signals replaceability (BIP125 opt-in RBF): the hub re-signs a stuck
/// ch2 refund at a higher fee (AGP-044). Below 0xFFFFFFFE, so nLockTime is still enforced.
pub const RBF_SEQUENCE: u32 = 0xFFFF_FFFD;
/// 1-in/2-out close vsize estimate (plus room for a P2TR change).
pub const STATE_VSIZE: u64 = 190;
/// 1-in/1-out refund vsize estimate.
pub const REFUND_VSIZE: u64 = 140;
/// Below this nLockTime/CLTV is a block height.
pub const EXPIRY_MAX: u32 = 500_000_000;
/// v1.1 payee key derivation tag (v1.0 was "xbt-channel/payee", without the network).
pub const PAYEE_TAG: &str = "xbt-channel/payee/v2";
/// Advertised as `PaymentRequirements.extra.derivation`: what a client must speak before it funds.
/// "v3" (AGP-068) keeps the v2 payee key ([`PAYEE_TAG`]) and binds requests with
/// [`crate::wire::request_digest_v2`] and receipts over the answer; a "v2" client refuses it
/// before funding, as a "v3" client refuses a "v2" server.
pub const DERIVATION: &str = "v3";

/// Who pays a state's close fee (v1.2 `closeFeePayer`; v1.1 is always the payer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum FeePayer {
    #[default]
    Payer,
    Payee,
}

impl FeePayer {
    pub fn as_str(self) -> &'static str {
        match self {
            FeePayer::Payer => "payer",
            FeePayer::Payee => "payee",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "payer" => Ok(FeePayer::Payer),
            "payee" => Ok(FeePayer::Payee),
            _ => fail("bad_fee_payer", "closeFeePayer must be payer or payee"),
        }
    }
}

/// The one spelling of a channel id: 64 lowercase hex txid, ':', decimal vout. bitcoind parses
/// txids case-insensitively, so without this one outpoint could be opened (and credited) under
/// many ids.
pub fn canonical_chan(chan: &str) -> Result<String> {
    let bad = || ChannelError::new("unknown_channel", "chan must be txid:vout");
    let (txid, vout) = chan.split_once(':').ok_or_else(bad)?;
    if txid.len() != 64 || vout.is_empty() || vout.len() > 10 || !vout.bytes().all(|c| c.is_ascii_digit()) {
        return Err(bad());
    }
    let raw = hex::decode(txid).map_err(|_| ChannelError::new("unknown_channel", "txid is not hex"))?;
    let n: u64 = vout.parse().map_err(|_| bad())?;
    Ok(format!("{}:{}", hex::encode(raw), n))
}

/// A payout scriptPubKey both sides can put in every state: P2WPKH, P2WSH or P2TR, which are
/// standard and fit the RDTS 34-byte output cap.
pub fn check_payout_spk(spk_hex: &str) -> Result<Vec<u8>> {
    let b = hex::decode(spk_hex).map_err(|_| ChannelError::new("bad_payer_spk", "payerSpk is not hex"))?;
    if classify(&b).is_none() {
        return fail("bad_payer_spk", "payerSpk must be P2WPKH, P2WSH or P2TR");
    }
    Ok(b)
}

pub fn funding_script(payer_pub: &[u8], payee_pub: &[u8], expiry: u32) -> Result<Vec<u8>> {
    if !(0 < expiry && expiry < EXPIRY_MAX) {
        return fail("bad_expiry", "expiry must be a block height");
    }
    let mut s = vec![script::OP_IF];
    push_into(&mut s, payee_pub)?;
    s.extend_from_slice(&[script::OP_CHECKSIGVERIFY, script::OP_ELSE]);
    s.extend(script_num(expiry as u64));
    s.extend_from_slice(&[script::OP_CHECKLOCKTIMEVERIFY, script::OP_DROP, script::OP_ENDIF]);
    push_into(&mut s, payer_pub)?;
    s.push(script::OP_CHECKSIG);
    Ok(s)
}

/// `len8(NET) || NET || payTo || A || LE32(expiry)`, NET = the UTF-8 CAIP-2 network string
/// exactly as in the 402. The length byte keeps the encoding injective.
pub fn payee_tweak_preimage(network: &str, pay_to: &[u8], payer_pub: &[u8], expiry: u32) -> Result<Vec<u8>> {
    let net = network.as_bytes();
    if net.is_empty() || net.len() >= 256 {
        return fail("wrong_network", "network must be a non-empty CAIP-2 string");
    }
    let mut v = Vec::with_capacity(1 + net.len() + pay_to.len() + payer_pub.len() + 4);
    v.push(net.len() as u8);
    v.extend_from_slice(net);
    v.extend_from_slice(pay_to);
    v.extend_from_slice(payer_pub);
    v.extend_from_slice(&expiry.to_le_bytes());
    Ok(v)
}

/// `t = tagged_hash("xbt-channel/payee/v2", preimage) mod n`, big-endian.
pub fn payee_tweak(network: &str, pay_to: &[u8], payer_pub: &[u8], expiry: u32) -> Result<[u8; 32]> {
    let h = tagged_hash(PAYEE_TAG, &payee_tweak_preimage(network, pay_to, payer_pub, expiry)?);
    Ok(ecdsa::scalar_mod_n(&h).to_be_bytes())
}

fn parse_pub(b: &[u8], code: &str) -> Result<PublicKey> {
    ecdsa::public_key(b).map_err(|_| ChannelError::new(code, "not a secp256k1 public key"))
}

/// Per-channel payee key `P = payTo + t·G`. The payer derives it from the 402 alone, so opening is
/// one round trip and no two channels share a key; the network is in t, so one payTo reused on
/// regtest and mainnet derives unrelated channel keys.
pub fn channel_payee_pub(network: &str, pay_to: &[u8], payer_pub: &[u8], expiry: u32) -> Result<PubkeyBytes> {
    let h = tagged_hash(PAYEE_TAG, &payee_tweak_preimage(network, pay_to, payer_pub, expiry)?);
    let p = ecdsa::tweak_add_pub(&parse_pub(pay_to, "bad_key")?, &ecdsa::scalar_mod_n(&h))?;
    Ok(p.serialize())
}

/// `p = payTo_secret + t`: the channel payee secret. Never export it.
pub fn channel_payee_secret(network: &str, pay_to_secret: &SecretKey, payer_pub: &[u8], expiry: u32) -> Result<SecretKey> {
    let pay_to = ecdsa::pubkey(pay_to_secret);
    let h = tagged_hash(PAYEE_TAG, &payee_tweak_preimage(network, &pay_to, payer_pub, expiry)?);
    Ok(ecdsa::tweak_add_secret(pay_to_secret, &ecdsa::scalar_mod_n(&h))?)
}

/// Per-channel request-authentication key, `tagged_hash("xbt402/auth-key", ECDH(A, P).x)`: the
/// payer computes it with a and P, the payee with p and A.
pub fn channel_auth_key(secret: &SecretKey, other_pub: &[u8]) -> Result<[u8; 32]> {
    let pk = parse_pub(other_pub, "bad_key")?;
    Ok(tagged_hash("xbt402/auth-key", &ecdsa::ecdh_x(secret, &pk)))
}

/// Everything both sides need to rebuild any state tx byte for byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelParams {
    pub payer_pub: PubkeyBytes,
    pub payee_pub: PubkeyBytes,
    /// Absolute block height.
    pub expiry: u32,
    /// The payer's change scriptPubKey.
    pub payer_spk: Vec<u8>,
    /// The payee's earnings scriptPubKey.
    pub payee_spk: Vec<u8>,
    /// Sats, fixed at open (x402 `extra.closeFeeSat`).
    pub close_fee: u64,
    /// The funding output, once funded.
    pub funding: Option<OutPoint>,
    /// Sats in the funding output.
    pub capacity: u64,
    /// v1.2: who pays `close_fee`, fixed at open.
    pub close_fee_payer: FeePayer,
}

fn pub33(b: &[u8], code: &str) -> Result<PubkeyBytes> {
    let pk = parse_pub(b, code)?;
    if b.len() != 33 {
        return fail(code, "public keys must be 33-byte compressed");
    }
    Ok(pk.serialize())
}

impl ChannelParams {
    /// Terms both sides compute from the challenge (payTo, network), the payer's key and expiry.
    /// `payer_spk` defaults to P2WPKH(payer_pub).
    pub fn derive(pay_to: &[u8], payer_pub: &[u8], expiry: u32, close_fee: u64, payer_spk: Option<Vec<u8>>,
                  network: &str, close_fee_payer: FeePayer) -> Result<Self> {
        let payer = pub33(payer_pub, "bad_key")?;
        let payee = channel_payee_pub(network, pay_to, &payer, expiry)?;
        funding_script(&payer, &payee, expiry)?;
        Ok(Self {
            payer_pub: payer,
            payee_pub: payee,
            expiry,
            payer_spk: payer_spk.filter(|s| !s.is_empty()).unwrap_or_else(|| p2wpkh_spk(&payer)),
            payee_spk: p2wpkh_spk(&payee),
            close_fee,
            funding: None,
            capacity: 0,
            close_fee_payer,
        })
    }

    /// Set the funding outpoint (display txid) and capacity.
    pub fn with_funding(mut self, txid_hex: &str, vout: u32, capacity: u64) -> Result<Self> {
        self.funding = Some(OutPoint::from_display(txid_hex, vout).map_err(|_| ChannelError::new("unknown_channel", "txid is not hex"))?);
        self.capacity = capacity;
        Ok(self)
    }

    pub fn script(&self) -> Vec<u8> {
        // validated at construction (derive / from_json), so this cannot fail
        funding_script(&self.payer_pub, &self.payee_pub, self.expiry).unwrap_or_default()
    }

    pub fn spk(&self) -> Vec<u8> {
        p2wsh_spk(&self.script())
    }

    pub fn funding_txid(&self) -> String {
        self.funding.map(|o| o.txid_hex()).unwrap_or_default()
    }

    pub fn funding_vout(&self) -> u32 {
        self.funding.map(|o| o.vout).unwrap_or(0)
    }

    /// `txid:vout`.
    pub fn channel_id(&self) -> String {
        format!("{}:{}", self.funding_txid(), self.funding_vout())
    }

    // who pays the close fee (v1.2). A state for cumulative amount `cum` pays
    //     payer-pays (v1.1): payee cum,              payer capacity - close_fee - cum
    //     payee-pays (v1.2): payee cum - close_fee,  payer capacity - cum

    /// The part of the close fee that comes out of the payee's output.
    pub fn payee_fee(&self) -> u64 {
        if self.close_fee_payer == FeePayer::Payee { self.close_fee } else { 0 }
    }

    /// The part of the close fee that comes out of the payer's output.
    pub fn payer_fee(&self) -> u64 {
        if self.close_fee_payer == FeePayer::Payer { self.close_fee } else { 0 }
    }

    /// Least cumulative amount a state can pay: the payee output must clear dust after its fee.
    pub fn min_amount(&self) -> u64 {
        DUST + self.payee_fee()
    }

    /// Most the payer can ever sign to the payee (0 when the fee exceeds the capacity).
    pub fn max_amount(&self) -> u64 {
        self.capacity.saturating_sub(self.payer_fee())
    }

    /// What the payee's output of the state for `amount` holds (its net payout).
    pub fn payee_value(&self, amount: u64) -> u64 {
        amount.saturating_sub(self.payee_fee())
    }

    /// The reference's `to_dict()`: field order kept, `close_fee_payer` only when "payee" (v1.1
    /// channels serialise exactly as before).
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("payer_pub".into(), hex::encode(self.payer_pub).into());
        m.insert("payee_pub".into(), hex::encode(self.payee_pub).into());
        m.insert("expiry".into(), self.expiry.into());
        m.insert("payer_spk".into(), hex::encode(&self.payer_spk).into());
        m.insert("payee_spk".into(), hex::encode(&self.payee_spk).into());
        m.insert("close_fee".into(), self.close_fee.into());
        m.insert("funding_txid".into(), self.funding_txid().into());
        m.insert("funding_vout".into(), self.funding_vout().into());
        m.insert("capacity".into(), self.capacity.into());
        if self.close_fee_payer != FeePayer::Payer {
            m.insert("close_fee_payer".into(), self.close_fee_payer.as_str().into());
        }
        Value::Object(m)
    }

    /// Inverse of [`to_json`](Self::to_json) (the reference's `ChannelParams(**d)`).
    pub fn from_json(v: &Value) -> Result<Self> {
        let bad = |w: &str| ChannelError::new("bad_params", w.to_string());
        let s = |k: &str| v.get(k).and_then(Value::as_str).ok_or_else(|| bad(k));
        let n = |k: &str| v.get(k).and_then(Value::as_u64).ok_or_else(|| bad(k));
        let h = |k: &str| s(k).and_then(|x| hex::decode(x).map_err(|_| bad(k)));
        let payer_pub = pub33(&h("payer_pub")?, "bad_params")?;
        let payee_pub = pub33(&h("payee_pub")?, "bad_params")?;
        let expiry = u32::try_from(n("expiry")?).map_err(|_| bad("expiry"))?;
        funding_script(&payer_pub, &payee_pub, expiry)?;
        let txid = v.get("funding_txid").and_then(Value::as_str).unwrap_or("");
        let vout = v.get("funding_vout").and_then(Value::as_u64).unwrap_or(0);
        let funding = if txid.is_empty() {
            None
        } else {
            Some(OutPoint::from_display(txid, u32::try_from(vout).map_err(|_| bad("funding_vout"))?).map_err(|_| bad("funding_txid"))?)
        };
        Ok(Self {
            payer_pub,
            payee_pub,
            expiry,
            payer_spk: h("payer_spk")?,
            payee_spk: h("payee_spk")?,
            close_fee: n("close_fee")?,
            funding,
            capacity: v.get("capacity").and_then(Value::as_u64).unwrap_or(0),
            close_fee_payer: FeePayer::parse(v.get("close_fee_payer").and_then(Value::as_str).unwrap_or("payer"))?,
        })
    }

    pub fn funding_prevout(&self) -> TxOut {
        TxOut::new(self.capacity as i64, self.spk())
    }

    fn funding_in(&self, sequence: u32) -> Result<TxIn> {
        let op = self.funding.ok_or_else(|| ChannelError::new("no_funding", "channel has no funding outpoint"))?;
        Ok(TxIn::new(op, sequence))
    }

    fn check_amount(&self, amount: u64) -> Result<()> {
        if amount < self.min_amount() || amount > self.max_amount() {
            return fail("bad_amount", format!("amount {amount} outside [{}, {}]", self.min_amount(), self.max_amount()));
        }
        Ok(())
    }

    /// Close tx for cumulative `amount`: the payee gets `amount` (less its close fee under
    /// payee-pays), the payer the rest. A payer remainder below dust is left to the fee.
    pub fn state_tx(&self, amount: u64) -> Result<Tx> {
        self.check_amount(amount)?;
        let mut outs = vec![TxOut::new(self.payee_value(amount) as i64, self.payee_spk.clone())];
        let change = self.capacity - self.payer_fee() - amount;
        if change >= DUST {
            outs.push(TxOut::new(change as i64, self.payer_spk.clone()));
        }
        Ok(Tx::new(2, vec![self.funding_in(0xFFFF_FFFD)?], outs, 0))
    }

    /// The 0x21 message for a tx spending the funding output.
    pub fn sighash(&self, tx: &Tx) -> Result<[u8; 32]> {
        Ok(unified_sighash(tx, &[self.funding_prevout()], 0, ScriptType::WitnessV0, &self.script(), SIGHASH_ALL_UNIFIED, None)?)
    }

    /// The 0xA3 message.
    pub fn sighash_a3(&self, tx: &Tx) -> Result<[u8; 32]> {
        Ok(unified_sighash(tx, &[self.funding_prevout()], 0, ScriptType::WitnessV0, &self.script(), SIGHASH_SINGLE_ACP_UNIFIED, None)?)
    }

    /// The payer's unilateral refund, valid once the chain reaches `expiry`. `dest_spk` defaults
    /// to the payer's change script, `fee` to the close fee.
    pub fn refund_tx(&self, payer_secret: &SecretKey, dest_spk: Option<&[u8]>, fee: Option<u64>) -> Result<Tx> {
        self.refund_tx_seq(payer_secret, dest_spk, fee, 0xFFFF_FFFE)
    }

    /// [`refund_tx`](Self::refund_tx) with its input's nSequence: [`RBF_SEQUENCE`] makes it
    /// replaceable (the hub's ch2 refunds, AGP-044); any value below 0xFFFFFFFF keeps nLockTime.
    pub fn refund_tx_seq(&self, payer_secret: &SecretKey, dest_spk: Option<&[u8]>, fee: Option<u64>, sequence: u32) -> Result<Tx> {
        let fee = fee.unwrap_or(self.close_fee);
        let value = self.capacity.checked_sub(fee).ok_or_else(|| ChannelError::new("bad_amount", "refund fee exceeds the capacity"))?;
        let dest = dest_spk.map(<[u8]>::to_vec).unwrap_or_else(|| self.payer_spk.clone());
        let mut tx = Tx::new(2, vec![self.funding_in(sequence)?], vec![TxOut::new(value as i64, dest)], self.expiry);
        let mut sig = ecdsa::sign(payer_secret, &self.sighash(&tx)?);
        sig.push(SIGHASH_ALL_UNIFIED);
        tx.inputs[0].witness = vec![sig, Vec::new(), self.script()];
        Ok(tx)
    }

    /// Fee-input variant, signed 0xA3 so the payee can add fee inputs. SINGLE commits to output 0
    /// only, so output 0 is the payer's change; no change means no 0xA3 state (use 0x21).
    pub fn state_tx_a3(&self, amount: u64) -> Result<Tx> {
        self.check_amount(amount)?;
        let change = self.capacity - self.payer_fee() - amount;
        if change < DUST {
            return fail("bad_amount", "no payer change to commit to: sign a 0x21 state instead");
        }
        Ok(Tx::new(2, vec![self.funding_in(0xFFFF_FFFD)?],
                   vec![TxOut::new(change as i64, self.payer_spk.clone()),
                        TxOut::new(self.payee_value(amount) as i64, self.payee_spk.clone())], 0))
    }

    /// The next channel's capacity in a rollover paying `amount`: the payer's whole remainder
    /// after its share of the close fee.
    pub fn rollover_next_capacity(&self, amount: u64) -> u64 {
        self.capacity.saturating_sub(self.payer_fee()).saturating_sub(amount)
    }

    /// A close that pays the payee and funds the next channel from the payer's leftover.
    pub fn rollover_tx(&self, amount: u64, next_spk: &[u8], next_capacity: u64) -> Result<Tx> {
        self.check_amount(amount)?;
        if next_capacity < DUST {
            return fail("bad_amount", "next channel capacity below dust");
        }
        if next_capacity > self.capacity - amount {
            return fail("bad_amount", "next channel capacity above the payer's remainder");
        }
        Ok(Tx::new(2, vec![self.funding_in(0xFFFF_FFFD)?],
                   vec![TxOut::new(self.payee_value(amount) as i64, self.payee_spk.clone()),
                        TxOut::new(next_capacity as i64, next_spk.to_vec())], 0))
    }
}

/// The settlement threshold: the payee's net payout for `cum` is at least `multiple` × closeFee,
/// so a settlement's fee is at most 1/multiple of what it pays out.
pub fn settle_due(p: &ChannelParams, cum: u64, multiple: u64) -> bool {
    cum >= p.min_amount() && p.payee_value(cum) >= multiple.saturating_mul(p.close_fee)
}

/// `DER || hash_type`.
pub fn sign_with_type(sk: &SecretKey, msg: &[u8; 32], hash_type: u8) -> Vec<u8> {
    let mut s = ecdsa::sign(sk, msg);
    s.push(hash_type);
    s
}

/// Client side of one channel: signs ever-increasing cumulative amounts, either with the payer
/// key it holds or through a [`StateSigner`](crate::signer::StateSigner) that holds the key
/// (AGP-027: B2's signer process; the client then never sees the secret).
#[derive(Clone)]
pub struct Payer {
    pub params: ChannelParams,
    secret: Option<SecretKey>,
    backend: Option<std::sync::Arc<dyn crate::signer::StateSigner>>,
    /// Highest cumulative amount signed so far.
    pub signed: u64,
}

impl Drop for Payer {
    fn drop(&mut self) {
        if let Some(s) = &mut self.secret {
            s.non_secure_erase(); // AGP-080 K1: a payer key is wiped with the payer that held it
        }
    }
}

impl std::fmt::Debug for Payer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Payer").field("params", &self.params).field("signed", &self.signed)
            .field("key", &if self.backend.is_some() { "signer" } else { "local" }).finish()
    }
}

impl Payer {
    pub fn new(params: ChannelParams, secret: SecretKey) -> Result<Self> {
        if ecdsa::pubkey(&secret) != params.payer_pub {
            return fail("bad_key", "secret does not match payer_pub");
        }
        Ok(Self { params, secret: Some(secret), backend: None, signed: 0 })
    }

    /// A payer whose key lives in `backend` (the channel must already be attached there).
    pub fn with_backend(params: ChannelParams, backend: std::sync::Arc<dyn crate::signer::StateSigner>) -> Self {
        Self { params, secret: None, backend: Some(backend), signed: 0 }
    }

    /// The payer key, when this payer holds it (`None` with a signer backend).
    pub fn secret(&self) -> Option<&SecretKey> {
        self.secret.as_ref()
    }

    /// The signer backend, if the key lives in one.
    pub fn backend(&self) -> Option<&std::sync::Arc<dyn crate::signer::StateSigner>> {
        self.backend.as_ref()
    }

    fn key(&self) -> Result<&SecretKey> {
        self.secret.as_ref().ok_or_else(|| ChannelError::new("bad_key", "the payer key lives in a signer"))
    }

    /// The payer's 0x21 signature (DER || 0x21) for the state paying `amount`. Never lower.
    pub fn sign_state(&mut self, amount: u64) -> Result<Vec<u8>> {
        if amount < self.signed {
            return fail("stale_amount", "never sign a lower cumulative amount");
        }
        let sig = match &self.backend {
            Some(b) => b.sign_state(&self.params.channel_id(), amount)?,
            None => {
                let tx = self.params.state_tx(amount)?;
                sign_with_type(self.key()?, &self.params.sighash(&tx)?, SIGHASH_ALL_UNIFIED)
            }
        };
        self.signed = amount;
        Ok(sig)
    }

    /// The 0xA3 fee-input state signature for `amount`.
    pub fn sign_state_a3(&mut self, amount: u64) -> Result<Vec<u8>> {
        if amount < self.signed {
            return fail("stale_amount", "never sign a lower cumulative amount");
        }
        let sig = match &self.backend {
            Some(b) => b.sign_state_a3(&self.params.channel_id(), amount)?,
            None => {
                let tx = self.params.state_tx_a3(amount)?;
                sign_with_type(self.key()?, &self.params.sighash_a3(&tx)?, SIGHASH_SINGLE_ACP_UNIFIED)
            }
        };
        self.signed = amount;
        Ok(sig)
    }

    /// The payer's signature for a rollover tx (the provider co-signs and broadcasts it).
    pub fn sign_rollover(&mut self, amount: u64, next_spk: &[u8], next_capacity: u64) -> Result<Vec<u8>> {
        self.sign_rollover_to(amount, next_spk, None, next_capacity)
    }

    /// [`Payer::sign_rollover`] into the channel `next` (unfunded), so a signer backend can check
    /// the next channel is its own (AGP-063 W3).
    pub fn sign_rollover_next(&mut self, amount: u64, next: &ChannelParams, next_capacity: u64) -> Result<Vec<u8>> {
        self.sign_rollover_to(amount, &next.spk(), Some(next), next_capacity)
    }

    fn sign_rollover_to(&mut self, amount: u64, next_spk: &[u8], next: Option<&ChannelParams>, next_capacity: u64) -> Result<Vec<u8>> {
        if amount < self.signed {
            return fail("stale_amount", "never sign a lower cumulative amount");
        }
        let sig = match (&self.backend, next) {
            (Some(b), Some(n)) => b.sign_rollover_next(&self.params.channel_id(), amount, n, next_capacity)?,
            (Some(b), None) => b.sign_rollover(&self.params.channel_id(), amount, next_spk, next_capacity)?,
            (None, _) => {
                let tx = self.params.rollover_tx(amount, next_spk, next_capacity)?;
                sign_with_type(self.key()?, &self.params.sighash(&tx)?, SIGHASH_ALL_UNIFIED)
            }
        };
        self.signed = amount;
        Ok(sig)
    }

    /// The payer's close authorisation (DER over `close_message(chan)`).
    pub fn sign_close(&self) -> Result<Vec<u8>> {
        let chan = self.params.channel_id();
        match &self.backend {
            Some(b) => b.sign_close(&chan),
            None => Ok(ecdsa::sign(self.key()?, &crate::wire::close_message(&chan))),
        }
    }

    /// The 0x21 hash-locked state paying `uncond` plus `cond`'s amount.
    pub fn sign_conditional(&mut self, uncond: u64, cond: &crate::conditional::ConditionalParams) -> Result<Vec<u8>> {
        if uncond < self.signed {
            return fail("stale_amount", "never sign a lower cumulative amount");
        }
        let sig = match &self.backend {
            Some(b) => b.sign_conditional(&self.params.channel_id(), uncond, cond)?,
            None => {
                let tx = cond.state_tx(uncond)?;
                sign_with_type(self.key()?, &cond.sighash(&tx)?, SIGHASH_ALL_UNIFIED)
            }
        };
        self.signed = uncond;
        Ok(sig)
    }

    /// The signed CLTV refund. A signer backend decides the destination and fee itself.
    pub fn refund_tx(&self, dest_spk: Option<&[u8]>, fee: Option<u64>) -> Result<Tx> {
        match &self.backend {
            Some(b) => Tx::parse_hex(&b.sign_refund(&self.params.channel_id())?).map_err(ChannelError::from),
            None => self.params.refund_tx(self.key()?, dest_spk, fee),
        }
    }
}

/// Server side of one channel: verifies payer states, keeps the best one, closes.
#[derive(Debug, Clone)]
pub struct Payee {
    pub params: ChannelParams,
    secret: SecretKey,
    pub best_amount: u64,
    pub best_sig: Vec<u8>,
}

impl Payee {
    pub fn new(params: ChannelParams, secret: SecretKey) -> Result<Self> {
        if ecdsa::pubkey(&secret) != params.payee_pub {
            return fail("bad_key", "secret does not match payee_pub");
        }
        Ok(Self { params, secret, best_amount: 0, best_sig: Vec::new() })
    }

    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// Err unless `sig` is the payer's valid 0x21 signature for `amount`.
    pub fn verify_state(&self, amount: u64, sig: &[u8]) -> Result<()> {
        if sig.last() != Some(&SIGHASH_ALL_UNIFIED) {
            return fail("bad_sighash", "state signatures must be SIGHASH_ALL|UNIFIED (0x21)");
        }
        let tx = self.params.state_tx(amount)?;
        if !ecdsa::verify(&self.params.payer_pub, &self.params.sighash(&tx)?, &sig[..sig.len() - 1]) {
            return fail("bad_sig", "payer signature does not verify");
        }
        Ok(())
    }

    /// Verify and store a state; the newly paid delta (0 for a replay of the best state).
    pub fn accept(&mut self, amount: u64, sig: &[u8]) -> Result<u64> {
        if amount <= self.best_amount {
            if amount == self.best_amount && sig == self.best_sig.as_slice() {
                return Ok(0);
            }
            return fail("stale_amount", format!("have {}, got {amount}", self.best_amount));
        }
        self.verify_state(amount, sig)?;
        let delta = amount - self.best_amount;
        self.best_amount = amount;
        self.best_sig = sig.to_vec();
        Ok(delta)
    }

    /// Fully signed close for the best state.
    pub fn close_tx(&self) -> Result<Tx> {
        if self.best_sig.is_empty() {
            return fail("no_state", "nothing to close");
        }
        let mut tx = self.params.state_tx(self.best_amount)?;
        let mine = sign_with_type(&self.secret, &self.params.sighash(&tx)?, SIGHASH_ALL_UNIFIED);
        tx.inputs[0].witness = vec![self.best_sig.clone(), mine, vec![0x01], self.params.script()];
        Ok(tx)
    }

    /// Complete a 0xA3 state by adding a fee input (P2WPKH of `extra_secret`). Output 0 (the
    /// payer's change) stays exactly as signed.
    pub fn close_tx_with_fee_input(&self, extra_prev: TxOut, extra_in: TxIn, extra_secret: &SecretKey,
                                   extra_change: &[u8], extra_fee: u64, sig_a3: &[u8]) -> Result<Tx> {
        if sig_a3.last() != Some(&SIGHASH_SINGLE_ACP_UNIFIED) {
            return fail("bad_sighash", "fee-input variant needs SIGHASH_SINGLE|ACP|UNIFIED (0xA3)");
        }
        let mut tx = self.params.state_tx_a3(self.best_amount)?;
        tx.inputs.push(extra_in);
        let change = (extra_prev.value as i128) - extra_fee as i128;
        if change >= DUST as i128 {
            tx.outputs.push(TxOut::new(change as i64, extra_change.to_vec()));
        }
        let prevouts = [self.params.funding_prevout(), extra_prev];
        let h0 = unified_sighash(&tx, &prevouts, 0, ScriptType::WitnessV0, &self.params.script(), SIGHASH_ALL_UNIFIED, None)?;
        tx.inputs[0].witness = vec![sig_a3.to_vec(), sign_with_type(&self.secret, &h0, SIGHASH_ALL_UNIFIED), vec![0x01], self.params.script()];
        let pubk = ecdsa::pubkey(extra_secret);
        let h1 = unified_sighash(&tx, &prevouts, 1, ScriptType::WitnessV0, &p2wpkh_script_code(&pubk), SIGHASH_ALL_UNIFIED, None)?;
        tx.inputs[1].witness = vec![sign_with_type(extra_secret, &h1, SIGHASH_ALL_UNIFIED), pubk.to_vec()];
        Ok(tx)
    }
}

/// Sign input `index` as P2WPKH with 0x21 (CPFP child, extra fee input, sweep).
pub fn sign_p2wpkh(secret: &SecretKey, tx: &mut Tx, prevouts: &[TxOut], index: usize) -> Result<()> {
    let pubk = ecdsa::pubkey(secret);
    let h = unified_sighash(tx, prevouts, index, ScriptType::WitnessV0, &p2wpkh_script_code(&pubk), SIGHASH_ALL_UNIFIED, None)?;
    tx.inputs[index].witness = vec![sign_with_type(secret, &h, SIGHASH_ALL_UNIFIED), pubk.to_vec()];
    Ok(())
}

/// A child that spends the payee close output, bumping the parent (CPFP).
pub fn cpfp_child(close_txid: &str, vout: u32, value: u64, payee_spk: &[u8], payee_secret: &SecretKey, fee: u64) -> Result<Tx> {
    if value < fee + DUST {
        return fail("bad_amount", "CPFP fee leaves dust");
    }
    let op = OutPoint::from_display(close_txid, vout).map_err(|_| ChannelError::new("bad_request", "bad txid"))?;
    let mut tx = Tx::new(2, vec![TxIn::new(op, 0xFFFF_FFFD)], vec![TxOut::new((value - fee) as i64, payee_spk.to_vec())], 0);
    sign_p2wpkh(payee_secret, &mut tx, &[TxOut::new(value as i64, payee_spk.to_vec())], 0)?;
    Ok(tx)
}
