//! Transactions with segwit witnesses: (de)serialization, txid, vsize.
use crate::encode::{write_varbytes, write_varint, Reader};
use crate::error::{Error, Result};
use crate::hash::{display_hex, dsha256, from_display_hex};

/// A transaction output reference. `txid` is in internal (serialized) byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

impl OutPoint {
    pub fn new(txid: [u8; 32], vout: u32) -> Self {
        Self { txid, vout }
    }

    /// From a displayed txid (the hex bitcoind prints).
    pub fn from_display(txid_hex: &str, vout: u32) -> Result<Self> {
        Ok(Self { txid: from_display_hex(txid_hex)?, vout })
    }

    /// The displayed txid.
    pub fn txid_hex(&self) -> String {
        display_hex(&self.txid)
    }

    /// 36 bytes: txid || LE32(vout).
    pub fn serialize(&self) -> [u8; 36] {
        let mut b = [0u8; 36];
        b[..32].copy_from_slice(&self.txid);
        b[32..].copy_from_slice(&self.vout.to_le_bytes());
        b
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    pub prevout: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

impl TxIn {
    /// An unsigned input (empty scriptSig and witness).
    pub fn new(prevout: OutPoint, sequence: u32) -> Self {
        Self { prevout, script_sig: Vec::new(), sequence, witness: Vec::new() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    /// Satoshis. Signed on the wire, as in Bitcoin.
    pub value: i64,
    pub script_pubkey: Vec<u8>,
}

impl TxOut {
    pub fn new(value: i64, script_pubkey: Vec<u8>) -> Self {
        Self { value, script_pubkey }
    }

    pub fn serialize_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.value.to_le_bytes());
        write_varbytes(out, &self.script_pubkey);
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(9 + self.script_pubkey.len());
        self.serialize_into(&mut v);
        v
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tx {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
}

impl Default for Tx {
    fn default() -> Self {
        Self { version: 2, inputs: Vec::new(), outputs: Vec::new(), locktime: 0 }
    }
}

impl Tx {
    pub fn new(version: i32, inputs: Vec<TxIn>, outputs: Vec<TxOut>, locktime: u32) -> Self {
        Self { version, inputs, outputs, locktime }
    }

    fn has_witness(&self) -> bool {
        self.inputs.iter().any(|i| !i.witness.is_empty())
    }

    /// BIP144 serialization; the marker and flag only when some input has a witness.
    pub fn serialize_with(&self, with_witness: bool) -> Vec<u8> {
        let seg = with_witness && self.has_witness();
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&self.version.to_le_bytes());
        if seg {
            out.extend_from_slice(&[0x00, 0x01]);
        }
        write_varint(&mut out, self.inputs.len() as u64);
        for i in &self.inputs {
            out.extend_from_slice(&i.prevout.serialize());
            write_varbytes(&mut out, &i.script_sig);
            out.extend_from_slice(&i.sequence.to_le_bytes());
        }
        write_varint(&mut out, self.outputs.len() as u64);
        for o in &self.outputs {
            o.serialize_into(&mut out);
        }
        if seg {
            for i in &self.inputs {
                write_varint(&mut out, i.witness.len() as u64);
                for w in &i.witness {
                    write_varbytes(&mut out, w);
                }
            }
        }
        out.extend_from_slice(&self.locktime.to_le_bytes());
        out
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.serialize_with(true)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.serialize())
    }

    /// The txid in internal byte order.
    pub fn txid_bytes(&self) -> [u8; 32] {
        dsha256(&self.serialize_with(false))
    }

    /// The displayed txid.
    pub fn txid(&self) -> String {
        display_hex(&self.txid_bytes())
    }

    pub fn vsize(&self) -> usize {
        let base = self.serialize_with(false).len();
        let total = self.serialize_with(true).len();
        (base * 3 + total).div_ceil(4)
    }

    /// Parse a whole transaction; trailing bytes are an error. Every count and length is checked
    /// against the bytes left, so a hostile encoding cannot make this allocate beyond its input.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let mut r = Reader::new(raw);
        let version = r.i32_le()?;
        let mut n_in = r.varint()?;
        let mut seg = false;
        if n_in == 0 {
            let flag = r.u8()?;
            if flag != 1 {
                return Err(Error::BadTx("segwit flag must be 0x01"));
            }
            seg = true;
            n_in = r.varint()?;
        }
        // an input is at least 41 bytes
        if n_in > (r.remaining() / 41) as u64 {
            return Err(Error::BadTx("input count exceeds the data"));
        }
        let mut inputs = Vec::with_capacity(n_in as usize);
        for _ in 0..n_in {
            let txid = r.array::<32>()?;
            let vout = r.u32_le()?;
            let script_sig = r.varbytes()?.to_vec();
            let sequence = r.u32_le()?;
            inputs.push(TxIn { prevout: OutPoint { txid, vout }, script_sig, sequence, witness: Vec::new() });
        }
        let n_out = r.varint()?;
        if n_out > (r.remaining() / 9) as u64 {
            return Err(Error::BadTx("output count exceeds the data"));
        }
        let mut outputs = Vec::with_capacity(n_out as usize);
        for _ in 0..n_out {
            let value = r.i64_le()?;
            outputs.push(TxOut { value, script_pubkey: r.varbytes()?.to_vec() });
        }
        if seg {
            for i in inputs.iter_mut() {
                let n = r.len_prefix()?;
                let mut w = Vec::with_capacity(n);
                for _ in 0..n {
                    w.push(r.varbytes()?.to_vec());
                }
                i.witness = w;
            }
            if inputs.iter().all(|i| i.witness.is_empty()) {
                return Err(Error::BadTx("segwit marker with no witness"));
            }
        }
        let locktime = r.u32_le()?;
        r.finish()?;
        Ok(Tx { version, inputs, outputs, locktime })
    }

    pub fn parse_hex(s: &str) -> Result<Self> {
        Self::parse(&hex::decode(s).map_err(|e| Error::BadHex(e.to_string()))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_segwit_and_legacy() {
        let mut tx = Tx::new(2, vec![TxIn::new(OutPoint::new([7; 32], 1), 0xFFFF_FFFD)],
                             vec![TxOut::new(1000, vec![0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20])], 0);
        let legacy = tx.serialize();
        assert_eq!(Tx::parse(&legacy).unwrap(), tx);
        tx.inputs[0].witness = vec![vec![1, 2, 3], vec![]];
        let seg = tx.serialize();
        assert_eq!(Tx::parse(&seg).unwrap(), tx);
        assert_eq!(tx.txid_bytes(), dsha256(&legacy));
        assert!(tx.vsize() < seg.len());
    }

    #[test]
    fn hostile_input_is_refused() {
        assert!(Tx::parse(&[]).is_err());
        assert!(Tx::parse(&[2, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).is_err());
        let tx = Tx::new(2, vec![], vec![], 0);
        let mut raw = tx.serialize();
        raw.push(0);
        assert!(Tx::parse(&raw).is_err());
    }
}
