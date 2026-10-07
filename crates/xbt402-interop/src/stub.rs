//! The stub node the reference vectors are generated against (B1 `check_vectors.StubNode`): fixed
//! answers for the four RPCs a provider's paid path uses.
use std::sync::Mutex;

use xbt402::channel::ChannelParams;
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt402::Result;
use xbt_primitives::tx::Tx;

pub struct StubNode {
    pub p: ChannelParams,
    pub tip: Mutex<u32>,
    pub sent: Mutex<Vec<String>>,
}

impl StubNode {
    pub fn new(p: ChannelParams, tip: u32) -> Self {
        Self { p, tip: Mutex::new(tip), sent: Mutex::new(Vec::new()) }
    }

    pub fn set_tip(&self, t: u32) {
        *self.tip.lock().unwrap() = t;
    }

    pub fn sent(&self) -> Vec<String> {
        self.sent.lock().unwrap().clone()
    }
}

impl ChainBackend for StubNode {
    fn block_count(&self) -> Result<u32> {
        Ok(*self.tip.lock().unwrap())
    }

    fn get_tx_out(&self, _txid: &str, _vout: u32, _mempool: bool) -> Result<Option<UtxoInfo>> {
        Ok(Some(UtxoInfo { confirmations: 1, value: self.p.capacity, script_pubkey: self.p.spk(), coinbase: false }))
    }

    fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        self.sent.lock().unwrap().push(hex.to_string());
        Ok(Tx::parse_hex(hex)?.txid())
    }

    fn has_transaction(&self, _txid: &str) -> Result<bool> {
        Ok(true)
    }
}
