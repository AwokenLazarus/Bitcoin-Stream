//! Offline self-test (no network, no node): a Rust payer pays a Rust provider in process over a
//! mock chain: open, 10 postpay calls, a v1.2 payee-pays channel, cooperative closes, amounts
//! checked. Built for aarch64 to prove the crate links there:
//! `cargo build --release --target aarch64-unknown-linux-gnu -p xbt402 --example selftest`.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use xbt402::channel::FeePayer;
use xbt402::client::{split_url, Client, ClientConfig, Transport, Wallet};
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::{ChannelError, Result};
use xbt_primitives::address::address_to_spk;
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

const NET: &str = "bip122:11111111111111111111111111111111";

#[derive(Default)]
struct Chain {
    utxos: Mutex<HashMap<(String, u32), UtxoInfo>>,
    sent: Mutex<Vec<Tx>>,
}

impl ChainBackend for Chain {
    fn block_count(&self) -> Result<u32> {
        Ok(1_000)
    }
    fn get_tx_out(&self, txid: &str, vout: u32, _: bool) -> Result<Option<UtxoInfo>> {
        Ok(self.utxos.lock().unwrap().get(&(txid.to_string(), vout)).cloned())
    }
    fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        let tx = Tx::parse_hex(hex)?;
        self.sent.lock().unwrap().push(tx.clone());
        Ok(tx.txid())
    }
    fn has_transaction(&self, _: &str) -> Result<bool> {
        Ok(false)
    }
}

struct W(Arc<Chain>);
impl Wallet for W {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        let txid = hex::encode(sha256(address.as_bytes()));
        let spk = address_to_spk(address, None).map_err(|e| ChannelError::new("bad_address", e.to_string()))?;
        self.0.utxos.lock().unwrap().insert((txid.clone(), 0), UtxoInfo { confirmations: 1, value: sats, script_pubkey: spk, coinbase: false });
        Ok((txid, 0))
    }
}

struct Local(Arc<Provider>);
impl Transport for Local {
    fn request(&self, m: &str, url: &str, body: &[u8], h: &[(String, String)]) -> Result<HttpResponse> {
        Ok(self.0.serve(m, &split_url(url).1, h, body, url, None))
    }
}

fn run(fee_payer: FeePayer) -> Result<(i64, i64)> {
    let chain = Arc::new(Chain::default());
    let mut cfg = ProviderConfig::new(NET);
    cfg.close_fee_payer = fee_payer;
    let sk = SecretKey::from_slice(&sha256(b"selftest payTo")).expect("key");
    let prov = Arc::new(Provider::new(chain.clone(), sk, cfg, Ledger::in_memory(), Box::new(|_, _| 150),
                                      Box::new(|_, _, _| HttpResponse::new(200, vec![], b"ok".to_vec())))?);
    let c2 = chain.clone();
    let mut client = Client::new(ClientConfig::new(NET), Box::new(Local(prov)), Box::new(W(chain.clone())), Box::new(move || c2.block_count()));
    for _ in 0..10 {
        let r = client.request("GET", "https://p.example/v1/q", b"")?;
        if r.status != 200 {
            return Err(ChannelError::new("selftest", format!("HTTP {}", r.status)));
        }
    }
    client.close("https://p.example")?;
    let p = client.channels["https://p.example"].payer.params.clone();
    let close = chain.sent.lock().unwrap().last().cloned().ok_or_else(|| ChannelError::code("no close"))?;
    let to = |spk: &[u8]| close.outputs.iter().filter(|o| o.script_pubkey == spk).map(|o| o.value).sum::<i64>();
    Ok((to(&p.payee_spk), to(&p.payer_spk)))
}

fn main() {
    let v11 = run(FeePayer::Payer).expect("v1.1 channel");
    let v12 = run(FeePayer::Payee).expect("v1.2 channel");
    assert_eq!(v11, (1_500, 200_000 - 600 - 1_500), "payer-pays amounts");
    assert_eq!(v12, (1_500 - 600, 200_000 - 1_500), "payee-pays amounts");
    println!("xbt402 selftest OK ({}): payer-pays close {:?}, payee-pays close {:?}", std::env::consts::ARCH, v11, v12);
}
