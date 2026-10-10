//! AGP-067: review C1 (B1 `tests/security/test_agp067_review_c1.py`, same names). A close pays the
//! fixed closeFee agreed at open (600 sat, about 3 sat/vB); if fees spike through the close margin
//! and nothing bumps it, the payer's refund at expiry takes the whole channel back. The watcher
//! now bumps the close with a CPFP child from the provider's own close output.
//!
//! [`Pool`] is a node with a mempool: a floor (`minrelaytxfee`/`mempoolminfee`), full RBF with the
//! 1 sat/vB increment, `submitpackage` (a parent below the floor goes in on its child's fee), an
//! estimate the test sets, and blocks that take only packages at or above the market's feerate.
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use xbt402::channel::DUST;
use xbt402::client::{split_url, Client, ClientConfig, Transport, Wallet};
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig, CPFP_CHILD_VSIZE};
use xbt402::{ChannelError, Result};
use xbt_primitives::address::address_to_spk;
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

const NET: &str = "bip122:11111111111111111111111111111111";
const O: &str = "https://api.example";

#[derive(Default)]
struct PoolState {
    tip: u32,
    /// confirmed unspent outputs: value, spk, height
    utxos: HashMap<(String, u32), (u64, Vec<u8>, u32)>,
    confirmed: HashSet<String>,
    mempool: Vec<Tx>,
    floor: f64,
    estimate: Option<f64>,
    funded: u64,
}

#[derive(Default)]
struct Pool(Mutex<PoolState>);

fn err(m: impl Into<String>) -> ChannelError {
    ChannelError::new("rpc_error", m.into())
}

impl PoolState {
    fn value_of(&self, txid: &str, vout: u32) -> Option<u64> {
        if let Some((v, _, _)) = self.utxos.get(&(txid.to_string(), vout)) {
            return Some(*v);
        }
        self.mempool.iter().find(|t| t.txid() == txid).and_then(|t| t.outputs.get(vout as usize)).map(|o| o.value as u64)
    }
    fn fee(&self, tx: &Tx) -> Option<u64> {
        let ins: Option<u64> = tx.inputs.iter().map(|i| self.value_of(&i.prevout.txid_hex(), i.prevout.vout)).sum();
        ins?.checked_sub(tx.outputs.iter().map(|o| o.value as u64).sum())
    }
    fn children(&self, txid: &str) -> Vec<Tx> {
        self.mempool.iter().filter(|t| t.inputs.iter().any(|i| i.prevout.txid_hex() == txid)).cloned().collect()
    }
    /// The best feerate this tx confirms at: alone, or with all its children in the pool (CPFP).
    fn package_rate(&self, tx: &Tx) -> f64 {
        let own = self.fee(tx).unwrap_or(0) as f64 / tx.vsize() as f64;
        let kids = self.children(&tx.txid());
        let fee = self.fee(tx).unwrap_or(0) + kids.iter().map(|k| self.fee(k).unwrap_or(0)).sum::<u64>();
        let vs = tx.vsize() + kids.iter().map(Tx::vsize).sum::<usize>();
        own.max(fee as f64 / vs as f64)
    }
    fn remove_with_descendants(&mut self, txid: &str) {
        let kids: Vec<String> = self.children(txid).iter().map(Tx::txid).collect();
        self.mempool.retain(|t| t.txid() != txid);
        for k in kids {
            self.remove_with_descendants(&k);
        }
    }
    /// Mempool acceptance; `rate` is the package's feerate when it comes in a package.
    fn accept(&mut self, tx: &Tx, rate: Option<f64>) -> Result<()> {
        if self.mempool.iter().any(|t| t.txid() == tx.txid()) || self.confirmed.contains(&tx.txid()) {
            return Ok(());
        }
        let fee = self.fee(tx).ok_or_else(|| err("bad-txns-inputs-missingorspent"))?;
        let own = fee as f64 / tx.vsize() as f64;
        if rate.unwrap_or(own) < self.floor {
            return Err(err(format!("min relay fee not met ({own:.2} sat/vB < {})", self.floor)));
        }
        let conflicts: Vec<Tx> = self.mempool.iter()
            .filter(|t| t.inputs.iter().any(|i| tx.inputs.iter().any(|j| j.prevout == i.prevout))).cloned().collect();
        if !conflicts.is_empty() {
            let mut replaced = 0;
            for c in &conflicts {
                replaced += self.fee(c).unwrap_or(0) + self.children(&c.txid()).iter().map(|k| self.fee(k).unwrap_or(0)).sum::<u64>();
            }
            if fee < replaced + tx.vsize() as u64 {
                return Err(err("insufficient fee (BIP125 rule 4)"));
            }
            for c in conflicts {
                self.remove_with_descendants(&c.txid());
            }
        }
        self.mempool.push(tx.clone());
        Ok(())
    }
}

impl Pool {
    fn new() -> Arc<Self> {
        let p = Self::default();
        {
            let mut s = p.0.lock().unwrap();
            s.tip = 1_000;
            s.floor = 1.0;
        }
        Arc::new(p)
    }
    fn st(&self) -> std::sync::MutexGuard<'_, PoolState> {
        self.0.lock().unwrap()
    }
    /// A fee spike: the floor rises and what pays less leaves the mempool (a full node trimming,
    /// or a restart with a higher `minrelaytxfee`).
    fn set_floor(&self, f: f64) {
        let mut s = self.st();
        s.floor = f;
        let gone: Vec<String> = s.mempool.iter().filter(|t| s.package_rate(t) < f).map(Tx::txid).collect();
        for g in gone {
            s.remove_with_descendants(&g);
        }
    }
    /// One block of the packages paying `market` sat/vB or more (CPFP counted).
    fn mine(&self, market: f64) {
        let mut s = self.st();
        s.tip += 1;
        let h = s.tip;
        loop {
            let ready = s.mempool.iter().find(|t| {
                t.inputs.iter().all(|i| s.utxos.contains_key(&(i.prevout.txid_hex(), i.prevout.vout))) && s.package_rate(t) >= market
            }).cloned();
            let Some(tx) = ready else { break };
            s.mempool.retain(|t| t.txid() != tx.txid());
            for i in &tx.inputs {
                s.utxos.remove(&(i.prevout.txid_hex(), i.prevout.vout));
            }
            for (n, o) in tx.outputs.iter().enumerate() {
                s.utxos.insert((tx.txid(), n as u32), (o.value as u64, o.script_pubkey.clone(), h));
            }
            s.confirmed.insert(tx.txid());
        }
    }
    fn in_block(&self, txid: &str) -> bool {
        self.st().confirmed.contains(txid)
    }
    fn in_pool(&self, txid: &str) -> bool {
        self.st().mempool.iter().any(|t| t.txid() == txid)
    }
}

impl ChainBackend for Pool {
    fn block_count(&self) -> Result<u32> {
        Ok(self.st().tip)
    }
    fn get_tx_out(&self, txid: &str, vout: u32, mempool: bool) -> Result<Option<UtxoInfo>> {
        let s = self.st();
        let key = (txid.to_string(), vout);
        if mempool && s.mempool.iter().any(|t| t.inputs.iter().any(|i| i.prevout.txid_hex() == txid && i.prevout.vout == vout)) {
            return Ok(None);
        }
        if let Some((v, spk, h)) = s.utxos.get(&key) {
            return Ok(Some(UtxoInfo { confirmations: s.tip - h + 1, value: *v, script_pubkey: spk.clone(), coinbase: false }));
        }
        if !mempool {
            return Ok(None);
        }
        Ok(s.mempool.iter().find(|t| t.txid() == txid).and_then(|t| t.outputs.get(vout as usize))
            .map(|o| UtxoInfo { confirmations: 0, value: o.value as u64, script_pubkey: o.script_pubkey.clone(), coinbase: false }))
    }
    fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        let tx = Tx::parse_hex(hex)?;
        self.st().accept(&tx, None)?;
        Ok(tx.txid())
    }
    fn has_transaction(&self, txid: &str) -> Result<bool> {
        let s = self.st();
        Ok(s.confirmed.contains(txid) || s.mempool.iter().any(|t| t.txid() == txid))
    }
    fn estimate_fee_rate(&self, _target: u32) -> Result<Option<f64>> {
        Ok(self.st().estimate)
    }
    fn mempool_min_fee(&self) -> Result<Option<f64>> {
        Ok(Some(self.st().floor))
    }
    fn submit_package(&self, hexes: &[String]) -> Result<()> {
        let txs = hexes.iter().map(|h| Tx::parse_hex(h).map_err(ChannelError::from)).collect::<Result<Vec<_>>>()?;
        let mut s = self.st();
        let (parent, child) = (&txs[0], &txs[1]);
        if s.mempool.iter().any(|t| t.txid() == parent.txid()) {
            return s.accept(child, None);
        }
        // the child's input is the parent's output, not in the pool yet: the package's fee
        let pf = s.fee(parent).ok_or_else(|| err("package: parent inputs missing"))?;
        let cf = parent.outputs.get(child.inputs[0].prevout.vout as usize).map(|o| o.value as u64)
            .and_then(|v| v.checked_sub(child.outputs.iter().map(|o| o.value as u64).sum())).ok_or_else(|| err("package: not a child"))?;
        let rate = (pf + cf) as f64 / (parent.vsize() + child.vsize()) as f64;
        s.accept(parent, Some(rate))?;
        s.accept(child, None).inspect_err(|_| s.remove_with_descendants(&parent.txid()))
    }
}

struct PoolWallet(Arc<Pool>);

impl Wallet for PoolWallet {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        let mut s = self.0.st();
        s.funded += 1;
        let txid = hex::encode(sha256(format!("funding {}", s.funded).as_bytes()));
        let spk = address_to_spk(address, None).map_err(|e| ChannelError::new("bad_address", e.to_string()))?;
        let h = s.tip;
        s.utxos.insert((txid.clone(), 0), (sats, spk, h));
        s.confirmed.insert(txid.clone());
        Ok((txid, 0))
    }
}

struct Local(Arc<Provider>);

impl Transport for Local {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        let (_, path) = split_url(url);
        Ok(self.0.serve(method, &path, headers, body, url, None))
    }
}

fn provider(pool: &Arc<Pool>, cfg: ProviderConfig, price: u64) -> Arc<Provider> {
    let key = SecretKey::from_slice(&sha256(b"provider payTo")).unwrap();
    Arc::new(Provider::new(pool.clone(), key, cfg, Ledger::in_memory(), Box::new(move |_, _| price),
                           Box::new(|_, p, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())],
                                                                  json!({"answer": p}).to_string().into_bytes()))).unwrap())
}

/// A channel with `calls` paid calls at `price` sat; returns (client, channel id, expiry).
fn channel(pool: &Arc<Pool>, prov: &Arc<Provider>, calls: usize) -> (Client, String, u32) {
    let p2 = pool.clone();
    let mut c = Client::new(ClientConfig::new(NET), Box::new(Local(prov.clone())), Box::new(PoolWallet(pool.clone())),
                            Box::new(move || p2.block_count()));
    for _ in 0..calls {
        assert_eq!(c.request("GET", &format!("{O}/v1/q"), b"").unwrap().status, 200);
    }
    let p = c.channels[O].payer.params.clone();
    (c, p.channel_id(), p.expiry)
}

fn cfg(max_fee: u64) -> ProviderConfig {
    let mut c = ProviderConfig::new(NET);
    c.close_bump_max_fee = max_fee;
    c
}

fn bump(prov: &Provider, chan: &str) -> Value {
    prov.channel_state(chan).unwrap().extra.get("close_bump").cloned().unwrap_or(Value::Null)
}

fn funding_spent_in_a_block(pool: &Pool, chan: &str) -> bool {
    let (txid, vout) = chan.split_once(':').unwrap();
    pool.get_tx_out(txid, vout.parse().unwrap(), false).unwrap().is_none()
}

/// The watcher every block from the close margin to expiry, blocks at `market`; the height the
/// funding was spent in a block, if before expiry.
fn run_to_expiry(pool: &Pool, prov: &Provider, chan: &str, expiry: u32, market: f64) -> Option<u32> {
    pool.st().tip = expiry - prov.cfg.close_margin;
    while pool.st().tip < expiry {
        let _ = prov.close_due();
        pool.mine(market);
        if funding_spent_in_a_block(pool, chan) {
            return Some(pool.st().tip);
        }
    }
    None
}

#[test]
fn c1_a_close_below_the_mempool_floor_goes_in_with_a_child() {
    let pool = Pool::new();
    let prov = provider(&pool, cfg(10_000), 1_000);
    let (_c, chan, expiry) = channel(&pool, &prov, 20);
    pool.set_floor(10.0);
    let at = run_to_expiry(&pool, &prov, &chan, expiry, 10.0).expect("the close confirmed before expiry");
    assert_eq!(at, expiry - prov.cfg.close_margin + 1, "in the first block after the margin close");
    let st = prov.channel_state(&chan).unwrap();
    assert!(pool.in_block(&st.closed_txid));
    let b = bump(&prov, &chan);
    assert!(pool.in_block(b["txid"].as_str().unwrap()), "{b}");
    let close = Tx::parse_hex(st.extra["close_hex"].as_str().unwrap()).unwrap();
    let rate = (600 + b["fee"].as_u64().unwrap()) as f64 / (close.vsize() as u64 + CPFP_CHILD_VSIZE) as f64;
    assert!((10.0..10.1).contains(&rate), "the package pays the floor, no more: {rate} {b}");
}

#[test]
fn c1_without_the_bump_the_close_never_confirms() {
    // main's behaviour (close_bump_max_fee 0): the close only rebroadcasts, the node refuses it
    // through the whole margin, and at expiry the payer's refund is valid on an unspent funding
    let pool = Pool::new();
    let prov = provider(&pool, cfg(0), 1_000);
    let (c, chan, expiry) = channel(&pool, &prov, 20);
    pool.set_floor(10.0);
    assert_eq!(run_to_expiry(&pool, &prov, &chan, expiry, 10.0), None);
    assert!(!funding_spent_in_a_block(&pool, &chan));
    assert!(prov.channel_state(&chan).unwrap().close_error.contains("min relay fee"));
    // the refund at expiry, re-signed at the market's rate by the payer, takes the channel back
    let refund = Tx::parse_hex(&c.channels[O].refund_hex).unwrap();
    assert_eq!(refund.locktime, expiry);
}

#[test]
fn c1_the_bump_follows_the_estimate_and_escalates_near_expiry() {
    let pool = Pool::new();
    let prov = provider(&pool, cfg(50_000), 1_000);
    let (_c, chan, expiry) = channel(&pool, &prov, 40);
    // the close goes in alone at the margin; the market moves to 50 sat/vB, the estimate says 5
    pool.st().estimate = Some(5.0);
    let at = run_to_expiry(&pool, &prov, &chan, expiry, 50.0).expect("the close confirmed before expiry");
    let b = bump(&prov, &chan);
    let half = expiry - prov.cfg.close_margin / 2;
    assert!((half + 1..half + 20).contains(&at), "doubled from the estimate every close_bump_blocks in the margin's second half: at {at}, {b}");
    assert!(b["rate"].as_f64().unwrap() >= 50.0 && !b["replaced"].as_array().unwrap().is_empty(), "{b}");
    assert!(pool.in_block(b["txid"].as_str().unwrap()));
}

#[test]
fn c1_the_child_never_pays_more_than_the_cap_or_the_output() {
    // the cap: the estimate wants 40 sat/vB, the operator allows 2,000 sat
    let pool = Pool::new();
    let prov = provider(&pool, cfg(2_000), 1_000);
    let (_c, chan, expiry) = channel(&pool, &prov, 20);
    pool.set_floor(5.0);
    pool.st().estimate = Some(40.0);
    pool.st().tip = expiry - prov.cfg.close_margin;
    assert_eq!(prov.close_due().unwrap().len(), 1);
    let b = bump(&prov, &chan);
    assert_eq!((b["fee"].as_u64(), b["capped"].as_bool()), (Some(2_000), Some(true)), "{b}");
    assert!(pool.in_pool(b["txid"].as_str().unwrap()));
    // the output: a small channel's close output (here 1,546 sat) is all the child can spend
    let pool = Pool::new();
    let prov = provider(&pool, cfg(1_000_000), 1_000);
    let (_c, chan, expiry) = channel(&pool, &prov, 2);
    pool.st().estimate = Some(400.0);
    pool.st().tip = expiry - prov.cfg.close_margin;
    // the close goes in alone (the floor is 1 sat/vB); the next look bumps it
    assert_eq!(prov.close_due().unwrap().len(), 1);
    prov.close_due().unwrap();
    let st = prov.channel_state(&chan).unwrap();
    let close = Tx::parse_hex(st.extra["close_hex"].as_str().unwrap()).unwrap();
    let value = close.outputs.iter().find(|o| o.script_pubkey == st.params.payee_spk).unwrap().value as u64;
    let b = bump(&prov, &chan);
    assert_eq!((b["fee"].as_u64(), b["capped"].as_bool()), (Some(value - DUST), Some(true)), "{b}");
}

#[test]
fn c1_the_payee_sweep_spends_the_child_after_a_bump() {
    let pool = Pool::new();
    let prov = provider(&pool, cfg(10_000), 1_000);
    let (_c, chan, expiry) = channel(&pool, &prov, 20);
    pool.set_floor(10.0);
    run_to_expiry(&pool, &prov, &chan, expiry, 10.0).unwrap();
    let b = bump(&prov, &chan);
    let dest = [vec![0u8, 20], vec![7u8; 20]].concat();
    let r = prov.sweep_payee(&chan, &dest, 2_000).unwrap();
    assert_eq!(r["outpoint"], format!("{}:0", b["txid"].as_str().unwrap()), "{r}");
    let st = prov.channel_state(&chan).unwrap();
    let close = Tx::parse_hex(st.extra["close_hex"].as_str().unwrap()).unwrap();
    let paid = close.outputs.iter().find(|o| o.script_pubkey == st.params.payee_spk).unwrap().value as u64;
    assert_eq!(r["value"].as_u64(), Some(paid - b["fee"].as_u64().unwrap()));
    assert!(pool.in_pool(r["txid"].as_str().unwrap()));
}

#[test]
fn c1_a_close_that_pays_enough_is_left_alone() {
    let pool = Pool::new();
    let prov = provider(&pool, cfg(10_000), 1_000);
    let (_c, chan, expiry) = channel(&pool, &prov, 20);
    assert!(run_to_expiry(&pool, &prov, &chan, expiry, 1.0).is_some());
    let b = bump(&prov, &chan);
    assert!(b["txid"].is_null(), "no child for a close the market takes: {b}");
}
