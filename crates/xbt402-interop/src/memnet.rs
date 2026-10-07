//! An in-process routing world for tests (B1 `tests/security/routehelp.py`): a fake chain
//! ([`MemChain`]: the node calls, the watcher's spend scan and a wallet) and an in-process HTTP
//! network ([`MemNet`]: origin → service, with answers that can be dropped after serving). No
//! sockets, no node.
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use xbt402::client::{Transport, Wallet, WalletSend};
use xbt402::error::{ChannelError, Result};
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt402::http::HttpService;
use xbt402::provider::HttpResponse;
use xbt402::route::SpendScan;
use xbt_primitives::address::address_to_spk;
use xbt_primitives::tx::Tx;

#[derive(Default)]
struct ChainState {
    height: u32,
    utxos: HashMap<(String, u32), UtxoInfo>,
    spent: HashMap<(String, u32), String>,
    /// Spends that are in a block (the rest are in the mempool).
    mined: HashSet<(String, u32)>,
    raw: HashMap<String, String>,
    /// `estimatesmartfee`, sat/vB (None: no estimate).
    fee_rate: Option<f64>,
    /// Fee and vsize of each broadcast tx (its inputs were known when it came in).
    fees: HashMap<String, (u64, u64)>,
    /// Blocks take only txs paying at least this, sat/vB (a fee market; 0: everything).
    block_min_feerate: f64,
    /// Txs in the mempool whose outputs `gettxout` does not show (`hide_outputs`).
    hidden: HashSet<String>,
    /// The wallet's sends (AGP-045), remembered after they leave the mempool, in send order.
    wallet: Vec<WalletTx>,
}

#[derive(Clone)]
struct WalletTx {
    address: String,
    txid: String,
    vout: u32,
    sats: u64,
    spk: Vec<u8>,
    abandoned: bool,
    conflicted: bool,
}

/// A fake node: fundings appear with 6 confirmations, broadcasts spend their inputs (a conflicting
/// spend is refused unless it replaces a mempool spend by BIP125: the old one signals, the new one
/// pays its fee + 1 sat/vB more; a tx not final at the tip is refused too) and create unconfirmed
/// outputs; `confirm_all` confirms everything paying the block min feerate. `gettxout` without the
/// mempool still shows an output spent only in the mempool, as a node does. It is also the fund
/// wallet (AGP-045): every `fund` is a wallet send (`wallet_sends_to`, `wallet_send`), remembered
/// after it leaves the mempool; `abandon` / `conflict` mark one that can never confirm.
pub struct MemChain {
    st: Mutex<ChainState>,
}

impl MemChain {
    pub fn new(height: u32) -> Arc<Self> {
        Arc::new(Self { st: Mutex::new(ChainState { height, ..Default::default() }) })
    }

    fn st(&self) -> std::sync::MutexGuard<'_, ChainState> {
        self.st.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn height(&self) -> u32 {
        self.st().height
    }

    pub fn set_height(&self, h: u32) {
        self.st().height = h;
    }

    pub fn confirm_all(&self) {
        let mut st = self.st();
        let min = st.block_min_feerate;
        let held: HashSet<String> = st.fees.iter().filter(|(_, (f, v))| (*f as f64) < min * *v as f64).map(|(t, _)| t.clone()).collect();
        for (k, u) in st.utxos.iter_mut() {
            if !held.contains(&k.0) {
                u.confirmations = u.confirmations.max(1);
            }
        }
        let spent: Vec<_> = st.spent.iter().filter(|(_, s)| !held.contains(*s)).map(|(k, _)| k.clone()).collect();
        st.mined.extend(spent);
    }

    /// Blocks take only txs paying at least `sat_per_vb` (the rest wait in the mempool).
    pub fn set_block_min_feerate(&self, sat_per_vb: f64) {
        self.st().block_min_feerate = sat_per_vb;
    }

    /// (fee, vsize) of a broadcast tx.
    pub fn fee_of(&self, txid: &str) -> Option<(u64, u64)> {
        self.st().fees.get(txid).copied()
    }

    /// Whether `txid`'s outputs are in a block.
    pub fn confirmed(&self, txid: &str) -> bool {
        self.st().utxos.iter().any(|(k, u)| k.0 == txid && u.confirmations >= 1)
    }

    /// `n` blocks: every mempool tx and spend confirms.
    pub fn mine(&self, n: u32) {
        self.st().height += n;
        self.confirm_all();
    }

    /// A mempool tx leaves the mempool (expired, or replaced by what the caller broadcasts next).
    pub fn evict(&self, txid: &str) {
        let mut st = self.st();
        st.spent.retain(|_, s| s != txid);
        st.utxos.retain(|k, _| k.0 != txid);
        st.raw.remove(txid);
    }

    /// The block with `txid` is reorged out (AGP-053): the tx is back in the mempool, its outputs
    /// unconfirmed and its inputs unspent in blocks again.
    pub fn unconfirm(&self, txid: &str) {
        let mut st = self.st();
        for (k, u) in st.utxos.iter_mut() {
            if k.0 == txid {
                u.confirmations = 0;
            }
        }
        let spends: Vec<_> = st.spent.iter().filter(|(_, s)| *s == txid).map(|(k, _)| k.clone()).collect();
        for k in spends {
            st.mined.remove(&k);
        }
    }

    /// The spender of an outpoint, if any.
    pub fn spender(&self, txid: &str, vout: u32) -> Option<String> {
        self.st().spent.get(&(txid.to_string(), vout)).cloned()
    }

    pub fn set_fee_rate(&self, sat_per_vb: Option<f64>) {
        self.st().fee_rate = sat_per_vb;
    }

    pub fn raw(&self, txid: &str) -> Option<Tx> {
        self.st().raw.get(txid).and_then(|h| Tx::parse_hex(h).ok())
    }

    /// A wallet send of `sats` to `address` with `confirmations` (0: in the mempool).
    pub fn fund_with(&self, address: &str, sats: u64, confirmations: u32) -> Result<(String, u32)> {
        let spk = address_to_spk(address, Some("bcrt")).map_err(|e| ChannelError::new("bad_address", e.to_string()))?;
        let txid = rand_txid();
        let mut st = self.st();
        st.utxos.insert((txid.clone(), 0), UtxoInfo { confirmations, value: sats, script_pubkey: spk.clone(), coinbase: false });
        st.wallet.push(WalletTx { address: address.into(), txid: txid.clone(), vout: 0, sats, spk, abandoned: false, conflicted: false });
        Ok((txid, 0))
    }

    /// The wallet rebroadcasts an evicted send and it confirms.
    pub fn confirm_late(&self, txid: &str) {
        let mut st = self.st();
        if let Some(w) = st.wallet.iter().find(|w| w.txid == txid).cloned() {
            st.utxos.insert((w.txid, w.vout), UtxoInfo { confirmations: 1, value: w.sats, script_pubkey: w.spk, coinbase: false });
        }
    }

    /// The wallet gives up on a send that left the mempool (`abandontransaction`).
    pub fn abandon(&self, txid: &str) {
        self.evict(txid);
        self.st().wallet.iter_mut().filter(|w| w.txid == txid).for_each(|w| w.abandoned = true);
    }

    /// A send double-spent by a confirmed tx (`gettransaction` confirmations -1).
    pub fn conflict(&self, txid: &str) {
        self.evict(txid);
        self.st().wallet.iter_mut().filter(|w| w.txid == txid).for_each(|w| w.conflicted = true);
    }

    /// Hide a tx's outputs from `gettxout` while it stays in the mempool (an output a node does not
    /// show: only `getmempoolentry` sees the tx).
    pub fn hide_outputs(&self, txid: &str) {
        let mut st = self.st();
        st.utxos.retain(|k, _| k.0 != txid);
        st.hidden.insert(txid.to_string());
    }
}

fn rand_txid() -> String {
    let mut b = [0u8; 32];
    getrandom_fill(&mut b);
    hex::encode(b)
}

fn getrandom_fill(b: &mut [u8]) {
    // std-only randomness for test txids: hash a counter with the address of a stack value and time
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let h = xbt_primitives::hash::sha256(format!("{n}/{t}/{:p}", &n).as_bytes());
    b.copy_from_slice(&h[..b.len()]);
}

impl ChainBackend for MemChain {
    fn block_count(&self) -> Result<u32> {
        Ok(self.height())
    }

    fn get_tx_out(&self, txid: &str, vout: u32, mempool: bool) -> Result<Option<UtxoInfo>> {
        let st = self.st();
        let k = (txid.to_string(), vout);
        if st.spent.contains_key(&k) && (mempool || st.mined.contains(&k)) {
            return Ok(None);
        }
        Ok(st.utxos.get(&k).cloned())
    }

    fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        let tx = Tx::parse_hex(hex)?;
        let txid = tx.txid();
        let st = self.st();
        if st.raw.contains_key(&txid) {
            return Ok(txid);
        }
        if tx.locktime > st.height && tx.locktime < 500_000_000 {
            return Err(ChannelError::new("rpc_error", "non-final"));
        }
        let ins: u64 = tx.inputs.iter().map(|i| st.utxos.get(&(i.prevout.txid_hex(), i.prevout.vout)).map(|u| u.value).unwrap_or(0)).sum();
        let outs: u64 = tx.outputs.iter().map(|o| o.value as u64).sum();
        let (fee, vsize) = (ins.saturating_sub(outs), tx.vsize() as u64);
        let mut replaced = vec![];
        for i in &tx.inputs {
            let k = (i.prevout.txid_hex(), i.prevout.vout);
            let Some(old) = st.spent.get(&k).filter(|s| **s != txid).cloned() else { continue };
            let signals = st.raw.get(&old).and_then(|h| Tx::parse_hex(h).ok()).is_some_and(|o| o.inputs.iter().any(|i| i.sequence < 0xFFFF_FFFE));
            let old_fee = st.fees.get(&old).map(|f| f.0).unwrap_or(u64::MAX);
            if st.mined.contains(&k) || !signals || fee < old_fee.saturating_add(vsize) {
                return Err(ChannelError::new("rpc_error", "txn-mempool-conflict"));
            }
            replaced.push(old);
        }
        drop(st);
        for old in replaced {
            self.evict(&old);
        }
        let mut st = self.st();
        st.fees.insert(txid.clone(), (fee, vsize));
        for i in &tx.inputs {
            st.spent.insert((i.prevout.txid_hex(), i.prevout.vout), txid.clone());
        }
        for (n, o) in tx.outputs.iter().enumerate() {
            st.utxos.insert((txid.clone(), n as u32), UtxoInfo { confirmations: 0, value: o.value as u64, script_pubkey: o.script_pubkey.clone(), coinbase: false });
        }
        st.raw.insert(txid.clone(), hex.to_string());
        Ok(txid)
    }

    fn has_transaction(&self, txid: &str) -> Result<bool> {
        Ok(self.st().raw.contains_key(txid))
    }
}

impl SpendScan for MemChain {
    fn find_spend(&self, txid: &str, vout: u32, _from: u32) -> Result<Option<Tx>> {
        let st = self.st();
        Ok(st.spent.get(&(txid.to_string(), vout)).and_then(|s| st.raw.get(s)).and_then(|h| Tx::parse_hex(h).ok()))
    }

    fn scan_spk(&self, spk: &[u8]) -> Result<Vec<(String, u32, u64)>> {
        let st = self.st();
        Ok(st.utxos.iter().filter(|(k, u)| u.script_pubkey == spk && u.confirmations >= 1 && !st.spent.contains_key(*k))
            .map(|(k, u)| (k.0.clone(), k.1, u.value)).collect())
    }

    fn fee_rate(&self, _target: u32) -> Result<Option<f64>> {
        Ok(self.st().fee_rate)
    }

    fn in_mempool(&self, txid: &str) -> Result<bool> {
        let st = self.st();
        Ok(st.hidden.contains(txid) || st.utxos.iter().any(|(k, u)| k.0 == txid && u.confirmations == 0))
    }
}

impl Wallet for MemChain {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        self.fund_with(address, sats, 6)
    }

    fn wallet_sends_to(&self, address: &str) -> Result<Vec<String>> {
        Ok(self.st().wallet.iter().filter(|w| w.address == address).map(|w| w.txid.clone()).collect())
    }

    fn wallet_send(&self, txid: &str, address: &str) -> Result<Option<WalletSend>> {
        let st = self.st();
        Ok(st.wallet.iter().find(|w| w.txid == txid && w.address == address).map(|w| {
            let conf = st.utxos.get(&(w.txid.clone(), w.vout)).map(|u| u.confirmations as i64).unwrap_or(0);
            WalletSend { txid: w.txid.clone(), vout: w.vout, sats: w.sats, confirmations: if w.conflicted { -1 } else { conf },
                         abandoned: w.abandoned }
        }))
    }
}

/// The hub's own node while it lags the provider's (AGP-056): with `lag(true)`, every tx broadcast
/// since is still on its way over P2P, so this view shows neither it nor what it spends (the
/// [`MemChain`] behind, the provider's node, has it). Blocks reach it at once.
pub struct LagChain {
    pub chain: Arc<MemChain>,
    known: Mutex<Option<HashSet<String>>>,
}

impl LagChain {
    pub fn new(chain: Arc<MemChain>) -> Arc<Self> {
        Arc::new(Self { chain, known: Mutex::new(None) })
    }

    pub fn lag(&self, on: bool) {
        let known = on.then(|| self.chain.st().raw.keys().cloned().collect());
        *self.known.lock().unwrap() = known;
    }

    fn hidden(&self, txid: &str) -> bool {
        let known = self.known.lock().unwrap();
        let Some(k) = known.as_ref() else { return false };
        let st = self.chain.st();
        st.raw.contains_key(txid) && !k.contains(txid) && st.utxos.iter().any(|(o, u)| o.0 == txid && u.confirmations == 0)
    }
}

impl ChainBackend for LagChain {
    fn block_count(&self) -> Result<u32> {
        self.chain.block_count()
    }

    fn get_tx_out(&self, txid: &str, vout: u32, mempool: bool) -> Result<Option<UtxoInfo>> {
        if self.hidden(txid) {
            return Ok(None);
        }
        let spender = self.chain.st().spent.get(&(txid.to_string(), vout)).cloned();
        if mempool && spender.is_some_and(|s| self.hidden(&s)) {
            return Ok(self.chain.st().utxos.get(&(txid.to_string(), vout)).cloned());
        }
        self.chain.get_tx_out(txid, vout, mempool)
    }

    fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        self.chain.send_raw_transaction(hex)
    }

    fn has_transaction(&self, txid: &str) -> Result<bool> {
        Ok(!self.hidden(txid) && self.chain.has_transaction(txid)?)
    }
}

impl SpendScan for LagChain {
    fn find_spend(&self, txid: &str, vout: u32, from: u32) -> Result<Option<Tx>> {
        Ok(self.chain.find_spend(txid, vout, from)?.filter(|t| !self.hidden(&t.txid())))
    }

    fn scan_spk(&self, spk: &[u8]) -> Result<Vec<(String, u32, u64)>> {
        self.chain.scan_spk(spk)
    }

    fn fee_rate(&self, target: u32) -> Result<Option<f64>> {
        self.chain.fee_rate(target)
    }

    fn in_mempool(&self, txid: &str) -> Result<bool> {
        Ok(!self.hidden(txid) && self.chain.in_mempool(txid)?)
    }
}

/// A shared chain as a boxed wallet.
pub struct ChainWallet(pub Arc<MemChain>);

impl Wallet for ChainWallet {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        self.0.fund(address, sats)
    }

    fn wallet_sends_to(&self, address: &str) -> Result<Vec<String>> {
        self.0.wallet_sends_to(address)
    }

    fn wallet_send(&self, txid: &str, address: &str) -> Result<Option<WalletSend>> {
        self.0.wallet_send(txid, address)
    }
}

/// `drop(method, path) -> true` loses the answer after the service handled the request.
pub type DropFn = Box<dyn Fn(&str, &str) -> bool + Send + Sync>;

/// origin → service, in process.
#[derive(Default)]
pub struct MemNet {
    apps: Mutex<HashMap<String, Arc<dyn HttpService>>>,
    drops: Mutex<HashMap<String, DropFn>>,
    /// (method, origin, path) of every request.
    pub calls: Mutex<Vec<(String, String, String)>>,
}

impl MemNet {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn add(&self, origin: &str, app: Arc<dyn HttpService>) {
        self.apps.lock().unwrap().insert(origin.into(), app);
    }

    pub fn set_drop(&self, origin: &str, f: Option<DropFn>) {
        let mut d = self.drops.lock().unwrap();
        match f {
            Some(f) => d.insert(origin.into(), f),
            None => d.remove(origin),
        };
    }

    pub fn count(&self, path: &str) -> usize {
        self.calls.lock().unwrap().iter().filter(|c| c.2 == path).count()
    }
}

/// A [`Transport`] over a [`MemNet`].
pub struct NetTransport(pub Arc<MemNet>);

impl Transport for NetTransport {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        let (origin, path) = xbt402::client::split_url(url);
        let app = self.0.apps.lock().unwrap().get(&origin).cloned().ok_or_else(|| ChannelError::new("transport_error", format!("connection refused: {origin}")))?;
        self.0.calls.lock().unwrap().push((method.into(), origin.clone(), path.clone()));
        let r = app.serve(method, &path, headers, body, url);
        if self.0.drops.lock().unwrap().get(&origin).is_some_and(|d| d(method, &path)) {
            return Err(ChannelError::new("transport_error", "answer lost"));
        }
        let headers = r.headers.into_iter().map(|(k, v)| (k.to_ascii_uppercase(), v)).collect();
        Ok(HttpResponse::new(r.status, headers, r.body))
    }
}
