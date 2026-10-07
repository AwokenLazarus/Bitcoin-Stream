//! A simulated chain and an Electrum server over it, with knobs for lying (feature `sim`; a port of
//! B2's `tests/_electrum_sim.py`).
//!
//! [`SimChain`] mines real v2 BLAKE2b headers at the regtest target from block 101 (the checkpoint)
//! on, with real transactions (txid = hash of the raw bytes), Merkle roots and committed transaction
//! counts. [`FakeElectrum`] serves it over TCP or TLS with the methods electrs serves (batches and
//! notifications included) and can hide transactions, forge Merkle proofs, claim wrong heights,
//! substitute transactions, invent mempool spends, serve another header chain, withhold blocks, lie
//! about fees, or go down. [`TlsProxy`] puts TLS in front of any TCP Electrum server.
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{json, Value};
use xbt_primitives::hash::{display_hex, hex32, sha256};
use xbt_primitives::header::{self, merkle_root, parse_header, ChainRules, V2_FLAG};
use xbt_primitives::tx::{OutPoint, Tx, TxIn, TxOut};

use crate::backend::scripthash;

pub const REGTEST_BITS: u32 = 0x207F_FFFF;
pub const CHECKPOINT: u32 = 101;
pub const T0: u32 = 1_780_000_000;
/// The test CA (PEM) that signed [`TEST_CERT`]; give it to the client as an extra root.
pub const TEST_CA: &str = include_str!("../tests/data/test-ca.pem");
/// A certificate for `localhost` and `127.0.0.1`.
pub const TEST_CERT: &str = include_str!("../tests/data/localhost.pem");
pub const TEST_KEY: &str = include_str!("../tests/data/localhost.key");

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// A v2 header meeting its target (profile 0, no xor key, no time offset).
pub fn mine_header(prev_display: [u8; 32], merkle_internal: [u8; 32], height: u32, txcount: u16, time: u32, bits: u32) -> Vec<u8> {
    let rules = ChainRules::regtest();
    for nonce in 0u32.. {
        let mut b = Vec::with_capacity(164);
        b.extend((0x2000_0000u32 | V2_FLAG).to_le_bytes());
        let mut prev = prev_display;
        prev.reverse();
        b.extend(prev);
        b.extend(merkle_internal);
        b.extend(time.to_le_bytes());
        b.extend(bits.to_le_bytes());
        b.extend(nonce.to_le_bytes());
        b.extend([0u8; 8]);
        b.extend([0u8; 16]);
        b.extend(0u32.to_le_bytes());
        b.extend(txcount.to_le_bytes());
        b.extend([0u8, 0u8]);
        b.extend([0u8; 16]);
        b.extend(height.to_le_bytes());
        b.extend([0u8; 32]);
        let h = parse_header(&b).expect("well formed");
        if header::check_pow(&h, &rules).is_ok() {
            return b;
        }
    }
    unreachable!()
}

/// Electrum's Merkle branch (display hex) for `txids[pos]` (txids in internal order).
pub fn merkle_branch(txids: &[[u8; 32]], pos: usize) -> Vec<String> {
    let mut level = txids.to_vec();
    let (mut branch, mut idx) = (Vec::new(), pos);
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        branch.push(display_hex(&level[idx ^ 1]));
        level = level.chunks(2).map(|c| {
            let mut cat = [0u8; 64];
            cat[..32].copy_from_slice(&c[0]);
            cat[32..].copy_from_slice(&c[1]);
            xbt_primitives::hash::dsha256(&cat)
        }).collect();
        idx /= 2;
    }
    branch
}

pub fn coinbase(height: u32, salt: u8) -> Tx {
    let mut sig = height.to_le_bytes().to_vec();
    sig.push(salt);
    let mut i = TxIn::new(OutPoint::new([0u8; 32], 0xFFFF_FFFF), 0xFFFF_FFFF);
    i.script_sig = sig;
    Tx::new(2, vec![i], vec![TxOut::new(312_500_000, [vec![0x00, 0x14], vec![0x11; 20]].concat())], 0)
}

/// A chain from the checkpoint up: headers, blocks, transactions, a mempool.
pub struct SimChain {
    pub salt: u8,
    /// Raw headers, `headers[0]` at [`CHECKPOINT`].
    pub headers: Vec<Vec<u8>>,
    /// txids (display) per block, same indexing.
    pub blocks: Vec<Vec<String>>,
    pub txs: HashMap<String, Tx>,
    pub height_of: HashMap<String, u32>,
    pub mempool: Vec<String>,
    /// Bumped on every change (servers notify on it).
    pub version: u64,
    faucet_n: u64,
}

impl SimChain {
    /// A chain up to `height` (>= 101).
    pub fn new(height: u32, salt: u8) -> Self {
        let mut c = Self { salt, headers: vec![], blocks: vec![], txs: HashMap::new(), height_of: HashMap::new(),
                           mempool: vec![], version: 0, faucet_n: 0 };
        c.mine_one([0xAB; 32]);
        c.mine(height - CHECKPOINT);
        c
    }

    pub fn tip_height(&self) -> u32 {
        CHECKPOINT + self.headers.len() as u32 - 1
    }

    pub fn header(&self, height: u32) -> Option<&Vec<u8>> {
        height.checked_sub(CHECKPOINT).and_then(|i| self.headers.get(i as usize))
    }

    pub fn hash_at(&self, height: u32) -> [u8; 32] {
        parse_header(self.header(height).expect("height")).unwrap().hash
    }

    fn mine_one(&mut self, prev: [u8; 32]) {
        let h = CHECKPOINT + self.headers.len() as u32;
        let cb = coinbase(h, self.salt);
        let mut txids = vec![cb.txid()];
        self.txs.insert(cb.txid(), cb);
        txids.append(&mut self.mempool);
        let internal: Vec<[u8; 32]> = txids.iter().map(|t| self.txs[t].txid_bytes()).collect();
        let raw = mine_header(prev, merkle_root(&internal), h, txids.len() as u16, T0 + 60 * h, REGTEST_BITS);
        for t in &txids {
            self.height_of.insert(t.clone(), h);
        }
        self.headers.push(raw);
        self.blocks.push(txids);
        self.version += 1;
    }

    pub fn mine(&mut self, n: u32) {
        for _ in 0..n {
            let prev = self.hash_at(self.tip_height());
            self.mine_one(prev);
        }
    }

    /// Put a transaction in the mempool.
    pub fn add(&mut self, tx: Tx) -> String {
        let id = tx.txid();
        if !self.txs.contains_key(&id) {
            self.txs.insert(id.clone(), tx);
            self.mempool.push(id.clone());
            self.version += 1;
        }
        id
    }

    /// A faucet payment of `sats` to `spk` at output `vout` (dust outputs before it). Returns its txid.
    pub fn credit(&mut self, vout: u32, sats: u64, spk: &[u8], confirmed: bool) -> String {
        self.faucet_n += 1;
        let mut prev = sha256(&[&self.faucet_n.to_le_bytes()[..], &[self.salt]].concat());
        prev[0] ^= 0x5A;
        let mut outs: Vec<TxOut> = (0..vout).map(|_| TxOut::new(546, [vec![0x00, 0x14], vec![0x22; 20]].concat())).collect();
        outs.push(TxOut::new(sats as i64, spk.to_vec()));
        let id = self.add(Tx::new(2, vec![TxIn::new(OutPoint::new(prev, 0), 0xFFFF_FFFD)], outs, 0));
        if confirmed {
            self.mine(1);
        }
        id
    }

    /// A transaction spending `outpoints` to `outs` (scripts are not checked here).
    pub fn spend(&mut self, outpoints: &[(&str, u32)], outs: Vec<TxOut>, confirmed: bool) -> String {
        let ins = outpoints.iter().map(|(t, v)| TxIn::new(OutPoint::from_display(t, *v).unwrap(), 0xFFFF_FFFD)).collect();
        let id = self.add(Tx::new(2, ins, outs, 0));
        if confirmed {
            self.mine(1);
        }
        id
    }

    /// Another branch: `n` headers on top of our header at `from`, with `salt` making them differ.
    /// Returns the whole alternative header list from the checkpoint (ours up to `from`).
    pub fn alt_chain(&self, from: u32, n: u32, salt: u8) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = self.headers[..=(from - CHECKPOINT) as usize].to_vec();
        let mut prev = self.hash_at(from);
        for h in from + 1..=from + n {
            let mut m = [salt; 32];
            m[..4].copy_from_slice(&h.to_le_bytes());
            let raw = mine_header(prev, m, h, 1, T0 + 60 * h + 1, REGTEST_BITS);
            prev = parse_header(&raw).unwrap().hash;
            out.push(raw);
        }
        out
    }

    fn all(&self) -> Vec<(String, i64)> {
        let mut v: Vec<(String, i64)> = self.blocks.iter().enumerate()
            .flat_map(|(i, b)| b.iter().map(move |t| (t.clone(), (CHECKPOINT + i as u32) as i64))).collect();
        v.extend(self.mempool.iter().map(|t| (t.clone(), 0)));
        v
    }

    fn touches(&self, tx: &Tx, sh: &str) -> bool {
        tx.outputs.iter().any(|o| scripthash(&o.script_pubkey) == sh)
            || tx.inputs.iter().any(|i| self.txs.get(&i.prevout.txid_hex())
                .and_then(|p| p.outputs.get(i.prevout.vout as usize))
                .map(|o| scripthash(&o.script_pubkey) == sh).unwrap_or(false))
    }

    pub fn history(&self, sh: &str) -> Vec<(String, i64)> {
        self.all().into_iter().filter(|(t, _)| self.touches(&self.txs[t], sh)).collect()
    }

    pub fn listunspent(&self, sh: &str) -> Vec<(String, u32, i64, u64)> {
        let spent: HashSet<(String, u32)> = self.all().iter()
            .flat_map(|(t, _)| self.txs[t].inputs.iter().map(|i| (i.prevout.txid_hex(), i.prevout.vout))).collect();
        let mut out = vec![];
        for (t, h) in self.all() {
            for (n, o) in self.txs[&t].outputs.iter().enumerate() {
                if scripthash(&o.script_pubkey) == sh && !spent.contains(&(t.clone(), n as u32)) {
                    out.push((t.clone(), n as u32, h, o.value as u64));
                }
            }
        }
        out
    }

    /// (branch, pos) for a confirmed tx.
    pub fn proof(&self, txid: &str) -> Option<(u32, Vec<String>, usize)> {
        let h = *self.height_of.get(txid)?;
        let b = &self.blocks[(h - CHECKPOINT) as usize];
        let pos = b.iter().position(|t| t == txid)?;
        let internal: Vec<[u8; 32]> = b.iter().map(|t| self.txs[t].txid_bytes()).collect();
        Some((h, merkle_branch(&internal, pos), pos))
    }
}

/// How a server forges Merkle proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forge {
    /// A sibling flipped: the root misses our header.
    WrongSibling,
    /// One level too many (a 64-byte inner node posing as a transaction, CVE-2017-12842).
    WrongDepth,
    /// A position past the block's committed transaction count.
    PastEnd,
}

/// What a server lies about.
#[derive(Debug, Default, Clone)]
pub struct Knobs {
    /// txids left out of everything.
    pub hide: HashSet<String>,
    pub forge: Option<Forge>,
    /// txid -> the height get_history claims.
    pub claim_height: HashMap<String, i64>,
    /// txid -> another transaction served for it.
    pub substitute: HashMap<String, Tx>,
    /// scripthash -> extra history entries (txid, height); pair with `invented`.
    pub extra_history: HashMap<String, Vec<(String, i64)>>,
    /// Invented transactions, served by txid.
    pub invented: HashMap<String, Tx>,
    /// Another header chain (from the checkpoint).
    pub headers: Option<Vec<Vec<u8>>>,
    /// Serve the chain only up to this height (withheld blocks: a stale tip).
    pub withhold_above: Option<u32>,
    /// Refuse to serve any header above this height, while still claiming the real tip.
    pub refuse_headers_above: Option<u32>,
    pub fee: Option<f64>,
    /// Answer broadcasts with this txid.
    pub broadcast_txid: Option<String>,
    /// Refuse broadcasts with this error.
    pub refuse_broadcast: Option<String>,
    /// Stop answering requests (connection stays open: the client times out).
    pub mute: bool,
}

enum SLink {
    Plain(TcpStream),
    Tls(TcpStream, Box<rustls::ServerConnection>),
}

impl SLink {
    /// New plaintext bytes; Ok(None) at EOF, Ok(Some(empty)) on a timeout.
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<Option<Vec<u8>>> {
        match self {
            SLink::Plain(s) => match s.read(buf) {
                Ok(0) => Ok(None),
                Ok(n) => Ok(Some(buf[..n].to_vec())),
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => Ok(Some(vec![])),
                Err(e) => Err(e),
            },
            SLink::Tls(s, c) => {
                match c.read_tls(s) {
                    Ok(0) => return Ok(None),
                    Ok(_) => {}
                    Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return Ok(Some(vec![])),
                    Err(e) => return Err(e),
                }
                c.process_new_packets().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                let mut out = vec![];
                loop {
                    match c.reader().read(buf) {
                        Ok(0) => break,
                        Ok(n) => out.extend_from_slice(&buf[..n]),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e),
                    }
                }
                while c.wants_write() {
                    c.write_tls(s)?;
                }
                Ok(Some(out))
            }
        }
    }

    fn send(&mut self, b: &[u8]) -> io::Result<()> {
        match self {
            SLink::Plain(s) => s.write_all(b),
            SLink::Tls(s, c) => {
                c.writer().write_all(b)?;
                while c.wants_write() {
                    c.write_tls(s)?;
                }
                Ok(())
            }
        }
    }

    fn sock(&self) -> &TcpStream {
        match self {
            SLink::Plain(s) | SLink::Tls(s, _) => s,
        }
    }
}

/// The server side TLS config for [`TEST_CERT`].
pub fn test_server_tls() -> Arc<rustls::ServerConfig> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(TEST_CERT.as_bytes()).collect::<Result<_, _>>().unwrap();
    let key = PrivateKeyDer::from_pem_slice(TEST_KEY.as_bytes()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Arc::new(rustls::ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap()
        .with_no_client_auth().with_single_cert(certs, key).unwrap())
}

/// An Electrum server over a shared [`SimChain`].
pub struct FakeElectrum {
    pub chain: Arc<Mutex<SimChain>>,
    pub knobs: Mutex<Knobs>,
    pub addr: SocketAddr,
    pub tls: bool,
    /// Every method called, in order.
    pub calls: Mutex<Vec<String>>,
    /// While down, connections are refused (closed at once) and live ones dropped.
    pub down: AtomicBool,
    pub stopped: AtomicBool,
    conns: AtomicU64,
}

impl FakeElectrum {
    pub fn start(chain: Arc<Mutex<SimChain>>, tls: bool) -> Arc<Self> {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let s = Arc::new(Self { chain, knobs: Mutex::new(Knobs::default()), addr: l.local_addr().unwrap(), tls,
                                calls: Mutex::new(vec![]), down: AtomicBool::new(false), stopped: AtomicBool::new(false),
                                conns: AtomicU64::new(0) });
        let srv = s.clone();
        let cfg = tls.then(test_server_tls);
        std::thread::spawn(move || {
            for sock in l.incoming() {
                if srv.stopped.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(sock) = sock else { continue };
                if srv.down.load(Ordering::SeqCst) {
                    let _ = sock.shutdown(Shutdown::Both);
                    continue;
                }
                srv.conns.fetch_add(1, Ordering::SeqCst);
                let link = match &cfg {
                    Some(c) => SLink::Tls(sock, Box::new(rustls::ServerConnection::new(c.clone()).unwrap())),
                    None => SLink::Plain(sock),
                };
                let srv = srv.clone();
                std::thread::spawn(move || srv.serve(link));
            }
        });
        s
    }

    /// `tcp://127.0.0.1:port` or `ssl://localhost:port`.
    pub fn url(&self) -> String {
        if self.tls { format!("ssl://localhost:{}", self.addr.port()) } else { format!("tcp://127.0.0.1:{}", self.addr.port()) }
    }

    pub fn connections(&self) -> u64 {
        self.conns.load(Ordering::SeqCst)
    }

    pub fn knobs(&self) -> MutexGuard<'_, Knobs> {
        lock(&self.knobs)
    }

    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.down.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }

    fn serve(&self, mut link: SLink) {
        let _ = link.sock().set_read_timeout(Some(Duration::from_millis(20)));
        let mut buf = vec![0u8; 1 << 16];
        let mut pending: Vec<u8> = vec![];
        let mut subs: BTreeMap<String, Option<String>> = BTreeMap::new(); // scripthash -> last status
        let mut tip_sub: Option<u32> = None;
        let mut seen_version = u64::MAX;
        loop {
            if self.down.load(Ordering::SeqCst) {
                break;
            }
            let got = match link.recv(&mut buf) {
                Ok(Some(b)) => b,
                _ => break,
            };
            pending.extend_from_slice(&got);
            while let Some(i) = pending.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = pending.drain(..=i).collect();
                let Ok(msg) = serde_json::from_slice::<Value>(&line) else { return };
                if self.knobs().mute {
                    continue;
                }
                let reply = match msg {
                    Value::Array(items) => Value::Array(items.iter().map(|m| self.answer(m, &mut subs, &mut tip_sub)).collect()),
                    m => self.answer(&m, &mut subs, &mut tip_sub),
                };
                let mut out = reply.to_string();
                out.push('\n');
                if link.send(out.as_bytes()).is_err() {
                    return;
                }
            }
            // notifications
            let v = lock(&self.chain).version;
            if v != seen_version {
                seen_version = v;
                let mut notes = vec![];
                if let Some(last) = tip_sub {
                    let (h, hex) = self.tip();
                    if h != last {
                        tip_sub = Some(h);
                        notes.push(json!({"jsonrpc": "2.0", "method": "blockchain.headers.subscribe", "params": [{"height": h, "hex": hex}]}));
                    }
                }
                for (sh, last) in subs.iter_mut() {
                    let st = self.status_of(sh);
                    if &st != last {
                        *last = st.clone();
                        notes.push(json!({"jsonrpc": "2.0", "method": "blockchain.scripthash.subscribe", "params": [sh, st]}));
                    }
                }
                for n in notes {
                    if link.send(format!("{n}\n").as_bytes()).is_err() {
                        return;
                    }
                }
            }
        }
        let _ = link.sock().shutdown(Shutdown::Both);
    }

    fn headers_view(&self) -> Vec<Vec<u8>> {
        let k = self.knobs();
        let mut hs = k.headers.clone().unwrap_or_else(|| lock(&self.chain).headers.clone());
        if let Some(w) = k.withhold_above {
            hs.truncate((w + 1).saturating_sub(CHECKPOINT) as usize);
        }
        hs
    }

    fn tip(&self) -> (u32, String) {
        let hs = self.headers_view();
        (CHECKPOINT + hs.len() as u32 - 1, hex::encode(hs.last().unwrap()))
    }

    fn history(&self, sh: &str) -> Vec<(String, i64)> {
        let k = self.knobs().clone();
        let tip = self.tip().0 as i64;
        let mut h: Vec<(String, i64)> = lock(&self.chain).history(sh).into_iter()
            .filter(|(t, _)| !k.hide.contains(t))
            .map(|(t, h)| (t.clone(), if h > tip { 0 } else { h }))
            .map(|(t, h)| { let c = k.claim_height.get(&t).copied().unwrap_or(h); (t, c) })
            .collect();
        h.extend(k.extra_history.get(sh).cloned().unwrap_or_default());
        h
    }

    fn status_of(&self, sh: &str) -> Option<String> {
        let h = self.history(sh);
        if h.is_empty() {
            return None;
        }
        let s: String = h.iter().map(|(t, h)| format!("{t}:{h}:")).collect();
        Some(hex::encode(sha256(s.as_bytes())))
    }

    fn answer(&self, m: &Value, subs: &mut BTreeMap<String, Option<String>>, tip_sub: &mut Option<u32>) -> Value {
        let id = m.get("id").cloned().unwrap_or(Value::Null);
        let method = m.get("method").and_then(Value::as_str).unwrap_or("").to_string();
        let p = m.get("params").and_then(Value::as_array).cloned().unwrap_or_default();
        lock(&self.calls).push(method.clone());
        let r = self.dispatch(&method, &p, subs, tip_sub);
        match r {
            Ok(v) => json!({"jsonrpc": "2.0", "id": id, "result": v}),
            Err(e) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": 1, "message": e}}),
        }
    }

    fn dispatch(&self, method: &str, p: &[Value], subs: &mut BTreeMap<String, Option<String>>, tip_sub: &mut Option<u32>) -> Result<Value, String> {
        let s = |i: usize| p.get(i).and_then(Value::as_str).unwrap_or("").to_string();
        let u = |i: usize| p.get(i).and_then(Value::as_u64).unwrap_or(0) as u32;
        match method {
            "server.version" => Ok(json!(["FakeElectrum 0.1", "1.8"])),
            "server.ping" => Ok(Value::Null),
            "blockchain.headers.subscribe" => {
                let (h, hex) = self.tip();
                *tip_sub = Some(h);
                Ok(json!({"height": h, "hex": hex}))
            }
            "blockchain.block.header" => {
                let h = u(0);
                if self.knobs().refuse_headers_above.map(|r| h > r).unwrap_or(false) {
                    return Err("header unavailable".into());
                }
                let hs = self.headers_view();
                h.checked_sub(CHECKPOINT).and_then(|i| hs.get(i as usize)).map(|r| json!(hex::encode(r)))
                    .ok_or_else(|| format!("height {h} not found"))
            }
            "blockchain.block.headers" => {
                let (start, count) = (u(0), u(1).min(2016));
                let hs = self.headers_view();
                let refuse = self.knobs().refuse_headers_above;
                let mut blob = vec![];
                let mut n = 0;
                for h in start..start + count {
                    if refuse.map(|r| h > r).unwrap_or(false) {
                        break;
                    }
                    match h.checked_sub(CHECKPOINT).and_then(|i| hs.get(i as usize)) {
                        Some(r) => {
                            blob.extend_from_slice(r);
                            n += 1;
                        }
                        None => break,
                    }
                }
                Ok(json!({"hex": hex::encode(blob), "count": n, "max": 2016}))
            }
            "blockchain.transaction.get" => {
                let t = s(0).to_ascii_lowercase();
                let k = self.knobs().clone();
                if k.hide.contains(&t) {
                    return Err("No such mempool or blockchain transaction".into());
                }
                if let Some(x) = k.substitute.get(&t).or_else(|| k.invented.get(&t)) {
                    return Ok(json!(x.to_hex()));
                }
                lock(&self.chain).txs.get(&t).map(|x| json!(x.to_hex())).ok_or_else(|| "No such mempool or blockchain transaction".into())
            }
            "blockchain.transaction.get_merkle" => {
                let t = s(0).to_ascii_lowercase();
                let forge = self.knobs().forge;
                let (h, mut branch, mut pos) = lock(&self.chain).proof(&t).ok_or("tx not confirmed")?;
                match forge {
                    Some(Forge::WrongSibling) if !branch.is_empty() => branch[0] = "11".repeat(32),
                    Some(Forge::WrongSibling) => branch.push("11".repeat(32)),
                    Some(Forge::WrongDepth) => branch.push("22".repeat(32)),
                    Some(Forge::PastEnd) => pos += 1 << branch.len(),
                    None => {}
                }
                Ok(json!({"block_height": h, "merkle": branch, "pos": pos}))
            }
            "blockchain.scripthash.get_history" => {
                Ok(Value::Array(self.history(&s(0)).into_iter().map(|(t, h)| json!({"tx_hash": t, "height": h})).collect()))
            }
            "blockchain.scripthash.listunspent" => {
                let k = self.knobs().clone();
                let tip = self.tip().0 as i64;
                Ok(Value::Array(lock(&self.chain).listunspent(&s(0)).into_iter().filter(|(t, ..)| !k.hide.contains(t))
                    .map(|(t, n, h, v)| json!({"tx_hash": t, "tx_pos": n, "height": if h > tip { 0 } else { h }, "value": v})).collect()))
            }
            "blockchain.scripthash.subscribe" => {
                let sh = s(0);
                let st = self.status_of(&sh);
                subs.insert(sh, st.clone());
                Ok(json!(st))
            }
            "blockchain.transaction.broadcast" => {
                let k = self.knobs().clone();
                if let Some(e) = k.refuse_broadcast {
                    return Err(e);
                }
                let tx = Tx::parse_hex(&s(0)).map_err(|e| e.to_string())?;
                let id = lock(&self.chain).add(tx);
                Ok(json!(k.broadcast_txid.unwrap_or(id)))
            }
            "blockchain.estimatefee" => Ok(json!(self.knobs().fee.unwrap_or(0.0001))),
            _ => Err(format!("unknown method {method}")),
        }
    }
}

/// TLS in front of a TCP Electrum server (with [`TEST_CERT`]): the interop run's `ssl://` server.
pub struct TlsProxy {
    pub addr: SocketAddr,
}

impl TlsProxy {
    pub fn start(listen: &str, upstream: SocketAddr) -> io::Result<Self> {
        let l = TcpListener::bind(listen)?;
        let addr = l.local_addr()?;
        let cfg = test_server_tls();
        std::thread::spawn(move || {
            for sock in l.incoming().flatten() {
                let cfg = cfg.clone();
                std::thread::spawn(move || {
                    let Ok(up) = TcpStream::connect(upstream) else { return };
                    let Ok(mut up_r) = up.try_clone() else { return };
                    let mut link = SLink::Tls(sock, Box::new(rustls::ServerConnection::new(cfg).unwrap()));
                    let _ = link.sock().set_read_timeout(Some(Duration::from_millis(10)));
                    let _ = up_r.set_read_timeout(Some(Duration::from_millis(10)));
                    let mut up_w = up;
                    let (mut b1, mut b2) = (vec![0u8; 1 << 16], vec![0u8; 1 << 16]);
                    loop {
                        match link.recv(&mut b1) {
                            Ok(Some(d)) => {
                                if !d.is_empty() && up_w.write_all(&d).is_err() {
                                    break;
                                }
                            }
                            _ => break,
                        }
                        match up_r.read(&mut b2) {
                            Ok(0) => break,
                            Ok(n) => {
                                if link.send(&b2[..n]).is_err() {
                                    break;
                                }
                            }
                            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
                            Err(_) => break,
                        }
                    }
                    let _ = up_w.shutdown(Shutdown::Both);
                    let _ = link.sock().shutdown(Shutdown::Both);
                });
            }
        });
        Ok(Self { addr })
    }
}

/// `hex32` for tests that name blocks.
pub fn h32(s: &str) -> [u8; 32] {
    hex32(s).unwrap()
}
