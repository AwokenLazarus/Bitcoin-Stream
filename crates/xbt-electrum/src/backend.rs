//! The light chain backend: the node calls of the xbt402 client path answered from Electrum
//! servers and verified against our own BLAKE2b header chain (a port of B2 `agentwallet/electrum.py`,
//! AGP-024; the threat model is in the crate docs and `docs/B2_CHAIN_BACKEND.md`).
//!
//! No network read happens under the shared state lock: requests run unlocked and the lock is taken
//! only to read or record what they returned. Servers sync in parallel; header chunks are checked as
//! they arrive (the first bad header ends that server's sync, the valid headers before it count).
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt_primitives::address::segwit_address;
use xbt_primitives::hash::{hex32, sha256};
use xbt_primitives::header::{self, merkle_root_from_proof, parse_header, split_headers, ChainRules, Clock, HeaderChain,
                             MAINNET_CHECKPOINT, U512};
use xbt_primitives::network::Chain;
use xbt_primitives::tx::Tx;

use crate::conn::{tls_config, Connection, Notify};
use crate::error::{err, ElectrumError, Kind, Result};

/// Headers per `blockchain.block.headers` request (electrs' maximum).
pub const HEADERS_CHUNK: u32 = 2016;
/// Header chunk requests per JSON-RPC batch while catching up.
pub const CHUNKS_PER_BATCH: u32 = 4;
/// A mainnet tip older than this means every server is behind, or withholding blocks.
pub const STALE_TIP_S: u64 = 3 * 60 * 60;
/// A claimed tip is believed up to one block per this many seconds since our tip's time (a quarter
/// of the target spacing), plus [`HEADERS_CHUNK`]; headers above that are not fetched.
pub const TIP_CAP_SPACING_S: u64 = 150;
/// Node RPCs a light client cannot answer: the node wallet, blocks, mining.
pub const NODE_ONLY: &[&str] = &[
    "getbalances", "getbalance", "sendtoaddress", "listunspent", "createrawtransaction", "fundrawtransaction",
    "signrawtransactionwithwallet", "getnewaddress", "generatetoaddress", "generatetodescriptor", "generateblock",
    "generate", "getblock", "getwalletinfo", "sendmany",
];
const SATS: f64 = 100_000_000.0;
const MAX_FLAGS: usize = 50;

/// Electrum's script hash: SHA-256 of the scriptPubKey, byte-reversed, hex.
pub fn scripthash(spk: &[u8]) -> String {
    let mut h = sha256(spk);
    h.reverse();
    hex::encode(h)
}

fn now_s() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn is_coinbase(tx: &Tx) -> bool {
    tx.inputs.len() == 1 && tx.inputs[0].prevout.txid == [0u8; 32] && tx.inputs[0].prevout.vout == 0xFFFF_FFFF
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// `localhost`, 127.0.0.0/8, `::1` or an IPv4-mapped loopback address.
pub fn is_loopback_host(host: &str) -> bool {
    let h = host.trim_end_matches('.');
    if h.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match h.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => a.is_loopback(),
        Ok(IpAddr::V6(a)) => a.is_loopback() || a.to_ipv4_mapped().map(|m| m.is_loopback()).unwrap_or(false),
        Err(_) => false,
    }
}

/// When the verified chain is believable (see [`HeaderChain::implausible`]): until it is, every
/// chain answer fails with [`Kind::Implausible`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plausibility {
    /// Work the chain must carry above the checkpoint.
    pub min_work_above: U512,
    /// The tip may trail one block per `floor_spacing_s` since the newest pinned block we hold (or
    /// the checkpoint) by at most `floor_slack` blocks.
    pub floor_spacing_s: u64,
    pub floor_slack: u32,
}

impl Plausibility {
    /// Mainnet from `checkpoint`: Knots' nMinimumChainWork less the checkpoint's chainwork (zero for
    /// a checkpoint of unknown chainwork, which still has to reach the pinned block 964264), and a
    /// floor of one block per 600 s with 2016 blocks of slack.
    pub fn mainnet(checkpoint: (u32, &[u8; 32])) -> Self {
        Self {
            min_work_above: header::mainnet_min_work_above(checkpoint).unwrap_or(U512::ZERO),
            floor_spacing_s: 600,
            floor_slack: HEADERS_CHUNK,
        }
    }
}

/// How the backend is set up.
#[derive(Clone)]
pub struct Config {
    /// `ssl://host:port` (certificates verified) or `tcp://host:port`; on mainnet `tcp://` only to a
    /// loopback host.
    pub servers: Vec<String>,
    /// `main` or `regtest` (testnet3, testnet4 and signet have no header rules here and are refused):
    /// a light client does not ask a node.
    pub chain: String,
    /// `(height, block hash)`. Mainnet defaults to 961640, the first BLAKE2b block; other chains must set it.
    pub checkpoint: Option<(u32, String)>,
    /// Where the verified headers persist (re-verified at load).
    pub store_path: Option<PathBuf>,
    /// Per request.
    pub timeout: Duration,
    /// Servers that must answer (default 2 on mainnet, 1 elsewhere; capped at the number configured).
    pub min_servers: Option<usize>,
    /// Re-ask the servers' tips at most this often (a tip notification forces it sooner).
    pub sync_interval: Duration,
    /// Extra CA certificates (PEM) for `ssl://` servers, besides the Mozilla roots.
    pub extra_ca: Vec<PathBuf>,
    /// None: [`Plausibility::mainnet`] on mainnet, no check elsewhere.
    pub plausibility: Option<Plausibility>,
    /// A claimed tip is believed up to one block per this many seconds since our tip's time, plus
    /// [`HEADERS_CHUNK`]. None: [`TIP_CAP_SPACING_S`] on mainnet, no cap elsewhere (regtest mines
    /// blocks as fast as it is asked to).
    pub tip_cap_spacing_s: Option<u64>,
    /// The current unix time (the 2 h future rule, the tip cap, the height floor); None: the system clock.
    pub clock: Option<Clock>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config").field("servers", &self.servers).field("chain", &self.chain)
            .field("checkpoint", &self.checkpoint).field("store_path", &self.store_path).field("timeout", &self.timeout)
            .field("min_servers", &self.min_servers).field("sync_interval", &self.sync_interval)
            .field("extra_ca", &self.extra_ca).field("plausibility", &self.plausibility)
            .field("tip_cap_spacing_s", &self.tip_cap_spacing_s).field("clock", &self.clock.as_ref().map(|_| "custom")).finish()
    }
}

impl Config {
    pub fn new(servers: &[&str], chain: &str) -> Self {
        Self {
            servers: servers.iter().map(|s| s.to_string()).collect(),
            chain: chain.to_string(),
            checkpoint: None,
            store_path: None,
            timeout: Duration::from_secs(15),
            min_servers: None,
            sync_interval: Duration::from_secs(1),
            extra_ca: Vec::new(),
            plausibility: None,
            tip_cap_spacing_s: None,
            clock: None,
        }
    }

    /// B2's environment (`docs/B2_CHAIN_BACKEND.md`): `B2_CHAIN`, `B2_ELECTRUM_SERVERS`,
    /// `B2_ELECTRUM_CHECKPOINT` (`<height>:<hash>`), `B2_ELECTRUM_MIN_SERVERS`, `B2_ELECTRUM_TIMEOUT`,
    /// plus `B2_ELECTRUM_CA` (comma-separated PEM files) and the run dir for the header store.
    pub fn from_env(run_dir: Option<&std::path::Path>) -> Result<Self> {
        let get = |k: &str| std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let chain = get("B2_CHAIN").ok_or_else(|| ElectrumError::new(Kind::BadRequest, "the Electrum backend needs B2_CHAIN (a light client has no node to ask)"))?;
        let servers = split_list(get("B2_ELECTRUM_SERVERS").as_deref());
        if servers.is_empty() {
            return err(Kind::BadRequest, "the Electrum backend needs B2_ELECTRUM_SERVERS");
        }
        let mut c = Config::new(&servers.iter().map(String::as_str).collect::<Vec<_>>(), &chain);
        c.checkpoint = parse_checkpoint(get("B2_ELECTRUM_CHECKPOINT").as_deref())?;
        if let Some(m) = get("B2_ELECTRUM_MIN_SERVERS") {
            c.min_servers = Some(m.parse().map_err(|_| ElectrumError::new(Kind::BadRequest, "B2_ELECTRUM_MIN_SERVERS: a number"))?);
        }
        if let Some(t) = get("B2_ELECTRUM_TIMEOUT") {
            let s: f64 = t.parse().map_err(|_| ElectrumError::new(Kind::BadRequest, "B2_ELECTRUM_TIMEOUT: seconds"))?;
            c.timeout = Duration::from_secs_f64(s.clamp(0.1, 3600.0));
        }
        c.extra_ca = split_list(get("B2_ELECTRUM_CA").as_deref()).into_iter().map(PathBuf::from).collect();
        c.store_path = run_dir.map(|d| d.join(format!("headers-{chain}.bin")));
        Ok(c)
    }
}

fn split_list(v: Option<&str>) -> Vec<String> {
    v.unwrap_or("").split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
}

/// `"<height>:<64-hex block hash>"`.
pub fn parse_checkpoint(v: Option<&str>) -> Result<Option<(u32, String)>> {
    let Some(v) = v.map(str::trim).filter(|v| !v.is_empty()) else { return Ok(None) };
    let (h, bh) = v.split_once(':').unwrap_or((v, ""));
    match (h.parse::<u32>(), bh.len() == 64 && bh.chars().all(|c| c.is_ascii_hexdigit())) {
        (Ok(h), true) => Ok(Some((h, bh.to_ascii_lowercase()))),
        _ => err(Kind::BadRequest, "the checkpoint must be <height>:<64-hex block hash>"),
    }
}

/// Where a transaction is, as far as can be proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxStatus {
    /// A server says it is unconfirmed (unprovable, and never treated as confirmed).
    Mempool,
    /// A Merkle proof ties it to our header at this height.
    Confirmed { height: u32, block_hash: [u8; 32] },
}

/// `gettxout`, verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutInfo {
    pub best_block: String,
    /// 0 for a mempool output.
    pub confirmations: u32,
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    pub coinbase: bool,
}

/// A confirmed, proven, unspent coin of a script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    pub height: u32,
    /// The block the Merkle proof ties it to (display hex).
    pub block_hash: String,
    pub coinbase: bool,
}

/// A fee estimate. Never verifiable: the median over the servers that answered, so one lying
/// server cannot set it alone.
#[derive(Debug, Clone, PartialEq)]
pub struct FeeEstimate {
    /// BTC per kvB; None when no server had an estimate.
    pub feerate: Option<f64>,
    pub blocks: u32,
    pub answers: Vec<f64>,
}

/// What we know about one server (the `status()` report).
#[derive(Debug, Clone, Default)]
pub struct ServerState {
    pub server: String,
    pub proto: String,
    pub tip: Option<u32>,
    pub tip_hash: Option<String>,
    pub on_best_chain: Option<bool>,
    pub errors: u64,
    pub last_error: Option<String>,
}

/// A server answered something that failed verification (or failed to answer).
#[derive(Debug, Clone)]
pub struct Flag {
    pub server: String,
    pub reason: String,
    pub t: u64,
}

struct Signal {
    tip_dirty: AtomicBool,
    changed: Mutex<bool>,
    cv: Condvar,
}

struct Inner {
    headers: HeaderChain,
    last_sync: Option<Instant>,
    watched: BTreeSet<String>,
    txs: HashMap<String, Tx>,
    conf: HashMap<String, (u32, [u8; 32])>,
    servers: HashMap<String, ServerState>,
    flags: VecDeque<Flag>,
}

impl Inner {
    fn flag(&mut self, url: &str, reason: impl Into<String>) {
        let mut reason: String = reason.into();
        if reason.len() > 200 {
            let mut i = 200;
            while !reason.is_char_boundary(i) {
                i -= 1;
            }
            reason.truncate(i);
        }
        let st = self.servers.entry(url.to_string()).or_default();
        st.errors += 1;
        st.last_error = Some(reason.clone());
        self.flags.push_back(Flag { server: url.to_string(), reason, t: now_s() });
        while self.flags.len() > MAX_FLAGS {
            self.flags.pop_front();
        }
    }

    fn tip_height(&self) -> u32 {
        self.headers.tip_height().unwrap_or(0)
    }

    /// Still on our best chain? (A cached proof into a header that was reorged out must be redone.)
    fn conf_holds(&self, c: &(u32, [u8; 32])) -> bool {
        self.headers.at(c.0).map(|h| h.hash == c.1).unwrap_or(false)
    }
}

/// (the server that claimed it, the height it claimed; 0 or less = its mempool)
type Claims = Vec<(Arc<Connection>, i64)>;

enum SyncFail {
    OffCheckpoint(String),
    Other(String),
}

impl From<ElectrumError> for SyncFail {
    fn from(e: ElectrumError) -> Self {
        SyncFail::Other(e.msg)
    }
}

impl From<xbt_primitives::Error> for SyncFail {
    fn from(e: xbt_primitives::Error) -> Self {
        SyncFail::Other(e.to_string())
    }
}

/// The light backend (see the crate docs). Share it behind an `Arc`; every method takes `&self`.
pub struct ElectrumBackend {
    pub chain: String,
    hrp: &'static str,
    conns: Vec<Arc<Connection>>,
    pub min_servers: usize,
    sync_interval: Duration,
    signal: Arc<Signal>,
    /// The pinned checkpoint (height, display-order hash).
    cp: (u32, [u8; 32]),
    rules: ChainRules,
    plausibility: Option<Plausibility>,
    tip_cap_spacing_s: Option<u64>,
    clock: Clock,
    /// Held by the one sync in flight; callers with a verified chain do not wait for it.
    sync_gate: Mutex<()>,
    inner: Mutex<Inner>,
}

impl ElectrumBackend {
    pub fn new(cfg: Config) -> Result<Self> {
        if cfg.servers.is_empty() {
            return err(Kind::BadRequest, "no Electrum servers configured");
        }
        let chain = Chain::from_name(&cfg.chain).map_err(|e| ElectrumError::new(Kind::BadRequest, e.to_string()))?;
        let addrs = cfg.servers.iter().map(|u| crate::conn::parse_server(u)).collect::<Result<Vec<_>>>()?;
        if chain == Chain::Main {
            if let Some((u, _)) = cfg.servers.iter().zip(&addrs).find(|(_, a)| !a.tls && !is_loopback_host(&a.host)) {
                return err(Kind::BadRequest, format!("{u}: mainnet needs ssl:// (TLS); plain tcp:// only to a loopback host"));
            }
        }
        let (cp_h, cp_hash) = match cfg.checkpoint.clone() {
            Some(cp) => cp,
            None if chain == Chain::Main => (MAINNET_CHECKPOINT.0, MAINNET_CHECKPOINT.1.to_string()),
            None => return err(Kind::BadRequest, format!("a {} light backend needs a pinned checkpoint", cfg.chain)),
        };
        let cp = (cp_h, hex32(&cp_hash).map_err(|e| ElectrumError::new(Kind::BadRequest, e.to_string()))?);
        let clock: Clock = cfg.clock.clone().unwrap_or_else(|| Arc::new(now_s));
        let headers = HeaderChain::with_clock(&cfg.chain, (cp_h, &cp_hash), cfg.store_path.as_deref(), clock.clone())
            .map_err(|e| ElectrumError::new(Kind::BadRequest, e.to_string()))?;
        let plausibility = cfg.plausibility.clone().or_else(|| (chain == Chain::Main).then(|| Plausibility::mainnet((cp.0, &cp.1))));
        let signal = Arc::new(Signal { tip_dirty: AtomicBool::new(true), changed: Mutex::new(false), cv: Condvar::new() });
        let notify: Notify = {
            let s = signal.clone();
            Arc::new(move |_url: &str, method: &str, _params: &Value| {
                if method == "blockchain.headers.subscribe" {
                    s.tip_dirty.store(true, Ordering::SeqCst);
                }
                *lock(&s.changed) = true;
                s.cv.notify_all();
            })
        };
        let tls = if addrs.iter().any(|a| a.tls) {
            Some(tls_config(&cfg.extra_ca.iter().map(PathBuf::as_path).collect::<Vec<_>>())?)
        } else {
            None
        };
        let conns = cfg.servers.iter()
            .map(|u| Connection::new(u, cfg.timeout, tls.clone(), Some(notify.clone())).map(Arc::new))
            .collect::<Result<Vec<_>>>()?;
        let default_min = if chain == Chain::Main { 2 } else { 1 };
        let min_servers = cfg.min_servers.unwrap_or(default_min).clamp(1, conns.len());
        let servers = conns.iter().map(|c| (c.url.clone(), ServerState::default())).collect();
        Ok(Self {
            chain: cfg.chain.clone(),
            hrp: chain.hrp(),
            conns,
            min_servers,
            sync_interval: cfg.sync_interval,
            signal,
            cp,
            rules: headers.rules.clone(),
            plausibility,
            tip_cap_spacing_s: cfg.tip_cap_spacing_s.or((chain == Chain::Main).then_some(TIP_CAP_SPACING_S)),
            clock,
            sync_gate: Mutex::new(()),
            inner: Mutex::new(Inner {
                headers,
                last_sync: None,
                watched: BTreeSet::new(),
                txs: HashMap::new(),
                conf: HashMap::new(),
                servers,
                flags: VecDeque::new(),
            }),
        })
    }

    // --- plumbing ------------------------------------------------------------------------------

    /// The shared state, briefly: never hold it across a request.
    fn st(&self) -> MutexGuard<'_, Inner> {
        lock(&self.inner)
    }

    fn flag(&self, url: &str, reason: impl Into<String>) {
        self.st().flag(url, reason);
    }

    /// `f` on every connection, in parallel.
    fn each<T: Send>(conns: &[Arc<Connection>], f: impl Fn(&Connection) -> T + Sync) -> Vec<T> {
        if conns.len() <= 1 {
            return conns.iter().map(|c| f(c)).collect();
        }
        std::thread::scope(|s| {
            let hs: Vec<_> = conns.iter().map(|c| { let f = &f; s.spawn(move || f(c)) }).collect();
            hs.into_iter().map(|h| h.join().expect("an Electrum worker panicked")).collect()
        })
    }

    /// The connected servers (connecting the others first); an error below `min_servers`.
    fn live(&self) -> Result<Vec<Arc<Connection>>> {
        let down: Vec<Arc<Connection>> = self.conns.iter().filter(|c| !c.connected()).cloned().collect();
        if !down.is_empty() {
            let watched: Vec<(String, Value)> = self.st().watched.iter()
                .map(|sh| ("blockchain.scripthash.subscribe".to_string(), json!([sh]))).collect();
            let results = Self::each(&down, |c| -> Result<()> {
                c.connect()?;
                for r in c.subscribe_many(&watched)? {
                    r?;
                }
                Ok(())
            });
            let mut i = self.st();
            for (c, r) in down.iter().zip(results) {
                match r {
                    Ok(()) => {
                        let (server, proto) = c.server_info();
                        let st = i.servers.entry(c.url.clone()).or_default();
                        st.server = server;
                        st.proto = proto;
                    }
                    Err(e) => i.flag(&c.url, format!("unreachable: {e}")),
                }
            }
        }
        let live: Vec<Arc<Connection>> = self.conns.iter().filter(|c| c.connected()).cloned().collect();
        if live.len() < self.min_servers {
            return err(Kind::TooFewServers, format!("{} of {} Electrum servers reachable; at least {} needed",
                                                    live.len(), self.conns.len(), self.min_servers));
        }
        Ok(live)
    }

    fn ask(&self, c: &Connection, method: &str, params: Value) -> Result<Value> {
        c.request(method, params).map_err(|e| {
            self.flag(&c.url, format!("{method}: {e}"));
            e
        })
    }

    // --- headers -------------------------------------------------------------------------------

    /// Bring our header chain up to the most-work tip any live server shows. Returns our tip.
    /// With a verified chain, a call that finds another sync in flight answers from the chain as it
    /// is rather than wait for it.
    pub fn sync(&self, force: bool) -> Result<u32> {
        let (ready, due) = {
            let i = self.st();
            (i.headers.ready(), i.last_sync.map(|t| t.elapsed() >= self.sync_interval).unwrap_or(true))
        };
        if force || due || !ready || self.signal.tip_dirty.load(Ordering::SeqCst) {
            let gate = if ready {
                match self.sync_gate.try_lock() {
                    Ok(g) => Some(g),
                    Err(TryLockError::Poisoned(p)) => Some(p.into_inner()),
                    Err(TryLockError::WouldBlock) => None,
                }
            } else {
                Some(lock(&self.sync_gate))
            };
            if let Some(_g) = gate {
                self.sync_now()?;
            }
        }
        self.believable()
    }

    fn sync_now(&self) -> Result<()> {
        self.signal.tip_dirty.store(false, Ordering::SeqCst);
        let live = self.live()?;
        let results = Self::each(&live, |c| self.sync_from(c));
        let mut i = self.st();
        let mut off_chain = Vec::new();
        for (c, r) in live.iter().zip(results) {
            match r {
                Ok(()) => {}
                Err(SyncFail::OffCheckpoint(e)) => {
                    i.flag(&c.url, format!("headers: {e}"));
                    off_chain.push(format!("{}: {e}", c.url));
                }
                Err(SyncFail::Other(e)) => i.flag(&c.url, format!("headers: {e}")),
            }
        }
        i.last_sync = Some(Instant::now());
        if i.headers.ready() {
            let Inner { headers, servers, .. } = &mut *i;
            for st in servers.values_mut() {
                if let (Some(t), Some(th)) = (st.tip, st.tip_hash.as_ref()) {
                    st.on_best_chain = Some(headers.at(t).map(|h| &h.hash_hex() == th).unwrap_or(false));
                }
            }
        } else if !off_chain.is_empty() {
            let cp = hex::encode(self.cp.1);
            return err(Kind::CheckpointMismatch, format!("no server is on the {} checkpoint {}:{}.. ({})",
                                                         self.chain, self.cp.0, &cp[..16], off_chain.join("; ")));
        }
        Ok(())
    }

    /// Our tip, if the chain can be answered from.
    fn believable(&self) -> Result<u32> {
        let i = self.st();
        if !i.headers.ready() {
            return err(Kind::NotFound, "no Electrum server served the pinned checkpoint");
        }
        if let Some(why) = self.implausible(&i) {
            return err(Kind::Implausible, format!("the verified chain is not believable yet: {why}"));
        }
        Ok(i.tip_height())
    }

    fn implausible(&self, i: &Inner) -> Option<String> {
        let p = self.plausibility.as_ref()?;
        i.headers.implausible(p.min_work_above, Some((p.floor_spacing_s, p.floor_slack)))
    }

    fn header_at(&self, c: &Connection, height: u32) -> std::result::Result<header::Header, SyncFail> {
        let v = self.ask(c, "blockchain.block.header", json!([height]))?;
        let raw = hex::decode(v.as_str().unwrap_or("")).map_err(|_| SyncFail::Other("block.header: not hex".into()))?;
        let h = parse_header(&raw)?;
        if h.height != height {
            return Err(SyncFail::Other(format!("block.header {height} commits height {}", h.height)));
        }
        Ok(h)
    }

    /// The checkpoint header and the headers below it that the median-time rule needs.
    fn fetch_checkpoint(&self, c: &Connection) -> std::result::Result<(), SyncFail> {
        let off = |e: String| SyncFail::OffCheckpoint(e);
        let (cp, n) = (self.cp.0, self.st().headers.prior_needed());
        let raw = match self.header_at(c, cp) {
            Ok(h) => h.raw,
            Err(SyncFail::Other(e)) | Err(SyncFail::OffCheckpoint(e)) => return Err(off(e)),
        };
        let mut prior: Vec<Vec<u8>> = Vec::new();
        if n > 0 {
            let a = self.ask(c, "blockchain.block.headers", json!([cp - n, n])).map_err(|e| off(e.msg))?;
            let blob = hex::decode(a.get("hex").and_then(Value::as_str).unwrap_or("")).map_err(|_| off("block.headers: not hex".into()))?;
            prior = split_headers(&blob).map_err(|e| off(e.to_string()))?.into_iter().map(<[u8]>::to_vec).collect();
        }
        let mut i = self.st();
        if !i.headers.ready() {
            i.headers.set_checkpoint(&raw, &prior).map_err(|e| off(e.to_string()))?;
        }
        Ok(())
    }

    fn sync_from(&self, c: &Connection) -> std::result::Result<(), SyncFail> {
        let tip = c.subscribe("blockchain.headers.subscribe", json!([])).map_err(|e| SyncFail::Other(e.msg))?;
        let th = tip.get("height").and_then(Value::as_u64).and_then(|h| u32::try_from(h).ok())
            .ok_or_else(|| SyncFail::Other("headers.subscribe: no height".into()))?;
        let tip_raw = hex::decode(tip.get("hex").and_then(Value::as_str).unwrap_or(""))
            .map_err(|_| SyncFail::Other("headers.subscribe: not hex".into()))?;
        let tip_h = parse_header(&tip_raw)?;
        {
            let mut i = self.st();
            let st = i.servers.entry(c.url.clone()).or_default();
            st.tip = Some(th);
            st.tip_hash = Some(tip_h.hash_hex());
        }
        let cp = self.cp.0;
        if th < cp {
            return Err(SyncFail::OffCheckpoint(format!("server tip {th} is below the checkpoint {cp}")));
        }
        if tip_h.height != th {
            return Err(SyncFail::Other(format!("tip at {th} commits height {}", tip_h.height)));
        }
        let ready = self.st().headers.ready();
        header::check_pow(&tip_h, &self.rules).map_err(|e| {
            // before we hold a chain, a tip outside our powLimit is another chain
            let why = format!("tip at {th}: {e}");
            if ready { SyncFail::Other(why) } else { SyncFail::OffCheckpoint(why) }
        })?;
        if !ready {
            self.fetch_checkpoint(c)?;
        }
        let (ours, our_time, on_ours) = {
            let i = self.st();
            let t = i.headers.tip().map(|h| h.time as u64).unwrap_or(0);
            (i.tip_height(), t, i.headers.at(th).map(|h| h.hash == tip_h.hash).unwrap_or(false))
        };
        if on_ours {
            return Ok(());
        }
        let elapsed = (self.clock)().saturating_sub(our_time);
        let cap = self.tip_cap_spacing_s.map_or(u32::MAX, |s| {
            (ours as u64 + elapsed / s.max(1) + HEADERS_CHUNK as u64).min(u32::MAX as u64) as u32
        });
        let end = th.min(cap);
        if th > cap {
            self.flag(&c.url, format!("headers: claims tip {th}, beyond the plausible {cap}: nothing above it is fetched"));
        }
        // the highest height where the server agrees with us (the checkpoint at worst)
        let (mut h, mut step) = (end.min(ours), 1u32);
        while h > cp {
            let theirs = self.header_at(c, h)?;
            if self.st().headers.at(h).map(|m| m.hash == theirs.hash).unwrap_or(false) {
                break;
            }
            h = h.saturating_sub(step).max(cp);
            step = step.saturating_mul(2);
        }
        let mut b = self.st().headers.branch(h)?;
        let mut start = h + 1;
        let mut bad = None;
        'fetch: while start <= end {
            let mut reqs = Vec::new();
            let mut s = start;
            while s <= end && (reqs.len() as u32) < CHUNKS_PER_BATCH {
                let n = HEADERS_CHUNK.min(end - s + 1);
                reqs.push(("blockchain.block.headers".to_string(), json!([s, n])));
                s += n;
            }
            let answers = c.batch(&reqs).map_err(|e| SyncFail::Other(e.msg))?;
            for a in answers {
                let a = a.map_err(|e| SyncFail::Other(format!("block.headers: {e}")))?;
                let blob = hex::decode(a.get("hex").and_then(Value::as_str).unwrap_or(""))
                    .map_err(|_| SyncFail::Other("block.headers: not hex".into()))?;
                let chunk = split_headers(&blob)?;
                if chunk.is_empty() {
                    break 'fetch; // withheld: keep what we have, most work still decides
                }
                let before = b.len();
                let r = b.extend(&chunk);
                start += (b.len() - before) as u32;
                if let Err(e) = r {
                    bad = Some(e);
                    break 'fetch;
                }
            }
        }
        if !b.is_empty() {
            self.st().headers.adopt(b)?;
        }
        if let Some(e) = bad {
            return Err(SyncFail::Other(format!("block.headers: {e} (the headers before it were kept)")));
        }
        if start <= end {
            // most work still decides; this server just cannot back the tip it claims
            return Err(SyncFail::Other(format!("withheld headers: served up to {}, claims tip {th}", start - 1)));
        }
        Ok(())
    }

    /// `(height, display hex)` of the pinned checkpoint.
    pub fn checkpoint(&self) -> (u32, String) {
        (self.cp.0, hex::encode(self.cp.1))
    }

    // --- verified transactions -----------------------------------------------------------------

    /// A raw tx counts only if it re-serializes byte for byte and hashes to the txid asked for.
    fn verify_raw(txid: &str, raw: &Value) -> Option<Tx> {
        let s = raw.as_str()?;
        let tx = Tx::parse_hex(s).ok()?;
        (tx.to_hex() == s.to_ascii_lowercase() && tx.txid() == txid).then_some(tx)
    }

    fn fetch_tx(&self, txid: &str) -> Result<Option<Tx>> {
        let txid = txid.to_ascii_lowercase();
        if let Some(t) = self.st().txs.get(&txid) {
            return Ok(Some(t.clone()));
        }
        for c in self.live()? {
            // "not found" is an answer, not a fault
            let Ok(raw) = c.request("blockchain.transaction.get", json!([txid])) else { continue };
            match Self::verify_raw(&txid, &raw) {
                Some(tx) => {
                    self.st().txs.insert(txid, tx.clone());
                    return Ok(Some(tx));
                }
                None => self.flag(&c.url, format!("transaction.get {}: not the transaction asked for", &txid[..16.min(txid.len())])),
            }
        }
        Ok(None)
    }

    /// Several transactions: one batch to the first live server, then one by one for the rest.
    fn fetch_txs(&self, txids: &[String]) -> Result<()> {
        let missing: Vec<String> = {
            let i = self.st();
            txids.iter().filter(|t| !i.txs.contains_key(*t)).cloned().collect()
        };
        if missing.len() > 1 {
            if let Some(c) = self.live()?.first().cloned() {
                let reqs: Vec<(String, Value)> = missing.iter().map(|t| ("blockchain.transaction.get".to_string(), json!([t]))).collect();
                if let Ok(answers) = c.batch(&reqs) {
                    let mut i = self.st();
                    for (t, a) in missing.iter().zip(answers) {
                        let Ok(raw) = a else { continue };
                        match Self::verify_raw(t, &raw) {
                            Some(tx) => {
                                i.txs.insert(t.clone(), tx);
                            }
                            None => i.flag(&c.url, format!("transaction.get {}: not the transaction asked for", &t[..16])),
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// txid -> [(server, claimed height)], the union over every live server.
    fn history(&self, spk: &[u8]) -> Result<HashMap<String, Claims>> {
        let sh = scripthash(spk);
        let live = self.live()?;
        let answers = Self::each(&live, |c| c.request("blockchain.scripthash.get_history", json!([sh])));
        let mut out: HashMap<String, Claims> = HashMap::new();
        let mut i = self.st();
        for (c, a) in live.iter().zip(answers) {
            let hist = match a {
                Ok(h) => h,
                Err(e) => {
                    i.flag(&c.url, format!("get_history: {e}"));
                    continue;
                }
            };
            for e in hist.as_array().map(Vec::as_slice).unwrap_or(&[]) {
                match (e.get("tx_hash").and_then(Value::as_str), e.get("height").and_then(Value::as_i64)) {
                    (Some(t), Some(h)) if t.len() == 64 && t.chars().all(|x| x.is_ascii_hexdigit()) => {
                        out.entry(t.to_ascii_lowercase()).or_default().push((c.clone(), h));
                    }
                    _ => i.flag(&c.url, "get_history: malformed entry"),
                }
            }
        }
        Ok(out)
    }

    /// A cached proof, if its block is still on our best chain (dropped if it was reorged out).
    fn cached_conf(&self, txid: &str) -> Option<TxStatus> {
        let mut i = self.st();
        let c = i.conf.get(txid).copied()?;
        if i.conf_holds(&c) {
            return Some(TxStatus::Confirmed { height: c.0, block_hash: c.1 });
        }
        i.conf.remove(txid);
        None
    }

    /// Confirmed once a Merkle proof ties `txid` to our header at a claimed height; Mempool if
    /// only mempool claims remain; None if no claim holds.
    fn confirmed(&self, txid: &str, claims: &[(Arc<Connection>, i64)]) -> Result<Option<TxStatus>> {
        if let Some(st) = self.cached_conf(txid) {
            return Ok(Some(st));
        }
        let txid_b = hex32(txid).map_err(|e| ElectrumError::new(Kind::BadRequest, e.to_string()))?;
        let mut tried = BTreeSet::new();
        let mut mempool = false;
        for (c, height) in claims {
            if *height <= 0 {
                mempool = true;
                continue;
            }
            let Ok(height) = u32::try_from(*height) else { continue };
            if !tried.insert((c.url.clone(), height)) {
                continue;
            }
            let mut hdr = self.st().headers.at(height).cloned();
            if hdr.is_none() {
                self.sync(true)?;
                hdr = self.st().headers.at(height).cloned();
            }
            let Some(hdr) = hdr else { continue }; // a height beyond our best chain: not proven
            let m = match self.ask(c, "blockchain.transaction.get_merkle", json!([txid, height])) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let branch: Option<Vec<[u8; 32]>> = m.get("merkle").and_then(Value::as_array).and_then(|a| {
                a.iter().map(|x| x.as_str().and_then(|s| hex32(s).ok())).collect()
            });
            let pos = m.get("pos").and_then(Value::as_u64);
            let (Some(branch), Some(pos)) = (branch, pos) else {
                self.flag(&c.url, format!("get_merkle {}@{height}: malformed", &txid[..16]));
                continue;
            };
            let root = match merkle_root_from_proof(&txid_b, &branch, pos, Some(hdr.txcount as u32)) {
                Ok(r) => r,
                Err(e) => {
                    self.flag(&c.url, format!("get_merkle {}@{height}: {e}", &txid[..16]));
                    continue;
                }
            };
            let bh = m.get("block_height").and_then(Value::as_u64).unwrap_or(height as u64);
            if root != hdr.merkle_root || bh != height as u64 {
                self.flag(&c.url, format!("get_merkle {}@{height}: proof does not reach our header", &txid[..16]));
                continue;
            }
            let mut i = self.st();
            if !i.conf_holds(&(height, hdr.hash)) {
                continue; // reorged out while we asked
            }
            i.conf.insert(txid.to_string(), (height, hdr.hash));
            return Ok(Some(TxStatus::Confirmed { height, block_hash: hdr.hash }));
        }
        Ok(mempool.then_some(TxStatus::Mempool))
    }

    /// Scripts whose history lists this tx: its outputs (OP_RETURN has no history).
    fn index_spks(tx: &Tx) -> Vec<Vec<u8>> {
        tx.outputs.iter().filter(|o| !o.script_pubkey.is_empty() && o.script_pubkey[0] != 0x6A)
            .take(2).map(|o| o.script_pubkey.clone()).collect()
    }

    fn locate(&self, txid: &str) -> Result<(Option<Tx>, Option<TxStatus>)> {
        let txid = txid.to_ascii_lowercase();
        let Some(tx) = self.fetch_tx(&txid)? else { return Ok((None, None)) };
        if let Some(st) = self.cached_conf(&txid) {
            return Ok((Some(tx), Some(st)));
        }
        for spk in Self::index_spks(&tx) {
            let hist = self.history(&spk)?;
            if let Some(claims) = hist.get(&txid) {
                let st = self.confirmed(&txid, claims)?;
                return Ok((Some(tx), st));
            }
        }
        Ok((Some(tx), None))
    }

    /// (spending txid, its status) from the union of the script's histories: the spend parsed
    /// from the spending transaction itself. A mempool spend is returned only with `mempool`.
    fn spender(&self, txid: &str, vout: u32, spk: &[u8], mempool: bool) -> Result<Option<(String, TxStatus)>> {
        let hist = self.history(spk)?;
        let others: Vec<String> = hist.keys().filter(|t| t.as_str() != txid).cloned().collect();
        self.fetch_txs(&others)?;
        let mut found = None;
        for t in others {
            let Some(stx) = self.fetch_tx(&t)? else { continue };
            if !stx.inputs.iter().any(|i| i.prevout.txid_hex() == txid && i.prevout.vout == vout) {
                continue;
            }
            match self.confirmed(&t, &hist[&t])? {
                Some(st @ TxStatus::Confirmed { .. }) => return Ok(Some((t, st))),
                Some(TxStatus::Mempool) if mempool => found = Some((t, TxStatus::Mempool)),
                _ => {}
            }
        }
        Ok(found)
    }

    // --- the typed API -------------------------------------------------------------------------

    pub fn block_count(&self) -> Result<u32> {
        self.sync(false)
    }

    /// Our header at `height` (display hex hash).
    pub fn block_hash(&self, height: u32) -> Result<String> {
        let tip = self.sync(false)?;
        self.st().headers.at(height).map(|h| h.hash_hex()).ok_or_else(|| {
            ElectrumError::new(Kind::NotFound, format!("Block height {height} out of range (verified chain {}..{tip})", self.cp.0))
        })
    }

    /// The transaction and where it is. None if no server shows it (or no claim about it holds).
    pub fn transaction(&self, txid: &str) -> Result<Option<(Tx, TxStatus)>> {
        self.sync(false)?;
        Ok(match self.locate(txid)? {
            (Some(tx), Some(st)) => Some((tx, st)),
            _ => None,
        })
    }

    /// `gettxout`. An output counts as spent only when a confirmed spend is proven: a spend seen
    /// only in a mempool never hides it (so a lying server cannot talk a payer out of a refund).
    pub fn tx_out(&self, txid: &str, vout: u32, include_mempool: bool) -> Result<Option<TxOutInfo>> {
        let txid = txid.to_ascii_lowercase();
        self.sync(false)?;
        let (Some(tx), Some(st)) = self.locate(&txid)? else { return Ok(None) };
        let Some(out) = tx.outputs.get(vout as usize).cloned() else { return Ok(None) };
        if st == TxStatus::Mempool && !include_mempool {
            return Ok(None);
        }
        if self.spender(&txid, vout, &out.script_pubkey, false)?.is_some() {
            return Ok(None);
        }
        let i = self.st();
        let tip = i.tip_height();
        let confirmations = match st {
            TxStatus::Confirmed { height, .. } => (tip + 1).saturating_sub(height),
            TxStatus::Mempool => 0,
        };
        Ok(Some(TxOutInfo {
            best_block: i.headers.tip().map(|h| h.hash_hex()).unwrap_or_default(),
            confirmations,
            value: out.value.max(0) as u64,
            script_pubkey: out.script_pubkey,
            coinbase: is_coinbase(&tx),
        }))
    }

    /// `gettxspendingprevout` for one outpoint: the spending txid, mempool spends included (a
    /// hint for the watcher; [`Self::tx_out`] is what decides).
    pub fn spending_tx(&self, txid: &str, vout: u32) -> Result<Option<(String, TxStatus)>> {
        let txid = txid.to_ascii_lowercase();
        self.sync(false)?;
        let Some(tx) = self.fetch_tx(&txid)? else { return Ok(None) };
        let Some(out) = tx.outputs.get(vout as usize) else { return Ok(None) };
        let spk = out.script_pubkey.clone();
        self.spender(&txid, vout, &spk, true)
    }

    /// Broadcast to every live server. Ok once one accepts it (and answers with its txid).
    pub fn broadcast(&self, hex_tx: &str) -> Result<String> {
        let tx = Tx::parse_hex(hex_tx).map_err(|e| ElectrumError::new(Kind::BadRequest, format!("TX decode failed: {e}")))?;
        let txid = tx.txid();
        let live = self.live()?;
        let answers = Self::each(&live, |c| c.request("blockchain.transaction.broadcast", json!([hex_tx])));
        let (mut errors, mut accepted) = (Vec::new(), false);
        let mut i = self.st();
        for (c, a) in live.iter().zip(answers) {
            match a {
                Ok(v) if v.as_str().map(str::to_ascii_lowercase).as_deref() == Some(txid.as_str()) => accepted = true,
                Ok(_) => i.flag(&c.url, "broadcast answered another txid"),
                Err(e) => errors.push(e),
            }
        }
        if !accepted {
            // every server refused it: the node's reason, as sendrawtransaction gives it
            return Err(errors.into_iter().next().unwrap_or_else(|| ElectrumError::new(Kind::Server, "no server accepted the transaction")));
        }
        i.txs.entry(txid.clone()).or_insert(tx);
        Ok(txid)
    }

    /// `scantxoutset raw(spk)`: the script's confirmed, proven, unspent coins, from the union of
    /// every server's unspent list.
    pub fn unspent(&self, spk: &[u8]) -> Result<Vec<Utxo>> {
        self.sync(false)?;
        let sh = scripthash(spk);
        let live = self.live()?;
        let answers = Self::each(&live, |c| c.request("blockchain.scripthash.listunspent", json!([sh])));
        let mut claims: HashMap<(String, u32), Claims> = HashMap::new();
        {
            let mut i = self.st();
            for (c, a) in live.iter().zip(answers) {
                let Ok(list) = a else { continue };
                for u in list.as_array().map(Vec::as_slice).unwrap_or(&[]) {
                    match (u.get("tx_hash").and_then(Value::as_str), u.get("tx_pos").and_then(Value::as_u64), u.get("height").and_then(Value::as_i64)) {
                        (Some(t), Some(n), Some(h)) if t.len() == 64 && n <= u32::MAX as u64 => {
                            claims.entry((t.to_ascii_lowercase(), n as u32)).or_default().push((c.clone(), h));
                        }
                        _ => i.flag(&c.url, "listunspent: malformed entry"),
                    }
                }
            }
        }
        let mut keys: Vec<(String, u32)> = claims.keys().cloned().collect();
        keys.sort();
        let txids: Vec<String> = keys.iter().map(|k| k.0.clone()).collect();
        self.fetch_txs(&txids)?;
        let mut out = Vec::new();
        for (txid, n) in keys {
            let Some(tx) = self.fetch_tx(&txid)? else { continue };
            match tx.outputs.get(n as usize) {
                Some(o) if o.script_pubkey == spk => {}
                _ => continue,
            }
            let Some(TxStatus::Confirmed { height, block_hash }) = self.confirmed(&txid, &claims[&(txid.clone(), n)])? else {
                continue; // the UTXO set holds confirmed coins only
            };
            if self.spender(&txid, n, spk, false)?.is_some() {
                continue;
            }
            out.push(Utxo { txid, vout: n, value: tx.outputs[n as usize].value.max(0) as u64, script_pubkey: spk.to_vec(), height,
                           block_hash: hex::encode(block_hash), coinbase: is_coinbase(&tx) });
        }
        Ok(out)
    }

    /// Unverifiable: the median of the servers' answers.
    pub fn estimate_fee(&self, blocks: u32) -> Result<FeeEstimate> {
        let live = self.live()?;
        let answers = Self::each(&live, |c| c.request("blockchain.estimatefee", json!([blocks])));
        let mut fees = Vec::new();
        let mut any = false;
        let mut i = self.st();
        for (c, a) in live.iter().zip(answers) {
            match a.map(|v| v.as_f64()) {
                Ok(Some(f)) if f.is_finite() => {
                    any = true;
                    if f > 0.0 {
                        fees.push(f);
                    }
                }
                Ok(_) => i.flag(&c.url, "estimatefee: not a number"),
                Err(e) => i.flag(&c.url, format!("estimatefee: {e}")),
            }
        }
        if !any {
            return err(Kind::Unreachable, "no server answered estimatefee");
        }
        fees.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
        let feerate = match fees.len() {
            0 => None,
            n if n % 2 == 1 => Some(fees[n / 2]),
            n => Some((fees[n / 2 - 1] + fees[n / 2]) / 2.0),
        };
        Ok(FeeEstimate { feerate, blocks, answers: fees })
    }

    // --- subscriptions (a watcher wakes on them) -------------------------------------------------

    /// Subscribe every live server to these scripts: a change (a close, a refund, a funding
    /// confirming) wakes [`Self::wait_for_change`]. Returns how many scripts are watched.
    pub fn watch(&self, spks: &[&[u8]]) -> Result<usize> {
        let new: Vec<String> = {
            let i = self.st();
            spks.iter().map(|s| scripthash(s)).filter(|sh| !i.watched.contains(sh)).collect()
        };
        if !new.is_empty() {
            let reqs: Vec<(String, Value)> = new.iter().map(|sh| ("blockchain.scripthash.subscribe".to_string(), json!([sh]))).collect();
            let live = self.live()?;
            let answers = Self::each(&live, |c| c.subscribe_many(&reqs));
            let mut i = self.st();
            for (c, a) in live.iter().zip(answers) {
                match a {
                    Ok(rs) => {
                        for r in rs {
                            if let Err(e) = r {
                                i.flag(&c.url, format!("subscribe: {e}"));
                            }
                        }
                    }
                    Err(e) => i.flag(&c.url, format!("subscribe: {e}")),
                }
            }
            i.watched.extend(new);
        }
        Ok(self.st().watched.len())
    }

    /// Block until a subscribed script or the tip changes, or `timeout`. True if something did.
    pub fn wait_for_change(&self, timeout: Duration) -> bool {
        let g = lock(&self.signal.changed);
        let (mut g, _) = self.signal.cv.wait_timeout_while(g, timeout, |c| !*c).unwrap_or_else(|p| p.into_inner());
        std::mem::replace(&mut *g, false)
    }

    /// Checkpoint, tip, tip age, whether the chain is believable yet (and why not), each server's tip
    /// and whether it is on our best chain, errors, the scripts watched and the last verification failures.
    pub fn status(&self) -> Value {
        let i = self.st();
        let (cp_h, cp) = self.cp;
        let tip = i.headers.tip();
        let tip_age = tip.map(|t| now_s().saturating_sub(t.time as u64));
        let servers: Vec<Value> = self.conns.iter().map(|c| {
            let st = i.servers.get(&c.url).cloned().unwrap_or_default();
            json!({"url": c.url, "connected": c.connected(), "server": st.server, "proto": st.proto, "tip": st.tip,
                   "tip_hash": st.tip_hash, "on_best_chain": st.on_best_chain, "errors": st.errors, "last_error": st.last_error})
        }).collect();
        let flags: Vec<Value> = i.flags.iter().rev().take(10).rev()
            .map(|f| json!({"server": f.server, "reason": f.reason, "t": f.t})).collect();
        let implausible = if i.headers.ready() { self.implausible(&i) } else { None };
        json!({"backend": "electrum", "chain": self.chain, "checkpoint": [cp_h, hex::encode(cp)],
               "tip": tip.map(|_| i.tip_height()), "tip_hash": tip.map(|t| t.hash_hex()), "tip_age_s": tip_age,
               "tip_stale": tip_age.map(|a| self.chain == "main" && a > STALE_TIP_S).unwrap_or(false),
               "implausible": implausible,
               "min_servers": self.min_servers, "watched_scripts": i.watched.len(), "servers": servers,
               "verification_failures": flags})
    }

    /// Every verification failure so far (at most the last 50).
    pub fn flags(&self) -> Vec<Flag> {
        self.st().flags.iter().cloned().collect()
    }

    pub fn close(&self) {
        for c in &self.conns {
            c.close();
        }
    }

    // --- the node-RPC surface (B2's `call`) ------------------------------------------------------

    fn address(&self, spk: &[u8]) -> Option<String> {
        let segwit = matches!(spk.len(), 22 | 34) && matches!(spk[0], 0x00 | 0x51) && spk[1] as usize == spk.len() - 2;
        if segwit { segwit_address(self.hrp, spk).ok() } else { None }
    }

    fn spk_json(&self, spk: &[u8]) -> Value {
        let mut m = Map::new();
        m.insert("hex".into(), hex::encode(spk).into());
        if let Some(a) = self.address(spk) {
            m.insert("address".into(), a.into());
        }
        Value::Object(m)
    }

    fn verbose(&self, tx: &Tx, st: TxStatus, tip: u32) -> Value {
        let cb = is_coinbase(tx);
        let vin: Vec<Value> = tx.inputs.iter().map(|i| if cb {
            json!({"coinbase": hex::encode(&i.script_sig)})
        } else {
            let mut v = json!({"txid": i.prevout.txid_hex(), "vout": i.prevout.vout,
                               "scriptSig": {"hex": hex::encode(&i.script_sig)}, "sequence": i.sequence});
            if !i.witness.is_empty() {
                v["txinwitness"] = i.witness.iter().map(hex::encode).collect::<Vec<_>>().into();
            }
            v
        }).collect();
        let vout: Vec<Value> = tx.outputs.iter().enumerate().map(|(n, o)| {
            json!({"n": n, "value": o.value as f64 / SATS, "scriptPubKey": self.spk_json(&o.script_pubkey)})
        }).collect();
        let mut d = json!({"txid": tx.txid(), "hex": tx.to_hex(), "vin": vin, "vout": vout});
        match st {
            TxStatus::Confirmed { height, block_hash } => {
                d["blockhash"] = hex::encode(block_hash).into();
                d["height"] = height.into();
                d["confirmations"] = (tip + 1).saturating_sub(height).into();
            }
            TxStatus::Mempool => d["confirmations"] = 0.into(),
        }
        d
    }

    /// The node RPCs of the client path, answered as the node answers them (B2's `ElectrumBackend.call`):
    /// getblockchaininfo, getblockcount, getblockhash, getblockheader, gettxout, gettxspendingprevout,
    /// getrawtransaction, sendrawtransaction, scantxoutset (raw descriptors), estimatesmartfee.
    /// Node-only RPCs (the wallet, blocks, mining) are refused with [`Kind::LightBackend`].
    pub fn call(&self, method: &str, params: &Value) -> Result<Value> {
        let m = method.to_ascii_lowercase();
        let p = params.as_array().cloned().unwrap_or_default();
        let arg = |k: usize| p.get(k).cloned().unwrap_or(Value::Null);
        let bad = |what: &str| ElectrumError::new(Kind::BadRequest, format!("{method}: {what}"));
        if NODE_ONLY.contains(&m.as_str()) {
            return err(Kind::LightBackend, format!("{method} needs a full node: not available on the light Electrum backend"));
        }
        match m.as_str() {
            "getblockchaininfo" => {
                let tip = self.sync(false)?;
                let hash = self.block_hash(tip)?;
                Ok(json!({"chain": self.chain, "blocks": tip, "headers": tip, "bestblockhash": hash,
                          "initialblockdownload": false, "pruned": true, "light": true, "backend": "electrum"}))
            }
            "getblockcount" => Ok(self.sync(false)?.into()),
            "getblockhash" => {
                let h = arg(0).as_u64().and_then(|h| u32::try_from(h).ok()).ok_or_else(|| bad("height"))?;
                Ok(self.block_hash(h)?.into())
            }
            "getblockheader" => {
                let hash = hex32(arg(0).as_str().unwrap_or("")).map_err(|_| bad("block hash"))?;
                let verbose = arg(1).as_bool().unwrap_or(true);
                self.sync(false)?;
                let i = self.st();
                let tip = i.tip_height();
                let height = i.headers.height_of(&hash).ok_or_else(|| ElectrumError::new(Kind::NotFound, "Block not found"))?;
                let h = i.headers.at(height).ok_or_else(|| ElectrumError::new(Kind::NotFound, "Block not found"))?;
                if !verbose {
                    return Ok(hex::encode(&h.raw).into());
                }
                let mut root = h.merkle_root;
                root.reverse();
                let mut d = json!({"hash": h.hash_hex(), "height": height, "confirmations": (tip + 1).saturating_sub(height), "time": h.time,
                                   "bits": format!("{:08x}", h.bits), "nTx": h.txcount, "merkleroot": hex::encode(root)});
                if let Some(prev) = height.checked_sub(1).and_then(|ph| i.headers.at(ph)) {
                    d["previousblockhash"] = prev.hash_hex().into();
                }
                Ok(d)
            }
            "gettxout" => {
                let txid = arg(0).as_str().ok_or_else(|| bad("txid"))?.to_string();
                let vout = arg(1).as_u64().and_then(|v| u32::try_from(v).ok()).ok_or_else(|| bad("vout"))?;
                let mempool = arg(2).as_bool().unwrap_or(true);
                Ok(match self.tx_out(&txid, vout, mempool)? {
                    None => Value::Null,
                    Some(o) => json!({"bestblock": o.best_block, "confirmations": o.confirmations, "value": o.value as f64 / SATS,
                                      "scriptPubKey": self.spk_json(&o.script_pubkey), "coinbase": o.coinbase}),
                })
            }
            "gettxspendingprevout" => {
                let mut res = Vec::new();
                for op in arg(0).as_array().cloned().unwrap_or_default() {
                    let txid = op.get("txid").and_then(Value::as_str).ok_or_else(|| bad("txid"))?.to_ascii_lowercase();
                    let vout = op.get("vout").and_then(Value::as_u64).and_then(|v| u32::try_from(v).ok()).ok_or_else(|| bad("vout"))?;
                    let mut row = json!({"txid": txid, "vout": vout});
                    // as the node answers it: the mempool only (a confirmed spend shows as a spent gettxout)
                    if let Some((sp, TxStatus::Mempool)) = self.spending_tx(&txid, vout)? {
                        row["spendingtxid"] = sp.into();
                    }
                    res.push(row);
                }
                Ok(Value::Array(res))
            }
            "getrawtransaction" => {
                let txid = arg(0).as_str().ok_or_else(|| bad("txid"))?.to_string();
                let verbose = match arg(1) {
                    Value::Bool(b) => b,
                    Value::Number(n) => n.as_u64().unwrap_or(0) > 0,
                    _ => false,
                };
                let Some((tx, st)) = self.transaction(&txid)? else {
                    return err(Kind::NotFound, "No such mempool or blockchain transaction");
                };
                if let Some(bh) = arg(2).as_str() {
                    let ok = matches!(st, TxStatus::Confirmed { block_hash, .. } if hex::encode(block_hash) == bh.to_ascii_lowercase());
                    if !ok {
                        return err(Kind::NotFound, "No such transaction found in the provided block");
                    }
                }
                if !verbose {
                    return Ok(tx.to_hex().into());
                }
                let tip = self.st().tip_height();
                Ok(self.verbose(&tx, st, tip))
            }
            "sendrawtransaction" => Ok(self.broadcast(arg(0).as_str().ok_or_else(|| bad("hex"))?)?.into()),
            "scantxoutset" => {
                if arg(0).as_str() != Some("start") {
                    return Err(bad("only 'start'"));
                }
                let mut unspents = Vec::new();
                let mut total = 0u64;
                for desc in arg(1).as_array().cloned().unwrap_or_default() {
                    let d = desc.as_str().map(str::to_string)
                        .or_else(|| desc.get("desc").and_then(Value::as_str).map(str::to_string)).unwrap_or_default();
                    let spk = d.strip_prefix("raw(").and_then(|r| r.strip_suffix(')')).and_then(|h| hex::decode(h).ok())
                        .ok_or_else(|| bad(&format!("the light backend takes raw(<script>) descriptors, not {d:?}")))?;
                    for u in self.unspent(&spk)? {
                        total += u.value;
                        unspents.push(json!({"txid": u.txid, "vout": u.vout, "scriptPubKey": hex::encode(&u.script_pubkey), "desc": d,
                                             "amount": u.value as f64 / SATS, "coinbase": u.coinbase, "height": u.height,
                                             "blockhash": u.block_hash}));
                    }
                }
                let i = self.st();
                Ok(json!({"success": true, "height": i.tip_height(), "bestblock": i.headers.tip().map(|h| h.hash_hex()),
                          "unspents": unspents, "total_amount": total as f64 / SATS}))
            }
            "estimatesmartfee" => {
                let blocks = arg(0).as_u64().unwrap_or(1).clamp(1, 1008) as u32;
                let f = self.estimate_fee(blocks)?;
                Ok(match f.feerate {
                    Some(r) => json!({"feerate": r, "blocks": blocks, "source": "electrum (unverified)", "servers": f.answers.len()}),
                    None => json!({"errors": ["Insufficient data or no feerate found"], "blocks": blocks}),
                })
            }
            _ => err(Kind::LightBackend, format!("{method} is not served by the light Electrum backend")),
        }
    }
}

impl ChainBackend for ElectrumBackend {
    fn block_count(&self) -> xbt402::Result<u32> {
        Ok(ElectrumBackend::block_count(self)?)
    }

    fn get_tx_out(&self, txid: &str, vout: u32, include_mempool: bool) -> xbt402::Result<Option<UtxoInfo>> {
        Ok(self.tx_out(txid, vout, include_mempool)?.map(|o| UtxoInfo {
            confirmations: o.confirmations,
            value: o.value,
            script_pubkey: o.script_pubkey,
            coinbase: o.coinbase,
        }))
    }

    fn send_raw_transaction(&self, hex: &str) -> xbt402::Result<String> {
        Ok(self.broadcast(hex)?)
    }

    fn has_transaction(&self, txid: &str) -> xbt402::Result<bool> {
        Ok(self.transaction(txid)?.is_some())
    }
}
