//! A Rust RoutePayer on a regtest node, for route_interop.sh: one ch1 to the hub, sessions on
//! every shard, `--rate` calls/s per shard for `--seconds` with the per-window locks beside them,
//! a last lock pass, then a cooperative close of ch1. Prints a JSON summary on stdout.
//!
//! xbt402-route-payer --hub URL --shards URL,URL --rpc-port R --cookie PATH [--seconds 6] [--rate 10]
//!                    [--signer-sock PATH] [--ledger PATH [--no-close]]
//!
//! With `--signer-sock` the keys live in the Rust B2 signer (`xbt-signer`, AGP-034): the payer is an
//! `xbt_signer::client::RemoteSigner` (every adaptor lock under the signer's routing policy and
//! policy engine), ch1 is funded from the signer's hot key, and after the close the signer is told
//! (`xbt402_mark_closed`) so it counts the change.
//!
//! With `--ledger` (AGP-044) the payer keeps its state in a [`FileRouteLedger`] and resumes from it:
//! run it, SIGKILL it mid-window, run it again with the same ledger (and the same signer) and it
//! goes on with the same ch1 and the same provider sessions. `--no-close` skips the last pass and
//! the close (a run that is meant to be killed).
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::client::Wallet;
use xbt402::http::UreqTransport;
use xbt402::route_client::{FileRouteLedger, RoutePayer, RoutePayerConfig};
use xbt402::rpc::Rpc;
use xbt402::signer::{LocalSigner, RouteSigner};
use xbt_signer::client::RemoteSigner;
use xbt402::funding::ChainBackend;
use xbt_primitives::network::network_id;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

/// The node wallet, mining one block after each funding (regtest: the hub wants minConf 1).
struct MiningWallet(Rpc, String);

impl Wallet for MiningWallet {
    fn fund(&self, address: &str, sats: u64) -> xbt402::Result<(String, u32)> {
        let r = self.0.wallet("w").fund(address, sats)?;
        self.0.call("generatetoaddress", json!([1, self.1]))?;
        Ok(r)
    }
}

/// The signer's hot key funds; a block is mined for the hub's minConf 1 (regtest harness only).
struct SignerMiningWallet(RemoteSigner, Rpc, String);

impl Wallet for SignerMiningWallet {
    fn fund(&self, address: &str, sats: u64) -> xbt402::Result<(String, u32)> {
        let r = self.0.fund(address, sats)?;
        self.1.call("generatetoaddress", json!([1, self.2]))?;
        Ok(r)
    }

    fn fund_channel(&self, origin: &str, params: &xbt402::channel::ChannelParams, address: &str, sats: u64) -> xbt402::Result<(String, u32)> {
        let r = self.0.fund_channel(origin, params, address, sats)?;
        self.1.call("generatetoaddress", json!([1, self.2]))?;
        Ok(r)
    }
}

fn pct(xs: &mut [f64], q: f64) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    xs[((q * xs.len() as f64) as usize).min(xs.len() - 1)]
}

fn main() {
    let rpc = Rpc::from_cookie(&format!("http://127.0.0.1:{}", arg("--rpc-port").expect("--rpc-port")),
                               std::path::Path::new(&arg("--cookie").expect("--cookie"))).expect("cookie");
    let network = network_id(rpc.call("getblockhash", json!([101])).expect("block 101").as_str().expect("hash"));
    let addr = rpc.wallet("w").call("getnewaddress", json!([])).expect("address").as_str().unwrap().to_string();
    let remote = arg("--signer-sock").map(|s| RemoteSigner::new(std::path::Path::new(&s)));
    let (signer, wallet): (Arc<dyn RouteSigner>, Arc<dyn Wallet>) = match &remote {
        Some(r) => (Arc::new(r.clone()), Arc::new(SignerMiningWallet(r.clone(), rpc.clone(), addr))),
        None => (Arc::new(LocalSigner::new()), Arc::new(MiningWallet(rpc.clone(), addr))),
    };
    let node = rpc.clone();
    let mut pay = RoutePayer::new(&arg("--hub").expect("--hub"), RoutePayerConfig::new(&network), signer, wallet,
                                  Box::new(UreqTransport::default()), Box::new(move || node.block_count()));
    if let Some(l) = arg("--ledger") {
        pay = pay.with_ledger(Box::new(FileRouteLedger::open(std::path::Path::new(&l)).expect("ledger"))).expect("resume from the ledger");
    }
    let pay = Arc::new(pay);
    let no_close = std::env::args().any(|a| a == "--no-close");
    let ch1 = pay.open().expect("open ch1");
    let shards: Vec<_> = arg("--shards").expect("--shards").split(',').map(|u| pay.shard(u, "POST").expect("shard")).collect();
    let (secs, rate): (f64, f64) = (arg("--seconds").map(|s| s.parse().unwrap()).unwrap_or(6.0), arg("--rate").map(|s| s.parse().unwrap()).unwrap_or(10.0));
    let stop = Arc::new(AtomicBool::new(false));
    pay.start(Duration::from_millis(500));
    let t0 = Instant::now();
    let ths: Vec<_> = shards.iter().cloned().map(|sh| {
        let (pay, stop) = (pay.clone(), stop.clone());
        std::thread::spawn(move || {
            let (mut ok, mut next) = (0u64, Instant::now());
            while !stop.load(Ordering::Relaxed) {
                next += Duration::from_secs_f64(1.0 / rate);
                if pay.call(&sh, "POST", br#"{"tokens":1}"#).map(|r| r.status == 200).unwrap_or(false) {
                    ok += 1;
                }
                if let Some(d) = next.checked_duration_since(Instant::now()) {
                    std::thread::sleep(d);
                }
            }
            ok
        })
    }).collect();
    std::thread::sleep(Duration::from_secs_f64(secs));
    stop.store(true, Ordering::Relaxed);
    let ok: Vec<u64> = ths.into_iter().map(|t| t.join().unwrap()).collect();
    let dur = t0.elapsed().as_secs_f64();
    if no_close {
        pay.stop();
        println!("{}", json!({"impl": "rust", "ch1": ch1, "summary": pay.summary(), "okCalls": ok, "seconds": dur}));
        return;
    }
    // last pass: pay what is due now (the provider's credit window covers the tail otherwise)
    let until = Instant::now() + Duration::from_secs(8);
    while Instant::now() < until && (pay.pending().is_some() || shards.iter().any(|s| s.due_sat() > 0)) {
        std::thread::sleep(Duration::from_millis(300));
    }
    pay.stop();
    let close = pay.close().map_err(|e| e.to_string());
    // the Rust signer: learn ch1's close (change to the hot key), then its routing view and log
    let signer_view = remote.as_ref().map(|r| {
        let chan = pay.chan().unwrap_or_default();
        let txid = close.as_ref().ok().and_then(|c| c.get("txid")).and_then(Value::as_str).unwrap_or("").to_string();
        let mark = r.mark_closed(&chan, &txid).map_err(|e| e.to_string());
        let sigs = r.client.call("signatures", json!({"limit": 100000})).unwrap_or(Value::Null);
        let kinds: Vec<Value> = sigs.get("signatures").and_then(Value::as_array).into_iter().flatten()
            .map(|x| json!([x["kind"], x["method"], x["rule"]])).collect();
        json!({"health": r.client.call("health", json!({})).ok(), "routing": r.client.call("routing_status", json!({})).ok(),
               "hot": r.client.call("hot_address", json!({})).ok(), "mark_closed": mark.unwrap_or_else(|e| json!({"error": e})),
               "signatures": kinds, "chain_ok": sigs.get("chain_ok")})
    });
    let mut lock_ms: Vec<f64> = shards.iter().flat_map(|s| s.snapshot().lock_ms).collect();
    let mut call_ms: Vec<f64> = shards.iter().flat_map(|s| s.snapshot().call_ms).collect();
    let out = json!({"impl": "rust", "ch1": ch1, "ch1Params": pay.ch1_params().map(|p| p.to_json()), "close": close.unwrap_or_else(|e| json!({"error": e})),
                     "summary": pay.summary(), "okCalls": ok, "seconds": dur,
                     "lockMs": {"n": lock_ms.len(), "p50": pct(&mut lock_ms, 0.5), "p95": pct(&mut lock_ms, 0.95)},
                     "callMs": {"n": call_ms.len(), "p50": pct(&mut call_ms, 0.5), "p95": pct(&mut call_ms, 0.95)},
                     "events": *pay.events.lock().unwrap(), "signer": signer_view});
    println!("{}", Value::to_string(&out));
}
