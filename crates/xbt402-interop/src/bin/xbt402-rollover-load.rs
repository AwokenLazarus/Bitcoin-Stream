//! The client of the AGP-053 rollover-under-load test (scripts/rollover_load_regtest.sh): one ch1 to
//! the hub, one routed shard, and a lock after every call at `--rate` per second for `--seconds`, so
//! the provider's ch2 is rolled over while locks stream. Every lock's outcome and time is recorded;
//! the JSON summary on stdout has the paid locks, each refusal's code and detail plus timestamp
//! (`refusals`: `{t, ts, code, detail}`; a refused lock is what makes a client fail over), calls that
//! were not 200 (a session the provider stopped serving), and the gaps between paid locks. Then a last
//! pass pays what is due and ch1 is closed cooperatively.
//!
//! xbt402-rollover-load --hub URL --shard URL --rpc-port R --cookie PATH [--seconds 60] [--rate 15]
//!                      [--progress FILE]
//! `--progress` is rewritten every second with {t, paid, refused, refusals} (the driver acts on it).
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use xbt402::client::Wallet;
use xbt402::funding::ChainBackend;
use xbt402::http::UreqTransport;
use xbt402::route_client::{RoutePayer, RoutePayerConfig};
use xbt402::rpc::Rpc;
use xbt402::signer::LocalSigner;
use xbt_primitives::network::network_id;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

/// The node wallet, mining one block after each funding (ch1 needs the hub's minConf 1).
struct MiningWallet(Rpc, String);

impl Wallet for MiningWallet {
    fn fund(&self, address: &str, sats: u64) -> xbt402::Result<(String, u32)> {
        let r = self.0.wallet("w").fund(address, sats)?;
        self.0.call("generatetoaddress", json!([1, self.1]))?;
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

fn bump(m: &mut Map<String, Value>, k: &str) {
    let n = m.get(k).and_then(Value::as_u64).unwrap_or(0) + 1;
    m.insert(k.into(), n.into());
}

fn unix_now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn main() {
    let rpc = Rpc::from_cookie(&format!("http://127.0.0.1:{}", arg("--rpc-port").expect("--rpc-port")),
                               std::path::Path::new(&arg("--cookie").expect("--cookie"))).expect("cookie");
    let network = network_id(rpc.call("getblockhash", json!([101])).expect("block 101").as_str().expect("hash"));
    let addr = rpc.wallet("w").call("getnewaddress", json!([])).expect("address").as_str().unwrap().to_string();
    let node = rpc.clone();
    let mut cfg = RoutePayerConfig::new(&network);
    cfg.capacity = 400_000;
    let pay = Arc::new(RoutePayer::new(&arg("--hub").expect("--hub"), cfg, Arc::new(LocalSigner::new()),
                                       Arc::new(MiningWallet(rpc.clone(), addr)), Box::new(UreqTransport::default()),
                                       Box::new(move || node.block_count())));
    let ch1 = pay.open().expect("open ch1");
    let sh = pay.shard(&arg("--shard").expect("--shard"), "POST").expect("shard");
    let secs: f64 = arg("--seconds").map(|s| s.parse().unwrap()).unwrap_or(60.0);
    let rate: f64 = arg("--rate").map(|s| s.parse().unwrap()).unwrap_or(15.0);
    let progress = arg("--progress");
    let t0 = Instant::now();
    let (mut paid, mut calls, mut idle) = (0u64, 0u64, 0u64);
    let (mut refused, mut other, mut bad_calls) = (Map::new(), Map::new(), Map::new());
    let mut refusals: Vec<Value> = vec![];
    let mut timeline: Vec<Value> = vec![];
    let mut paid_at: Vec<f64> = vec![];
    let mut lock_ms: Vec<f64> = vec![];
    let (mut next, mut last_progress) = (Instant::now(), 0.0f64);
    while t0.elapsed().as_secs_f64() < secs {
        next += Duration::from_secs_f64(1.0 / rate);
        let t = t0.elapsed().as_secs_f64();
        calls += 1;
        match pay.call(&sh, "POST", br#"{"tokens":1}"#) {
            Ok(r) if r.status == 200 => {}
            Ok(r) => {
                bump(&mut bad_calls, &r.status.to_string());
                timeline.push(json!([round3(t), "call", r.status]));
            }
            Err(e) => {
                bump(&mut bad_calls, &e.code);
                timeline.push(json!([round3(t), "call", e.code]));
            }
        }
        let l0 = Instant::now();
        match pay.lock(&sh) {
            Ok(Some(v)) if v["status"] == "paid" => {
                paid += 1;
                paid_at.push(t0.elapsed().as_secs_f64());
                lock_ms.push(l0.elapsed().as_secs_f64() * 1000.0);
            }
            Ok(Some(v)) if v["status"] == "refused" => {
                let code = v["error"].as_str().unwrap_or("?").to_string();
                let detail = v["detail"].as_str().unwrap_or("").to_string();
                bump(&mut refused, &code);
                let rec = json!({"t": round3(t), "ts": round3(unix_now()), "code": code, "detail": detail});
                refusals.push(rec.clone());
                timeline.push(json!([round3(t), "refused", rec]));
            }
            Ok(Some(v)) => {
                let k = v["status"].as_str().unwrap_or("?").to_string();
                bump(&mut other, &k);
                timeline.push(json!([round3(t), "lock", v]));
            }
            Ok(None) => idle += 1,
            Err(e) => {
                bump(&mut other, &format!("error:{}", e.code));
                timeline.push(json!([round3(t), "lock_error", e.code]));
            }
        }
        if let Some(p) = &progress {
            let el = t0.elapsed().as_secs_f64();
            if el - last_progress >= 1.0 {
                last_progress = el;
                let _ = std::fs::write(p, json!({"t": round3(el), "paid": paid, "refused": refused, "refusals": refusals, "badCalls": bad_calls}).to_string());
            }
        }
        if let Some(d) = next.checked_duration_since(Instant::now()) {
            std::thread::sleep(d);
        }
    }
    let dur = t0.elapsed().as_secs_f64();
    let mut gaps: Vec<f64> = paid_at.windows(2).map(|w| (w[1] - w[0]) * 1000.0).collect();
    let max_gap = gaps.iter().cloned().fold(0.0, f64::max);
    let over_1s = gaps.iter().filter(|g| **g > 1000.0).count();
    // last pass: pay what is due, then close ch1
    let until = Instant::now() + Duration::from_secs(20);
    while Instant::now() < until && sh.due_sat() > 0 {
        let _ = pay.lock(&sh);
        std::thread::sleep(Duration::from_millis(300));
    }
    let close = pay.close().map_err(|e| e.to_string());
    let out = json!({"ch1": ch1, "seconds": round3(dur), "rate": rate, "calls": calls, "badCalls": bad_calls, "locksPaid": paid,
                     "lockRate": round3(paid as f64 / dur), "refused": refused, "refusals": refusals, "lockOther": other, "idleTicks": idle,
                     "maxGapMs": round3(max_gap), "gapsOver1s": over_1s, "gapP50Ms": round3(pct(&mut gaps, 0.5)),
                     "lockMs": {"p50": round3(pct(&mut lock_ms.clone(), 0.5)), "p95": round3(pct(&mut lock_ms, 0.95))},
                     "timeline": timeline, "summary": pay.summary(), "close": close.unwrap_or_else(|e| json!({"error": e})),
                     "events": *pay.events.lock().unwrap()});
    println!("{out}");
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}
