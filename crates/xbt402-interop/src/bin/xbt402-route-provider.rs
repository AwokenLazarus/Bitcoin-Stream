//! A Rust provider selling a routed path on a regtest node, for route_interop.sh.
//!
//! xbt402-route-provider --port P --rpc-port R --cookie PATH --secret HEX --amsat N
//!                       [--window 1.0] [--lock-wait 3.0] [--ttl 8.0] [--settle-multiple 20] [--ledger FILE]
//!                       [--zero-conf-max SAT] [--watch-secs 5] [--route-wal FILE] [--settle-lock-multiple 4]
//! `--zero-conf-max` (AGP-053): the cap on an unconfirmed rollover child (0: never; default: 2 ×
//! settleMultiple × closeFee). `--route-wal` (AGP-054): the provider's RouteWal (each call's meter
//! durable before its ROUTE-STATE leaves, written ahead while the handler runs). `--settle-lock-multiple`
//! (AGP-056): the default zero-conf cap is at least 2 × this × the largest lock (0: the AGP-053 cap).
//! Serves `/v1/chunk` (routed, N amsat per call) with a watcher; prints "ready" on stderr.
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use xbt402::adaptor::Sc;
use xbt402::funding::FundingPolicy;
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route_seller::RouteOffer;
use xbt402::rpc::Rpc;
use xbt_primitives::network::network_id;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

fn f(name: &str, d: f64) -> f64 {
    arg(name).map(|v| v.parse().expect(name)).unwrap_or(d)
}

fn main() {
    let port = arg("--port").expect("--port");
    let rpc = Rpc::from_cookie(&format!("http://127.0.0.1:{}", arg("--rpc-port").expect("--rpc-port")),
                               std::path::Path::new(&arg("--cookie").expect("--cookie"))).expect("cookie");
    let network = network_id(rpc.call("getblockhash", json!([101])).expect("block 101").as_str().expect("hash"));
    let mut cfg = ProviderConfig::new(&network);
    cfg.policy = FundingPolicy { min_capacity: 20_000, min_expiry_blocks: 1_008, max_expiry_blocks: 8_640, close_margin: 144, ..FundingPolicy::default() };
    cfg.settle_multiple = f("--settle-multiple", 20.0) as u64;
    cfg.rollover_zero_conf_max = arg("--zero-conf-max").map(|v| v.parse().expect("--zero-conf-max"));
    cfg.height_ttl = Duration::from_millis(500);
    cfg.settle_lock_multiple = f("--settle-lock-multiple", cfg.settle_lock_multiple as f64) as u64;
    cfg.route_wal = arg("--route-wal").map(std::path::PathBuf::from);
    let ledger = match arg("--ledger") {
        Some(p) => Ledger::open(std::path::Path::new(&p)).expect("ledger"),
        None => Ledger::in_memory(),
    };
    let secret = Sc::from_hex_mod_n(&arg("--secret").expect("--secret")).and_then(|s| s.secret()).expect("secret");
    let served = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let s2 = served.clone();
    let prov = Provider::new(Arc::new(rpc), secret, cfg, ledger, Box::new(|_, _| 1000), Box::new(move |_, _, _| {
        let n = s2.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], json!({"shard": "rust", "chunk": n}).to_string())
    })).expect("provider");
    let amsat: u128 = arg("--amsat").expect("--amsat").parse().expect("amsat");
    prov.offer_route(RouteOffer { window: f("--window", 1.0), lock_wait: f("--lock-wait", 3.0), invoice_ttl: f("--ttl", 8.0),
                                  ..RouteOffer::new("/v1/chunk", amsat) });
    let prov = Arc::new(prov);
    let hs = xbt402::http::serve_http(prov.clone(), &format!("127.0.0.1:{port}"), 8).expect("bind");
    eprintln!("rust route provider {} on {port} ready", prov.pay_to());
    let w = prov.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs_f64(f("--watch-secs", 5.0)));
        if let Err(e) = w.close_due() {
            eprintln!("watcher: {e}");
        }
    });
    for h in hs {
        let _ = h.join();
    }
}
