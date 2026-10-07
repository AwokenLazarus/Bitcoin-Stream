//! The Rust provider verifier on a regtest node, for the cross-implementation run: serves a paid
//! JSON API (`/v1/*`, 150 sat per call) behind `xbt402::provider::Provider`, with a watcher.
//!
//! xbt402-rust-provider --port P --rpc-port R --cookie PATH [--close-fee-payer payer|payee]
//!                      [--conditional PATH:PRICE:PLAINTEXT] [--ledger FILE] [--price SAT]
//!                      [--bind ADDR] [--rpc-host HOST]   (default 127.0.0.1; the container test, AGP-038)
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use xbt402::channel::FeePayer;
use xbt402::funding::ChainBackend;
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::rpc::Rpc;
use xbt_primitives::network::network_id;
use xbt_primitives::secp256k1::SecretKey;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

fn main() {
    let port = arg("--port").expect("--port");
    let rpc = Rpc::from_cookie(&format!("http://{}:{}", arg("--rpc-host").unwrap_or_else(|| "127.0.0.1".into()), arg("--rpc-port").expect("--rpc-port")),
                               std::path::Path::new(&arg("--cookie").expect("--cookie"))).expect("cookie");
    let anchor = rpc.call("getblockhash", json!([101])).expect("block 101");
    let network = network_id(anchor.as_str().expect("hash"));
    let mut cfg = ProviderConfig::new(&network);
    if arg("--close-fee-payer").as_deref() == Some("payee") {
        cfg.close_fee_payer = FeePayer::Payee;
    }
    let price: u64 = arg("--price").map(|p| p.parse().expect("price")).unwrap_or(150);
    let ledger = match arg("--ledger") {
        Some(p) => Ledger::open(std::path::Path::new(&p)).expect("ledger"),
        None => Ledger::in_memory(),
    };
    let mut sk = [0u8; 32];
    getrandom_fill(&mut sk);
    let secret = SecretKey::from_slice(&sk).expect("key");
    let chain: Arc<dyn ChainBackend> = Arc::new(rpc.clone());
    let prov = Arc::new(Provider::new(chain, secret, cfg, ledger, Box::new(move |_, _| price),
                                      Box::new(|m, p, b| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())],
                                          json!({"answer": p, "method": m, "bytes": b.len(), "server": "rust"}).to_string().into_bytes())))
        .expect("provider"));
    if let Some(c) = arg("--conditional") {
        let mut it = c.splitn(3, ':');
        let (path, p, plain) = (it.next().expect("path"), it.next().expect("price"), it.next().unwrap_or(""));
        prov.offer_conditional(path, p.parse().expect("price"), plain.as_bytes(), None);
    }
    let w = prov.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(2));
        if let Err(e) = w.close_due() {
            eprintln!("watcher: {e}");
        }
    });
    let bind = arg("--bind").unwrap_or_else(|| "127.0.0.1".into());
    let hs = xbt402::http::serve_http(prov.clone(), &format!("{bind}:{port}"), 4).expect("bind");
    println!("xbt402-rust-provider ready on {bind}:{port} network {network} payTo {} closeFeePayer {:?}",
             prov.pay_to(), prov.cfg.close_fee_payer);
    for h in hs {
        let _ = h.join();
    }
}

fn getrandom_fill(b: &mut [u8]) {
    use std::io::Read;
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(b)).expect("urandom");
}
