//! Sync the verified header chain from Electrum servers and print the backend status (a smoke test
//! for any target: `light_check <chain> <servers,...> [<height>:<hash>] [ca.pem]`).
use xbt_electrum::{parse_checkpoint, Config, ElectrumBackend};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        eprintln!("usage: light_check <chain> <tcp://h:p,ssl://h:p> [<height>:<hash>] [ca.pem]");
        std::process::exit(2);
    }
    let mut cfg = Config::new(&a[2].split(',').collect::<Vec<_>>(), &a[1]);
    cfg.checkpoint = parse_checkpoint(a.get(3).map(String::as_str)).unwrap_or_else(|e| panic!("{e}"));
    cfg.extra_ca = a.get(4).into_iter().map(Into::into).collect();
    let b = ElectrumBackend::new(cfg).unwrap_or_else(|e| panic!("{e}"));
    let tip = b.block_count();
    println!("{}", serde_json::json!({"tip": tip.as_ref().ok(), "error": tip.err().map(|e| e.to_string()), "status": b.status()}));
}
