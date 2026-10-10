//! Per-request latency of an HTTP server, a fresh connection per request (AGP-072: the bounded
//! server against tiny_http). `cargo run --release -p xbt-svc --example http_bench -- <host:port> [path] [n] [conns]`
//! prints the median, p90 and p99 of `n` GETs, and the rate with `conns` clients at once.
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

fn one(addr: &str, req: &[u8]) -> Duration {
    let t = Instant::now();
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_nodelay(true).ok();
    s.write_all(req).expect("write");
    let mut out = Vec::with_capacity(512);
    s.read_to_end(&mut out).expect("read");
    assert!(
        out.starts_with(b"HTTP/1.1 2"),
        "{}",
        String::from_utf8_lossy(&out)
    );
    t.elapsed()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(addr) = args.first().cloned() else {
        eprintln!("usage: http_bench <host:port> [path] [n] [conns]");
        std::process::exit(2);
    };
    let path = args.get(1).cloned().unwrap_or_else(|| "/healthz".into());
    let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5000);
    let conns: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(8);
    let req =
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").into_bytes();
    for _ in 0..200 {
        one(&addr, &req);
    }
    let mut lat: Vec<Duration> = (0..n).map(|_| one(&addr, &req)).collect();
    lat.sort();
    let q = |p: f64| lat[((lat.len() - 1) as f64 * p) as usize].as_secs_f64() * 1e6;
    let t = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..conns {
            s.spawn(|| {
                for _ in 0..n / conns {
                    one(&addr, &req);
                }
            });
        }
    });
    let rate = (n / conns * conns) as f64 / t.elapsed().as_secs_f64();
    println!("{addr}{path}: n={n} median={:.1}us p90={:.1}us p99={:.1}us; {conns} clients: {rate:.0} req/s", q(0.5), q(0.9), q(0.99));
}
