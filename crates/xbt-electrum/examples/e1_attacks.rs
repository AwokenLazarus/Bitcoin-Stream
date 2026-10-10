//! The three ways one Electrum server could stall or exhaust the light backend (the AGP-077 closure
//! audit, review E1), each run against the simulator, with the wall time and the peak resident memory
//! of the client. The hostile server runs in a child process, so the peak is the client's alone:
//!
//! ```text
//! for a in trickle bigline history; do
//!   cargo run -q --release --offline -p xbt-electrum --example e1_attacks -- $a
//! done
//! ```
//!
//! * `trickle`: the real chain, 120 headers above the checkpoint, served one header per answer,
//!   400 ms each, inside a 500 ms request timeout; an honest server is configured beside it. Timed:
//!   the first `block_count()`.
//! * `bigline`: a 16 MiB line of `[[],[],...]` sent ahead of the answer to one small request.
//! * `history [N]`: N invented entries (8,000 unless given) in one script's history, each a
//!   transaction the server serves.
//!
//! It uses nothing but the backend's public calls and a line proxy of its own, so the same file
//! builds against a tree from before the limits: that is how the "before" column was measured.
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt_electrum::sim::{coinbase, FakeElectrum, SimChain, CHECKPOINT};
use xbt_electrum::{scripthash, Config, ElectrumBackend};

#[derive(Clone, Copy, PartialEq)]
enum Attack {
    Trickle,
    BigLine,
}

/// A line proxy in front of `upstream` that plays `attack` on the answers passing through it.
fn proxy(upstream: SocketAddr, attack: Attack) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let Ok(server) = TcpStream::connect(upstream) else { continue };
            let (trickled, inject) = (Arc::new(Mutex::new(HashSet::<u64>::new())), Arc::new(AtomicBool::new(false)));
            let (mut to_server, from_client) = (server.try_clone().expect("clone"), BufReader::new(client.try_clone().expect("clone")));
            let (t, i) = (trickled.clone(), inject.clone());
            std::thread::spawn(move || {
                for line in from_client.lines().map_while(Result::ok) {
                    let msg: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
                    for req in msg.as_array().map_or(std::slice::from_ref(&msg), Vec::as_slice) {
                        let (method, id) = (req["method"].as_str().unwrap_or(""), req["id"].as_u64().unwrap_or(0));
                        if method == "blockchain.block.headers" && req["params"][0].as_u64().unwrap_or(0) >= CHECKPOINT as u64 {
                            t.lock().expect("lock").insert(id);
                        }
                        if method == "blockchain.estimatefee" {
                            i.store(true, Ordering::SeqCst);
                        }
                    }
                    if to_server.write_all(format!("{line}\n").as_bytes()).is_err() {
                        break;
                    }
                }
            });
            let mut to_client = client;
            std::thread::spawn(move || {
                for line in BufReader::new(server).lines().map_while(Result::ok) {
                    let mut msg: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
                    let mut slow = false;
                    let mut one_header = |a: &mut Value| {
                        if attack == Attack::Trickle && trickled.lock().expect("lock").remove(&a["id"].as_u64().unwrap_or(0)) {
                            let hex = a["result"]["hex"].as_str().unwrap_or("").to_string();
                            a["result"]["hex"] = hex[..hex.len().min(2 * 164)].into();
                            a["result"]["count"] = 1.into();
                            slow = true;
                        }
                    };
                    match &mut msg {
                        Value::Array(items) => items.iter_mut().for_each(&mut one_header),
                        other => one_header(other),
                    }
                    if slow {
                        std::thread::sleep(Duration::from_millis(400));
                    }
                    if attack == Attack::BigLine && inject.swap(false, Ordering::SeqCst) {
                        let mut big = Vec::with_capacity(16 << 20);
                        big.push(b'[');
                        while big.len() < (16 << 20) - 4 {
                            big.extend_from_slice(b"[],");
                        }
                        big.extend_from_slice(b"[]]\n");
                        // the client may hang up part-way: that is the fix working
                        if to_client.write_all(&big).is_err() {
                            break;
                        }
                    }
                    if to_client.write_all(format!("{msg}\n").as_bytes()).is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

fn peak_rss_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    status.lines().find_map(|l| l.strip_prefix("VmHWM:")).and_then(|v| v.split_whitespace().next()?.parse().ok()).unwrap_or(0)
}

/// The hostile side, in its own process: prints where it listens, then one line with the number of
/// transactions it was asked for each time a line arrives on stdin.
fn serve(attack: &str, entries: u32) {
    let chain = Arc::new(Mutex::new(SimChain::new(CHECKPOINT + 120, 0)));
    let (server, honest) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    let spk = [vec![0x00, 0x14], vec![0x41; 20]].concat();
    let funding = chain.lock().expect("lock").credit(0, 70_000, &spk, true);
    let url = match attack {
        "trickle" => format!("tcp://{}", proxy(server.addr, Attack::Trickle)),
        "bigline" => format!("tcp://{}", proxy(server.addr, Attack::BigLine)),
        _ => {
            let mut k = server.knobs();
            let invented: Vec<_> = (0..entries).map(|n| coinbase(1_000_000 + n, 9)).collect();
            k.extra_history.insert(scripthash(&spk), invented.iter().map(|t| (t.txid(), 150)).collect());
            k.invented = invented.into_iter().map(|t| (t.txid(), t)).collect();
            server.url()
        }
    };
    let cp = hex::encode(chain.lock().expect("lock").hash_at(CHECKPOINT));
    println!("{}", json!({"url": url, "honest": honest.url(), "checkpoint": cp, "funding": funding, "tip": chain.lock().expect("lock").tip_height()}));
    for _ in std::io::stdin().lock().lines() {
        println!("{}", server.calls.lock().expect("lock").iter().filter(|m| *m == "blockchain.transaction.get").count());
    }
}

fn backend(servers: &[&str], checkpoint: &str, timeout: Duration) -> ElectrumBackend {
    let mut c = Config::new(servers, "regtest");
    c.checkpoint = Some((CHECKPOINT, checkpoint.to_string()));
    c.timeout = timeout;
    c.sync_interval = Duration::ZERO;
    ElectrumBackend::new(c).expect("backend")
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let serving = args.first().map(String::as_str) == Some("serve");
    if serving {
        args.remove(0);
    }
    let attack = args.first().cloned().unwrap_or_default();
    let entries = args.get(1).map_or(Ok(8_000), |n| n.parse::<u32>());
    let (true, Ok(entries)) = (["trickle", "bigline", "history"].contains(&attack.as_str()), entries) else {
        eprintln!("usage: e1_attacks trickle|bigline|history [entries]");
        std::process::exit(2);
    };
    if serving {
        return serve(&attack, entries);
    }
    let mut child = Command::new(std::env::current_exe().expect("exe")).args(["serve", &attack, &entries.to_string()])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("the hostile server");
    let mut from_child = BufReader::new(child.stdout.take().expect("stdout"));
    let mut line = String::new();
    from_child.read_line(&mut line).expect("the server's address");
    let at: Value = serde_json::from_str(&line).expect("json");
    let s = |k: &str| at[k].as_str().unwrap_or("").to_string();
    let (url, cp) = (s("url"), s("checkpoint"));
    let t = Instant::now();
    let (outcome, flags) = match attack.as_str() {
        "trickle" => {
            let b = backend(&[&url, &s("honest")], &cp, Duration::from_millis(500));
            let tip = b.block_count().map(|h| h.to_string()).unwrap_or_else(|e| format!("error: {e}"));
            (format!("first block_count: tip {tip} of {}", at["tip"]), b.flags())
        }
        "bigline" => {
            let b = backend(&[&url], &cp, Duration::from_secs(15));
            b.block_count().expect("sync");
            let r = b.estimate_fee(6);
            (format!("estimate_fee: {}", r.map(|f| format!("{:?}", f.feerate)).unwrap_or_else(|e| format!("error: {e}"))), b.flags())
        }
        _ => {
            let b = backend(&[&url], &cp, Duration::from_secs(15));
            let r = b.tx_out(&s("funding"), 0, false);
            let seen = r.map(|o| if o.is_some() { "unspent".to_string() } else { "none".to_string() }).unwrap_or_else(|e| format!("error: {e}"));
            let mut fetched = String::new();
            let asked = child.stdin.as_mut().expect("stdin").write_all(b"\n").and_then(|_| from_child.read_line(&mut fetched));
            (format!("tx_out: {seen}; {} transaction fetches", if asked.is_ok() { fetched.trim() } else { "?" }), b.flags())
        }
    };
    let ms = t.elapsed().as_millis() as u64;
    let _ = child.kill();
    let _ = child.wait();
    let flagged: Vec<&str> = flags.iter().map(|f| f.reason.as_str()).collect();
    println!("{}", json!({"attack": attack, "wall_ms": ms, "peak_rss_kib": peak_rss_kib(), "outcome": outcome, "flags": flagged.len(),
                          "last_flag": flagged.last().copied().unwrap_or("-")}));
}
