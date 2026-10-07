//! The xbt-work blinded receipt relay as a service (spec §11.1; see the crate docs).
//!
//! ```text
//! xbt-work-relay [serve] [--bind ADDR] [--push-bind ADDR|off] [--store DIR | --memory]
//!                [--rate N] [--burst N] [--max-entries N] [--ttl-days N] [--threads N]
//! xbt-work-relay healthcheck [--ready]      GET our own /healthz (/readyz): the image's HEALTHCHECK
//! ```
//! Every flag has an env variable (docs/CONTAINER.md):
//!
//! | flag | env | default |
//! |---|---|---|
//! | `--bind` | `XBT_RELAY_BIND` | `127.0.0.1:9490` (image: `0.0.0.0:9490`), public, read-only |
//! | `--push-bind` | `XBT_RELAY_PUSH_BIND` | `127.0.0.1:9491` (image: `0.0.0.0:9491`), the Prime's pushes; `off`: none |
//! | `--store` | `XBT_RELAY_STORE` | `$XBT_DATA_DIR/relay/blobs` when `XBT_DATA_DIR` is set, else memory |
//! | `--rate`, `--burst` | `XBT_RELAY_RATE`, `XBT_RELAY_BURST` | 10 GETs/s per client, bursts of 40 (0: no limit) |
//! | `--max-entries` | `XBT_RELAY_MAX_ENTRIES` | 1,000,000 (about 1 GB of blobs) |
//! | `--ttl-days` | `XBT_RELAY_TTL_DAYS` | 30 (an entry not pushed again for this long expires; 0: never) |
//! | `--threads` | `XBT_RELAY_THREADS` | 8 |
//!
//! `XBT_BASE_PATH`, `XBT_TRUST_FORWARDED=1` (count clients by the proxy's `X-Forwarded-For` hop) as
//! for every service. The push token is the secret `relay-push-token` (`XBT_SECRET_RELAY_PUSH_TOKEN_FILE`,
//! `$CREDENTIALS_DIRECTORY/relay-push-token`, or `$XBT_DATA_DIR/relay/secrets/relay-push-token`); with
//! one, every push needs `Authorization: Bearer <token>`. A push listener off loopback without a token
//! is refused unless `XBT_RELAY_PUSH_ALLOW_OPEN=1` (a push port reachable only on a private network,
//! for a Prime that sends no token).
use std::sync::Arc;
use std::time::Duration;

use xbt_svc::{env, env_bool, probe, proxy, DataDir, Mode, Secrets};
use xbt_work_relay::{serve, Config, Relay, Store, SERVICE};

fn die(msg: String) -> ! {
    eprintln!("{SERVICE}: {msg}");
    std::process::exit(2);
}

fn opt(args: &[String], flag: &str, var: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned().or_else(|| env(var))
}

fn num<T: std::str::FromStr>(args: &[String], flag: &str, var: &str, default: T) -> T {
    match opt(args, flag, var) {
        Some(v) => v.parse().unwrap_or_else(|_| die(format!("{flag} / {var} = {v}: not a number"))),
        None => default,
    }
}

fn loopback(bind: &str) -> bool {
    bind.rsplit_once(':').is_some_and(|(h, _)| matches!(h.trim_matches(['[', ']']), "127.0.0.1" | "::1" | "localhost"))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("usage: {SERVICE} [serve] [--bind ADDR] [--push-bind ADDR|off] [--store DIR | --memory] [--rate N] [--burst N] \
                  [--max-entries N] [--ttl-days N] [--threads N] | healthcheck [--ready]");
        return;
    }
    let bind = opt(&args, "--bind", "XBT_RELAY_BIND").unwrap_or_else(|| "127.0.0.1:9490".into());
    let base = proxy::normalize_base(&env("XBT_BASE_PATH").unwrap_or_default());
    if args.first().map(String::as_str) == Some("healthcheck") {
        let which = if args.iter().any(|a| a == "--ready") { "/readyz" } else { "/healthz" };
        match probe::get(&probe::local_addr(&bind), &format!("{base}{which}"), Duration::from_secs(5)) {
            Ok((200, _)) => std::process::exit(0),
            Ok((s, b)) => die(format!("{which}: HTTP {s} {b}")),
            Err(e) => die(e),
        }
    }
    let mode = Mode::from_env().unwrap_or_else(|e| die(e));
    let data = DataDir::from_env();
    let push_bind = opt(&args, "--push-bind", "XBT_RELAY_PUSH_BIND").unwrap_or_else(|| "127.0.0.1:9491".into());
    let push_bind = (push_bind != "off").then_some(push_bind);
    let secrets = Secrets::for_component(data.as_ref(), xbt_svc::RELAY, mode);
    let push_token = secrets.get("relay-push-token").unwrap_or_else(|e| die(e))
        .map(|s| s.text().unwrap_or_else(|e| die(e)).trim().to_string()).filter(|t| !t.is_empty());
    if let Some(pb) = &push_bind {
        if !loopback(pb) && push_token.is_none() && !env_bool("XBT_RELAY_PUSH_ALLOW_OPEN", false) {
            die(format!("push listener {pb} is off loopback with no relay-push-token: set the secret, or \
                         XBT_RELAY_PUSH_ALLOW_OPEN=1 when that port is reachable only from the Prime"));
        }
    }
    let max_entries = num(&args, "--max-entries", "XBT_RELAY_MAX_ENTRIES", 1_000_000usize);
    let ttl = num(&args, "--ttl-days", "XBT_RELAY_TTL_DAYS", 30u64) * 86_400;
    let store_dir = if args.iter().any(|a| a == "--memory") {
        None
    } else {
        opt(&args, "--store", "XBT_RELAY_STORE").map(Into::into).or_else(|| data.as_ref().map(|d| d.component(xbt_svc::RELAY).join("blobs")))
    };
    let store = match &store_dir {
        Some(d) => Store::disk(d, max_entries, ttl).unwrap_or_else(|e| die(format!("store {}: {e}", d.display()))),
        None => Store::memory(max_entries, ttl),
    };
    let cfg = Config {
        rate: num(&args, "--rate", "XBT_RELAY_RATE", 10.0f64),
        burst: num(&args, "--burst", "XBT_RELAY_BURST", 40u32),
        push_token,
        trust_forwarded: env_bool("XBT_TRUST_FORWARDED", false),
        base,
    };
    let token = cfg.push_token.is_some();
    let relay = Arc::new(Relay::new(cfg, store));
    let threads = num(&args, "--threads", "XBT_RELAY_THREADS", 8usize);
    let sweep = Duration::from_secs((ttl / 24).clamp(60, 3600));
    let run = serve(relay.clone(), &bind, push_bind.as_deref(), threads, sweep).unwrap_or_else(|e| die(e.to_string()));
    println!("{SERVICE}: public http://{} (GET /<lookup>), push {} (PUT /<lookup>{}), store {} ({} entries, max {max_entries}, ttl {}d)",
             run.public, run.push.map(|a| format!("http://{a}")).unwrap_or_else(|| "off".into()), if token { ", bearer token" } else { "" },
             store_dir.map(|d| format!("disk:{}", d.display())).unwrap_or_else(|| "memory".into()), relay.store.len(), ttl / 86_400);
    // counters only: the relay never logs a lookup
    let r = relay.clone();
    std::thread::spawn(move || {
        use std::sync::atomic::Ordering::Relaxed;
        let mut last = [0u64; 5];
        loop {
            std::thread::sleep(Duration::from_secs(300));
            let c = &r.counters;
            let now = [c.hits.load(Relaxed), c.misses.load(Relaxed), c.limited.load(Relaxed), c.pushes.load(Relaxed), c.refused.load(Relaxed)];
            if now != last {
                eprintln!("{SERVICE}: hits {} misses {} rate-limited {} pushes {} refused pushes {} entries {}", now[0], now[1], now[2], now[3],
                          now[4], r.store.len());
                last = now;
            }
        }
    });
    for t in run.threads {
        let _ = t.join();
    }
}
