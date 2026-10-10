//! The Rust provider for the pay-with-work regtest run: a paid JSON API (`/v1/*`, 150 sat) behind
//! the xbt402 Provider, offering `xbt-channel` and `xbt-work` in one 402. The work rail pulls
//! receipts through the blinded relay every few seconds, re-prices on every new epoch (§6.3) and,
//! with `--admin`, audits pool coinbases on request (loopback only).
//!
//! xbt-work-provider --port P --rpc-port R --cookie PATH --identity ADDR --prime-pubkey HEX
//!                   --prime-id N --receipt-url URL [--relay-url URL] [--window-url URL]
//!                   [--state FILE | off] [--price SAT] [--haircut-bps N] [--work-units N] [--admin]
//!                   [--pull-secs N]   (relay pull interval, default 3; 0: only before an audit)
//!                   [--nta]           (§13.8: refuse an identity that is not key-path P2TR)
//!                   [--audit-depth K | off [--audit-from H]]   (audit every block K deep on its own)
//!                   [--cap-invoice W | --cap-invoice-sats S | --cap-invoice-calls N | off]
//!                   [--cap-total ... ]   (the same four forms)
//!                   [--max-carry-sats S | off] [--carry-growth-blocks N] [--max-unpaid-blocks N]
//!                   [--prime-window N] [--prime-window-min-work W] [--window-tolerance-bps N]
//!                   [--prime-fee-bps N] [--prime-min-payout S]
//!                   [--max-unfunded-per-client N] [--trust-forwarded]
//!                   [--data-dir DIR] [--watch-secs N]
//!
//! AGP-067 (review C4): the channel side keeps its payTo key (`DIR/payto.key`, created 0600 on first
//! start) and its channel ledger (`DIR/channels.jsonl`, locked to one process) in `--data-dir`
//! (`XBT_WORK_DATA_DIR`, default `./xbt-work-provider-data`), and a watcher runs `close_due` every
//! `--watch-secs` (default 5): it closes each channel before its expiry and bumps a stuck close. A
//! restart keeps every channel; before, a new random key and an empty ledger let each buyer refund.
//!
//! §13.1 caps (AGP-043): unaudited credit per invoice and in total, in work units, in sats converted
//! at each epoch's price (without the haircut), or in calls at the `--price` (sats); `off` removes
//! a cap. Owed carry above `--max-carry-sats`, or growing over `--carry-growth-blocks` audited
//! blocks, stops new credit. AGP-065 (review P5): with no cap flag the provider caps unaudited
//! credit at 100 calls per invoice and 1000 calls in total.
//!
//! AGP-079, the shipped defaults (`WorkConfig::shipped`; no flag needed for any of them):
//! * Credit stops being unaudited only as far as the audited coinbases paid for it, at this
//!   provider's price (`WorkProvider::paid_work`). `--cap-skipped` is gone: nothing is forgiven.
//! * Owed carry is capped at the value of 1000 calls (`--max-carry-sats S`, or `off`).
//!   `--carry-growth-blocks` stays off: a share below the Prime's `min-payout` grows as carry for
//!   several blocks at an honest Prime, so only a provider that attests every tip should set it.
//! * The work book is kept in `DIR/work.json` (`--state FILE` moves it, `--state off` keeps it in
//!   memory only: every balance is then lost on restart).
//! * With `--window-url` the audit loop runs 6 blocks deep (`--audit-depth K`, or `off`). Without a
//!   window URL nothing can be audited or paid for: credit stops for good at the total cap, and the
//!   provider says so when it starts.
//!
//! AGP-065 (review P1): the Prime's pool terms are pinned here, never taken from a statement:
//! `--prime-window` (primed `window`, default 8), `--prime-window-min-work` (primed
//! `window-min-work`, default 0; regtest runs need the Prime's floor), `--window-tolerance-bps`
//! (default 500), `--prime-fee-bps` (default 0, the fee the provider prices with) and
//! `--prime-min-payout` (default 546). Every flag also reads an env variable: `XBT_WORK_CAP_INVOICE`,
//! `XBT_WORK_CAP_INVOICE_SATS`, `XBT_WORK_CAP_INVOICE_CALLS`, the same for `_TOTAL`,
//! `XBT_WORK_MAX_CARRY_SATS`, `XBT_WORK_CARRY_GROWTH_BLOCKS`, `XBT_WORK_MAX_UNPAID_BLOCKS`, `XBT_WORK_AUDIT_DEPTH`, `XBT_WORK_NTA=1`,
//! `XBT_WORK_PRIME_WINDOW`, `XBT_WORK_PRIME_WINDOW_MIN_WORK`, `XBT_WORK_WINDOW_TOLERANCE_BPS`,
//! `XBT_WORK_PRIME_FEE_BPS`, `XBT_WORK_PRIME_MIN_PAYOUT`, `XBT_WORK_MAX_UNFUNDED_PER_CLIENT`.
//!
//! The audit loop audits every block (review P4): a block that paid the identity with no statement,
//! or with one the audit refuses, fails and distrusts the Prime; a Prime or node it cannot reach
//! stops the pass, which resumes at that block. A block that paid the identity nothing and has no
//! statement has no verdict (it may be any pool's), but while credit is unpaid it is counted
//! (AGP-084): the report's `unpaidBlocks` is the run of them since a coinbase last paid for credit.
//! `--max-unpaid-blocks N` stops new credit once the run reaches N, until a coinbase pays; it is off
//! unless set, because N depends on how often the Prime's pool finds a block. A statement the Prime
//! signed for such a block and the audit refuses is a failed audit, as on a paid block. Before each
//! pass it compares the audited blocks with the node and undoes the audit of any reorged one.
//!
//! Admin (only with --admin, only from a loopback peer): `POST /admin/xbt-work/audit` with
//! `{"from": H0, "to": H1, "underpayHeight": H?}` audits every coinbase in [H0, H1] that pays the
//! identity against its signed window statement and returns the verdicts, the carry ledger and,
//! for `underpayHeight`, the fraud proof of the same block audited as if it paid 1 sat. Blocks that pay
//! the identity nothing are audited too when the Prime published a statement for them (a block that
//! carried the provider's share). `{"withoutDeferrals": H}` adds the control: block H audited as if its
//! deferral lines were missing (not recorded). `GET /admin/xbt-work/report`: the audit log, the carry
//! ledger, the credit exposure (unaudited, held, paid for, caps, frozen), the pinned Prime terms, and
//! the audited payouts split into liquid and locked by the node's coinbase maturity.
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use xbt402::funding::ChainBackend;
use xbt402::http::{serve_service, HttpService, UreqTransport};
use xbt402::ledger::Ledger;
use xbt402::provider::{load_or_create_secret, HttpResponse, Provider, ProviderConfig, PEER_HEADER};
use xbt402::rpc::Rpc;
use xbt_work::audit::{audit_block, check_fraud_proof};
use xbt_work::chain::ChainBlock;
use xbt_work::pricing::Pricing;
use xbt_work::provider::{Amount, Cap, Caps, Statement, WorkConfig, WorkProvider, WorkScheme, SETTLE_DEPTH, SHIPPED_AUDIT_DEPTH, SHIPPED_HAIRCUT_BPS};
use xbt_work::tools::{arg, block_count, block_hash, chain_block, flag, maturity, network, opt, prime_terms, rpc, tip_bits, window};

fn num<T: std::str::FromStr>(flag: &str, var: &str) -> Option<T> {
    opt(flag, var).map(|v| v.parse().unwrap_or_else(|_| panic!("{flag} / {var}: not a number: {v}")))
}

/// `--flag N` or `--flag off` (or the env variable): Some(None) for `off`, None when not given.
fn num_or_off<T: std::str::FromStr>(flag: &str, var: &str) -> Option<Option<T>> {
    opt(flag, var).map(|v| if v == "off" { None } else { Some(v.parse().unwrap_or_else(|_| panic!("{flag} / {var}: not a number or off: {v}"))) })
}

/// `--cap-<name>[-sats|-calls]` (or the env variables), else `default`.
fn cap_from_args(name: &str, default: Cap) -> Cap {
    let var = format!("XBT_WORK_CAP_{}", name.to_uppercase());
    for (suffix, mk) in [("", Cap::Work as fn(u64) -> Cap), ("-sats", Cap::Sats), ("-calls", Cap::Calls)] {
        let (f, v) = (format!("--cap-{name}{suffix}"), format!("{var}{}", suffix.replace('-', "_").to_uppercase()));
        if let Some(s) = opt(&f, &v) {
            return if s == "off" { Cap::Off } else { mk(s.parse().unwrap_or_else(|_| panic!("{f} / {v}: not a number or off: {s}"))) };
        }
    }
    default
}

struct Service {
    prov: Arc<Provider>,
    work: Arc<WorkProvider>,
    rpc: Rpc,
    window_url: Option<String>,
    admin: bool,
}

impl Service {
    fn identity(&self) -> &str {
        &self.work.cfg.identity
    }

    fn audit(&self, req: &Value) -> xbt_work::Result<Value> {
        let t = UreqTransport::default();
        let wurl = self.window_url.as_deref().ok_or_else(|| xbt_work::WorkError::new("no_window_url", ""))?;
        let tip = block_count(&self.rpc)?;
        let h32 = |v: &Value| v.as_u64().and_then(|x| u32::try_from(x).ok());
        let from = h32(&req["from"]).unwrap_or(1);
        let to = h32(&req["to"]).unwrap_or(tip).min(tip);
        // pull the latest receipts first so the book's intervals are as tight as they can be
        let _ = self.work.refresh(&t);
        let mut results = vec![];
        for h in from..=to {
            let block = chain_block(&self.rpc, h, self.identity())?;
            let stmt = window(&t, wurl, h)?;
            let found = match &stmt {
                Some((sw, def, _)) => Statement::Found(sw, def),
                None => Statement::Missing,
            };
            match self.work.audit_chain(&block, found) {
                Ok(None) => {}
                Ok(Some(o)) => {
                    let mut r = json!({"height": h, "ok": o.ok, "blockHash": block.hash, "coinbaseValueSats": block.value_sats,
                                       "paidSats": block.paid_sats, "expectedSats": o.expected_sats, "deferredSats": o.deferred_sats,
                                       "belowMinSats": o.below_min_sats, "provenWork": o.proven_work, "windowWork": o.window_work,
                                       "bounded": o.bounded, "proof": o.proof});
                    match &stmt {
                        Some((sw, _, _)) => r["windowStart"] = sw.stmt.window_start.into(),
                        None => r["error"] = "no window statement".into(),
                    }
                    results.push(r);
                }
                Err(e) => results.push(json!({"height": h, "ok": false, "error": e.to_string()})),
            }
        }
        let (unaudited, held) = self.work.exposure();
        let mut out = json!({"identity": self.identity(), "results": results, "carry": self.work.carry().to_json(),
                             "credit": {"unauditedWork": unaudited, "heldWork": held},
                             "ok": results.iter().all(|r| r["ok"] == json!(true)) && !results.is_empty()});
        // the controls: the same block as if it paid 1 sat (the provider's own bound convicts it),
        // and with its deferral lines left out; neither is recorded
        let control = |h: u32, paid: Option<u64>, lines: bool| -> xbt_work::Result<Option<Value>> {
            let block = chain_block(&self.rpc, h, self.identity())?;
            let Some((sw, def, _)) = window(&t, wurl, h)? else { return Ok(None) };
            let b = ChainBlock { paid_sats: paid.unwrap_or(block.paid_sats), ..block };
            let bounds = self.work.bounds(&b)?;
            let o = audit_block(&self.work.book(), &sw, &b, &bounds, if lines { &def } else { &[] })?;
            let checks = o.proof.as_ref().is_some_and(|p| check_fraud_proof(p, self.work.prime_pubkey(), &b, &bounds));
            Ok(Some(json!({"height": h, "ok": o.ok, "expectedSats": o.expected_sats, "paidSats": b.paid_sats, "proof": o.proof, "proofChecks": checks})))
        };
        if let Some(h) = h32(&req["underpayHeight"]) {
            if let Some(v) = control(h, Some(1), true)? {
                out["underpay"] = v;
            }
        }
        if let Some(h) = h32(&req["withoutDeferrals"]) {
            if let Some(v) = control(h, None, false)? {
                out["withoutDeferrals"] = v;
            }
        }
        Ok(out)
    }

    /// Undo the audits of blocks the node no longer has (a reorg): the lowest height undone.
    fn reorgs(&self, tip: u32) -> xbt_work::Result<Option<u32>> {
        let mut low = None;
        for (h, hash) in self.work.audited_blocks().into_iter().filter(|(h, _)| h.saturating_add(SETTLE_DEPTH) > tip) {
            if h > tip || block_hash(&self.rpc, h)? != hash {
                if let Some(back) = self.work.orphaned(h)? {
                    eprintln!("audit: block {h} ({hash}) left the chain: its audit undone, {back} work units unaudited again");
                    low = Some(low.map_or(h, |l: u32| l.min(h)));
                }
            }
        }
        Ok(low)
    }

    /// Audit every block in [from, to] (the auto-audit loop, review P4): the verdicts, and the next
    /// height to audit. A node or Prime it cannot reach stops the pass there (retried next time);
    /// a statement it refuses (another block, a window start that went backwards) is the block
    /// having no statement: a failed audit when the coinbase paid the identity.
    fn audit_range(&self, t: &UreqTransport, from: u32, to: u32) -> (Vec<(u32, bool)>, u32) {
        let Some(wurl) = self.window_url.as_deref() else { return (vec![], from) };
        let mut out = vec![];
        for h in from..=to {
            let block = match chain_block(&self.rpc, h, self.identity()) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("audit: height {h}: node: {e}; retrying");
                    return (out, h);
                }
            };
            let stmt = match window(t, wurl, h) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("audit: height {h}: {e}; credit held, retrying");
                    return (out, h);
                }
            };
            let found = match &stmt {
                Some((sw, def, _)) => Statement::Found(sw, def),
                None => Statement::Missing,
            };
            match self.work.audit_chain(&block, found) {
                Ok(Some(o)) => out.push((h, o.ok)),
                Ok(None) => {}
                Err(e) => {
                    eprintln!("audit: height {h}: {e}; retrying");
                    return (out, h);
                }
            }
        }
        (out, to.saturating_add(1))
    }

    fn report(&self) -> Value {
        let (unaudited, held) = self.work.exposure();
        let mut v = self.work.report();
        v["credit"]["unauditedWork"] = unaudited.into();
        v["credit"]["heldWork"] = held.into();
        // M1: payouts under the node's own coinbase maturity, never a hard-coded depth
        v["payouts"] = match block_count(&self.rpc).and_then(|tip| Ok((tip, maturity(&self.rpc)?))) {
            Ok((tip, m)) => {
                let (liquid, locked) = self.work.payouts(tip, &m);
                json!({"liquidSats": liquid, "lockedSats": locked, "tip": tip, "maturityDepth": m.relay_at(0)})
            }
            Err(e) => json!({"error": e.to_string()}),
        };
        v
    }
}

impl HttpService for Service {
    fn body_limit(&self, path: &str) -> usize {
        self.prov.body_limit(path, None)
    }

    fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str) -> HttpResponse {
        if path.starts_with("/admin/") {
            // the peer address the server set (Host is the client's to choose)
            let local = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(PEER_HEADER))
                .and_then(|(_, v)| v.parse::<std::net::IpAddr>().ok()).is_some_and(|ip| ip.is_loopback());
            if self.admin && local && method == "GET" && path == "/admin/xbt-work/report" {
                let v = self.report();
                return HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], xbt402::json::dumps(&v).into_bytes());
            }
            if !self.admin || !local || method != "POST" || path != "/admin/xbt-work/audit" {
                return HttpResponse::new(404, vec![], b"not found".to_vec());
            }
            let req = xbt402::json::parse_slice(body).unwrap_or(json!({}));
            let v = self.audit(&req).unwrap_or_else(|e| json!({"ok": false, "error": e.to_string()}));
            return HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], xbt402::json::dumps(&v).into_bytes());
        }
        if path == "/" || path == "/health" {
            let v = json!({"server": "xbt-work-provider (rust)", "payTo": self.prov.pay_to(), "workIdentity": self.work.cfg.identity,
                           "network": self.prov.cfg.network, "invoices": self.work.invoices().len()});
            return HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], xbt402::json::dumps(&v).into_bytes());
        }
        self.prov.serve(method, path, headers, body, url, None)
    }
}

fn answer(path: &str) -> HttpResponse {
    // a small pool-analytics answer, the same shape as the flagship's
    let v = json!({"window": "7d", "server": "rust", "path": path,
                   "pools": [{"pool": "lazarus", "name": "Lazarus", "blocksThis": 333, "blocksPrev": 288, "shareThis": 0.2546,
                              "sharePrev": 0.1538, "deltaPp": 10.08},
                             {"pool": "other", "name": "Other", "blocksThis": 975, "blocksPrev": 1584, "shareThis": 0.7454,
                              "sharePrev": 0.8462, "deltaPp": -10.08}]});
    HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], xbt402::json::dumps(&v).into_bytes())
}

fn main() {
    let port = arg("--port").expect("--port");
    let node = rpc(&arg("--rpc-port").expect("--rpc-port"), &arg("--cookie").expect("--cookie")).expect("cookie");
    let net = network(&node).expect("network");
    let price: u64 = arg("--price").map(|p| p.parse().expect("price")).unwrap_or(150);
    let subsidy = node.call("getblockstats", json!([block_count(&node).expect("height"), ["subsidy"]])).ok()
        .and_then(|s| s["subsidy"].as_u64()).unwrap_or(5_000_000_000);
    let bits = tip_bits(&node).expect("bits");
    let mut wcfg = WorkConfig::new(&net, &arg("--identity").expect("--identity"), arg("--prime-id").expect("--prime-id").parse().expect("prime id"),
                                   &arg("--prime-pubkey").expect("--prime-pubkey"), &arg("--receipt-url").expect("--receipt-url"));
    wcfg.terms = prime_terms().unwrap_or_else(|e| {
        eprintln!("xbt-work-provider: {e}");
        std::process::exit(2);
    });
    // AGP-079: the shipped defaults (pricing, caps on unaudited credit and on owed carry), then the flags
    let mut wcfg = wcfg.shipped(bits, subsidy, price);
    wcfg.relay_url = arg("--relay-url");
    wcfg.nta = flag("--nta") || std::env::var("XBT_WORK_NTA").is_ok_and(|v| v == "1");
    let caps = Caps { invoice: cap_from_args("invoice", Caps::SHIPPED.invoice), total: cap_from_args("total", Caps::SHIPPED.total) };
    wcfg.caps = caps.at(bits, subsidy, price);
    if ["--cap-skipped", "--cap-skipped-sats", "--cap-skipped-calls"].iter().any(|f| arg(f).is_some())
        || ["XBT_WORK_CAP_SKIPPED", "XBT_WORK_CAP_SKIPPED_SATS", "XBT_WORK_CAP_SKIPPED_CALLS"].iter().any(|v| std::env::var(v).is_ok())
    {
        eprintln!("caps: --cap-skipped is no longer used (AGP-079): no credit is forgiven, it is covered by what the coinbases paid");
    }
    if let Some(m) = num_or_off("--max-carry-sats", "XBT_WORK_MAX_CARRY_SATS") {
        wcfg.max_owed_carry_sats = m;
    }
    wcfg.carry_growth_blocks = num("--carry-growth-blocks", "XBT_WORK_CARRY_GROWTH_BLOCKS");
    wcfg.max_unpaid_blocks = num("--max-unpaid-blocks", "XBT_WORK_MAX_UNPAID_BLOCKS");
    wcfg.max_unfunded_per_client = match num::<usize>("--max-unfunded-per-client", "XBT_WORK_MAX_UNFUNDED_PER_CLIENT") {
        Some(0) => None,
        Some(n) => Some(n),
        None => wcfg.max_unfunded_per_client,
    };
    wcfg.trust_forwarded = flag("--trust-forwarded");
    eprintln!("caps: {:?} -> {:?} work units at this epoch, owed carry at most {:?} sats; Prime terms {:?}",
              (caps.invoice, caps.total), wcfg.caps, wcfg.max_owed_carry_sats, wcfg.terms);
    wcfg.amount = match arg("--work-units") {
        Some(n) => Amount::Fixed(n.parse().expect("work units")),
        None => Amount::Priced(Pricing { price_sats: price, bits, block_value_sats: subsidy, fee_bps: wcfg.terms.fee_bps,
                                         haircut_bps: arg("--haircut-bps").map(|h| h.parse().expect("haircut")).unwrap_or(SHIPPED_HAIRCUT_BPS) }),
    };
    let data = std::path::PathBuf::from(opt("--data-dir", "XBT_WORK_DATA_DIR").unwrap_or_else(|| "xbt-work-provider-data".into()));
    let die = |e: xbt402::ChannelError| -> ! {
        eprintln!("xbt-work-provider: {e}");
        std::process::exit(2);
    };
    // the ledger first: its lock keeps a second process off this data dir, key file and work book included
    let ledger = Ledger::open(&data.join("channels.jsonl")).unwrap_or_else(|e| die(e));
    let sk = load_or_create_secret(&data.join("payto.key")).unwrap_or_else(|e| die(e));
    wcfg.state_path = match arg("--state") {
        Some(s) if s == "off" => {
            eprintln!("state: --state off: the work book is in memory only, every balance is lost on restart");
            None
        }
        Some(s) => Some(s.into()),
        None => Some(data.join("work.json")),
    };
    let work = Arc::new(WorkProvider::new(wcfg).unwrap_or_else(|e| {
        eprintln!("xbt-work-provider: {e}");
        std::process::exit(2);
    }));
    let chain: Arc<dyn ChainBackend> = Arc::new(node.clone());
    let prov = Arc::new(Provider::new(chain, sk, ProviderConfig::new(&net), ledger,
                                      Box::new(move |_, p| if p.starts_with("/v1/") { price } else { 0 }),
                                      Box::new(|_, p, _| answer(p))).unwrap_or_else(|e| die(e))
        .with_scheme(Arc::new(WorkScheme(work.clone()))));
    let (w, every) = (prov.clone(), num::<u64>("--watch-secs", "XBT_WORK_WATCH_SECS").unwrap_or(5).max(1));
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(every));
        match w.close_due() {
            Ok(closed) if !closed.is_empty() => eprintln!("watcher: closed {closed:?}"),
            Ok(_) => {}
            Err(e) => eprintln!("watcher: {e}"),
        }
    });
    // pull receipts through the relay, and follow the epoch (§6.3: re-price new 402s)
    let (w2, n2) = (work.clone(), node.clone());
    let pull_secs: u64 = arg("--pull-secs").map(|p| p.parse().expect("pull secs")).unwrap_or(3);
    std::thread::spawn(move || {
        let t = UreqTransport::default();
        loop {
            for (inv, r) in if pull_secs > 0 { w2.refresh(&t) } else { vec![] } {
                match r {
                    Ok(0) => {}
                    Ok(d) => eprintln!("relay: invoice {inv}: +{d} work units credited (verified under the Prime key)"),
                    Err(e) => eprintln!("relay: invoice {inv}: {e}"),
                }
            }
            if let Ok(b) = tip_bits(&n2) {
                let v = n2.call("getblockstats", json!([block_count(&n2).unwrap_or(0), ["subsidy"]])).ok()
                    .and_then(|s| s["subsidy"].as_u64()).unwrap_or(subsidy);
                if w2.set_epoch(b, v) {
                    eprintln!("epoch: bits {b:08x}, block value {v} sats: new 402s quote {} work units", w2.amount(price).unwrap_or(0));
                    if caps.invoice.priced() || caps.total.priced() {
                        let c = caps.at(b, v, price);
                        eprintln!("caps: per invoice {:?}, total {:?} work units at this epoch", c.per_invoice, c.total);
                        if let Err(e) = w2.set_caps(c) {
                            eprintln!("caps: {e}");
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(pull_secs.clamp(1, 3)));
        }
    });
    let svc = Arc::new(Service { prov: prov.clone(), work: work.clone(), rpc: node, window_url: arg("--window-url"), admin: flag("--admin") });
    // audit every pool block `depth` deep on its own (§10.3: RECOMMENDED k = 6), unless told not to;
    // what a passing block's coinbase paid for covers credit, and held credit follows
    let depth = match (num_or_off::<u32>("--audit-depth", "XBT_WORK_AUDIT_DEPTH"), svc.window_url.is_some()) {
        (Some(d), _) => d,
        (None, true) => Some(SHIPPED_AUDIT_DEPTH),
        (None, false) => None,
    };
    match (depth, svc.window_url.is_some()) {
        (Some(d), true) => eprintln!("audit: every block {d} deep, on its own"),
        (Some(_), false) => eprintln!("audit: --audit-depth without --window-url: NO AUDIT RUNS; credit stops for good at the total cap"),
        (None, true) => eprintln!("audit: off (--audit-depth off): only POST /admin/xbt-work/audit audits; credit stops at the total cap until it does"),
        (None, false) => eprintln!("audit: no --window-url: NO AUDIT RUNS; credit stops for good at the total cap"),
    }
    if let Some(depth) = depth.filter(|_| svc.window_url.is_some()) {
        let s2 = svc.clone();
        let mut next = num::<u32>("--audit-from", "XBT_WORK_AUDIT_FROM")
            .unwrap_or_else(|| block_count(&s2.rpc).unwrap_or(0).saturating_sub(depth + 100).max(1));
        std::thread::spawn(move || {
            let t = UreqTransport::default();
            loop {
                if let Ok(tip) = block_count(&s2.rpc) {
                    match s2.reorgs(tip) {
                        Ok(Some(low)) => next = next.min(low),
                        Ok(None) => {}
                        Err(e) => eprintln!("audit: reorg check: {e}"),
                    }
                    let to = tip.saturating_sub(depth);
                    if to >= next {
                        let _ = s2.work.refresh(&t);
                        let (verdicts, n) = s2.audit_range(&t, next, to);
                        for (h, ok) in verdicts {
                            let (u, held) = s2.work.exposure();
                            eprintln!("audit: block {h}: {} (unaudited {u}, held {held} work units, owed carry {} sats)",
                                      if ok { "PASS" } else { "FAIL" }, s2.work.carry().owed());
                        }
                        next = n;
                    }
                }
                std::thread::sleep(Duration::from_secs(2));
            }
        });
    }
    let hs = serve_service(svc, &format!("127.0.0.1:{port}"), 4).expect("bind");
    println!("xbt-work-provider ready on 127.0.0.1:{port} network {net} channel payTo {} work payTo {} amount {} work units / {price} sat",
             prov.pay_to(), work.cfg.identity, work.amount(price).unwrap_or(0));
    for h in hs {
        let _ = h.join();
    }
}
