//! The Rust provider for the pay-with-work regtest run: a paid JSON API (`/v1/*`, 150 sat) behind
//! the xbt402 Provider, offering `xbt-channel` and `xbt-work` in one 402. The work rail pulls
//! receipts through the blinded relay every few seconds, re-prices on every new epoch (§6.3) and,
//! with `--admin`, audits pool coinbases on request (loopback only).
//!
//! xbt-work-provider --port P --rpc-port R --cookie PATH --identity ADDR --prime-pubkey HEX
//!                   --prime-id N --receipt-url URL [--relay-url URL] [--window-url URL]
//!                   [--state FILE] [--price SAT] [--haircut-bps N] [--work-units N] [--admin]
//!                   [--pull-secs N]   (relay pull interval, default 3; 0: only before an audit)
//!                   [--nta]           (§13.8: refuse an identity that is not key-path P2TR)
//!                   [--audit-depth K [--audit-from H]]   (audit every pool block K deep on its own)
//!                   [--cap-invoice W | --cap-invoice-sats S] [--cap-total W | --cap-total-sats S]
//!                   [--max-carry-sats S] [--carry-growth-blocks N]
//!
//! §13.1 caps (AGP-043): unaudited credit per invoice and in total, in work units, or in sats converted
//! at each epoch's price (without the haircut); owed carry above `--max-carry-sats`, or growing over
//! `--carry-growth-blocks` audited blocks, stops new credit. Every flag also reads an env variable:
//! `XBT_WORK_CAP_INVOICE`, `XBT_WORK_CAP_INVOICE_SATS`, `XBT_WORK_CAP_TOTAL`, `XBT_WORK_CAP_TOTAL_SATS`,
//! `XBT_WORK_MAX_CARRY_SATS`, `XBT_WORK_CARRY_GROWTH_BLOCKS`, `XBT_WORK_AUDIT_DEPTH`, `XBT_WORK_NTA=1`.
//!
//! Admin (only with --admin, only from 127.0.0.1): `POST /admin/xbt-work/audit` with
//! `{"from": H0, "to": H1, "underpayHeight": H?}` audits every coinbase in [H0, H1] that pays the
//! identity against its signed window statement and returns the verdicts, the carry ledger and,
//! for `underpayHeight`, the fraud proof of the same block audited as if it paid 1 sat. Blocks that pay
//! the identity nothing are audited too when the Prime published a statement for them (a block that
//! carried the provider's share). `{"withoutDeferrals": H}` adds the control: block H audited as if its
//! deferral lines were missing (not recorded). `GET /admin/xbt-work/report`: the audit log, the carry
//! ledger, the credit exposure (unaudited, held, caps, frozen).
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use xbt402::funding::ChainBackend;
use xbt402::http::{serve_service, HttpService, UreqTransport};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::rpc::Rpc;
use xbt_primitives::secp256k1::SecretKey;
use xbt_work::audit::{audit_block, check_fraud_proof};
use xbt_work::book::CreditCaps;
use xbt_work::pricing::{work_units_for_price, Pricing};
use xbt_work::provider::{Amount, WorkConfig, WorkProvider, WorkScheme};
use xbt_work::tools::{arg, block_count, coinbase, flag, network, paid_to, rpc, tip_bits, window};

/// `--flag value`, else the env variable.
fn opt(flag: &str, var: &str) -> Option<String> {
    arg(flag).or_else(|| std::env::var(var).ok().filter(|v| !v.trim().is_empty()))
}

fn num<T: std::str::FromStr>(flag: &str, var: &str) -> Option<T> {
    opt(flag, var).map(|v| v.parse().unwrap_or_else(|_| panic!("{flag} / {var}: not a number: {v}")))
}

/// A cap given in work units or in sats (converted at the epoch's price, no haircut).
#[derive(Clone, Copy)]
enum Cap {
    Work(u64),
    Sats(u64),
}

impl Cap {
    fn from_args(work: (&str, &str), sats: (&str, &str)) -> Option<Self> {
        num(work.0, work.1).map(Cap::Work).or_else(|| num(sats.0, sats.1).map(Cap::Sats))
    }

    fn units(self, bits: u32, block_value_sats: u64) -> Option<u64> {
        match self {
            Cap::Work(w) => Some(w),
            Cap::Sats(s) => work_units_for_price(s, bits, block_value_sats, 0, 0).ok(),
        }
    }
}

fn caps_at(ci: Option<Cap>, ct: Option<Cap>, bits: u32, v: u64) -> CreditCaps {
    CreditCaps { per_invoice: ci.and_then(|c| c.units(bits, v)), total: ct.and_then(|c| c.units(bits, v)) }
}

struct Service {
    prov: Arc<Provider>,
    work: Arc<WorkProvider>,
    rpc: Rpc,
    window_url: Option<String>,
    admin: bool,
}

impl Service {
    fn audit(&self, req: &Value) -> xbt_work::Result<Value> {
        let t = UreqTransport::default();
        let wurl = self.window_url.as_deref().ok_or_else(|| xbt_work::WorkError::new("no_window_url", ""))?;
        let tip = block_count(&self.rpc)?;
        let from = req["from"].as_u64().unwrap_or(1) as u32;
        let to = req["to"].as_u64().map(|x| x as u32).unwrap_or(tip).min(tip);
        // pull the latest receipts first so the book's intervals are as tight as they can be
        let _ = self.work.refresh(&t);
        let mut results = vec![];
        for h in from..=to {
            let (hash, v, outs) = coinbase(&self.rpc, h)?;
            let paid = paid_to(&outs, &self.work.cfg.identity);
            let Some((sw, def, _)) = window(&t, wurl, h)? else {
                if paid > 0 {
                    results.push(json!({"height": h, "ok": false, "error": "no window statement"}));
                }
                continue;
            };
            if sw.stmt.block_hash != hash {
                results.push(json!({"height": h, "ok": false, "error": "window statement names another block"}));
                continue;
            }
            match self.work.audit(&sw, &def, v, paid) {
                Ok(o) => results.push(json!({"height": h, "ok": o.ok, "blockHash": hash, "coinbaseValueSats": v, "paidSats": paid, "expectedSats": o.expected_sats,
                                             "deferredSats": o.deferred_sats, "provenWork": o.proven_work, "windowStart": sw.stmt.window_start,
                                             "windowWork": sw.stmt.window_work, "proof": o.proof})),
                Err(e) => results.push(json!({"height": h, "ok": false, "error": e.to_string()})),
            }
        }
        let (unaudited, held) = self.work.exposure();
        let mut out = json!({"identity": self.work.cfg.identity, "results": results, "carry": self.work.carry().to_json(),
                             "credit": {"unauditedWork": unaudited, "heldWork": held},
                             "ok": results.iter().all(|r| r["ok"] == json!(true)) && !results.is_empty()});
        if let Some(h) = req["underpayHeight"].as_u64() {
            // the same block as if it paid 1 sat: the provider's own bound convicts it
            let (_, v, _) = coinbase(&self.rpc, h as u32)?;
            if let Some((sw, def, _)) = window(&t, wurl, h as u32)? {
                let o = audit_block(&self.work.book(), &sw, v, 1, &def)?;
                let checks = o.proof.as_ref().is_some_and(|p| check_fraud_proof(p, self.work.prime_pubkey(), v, 1));
                out["underpay"] = json!({"height": h, "ok": o.ok, "expectedSats": o.expected_sats, "proof": o.proof, "proofChecks": checks});
            }
        }
        if let Some(h) = req["withoutDeferrals"].as_u64() {
            // the control: the same block, its deferral lines left out (not recorded)
            let (_, v, outs) = coinbase(&self.rpc, h as u32)?;
            if let Some((sw, _, _)) = window(&t, wurl, h as u32)? {
                let paid = paid_to(&outs, &self.work.cfg.identity);
                let o = audit_block(&self.work.book(), &sw, v, paid, &[])?;
                let checks = o.proof.as_ref().is_some_and(|p| check_fraud_proof(p, self.work.prime_pubkey(), v, paid));
                out["withoutDeferrals"] = json!({"height": h, "ok": o.ok, "expectedSats": o.expected_sats, "paidSats": paid,
                                                  "proof": o.proof, "proofChecks": checks});
            }
        }
        Ok(out)
    }

    /// Audit every pool block in [from, to] that has a statement (the auto-audit loop): the
    /// heights audited, and whether each passed.
    fn audit_range(&self, t: &UreqTransport, from: u32, to: u32) -> Vec<(u32, bool)> {
        let Some(wurl) = self.window_url.as_deref() else { return vec![] };
        let mut out = vec![];
        for h in from..=to {
            let Ok((hash, v, outs)) = coinbase(&self.rpc, h) else { break };
            let Ok(Some((sw, def, _))) = window(t, wurl, h) else { continue };
            if sw.stmt.block_hash != hash {
                eprintln!("audit: height {h}: the statement names another block; not audited");
                continue;
            }
            match self.work.audit(&sw, &def, v, paid_to(&outs, &self.work.cfg.identity)) {
                Ok(o) => out.push((h, o.ok)),
                Err(e) => eprintln!("audit: height {h}: {e}"),
            }
        }
        out
    }
}

impl HttpService for Service {
    fn body_limit(&self, path: &str) -> usize {
        self.prov.body_limit(path, None)
    }

    fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str) -> HttpResponse {
        if path.starts_with("/admin/") {
            let local = url.starts_with("http://127.0.0.1:") || url.starts_with("http://localhost:");
            if self.admin && local && method == "GET" && path == "/admin/xbt-work/report" {
                let (unaudited, held) = self.work.exposure();
                let mut v = self.work.report();
                v["credit"]["unauditedWork"] = unaudited.into();
                v["credit"]["heldWork"] = held.into();
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
    let mut wcfg = WorkConfig::new(&net, &arg("--identity").expect("--identity"), arg("--prime-id").expect("--prime-id").parse().expect("prime id"),
                                   &arg("--prime-pubkey").expect("--prime-pubkey"), &arg("--receipt-url").expect("--receipt-url"));
    wcfg.relay_url = arg("--relay-url");
    wcfg.state_path = arg("--state").map(Into::into);
    wcfg.invoice_price_sats = price;
    wcfg.nta = flag("--nta") || std::env::var("XBT_WORK_NTA").is_ok_and(|v| v == "1");
    let subsidy = node.call("getblockstats", json!([block_count(&node).expect("height"), ["subsidy"]])).ok()
        .and_then(|s| s["subsidy"].as_u64()).unwrap_or(5_000_000_000);
    let cap_inv = Cap::from_args(("--cap-invoice", "XBT_WORK_CAP_INVOICE"), ("--cap-invoice-sats", "XBT_WORK_CAP_INVOICE_SATS"));
    let cap_tot = Cap::from_args(("--cap-total", "XBT_WORK_CAP_TOTAL"), ("--cap-total-sats", "XBT_WORK_CAP_TOTAL_SATS"));
    wcfg.caps = caps_at(cap_inv, cap_tot, tip_bits(&node).expect("bits"), subsidy);
    wcfg.max_owed_carry_sats = num("--max-carry-sats", "XBT_WORK_MAX_CARRY_SATS");
    wcfg.carry_growth_blocks = num("--carry-growth-blocks", "XBT_WORK_CARRY_GROWTH_BLOCKS");
    wcfg.amount = match arg("--work-units") {
        Some(n) => Amount::Fixed(n.parse().expect("work units")),
        None => Amount::Priced(Pricing { price_sats: price, bits: tip_bits(&node).expect("bits"), block_value_sats: subsidy, fee_bps: 0,
                                         haircut_bps: arg("--haircut-bps").map(|h| h.parse().expect("haircut")).unwrap_or(1000) }),
    };
    let work = Arc::new(WorkProvider::new(wcfg).unwrap_or_else(|e| {
        eprintln!("xbt-work-provider: {e}");
        std::process::exit(2);
    }));
    let mut sk = [0u8; 32];
    getrandom::getrandom(&mut sk).expect("randomness");
    let chain: Arc<dyn ChainBackend> = Arc::new(node.clone());
    let prov = Arc::new(Provider::new(chain, SecretKey::from_slice(&sk).expect("key"), ProviderConfig::new(&net), Ledger::in_memory(),
                                      Box::new(move |_, p| if p.starts_with("/v1/") { price } else { 0 }),
                                      Box::new(|_, p, _| answer(p))).expect("provider")
        .with_scheme(Arc::new(WorkScheme(work.clone()))));
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
                    if matches!(cap_inv, Some(Cap::Sats(_))) || matches!(cap_tot, Some(Cap::Sats(_))) {
                        let c = caps_at(cap_inv, cap_tot, b, v);
                        eprintln!("caps: per invoice {:?}, total {:?} work units at this epoch", c.per_invoice, c.total);
                        let _ = w2.set_caps(c);
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(pull_secs.clamp(1, 3)));
        }
    });
    let svc = Arc::new(Service { prov: prov.clone(), work: work.clone(), rpc: node, window_url: arg("--window-url"), admin: flag("--admin") });
    // audit every pool block `depth` deep on its own (§10.3: RECOMMENDED k = 6); a pass releases held credit
    if let Some(depth) = num::<u32>("--audit-depth", "XBT_WORK_AUDIT_DEPTH") {
        let s2 = svc.clone();
        let mut next = num::<u32>("--audit-from", "XBT_WORK_AUDIT_FROM")
            .unwrap_or_else(|| block_count(&s2.rpc).unwrap_or(0).saturating_sub(depth + 100).max(1));
        std::thread::spawn(move || {
            let t = UreqTransport::default();
            loop {
                if let Ok(tip) = block_count(&s2.rpc) {
                    let to = tip.saturating_sub(depth);
                    if to >= next {
                        let _ = s2.work.refresh(&t);
                        for (h, ok) in s2.audit_range(&t, next, to) {
                            let (u, held) = s2.work.exposure();
                            eprintln!("audit: block {h}: {} (unaudited {u}, held {held} work units, owed carry {} sats)",
                                      if ok { "PASS" } else { "FAIL" }, s2.work.carry().owed());
                        }
                        next = to + 1;
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
