//! The Rust pay-with-work payer for the regtest run (the xbt-063 `flagship.pww_payer` scenario,
//! with the Rust xbt402 Client and the xbt-work payer).
//!
//! xbt-work-payer prepare BASE --state FILE
//!     unpaid call -> 402 offering xbt-channel AND xbt-work; take a work invoice; print the stratum
//!     username to mine as (`<identity>.pw-<invoice>.payer`, the worker-field form)
//! xbt-work-payer pay BASE CALLS SECS --state FILE --rpc-port R --cookie PATH --window-url URL
//!                [--pause-file FILE] [--provider-admin]
//!     wait for the Prime's signed receipts (through the blinded relay) to cover CALLS calls, pay them
//!     with the Rust Client, run the refusal checks, read the coinbases, audit them (payer side: the
//!     third-party bound from receipts and signed window statements; provider side: its own bound,
//!     over the provider's admin endpoint), print the evidence JSON. Exit 0 when every check passes.
//!     `--pause-file`: written once the receipts cover the calls (the harness pauses the miner), then
//!     the receipt must stay unchanged for 12 s before paying, so the refusals see a settled balance.
//! xbt-work-payer call BASE PATH --state FILE
//!     one paid call with the Rust Client (AGP-043: the live cap refusals); prints
//!     `{"status", "error", "code", "balanceWork", "heldWork"}` and exits 0 on HTTP 200, 1 otherwise.
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use xbt402::client::{Client, ClientConfig, Transport, Wallet};
use xbt402::error::{ChannelError, Result as XResult};
use xbt402::http::UreqTransport;
use xbt402::wire::unb64json;
use xbt_work::audit::{audit_block, check_fraud_proof, deferred_sats, expected_sats, receipts_bound, TOLERANCE};
use xbt_work::auth::request_digest;
use xbt_work::book::ReceiptBook;
use xbt_work::payer::{PayerConfig, WorkPayer};
use xbt_work::receipt::{pubkey_from_hex, Signed};
use xbt_work::tools::{arg, block_count, coinbase, flag, network, paid_to, rpc, window};

const CALLS: [&str; 4] = ["/v1/share-change?window=7d", "/v1/pools?window=7d", "/v1/pool/lazarus", "/v1/pools?window=1d"];

struct NoWallet;

impl Wallet for NoWallet {
    fn fund(&self, _: &str, _: u64) -> XResult<(String, u32)> {
        Err(ChannelError::new("no_wallet", "the work payer never funds a channel"))
    }
}

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn meta_path(state: &str) -> String {
    format!("{state}.meta.json")
}

fn payer(state: &str, net: &str) -> Arc<WorkPayer> {
    Arc::new(WorkPayer::new(PayerConfig { network: net.into(), max_amount: 1_000_000, state_path: Some(state.into()), ..Default::default() }).expect("payer"))
}

fn prepare(base: &str, state: &str) {
    let t = UreqTransport::default();
    let url = format!("{base}{}", CALLS[0]);
    let r = t.request("GET", &url, b"", &[]).expect("GET");
    let pr = unb64json(r.header("PAYMENT-REQUIRED").expect("402")).expect("PAYMENT-REQUIRED");
    let schemes: Vec<Value> = pr["accepts"].as_array().into_iter().flatten().map(|a| a["scheme"].clone()).collect();
    let net = pr["accepts"].as_array().into_iter().flatten().find(|a| a["scheme"] == json!("xbt-work")).expect("an xbt-work offer")["network"]
        .as_str().expect("network").to_string();
    let p = payer(state, &net);
    let s = p.prepare(&t, &url).expect("invoice");
    let user = s.username("payer");
    std::fs::write(meta_path(state), xbt402::json::dumps(&json!({"base": base, "network": net, "schemes": schemes, "user": user,
                                                                   "accepted": s.accepted, "preparedAt": now()}))).expect("meta");
    println!("{user}");
}

struct Checks {
    list: Vec<Value>,
    ok: bool,
}

impl Checks {
    fn check(&mut self, cond: bool, what: String) {
        eprintln!("{} {what}", if cond { "  ok  " } else { "  FAIL" });
        self.list.push(json!({"ok": cond, "what": what}));
        self.ok &= cond;
    }
}

fn pay(base: &str, calls: usize, secs: f64, state: &str) -> i32 {
    let meta = xbt402::json::parse(&std::fs::read_to_string(meta_path(state)).expect("prepare first")).expect("meta");
    let net = meta["network"].as_str().expect("network").to_string();
    let node = rpc(&arg("--rpc-port").expect("--rpc-port"), &arg("--cookie").expect("--cookie")).expect("node");
    let window_url = arg("--window-url").expect("--window-url");
    let t = UreqTransport::default();
    let p = payer(state, &net);
    let s = p.session(base).expect("session: run prepare first");
    let (ident, inv) = (s.identity().to_string(), s.invoice_id().to_string());
    let amount = s.amount();
    let pk = pubkey_from_hex(s.accepted["extra"]["primePubkey"].as_str().unwrap_or("")).expect("prime key");
    let mut c = Checks { list: vec![], ok: true };
    c.check(network(&node).ok().as_deref() == Some(net.as_str()), format!("the payer's node is on the offer's network {net}"));
    c.check(meta["schemes"] == json!(["batch-settlement", "xbt-work"]), format!("402 offers both rails: {}", meta["schemes"]));

    // receipts: poll the relay until they cover the calls
    let need = calls as u64 * amount;
    let t0 = Instant::now();
    let prepared = meta["preparedAt"].as_f64().unwrap_or(0.0);
    let (mut receipts, mut first_receipt_s): (Vec<Signed>, Option<f64>) = (vec![], None);
    let mut note = |r: &Signed, receipts: &mut Vec<Signed>| {
        if r.receipt.seq > 0 && receipts.last().map_or(true, |l| l.receipt.seq != r.receipt.seq) {
            eprintln!("  receipt seq {} cum_work {} heights {}..{}", r.receipt.seq, r.receipt.cum_work, r.receipt.first_height, r.receipt.last_height);
            receipts.push(r.clone());
            first_receipt_s.get_or_insert(((now() - prepared) * 10.0).round() / 10.0);
        }
    };
    while t0.elapsed().as_secs_f64() < secs {
        if let Ok(Some(r)) = p.refresh(&t, base) {
            note(&r, &mut receipts);
            if r.receipt.cum_work >= need {
                break;
            }
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    let cum = receipts.last().map(|r| r.receipt.cum_work).unwrap_or(0);
    c.check(cum >= need, format!("Prime receipted {cum} work units for {inv} (needed {need}) in {} s", (now() - prepared).round()));
    c.check(s.invoice.get("relayUrl").is_some(), "payer fetched receipts through the blinded relay (the lookup reveals neither identity nor invoice)".into());
    if receipts.is_empty() {
        println!("{}", json!({"ok": false, "checks": c.list}));
        return 1;
    }
    if let Some(pf) = arg("--pause-file") {
        // the harness pauses the miner; wait until the receipt stops moving
        std::fs::write(&pf, "pause\n").expect("pause file");
        let (mut last, mut still) = (receipts.last().map(|r| r.receipt.seq).unwrap_or(0), Instant::now());
        let t1 = Instant::now();
        while still.elapsed() < Duration::from_secs(12) && t1.elapsed() < Duration::from_secs(120) {
            std::thread::sleep(Duration::from_secs(3));
            if let Ok(Some(r)) = p.refresh(&t, base) {
                note(&r, &mut receipts);
                if r.receipt.seq != last {
                    (last, still) = (r.receipt.seq, Instant::now());
                }
            }
        }
    }
    let last = receipts.last().cloned().expect("a receipt");

    // the paid calls, through the Rust xbt402 Client with the xbt-work payer
    let hn = node.clone();
    let mut client = Client::new(ClientConfig::new(&net), Box::new(UreqTransport::default()), Box::new(NoWallet),
                                 Box::new(move || block_count(&hn).map_err(|e| ChannelError::new(&e.code, e.msg))))
        .with_payer(p.clone());
    let (mut calls_out, mut bal, mut answer) = (vec![], 0u64, Value::Null);
    for (i, path) in CALLS.iter().take(calls).enumerate() {
        let t = Instant::now();
        match client.request("GET", &format!("{base}{path}"), b"") {
            Ok(r) => {
                let ms = (t.elapsed().as_secs_f64() * 10_000.0).round() / 10.0;
                let resp = r.header("PAYMENT-RESPONSE").and_then(|h| unb64json(h).ok()).unwrap_or(Value::Null);
                let rc = &resp["extra"]["receipt"];
                let shape = r.status == 200 && resp["success"] == json!(true) && resp["transaction"] == json!("")
                    && resp["extra"]["chargedAmount"] == json!(amount.to_string()) && rc["charged"] == json!(amount.to_string())
                    && rc["req"] == json!(request_digest("GET", path, b""));
                bal = rc["balanceWork"].as_str().and_then(|b| b.parse().ok()).unwrap_or(0);
                if i == 0 {
                    answer = xbt402::json::parse_slice(&r.body).ok().map(|b| b["pools"][0].clone()).unwrap_or(Value::Null);
                }
                c.check(shape, format!("paid call {path} with work (Rust Client + xbt-work payer): HTTP {}, {ms} ms, SettlementResponse balance {bal}", r.status));
                calls_out.push(json!({"path": path, "status": r.status, "ms": ms, "resp": resp}));
            }
            Err(e) => {
                c.check(false, format!("paid call {path}: {e}"));
                calls_out.push(json!({"path": path, "error": e.to_string()}));
            }
        }
    }
    // spend what the provider still credits (shares can land between the wait and the calls)
    let drained = bal / amount.max(1);
    for _ in 0..drained {
        if let Ok(r) = client.request("GET", &format!("{base}{}", CALLS[1]), b"") {
            let resp = r.header("PAYMENT-RESPONSE").and_then(|h| unb64json(h).ok()).unwrap_or(Value::Null);
            bal = resp["extra"]["receipt"]["balanceWork"].as_str().and_then(|b| b.parse().ok()).unwrap_or(bal);
            calls_out.push(json!({"path": CALLS[1], "status": r.status, "resp": resp, "drain": true}));
        }
    }
    if drained > 0 {
        c.check(bal < amount, format!("receipts covered more than {calls} calls: {drained} more call(s) spent the rest"));
    }

    // refusals, with headers built by hand (auth over the values presented)
    let raw = |hdr: &str, path: &str| -> (u16, Value) {
        let r = t.request("GET", &format!("{base}{path}"), b"", &[("PAYMENT-SIGNATURE".into(), hdr.into())]).expect("GET");
        match r.status {
            402 => (402, unb64json(r.header("PAYMENT-REQUIRED").unwrap_or("")).unwrap_or(Value::Null)),
            s => (s, r.header("PAYMENT-RESPONSE").and_then(|h| unb64json(h).ok()).unwrap_or(Value::Null)),
        }
    };
    let code = |v: &(u16, Value)| format!("{} {}", v.0, v.1["error"].as_str().unwrap_or(""));
    let with = |doc: &Value, sig: &str, path: &str| p.header_with(base, doc, sig, "GET", path, b"").expect("header");
    let (doc, sig) = (last.receipt.to_doc(), hex::encode(last.sig));
    let h = with(&doc, &sig, CALLS[0]);
    let first = raw(&h, CALLS[0]);
    if first.0 == 200 {
        let _ = p.check_response(base, &first.1, "GET", CALLS[0], b"");
    }
    let again = raw(&h, CALLS[0]);
    c.check(again.0 == 402 && again.1["error"] == json!("bad_auth"), format!("captured PAYMENT-SIGNATURE header replayed -> {}", code(&again)));
    let r = raw(&with(&doc, &sig, CALLS[1]), CALLS[1]);
    c.check(r.0 == 402 && r.1["error"] == json!("insufficient_work"), format!("same receipt again once spent -> {} (replay pays nothing)", code(&r)));
    if receipts.len() > 1 {
        let r = raw(&with(&receipts[0].receipt.to_doc(), &hex::encode(receipts[0].sig), CALLS[0]), CALLS[0]);
        c.check(r.0 == 402 && r.1["error"] == json!("insufficient_work"), format!("older receipt (seq {}) -> {}", receipts[0].receipt.seq, code(&r)));
    }
    let mut d = doc.clone();
    d["receipt"]["cum_work"] = json!(1_000_000);
    let r = raw(&with(&d, &sig, CALLS[0]), CALLS[0]);
    c.check(r.1["error"] == json!("bad_sig"), format!("receipt with inflated cum_work -> {}", code(&r)));
    let mut d = doc.clone();
    d["identity"] = json!("bcrt1qsomeoneelse");
    let r = raw(&with(&d, &sig, CALLS[0]), CALLS[0]);
    c.check(r.1["error"] == json!("wrong_identity"), format!("receipt for another identity -> {}", code(&r)));
    let mut d = doc.clone();
    d["invoice"] = json!("inv0000000000000000");
    let r = raw(&with(&d, &sig, CALLS[0]), CALLS[0]);
    c.check(r.1["error"] == json!("unknown_invoice"), format!("receipt for an invoice the provider never issued -> {}", code(&r)));
    // field injection: the Prime must refuse to sign `<inv>|999|...` (HTTP 400), and the provider a non-integer field
    let rurl = s.invoice["receiptUrl"].as_str().unwrap_or("").split('?').next().unwrap_or("").to_string();
    let evil = t.request("GET", &format!("{rurl}?identity={ident}&invoice={inv}|999|999999|1|1|1|1"), b"", &[]).expect("GET");
    let evil_sig = xbt402::json::parse_slice(&evil.body).ok().and_then(|v| v["sig"].as_str().map(str::to_string)).unwrap_or_default();
    c.check(evil.status == 400 && evil_sig.is_empty(),
            format!("Prime refuses to sign a receipt for an out-of-grammar invoice (`inv|999|...`): HTTP {}", evil.status));
    let mut d = doc.clone();
    d["receipt"] = json!({"seq": 999, "cum_work": 999999, "shares": 1, "first_height": 1, "last_height": 1, "difficulty": "1|0|0|0|0|0|0"});
    let r = raw(&with(&d, if evil_sig.is_empty() { &sig } else { &evil_sig }, CALLS[0]), CALLS[0]);
    c.check(r.1["error"] == json!("bad_payload"), format!("receipt with a `|` smuggled into a numeric field -> {}", code(&r)));

    // on-chain: the payer's shares were pool blocks; their coinbases pay the provider's TIDES row
    let (lo, hi) = (receipts[0].receipt.first_height, block_count(&node).unwrap_or(0));
    let mut paid_out = vec![];
    for h in lo..=hi {
        if let Ok((hash, v, outs)) = coinbase(&node, h) {
            let paid = paid_to(&outs, &ident);
            if paid > 0 {
                paid_out.push((h, hash, v, paid));
            }
        }
    }
    c.check(!paid_out.is_empty(), format!("coinbases of the payer's blocks paid the provider identity on-chain: {} sat in {} coinbase output(s)",
                                         paid_out.iter().map(|p| p.3).sum::<u64>(), paid_out.len()));
    // payer-side audit: the third-party bound (§10.4) from the receipts it holds and the signed statements
    let mut audits = vec![];
    for (h, hash, v, paid) in &paid_out {
        let r = match window(&t, &window_url, *h) {
            Ok(Some((sw, def, _))) if sw.verify(&pk) && &sw.stmt.block_hash == hash => {
                let l = receipts_bound(receipts.iter().map(|r| &r.receipt), &sw.stmt);
                let exp = expected_sats(*v, sw.stmt.fee_bps, l, sw.stmt.window_work).unwrap_or(u64::MAX);
                let (owed, _) = deferred_sats(&pk, &sw.stmt, &ident, &def);
                let ok = exp < sw.stmt.min_payout || paid + owed + TOLERANCE >= exp;
                json!({"height": h, "ok": ok, "expectedSats": exp, "paidSats": paid, "deferredSats": owed, "provenWork": l,
                       "windowStart": sw.stmt.window_start, "windowWork": sw.stmt.window_work, "statement": sw.line_doc()})
            }
            Ok(Some(_)) => json!({"height": h, "ok": false, "error": "window statement unsigned, or for another block"}),
            _ => json!({"height": h, "ok": false, "error": "no window statement"}),
        };
        audits.push(r);
    }
    c.check(!audits.is_empty() && audits.iter().all(|a| a["ok"] == json!(true)),
            format!("payer-side coinbase audit of {} pool block(s) vs signed window statements (Rust, third-party bound): {}", audits.len(),
                    if audits.iter().all(|a| a["ok"] == json!(true)) { "PASS".to_string() } else { json!(audits).to_string() }));
    // a deliberately under-paying block: the payer's own book of the receipts it presented convicts it
    let mut book = ReceiptBook::new(&ident, pk, s.accepted["extra"]["primeId"].as_u64().unwrap_or(0) as u32);
    for r in &receipts {
        let _ = book.accept(r, &inv);
    }
    let mut underpay = Value::Null;
    for (h, _, v, _) in paid_out.iter().rev() {
        if let Ok(Some((sw, def, _))) = window(&t, &window_url, *h) {
            if let Ok(o) = audit_block(&book, &sw, *v, 1, &def) {
                if let Some(proof) = o.proof {
                    let ok = check_fraud_proof(&proof, &pk, *v, 1) && !check_fraud_proof(&proof, &pk, *v, o.expected_sats);
                    underpay = json!({"height": h, "expectedSats": o.expected_sats, "proof": proof, "checks": ok});
                    break;
                }
            }
        }
    }
    c.check(underpay["checks"] == json!(true),
            format!("deliberately under-paying block {} emits a fraud proof that checks from its signed contents (expected {} sat)",
                    underpay["height"], underpay["expectedSats"]));
    // provider-side audit: its own bound, over its admin endpoint
    let mut provider_audit = Value::Null;
    if flag("--provider-admin") {
        let req = json!({"from": lo, "to": hi, "underpayHeight": underpay["height"]});
        let r = t.request("POST", &format!("{base}/admin/xbt-work/audit"), xbt402::json::dumps(&req).as_bytes(), &[]).expect("admin");
        provider_audit = xbt402::json::parse_slice(&r.body).unwrap_or(Value::Null);
        let res = provider_audit["results"].as_array().cloned().unwrap_or_default();
        c.check(provider_audit["ok"] == json!(true),
                format!("Rust provider audited {} coinbase(s) with its own receipt book, verified window statements and deferral lines: {}", res.len(),
                        if provider_audit["ok"] == json!(true) { "PASS".to_string() } else { provider_audit.to_string() }));
        c.check(provider_audit["underpay"]["proofChecks"] == json!(true),
                format!("Rust provider's fraud proof for block {} audited as paying 1 sat checks (expected {} sat)", provider_audit["underpay"]["height"],
                        provider_audit["underpay"]["expectedSats"]));
    }
    let user = meta["user"].as_str().unwrap_or("");
    c.check(user.starts_with(&format!("{ident}.pw-{inv}.")), format!("shares mined as {user} (worker-field invoice) were receipted by the Prime"));
    let ev = json!({"payer": "rust (xbt-work-payer)", "answer_top_gainer": answer, "invoice": inv, "identity": ident, "user": user,
                    "prime_pubkey": s.accepted["extra"]["primePubkey"], "first_receipt_s": first_receipt_s,
                    "receipts": receipts.iter().map(|r| r.receipt.to_doc()["receipt"].clone()).collect::<Vec<_>>(), "last_receipt": last.to_doc(),
                    "calls": calls_out,
                    "coinbase_payouts": paid_out.iter().map(|(h, hash, v, p)| json!({"height": h, "block": hash, "coinbaseValueSats": v, "sat": p})).collect::<Vec<_>>(),
                    "payer_audit": audits, "underpay_fraud_proof": underpay, "provider_audit": provider_audit, "checks": c.list, "ok": c.ok});
    println!("{}", xbt402::json::dumps(&ev));
    if c.ok { 0 } else { 1 }
}

fn call(base: &str, path: &str, state: &str) -> i32 {
    let meta = xbt402::json::parse(&std::fs::read_to_string(meta_path(state)).expect("prepare first")).expect("meta");
    let net = meta["network"].as_str().expect("network").to_string();
    let p = payer(state, &net);
    let mut client = Client::new(ClientConfig::new(&net), Box::new(UreqTransport::default()), Box::new(NoWallet), Box::new(|| Ok(0)))
        .with_payer(p.clone());
    let out = match client.request("GET", &format!("{base}{path}"), b"") {
        Ok(r) => {
            let pr = r.header("PAYMENT-REQUIRED").and_then(|h| unb64json(h).ok()).unwrap_or(Value::Null);
            let resp = r.header("PAYMENT-RESPONSE").and_then(|h| unb64json(h).ok()).unwrap_or(Value::Null);
            json!({"status": r.status, "error": pr["error"], "code": pr["error"], "heldWork": pr["work"]["heldWork"],
                   "balanceWork": resp["extra"]["receipt"]["balanceWork"], "creditedWork": resp["extra"]["receipt"]["creditedWork"]})
        }
        Err(e) => json!({"status": Value::Null, "error": e.to_string(), "code": e.code}),
    };
    println!("{}", xbt402::json::dumps(&out));
    if out["status"] == json!(200) { 0 } else { 1 }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let state = arg("--state").expect("--state FILE");
    let code = match a.get(1).map(String::as_str) {
        Some("prepare") => {
            prepare(a.get(2).expect("BASE"), &state);
            0
        }
        Some("call") => call(a.get(2).expect("BASE"), a.get(3).expect("PATH"), &state),
        Some("pay") => pay(a.get(2).expect("BASE"), a.get(3).expect("CALLS").parse().expect("calls"), a.get(4).expect("SECS").parse().expect("secs"), &state),
        _ => {
            eprintln!("usage: xbt-work-payer prepare BASE --state F | pay BASE CALLS SECS --state F --rpc-port R --cookie C --window-url U \
                       | call BASE PATH --state F");
            2
        }
    };
    std::process::exit(code);
}
