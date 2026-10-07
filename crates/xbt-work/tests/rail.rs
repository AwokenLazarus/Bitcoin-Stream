//! The xbt-work rail end to end, in process: the xbt402 Provider offering xbt-channel and
//! xbt-work, the xbt402 Client paying with the xbt-work payer, a Rust Prime key pushing receipts
//! to an in-memory blinded relay, every §9.1 refusal, the 5xx release, durable state, and the
//! coinbase audit with carry.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use xbt402::client::{Client, ClientConfig, Transport, Wallet};
use xbt402::error::{ChannelError, Result as XResult};
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::wire::{b64json, unb64json};
use xbt_primitives::secp256k1::SecretKey;
use xbt_work::audit::{check_fraud_proof, Deferral, WindowStatement};
use xbt_work::book::CreditCaps;
use xbt_work::payer::{PayerConfig, WorkPayer};
use xbt_work::provider::{Amount, WorkConfig, WorkProvider, WorkScheme};
use xbt_work::receipt::{PrimeKey, WorkReceipt};
use xbt_work::relay;

const NET: &str = "bip122:00000000000000000000000000000001";
const PROV: &str = "bcrt1q76vavszzsq657n375vk6updhxm0tfay7k28cc3";
const API: &str = "http://api.test";
const RELAY: &str = "http://relay.test";

struct Chain;

impl ChainBackend for Chain {
    fn block_count(&self) -> XResult<u32> {
        Ok(200)
    }
    fn get_tx_out(&self, _: &str, _: u32, _: bool) -> XResult<Option<UtxoInfo>> {
        Ok(None)
    }
    fn send_raw_transaction(&self, _: &str) -> XResult<String> {
        Err(ChannelError::code("no"))
    }
    fn has_transaction(&self, _: &str) -> XResult<bool> {
        Ok(false)
    }
}

struct NoWallet;

impl Wallet for NoWallet {
    fn fund(&self, _: &str, _: u64) -> XResult<(String, u32)> {
        Err(ChannelError::new("no_wallet", "this payer mines, it never funds a channel"))
    }
}

/// The in-process network: the API origin and the relay.
struct Net {
    api: Mutex<Option<Arc<Provider>>>,
    relay: Mutex<HashMap<String, Vec<u8>>>,
}

#[derive(Clone)]
struct T(Arc<Net>);

impl Transport for T {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> XResult<HttpResponse> {
        if let Some(lk) = url.strip_prefix(&format!("{RELAY}/")) {
            return Ok(match self.0.relay.lock().unwrap().get(lk) {
                Some(b) => HttpResponse::new(200, vec![], b.clone()),
                None => HttpResponse::new(404, vec![], b"not found".to_vec()),
            });
        }
        let path = url.strip_prefix(API).expect("api url");
        let p = self.0.api.lock().unwrap().clone().expect("provider");
        Ok(p.serve(method, path, headers, body, url, None))
    }
}

struct World {
    t: T,
    prime: PrimeKey,
    work: Arc<WorkProvider>,
}

impl World {
    fn new(state: Option<std::path::PathBuf>) -> Self {
        Self::new_with(state, |_| {})
    }

    fn new_with(state: Option<std::path::PathBuf>, f: impl FnOnce(&mut WorkConfig)) -> Self {
        let prime = PrimeKey::from_seed(70, &[9u8; 32]);
        let net = Arc::new(Net { api: Mutex::new(None), relay: Mutex::new(HashMap::new()) });
        let mut cfg = WorkConfig::new(NET, &PROV.to_uppercase(), 70, &format!("{}{}", prime.pubkey_hex(), "ab".repeat(32)), "http://prime.test/receipt");
        cfg.relay_url = Some(RELAY.into());
        cfg.amount = Amount::Fixed(10);
        cfg.state_path = state;
        f(&mut cfg);
        let work = Arc::new(WorkProvider::new(cfg).unwrap());
        let w = World { t: T(net), prime, work };
        w.install();
        w
    }

    fn install(&self) {
        let prov = Provider::new(Arc::new(Chain), SecretKey::from_slice(&[5u8; 32]).unwrap(), ProviderConfig::new(NET), Ledger::in_memory(),
                                 Box::new(|_, _| 150),
                                 Box::new(|_, p, _| if p == "/v1/fail" { HttpResponse::new(503, vec![], b"down".to_vec()) }
                                          else { HttpResponse::new(200, vec![], format!("{{\"answer\": \"{p}\"}}").into_bytes()) }))
            .unwrap().with_scheme(Arc::new(WorkScheme(self.work.clone())));
        *self.t.0.api.lock().unwrap() = Some(Arc::new(prov));
    }

    /// The Prime credits the invoice and pushes the blinded receipt.
    fn credit(&self, inv: &str, seq: u64, cum: u64, first: u32, last: u32) -> WorkReceipt {
        let r = WorkReceipt { seq, cum_work: cum, shares: seq, first_height: first, last_height: last, difficulty: 1, ..WorkReceipt::zero(70, PROV, inv) };
        let doc = self.prime.sign(&r).unwrap().to_doc();
        let blob = relay::seal(xbt402::json::dumps(&doc).as_bytes(), PROV, inv, None).unwrap();
        self.t.0.relay.lock().unwrap().insert(relay::lookup(PROV, inv), blob);
        r
    }

    fn client(&self, payer: Arc<WorkPayer>) -> Client {
        Client::new(ClientConfig::new(NET), Box::new(self.t.clone()), Box::new(NoWallet), Box::new(|| Ok(200))).with_payer(payer)
    }

    fn payer(&self) -> Arc<WorkPayer> {
        Arc::new(WorkPayer::new(PayerConfig { network: NET.into(), max_amount: 100, pinned_prime: Some(self.prime.pubkey_hex()), ..Default::default() }).unwrap())
    }

    fn raw(&self, path: &str, hdr: &str) -> (u16, Value) {
        let r = self.t.request("GET", &format!("{API}{path}"), b"", &[("PAYMENT-SIGNATURE".into(), hdr.into())]).unwrap();
        let h = if r.status == 402 { "PAYMENT-REQUIRED" } else { "PAYMENT-RESPONSE" };
        (r.status, unb64json(r.header(h).unwrap()).unwrap())
    }
}

fn err(v: &Value) -> &str {
    v["error"].as_str().unwrap_or("")
}

#[test]
fn pay_with_work_end_to_end() {
    let w = World::new(None);
    // an unpaid call: one 402 offers both rails
    let r = w.t.request("GET", &format!("{API}/v1/pools"), b"", &[]).unwrap();
    assert_eq!(r.status, 402);
    let pr = unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap();
    let schemes: Vec<&str> = pr["accepts"].as_array().unwrap().iter().map(|a| a["scheme"].as_str().unwrap()).collect();
    assert_eq!(schemes, ["batch-settlement", "xbt-work"]);
    let acc = &pr["accepts"][1];
    assert_eq!((acc["amount"].as_str(), acc["payTo"].as_str(), acc["asset"].as_str()), (Some("10"), Some(PROV), Some("XBT:work-diff1")));

    // take an invoice; the username is the worker-field form under the canonical identity
    let payer = w.payer();
    let s = payer.prepare(&w.t, &format!("{API}/v1/pools")).unwrap();
    let inv = s.invoice_id().to_string();
    assert_eq!(s.username("rig"), format!("{PROV}.pw-{inv}.rig"));
    assert_eq!(xbt_work::grammar::parse_username(&s.username("rig")).invoice.as_deref(), Some(inv.as_str()));
    let mut client = w.client(payer.clone());
    // nothing mined yet
    assert_eq!(client.request("GET", &format!("{API}/v1/pools"), b"").unwrap_err().code, "insufficient_work");

    // 25 units credited: two 10-unit calls, then the balance runs out
    w.credit(&inv, 5, 25, 101, 103);
    let r = client.request("GET", &format!("{API}/v1/pools?window=7d"), b"").unwrap();
    assert_eq!(r.status, 200);
    let sr = unb64json(r.header("PAYMENT-RESPONSE").unwrap()).unwrap();
    assert_eq!(sr["payer"], json!(inv));
    assert_eq!(sr["extra"]["receipt"]["newlyCreditedWork"], json!("25"));
    assert_eq!(sr["extra"]["receipt"]["balanceWork"], json!("15"));
    assert_eq!(sr["transaction"], json!(""));
    let r = client.request("GET", &format!("{API}/v1/share-change"), b"").unwrap();
    assert_eq!(unb64json(r.header("PAYMENT-RESPONSE").unwrap()).unwrap()["extra"]["receipt"]["balanceWork"], json!("5"));
    assert_eq!(client.request("GET", &format!("{API}/v1/x"), b"").unwrap_err().code, "insufficient_work");
    assert_eq!(w.work.balance(&inv), Some((25, 20)));

    // more work; the provider pulls it through the relay itself, then a failing handler is not charged
    w.credit(&inv, 8, 60, 103, 105);
    let pulled = w.work.refresh(&w.t);
    assert_eq!(pulled.len(), 1);
    assert_eq!(pulled[0].1.as_ref().unwrap(), &35);
    let r = client.request("GET", &format!("{API}/v1/fail"), b"").unwrap();
    assert_eq!(r.status, 503);
    let sr = unb64json(r.header("PAYMENT-RESPONSE").unwrap()).unwrap();
    assert_eq!((sr["success"].clone(), sr["extra"]["chargedAmount"].clone()), (json!(false), json!("0")));
    assert_eq!(w.work.balance(&inv), Some((60, 20)));

    // the refusals of §9.1 / §12, with headers built by hand
    let best = payer.session(API).unwrap().best.unwrap();
    let doc = best.receipt.to_doc();
    let sig = hex::encode(best.sig);
    let h = payer.header_with(API, &doc, &sig, "GET", "/v1/a", b"").unwrap();
    assert_eq!(w.raw("/v1/a", &h).0, 200);
    assert_eq!(err(&w.raw("/v1/a", &h).1), "bad_auth", "a captured header replayed");
    let mut d = doc.clone();
    d["receipt"]["cum_work"] = json!(1_000_000);
    assert_eq!(err(&w.raw("/v1/a", &payer.header_with(API, &d, &sig, "GET", "/v1/a", b"").unwrap()).1), "bad_sig");
    let mut d = doc.clone();
    d["identity"] = json!("bcrt1qsomeoneelse");
    assert_eq!(err(&w.raw("/v1/a", &payer.header_with(API, &d, &sig, "GET", "/v1/a", b"").unwrap()).1), "wrong_identity");
    let mut d = doc.clone();
    d["prime_id"] = json!(71);
    assert_eq!(err(&w.raw("/v1/a", &payer.header_with(API, &d, &sig, "GET", "/v1/a", b"").unwrap()).1), "wrong_prime");
    let mut d = doc.clone();
    d["invoice"] = json!("inv0000000000000000");
    assert_eq!(err(&w.raw("/v1/a", &payer.header_with(API, &d, &sig, "GET", "/v1/a", b"").unwrap()).1), "unknown_invoice");
    let mut d = doc.clone();
    d["receipt"] = json!({"seq": 999, "cum_work": 999999, "shares": 1, "first_height": 1, "last_height": 1, "difficulty": "1|0|0|0|0|0|0"});
    assert_eq!(err(&w.raw("/v1/a", &payer.header_with(API, &d, &sig, "GET", "/v1/a", b"").unwrap()).1), "bad_payload");
    // a header for another request (auth covers the request)
    let h = payer.header_with(API, &doc, &sig, "GET", "/v1/a", b"").unwrap();
    assert_eq!(err(&w.raw("/v1/b", &h).1), "bad_auth");
    // wrong network in accepted
    let mut pp = unb64json(&payer.header_with(API, &doc, &sig, "GET", "/v1/a", b"").unwrap()).unwrap();
    pp["accepted"]["network"] = json!("bip122:ffff");
    assert_eq!(err(&w.raw("/v1/a", &b64json(&pp)).1), "unsupported_scheme_or_network");
    // an older receipt credits nothing; the balance still pays
    let old = w.prime.sign(&WorkReceipt { seq: 5, cum_work: 25, shares: 5, first_height: 101, last_height: 103, difficulty: 1, ..WorkReceipt::zero(70, PROV, &inv) }).unwrap();
    let (st, sr) = w.raw("/v1/a", &payer.header_with(API, &old.receipt.to_doc(), &hex::encode(old.sig), "GET", "/v1/a", b"").unwrap());
    assert_eq!((st, sr["extra"]["receipt"]["newlyCreditedWork"].clone()), (200, json!("0")));
    // equivocation: the Prime key signs a second state for seq 8
    let twin = w.prime.sign(&WorkReceipt { cum_work: 70, ..best.receipt.clone() }).unwrap();
    assert_eq!(err(&w.raw("/v1/a", &payer.header_with(API, &twin.receipt.to_doc(), &hex::encode(twin.sig), "GET", "/v1/a", b"").unwrap()).1), "equivocation");
    let rep = w.work.report();
    assert_eq!(rep["equivocations"].as_array().unwrap().len(), 1);
    assert_eq!(rep["distrust"]["code"], json!("equivocation"));
    // from here on the provider no longer accepts this Prime key's receipts (§9.1 step 7)
    assert_eq!(err(&w.raw("/v1/a", &payer.header_with(API, &doc, &sig, "GET", "/v1/a", b"").unwrap()).1), "equivocation");
    let (credited, spent) = w.work.balance(&inv).unwrap();
    assert_eq!((credited, spent), (60, 40));

    // invoice issuance is no-store, and the bound on unfunded invoices holds
    let r = w.t.request("POST", &format!("{API}/x402/xbt-work/invoice"), b"", &[]).unwrap();
    assert_eq!((r.status, r.header("Cache-Control")), (200, Some("no-store")));

    // the coinbase audit over the provider's own intervals (§10.2): [101,103] 25 and [103,105] 35
    let stmt = WindowStatement { prime_id: 70, height: 110, block_hash: "cd".repeat(32), window_start: 100, window_work: 1000, min_payout: 546, fee_bps: 0 };
    let sw = w.prime.sign_window(&stmt).unwrap();
    let v = 5_000_000_000u64;
    let ok = w.work.audit(&sw, &[], v, 300_000_000).unwrap();
    assert!(ok.ok);
    assert_eq!((ok.expected_sats, ok.proven_work), (300_000_000, 60));
    let bad = w.work.audit(&sw, &[], v, 100).unwrap();
    assert!(!bad.ok);
    assert!(check_fraud_proof(bad.proof.as_ref().unwrap(), &w.prime.pubkey(), v, 100));
    assert!(!check_fraud_proof(bad.proof.as_ref().unwrap(), &w.prime.pubkey(), v, 300_000_000));
    // a block right after the last share: the latest receipt's span [101,105] does not end below
    // height 105, so the proof also carries the in-span receipt [101,103] that brackets the window
    let sw5 = w.prime.sign_window(&WindowStatement { height: 105, block_hash: "cf".repeat(32), ..stmt.clone() }).unwrap();
    let o5 = xbt_work::audit::audit_block(&w.work.book(), &sw5, v, 1, &[]).unwrap();
    let rs = o5.proof.as_ref().unwrap()["receipts"].as_array().unwrap().clone();
    assert_eq!(rs.len(), 2);
    assert!(rs[0]["message"].as_str().unwrap().ends_with("|101|103|1"));
    assert!(check_fraud_proof(o5.proof.as_ref().unwrap(), &w.prime.pubkey(), v, 1));
    // an unattested provider is carried: the signed deferral line makes it a debt, not a shortfall
    let dl = w.prime.sign_deferral(&Deferral { prime_id: 70, height: 110, block_hash: "cd".repeat(32), identity: PROV.into(), sats: 300_000_000,
                                                reason: "unattested".into() }).unwrap();
    let carried = w.work.audit(&sw, std::slice::from_ref(&dl), v, 0).unwrap();
    assert!(carried.ok && carried.deferred_sats == 300_000_000);
    // a forged line (another key) counts for nothing
    let forged = PrimeKey::from_seed(70, &[1u8; 32]).sign_deferral(&dl.d).unwrap();
    assert!(!w.work.audit(&sw, &[forged], v, 0).unwrap().ok);
    // a later block releases the carry: paid above expected
    let sw2 = w.prime.sign_window(&WindowStatement { height: 111, block_hash: "ce".repeat(32), ..stmt.clone() }).unwrap();
    assert!(w.work.audit(&sw2, &[], v, 600_000_000).unwrap().ok);
    assert_eq!(w.work.carry().owed(), 0);
    // a window statement signed by another key is refused
    let other = PrimeKey::from_seed(70, &[2u8; 32]).sign_window(&stmt).unwrap();
    assert_eq!(w.work.audit(&other, &[], v, 0).unwrap_err().code, "bad_window_sig");
}

#[test]
fn state_survives_a_restart() {
    let dir = std::env::temp_dir().join(format!("xbt-work-rail-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("work.json");
    let _ = std::fs::remove_file(&path);
    let w = World::new(Some(path.clone()));
    let payer = w.payer();
    let inv = payer.prepare(&w.t, &format!("{API}/v1/pools")).unwrap().invoice_id().to_string();
    w.credit(&inv, 3, 30, 101, 102);
    let mut client = w.client(payer.clone());
    assert_eq!(client.request("GET", &format!("{API}/v1/a"), b"").unwrap().status, 200);
    let best = payer.session(API).unwrap().best.unwrap();
    let h = payer.header_with(API, &best.receipt.to_doc(), &hex::encode(best.sig), "GET", "/v1/b", b"").unwrap();
    let (st, sr) = w.raw("/v1/b", &h);
    assert_eq!(st, 200);
    // a call paid outside the Client still goes through the payer's response check
    payer.check_response(API, &sr, "GET", "/v1/b", b"").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // a new process: same book, same n, same spent
    let mut cfg = w.work.cfg.clone();
    cfg.state_path = Some(path.clone());
    let w2 = World { t: w.t.clone(), prime: PrimeKey::from_seed(70, &[9u8; 32]), work: Arc::new(WorkProvider::new(cfg).unwrap()) };
    w2.install();
    assert_eq!(w2.work.balance(&inv), Some((30, 20)));
    assert_eq!(err(&w2.raw("/v1/b", &h).1), "bad_auth", "n survives the restart");
    let mut c2 = w2.client(payer.clone());
    assert_eq!(c2.request("GET", &format!("{API}/v1/c"), b"").unwrap().status, 200);
    assert_eq!(c2.request("GET", &format!("{API}/v1/d"), b"").unwrap_err().code, "insufficient_work");
    let _ = std::fs::remove_dir_all(&dir);
}

/// §13.1 (AGP-043): unaudited credit capped per invoice and in total, the rest held until an audit
/// passes; owed carry over its cap, or growing block after block, stops new credit until released.
#[test]
fn credit_caps_end_to_end() {
    let w = World::new_with(None, |c| {
        c.caps = CreditCaps { per_invoice: Some(30), total: Some(45) };
        c.max_owed_carry_sats = Some(100_000_000);
    });
    let (pa, pb) = (w.payer(), w.payer());
    let ia = pa.prepare(&w.t, &format!("{API}/v1/pools")).unwrap().invoice_id().to_string();
    let ib = pb.prepare(&w.t, &format!("{API}/v1/pools")).unwrap().invoice_id().to_string();
    let (mut ca, mut cb) = (w.client(pa.clone()), w.client(pb.clone()));

    // A mines 50 units: 30 are credited (the invoice cap), 20 held
    w.credit(&ia, 5, 50, 101, 103);
    for i in 0..3 {
        assert_eq!(ca.request("GET", &format!("{API}/v1/a{i}"), b"").unwrap().status, 200);
    }
    assert_eq!(ca.request("GET", &format!("{API}/v1/a3"), b"").unwrap_err().code, "credit_cap");
    let best = pa.session(API).unwrap().best.unwrap();
    let (st, pr) = w.raw("/v1/a3", &pa.header_with(API, &best.receipt.to_doc(), &hex::encode(best.sig), "GET", "/v1/a3", b"").unwrap());
    assert_eq!((st, err(&pr)), (402, "credit_cap"));
    assert_eq!((pr["work"]["creditedWork"].clone(), pr["work"]["heldWork"].clone(), pr["work"]["capInvoiceWork"].clone()),
               (json!("30"), json!("20"), json!("30")));
    // B mines 30: the total cap (45) leaves 15
    w.credit(&ib, 3, 30, 101, 103);
    assert_eq!(cb.request("GET", &format!("{API}/v1/b0"), b"").unwrap().status, 200);
    assert_eq!(cb.request("GET", &format!("{API}/v1/b1"), b"").unwrap_err().code, "credit_cap");
    assert_eq!(w.work.balance(&ib), Some((15, 10)));
    assert_eq!(w.work.exposure(), (45, 35));
    assert_eq!(w.work.report()["credit"]["unauditedWork"], json!(45));

    // a pool block at 104 passes its audit (its bound counts all 80 receipted units, credited or held):
    // the 45 credited are covered, the held 35 are credited
    let v = 5_000_000_000u64;
    let stmt = |h: u32, c: &str| WindowStatement { prime_id: 70, height: h, block_hash: c.repeat(32), window_start: 100, window_work: 1000,
                                                  min_payout: 546, fee_bps: 0 };
    let o = w.work.audit(&w.prime.sign_window(&stmt(104, "a1")).unwrap(), &[], v, 400_000_000).unwrap();
    assert!(o.ok && o.proven_work == 80);
    assert_eq!(w.work.exposure(), (35, 0));
    assert_eq!(w.work.balance(&ia), Some((50, 30)));
    assert_eq!(ca.request("GET", &format!("{API}/v1/a4"), b"").unwrap().status, 200);
    assert_eq!(cb.request("GET", &format!("{API}/v1/b2"), b"").unwrap().status, 200);

    // block 105 (80 units in its window) defers the provider's 400M sats (unattested): owed carry over the 100M cap
    let sw = w.prime.sign_window(&stmt(105, "a2")).unwrap();
    let dl = w.prime.sign_deferral(&Deferral { prime_id: 70, height: 105, block_hash: "a2".repeat(32), identity: PROV.into(), sats: 400_000_000,
                                                reason: "unattested".into() }).unwrap();
    assert!(w.work.audit(&sw, std::slice::from_ref(&dl), v, 0).unwrap().ok);
    // auditing it again counts the carry once
    assert!(w.work.audit(&sw, std::slice::from_ref(&dl), v, 0).unwrap().ok);
    assert_eq!(w.work.carry().owed(), 400_000_000);
    assert_eq!(w.work.report()["credit"]["frozen"], json!("carry_cap"));
    // no new credit while it is owed: A's next receipt is held, the call refused with carry_cap
    w.credit(&ia, 9, 70, 104, 106);
    assert_eq!(w.work.refresh(&w.t).iter().find(|(i, _)| *i == ia).unwrap().1, Ok(0));
    assert_eq!(ca.request("GET", &format!("{API}/v1/a5"), b"").unwrap().status, 200);  // the last 10 of its 50
    assert_eq!(ca.request("GET", &format!("{API}/v1/a6"), b"").unwrap_err().code, "carry_cap");
    // block 106 pays the share plus the carry: released, credit flows again
    let o = w.work.audit(&w.prime.sign_window(&stmt(106, "a3")).unwrap(), &[], v, 800_000_000).unwrap();
    assert!(o.ok && o.expected_sats == 400_000_000);
    assert_eq!(w.work.carry().owed(), 0);
    assert_eq!(w.work.report()["credit"]["frozen"], Value::Null);
    assert_eq!(w.work.balance(&ia), Some((70, 50)));
    assert_eq!(ca.request("GET", &format!("{API}/v1/a7"), b"").unwrap().status, 200);
}

#[test]
fn carry_that_keeps_growing_stops_credit() {
    let w = World::new_with(None, |c| c.carry_growth_blocks = Some(2));
    let payer = w.payer();
    let inv = payer.prepare(&w.t, &format!("{API}/v1/pools")).unwrap().invoice_id().to_string();
    let v = 5_000_000_000u64;
    let grow = |h: u32, sats: u64| {
        let s = WindowStatement { prime_id: 70, height: h, block_hash: format!("{h:064x}"), window_start: 100, window_work: 1000, min_payout: 546, fee_bps: 0 };
        let dl = w.prime.sign_deferral(&Deferral { prime_id: 70, height: h, block_hash: s.block_hash.clone(), identity: PROV.into(), sats,
                                                    reason: "unattested".into() }).unwrap();
        assert!(w.work.audit(&w.prime.sign_window(&s).unwrap(), &[dl], v, 0).unwrap().ok);
    };
    grow(110, 1_000);
    assert_eq!(w.work.report()["credit"]["frozen"], Value::Null);
    grow(111, 1_000);
    assert_eq!(w.work.report()["credit"]["frozen"], json!("carry_growing"));
    w.credit(&inv, 2, 20, 111, 112);
    assert_eq!(w.work.refresh(&w.t)[0].1, Ok(0));
    let mut client = w.client(payer);
    // the first call answers the unpaid 402 with the receipt: the provider's refusal comes back as is
    let r = client.request("GET", &format!("{API}/v1/x"), b"").unwrap();
    assert_eq!((r.status, err(&unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap())), (402, "carry_growing"));
    // the next one (header up front) turns it into the payer's error
    assert_eq!(client.request("GET", &format!("{API}/v1/y"), b"").unwrap_err().code, "carry_growing");
}
