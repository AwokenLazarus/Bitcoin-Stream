//! The Rust payer against the Rust provider, in process: a mock chain that tracks outputs and a
//! transport that calls `Provider::serve` directly. Covers the whole lifecycle (open, paid calls,
//! close, rollover, refund), both billings, v1.2 payee-pays, conditional sales, metering, the
//! watcher, restarts from the ledger, refusals, and hostile input.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use xbt402::channel::{FeePayer, DUST};
use xbt402::client::{split_url, Client, ClientConfig, Transport, Wallet};
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::wire::*;
use xbt402::{ChannelError, Result};
use xbt_primitives::address::address_to_spk;
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

const NET: &str = "bip122:11111111111111111111111111111111";

#[derive(Default)]
struct MemChain {
    tip: Mutex<u32>,
    utxos: Mutex<HashMap<(String, u32), UtxoInfo>>,
    sent: Mutex<Vec<Tx>>,
    n: Mutex<u64>,
}

impl MemChain {
    fn new() -> Arc<Self> {
        let c = Self::default();
        *c.tip.lock().unwrap() = 1_000;
        Arc::new(c)
    }
    fn sent(&self) -> Vec<Tx> {
        self.sent.lock().unwrap().clone()
    }
}

impl ChainBackend for MemChain {
    fn block_count(&self) -> Result<u32> {
        Ok(*self.tip.lock().unwrap())
    }
    fn get_tx_out(&self, txid: &str, vout: u32, _m: bool) -> Result<Option<UtxoInfo>> {
        Ok(self.utxos.lock().unwrap().get(&(txid.to_string(), vout)).cloned())
    }
    fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        let tx = Tx::parse_hex(hex)?;
        let mut u = self.utxos.lock().unwrap();
        for i in &tx.inputs {
            if u.remove(&(i.prevout.txid_hex(), i.prevout.vout)).is_none() && !tx.inputs.is_empty() && i.prevout.vout < 1000 {
                // spending an output we do not know: the node would refuse
                if !self.sent.lock().unwrap().iter().any(|t| t.txid() == tx.txid()) {
                    return Err(ChannelError::new("rpc_error", "missing inputs"));
                }
            }
        }
        for (n, o) in tx.outputs.iter().enumerate() {
            u.insert((tx.txid(), n as u32), UtxoInfo { confirmations: 1, value: o.value as u64, script_pubkey: o.script_pubkey.clone(), coinbase: false });
        }
        self.sent.lock().unwrap().push(tx.clone());
        Ok(tx.txid())
    }
    fn has_transaction(&self, txid: &str) -> Result<bool> {
        Ok(self.sent.lock().unwrap().iter().any(|t| t.txid() == txid))
    }
}

struct MemWallet(Arc<MemChain>);

impl Wallet for MemWallet {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        let mut n = self.0.n.lock().unwrap();
        *n += 1;
        let txid = hex::encode(sha256(format!("funding {n}").as_bytes()));
        let spk = address_to_spk(address, None).map_err(|e| ChannelError::new("bad_address", e.to_string()))?;
        self.0.utxos.lock().unwrap().insert((txid.clone(), 0), UtxoInfo { confirmations: 1, value: sats, script_pubkey: spk, coinbase: false });
        Ok((txid, 0))
    }
}

struct Local(Arc<Provider>);

impl Transport for Local {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        let (_, path) = split_url(url);
        Ok(self.0.serve(method, &path, headers, body, url, None))
    }
}

fn secret(label: &str) -> SecretKey {
    SecretKey::from_slice(&sha256(label.as_bytes())).unwrap()
}

fn provider_with(chain: Arc<MemChain>, cfg: ProviderConfig, ledger: Ledger) -> Arc<Provider> {
    Arc::new(Provider::new(chain, secret("provider payTo"), cfg, ledger, Box::new(|_, _| 150),
                           Box::new(|_, p, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())],
                                                                  json!({"answer": p}).to_string().into_bytes()))).unwrap())
}

fn client(chain: &Arc<MemChain>, prov: &Arc<Provider>) -> Client {
    let c = chain.clone();
    Client::new(ClientConfig::new(NET), Box::new(Local(prov.clone())), Box::new(MemWallet(chain.clone())),
                Box::new(move || c.block_count()))
}

const O: &str = "https://api.example";

fn outputs_to(tx: &Tx, spk: &[u8]) -> i64 {
    tx.outputs.iter().filter(|o| o.script_pubkey == spk).map(|o| o.value).sum()
}

#[test]
fn postpay_ten_calls_then_cooperative_close() {
    let chain = MemChain::new();
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::in_memory());
    let mut c = client(&chain, &prov);
    for i in 0..10 {
        let r = c.request("POST", &format!("{O}/v1/infer?i={i}"), b"{}").unwrap();
        assert_eq!(r.status, 200, "call {i}: {}", String::from_utf8_lossy(&r.body));
    }
    let ch = c.channels[O].clone();
    assert_eq!(ch.receipts.len(), 10);
    assert_eq!(ch.spent_msat, 1_500_000);
    let r = c.close(O).unwrap();
    assert_eq!(r["cum"], "1500");
    assert_eq!(r["unpaidMsat"], "0");
    assert!(r.get("payeeFee").is_none() && r.get("payeeNet").is_none(), "v1.1 answer unchanged: {r}");
    assert_eq!(r.as_object().unwrap().keys().collect::<Vec<_>>(), ["chan", "txid", "cum", "unpaidMsat"]);
    let close = chain.sent().last().unwrap().clone();
    let p = &ch.payer.params;
    assert_eq!(outputs_to(&close, &p.payee_spk), 1500);
    assert_eq!(outputs_to(&close, &p.payer_spk), (p.capacity - 600 - 1500) as i64);
    // a second close is idempotent
    assert_eq!(c.close(O).unwrap()["txid"], r["txid"]);
    // the refund the client kept spends the same funding, after expiry, to the payer
    let refund = Tx::parse_hex(&ch.refund_hex).unwrap();
    assert_eq!(refund.locktime, p.expiry);
    assert_eq!(refund.outputs[0].value as u64, p.capacity - 600);
}

#[test]
fn prepay_pays_before_each_call() {
    let chain = MemChain::new();
    let mut cfg = ProviderConfig::new(NET);
    cfg.billing = "prepay".into();
    let prov = provider_with(chain.clone(), cfg, Ledger::in_memory());
    let mut c = client(&chain, &prov);
    for _ in 0..5 {
        assert_eq!(c.request("GET", &format!("{O}/v1/q"), b"").unwrap().status, 200);
    }
    let ch = &c.channels[O];
    // the first state is the least one (546), then each call is paid in advance
    assert_eq!(ch.payer.signed, 750);
    assert_eq!(prov.channel_state(&ch.payer.params.channel_id()).unwrap().best_cum, 750);
}

#[test]
fn payee_pays_v12_close_fee_comes_out_of_the_payee() {
    let chain = MemChain::new();
    let mut cfg = ProviderConfig::new(NET);
    cfg.close_fee_payer = FeePayer::Payee;
    let prov = provider_with(chain.clone(), cfg, Ledger::in_memory());
    let mut c = client(&chain, &prov);
    for _ in 0..10 {
        assert_eq!(c.request("GET", &format!("{O}/v1/q"), b"").unwrap().status, 200);
    }
    let p = c.channels[O].payer.params.clone();
    assert_eq!(p.close_fee_payer, FeePayer::Payee);
    assert_eq!(p.min_amount(), DUST + 600);
    let r = c.close(O).unwrap();
    let close = chain.sent().last().unwrap().clone();
    assert_eq!(outputs_to(&close, &p.payee_spk), 1500 - 600);
    assert_eq!(outputs_to(&close, &p.payer_spk), (p.capacity - 1500) as i64);
    // AGP-029: the report is the gross cum the payer paid, the fee is the payee's, nothing is unpaid
    assert_eq!(r, json!({"chan": p.channel_id(), "txid": close.txid(), "cum": "1500", "unpaidMsat": "0",
                         "payeeFee": "600", "payeeNet": "900"}));
    let chan = p.channel_id();
    let sig = hex::encode(xbt_primitives::ecdsa::sign(c.channels[O].payer.secret().unwrap(), &xbt402::wire::close_message(&chan)));
    let acc = prov.requirements(150);
    let s = prov.facilitator_settle(&json!({"x402Version": 2, "paymentPayload": {"x402Version": 2, "accepted": acc, "payload": {"chan": chan, "sig": sig}},
                                            "paymentRequirements": acc}));
    assert_eq!((&s["amount"], &s["transaction"]), (&json!("1500"), &json!(close.txid())));
    assert_eq!(s["extra"], json!({"chan": chan, "unpaidMsat": "0", "payeeFee": "600", "payeeNet": "900"}));
}

#[test]
fn conditional_sale_delivers_and_folds() {
    let chain = MemChain::new();
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::in_memory());
    prov.offer_conditional("/v1/report", 900, b"the secret report", None);
    let mut c = client(&chain, &prov);
    assert_eq!(c.request("GET", &format!("{O}/v1/q"), b"").unwrap().status, 200);
    let (r, plain) = c.request_conditional("GET", &format!("{O}/v1/report"), b"").unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(plain, b"the secret report");
    let ch = &c.channels[O];
    // the increment was folded into a plain state and acknowledged through /x402/verify
    assert_eq!(ch.acked_cum, ch.payer.signed);
    let st = prov.channel_state(&ch.payer.params.channel_id()).unwrap();
    assert_eq!(st.best_cum, ch.payer.signed);
    assert!(st.best_cum >= 546 + 900 - 546);
    // the next buyer gets a fresh key
    let (_, again) = client(&chain, &prov).request_conditional("GET", &format!("{O}/v1/report"), b"").unwrap();
    assert_eq!(again, b"the secret report");
}

#[test]
fn watcher_closes_with_an_unfolded_conditional_state_and_claims() {
    let chain = MemChain::new();
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::in_memory());
    prov.offer_conditional("/v1/report", 1_000, b"deliverable", None);
    let mut c = client(&chain, &prov);
    c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    c.request("GET", &format!("{O}/v1/q"), b"").unwrap();   // signs 546
    // sign the hash lock but never fold it: drive the conditional call by hand
    let pr = unb64json(prov.serve("GET", "/v1/report", &[], b"", "", None).header("PAYMENT-REQUIRED").unwrap()).unwrap();
    let acc = pr["accepts"][0].clone();
    let ch = c.channels.get_mut(O).unwrap();
    let h: [u8; 32] = hex::decode(acc["extra"]["conditional"]["hash"].as_str().unwrap()).unwrap().try_into().unwrap();
    let cp = xbt402::conditional::ConditionalParams::new(ch.payer.params.clone(), h, 1_000, 10).unwrap();
    let tx = cp.state_tx(ch.payer.signed).unwrap();
    let sig = hex::encode(xbt402::channel::sign_with_type(ch.payer.secret().unwrap(), &cp.sighash(&tx).unwrap(), 0x21));
    ch.seq += 1;
    let chan = ch.payer.params.channel_id();
    let mut pl = json!({"chan": chan, "seq": ch.seq, "cum": ch.payer.signed.to_string(), "hashlock": hex::encode(h), "sig": sig});
    pl["auth"] = request_auth(&ch.auth_key, &chan, pl.get("seq"), pl.get("cum"), pl.get("sig").and_then(Value::as_str),
                              &request_digest("GET", "/v1/report", b"")).into();
    let r = prov.serve("GET", "/v1/report", &[("PAYMENT-SIGNATURE".into(), b64json(&payment_payload(&acc, &pl)))], b"", "", None);
    assert_eq!(r.status, 200);
    let expiry = ch.payer.params.expiry;
    *chain.tip.lock().unwrap() = expiry - prov.cfg.close_margin;
    let closed = prov.close_due().unwrap();
    assert_eq!(closed.len(), 1);
    let sent = chain.sent();
    let claim = sent.iter().find(|t| t.inputs[0].prevout.txid_hex() == closed[0]).expect("claim");
    // the claim reveals k, so the payer recovers the deliverable even without the response
    let ch = c.channels.get_mut(O).unwrap();
    ch.pending_cond = Some(xbt402::client::PendingCond { hash: h, cipher: hex::decode(acc["extra"]["conditional"]["cipher"].as_str().unwrap()).unwrap(), amount: 1_000 });
    assert_eq!(c.recover_conditional(O, claim).unwrap(), b"deliverable");
    let st = prov.channel_state(&chan).unwrap();
    assert!(st.extra["cond_close"].as_bool().unwrap());
    assert_eq!(st.extra["close_paid"], json!(546 + 1_000));
}

#[test]
fn rollover_pays_and_funds_the_next_channel() {
    let chain = MemChain::new();
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::in_memory());
    let mut c = client(&chain, &prov);
    for _ in 0..8 {
        c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    }
    let old = c.channels[O].payer.params.clone();
    let r = c.rollover(O).unwrap();
    let roll = chain.sent().last().unwrap().clone();
    assert_eq!(r["amount"], json!(1_200));
    assert_eq!(outputs_to(&roll, &old.payee_spk), 1_200);
    assert_eq!(roll.outputs[1].value as u64, old.capacity - 600 - 1_200);
    let opened = c.open_rolled(O).unwrap();
    assert_eq!(opened["chan"], r["nextChan"]);
    for _ in 0..3 {
        assert_eq!(c.request("GET", &format!("{O}/v1/q"), b"").unwrap().status, 200);
    }
    assert_eq!(c.channels[O].payer.params.channel_id(), r["nextChan"].as_str().unwrap());
    assert!(prov.channel_state(&old.channel_id()).unwrap().extra.contains_key("rollover_to"));
}

#[test]
fn metered_charges_and_failed_calls() {
    let chain = MemChain::new();
    let prov = Arc::new(Provider::new(chain.clone(), secret("provider payTo"), ProviderConfig::new(NET), Ledger::in_memory(),
                                      Box::new(|_, _| 150),
                                      Box::new(|_, p, _| HttpResponse::new(if p.starts_with("/boom") { 503 } else { 200 }, vec![], b"x".to_vec())))
        .unwrap().with_charge(Box::new(|_, _, _, body| 40 * body.len() as i64)));
    let mut c = client(&chain, &prov);
    c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    assert_eq!(c.channels[O].receipts[0]["charged"], "40");
    c.request("GET", &format!("{O}/boom"), b"").unwrap();
    assert_eq!(c.channels[O].receipts[1]["charged"], "0");
    assert_eq!(c.channels[O].spent_msat, 40_000);
}

#[test]
fn refusals() {
    let chain = MemChain::new();
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::in_memory());
    let mut c = client(&chain, &prov);
    c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    // capture a paid call's header by replaying the client's next payload
    let ch = c.channels.get_mut(O).unwrap();
    ch.seq += 1;
    let chan = ch.payer.params.channel_id();
    // postpay: this call owes the first call's 150 sat, so it carries the least state (546)
    let sig546 = hex::encode(ch.payer.sign_state(546).unwrap());
    let mut pl = json!({"chan": chan, "seq": ch.seq, "cum": "546", "sig": sig546});
    pl["auth"] = request_auth(&ch.auth_key, &chan, pl.get("seq"), pl.get("cum"), Some(&sig546), &request_digest("GET", "/v1/q", b"")).into();
    let acc = ch.accepted.clone();
    let hdr = vec![("PAYMENT-SIGNATURE".to_string(), b64json(&payment_payload(&acc, &pl)))];
    assert_eq!(prov.serve("GET", "/v1/q", &hdr, b"", "", None).status, 200);
    let replay = prov.serve("GET", "/v1/q", &hdr, b"", "", None);
    let b: Value = xbt402::json::parse_slice(&replay.body).unwrap();
    assert_eq!((replay.status, b["error"].as_str().unwrap(), b.get("channel").is_none()), (402, "bad_auth", true));
    // the same payload for another request body does not authenticate
    let mut pl2 = pl.clone();
    pl2["seq"] = json!(ch.seq + 5);
    let other = vec![("PAYMENT-SIGNATURE".to_string(), b64json(&payment_payload(&acc, &pl2)))];
    let b: Value = xbt402::json::parse_slice(&prov.serve("GET", "/v1/q", &other, b"", "", None).body).unwrap();
    assert_eq!(b["error"], "bad_auth");
    // wrong network / payTo
    let mut acc2 = acc.clone();
    acc2["network"] = "bip122:22222222222222222222222222222222".into();
    let wrong = vec![("PAYMENT-SIGNATURE".to_string(), b64json(&payment_payload(&acc2, &pl2)))];
    let b: Value = xbt402::json::parse_slice(&prov.serve("GET", "/v1/q", &wrong, b"", "", None).body).unwrap();
    assert_eq!(b["error"], "unsupported_scheme_or_network");
    // a lowered state is stale; a relabelled signature is refused
    let v = prov.facilitator_verify(&facilitator_request(&acc, &json!({"chan": chan, "cum": "547", "sig": sig546})));
    assert_eq!(v["invalidReason"], "invalid_batch_settlement_xbt_signature");
    // body over the limit; the routing lock endpoint (AGP-026) refuses a request without a payment as B1 does
    assert_eq!(prov.serve("POST", "/v1/q", &[], &vec![0u8; MAX_BODY + 1], "", None).status, 400);
    let r = prov.serve("POST", LOCK_PATH, &[], b"{}", "", None);
    assert_eq!((r.status, xbt402::json::parse_slice(&r.body).unwrap()["error"].clone()), (400, json!("bad_payload")));
    assert_eq!(prov.serve("GET", LOCK_PATH, &[], b"", "", None).status, 405);
    // a close not signed by the payer
    let r = prov.serve("POST", CLOSE_PATH, &[], json!({"chan": chan, "sig": "3006020101020101"}).to_string().as_bytes(), "", None);
    assert_eq!(xbt402::json::parse_slice(&r.body).unwrap()["error"], "bad_sig");
    // a price raised mid-channel is refused by the client
    let prov2 = Arc::new(Provider::new(chain.clone(), secret("provider payTo"), ProviderConfig::new(NET), Ledger::in_memory(),
                                       Box::new(|_, _| 5_000), Box::new(|_, _, _| HttpResponse::new(200, vec![], vec![]))).unwrap());
    let mut c2 = client(&chain, &prov2);
    assert_eq!(c2.request("GET", &format!("{O}/v1/q"), b"").unwrap_err().code, "too_expensive");
}

#[test]
fn provider_restarts_from_its_ledger() {
    let dir = std::env::temp_dir().join(format!("xbt402-ledger-{}", std::process::id()));
    let path = dir.join("ledger.jsonl");
    let chain = MemChain::new();
    let mut c;
    {
        let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::open(&path).unwrap());
        c = client(&chain, &prov);
        for _ in 0..4 {
            c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
        }
    }
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::open(&path).unwrap());
    let chan = c.channels[O].payer.params.channel_id();
    let st = prov.channel_state(&chan).unwrap();
    assert_eq!((st.seq, st.spent_msat), (4, 600_000));
    // the client continues against the restarted provider
    let mut c2 = Client::new(ClientConfig::new(NET), Box::new(Local(prov.clone())), Box::new(MemWallet(chain.clone())), Box::new(|| Ok(1_000)));
    c2.channels = c.channels.clone();
    assert_eq!(c2.request("GET", &format!("{O}/v1/q"), b"").unwrap().status, 200);
    assert_eq!(c2.close(O).unwrap()["cum"], "750");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn hostile_requests_never_panic() {
    let chain = MemChain::new();
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::in_memory());
    let mut c = client(&chain, &prov);
    c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    let chan = c.channels[O].payer.params.channel_id();
    let acc = c.channels[O].accepted.clone();
    let junk = [json!(null), json!(-1), json!("x"), json!(1e300), json!([]), json!({}), json!("99999999999999999999999999"), json!(u64::MAX)];
    let mut n = 0;
    for a in &junk {
        for b in &junk {
            let pl = json!({"chan": chan, "seq": a, "cum": b, "sig": a, "auth": b, "hashlock": a});
            let h = vec![("PAYMENT-SIGNATURE".to_string(), b64json(&payment_payload(&acc, &pl)))];
            let _ = prov.serve("GET", "/v1/q", &h, b"", "", None);
            for path in [OPEN_PATH, CLOSE_PATH, ROLLOVER_PATH, FACILITATOR_VERIFY, FACILITATOR_SETTLE] {
                let body = json!({"chan": a, "sig": b, "channel": {"payerPub": a, "expiry": b, "vout": a, "txid": b}, "network": NET,
                                  "x402Version": 2, "paymentPayload": {"x402Version": 2, "accepted": acc, "payload": {"chan": chan, "cum": a, "sig": b}},
                                  "paymentRequirements": acc, "amount": a, "next": {"payerPub": b, "expiry": a}});
                let _ = prov.serve("POST", path, &[], body.to_string().as_bytes(), "", None);
                n += 1;
            }
        }
    }
    for h in ["", "!!!", "e30=", "bnVsbA==", &b64json(&json!({"x402Version": 2, "accepted": 1, "payload": 2}))] {
        let _ = prov.serve("GET", "/v1/q", &[("PAYMENT-SIGNATURE".into(), h.into())], b"", "", None);
    }
    assert!(n > 300);
}

// --- AGP-027: payer keys behind the StateSigner seam -------------------------------------------

#[test]
fn signer_backed_client_never_holds_a_payer_key() {
    use xbt402::signer::{LocalSigner, StateSigner};
    let chain = MemChain::new();
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::in_memory());
    prov.offer_conditional("/v1/report", 900, b"the secret report", None);
    let signer: Arc<dyn StateSigner> = Arc::new(LocalSigner::new());
    let mut c = client(&chain, &prov).with_signer(signer.clone());
    for i in 0..4 {
        let r = c.request("POST", &format!("{O}/v1/infer?i={i}"), b"{}").unwrap();
        assert_eq!(r.status, 200, "call {i}: {}", String::from_utf8_lossy(&r.body));
    }
    let ch = c.channels[O].clone();
    assert!(ch.payer.secret().is_none(), "the client holds no payer secret");
    assert!(ch.payer.backend().is_some());
    assert_eq!(ch.auth_key, [0u8; 32], "no ECDH key in the client");
    assert_eq!(ch.receipts.len(), 4);
    // hash-locked sale signed by the signer
    let (_, plain) = c.request_conditional("GET", &format!("{O}/v1/report"), b"").unwrap();
    assert_eq!(plain, b"the secret report");
    // the refund kept at open came from the signer and spends this channel
    let p = c.channels[O].payer.params.clone();
    let refund = Tx::parse_hex(&ch.refund_hex).unwrap();
    assert_eq!(refund.locktime, p.expiry);
    assert_eq!(refund.inputs[0].prevout.txid_hex(), p.funding_txid());
    // the close authorisation comes from the signer too
    let r = c.close(O).unwrap();
    let close = chain.sent().last().unwrap().clone();
    assert_eq!(outputs_to(&close, &p.payee_spk) as u64, py_u64_of(&r["cum"]));
    // a stale state is refused by the signer, not only by the client
    assert_eq!(signer.sign_state(&p.channel_id(), 1).unwrap_err().code, "stale_amount");
}

#[test]
fn signer_backed_rollover_keeps_the_next_key_in_the_signer() {
    use xbt402::signer::{LocalSigner, StateSigner};
    let chain = MemChain::new();
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::in_memory());
    let signer: Arc<dyn StateSigner> = Arc::new(LocalSigner::new());
    let mut c = client(&chain, &prov).with_signer(signer);
    for _ in 0..3 {
        assert_eq!(c.request("GET", &format!("{O}/v1/q"), b"").unwrap().status, 200);
    }
    let old = c.channels[O].payer.params.clone();
    let r = c.rollover(O).unwrap();
    let next = c.channels[O].payer.params.clone();
    assert_ne!(old.channel_id(), next.channel_id());
    assert_eq!(r["nextChan"], format!("{}:1", r["txid"].as_str().unwrap()));
    assert!(c.channels[O].payer.secret().is_none());
    c.open_rolled(O).unwrap();
    assert_eq!(c.request("GET", &format!("{O}/v1/q"), b"").unwrap().status, 200);
}

fn py_u64_of(v: &Value) -> u64 {
    v.as_str().and_then(|s| s.parse().ok()).or_else(|| v.as_u64()).unwrap()
}
