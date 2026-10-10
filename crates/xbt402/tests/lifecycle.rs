//! The Rust payer against the Rust provider, in process: a mock chain that tracks outputs and a
//! transport that calls `Provider::serve` directly. Covers the whole lifecycle (open, paid calls,
//! close, rollover, refund), both billings, v1.2 payee-pays, conditional sales, metering, the
//! watcher, restarts from the ledger, refusals, and hostile input; and the embedder surface of
//! AGP-059 (extra headers and a caller-chosen cum, close-one-channel, the reservation crash window).
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use xbt402::channel::{FeePayer, DUST};
use xbt402::client::{split_url, CallOpts, Client, ClientConfig, Transport, Wallet};
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
    /// AGP-084: the node answers a broadcast with an error and does not have the tx.
    down: Mutex<bool>,
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
    fn down(&self, on: bool) {
        *self.down.lock().unwrap() = on;
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
        if *self.down.lock().unwrap() {
            return Err(ChannelError::new("rpc_error", "timed out"));
        }
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
                              &request_digest_v2("GET", "/v1/report", b"")).into();
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
    pl["auth"] = request_auth(&ch.auth_key, &chan, pl.get("seq"), pl.get("cum"), Some(&sig546), &request_digest_v2("GET", "/v1/q", b"")).into();
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
    // the crash: the client's transport held the first provider (and its ledger lock)
    let channels = c.channels.clone();
    drop(c);
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::open(&path).unwrap());
    let chan = channels[O].payer.params.channel_id();
    let st = prov.channel_state(&chan).unwrap();
    assert_eq!((st.seq, st.spent_msat), (4, 600_000));
    // the client continues against the restarted provider
    let mut c2 = Client::new(ClientConfig::new(NET), Box::new(Local(prov.clone())), Box::new(MemWallet(chain.clone())), Box::new(|| Ok(1_000)));
    c2.channels = channels;
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

// --- AGP-059: the embedder surface -----------------------------------------------------------

/// A provider at `price` sat per call; with `charge`, metered at that many sat per call. A request
/// to `/crash...` copies the ledger file to `snap` while its handler runs (the disk as a crash at
/// that moment leaves it), and `/panic...` panics in the handler.
fn metered(chain: &Arc<MemChain>, ledger: Ledger, price: u64, charge: Option<i64>, snap: Option<(std::path::PathBuf, std::path::PathBuf)>) -> Arc<Provider> {
    let handler = move |_: &str, p: &str, _: &[u8]| {
        if let (true, Some((from, to))) = (p.starts_with("/crash"), &snap) {
            std::fs::copy(from, to).unwrap();
        }
        assert!(!p.starts_with("/panic"), "handler panic");
        HttpResponse::new(200, vec![], b"x".to_vec())
    };
    let prov = Provider::new(chain.clone(), secret("provider payTo"), ProviderConfig::new(NET), ledger, Box::new(move |_, _| price), Box::new(handler)).unwrap();
    Arc::new(match charge {
        Some(c) => prov.with_charge(Box::new(move |_, _, _, _| c)),
        None => prov,
    })
}

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("xbt402-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn a_crash_between_reservation_and_refund_leaves_spent_at_what_was_charged() {
    let dir = tmp("resv");
    let (path, snap) = (dir.join("ledger.jsonl"), dir.join("crashed.jsonl"));
    let chain = MemChain::new();
    let prov = metered(&chain, Ledger::open(&path).unwrap(), 1_000, Some(400), Some((path.clone(), snap.clone())));
    let mut c = client(&chain, &prov);
    c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    let chan = c.channels[O].payer.params.channel_id();
    assert_eq!(prov.channel_state(&chan).unwrap().spent_msat, 400_000);
    // the payer as the crash leaves it: call 2 was sent (its seq is spent) and never answered
    let mut before = c.channels.clone();
    before.get_mut(O).unwrap().seq += 1;
    c.request("GET", &format!("{O}/crash"), b"").unwrap();
    assert_eq!((prov.channel_state(&chan).unwrap().spent_msat, prov.channel_state(&chan).unwrap().reserved_msat()), (800_000, 0));
    // the disk at the crash: call 2's max-price reservation, recorded as one
    let crashed = Ledger::open(&snap).unwrap();
    assert_eq!((crashed.channels[&chan].spent_msat, crashed.channels[&chan].reserved_msat()), (1_400_000, 1_000_000));
    drop(crashed);
    // restart: the reservation was never charged
    let prov2 = metered(&chain, Ledger::open(&snap).unwrap(), 1_000, Some(400), None);
    assert_eq!(prov2.recovered_reservations(), [(chan.clone(), 1_000_000)]);
    let st = prov2.channel_state(&chan).unwrap();
    assert_eq!((st.seq, st.spent_msat, st.reserved_msat()), (2, 400_000, 0));
    // and the refund is on disk: a second restart finds nothing to recover
    drop(prov2);
    let prov2 = metered(&chain, Ledger::open(&snap).unwrap(), 1_000, Some(400), None);
    assert!(prov2.recovered_reservations().is_empty());
    assert_eq!(prov2.channel_state(&chan).unwrap().spent_msat, 400_000);
    // the payer's next call is served, no 402, and spent = charged
    let hits = Sent::default();
    let mut c2 = Client::new(ClientConfig::new(NET), Box::new(Rec(prov2.clone(), hits.clone())), Box::new(MemWallet(chain.clone())), Box::new(|| Ok(1_000)));
    c2.channels = before;
    assert_eq!((c2.channels[O].seq, c2.channels[O].spent_msat), (2, 400_000));
    let r = c2.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    assert_eq!((r.status, hits.lock().unwrap().len()), (200, 1), "one request, no 402");
    assert_eq!(c2.channels[O].receipts.last().unwrap()["spentMsat"], "800000");
    assert_eq!(prov2.channel_state(&chan).unwrap().spent_msat, 800_000);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn an_unmetered_call_in_flight_at_a_crash_is_charged_once_at_its_price() {
    let dir = tmp("resv-fixed");
    let (path, snap) = (dir.join("ledger.jsonl"), dir.join("crashed.jsonl"));
    let chain = MemChain::new();
    let prov = metered(&chain, Ledger::open(&path).unwrap(), 150, None, Some((path.clone(), snap.clone())));
    let mut c = client(&chain, &prov);
    c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    c.request("GET", &format!("{O}/crash"), b"").unwrap();
    let chan = c.channels[O].payer.params.channel_id();
    let prov2 = metered(&chain, Ledger::open(&snap).unwrap(), 150, None, None);
    assert!(prov2.recovered_reservations().is_empty());
    assert_eq!(prov2.channel_state(&chan).unwrap().spent_msat, 300_000, "the fixed price is the exact charge");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_panicking_handler_refunds_its_reservation() {
    let chain = MemChain::new();
    for charge in [Some(400), None] {
        let prov = metered(&chain, Ledger::in_memory(), 1_000, charge, None);
        let mut c = client(&chain, &prov);
        c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
        let chan = c.channels[O].payer.params.channel_id();
        let spent = prov.channel_state(&chan).unwrap().spent_msat;
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.request("GET", &format!("{O}/panic"), b"")));
        assert!(r.is_err());
        let st = prov.channel_state(&chan).unwrap();
        assert_eq!((st.spent_msat, st.reserved_msat()), (spent, 0));
        // and the call is no longer in flight
        assert_eq!(prov.close_channel(&chan).unwrap()["chan"], chan);
    }
}

/// The headers of each request sent.
type Sent = Arc<Mutex<Vec<Vec<(String, String)>>>>;

/// `Local`, recording the headers of every request.
struct Rec(Arc<Provider>, Sent);

impl Transport for Rec {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        self.1.lock().unwrap().push(headers.to_vec());
        Local(self.0.clone()).request(method, url, body, headers)
    }
}

#[test]
fn extra_headers_go_with_every_request_of_a_call() {
    let chain = MemChain::new();
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::in_memory());
    let hits = Sent::default();
    let mut c = Client::new(ClientConfig::new(NET), Box::new(Rec(prov.clone(), hits.clone())), Box::new(MemWallet(chain.clone())), Box::new(|| Ok(1_000)));
    let mine = [("X-CMP-Payer".to_string(), "me".to_string())];
    let url = format!("{O}/v1/q");
    assert_eq!(c.request_with("GET", &url, b"", &CallOpts::new().headers(&mine)).unwrap().status, 200);
    assert_eq!(c.request_with("GET", &url, b"", &CallOpts::new().headers(&mine)).unwrap().status, 200);
    let seen = hits.lock().unwrap().clone();
    // the unpaid try, its paid retry, and the next paid call (the open is the client's own request)
    let calls: Vec<_> = seen.iter().filter(|h| h.iter().any(|(k, _)| k == "X-CMP-Payer")).collect();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls.iter().map(|h| h.iter().filter(|(k, _)| k == "PAYMENT-SIGNATURE").count()).collect::<Vec<_>>(), [0, 1, 1]);
    assert!(calls.iter().all(|h| h.last() == Some(&mine[0])));
    // a caller header never replaces the payment or splits a header line
    for (k, v) in [("payment-signature", "x"), ("X-A", "a\r\nX-B: b"), ("", "x"), ("X\nY", "x")] {
        let bad = [(k.to_string(), v.to_string())];
        let n = hits.lock().unwrap().len();
        assert_eq!(c.request_with("GET", &url, b"", &CallOpts::new().headers(&bad)).unwrap_err().code, "bad_header");
        assert_eq!(hits.lock().unwrap().len(), n, "nothing was sent");
    }
}

#[test]
fn a_caller_chosen_cum_is_bounded() {
    let chain = MemChain::new();
    let prov = metered(&chain, Ledger::in_memory(), 600, None, None);
    let mut c = client(&chain, &prov);
    let url = format!("{O}/v1/q");
    // under the channel's minimum state nothing is signed: never rounded up to it
    c.request_with("GET", &url, b"", &CallOpts::new().cum(100)).unwrap();
    let chan = c.channels[O].payer.params.channel_id();
    assert_eq!((c.channels[O].payer.signed, prov.channel_state(&chan).unwrap().best_cum), (0, 0));
    // the caller's amount is the state signed, not the client's own ceil(spent) = 600
    c.request_with("GET", &url, b"", &CallOpts::new().cum(700)).unwrap();
    assert_eq!((c.channels[O].payer.signed, prov.channel_state(&chan).unwrap().best_cum), (700, 700));
    assert_eq!(c.channels[O].spent_msat, 1_200_000);
    let (seq, max) = (c.channels[O].seq, c.channels[O].payer.params.max_amount());
    for (cum, code) in [(699, "bad_amount"),            // below the last signed state
                        (max + 1, "exhausted"),         // above the channel's capacity
                        (1_801, "too_expensive")] {     // above receipts (1200) + one call (600)
        let e = c.request_with("GET", &url, b"", &CallOpts::new().cum(cum)).unwrap_err();
        assert_eq!(e.code, code, "cum {cum}: {e}");
        assert_eq!(c.close_with(O, &CallOpts::new().cum(cum)).unwrap_err().code, code);
        assert_eq!((c.channels[O].payer.signed, c.channels[O].seq), (700, seq), "nothing signed, no seq spent");
    }
    // the bound itself is allowed, and the daily budget still counts what a chosen cum signs
    c.cfg.daily_budget = 1_000;
    c.day_spent = 0;
    c.request_with("GET", &url, b"", &CallOpts::new().cum(1_700)).unwrap();
    assert_eq!((c.channels[O].payer.signed, c.day_spent), (1_700, 1_000));
    assert_eq!(c.request_with("GET", &url, b"", &CallOpts::new().cum(1_701)).unwrap_err().code, "budget");
    c.cfg.daily_budget = 0;
    // a close at the caller's amount settles exactly it
    let r = c.close_with(O, &CallOpts::new().cum(1_900)).unwrap();
    assert_eq!((r["cum"].as_str(), r["unpaidMsat"].as_str()), (Some("1900"), Some("0")));
    assert_eq!(outputs_to(chain.sent().last().unwrap(), &c.channels[O].payer.params.payee_spk), 1_900);
}

#[test]
fn close_channel_closes_one_channel_with_the_best_state() {
    let chain = MemChain::new();
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::in_memory());
    let mut c = client(&chain, &prov);
    for _ in 0..5 {
        c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    }
    let p = c.channels[O].payer.params.clone();
    let chan = p.channel_id();
    assert_eq!(prov.channel_state(&chan).unwrap().best_cum, 600);
    // a second channel that stays open, and one with nothing signed yet
    let o2 = "https://other.example";
    c.request("GET", &format!("{o2}/v1/q"), b"").unwrap();
    let chan2 = c.channels[o2].payer.params.channel_id();
    assert_eq!(prov.close_channel(&chan2).unwrap_err().code, "no_state");
    assert_eq!(prov.close_channel(&format!("{}:0", "00".repeat(32))).unwrap_err().code, "unknown_channel");
    // a routed lock open on it; a hub-funded ch2
    prov.with_state(&chan, |st| st.extra.insert("route_lock".into(), json!({"lockId": "l1"}))).unwrap();
    assert_eq!(prov.close_channel(&chan).unwrap_err().code, "lock_pending");
    prov.with_state(&chan, |st| {
        st.extra.insert("route_lock".into(), Value::Null);
        st.extra.insert("hub".into(), "02ab".into())
    }).unwrap();
    assert_eq!(prov.close_channel(&chan).unwrap_err().code, "hub_channel");
    prov.with_state(&chan, |st| st.extra.remove("hub")).unwrap();
    assert!(prov.channel_state(&chan).unwrap().closed_txid.is_empty() && chain.sent().is_empty(), "a refusal changes nothing");
    // the close pays the provider the best signed state, by the margin close's path
    let r = prov.close_channel(&chan).unwrap();
    assert_eq!(r.as_object().unwrap().keys().collect::<Vec<_>>(), ["chan", "txid", "cum", "unpaidMsat"]);
    assert_eq!((r["cum"].as_str(), r["unpaidMsat"].as_str()), (Some("600"), Some("150000")));
    let close = chain.sent().last().unwrap().clone();
    assert_eq!((close.txid(), outputs_to(&close, &p.payee_spk)), (r["txid"].as_str().unwrap().to_string(), 600));
    assert_eq!(close.to_hex(), prov.channel_state(&chan).unwrap().extra["close_hex"]);
    assert_eq!(prov.close_channel(&chan).unwrap_err().code, "channel_closed");
    assert_eq!(chain.sent().len(), 1);
    assert!(prov.channel_state(&chan2).unwrap().closed_txid.is_empty(), "only the named channel");
    // the watcher has nothing left to do for it
    assert!(prov.close_due().unwrap().is_empty());
}

#[test]
fn close_channel_refuses_a_channel_with_a_call_in_flight() {
    type Shared = Arc<Mutex<(Option<std::sync::Weak<Provider>>, String, Vec<String>)>>;
    let shared: Shared = Arc::default();
    let sh = shared.clone();
    let chain = MemChain::new();
    let handler = move |_: &str, _: &str, _: &[u8]| {
        let (prov, chan) = {
            let g = sh.lock().unwrap();
            (g.0.as_ref().and_then(|w| w.upgrade()), g.1.clone())
        };
        if let (Some(prov), false) = (prov, chan.is_empty()) {
            let code = prov.close_channel(&chan).map(|_| "closed".to_string()).unwrap_or_else(|e| e.code);
            sh.lock().unwrap().2.push(code);
        }
        HttpResponse::new(200, vec![], vec![])
    };
    let prov = Arc::new(Provider::new(chain.clone(), secret("provider payTo"), ProviderConfig::new(NET), Ledger::in_memory(),
                                      Box::new(|_, _| 600), Box::new(handler)).unwrap());
    shared.lock().unwrap().0 = Some(Arc::downgrade(&prov));
    let mut c = client(&chain, &prov);
    c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    let chan = c.channels[O].payer.params.channel_id();
    shared.lock().unwrap().1 = chan.clone();
    c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    assert_eq!(shared.lock().unwrap().2, ["call_in_flight"]);
    shared.lock().unwrap().1.clear();
    assert_eq!(prov.close_channel(&chan).unwrap()["cum"], "1200");
}

// --- AGP-068: request binding and receipts (review T2, T4) ------------------------------------

/// The request binding of `method url body` (the digest `payload.auth` and `receipt.req` carry).
fn req(method: &str, url: &str, body: &[u8]) -> String {
    request_digest_v2(method, url, body)
}

/// A paid call's PAYMENT-SIGNATURE for `method url body` at `seq`, carrying the least state.
fn paid_header(ch: &xbt402::client::ClientChannel, seq: u64, cum: &str, sig: Option<&str>, method: &str, url: &str, body: &[u8]) -> Vec<(String, String)> {
    let chan = ch.payer.params.channel_id();
    let mut pl = json!({"chan": chan, "seq": seq, "cum": cum});
    if let Some(s) = sig {
        pl["sig"] = s.into();
    }
    pl["auth"] = request_auth(&ch.auth_key, &chan, pl.get("seq"), pl.get("cum"), sig, &req(method, url, body)).into();
    vec![("PAYMENT-SIGNATURE".to_string(), b64json(&payment_payload(&ch.accepted, &pl)))]
}

fn error_of(r: &HttpResponse) -> String {
    xbt402::json::parse_slice(&r.body).ok().and_then(|b| b.get("error").and_then(Value::as_str).map(str::to_string)).unwrap_or_default()
}

fn receipt_in(r: &HttpResponse) -> Value {
    receipt_of(&unb64json(r.header("PAYMENT-RESPONSE").expect("PAYMENT-RESPONSE")).unwrap()).unwrap().clone()
}

#[test]
fn a_payment_is_bound_to_one_request_and_one_origin() {
    let chain = MemChain::new();
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::in_memory());
    let mut c = client(&chain, &prov);
    c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    let ch = c.channels.get_mut(O).unwrap();
    let sig = hex::encode(ch.payer.sign_state(546).unwrap());
    let ch = ch.clone();
    // fields that ran together under "|": paid for (GET, /q?a|b, ""), sent as (GET, /q?a, "b|")
    let h = paid_header(&ch, 10, "546", Some(&sig), "GET", &format!("{O}/q?a|b"), b"");
    let r = prov.serve("GET", "/q?a", &h, b"b|", &format!("{O}/q?a"), None);
    assert_eq!((r.status, error_of(&r)), (402, "bad_auth".into()), "a payment moved to another request");
    // the same request sent to another scheme, host or port
    for (seq, other) in [(11, "http://api.example"), (12, "https://evil.example"), (13, "https://api.example:8443")] {
        let h = paid_header(&ch, seq, "546", Some(&sig), "GET", &format!("{O}/v1/q"), b"");
        let r = prov.serve("GET", "/v1/q", &h, b"", &format!("{other}/v1/q"), None);
        assert_eq!((r.status, error_of(&r)), (402, "bad_auth".into()), "a payment moved to {other}");
    }
    // where it was sent, it pays: the host's case and the scheme's default port make no difference
    let h = paid_header(&ch, 20, "546", Some(&sig), "GET", "https://API.example:443/v1/q", b"");
    let r = prov.serve("GET", "/v1/q", &h, b"", &format!("{O}/v1/q"), None);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
}

#[test]
fn concurrent_calls_get_the_numbers_of_their_own_reservation() {
    use std::sync::mpsc;
    let chain = MemChain::new();
    let (entered_tx, entered) = mpsc::sync_channel::<()>(1);
    let (release, release_rx) = mpsc::sync_channel::<()>(1);
    let gate = Mutex::new((entered_tx, release_rx));
    let handler = move |_: &str, p: &str, _: &[u8]| {
        if p == "/slow" {
            let g = gate.lock().unwrap();
            g.0.send(()).unwrap();
            g.1.recv().unwrap();
        }
        HttpResponse::new(200, vec![], p.as_bytes().to_vec())
    };
    let prov = Arc::new(Provider::new(chain.clone(), secret("provider payTo"), ProviderConfig::new(NET), Ledger::in_memory(),
                                      Box::new(|_, _| 150), Box::new(handler)).unwrap());
    let mut c = client(&chain, &prov);
    c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    let ch = c.channels.get_mut(O).unwrap();
    let sig = hex::encode(ch.payer.sign_state(546).unwrap());
    let ch = ch.clone();
    let ha = paid_header(&ch, 10, "546", Some(&sig), "GET", &format!("{O}/slow"), b"");
    let hb = paid_header(&ch, 11, "546", Some(&sig), "GET", &format!("{O}/fast"), b"");
    let p2 = prov.clone();
    let a = std::thread::spawn(move || p2.serve("GET", "/slow", &ha, b"", &format!("{O}/slow"), None));
    entered.recv().unwrap();
    // B is reserved and answered while A's handler runs
    let rb = prov.serve("GET", "/fast", &hb, b"", &format!("{O}/fast"), None);
    release.send(()).unwrap();
    let ra = a.join().unwrap();
    let (ra, rb) = (receipt_in(&ra), receipt_in(&rb));
    // 150 sat before; A reserved 150 more, then B
    assert_eq!((ra["seq"].as_u64(), ra["spentMsat"].as_str()), (Some(10), Some("300000")), "A's receipt: {ra}");
    assert_eq!((rb["seq"].as_u64(), rb["spentMsat"].as_str()), (Some(11), Some("450000")), "B's receipt: {rb}");
}

#[test]
fn a_seq_spent_on_a_refusal_survives_a_restart() {
    let dir = tmp("seq-refused");
    let path = dir.join("ledger.jsonl");
    let chain = MemChain::new();
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::open(&path).unwrap());
    let mut c = client(&chain, &prov);
    c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    let ch = c.channels[O].clone();
    let chan = ch.payer.params.channel_id();
    // authentic, but postpay owes the first call's 150 sat and this carries no state: refused
    let h = paid_header(&ch, 7, "0", None, "GET", &format!("{O}/v1/q"), b"");
    let r = prov.serve("GET", "/v1/q", &h, b"", &format!("{O}/v1/q"), None);
    assert_eq!(error_of(&r), "insufficient_payment");
    drop((prov, c));
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::open(&path).unwrap());
    assert_eq!(prov.channel_state(&chan).unwrap().seq, 7, "the refused call's seq was only in memory");
    let r = prov.serve("GET", "/v1/q", &h, b"", &format!("{O}/v1/q"), None);
    assert_eq!(error_of(&r), "bad_auth", "the refused header still authenticates after a restart");
    let _ = std::fs::remove_dir_all(dir);
}

/// `Local`, changing the body of answers to `/tamper...` on the way back (a conditional answer
/// keeps its key and gets another ciphertext).
struct Tamper(Arc<Provider>);

impl Transport for Tamper {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        let mut r = Local(self.0.clone()).request(method, url, body, headers)?;
        if split_url(url).1.starts_with("/tamper") && r.status == 200 {
            r.body = match serde_json::from_slice::<Value>(&r.body) {
                Ok(mut v) if v.get("preimage").is_some() => {
                    v["cipher"] = json!("00".repeat(11));
                    serde_json::to_vec(&v).unwrap()
                }
                _ => b"something else".to_vec(),
            };
        }
        Ok(r)
    }
}

#[test]
fn the_receipt_covers_the_response() {
    let chain = MemChain::new();
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::in_memory());
    let mut c = Client::new(ClientConfig::new(NET), Box::new(Tamper(prov.clone())), Box::new(MemWallet(chain.clone())), Box::new(|| Ok(1_000)));
    let r = c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    let rc = c.channels[O].receipts.last().unwrap().clone();
    assert_eq!(rc["status"], json!(200), "{rc}");
    assert_eq!(rc["bodyHash"], json!(hex::encode(sha256(&r.body))), "{rc}");
    let e = c.request("GET", &format!("{O}/tamper"), b"").unwrap_err();
    assert_eq!(e.code, "bad_receipt", "a changed body was accepted: {e}");
}

#[test]
fn an_altered_conditional_answer_keeps_the_hash_lock() {
    let chain = MemChain::new();
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::in_memory());
    prov.offer_conditional("/tamper/report", 1_000, b"deliverable", None);
    let mut c = Client::new(ClientConfig::new(NET), Box::new(Tamper(prov.clone())), Box::new(MemWallet(chain.clone())), Box::new(|| Ok(1_000)));
    c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    let e = c.request_conditional("GET", &format!("{O}/tamper/report"), b"").unwrap_err();
    assert_eq!(e.code, "bad_receipt", "{e}");
    assert!(c.channels[O].pending_cond.is_some(), "the hash lock was dropped with the answer");
    // the provider closes with the hash lock; its claim reveals k for the offered ciphertext
    *chain.tip.lock().unwrap() = c.channels[O].payer.params.expiry - prov.cfg.close_margin;
    let closed = prov.close_due().unwrap();
    let sent = chain.sent();
    let claim = sent.iter().find(|t| t.inputs[0].prevout.txid_hex() == closed[0]).expect("claim");
    assert_eq!(c.recover_conditional(O, claim).unwrap(), b"deliverable");
}

// --- AGP-084: a close or rollover whose broadcast errored ---------------------------------------

/// Five paid calls, then the close (or the rollover) while the node answers every broadcast with
/// an error: the provider, the client's channel, the channel id and the intent left behind.
fn errored_spend(chain: &Arc<MemChain>, rollover: bool) -> (Arc<Provider>, Client, String, Value) {
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::in_memory());
    let mut c = client(chain, &prov);
    for _ in 0..5 {
        c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    }
    let chan = c.channels[O].payer.params.channel_id();
    chain.down(true);
    let e = if rollover { c.rollover(O).unwrap_err() } else { c.close(O).unwrap_err() };
    assert_eq!(e.code, "close_failed", "{e}");
    chain.down(false);
    let st = prov.channel_state(&chan).unwrap();
    assert!(st.closed_txid.is_empty() && chain.sent().is_empty(), "the node took nothing");
    let intent = st.extra["close_intent"].clone();
    (prov, c, chan, intent)
}

#[test]
fn a_channel_whose_spend_the_node_errored_on_serves_nothing_above_it() {
    // the provider holds the fully signed close (or rollover). The node said no, but the tx can
    // still reach the chain: a call served on a later state would be above what that spend pays
    for rollover in [false, true] {
        let chain = MemChain::new();
        let (prov, mut c, chan, intent) = errored_spend(&chain, rollover);
        let (paid, spent) = (py_u64_of(&json!(Tx::parse_hex(intent["hex"].as_str().unwrap()).unwrap().outputs[0].value)), prov.channel_state(&chan).unwrap().spent_msat);
        let ch = c.channels.get_mut(O).unwrap();
        let sig = hex::encode(ch.payer.sign_state(paid + 300).unwrap());
        let ch = ch.clone();
        let url = format!("{O}/v1/q");
        let h = paid_header(&ch, 50, &(paid + 300).to_string(), Some(&sig), "GET", &url, b"");
        let r = prov.serve("GET", "/v1/q", &h, b"", &url, None);
        // the spend reaches the chain after all, and the watcher records it
        chain.send_raw_transaction(intent["hex"].as_str().unwrap()).unwrap();
        assert_eq!(prov.close_due().unwrap(), vec![intent["txid"].as_str().unwrap().to_string()]);
        let st = prov.channel_state(&chan).unwrap();
        assert_eq!(st.closed_txid, intent["txid"].as_str().unwrap());
        assert_eq!((r.status, error_of(&r)), (402, "channel_closing".into()), "rollover {rollover}: a call was served above a spend that confirmed at {paid}");
        assert_eq!(st.spent_msat, spent, "rollover {rollover}: nothing was served after the spend was signed");
        assert_eq!(st.extra.contains_key("rollover_to"), rollover, "a rollover that lands later is recorded as one");
    }
}

#[test]
fn the_watcher_sends_a_close_the_node_errored_on_again() {
    // nothing else would resolve it: the channel takes no new state until its close is on the node
    let chain = MemChain::new();
    let (prov, mut c, chan, intent) = errored_spend(&chain, false);
    let txid = intent["txid"].as_str().unwrap().to_string();
    chain.down(true);
    assert!(prov.close_due().unwrap().is_empty());
    let st = prov.channel_state(&chan).unwrap();
    assert!(st.closed_txid.is_empty() && !st.close_error.is_empty(), "still open, and the failure shows: {:?}", st.close_error);
    chain.down(false);
    assert_eq!(prov.close_due().unwrap(), vec![txid.clone()]);
    assert_eq!(chain.sent().last().unwrap().txid(), txid);
    assert_eq!(prov.channel_state(&chan).unwrap().closed_txid, txid);
    // the client asks again and gets the answer it lost
    assert_eq!(c.close(O).unwrap()["txid"], txid);
}

#[test]
fn the_watcher_does_not_send_a_rollover_the_client_was_told_failed() {
    // the client was answered close_failed and may have dropped the next channel's key: sent now,
    // the rollover would fund a channel nobody can spend from. The client rolls over again or closes
    let chain = MemChain::new();
    let (prov, mut c, chan, intent) = errored_spend(&chain, true);
    assert!(prov.close_due().unwrap().is_empty() && chain.sent().is_empty());
    assert!(prov.channel_state(&chan).unwrap().closed_txid.is_empty());
    let r = c.rollover(O).unwrap();
    assert_ne!(r["txid"], intent["txid"], "a new rollover, to a key the client holds");
    assert_eq!(prov.channel_state(&chan).unwrap().closed_txid, r["txid"].as_str().unwrap());
    assert_eq!(c.open_rolled(O).unwrap()["chan"], r["nextChan"]);
    assert_eq!(c.request("GET", &format!("{O}/v1/q"), b"").unwrap().status, 200);
    // or the operator closes it, at the best state
    let chain = MemChain::new();
    let (prov, _c, chan, intent) = errored_spend(&chain, true);
    let r = prov.close_channel(&chan).unwrap();
    assert_ne!(r["txid"], intent["txid"]);
    assert_eq!(prov.channel_state(&chan).unwrap().closed_txid, r["txid"].as_str().unwrap());
}

#[test]
fn a_spend_that_reached_the_chain_is_recorded_before_another_replaces_it() {
    // the rollover the node errored on confirms; the client, told it failed, rolls over again or
    // closes. Either would overwrite the intent, and the spend on the chain would never be recorded
    for close in [false, true] {
        let chain = MemChain::new();
        let (prov, mut c, chan, intent) = errored_spend(&chain, true);
        let txid = intent["txid"].as_str().unwrap();
        chain.send_raw_transaction(intent["hex"].as_str().unwrap()).unwrap();
        let r = if close { c.close(O).map(|r| r["txid"].clone()).map_err(|e| e.code) } else { c.rollover(O).map(|r| r["txid"].clone()).map_err(|e| e.code) };
        let st = prov.channel_state(&chan).unwrap();
        assert_eq!(st.closed_txid, txid, "close {close}: {r:?}");
        assert_eq!(st.extra["rollover_to"], format!("{txid}:1"));
        assert_eq!(r, if close { Ok(json!(txid)) } else { Err("channel_closing".to_string()) });
        assert_eq!(chain.sent().len(), 1);
    }
}


// --- AGP-081: closure audit, transport and channel side paths (T4c, T2, C3) -------------------

/// `Local`, as someone between payer and provider: an answer to `/strip...` loses its
/// PAYMENT-RESPONSE and gets another body (a conditional answer keeps its key); a request to
/// `/frag...` reaches the provider with `#junk` appended to its target; a request to `/down...` is
/// answered 500 with no receipt and never reaches the provider. Counts the requests it carried.
struct Meddle(Arc<Provider>, Arc<Mutex<u32>>);

impl Transport for Meddle {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        *self.1.lock().unwrap() += 1;
        let path = split_url(url).1;
        if path.starts_with("/frag") {
            return Ok(self.0.serve(method, &format!("{path}#junk"), headers, body, &format!("{url}#junk"), None));
        }
        if path.starts_with("/down") {
            return Ok(HttpResponse::new(500, vec![], b"upstream down".to_vec()));
        }
        let mut r = Local(self.0.clone()).request(method, url, body, headers)?;
        if path.starts_with("/strip") && r.status == 200 {
            r.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("PAYMENT-RESPONSE"));
            if serde_json::from_slice::<Value>(&r.body).map(|v| v.get("preimage").is_none()).unwrap_or(true) {
                r.body = b"a forged answer".to_vec();
            }
        }
        Ok(r)
    }
}

fn meddled(chain: &Arc<MemChain>, prov: &Arc<Provider>) -> (Client, Arc<Mutex<u32>>) {
    let n = Arc::new(Mutex::new(0));
    let c = Client::new(ClientConfig::new(NET), Box::new(Meddle(prov.clone(), n.clone())), Box::new(MemWallet(chain.clone())), Box::new(|| Ok(1_000)));
    (c, n)
}

#[test]
fn a_paid_answer_without_a_receipt_is_refused() {
    let chain = MemChain::new();
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::in_memory());
    let (mut c, _) = meddled(&chain, &prov);
    c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    // an error answer may carry no receipt (the provider's own failures have none): it comes back
    // as it is, and the channel still pays where the answer arrives whole
    let r = c.request("GET", &format!("{O}/down/q"), b"").unwrap();
    assert_eq!((r.status, c.channels[O].receipts.len()), (500, 1));
    assert_eq!(c.request("GET", &format!("{O}/v1/q"), b"").unwrap().status, 200);
    let before = c.channels[O].clone();
    let e = c.request("GET", &format!("{O}/strip/q"), b"").expect_err("a forged body with no receipt was taken as the paid answer");
    assert_eq!(e.code, "bad_receipt", "{e}");
    let ch = &c.channels[O];
    assert_eq!((ch.spent_msat, ch.receipts.len(), ch.acked_cum), (before.spent_msat, before.receipts.len(), before.acked_cum),
               "nothing is adopted from an answer without a receipt");
}

#[test]
fn a_conditional_answer_without_a_receipt_is_refused() {
    let chain = MemChain::new();
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::in_memory());
    prov.offer_conditional("/strip/report", 1_000, b"deliverable", None);
    let (mut c, _) = meddled(&chain, &prov);
    c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    let e = c.request_conditional("GET", &format!("{O}/strip/report"), b"").expect_err("a hash-locked sale was folded with no receipt");
    assert_eq!(e.code, "bad_receipt", "{e}");
    assert!(c.channels[O].pending_cond.is_some(), "the hash lock stays pending: the provider's claim still reveals k");
}

#[test]
fn a_target_with_a_fragment_is_refused_by_the_payer() {
    let chain = MemChain::new();
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::in_memory());
    prov.offer_conditional("/v1/report", 1_000, b"deliverable", None);
    let (mut c, sent) = meddled(&chain, &prov);
    c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    let (n, seq, signed) = (*sent.lock().unwrap(), c.channels[O].seq, c.channels[O].payer.signed);
    for url in [format!("{O}/v1/q#x"), format!("{O}/v1/q?a=1#x"), format!("{O}#x"), format!("{O}/v1/q#")] {
        let e = c.request("GET", &url, b"").expect_err(&url);
        assert_eq!(e.code, "bad_request", "{url}: {e}");
    }
    assert_eq!(c.request_conditional("GET", &format!("{O}/v1/report#x"), b"").unwrap_err().code, "bad_request");
    assert_eq!((*sent.lock().unwrap(), c.channels[O].seq, c.channels[O].payer.signed), (n, seq, signed),
               "nothing is sent, numbered or signed for a URL the binding does not cover whole");
    // an origin that was never paid is not opened for one either
    assert_eq!(c.request("GET", "https://other.example/v1/q#x", b"").unwrap_err().code, "bad_request");
    assert!(!c.channels.contains_key("https://other.example"));
}

#[test]
fn a_target_with_a_fragment_is_refused_by_the_provider() {
    let chain = MemChain::new();
    let served = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen = served.clone();
    let handler = move |_: &str, p: &str, _: &[u8]| {
        seen.lock().unwrap().push(p.to_string());
        HttpResponse::new(200, vec![], b"x".to_vec())
    };
    let prov = Arc::new(Provider::new(chain.clone(), secret("provider payTo"), ProviderConfig::new(NET), Ledger::in_memory(), Box::new(|_, _| 150),
                                      Box::new(handler)).unwrap());
    let (mut c, _) = meddled(&chain, &prov);
    c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    // the payer signs for /frag/q; on the way `#junk` is appended: the digest dropped it, the
    // handler was routed on it
    let r = c.request("GET", &format!("{O}/frag/q"), b"");
    assert!(!served.lock().unwrap().iter().any(|p| p.contains('#')), "a payment was served on a target the payer never sent: {:?}", served.lock().unwrap());
    assert!(r.is_err() || r.is_ok_and(|r| r.status == 400));
    // refused before anything is looked at: unpaid, control and facilitator paths alike
    for (m, p) in [("GET", "/v1/q#x"), ("POST", "/x402/xbt-channel/open#x"), ("POST", "/x402/xbt-channel/lock#x"), ("GET", "/x402/supported#x"),
                   ("GET", "/#"), ("GET", "/v1/q?a=1#x")] {
        let r = prov.serve(m, p, &[], b"{}", &format!("{O}{p}"), None);
        assert_eq!(r.status, 400, "{m} {p}: {}", String::from_utf8_lossy(&r.body));
    }
}

/// A transport whose rollover reaches the provider (which broadcasts) while the reply is lost.
struct LostRollover(Arc<Provider>);

impl Transport for LostRollover {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        let r = Local(self.0.clone()).request(method, url, body, headers)?;
        if split_url(url).1 == "/x402/xbt-channel/rollover" {
            return Err(ChannelError::new("transport_error", "connection reset"));
        }
        Ok(r)
    }
}

/// A [`ClientLedger`] the test can read back.
#[derive(Clone, Default)]
struct Book(Arc<xbt402::client::MemoryClientLedger>);

impl xbt402::client::ClientLedger for Book {
    fn load(&self) -> Result<Vec<(String, Value)>> {
        self.0.load()
    }
    fn save(&self, records: &[(String, Value)]) -> Result<()> {
        self.0.save(records)
    }
}

#[test]
fn a_rollover_binds_the_next_channel_before_the_request_leaves() {
    use xbt402::client::ClientLedger;
    let chain = MemChain::new();
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::in_memory());
    let book = Book::default();
    let refunds = Arc::new(Mutex::new(Vec::<(String, u32)>::new()));
    let kept = refunds.clone();
    let mut c = Client::new(ClientConfig::new(NET), Box::new(LostRollover(prov.clone())), Box::new(MemWallet(chain.clone())), Box::new(|| Ok(1_000)))
        .with_ledger(Box::new(book.clone())).unwrap();
    c.on_refund = Some(Box::new(move |hex, expiry| kept.lock().unwrap().push((hex.to_string(), expiry))));
    for _ in 0..4 {
        c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    }
    let old = c.channels[O].payer.params.clone();
    assert_eq!(c.rollover(O).unwrap_err().code, "transport_error");
    // the provider broadcast the one transaction we signed: its output 1 is the next channel
    let roll = chain.sent().last().unwrap().clone();
    assert_eq!(roll.inputs[0].prevout.txid_hex(), old.funding_txid());
    let next_cap = roll.outputs[1].value as u64;
    let refund = refunds.lock().unwrap().iter().map(|(h, e)| (Tx::parse_hex(h).unwrap(), *e))
        .find(|(t, _)| t.inputs[0].prevout.txid_hex() == roll.txid() && t.inputs[0].prevout.vout == 1);
    let (refund, expiry) = refund.expect("no refund was produced for the next channel: its capacity has no way back");
    assert_eq!(refund.locktime, expiry);
    // and the book on disk holds the next channel with its key, so a restart can still use or refund it
    let rec = book.load().unwrap().into_iter().find(|(k, _)| k == &format!("next {O}")).expect("the next channel was not saved").1;
    let rec = rec.as_array().and_then(|a| a.first()).cloned().expect("one signed rollover");
    assert_eq!(rec["params"]["capacity"], json!(next_cap));
    assert_eq!(rec["key"].as_str().map(str::len), Some(64), "the next channel's key");
    assert_eq!(Tx::parse_hex(rec["refund_hex"].as_str().unwrap()).unwrap().txid(), refund.txid());
}

/// A signer that, like the wallet's, binds a rollover's next channel only once its node shows the
/// rollover (the flag): until then `attach` of `<origin>/next` is refused.
struct LateAttach(xbt402::signer::LocalSigner, std::sync::atomic::AtomicBool);

impl xbt402::signer::StateSigner for LateAttach {
    fn new_key(&self, origin: &str) -> Result<xbt_primitives::ecdsa::PubkeyBytes> {
        self.0.new_key(origin)
    }
    fn attach(&self, origin: &str, params: &xbt402::channel::ChannelParams) -> Result<String> {
        if origin.ends_with("/next") && !self.1.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ChannelError::new("rollover_unproven", "this node does not show the rollover"));
        }
        self.0.attach(origin, params)
    }
    fn sign_state(&self, chan: &str, amount: u64) -> Result<Vec<u8>> {
        self.0.sign_state(chan, amount)
    }
    fn sign_state_a3(&self, chan: &str, amount: u64) -> Result<Vec<u8>> {
        self.0.sign_state_a3(chan, amount)
    }
    fn sign_rollover(&self, chan: &str, amount: u64, next_spk: &[u8], next_capacity: u64) -> Result<Vec<u8>> {
        self.0.sign_rollover(chan, amount, next_spk, next_capacity)
    }
    fn sign_close(&self, chan: &str) -> Result<Vec<u8>> {
        self.0.sign_close(chan)
    }
    fn sign_refund(&self, chan: &str) -> Result<String> {
        self.0.sign_refund(chan)
    }
    fn request_auth(&self, chan: &str, seq: Option<&Value>, cum: Option<&Value>, sig: Option<&str>, req: &str) -> Result<String> {
        self.0.request_auth(chan, seq, cum, sig, req)
    }
    fn sign_conditional(&self, chan: &str, uncond: u64, cond: &xbt402::conditional::ConditionalParams) -> Result<Vec<u8>> {
        self.0.sign_conditional(chan, uncond, cond)
    }
}

#[test]
fn a_signer_backed_rollover_keeps_its_next_channel_until_the_signer_binds_it() {
    use xbt402::client::ClientLedger;
    use xbt402::signer::StateSigner;
    let chain = MemChain::new();
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::in_memory());
    let signer = Arc::new(LateAttach(xbt402::signer::LocalSigner::new(), false.into()));
    let book = Book::default();
    let refunds = Arc::new(Mutex::new(Vec::<String>::new()));
    let kept = refunds.clone();
    let dyn_signer: Arc<dyn StateSigner> = signer.clone();
    let mut c = client(&chain, &prov).with_signer(dyn_signer).with_ledger(Box::new(book.clone())).unwrap();
    c.on_refund = Some(Box::new(move |hex, _| kept.lock().unwrap().push(hex.to_string())));
    for _ in 0..3 {
        c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    }
    let old = c.channels[O].payer.params.clone();
    // the provider answers and broadcasts; the signer's node has not seen the transaction yet
    assert_eq!(c.rollover(O).unwrap_err().code, "rollover_unproven");
    let roll = chain.sent().last().unwrap().clone();
    assert_eq!(roll.inputs[0].prevout.txid_hex(), old.funding_txid());
    let rec = book.load().unwrap().into_iter().find(|(k, _)| k == &format!("next {O}")).expect("the next channel was not saved").1;
    assert_eq!(rec[0]["key"], json!("signer"));
    assert_eq!((&rec[0]["params"]["funding_txid"], &rec[0]["params"]["funding_vout"]), (&json!(roll.txid()), &json!(1)), "{rec}");
    assert_eq!(c.channels[O].payer.params.channel_id(), old.channel_id(), "the live channel is still the old one");
    // a restart later, the node shows it: the signer binds the key, the refund is handed out, the channel is used
    drop(c);
    let dyn_signer: Arc<dyn StateSigner> = signer.clone();
    let mut c = client(&chain, &prov).with_signer(dyn_signer).with_ledger(Box::new(book.clone())).unwrap();
    let kept = refunds.clone();
    c.on_refund = Some(Box::new(move |hex, _| kept.lock().unwrap().push(hex.to_string())));
    assert_eq!(c.adopt_rolled(O, &roll.txid()).unwrap_err().code, "rollover_unproven");
    signer.1.store(true, std::sync::atomic::Ordering::SeqCst);
    c.adopt_rolled(O, &roll.txid()).unwrap();
    assert!(refunds.lock().unwrap().iter().any(|h| {
        let t = Tx::parse_hex(h).unwrap();
        t.inputs[0].prevout.txid_hex() == roll.txid() && t.inputs[0].prevout.vout == 1
    }), "no refund for the next channel");
    assert!(c.next_rolled.is_empty() && book.load().unwrap().iter().all(|(k, _)| !k.starts_with("next ")));
    c.open_rolled(O).unwrap();
    assert_eq!(c.request("GET", &format!("{O}/v1/q"), b"").unwrap().status, 200);
    assert_eq!(c.channels[O].payer.params.funding_txid(), roll.txid());
}

#[test]
fn a_rollover_whose_reply_was_lost_is_adopted_from_the_chain() {
    let chain = MemChain::new();
    let prov = provider_with(chain.clone(), ProviderConfig::new(NET), Ledger::in_memory());
    let mut c = Client::new(ClientConfig::new(NET), Box::new(LostRollover(prov.clone())), Box::new(MemWallet(chain.clone())), Box::new(|| Ok(1_000)));
    for _ in 0..4 {
        c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    }
    assert_eq!(c.rollover(O).unwrap_err().code, "transport_error");
    let roll = chain.sent().last().unwrap().txid();
    assert_eq!(c.adopt_rolled(O, &"00".repeat(32)).unwrap_err().code, "no_channel", "only a rollover this client signed");
    c.adopt_rolled(O, &roll).unwrap();
    c.open_rolled(O).unwrap();
    assert_eq!(c.request("GET", &format!("{O}/v1/q"), b"").unwrap().status, 200);
    assert_eq!(c.channels[O].payer.params.funding_txid(), roll);
    assert!(c.next_rolled.is_empty() && c.pending_rolled.is_empty());
}
