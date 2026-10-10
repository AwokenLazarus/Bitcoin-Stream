//! The light backend against simulated Electrum servers: every call, TLS, batching, reconnects,
//! subscriptions, and lying servers (hidden txs, withheld headers, lying fees, wrong/weaker/stronger
//! chains, bad proofs, substituted txs, wrong heights, invented spends, bad broadcasts, mute servers).
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::funding::ChainBackend;
use xbt_electrum::sim::{mine_header, FakeElectrum, Forge, SimChain, CHECKPOINT, REGTEST_BITS, T0, TEST_CA};
use xbt_electrum::backend::TIP_CAP_SPACING_S;
use xbt_electrum::{scripthash, Config, ElectrumBackend, Kind, Plausibility, TxStatus};
use xbt_primitives::header::U512;
use xbt_primitives::tx::TxOut;

fn spk(b: u8) -> Vec<u8> {
    [vec![0x00, 0x14], vec![b; 20]].concat()
}

fn sim(height: u32) -> Arc<Mutex<SimChain>> {
    Arc::new(Mutex::new(SimChain::new(height, 0)))
}

fn servers(chain: &Arc<Mutex<SimChain>>, n: usize) -> Vec<Arc<FakeElectrum>> {
    (0..n).map(|_| FakeElectrum::start(chain.clone(), false)).collect()
}

fn cfg(chain: &Arc<Mutex<SimChain>>, srv: &[&Arc<FakeElectrum>]) -> Config {
    let urls: Vec<String> = srv.iter().map(|s| s.url()).collect();
    let mut c = Config::new(&urls.iter().map(String::as_str).collect::<Vec<_>>(), "regtest");
    c.checkpoint = Some((CHECKPOINT, hex::encode(chain.lock().unwrap().hash_at(CHECKPOINT))));
    c.timeout = Duration::from_secs(3);
    c.sync_interval = Duration::ZERO;
    c
}

fn backend(chain: &Arc<Mutex<SimChain>>, srv: &[&Arc<FakeElectrum>]) -> ElectrumBackend {
    ElectrumBackend::new(cfg(chain, srv)).unwrap()
}

fn call(b: &ElectrumBackend, m: &str, p: Value) -> Value {
    b.call(m, &p).unwrap_or_else(|e| panic!("{m}: {e}"))
}

#[test]
fn every_call_answers_from_verified_data() {
    let chain = sim(300);
    let s = servers(&chain, 1);
    let b = backend(&chain, &[&s[0]]);
    assert_eq!(call(&b, "getblockcount", json!([])), 300);
    let tip_hash = hex::encode(chain.lock().unwrap().hash_at(300));
    assert_eq!(call(&b, "getblockhash", json!([300])), tip_hash);
    assert_eq!(call(&b, "getblockchaininfo", json!([]))["bestblockhash"], tip_hash);
    let hdr = call(&b, "getblockheader", json!([tip_hash]));
    assert_eq!((hdr["height"].as_u64(), hdr["confirmations"].as_u64(), hdr["nTx"].as_u64()), (Some(300), Some(1), Some(1)));
    assert_eq!(hdr["previousblockhash"], hex::encode(chain.lock().unwrap().hash_at(299)));
    assert!(b.call("getblockhash", &json!([100])).is_err(), "below the checkpoint is never read");
    assert!(b.call("getblockhash", &json!([301])).is_err());

    // a confirmed coin, then an unconfirmed one
    let a = spk(0xA1);
    let t1 = chain.lock().unwrap().credit(1, 50_000, &a, true);
    let o = call(&b, "gettxout", json!([t1, 1, true]));
    assert_eq!((o["confirmations"].as_u64(), o["value"].as_f64(), o["coinbase"].as_bool()), (Some(1), Some(0.0005), Some(false)));
    assert_eq!(o["scriptPubKey"]["hex"], hex::encode(&a));
    assert!(o["scriptPubKey"]["address"].as_str().unwrap().starts_with("bcrt1q"));
    assert_eq!(o["bestblock"], hex::encode(chain.lock().unwrap().hash_at(301)));
    assert_eq!(call(&b, "gettxout", json!([t1, 7, true])), Value::Null, "no such output");
    let t2 = chain.lock().unwrap().credit(0, 20_000, &a, false);
    assert_eq!(call(&b, "gettxout", json!([t2, 0, true]))["confirmations"], 0);
    assert_eq!(call(&b, "gettxout", json!([t2, 0, false])), Value::Null, "mempool coins only on request");

    // a coinbase is reported as one
    let cb = chain.lock().unwrap().blocks[10][0].clone();
    assert_eq!(call(&b, "gettxout", json!([cb, 0, true]))["coinbase"], true);

    // spent in the mempool: the output is still there (not proven spent), the spend is a hint
    let sp = chain.lock().unwrap().spend(&[(&t1, 1)], vec![TxOut::new(49_000, spk(0xB2))], false);
    assert!(call(&b, "gettxout", json!([t1, 1, true])).is_object(), "a mempool spend proves nothing");
    assert_eq!(call(&b, "gettxspendingprevout", json!([[{"txid": t1, "vout": 1}]]))[0]["spendingtxid"], sp);
    let raw = call(&b, "getrawtransaction", json!([sp, true]));
    assert_eq!(raw["confirmations"], 0);
    chain.lock().unwrap().mine(1);
    assert_eq!(call(&b, "gettxout", json!([t1, 1, true])), Value::Null, "proven spent once confirmed");
    assert_eq!(call(&b, "gettxspendingprevout", json!([[{"txid": t1, "vout": 1}]]))[0].get("spendingtxid"), None,
               "as the node: gettxspendingprevout reports mempool spends only");
    assert_eq!(b.spending_tx(&t1, 1).unwrap().map(|x| x.0), Some(sp.clone()), "the typed call reports the proven spend");
    let raw = call(&b, "getrawtransaction", json!([sp, true]));
    assert_eq!((raw["confirmations"].as_u64(), raw["height"].as_u64()), (Some(1), Some(302)));
    assert_eq!((raw["vin"][0]["txid"].as_str(), raw["vin"][0]["vout"].as_u64(), raw["vin"][0]["sequence"].as_u64()), (Some(t1.as_str()), Some(1), Some(0xFFFF_FFFD)));
    assert_eq!(call(&b, "getrawtransaction", json!([sp, false, raw["blockhash"]])), raw["hex"]);
    assert!(b.call("getrawtransaction", &json!([sp, false, tip_hash])).is_err(), "not in that block");
    assert!(b.call("getrawtransaction", &json!(["00".repeat(32)])).is_err());

    // scantxoutset: confirmed, proven, unspent only
    chain.lock().unwrap().mine(1); // confirms t2
    let scan = call(&b, "scantxoutset", json!(["start", [format!("raw({})", hex::encode(&a))]]));
    let got: Vec<(String, u64)> = scan["unspents"].as_array().unwrap().iter().map(|u| (u["txid"].as_str().unwrap().into(), u["vout"].as_u64().unwrap())).collect();
    assert_eq!(got, vec![(t2.clone(), 0)]);
    assert_eq!(scan["total_amount"].as_f64(), Some(0.0002));
    assert!(b.call("scantxoutset", &json!(["start", ["addr(bcrt1q...)"]])).is_err());

    // broadcast
    let tx = xbt_primitives::tx::Tx::new(2, vec![xbt_primitives::tx::TxIn::new(xbt_primitives::tx::OutPoint::from_display(&t2, 0).unwrap(), 0)],
                                         vec![TxOut::new(19_000, spk(0xC3))], 0);
    assert_eq!(call(&b, "sendrawtransaction", json!([tx.to_hex()])), tx.txid());
    assert!(chain.lock().unwrap().mempool.contains(&tx.txid()));
    assert!(b.call("sendrawtransaction", &json!(["zz"])).is_err());

    // fee: unverifiable, marked so
    let f = call(&b, "estimatesmartfee", json!([2]));
    assert_eq!((f["feerate"].as_f64(), f["source"].as_str()), (Some(0.0001), Some("electrum (unverified)")));

    // what a light client cannot do
    for m in ["getbalances", "sendtoaddress", "getblock", "generatetoaddress", "fundrawtransaction"] {
        assert_eq!(b.call(m, &json!([])).unwrap_err().kind, Kind::LightBackend, "{m}");
    }
    assert_eq!(b.call("verifychain", &json!([])).unwrap_err().kind, Kind::LightBackend);
    assert!(b.flags().is_empty(), "{:?}", b.flags());
}

#[test]
fn chain_backend_trait() {
    let chain = sim(200);
    let s = servers(&chain, 1);
    let b: Arc<dyn ChainBackend> = Arc::new(backend(&chain, &[&s[0]]));
    let t = chain.lock().unwrap().credit(0, 30_000, &spk(0xD4), true);
    chain.lock().unwrap().mine(2);
    assert_eq!(b.block_count().unwrap(), 203);
    let u = b.get_tx_out(&t, 0, true).unwrap().unwrap();
    assert_eq!((u.confirmations, u.value, u.coinbase, u.script_pubkey), (3, 30_000, false, spk(0xD4)));
    assert!(b.has_transaction(&t).unwrap());
    assert!(!b.has_transaction(&"ab".repeat(32)).unwrap());
    let e = b.send_raw_transaction("00").unwrap_err();
    assert_eq!(e.code, "chain_error");
}

#[test]
fn tls_with_a_pinned_ca_and_refused_without() {
    let chain = sim(150);
    let s = FakeElectrum::start(chain.clone(), true);
    let dir = std::env::temp_dir().join(format!("xbt-electrum-ca-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ca = dir.join("ca.pem");
    std::fs::write(&ca, TEST_CA).unwrap();
    let mut c = cfg(&chain, &[&s]);
    assert!(c.servers[0].starts_with("ssl://localhost:"));
    c.extra_ca = vec![ca];
    let b = ElectrumBackend::new(c).unwrap();
    assert_eq!(b.block_count().unwrap(), 150);
    let t = chain.lock().unwrap().credit(0, 25_000, &spk(0xE5), true);
    assert_eq!(b.tx_out(&t, 0, true).unwrap().unwrap().confirmations, 1);
    // without the CA the certificate is not trusted: nothing connects
    let b2 = ElectrumBackend::new(cfg(&chain, &[&s])).unwrap();
    let e = b2.block_count().unwrap_err();
    assert_eq!(e.kind, Kind::TooFewServers, "{e}");
    assert!(b2.flags()[0].reason.contains("TLS"), "{:?}", b2.flags());
    // a TLS server named by an address the certificate does not cover
    let mut c3 = cfg(&chain, &[&s]);
    c3.servers = vec![format!("ssl://127.0.0.2:{}", s.addr.port())];
    c3.extra_ca = vec![dir.join("ca.pem")];
    assert!(ElectrumBackend::new(c3).unwrap().block_count().is_err());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn headers_catch_up_in_batches_and_persist() {
    let chain = sim(5_000);
    let s = servers(&chain, 1);
    let dir = std::env::temp_dir().join(format!("xbt-electrum-store-{}", std::process::id()));
    let mut c = cfg(&chain, &[&s[0]]);
    c.store_path = Some(dir.join("headers-regtest.bin"));
    let b = ElectrumBackend::new(c.clone()).unwrap();
    assert_eq!(b.block_count().unwrap(), 5_000);
    let calls = s[0].calls.lock().unwrap().clone();
    assert_eq!(calls.iter().filter(|m| *m == "blockchain.block.headers").count(), 4,
               "the 10 below the checkpoint, then 4,899 headers = 3 chunks, one batch");
    drop(b);
    s[0].calls.lock().unwrap().clear();
    chain.lock().unwrap().mine(5);
    let b = ElectrumBackend::new(c).unwrap();
    assert_eq!(b.block_count().unwrap(), 5_005);
    let calls = s[0].calls.lock().unwrap().clone();
    assert_eq!(calls.iter().filter(|m| *m == "blockchain.block.headers").count(), 1, "only the 5 new ones: {calls:?}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn subscriptions_wake_the_watcher_and_survive_a_reconnect() {
    let chain = sim(200);
    let s = servers(&chain, 2);
    let b = backend(&chain, &[&s[0], &s[1]]);
    let a = spk(0xF6);
    b.block_count().unwrap();
    assert_eq!(b.watch(&[&a]).unwrap(), 1);
    b.wait_for_change(Duration::from_millis(100));
    assert!(!b.wait_for_change(Duration::from_millis(100)), "quiet");
    let t = chain.lock().unwrap().credit(0, 10_000, &a, false);
    assert!(b.wait_for_change(Duration::from_secs(2)), "a payment to a watched script wakes us");
    assert_eq!(b.tx_out(&t, 0, true).unwrap().unwrap().confirmations, 0);
    chain.lock().unwrap().mine(1);
    assert!(b.wait_for_change(Duration::from_secs(2)), "a new block wakes us");
    assert_eq!(b.tx_out(&t, 0, true).unwrap().unwrap().confirmations, 1);

    // server 0 goes down: server 1 carries on; back up, it reconnects and resubscribes
    s[0].down.store(true, std::sync::atomic::Ordering::SeqCst);
    chain.lock().unwrap().mine(1);
    assert!(b.wait_for_change(Duration::from_secs(2)));
    assert_eq!(b.block_count().unwrap(), 202);
    assert_eq!(b.status()["servers"][0]["connected"], false);
    s[1].down.store(true, std::sync::atomic::Ordering::SeqCst);
    s[0].down.store(false, std::sync::atomic::Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(100));
    b.wait_for_change(Duration::from_millis(50));
    assert_eq!(b.block_count().unwrap(), 202, "reconnected to server 0");
    let before = s[0].calls.lock().unwrap().iter().filter(|m| *m == "blockchain.scripthash.subscribe").count();
    assert!(before >= 2, "resubscribed after the reconnect");
    chain.lock().unwrap().credit(0, 11_000, &a, false);
    assert!(b.wait_for_change(Duration::from_secs(2)), "the resubscription fires");
    let st = b.status();
    assert_eq!((st["watched_scripts"].as_u64(), st["servers"][0]["connected"].as_bool()), (Some(1), Some(true)));
}

#[test]
fn too_few_servers_and_a_mute_one() {
    let chain = sim(150);
    let s = servers(&chain, 2);
    let mut c = cfg(&chain, &[&s[0], &s[1]]);
    c.min_servers = Some(2);
    c.timeout = Duration::from_millis(500);
    let b = ElectrumBackend::new(c).unwrap();
    assert_eq!(b.block_count().unwrap(), 150);
    s[1].down.store(true, std::sync::atomic::Ordering::SeqCst);
    chain.lock().unwrap().mine(1);
    std::thread::sleep(Duration::from_millis(100));
    let e = b.block_count().unwrap_err();
    assert_eq!(e.kind, Kind::TooFewServers, "{e}");

    // a server that stops answering is dropped after the timeout; the other one answers
    let chain = sim(150);
    let s = servers(&chain, 2);
    let mut c = cfg(&chain, &[&s[0], &s[1]]);
    c.timeout = Duration::from_millis(500);
    let b = ElectrumBackend::new(c).unwrap();
    b.block_count().unwrap();
    s[0].knobs().mute = true;
    chain.lock().unwrap().mine(2);
    assert_eq!(b.block_count().unwrap(), 152);
    assert!(b.flags().iter().any(|f| f.server == s[0].url() && f.reason.contains("timed out")), "{:?}", b.flags());
}

#[test]
fn hostile_hidden_transaction() {
    let chain = sim(200);
    let s = servers(&chain, 2);
    let a = spk(0x31);
    let t = chain.lock().unwrap().credit(0, 40_000, &a, true);
    s[0].knobs().hide.insert(t.clone());
    // alone, the hiding server only delays us: the coin is unknown, not refuted
    let alone = backend(&chain, &[&s[0]]);
    assert!(alone.tx_out(&t, 0, true).unwrap().is_none());
    assert!(alone.unspent(&a).unwrap().is_empty());
    // one honest server defeats hiding (the union of histories)
    let b = backend(&chain, &[&s[0], &s[1]]);
    assert_eq!(b.tx_out(&t, 0, true).unwrap().unwrap().confirmations, 1);
    assert_eq!(b.unspent(&a).unwrap().len(), 1);
    // a hidden confirmed spend: the honest server shows it, so the coin is spent
    let sp = chain.lock().unwrap().spend(&[(&t, 0)], vec![TxOut::new(39_000, spk(0x32))], true);
    s[0].knobs().hide.insert(sp.clone());
    assert!(b.tx_out(&t, 0, true).unwrap().is_none());
    assert_eq!(b.spending_tx(&t, 0).unwrap().unwrap().0, sp);
}

#[test]
fn hostile_withheld_headers_and_stale_tip() {
    let chain = sim(200);
    let s = servers(&chain, 2);
    s[0].knobs().withhold_above = Some(195);
    // alone: the tip lags (it can only delay a refund), and the status shows how old it is
    let alone = backend(&chain, &[&s[0]]);
    assert_eq!(alone.block_count().unwrap(), 195);
    assert!(alone.status()["tip_age_s"].as_u64().unwrap() > 0);
    // with an honest server we follow the most work
    let b = backend(&chain, &[&s[0], &s[1]]);
    assert_eq!(b.block_count().unwrap(), 200);
    // a server that claims a tip but refuses its headers: flagged, never adopted
    s[0].knobs().withhold_above = None;
    s[0].knobs().refuse_headers_above = Some(190);
    chain.lock().unwrap().mine(3);
    let alone = backend(&chain, &[&s[0]]);
    assert_eq!(alone.block_count().unwrap(), 190);
    assert!(!alone.flags().is_empty());
    let b = backend(&chain, &[&s[0], &s[1]]);
    assert_eq!(b.block_count().unwrap(), 203);
    // a confirmation in a withheld block is not proven by the withholding server alone
    let t = chain.lock().unwrap().credit(0, 12_000, &spk(0x33), true);
    s[0].knobs().refuse_headers_above = None;
    s[0].knobs().withhold_above = Some(203);
    let alone = backend(&chain, &[&s[0]]);
    let st = alone.tx_out(&t, 0, true).unwrap();
    assert_eq!(st.map(|o| o.confirmations), Some(0), "served as unconfirmed, never as confirmed");
}

#[test]
fn hostile_lying_fee() {
    let chain = sim(150);
    let s = servers(&chain, 3);
    s[0].knobs().fee = Some(50.0);
    let b = backend(&chain, &[&s[0], &s[1], &s[2]]);
    let f = b.estimate_fee(2).unwrap();
    assert_eq!(f.feerate, Some(0.0001), "the median: one liar cannot set it");
    assert_eq!(f.answers.len(), 3);
    let alone = backend(&chain, &[&s[0]]);
    let r = alone.call("estimatesmartfee", &json!([2])).unwrap();
    assert_eq!((r["feerate"].as_f64(), r["source"].as_str()), (Some(50.0), Some("electrum (unverified)")), "alone it is only marked unverified");
    s[1].knobs().fee = Some(-1.0);
    let f = backend(&chain, &[&s[1]]).call("estimatesmartfee", &json!([2])).unwrap();
    assert!(f.get("errors").is_some());
}

#[test]
fn hostile_wrong_chain() {
    let chain = sim(200);
    let other = sim_salted(200, 9);
    let s = servers(&chain, 1);
    let wrong = FakeElectrum::start(other, false);
    // alone: servers that answer but are not on our checkpoint = the wrong chain
    let b = backend(&chain, &[&wrong]);
    let e = b.block_count().unwrap_err();
    assert_eq!(e.kind, Kind::CheckpointMismatch, "{e}");
    // with an honest server the wrong one is flagged and ignored
    let b = backend(&chain, &[&wrong, &s[0]]);
    assert_eq!(b.block_count().unwrap(), 200);
    assert!(b.flags().iter().any(|f| f.server == wrong.url()));
    let st = b.status();
    assert_eq!(st["servers"][1]["on_best_chain"], true);
    assert_eq!(st["servers"][0]["on_best_chain"], false);
    // a checkpoint pinned for another chain: refused at the first sync
    let mut c = cfg(&chain, &[&s[0]]);
    c.checkpoint = Some((CHECKPOINT, "11".repeat(32)));
    assert_eq!(ElectrumBackend::new(c).unwrap().block_count().unwrap_err().kind, Kind::CheckpointMismatch);
    // non-mainnet without a checkpoint: refused
    let mut c = cfg(&chain, &[&s[0]]);
    c.checkpoint = None;
    assert!(ElectrumBackend::new(c).is_err());
}

fn sim_salted(h: u32, salt: u8) -> Arc<Mutex<SimChain>> {
    Arc::new(Mutex::new(SimChain::new(h, salt)))
}

#[test]
fn hostile_weaker_chain_and_a_real_reorg() {
    let chain = sim(200);
    let s = servers(&chain, 2);
    let b = backend(&chain, &[&s[0], &s[1]]);
    let t = chain.lock().unwrap().credit(0, 15_000, &spk(0x41), true); // block 201
    chain.lock().unwrap().mine(2);
    assert_eq!(b.tx_out(&t, 0, true).unwrap().unwrap().confirmations, 3);
    // a weaker fork from 198 (4 blocks < our 5): not adopted
    let weak = chain.lock().unwrap().alt_chain(198, 4, 0x77);
    s[0].knobs().headers = Some(weak);
    assert_eq!(b.sync(true).unwrap(), 203);
    assert_eq!(b.status()["servers"][0]["on_best_chain"], false);
    // a stronger fork from 198 (8 blocks): adopted, and the proof into the old block 201 no longer holds
    let strong = chain.lock().unwrap().alt_chain(198, 8, 0x78);
    s[0].knobs().headers = Some(strong.clone());
    assert_eq!(b.sync(true).unwrap(), 206);
    assert_eq!(b.block_hash(206).unwrap(), hex::encode(xbt_primitives::header::parse_header(strong.last().unwrap()).unwrap().hash));
    assert!(b.tx_out(&t, 0, true).unwrap().is_none(), "its block was reorged out: no proof into our chain now");
    assert!(b.transaction(&t).unwrap().is_none());
}

#[test]
fn hostile_bad_proofs() {
    for forge in [Forge::WrongSibling, Forge::WrongDepth, Forge::PastEnd] {
        let chain = sim(200);
        let s = servers(&chain, 2);
        let t = chain.lock().unwrap().credit(0, 18_000, &spk(0x51), false);
        for i in 0..5 {
            chain.lock().unwrap().credit(0, 1_000 + i, &spk(0x52), false);
        }
        chain.lock().unwrap().mine(1); // a 7-transaction block
        s[0].knobs().forge = Some(forge);
        let alone = backend(&chain, &[&s[0]]);
        assert!(alone.tx_out(&t, 0, true).unwrap().is_none(), "{forge:?}: never confirmed by a bad proof");
        assert!(alone.flags().iter().any(|f| f.reason.contains("get_merkle")), "{forge:?}: {:?}", alone.flags());
        let b = backend(&chain, &[&s[0], &s[1]]);
        assert_eq!(b.tx_out(&t, 0, true).unwrap().unwrap().confirmations, 1, "{forge:?}: the honest proof");
    }
}

#[test]
fn hostile_substituted_tx_and_wrong_height() {
    let chain = sim(200);
    let s = servers(&chain, 2);
    let t = chain.lock().unwrap().credit(0, 22_000, &spk(0x61), true);
    let other = chain.lock().unwrap().credit(0, 99_000, &spk(0x61), true);
    let other_tx = chain.lock().unwrap().txs[&other].clone();
    s[0].knobs().substitute.insert(t.clone(), other_tx);
    let alone = backend(&chain, &[&s[0]]);
    assert!(alone.tx_out(&t, 0, true).unwrap().is_none());
    assert!(alone.flags().iter().any(|f| f.reason.contains("not the transaction asked for")));
    let b = backend(&chain, &[&s[0], &s[1]]);
    assert_eq!(b.tx_out(&t, 0, true).unwrap().unwrap().value, 22_000);

    // a claimed height the proof does not reach
    let chain = sim(200);
    let s = servers(&chain, 1);
    let t = chain.lock().unwrap().credit(0, 22_000, &spk(0x62), true);
    s[0].knobs().claim_height.insert(t.clone(), 150);
    let b = backend(&chain, &[&s[0]]);
    assert!(b.tx_out(&t, 0, true).unwrap().is_none());
    assert!(b.flags().iter().any(|f| f.reason.contains("get_merkle")));
    // a height beyond our chain: not proven either
    s[0].knobs().claim_height.insert(t.clone(), 5_000);
    let b = backend(&chain, &[&s[0]]);
    assert!(b.tx_out(&t, 0, true).unwrap().is_none());
}

#[test]
fn hostile_invented_spend_cannot_suppress_a_refund() {
    let chain = sim(200);
    let s = servers(&chain, 1);
    let fund_spk = [vec![0x00, 0x20], vec![0x71; 32]].concat(); // a channel's P2WSH funding
    let f = chain.lock().unwrap().credit(0, 100_000, &fund_spk, true);
    // the server invents a close spending the funding, in its mempool and then "confirmed"
    let fake = xbt_primitives::tx::Tx::new(2, vec![xbt_primitives::tx::TxIn::new(xbt_primitives::tx::OutPoint::from_display(&f, 0).unwrap(), 0)],
                                           vec![TxOut::new(99_000, spk(0x72))], 0);
    let sh = scripthash(&fund_spk);
    {
        let mut k = s[0].knobs();
        k.invented.insert(fake.txid(), fake.clone());
        k.extra_history.insert(sh.clone(), vec![(fake.txid(), 0)]);
    }
    let b = backend(&chain, &[&s[0]]);
    assert_eq!(b.spending_tx(&f, 0).unwrap(), Some((fake.txid(), TxStatus::Mempool)), "reported as a hint");
    assert!(b.tx_out(&f, 0, true).unwrap().is_some(), "but the funding still counts as unspent: the refund goes ahead");
    s[0].knobs().extra_history.insert(sh, vec![(fake.txid(), 201)]);
    assert!(b.tx_out(&f, 0, true).unwrap().is_some(), "an unprovable 'confirmed' spend changes nothing");
    assert!(b.spending_tx(&f, 0).unwrap().is_none());
    // the refund itself is broadcast normally
    let refund = xbt_primitives::tx::Tx::new(2, vec![xbt_primitives::tx::TxIn::new(xbt_primitives::tx::OutPoint::from_display(&f, 0).unwrap(), 0xFFFF_FFFE)],
                                             vec![TxOut::new(99_400, spk(0x73))], 250);
    assert_eq!(b.broadcast(&refund.to_hex()).unwrap(), refund.txid());
    chain.lock().unwrap().mine(1);
    assert!(b.tx_out(&f, 0, true).unwrap().is_none());
    assert_eq!(b.spending_tx(&f, 0).unwrap().unwrap().0, refund.txid());
}

#[test]
fn hostile_broadcasts() {
    let chain = sim(150);
    let s = servers(&chain, 2);
    let tx = xbt_primitives::tx::Tx::new(2, vec![xbt_primitives::tx::TxIn::new(xbt_primitives::tx::OutPoint::from_display(&"cd".repeat(32), 0).unwrap(), 0)],
                                         vec![TxOut::new(1_000, spk(0x81))], 0);
    s[0].knobs().broadcast_txid = Some("ee".repeat(32));
    let b = backend(&chain, &[&s[0], &s[1]]);
    assert_eq!(b.broadcast(&tx.to_hex()).unwrap(), tx.txid(), "the honest server accepted it");
    assert!(b.flags().iter().any(|f| f.reason.contains("another txid")));
    let alone = backend(&chain, &[&s[0]]);
    assert!(alone.broadcast(&tx.to_hex()).is_err(), "a lie about the txid is not an acceptance");
    s[1].knobs().refuse_broadcast = Some("non-final".into());
    let e = backend(&chain, &[&s[1]]).broadcast(&tx.to_hex()).unwrap_err();
    assert_eq!((e.kind, e.msg.as_str()), (Kind::Server, "non-final"), "the server's reason, as the node gives it");
}

#[test]
fn config_from_env_and_checkpoint_parsing() {
    assert_eq!(xbt_electrum::parse_checkpoint(Some(&format!("101:{}", "AB".repeat(32)))).unwrap(), Some((101, "ab".repeat(32))));
    assert!(xbt_electrum::parse_checkpoint(Some("101:abc")).is_err());
    assert!(xbt_electrum::parse_checkpoint(Some("x:".to_string().as_str())).is_err());
    assert_eq!(xbt_electrum::parse_checkpoint(None).unwrap(), None);
    // mainnet defaults to block 961640 and 2 servers
    let b = ElectrumBackend::new(Config::new(&["tcp://127.0.0.1:1", "tcp://localhost:2", "ssl://example.com:50002"], "main")).unwrap();
    assert_eq!(b.checkpoint(), (961_640, "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb".to_string()));
    assert_eq!(b.min_servers, 2);
    assert!(ElectrumBackend::new(Config::new(&["http://x:1"], "main")).is_err());
    assert!(ElectrumBackend::new(Config::new(&[], "main")).is_err());
    assert!(ElectrumBackend::new(Config::new(&["tcp://h:1"], "nochain")).is_err());
    assert!(ElectrumBackend::new(Config::new(&["tcp://h:1"], "testnet4")).is_err(), "no testnet4 header rules: fails closed");
}

/// review E2: plain TCP on mainnet only to a loopback host (anything else needs ssl://).
#[test]
fn mainnet_needs_tls() {
    for ok in ["tcp://127.0.0.1:50001", "tcp://127.8.9.10:1", "tcp://localhost:1", "tcp://LOCALHOST.:1", "tcp://[::1]:1",
               "tcp://[::ffff:127.0.0.1]:1", "127.0.0.1:50001:t", "ssl://electrum.example:50002", "electrum.example:50002:s"] {
        assert!(ElectrumBackend::new(Config::new(&[ok, "ssl://b.example:1"], "main")).is_ok(), "{ok}");
    }
    for bad in ["tcp://electrum.example:50001", "tcp://10.0.0.5:50001", "tcp://192.168.1.2:1", "tcp://[::ffff:10.0.0.1]:1",
                "tcp://localhost.example.com:1", "tcp://127.0.0.1.nip.io:1", "electrum.example:50001:t", "tcp://0.0.0.0:1"] {
        let e = ElectrumBackend::new(Config::new(&[bad, "ssl://b.example:1"], "main")).err().unwrap_or_else(|| panic!("{bad} accepted"));
        assert!(e.msg.contains("mainnet needs ssl://"), "{bad}: {e}");
    }
    // regtest is not held to it
    assert!(ElectrumBackend::new({
        let mut c = Config::new(&["tcp://10.0.0.5:1"], "regtest");
        c.checkpoint = Some((101, "ab".repeat(32)));
        c
    }).is_ok());
}

/// review E1: a server claiming a tip near 2^32 and streaming junk headers, slowly, neither stalls
/// the other callers nor costs more than one batch of headers per sync.
#[test]
fn hostile_lying_server_cannot_stall() {
    let chain = sim(300);
    let honest = FakeElectrum::start(chain.clone(), false);
    let liar = FakeElectrum::start(chain.clone(), false);
    {
        let mut k = liar.knobs();
        k.fake_tip = Some(mine_header([0x44; 32], [0x45; 32], 4_000_000_000, 1, T0 + 60 * 300, REGTEST_BITS));
        k.junk_above = Some(300);
    }
    let mut c = cfg(&chain, &[&liar, &honest]);
    c.timeout = Duration::from_secs(5);
    c.tip_cap_spacing_s = Some(TIP_CAP_SPACING_S);
    let b = Arc::new(ElectrumBackend::new(c).unwrap());
    let t = Instant::now();
    assert_eq!(b.block_count().unwrap(), 300);
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    assert!(b.flags().iter().any(|f| f.server == liar.url() && f.reason.contains("beyond the plausible")), "{:?}", b.flags());
    let asked = liar.calls.lock().unwrap().iter().filter(|m| *m == "blockchain.block.headers").count();
    assert!(asked <= 5, "the first junk chunk ends the fetch: {asked} header requests");

    // the liar now claims the real tip but answers header requests slowly: a sync in flight does
    // not hold up anyone else
    {
        let mut k = liar.knobs();
        k.fake_tip = None;
        k.junk_above = None;
        k.delay_headers_ms = 1_500;
    }
    chain.lock().unwrap().mine(1);
    let b2 = b.clone();
    let syncing = std::thread::spawn(move || b2.sync(true));
    std::thread::sleep(Duration::from_millis(300));
    let t = Instant::now();
    let _ = b.status();
    assert!(b.block_hash(300).is_ok());
    assert!(b.flags().len() < 60);
    assert!(t.elapsed() < Duration::from_millis(700), "held up {:?} by the slow server's sync", t.elapsed());
    assert_eq!(syncing.join().unwrap().unwrap(), 301, "the honest server's block still arrives");
}

/// review E1: the tip cap is a mainnet rule (regtest mines as fast as it is asked to); where it is set,
/// a chain that outran it is caught up over more than one sync, and the server is flagged.
#[test]
fn tip_cap_is_mainnet_only() {
    let chain = sim(CHECKPOINT + 4_000); // 60 s blocks: faster than one per 150 s
    let tip_time = (T0 + 60 * (CHECKPOINT + 4_000)) as u64;
    let s = servers(&chain, 1);
    let mut c = cfg(&chain, &[&s[0]]);
    c.clock = Some(Arc::new(move || tip_time));
    let b = ElectrumBackend::new(c.clone()).unwrap();
    assert_eq!(b.block_count().unwrap(), CHECKPOINT + 4_000);
    assert!(b.flags().is_empty(), "{:?}", b.flags());

    c.tip_cap_spacing_s = Some(TIP_CAP_SPACING_S);
    let capped = ElectrumBackend::new(c).unwrap();
    let cap = CHECKPOINT + 60 * 4_000 / TIP_CAP_SPACING_S as u32 + 2016;
    assert_eq!(capped.block_count().unwrap(), cap);
    assert!(capped.flags().iter().any(|f| f.reason.contains("beyond the plausible")), "{:?}", capped.flags());
    assert_eq!(capped.sync(true).unwrap(), CHECKPOINT + 4_000);
}

/// review E2: a fresh client whose only server serves the real checkpoint and then a few cheap
/// blocks with a fake funding in them believes nothing until the chain is plausible.
#[test]
fn hostile_cheap_fork_is_not_believed() {
    let base = SimChain::new(CHECKPOINT, 0);
    let mut honest = base.clone();
    honest.mine(299); // tip 400
    let mut cheap = base;
    let fake = cheap.credit(0, 5_000_000, &spk(0x91), true);
    cheap.mine(19); // tip 121
    let honest = Arc::new(Mutex::new(honest));
    let cheap = Arc::new(Mutex::new(cheap));
    let good = FakeElectrum::start(honest.clone(), false);
    let liar = FakeElectrum::start(cheap.clone(), false);
    let per_block = xbt_primitives::header::work_of(REGTEST_BITS).unwrap();
    let rules = |srv: &[&Arc<FakeElectrum>], now: u32| {
        let mut c = cfg(&honest, srv);
        c.plausibility = Some(Plausibility { min_work_above: per_block * U512::from(200u32), floor_spacing_s: 60, floor_slack: 50 });
        c.clock = Some(Arc::new(move || now as u64));
        c
    };
    let now = T0 + 60 * 400 + 30;
    let alone = ElectrumBackend::new(rules(&[&liar], now)).unwrap();
    let e = alone.tx_out(&fake, 0, true).unwrap_err();
    assert_eq!(e.kind, Kind::Implausible, "{e}");
    assert!(e.msg.contains("below the minimum"), "{e}");
    assert_eq!(alone.block_count().unwrap_err().kind, Kind::Implausible);
    assert!(alone.call("getblockhash", &json!([CHECKPOINT])).is_err(), "nothing is answered from it");
    assert!(alone.status()["implausible"].is_string());
    // with an honest server, most work wins and the fake funding has no proof into it
    let b = ElectrumBackend::new(rules(&[&liar, &good], now)).unwrap();
    assert_eq!(b.block_count().unwrap(), 400);
    assert!(b.tx_out(&fake, 0, true).unwrap().is_none());
    assert!(b.status()["implausible"].is_null());
    // enough work but a tip far behind what the clock says: withheld as well
    let late = ElectrumBackend::new(rules(&[&good], T0 + 60 * 500)).unwrap();
    let e = late.block_count().unwrap_err();
    assert_eq!(e.kind, Kind::Implausible);
    assert!(e.msg.contains("implausibly low"), "{e}");
}

// --- AGP-081: one server can no longer stall or exhaust the client (closure audit, review E1) ----

/// A server that serves the real chain one header per answer, each just inside the timeout, held
/// the whole sync round and was never flagged. The first answer with fewer headers than asked ends
/// its part of the round, with the headers it did serve kept.
#[test]
fn a_trickled_header_sync_is_cut_off_and_flagged() {
    let chain = sim(CHECKPOINT + 120);
    let trickler = FakeElectrum::start(chain.clone(), false);
    {
        let mut k = trickler.knobs();
        k.headers_per_answer = Some(1);
        k.delay_headers_ms = 100;
    }
    let b = backend(&chain, &[&trickler]);
    let t = Instant::now();
    assert_eq!(b.block_count().unwrap(), CHECKPOINT + 1, "the one header it served is kept");
    assert!(t.elapsed() < Duration::from_secs(2), "the trickle held the round for {:?}", t.elapsed());
    assert!(b.flags().iter().any(|f| f.server == trickler.url() && f.reason.contains("withheld headers")), "{:?}", b.flags());
    let asked = trickler.calls.lock().unwrap().iter().filter(|m| *m == "blockchain.block.headers").count();
    assert!(asked <= 2, "{asked} header requests in one round");
    // beside an honest server the tip arrives at once (the trickler is asked for nothing we hold)
    let honest = FakeElectrum::start(chain.clone(), false);
    let b = backend(&chain, &[&trickler, &honest]);
    let t = Instant::now();
    assert_eq!(b.block_count().unwrap(), CHECKPOINT + 120);
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
}

/// One server's part of a sync round ends at the deadline, however slowly it answers inside the
/// request timeout.
#[test]
fn a_slow_header_sync_ends_at_its_deadline() {
    let chain = sim(CHECKPOINT + 50);
    let slow = FakeElectrum::start(chain.clone(), false);
    let mut c = cfg(&chain, &[&slow]);
    c.timeout = Duration::from_secs(5);
    c.sync_deadline = Some(Duration::from_millis(300));
    let b = ElectrumBackend::new(c).unwrap();
    assert_eq!(b.block_count().unwrap(), CHECKPOINT + 50);
    slow.knobs().delay_headers_ms = 2_000;
    chain.lock().unwrap().mine(3);
    let t = Instant::now();
    assert_eq!(b.sync(true).unwrap(), CHECKPOINT + 50, "nothing new was proven in time");
    assert!(t.elapsed() < Duration::from_millis(1_500), "the round ran {:?} past a 300 ms deadline", t.elapsed());
    assert!(b.flags().iter().any(|f| f.reason.contains("sync deadline")), "{:?}", b.flags());
    slow.knobs().delay_headers_ms = 0;
    assert_eq!(b.sync(true).unwrap(), CHECKPOINT + 53);
}

/// A line is held to what the waiting requests allow before it is parsed: a long one is cut off
/// while it arrives, a short dense one (many values) is refused whole. Either drops the server.
#[test]
fn an_oversized_line_is_dropped_before_it_is_parsed() {
    let chain = sim(150);
    let s = servers(&chain, 1);
    let b = backend(&chain, &[&s[0]]);
    assert_eq!(b.block_count().unwrap(), 150);
    for (what, line) in [("bytes", "[],".repeat(4 << 20 >> 2)), ("JSON values", "0,".repeat(5_000))] {
        let line = format!("[{}0]", line);
        s[0].knobs().line_before = Some(("blockchain.estimatefee".into(), Arc::new(line.into_bytes())));
        let e = b.estimate_fee(6).expect_err("a line no request allows was read and parsed");
        assert_eq!(e.kind, Kind::Unreachable, "{e}");
        assert!(b.flags().iter().any(|f| f.reason.contains("a line over the limit") && f.reason.contains(what)), "{what}: {:?}", b.flags());
        // dropped, not trusted less: the next request reconnects
        s[0].knobs().line_before = None;
        assert!(b.estimate_fee(6).unwrap().feerate.is_some());
    }
    // and the calls that follow are answered as before
    let fund = spk(0x31);
    let f = chain.lock().unwrap().credit(0, 50_000, &fund, true);
    assert!(b.tx_out(&f, 0, false).unwrap().is_some());
}

/// Invented history entries cost a bounded number of fetches and are flagged: a history over
/// MAX_HISTORY entries is not used at all, and an entry that neither pays nor spends the script
/// flags the server that listed it.
#[test]
fn an_invented_history_is_bounded_and_flagged() {
    use xbt_electrum::conn::MAX_HISTORY;
    use xbt_electrum::sim::coinbase;
    let chain = sim(200);
    let fund = spk(0x41);
    let f = chain.lock().unwrap().credit(0, 70_000, &fund, true);
    let sh = scripthash(&fund);
    let gets = |s: &Arc<FakeElectrum>| s.calls.lock().unwrap().iter().filter(|m| *m == "blockchain.transaction.get").count();
    let (liar, honest) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    // 50 real-looking transactions that have nothing to do with the script
    {
        let mut k = liar.knobs();
        let invented: Vec<_> = (0..50).map(|n| coinbase(1_000_000 + n, 9)).collect();
        k.extra_history.insert(sh.clone(), invented.iter().map(|t| (t.txid(), 150)).collect());
        k.invented = invented.into_iter().map(|t| (t.txid(), t)).collect();
    }
    let b = backend(&chain, &[&liar, &honest]);
    assert!(b.tx_out(&f, 0, false).unwrap().is_some());
    assert!(b.flags().iter().any(|fl| fl.server == liar.url() && fl.reason.contains("neither pays nor spends")), "{:?}", b.flags());
    assert!(!b.flags().iter().any(|fl| fl.server == honest.url()), "{:?}", b.flags());
    // more entries than any script we answer for: the answer is not used, nothing in it is fetched
    liar.knobs().extra_history.insert(sh.clone(), (0..MAX_HISTORY as u32 + 1).map(|n| (coinbase(2_000_000 + n, 9).txid(), 150)).collect());
    let b = backend(&chain, &[&liar, &honest]);
    let before = gets(&liar) + gets(&honest);
    assert!(b.tx_out(&f, 0, false).unwrap().is_some(), "the honest server's history still answers");
    assert!(b.flags().iter().any(|fl| fl.server == liar.url() && fl.reason.contains("at most")), "{:?}", b.flags());
    assert!(gets(&liar) + gets(&honest) - before < 20, "{} fetches for an unusable history", gets(&liar) + gets(&honest) - before);
    // with no other server, the call fails: it is never answered from an empty history
    let b = backend(&chain, &[&liar]);
    let e = b.tx_out(&f, 0, false).expect_err("answered from a history no server gave");
    assert_eq!(e.kind, Kind::Unreachable, "{e}");
}
