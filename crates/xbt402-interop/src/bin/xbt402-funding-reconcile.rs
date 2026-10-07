//! AGP-045 on regtest: a hub ch2 funding whose wallet call failed after it broadcast is reconciled
//! against the wallet (`listtransactions`, `gettransaction`), the mempool (`gettxout` incl. the
//! mempool, `getmempoolentry`) and the UTXO set, not `scantxoutset` alone. Run by
//! `scripts/funding_reconcile_regtest.sh` against the provider of `xbt402-refund-bump --provider-only`.
//!
//! xbt402-funding-reconcile --rpc-port R --cookie PATH --provider URL [--report FILE]
//!
//! * run A (slow): the send stays in the mempool past `funding_timeout_blocks` (blocks mined with
//!   `generateblock ADDR []` leave it out); the hub finds it in the wallet and the mempool, never
//!   drops it, and opens the ch2 once it confirms (the old reconcile, scantxoutset only, dropped it);
//! * run B (conflicted): the send is replaced in the mempool by a conflicting spend of its input; at
//!   the timeout the hub drops the record but keeps watching the send it knows; once the conflict
//!   confirms the wallet says the send never will (`ch2_funding_failed`) and the record is final.
//!
//! Exit 0 iff every check passes.
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use xbt402::adaptor;
use xbt402::client::{Wallet, WalletSend};
use xbt402::error::ChannelError;
use xbt402::funding::ChainBackend;
use xbt402::http::UreqTransport;
use xbt402::hub::{HubConfig, OutChannel, RouteHub};
use xbt402::rpc::Rpc;
use xbt402::route::SpendScan;
use xbt_primitives::network::network_id;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

struct Checks(Vec<Value>);

impl Checks {
    fn check(&mut self, name: &str, ok: bool, detail: String) {
        println!("  {}  {name}{}", if ok { "PASS" } else { "FAIL" }, if detail.is_empty() { String::new() } else { format!("  ({detail})") });
        self.0.push(json!({"check": name, "ok": ok, "detail": detail}));
    }
}

/// The node wallet "w": `fund` sends (replaceable) and then fails, as a wallet call that times out
/// after `sendtoaddress`; its wallet view is the real one.
struct FailAfterSend {
    w: Rpc,
    sent: Arc<Mutex<Vec<String>>>,
}

impl Wallet for FailAfterSend {
    fn fund(&self, address: &str, sats: u64) -> xbt402::Result<(String, u32)> {
        let txid = self.w.call("sendtoaddress", json!([address, sats as f64 / 1e8, "", "", false, true]))?;
        self.sent.lock().unwrap().push(txid.as_str().unwrap_or("").to_string());
        Err(ChannelError::new("rpc_error", "gettransaction: timeout"))
    }

    fn wallet_sends_to(&self, address: &str) -> xbt402::Result<Vec<String>> {
        self.w.wallet_sends_to(address)
    }

    fn wallet_send(&self, txid: &str, address: &str) -> xbt402::Result<Option<WalletSend>> {
        self.w.wallet_send(txid, address)
    }
}

struct Node {
    rpc: Rpc,
    addr: String,
}

impl Node {
    fn mine(&self, n: u32) {
        self.rpc.call("generatetoaddress", json!([n, self.addr])).expect("mine");
    }

    /// `n` blocks that take nothing from the mempool (a slow funding stays there).
    fn mine_empty(&self, n: u32) {
        for _ in 0..n {
            self.rpc.call("generateblock", json!([self.addr, []])).expect("generateblock");
        }
    }

    fn in_mempool(&self, txid: &str) -> bool {
        self.rpc.in_mempool(txid).unwrap_or(false)
    }

    /// Replace `txid` in the mempool with a spend of its first input back to the wallet, at a far
    /// higher fee (BIP125: the send signals).
    fn conflict(&self, txid: &str) -> String {
        let tx = self.rpc.call("getrawtransaction", json!([txid, true])).expect("send");
        let (pt, pv) = (tx["vin"][0]["txid"].as_str().unwrap().to_string(), tx["vin"][0]["vout"].as_u64().unwrap());
        let prev = self.rpc.call("getrawtransaction", json!([pt, true])).expect("prev");
        let value = prev["vout"][pv as usize]["value"].as_f64().unwrap();
        let w = self.rpc.wallet("w");
        let dest = w.call("getnewaddress", json!(["", "bech32"])).unwrap();
        let out = ((value - 0.001) * 1e8).round() / 1e8;
        let raw = w.call("createrawtransaction", json!([[{"txid": pt, "vout": pv, "sequence": 0xFFFF_FFFDu32}], [{dest.as_str().unwrap(): out}]])).unwrap();
        let signed = w.call("signrawtransactionwithwallet", json!([raw])).unwrap();
        self.rpc.call("sendrawtransaction", json!([signed["hex"]])).expect("the conflicting spend").as_str().unwrap().to_string()
    }
}

fn hub(node: &Node, net: &str, dir: &std::path::Path, sent: &Arc<Mutex<Vec<String>>>) -> RouteHub {
    let c = json!({"ch2_capacity": 50_000, "ch2_expiry_blocks": 20, "close_margin": 5, "rollover_margin": 2, "funding_timeout_blocks": 3});
    let rpc = Arc::new(node.rpc.clone());
    RouteHub::new(rpc.clone(), rpc, Box::new(FailAfterSend { w: node.rpc.wallet("w"), sent: sent.clone() }), Box::new(UreqTransport::default()),
                  adaptor::random_secret(), net, Some(dir), HubConfig::from_json(&c).expect("config")).expect("hub")
}

fn events(h: &RouteHub, name: &str) -> Vec<Value> {
    h.events.lock().unwrap().iter().filter(|e| e["event"] == name).cloned().collect()
}

fn main() {
    let rpc = Rpc::from_cookie(&format!("http://127.0.0.1:{}", arg("--rpc-port").expect("--rpc-port")),
                               std::path::Path::new(&arg("--cookie").expect("--cookie"))).expect("cookie");
    let origin = arg("--provider").expect("--provider");
    let net = network_id(rpc.call("getblockhash", json!([101])).unwrap().as_str().unwrap());
    let addr = rpc.wallet("w").call("getnewaddress", json!([])).unwrap().as_str().unwrap().to_string();
    let node = Node { rpc: rpc.clone(), addr };
    let run = std::env::temp_dir().join(format!("xbt402-funding-reconcile-{}", std::process::id()));
    std::fs::create_dir_all(&run).unwrap();
    let mut ck = Checks(vec![]);
    println!("== node: height {}, network {net}", node.rpc.block_count().unwrap());

    // --- run A: slow, in the mempool past the timeout --------------------------------------------------
    println!("== run A (Rust hub): a funding still in the mempool past funding_timeout_blocks");
    let sent = Arc::new(Mutex::new(vec![]));
    let h = hub(&node, &net, &run.join("hubA"), &sent);
    let e = h.connect(&origin, None, None).unwrap_err();
    let s = sent.lock().unwrap()[0].clone();
    ck.check("A: the wallet sent the funding, then its call failed: record `funding`, send in the mempool",
             e.code == "fund_failed" && h.ch2_for(&origin).is_some_and(|c| c.state == "funding") && node.in_mempool(&s), s[..16].to_string());
    node.mine_empty(h.cfg.funding_timeout_blocks + 1);
    let scan = node.rpc.scan_spk(&h.ch2_for(&origin).unwrap().params.spk()).unwrap_or_default();
    let acts = h.watch_tick();
    let rec = acts.iter().find(|a| a["event"] == "ch2_funding_recovered").cloned().unwrap_or(Value::Null);
    let oc = h.ch2_for(&origin).unwrap();
    ck.check("A: past the timeout, unconfirmed (scantxoutset sees nothing): found by the wallet + mempool, funded, not dropped",
             scan.is_empty() && rec["txid"] == s.as_str() && oc.state == "funded" && oc.params.funding_txid() == s && oc.fund_txid == s
             && events(&h, "ch2_funding_dropped").is_empty() && node.in_mempool(&s) && h.committed_sat() == 50_000,
             format!("{} blocks, vout {}, capacity {}", h.cfg.funding_timeout_blocks + 1, oc.params.funding_vout(), oc.params.capacity));
    node.mine(1);
    h.watch_tick();
    let oc = h.ch2_for(&origin).unwrap();
    ck.check("A: once it confirmed the ch2 opened at the provider", oc.state == "open" && !events(&h, "ch2_open").is_empty(),
             oc.params.channel_id()[..16].to_string());

    // --- run B: conflicted --------------------------------------------------------------------------------
    println!("== run B (Rust hub): a funding replaced by a conflicting spend");
    let sent_b = Arc::new(Mutex::new(vec![]));
    let hb = hub(&node, &net, &run.join("hubB"), &sent_b);
    let _ = hb.connect(&origin, None, None).unwrap_err();
    let sb = sent_b.lock().unwrap()[0].clone();
    let c = node.conflict(&sb);
    ck.check("B: the send was replaced in the mempool by a conflicting spend of its input",
             !node.in_mempool(&sb) && node.in_mempool(&c), format!("{} -> {}", &sb[..12], &c[..12]));
    node.mine_empty(hb.cfg.funding_timeout_blocks);
    let acts = hb.watch_tick();
    let dropped = acts.iter().find(|a| a["event"] == "ch2_funding_dropped").cloned().unwrap_or(Value::Null);
    let last = hb.archived().last().cloned().unwrap_or(Value::Null);
    ck.check("B: at the timeout the record is dropped, but the send it knows is watched (not final)",
             dropped["watching"] == sb.as_str() && last["state"] == "dropped" && last["fund_txid"] == sb.as_str() && last["final"] == false
             && hb.ch2_for(&origin).is_none(), String::new());
    node.mine(1);
    let acts = hb.watch_tick();
    let failed = acts.iter().find(|a| a["event"] == "ch2_funding_failed").cloned().unwrap_or(Value::Null);
    let last = OutChannel::from_json(&hb.archived().last().cloned().unwrap()).unwrap();
    let ws = node.rpc.wallet("w").wallet_send(&sb, &xbt_primitives::address::segwit_address("bcrt", &last.params.spk()).unwrap()).ok().flatten();
    ck.check("B: the conflict confirmed: the wallet says the send never will (confirmations < 0), ch2_funding_failed, final",
             failed["txid"] == sb.as_str() && failed["why"] == "conflicted" && last.final_ && ws.as_ref().is_some_and(|w| w.confirmations < 0),
             format!("gettransaction confirmations {:?}", ws.map(|w| w.confirmations)));
    let n = hb.events.lock().unwrap().len();
    hb.watch_tick();
    ck.check("B: final: not watched any more", hb.events.lock().unwrap().len() == n, String::new());

    let ok = ck.0.iter().all(|c| c["ok"] == true);
    if let Some(p) = arg("--report") {
        let rep = json!({"network": net, "checks": ck.0, "runA": {"send": s}, "runB": {"send": sb, "conflict": c},
                         "hubA_events": *h.events.lock().unwrap(), "hubB_events": *hb.events.lock().unwrap()});
        std::fs::write(p, serde_json::to_string_pretty(&rep).unwrap()).unwrap();
    }
    let n_ok = ck.0.iter().filter(|c| c["ok"] == true).count();
    println!("== funding reconcile (Rust hub, regtest): {} ({n_ok}/{} checks)", if ok { "PASS" } else { "FAIL" }, ck.0.len());
    let _ = std::fs::remove_dir_all(&run);
    std::process::exit(if ok { 0 } else { 1 });
}
