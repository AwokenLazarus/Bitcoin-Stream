//! The Rust payer on a regtest node, for the cross-implementation run: opens a channel to a
//! provider (any implementation), makes N paid calls, closes cooperatively, mines the close and
//! checks the on-chain amounts exactly. Prints one JSON result line; exit 0 only if every check
//! holds.
//!
//! xbt402-rust-payer --url http://127.0.0.1:P --rpc-port R --cookie PATH [--wallet w] [--calls 10]
//!                   [--conditional /v1/secret]
use serde_json::{json, Value};
use xbt402::client::{Client, ClientConfig, Wallet};
use xbt402::funding::ChainBackend;
use xbt402::http::UreqTransport;
use xbt402::rpc::Rpc;
use xbt402::{ChannelError, Result};
use xbt_primitives::network::network_id;
use xbt_primitives::tx::Tx;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

/// Funds from the node's wallet and mines one block, so the provider sees a confirmed funding.
struct MiningWallet(Rpc);

impl MiningWallet {
    fn mine(&self, n: u32) -> Result<()> {
        let addr = self.0.call("getnewaddress", json!([]))?;
        self.0.call("generatetoaddress", json!([n, addr]))?;
        Ok(())
    }
}

impl Wallet for MiningWallet {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        let r = self.0.fund(address, sats)?;
        self.mine(1)?;
        Ok(r)
    }
}

fn main() {
    let r = run();
    match r {
        Ok(v) => {
            println!("{v}");
            std::process::exit(if v["ok"] == Value::Bool(true) { 0 } else { 1 });
        }
        Err(e) => {
            println!("{}", json!({"ok": false, "error": e.to_string()}));
            std::process::exit(1);
        }
    }
}

fn run() -> Result<Value> {
    let url = arg("--url").expect("--url");
    let node = Rpc::from_cookie(&format!("http://127.0.0.1:{}", arg("--rpc-port").expect("--rpc-port")),
                                std::path::Path::new(&arg("--cookie").expect("--cookie")))?;
    let wallet = node.wallet(&arg("--wallet").unwrap_or_else(|| "w".into()));
    let calls: u32 = arg("--calls").map(|c| c.parse().expect("calls")).unwrap_or(10);
    let network = network_id(node.call("getblockhash", json!([101]))?.as_str().unwrap_or(""));
    let h = node.clone();
    let mut client = Client::new(ClientConfig::new(&network), Box::new(UreqTransport::default()),
                                 Box::new(MiningWallet(wallet.clone())), Box::new(move || h.block_count()));
    let rollover_after: Option<u32> = arg("--rollover-after").map(|c| c.parse().expect("rollover-after"));
    let mut roll = Value::Null;
    let mut statuses = vec![];
    for i in 0..calls {
        if Some(i) == rollover_after {
            // one tx pays the provider what is owed and funds the next channel; the provider
            // co-signs and broadcasts it; once mined the next channel is opened at the provider
            let old = client.channels[&url].payer.params.clone();
            let owed = (client.channels[&url].spent_msat / 1000).max(client.channels[&url].payer.signed).max(old.min_amount());
            let r = client.rollover(&url)?;
            MiningWallet(wallet.clone()).mine(1)?;
            let opened = client.open_rolled(&url)?;
            let rtx = Tx::parse_hex(node.call("getrawtransaction", json!([r["txid"], true]))?["hex"].as_str().unwrap_or(""))?;
            let next = client.channels[&url].payer.params.clone();
            roll = json!({"txid": r["txid"], "amount": owed, "nextChan": r["nextChan"], "nextCapacity": r["nextCapacity"],
                          "opened": opened["chan"], "payeeOut": rtx.outputs[0].value, "nextOut": rtx.outputs[1].value,
                          "ok": rtx.outputs[0].script_pubkey == old.payee_spk && rtx.outputs[0].value as u64 == old.payee_value(owed)
                                && rtx.outputs[1].script_pubkey == next.spk() && rtx.outputs[1].value as u64 == old.rollover_next_capacity(owed)
                                && opened["chan"] == r["nextChan"] && next.capacity == old.rollover_next_capacity(owed)});
        }
        let r = client.request("POST", &format!("{url}/v1/infer?i={i}"), format!("{{\"q\":{i}}}").as_bytes())?;
        statuses.push(r.status);
    }
    let mut cond = Value::Null;
    if let Some(path) = arg("--conditional") {
        let (r, plain) = client.request_conditional("GET", &format!("{url}{path}"), b"")?;
        cond = json!({"status": r.status, "plaintext": String::from_utf8_lossy(&plain)});
    }
    let ch = client.channels[&url].clone();
    let p = ch.payer.params.clone();
    let spent_sat = ch.spent_msat / 1000;
    let close = client.close(&url)?;
    // the payer's own final state: what it signed, whatever the provider reports
    let signed = client.channels[&url].payer.signed;
    MiningWallet(wallet.clone()).mine(1)?;
    let txid = close["txid"].as_str().ok_or_else(|| ChannelError::code("no close txid"))?.to_string();
    let raw = node.call("getrawtransaction", json!([txid, true]))?;
    let tx = Tx::parse_hex(raw["hex"].as_str().unwrap_or(""))?;
    let to = |spk: &[u8]| tx.outputs.iter().filter(|o| o.script_pubkey == spk).map(|o| o.value).sum::<i64>();
    let (payee_out, payer_out) = (to(&p.payee_spk), to(&p.payer_spk));
    let reported: u64 = close["cum"].as_str().and_then(|c| c.parse().ok()).unwrap_or(u64::MAX);
    let unpaid: u64 = close["unpaidMsat"].as_str().and_then(|c| c.parse().ok()).unwrap_or(u64::MAX);
    let want_payee = p.payee_value(signed) as i64;
    let want_payer = (p.capacity - p.payer_fee() - signed) as i64;
    let checks = json!({
        "all_calls_200": statuses.iter().all(|s| *s == 200),
        "receipts_verified": ch.receipts.len() as u32 == calls - rollover_after.unwrap_or(0) + u32::from(!cond.is_null()),
        "final_state_pays_what_was_spent": signed == spent_sat.max(p.min_amount()),
        "payee_output_exact": payee_out == want_payee,
        "payer_output_exact": payer_out == want_payer,
        "fee_exact": p.capacity as i64 - payee_out - payer_out == p.close_fee as i64,
        "close_confirmed": raw["confirmations"].as_u64().unwrap_or(0) >= 1,
        // the close report (AGP-029): cum = the gross state the payer signed, unpaidMsat = spent - cum
        // (0 when fully paid, never the provider's own close fee); under payee-pays payeeFee is the
        // close fee and payeeNet what the payee output holds, and payer-pays carries neither.
        "provider_report_gross": reported == signed && unpaid == ch.spent_msat.saturating_sub(reported * 1000),
        "provider_report_fee": if p.payee_fee() > 0 {
            close["payeeFee"].as_str() == Some(p.close_fee.to_string().as_str())
                && close["payeeNet"].as_str() == Some(payee_out.to_string().as_str())
        } else {
            close.get("payeeFee").is_none() && close.get("payeeNet").is_none()
        },
    });
    let ok = checks.as_object().map(|m| m.values().all(|v| v == &Value::Bool(true))).unwrap_or(false)
        && (cond.is_null() || cond["status"] == 200) && (roll.is_null() || roll["ok"] == true);
    Ok(json!({"ok": ok, "impl": "rust-payer", "url": url, "network": network, "chan": p.channel_id(),
              "closeFeePayer": p.close_fee_payer.as_str(), "capacity": p.capacity, "closeFee": p.close_fee, "calls": calls,
              "spentSat": spent_sat, "finalCum": signed, "reportedCum": reported, "reportedUnpaidMsat": unpaid, "closeTxid": txid, "payeeOut": payee_out, "payerOut": payer_out,
              "conditional": cond, "rollover": roll, "checks": checks}))
}
