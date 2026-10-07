#!/usr/bin/env python3
"""The Python B1 client (reference, b1 agp-023) pays a provider on the interop node: N paid calls,
optionally one hash-locked conditional call, a cooperative close, then the close is mined and its
on-chain amounts are checked exactly. Prints one JSON line; exit 0 only if every check holds.
    py_payer.py URL [CALLS] [CONDITIONAL_PATH]
Env: XBT402_B1, XBT402_DATADIR, XBT402_RPCPORT."""
import json, os, sys
sys.path.insert(0, os.environ.get("XBT402_B1", os.path.expanduser("~/xbt-rnd/b1-agp-050")))
from xbt402.rpc import RPC  # noqa: E402
from xbt402.tx import Tx  # noqa: E402
from xbt402.x402_channel import XbtChannelClient, network_id  # noqa: E402

SAT = 100_000_000
url = sys.argv[1]
calls = int(sys.argv[2]) if len(sys.argv) > 2 else 10
cond_path = sys.argv[3] if len(sys.argv) > 3 else ""
node = RPC.from_env()
w = node.wallet("w")
net = network_id(node.getblockhash(101))


def fund(address, sats):
    txid = w.sendtoaddress(address, sats / SAT)
    raw = node.getrawtransaction(txid, True)
    return txid, next(o["n"] for o in raw["vout"] if o["scriptPubKey"].get("address") == address)


client = XbtChannelClient(net, fund, node.getblockcount, capacity=200_000,
                          on_open=lambda ch: node.generatetoaddress(1, w.getnewaddress()))
statuses = [client.request("POST", f"{url}/v1/infer?i={i}", json.dumps({"q": i}).encode())[0] for i in range(calls)]
cond = None
if cond_path:
    st, _, _, plain = client.request_conditional("GET", url + cond_path)
    cond = {"status": st, "plaintext": plain.decode(errors="replace")}
ch = client.channels[url]
p = ch.payer.params
spent_sat = ch.spent_msat // 1000
close = client.close(url)
node.generatetoaddress(1, w.getnewaddress())
raw = node.getrawtransaction(close["txid"], True)
tx = Tx.parse(bytes.fromhex(raw["hex"]))
to = lambda spk: sum(o.value for o in tx.outputs if o.script_pubkey.hex() == spk)  # noqa: E731
payee_out, payer_out = to(p.payee_spk), to(p.payer_spk)
cum = ch.payer.signed                   # the payer's own final state, whatever the provider reports
reported, unpaid = int(close["cum"]), int(close["unpaidMsat"])
checks = {
    "all_calls_200": all(s == 200 for s in statuses),
    "receipts_verified": len(ch.receipts) == calls + (1 if cond else 0),
    "final_state_pays_what_was_spent": cum == max(spent_sat, p.min_amount),
    "payee_output_exact": payee_out == p.payee_value(cum),
    "payer_output_exact": payer_out == p.capacity - p.payer_fee - cum,
    "fee_exact": p.capacity - payee_out - payer_out == p.close_fee,
    "close_confirmed": raw.get("confirmations", 0) >= 1,
    # the close report (AGP-029): cum = the gross state the payer signed, unpaidMsat = spent - cum (0
    # when fully paid, never the provider's own close fee); payee-pays adds payeeFee and payeeNet
    "provider_report_gross": reported == cum and unpaid == max(0, ch.spent_msat - reported * 1000),
    "provider_report_fee": ((close.get("payeeFee"), close.get("payeeNet")) == (str(p.close_fee), str(payee_out))
                            if p.payee_fee else "payeeFee" not in close and "payeeNet" not in close),
}
ok = all(checks.values()) and (cond is None or cond["status"] == 200)
print(json.dumps({"ok": ok, "impl": "python-payer", "url": url, "network": net, "chan": p.channel_id,
                  "closeFeePayer": p.close_fee_payer, "capacity": p.capacity, "closeFee": p.close_fee, "calls": calls,
                  "spentSat": spent_sat, "finalCum": cum, "reportedCum": reported, "reportedUnpaidMsat": unpaid, "closeTxid": close["txid"], "payeeOut": payee_out,
                  "payerOut": payer_out, "conditional": cond, "checks": checks}))
sys.exit(0 if ok else 1)
