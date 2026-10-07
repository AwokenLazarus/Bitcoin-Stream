#!/usr/bin/env python3
"""AGP-045 on regtest, the Python hub (B1): the same two runs as the Rust hub's xbt402-funding-reconcile,
against a Rust provider (xbt402-refund-bump --provider-only), driven by scripts/funding_reconcile_regtest.sh.

  run A (slow): the wallet's funding send stays in the mempool past funding_timeout_blocks (generateblock
        ADDR [] leaves it out); the hub finds it in the wallet and the mempool, never drops it, and opens
        the ch2 once it confirms;
  run B (conflicted): the send is replaced in the mempool by a conflicting spend of its input; at the
        timeout the record is dropped but the known send is watched; once the conflict confirms the
        wallet says it never will (ch2_funding_failed) and the record is final.

usage: py_funding_reconcile.py PROVIDER_URL REPORT.json   (cwd: the B1 checkout; env XBT402_DATADIR, XBT402_RPCPORT)"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.getcwd())
from xbt402.hub import OutChannel, RouteHub  # noqa: E402
from xbt402.rpc import RPC  # noqa: E402
from xbt402.x402_channel import network_id  # noqa: E402

ORIGIN, REPORT = sys.argv[1], sys.argv[2]
node = RPC.from_env()
W = node.wallet("w")
ADDR = W.getnewaddress("", "bech32")
NET = network_id(node.getblockhash(101))
CHECKS = []


def check(name, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)
    CHECKS.append({"check": name, "ok": bool(ok), "detail": detail})


def mine(n=1):
    node.generatetoaddress(n, ADDR)


def mine_empty(n=1):
    """n blocks that take nothing from the mempool (a slow funding stays there)."""
    for _ in range(n):
        node.generateblock(ADDR, [])


def in_mempool(txid):
    try:
        return bool(node.getmempoolentry(txid))
    except Exception:  # noqa: BLE001
        return False


def conflict(txid):
    """Replace txid in the mempool with a spend of its first input back to the wallet, at a far higher fee."""
    tx = node.getrawtransaction(txid, True)
    pt, pv = tx["vin"][0]["txid"], tx["vin"][0]["vout"]
    value = node.getrawtransaction(pt, True)["vout"][pv]["value"]
    dest = W.getnewaddress("", "bech32")
    raw = W.createrawtransaction([{"txid": pt, "vout": pv, "sequence": 0xFFFFFFFD}], [{dest: round(value - 0.001, 8)}])
    return node.sendrawtransaction(W.signrawtransactionwithwallet(raw)["hex"])


def hub(sent):
    def fund(address, sats):                 # sends (replaceable), then the wallet call fails
        sent.append(W.sendtoaddress(address, sats / 1e8, "", "", False, True))
        raise RuntimeError("gettransaction: timeout")
    return RouteHub(node, int.from_bytes(os.urandom(31), "big") + 1, NET, tempfile.mkdtemp(prefix="pyhub-"), fund,
                    wallet=W, ch2_capacity=50_000, ch2_expiry_blocks=20, close_margin=5, rollover_margin=2,
                    funding_timeout_blocks=3)


def events(h, name):
    return [e for e in h.events if e["event"] == name]


def main():
    print(f"== node: height {node.getblockcount()}, network {NET}")
    print("== run A (Python hub): a funding still in the mempool past funding_timeout_blocks")
    sent = []
    h = hub(sent)
    try:
        h.connect(ORIGIN)
        code = None
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
    s = sent[0]
    check("A: the wallet sent the funding, then its call failed: record `funding`, send in the mempool",
          code == "fund_failed" and h.ch2_for(ORIGIN) is not None and h.ch2_for(ORIGIN).state == "funding" and in_mempool(s), s[:16])
    mine_empty(h.config.funding_timeout_blocks + 1)
    scan = node.scantxoutset("start", [f"raw({h.ch2_for(ORIGIN).p().spk.hex()})"])["unspents"]
    acts = h.watch_tick()
    rec = next((a for a in acts if a["event"] == "ch2_funding_recovered"), {})
    oc = h.ch2_for(ORIGIN)
    check("A: past the timeout, unconfirmed (scantxoutset sees nothing): found by the wallet + mempool, funded, not dropped",
          not scan and rec.get("txid") == s and oc.state == "funded" and oc.p().funding_txid == s and oc.fund_txid == s
          and not events(h, "ch2_funding_dropped") and in_mempool(s) and h.committed_sat() == 50_000,
          f"{h.config.funding_timeout_blocks + 1} blocks, vout {oc.p().funding_vout}, capacity {oc.p().capacity}")
    mine()
    h.watch_tick()
    oc = h.ch2_for(ORIGIN)
    check("A: once it confirmed the ch2 opened at the provider", oc.state == "open" and bool(events(h, "ch2_open")),
          oc.p().channel_id[:16])

    print("== run B (Python hub): a funding replaced by a conflicting spend")
    sent_b = []
    hb = hub(sent_b)
    try:
        hb.connect(ORIGIN)
    except Exception:  # noqa: BLE001
        pass
    sb = sent_b[0]
    c = conflict(sb)
    check("B: the send was replaced in the mempool by a conflicting spend of its input",
          not in_mempool(sb) and in_mempool(c), f"{sb[:12]} -> {c[:12]}")
    mine_empty(hb.config.funding_timeout_blocks)
    acts = hb.watch_tick()
    dropped = next((a for a in acts if a["event"] == "ch2_funding_dropped"), {})
    last = hb.out.archived[-1] if hb.out.archived else {}
    check("B: at the timeout the record is dropped, but the send it knows is watched (not final)",
          dropped.get("watching") == sb and last.get("state") == "dropped" and last.get("fund_txid") == sb
          and last.get("final") is False and hb.ch2_for(ORIGIN) is None)
    mine()
    acts = hb.watch_tick()
    failed = next((a for a in acts if a["event"] == "ch2_funding_failed"), {})
    last = OutChannel(**hb.out.archived[-1])
    conf = W.gettransaction(sb).get("confirmations")
    check("B: the conflict confirmed: the wallet says the send never will (confirmations < 0), ch2_funding_failed, final",
          failed.get("txid") == sb and failed.get("why") == "conflicted" and last.final and conf is not None and conf < 0,
          f"gettransaction confirmations {conf}")
    n = len(hb.events)
    hb.watch_tick()
    check("B: final: not watched any more", len(hb.events) == n)
    ok = all(c["ok"] for c in CHECKS)
    with open(REPORT, "w") as f:
        json.dump({"network": NET, "checks": CHECKS, "runA": {"send": s}, "runB": {"send": sb, "conflict": c},
                   "hubA_events": h.events, "hubB_events": hb.events}, f, indent=1, default=str)
    print(f"== funding reconcile (Python hub, regtest): {'PASS' if ok else 'FAIL'} ({sum(c['ok'] for c in CHECKS)}/{len(CHECKS)} checks)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
