#!/usr/bin/env python3
"""AGP-044 on regtest, the Python hub (B1): the same two runs as the Rust hub's xbt402-refund-bump, against
a Rust provider (xbt402-refund-bump --provider-only), driven by scripts/refund_bump_regtest.sh.

  run 1 (refund_bump_blocks 2): an unused ch2's refund at the 1 sat/vB floor is left out of blocks
        (generateblock ADDR []), re-signed at 2x after 2 blocks, replaces itself in the node's mempool
        (BIP125: it signals), and the replacement confirms paying capacity - the bumped fee to the hub
        wallet; the first version never confirms;
  run 2 (refund_max_fee_sat = 3.5x the first fee): bumped to 2x, to the cap, then no further
        (ch2_refund_bump_capped); released, the capped version confirms at exactly the cap.

usage: py_refund_bump.py PROVIDER_URL REPORT.json   (cwd: the B1 checkout; env XBT402_DATADIR, XBT402_RPCPORT)"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.getcwd())
from xbt402.channel import RBF_SEQUENCE  # noqa: E402
from xbt402.hub import RouteHub  # noqa: E402
from xbt402.rpc import RPC  # noqa: E402
from xbt402.tx import Tx  # noqa: E402
from xbt402.x402_channel import network_id  # noqa: E402

SAT = 100_000_000
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
    """n blocks that take nothing from the mempool (a stuck refund stays there)."""
    for _ in range(n):
        node.generateblock(ADDR, [])


def mempool(txid):
    try:
        e = node.getmempoolentry(txid)
        return True, round(e["fees"]["base"] * SAT), bool(e.get("bip125-replaceable"))
    except Exception:  # noqa: BLE001
        return False, 0, False


def confs(txid):
    try:
        return node.getrawtransaction(txid, True).get("confirmations", 0)
    except Exception:  # noqa: BLE001
        return None


def fund(address, sats):
    txid = W.sendtoaddress(address, sats / 1e8)
    raw = W.gettransaction(txid, False, True)["decoded"]
    mine()
    return txid, next(o["n"] for o in raw["vout"] if o["scriptPubKey"].get("address") == address)


def hub(**cfg):
    opts = dict(ch2_capacity=50_000, ch2_expiry_blocks=20, close_margin=5, rollover_margin=2, refund_min_feerate=1.0,
                refund_bump_blocks=2, refund_max_fee_sat=5_000)
    opts.update(cfg)
    return RouteHub(node, int.from_bytes(os.urandom(31), "big") + 1, NET, tempfile.mkdtemp(prefix="pyhub-"), fund,
                    refund_to=lambda: W.getnewaddress("", "bech32"), **opts)


def events(h, name):
    return [e for e in h.events if e["event"] == name]


def stuck_refund(h, tag):
    oc = h.connect(ORIGIN)
    h.watch_tick()
    oc = h.ch2_for(ORIGIN)
    check(f"{tag}: hub-funded ch2 open (nothing routed: its refund is due at expiry)", oc.state == "open" and oc.signed == 0,
          f"{oc.p().channel_id[:16]} capacity {oc.p().capacity}, expiry {oc.p().expiry}")
    tip = node.getblockcount()
    if oc.p().expiry > tip:
        mine(oc.p().expiry - tip)
    h.watch_tick()
    oc = h.ch2_for(ORIGIN)
    r1 = oc.refund_txid
    inpool, fee, rbf = mempool(r1)
    tx = Tx.parse(bytes.fromhex(oc.refund_hex))
    check(f"{tag}: refund at expiry at the 1 sat/vB floor, in the mempool, signalling RBF (nSequence 0xFFFFFFFD)",
          inpool and fee == oc.refund_fee and rbf and tx.inputs[0].sequence == RBF_SEQUENCE and tx.locktime == oc.p().expiry
          and fee <= tx.vsize() + 2, f"{r1[:16]} fee {fee} sat for {tx.vsize()} vB, bip125-replaceable {rbf}")
    mine_empty()
    h.watch_tick()
    check(f"{tag}: left out of blocks: still unconfirmed a block later, not bumped yet",
          mempool(r1)[0] and h.ch2_for(ORIGIN).refund_txid == r1 and not events(h, "ch2_refund_bump"))
    return r1, fee, oc.p().capacity


def main():
    print(f"== node: height {node.getblockcount()}, network {NET}")
    print("== run 1 (Python hub): a stuck refund is re-signed at a higher fee (RBF) and confirms")
    h = hub()
    r1, f1, cap = stuck_refund(h, "run 1")
    mine_empty()
    h.watch_tick()
    oc = h.ch2_for(ORIGIN)
    bump = events(h, "ch2_refund_bump")
    r2 = oc.refund_txid
    in2, f2, rbf2 = mempool(r2)
    check("run 1: refund_bump_blocks (2) later the hub re-signed it at 2x and it replaced the first in the node's mempool",
          len(bump) == 1 and bump[0]["replaces"] == r1 and r2 != r1 and in2 and f2 == oc.refund_fee and f2 >= 2 * f1 and rbf2
          and not mempool(r1)[0] and oc.refund_prev == [{"txid": r1, "fee": f1}], f"{r1[:12]} -> {r2[:12]} fee {f1} -> {f2} sat")
    mine()
    acts = h.watch_tick()
    oc = h.ch2_for(ORIGIN)
    conf = next((a for a in acts if a["event"] == "ch2_refund_confirmed"), {})
    tx2 = node.getrawtransaction(r2, True)
    out2 = round(tx2["vout"][0]["value"] * SAT)
    addr2 = tx2["vout"][0]["scriptPubKey"].get("address", "")
    ours = bool(addr2) and W.getaddressinfo(addr2).get("ismine")
    check("run 1: the replacement confirmed; on chain it pays capacity - the bumped fee to the hub wallet's refund address",
          conf.get("txid") == r2 and conf.get("fee") == f2 and oc.final and tx2.get("confirmations", 0) >= 1
          and out2 == cap - f2 and ours and h.refund_fees_sat() == f2 and h.committed_sat() == 0,
          f"{tx2.get('confirmations')} conf, output {out2} = {cap} - {f2}, ours {ours}")
    check("run 1: the first version never confirmed (txindex has no such tx)", confs(r1) is None)

    print("== run 2 (Python hub): refund_max_fee_sat caps the bumps")
    cap_fee = f1 * 7 // 2
    h2 = hub(refund_max_fee_sat=cap_fee)
    q1, g1, cap2 = stuck_refund(h2, "run 2")
    fees, txids = [g1], [q1]
    for _ in range(8):
        mine_empty()
        h2.watch_tick()
        oc = h2.ch2_for(ORIGIN)
        if oc.refund_txid != txids[-1]:
            fees.append(oc.refund_fee)
            txids.append(oc.refund_txid)
    capped = events(h2, "ch2_refund_bump_capped")
    check("run 2: bumped to 2x, then to the cap, then no further (ch2_refund_bump_capped)",
          fees == [g1, 2 * g1, cap_fee] and capped and all(c["fee"] == cap_fee and c["cap"] == cap_fee for c in capped)
          and mempool(txids[-1])[0], f"fees {fees}, cap {cap_fee}, {len(capped)} capped event(s)")
    mine()
    h2.watch_tick()
    oc = h2.ch2_for(ORIGIN)
    tx = node.getrawtransaction(txids[-1], True)
    out = round(tx["vout"][0]["value"] * SAT)
    check("run 2: released, the capped version confirmed at exactly the cap; the earlier ones never did",
          oc.final and oc.refund_fee == cap_fee and out == cap2 - cap_fee and tx.get("confirmations", 0) >= 1
          and all(confs(t) is None for t in txids[:-1]), f"output {out} = {cap2} - {cap_fee}")
    ok = all(c["ok"] for c in CHECKS)
    with open(REPORT, "w") as f:
        json.dump({"network": NET, "checks": CHECKS, "run1": {"fees": [f1, f2], "txids": [r1, r2]},
                   "run2": {"fees": fees, "txids": txids, "cap": cap_fee}, "hub1_events": h.events, "hub2_events": h2.events},
                  f, indent=1, default=str)
    print(f"== refund bump (Python hub, regtest): {'PASS' if ok else 'FAIL'} ({sum(c['ok'] for c in CHECKS)}/{len(CHECKS)} checks)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
