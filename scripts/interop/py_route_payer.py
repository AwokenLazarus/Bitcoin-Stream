#!/usr/bin/env python3
"""The Python B1 RoutePayer (reference, b1 agp-023) on the interop node, B1's ChannelSigner holding
the keys; the same flow and JSON summary as xbt402-route-payer.
    py_route_payer.py HUB_URL SHARD_URL,SHARD_URL [SECONDS] [RATE]
Env: XBT402_B1, XBT402_DATADIR, XBT402_RPCPORT."""
import json, os, statistics, sys, threading, time
sys.path.insert(0, os.environ.get("XBT402_B1", os.path.expanduser("~/xbt-rnd/b1-agp-023")))
from xbt402.route_client import RoutePayer  # noqa: E402
from xbt402.rpc import RPC  # noqa: E402
from xbt402.signer import ChannelSigner  # noqa: E402
from xbt402.x402_channel import network_id  # noqa: E402

hub, urls = sys.argv[1], sys.argv[2].split(",")
secs = float(sys.argv[3]) if len(sys.argv) > 3 else 6.0
rate = float(sys.argv[4]) if len(sys.argv) > 4 else 10.0
node = RPC.from_env()
w = node.wallet("w")
addr = w.getnewaddress()
net = network_id(node.getblockhash(101))


def fund(address, sats):
    txid = w.sendtoaddress(address, sats / 1e8)
    raw = w.gettransaction(txid, False, True)["decoded"]
    node.generatetoaddress(1, addr)
    return txid, next(o["n"] for o in raw["vout"] if o["scriptPubKey"].get("address") == address)


pay = RoutePayer(hub, net, node.getblockcount, fund=fund, signer=ChannelSigner(fund=fund), capacity=200_000, expiry_blocks=8_000)
ch1 = pay.open()
shards = [pay.shard(u) for u in urls]
stop = threading.Event()
ok = [0] * len(shards)


def run(i):
    nxt = time.time()
    while not stop.is_set():
        nxt += 1 / rate
        try:
            st, _, _ = pay.call(shards[i], "POST", b'{"tokens":1}')
            ok[i] += st == 200
        except Exception as e:  # noqa: BLE001
            print("call:", e, file=sys.stderr)
        time.sleep(max(0.0, nxt - time.time()))


pay.start(interval=0.5)
t0 = time.time()
ths = [threading.Thread(target=run, args=(i,)) for i in range(len(shards))]
[t.start() for t in ths]
time.sleep(secs)
stop.set()
[t.join() for t in ths]
dur = time.time() - t0
until = time.time() + 8
while time.time() < until and (pay.pending or any(s.due_sat() > 0 for s in shards)):
    time.sleep(0.3)
pay.stop()
try:
    close = pay.close()
except Exception as e:  # noqa: BLE001
    close = {"error": str(e)}


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else 0.0


lock_ms = [x for s in shards for x in s.lock_ms]
call_ms = [x for s in shards for x in s.call_ms]
summ = pay.summary()
for u, s in summ["shards"].items():
    sh = pay.shards[u]
    s.update(accrued_amsat=str(s["accrued_amsat"]), seen_amsat=str(s["seen_amsat"]), pay_to=sh.pay_to, session=sh.session)
summ.update(fee_units=str(pay.fee_units), locks=pay.stats["locks"])
print(json.dumps({"impl": "python", "ch1": ch1, "ch1Params": pay.ch.payer.params.to_dict(), "close": close, "summary": summ,
                  "okCalls": ok, "seconds": dur,
                  "lockMs": {"n": len(lock_ms), "p50": pct(lock_ms, 0.5), "p95": pct(lock_ms, 0.95)},
                  "callMs": {"n": len(call_ms), "p50": pct(call_ms, 0.5), "p95": pct(call_ms, 0.95)},
                  "events": pay.events}, default=str))
