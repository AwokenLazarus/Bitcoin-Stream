#!/usr/bin/env python3
"""The Python B1 provider (reference, b1 agp-023) selling a routed path on the interop node.
    py_route_provider.py PORT SECRET_HEX AMSAT_PER_CALL [SETTLE_MULTIPLE [ZERO_CONF_MAX|default [WATCH_SECS]]]
(AGP-053: ZERO_CONF_MAX caps an unconfirmed rollover child, 0 never; default 2 x settleMultiple x closeFee.)
Env: XBT402_B1, XBT402_DATADIR, XBT402_RPCPORT (B1's RPC.from_env); XBT402_ROUTE_WAL (AGP-054: a RouteWal path)."""
import json, os, sys, tempfile
sys.path.insert(0, os.environ.get("XBT402_B1", os.path.expanduser("~/xbt-rnd/b1-agp-023")))
from xbt402.funding import FundingPolicy  # noqa: E402
from xbt402.rpc import RPC  # noqa: E402
from xbt402.x402_channel import XbtChannelProvider, network_id  # noqa: E402

port, secret, amsat = int(sys.argv[1]), int(sys.argv[2], 16), int(sys.argv[3])
settle = int(sys.argv[4]) if len(sys.argv) > 4 else 20
zc_max = int(sys.argv[5]) if len(sys.argv) > 5 and sys.argv[5] != "default" else None
watch_s = float(sys.argv[6]) if len(sys.argv) > 6 else 5.0
node = RPC.from_env()
net = network_id(node.getblockhash(101))
tmp = tempfile.mkdtemp(prefix="xbt-rs-route-py-")
n = {"calls": 0}


def api(m, p, b):
    n["calls"] += 1
    return 200, {"Content-Type": "application/json"}, json.dumps({"shard": "python", "chunk": n["calls"]}).encode()


pol = FundingPolicy(min_capacity=20_000, min_expiry_blocks=1_008, max_expiry_blocks=8_640, close_margin=144)
prov = XbtChannelProvider(node, secret, net, f"{tmp}/ledger.sqlite", lambda m, p: 1000, api, close_margin=144, policy=pol,
                          settle_multiple=settle, height_ttl=0.5, **({"rollover_zero_conf_max": zc_max} if zc_max is not None else {}),
                          **({"route_wal": os.environ["XBT402_ROUTE_WAL"]} if os.environ.get("XBT402_ROUTE_WAL") else {}))
prov.offer_route("/v1/chunk", window=1.0, lock_wait=3.0, invoice_ttl=8.0, amsat_per_call=amsat)
prov.watch(interval=watch_s)
srv = prov.http_server(port)
print(f"py route provider {prov.pay_to} on {port} ready", file=sys.stderr, flush=True)
srv.serve_forever()
