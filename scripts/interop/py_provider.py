#!/usr/bin/env python3
"""The Python B1 provider (reference, b1 agp-023) on the interop node, over http.server.
    py_provider.py PORT [payer|payee] [CONDITIONAL_PATH:PRICE:PLAINTEXT]
Env: XBT402_B1, XBT402_DATADIR, XBT402_RPCPORT (B1's RPC.from_env)."""
import json, os, secrets, sys, tempfile
sys.path.insert(0, os.environ.get("XBT402_B1", os.path.expanduser("~/xbt-rnd/b1-agp-050")))
from xbt402.rpc import RPC  # noqa: E402
from xbt402.x402_channel import XbtChannelProvider, network_id  # noqa: E402

port = int(sys.argv[1])
fee_payer = sys.argv[2] if len(sys.argv) > 2 else "payer"
node = RPC.from_env()
net = network_id(node.getblockhash(101))
tmp = tempfile.mkdtemp(prefix="xbt-rs-interop-py-")
api = lambda m, p, b: (200, {"Content-Type": "application/json"}, json.dumps({"answer": p, "server": "python"}).encode())  # noqa: E731
prov = XbtChannelProvider(node, secrets.randbelow(2**255) + 1, net, f"{tmp}/ledger.sqlite", lambda m, p: 150, api,
                          billing="postpay", close_fee=600, close_fee_payer=fee_payer)
if len(sys.argv) > 3:
    path, price, plain = sys.argv[3].split(":", 2)
    prov.offer_conditional(path, int(price), plain.encode())
prov.watch(interval=2.0)
srv = prov.http_server(port)
print(f"py-provider ready on 127.0.0.1:{port} network {net} payTo {prov.pay_to} closeFeePayer {fee_payer}", flush=True)
srv.serve_forever()
