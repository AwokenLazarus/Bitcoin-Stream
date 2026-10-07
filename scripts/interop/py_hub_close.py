#!/usr/bin/env python3
"""Operator tool for a stopped Python B1 hub (the counterpart of `xbt402-hub --close-all`): load the
RouteHub on its datadir, ask every provider with an open ch2 to close it, print JSON.
    py_hub_close.py CONFIG.json
Env: XBT402_B1."""
import json, os, sys
sys.path.insert(0, os.environ.get("XBT402_B1", os.path.expanduser("~/xbt-rnd/b1-agp-023")))
from xbt402.hub import HubConfig, RouteHub  # noqa: E402
from xbt402.rpc import RPC  # noqa: E402

conf = json.load(open(sys.argv[1]))
rpc = RPC(int(conf["node"]["rpcport"]), os.path.expanduser(conf["node"]["cookie"]))
secret = int(open(conf["pay_to_key_file"]).read().strip(), 16)
hub = RouteHub(rpc, secret, conf["network"], conf["datadir"], lambda a, s: (_ for _ in ()).throw(RuntimeError("no funding")),
               HubConfig.from_dict(conf.get("hub") or {}))
closes = []
for origin, oc in list(hub.out.chans.items()):
    if oc.state != "open":
        continue
    rec = {"origin": origin, "chan": oc.p().channel_id, "routed": oc.routed, "signed": oc.signed, "params": oc.params}
    try:
        closes.append({"close": hub.close_ch2(oc), "ch2": rec})
    except Exception as e:  # noqa: BLE001
        closes.append({"error": str(e), "ch2": rec})
print(json.dumps({"closes": closes, "events": hub.events}))
