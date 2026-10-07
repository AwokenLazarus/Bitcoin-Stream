#!/usr/bin/env python3
"""One line per electrum interop result (xbt-electrum-interop's JSON on stdin)."""
import json, sys
d = json.loads(sys.stdin.read() or "{}")
c = d.get("checks", {})
print(f"{d.get('scenario')} -> {d.get('url')} feePayer={d.get('closeFeePayer', 'payer')} finalCum={d.get('finalCum', '-')} "
      f"payee={d.get('payeeOut', '-')} payer={d.get('payerOut', '-')} refund={d.get('refundSats', '-')} "
      f"checks={sum(v is True for v in c.values())}/{len(c)} node-compared={d.get('comparisons')} "
      f"mismatches={len(d.get('mismatches', []))} flags={len(d.get('flags', []))} sync={d.get('headerSyncMs', '-')}ms "
      f"{d.get('error', '')}".rstrip())
