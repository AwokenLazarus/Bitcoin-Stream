#!/usr/bin/env python3
"""One line per interop result (a payer's JSON on stdin)."""
import json, sys
d = json.loads(sys.stdin.read() or "{}")
c = d.get("checks", {})
print(f"{d.get('impl', '?')} -> {d.get('url', '?')} closeFeePayer={d.get('closeFeePayer')} calls={d.get('calls')} "
      f"spent={d.get('spentSat')} finalCum={d.get('finalCum')} payee={d.get('payeeOut')} payer={d.get('payerOut')} "
      f"fee={d.get('closeFee')} cond={(d.get('conditional') or {}).get('plaintext')} "
      f"rollover={'ok' if (d.get('rollover') or {}).get('ok') else '-'} "
      f"report(cum/unpaidMsat)={d.get('reportedCum')}/{d.get('reportedUnpaidMsat')} checks={sum(map(bool, c.values()))}/{len(c)} "
      f"{d.get('error', '')}".rstrip())
