#!/usr/bin/env python3
"""The reverse conformance check: the Python reference checks values the Rust crates produced.

    python3 scripts/py_check_rust_vectors.py RUST_VECTORS.json

RUST_VECTORS.json is the Rust emitter's output (`xbt402-vectors`): the whole xbt402 vector file
rebuilt by xbt-primitives/xbt402, the Rust provider serving every round trip. This imports B1's
`docs/x402/check_vectors.py` (B1 = $XBT402_B1, default ~/xbt-rnd/b1-agp-050) and runs, unchanged:
  * diff(python_generate(), rust): what the Python library computes vs what Rust emitted;
  * independent_checks(rust): the checks that do not trust any generator (tweak preimage layout,
    p*G = P, each signature under the key the spec names, receipts under P, the refusals with their
    codes, the conditional and v1.2 payee-pays formulas), run by the Python library over Rust output.
Exits 0 when both find nothing.
"""
import json
import os
import sys

B1 = os.environ.get("XBT402_B1", os.path.expanduser("~/xbt-rnd/b1-agp-050"))
sys.path.insert(0, B1)
sys.path.insert(0, os.path.join(B1, "docs", "x402"))
import check_vectors as cv  # noqa: E402

rust = json.load(open(sys.argv[1]))
py = cv.generate()
errs = [f"diff {e}" for e in cv.diff(py, rust)] + [f"independent {e}" for e in cv.independent_checks(rust)]
n = (len(rust["derivation"]) + len(rust["auth"]["cases"]) + len(rust["state"]["states"]) + len(rust["state"]["invalid"]) + 2
     + len(rust["roundtrip"]["steps"]) + 1 + len(rust["conditional"]["steps"]) + len(rust["payeePays"]["states"])
     + len(rust["payeePays"]["invalid"]) + 6 + ("close" in rust["payeePays"]))
for e in errs:
    print("MISMATCH", e)
print(f"{'FAIL' if errs else 'OK'}: Python check_vectors.py (B1 {B1}, backend {cv.ecc.BACKEND}) on the Rust-emitted file: "
      f"{n} vectors, {len(errs)} mismatches")
sys.exit(1 if errs else 0)
