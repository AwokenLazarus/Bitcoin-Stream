#!/usr/bin/env python3
"""Record B2's mainnet retarget rule (agentwallet/headers.py ChainRules.next_bits) on random
parents, for the Rust test crates/xbt-primitives/tests/retarget.rs (recorded outputs: the Python
is the reference). Writes vectors/retarget_main_cases.json.  B2 = $XBT402_B2 (~/xbt-rnd/b2)."""
import json, os, random, sys
B2 = os.environ.get("XBT402_B2", os.path.expanduser("~/xbt-rnd/b2"))
sys.path.insert(0, B2)
if not os.environ.get("B1_ROOT", "").strip():
    xbt_b1 = os.environ.get("XBT402_B1", "").strip()
    if xbt_b1:
        os.environ["B1_ROOT"] = xbt_b1
from agentwallet.headers import RULES, Header, bits_to_target, target_to_bits  # noqa: E402

rules = RULES["main"]
rnd = random.Random(25)
cases = []
for i in range(400):
    exp = rnd.choice([0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d])
    bits = exp << 24 | rnd.randrange(0x008000, 0x7fffff)
    if bits_to_target(bits) > rules.pow_limit:
        bits = target_to_bits(rules.pow_limit)
    boundary = rnd.random() < 0.7
    height = rnd.randrange(1, 400) * 2016 - 1 if boundary else rnd.randrange(961_640, 1_200_000)
    t = rnd.randrange(1_700_000_000, 1_900_000_000)
    first = None if rnd.random() < 0.3 else t - rnd.choice([1, 100_000, 302_400, 600_000, 1_209_600, 2_000_000, 4_838_400, 9_000_000, 1_000_000_000])
    parent = Header(raw=b"", hash="", prev="", merkle_root=b"", time=t, bits=bits, height=height, txcount=1)
    got = rules.next_bits(parent, first)
    out = {"exact": sorted(got)} if isinstance(got, set) else {"range": ["%064x" % got[0], "%064x" % got[1]]}
    cases.append({"height": height, "time": t, "bits": bits, "firstTime": first, **out})
for n, (bits, target) in enumerate([(0x1d00ffff, None), (0x207fffff, None), (0x03123456, None), (0x04123456, None), (0x01003456, None), (0x1b04864c, None)]):
    cases.append({"compact": bits, "target": "%064x" % bits_to_target(bits), "roundTrip": target_to_bits(bits_to_target(bits))})
json.dump({"source": "B2 agentwallet/headers.py (agp-next2) ChainRules('main').next_bits, bits_to_target, target_to_bits",
           "cases": cases}, open(os.path.join(os.path.dirname(__file__), "..", "vectors", "retarget_main_cases.json"), "w"), indent=0)
print(len(cases), "cases")
