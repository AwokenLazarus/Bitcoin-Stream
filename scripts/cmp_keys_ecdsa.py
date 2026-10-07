#!/usr/bin/env python3
"""ECDSA byte-identity with xbt-compute (AGP-035): xbt_primitives::ecdsa vs cmp's `cmp/keys.py`.

cmp signs with `OperatorKey(secret).sign(msg)` = b1 `ecc.sign(secret, sha256(msg))`: low-S,
strict DER, RFC 6979 (libsecp256k1 via coincurve). This signs the same (secret, message) pairs on
both sides and requires the same pub and the same DER bytes, then cross-verifies: cmp's `verify`
accepts every Rust signature, Rust's `ecdsa::verify` accepts every cmp signature, and both refuse
each signature over a changed message.

    scripts/cmp_keys_ecdsa.py [--cases N] [--seed S]     (N >= 1000; default 2000)

Run it with cmp's venv (coincurve, cryptography): XBT_CMP_PYTHON, default ~/xbt-rnd/cmp/.venv/bin/python
(the script re-executes itself under it). cmp's tree (XBT_CMP, default ~/xbt-rnd/cmp) is only
read: no bytecode is written there. The Rust side is target/release/xbt-ecdsa-cmp (built here).
"""
import argparse
import os
import random
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CMP = os.environ.get("XBT_CMP", os.path.expanduser("~/xbt-rnd/cmp"))
CMP_PY = os.environ.get("XBT_CMP_PYTHON", os.path.join(CMP, ".venv/bin/python"))
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

if not os.environ.get("XBT_CMP_REEXEC") and os.path.exists(CMP_PY):
    os.execve(CMP_PY, [CMP_PY, "-B", *sys.argv], {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "XBT_CMP_REEXEC": "1"})
sys.dont_write_bytecode = True
sys.path.insert(0, CMP)
from cmp import keys  # noqa: E402  (cmp/keys.py, read only)


def cases(n, seed):
    rng = random.Random(seed)
    edge_secrets = [1, 2, 3, N - 1, N - 2, 1 << 255, (1 << 128) + 1, N // 2]
    edge_msgs = [b"", b"\x00", b"a", b"\xff" * 32, bytes(range(256)) * 4,
                 b'{"amsatPerCall":813000000000123456789,"network":"bip122:x"}']
    out = [(s, m) for s in edge_secrets for m in edge_msgs]
    while len(out) < n:
        s = rng.randrange(1, N)
        m = rng.randbytes(rng.choice((0, 1, 31, 32, 33, 64, rng.randrange(0, 2048))))
        out.append((s, m))
    return out


def hx(b):
    return b.hex() or "-"                  # one field per value, the empty message included


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=35)
    a = ap.parse_args()
    assert a.cases >= 1000, "at least 1,000 cases"
    subprocess.run(["cargo", "build", "-q", "-j2", "--release", "-p", "xbt402-interop", "--bin", "xbt-ecdsa-cmp"],
                   cwd=ROOT, check=True)
    rust = os.path.join(ROOT, "target/release/xbt-ecdsa-cmp")
    cs = cases(a.cases, a.seed)
    py = []
    for s, m in cs:
        k = keys.OperatorKey(s)
        py.append((k.pub_hex, k.sign(m)))
    lines = [f"sign {s:064x} {hx(m)}" for s, m in cs]
    # every cmp signature under Rust verify, then each over a changed message (must fail)
    lines += [f"verify {p} {hx(m)} {sig}" for (s, m), (p, sig) in zip(cs, py)]
    lines += [f"verify {p} {hx(m + b'!')} {sig}" for (s, m), (p, sig) in zip(cs, py)]
    r = subprocess.run([rust], input="\n".join(lines) + "\n", capture_output=True, text=True, check=True).stdout.split("\n")
    n = len(cs)
    signed, ver, ver_bad = r[:n], r[n:2 * n], r[2 * n:3 * n]
    fails = []
    for i, ((s, m), (p, sig), got) in enumerate(zip(cs, py, signed)):
        rp, rsig = got.split()
        if (rp, rsig) != (p, sig):
            fails.append(f"case {i}: rust {rp} {rsig} != cmp {p} {sig}")
        if not keys.is_strict_der(bytes.fromhex(rsig)) or not keys.verify(p, m, rsig) or keys.verify(p, m + b"!", rsig):
            fails.append(f"case {i}: cmp keys.verify disagrees on the Rust signature")
        if ver[i] != "1" or ver_bad[i] != "0":
            fails.append(f"case {i}: Rust ecdsa::verify disagrees on the cmp signature")
    for f in fails[:20]:
        print("FAIL", f)
    if fails:
        print(f"cmp keys.py ECDSA: FAIL ({len(fails)} problems over {n} cases)")
        sys.exit(1)
    print(f"cmp keys.py ECDSA: OK: {n}/{n} (secret, message) pairs byte-identical (pub + strict-DER low-S sig), "
          f"{2 * n} cross-verifications ({CMP}/cmp/keys.py, seed {a.seed})")


if __name__ == "__main__":
    main()
