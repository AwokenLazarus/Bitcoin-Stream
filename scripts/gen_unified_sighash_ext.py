#!/usr/bin/env python3
"""UnifiedSighash vectors with an annex and a codeseparator position (AGP-069 S1).

The messages come from Knots' own independent Python implementation
(test/functional/test_framework/script.py `UnifiedSignatureHash`), so they are not ours checking
ours. Taproot key path and tapscript only: those are the script types whose message commits to the
annex, and tapscript the only one that commits to a codeseparator position.

  python3 scripts/gen_unified_sighash_ext.py [KNOTS_DIR] > vectors/unified_sighash_ext.json

KNOTS_DIR defaults to ~/xbt-rnd/a1/knots. Deterministic: the same Knots gives the same bytes.
"""
import json
import os
import random
import sys

KNOTS = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/xbt-rnd/a1/knots")
sys.path.insert(0, os.path.join(KNOTS, "test", "functional"))

from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut  # noqa: E402
from test_framework.script import (LEAF_VERSION_TAPSCRIPT, TaggedHash, UnifiedSignatureHash,  # noqa: E402
                                   ser_string)

TAPROOT, TAPSCRIPT = 2, 3
HASH_TYPES = [0x21, 0x22, 0x23, 0xA1, 0xA2, 0xA3]
ANNEX_TAG = 0x50


def rand_tx(r, n_in, n_out):
    tx = CTransaction()
    tx.version = r.choice([1, 2, 3])
    tx.nLockTime = r.choice([0, r.randrange(1, 1 << 32)])
    for _ in range(n_in):
        tx.vin.append(CTxIn(COutPoint(r.getrandbits(256), r.randrange(0, 8)), b"", r.choice([0xFFFFFFFF, 0xFFFFFFFD, r.getrandbits(32)])))
    for _ in range(n_out):
        tx.vout.append(CTxOut(r.randrange(0, 21 * 10**14), bytes([0x51, 0x20]) + r.randbytes(32)))
    return tx


def main():
    r = random.Random(69)
    rows = [["rawTx", "inIdx", "hashType", "scriptType", "spentOutputs", "leafHash", "annex", "codesepPos", "sighash"]]
    annexes = [None, bytes([ANNEX_TAG]), bytes([ANNEX_TAG]) + r.randbytes(31), bytes([ANNEX_TAG]) + r.randbytes(252),
               bytes([ANNEX_TAG]) + r.randbytes(300)]
    for case in range(60):
        n_in, n_out = r.randrange(1, 4), r.randrange(1, 4)
        tx = rand_tx(r, n_in, n_out)
        spent = [CTxOut(r.randrange(1, 21 * 10**14), bytes([0x51, 0x20]) + r.randbytes(32)) for _ in range(n_in)]
        idx = r.randrange(0, n_in)
        ht = HASH_TYPES[case % len(HASH_TYPES)]
        if ht & 0x1F == 3 and idx >= n_out:
            idx = r.randrange(0, min(n_in, n_out))
        st = TAPSCRIPT if case % 2 else TAPROOT
        annex = annexes[(case // 2) % len(annexes)]
        leaf_script, leaf_hash, pos = None, None, -1
        if st == TAPSCRIPT:
            leaf_script = r.randbytes(r.randrange(1, 40))
            leaf_hash = TaggedHash("TapLeaf", bytes([LEAF_VERSION_TAPSCRIPT]) + ser_string(leaf_script))
            pos = [-1, 0, 7, r.getrandbits(31)][(case // 2) % 4]
        h = UnifiedSignatureHash(b"", tx, idx, ht, spent, True, script_type=st, annex=annex,
                                 leaf_script=leaf_script, codeseparator_pos=pos)
        assert h is not None, case
        rows.append([tx.serialize().hex(), idx, ht, st, [[o.nValue, o.scriptPubKey.hex()] for o in spent],
                     leaf_hash.hex() if leaf_hash else None, annex.hex() if annex is not None else None,
                     pos & 0xFFFFFFFF, h.hex()])
    json.dump(rows, sys.stdout, indent=None, separators=(",", ":"))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
