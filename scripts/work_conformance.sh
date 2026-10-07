#!/bin/bash
# AGP-032: conformance of the Rust xbt-work crate with XBT-053 (pay-with-work, agp-011), both directions.
#   1. the pinned copy vectors/xbt_work_vectors.json is XBT-053's published vectors.json;
#   2. Rust -> reference: the Rust emitter rebuilds the whole file (byte-identical, cmp), and the Rust
#      checks run over the published file (16 sections recomputed byte for byte + 75 independent checks);
#   3. reference -> Rust: XBT-053's own check_work_vectors.py, unchanged, checks the Rust-emitted file
#      (its 124 checks: diff against receipts.py/nta.py, its independent checks, and the cross-checks
#      against xbt-070 coinbase_audit.py, the flagship's workrail.py, sov-014's NTA vectors, the Knots
#      test framework's BIP340 and the reference nta-signer).
# Env: XBT053 (default ~/xbt-rnd/XBT-053, branch agp-011). Soak rules for the build.
set -euo pipefail
cd "$(dirname "$0")/.."
X053=${XBT053:-$HOME/xbt-rnd/XBT-053}
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$HOME/xbt-rnd/xbt-rs-target}
SOAK=(systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19)
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
echo "== 1. pinned vectors are XBT-053's ($(git -C "$X053" rev-parse --abbrev-ref HEAD) $(git -C "$X053" rev-parse --short HEAD))"
if cmp -s "$X053/vectors.json" vectors/xbt_work_vectors.json; then echo "  same  vectors/xbt_work_vectors.json = $X053/vectors.json"; else echo "  DIFF" >&2; exit 1; fi
echo "== 2. Rust -> reference"
"${SOAK[@]}" cargo build -q -j2 --release -p xbt-work --features tools --bin xbt-work-vectors
"$CARGO_TARGET_DIR/release/xbt-work-vectors" "$OUT/rust_vectors.json"
if cmp -s "$OUT/rust_vectors.json" vectors/xbt_work_vectors.json; then echo "  same  Rust-emitted vectors.json = published (byte-identical)"; else echo "  DIFF Rust-emitted file" >&2; exit 1; fi
"$CARGO_TARGET_DIR/release/xbt-work-vectors" --check vectors/xbt_work_vectors.json
echo "== 3. reference -> Rust: XBT-053 check_work_vectors.py on the Rust-emitted file"
mkdir -p "$OUT/x053"
git -C "$X053" archive HEAD | tar -x -C "$OUT/x053"
cp "$OUT/rust_vectors.json" "$OUT/x053/vectors.json"
(cd "$OUT/x053" && python3 check_work_vectors.py)
echo "work conformance: OK"
