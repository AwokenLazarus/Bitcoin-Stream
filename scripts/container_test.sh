#!/bin/bash
# AGP-038: the container test. Builds the multi-arch images (scripts/oci_build.sh --load: all three platforms
# into dist/oci/*.tar, the amd64 ones loaded as <image>:agp038), checks the arm64 and arm/v7 images with
# scripts/oci_inspect.py, then runs scripts/container/container_test.py: signer + witness + MCP (+ hub)
# composed with a Knots 29.4.2 regtest node, configured only by env and a data dir; one xbt402 call paid
# through the MCP over HTTP; kill/restart persistence; /readyz gating. Ports 33700-33799 (published on
# 127.0.0.1 only: MCP 33710, hub 33720, provider 33730). Soak rules: cargo under CPUQuota 200%,
# MemoryMax 4G, nice 19, -j2. Evidence: run/container-test/<stamp>/.
#   scripts/container_test.sh [--skip-build]      CONTAINER_TEST_KEEP=1 keeps the volumes
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
STAMP=$(date +%Y%m%d-%H%M%S)
OUT=$ROOT/run/container-test/$STAMP
mkdir -p "$OUT"
busy=$(ss -ltnH | awk '{print $4}' | sed 's/.*://' | awk '$1>=33700 && $1<=33799' | sort -u | tr '\n' ' ')
[ -z "$busy" ] || { echo "container_test: ports busy in 33700-33799: $busy" >&2; exit 1; }
if [ "${1:-}" != "--skip-build" ]; then
  echo "== images (scripts/oci_build.sh --load)"
  ./scripts/oci_build.sh --load | tee "$OUT/oci_build.log"
fi
echo "== test provider binary (x86_64 musl)"
SOAK=(nice -n 19)
command -v systemd-run >/dev/null && SOAK=(systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19)
"${SOAK[@]}" cargo build -q -j2 --release --target x86_64-unknown-linux-musl -p xbt402-interop --bin xbt402-rust-provider
echo "== inspect: every image, every platform (arm64 and arm/v7 included)"
set +e
python3 scripts/oci_inspect.py dist/oci xbt-signer xbt-anchor-witness xbt-wallet-mcp xbt402-hub >"$OUT/oci_inspect.json"
irc=$?
set -e
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print('   inspect ok:', d['ok'], d['problems'] or '')" "$OUT/oci_inspect.json"
set +e
python3 scripts/container/container_test.py "$OUT"
rc=$?
set -e
ln -sfn "$STAMP" "$ROOT/run/container-test/latest"
echo "evidence: $OUT"
[ $rc -eq 0 ] && [ $irc -eq 0 ] && echo "container_test: PASS" || { echo "container_test: FAIL"; exit 1; }
