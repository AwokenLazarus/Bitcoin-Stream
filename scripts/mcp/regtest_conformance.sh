#!/bin/bash
# AGP-030: MCP conformance on regtest, B2's Python MCP vs the Rust xbt-wallet-mcp, on BOTH signers.
#
# For each signer (B2's Python signer, the Rust xbt-signer), xbt-063's flagship (master) runs
# twice with the scripted agent in conformance mode (MCP_CONFORMANCE=1): once driven through B2's MCP,
# once through the Rust MCP. In each run every read, and every call the signer never sees, also goes
# to the other server at the same wallet state and must be equal; then regtest_diff.py compares the two
# runs step by step after normalizing txids, keys, addresses and times. The flagship's own checks
# (settlement, custody, restart) run too and their verdict is reported.
#
# Ports 33500-33599 (FLAGSHIP_PORT_BASE=33500, sequential runs). Soak rules: CPUQuota 200%,
# MemoryMax 4G, nice 19, cargo -j2. PYTHONHASHSEED=0 keeps the demo provider's tie order fixed, so
# two runs sell the same bytes. Evidence: run/mcp-regtest/<stamp>/ (a JSON table per signer).
#   scripts/mcp/regtest_conformance.sh [py|rust ...]   (default: py rust)
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$PWD
XBT063=${XBT063:-$HOME/xbt-rnd/xbt-063}
STAMP=$(date +%Y%m%d-%H%M%S)
OUT=$ROOT/run/mcp-regtest/$STAMP
mkdir -p "$OUT"
echo "== build (release, -j2)"
nice -n 19 cargo build -q -j2 --release -p xbt-wallet-mcp -p xbt-signer --bins
export XBT_WALLET_MCP=$ROOT/target/release/xbt-wallet-mcp XBT_SIGNER=$ROOT/target/release/xbt-signer

flagship() {   # $1 label, rest: env
  local label=$1; shift
  echo "== flagship $label ($*)"
  set +e
  (cd "$XBT063" && env FLAGSHIP_PORT_BASE=33500 FLAGSHIP_AGENT=script MCP_CONFORMANCE=1 PYTHONHASHSEED=0 "$@" \
      systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19 ./flagship.sh) >"$OUT/$label.log" 2>&1
  local rc=$?
  set -e
  local ev
  ev=$(awk '/^evidence:/{print $2}' "$OUT/$label.log" | tail -1)
  echo "   flagship rc=$rc $(tail -1 "$OUT/$label.log")  evidence $ev"
  echo "$ev" >"$OUT/$label.evidence"
  echo "$rc" >"$OUT/$label.rc"
}

rc=0
for signer in "${@:-py rust}"; do
  for s in $signer; do
    sig=$([ "$s" = rust ] && echo rust || echo b2)
    flagship "b2mcp-${s}signer" MCP_IMPL=b2 SIGNER_IMPL=$sig
    flagship "rustmcp-${s}signer" MCP_IMPL=rust SIGNER_IMPL=$sig
    echo "== diff on the $s signer"
    python3 "$ROOT/scripts/mcp/regtest_diff.py" "$(cat "$OUT/b2mcp-${s}signer.evidence")/mcp_conformance.jsonl" \
      "$(cat "$OUT/rustmcp-${s}signer.evidence")/mcp_conformance.jsonl" --out "$OUT/diff-${s}signer.json" || rc=1
  done
done
ln -sfn "$STAMP" "$ROOT/run/mcp-regtest/latest"
echo "evidence: $OUT"
[ $rc -eq 0 ] && echo "regtest_conformance: PASS" || { echo "regtest_conformance: FAIL"; exit 1; }
