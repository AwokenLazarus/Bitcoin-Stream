#!/bin/bash
# AGP-044 on regtest: a stuck hub ch2 refund is re-signed at a higher fee and replaces itself (RBF),
# within refund_max_fee_sat. A private Knots 29.4.2 node (B1's scripts/node.sh flags), then:
#   1. the Rust hub (xbt402-refund-bump): bumped once and confirmed; capped at refund_max_fee_sat;
#   2. the Python hub (B1 agp-044, scripts/interop/py_refund_bump.py) against the same Rust provider:
#      the same two runs, the same checks.
# A refund is kept out of blocks with `generateblock ADDR []` (blocks that leave it out, as a fee market does).
# Ports 34440-34449 (AGP-044 has 34400-34499). Starts NO miners. Node and processes wiped on exit.
# Soak rules: CPUQuota 200%, 4G, nice 19.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
B1=${XBT402_B1:-$HOME/xbt-rnd/b1-agp-044}
PB=${XBT_RS_BUMP_PORT_BASE:-34440}
R=${XBT_RS_RUN:-$ROOT/run}/bump-$$
BIN=${CARGO_TARGET_DIR:-$ROOT/target}/release
export XBT402_B1=$B1
export XBT_BIN=${XBT_BIN:-$HOME/lazarus-regtest/b1-xbt402/knots-29.4.2}
export XBT402_DATADIR=$R/node
export XBT402_RPCPORT=$((PB + 1)) XBT402_P2PPORT=$((PB + 2))
export XBT402_MATURITY_PAD=6800
PY=${XBT402_PYTHON:-$HOME/xbt-rnd/b1/.venv/bin/python}
[ -x "$PY" ] || PY=python3
SOAK=(systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19)
mkdir -p "$R"
PROV=""
cleanup() {
  [ -n "$PROV" ] && kill "$PROV" 2>/dev/null || true
  wait 2>/dev/null || true
  "$B1/scripts/node.sh" wipe >/dev/null 2>&1 || true
  mkdir -p "$ROOT/run"
  cp "$R"/refund_bump_*.json "$ROOT/run/" 2>/dev/null || true
  rm -rf "$R"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

python3 "$HOME/xbt-rnd/xbt-063/tools/portcheck.py" wait $((PB + 1)) $((PB + 2)) $((PB + 3)) $((PB + 4))
"${SOAK[@]}" cargo build -q -j2 --release -p xbt402-interop --bin xbt402-refund-bump
"$B1/scripts/node.sh" wipe >/dev/null 2>&1 || true
"$B1/scripts/node.sh" up
COOKIE=$XBT402_DATADIR/regtest/.cookie
FAIL=0
echo "== 1. Rust hub"
"${SOAK[@]}" "$BIN/xbt402-refund-bump" --rpc-port "$XBT402_RPCPORT" --cookie "$COOKIE" --port $((PB + 3)) \
  --report "$R/refund_bump_rust.json" || FAIL=1
echo "== 2. Python hub (B1) against a Rust provider"
"${SOAK[@]}" "$BIN/xbt402-refund-bump" --rpc-port "$XBT402_RPCPORT" --cookie "$COOKIE" --port $((PB + 4)) --provider-only \
  >"$R/provider.log" 2>&1 & PROV=$!
for _ in $(seq 100); do curl -s -o /dev/null "http://127.0.0.1:$((PB + 4))/x402/supported" && break; sleep 0.1; done
(cd "$B1" && "${SOAK[@]}" "$PY" "$ROOT/scripts/interop/py_refund_bump.py" "http://127.0.0.1:$((PB + 4))" "$R/refund_bump_python.json") || FAIL=1
[ "$FAIL" = 0 ] && echo "refund_bump_regtest: OK" || { echo "refund_bump_regtest: FAIL"; exit 1; }
