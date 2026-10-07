#!/bin/bash
# AGP-045 on regtest: a hub ch2 funding whose wallet call failed after it broadcast is reconciled against
# the wallet (listtransactions/gettransaction), the mempool (gettxout incl. the mempool, getmempoolentry)
# and the UTXO set, not scantxoutset alone. A private Knots 29.4.2 node (B1's scripts/node.sh flags), a
# Rust provider (xbt402-refund-bump --provider-only), then:
#   1. the Rust hub (xbt402-funding-reconcile): run A (slow: in the mempool past funding_timeout_blocks ->
#      recovered, opened once confirmed) and run B (conflicted: dropped but watched, then failed and final);
#   2. the Python hub (B1 agp-045, scripts/interop/py_funding_reconcile.py): the same runs, the same checks.
# Ports 34540-34549 (AGP-045 has 34500-34599). Starts NO miners. Node and processes wiped on exit.
# Soak rules: CPUQuota 200%, 4G, nice 19.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
B1=${XBT402_B1:-$HOME/xbt-rnd/b1-agp-045}
PB=${XBT_RS_FUNDREC_PORT_BASE:-34540}
R=${XBT_RS_RUN:-$ROOT/run}/fundrec-$$
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
  cp "$R"/funding_reconcile_*.json "$ROOT/run/" 2>/dev/null || true
  rm -rf "$R"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

python3 "$HOME/xbt-rnd/xbt-063/tools/portcheck.py" wait $((PB + 1)) $((PB + 2)) $((PB + 3))
"${SOAK[@]}" cargo build -q -j2 --release -p xbt402-interop --bin xbt402-refund-bump --bin xbt402-funding-reconcile
"$B1/scripts/node.sh" wipe >/dev/null 2>&1 || true
"$B1/scripts/node.sh" up
COOKIE=$XBT402_DATADIR/regtest/.cookie
"${SOAK[@]}" "$BIN/xbt402-refund-bump" --rpc-port "$XBT402_RPCPORT" --cookie "$COOKIE" --port $((PB + 3)) --provider-only \
  >"$R/provider.log" 2>&1 & PROV=$!
for _ in $(seq 100); do curl -s -o /dev/null "http://127.0.0.1:$((PB + 3))/x402/supported" && break; sleep 0.1; done
FAIL=0
echo "== 1. Rust hub"
"${SOAK[@]}" "$BIN/xbt402-funding-reconcile" --rpc-port "$XBT402_RPCPORT" --cookie "$COOKIE" --provider "http://127.0.0.1:$((PB + 3))" \
  --report "$R/funding_reconcile_rust.json" || FAIL=1
echo "== 2. Python hub (B1)"
(cd "$B1" && "${SOAK[@]}" "$PY" "$ROOT/scripts/interop/py_funding_reconcile.py" "http://127.0.0.1:$((PB + 3))" "$R/funding_reconcile_python.json") || FAIL=1
[ "$FAIL" = 0 ] && echo "funding_reconcile_regtest: OK" || { echo "funding_reconcile_regtest: FAIL"; exit 1; }
