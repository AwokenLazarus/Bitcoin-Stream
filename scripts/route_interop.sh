#!/bin/bash
# Routed cross-implementation runs on regtest (AGP-026): the Rust xbt402 routing (xbt-rs) against the
# Python reference (B1 agp-029 22afed2 = agp-023 c9243ef + the AGP-029 close report) on a private Knots 29.4.2 node (B1's scripts/node.sh flags:
# RDTS on, #419 long coinbase maturity, BLAKE2b from block 101).
#   1. every client x hub x provider combination, Rust or Python (8 runs, scripts/interop/route_interop.py),
#      including Rust client -> Python hub -> Rust provider and Python client -> Rust hub -> Python provider;
#      exact amounts on chain for every ch1 and ch2 close;
#   1b. (AGP-034) the Rust payer with its keys in the Rust B2 signer (xbt-signer, RemoteSigner behind RoutePayer,
#      the signer's routing policy on every lock) -> Rust hub -> Rust providers, and -> Python hub -> Python providers;
#   1c. (AGP-044) the same payer on a route ledger, SIGKILLed mid-stream and restarted from it (RSSR), same checks;
#   2. the all-Rust AGP-021 demo (xbt402-route-demo): 4 providers (two provider processes under one payTo), rollover,
#      a provider that never reveals, a hub that withholds receipts then everything; cmp-lead's
#      constraints 1-7 and exact amounts on chain.
# Ports 33100-33299 (AGP-026/034/044): node 33101/33102, matrix 33110-33182, demo 33190-33194, signer runs
# 33200-33232 (RSS j = 0, 1; RSSR j = 2, 3; sequential, before signer_interop.sh's 33200-33299 in the verify). Starts NO
# miners (blocks come from generatetoaddress). The node and every process are stopped and wiped on
# exit. Soak rules: CPUQuota 200%, 4G, nice 19.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
B1=${XBT402_B1:-$HOME/xbt-rnd/b1}
PB=${XBT_RS_ROUTE_PORT_BASE:-33100}
# the RSS and RSSR runs sit at PB+RSS+10*j (j = 0..3); ROUTE_RSS_OFFSET=3 keeps every port below PB+100
RSS=${ROUTE_RSS_OFFSET:-100}
R=${XBT_RS_RUN:-$ROOT/run}/route-$$
export XBT402_B1=$B1
export XBT_BIN=${XBT_BIN:-$HOME/lazarus-regtest/b1-xbt402/knots-29.4.2}
export XBT402_DATADIR=$R/node
export XBT402_RPCPORT=$((PB + 1)) XBT402_P2PPORT=$((PB + 2))
export XBT402_MATURITY_PAD=6800
export PY=${XBT402_PYTHON:-$HOME/xbt-rnd/b1/.venv/bin/python}
[ -x "$PY" ] || PY=python3
export RS_BIN=${CARGO_TARGET_DIR:-$ROOT/target}/release ROUTE_PB=$PB ROUTE_RUN=$R ROUTE_RSS_OFFSET=$RSS
SOAK=(systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19)
mkdir -p "$R"
cleanup() {
  pkill -f -- "$R/" 2>/dev/null || true
  "$B1/scripts/node.sh" wipe >/dev/null 2>&1 || true
  mkdir -p "$ROOT/run"
  cp "$R"/route_interop_results.json "$R"/route_demo_report.json "$R"/route_interop.log "$ROOT/run/" 2>/dev/null || true
  rm -rf "$R"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

ports=$(seq $((PB + 1)) $((PB + 2)); seq $((PB + 10)) $((PB + 94)); for j in 0 1 2 3; do seq $((PB + RSS + 10 * j)) $((PB + RSS + 10 * j + 2)); done)
python3 "$HOME/xbt-rnd/xbt-063/tools/portcheck.py" wait $ports
"${SOAK[@]}" cargo build -q -j2 --release -p xbt402-interop --bins
"${SOAK[@]}" cargo build -q -j2 --release -p xbt402 --all-features --bin xbt402-hub
"${SOAK[@]}" cargo build -q -j2 --release -p xbt-signer --bin xbt-signer
"$B1/scripts/node.sh" wipe >/dev/null 2>&1 || true
"$B1/scripts/node.sh" up
FAIL=0
echo "== 1. client x hub x provider, Rust (RS), Python B1 (PY), Rust payer on the Rust signer (RSS); exact amounts on chain"
"$PY" scripts/interop/route_interop.py || FAIL=1
if [ -z "${ROUTE_SKIP_DEMO:-}" ]; then
  echo "== 2. the all-Rust AGP-021 demo scenarios"
  "${SOAK[@]}" "$RS_BIN/xbt402-route-demo" --rpc-port "$XBT402_RPCPORT" --cookie "$XBT402_DATADIR/regtest/.cookie" \
    --port-base $((PB + 90)) --report "$R/route_demo_report.json" || FAIL=1
fi
[ "$FAIL" = 0 ] && echo "route_interop: OK" || { echo "route_interop: FAIL (log: run/route_interop.log)"; exit 1; }
