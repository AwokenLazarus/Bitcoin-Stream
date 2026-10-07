#!/bin/bash
# AGP-053 on regtest: a ch2 rollover while a client streams >= 10 locks/s to that provider, repeated,
# with make-before-break (the next ch2 taken unconfirmed, bounded) in both hubs and both providers
# (Rust xbt-rs, Python B1 agp-053): ZERO refused locks. Also the pre-AGP-053 baseline (provider
# --zero-conf-max 0), a rollover kept out of blocks (the fallback: the provider's cap, then the hub
# holds), and a reorg across the switch (cap/close-margin route_blocked only in the reorg window,
# reported as refusedDuringReorg; plain runs stay zero refusals). scripts/interop/rollover_load.py
# has the runs and checks. AGP-056 adds a high price (every lock above the provider's settle threshold):
# with the settle floor a rollover per >= 4 locks and zero refusals, and the floor-off baseline (a
# rollover and a refusal per lock).
# A private Knots 29.4.2 node (B1's scripts/node.sh flags); blocks from the driver's miner only.
# AGP-057 adds cmp's prices (16,515-sat locks on a 1M ch2: the zero-conf cap of a rollover child, with the
# refusals classified) and exhaustion under load (the ch2 line runs out several times: make-before-break
# refill, zero refusals; and the refill-after-close baseline).
# Ports 34900-34999 (AGP-053). Node and processes wiped on exit. Soak rules: CPUQuota 200%, 4G, nice 19.
# Env: XBT402_B1, LOAD_ONLY, LOAD_SECONDS, LOAD_RATE, LOAD_BLOCK_S, LOAD_STUCK_S, LOAD_REORG_S, LOAD_REPORT.
# XBT_RS_LOAD_PORT_BASE / XBT_RS_LOAD_PORT_SPAN (default 100): with a span under 100 the selected runs
# (LOAD_ONLY) are packed two ports each from base + 4 (a worker's 20-port grant holds 8 runs).
set -euo pipefail
lazvault hold check --project xbt-agentpay || exit 75   # IMP-030: heavy entry point, refuses during a host hold
cd "$(dirname "$0")/.."
ROOT=$PWD
B1=${XBT402_B1:-$HOME/xbt-rnd/b1-agp-057}
PB=${XBT_RS_LOAD_PORT_BASE:-34900}
SPAN=${XBT_RS_LOAD_PORT_SPAN:-100}
R=${XBT_RS_RUN:-$ROOT/run}/load-$$
export XBT402_B1=$B1
export XBT_BIN=${XBT_BIN:-$HOME/lazarus-regtest/b1-xbt402/knots-29.4.2}
export XBT402_DATADIR=$R/node
export XBT402_RPCPORT=$((PB + 1)) XBT402_P2PPORT=$((PB + 2))
export XBT402_MATURITY_PAD=6800
export PY=${XBT402_PYTHON:-$HOME/xbt-rnd/b1/.venv/bin/python}
[ -x "$PY" ] || PY=python3
export RS_BIN=${CARGO_TARGET_DIR:-$ROOT/target}/release LOAD_PB=$PB LOAD_SPAN=$SPAN LOAD_RUN=$R
SOAK=(systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19)
mkdir -p "$R"
cleanup() {
  pkill -f -- "$R/" 2>/dev/null || true
  "$B1/scripts/node.sh" wipe >/dev/null 2>&1 || true
  mkdir -p "$ROOT/run"
  cp "$R"/rollover_load.json "$R"/rollover_load.log "$ROOT/run/" 2>/dev/null || true
  rm -rf "$R"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

python3 "$HOME/xbt-rnd/xbt-063/tools/portcheck.py" wait $(seq $((PB + 1)) $((PB + 2))) $(seq $((PB + (SPAN < 100 ? 4 : 10))) $((PB + SPAN - 1)))
"${SOAK[@]}" cargo build -q -j2 --release -p xbt402-interop --bins
"${SOAK[@]}" cargo build -q -j2 --release -p xbt402 --all-features --bin xbt402-hub
"$B1/scripts/node.sh" wipe >/dev/null 2>&1 || true
"$B1/scripts/node.sh" up
echo "== rollover under load (hub-provider[-kind]); rate ${LOAD_RATE:-15}/s, a block every ${LOAD_BLOCK_S:-3} s"
if "$PY" scripts/interop/rollover_load.py; then echo "rollover_load_regtest: OK"; else echo "rollover_load_regtest: FAIL (run/rollover_load.log)"; exit 1; fi
