#!/bin/bash
# AGP-067 (review C1) on regtest: a fee spike through the close margin. A private Knots 29.4.2 node
# (B1's scripts/node.sh flags, maxmempool=5 in its bitcoin.conf), then xbt402-close-bump: a direct
# channel and a hub ch2, each with the provider's close bump on and off. Before the close margin the
# mempool is filled until its floor is about 10 sat/vB, and blocks take only packages paying 10
# sat/vB or more. With the bump the provider's close (with a CPFP child) confirms right after the
# margin; without it the close is refused to expiry and the payer's refund takes the channel back.
# Ports 24860-24869 (below the ephemeral range). Starts NO miners. Node and processes wiped on exit.
# Soak rules: CPUQuota 200%, 4G, nice 19.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
B1=${XBT402_B1:-$HOME/xbt-rnd/b1-agp-067}
PB=${XBT_RS_CLOSE_BUMP_PORT_BASE:-24860}
R=${XBT_RS_RUN:-$ROOT/run}/close-bump-$$
BIN=${CARGO_TARGET_DIR:-$ROOT/target}/release
export XBT402_B1=$B1
export XBT_BIN=${XBT_BIN:-$HOME/lazarus-regtest/b1-xbt402/knots-29.4.2}
export XBT402_DATADIR=$R/node
export XBT402_RPCPORT=$((PB + 8)) XBT402_P2PPORT=$((PB + 9))
export XBT402_MATURITY_PAD=6800
SOAK=(systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19)
mkdir -p "$R"
cleanup() {
  "$B1/scripts/node.sh" wipe >/dev/null 2>&1 || true
  mkdir -p "$ROOT/run"
  cp "$R"/close_bump*.json "$ROOT/run/" 2>/dev/null || true
  rm -rf "$R"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

python3 "$HOME/xbt-rnd/xbt-063/tools/portcheck.py" wait $(seq "$PB" $((PB + 9)))
"${SOAK[@]}" cargo build -q -j2 --release -p xbt402-interop --bin xbt402-close-bump
"$B1/scripts/node.sh" wipe >/dev/null 2>&1 || true
mkdir -p "$XBT402_DATADIR"
echo "maxmempool=5" > "$XBT402_DATADIR/bitcoin.conf"
"$B1/scripts/node.sh" up
"${SOAK[@]}" "$BIN/xbt402-close-bump" --rpc-port "$XBT402_RPCPORT" --cookie "$XBT402_DATADIR/regtest/.cookie" --port-base "$PB" \
  --report "$R/close_bump.json" && OK=1 || OK=0
[ "$OK" = 1 ] && echo "close_bump_regtest: OK" || { echo "close_bump_regtest: FAIL"; exit 1; }
