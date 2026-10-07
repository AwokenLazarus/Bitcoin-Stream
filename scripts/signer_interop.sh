#!/bin/bash
# AGP-027: the Rust B2 signer (xbt-signer) on regtest, against the Python references.
#   1. the AGP-017 runbook rehearsal (xbt-063 rehearsal/runbook.py: G1-G7, rollback A = the kill after the
#      funding and the refund at expiry, rollback B = the provider's own close found on a pruned node) with
#      the Rust signer behind the Python B2 MCP session, B2's anchor witness and approve CLI, and B1's
#      mainnet_provider.py (Python) as the provider;
#   2. a Rust payer (xbt402 Client + RemoteSigner) on the Rust signer against the same Python provider;
#   3. B2's Python classes open the Rust signer's sealed files; B2's anchor CLI checks its log.
# Exact amounts on chain. One pruned Knots 29.4.2 regtest node without txindex, loopback only, no miner
# processes (blocks from generatetodescriptor). Ports 33200-33299 (AGP-027): node RPC 33201, provider 33210.
# B1/B2 are git-archived at xbt-063's rehearsal/PINS (b1 c9243ef, b2 b4f2fe5) so later edits cannot change
# a run. Soak rules: CPUQuota 200%, MemoryMax 4G, nice 19, cargo -j2. Evidence: run/signer-interop-results/.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -z "${SIGNER_INTEROP_SCOPED:-}" ] && command -v systemd-run >/dev/null; then
  export SIGNER_INTEROP_SCOPED=1
  exec systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19 "$0" "$@"
fi
ROOT=$PWD
XBT063=${XBT063:-$HOME/xbt-rnd/xbt-063}
export XBT063
export REHEARSAL_PORT_BASE=${SIGNER_INTEROP_PORT_BASE:-33200}
export REHEARSAL_RUN=${REHEARSAL_RUN:-$ROOT/run/signer-interop}
export XBT_BIN=${XBT_BIN:-$HOME/lazarus-regtest/b1-xbt402/knots-29.4.2}
PY=${SIGNER_INTEROP_PYTHON:-$XBT063/.venv/bin/python}
RUN=$REHEARSAL_RUN
STAMP=$(date +%Y%m%d-%H%M%S)
OUT=$ROOT/run/signer-interop-results/$STAMP

cleanup() {
  if [ -f "$RUN/pids" ]; then
    while read -r p; do kill -TERM -- "-$p" 2>/dev/null || kill -TERM "$p" 2>/dev/null || true; done <"$RUN/pids"
  fi
  "$XBT_BIN/bitcoin-cli" -regtest -datadir="$RUN/knots" -rpcport=$((REHEARSAL_PORT_BASE + 1)) stop >/dev/null 2>&1 || true
  for _ in $(seq 120); do [ -e "$RUN/knots/regtest/bitcoind.pid" ] || break; sleep 0.25; done
  [ -n "${SIGNER_INTEROP_KEEP:-}" ] || rm -rf "$RUN/knots" "$RUN/src"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

[ -x "$PY" ] || { echo "signer_interop: $PY missing (xbt-063's venv: run its ./flagship.sh once)" >&2; exit 1; }
echo "== build (release, -j2)"
cargo build -q -j2 --release -p xbt-signer --bins
export XBT_SIGNER_BIN=$ROOT/target/release/xbt-signer XBT_SIGNER_PAYER_BIN=$ROOT/target/release/xbt-signer-payer
cleanup
python3 "$XBT063/tools/portcheck.py" wait --timeout 75 $((REHEARSAL_PORT_BASE + 1)) $((REHEARSAL_PORT_BASE + 10)) \
  || { echo "signer_interop: ports busy" >&2; exit 1; }
rm -rf "${RUN:?}"
mkdir -p "$RUN/src/b1" "$RUN/src/b2" "$OUT"
# AGP-055: SIGNER_INTEROP_B2_PIN overrides the B2 pin. Part 3 needs a B2 that reads the append-only
# payments log (agp-055 or later): the xbt-063 pin b4f2fe5 reads payments from ledger.json, where they no longer are.
export REHEARSAL_B1_PIN=$(awk '$1=="b1"{print $2}' "$XBT063/rehearsal/PINS")
export REHEARSAL_B2_PIN=${SIGNER_INTEROP_B2_PIN:-$(awk '$1=="b2"{print $2}' "$XBT063/rehearsal/PINS")}
git -C "$HOME/xbt-rnd/b1" archive "$REHEARSAL_B1_PIN" xbt402 scripts | tar -x -C "$RUN/src/b1"
git -C "$HOME/xbt-rnd/b2" archive "$REHEARSAL_B2_PIN" agentwallet agentwallet-approve | tar -x -C "$RUN/src/b2"
echo "== AGP-027 signer interop on regtest: ports $REHEARSAL_PORT_BASE-$((REHEARSAL_PORT_BASE + 99)), b1 $REHEARSAL_B1_PIN, b2 $REHEARSAL_B2_PIN, signer $XBT_SIGNER_BIN"
set +e
"$PY" "$ROOT/scripts/interop/signer_runbook.py" "$OUT" 2>&1 | tee "$OUT/signer_interop.log"
rc=${PIPESTATUS[0]}
set -e
ln -sfn "$STAMP" "$ROOT/run/signer-interop-results/latest"
echo "evidence: $OUT"
[ "$rc" -eq 0 ] && echo "signer_interop: PASS" || { echo "signer_interop: FAIL"; exit 1; }
