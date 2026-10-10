#!/bin/bash
# The Rust light backend (xbt-electrum) on regtest, against real electrs and the Python B1 provider.
# A private Knots 29.4.2 node (B1's scripts/node.sh flags: RDTS on, #419 long coinbase maturity,
# BLAKE2b from block 101), two patched electrs 0.11.1 (header v2 + the Knots 29.4.2 RPC patch,
# AGP-024) indexing it, TLS (the test certificate) in front of the second one, and Python B1
# providers. The Rust payer is light: its own hot key, every chain read and broadcast through
# Electrum (tcp:// + ssl://, both required). The node is only the faucet, the miner and the oracle
# every answer is compared with.
#   E1  pay     -> Python provider (v1.1 payer-pays)  10 calls, close, the close change counted late
#   E2  pay     -> Python provider (v1.2 payee-pays)  10 calls, close, the close change counted late
#   E3  refund  -> Python provider                    3 calls, the provider vanishes, refund at expiry
# Ports 33300-33399 (AGP-028). Starts NO miners (blocks from generatetoaddress). Never contacts
# production Electrum servers: every server here is 127.0.0.1. Everything is stopped and wiped on
# exit. Soak rules: CPUQuota 200%, 4G, nice 19.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
B1=${XBT402_B1:-$HOME/xbt-rnd/b1}
R=${XBT_RS_RUN:-$ROOT/run}/electrum
PB=${XBT_ELECTRUM_PORT_BASE:-33300}
ELECTRS_DIR=${XBT_ELECTRS_DIR:-$HOME/xbt-rnd/electrs-agp-024}
ELECTRS=${XBT_ELECTRS:-$ELECTRS_DIR/src/target/release/electrs}
export XBT402_B1=$B1
export XBT_BIN=${XBT_BIN:-$HOME/lazarus-regtest/b1-xbt402/knots-29.4.2}
export XBT402_DATADIR=$R/node
export XBT402_RPCPORT=$PB XBT402_P2PPORT=$((PB + 1))
export XBT402_MATURITY_PAD=6800
PY=${XBT402_PYTHON:-$HOME/xbt-rnd/b1/.venv/bin/python}
[ -x "$PY" ] || PY=python3
E1=$((PB + 10)) M1=$((PB + 11)) E2=$((PB + 12)) M2=$((PB + 13)) TLS=$((PB + 14))
P_PAYER=$((PB + 20)) P_PAYEE=$((PB + 21)) P_REFUND=$((PB + 22))
COOKIE=$XBT402_DATADIR/regtest/.cookie
SOAK=(systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19)
PIDS=()
rm -rf "$R"
mkdir -p "$R"
LOG=$R/interop.log
: > "$LOG"

cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  "$B1/scripts/node.sh" wipe >/dev/null 2>&1 || true
  rm -rf "$R/db1" "$R/db2"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

# the patched electrs: reuse AGP-024's build, or build it from its patched tree
if [ ! -x "$ELECTRS" ]; then
  [ -f "$ELECTRS_DIR/src/Cargo.toml" ] || { echo "no electrs at $ELECTRS and no patched tree at $ELECTRS_DIR/src (AGP-024)" >&2; exit 1; }
  echo "building electrs (AGP-024 patched tree)"
  LIBCLANG_PATH=$(dirname "$(find "$ELECTRS_DIR/clangvenv" -name 'libclang.so' | head -1)") \
    "${SOAK[@]}" cargo build -q -j2 --release --manifest-path "$ELECTRS_DIR/src/Cargo.toml"
fi
echo "electrs: $("$ELECTRS" --version 2>&1 | head -1) ($ELECTRS)"

python3 "$HOME/xbt-rnd/xbt-063/tools/portcheck.py" wait "$XBT402_RPCPORT" "$XBT402_P2PPORT" "$E1" "$M1" "$E2" "$M2" "$TLS" "$P_PAYER" "$P_PAYEE" "$P_REFUND"
"${SOAK[@]}" cargo build -q -j2 --release -p xbt-electrum --features interop --bins
BIN=./target/release/xbt-electrum-interop
"$B1/scripts/node.sh" wipe >/dev/null 2>&1 || true
"$B1/scripts/node.sh" up

start_electrs() {  # rpc-port monitoring-port db
  "${SOAK[@]}" "$ELECTRS" --skip-default-conf-files --network regtest --db-dir "$R/$3" \
    --daemon-dir "$XBT402_DATADIR" --cookie-file "$COOKIE" \
    --daemon-rpc-addr "127.0.0.1:$XBT402_RPCPORT" --daemon-p2p-addr "127.0.0.1:$XBT402_P2PPORT" \
    --electrum-rpc-addr "127.0.0.1:$1" --monitoring-addr "127.0.0.1:$2" >>"$R/electrs-$3.log" 2>&1 &
  PIDS+=($!)
}
start_electrs "$E1" "$M1" db1
start_electrs "$E2" "$M2" db2
"$BIN" tls-proxy --listen "127.0.0.1:$TLS" --upstream "127.0.0.1:$E2" >>"$LOG" 2>&1 & PIDS+=($!)

wait_http() {
  for _ in $(seq 100); do curl -s -o /dev/null "http://127.0.0.1:$1/x402/supported" && return 0; sleep 0.1; done
  echo "provider on $1 did not come up" >&2; tail -20 "$LOG" >&2; exit 1
}
"${SOAK[@]}" "$PY" scripts/interop/py_provider.py "$P_PAYER" payer >>"$LOG" 2>&1 & PIDS+=($!)
"${SOAK[@]}" "$PY" scripts/interop/py_provider.py "$P_PAYEE" payee >>"$LOG" 2>&1 & PIDS+=($!)
# the refund scenario kills this one (not through systemd-run, so its pid is the python process)
nice -n 19 "$PY" scripts/interop/py_provider.py "$P_REFUND" payer >>"$LOG" 2>&1 & REFUND_PID=$!; PIDS+=($REFUND_PID)
for p in "$P_PAYER" "$P_PAYEE" "$P_REFUND"; do wait_http "$p"; done

SERVERS="tcp://127.0.0.1:$E1,ssl://localhost:$TLS"
COMMON=(--rpc-port "$XBT402_RPCPORT" --cookie "$COOKIE" --servers "$SERVERS" --min-servers 2
        --ca crates/xbt-electrum/tests/data/test-ca.pem)
RES=$R/electrum_results.jsonl
: > "$RES"
FAIL=0
run() {  # name, command...
  local name=$1; shift
  local out
  if out=$("$@" 2>>"$LOG"); then st=PASS; else st=FAIL; FAIL=1; fi
  echo "{\"scenario\": \"$name\", \"result\": $out}" >> "$RES"
  printf '%-3s %-4s %s\n' "$name" "$st" "$(echo "$out" | python3 scripts/interop/electrum_summary.py 2>/dev/null || echo "$out")"
}
run E1 "${SOAK[@]}" "$BIN" pay "${COMMON[@]}" --url "http://127.0.0.1:$P_PAYER" --calls 10
run E2 "${SOAK[@]}" "$BIN" pay "${COMMON[@]}" --url "http://127.0.0.1:$P_PAYEE" --calls 10
run E3 "${SOAK[@]}" "$BIN" refund "${COMMON[@]}" --url "http://127.0.0.1:$P_REFUND" --kill-pid "$REFUND_PID"
echo "results: $RES"
[ "$FAIL" = 0 ] && echo "electrum interop: OK (3/3 scenarios, exact amounts, every answer matches the node)" \
  || { echo "electrum interop: FAIL"; tail -30 "$LOG"; exit 1; }
