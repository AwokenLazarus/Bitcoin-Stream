#!/bin/bash
# Cross-implementation run on regtest: the Rust xbt402 against the Python reference (B1 agp-029).
# A private Knots 29.4.2 node (RDTS on, #419 long coinbase maturity, BLAKE2b from block 101: B1's
# scripts/node.sh flags), two Python B1 providers and two Rust providers, then:
#   A1  Rust payer   -> Python provider  10 calls + 1 hash-locked conditional call, close  (v1.1 payer-pays)
#   A2  Rust payer   -> Python provider  10 calls, close                                   (v1.2 payee-pays)
#   A3  Rust payer   -> Python provider  5 calls, rollover (provider co-signs), 5 calls on the next channel, close
#   B1  Python payer -> Rust provider    10 calls + 1 hash-locked conditional call, close  (v1.1 payer-pays)
#   B2  Python payer -> Rust provider    10 calls, close                                   (v1.2 payee-pays)
#   C1  Rust payer   -> Rust provider    10 calls, close                                   (v1.1, same node)
# Every close is mined and its outputs checked exactly (payee, payer change, fee).
# Ports 33030-33049 (AGP-025 has 33000-33099). Starts NO miners (blocks come from generatetoaddress).
# The node and the providers are stopped and wiped on exit. Soak rules: CPUQuota 200%, 4G, nice 19.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
B1=${XBT402_B1:-$HOME/xbt-rnd/b1-agp-068}
R=${XBT_RS_RUN:-$ROOT/run}
PB=${XBT_RS_PORT_BASE:-33000}
export XBT402_B1=$B1
export XBT_BIN=${XBT_BIN:-$HOME/lazarus-regtest/b1-xbt402/knots-29.4.2}
export XBT402_DATADIR=$R/interop-node
export XBT402_RPCPORT=$((PB + 30)) XBT402_P2PPORT=$((PB + 31))
export XBT402_MATURITY_PAD=6800
PY=${XBT402_PYTHON:-$HOME/xbt-rnd/b1/.venv/bin/python}
[ -x "$PY" ] || PY=python3
P_PY=$((PB + 40)) P_PY_PAYEE=$((PB + 41)) P_RS=$((PB + 42)) P_RS_PAYEE=$((PB + 43))
COOKIE=$XBT402_DATADIR/regtest/.cookie
SOAK=(systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19)
PIDS=()
mkdir -p "$R"
LOG=$R/interop.log
: > "$LOG"

cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  "$B1/scripts/node.sh" wipe >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

python3 "$HOME/xbt-rnd/xbt-063/tools/portcheck.py" wait "$XBT402_RPCPORT" "$XBT402_P2PPORT" "$P_PY" "$P_PY_PAYEE" "$P_RS" "$P_RS_PAYEE"
"${SOAK[@]}" cargo build -q -j2 --release -p xbt402-interop --bins
"$B1/scripts/node.sh" wipe >/dev/null 2>&1 || true
"$B1/scripts/node.sh" up
echo "network $(python3 -c "import sys;sys.path.insert(0,'$B1');from xbt402.rpc import RPC;from xbt402.x402_channel import network_id;print(network_id(RPC.from_env().getblockhash(101)))")"

wait_http() {
  for _ in $(seq 100); do curl -s -o /dev/null "http://127.0.0.1:$1/x402/supported" && return 0; sleep 0.1; done
  echo "provider on $1 did not come up" >&2; tail -20 "$LOG" >&2; exit 1
}
"${SOAK[@]}" "$PY" scripts/interop/py_provider.py "$P_PY" payer "/v1/secret:600:python-sold-this" >>"$LOG" 2>&1 & PIDS+=($!)
"${SOAK[@]}" "$PY" scripts/interop/py_provider.py "$P_PY_PAYEE" payee >>"$LOG" 2>&1 & PIDS+=($!)
"${SOAK[@]}" ./target/release/xbt402-rust-provider --port "$P_RS" --rpc-port "$XBT402_RPCPORT" --cookie "$COOKIE" \
  --conditional "/v1/secret:600:rust-sold-this" --ledger "$R/rust-provider.jsonl" >>"$LOG" 2>&1 & PIDS+=($!)
"${SOAK[@]}" ./target/release/xbt402-rust-provider --port "$P_RS_PAYEE" --rpc-port "$XBT402_RPCPORT" --cookie "$COOKIE" \
  --close-fee-payer payee >>"$LOG" 2>&1 & PIDS+=($!)
for p in "$P_PY" "$P_PY_PAYEE" "$P_RS" "$P_RS_PAYEE"; do wait_http "$p"; done
grep -E "ready" "$LOG" || true

RES=$R/interop_results.jsonl
: > "$RES"
FAIL=0
run() {  # name, command...
  local name=$1; shift
  local out
  if out=$("$@" 2>>"$LOG"); then st=PASS; else st=FAIL; FAIL=1; fi
  echo "{\"scenario\": \"$name\", \"result\": $out}" >> "$RES"
  printf '%-4s %-4s %s\n' "$name" "$st" "$(echo "$out" | python3 scripts/interop/summary.py 2>/dev/null || echo "$out")"
}
RSPAY=(./target/release/xbt402-rust-payer --rpc-port "$XBT402_RPCPORT" --cookie "$COOKIE" --calls 10)
run A1 "${SOAK[@]}" "${RSPAY[@]}" --url "http://127.0.0.1:$P_PY" --conditional /v1/secret
run A2 "${SOAK[@]}" "${RSPAY[@]}" --url "http://127.0.0.1:$P_PY_PAYEE"
run A3 "${SOAK[@]}" "${RSPAY[@]}" --url "http://127.0.0.1:$P_PY" --rollover-after 5
run B1 "${SOAK[@]}" "$PY" scripts/interop/py_payer.py "http://127.0.0.1:$P_RS" 10 /v1/secret
run B2 "${SOAK[@]}" "$PY" scripts/interop/py_payer.py "http://127.0.0.1:$P_RS_PAYEE" 10
run C1 "${SOAK[@]}" "${RSPAY[@]}" --url "http://127.0.0.1:$P_RS_PAYEE"
echo "results: $RES"
[ "$FAIL" = 0 ] && echo "interop: OK (6/6 scenarios, exact amounts)" || { echo "interop: FAIL"; tail -30 "$LOG"; exit 1; }
