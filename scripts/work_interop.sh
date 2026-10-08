#!/bin/bash
# AGP-032: pay-with-work (xbt-work v1) on regtest with the Rust side: the xbt-063 flagship-pww scenario
# with the Rust payer (xbt402 Client + xbt-work payer) mining via `.pw-` through its own DATUM gateway into
# primed rnd/agp-011, and the Rust provider (xbt402 Provider with xbt-channel + xbt-work) verifying the
# receipts it pulls through the blinded relay and auditing the pool coinbases against the Prime's signed
# window statements and deferral lines.
#
#   scripts/work_interop.sh                         Rust payer  -> Rust provider   (default)
#   PAYER=py  scripts/work_interop.sh               Python payer (xbt-063 flagship.pww_payer) -> Rust provider
#   PROVIDER=py scripts/work_interop.sh             Rust payer  -> Python provider (xbt-063 flagship.server WorkRail)
#   RELAY=py    scripts/work_interop.sh             the XBT-053 Python relay instead of the Rust xbt-work-relay (AGP-043;
#                                                   the Rust relay is the default: primed pushes to its push listener)
#
# Everything else is the reference stack: isolated Knots 29.4.2 regtest (xbt-063 scripts/node.sh, BLAKE2b
# from 101), primed built from ~/Bitcoin.worktrees/rnd-agp-011 (no source change), the stock C
# datum_gateway and stratum-grind from xbt-063/build (2 cores, under timeout: no miner outlives the run),
# the XBT-053 agp-011 relay (a dumb blob store; the Rust side is the relay client, as the spec's payer and
# provider are). Miner on cores WORK_CPUS (default 14,15). Ports WORK_PORT_BASE..+99 (default 34100), datadirs under run/work-<base>/. Evidence:
# the payer's JSON in docs/ (WORK_EVIDENCE), logs in run/work-<base>/.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
X063=${XBT063:-$HOME/xbt-rnd/xbt-063}
X053=${XBT053:-$HOME/xbt-rnd/XBT-053}
PRIMED=${PRIMED:-$HOME/Bitcoin.worktrees/rnd-agp-011/prime/target/release/primed}
PAYER=${PAYER:-rust}
PROVIDER=${PROVIDER:-rust}
RELAY_IMPL=${RELAY:-rust}
export FLAGSHIP_PORT_BASE=${WORK_PORT_BASE:-34100}
BASE=$FLAGSHIP_PORT_BASE
export XBT063_RUN=${WORK_RUN:-$ROOT/run/work-$BASE}
RUN=$XBT063_RUN
T=${CARGO_TARGET_DIR:-$HOME/xbt-rnd/xbt-rs-target}/release
CALLS=${WORK_CALLS:-2}
MINER_MAX_SECS=${WORK_MAX_SECS:-1500}
RPC_A=$((BASE + 1)); RPC_B=$((BASE + 3))
API=$((BASE + 12)); PRIME=$((BASE + 20)); STATS=$((BASE + 21)); STRATUM=$((BASE + 22)); GWAPI=$((BASE + 23)); RELAY=$((BASE + 24)); PUSH=$((BASE + 25))
PORTS=($RPC_A $((BASE + 2)) $RPC_B $((BASE + 4)) $API $PRIME $STATS $STRATUM $GWAPI $RELAY $PUSH)
STAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE=${WORK_EVIDENCE:-$ROOT/docs/work-interop-agp032-$(date +%F)-payer-$PAYER-provider-$PROVIDER.json}
PY=$X063/.venv/bin/python
source "$X063/scripts/lib-miner.sh"
PIDS=(); MINER_PID=""; GW_PID=""; PAYER_PID=""
node() { "$X063/scripts/node.sh" "$@"; }
cli() { node cli a "$@"; }

wait_http() {
  local url=$1 name=$2 secs=${3:-20} i
  for i in $(seq $((secs * 4))); do curl -sf "$url" >/dev/null && return 0; sleep 0.25; done
  echo "work_interop: $name not ready after ${secs}s ($url)" >&2; return 1
}
cleanup() {
  kill_miner "$MINER_PID"
  [ -n "$PAYER_PID" ] && { kill "$PAYER_PID" 2>/dev/null || true; }
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
  node wipe >/dev/null 2>&1 || true
}
trap cleanup EXIT

for f in "$PRIMED" "$X063/build/datum_gateway-fte" "$X063/build/stratum-grind"; do
  [ -x "$f" ] || { echo "missing $f (build primed in ~/Bitcoin.worktrees/rnd-agp-011/prime: cargo build --release -p primed)" >&2; exit 1; }
done
echo "== build the Rust tools (release, -j2)"
nice -n 10 cargo build -q -j2 --release -p xbt-work --features tools --bins -p xbt-work-relay
cleanup
rm -rf "${RUN:?}"; mkdir -p "$RUN/prime"
python3 "$X063/tools/portcheck.py" wait --timeout 75 "${PORTS[@]}" || { echo "work_interop: ports busy" >&2; exit 1; }

echo "== node (short chain: 110 blocks), ports ${BASE}+ ; payer=$PAYER provider=$PROVIDER"
node up
cli createwallet faucet >/dev/null
cli generatetoaddress 110 "$(cli -rpcwallet=faucet getnewaddress)" >/dev/null
POOLPAY=$(cli -rpcwallet=faucet getnewaddress pool bech32)
PROVIDER_ID=$(cli -rpcwallet=faucet getnewaddress provider bech32)
COOKIE_A=$RUN/node-a/regtest/.cookie; COOKIE_B=$RUN/node-b/regtest/.cookie

if [ "$RELAY_IMPL" = rust ]; then
  echo "== blinded receipt relay (Rust xbt-work-relay) on ${RELAY}, pushes on ${PUSH}"
  "$T/xbt-work-relay" --bind "127.0.0.1:${RELAY}" --push-bind "127.0.0.1:${PUSH}" --store "$RUN/relay-blobs" --rate 50 --burst 200 \
      >"$RUN/relay.log" 2>&1 & PIDS+=($!)
  RELAY_PUSH_URL="http://127.0.0.1:${PUSH}"
else
  echo "== blinded receipt relay (XBT-053 agp-011) on ${RELAY}"
  (cd "$X053" && exec python3 -m relay --host 127.0.0.1 --port "$RELAY") >"$RUN/relay.log" 2>&1 & PIDS+=($!)
  RELAY_PUSH_URL="http://127.0.0.1:${RELAY}"
fi
wait_http "http://127.0.0.1:${RELAY}/health" "receipt relay" 15

echo "== primed ($(git -C "$(dirname "$PRIMED")/../.." rev-parse --short HEAD 2>/dev/null || echo ?), rnd/agp-011) on ${PRIME}/${STATS}"
PRIME_WINDOW_MIN_WORK=${WORK_WINDOW_MIN_WORK:-64}
# AGP-065: the provider and payer hold window statements to the Prime's published terms
PRIME_TERMS=(--prime-window 8 --prime-window-min-work "$PRIME_WINDOW_MIN_WORK" --prime-fee-bps 0 --prime-min-payout 546)
cat >"$RUN/prime.toml" <<EOF
listen = "127.0.0.1:${PRIME}"
stats-listen = "127.0.0.1:${STATS}"
advertise-address = "127.0.0.1:${PRIME}"
data-dir = "$RUN/prime"
motd = "agp-032 pay-with-work"
min-diff = 1
payout-address = "$POOLPAY"
coinbase-tag = "Lazarus"
prime-id = 70
window = 8
# regtest D is ~5e-10, so 8 x D is under one share and the window would hold only the latest one:
# no receipted span could lie strictly inside (window_start, H) and the audit could never prove work.
# The floor keeps every share of the run in the window, as a real window holds many.
window-min-work = ${PRIME_WINDOW_MIN_WORK}
min-payout = 546
fee-bps = 0
network = "regtest"
rpc = "http://127.0.0.1:${RPC_A}"
rpc-cookie = "$COOKIE_A"
poll = 0.5
receipt-relay = "${RELAY_PUSH_URL}"
EOF
"$PRIMED" -c "$RUN/prime.toml" check >/dev/null
PRIME_PUB=$("$PRIMED" -c "$RUN/prime.toml" pubkey)
"$PRIMED" -c "$RUN/prime.toml" run >"$RUN/primed.log" 2>&1 & PIDS+=($!)
wait_http "http://127.0.0.1:${STATS}/healthz" "primed stats" 20

stat_line() {
  curl -sf "http://127.0.0.1:${STATS}/stats.json" | python3 -c 'import json,sys
d=json.load(sys.stdin); t=d["totals"]; print(d["gateways"], d["connections_open"], t["coinbasers"], t["shares_accepted"])' 2>/dev/null || echo "- - - -"
}
echo "== payer's own DATUM gateway on ${STRATUM}"
cat >"$RUN/gw.json" <<EOF
{
 "bitcoind": { "rpccookiefile": "$COOKIE_A", "rpcurl": "http://127.0.0.1:${RPC_A}", "work_update_seconds": 8, "notify_fallback": true },
 "stratum": { "listen_addr": "127.0.0.1", "listen_port": ${STRATUM}, "vardiff_min": 1 },
 "mining": { "pool_address": "bc1qt5praystcdle0nq04e3h02yjszha82uzhww85x6972lcy40k4eyqz9jfaq",
             "coinbase_tag_primary": "Lazarus", "coinbase_tag_secondary": "agp032-payer",
             "blake2b_activation_height": 101, "blake2b_headline": "xbt063" },
 "api": { "listen_port": ${GWAPI}, "admin_password": "" },
 "logger": { "log_to_console": true, "log_to_file": false, "log_level_console": 1 },
 "datum": { "pool_host": "127.0.0.1", "pool_port": ${PRIME}, "pool_pubkey": "$PRIME_PUB",
            "pool_pass_workers": true, "pool_pass_full_users": true, "pooled_mining_only": true,
            "protocol_global_timeout": 60 }
}
EOF
ready=
for attempt in 1 2 3; do
  echo "--- gateway start $attempt" >>"$RUN/gw.log"
  "$X063/build/datum_gateway-fte" -c "$RUN/gw.json" >>"$RUN/gw.log" 2>&1 & GW_PID=$!; PIDS+=($GW_PID)
  for _ in $(seq 80); do
    kill -0 "$GW_PID" 2>/dev/null || break
    read -r g _ cb _ <<<"$(stat_line)"
    if [ "$g" = 1 ] && [ "$cb" != - ] && [ "$cb" -ge 1 ] && curl -s -o /dev/null "http://127.0.0.1:${GWAPI}/" \
       && [ -n "$(ss -tlnH "( sport = :${STRATUM} )")" ]; then
      sleep 1; kill -0 "$GW_PID" 2>/dev/null && ready=1; break
    fi
    sleep 0.25
  done
  [ -n "$ready" ] && break
  kill -0 "$GW_PID" 2>/dev/null && { echo "work_interop: gateway up but not ready (primed: $(stat_line))" >&2; exit 1; }
  python3 "$X063/tools/portcheck.py" wait --timeout 75 "$STRATUM" "$GWAPI" || exit 1
done
[ -n "$ready" ] || { echo "work_interop: gateway failed to start 3 times" >&2; exit 1; }

echo "== provider ($PROVIDER): pool-analytics :${API} with xbt-channel + xbt-work (identity $PROVIDER_ID)"
if [ "$PROVIDER" = rust ]; then
  "$T/xbt-work-provider" --port "$API" --rpc-port "$RPC_B" --cookie "$COOKIE_B" --identity "$PROVIDER_ID" --prime-pubkey "$PRIME_PUB" \
      --prime-id 70 --receipt-url "http://127.0.0.1:${STATS}/receipt" --relay-url "http://127.0.0.1:${RELAY}" \
      --window-url "http://127.0.0.1:${STATS}/window" --state "$RUN/provider-work.json" --admin "${PRIME_TERMS[@]}" \
      --pull-secs "$([ "$PAYER" = rust ] && echo 3 || echo 0)" >"$RUN/server.log" 2>&1 & PIDS+=($!)
  # (with the Python payer, which has no pause signal, the provider credits only the receipts presented:
  #  a relay pull mid-run would refill the balance its "spent receipt" refusal check expects to be empty)
else
  export XBT063_B1=$X063/vendor/b1 XBT063_B2=$X063/vendor/b2 B1_ROOT=$X063/vendor/b1
  export PYTHONPATH=$X063/vendor/b2:$X063/vendor/b1:$X063:$HOME/xbt-rnd/xbt-070:$X053${PYTHONPATH:+:$PYTHONPATH}
  (cd "$X063" && exec "$PY" -m flagship.server --port "$API" --work-identity "$PROVIDER_ID" --work-prime-pubkey "$PRIME_PUB" \
      --work-prime-id 70 --work-receipt-url "http://127.0.0.1:${STATS}/receipt" \
      --work-relay-url "http://127.0.0.1:${RELAY}") >"$RUN/server.log" 2>&1 & PIDS+=($!)
fi
wait_http "http://127.0.0.1:${API}/" "provider" 30
BASEURL="http://127.0.0.1:${API}"

echo "== payer ($PAYER): take a work invoice, mine through its own gateway (stratum-grind, 2 cores)"
if [ "$PAYER" = rust ]; then
  USER_NAME=$("$T/xbt-work-payer" prepare "$BASEURL" --state "$RUN/payer-work.json")
else
  export XBT063_B1=$X063/vendor/b1 XBT063_B2=$X063/vendor/b2 B1_ROOT=$X063/vendor/b1
  export PYTHONPATH=$X063/vendor/b2:$X063/vendor/b1:$X063:$HOME/xbt-rnd/xbt-070:$X053${PYTHONPATH:+:$PYTHONPATH}
  USER_NAME=$(cd "$X063" && "$PY" -m flagship.pww_payer prepare "$BASEURL")
fi
echo "   mining as $USER_NAME"
run_miner "$RUN/miner.log" taskset -c "${WORK_CPUS:-14,15}" nice -n 10 "$X063/build/stratum-grind" --host 127.0.0.1 --port "$STRATUM" --user "$USER_NAME"
MINER_PID=$!

echo "== payer: wait for receipts covering $CALLS calls, pay, refusal checks, coinbase audit"
PAUSE=$RUN/pause-miner
if [ "$PAYER" = rust ]; then
  PAYER_ARGS=(--state "$RUN/payer-work.json" --rpc-port "$RPC_A" --cookie "$COOKIE_A" --window-url "http://127.0.0.1:${STATS}/window" --pause-file "$PAUSE"
              "${PRIME_TERMS[@]}")
  [ "$PROVIDER" = rust ] && PAYER_ARGS+=(--provider-admin)
  "$T/xbt-work-payer" pay "$BASEURL" "$CALLS" "$((MINER_MAX_SECS - 60))" "${PAYER_ARGS[@]}" >"$RUN/evidence.json" 2>"$RUN/payer.log" & PAYER_PID=$!
else
  export PWW_RELAY_URL="http://127.0.0.1:${RELAY}" PWW_WINDOW_URL="http://127.0.0.1:${STATS}/window"
  (cd "$X063" && exec "$PY" -m flagship.pww_payer pay "$BASEURL" "$CALLS" "$((MINER_MAX_SECS - 60))") >"$RUN/evidence.json" 2>"$RUN/payer.log" & PAYER_PID=$!
fi
t0=$SECONDS; last=-30; paused=
while kill -0 "$PAYER_PID" 2>/dev/null; do
  el=$((SECONDS - t0))
  if [ -z "$paused" ] && [ -f "$PAUSE" ]; then
    kill -STOP -- -"$MINER_PID" 2>/dev/null || true; paused=1; echo "   [+${el}s] receipts cover the calls: miner paused"
  fi
  if [ $((el - last)) -ge 30 ]; then
    echo "   [+${el}s] prime: gateways connections coinbasers shares = $(stat_line)"; last=$el
  fi
  kill -0 "$GW_PID" 2>/dev/null || { echo "work_interop: gateway died" >&2; grep -E "FATAL|ERROR" "$RUN/gw.log" | tail -5 >&2; break; }
  sleep 2
done
set +e; wait "$PAYER_PID"; rc=$?; set -e; PAYER_PID=""
kill_miner "$MINER_PID"; MINER_PID=""
cat "$RUN/payer.log"
cp "$RUN/evidence.json" "$EVIDENCE"
python3 - "$EVIDENCE" "$PAYER" "$PROVIDER" "$(git -C "$ROOT" rev-parse --short HEAD)" \
  "$([ "$RELAY_IMPL" = rust ] && echo "Rust xbt-work-relay (AGP-043)" || echo "XBT-053 agp-011")" <<'EOF'
import json, sys
p, payer, provider, head, relay = sys.argv[1:]
v = json.load(open(p))
v["run"] = {"payer": payer, "provider": provider, "xbt_rs": head, "primed": "rnd/agp-011", "relay": relay}
json.dump(v, open(p, "w"), indent=1)
print(f"evidence: {p}  ({sum(c['ok'] for c in v['checks'])}/{len(v['checks'])} checks ok)")
EOF
[ $rc -eq 0 ] && echo "work_interop ($PAYER payer -> $PROVIDER provider): PASS" || { echo "work_interop ($PAYER payer -> $PROVIDER provider): FAIL"; exit 1; }
