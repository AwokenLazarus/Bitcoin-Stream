#!/bin/bash
# AGP-043: the live NTA regtest leg of xbt-work with the Rust side (see scripts/work_nta.py): the Rust provider
# on an XBT-NTA chain, signer stopped -> a signed `unattested` deferral line -> the Rust audit passes -> paid with
# the carry; the Rust relay server (xbt-work-relay) in front of primed; the §13.1 caps holding and releasing credit.
#
#   scripts/work_nta.sh          (~10-25 min; prints RESULT PASS|FAIL)
#
# Reuses AGP-011's NTA stack (sov-017's regtest setup): Knots 29.4.2 + NTA (~/xbt-rnd/xbt-071/knots), primed,
# stratum-grind and nta-signer from ~/Bitcoin branch rnd/agp-011 (built, no source change), the payer's split-only
# datum_gateway (xbt-063-agp-011 run/cgw), XBT-053 nta.py/receipts.py (keys, and the Python relay client as a
# cross-check). The Rust side: xbt-work-provider, xbt-work-payer, xbt-work-relay from this tree.
#
# Ports WORK_NTA_BASE..+49 (default 34300; it uses +1..+25), preflighted; the leftover-miner sweep covers only these. Datadirs under run/work-nta-<base>/. Every exit, pass or
# fail, copies every log into docs/work-nta-agp043-<stamp>/ (WORK_NTA_OUT to override). The whole run is one
# systemd-run --user scope (CPUQuota=200%, MemoryMax=4G, nice 19); cargo -j2; the miner 2 threads under `timeout`.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
if [ -z "${WORK_NTA_SCOPED:-}" ]; then
  exec env WORK_NTA_SCOPED=1 systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G \
    nice -n 19 bash "$ROOT/scripts/$(basename "$0")" "$@"
fi
BASE=${WORK_NTA_BASE:-34300}
END=$((BASE + 49))   # its own ports only (BASE..+25): a run beside it at +50 keeps its miner
RUN=$ROOT/run/work-nta-$BASE
STAMP=$(date +%Y%m%d-%H%M%S)
OUT=${WORK_NTA_OUT:-$ROOT/docs/work-nta-agp043-$STAMP}
WT=${AGP011_WT:-$HOME/Bitcoin.worktrees/rnd-agp-011}
PRIME_T=${PRIME_TARGET:-$HOME/xbt-rnd/XBT-053/run/prime-target}
KNOTS=${KNOTS:-$HOME/xbt-rnd/xbt-071/knots}
CGW=${CGW:-$HOME/xbt-rnd/xbt-063-agp-011/run/cgw/datum_gateway}
X053=${XBT053:-$HOME/xbt-rnd/XBT-053}
PORTCHECK=${PORTCHECK:-$HOME/xbt-rnd/xbt-063/tools/portcheck.py}
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$HOME/xbt-rnd/xbt-rs-target}
T=$CARGO_TARGET_DIR/release
DRIVER_PID=""; EVIDENCE=""

cleanup() {
  if [ -n "$DRIVER_PID" ]; then kill "$DRIVER_PID" 2>/dev/null || true; wait "$DRIVER_PID" 2>/dev/null || true; DRIVER_PID=""; fi
  python3 "$HOME/xbt-rnd/tools/miners_left.py" "$BASE-$END" >/dev/null 2>&1 || true
  pkill -f -- "nta-signer run .*$RUN/" 2>/dev/null || true
  pkill -f -- "--config $RUN/gw.json" 2>/dev/null || true
  pkill -f -- "-c $RUN/prime.toml" 2>/dev/null || true
  pkill -f -- "xbt-work-provider --port $((BASE + 12)) " 2>/dev/null || true
  pkill -f -- "xbt-work-relay --bind 127.0.0.1:$((BASE + 24)) " 2>/dev/null || true
  pkill -f -- "-datadir=$RUN/node-" 2>/dev/null || true
  if [ -n "$EVIDENCE" ]; then   # full logs, on every exit
    for f in primed.log gw.log miner.log relay.log provider.log signer.log prime.toml gw.json payer-work.json.meta.json; do
      [ -f "$RUN/$f" ] && cp "$RUN/$f" "$OUT/"
    done
    for n in a b; do [ -f "$RUN/node-$n/regtest/debug.log" ] && cp "$RUN/node-$n/regtest/debug.log" "$OUT/node-$n-debug.log"; done
    cp "$RUN/provider-work.json" "$RUN/prime/work-receipts.json" "$RUN/prime/window-statements.json" "$OUT/" 2>/dev/null || true
    EVIDENCE=""
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

echo "== work-nta (ports $BASE-$END) xbt-rs $(git rev-parse --short HEAD)$(git diff --quiet HEAD -- crates scripts || echo +dirty); rnd/agp-011 @ $(git -C "$WT" rev-parse --short HEAD)"
for f in "$KNOTS/build/bin/bitcoind" "$PRIME_T/release/primed" "$PRIME_T/release/stratum-grind" "$WT/lazarus/target/release/nta-signer" "$CGW"; do
  [ -x "$f" ] || { echo "missing $f (AGP-011's stack: see scripts/work_nta.sh header)" >&2; exit 1; }
done
echo "== build the Rust tools (release, -j2)"
cargo build -q -j2 --release -p xbt-work --features tools --bins -p xbt-work-relay

cleanup
for _ in $(seq 60); do pgrep -f -- "-datadir=$RUN/node-" >/dev/null || break; sleep 1; done
rm -rf "${RUN:?}"
mkdir -p "$RUN" "$OUT"
EVIDENCE=1
PORTS=($((BASE + 1)) $((BASE + 2)) $((BASE + 3)) $((BASE + 4)) $((BASE + 12)) $((BASE + 13)) $((BASE + 20)) $((BASE + 21)) $((BASE + 22)) $((BASE + 24)) $((BASE + 25)))
python3 "$PORTCHECK" wait --timeout 75 "${PORTS[@]}" || { echo "work_nta: ports busy, see above" >&2; exit 1; }
{
  echo "xbt-rs $(git rev-parse HEAD)$(git diff --quiet HEAD -- crates scripts || echo ' +uncommitted')"
  echo "rnd/agp-011 $(git -C "$WT" rev-parse HEAD)"
  echo "knots $(git -C "$KNOTS" rev-parse HEAD)"
  echo "datum_gateway $CGW (stamp $(cat "$(dirname "$CGW")/.stamp" 2>/dev/null))"
  echo "XBT-053 $(git -C "$X053" rev-parse HEAD)"
} > "$OUT/versions.txt"
cat > "$OUT/cfg.json" <<JSON
{"run": "$RUN", "out": "$OUT", "base": $BASE, "xbt053": "$X053", "portcheck": "$PORTCHECK",
 "bins": {"bitcoind": "$KNOTS/build/bin/bitcoind", "primed": "$PRIME_T/release/primed", "grind": "$PRIME_T/release/stratum-grind",
          "signer": "$WT/lazarus/target/release/nta-signer", "cgw": "$CGW", "provider": "$T/xbt-work-provider",
          "payer": "$T/xbt-work-payer", "relay": "$T/xbt-work-relay"}}
JSON
echo "== run -> $OUT"
set +e
python3 -u scripts/work_nta.py "$OUT/cfg.json" > >(tee "$OUT/demo.log") 2>&1 &
DRIVER_PID=$!
wait "$DRIVER_PID"; rc=$?
DRIVER_PID=""
set -e
left=$(python3 "$HOME/xbt-rnd/tools/miners_left.py" "$BASE-$END" 2>&1 || true)
echo "miners left in $BASE-$END: ${left:-none}"
echo "evidence: $OUT"
if [ $rc -eq 0 ]; then echo "work_nta: RESULT PASS"; else echo "work_nta: RESULT FAIL (rc $rc)"; exit 1; fi
