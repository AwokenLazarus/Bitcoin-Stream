#!/bin/bash
# AGP-040 verify for the Umbrel apps (SOV-005's test-umbrel-app.sh shape): lint the store, then install the
# node, wallet and hub apps from cold on a regtest chain the way umbrelOS does (umbrel_regtest.py), RUNS times
# (default 2), and print RESULT PASS|FAIL with each run's time to a ready wallet.
# Needs the images loaded (scripts/oci_build.sh --load). Ports 34000-34099 on 127.0.0.1 only (UMBREL_TEST_PORTS=LO-HI
# and UMBREL_TEST_*_PORT move them). Soak rules:
# CPUQuota 200%, MemoryMax 4G, nice 19. Starts no miners (blocks come from generatetoaddress). Never pushes,
# never submits to a store. Evidence: run/umbrel-test/<stamp>/.
set -euo pipefail
if [ -z "${UMBREL_TEST_SCOPED:-}" ] && command -v systemd-run >/dev/null; then
  export UMBREL_TEST_SCOPED=1
  exec systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19 "$0" "$@"
fi
cd "$(dirname "$0")/../.."
ROOT=$PWD
RUNS=${RUNS:-2}
STAMP=$(date +%Y%m%d-%H%M%S)
OUT=$ROOT/run/umbrel-test/$STAMP
mkdir -p "$OUT"
PORTS=${UMBREL_TEST_PORTS:-34000-34099}
busy=$(ss -ltnH | awk '{print $4}' | sed 's/.*://' | awk -v lo="${PORTS%-*}" -v hi="${PORTS#*-}" '$1>=lo && $1<=hi' | sort -u | tr '\n' ' ')
[ -z "$busy" ] || { echo "test-umbrel-apps: ports busy in $PORTS: $busy" >&2; exit 1; }
for i in xbt-signer xbt-anchor-witness xbt-wallet-mcp xbt-wallet-ui xbt402-hub xbt-init; do
  docker image inspect "$i:0.1.0" >/dev/null 2>&1 || { echo "test-umbrel-apps: image $i:0.1.0 missing (scripts/oci_build.sh --load)" >&2; exit 1; }
done

echo "== lint the store" | tee "$OUT/lint.log"
python3 packaging/umbrel/lint.py packaging/umbrel 2>&1 | tee -a "$OUT/lint.log"
echo "== lint catches a broken app (a copy with the signer run as the box user)" | tee -a "$OUT/lint.log"
NEG=$(mktemp -d)
cp -r packaging/umbrel/. "$NEG/"
python3 - "$NEG/lazarus-xbt-agent-wallet/docker-compose.yml" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read().replace("    image: xbt-signer:0.1.0\n", "    image: xbt-signer:0.1.0\n    user: \"1000:1000\"\n", 1)
open(p, "w").write(s)
PY
if python3 packaging/umbrel/lint.py "$NEG" >>"$OUT/lint.log" 2>&1; then echo "lint missed the broken app" | tee -a "$OUT/lint.log"; rm -rf "$NEG"; echo "RESULT FAIL"; exit 1; fi
rm -rf "$NEG"
echo "   refused, as it should be" | tee -a "$OUT/lint.log"

rc=0
TIMES=()
for i in $(seq 1 "$RUNS"); do
  echo "== cold run $i / $RUNS"
  mkdir -p "$OUT/run$i"
  if python3 packaging/umbrel/regtest/umbrel_regtest.py "$OUT/run$i" "$i"; then
    TIMES+=("$(python3 -c 'import json,sys; print("%.1f" % json.load(open(sys.argv[1]))["t_wallet_ready_s"])' "$OUT/run$i/facts.json")")
  else
    rc=1
  fi
done
ln -sfn "$STAMP" "$ROOT/run/umbrel-test/latest"
echo "evidence: $OUT"
if [ $rc -eq 0 ]; then
  echo "RESULT PASS"
  n=1; for t in "${TIMES[@]}"; do echo "run $n: wallet ready ${t}s after install"; n=$((n + 1)); done
else
  echo "RESULT FAIL"; exit 1
fi
