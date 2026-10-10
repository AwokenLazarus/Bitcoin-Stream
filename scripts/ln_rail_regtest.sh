#!/bin/bash
# AGP-048 on regtest: rail=ln. The Rust signer and MCP pay XBT Lightning invoices through a Lightning
# Fork node under B2's policy, with the AGP-047 guards (bit 512, the LN node's chain identity, no
# taproot or non-unified or pre-split channels). Lab: paulscode/lightning-fork-lab a5cadc5 (Knots
# v29.4.1 BLAKE2b regtest, activation at 20; lf1, lf2 and lf3 = Lightning Fork cebc10fe,
# v0.21.3-beta-blake2b.17 (AGP-083; dd659b3, .13, until then); bitcoind-sha + lnd-sha = stock Core and
# lnd on a SHA-256 regtest), cloned read-only under run/. Scenarios: scripts/ln_rail/drive.py (S1-S9 AGP-048, S10-S15 AGP-049: funding
# proven from the transaction, the exposure cap, the macaroon IP caveat, watchtowers, the rate limit,
# HTLC CLTV locks; S16-S18 AGP-066: lookup by payment hash, the macaroon allowlist, plain http only on
# loopback; S19-S24 AGP-083: BOLT 12 offers on the real node: lf1, which holds a taproot and a pre-split
# channel, pays none; lf3, whose one channel is proven, pays lf2's offers, and a failed pay is retried
# from the stored invoice); report run/ln_rail_regtest.json.
#
# Regtest only: no mainnet LN node is contacted. Ports 17481, 17491, 17493, 17495 (loopback; below the
# kernel's ephemeral range since AGP-083, 34781/34791/34793 before), compose project agp049ln, container CPU caps (scripts/ln_rail/compose.ln_rail.yml),
# host builds at nice 19 -j4. The lab's containers and volumes are removed on exit (LN_RAIL_KEEP=1
# keeps them). LN_RAIL_GOCACHE: a Go build cache to reuse (default run/gocache).
#
#   scripts/ln_rail_regtest.sh            build what is missing, run S1-S24, tear down
set -euo pipefail
lazvault hold check --project xbt-agentpay || exit 75   # IMP-030: heavy entry point, refuses during a host hold
cd "$(dirname "$0")/.."
ROOT=$PWD
LAB=$ROOT/run/lightning-fork-lab
LF=$ROOT/run/lightning-fork
LAB_REV=a5cadc5604cd18a0b2f4901ef380cdf4d44ee75a
LF_REV=cebc10fe01e811a38c2830c0396bd3c9182e5d62
export COMPOSE_PROJECT_NAME=agp049ln
export COMPOSE_FILE=$LAB/docker-compose.yml:$ROOT/scripts/ln_rail/compose.ln_rail.yml
export ACTIVATION_HEIGHT=20
R=$ROOT/run/ln-rail-$$
mkdir -p "$R"

[ -d "$LAB/.git" ] || git clone -q https://github.com/paulscode/lightning-fork-lab.git "$LAB"
git -C "$LAB" checkout -q "$LAB_REV"
[ -d "$LF/.git" ] || git clone -q https://github.com/paulscode/lightning-fork.git "$LF"
git -C "$LF" cat-file -e "$LF_REV^{commit}" 2>/dev/null || git -C "$LF" fetch -q --tags origin
git -C "$LF" checkout -q "$LF_REV"
# wtclientrpc (AGP-049): ln_status lists the wtclient's towers over REST
TAGS="autopilotrpc signrpc walletrpc chainrpc invoicesrpc watchtowerrpc wtclientrpc peersrpc routerrpc offersrpc"
GOCACHE_DIR=${LN_RAIL_GOCACHE:-$ROOT/run/gocache}
if [ ! -x "$LAB/bin/lnd" ] || [ ! -x "$LAB/bin/lncli" ] || [ "$(cat "$LAB/bin/.tags" 2>/dev/null)" != "$LF_REV $TAGS" ]; then
  mkdir -p "$LAB/bin" "$GOCACHE_DIR"
  docker run --rm --cpus=4 -u "$(id -u):$(id -g)" -e HOME=/tmp -e GOWORK=off -e GOCACHE=/cache/build -e GOMODCACHE=/cache/mod \
    -e GOFLAGS=-buildvcs=false -e T="$TAGS" -v "$LF:/src:ro" -v "$GOCACHE_DIR:/cache" -v "$LAB/bin:/out" -w /src golang:1.25.13 \
    sh -c 'go build -tags "$T" -o /out/lnd ./cmd/lnd && go build -tags "$T" -o /out/lncli ./cmd/lncli'
  echo "$LF_REV $TAGS" > "$LAB/bin/.tags"
fi
docker image inspect knots-blake2b:final-zmq >/dev/null 2>&1 || \
  (cd "$LAB/knots" && DOCKER_BUILDKIT=0 docker build --cpuset-cpus=0-3 -t knots-blake2b:final-zmq .)
(cd "$LAB" && docker compose build -q lf1)

# a lab an earlier LN_RAIL_KEEP=1 run left holds the ports: it goes before they are checked
(cd "$LAB" && docker compose down -v >/dev/null 2>&1 || true)
python3 "$HOME/xbt-rnd/xbt-063/tools/portcheck.py" wait 17481 17491 17493 17495
nice -n 19 cargo build -q -j4 --release -p xbt-signer --bin xbt-signer -p xbt-wallet-mcp --bin xbt-wallet-mcp
BIN=${CARGO_TARGET_DIR:-$ROOT/target}/release

cleanup() {
  pkill -f "$R/" 2>/dev/null || true
  if [ "${LN_RAIL_KEEP:-0}" != 1 ]; then
    (cd "$LAB" && docker compose --profile refuse --profile cln down -v >/dev/null 2>&1) || true
  fi
  cp "$R"/*.log "$ROOT/run/" 2>/dev/null || true
  rm -rf "$R"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

(cd "$LAB" && docker compose up -d fees knots-b2b bitcoind-sha)
bash "$LAB/scripts/wait-chains.sh"
(cd "$LAB" && docker compose up -d lf1 lf2 lf3 lnd-sha)

LAB=$LAB OUT=$ROOT/run BIN=$BIN RUN=$R nice -n 19 python3 "$ROOT/scripts/ln_rail/drive.py"
