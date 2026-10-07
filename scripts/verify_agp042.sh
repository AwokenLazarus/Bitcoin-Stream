#!/bin/bash
# AGP-042: box packaging gaps. Soak rules (CPUQuota 200%, MemoryMax 4G, nice 19, cargo -j2).
# Ports for packaging runs: 34200-34299 (do not collide with AGP-040 34000 / StartOS 34100).
# Shared CARGO_TARGET_DIR=~/xbt-rnd/xbt-rs-target.
#   1. xbt-svc, xbt-wallet-ui, xbt-wallet-mcp, xbt402-hub tests (incl. the token rotation: the UI owns the
#      token file, the MCP only reads it and has no rotation endpoint, docs/CONTAINER.md §10)
#   2. clippy: no warning in those crates / xbt402-hub.rs
#   3. Umbrel store lint
#   4. no MCP rotation endpoint left; compose/spec mount run/ui (UI rw, MCP ro)
#   5. (PACKAGING=1) images + one Umbrel cold run + StartOS build, inspect and spec run, all on 34200-34299
set -euo pipefail
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/xbt-rnd/xbt-rs-target}"
if [ -z "${VERIFY_SCOPED:-}" ] && command -v systemd-run >/dev/null; then
  export VERIFY_SCOPED=1
  export UMBREL_TEST_SCOPED=1 STARTOS_TEST_SCOPED=1
  exec systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19 "$0" "$@"
fi
cd "$(dirname "$0")/.."
step() { echo; echo "== $*"; }
step "1. xbt-svc + xbt-wallet-ui + xbt-wallet-mcp + xbt402-hub"
cargo test -q -j2 -p xbt-svc -p xbt-wallet-ui -p xbt-wallet-mcp --all-targets 2>&1 | grep -E "test result|FAILED|panicked" | grep -v " 0 passed"
cargo test -q -j2 -p xbt402 --features rpc,http-client,http-server --bin xbt402-hub 2>&1 | grep -E "test result|FAILED|panicked"
step "2. clippy (xbt-svc, xbt-wallet-ui, xbt-wallet-mcp, xbt402-hub.rs)"
n=$(cargo clippy -q -j2 -p xbt-svc -p xbt-wallet-ui -p xbt-wallet-mcp --all-targets 2>&1 | grep -cE "^ *--> crates/(xbt-svc|xbt-wallet-ui|xbt-wallet-mcp)/" || true)
m=$(cargo clippy -q -j2 -p xbt402 --features rpc,http-client,http-server --bin xbt402-hub 2>&1 | grep -cE "^ *--> crates/xbt402/src/bin/xbt402-hub.rs" || true)
echo "clippy warnings: crates $n, xbt402-hub.rs $m"; [ "$n" = 0 ] && [ "$m" = 0 ]
step "3. Umbrel lint"
python3 packaging/umbrel/lint.py packaging/umbrel
step "4. Knots CMP-098 contract documented"
grep -q 'APP_XBT_KNOTS_NODE_HOST' packaging/umbrel/lazarus-xbt-knots/README.md
grep -q 'amd64-only' packaging/umbrel/lazarus-xbt-knots/README.md
grep -q 'XBT_HUB_ONION' packaging/umbrel/lazarus-xbt402-hub/docker-compose.yml
echo "docs/compose contract: ok"
step "4b. token rotation: no MCP rotation endpoint; run/ui mounts"
if grep -rn 'rotate-token\|X-XBT-Rotate\|ROTATE_URL' crates/xbt-wallet-mcp/src packaging/umbrel/lazarus-* packaging/startos/xbt-agent-wallet/startos; then
  echo "a rotation endpoint or its URL is still wired to the MCP" >&2; exit 1
fi
grep -q 'data/run/ui:/data/run/ui:ro' packaging/umbrel/lazarus-xbt-agent-wallet/docker-compose.yml
grep -qE 'data/run/ui:/data/run/ui$' packaging/umbrel/lazarus-xbt-agent-wallet/docker-compose.yml
grep -q "vol('run/ui', '/data/run/ui', true)" packaging/startos/xbt-agent-wallet/startos/spec.ts
grep -q '"xbt-wallet-ui": "xbt-wallet-mcp"' container/mkbase.py
echo "rotation contract: ok"
if [ "${PACKAGING:-}" = 1 ]; then
  step "5. images + Umbrel + StartOS (ports 34200-34299)"
  mkdir -p run/verify-agp042
  scripts/oci_build.sh --load >run/verify-agp042/oci_build.log 2>&1
  grep -q "^Checks: PASS" dist/oci/IMAGES.md
  # the shared target dir is shared with other worktrees (same crate hashes): prove these are this branch's binaries
  for a in amd64 arm64 armv7; do
    f=dist/oci/ctx/bin/$a/xbt-wallet-mcp
    grep -qa XBT_MCP_HTTP_TOKEN_FILE "$f" && ! grep -qa rotate-token "$f" || { echo "$f is not this branch's MCP" >&2; exit 1; }
  done
  echo "images: this branch's MCP (token file, no rotate endpoint) for amd64, arm64, armv7"
  export UMBREL_TEST_PORTS=34210-34250 UMBREL_TEST_MCP_PORT=34210 UMBREL_TEST_HUB_PORT=34220 UMBREL_TEST_UI_PORT=34230
  export UMBREL_TEST_PROV_PORT=34240 UMBREL_TEST_PROXY_PORT=34250
  export STARTOS_TEST_PORTS=34260-34290 STARTOS_TEST_MCP_PORT=34260 STARTOS_TEST_HUB_PORT=34270 STARTOS_TEST_UI_PORT=34280
  export STARTOS_TEST_PROV_PORT=34290
  RUNS=1 packaging/umbrel/test-umbrel-apps.sh 2>&1 | grep -E "lint (PASS|FAIL)|refused|RESULT|run [0-9]:|FAIL|evidence"
  packaging/startos/test-startos.sh 2>&1 | grep -E "\"ok\"|bytes|checks passed|RESULT|FAIL|evidence"
fi
echo; echo "verify_agp042: PASS"
