#!/bin/bash
# AGP-040: every check result.md reports. Soak rules (CPUQuota 200%, MemoryMax 4G, nice 19, cargo -j2).
#   1. xbt-svc (layout, xbt-init) + xbt-wallet-ui (the Agents page) suites, the hub's env-number test
#   2. the whole workspace
#   3. clippy: no warning in xbt-svc, xbt-wallet-ui or xbt402-hub.rs
#   4. the six images for amd64, arm64, arm/v7 (scripts/oci_build.sh --load; oci_inspect)
#   5. AGP-038's container test on the new images (the base layer changed: the UI's user and data dir)
#   6. the Umbrel apps: lint + two cold regtest installs (packaging/umbrel/test-umbrel-apps.sh, ports 34000-34099)
#   7. the StartOS package: build, inspect both .s9pk, the StartOS-shaped regtest run (ports 34100-34199)
#   8. the Umbrel side-load bundle (packaging/umbrel/bundle.sh; dist/umbrel, git-ignored)
set -euo pipefail
if [ -z "${VERIFY_SCOPED:-}" ] && command -v systemd-run >/dev/null; then
  export VERIFY_SCOPED=1
  export UMBREL_TEST_SCOPED=1 STARTOS_TEST_SCOPED=1
  exec systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19 "$0" "$@"
fi
cd "$(dirname "$0")/.."
step() { echo; echo "== $*"; }
step "1. xbt-svc + xbt-wallet-ui suites, xbt402-hub env numbers"
cargo test -q -j2 -p xbt-svc -p xbt-wallet-ui 2>&1 | grep -E "test result|FAILED|panicked" | grep -v " 0 passed"
cargo test -q -j2 -p xbt402 --features rpc,http-client,http-server --bin xbt402-hub 2>&1 | grep -E "test result|FAILED|panicked"
step "2. workspace"
cargo test -q -j2 --workspace 2>&1 | grep -E "test result|FAILED" | awk '{p+=$4; f+=$6} END {print "workspace: " p " passed, " f " failed"; exit f>0}'
step "3. clippy (xbt-svc, xbt-wallet-ui, xbt402-hub.rs)"
# (warnings elsewhere in the workspace predate AGP-040)
n=$(cargo clippy -q -j2 -p xbt-svc -p xbt-wallet-ui --all-targets 2>&1 | grep -cE "^ *--> crates/(xbt-svc|xbt-wallet-ui)/" || true)
m=$(cargo clippy -q -j2 -p xbt402 --features rpc,http-client,http-server --bin xbt402-hub 2>&1 | grep -cE "^ *--> crates/xbt402/src/bin/xbt402-hub.rs" || true)
echo "clippy warnings: xbt-svc + xbt-wallet-ui $n, xbt402-hub.rs $m"; [ "$n" = 0 ] && [ "$m" = 0 ]
step "4. images (6 x 3 platforms)"
mkdir -p run/verify-agp040
scripts/oci_build.sh --load >run/verify-agp040/oci_build.log 2>&1
grep -E "^Shared base layer|^- \`|^Checks" dist/oci/IMAGES.md
grep -q "^Checks: PASS" dist/oci/IMAGES.md
step "5. AGP-038 container test (new images)"
scripts/container_test.sh --skip-build 2>&1 | grep -E "checks passed|container_test:|FAIL"
step "6. Umbrel apps"
RUNS=2 packaging/umbrel/test-umbrel-apps.sh 2>&1 | grep -E "lint (PASS|FAIL)|refused|checks passed|RESULT|run [0-9]:|FAIL|evidence"
step "7. StartOS package"
packaging/startos/test-startos.sh 2>&1 | grep -E "\"ok\"|bytes|checks passed|RESULT|FAIL|evidence"
step "8. Umbrel side-load bundle"
packaging/umbrel/bundle.sh | tail -8
echo; echo "verify_agp040: PASS"
