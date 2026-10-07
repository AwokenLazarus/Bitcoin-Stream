#!/bin/bash
# AGP-039: every check result.md reports. Soak rules (CPUQuota 200%, MemoryMax 4G, nice 19, cargo -j2).
#   1. the signer, MCP and UI suites (the UI's include auth/CSRF/every action over HTTP, the JS crypto
#      cross-check and the headless Chrome run when node and Chrome are installed)
#   2. the whole workspace
#   3. clippy: no warning in the new crate
#   4. the JS crypto vectors (node)
#   5. static musl builds of xbt-wallet-ui for x86_64, aarch64, armv7 (sizes)
#   6. regtest end to end (scripts/ui/regtest_ui.sh, ports 33800-33899)
set -euo pipefail
if [ -z "${VERIFY_SCOPED:-}" ] && command -v systemd-run >/dev/null; then
  export VERIFY_SCOPED=1
  exec systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19 "$0" "$@"
fi
cd "$(dirname "$0")/../.."
export XBT_UI_SNAPSHOT_DIR=${XBT_UI_SNAPSHOT_DIR:-$PWD/target/ui-browser}
step() { echo; echo "== $*"; }
step "1. signer + MCP + UI suites"
cargo test -q -j2 -p xbt-signer -p xbt-wallet-mcp -p xbt-wallet-ui 2>&1 | grep -E "test result|FAILED|panicked|skipped" | grep -v " 0 passed"
step "2. workspace"
cargo test -q -j2 --workspace 2>&1 | grep -E "test result|FAILED" | awk '{p+=$4; f+=$6} END {print "workspace: " p " passed, " f " failed"; exit f>0}'
step "3. clippy (xbt-wallet-ui)"
# (warnings elsewhere in the workspace predate AGP-039)
n=$(cargo clippy -q -j2 -p xbt-wallet-ui --all-targets 2>&1 | grep -cE "^ *--> crates/xbt-wallet-ui/" || true)
echo "clippy warnings in crates/xbt-wallet-ui: $n"; [ "$n" = 0 ]
step "4. JS crypto vectors"
NODE=$(command -v node || echo "$HOME/.local/share/nodejs/bin/node")
"$NODE" crates/xbt-wallet-ui/tests/js/crypto_test.mjs
step "5. static musl builds"
for t in x86_64-unknown-linux-musl aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf; do
  cargo build -q -j2 --profile release-small -p xbt-wallet-ui --target $t
  echo "$t $(stat -c %s target/$t/release-small/xbt-wallet-ui) bytes"
done
step "6. regtest end to end"
scripts/ui/regtest_ui.sh 2>&1 | grep -E "PASS|FAIL|checks passed|regtest_ui:|evidence"
echo; echo "verify_agp039: PASS"
