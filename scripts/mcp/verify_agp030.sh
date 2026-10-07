#!/bin/bash
# AGP-030 verify: everything result.md reports, in one run, at this commit.
#   scripts/mcp/verify_agp030.sh            (add CLAUDE=0 to skip the two real-Claude flagships, ~$0.25 each)
# Needs: ~/xbt-rnd/xbt-063-agp-030 (xbt-063 branch agp-030) with its .venv (mcp 2.2.0), ~/xbt-rnd/b2 at
# b4f2fe5, hermes on PATH, claude on PATH. Ports 33500-33599. Soak rules: CPUQuota 200%, 4G, nice 19, -j2.
set -uo pipefail
cd "$(dirname "$0")/../.."
ROOT=$PWD
X63=${XBT063:-$HOME/xbt-rnd/xbt-063-agp-030}
PY=$HOME/xbt-rnd/xbt-063/.venv/bin/python
B2=${B2_TREE:-$HOME/xbt-rnd/b2}
SOAK=(systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19)
declare -a RES=()
step() {   # label, command...
  local label=$1; shift
  echo "==== $label"
  local t0=$SECONDS
  "$@"
  local rc=$?
  RES+=("$( [ $rc -eq 0 ] && echo PASS || echo "FAIL($rc)" )  $label  ($((SECONDS - t0)) s)")
  echo "==== $label: rc=$rc"
}
flagship() {   # label, env...
  local label=$1; shift
  (cd "$X63" && env FLAGSHIP_PORT_BASE=33500 "$@" XBT_WALLET_MCP="$ROOT/target/release/xbt-wallet-mcp" XBT_SIGNER="$ROOT/target/release/xbt-signer" \
     "${SOAK[@]}" ./flagship.sh) >"$ROOT/run/verify-$label.log" 2>&1
  local rc=$?
  grep -E "^\s+FAIL|^flagship:|^evidence:|agent:|Tools discovered|model probe|MCP_IMPL=|XBT_MCP_PAYER" "$ROOT/run/verify-$label.log"
  return $rc
}
mkdir -p run
echo "AGP-030 verify: xbt-rs $(git rev-parse --short HEAD), xbt-063 $(git -C "$X63" rev-parse --short HEAD), b2 $(git -C "$B2" rev-parse --short HEAD), $(date -u +%FT%TZ)"
step "build (release, -j2)" "${SOAK[@]}" cargo build -q -j2 --release -p xbt-wallet-mcp -p xbt-signer --bins
step "cargo test --workspace" bash -c "${SOAK[*]} cargo test -q -j2 --workspace 2>&1 | grep -E '^test result' | awk '{p+=\$4; f+=\$6} END {print \"tests passed\", p, \"failed\", f; exit f>0}'"
step "no serde_json arbitrary_precision" bash -c "! cargo tree -e features -i serde_json --workspace 2>/dev/null | grep -q arbitrary_precision"
step "protocol conformance vs B2 (mock signer)" python3 scripts/mcp/mcp_conformance.py --py "$PY" --b2 "$B2" --rust target/release/xbt-wallet-mcp --out run/verify-mcp-conformance.json
step "Python SDK streamable HTTP vs B2 stdio" python3 scripts/mcp/http_sdk_check.py --py "$PY" --b2 "$B2" --rust target/release/xbt-wallet-mcp
step "regtest conformance, both signers" env XBT063="$X63" scripts/mcp/regtest_conformance.sh
step "scripted flagship, Rust MCP + Rust signer + local payer" flagship rust-rust-local FLAGSHIP_AGENT=script MCP_IMPL=rust SIGNER_IMPL=rust LOCAL_PAYER_TEST=1
step "Hermes (MCP-level), Rust MCP" flagship hermes FLAGSHIP_AGENT=hermes MCP_IMPL=rust
if [ "${CLAUDE:-1}" != 0 ]; then
  step "REAL CLAUDE flagship, Rust MCP (B2 Python signer)" flagship claude-rust MCP_IMPL=rust FLAGSHIP_MAX_USD=3
  step "REAL CLAUDE flagship, Rust MCP + Rust signer" flagship claude-rust-rust MCP_IMPL=rust SIGNER_IMPL=rust FLAGSHIP_MAX_USD=3
fi
step "cmp_clean_build (clean clone, cargo-zigbuild, 3 musl targets)" scripts/cmp_clean_build.sh "$(git rev-parse HEAD)"
step "no scoped miners left on 33500-33599" python3 "$HOME/xbt-rnd/tools/miners_left.py" 33500-33599
echo
echo "==== summary"
printf '%s\n' "${RES[@]}"
! printf '%s\n' "${RES[@]}" | grep -q "^FAIL"
