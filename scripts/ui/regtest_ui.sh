#!/bin/bash
# AGP-039: the web UI on regtest, end to end. A private Knots 29.4.2 regtest node (B1's scripts/node.sh),
# the Rust xbt402 provider (price 150 sats), xbt-signer with the anchor witness, xbt-wallet-mcp over
# streamable HTTP with XBT_MCP_APPROVAL_WAIT_S, and xbt-wallet-ui. Then (regtest_ui.py):
#   an agent's over-threshold xbt402_pay through the MCP waits; the human logs in to the UI, sees it,
#   signs the approval (with `xbt-wallet-ui sign`, the "another device" path; the in-browser signing is
#   covered by tests/browser.rs) and submits it in the UI; the MCP call returns paid; the channel is
#   closed and the close is confirmed on chain; the UI shows the channel, its close report and an
#   intact, anchored signature log.
# Ports 33800-33899 (AGP-039): node RPC 33801, P2P 33802, provider 33810, MCP 33820, UI 33830.
# Soak rules: CPUQuota 200%, MemoryMax 4G, nice 19, cargo -j2. Starts no miners (blocks from
# generatetoaddress / the signer's regtest-only mining). Evidence: run/ui-regtest/<stamp>/.
set -euo pipefail
if [ -z "${UI_REGTEST_SCOPED:-}" ] && command -v systemd-run >/dev/null; then
  export UI_REGTEST_SCOPED=1
  exec systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19 "$0" "$@"
fi
cd "$(dirname "$0")/../.."
ROOT=$PWD
B1=${XBT402_B1:-$HOME/xbt-rnd/b1-agp-050}
[ -d "$B1" ] || B1=$HOME/xbt-rnd/b1
STAMP=$(date +%Y%m%d-%H%M%S)
R=$ROOT/run/ui-regtest/$STAMP
mkdir -p "$R"
export XBT_BIN=${XBT_BIN:-$HOME/lazarus-regtest/b1-xbt402/knots-29.4.2}
export XBT402_DATADIR=$R/node XBT402_RPCPORT=33801 XBT402_P2PPORT=33802 XBT402_MATURITY_PAD=6800
P_PROV=33810 P_MCP=33820 P_UI=33830
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  "$B1/scripts/node.sh" down >/dev/null 2>&1 || true
  [ -n "${UI_REGTEST_KEEP:-}" ] || rm -rf "$R/node"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

python3 "$HOME/xbt-rnd/xbt-063/tools/portcheck.py" wait --timeout 60 33801 33802 $P_PROV $P_MCP $P_UI
echo "== build (release, -j2)"
cargo build -q -j2 --release -p xbt-signer -p xbt-wallet-mcp -p xbt-wallet-ui -p xbt402-interop --bins
BIN=$ROOT/target/release
"$B1/scripts/node.sh" up
CLI=("$XBT_BIN/bitcoin-cli" -regtest -datadir="$XBT402_DATADIR" -rpcport=$XBT402_RPCPORT)
COOKIE=$XBT402_DATADIR/regtest/.cookie

echo "== provider"
"$BIN/xbt402-rust-provider" --port $P_PROV --rpc-port $XBT402_RPCPORT --cookie "$COOKIE" --price 150 --data-dir "$R/provider-data" >"$R/provider.log" 2>&1 & PIDS+=($!)
for _ in $(seq 100); do curl -s -o /dev/null "http://127.0.0.1:$P_PROV/x402/supported" && break; sleep 0.1; done

echo "== the human's key (on 'another device'), the signer's root and policy"
mkdir -p "$R/device" "$R/keys" "$R/wallet/.run" "$R/witness" "$R/ui"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$R/device/human.key"; chmod 600 "$R/device/human.key"
HUMAN_PUB=$("$BIN/xbt-wallet-ui" pubkey --key "$R/device/human.key")
cat >"$R/wallet/policy.json" <<JSON
{"allowlist": ["http://127.0.0.1:$P_PROV"], "counterparties": {}, "max_per_tx_sats": 5000, "daily_budget_sats": 100000,
 "weekly_budget_sats": 200000, "per_counterparty_cap_sats": 50000, "velocity_max": 60, "velocity_window_s": 3600,
 "human_threshold_sats": 1000, "split_window_s": 600, "approval_ttl_s": 900, "channel_expiry_blocks": 1008,
 "refund_enabled": true, "refund_margin_blocks": 6, "hot_balance_cap_sats": 0, "anchor_interval_s": 60, "anchor_required": true,
 "open_wait_s": 60, "human_pubkey": "$HUMAN_PUB"}
JSON

echo "== anchor witness, signer"
"$BIN/xbt-anchor-witness" serve --store "$R/witness" --sock "$R/witness/w.sock" >"$R/witness.log" 2>&1 & PIDS+=($!)
for _ in $(seq 50); do [ -S "$R/witness/w.sock" ] && break; sleep 0.1; done
export B2_ROOT=$R/wallet B2_DATADIR=$XBT402_DATADIR B2_RPCPORT=$XBT402_RPCPORT B2_WALLET=w B2_HOT_KEYFILE=$R/keys/hot.key \
       B2_ANCHOR_SOCK=$R/witness/w.sock B2_SIGNER_SOCK=$R/wallet/.run/signer.sock B2_WATCH_INTERVAL=5
"$BIN/xbt-signer" --root "$R/wallet" >"$R/signer.log" 2>&1 & PIDS+=($!)
for _ in $(seq 100); do [ -S "$B2_SIGNER_SOCK" ] && break; sleep 0.1; done
[ -S "$B2_SIGNER_SOCK" ] || { echo "signer did not start"; cat "$R/signer.log"; exit 1; }

echo "== MCP (HTTP, waits up to 180 s for the human), UI"
MCP_TOKEN=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')
XBT_MCP_HTTP_TOKEN=$MCP_TOKEN XBT_MCP_APPROVAL_WAIT_S=180 "$BIN/xbt-wallet-mcp" --http 127.0.0.1:$P_MCP >"$R/mcp.log" 2>&1 & PIDS+=($!)
printf 'regtest ui password %s\n' "$STAMP" | head -c -1 >"$R/ui/password"; chmod 600 "$R/ui/password"
XBT_UI_BIND=127.0.0.1:$P_UI XBT_UI_SIGNER_SOCK=$B2_SIGNER_SOCK XBT_UI_DATA_DIR=$R/ui/data XBT_UI_PASSWORD_FILE=$R/ui/password \
  "$BIN/xbt-wallet-ui" >"$R/ui.log" 2>&1 & PIDS+=($!)
for _ in $(seq 100); do curl -s -o /dev/null "http://127.0.0.1:$P_UI/healthz" && break; sleep 0.1; done

set +e
python3 "$ROOT/scripts/ui/regtest_ui.py" --out "$R" --sock "$B2_SIGNER_SOCK" --mcp "http://127.0.0.1:$P_MCP/mcp" --mcp-token "$MCP_TOKEN" \
  --ui "http://127.0.0.1:$P_UI" --ui-password-file "$R/ui/password" --human-key "$R/device/human.key" --sign-bin "$BIN/xbt-wallet-ui" \
  --provider "http://127.0.0.1:$P_PROV" --cli "${CLI[*]}" 2>&1 | tee "$R/regtest_ui.log"
rc=${PIPESTATUS[0]}
set -e
ln -sfn "$STAMP" "$ROOT/run/ui-regtest/latest"
echo "evidence: $R"
[ "$rc" -eq 0 ] && echo "regtest_ui: PASS" || { echo "regtest_ui: FAIL"; tail -20 "$R/signer.log"; exit 1; }
