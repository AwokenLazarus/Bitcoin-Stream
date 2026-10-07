#!/bin/bash
# AGP-040: build the StartOS package (packaging/startos/xbt-agent-wallet) into dist/startos/:
# xbt-agent-wallet_x86_64.s9pk and xbt-agent-wallet_aarch64.s9pk. Side-load only: never `make publish`.
#   - needs the images loaded (scripts/oci_build.sh --load): pack takes each arch from the local Docker;
#   - start-cli 2.1.0 (START_CLI, default ~/.local/opt/start-cli/start-cli) and the tar2sqfs shim (tools/);
#   - node/npm for the TypeScript (npm ci, tsc, the SDK's eslint, ncc).
# start-cli packs only inside a packaging workspace (a directory with .startos/: its config and the build key
# that signs the package). It lives outside the repo, so no key is committed: STARTOS_WS, default
# ~/.local/share/xbt-startos-ws, made once with `start-cli s9pk init-workspace`. packaging/startos/.startos is a
# git-ignored symlink to it, so the package is packed in place and its manifest records the commit.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
PKG=$HERE/xbt-agent-wallet
START_CLI=${START_CLI:-$HOME/.local/opt/start-cli/start-cli}
[ -x "$START_CLI" ] || { echo "build: start-cli missing at $START_CLI (github.com/Start9Labs/start-technologies releases, start-cli/v2.1.0)" >&2; exit 1; }
for i in xbt-init xbt-signer xbt-anchor-witness xbt-wallet-mcp xbt-wallet-ui xbt402-hub; do
  for p in linux/amd64 linux/arm64; do
    docker image inspect --platform "$p" "$i:0.1.0" >/dev/null 2>&1 || { echo "build: $i:0.1.0 ($p) not loaded (scripts/oci_build.sh --load)" >&2; exit 1; }
  done
done
BIN=$(mktemp -d)
trap 'rm -rf "$BIN"' EXIT
ln -s "$START_CLI" "$BIN/start-cli"
export PATH=$BIN:$HERE/tools:$PATH
WS=${STARTOS_WS:-$HOME/.local/share/xbt-startos-ws}
if [ ! -f "$WS/.startos/config.yaml" ]; then
  mkdir -p "$WS"
  (cd "$WS" && start-cli s9pk init-workspace .)
fi
ln -sfn "$WS/.startos" "$HERE/.startos"
cd "$PKG"
[ -d node_modules ] || npm ci --no-audit --no-fund
npm run -s check
node node_modules/@start9labs/start-sdk/lint.mjs
npm run -s build
mkdir -p "$ROOT/dist/startos"
for arch in x86_64 aarch64; do
  echo "== pack $arch"
  start-cli s9pk pack --arch="$arch" -o "$ROOT/dist/startos/xbt-agent-wallet_$arch.s9pk"
done
ls -l "$ROOT/dist/startos/"
