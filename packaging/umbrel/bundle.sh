#!/bin/bash
# AGP-040: a side-load bundle of the local Umbrel store, for a pilot on a box Mike chooses (never a store
# submission, never a registry). Writes dist/umbrel/:
#   lazarus-store/            the store folder to copy to the box (umbrel-app-store.yml + the three apps)
#   images-amd64.tar          `docker save` of the images for an x86_64 box (Umbrel Home, a PC)
#   images-arm64.tar          the same for a Raspberry Pi 4/5 (no XBT node stand-in: its image is amd64-only)
#   SHA256SUMS, IMAGES.txt    checksums; each image's id per platform (compare after `docker load`)
# Needs the images loaded (scripts/oci_build.sh --load) and xbt-a3-knots:29.4.2 (SOV-005/A3) for amd64.
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT=dist/umbrel
rm -rf "$OUT"
mkdir -p "$OUT/lazarus-store"
cp packaging/umbrel/umbrel-app-store.yml "$OUT/lazarus-store/"
for app in lazarus-xbt-knots lazarus-xbt-agent-wallet lazarus-xbt402-hub; do
  cp -r "packaging/umbrel/$app" "$OUT/lazarus-store/"
done
IMGS=(xbt-init:0.1.0 xbt-signer:0.1.0 xbt-anchor-witness:0.1.0 xbt-wallet-mcp:0.1.0 xbt-wallet-ui:0.1.0 xbt402-hub:0.1.0)
: >"$OUT/IMAGES.txt"
for plat in amd64 arm64; do
  extra=()
  [ $plat = amd64 ] && extra=(xbt-a3-knots:29.4.2)
  for i in "${IMGS[@]}" "${extra[@]}"; do
    echo "$plat $i $(docker image inspect --platform linux/$plat --format '{{.Id}}' "$i")" >>"$OUT/IMAGES.txt"
  done
  echo "== docker save linux/$plat"
  docker save --platform "linux/$plat" -o "$OUT/images-$plat.tar" "${IMGS[@]}" "${extra[@]}"
done
(cd "$OUT" && sha256sum images-*.tar >SHA256SUMS)
cat >"$OUT/README.txt" <<'TXT'
XBT Agent Wallet for Umbrel: local side-load bundle (AGP-040). Not in any app store.

On the box (ssh umbrel@umbrel.local):
  1. sha256sum -c SHA256SUMS
  2. docker load -i images-amd64.tar      (a Raspberry Pi: images-arm64.tar; it has no XBT node stand-in)
  3. mkdir -p ~/umbrel/app-stores/lazarus-local && cp -r lazarus-store/. ~/umbrel/app-stores/lazarus-local/
  4. umbrelOS adds community app stores by git URL: put lazarus-store/ in a private git repo the box can
     reach (a bare repo on the LAN), add it under App Store -> Community App Stores, then install
     "XBT Node (stand-in)", then "XBT Agent Wallet" (and "xbt402 Hub" if wanted). This step is unverified
     until the pilot box: umbrelOS dev tooling does not run rootless on the build host.
  5. Open XBT Agent Wallet; log in with the password the dashboard shows for it; Setup: enrol your approval
     key, sign a policy; Agents: copy the MCP endpoint and token into your agent.
TXT
ls -l "$OUT"
