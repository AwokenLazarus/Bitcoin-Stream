# XBT Node (stand-in) — amd64-only

This app is a **stand-in** until xbt-compute's node-host app (CMP-098, image `knots-xbt`) exists.
It reuses A3's `xbt-a3-knots:29.4.2`, which is **amd64-only** (linux/amd64). A Raspberry Pi or any
arm64 / arm/v7 Umbrel box **cannot** run this image.

## What to install on those boxes

Use CMP-098's real XBT node app when it ships. It **must export the same contract** this stand-in
already exports (`exports.sh`):

| variable | meaning |
|---|---|
| `APP_XBT_KNOTS_NODE_HOST` | container name of the node (`<app-id>_node_1`) |
| `APP_XBT_KNOTS_RPC_PORT` | RPC port (8332) |
| `APP_XBT_KNOTS_CHAIN` | `main` on a box; the wallet/hub apps read this |
| `APP_XBT_KNOTS_RPC_USER` | RPC user |
| `APP_XBT_KNOTS_RPC_PASS` | RPC password (`derive_entropy` on Umbrel) |

The wallet (`lazarus-xbt-agent-wallet`) and hub (`lazarus-xbt402-hub`) depend on these names only.
When CMP-098's app is installed, they do not change. Until then, an arm box needs an external
XBT (BLAKE2b) node and cannot use this stand-in.

## Why this image is not rebuilt here

A multi-arch Knots 29.4.2 image is a full Bitcoin Core / Knots build (hours, large toolchain),
not an agentpay packaging job. Soak rules (CPUQuota 200%, MemoryMax 4G, cargo -j2) make that
infeasible on the build host. CMP-098 owns the shipping multi-arch node.

## Side-load

`packaging/umbrel/bundle.sh` writes `images-amd64.tar` (includes this node) and `images-arm64.tar`
(wallet, hub, init only — **no** stand-in node).
