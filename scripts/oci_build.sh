#!/bin/bash
# AGP-038: multi-arch OCI images of the agentpay services, saved locally (never pushed).
#   xbt-signer, xbt-anchor-witness, xbt-wallet-mcp, xbt402-hub; AGP-040: xbt-wallet-ui, xbt-init; AGP-043: xbt-work-relay
#   platforms linux/amd64, linux/arm64, linux/arm/v7, FROM scratch, static musl (zig), docs/CONTAINER.md
#
# Steps: build the static musl binaries for the three targets (release profile, cargo -j2 under the soak
# rules); stage them with the shared base layer (container/mkbase.py); `docker buildx build` each image
# for all three platforms into dist/oci/<image>.tar (an OCI archive with SOURCE_DATE_EPOCH = the commit
# time and rewritten timestamps). With --load, also load the images into the local Docker: the amd64 ones as
# <image>:agp038 (scripts/container_test.sh runs these), and every platform as <image>:<version> (the
# Umbrel apps and the StartOS package, packaging/, reference these). dist/oci/IMAGES.md gets digests and sizes.
#
# The Dockerfile has no RUN, so building the arm images needs no emulator (no binfmt, no qemu). The tool is
# docker buildx through the docker group (no sudo); this host has no rootless Docker, podman or buildah.
#   scripts/oci_build.sh [--load] [--skip-cargo] [--only IMAGE[,IMAGE...]]
# The binaries come from $CARGO_TARGET_DIR (default target/). --only builds a subset (the base layer is shared,
# so a subset's archives match the others only when built from the same mkbase.py).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
LOAD=0
CARGO=1
ONLY=""
while [ $# -gt 0 ]; do
  case $1 in
    --load) LOAD=1 ;;
    --skip-cargo) CARGO=0 ;;
    --only) ONLY=$2; shift ;;
    *) echo "usage: $0 [--load] [--skip-cargo] [--only IMAGE[,IMAGE...]]" >&2; exit 2 ;;
  esac
  shift
done
IMAGES=(xbt-signer xbt-anchor-witness xbt-wallet-mcp xbt402-hub xbt-wallet-ui xbt-init xbt-work-relay)
[ -n "$ONLY" ] && IMAGES=(${ONLY//,/ })
TGT=${CARGO_TARGET_DIR:-target}
want() { [[ " ${IMAGES[*]} " == *" $1 "* ]]; }
# rust target -> buildx TARGETARCH+TARGETVARIANT
declare -A ARCH=([x86_64-unknown-linux-musl]=amd64 [aarch64-unknown-linux-musl]=arm64 [armv7-unknown-linux-musleabihf]=armv7)
PLATFORMS=linux/amd64,linux/arm64,linux/arm/v7
SOAK=(nice -n 19)
command -v systemd-run >/dev/null && SOAK=(systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19)
REV=$(git rev-parse --short=12 HEAD)
DIRTY=$(git status --porcelain --untracked-files=no | grep -q . && echo "-dirty" || true)
EPOCH=$(git log -1 --format=%ct)
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
OUT=$ROOT/dist/oci
CTX=$OUT/ctx
mkdir -p "$OUT"
rm -rf "$CTX"
mkdir -p "$CTX"

if [ $CARGO = 1 ]; then
  for t in "${!ARCH[@]}"; do
    echo "== cargo build --release --target $t"
    if want xbt-signer || want xbt-anchor-witness; then
      "${SOAK[@]}" cargo build -q -j2 --release --target "$t" -p xbt-signer --bin xbt-signer --bin xbt-anchor-witness
    fi
    if want xbt-wallet-mcp; then "${SOAK[@]}" cargo build -q -j2 --release --target "$t" -p xbt-wallet-mcp; fi
    if want xbt402-hub; then "${SOAK[@]}" cargo build -q -j2 --release --target "$t" -p xbt402 --features rpc,http-client,http-server --bin xbt402-hub; fi
    if want xbt-wallet-ui || want xbt-init; then
      "${SOAK[@]}" cargo build -q -j2 --release --target "$t" -p xbt-wallet-ui -p xbt-svc --bin xbt-wallet-ui --bin xbt-init
    fi
    if want xbt-work-relay; then "${SOAK[@]}" cargo build -q -j2 --release --target "$t" -p xbt-work-relay --bin xbt-work-relay; fi
  done
fi
for t in "${!ARCH[@]}"; do
  mkdir -p "$CTX/bin/${ARCH[$t]}"
  for b in "${IMAGES[@]}"; do
    f=$TGT/$t/release/$b
    [ -x "$f" ] || { echo "oci_build: $f missing (run without --skip-cargo)" >&2; exit 1; }
    file -b "$f" | grep -q "statically linked" || { echo "oci_build: $f is not static: $(file -b "$f")" >&2; exit 1; }
    cp "$f" "$CTX/bin/${ARCH[$t]}/$b"
  done
done
python3 container/mkbase.py "$CTX/base.tar"
cp container/Dockerfile "$CTX/Dockerfile"

LABELS=(--label "org.opencontainers.image.source=xbt-rs (local)" --label "org.opencontainers.image.revision=$REV$DIRTY"
        --label "org.opencontainers.image.version=$VERSION" --label "org.opencontainers.image.licenses=MIT OR Apache-2.0"
        --label "xbt.task=AGP-038")
for img in "${IMAGES[@]}"; do
  echo "== buildx $img ($PLATFORMS)"
  docker buildx build -q --platform "$PLATFORMS" --target "$img" "${LABELS[@]}" \
    --label "org.opencontainers.image.title=$img" \
    --build-arg SOURCE_DATE_EPOCH="$EPOCH" -t "$img:$VERSION-$REV$DIRTY" \
    --output "type=oci,dest=$OUT/$img.tar,rewrite-timestamp=true" "$CTX" >/dev/null
  if [ $LOAD = 1 ]; then
    docker buildx build -q --platform linux/amd64 --target "$img" "${LABELS[@]}" --label "org.opencontainers.image.title=$img" \
      --build-arg SOURCE_DATE_EPOCH="$EPOCH" -t "$img:agp038" --load "$CTX" >/dev/null
    # every platform under the version tag (Docker's containerd image store keeps a multi-platform index)
    docker buildx build -q --platform "$PLATFORMS" --target "$img" "${LABELS[@]}" --label "org.opencontainers.image.title=$img" \
      --build-arg SOURCE_DATE_EPOCH="$EPOCH" -t "$img:$VERSION" --load "$CTX" >/dev/null
  fi
done
python3 scripts/oci_inspect.py "$OUT" "${IMAGES[@]}" --md "$OUT/IMAGES.md" --rev "$REV$DIRTY"
echo "oci_build: $OUT/{$(IFS=,; echo "${IMAGES[*]}")}.tar"
