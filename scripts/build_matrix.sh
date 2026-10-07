#!/bin/bash
# Cross-platform build matrix for xbt-primitives + xbt402 + the offline selftest example.
# Builds release and release-small for every AGP-031 target via zig (tools/zig-cc).
# Records sizes, glibc floor, and selftest status in dist/MATRIX.md.
# Soak: cargo -j2 under CPUQuota=200% / MemoryMax=4G / nice 19. No sudo, no binfmt.
set -euo pipefail
lazvault hold check --project xbt-agentpay || exit 75   # IMP-030: heavy entry point, refuses during a host hold
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

SOAK=(systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19)
JOBS=${CARGO_JOBS:-2}
DIST="$ROOT/dist"
LOGDIR="$DIST/logs"
mkdir -p "$DIST" "$LOGDIR"

HOST=$(rustc -vV | awk '/^host:/{print $2}')
RUSTC_V=$(rustc --version)
ZIG_PY=${XBT_ZIG_PY:-$HOME/.local/share/ziglang-venv/bin/python}
ZIG_V=$("$ZIG_PY" -m ziglang version 2>/dev/null || echo "missing")
GIT=$(git -C "$ROOT" rev-parse --short HEAD)
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# rustc triple | display name | abi note | glibc floor or "-"
TARGETS=(
  "x86_64-unknown-linux-gnu|x86_64 Linux glibc|host libc (typically newer than the 2.28 floor)|host"
  "x86_64-unknown-linux-musl|x86_64 Linux static musl|static musl|- "
  "aarch64-unknown-linux-gnu|aarch64 Linux glibc|zig -target aarch64-linux-gnu.2.28|2.28"
  "aarch64-unknown-linux-musl|aarch64 Linux static musl|static musl|-"
  "armv7-unknown-linux-gnueabihf|armv7 Linux glibc (hard-float)|zig -target arm-linux-gnueabihf.2.28|2.28"
  "armv7-unknown-linux-musleabihf|armv7 Linux static musl (hard-float)|static musl|-"
  "riscv64gc-unknown-linux-gnu|riscv64 Linux glibc|zig -target riscv64-linux-gnu.2.28|2.28"
  "x86_64-apple-darwin|macOS x86_64|zig -target x86_64-macos|-"
  "aarch64-apple-darwin|macOS arm64|zig -target aarch64-macos|-"
  "x86_64-pc-windows-gnu|Windows x86_64 (gnu)|zig -target x86_64-windows-gnu|-"
)

need_targets=()
for spec in "${TARGETS[@]}"; do
  t=${spec%%|*}
  if ! rustup target list --installed | grep -qx "$t"; then
    need_targets+=("$t")
  fi
done
if [ ${#need_targets[@]} -gt 0 ]; then
  echo "== rustup target add ${need_targets[*]}"
  rustup target add "${need_targets[@]}"
fi

if [ ! -x "$ZIG_PY" ]; then
  echo "zig python missing at $ZIG_PY (install ziglang wheel; see README)" >&2
  exit 1
fi

selftest_name() {
  local t=$1
  case "$t" in
    *-pc-windows-*) echo selftest.exe ;;
    *) echo selftest ;;
  esac
}

selftest_path() {
  local t=$1 profile=$2
  echo "$ROOT/target/$t/$profile/examples/$(selftest_name "$t")"
}

human_bytes() {
  local n=$1
  if [ "$n" -ge 1048576 ]; then
    awk -v n="$n" 'BEGIN{printf "%.2f MiB", n/1048576}'
  else
    awk -v n="$n" 'BEGIN{printf "%.1f KiB", n/1024}'
  fi
}

glibc_floor_of() {
  local bin=$1
  if command -v readelf >/dev/null && readelf -V "$bin" >/dev/null 2>&1; then
    local vers
    vers=$(readelf -V "$bin" 2>/dev/null | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sed 's/GLIBC_//' | sort -t. -k1,1n -k2,2n | tail -n1 || true)
    if [ -n "${vers:-}" ]; then
      echo "$vers"
      return
    fi
  fi
  echo "-"
}

file_kind() {
  local bin=$1
  if command -v file >/dev/null; then
    file -b "$bin" | tr ',|' ';/'
  else
    echo "unknown"
  fi
}

# Rows are pipe-separated; never let file(1) or selftest text inject extra columns.
sanitize() {
  printf '%s' "$1" | tr '|\n' '/ '
}

# Returns 0 if this host can execute the binary (native, or a user-mode emulator on PATH).
emulator_for() {
  local t=$1
  case "$t" in
    x86_64-unknown-linux-gnu|x86_64-unknown-linux-musl)
      [ "$HOST" = "x86_64-unknown-linux-gnu" ] && echo native && return 0
      command -v qemu-x86_64 >/dev/null && echo qemu-x86_64 && return 0
      ;;
    aarch64-unknown-linux-gnu|aarch64-unknown-linux-musl)
      command -v qemu-aarch64 >/dev/null && echo qemu-aarch64 && return 0
      ;;
    armv7-unknown-linux-gnueabihf|armv7-unknown-linux-musleabihf)
      command -v qemu-arm >/dev/null && echo qemu-arm && return 0
      ;;
    riscv64gc-unknown-linux-gnu)
      command -v qemu-riscv64 >/dev/null && echo qemu-riscv64 && return 0
      ;;
  esac
  return 1
}

run_selftest() {
  local t=$1 bin=$2
  local emu
  if ! emu=$(emulator_for "$t"); then
    echo "skipped (no user-mode emulator; not installing binfmt/qemu)"
    return 2
  fi
  local out rc
  if [ "$emu" = native ]; then
    set +e
    out=$("$bin" 2>&1)
    rc=$?
    set -e
  else
    set +e
    out=$("$emu" "$bin" 2>&1)
    rc=$?
    set -e
  fi
  if [ $rc -eq 0 ]; then
    echo "OK ($emu): $(echo "$out" | tr '\n' ' ')"
    return 0
  fi
  echo "FAIL ($emu, exit $rc): $(echo "$out" | tr '\n' ' ' | head -c 240)"
  return 1
}

build_one() {
  local t=$1 profile=$2
  local log="$LOGDIR/${t}.${profile}.log"
  local bin
  bin=$(selftest_path "$t" "$profile")
  echo "  cargo build -j$JOBS --profile $profile --target $t -p xbt402 --example selftest" >&2
  set +e
  "${SOAK[@]}" cargo build -j"$JOBS" --profile "$profile" --target "$t" -p xbt402 --example selftest >"$log" 2>&1
  local rc=$?
  set -e
  if [ $rc -ne 0 ]; then
    local why
    why=$(tail -n 40 "$log" | tr '\n' ' ' | head -c 400)
    echo "failed|$why"
    return
  fi
  if [ ! -f "$bin" ]; then
    echo "failed|build reported success but $bin missing"
    return
  fi
  local sz floor kind
  sz=$(stat -c%s "$bin")
  floor=$(glibc_floor_of "$bin")
  kind=$(file_kind "$bin")
  echo "built|$sz|$floor|$kind"
}

# rows: target|profile|status|size|glibc|kind|selftest
declare -a ROWS=()

echo "== xbt-rs build matrix  commit=$GIT  rustc=$RUSTC_V  zig=$ZIG_V  host=$HOST"
for spec in "${TARGETS[@]}"; do
  IFS='|' read -r t name abi floor_note <<<"$spec"
  echo "== $t  ($name)"
  for profile in release release-small; do
    result=$(build_one "$t" "$profile")
    status=${result%%|*}
    rest=${result#*|}
    st_note="-"
    sz="-"
    floor="-"
    kind="-"
    if [ "$status" = built ]; then
      IFS='|' read -r sz floor kind <<<"$rest"
      kind=$(sanitize "$kind")
      if [ "$profile" = release ]; then
        bin=$(selftest_path "$t" release)
        set +e
        st_note=$(run_selftest "$t" "$bin")
        st_rc=$?
        set -e
        if [ $st_rc -eq 0 ]; then st_note="ran: $st_note"
        fi
        st_note=$(sanitize "$st_note")
      else
        st_note="(see release)"
      fi
    else
      status="failed"
      kind=$(sanitize "$rest")
    fi
    ROWS+=("$t|$profile|$status|$sz|$floor|$kind|$st_note")
    echo "   $profile  $status  size=$sz  glibc=$floor"
  done
done

# Write MATRIX.md
{
  echo "# xbt-rs cross-platform build matrix"
  echo
  echo "Generated by \`scripts/build_matrix.sh\` on **$DATE**."
  echo
  echo "| field | value |"
  echo "|---|---|"
  echo "| commit | \`$GIT\` |"
  echo "| host | \`$HOST\` |"
  echo "| rustc | $RUSTC_V |"
  echo "| zig | $ZIG_V (\`tools/zig-cc\`) |"
  echo "| profiles | \`release\` (opt-level 3, thin LTO) and \`release-small\` (opt-level z, fat LTO, strip, panic=abort) |"
  echo "| crates | \`xbt-primitives\`, \`xbt402\`, example \`selftest\` |"
  echo "| linker | zig cc; GNU/Linux glibc floor **2.28** |"
  echo
  echo "## Matrix"
  echo
  echo "| target | profile | status | selftest bytes | human | glibc used | selftest |"
  echo "|---|---|---|---:|---:|---|---|"
  for row in "${ROWS[@]}"; do
    IFS='|' read -r t profile status sz floor kind st <<<"$row"
    human="-"
    if [ "$sz" != "-" ] && [ -n "$sz" ]; then
      human=$(human_bytes "$sz")
    fi
    # shorten kind for the table; full file(1) in details
    echo "| \`$t\` | $profile | $status | ${sz} | $human | $floor | $st |"
  done
  echo
  echo "## Per-target notes"
  echo
  for spec in "${TARGETS[@]}"; do
    IFS='|' read -r t name abi floor_note <<<"$spec"
    echo "### \`$t\`"
    echo
    echo "- **$name** — $abi. Configured glibc floor: \`$floor_note\`."
    for row in "${ROWS[@]}"; do
      IFS='|' read -r rt profile status sz floor kind st <<<"$row"
      if [ "$rt" != "$t" ]; then continue; fi
      echo "- **$profile:** $status"
      if [ "$status" = built ]; then
        echo "  - size: $sz bytes ($(human_bytes "$sz"))"
        echo "  - glibc symbols used: $floor"
        echo "  - file(1): $kind"
        if [ "$profile" = release ]; then
          echo "  - selftest: $st"
        fi
      else
        echo "  - why: $kind"
      fi
    done
    echo
  done
  echo "## How this is built"
  echo
  echo "- build host has no system cross toolchain and no sudo. \`tools/zig-cc\` drives \`python -m ziglang cc\` for libsecp256k1 and for rustc's link step."
  echo "- Musl targets are linked with \`-C target-feature=+crt-static\` so boards get a single static binary."
  echo "- Self-test is run only when the host can execute the binary (native x86_64), or when a user-mode emulator is already on PATH. This script never installs binfmt or qemu."
  echo "- Optional HTTP/RPC features (\`ureq\`, \`tiny_http\`) stay behind crate features and are not part of this matrix."
  echo "- Build logs: \`dist/logs/<target>.<profile>.log\`."
} > "$DIST/MATRIX.md"

echo "== wrote $DIST/MATRIX.md"
cat "$DIST/MATRIX.md"
