#!/bin/bash
# AGP-035: build xbt-rs the way xbt-compute (cmp) builds it - from a clean checkout, with no .cargo
# config, cross-compiled with cargo-zigbuild 0.23.4 and zig 0.16.0.
#
#   scripts/cmp_clean_build.sh [REF]          (REF: branch, tag or commit of this repo; default main)
#
# 1. git clone of this repo into a temp dir, checkout REF, delete .cargo/ (our zig-cc linker config);
#    refuse if any other cargo config or build env could still steer the build;
# 2. serde_json is built without arbitrary_precision (cmp's feature unification);
# 3. cargo zigbuild --release --locked for x86_64/aarch64-unknown-linux-musl and
#    armv7-unknown-linux-musleabihf: `-p xbt402 --no-default-features`, `-p xbt-signer` and (AGP-030)
#    `-p xbt-wallet-mcp`; every
#    binary must be a static ELF of the right machine;
# 4. a cmp-shaped consumer outside the repo: xbt402 + xbt-signer as git dependencies at REF's commit,
#    default-features = false, its own serde_json (no features), built for aarch64 musl.
#
# Env: XBT_ZIGBUILD (default ~/xbt-rnd/tools/zigbuild/bin/cargo-zigbuild, installed with
#   cargo install --locked cargo-zigbuild@0.23.4 --root ~/xbt-rnd/tools/zigbuild),
#   XBT_ZIG_VENV (the ziglang 0.16.0 venv, default ~/.local/share/ziglang-venv),
#   XBT_CLEAN_TARGETS (space separated), XBT_CLEAN_KEEP=1 keeps the temp dir.
# Soak rules: CPUQuota 200%, 4G, nice 19, cargo -j2. Writes nothing in this repo.
set -euo pipefail
lazvault hold check --project xbt-agentpay || exit 75   # IMP-030: heavy entry point, refuses during a host hold
ROOT=$(cd "$(dirname "$0")/.." && pwd)
REF=${1:-main}
ZB=${XBT_ZIGBUILD:-$HOME/xbt-rnd/tools/zigbuild/bin/cargo-zigbuild}
ZIGVENV=${XBT_ZIG_VENV:-$HOME/.local/share/ziglang-venv}
read -r -a TARGETS <<< "${XBT_CLEAN_TARGETS:-x86_64-unknown-linux-musl aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf}"
SOAK=(systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19)
W=$(mktemp -d "${TMPDIR:-/tmp}/xbt-clean-build.XXXXXX")
[ -n "${XBT_CLEAN_KEEP:-}" ] && echo "kept: $W" || trap 'rm -rf "$W"' EXIT
FAIL=0
bad() { echo "  FAIL  $*"; FAIL=1; }

echo "== toolchain"
[ -x "$ZB" ] || { echo "no cargo-zigbuild at $ZB (see the header)"; exit 1; }
zbv=$("$ZB" --version); echo "  $zbv"
[ "$zbv" = "cargo-zigbuild 0.23.4" ] || bad "want cargo-zigbuild 0.23.4"
# cargo-zigbuild finds zig as `python3 -m ziglang` when there is no zig on PATH: the venv's python3 first
export PATH="$ZIGVENV/bin:$PATH"
zv=$(python3 -m ziglang version); echo "  zig $zv ($ZIGVENV)"
[ "$zv" = "0.16.0" ] || bad "want zig 0.16.0"
echo "  $(cargo --version), $(rustc --version)"

echo "== 1. clean checkout of $REF, no .cargo"
git clone -q "$ROOT" "$W/xbt-rs"
git -C "$W/xbt-rs" checkout -q --detach "$REF"
REV=$(git -C "$W/xbt-rs" rev-parse HEAD)
rm -rf "$W/xbt-rs/.cargo"
echo "  $REV (.cargo/ deleted)"
# nothing else may configure the build: cargo reads .cargo/config* in every parent dir and in CARGO_HOME
d="$W/xbt-rs"
while [ "$d" != / ]; do
  for c in "$d/.cargo/config" "$d/.cargo/config.toml"; do [ -e "$c" ] && bad "cargo config in effect: $c"; done
  d=$(dirname "$d")
done
for c in "${CARGO_HOME:-$HOME/.cargo}/config" "${CARGO_HOME:-$HOME/.cargo}/config.toml"; do [ -e "$c" ] && bad "cargo config in effect: $c"; done
for v in $(env | grep -oE '^(RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_BUILD_[A-Z_]+|CARGO_TARGET_[A-Z0-9_]+|CARGO_PROFILE_[A-Z0-9_]+|CC|CXX|AR|CFLAGS|CC_[a-z0-9_]+|AR_[a-z0-9_]+|CFLAGS_[a-z0-9_]+|TARGET_CC|TARGET_AR)=' | tr -d =); do
  echo "  unset $v"; unset "$v"
done
export CARGO_TARGET_DIR="$W/target"
[ "$FAIL" = 0 ] || exit 1

echo "== 2. serde_json features (cmp must not inherit arbitrary_precision)"
feats=$(cd "$W/xbt-rs" && cargo tree -e features -i serde_json --workspace --all-features --locked 2>/dev/null | grep -oE 'serde_json feature "[a-z_]+"' | sort -u | tr '\n' ' ')
echo "  $feats"
case "$feats" in *arbitrary_precision*) bad "arbitrary_precision is on";; esac

machine() {
  case "$1" in
    x86_64-*) echo "x86-64" ;;
    aarch64-*) echo "aarch64" ;;
    armv7-*) echo "ARM" ;;
  esac
}

check_bin() { # target path
  local f; f=$(file -b "$2")
  if [[ "$f" == *"$(machine "$1")"* && "$f" == *"statically linked"* || "$f" == *"$(machine "$1")"* && "$f" == *"static-pie linked"* ]]; then
    printf "  ok    %-32s %-24s %8s bytes\n" "$1" "$(basename "$2")" "$(stat -c %s "$2")"
  else
    bad "$1 $(basename "$2"): $f"
  fi
}

echo "== 3. cargo zigbuild --release --locked"
for t in "${TARGETS[@]}"; do
  for spec in "-p xbt402 --no-default-features" "-p xbt-signer" "-p xbt-wallet-mcp"; do
    # shellcheck disable=SC2086
    if (cd "$W/xbt-rs" && "${SOAK[@]}" "$ZB" zigbuild -q -j2 --release --locked --target "$t" $spec) > "$W/build.log" 2>&1; then
      echo "  built $t $spec"
    else
      tail -20 "$W/build.log"; bad "$t $spec"
    fi
  done
  [ -f "$W/target/$t/release/libxbt402.rlib" ] && echo "  ok    $t libxbt402.rlib" || bad "$t: no libxbt402.rlib"
  for b in xbt-signer xbt-anchor-witness xbt-signer-payer xbt-wallet-mcp; do
    [ -f "$W/target/$t/release/$b" ] && check_bin "$t" "$W/target/$t/release/$b" || bad "$t: no $b"
  done
done

echo "== 4. a cmp-shaped consumer: git dependencies at $REV, default-features = false"
C="$W/consumer"
mkdir -p "$C/src"
cat > "$C/Cargo.toml" <<EOF
[package]
name = "cmp-shaped-consumer"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
xbt402 = { git = "file://$W/xbt-rs", rev = "$REV", default-features = false }
xbt-signer = { git = "file://$W/xbt-rs", rev = "$REV", default-features = false }
serde_json = "1"
EOF
cat > "$C/src/main.rs" <<'EOF'
// Links the cmp surface: provider, client (+ signer seam, client ledger), routing payer, the signer
// client, and a big amsat integer through xbt402's JSON.
use xbt402::client::{Client, ClientLedger};
use xbt402::provider::Provider;
use xbt402::route_client::RoutePayer;
fn main() {
    let v = xbt402::json::parse(r#"{"amsatPerCall": 813000000000123456789}"#).unwrap();
    assert_eq!(xbt402::json::dumps_compact(&v), r#"{"amsatPerCall":813000000000123456789}"#);
    let _ = (std::mem::size_of::<Provider>(), std::mem::size_of::<Client>(), std::mem::size_of::<RoutePayer>());
    let _: Option<&dyn ClientLedger> = None;
    let _ = xbt_signer::client::SignerClient::new;
    println!("ok");
}
EOF
cp "$W/xbt-rs/Cargo.lock" "$C/Cargo.lock"
ct=aarch64-unknown-linux-musl
if (cd "$C" && "${SOAK[@]}" "$ZB" zigbuild -q -j2 --release --target "$ct") > "$W/consumer.log" 2>&1; then
  check_bin "$ct" "$W/target/$ct/release/cmp-shaped-consumer"
  cfeats=$(cd "$C" && cargo tree -e features -i serde_json 2>/dev/null | grep -oE 'serde_json feature "[a-z_]+"' | sort -u | tr '\n' ' ')
  echo "  consumer serde_json: $cfeats"
  case "$cfeats" in *arbitrary_precision*) bad "arbitrary_precision reaches the consumer";; esac
  if [ "$(uname -m)" = x86_64 ]; then
    (cd "$C" && "${SOAK[@]}" "$ZB" zigbuild -q -j2 --release --target x86_64-unknown-linux-musl) > "$W/consumer.log" 2>&1 \
      && out=$("$W/target/x86_64-unknown-linux-musl/release/cmp-shaped-consumer") && [ "$out" = ok ] \
      && echo "  ok    consumer runs (x86_64 musl): $out" || { tail -20 "$W/consumer.log"; bad "consumer run"; }
  fi
else
  tail -30 "$W/consumer.log"; bad "consumer build"
fi

[ "$FAIL" = 0 ] && echo "cmp_clean_build: OK ($REV, ${TARGETS[*]})" || { echo "cmp_clean_build: FAIL"; exit 1; }
