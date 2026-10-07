#!/bin/bash
# AGP-040 verify for the StartOS package: build it (build.sh: tsc, the SDK's eslint, ncc, `start-cli s9pk pack`
# for x86_64 and aarch64), check both .s9pk files (manifest, images per arch, static ELF of the right arch,
# image users), then run the package's own container spec on regtest the way StartOS does
# (test/startos_regtest.py). No StartOS VM runs here (no KVM for this user); a real-box test needs Mike.
# Ports 34100-34199 on 127.0.0.1 only (STARTOS_TEST_PORTS=LO-HI and STARTOS_TEST_{MCP,HUB,UI,PROV}_PORT move them). Soak rules: CPUQuota 200%, MemoryMax 4G, nice 19. Never publishes.
# Evidence: run/startos-test/<stamp>/.
set -euo pipefail
if [ -z "${STARTOS_TEST_SCOPED:-}" ] && command -v systemd-run >/dev/null; then
  export STARTOS_TEST_SCOPED=1
  exec systemd-run --user --scope -q -p CPUQuota=200% -p MemoryMax=4G nice -n 19 "$0" "$@"
fi
cd "$(dirname "$0")/../.."
ROOT=$PWD
STAMP=$(date +%Y%m%d-%H%M%S)
OUT=$ROOT/run/startos-test/$STAMP
mkdir -p "$OUT"
PORTS=${STARTOS_TEST_PORTS:-34100-34199}
busy=$(ss -ltnH | awk '{print $4}' | sed 's/.*://' | awk -v lo="${PORTS%-*}" -v hi="${PORTS#*-}" '$1>=lo && $1<=hi' | sort -u | tr '\n' ' ')
[ -z "$busy" ] || { echo "test-startos: ports busy in $PORTS: $busy" >&2; exit 1; }
START_CLI=${START_CLI:-$HOME/.local/opt/start-cli/start-cli}

echo "== build (packaging/startos/build.sh)"
packaging/startos/build.sh 2>&1 | tee "$OUT/build.log" | grep -E "^== |s9pk$|error|Error" || true
[ "${PIPESTATUS[0]}" -eq 0 ] || { echo "RESULT FAIL (build)"; exit 1; }

echo "== inspect the .s9pk files"
python3 - "$START_CLI" "$ROOT/dist/startos" "$OUT" <<'PY' | tee "$OUT/inspect.log"
import json, os, subprocess, sys, tempfile
cli, d, out = sys.argv[1:4]
ELF = {"x86_64": 0x3E, "aarch64": 0xB7}
IMAGES = {"init": ("xbt-init", "0:0"), "signer": ("xbt-signer", "xbt-signer"), "witness": ("xbt-anchor-witness", "xbt-anchor-witness"),
          "mcp": ("xbt-wallet-mcp", "xbt-wallet-mcp"), "ui": ("xbt-wallet-ui", "xbt-wallet-ui"), "hub": ("xbt402-hub", "xbt402-hub")}
probs, rep = [], {}
for arch in ("x86_64", "aarch64"):
    f = os.path.join(d, f"xbt-agent-wallet_{arch}.s9pk")
    m = json.loads(subprocess.check_output([cli, "s9pk", "inspect", f, "manifest"]))
    tree = json.loads(subprocess.check_output([cli, "s9pk", "inspect", f, "file-tree"]))
    rep[arch] = {"bytes": os.path.getsize(f), "version": m["version"], "sdk": m["sdkVersion"], "os": m.get("osVersion"), "gitHash": m.get("gitHash")}
    if m["id"] != "xbt-agent-wallet" or m["volumes"] != ["main", "startos"] or m["hardwareRequirements"].get("arch") != [arch]:
        probs.append(f"{arch}: manifest {m['id']} {m['volumes']} {m['hardwareRequirements']}")
    for img, (binary, user) in IMAGES.items():
        for ext in ("json", "env", "squashfs"):
            if f"images/{arch}/{img}.{ext}" not in tree:
                probs.append(f"{arch}: images/{arch}/{img}.{ext} missing")
        meta = json.loads(subprocess.check_output([cli, "s9pk", "inspect", f, "cat", f"images/{arch}/{img}.json"]))
        env = subprocess.check_output([cli, "s9pk", "inspect", f, "cat", f"images/{arch}/{img}.env"], text=True)
        if meta["user"] != user or "XBT_MODE=production" not in env or "XBT_DATA_DIR=/data" not in env:
            probs.append(f"{arch}/{img}: user {meta['user']!r} env {env!r}")
        with tempfile.TemporaryDirectory() as t:
            sq = os.path.join(t, "i.sqfs")
            with open(sq, "wb") as o:
                subprocess.check_call([cli, "s9pk", "inspect", f, "cat", f"images/{arch}/{img}.squashfs"], stdout=o)
            subprocess.check_call(["unsquashfs", "-q", "-f", "-d", os.path.join(t, "r"), sq, f"usr/bin/{binary}"], stdout=subprocess.DEVNULL)
            b = open(os.path.join(t, "r", "usr/bin", binary), "rb").read(64)
            mach = int.from_bytes(b[18:20], "little")
            ls = subprocess.check_output(["unsquashfs", "-lln", sq, "squashfs-root"], text=True).split("\n")[0]
            if b[:4] != b"\x7fELF" or mach != ELF[arch]:
                probs.append(f"{arch}/{img}: /usr/bin/{binary} is not a {arch} ELF (machine {mach:#x})")
            if not ls.startswith("drwxr-xr-x 0/0"):
                probs.append(f"{arch}/{img}: image root is {ls}")
print(json.dumps({"ok": not probs, "problems": probs, "packages": rep}, indent=1))
sys.exit(1 if probs else 0)
PY
[ "${PIPESTATUS[0]}" -eq 0 ] || { echo "RESULT FAIL (inspect)"; exit 1; }

echo "== the package's containers on regtest, StartOS-shaped"
set +e
python3 packaging/startos/test/startos_regtest.py "$OUT"
rc=$?
set -e
ln -sfn "$STAMP" "$ROOT/run/startos-test/latest"
echo "evidence: $OUT"
[ $rc -eq 0 ] && echo "RESULT PASS" || { echo "RESULT FAIL"; exit 1; }
