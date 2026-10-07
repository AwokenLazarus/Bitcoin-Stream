#!/usr/bin/env python3
"""AGP-038: inspect the OCI archives scripts/oci_build.sh wrote, without a registry or an emulator.

For every image and platform it reads the index, the manifest, the config and the layers, and checks that:
  * the platforms are linux/amd64, linux/arm64 and linux/arm/v7;
  * the image runs as a non-root user, has an ENTRYPOINT and a HEALTHCHECK, and sets XBT_DATA_DIR and XBT_MODE=production
    (xbt-init, the one-shot that fixes a bind mount's owners, is the exception: root, and no HEALTHCHECK);
  * the binary layer holds exactly /usr/bin/<image>, a static ELF (no PT_INTERP) for that architecture;
  * the base layer is the same blob in every image and on every platform (it is stored once).
It prints a JSON report, writes a markdown table of sizes (--md), and exits 1 if any check fails.
    python3 scripts/oci_inspect.py dist/oci IMAGE... [--md OUT.md] [--rev REV]
"""
import gzip
import io
import json
import struct
import sys
import tarfile

WANT = {("amd64", ""): 0x3E, ("arm64", ""): 0xB7, ("arm", "v7"): 0x28}
ROOT_ONESHOTS = {"xbt-init"}
ELF_CLASS = {0x3E: 2, 0xB7: 2, 0x28: 1}


def blob(tar, digest):
    algo, h = digest.split(":")
    return tar.extractfile(f"blobs/{algo}/{h}").read()


def layer_files(raw):
    data = gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        return {m.name.lstrip("./"): (m, t.extractfile(m).read() if m.isfile() else None) for m in t.getmembers()}


def elf_info(b):
    if b[:4] != b"\x7fELF":
        return None
    cls, endian = b[4], "<" if b[5] == 1 else ">"
    machine = struct.unpack(endian + "H", b[18:20])[0]
    if cls == 2:
        phoff, phentsize, phnum = struct.unpack(endian + "Q", b[32:40])[0], *struct.unpack(endian + "HH", b[54:58])
    else:
        phoff, phentsize, phnum = struct.unpack(endian + "I", b[28:32])[0], *struct.unpack(endian + "HH", b[42:46])
    interp = any(struct.unpack(endian + "I", b[phoff + i * phentsize: phoff + i * phentsize + 4])[0] == 3 for i in range(phnum))
    return {"class": cls, "machine": machine, "interp": interp}


def inspect(path, image):
    rep = {"image": image, "file": path, "platforms": [], "problems": []}
    with tarfile.open(path) as tar:
        index = json.loads(tar.extractfile("index.json").read())
        rep["ref"] = next((m.get("annotations", {}).get("org.opencontainers.image.ref.name") for m in index["manifests"]), None)
        manifests = []
        for m in index["manifests"]:
            doc = json.loads(blob(tar, m["digest"]))
            if "manifests" in doc:      # an image index inside the layout index
                rep["index_digest"] = m["digest"]
                manifests += doc["manifests"]
            else:
                manifests.append(m)
        for m in manifests:
            if m.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest":
                continue
            man = json.loads(blob(tar, m["digest"]))
            cfg = json.loads(blob(tar, man["config"]["digest"]))
            plat = (cfg.get("architecture"), cfg.get("variant", ""))
            c = cfg.get("config", {})
            layers = man["layers"]
            p = {"platform": f"{cfg.get('os')}/{plat[0]}" + (f"/{plat[1]}" if plat[1] else ""), "manifest": m["digest"],
                 "user": c.get("User"), "entrypoint": c.get("Entrypoint"), "healthcheck": (c.get("Healthcheck") or {}).get("Test"),
                 "env": c.get("Env"), "layers": [{"digest": l["digest"], "size": l["size"]} for l in layers],
                 "compressed_bytes": sum(l["size"] for l in layers) + m.get("size", 0) + man["config"]["size"]}
            probs = []
            if plat not in WANT or cfg.get("os") != "linux":
                probs.append(f"unexpected platform {p['platform']}")
            if image in ROOT_ONESHOTS:
                if (p["user"] or "").split(":")[0] not in ("0", "root") or not p["entrypoint"]:
                    probs.append(f"the one-shot should run as root with an ENTRYPOINT ({p['user']!r})")
            else:
                if not p["user"] or p["user"].split(":")[0] in ("", "0", "root"):
                    probs.append(f"runs as root ({p['user']!r})")
                if not p["entrypoint"] or not p["healthcheck"]:
                    probs.append("no ENTRYPOINT or HEALTHCHECK")
            if "XBT_DATA_DIR=/data" not in (p["env"] or []) or "XBT_MODE=production" not in (p["env"] or []):
                probs.append("XBT_DATA_DIR/XBT_MODE not set")
            if len(layers) != 2:
                probs.append(f"{len(layers)} layers (want base + binary)")
            else:
                files = layer_files(blob(tar, layers[1]["digest"]))
                bins = {k: v for k, v in files.items() if v[1] is not None}
                want = f"usr/bin/{image}"
                if list(bins) != [want]:
                    probs.append(f"binary layer holds {sorted(bins)}")
                else:
                    member, data = bins[want]
                    e = elf_info(data)
                    p["binary_bytes"] = len(data)
                    p["binary_mode"] = oct(member.mode)
                    if not e or plat not in WANT or e["machine"] != WANT[plat] or e["class"] != ELF_CLASS[WANT[plat]]:
                        probs.append(f"binary is not a {p['platform']} ELF: {e}")
                    elif e["interp"]:
                        probs.append("binary is dynamically linked (PT_INTERP)")
                base = layer_files(blob(tar, layers[0]["digest"]))
                if "etc/passwd" not in base or "data/signer" not in base:
                    probs.append("base layer lacks passwd or the /data skeleton")
            p["problems"] = probs
            rep["platforms"].append(p)
        got = sorted(p["platform"] for p in rep["platforms"])
        if got != ["linux/amd64", "linux/arm/v7", "linux/arm64"]:
            rep["problems"].append(f"platforms {got}")
    return rep


def main():
    args = sys.argv[1:]
    md = args[args.index("--md") + 1] if "--md" in args else None
    rev = args[args.index("--rev") + 1] if "--rev" in args else ""
    pos = [a for i, a in enumerate(args) if not a.startswith("--") and (i == 0 or args[i - 1] not in ("--md", "--rev"))]
    out_dir, images = pos[0], pos[1:]
    reps = [inspect(f"{out_dir}/{img}.tar", img) for img in images]
    bases = {p["layers"][0]["digest"] for r in reps for p in r["platforms"] if p["layers"]}
    problems = [f"{r['image']}: {x}" for r in reps for x in r["problems"]]
    problems += [f"{r['image']} {p['platform']}: {x}" for r in reps for p in r["platforms"] for x in p["problems"]]
    if len(bases) != 1:
        problems.append(f"the base layer differs between images/platforms: {sorted(bases)}")
    summary = {"ok": not problems, "problems": problems, "base_layer": sorted(bases), "images": reps}
    print(json.dumps({"ok": summary["ok"], "problems": problems, "base_layer": summary["base_layer"],
                      "images": [{"image": r["image"], "ref": r["ref"], "index": r.get("index_digest"),
                                  "platforms": [{k: p.get(k) for k in ("platform", "manifest", "user", "compressed_bytes", "binary_bytes")}
                                                for p in r["platforms"]]} for r in reps]}, indent=1))
    if md:
        lines = [f"# OCI images (AGP-038, AGP-040; rev {rev})", "",
                 "Generated by `scripts/oci_build.sh` (the inspection is `scripts/oci_inspect.py`). The archives are in `dist/oci/*.tar`, "
                 "which is git-ignored and never pushed.", "",
                 f"Shared base layer: `{', '.join(sorted(bases))}` (stored once).", "",
                 "| image | platform | user | binary (bytes) | image, compressed (bytes) | manifest digest |", "|---|---|---|---:|---:|---|"]
        for r in reps:
            for p in sorted(r["platforms"], key=lambda p: p["platform"]):
                lines.append(f"| {r['image']} | {p['platform']} | {p['user']} | {p.get('binary_bytes', '')} | {p['compressed_bytes']} | `{p['manifest']}` |")
        lines += ["", "Index digests (pin these in app manifests):", ""]
        lines += [f"- `{r['image']}`: `{r.get('index_digest')}` ({r['ref']})" for r in reps]
        lines += ["", f"Checks: {'PASS' if summary['ok'] else 'FAIL: ' + '; '.join(problems)}", ""]
        open(md, "w").write("\n".join(lines))
    sys.exit(0 if summary["ok"] else 1)


if __name__ == "__main__":
    main()
