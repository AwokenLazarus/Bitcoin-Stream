#!/usr/bin/env python3
"""AGP-030 conformance on regtest: diff two xbt-063 flagship conformance runs (MCP_CONFORMANCE=1), one
driven through B2's Python MCP and one through the Rust xbt-wallet-mcp, on the same signer build.

Each run's mcp_conformance.jsonl holds every step's MCP result. Within a run, reads and signer-free
calls were already sent to both servers at the same wallet state ("equal"). Across the two runs every
step is compared after normalizing what differs between two chains and two sets of keys: txids,
channel ids, keys, scripts and digests (hex), addresses, times and latencies, and approval tokens.

usage: regtest_diff.py B2_RUN/mcp_conformance.jsonl RUST_RUN/mcp_conformance.jsonl [--out table.json]
"""
import argparse
import json
import re
import sys

HEX = re.compile(r"\b[0-9a-f]{12,}(:\d+)?\b")
ADDR = re.compile(r"\b(bcrt1|tb1|bc1)[0-9a-z]{20,}\b")
TIME_KEYS = re.compile(r"(^|_)(ts|time|at|ms|elapsed|created|expires|approval_expires|seconds|since|until|latency|age_s|last_anchor)$")
STAMP = re.compile(r"\d{8}-\d{6}")


def norm(v, key=""):
    if isinstance(v, dict):
        return {k: norm(x, k) for k, x in v.items()}
    if isinstance(v, list):
        return [norm(x, key) for x in v]
    if isinstance(v, float) and 1.5e9 < v < 2.5e9 or (TIME_KEYS.search(key) and isinstance(v, (int, float)) and not isinstance(v, bool)):
        return "<time>"
    if isinstance(v, str):
        if key in ("approval_token", "token"):
            return "<token>"
        s = ADDR.sub("<addr>", v)
        s = HEX.sub("<hex>", s)
        return STAMP.sub("<stamp>", s)
    return v


def text_of(result):
    t = "\n".join(c.get("text", "") for c in (result or {}).get("content", []))
    try:
        return json.loads(t)
    except ValueError:
        return t


def normalized(result):
    r = dict(result or {})
    body = text_of(r)
    return {"isError": r.get("isError"), "body": norm(body), "structured_matches_text":
            (r.get("structuredContent") or {}).get("result") == "\n".join(c.get("text", "") for c in r.get("content", []))
            if not r.get("isError") else None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("b2")
    ap.add_argument("rust")
    ap.add_argument("--out")
    a = ap.parse_args()
    runs = {}
    for k, p in (("b2", a.b2), ("rust", a.rust)):
        runs[k] = [json.loads(line) for line in open(p)]
    rows, diffs = [], []
    hs = [r for r in runs["b2"] if r.get("step") == "handshake"] + [r for r in runs["rust"] if r.get("step") == "handshake"]
    steps = {k: [r for r in v if r.get("step") != "handshake"] for k, v in runs.items()}
    if len(steps["b2"]) != len(steps["rust"]):
        diffs.append({"what": "step count", "b2": len(steps["b2"]), "rust": len(steps["rust"])})
    same_state = [r for v in steps.values() for r in v if "equal" in r]
    for x, y in zip(steps["b2"], steps["rust"]):
        if (x["tool"], x["args"]) != (y["tool"], y["args"]):
            diffs.append({"what": "plan", "b2": [x["tool"], x["args"]], "rust": [y["tool"], y["args"]]})
            continue
        nx, ny = normalized(x["result"]), normalized(y["result"])
        eq = nx == ny
        body = nx["body"]
        verdict = body.get("verdict") or body.get("rule") if isinstance(body, dict) else None
        rows.append({"step": x["step"], "kind": x["kind"], "tool": x["tool"], "args": x["args"], "equal": eq,
                     "same_state_b2_run": x.get("equal"), "same_state_rust_run": y.get("equal"),
                     "outcome": "isError: " + (body if isinstance(body, str) else json.dumps(body))[:60] if nx["isError"] else (verdict or "ok")})
        if not eq:
            diffs.append({"what": "result", "step": x["step"], "tool": x["tool"], "args": x["args"], "b2": nx, "rust": ny})
    for r in same_state:
        if not r["equal"]:
            diffs.append({"what": "same-state twin differs", "writer": r["writer"], "step": r["step"], "tool": r["tool"]})
    for h in hs:
        if not h.get("equal"):
            diffs.append({"what": "handshake (initialize / tools/list) differs", "writer": h["writer"]})
    report = {"ok": not diffs, "steps": len(rows), "cross_run_equal": sum(r["equal"] for r in rows),
              "same_state_comparisons": len(same_state), "same_state_equal": sum(bool(r["equal"]) for r in same_state),
              "tools_covered": sorted({r["tool"] for r in rows}), "rows": rows, "diffs": diffs}
    if a.out:
        json.dump(report, open(a.out, "w"), indent=1)
    for d in diffs[:20]:
        print("DIFF", json.dumps(d)[:2000])
    print(f"regtest_diff: {'PASS' if report['ok'] else 'FAIL'}: {report['cross_run_equal']}/{len(rows)} steps equal across runs, "
          f"{report['same_state_equal']}/{len(same_state)} same-state comparisons equal, tools {len(report['tools_covered'])}")
    sys.exit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
