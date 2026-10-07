#!/usr/bin/env python3
"""AGP-030 conformance, protocol level: B2's Python MCP (`python -m agentwallet.mcp_server`) and the
Rust `xbt-wallet-mcp` get the same MCP messages over stdio, in front of the same recording signer, and
their answers must be equal after parsing (JSON key order aside). Covered:

* the handshake: every protocol version, bad initialize params, requests before initialize, ping;
* tools/list, resources/list, resources/templates/list, prompts/list, unknown methods, bad messages;
* every tool: defaults, every argument, pydantic's coercions and every validation error type;
* the forbidden tools (answered as unknown), a signer error, an unreachable signer, key material
  (key-named fields dropped, key-shaped strings redacted, the untrusted subtree kept, a leak refused);
* the signer requests each server sent (method and params) must be the same too.

usage: mcp_conformance.py --py PYTHON --b2 B2_TREE --rust XBT_WALLET_MCP [--out report.json]
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

WIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
XPRV = "xprv" + "9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"


class MockSigner:
    """B2's socket protocol. Records every request; answers with a probe result that exercises the
    sanitizer, or a signer error / a key leak for the marked arguments."""

    def __init__(self, path: str):
        self.path, self.calls, self.lock = path, [], threading.Lock()
        self.srv = socket.socket(socket.AF_UNIX)
        self.srv.bind(path)
        self.srv.listen(64)
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c):
        buf = b""
        while b"\n" not in buf:
            d = c.recv(65536)
            if not d:
                break
            buf += d
        req = json.loads(buf)
        with self.lock:
            self.calls.append(req)
        p = req.get("params") or {}
        mark = next((v for v in p.values() if isinstance(v, str) and v.startswith("MARK:")), "")
        if mark == "MARK:error":
            resp = {"id": 1, "error": {"code": -1, "message": "boom from the signer"}}
        elif mark == "MARK:leak":
            resp = {"id": 1, "result": {"verdict": "allow", "note": "xprvShortButStillAKey"}}
        elif mark == "MARK:list":
            resp = {"id": 1, "result": [1, "two", {"seed_words": "x", "k": XPRV}, None, 2.5]}
        elif mark == "MARK:null":
            resp = {"id": 1, "result": None}
        elif mark == "MARK:garbage":
            c.sendall(b"not json\n")
            c.close()
            return
        else:
            resp = {"id": 1, "result": {
                "method": req["method"], "params": p, "f": 1.0, "tiny": 1e-7, "neg": -0.5, "big": 10 ** 30, "i": -3,
                "hot_secret": "x", "wif": WIF, "Descriptor": "wpkh(...)", "u": "é \U0001f600\"\\\n",
                "nested": [{"passphrase": 1, "txid": "ab" * 32, "w": WIF, "x": XPRV}, [], {}],
                "untrusted_provider_response": {"trust": "untrusted", "body": WIF + " " + XPRV, "secret": 1},
            }}
        c.sendall((json.dumps(resp) + "\n").encode())
        c.close()

    def take(self):
        with self.lock:
            out, self.calls = self.calls, []
        return out


def msg(i, method, params=None):
    m = {"jsonrpc": "2.0", "id": i, "method": method}
    if params is not None:
        m["params"] = params
    return m


def init(i=1, version="2025-06-18"):
    return msg(i, "initialize", {"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "conf", "version": "1"}})


INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}


def call(i, name, args=None, omit=False):
    p = {"name": name}
    if not omit:
        p["arguments"] = args
    return msg(i, "tools/call", p)


def tool_cases():
    """(name, arguments) for every tool: defaults, all arguments, coercions, every error type."""
    long = "z" * 80
    bad_str = [5, 1.5, True, None, [], ["a"], {"k": 1}, {"a": "b'c"}]
    bad_float = ["abc", "", "1__0", "_1", "0x10", None, [], {}, long, "٣"]
    ok_float = [0.001, 1, "0.5", " 1e3 ", "1_0", "inf", "-Infinity", "nan", True, False, 10 ** 30, 123456789.125, -0.0]
    bad_int = [5.5, "x", "5.5", "1e3", "0x10", "", None, [1, 2], {"a": 1}, 1e20, -1e19, long, "٣", "1__0"]
    ok_int = [5, "7", " 12 ", "1_000", "5.0", "-3", True, False, 1e3, -0.0, 9223372036854775808, 10 ** 24, "000123", "+4"]
    out = []
    for t in ("balance", "channels", "forward_status"):
        out += [(t, {}), (t, None), (t, {"extra": 1}), (t, "OMIT")]
    for t in ("quote_payment", "pay"):
        out += [(t, {"to": "bc1qexample", "amount_xbt": 0.001}), (t, {"to": "x", "amount_xbt": 1, "memo": "m"}), (t, {}), (t, None),
                (t, {"to": "x"}), (t, {"amount_xbt": 1}), (t, {"to": "MARK:error", "amount_xbt": 1}),
                (t, {"to": "é\n\u0001it's", "amount_xbt": 2})]
        out += [(t, {"to": v, "amount_xbt": 1}) for v in bad_str]
        out += [(t, {"to": "x", "amount_xbt": v}) for v in bad_float + ok_float]
        out += [(t, {"to": "x", "amount_xbt": 1, "memo": v}) for v in bad_str[:3]]
        out += [(t, {"to": 5, "amount_xbt": "abc", "memo": None})]
    out += [("history", {})] + [("history", {"limit": v}) for v in bad_int + ok_int]
    out += [("xbt402_pay", {"url": "http://127.0.0.1:1/x"}),
            ("xbt402_pay", {"url": "http://127.0.0.1:1/x", "method": "POST", "body": "{\"q\": 1}", "max_sats": 50}),
            ("xbt402_pay", {}), ("xbt402_pay", {"url": ["a"], "max_sats": "z"}), ("xbt402_pay", {"url": "u", "max_sats": 5.0}),
            ("xbt402_pay", {"url": "u", "body": {"k": 1}}), ("xbt402_pay", {"url": "u", "method": None}),
            ("xbt402_pay", {"url": "MARK:error"}), ("xbt402_pay", {"url": "u", "max_sats": -1})]
    out += [("xbt402_pay", {"url": "u", "max_sats": v}) for v in bad_int + ok_int]
    for t in ("close_channel", "xbt402_refund"):
        out += [(t, {"counterparty": "http://127.0.0.1:1"}), (t, {}), (t, {"counterparty": None}), (t, {"counterparty": 7}),
                (t, {"counterparty": "MARK:error"})]
    out += [("forward_recover", {"txid": "ab" * 32}), ("forward_recover", {}), ("forward_recover", {"txid": None}),
            ("forward_recover", {"txid": "MARK:error"})]
    # the result shapes the sanitizer must handle the same way
    out += [("forward_recover", {"txid": "MARK:leak"}), ("forward_recover", {"txid": "MARK:list"}),
            ("forward_recover", {"txid": "MARK:null"}), ("forward_recover", {"txid": "MARK:garbage"})]
    # never tools, and names that are not tools
    out += [(t, {}) for t in ("approve", "recover_vault", "recover_treasury", "sweep_hot", "rotate_hot_key", "fund", "health",
                              "sign_state", "", "BALANCE")]
    return out


def sessions():
    """(label, messages): each list is one fresh server process."""
    s = []
    # before initialize
    s.append(("pre-init", [msg(2, "tools/list"), call(3, "balance", {}), msg(4, "ping"), msg(5, "resources/list"), init(6),
                           INITIALIZED, msg(7, "tools/list")]))
    for v in ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28", "1999-01-01", "garbage"):
        s.append((f"version {v}", [init(1, v), INITIALIZED, msg(2, "tools/list"), msg(3, "ping")]))
    s.append(("bad initialize", [msg(1, "initialize"), msg(2, "initialize", {}), msg(3, "initialize", {"protocolVersion": "2025-06-18"}),
                                 msg(4, "initialize", {"protocolVersion": 5, "capabilities": {}, "clientInfo": {"name": "a", "version": "1"}}),
                                 msg(5, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "a"}}),
                                 msg(6, "initialize", []), init(7), msg(8, "ping")]))
    proto = [init(1), INITIALIZED, msg(2, "tools/list"), msg(3, "tools/list", {"cursor": "x"}), msg(4, "resources/list"),
             msg(5, "resources/templates/list"), msg(6, "prompts/list"), msg(7, "ping"), msg(8, "foo/bar"), msg(9, "completion/complete", {}),
             msg(10, "logging/setLevel", {"level": "info"}), msg("s-11", "ping"), msg(12, "tools/call"), msg(13, "tools/call", {}),
             msg(14, "tools/call", {"name": 5}), msg(15, "tools/call", {"name": "balance", "arguments": []}),
             msg(16, "tools/call", {"name": "balance", "arguments": "x"}), msg(17, "tools/call", []),
             {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 99}},
             {"jsonrpc": "1.0", "id": 18, "method": "ping"}, {"id": 19, "method": "ping"}, {"jsonrpc": "2.0", "id": 20},
             {"jsonrpc": "2.0", "id": 21, "result": {}}, msg(22, "resources/read", {"uri": "x"}), msg(23, "prompts/get", {"name": "x"}),
             msg(26, "completion/complete", {"ref": {"type": "ref/prompt", "name": "x"}, "argument": {"name": "a", "value": "b"}}),
             msg(27, "resources/subscribe", {"uri": "x"}), msg(28, "resources/read", {}), msg(29, "prompts/get", {}),
             msg(30, "resources/read", {"uri": 5}), msg(31, "prompts/get", {"name": "x", "arguments": {"a": "b"}}),
             msg(32, "tools/list", "x"), msg(33, "ping", []), msg(34, "ping", None), msg(35, "tasks/list"),
             {"jsonrpc": "2.0", "id": None, "method": "ping"}, {"jsonrpc": "2.0", "id": 36.5, "method": "ping"},
             {"jsonrpc": "2.0", "id": True, "method": "ping"}, msg(37, "foo", []),
             init(24), msg(25, "ping")]
    s.append(("protocol", proto))
    body = [init(1), INITIALIZED]
    for i, (name, args) in enumerate(tool_cases(), start=100):
        body.append(call(i, name, None if args == "OMIT" else args, omit=args == "OMIT"))
    s.append(("tools", body))
    return s


def run(cmd, env, messages, timeout=30.0):
    """Send `messages` to a stdio server, collect replies by id until every request is answered."""
    p = subprocess.Popen(cmd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    replies, stderr = {}, []
    t = threading.Thread(target=lambda: stderr.append(p.stderr.read()), daemon=True)
    t.start()
    want = {json.dumps(m["id"]) for m in messages if isinstance(m, dict) and "id" in m and "method" in m}
    done = threading.Event()

    def reader():
        for line in p.stdout:
            if not line.strip():
                continue
            d = json.loads(line)
            replies[json.dumps(d.get("id"))] = d
            if want <= set(replies):
                done.set()
        done.set()

    threading.Thread(target=reader, daemon=True).start()
    for m in messages:
        p.stdin.write(json.dumps(m) + "\n")
        p.stdin.flush()
        # the handshake first, as a client does; the rest may overlap
        if isinstance(m, dict) and m.get("method") == "initialize":
            t0 = time.time()
            while json.dumps(m.get("id")) not in replies and time.time() - t0 < timeout:
                time.sleep(0.01)
    done.wait(timeout)
    time.sleep(0.3)  # anything unexpected (a reply to a message that needs none) arrives now
    p.stdin.close()
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    return replies


def normalize_calls(calls):
    return sorted(json.dumps(c, sort_keys=True) for c in calls)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--py", required=True)
    ap.add_argument("--b2", required=True)
    ap.add_argument("--rust", required=True)
    ap.add_argument("--out")
    a = ap.parse_args()
    tmp = tempfile.mkdtemp(prefix="mcpconf-")
    sock = os.path.join(tmp, "signer.sock")
    signer = MockSigner(sock)
    base = {k: v for k, v in os.environ.items() if not k.startswith(("B2_", "XBT_MCP_"))}
    env = dict(base, B2_SIGNER_SOCK=sock, B2_SIGNER_TIMEOUT="5", PYTHONPATH=a.b2)
    if not env.get("B1_ROOT", "").strip():
        xbt_b1 = env.get("XBT402_B1", "").strip()
        if xbt_b1:
            env["B1_ROOT"] = xbt_b1
    servers = {"b2": [a.py, "-m", "agentwallet.mcp_server"], "rust": [a.rust]}
    report = {"sessions": [], "diffs": [], "requests": 0, "tool_calls": 0}
    for label, messages in sessions() + [("unreachable signer", [init(1), INITIALIZED, call(2, "balance", {}), call(3, "pay", {"to": "x", "amount_xbt": 1})])]:
        out, calls = {}, {}
        for k, cmd in servers.items():
            e = dict(env, B2_SIGNER_SOCK=os.path.join(tmp, "absent.sock")) if label == "unreachable signer" else env
            out[k] = run(cmd, e, messages)
            calls[k] = normalize_calls(signer.take())
        ids = sorted(set(out["b2"]) | set(out["rust"]))
        diffs = [{"session": label, "id": i, "b2": out["b2"].get(i), "rust": out["rust"].get(i)}
                 for i in ids if out["b2"].get(i) != out["rust"].get(i)]
        if calls["b2"] != calls["rust"]:
            diffs.append({"session": label, "signer_requests": {"b2": calls["b2"], "rust": calls["rust"]}})
        n_tool = sum(1 for m in messages if isinstance(m, dict) and m.get("method") == "tools/call")
        report["sessions"].append({"session": label, "messages": len(messages), "replies": len(ids), "tool_calls": n_tool,
                                   "signer_requests": len(calls["b2"]), "equal": not diffs})
        report["requests"] += len(messages)
        report["tool_calls"] += n_tool
        report["diffs"] += diffs
        print(f"{'OK ' if not diffs else 'DIFF'} {label}: {len(messages)} messages, {len(ids)} replies, {n_tool} tool calls, "
              f"{len(calls['b2'])} signer requests", flush=True)
        for d in diffs[:5]:
            print("   ", json.dumps(d)[:1500])
    report["ok"] = not report["diffs"]
    if a.out:
        json.dump(report, open(a.out, "w"), indent=1)
    print(f"mcp_conformance: {'PASS' if report['ok'] else 'FAIL'} ({report['requests']} messages, {report['tool_calls']} tool calls, "
          f"{len(report['diffs'])} diffs)")
    sys.exit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
