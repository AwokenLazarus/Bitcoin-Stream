#!/usr/bin/env python3
"""AGP-030: the Rust server's streamable HTTP transport under an independent client, the official
Python MCP SDK (`mcp` 2.2.0, the SDK B2 itself runs on): the same ClientSession talks to the Rust
server over streamable HTTP and to B2's server over stdio, in front of the same mock signer, and every
answer (tools/list and a set of tool calls, including errors) must be equal.

usage: http_sdk_check.py --py PYTHON_WITH_MCP --b2 B2_TREE --rust XBT_WALLET_MCP [--port 33594]
(re-executes itself under PYTHON_WITH_MCP)"""
import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))

CALLS = [("balance", {}), ("history", {"limit": "3"}), ("quote_payment", {"to": "x", "amount_xbt": 0.5}),
         ("xbt402_pay", {"url": "http://127.0.0.1:1/x", "max_sats": 5}), ("pay", {"to": "MARK:error", "amount_xbt": 1}),
         ("history", {"limit": 5.5}), ("approve", {}), ("forward_recover", {"txid": "MARK:list"})]


async def session_run(transport_cm):
    from mcp import ClientSession
    async with transport_cm as streams:
        read, write = streams[0], streams[1]
        async with ClientSession(read, write) as s:
            init = await s.initialize()
            tools = await s.list_tools()
            out = {"server": init.server_info.model_dump(mode="json"), "protocol": init.protocol_version,
                   "tools": [t.model_dump(mode="json", exclude_none=True) for t in tools.tools], "calls": []}
            for name, args in CALLS:
                r = await s.call_tool(name, args)
                out["calls"].append(r.model_dump(mode="json", exclude_none=True))
            return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--py", required=True)
    ap.add_argument("--b2", required=True)
    ap.add_argument("--rust", required=True)
    ap.add_argument("--port", type=int, default=33594)
    ap.add_argument("--inner", action="store_true")
    a = ap.parse_args()
    if not a.inner:
        os.execv(a.py, [a.py, os.path.abspath(__file__), "--inner"] + sys.argv[1:])
    sys.path.insert(0, HERE)
    from mcp_conformance import MockSigner
    from mcp.client.stdio import StdioServerParameters, stdio_client
    from mcp.client.streamable_http import streamable_http_client

    tmp = tempfile.mkdtemp(prefix="mcphttp-")
    sock = os.path.join(tmp, "signer.sock")
    MockSigner(sock)
    env = {"PATH": os.environ.get("PATH", ""), "B2_SIGNER_SOCK": sock, "B2_SIGNER_TIMEOUT": "5"}
    srv = subprocess.Popen([a.rust, "--http", f"127.0.0.1:{a.port}"], env=env, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                import socket
                socket.create_connection(("127.0.0.1", a.port), 0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        rust = asyncio.run(session_run(streamable_http_client(f"http://127.0.0.1:{a.port}/mcp")))
        b2 = asyncio.run(session_run(stdio_client(StdioServerParameters(command=a.py, args=["-m", "agentwallet.mcp_server"],
                                                                          env=dict(env, PYTHONPATH=a.b2)))))
    finally:
        srv.terminate()
        srv.wait(5)
    diffs = [k for k in ("server", "protocol", "tools") if rust[k] != b2[k]]
    diffs += [f"call {CALLS[i][0]} {json.dumps(CALLS[i][1])}" for i, (x, y) in enumerate(zip(rust["calls"], b2["calls"])) if x != y]
    for d in diffs:
        print("DIFF", d)
    print(f"http_sdk_check: {'PASS' if not diffs else 'FAIL'}: Python SDK {__import__('importlib.metadata').metadata.version('mcp')} "
          f"streamable HTTP -> Rust vs stdio -> B2: protocol {rust['protocol']}, {len(rust['tools'])} tools, "
          f"{len(CALLS)} calls ({sum(bool(c.get('is_error') or c.get('isError')) for c in rust['calls'])} errors), {len(diffs)} diffs")
    sys.exit(1 if diffs else 0)


if __name__ == "__main__":
    main()
