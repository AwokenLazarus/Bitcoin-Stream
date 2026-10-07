#!/usr/bin/env python3
"""AGP-027 interop on regtest: the AGP-017 runbook (G1-G7 and both rollbacks) with the **Rust signer**
behind the Python B2 MCP session, then a **Rust payer on the Rust signer** against the Python B1 provider.

The runbook is xbt-063's `rehearsal/runbook.py` (the AGP-017 rehearsal, 81+ checks), imported unchanged.
Three things are swapped:
  * `start_signer` starts `xbt-signer` (Rust) instead of `python -m agentwallet.signer`;
  * G1's P3 probe (`Signer(Path(probe))` with B2_CHAIN=main) runs `xbt-signer --root probe --check`;
  * the model-facing calls (`xbt402_pay`, `channels`, `close_channel`, `balance`, `xbt402_refund`) go through
    B2's MCP server tools (agentwallet/mcp_server.py: its socket client, sanitize and the key-material check);
    operator calls (health, hot_address, notice_hot_txid, signatures, anchor_*) and agentwallet-approve use
    B2's SignerClient as in production.
Everything else is B2's and B1's own code at the rehearsal pins: the anchor witness, agentwallet-approve,
mainnet_provider.py, and the anchor CLI check of the Rust signer's log.

Part R (after the runbook): the operator raises the budgets and restarts the signer; a Rust payer
(`xbt-signer-payer`: xbt402's Client with a RemoteSigner) pays 4 calls to the Python provider and closes.
Exact amounts on chain. Then B2's Python classes open every file the Rust signer wrote (keys, coins, channels,
ledger, log).

    python scripts/interop/signer_runbook.py OUT_DIR      (scripts/signer_interop.sh sets everything up)
"""
import json
import os
import subprocess
import sys
import threading
import time
import types

XBT063 = os.environ.get("XBT063", os.path.expanduser("~/xbt-rnd/xbt-063"))
sys.path.insert(0, XBT063)
from rehearsal import runbook as rb  # noqa: E402  (sets the B2_* environment for REHEARSAL_PORT_BASE)

RUST_SIGNER = os.environ["XBT_SIGNER_BIN"]
RUST_PAYER = os.environ["XBT_SIGNER_PAYER_BIN"]
MCP_CALLS = {}

# --- the swaps -------------------------------------------------------------------------------------------


def start_signer(log="signer.log"):
    if os.path.exists(rb.SOCK):
        os.unlink(rb.SOCK)
    rb.start("signer", [RUST_SIGNER, "--root", rb.WALLET_ROOT], log)
    rb.wait_until(lambda: os.path.exists(rb.SOCK) and rb.S("health")["ok"], 60, "the Rust signer socket")
    h = rb.S("health")
    if h.get("implementation") != "xbt-signer (Rust)":
        raise rb.Abort(f"the signer on the socket is not the Rust signer: {h}")


_run = subprocess.run


def _run_shim(argv, *a, **kw):
    """G1's P3 probe builds a Python Signer on a probe root with B2_CHAIN=main: build the Rust one."""
    if isinstance(argv, list) and len(argv) >= 4 and argv[1] == "-c" and "agentwallet.signer import Signer" in argv[2]:
        argv = [RUST_SIGNER, "--root", argv[3], "--check"]
    return _run(argv, *a, **kw)


_sub = types.ModuleType("subprocess")
_sub.__dict__.update(subprocess.__dict__)
_sub.run = _run_shim
rb.subprocess = _sub

_S = rb.S
MCP_TOOLS = {"balance", "channels", "xbt402_pay", "close_channel", "xbt402_refund", "history", "quote_payment", "pay"}


def S(op, **params):
    """The model's calls go through B2's MCP server; the operator's straight to the socket."""
    if op in MCP_TOOLS:
        from agentwallet import mcp_server
        tool = mcp_server.mcp._tool_manager.get_tool(op)
        MCP_CALLS[op] = MCP_CALLS.get(op, 0) + 1
        return json.loads(tool.fn(**params))
    return _S(op, **params)


rb.start_signer = start_signer
rb.S = S
check, FACTS, node = rb.check, rb.FACTS, rb.node


# --- part R: a Rust payer on the Rust signer against the Python provider ------------------------------------


def part_r():
    print("== R: Rust payer (xbt402 Client + RemoteSigner) on the Rust signer -> Python B1 provider", flush=True)
    path = os.path.join(rb.WALLET_ROOT, "policy.json")
    with open(path) as f:
        pol = json.load(f)
    pol.update(daily_budget_sats=20_000, weekly_budget_sats=20_000, per_counterparty_cap_sats=20_000)
    with open(path, "w") as f:
        json.dump(pol, f, indent=1)
    rb.kill("signer")
    start_signer("signer-restart-r.log")
    rb.g2(12_000, "R.G2")
    hot_spk = FACTS["hot_spk"]
    before = set(node.getrawmempool())
    lines0 = len(rb.S("signatures", limit=1000)["signatures"])
    proc = subprocess.Popen([RUST_PAYER, "--sock", rb.SOCK, "--url", rb.URL, "--network", FACTS["network"], "--calls", "4",
                             "--capacity", "10000", "--max-price", "500", "--min-conf", "1", "--close"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=rb.RUN)
    fund = rb.wait_until(lambda: list(set(node.getrawmempool()) - before), 60, "the Rust payer's funding")[0]
    rb.mine(1)
    out, err = proc.communicate(timeout=240)
    with open(os.path.join(rb.RUN, "rust-payer.json"), "w") as f:
        f.write(out + "\n" + err)
    rep = json.loads(out.strip().splitlines()[-1]) if out.strip() else {"ok": False, "stderr": err[-400:]}
    FACTS["rust_payer"] = {k: rep.get(k) for k in ("ok", "chan", "funding_txid", "capacity", "signed", "spent_msat", "client_holds_secret", "error")}
    check("R", "Rust payer: 4 paid calls and a cooperative close", rep.get("ok") and len(rep.get("calls") or []) == 4
          and all(c["status"] == 200 for c in rep["calls"]), rep.get("error") or rep.get("stderr"))
    check("R", "the Rust client never held a payer key (keys in the signer)", rep["client_holds_secret"] is False
          and rep["refund_hex_len"] > 0)
    check("R", "funding: 10,000 sat from the signer's hot key (0x21), 1,400 change", rep["funding_txid"] == fund)
    h, bh = rb.block_of(fund, 1)
    ftx = node.getrawtransaction(fund, True, bh)
    check("R", "funding outputs 10,000 P2WSH + 1,400 to the hot key, signed 0x21",
          rb.outs(ftx)[0][1] == 10_000 and rb.outs(ftx)[1] == (hot_spk, 1_400) and ftx["vin"][0]["txinwitness"][0].endswith("21"), rb.outs(ftx))
    check("R", "payer change goes to the signer's hot key", rep["payer_spk"] == hot_spk, rep["payer_spk"])
    close = rep["close"]["txid"]
    check("R", "close: cum 2,000 (4 calls x 500, postpay), the signer marked it closed and counted the change",
          rep["close"]["cum"] == "2000" and rep["mark_closed"].get("state") == "closed"
          and rep["mark_closed"].get("close_change") == "counted", {"close": rep["close"], "mark": rep["mark_closed"]})
    rb.wait_until(lambda: close in node.getrawmempool(), 30, "the close in the mempool")
    h = rb.mine(1)
    o = dict(rb.outs(rb.tx_in_block(close, h)))
    payee = [v for spk, v in o.items() if spk != hot_spk]
    check("R", "close on chain: 2,000 to the payee, 7,400 to the hot key, fee 600",
          payee == [2_000] and o.get(hot_spk) == 7_400 and 10_000 - sum(o.values()) == 600, o)
    check("R", "hot = 1,400 funding change + 7,400 close change", rb.hot()["hot_sats"] == 8_800, rb.hot()["hot_sats"])
    sig = rb.S("signatures", limit=1000)["signatures"][lines0:]
    kinds = [(x["kind"], x["method"], x["rule"]) for x in sig]
    FACTS["rust_payer"]["signatures"] = kinds
    states = [k for k in kinds if k[0] == "channel_state"]
    check("R", "the signer logged every signature: funding, refund custody, 4 states under policy:ok, close auth",
          ("funding", "fund", "method:fund") in kinds and ("refund", "xbt402_sign_refund", "client:refund_custody") in kinds
          and len(states) == 4 and all(k[1] == "xbt402_sign_state" and k[2] == "policy:ok" for k in states)
          and ("close_auth", "xbt402_sign_close", "client:close") in kinds, kinds)
    ps = [c for c in rb.admin_status()["channels"] if c["chan"] == rep["chan"]][0]
    check("R", "Python provider ledger: closed with this txid at best_cum 2,000", ps["closed_txid"] == close and ps["best_cum"] == 2_000, ps)
    FACTS["rust_payer"]["close_txid"] = close


PY_OPEN = r'''
import json, sys
from pathlib import Path
from agentwallet import sigaudit
from agentwallet.channels import ChannelBook
from agentwallet.hot import HotWallet
from agentwallet.keystore import KeyStore
from agentwallet.policy import PolicyStore
run, key = Path(sys.argv[1]), Path(sys.argv[2]).read_bytes()
ks = KeyStore(key=key)
hw = HotWallet(run / "hot.json", rpc=None, hrp="bcrt", keystore=ks)
book = ChannelBook(run / "channels.json", run / "channel_keys.json", keystore=ks)
print(json.dumps({"hot_address": hw.address, "hot_sats": hw.balance_sats(), "retired": len(hw._retired),
                  "channels": [r["state"] for r in book.list_public()], "keys": len(book._secrets),
                  "payments": len(PolicyStore(run / "ledger.json").payments()), "chain": sigaudit.check_chain(run / "signatures.jsonl")}))
'''


def py_opens_rust_files():
    print("== compat: B2 (Python) opens the Rust signer's files", flush=True)
    r = _run([rb.PY, "-c", PY_OPEN, os.path.join(rb.WALLET_ROOT, ".run"), os.path.join(rb.KEYS, "hot.key")],
             capture_output=True, text=True, cwd=rb.RUN)
    doc = json.loads(r.stdout) if r.returncode == 0 else {"error": r.stderr[-600:]}
    FACTS["python_opens_rust_files"] = doc
    hot = rb.hot()
    rust_chans = [c["state"] for c in rb.S("channels")["channels"]]
    check("compat", "B2 opens the Rust-sealed hot key and UTXO set: same address and balance",
          doc.get("hot_address") == hot["hot_address"] and doc.get("hot_sats") == hot["hot_sats"], doc)
    check("compat", "B2 loads channels.json (every ChannelRecord field) and the sealed channel keys",
          doc.get("channels") == rust_chans and doc.get("keys", 0) >= len(rust_chans), doc)
    check("compat", "B2 reads the policy ledger and verifies the Rust signature log's chain",
          doc.get("payments", 0) > 0 and doc.get("chain", {}).get("ok"), doc)


def main(out):
    os.makedirs(out, exist_ok=True)
    t0 = time.time()
    ok = False
    try:
        rb.setup_chain()
        rb.g1()
        rb.g2()
        rb.g3()
        rb.g4()
        rb.g5()
        g6_txid, g6_out = rb.g6(FACTS["chan"], FACTS["close_txid"], 5_000)
        g7_txid, g7_out, g7_ins = rb.g7()
        FACTS.update(payee_sweep_txid=g6_txid, hot_sweep_txid=g7_txid, hot_sweep_inputs=g7_ins)
        rb.success(g6_out, g7_out)
        rb.rollback_a()
        rb.rollback_b()
        part_r()
        py_opens_rust_files()
        rb.finish()
        check("mcp", "the model-facing calls went through B2's MCP server tools", MCP_CALLS.get("xbt402_pay", 0) >= 13
              and MCP_CALLS.get("close_channel", 0) >= 1 and MCP_CALLS.get("channels", 0) >= 1, MCP_CALLS)
        ok = True
    except rb.Abort as e:
        print(f"ABORT: {e}", flush=True)
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        rb.CHECKS.append({"gate": "harness", "check": f"{type(e).__name__}: {e}", "ok": False})
    finally:
        for name in list(rb.PROCS):
            rb.kill(name)
        try:
            FACTS["final_height"] = node.getblockcount()
        except Exception:  # noqa: BLE001
            pass
        rb.node_down()
        FACTS["mcp_calls"] = MCP_CALLS
        report = {"ok": ok and all(c["ok"] for c in rb.CHECKS), "seconds": round(time.time() - t0, 1), "port_base": rb.BASE,
                  "signer": "xbt-signer (Rust)", "pins": {"b1": os.environ.get("REHEARSAL_B1_PIN"), "b2": os.environ.get("REHEARSAL_B2_PIN")},
                  "checks": rb.CHECKS, "facts": FACTS}
        with open(os.path.join(out, "signer_interop.json"), "w") as f:
            json.dump(report, f, indent=1)
        for name in ("signer.log", "signer-restart-a.log", "signer-restart-r.log", "provider.log", "anchor.log", "calls.jsonl", "rust-payer.json"):
            p = os.path.join(rb.RUN, name)
            if os.path.exists(p):
                _run(["cp", p, out])
        for src in (os.path.join(rb.WALLET_ROOT, ".run", "signatures.jsonl"), os.path.join(rb.ANCHOR_DIR, "anchors.jsonl")):
            if os.path.exists(src):
                _run(["cp", src, out])
        print(f"{sum(c['ok'] for c in rb.CHECKS)}/{len(rb.CHECKS)} checks ok in {report['seconds']} s", flush=True)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
