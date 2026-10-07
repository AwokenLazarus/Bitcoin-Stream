#!/usr/bin/env python3
"""AGP-048 rail=ln on regtest: the Rust signer and MCP pay XBT Lightning invoices through a Lightning
Fork node (lf1) under B2's policy, against lightning-fork-lab (Knots BLAKE2b regtest, lf1, lf2, and a
stock lnd on a SHA-256 regtest). Run by scripts/ln_rail_regtest.sh, which brings the lab up.

  S1  ln_status through the MCP: the only channel is taproot -> not ready
  S2  ln_pay with only a taproot channel -> ln_no_safe_channel, no HTLC
  S3  a unified anchors channel opened from a post-split coin; ln_pay within budget -> SUCCEEDED
  S4  over the daily budget -> denied before any HTLC
  S5  over the human threshold -> needs_human; the human's ed25519 approval (not an MCP tool); paid
  S6  a stock lnd invoice (no feature bit 512) -> refused
  S7  a second signer whose LN node is the stock lnd on the SHA-256 chain -> refused (ln_chain)
  S8  the signature log and the audit log hold every payment and refusal; the ledger is exact
  S9  the MCP surface: 12 tools with XBT_MCP_LN=1, approve is not a tool
  AGP-049:
  S10 funding proven from the transaction on our Knots node: the unified channel's input is 0x21 and
      post-split; a channel LF opens from the pre-split coin A2 (0x21, LND says unified) is refused
  S11 ln.exposure_cap_sats below what lf1 holds -> ln_exposure_cap, no HTLC
  S12 the macaroon: permissions and caveats in ln_status; an ipaddr caveat binds gRPC callers but not
      REST ones (LND's REST gateway dials gRPC from 127.0.0.1)
  S13 ln.max_sends_per_hour 1 -> the second send is refused ln_rate_limit
  S14 lf2 runs a watchtower, lf1's wtclient uses it: ln_status lists it, chain not verified, warns;
      tower_policy refuse -> ln_tower_chain; listed in trusted_towers -> paid
  S15 a hold invoice: the payment stays in flight, booked, with its CLTV height; an HTLC lf1 sends
      outside the wallet counts against the budget (ln_htlc_lock) until it is cancelled

Environment: LAB (the lab checkout), OUT (report dir), BIN (the release binaries), RUN (scratch dir).
"""
import hashlib
import json
import os
import socket
import subprocess
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

LAB, OUT, BIN, RUN = (os.environ[k] for k in ("LAB", "OUT", "BIN", "RUN"))
SPLIT = 125  # the regtest stand-in for mainnet's 961,632
REPORT = {"checks": [], "scenarios": {}}
FAILED = []


def check(name, ok, detail=None):
    REPORT["checks"].append({"check": name, "ok": bool(ok), "detail": detail})
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  {json.dumps(detail)[:600]}"), flush=True)
    if not ok:
        FAILED.append(name)


def dc(*args, check_rc=True):
    r = subprocess.run(["docker", "compose", *args], cwd=LAB, capture_output=True, text=True)
    if check_rc and r.returncode != 0:
        raise RuntimeError(f"docker compose {' '.join(args)}: {r.stderr.strip()[:400]}")
    return r.stdout.strip()


def b2b(*a):
    return dc("exec", "-T", "knots-b2b", "bitcoin-cli", "-datadir=/data", "-rpcuser=lab", "-rpcpassword=lab", *a)


def ln(svc, *a):
    out = dc("exec", "-T", svc, "lncli", "--network=regtest", "--rpcserver=127.0.0.1:10009", *a)
    return json.loads(out) if out.startswith(("{", "[")) else out


def mine(n):
    addr = b2b("-rpcwallet=lab", "getnewaddress")
    b2b("-rpcwallet=lab", "generatetoaddress", str(n), addr)
    return int(b2b("getblockcount"))


def wait(what, secs, fn):
    end = time.time() + secs
    while time.time() < end:
        try:
            if fn():
                return
        except Exception:
            pass
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for {what}")


def synced(svc, height=None):
    i = ln(svc, "getinfo")
    return i.get("synced_to_chain") and (height is None or int(i["block_height"]) >= height)


def rpc_sock(path, method, params=None, timeout=120):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(path)
    s.sendall((json.dumps({"id": 1, "method": method, "params": params or {}}) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        c = s.recv(65536)
        if not c:
            break
        buf += c
    s.close()
    r = json.loads(buf)
    if r.get("error"):
        raise RuntimeError(f"signer {method}: {r['error']}")
    return r["result"]


class Mcp:
    """xbt-wallet-mcp over stdio."""

    def __init__(self, env):
        self.p = subprocess.Popen([f"{BIN}/xbt-wallet-mcp", "--stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=open(f"{RUN}/mcp.log", "a"), text=True, env=env)
        self.n = 0
        self.req("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "agp049", "version": "1"}})
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        self.p.stdin.flush()

    def req(self, method, params):
        self.n += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params}) + "\n")
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def tool(self, name, args):
        r = self.req("tools/call", {"name": name, "arguments": args})["result"]
        text = r["content"][0]["text"]
        return json.loads(text) if not r.get("isError") else {"isError": True, "text": text}

    def close(self):
        self.p.stdin.close()
        self.p.wait(10)


def start_signer(root, sock, extra_env, log):
    env = dict(os.environ, **extra_env, B2_SIGNER_SOCK=sock, B2_RPCHOST="127.0.0.1", B2_RPCPORT="34781",
               B2_RPCCOOKIE=f"{RUN}/rpc.cookie", B2_WALLET="agent", B2_HOT_KEYFILE=f"{RUN}/keys/{os.path.basename(root)}.key",
               B2_WATCH_INTERVAL="5")
    p = subprocess.Popen([f"{BIN}/xbt-signer", "--root", root], env=env, stdout=open(log, "a"), stderr=subprocess.STDOUT)
    wait(f"signer {root}", 60, lambda: os.path.exists(sock) and rpc_sock(sock, "health")["ok"])
    return p


def policy(human_pub, allow):
    return {"allowlist": allow, "max_per_tx_sats": 50_000, "daily_budget_sats": 30_000, "weekly_budget_sats": 100_000,
            "per_counterparty_cap_sats": 100_000, "velocity_max": 20, "velocity_window_s": 3600, "human_threshold_sats": 20_000,
            "split_window_s": 0, "human_pubkey": human_pub, "regtest_mine": False, "anchor_interval_s": 3600,
            "ln": {"enabled": True, "split_height": SPLIT, "max_fee_base_sats": 10, "max_fee_ppm": 5000, "timeout_s": 60}}


def fetch(svc, src, dst):
    dc("cp", f"{svc}:{src}", dst)
    os.chmod(dst, 0o600)


def bake(svc, dst, *caveats):
    ln(svc, "bakemacaroon", "--save_to=/tmp/rail.macaroon", *caveats, "info:read", "offchain:read", "offchain:write", "onchain:read")
    fetch(svc, "/tmp/rail.macaroon", dst)


def open_channel(*args):
    """lncli openchannel, retried: right after a connect or a new block the peer can answer
    "funding failed due to internal error" (the lab's own scenarios retry too)."""
    tip = int(b2b("getblockcount"))
    wait("lf1/lf2 at the tip", 60, lambda: synced("lf1", tip) and synced("lf2", tip))
    for i in range(6):
        try:
            return ln("lf1", "openchannel", *args)
        except RuntimeError as e:
            if i == 5:
                raise
            print(f"openchannel retry {i + 1}: {str(e)[-120:]}", flush=True)
            time.sleep(5)


def links_up():
    """Every lf1 channel active: right after a channel opens, lf1's peer bootstrapper can open a second
    connection to lf2 and drop the first, leaving the channels inactive for a moment (run 2 of AGP-049)."""
    wait("lf1's channels active", 60,
         lambda: len(ln("lf1", "listchannels", "--active_only")["channels"]) == len(ln("lf1", "listchannels")["channels"]))


def ledger_payments(run_dir):
    """The wallet's committed payments, read from its files as written (AGP-055): the append-only log
    named by ledger.json, a payment per line after the header, and {"amend": txid, "amount_sats": n|null}
    lines that change or drop the last row of that txid."""
    with open(f"{run_dir}/ledger.json") as f:
        doc = json.load(f)
    assert "payments" not in doc, "ledger.json no longer carries payments"
    rows = []
    with open(f"{run_dir}/{doc['payments_log']}") as f:
        for line in f.read().splitlines()[1:]:
            r = json.loads(line)
            if "amend" not in r:
                rows.append(r)
                continue
            i = max(i for i, p in enumerate(rows) if p["txid"] == r["amend"])
            if r["amount_sats"] is None:
                del rows[i]
            else:
                rows[i]["amount_sats"] = r["amount_sats"]
    return rows


def payments(svc):
    return {p["payment_hash"]: p for p in ln(svc, "listpayments", "--include_incomplete").get("payments", [])}


def outpoint_of(svc, sats):
    for u in ln(svc, "listunspent", "--min_confs=1")["utxos"]:
        if int(u["amount_sat"]) == sats:
            return u["outpoint"], int(u["confirmations"])
    raise RuntimeError(f"{svc}: no {sats}-sat coin")


def main():
    os.makedirs(f"{RUN}/keys", exist_ok=True)
    with open(f"{RUN}/rpc.cookie", "w") as f:
        f.write("lab:lab")

    # --- the chain: activation at 20, coins below and above the split --------------------------------
    h = int(b2b("getblockcount"))
    if h < 120:
        mine(120 - h)
    b2b("createwallet", "agent") if "agent" not in b2b("listwallets") else None
    wait("lf1/lf2 synced", 120, lambda: synced("lf1", 120) and synced("lf2", 120))
    wait("lnd-sha synced", 120, lambda: synced("lnd-sha"))
    lf2_pub, sha_pub = ln("lf2", "getinfo")["identity_pubkey"], ln("lnd-sha", "getinfo")["identity_pubkey"]
    lf1_pub = ln("lf1", "getinfo")["identity_pubkey"]
    addr = ln("lf1", "newaddress", "p2wkh")["address"]
    b2b("-rpcwallet=lab", "sendtoaddress", addr, "0.5")
    # a second pre-split coin that stays in lf1's wallet: ln_status must report it
    b2b("-rpcwallet=lab", "sendtoaddress", ln("lf1", "newaddress", "p2wkh")["address"], "0.2")
    hA = mine(1)
    mine(130 - hA)
    addr = ln("lf1", "newaddress", "p2wkh")["address"]
    b2b("-rpcwallet=lab", "sendtoaddress", addr, "1.0")
    hB = mine(1)
    tip = mine(1)
    wait("lf1 sees both coins", 60, lambda: synced("lf1", tip) and len(ln("lf1", "listunspent", "--min_confs=1")["utxos"]) >= 3)
    coinA, _ = outpoint_of("lf1", 50_000_000)
    coinA2, _ = outpoint_of("lf1", 20_000_000)
    coinB, _ = outpoint_of("lf1", 100_000_000)
    REPORT["chain"] = {"activation": 20, "split_height": SPLIT, "coin_a_height": hA, "coin_b_height": hB, "lf1": lf1_pub, "lf2": lf2_pub,
                       "lnd_sha": sha_pub, "anchor_101": b2b("getblockhash", "101")}
    print(f"chain: coin A (pre-split) at {hA}, coin B at {hB}, split {SPLIT}", flush=True)

    # --- a taproot channel only (from coin A: the operator's choice; this wallet opens none) -------------
    ln("lf1", "connect", f"{lf2_pub}@lf2:9735")
    tap = open_channel(f"--node_key={lf2_pub}", "--local_amt=400000", "--channel_type=taproot", "--private",
             f"--utxo={coinA}")
    mine(6)
    wait("taproot channel active", 90, lambda: len(ln("lf1", "listchannels", "--active_only")["channels"]) == 1)
    REPORT["taproot_channel"] = tap

    # --- the signer (the agent's) and the MCP ---------------------------------------------------------
    human = Ed25519PrivateKey.generate()
    human_pub = human.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    bake("lf1", f"{RUN}/lf1.macaroon")
    fetch("lf1", "/root/.lnd/tls.cert", f"{RUN}/lf1.tls.cert")
    root = f"{RUN}/wallet"
    os.makedirs(f"{root}/.run", exist_ok=True)
    with open(f"{root}/policy.json", "w") as f:
        json.dump(policy(human_pub, [f"ln:{lf2_pub}", f"ln:{sha_pub}"]), f, indent=2)
    sock = f"{RUN}/signer.sock"
    ln_env = {"B2_LN_REST": "https://127.0.0.1:34791", "B2_LN_MACAROON": f"{RUN}/lf1.macaroon", "B2_LN_TLS_CERT": f"{RUN}/lf1.tls.cert"}
    procs = [start_signer(root, sock, ln_env, f"{RUN}/signer.log")]
    menv = {k: v for k, v in os.environ.items() if not k.startswith("B2_LN")}
    mcp = Mcp(dict(menv, B2_SIGNER_SOCK=sock, XBT_MCP_LN="1"))
    try:
        run(mcp, sock, human, lf2_pub, sha_pub, coinB, procs)
        run_049(mcp, sock, human_pub, lf2_pub, coinA2, procs, ln_env)
    finally:
        mcp.close()
        for p in procs:
            p.terminate()
            p.wait(10)


def run(mcp, sock, human, lf2_pub, sha_pub, coinB, procs):
    dest = f"ln:{lf2_pub}"

    # S1 / S2: only a taproot channel
    st = mcp.tool("ln_status", {})
    REPORT["scenarios"]["S1_status_taproot_only"] = st
    check("S1 ln_status: chain check ok against our Knots node", st.get("chain_check", {}).get("ok") is True, st.get("chain_check"))
    check("S1 ln_status: the taproot channel is refused, rail not ready",
          st.get("ready") is False and st["channels"][0]["usable"] is False and "taproot" in st["channels"][0]["refused"], st.get("channels"))
    check("S1 ln_status: coin A's remainder (below the split) is reported", len(st.get("presplit_utxos", [])) >= 1, st.get("presplit_utxos"))
    inv1 = ln("lf2", "addinvoice", "--amt=1000", "--memo=coffee")
    r = mcp.tool("ln_pay", {"invoice": inv1["payment_request"], "max_sats": 1100})
    REPORT["scenarios"]["S2_taproot_only"] = r
    h1 = inv1["r_hash"]
    check("S2 taproot-only: refused ln_no_safe_channel", r.get("rule") == "ln_no_safe_channel", r)
    check("S2 no HTLC left lf1", h1 not in payments("lf1"), None)

    # S3: a unified anchors channel from the post-split coin B; pay within budget
    uni = open_channel(f"--node_key={lf2_pub}", "--local_amt=1000000", f"--utxo={coinB}")
    mine(6)
    wait("both channels active", 90, lambda: len(ln("lf1", "listchannels", "--active_only")["channels"]) == 2)
    chans = ln("lf1", "listchannels")["channels"]
    unified = [c for c in chans if c.get("unified_sigs")]
    REPORT["channels"] = [{k: c.get(k) for k in ("scid", "scid_str", "chan_id", "commitment_type", "unified_sigs", "capacity", "private")} for c in chans]
    check("S3 lf1 has one unified anchors channel and one taproot", len(unified) == 1 and "TAPROOT" not in unified[0]["commitment_type"], REPORT["channels"])
    time.sleep(3)
    r = mcp.tool("ln_pay", {"invoice": inv1["payment_request"], "max_sats": 1100, "description": "coffee"})
    for _ in range(5):  # a channel just active can fail its first try while channel_updates settle
        if r.get("rule") != "ln_payment_failed":
            break
        time.sleep(3)
        r = mcp.tool("ln_pay", {"invoice": inv1["payment_request"], "max_sats": 1100, "description": "coffee"})
    REPORT["scenarios"]["S3_within_budget"] = r
    check("S3 within budget: SUCCEEDED through the MCP", r.get("verdict") == "allow" and r.get("status") == "SUCCEEDED", r)
    pre = r.get("preimage", "")
    check("S3 sha256(preimage) is the payment hash", hashlib.sha256(bytes.fromhex(pre or "00")).hexdigest() == h1, pre)
    check("S3 lf2's invoice is SETTLED", ln("lf2", "lookupinvoice", h1)["state"] == "SETTLED", None)
    p1 = payments("lf1").get(h1, {})
    first_hops = {h["route"]["hops"][0]["chan_id"] for h in p1.get("htlcs", []) if h.get("status") == "SUCCEEDED"}
    # lncli prints chan_id as the 32-byte channel id and the numeric SCID as scid (REST's chan_id)
    check("S3 the HTLC left through the unified channel only", first_hops == {unified[0].get("scid", unified[0]["chan_id"])},
          {"hops": list(first_hops), "unified_scid": unified[0].get("scid")})
    charged1 = r.get("charged_sats", 0)

    # S4: over the daily budget (30,000): denied before any HTLC
    links_up()
    inv4 = ln("lf2", "addinvoice", "--amt=29500")
    r = mcp.tool("ln_pay", {"invoice": inv4["payment_request"], "max_sats": 40_000})
    REPORT["scenarios"]["S4_over_budget"] = r
    check("S4 over budget: denied daily_budget", r.get("verdict") == "deny" and r.get("rule") == "daily_budget", r)
    check("S4 no HTLC for it on lf1", inv4["r_hash"] not in payments("lf1"), None)

    # S5: over the human threshold (20,000): needs_human, the human approves on the signer socket
    links_up()
    inv5 = ln("lf2", "addinvoice", "--amt=21000")
    r = mcp.tool("ln_pay", {"invoice": inv5["payment_request"], "max_sats": 22_000})
    REPORT["scenarios"]["S5_needs_human"] = r
    check("S5 over threshold: needs_human", r.get("verdict") == "needs_human" and r.get("approval_token"), r)
    check("S5 nothing sent before the human", inv5["r_hash"] not in payments("lf1"), None)
    no_tool = mcp.tool("approve", {"token": r.get("approval_token")})
    check("S5 approve is not an MCP tool", no_tool.get("isError") and "Unknown tool" in no_tool.get("text", ""), no_tool)
    tok, exp, amt = r["approval_token"], int(r["approval_expires"]), int(r["amount_sats"])
    msg = b"\n".join([b"xbt-agentwallet-approve-v1", tok.encode(), dest.encode(), str(amt).encode(), str(exp).encode()])
    sig = human.sign(msg).hex()
    a = rpc_sock(sock, "approve", {"token": tok, "dest": dest, "amount_sats": amt, "expiry": exp, "signature": sig})
    REPORT["scenarios"]["S5_approve"] = a
    check("S5 the human's signature grants it", a.get("granted") is True and a.get("rail") == "ln", a)
    r = mcp.tool("ln_pay", {"invoice": inv5["payment_request"], "max_sats": 22_000})
    REPORT["scenarios"]["S5_paid"] = r
    check("S5 then paid under the approval", r.get("status") == "SUCCEEDED" and r.get("approved") is True, r)
    check("S5 lf2's invoice is SETTLED", ln("lf2", "lookupinvoice", inv5["r_hash"])["state"] == "SETTLED", None)
    charged5 = r.get("charged_sats", 0)

    # S6: an invoice without bit 512 (stock lnd on the SHA-256 regtest)
    inv6 = ln("lnd-sha", "addinvoice", "--amt=100")
    feats6 = sorted(int(k) for k in ln("lnd-sha", "decodepayreq", inv6["payment_request"]).get("features", {}))
    feats1 = sorted(int(k) for k in ln("lf1", "decodepayreq", inv1["payment_request"]).get("features", {}))
    r = mcp.tool("ln_pay", {"invoice": inv6["payment_request"], "max_sats": 1000})
    REPORT["scenarios"]["S6_no_512"] = {"result": r, "sha_invoice_features": feats6, "xbt_invoice_features": feats1}
    check("S6 the XBT invoice carries 512, the SHA-256 one does not", 512 in feats1 and 512 not in feats6, {"xbt": feats1, "sha": feats6})
    check("S6 no bit 512: refused ln_feature_512", r.get("rule") == "ln_feature_512", r)

    # S7: a signer whose LN node is the stock lnd on the SHA-256 chain
    bake("lnd-sha", f"{RUN}/sha.macaroon")
    fetch("lnd-sha", "/root/.lnd/tls.cert", f"{RUN}/sha.tls.cert")
    root2 = f"{RUN}/wallet-wrong"
    os.makedirs(f"{root2}/.run", exist_ok=True)
    with open(f"{root2}/policy.json", "w") as f:
        json.dump(policy(human.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
                         [f"ln:{lf2_pub}", f"ln:{sha_pub}"]), f)
    sock2 = f"{RUN}/signer-wrong.sock"
    procs.append(start_signer(root2, sock2, {"B2_LN_REST": "https://127.0.0.1:34793", "B2_LN_MACAROON": f"{RUN}/sha.macaroon",
                                             "B2_LN_TLS_CERT": f"{RUN}/sha.tls.cert"}, f"{RUN}/signer-wrong.log"))
    inv7 = ln("lf2", "addinvoice", "--amt=500")
    st7 = rpc_sock(sock2, "ln_status")
    r = rpc_sock(sock2, "ln_pay", {"invoice": inv7["payment_request"], "max_sats": 1000})
    REPORT["scenarios"]["S7_wrong_chain"] = {"status": st7, "pay": r}
    check("S7 wrong-chain backend: ln_status chain check fails", st7.get("chain_check", {}).get("ok") is False, st7.get("chain_check"))
    check("S7 wrong-chain backend: ln_pay refused ln_chain", r.get("rule") == "ln_chain", r)
    check("S7 nothing sent by either node", inv7["r_hash"] not in payments("lnd-sha") and inv7["r_hash"] not in payments("lf1"), None)
    # a pinned certificate that is not the node's: refused at TLS
    procs[-1].terminate()
    procs[-1].wait(10)
    os.remove(sock2) if os.path.exists(sock2) else None
    procs.append(start_signer(root2, sock2, {"B2_LN_REST": "https://127.0.0.1:34791", "B2_LN_MACAROON": f"{RUN}/lf1.macaroon",
                                             "B2_LN_TLS_CERT": f"{RUN}/sha.tls.cert"}, f"{RUN}/signer-wrong.log"))
    r = rpc_sock(sock2, "ln_pay", {"invoice": inv7["payment_request"], "max_sats": 1000})
    REPORT["scenarios"]["S7_wrong_cert"] = r
    check("S7 lf1 behind a certificate that is not the pinned one: refused", r.get("verdict") == "deny" and r.get("rule") in ("ln_backend", "ln_chain"), r)

    # S8: the logs and the ledger
    sigs = rpc_sock(sock, "signatures", {"limit": 1000})
    lnsigs = [s for s in sigs["signatures"] if s["kind"] == "ln_payment"]
    REPORT["scenarios"]["S8_signature_log"] = {"chain_ok": sigs["chain_ok"], "ln_payment": lnsigs}
    check("S8 signature log: one ln_payment per settled payment, sig_sha256 = payment hash",
          sorted(s["sig_sha256"] for s in lnsigs) == sorted([h1, inv5["r_hash"]]), lnsigs)
    check("S8 signature log chain intact", sigs["chain_ok"] is True, sigs.get("chain"))
    check("S8 the approved one is logged under the human's rule",
          any(s["sig_sha256"] == inv5["r_hash"] and s["rule"] == "human:approval_signature" for s in lnsigs), lnsigs)
    ev = rpc_sock(sock, "history", {"limit": 1000})["events"]
    kinds = {}
    for e in ev:
        kinds[e["type"]] = kinds.get(e["type"], 0) + 1
    REPORT["scenarios"]["S8_audit_counts"] = kinds
    check("S8 audit log: 2 settled, refusals and decisions recorded",
          kinds.get("ln_settled") == 2 and kinds.get("ln_refused", 0) >= 2 and kinds.get("decision", 0) >= 3, kinds)
    led = ledger_payments(f"{RUN}/wallet/.run")
    net = sum(p["amount_sats"] for p in led if p["dest"] == dest)
    check("S8 the ledger holds exactly what was charged", net == charged1 + charged5, {"ledger": net, "charged": charged1 + charged5})
    q = rpc_sock(sock, "ln_status")
    REPORT["scenarios"]["S8_final_status"] = q
    check("S8 final ln_status ready, nothing in flight", q.get("ready") is True and q.get("in_flight") == 0, {k: q.get(k) for k in ("ready", "in_flight")})

    # S9: the MCP surface
    names = [t["name"] for t in mcp.req("tools/list", {})["result"]["tools"]]
    REPORT["scenarios"]["S9_tools"] = names
    check("S9 12 tools with XBT_MCP_LN=1 (B2's 10 + ln_pay, ln_status)", len(names) == 12 and names[-2:] == ["ln_pay", "ln_status"], names)
    mcp_plain = Mcp({k: v for k, v in os.environ.items() if not k.startswith(("B2_LN", "XBT_MCP_LN"))} | {"B2_SIGNER_SOCK": sock})
    plain = [t["name"] for t in mcp_plain.req("tools/list", {})["result"]["tools"]]
    hidden = mcp_plain.tool("ln_pay", {"invoice": "x", "max_sats": 1})
    mcp_plain.close()
    check("S9 without XBT_MCP_LN: B2's exact 10, ln_pay unknown", len(plain) == 10 and hidden.get("isError"), {"tools": plain, "ln_pay": hidden})


# --- AGP-049 ------------------------------------------------------------------------------------------

def start_policy_signer(name, human_pub, lf2_pub, env, ln_extra=None, top=None):
    """A signer of its own (root RUN/name) on lf1 with the default policy plus these ln / top-level keys."""
    root = f"{RUN}/{name}"
    os.makedirs(f"{root}/.run", exist_ok=True)
    pol = policy(human_pub, [f"ln:{lf2_pub}"])
    pol["ln"].update(ln_extra or {})
    pol.update(top or {})
    with open(f"{root}/policy.json", "w") as f:
        json.dump(pol, f, indent=2)
    sock = f"{RUN}/{name}.sock"
    if os.path.exists(sock):
        os.remove(sock)
    return sock, start_signer(root, sock, env, f"{RUN}/{name}.log")


def stop(p):
    p.terminate()
    p.wait(10)


def first_hops(h):
    p = payments("lf1").get(h, {})
    return {x["route"]["hops"][0]["chan_id"] for x in p.get("htlcs", []) if x.get("status") == "SUCCEEDED"}


def pay_retry(call, inv, max_sats):
    r = call(inv, max_sats)
    for _ in range(5):  # a channel just active can fail its first try while channel_updates settle
        if r.get("rule") != "ln_payment_failed":
            break
        time.sleep(3)
        r = call(inv, max_sats)
    return r


def container_net(svc, field):
    cid = dc("ps", "-q", svc)
    r = subprocess.run(["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{." + field + "}}{{end}}", cid],
                       capture_output=True, text=True, check=True)
    return r.stdout.strip()


def lncli_from_lf2(macaroon_host_path, *args):
    """lncli in lf2 against lf1's gRPC (lf1:10009): the gRPC peer lf1 sees is lf2's own address."""
    dc("cp", macaroon_host_path, "lf2:/tmp/probe.macaroon")
    r = subprocess.run(["docker", "compose", "exec", "-T", "lf2", "lncli", "--network=regtest", "--rpcserver=lf1:10009",
                        "--tlscertpath=/tmp/lf1.cert", "--macaroonpath=/tmp/probe.macaroon", *args], cwd=LAB, capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()


def wait_status(sock, what, secs, pred):
    last = {}

    def ok():
        nonlocal last
        last = rpc_sock(sock, "ln_status")
        return pred(last)
    try:
        wait(what, secs, ok)
    except RuntimeError:
        pass
    return last


def run_049(mcp, sock, human_pub, lf2_pub, coinA2, procs, ln_env):
    # S10: funding proven from the transaction on our Knots node, not from LND's unified_sigs flag
    st = mcp.tool("ln_status", {})
    uni = [c for c in st.get("channels", []) if c.get("usable")]
    f = uni[0].get("funding", {}) if len(uni) == 1 else {}
    REPORT["scenarios"]["S10_status_funding"] = {"usable": uni}
    ins = f.get("evidence", {}).get("inputs", [])
    check("S10 the unified channel's funding is proven on our node: every input 0x21, confirmed at or above the split",
          f.get("proven") is True and ins and all(i["sighash"] == ["0x21"] and i["height"] >= SPLIT for i in ins), f)
    ftx = json.loads(b2b("getrawtransaction", f.get("evidence", {}).get("txid", "00"), "true")) if f.get("evidence") else {}
    wit = [v.get("txinwitness", [""])[0][-2:] for v in ftx.get("vin", [])]
    REPORT["scenarios"]["S10_knots_witness_sighash"] = wit
    check("S10 cross-check with bitcoin-cli: the funding inputs' signatures end in 0x21", wit and all(w == "21" for w in wit), wit)
    # LF opens a channel from coin A2, confirmed below the split: it signs 0x21 and LND calls it unified
    a2 = open_channel(f"--node_key={lf2_pub}", "--local_amt=150000", f"--utxo={coinA2}")
    mine(6)
    wait("the coin-A2 channel active", 90, lambda: len(ln("lf1", "listchannels", "--active_only")["channels"]) == 3)
    a2_txid = a2.get("funding_txid", "") if isinstance(a2, dict) else ""
    lnd_view = [c for c in ln("lf1", "listchannels")["channels"] if c["channel_point"].startswith(a2_txid)]
    st = mcp.tool("ln_status", {})
    ch = [c for c in st.get("channels", []) if (c.get("funding") or {}).get("evidence", {}).get("txid") == a2_txid]
    REPORT["scenarios"]["S10_presplit_channel"] = {"open": a2, "lnd": lnd_view, "ours": ch}
    check("S10 LND reports the coin-A2 channel unified (anchors)", lnd_view and lnd_view[0].get("unified_sigs") is True, lnd_view)
    check("S10 we refuse it: its 0x21 input was confirmed below the split",
          ch and ch[0]["usable"] is False and "below the split" in ch[0]["refused"]
          and ch[0]["funding"]["evidence"]["inputs"][0]["sighash"] == ["0x21"], ch)
    links_up()
    inv = ln("lf2", "addinvoice", "--amt=700")
    r = pay_retry(lambda i, m: mcp.tool("ln_pay", {"invoice": i, "max_sats": m}), inv["payment_request"], 800)
    REPORT["scenarios"]["S10_pay"] = r
    hops = first_hops(inv["r_hash"])
    check("S10 paid, and only through the proven channel", r.get("status") == "SUCCEEDED" and hops == {uni[0]["chan_id"]} if uni else False,
          {"result": r, "hops": list(hops)})

    # S11: the exposure cap is enforced
    links_up()
    s_cap, p = start_policy_signer("wallet-cap", human_pub, lf2_pub, ln_env, {"exposure_cap_sats": 100_000})
    procs.append(p)
    inv = ln("lf2", "addinvoice", "--amt=500")
    r = rpc_sock(s_cap, "ln_pay", {"invoice": inv["payment_request"], "max_sats": 1000})
    st = rpc_sock(s_cap, "ln_status")
    REPORT["scenarios"]["S11_exposure_cap"] = {"pay": r, "exposure": st.get("exposure"), "ready": st.get("ready")}
    check("S11 over the exposure cap: refused ln_exposure_cap", r.get("rule") == "ln_exposure_cap" and r["exposure"]["total_sats"] > 100_000, r)
    check("S11 no HTLC for it on lf1; ln_status not ready", inv["r_hash"] not in payments("lf1") and st.get("ready") is False, st.get("exposure"))

    # S12: the macaroon, and what an IP caveat does over REST and over gRPC
    mac = mcp.tool("ln_status", {}).get("macaroon", {})
    REPORT["scenarios"]["S12_macaroon"] = mac
    check("S12 ln_status reads the baked macaroon: exactly the rail's 4 permissions, no IP caveat",
          mac.get("ops") == ["info:read", "offchain:read", "offchain:write", "onchain:read"] and mac.get("ip_caveat") is None, mac)
    gw, lf2_ip = container_net("lf1", "Gateway"), container_net("lf2", "IPAddress")
    dc("cp", f"{RUN}/lf1.tls.cert", "lf2:/tmp/lf1.cert")
    bake("lf1", f"{RUN}/ip-lo.macaroon", "--ip_address=127.0.0.1")
    bake("lf1", f"{RUN}/ip-gw.macaroon", f"--ip_address={gw}")
    bake("lf1", f"{RUN}/ip-lf2.macaroon", f"--ip_address={lf2_ip}")
    s_lo, p = start_policy_signer("wallet-ip-lo", human_pub, lf2_pub, dict(ln_env, B2_LN_MACAROON=f"{RUN}/ip-lo.macaroon"))
    procs.append(p)
    st_lo = rpc_sock(s_lo, "ln_status")
    s_gw, p = start_policy_signer("wallet-ip-gw", human_pub, lf2_pub, dict(ln_env, B2_LN_MACAROON=f"{RUN}/ip-gw.macaroon"))
    procs.append(p)
    st_gw = rpc_sock(s_gw, "ln_status")
    rc_lf2, out_lf2 = lncli_from_lf2(f"{RUN}/ip-lf2.macaroon", "getinfo")
    rc_gw, out_gw = lncli_from_lf2(f"{RUN}/ip-gw.macaroon", "getinfo")
    REPORT["scenarios"]["S12_ip_caveat"] = {"gateway": gw, "lf2_ip": lf2_ip, "rest_127": {k: st_lo.get(k) for k in ("ready", "macaroon")},
                                            "rest_gateway": {k: st_gw.get(k) for k in ("ready", "reason")},
                                            "grpc_lf2_locked_to_lf2": [rc_lf2, out_lf2[-200:]], "grpc_lf2_locked_to_gateway": [rc_gw, out_gw[-200:]]}
    check("S12 REST: a macaroon locked to 127.0.0.1 works from the host (the REST gateway's gRPC peer is loopback)",
          st_lo.get("chain_check", {}).get("ok") is True and st_lo.get("macaroon", {}).get("ip_caveat") == "127.0.0.1", st_lo.get("macaroon"))
    check(f"S12 REST: a macaroon locked to the caller's real address ({gw}) is refused",
          st_gw.get("ready") is False and "locked to different IP" in str(st_gw.get("reason")), st_gw.get("reason"))
    check("S12 gRPC: the caveat binds: locked to lf2's address works from lf2, locked to another is refused",
          rc_lf2 == 0 and "identity_pubkey" in out_lf2 and rc_gw != 0 and "locked to different IP" in out_gw, {"lf2": out_lf2[-160:], "gw": out_gw[-160:]})

    # S14 + S13: lf2's watchtower on lf1's wtclient; the tower policy; the rate limit
    links_up()
    tinfo = ln("lf2", "tower", "info")
    tpub = tinfo["pubkey"]
    ln("lf1", "wtclient", "add", f"{tpub}@lf2:9911")
    st = mcp.tool("ln_status", {})
    tw = st.get("watchtowers", {})
    REPORT["scenarios"]["S14_status"] = {"watchtowers": tw, "warnings": st.get("warnings")}
    check("S14 ln_status lists lf1's wtclient tower (lf2), chain not verified",
          tw.get("wtclient") == "active" and [t["pubkey"] for t in tw.get("towers", [])] == [tpub] and tw["towers"][0]["chain_verified"] is False, tw)
    check("S14 ... and warns loudly", any("WARNING" in w and tpub in w for w in st.get("warnings", [])), st.get("warnings"))
    s_st, p = start_policy_signer("wallet-strict", human_pub, lf2_pub, ln_env, {"tower_policy": "refuse", "max_sends_per_hour": 1})
    procs.append(p)
    inv = ln("lf2", "addinvoice", "--amt=600")
    r = rpc_sock(s_st, "ln_pay", {"invoice": inv["payment_request"], "max_sats": 1000})
    REPORT["scenarios"]["S14_refuse"] = r
    check("S14 tower_policy refuse: ln_tower_chain, no HTLC", r.get("rule") == "ln_tower_chain" and inv["r_hash"] not in payments("lf1"), r)
    stop(p)
    s_st, p = start_policy_signer("wallet-strict", human_pub, lf2_pub, ln_env,
                                  {"tower_policy": "refuse", "trusted_towers": [tpub], "max_sends_per_hour": 1})
    procs.append(p)
    r = pay_retry(lambda i, m: rpc_sock(s_st, "ln_pay", {"invoice": i, "max_sats": m}), inv["payment_request"], 1000)
    REPORT["scenarios"]["S14_trusted"] = r
    check("S14 the tower in ln.trusted_towers: paid", r.get("status") == "SUCCEEDED", r)
    inv2 = ln("lf2", "addinvoice", "--amt=600")
    r = rpc_sock(s_st, "ln_pay", {"invoice": inv2["payment_request"], "max_sats": 1000})
    REPORT["scenarios"]["S13_rate_limit"] = r
    check("S13 max_sends_per_hour 1: the second send is refused ln_rate_limit, no HTLC",
          r.get("rule") == "ln_rate_limit" and inv2["r_hash"] not in payments("lf1"), r)

    # S15: a hold invoice keeps the payment in flight; an HTLC sent outside the wallet counts against the budget
    links_up()
    s_h, p = start_policy_signer("wallet-hold", human_pub, lf2_pub, ln_env, {"timeout_s": 5}, {"daily_budget_sats": 10_000})
    procs.append(p)
    pre = os.urandom(32)
    hh = hashlib.sha256(pre).hexdigest()
    hold = ln("lf2", "addholdinvoice", hh, "--amt=2000")
    r = rpc_sock(s_h, "ln_pay", {"invoice": hold["payment_request"], "max_sats": 3000}, timeout=180)
    tip = int(b2b("getblockcount"))
    st = rpc_sock(s_h, "ln_status")
    REPORT["scenarios"]["S15_hold_pending"] = {"pay": r, "in_flight": st.get("in_flight_payments"), "htlc_locks": st.get("htlc_locks"), "tip": tip}
    check("S15 the held payment is pending, booked at its worst case, with its CLTV height",
          r.get("verdict") == "pending" and st.get("in_flight") == 1 and (st.get("in_flight_payments") or [{}])[0].get("cltv_until", 0) > tip,
          {"pay": r, "in_flight": st.get("in_flight_payments")})
    check("S15 ln_status: the HTLC is on lf1's channel, booked", st.get("htlc_locks", {}).get("booked_sats", 0) >= 2000
          and st["htlc_locks"]["unbooked_sats"] == 0, st.get("htlc_locks"))
    ln("lf2", "settleinvoice", pre.hex())
    st = wait_status(s_h, "the held payment settled", 60, lambda q: q.get("in_flight") == 0)
    check("S15 settled by the payee: reconciled, settled", st.get("in_flight") == 0 and st.get("recent", [{}])[0].get("state") == "settled",
          st.get("recent", [])[:1])
    # lf1 pays a held invoice outside the wallet (lncli, not the signer)
    pre2 = os.urandom(32)
    h2 = hashlib.sha256(pre2).hexdigest()
    hold2 = ln("lf2", "addholdinvoice", h2, "--amt=5000")
    bg = subprocess.Popen(["docker", "compose", "exec", "-T", "lf1", "lncli", "--network=regtest", "--rpcserver=127.0.0.1:10009", "payinvoice",
                           "--force", "--json", hold2["payment_request"]], cwd=LAB, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        st = wait_status(s_h, "the foreign HTLC", 60, lambda q: q.get("htlc_locks", {}).get("unbooked_sats", 0) >= 5000)
        REPORT["scenarios"]["S15_foreign_lock"] = {"htlc_locks": st.get("htlc_locks"), "warnings": st.get("warnings")}
        check("S15 an HTLC lf1 sent outside the wallet is seen, unbooked, with its expiry",
              st.get("htlc_locks", {}).get("unbooked_sats") == 5000 and st["htlc_locks"]["until_height"] > tip, st.get("htlc_locks"))
        inv3 = ln("lf2", "addinvoice", "--amt=3000")
        r = rpc_sock(s_h, "ln_pay", {"invoice": inv3["payment_request"], "max_sats": 4000})
        REPORT["scenarios"]["S15_lock_refused"] = r
        check("S15 3,025 + 5,000 locked > the 8,000 left today: refused ln_htlc_lock, no HTLC",
              r.get("rule") == "ln_htlc_lock" and inv3["r_hash"] not in payments("lf1"), r)
        ln("lf2", "cancelinvoice", h2)
        st = wait_status(s_h, "the foreign HTLC gone", 60, lambda q: q.get("htlc_locks", {}).get("unbooked_sats", 1) == 0)
        r = pay_retry(lambda i, m: rpc_sock(s_h, "ln_pay", {"invoice": i, "max_sats": m}), inv3["payment_request"], 4000)
        REPORT["scenarios"]["S15_after_cancel"] = r
        check("S15 cancelled: the lock is gone and the same payment goes through", st.get("htlc_locks", {}).get("unbooked_sats") == 0
              and r.get("status") == "SUCCEEDED", r)
    finally:
        bg.kill()
    led = sum(x["amount_sats"] for x in ledger_payments(f"{RUN}/wallet-hold/.run"))
    check("S15 the hold wallet's ledger is exact: 2,000 + 3,000 (direct peer, no fee)", led == 5000, led)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # a harness failure is a failure
        check("harness", False, repr(e))
    REPORT["ok"] = not FAILED
    REPORT["failed"] = FAILED
    os.makedirs(OUT, exist_ok=True)
    with open(f"{OUT}/ln_rail_regtest.json", "w") as f:
        json.dump(REPORT, f, indent=2, sort_keys=True)
    print(f"\n{len(REPORT['checks']) - len(FAILED)}/{len(REPORT['checks'])} checks passed; report {OUT}/ln_rail_regtest.json")
    sys.exit(1 if FAILED else 0)
