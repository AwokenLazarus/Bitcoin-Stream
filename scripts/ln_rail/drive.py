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
  AGP-066:
  S16 lf1's TrackPaymentV2 by hash: a settled payment's record; a hash it never paid is 404 "payment
      isn't initiated"; the wallet holds nothing in flight and is not halted
  S17 the macaroon report is an allowlist: uri:/lnrpc.Lightning/SendCoins is excess, not least privilege
  S18 B2_LN_REST http://[::ffff:10.0.0.5]:8080 is refused (plain http only on loopback)
  AGP-083 (BOLT 12 offers, AGP-082, on the real node; lf2 mints the offers):
  S19 lf1 holds a taproot and a pre-split channel: an offer is refused ln_offer_unsafe_channel before
      any invoice is asked for, and the same node still pays a BOLT 11 invoice
  S20 lf3 opens one anchors channel from a coin confirmed above the split: ln_status ready, every
      channel proven; the wallet on lf3 has the rail's four-permission macaroon
  S21 an offer the policy does not list: denied before any invoice is asked for
  S22 a priced offer larger than lf3 can send: the invoice is fetched and written down, the payment
      FAILS on the node, nothing is charged; again, and after the signer restarts and lf3 has the
      funds, the stored lni1 is paid: lf2 issued one invoice for all of it; the preimage is booked
  S23 the same offer paid again: a second invoice, the same signing key, another payer id
  S24 an offer with no amount and blinded paths, paid with amount_sats, twice; the ledger is exact

  What run 1 of AGP-083 showed about the fork, which S20 now sets the lab up for:
  - lf2's BOLT 12 invoices are paid over blinded paths that start at its peer lf1, so lf3 -> lf2 pays
    lf3 -> lf2 -> lf1 -> lf2: it costs a routing fee (2,246 to 3,261 msat on 15,000 sats) though lf2 is lf3's
    direct peer, and it needs lf2 to hold funds towards lf1. lf1 pays lf2 300,000 sats first.
  - an offer minted --with_paths is reached through lf1 too. lf3, not lf1's peer, sent its invoice
    request by lf2, and lf1 dropped it ("onion message cycle: next hop is the sending peer"): the fetch
    timed out after 60 s (ln_fetch_invoice) and worked a minute later, once lf3 had connected to lf1.
    lf3 connects to lf1 first.

Environment: LAB (the lab checkout), OUT (report dir), BIN (the release binaries), RUN (scratch dir).
"""
import base64
import hashlib
import http.client
import json
import os
import socket
import ssl
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
    env = dict(os.environ, **extra_env, B2_SIGNER_SOCK=sock, B2_RPCHOST="127.0.0.1", B2_RPCPORT="17481",
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


def open_channel(*args, svc="lf1"):
    """lncli openchannel, retried: right after a connect or a new block the peer can answer
    "funding failed due to internal error" (the lab's own scenarios retry too)."""
    tip = int(b2b("getblockcount"))
    wait(f"{svc}/lf2 at the tip", 60, lambda: synced(svc, tip) and synced("lf2", tip))
    for i in range(6):
        try:
            return ln(svc, "openchannel", *args)
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
    ln_env = {"B2_LN_REST": "https://127.0.0.1:17491", "B2_LN_MACAROON": f"{RUN}/lf1.macaroon", "B2_LN_TLS_CERT": f"{RUN}/lf1.tls.cert"}
    procs = [start_signer(root, sock, ln_env, f"{RUN}/signer.log")]
    menv = {k: v for k, v in os.environ.items() if not k.startswith("B2_LN")}
    mcp = Mcp(dict(menv, B2_SIGNER_SOCK=sock, XBT_MCP_LN="1"))
    try:
        run(mcp, sock, human, lf2_pub, sha_pub, coinB, procs)
        run_049(mcp, sock, human_pub, lf2_pub, coinA2, procs, ln_env)
        run_066(mcp, human_pub, lf2_pub, procs, ln_env)
        run_083(mcp, human_pub, lf2_pub, procs)
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
    procs.append(start_signer(root2, sock2, {"B2_LN_REST": "https://127.0.0.1:17493", "B2_LN_MACAROON": f"{RUN}/sha.macaroon",
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
    procs.append(start_signer(root2, sock2, {"B2_LN_REST": "https://127.0.0.1:17491", "B2_LN_MACAROON": f"{RUN}/lf1.macaroon",
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


# --- AGP-066 ------------------------------------------------------------------------------------------

def lf1_rest(path):
    """GET lf1's REST API as the signer does (its tls.cert pinned, the rail macaroon): the status and the
    body, or only its first line for a 200 (TrackPaymentV2 streams one JSON object per line)."""
    ctx = ssl.create_default_context(cafile=f"{RUN}/lf1.tls.cert")
    ctx.check_hostname = False
    c = http.client.HTTPSConnection("127.0.0.1", 17491, context=ctx, timeout=30)
    with open(f"{RUN}/lf1.macaroon", "rb") as f:
        mac = f.read().hex()
    c.request("GET", path, headers={"Grpc-Metadata-macaroon": mac})
    r = c.getresponse()
    body = r.readline() if r.status == 200 else r.read()
    c.close()
    return r.status, json.loads(body or b"{}")


def track_path(hash_hex):
    return "/v2/router/track/" + base64.urlsafe_b64encode(bytes.fromhex(hash_hex)).decode()


def run_066(mcp, human_pub, lf2_pub, procs, ln_env):
    # S16 (L3): a payment is looked up by its hash; the node's answer for one it never started
    settled = [h for h, p in payments("lf1").items() if p.get("status") == "SUCCEEDED"]
    code, known = lf1_rest(track_path(settled[0]))
    unknown_hash = os.urandom(32).hex()
    code_u, unknown = lf1_rest(track_path(unknown_hash))
    REPORT["scenarios"]["S16_lookup_by_hash"] = {"known": [code, known], "unknown": [code_u, unknown], "payments_on_lf1": len(settled)}
    check("S16 TrackPaymentV2 by hash: a settled payment's record, its hash, SUCCEEDED",
          code == 200 and known.get("result", {}).get("payment_hash") == settled[0] and known["result"].get("status") == "SUCCEEDED", known)
    check("S16 a hash lf1 never paid: 404 \"payment isn't initiated\" (the only answer the signer reads as no payment)",
          code_u == 404 and "payment isn't initiated" in str((unknown.get("error") or unknown).get("message")), [code_u, unknown])
    st = mcp.tool("ln_status", {})
    check("S16 after every lookup, the wallet holds nothing in flight and is not halted",
          st.get("in_flight") == 0 and st.get("halted") is None, {k: st.get(k) for k in ("in_flight", "halted", "ready")})

    # S17 (L2): the macaroon report is an allowlist: one extra URI permission is not least privilege
    mac = st.get("macaroon", {})
    bake("lf1", f"{RUN}/uri.macaroon", "uri:/lnrpc.Lightning/SendCoins")
    s_uri, p = start_policy_signer("wallet-uri", human_pub, lf2_pub, dict(ln_env, B2_LN_MACAROON=f"{RUN}/uri.macaroon"))
    procs.append(p)
    mac_uri = rpc_sock(s_uri, "ln_status").get("macaroon", {})
    stop(p)
    REPORT["scenarios"]["S17_macaroon_allowlist"] = {"rail": mac, "with_send_coins": mac_uri}
    check("S17 the rail's own macaroon is least privilege", mac.get("only_needed") is True and mac.get("excess_ops") == [], mac)
    check("S17 a macaroon adding uri:/lnrpc.Lightning/SendCoins is not (refused on mainnet), though no denylist names it",
          mac_uri.get("only_needed") is False and "uri:/lnrpc.Lightning/SendCoins" in mac_uri.get("excess_ops", [])
          and mac_uri.get("dangerous_ops") == [], mac_uri)

    # S18 (L1): plain http to an IPv4-mapped LAN address is not loopback
    s_v6, p = start_policy_signer("wallet-v6", human_pub, lf2_pub, dict(ln_env, B2_LN_REST="http://[::ffff:10.0.0.5]:8080"))
    procs.append(p)
    st_v6 = rpc_sock(s_v6, "ln_status")
    stop(p)
    REPORT["scenarios"]["S18_ipv6_mapped_http"] = st_v6
    check("S18 http://[::ffff:10.0.0.5]:8080 is refused: plain http only on loopback, the macaroon is not sent",
          st_v6.get("ready") is not True and "must be https" in json.dumps(st_v6), st_v6)


# --- AGP-083: BOLT 12 offers on the real node --------------------------------------------------------------

def hexid(v):
    """A bytes field as lncli prints it (hex) or as the REST API does (base64), as hex."""
    v = v or ""
    if len(v) in (64, 66) and all(c in "0123456789abcdefABCDEF" for c in v):
        return v.lower()
    return base64.b64decode(v).hex()


def mint(*args):
    """lf2 mints an offer: its lno1 string and its id."""
    o = ln("lf2", "offer", "create", *args)
    o = o.get("offer", o)
    return o["bolt12"], hexid(o["offer_id"])


def issued(oid):
    """How many invoices lf2 has issued for its offer, by its own count and by its list of them."""
    count = [int(o.get("invoices_issued") or 0) for o in ln("lf2", "offer", "list").get("offers", []) if hexid(o.get("offer_id")) == oid]
    rows = [i for i in ln("lf2", "offer", "invoices").get("invoices", []) if hexid(i.get("offer_id")) == oid]
    return (count[0] if count else -1), rows


def offer_record(root, oid):
    with open(f"{root}/.run/ln_offers.json") as f:
        return json.load(f)["offers"].get(oid, {})


def run_083(mcp, human_pub, lf2_pub, procs):
    # S19: lf1 (a taproot channel, a pre-split one, and the proven one) pays no offer
    lno_a, oid_a = mint("--description", "tea", "--amount_msat", "2000000")
    r = mcp.tool("ln_pay", {"invoice": lno_a, "max_sats": 3000})
    n_a, rows_a = issued(oid_a)
    REPORT["scenarios"]["S19_unsafe_channel"] = {"offer": lno_a, "offer_id": oid_a, "pay": r, "lf2_invoices_issued": n_a,
                                                 "lf1_version": ln("lf1", "getinfo").get("version")}
    refused = [c for c in r.get("channels", []) if c.get("usable") is not True]
    check("S19 lf1 runs Lightning Fork .17", "blake2b.17" in str(ln("lf1", "getinfo").get("version")), ln("lf1", "getinfo").get("version"))
    check("S19 an offer through lf1: refused ln_offer_unsafe_channel, naming the taproot and the pre-split channel",
          r.get("rule") == "ln_offer_unsafe_channel" and r.get("dest") == f"ln-offer:{oid_a}" and len(refused) == 2
          and any("taproot" in str(c.get("refused")) for c in refused) and any("below the split" in str(c.get("refused")) for c in refused), r)
    check("S19 before any invoice: lf2 issued none for the offer", n_a == 0 and rows_a == [], {"issued": n_a, "rows": rows_a})
    links_up()
    inv = ln("lf2", "addinvoice", "--amt=400")
    r = pay_retry(lambda i, m: mcp.tool("ln_pay", {"invoice": i, "max_sats": m}), inv["payment_request"], 500)
    REPORT["scenarios"]["S19_bolt11_still_pays"] = r
    check("S19 the same node still pays a BOLT 11 invoice (confined to its proven channel)", r.get("status") == "SUCCEEDED", r)

    # S20: lf3, whose only channel is funded by a coin confirmed above the split
    wait("lf3 synced", 120, lambda: synced("lf3", int(b2b("getblockcount"))))
    lf3_pub = ln("lf3", "getinfo")["identity_pubkey"]
    # lf2's invoices are paid through its peer lf1 (see the top of this file): lf2 needs funds towards lf1 on
    # their announced channels, and lf3 must reach lf1 with an invoice request
    for c in ln("lf1", "listchannels")["channels"]:
        if not c["private"] and int(c["local_balance"]) > 400_000:
            fund = ln("lf2", "addinvoice", "--amt=300000")
            ln("lf1", "payinvoice", "--force", "--json", f"--outgoing_chan_id={c.get('scid', c['chan_id'])}", fund["payment_request"])
    lf1_pub = ln("lf1", "getinfo")["identity_pubkey"]
    ln("lf3", "connect", f"{lf1_pub}@lf1:9735")
    b2b("-rpcwallet=lab", "sendtoaddress", ln("lf3", "newaddress", "p2wkh")["address"], "0.05")
    h_coin = mine(1)
    tip = mine(1)
    wait("lf3 sees its coin", 60, lambda: synced("lf3", tip) and len(ln("lf3", "listunspent", "--min_confs=1")["utxos"]) == 1)
    ln("lf3", "connect", f"{lf2_pub}@lf2:9735")
    # lf3 keeps 20,000 of the 1,000,000: less than its reserve and the 15,000-sat offer of S22 together
    ch3 = open_channel(f"--node_key={lf2_pub}", "--local_amt=1000000", "--push_amt=980000", svc="lf3")
    mine(6)
    wait("lf3's channel active", 90, lambda: len(ln("lf3", "listchannels", "--active_only")["channels"]) == 1)
    wait("lf2 sees lf3's channel active", 90,
         lambda: any(c["remote_pubkey"] == lf3_pub for c in ln("lf2", "listchannels", "--active_only")["channels"]))
    lno_b, oid_b = mint("--description", "a report", "--amount_msat", "15000000")
    lno_c, oid_c = mint("--description", "tips", "--with_paths")
    lno_x, oid_x = mint("--description", "not on the list", "--amount_msat", "1000000")
    bake("lf3", f"{RUN}/lf3.macaroon")
    fetch("lf3", "/root/.lnd/tls.cert", f"{RUN}/lf3.tls.cert")
    env3 = {"B2_LN_REST": "https://127.0.0.1:17495", "B2_LN_MACAROON": f"{RUN}/lf3.macaroon", "B2_LN_TLS_CERT": f"{RUN}/lf3.tls.cert"}
    # the default 30,000-sat day is what two pays of the 15,000-sat offer cost
    allow = {"allowlist": [f"ln-offer:{oid_b}", f"ln-offer:{oid_c}"], "daily_budget_sats": 60_000}
    root3 = f"{RUN}/wallet-offer"
    s3, p3 = start_policy_signer("wallet-offer", human_pub, lf2_pub, env3, top=allow)
    procs.append(p3)
    st = rpc_sock(s3, "ln_status")
    chans = st.get("channels", [])
    ins = (chans[0].get("funding", {}).get("evidence", {}).get("inputs", []) if chans else [])
    REPORT["scenarios"]["S20_lf3"] = {"pubkey": lf3_pub, "version": ln("lf3", "getinfo").get("version"), "coin_height": h_coin, "open": ch3,
                                      "channels": chans, "macaroon": st.get("macaroon"), "chain_check": st.get("chain_check"),
                                      "offers": {"priced": [oid_b, lno_b], "any_amount_blinded": [oid_c, lno_c], "unlisted": [oid_x, lno_x]}}
    check("S20 lf3: ready, its one channel usable, funded 0x21 by a coin confirmed at or above the split",
          st.get("ready") is True and len(chans) == 1 and chans[0].get("usable") is True and chans[0]["funding"].get("proven") is True
          and ins and all(i["sighash"] == ["0x21"] and i["height"] >= SPLIT for i in ins), {"ready": st.get("ready"), "channels": chans})
    check("S20 the wallet on lf3 holds the rail's four permissions and no more (no invoices:read)",
          st.get("macaroon", {}).get("ops") == ["info:read", "offchain:read", "offchain:write", "onchain:read"], st.get("macaroon"))

    # S21: the policy decides on ln-offer:<offer id> before any invoice exists
    r = rpc_sock(s3, "ln_pay", {"invoice": lno_x, "max_sats": 2000})
    n_x, _ = issued(oid_x)
    REPORT["scenarios"]["S21_not_allowlisted"] = {"pay": r, "lf2_invoices_issued": n_x}
    check("S21 an offer the allowlist does not name: denied, and lf2 was asked for no invoice",
          r.get("verdict") == "deny" and r.get("rule") == "allowlist" and n_x == 0, {"pay": r, "issued": n_x})

    # S22: the pay fails on the node; the retry pays the stored lni1, and lf2 issues one invoice for all of it
    pay_b = {"invoice": lno_b, "max_sats": 16_000, "description": "a report"}
    r1 = rpc_sock(s3, "ln_pay", pay_b, timeout=180)
    h_b = r1.get("payment_hash", "")
    rec1 = offer_record(root3, oid_b)
    n1, rows1 = issued(oid_b)
    lf3_p1 = payments("lf3").get(h_b, {})
    REPORT["scenarios"]["S22_failed"] = {"pay": r1, "offer_record": rec1, "lf2_invoices_issued": n1, "lf2_invoices": rows1,
                                         "lf3_payment": {k: lf3_p1.get(k) for k in ("status", "failure_reason", "value_msat", "payment_request")}}
    check("S22 the offer is larger than lf3 can send: the payment FAILED on the node, nothing charged",
          r1.get("rule") == "ln_payment_failed" and r1.get("charged_sats") == 0 and r1.get("invoice_reused") is False
          and lf3_p1.get("status") == "FAILED", {"pay": r1, "lf3": lf3_p1.get("status")})
    lni = rec1.get("last_invoice", {}).get("invoice", "")
    check("S22 the fetched lni1 was written down before it was paid, with its hash and the key that signed it",
          lni.startswith("lni1") and rec1["last_invoice"].get("payment_hash") == h_b and len(rec1.get("node_id", "")) == 66, rec1)
    check("S22 lf2 issued one invoice for the offer, OPEN, with that hash", n1 == 1 and len(rows1) == 1 and hexid(rows1[0]["payment_hash"]) == h_b
          and rows1[0].get("state") == "OPEN", {"issued": n1, "rows": rows1})
    check("S22 nothing in the ledger", ledger_payments(f"{root3}/.run") == [], ledger_payments(f"{root3}/.run"))
    r2 = rpc_sock(s3, "ln_pay", pay_b, timeout=180)
    n2, _ = issued(oid_b)
    REPORT["scenarios"]["S22_failed_again"] = {"pay": r2, "lf2_invoices_issued": n2}
    check("S22 again while it cannot be sent: the same invoice is tried (invoice_reused), fails, and lf2 still issued one",
          r2.get("rule") == "ln_payment_failed" and r2.get("payment_hash") == h_b and r2.get("invoice_reused") is True and n2 == 1,
          {"pay": r2, "issued": n2})
    # lf3 is given the funds (lf2 pays it a BOLT 11 invoice), and the signer restarts: the lni1 is on disk
    top_up = ln("lf3", "addinvoice", "--amt=200000")
    ln("lf2", "payinvoice", "--force", "--json", top_up["payment_request"])
    wait("lf3 holds the top-up", 60, lambda: int(ln("lf3", "listchannels")["channels"][0]["local_balance"]) > 200_000)
    stop(p3)
    s3, p3 = start_policy_signer("wallet-offer", human_pub, lf2_pub, env3, top=allow)
    procs.append(p3)
    r3 = rpc_sock(s3, "ln_pay", pay_b, timeout=180)
    for _ in range(5):
        if r3.get("rule") != "ln_payment_failed":
            break
        time.sleep(3)
        r3 = rpc_sock(s3, "ln_pay", pay_b, timeout=180)
    n3, rows3 = issued(oid_b)
    st = rpc_sock(s3, "ln_status")
    booked = [x for x in st.get("recent", []) if x.get("payment_hash") == h_b or x.get("hash") == h_b]
    sigs = rpc_sock(s3, "signatures", {"limit": 1000})
    sig_b = [x for x in sigs["signatures"] if x["kind"] == "ln_payment" and x["sig_sha256"] == h_b]
    REPORT["scenarios"]["S22_retried"] = {"pay": r3, "lf2_invoices_issued": n3, "lf2_invoices": rows3, "booked": booked, "signature_log": sig_b,
                                          "lf3_payment_status": payments("lf3").get(h_b, {}).get("status")}
    pre = r3.get("preimage", "")
    check("S22 retried after a restart, with funds: SUCCEEDED, paying the stored invoice (same hash, invoice_reused)",
          r3.get("verdict") == "allow" and r3.get("status") == "SUCCEEDED" and r3.get("payment_hash") == h_b and r3.get("invoice_reused") is True
          and r3.get("dest") == f"ln-offer:{oid_b}", r3)
    check("S22 the preimage is booked: sha256(preimage) is the payment hash, in the reply, the payment book and the signature log",
          hashlib.sha256(bytes.fromhex(pre or "00")).hexdigest() == h_b and len(sig_b) == 1 and sig_b[0].get("offer_id", oid_b) == oid_b
          and any(x.get("state") == "settled" for x in booked), {"preimage": pre, "sig": sig_b, "booked": booked})
    check("S22 lf2 issued ONE invoice across two failures, a restart and the retry, and it is SETTLED for at least 15,000 sats",
          n3 == 1 and len(rows3) == 1 and rows3[0].get("state") == "SETTLED"
          and 15_000_000 <= int(rows3[0].get("amount_paid_msat") or 0) <= 15_085_000, {"issued": n3, "rows": rows3})
    # the invoice's blinded paths start at lf2's peer lf1, so the payment is routed and pays a fee
    fee3 = int(r3.get("fee_msat") or 0)
    check("S22 charged the 15,000 and the routing fee the node reports, within the 85-sat limit; the rest of the booking is released",
          r3.get("charged_sats") == -(-(15_000_000 + fee3) // 1000) and 15_000 <= r3.get("charged_sats", 0) <= 15_085,
          {"charged": r3.get("charged_sats"), "fee_msat": fee3})

    # S23: the same offer again: a second invoice, the same signer, another payer id
    r4 = rpc_sock(s3, "ln_pay", pay_b, timeout=180)
    n4, rows4 = issued(oid_b)
    rec4 = offer_record(root3, oid_b)
    REPORT["scenarios"]["S23_second_pay"] = {"pay": r4, "lf2_invoices_issued": n4, "lf2_invoices": rows4, "offer_record": rec4}
    check("S23 the same offer paid again: a new invoice (another hash), SUCCEEDED, lf2 issued two and both are SETTLED",
          r4.get("status") == "SUCCEEDED" and r4.get("payment_hash") not in ("", h_b) and r4.get("invoice_reused") is False and n4 == 2
          and sorted(x.get("state") for x in rows4) == ["SETTLED", "SETTLED"], {"pay": r4, "issued": n4})
    check("S23 signed by the key recorded with the first invoice (lf2's node id: the offer has no blinded path)",
          rec4.get("node_id") == rec1.get("node_id") == lf2_pub, {"recorded": rec4.get("node_id"), "lf2": lf2_pub})
    payer_ids = {r3.get("payer_id"), r4.get("payer_id")}
    check("S23 two pays of one offer carry two payer ids (lf2 lists the same two): no payer identity here",
          len(payer_ids) == 2 and None not in payer_ids and payer_ids == {hexid(x.get("payer_id")) for x in rows4},
          {"ours": [str(x) for x in payer_ids], "lf2": [hexid(x.get("payer_id")) for x in rows4]})

    # S24: an offer that names no amount and is reached through a blinded path
    pay_c = {"invoice": lno_c, "max_sats": 1300, "amount_sats": 1234, "description": "tips"}
    def pay_any():
        tries = [rpc_sock(s3, "ln_pay", pay_c, timeout=180)]
        while tries[-1].get("rule") in ("ln_payment_failed", "ln_fetch_invoice") and len(tries) < 4:
            time.sleep(3)
            tries.append(rpc_sock(s3, "ln_pay", pay_c, timeout=180))
        return tries[-1], tries[:-1]
    r5, before5 = pay_any()
    rec5 = offer_record(root3, oid_c)
    r6, before6 = pay_any()
    n6, rows6 = issued(oid_c)
    dec = ln("lf3", "offer", "decode", lno_c)
    REPORT["scenarios"]["S24_blinded_any_amount"] = {"first": r5, "second": r6, "offer_record": rec5, "lf2_invoices_issued": n6, "lf2_invoices": rows6,
                                                     "lf3_decode": dec, "tries_before": before5 + before6}
    check("S24 the offer carries blinded paths and names no amount (lf3's own decode)",
          int(dec.get("offer", {}).get("num_paths") or 0) >= 1 and int(dec.get("offer", {}).get("amount_msat") or 0) == 0, dec.get("offer"))
    check("S24 paid for the 1,234 sats asked with amount_sats: SUCCEEDED, the preimage proves it",
          r5.get("status") == "SUCCEEDED" and 1234 <= r5.get("charged_sats", 0) <= 1251 and r5.get("value_msat") == 1_234_000
          and r5.get("dest") == f"ln-offer:{oid_c}"
          and hashlib.sha256(bytes.fromhex(r5.get("preimage") or "00")).hexdigest() == r5.get("payment_hash"), r5)
    check("S24 the offer keeps its issuer id beside the paths, and both invoices are signed by it (lf2's node id), not by a blinded key",
          hexid(dec.get("offer", {}).get("issuer_id")) == lf2_pub == rec5.get("node_id") and r6.get("status") == "SUCCEEDED"
          and offer_record(root3, oid_c).get("node_id") == lf2_pub and r6.get("payment_hash") != r5.get("payment_hash"),
          {"recorded": rec5.get("node_id"), "lf2": lf2_pub, "second": r6})
    paid6 = [int(x.get("amount_paid_msat") or 0) for x in rows6 if x.get("state") == "SETTLED"]
    check("S24 lf2 holds two SETTLED invoices for it, each paid at least 1,234,000 msat, and no invoice was asked for in vain",
          n6 == 2 and len(paid6) == 2 and all(1_234_000 <= a <= 1_251_000 for a in paid6) and before5 + before6 == [],
          {"issued": n6, "rows": rows6, "tries_before": before5 + before6})
    led = ledger_payments(f"{root3}/.run")
    by_dest = {d: sum(x["amount_sats"] for x in led if x["dest"] == d) for d in {x["dest"] for x in led}}
    REPORT["scenarios"]["S24_ledger"] = by_dest
    want = {f"ln-offer:{oid_b}": r3.get("charged_sats", 0) + r4.get("charged_sats", 0),
            f"ln-offer:{oid_c}": r5.get("charged_sats", 0) + r6.get("charged_sats", 0)}
    check("S24 the offer wallet's ledger is exact: what the four settled payments were charged, nothing for the failures",
          by_dest == want and 30_000 <= want[f"ln-offer:{oid_b}"] <= 30_170 and 2468 <= want[f"ln-offer:{oid_c}"] <= 2502,
          {"ledger": by_dest, "charged": want})
    st = rpc_sock(s3, "ln_status")
    check("S24 final ln_status on lf3: ready, nothing in flight, not halted",
          st.get("ready") is True and st.get("in_flight") == 0 and st.get("halted") is None, {k: st.get(k) for k in ("ready", "in_flight", "halted")})


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
