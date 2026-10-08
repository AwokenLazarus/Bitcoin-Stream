#!/usr/bin/env python3
"""AGP-039 regtest driver (stdlib only; run by regtest_ui.sh).

1. Fund the signer's hot key from the node wallet (one block).
2. An agent calls xbt402_pay (max_sats 1000 >= human_threshold 1000) through the MCP over HTTP; the MCP
   waits (XBT_MCP_APPROVAL_WAIT_S).
3. The human logs in to the UI, finds it on the Approvals page, signs the message the page shows with
   the device key (`xbt-wallet-ui sign`), and submits the approval in the UI.
4. The MCP call returns: paid under the approval (charged 150 sats, the provider's price).
5. A second over-threshold call is denied in the UI, signed like the approval (AGP-063 W3: an unsigned
   deny is refused); the MCP answers needs_human, approval_state denied.
6. close_channel through the MCP; the close is confirmed on chain; the UI shows the channel closed with
   its close report, and the signature log intact and anchored.
"""
import argparse
import http.client
import json
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.parse

A = argparse.ArgumentParser()
for k in ["out", "sock", "mcp", "mcp-token", "ui", "ui-password-file", "human-key", "sign-bin", "provider", "cli"]:
    A.add_argument("--" + k, required=True)
a = A.parse_args()
RESULTS = []


def check(name, ok, detail=None):
    RESULTS.append({"check": name, "ok": bool(ok), "detail": detail})
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"), flush=True)
    return ok


def signer(method, **params):
    s = socket.socket(socket.AF_UNIX)
    s.connect(a.sock)
    s.sendall((json.dumps({"id": 1, "method": method, "params": params}) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        c = s.recv(65536)
        if not c:
            break
        buf += c
    r = json.loads(buf)
    if r.get("error"):
        raise RuntimeError(r["error"])
    return r["result"]


def cli(*args):
    return subprocess.check_output(a.cli.split() + list(args), text=True).strip()


class Mcp:
    def __init__(self, url, token):
        u = urllib.parse.urlparse(url)
        self.host, self.port, self.path, self.token, self.sid = u.hostname, u.port, u.path, token, None

    def post(self, msg, timeout=300):
        c = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Authorization": f"Bearer {self.token}"}
        if self.sid:
            h["Mcp-Session-Id"] = self.sid
        c.request("POST", self.path, json.dumps(msg), h)
        r = c.getresponse()
        body = r.read().decode()
        if r.getheader("Mcp-Session-Id"):
            self.sid = r.getheader("Mcp-Session-Id")
        return r.status, (json.loads(body) if body else None)

    def start(self):
        st, r = self.post({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "agp039-regtest-agent", "version": "1"}}})
        self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return r

    def tool(self, name, args, id_=1):
        st, r = self.post({"jsonrpc": "2.0", "id": id_, "method": "tools/call", "params": {"name": name, "arguments": args}})
        text = r["result"]["content"][0]["text"]
        try:
            return json.loads(text)
        except ValueError:
            return {"raw": text}


class Ui:
    def __init__(self, base):
        u = urllib.parse.urlparse(base)
        self.host, self.port, self.cookie = u.hostname, u.port, ""

    def req(self, method, path, form=None):
        c = http.client.HTTPConnection(self.host, self.port, timeout=60)
        h = {"Cookie": self.cookie} if self.cookie else {}
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            h["Content-Type"] = "application/x-www-form-urlencoded"
        c.request(method, path, body, h)
        r = c.getresponse()
        sc = r.getheader("Set-Cookie")
        if sc:
            self.cookie = sc.split(";")[0]
        return r.status, r.getheader("Location") or "", r.read().decode()

    def get(self, path):
        return self.req("GET", path)[2]

    def post(self, page, path, form):
        csrf = field(self.get(page), "csrf")
        st, loc, _ = self.req("POST", path, dict(form, csrf=csrf))
        return self.flash(loc.lstrip("."))

    def flash(self, path):
        m = re.search(r'class="flash[^"]*"[^>]*>(.*?)</div>', self.get(path), re.S)
        return unescape(m.group(1)) if m else ""


def unescape(s):
    return s.replace("&quot;", '"').replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")


def field(html, name):
    m = re.search(r'name="%s" value="([^"]*)"' % re.escape(name), html)
    return unescape(m.group(1)) if m else None


t0 = time.time()
# 1. fund the hot key
hot = signer("hot_address")["hot_address"]
txid = cli("-rpcwallet=w", "sendtoaddress", hot, "0.002")
cli("generatetoaddress", "1", cli("-rpcwallet=w", "getnewaddress"))
signer("notice_hot_txid", txid=txid)
check("hot key funded with 200,000 sats", signer("hot_address")["hot_sats"] == 200_000, signer("hot_address"))

# 2. the agent's call waits in the MCP
agent = Mcp(a.mcp, a.mcp_token)
init = agent.start()
check("MCP initialized (streamable HTTP, bearer token)", init and init.get("result", {}).get("serverInfo", {}).get("name") == "xbt-agent-wallet", init)
URL = a.provider + "/v1/answer"
out = {}
th = threading.Thread(target=lambda: out.setdefault("r", agent.tool("xbt402_pay", {"url": URL, "method": "GET", "max_sats": 1000})))
t_call = time.time()
th.start()

# 3. the human, in the UI
ui = Ui(a.ui)
pw = open(a.ui_password_file).read()
st, loc, _ = ui.req("POST", "/login", {"password": pw})
check("logged in to the UI", st == 303 and loc == "./", (st, loc))
page = ""
for _ in range(100):
    page = ui.get("/approvals")
    if 'name="token"' in page:
        break
    time.sleep(0.2)
check("the waiting call is on the Approvals page with its URL and amount", URL in page and "1,000 sats" in page)
token, dest, amount, expiry = field(page, "token"), field(page, "dest"), field(page, "amount_sats"), field(page, "expiry")
msg_hex = re.search(r'<pre class="hex">([0-9a-f]+)</pre>', page).group(1)
expect = "\n".join(["xbt-agentwallet-approve-v1", token, dest, amount, expiry]).encode().hex()
check("the message shown for the device is (token, dest, amount, expiry)", msg_hex == expect)
check("the agent is still waiting", th.is_alive())
sig = subprocess.check_output([a.sign_bin, "sign", "--key", a.human_key, "--message-hex", msg_hex], text=True).strip()
f = ui.post("/approvals", "/approve", {"token": token, "dest": dest, "amount_sats": amount, "expiry": expiry, "signature": "", "signature_ext": sig})
check("approved in the UI", f.startswith("Approved."), f)
t_approved = time.time()

# 4. the MCP call returns paid
th.join(240)
r = out.get("r", {})
check("the MCP xbt402_pay returned paid after the approval", r.get("verdict") == "allow" and r.get("approved") is True and r.get("waited_for_human") is True, r)
check("charged the provider's price (150 sats) under the 1,000-sat approval", r.get("charged_sats") == 150, r.get("charged_sats"))
check("the provider's answer came back", '"answer":"/v1/answer"' in r.get("untrusted_provider_response", {}).get("body", ""), r.get("untrusted_provider_response"))
chan = r.get("chan")
fund_tx = next((c.get("funding_txid") for c in signer("channels")["channels"] if c["chan"] == chan), None)
check("the channel's funding is confirmed on chain", fund_tx and int(json.loads(cli("getrawtransaction", fund_tx, "true")).get("confirmations", 0)) >= 1, fund_tx)
check("the token is used", signer("approval_status", token=token)["state"] == "used")
under = agent.tool("xbt402_pay", {"url": a.provider + "/v1/small", "method": "GET", "max_sats": 500}, id_=2)
check("a call under the threshold pays without a human", under.get("verdict") == "allow" and under.get("charged_sats") == 150, under)

# 5. a second over-threshold call, denied in the UI
out2 = {}
th2 = threading.Thread(target=lambda: out2.setdefault("r", agent.tool("xbt402_pay", {"url": a.provider + "/v1/other", "method": "GET", "max_sats": 2000}, id_=3)))
th2.start()
for _ in range(100):
    page = ui.get("/approvals")
    if "/v1/other" in page:
        break
    time.sleep(0.2)
t2 = field(page, "token")
f = ui.post("/approvals", "/deny", {"token": t2, "reason": "unsigned"})
check("an unsigned deny is refused (AGP-063 W3): the call still waits", signer("approval_status", token=t2)["state"] == "pending" and th2.is_alive(), f)
form = re.search(r'<form method="post" action="\./deny"(.*?)</form>', page, re.S).group(1)
d_exp = field(form, "expiry")
d_hex = re.search(r'<pre class="hex">([0-9a-f]+)</pre>', form).group(1)
check("the deny message shown for the device is (token, expiry)", d_hex == "\n".join(["xbt-agentwallet-deny-v1", t2, d_exp]).encode().hex())
d_sig = subprocess.check_output([a.sign_bin, "sign", "--key", a.human_key, "--message-hex", d_hex], text=True).strip()
f = ui.post("/approvals", "/deny", {"token": t2, "reason": "not this one", "expiry": d_exp, "signature": "", "signature_ext": d_sig})
th2.join(60)
r2 = out2.get("r", {})
check("denied in the UI: the MCP answers needs_human, approval_state denied", r2.get("verdict") == "needs_human" and r2.get("approval_state") == "denied", r2)

# 6. close, on chain, and what the UI shows
c = agent.tool("close_channel", {"counterparty": a.provider}, id_=4)
close_tx = c.get("txid")
check("closed cooperatively through the MCP", c.get("verdict") == "allow" and close_tx, c)
conf = 0
for _ in range(30):
    try:
        conf = int(json.loads(cli("getrawtransaction", close_tx, "true")).get("confirmations", 0))
    except Exception:
        conf = 0
    if conf >= 1:
        break
    time.sleep(0.5)
check("the close is confirmed on chain", conf >= 1, conf)
# 2 calls x 150 sats; the first state is at least the 546-sat dust floor, so the signed cum is 546
check("the close report is ok (the provider's cum = the state we signed, nothing unpaid)",
      c.get("close_report", {}).get("status") == "ok" and c["close_report"].get("cum") == c.get("cum") == 546 and c["close_report"].get("unpaid_msat") == 0,
      c.get("close_report"))
chans = ui.get("/channels")
check("the UI shows the channel closed with its close report", ">closed<" in chans and "Close report" in chans and "provider cum 546" in chans)
sigs = ui.get("/signatures")
check("the UI shows the signature log intact and anchored", "chain intact, matches the anchor" in sigs and "human:approval_signature" in sigs)
ov = ui.get("/")
check("the overview renders with the real node", "Recent activity" in ov and "regtest" in ov)
for p in ["approvals", "channels", "signatures", "keys", "policy", "hub", "setup"]:
    open(f"{a.out}/{p}.html", "w").write(ui.get("/" + p))
open(f"{a.out}/overview.html", "w").write(ov)

ok = all(x["ok"] for x in RESULTS)
summary = {"ok": ok, "checks": RESULTS, "wait_s": round(t_approved - t_call, 2), "total_s": round(time.time() - t0, 1),
           "close_txid": close_tx, "funding_txid": fund_tx, "chan": chan}
json.dump(summary, open(f"{a.out}/results.json", "w"), indent=2)
print(f"regtest_ui: {sum(x['ok'] for x in RESULTS)}/{len(RESULTS)} checks passed")
sys.exit(0 if ok else 1)
