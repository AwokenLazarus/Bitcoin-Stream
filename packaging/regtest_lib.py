"""AGP-040: helpers shared by the Umbrel and StartOS-shaped regtest drivers (stdlib only).

Checks are recorded as PASS/FAIL rows (results.json). HTTP, the MCP over streamable HTTP, a UI browser (cookie,
CSRF, the signed-form flow with `xbt-wallet-ui sign`), a small reverse proxy that plays the box's proxy
(Umbrel app_proxy, StartOS) by adding X-Forwarded-*, and the regtest chain set-up the AGP-038 test uses.
"""
import http.client as http_client
import http.server as http_server
import json
import os
import re
import socketserver
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = []
LOG = None


def open_log(path):
    global LOG
    LOG = open(path, "a")


def log(*a):
    s = " ".join(str(x) for x in a)
    print(s, flush=True)
    if LOG:
        LOG.write(s + "\n")
        LOG.flush()


def check(group, name, ok, detail=None):
    RESULTS.append({"group": group, "check": name, "ok": bool(ok), "detail": detail})
    log(f"  [{'PASS' if ok else 'FAIL'}] {group}: {name}" + ("" if ok else f"  -- {json.dumps(detail, default=str)[:700]}"))
    return ok


def sh(*argv, check_rc=True, input=None, timeout=600, env=None, cwd=None):
    r = subprocess.run([str(a) for a in argv], capture_output=True, text=True, input=input, timeout=timeout, env=env, cwd=cwd)
    if LOG:
        LOG.write(f"$ {' '.join(str(a) for a in argv)[:600]}\n{r.stdout[-3000:]}{r.stderr[-3000:]}\n")
    if check_rc and r.returncode != 0:
        raise RuntimeError(f"{' '.join(str(a) for a in argv[:5])}... rc={r.returncode}: {(r.stderr or r.stdout).strip()[-800:]}")
    return r


def docker(*a, **kw):
    return sh("docker", *a, **kw)


def wait_until(fn, timeout, what, every=1.0):
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        try:
            last = fn()
            if last:
                return last
        except Exception as e:  # noqa: BLE001
            last = e
        time.sleep(every)
    raise RuntimeError(f"timed out after {timeout}s waiting for {what} (last: {last})")


def http(method, url, body=None, headers=None, timeout=240):
    req = urllib.request.Request(url, method=method, data=body, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def status(url, headers=None):
    try:
        return http("GET", url, headers=headers, timeout=10)[0]
    except Exception:  # noqa: BLE001
        return 0


def root_helper(mount_src, script, ro=True):
    """A root debian container on a host path or volume (the auditor's view: the images have no shell)."""
    return docker("run", "--rm", "--network", "none", "-v", f"{mount_src}:/d" + (":ro" if ro else ""), "debian:bookworm-slim", "sh", "-c", script)


class Mcp:
    def __init__(self, base, token, path="/mcp"):
        self.url, self.token, self.sid, self.n = base.rstrip("/") + path, token, None, 0

    def post(self, msg):
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if self.sid:
            h["Mcp-Session-Id"] = self.sid
        code, hdrs, body = http("POST", self.url, json.dumps(msg).encode(), h)
        self.sid = self.sid or next((v for k, v in hdrs.items() if k.lower() == "mcp-session-id"), None)
        return code, json.loads(body) if body.strip().startswith("{") else body

    def start(self):
        self.sid = None
        code, r = self.post({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                             "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "agp040", "version": "1"}}})
        self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return code, r

    def tool(self, name, **args):
        self.n += 1
        code, r = self.post({"jsonrpc": "2.0", "id": self.n, "method": "tools/call", "params": {"name": name, "arguments": args}})
        if code != 200 or not isinstance(r, dict) or "result" not in r:
            raise RuntimeError(f"tools/call {name}: HTTP {code} {r}")
        text = r["result"]["content"][0]["text"]
        if r["result"].get("isError"):
            raise RuntimeError(f"{name}: {text}")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"_text": text}


def agent_rotation_attempts(base, tokens):
    """AGP-042: everything an agent holding a token could try in order to rotate it through the MCP. Returns
    [(what, status, headers, body)]. The MCP has no rotation endpoint, so none of these may succeed."""
    out = []
    for t in tokens:
        h = {"Authorization": f"Bearer {t}", "X-XBT-Rotate": "owner", "Content-Type": "application/json"}
        for method, path in (("POST", "/rotate-token"), ("POST", "/mcp/rotate-token"), ("GET", "/rotate-token"), ("PUT", "/mcp")):
            st, hd, body = http(method, base.rstrip("/") + path, b"{}", h, timeout=20)
            out.append((f"{method} {path} ({t[:6]}..)", st, hd, body))
    return out


def leaks(responses, secret):
    """The responses (what, status, headers, body) whose headers or body contain `secret`."""
    return [r[0] for r in responses if secret and (secret in r[3] or secret in json.dumps(r[2]))]


def unescape(s):
    return s.replace("&quot;", '"').replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")


def field(html, name):
    m = re.search(r'name="%s" value="([^"]*)"' % re.escape(name), html)
    return unescape(m.group(1)) if m else None


class Ui:
    """A browser without JS: one cookie, no redirects followed."""

    def __init__(self, base, headers=None):
        u = urllib.parse.urlparse(base)
        self.host, self.port, self.prefix = u.hostname, u.port, u.path.rstrip("/")
        self.cookie, self.headers, self.last_set_cookie = "", headers or {}, ""

    def req(self, method, path, form=None):
        c = http_client.HTTPConnection(self.host, self.port, timeout=120)
        h = dict(self.headers)
        if self.cookie:
            h["Cookie"] = self.cookie
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            h["Content-Type"] = "application/x-www-form-urlencoded"
        c.request(method, self.prefix + path, body, h)
        r = c.getresponse()
        sc = r.getheader("Set-Cookie")
        if sc:
            self.last_set_cookie = sc
            self.cookie = sc.split(";")[0]
        return r.status, r.getheader("Location") or "", r.read().decode()

    def get(self, path):
        return self.req("GET", path)[2]

    def login(self, password):
        st, loc, body = self.req("POST", "/login", {"password": password})
        return st, loc

    def flash(self, path):
        m = re.search(r'class="flash[^"]*"[^>]*>(.*?)</div>', self.get(path), re.S)
        return unescape(m.group(1)) if m else ""

    def post(self, page, path, form):
        csrf = field(self.get(page), "csrf")
        st, loc, body = self.req("POST", path, dict(form, csrf=csrf))
        return st, loc, body


def sign(sign_bin, key_file, message_hex):
    return sh(sign_bin, "sign", "--key", key_file, "--message-hex", message_hex).stdout.strip()


def owner_setup(ui, sign_bin, key_file, policy):
    """The owner's first run in the UI, no terminal: enrol the approval key, then sign a policy (the
    "sign on another device" path; the in-browser path is covered by xbt-wallet-ui's browser test).
    Returns (enrolled flash, applied flash, pending_restart text)."""
    pub = sh(sign_bin, "pubkey", "--key", key_file).stdout.strip()
    ui.post("/setup", "/human-key-enroll", {"pubkey": pub})
    f1 = ui.flash("/setup")
    csrf = field(ui.get("/policy"), "csrf")
    st, _, page = ui.req("POST", "/policy", {"csrf": csrf, "mode": "json", "json": json.dumps(policy)})
    hx = re.search(r'<pre class="hex">([0-9a-f]+)</pre>', page)
    if not hx:
        raise RuntimeError(f"policy preview without a message to sign: {st} {page[-1500:]}")
    form = {k: field(page, k) for k in ("text", "prev_sha256", "expiry")}
    if form["text"] is None:
        m = re.search(r'<textarea[^>]*name="text"[^>]*>(.*?)</textarea>', page, re.S)
        form["text"] = unescape(m.group(1)) if m else ""
    form["signature_ext"] = sign(sign_bin, key_file, hx.group(1))
    form["csrf"] = field(page, "csrf")
    ui.req("POST", "/policy-apply", form)
    f2 = ui.flash("/policy")
    return pub, f1, f2


class ProxyHandler(http_server.BaseHTTPRequestHandler):
    upstream = None  # (host, port)
    forwarded = {}

    def _go(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else None
        c = http_client.HTTPConnection(*self.upstream, timeout=300)
        h = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection")}
        h.update({"Host": self.headers.get("Host", ""), "X-Forwarded-For": self.client_address[0], **self.forwarded})
        c.request(self.command, self.path, body, h)
        r = c.getresponse()
        data = r.read()
        self.send_response(r.status)
        for k, v in r.getheaders():
            if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_DELETE = _go

    def log_message(self, *a):
        pass


def start_proxy(listen_port, upstream_port, forwarded):
    """The box's reverse proxy (app_proxy / StartOS): 127.0.0.1:listen -> 127.0.0.1:upstream, adding X-Forwarded-*."""
    h = type("H", (ProxyHandler,), {"upstream": ("127.0.0.1", upstream_port), "forwarded": forwarded})
    srv = type("S", (socketserver.ThreadingTCPServer,), {"allow_reuse_address": True})(("127.0.0.1", listen_port), h)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def ensure_provider_image():
    """The AGP-038 test provider (xbt402-rust-provider, 150 sat per call) as a FROM scratch image."""
    if docker("image", "inspect", "agp038-test-provider:1", check_rc=False).returncode == 0:
        return
    b = os.path.join(ROOT, "target/x86_64-unknown-linux-musl/release/xbt402-rust-provider")
    if not os.path.exists(b):
        sh("nice", "-n", "19", "cargo", "build", "-q", "-j2", "--release", "--target", "x86_64-unknown-linux-musl", "-p", "xbt402-interop",
           "--bin", "xbt402-rust-provider", cwd=ROOT)
    import tempfile
    with tempfile.TemporaryDirectory() as ctx:
        sh("cp", b, ctx)
        open(os.path.join(ctx, "Dockerfile"), "w").write(
            "FROM scratch\nCOPY xbt402-rust-provider /xbt402-rust-provider\nUSER 10009:10009\nENTRYPOINT [\"/xbt402-rust-provider\"]\n")
        docker("build", "-q", "-t", "agp038-test-provider:1", ctx)


POLICY_BASE = {"max_per_tx_sats": 1000, "daily_budget_sats": 20000, "weekly_budget_sats": 50000, "per_counterparty_cap_sats": 9400,
               "velocity_max": 50, "velocity_window_s": 3600, "human_threshold_sats": 5000, "channel_expiry_blocks": 1008,
               "refund_enabled": True, "refund_margin_blocks": 6, "hot_balance_cap_sats": 100000, "split_window_s": 0, "regtest_mine": False,
               "anchor_required": True, "anchor_interval_s": 5, "open_wait_s": 90, "open_retry_s": 5}


class Chain:
    """bitcoin-cli in the node container; the faucet; the AGP-017 maturity window mined past."""

    def __init__(self, container, rpc_user, rpc_pass):
        self.c, self.u, self.p = container, rpc_user, rpc_pass
        self.faucet = None

    def cli(self, *a, wallet=None):
        args = ["docker", "exec", self.c, "bitcoin-cli", "-regtest", "-datadir=/data", "-rpcport=8332", f"-rpcuser={self.u}", f"-rpcpassword={self.p}"]
        if wallet:
            args.append(f"-rpcwallet={wallet}")
        out = sh(*args, *[str(x) for x in a]).stdout.strip()
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return out

    def mine(self, n=1):
        return self.cli("generatetoaddress", n, self.faucet)

    def bootstrap(self):
        self.cli("createwallet", "faucet")
        self.faucet = self.cli("getnewaddress", wallet="faucet")
        self.mine(120)
        desc = self.cli("getdescriptorinfo", "raw(51)")["descriptor"]
        while self.cli("getblockcount") < 6720:
            self.cli("generatetodescriptor", min(1000, 6720 - self.cli("getblockcount")), desc)


class Miner:
    """A block every `every` seconds while a paid call waits for its funding's confirmation."""

    def __init__(self, chain, every=2.0):
        self.chain, self.every = chain, every
        self.stop = threading.Event()
        self.t = threading.Thread(target=self.run, daemon=True)

    def run(self):
        while not self.stop.wait(self.every):
            try:
                self.chain.mine(1)
            except Exception as e:  # noqa: BLE001
                log("miner:", e)

    def __enter__(self):
        self.t.start()
        return self

    def __exit__(self, *a):
        self.stop.set()
        self.t.join()


def write_results(out):
    with open(os.path.join(out, "results.json"), "w") as f:
        json.dump(RESULTS, f, indent=1, default=str)
    n_ok = sum(r["ok"] for r in RESULTS)
    log(f"== {n_ok}/{len(RESULTS)} checks passed")
    return bool(RESULTS) and n_ok == len(RESULTS)
