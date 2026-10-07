#!/usr/bin/env python3
"""AGP-038 container test: the amd64 images on regtest, configured only by env and a data dir.

Stack on a private Docker network (`agp038-net-<pid>`; nothing but the MCP, the hub and the provider is
published, and only on 127.0.0.1, ports 33700-33799):
  knots      Knots 29.4.2 regtest (a test-only image: debian:bookworm-slim + the binary), rpcuser auth
  provider   xbt402-rust-provider (a test-only FROM scratch image), 150 sat per call
  witness    xbt-anchor-witness:agp038   data volume `witness`, socket volume `run-anchor`
  signer     xbt-signer:agp038           data volume `signer`, socket volumes `run-signer` (rw), `run-anchor` (ro)
  mcp        xbt-wallet-mcp:agp038       data volume `mcp`, `run-signer` (ro); HTTP on 127.0.0.1:33710
  hub        xbt402-hub:agp038           data volume `hub`; HTTP on 127.0.0.1:33720
Every image container runs read-only, non-root, with /tmp a tmpfs. The data dir is a set of named volumes
that take their owners from the images' /data skeleton. The one provisioning step is the operator's: it
writes the node's RPC credentials into signer/secrets and hub/secrets (a root helper container, as an app
installer would). Everything else (the wrapping key, the MCP token, the hub's payTo key) is generated on
first run.

Checks (each is PASS/FAIL in results.json):
  S  static: non-root users, read-only root filesystems, HEALTHCHECK passing, generated secrets 0600
  G  /readyz gating: the MCP is up before the signer (healthz 200, readyz 503), then ready; the witness
     stopped / the node stopped make readyz 503 and ready again once they are back; the hub the same
  P  one xbt402 call paid through the MCP over HTTP (bearer token), exact amounts
  R  docker kill + start of witness, signer and MCP: the channel, cum, keys, token and anchors persist;
     a second paid call reuses the channel; the witness's check of the signature log passes
  H  the hub: healthz/readyz, and its payTo key persists across a restart
    scripts/container_test.sh   (builds the images, then runs this)
"""
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

OUT = sys.argv[1]
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KNOTS_BIN = os.environ.get("XBT_BIN", os.path.expanduser("~/lazarus-regtest/b1-xbt402/knots-29.4.2"))
PID = os.getpid()
P = f"agp038-{PID}"            # container/volume prefix
NET = f"agp038-net-{PID}"
MCP_PORT, HUB_PORT, PROV_PORT = 33710, 33720, 33730
RPC_PW = os.urandom(16).hex()
PROVIDER = f"http://{P}-provider:9500"
RESULTS = []
LOG = open(os.path.join(OUT, "container_test.log"), "a")


def log(*a):
    s = " ".join(str(x) for x in a)
    print(s, flush=True)
    LOG.write(s + "\n")
    LOG.flush()


def check(group, name, ok, detail=None):
    RESULTS.append({"group": group, "check": name, "ok": bool(ok), "detail": detail})
    log(f"  [{'PASS' if ok else 'FAIL'}] {group}: {name}" + ("" if ok else f"  -- {json.dumps(detail, default=str)[:600]}"))
    return ok


def sh(*argv, check_rc=True, input=None, timeout=300):
    r = subprocess.run(argv, capture_output=True, text=True, input=input, timeout=timeout)
    LOG.write(f"$ {' '.join(argv)}\n{r.stdout[-4000:]}{r.stderr[-4000:]}\n")
    if check_rc and r.returncode != 0:
        raise RuntimeError(f"{' '.join(argv[:4])}... rc={r.returncode}: {r.stderr.strip()[-800:]}")
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


# --- the node ----------------------------------------------------------------------------------------------

def cli(*a, wallet=None):
    args = ["docker", "exec", f"{P}-knots", "bitcoin-cli", "-regtest", "-datadir=/data/node", "-rpcuser=xbt", f"-rpcpassword={RPC_PW}"]
    if wallet:
        args.append(f"-rpcwallet={wallet}")
    r = sh(*args, *[str(x) for x in a])
    out = r.stdout.strip()
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out


def mine(n=1):
    return cli("generatetoaddress", n, FAUCET_ADDR)


class Miner:
    """A block every `every` seconds while a paid call waits for its funding's confirmation."""

    def __init__(self, every=2.0):
        self.stop = threading.Event()
        self.t = threading.Thread(target=self.run, args=(every,), daemon=True)

    def run(self, every):
        while not self.stop.wait(every):
            try:
                mine(1)
            except Exception as e:  # noqa: BLE001
                log("miner:", e)

    def __enter__(self):
        self.t.start()
        return self

    def __exit__(self, *a):
        self.stop.set()
        self.t.join()


# --- HTTP ---------------------------------------------------------------------------------------------------

def http(method, url, body=None, headers=None, timeout=240):
    req = urllib.request.Request(url, method=method, data=body, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def status(url):
    try:
        return http("GET", url, timeout=10)[0]
    except Exception:  # noqa: BLE001
        return 0


class Mcp:
    def __init__(self, base, token):
        self.base, self.token, self.sid, self.n = base, token, None, 0

    def post(self, msg):
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
             "Authorization": f"Bearer {self.token}", "MCP-Protocol-Version": "2025-06-18"}
        if self.sid:
            h["Mcp-Session-Id"] = self.sid
        code, hdrs, body = http("POST", self.base + "/mcp", json.dumps(msg).encode(), h)
        self.sid = self.sid or next((v for k, v in hdrs.items() if k.lower() == "mcp-session-id"), None)
        return code, json.loads(body) if body.strip() else None

    def start(self):
        self.sid = None
        code, r = self.post({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                             "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "agp038", "version": "1"}}})
        self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return code, r

    def tool(self, name, **args):
        self.n += 1
        code, r = self.post({"jsonrpc": "2.0", "id": self.n, "method": "tools/call", "params": {"name": name, "arguments": args}})
        if code != 200 or "result" not in (r or {}):
            raise RuntimeError(f"tools/call {name}: HTTP {code} {r}")
        text = r["result"]["content"][0]["text"]
        if r["result"].get("isError"):
            raise RuntimeError(f"{name}: {text}")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"_text": text}


# --- the stack ----------------------------------------------------------------------------------------------

POLICY = {"allowlist": [PROVIDER], "max_per_tx_sats": 1000, "daily_budget_sats": 20000, "weekly_budget_sats": 50000,
          "per_counterparty_cap_sats": 9400, "velocity_max": 50, "velocity_window_s": 3600, "human_threshold_sats": 5000,
          "channel_expiry_blocks": 1008, "refund_enabled": True, "refund_margin_blocks": 6, "hot_balance_cap_sats": 100000,
          "split_window_s": 0, "regtest_mine": False, "anchor_required": True, "anchor_interval_s": 5, "open_wait_s": 90, "open_retry_s": 5}
COMMON = ["--read-only", "--tmpfs", "/tmp:rw,size=16m", "--network", NET, "--restart", "no", "--security-opt", "no-new-privileges"]
ENV_NODE = ["-e", f"XBT_NODE_RPC_HOST={P}-knots", "-e", "XBT_NODE_RPC_PORT=18443", "-e", "XBT_CHAIN=regtest"]


def vol(name):
    return f"{P}-{name}"


def run_witness():
    docker("run", "-d", "--name", f"{P}-witness", *COMMON, "-v", f"{vol('witness')}:/data/witness", "-v", f"{vol('run-anchor')}:/data/run/anchor",
           "xbt-anchor-witness:agp038")


def run_signer():
    docker("run", "-d", "--name", f"{P}-signer", *COMMON, *ENV_NODE, "-e", "XBT_READY_INTERVAL=2", "-e", "B2_WATCH_INTERVAL=2",
           "-e", "B2_SIGNER_TIMEOUT=240", "-e", f"XBT_SIGNER_POLICY={json.dumps(POLICY)}",
           "-v", f"{vol('signer')}:/data/signer", "-v", f"{vol('run-signer')}:/data/run/signer", "-v", f"{vol('run-anchor')}:/data/run/anchor:ro",
           "xbt-signer:agp038")


def run_mcp():
    docker("run", "-d", "--name", f"{P}-mcp", *COMMON, "-e", "XBT_READY_INTERVAL=2", "-e", "B2_SIGNER_TIMEOUT=240", "-e", "XBT_BASE_PATH=/wallet",
           "-p", f"127.0.0.1:{MCP_PORT}:33510", "-v", f"{vol('mcp')}:/data/mcp", "-v", f"{vol('run-signer')}:/data/run/signer:ro",
           "xbt-wallet-mcp:agp038")


def run_hub():
    docker("run", "-d", "--name", f"{P}-hub", *COMMON, *ENV_NODE, "-e", "XBT_BASE_PATH=/hub", "-e", "XBT_TRUST_FORWARDED=1",
           "-p", f"127.0.0.1:{HUB_PORT}:9480", "-v", f"{vol('hub')}:/data/hub",
           "xbt402-hub:agp038")


def health(name):
    return docker("inspect", "-f", "{{.State.Health.Status}}", f"{P}-{name}", check_rc=False).stdout.strip()


def helper(volume, script, mount="/d", ro=False):
    """A root helper container on one volume (the installer/auditor role; the images have no shell)."""
    return docker("run", "--rm", "--network", "none", "-v", f"{vol(volume)}:{mount}" + (":ro" if ro else ""), "debian:bookworm-slim",
                  "sh", "-c", script)


def signer_call(method, params=None):
    r = docker("exec", f"{P}-signer", "/usr/bin/xbt-signer", "call", method, json.dumps(params or {}))
    return json.loads(r.stdout)


def mcp_ready():
    return status(f"http://127.0.0.1:{MCP_PORT}/readyz")


def hub_ready():
    return status(f"http://127.0.0.1:{HUB_PORT}/readyz")


def build_test_images():
    ctx = os.path.join(OUT, "ctx-knots")
    os.makedirs(ctx, exist_ok=True)
    for b in ("bitcoind", "bitcoin-cli"):
        sh("cp", os.path.join(KNOTS_BIN, b), ctx)
    with open(os.path.join(ctx, "Dockerfile"), "w") as f:
        f.write("FROM debian:bookworm-slim\nCOPY bitcoind bitcoin-cli /usr/local/bin/\nENTRYPOINT [\"/usr/local/bin/bitcoind\"]\n")
    docker("build", "-q", "-t", "agp038-test-knots:29.4.2", ctx)
    ctx = os.path.join(OUT, "ctx-provider")
    os.makedirs(ctx, exist_ok=True)
    sh("cp", os.path.join(ROOT, "target/x86_64-unknown-linux-musl/release/xbt402-rust-provider"), ctx)
    with open(os.path.join(ctx, "Dockerfile"), "w") as f:
        f.write("FROM scratch\nCOPY xbt402-rust-provider /xbt402-rust-provider\nUSER 10009:10009\nENTRYPOINT [\"/xbt402-rust-provider\"]\n")
    docker("build", "-q", "-t", "agp038-test-provider:1", ctx)


def teardown():
    names = docker("ps", "-aq", "--filter", f"name=^{P}-", check_rc=False).stdout.split()
    for n in ("mcp", "hub", "signer", "witness", "provider", "knots"):
        with open(os.path.join(OUT, f"{n}.log"), "w") as f:
            r = docker("logs", f"{P}-{n}", check_rc=False)
            f.write(r.stdout + r.stderr)
    if names:
        docker("rm", "-f", *names, check_rc=False)
    if os.environ.get("CONTAINER_TEST_KEEP"):
        log(f"kept volumes {P}-*")
    else:
        vols = docker("volume", "ls", "-q", "--filter", f"name=^{P}-", check_rc=False).stdout.split()
        if vols:
            docker("volume", "rm", *vols, check_rc=False)
    docker("network", "rm", NET, check_rc=False)


FAUCET_ADDR = None


def main():
    global FAUCET_ADDR
    log(f"== AGP-038 container test, prefix {P}, network {NET}, evidence {OUT}")
    build_test_images()
    docker("network", "create", NET)
    for v in ("node", "witness", "signer", "mcp", "hub", "run-signer", "run-anchor", "provider"):
        docker("volume", "create", vol(v))

    # --- the node and the provider ---------------------------------------------------------------------------
    log("== node")
    docker("run", "-d", "--name", f"{P}-knots", "--network", NET, "-v", f"{vol('node')}:/data/node", "agp038-test-knots:29.4.2",
           "-regtest", "-datadir=/data/node", "-server", "-listen=0", "-rpcbind=0.0.0.0", "-rpcallowip=0.0.0.0/0", "-rpcport=18443",
           "-rpcuser=xbt", f"-rpcpassword={RPC_PW}", "-printtoconsole", "-discover=0", "-listenonion=0", "-dnsseed=0", "-fixedseeds=0",
           # the AGP-017 rehearsal's chain rules: the BLAKE2b hardfork at 101, long coinbase maturity; a pruned node like a box's
           "-fallbackfee=0.0002", "-prune=550", "-testactivationheight=blake2b@101", "-blake2b_headline=agp038",
           "-testcoinbasematuritylong=200:200:6680", "-rdtsexpiry=4102444800")
    wait_until(lambda: cli("getblockcount") == 0 or cli("getblockcount"), 60, "knots RPC")
    cli("createwallet", "faucet")
    FAUCET_ADDR = cli("getnewaddress", wallet="faucet")
    mine(120)
    # the faucet's coinbases mature past the long-maturity window (height 6,680): mine to 6,720 as the rehearsal does
    desc = cli("getdescriptorinfo", "raw(51)")["descriptor"]
    while cli("getblockcount") < 6720:
        cli("generatetodescriptor", min(1000, 6720 - cli("getblockcount")), desc)
    cli("-named", "createwallet", "wallet_name=agent", "disable_private_keys=true", "blank=true", "descriptors=true")
    log("== provider")
    helper("provider", f"printf 'xbt:{RPC_PW}' > /d/rpc-auth && chown -R 10009:10009 /d && chmod 600 /d/rpc-auth")
    docker("run", "-d", "--name", f"{P}-provider", *COMMON, "-p", f"127.0.0.1:{PROV_PORT}:9500", "-v", f"{vol('provider')}:/p",
           "agp038-test-provider:1", "--port", "9500", "--bind", "0.0.0.0", "--rpc-host", f"{P}-knots", "--rpc-port", "18443",
           "--cookie", "/p/rpc-auth", "--ledger", "/p/ledger.jsonl")
    wait_until(lambda: status(f"http://127.0.0.1:{PROV_PORT}/x402/supported") == 200, 60, "the provider")

    # --- provisioning: the node credentials only ---------------------------------------------------------------
    for v, uid in (("signer", 10001), ("hub", 10004)):
        # the helper mounts the volume first, so Docker does not copy the image's /data/<component> owner into it: set it here
        helper(v, f"umask 077 && mkdir -p /d/secrets && printf 'xbt:{RPC_PW}' > /d/secrets/node-rpc-auth && chown -R {uid}:{uid} /d && chmod 700 /d")

    # --- G1: the MCP first: alive, not ready ------------------------------------------------------------------
    log("== G: MCP before the signer")
    run_mcp()
    wait_until(lambda: status(f"http://127.0.0.1:{MCP_PORT}/healthz") == 200, 30, "MCP /healthz")
    code, _, body = http("GET", f"http://127.0.0.1:{MCP_PORT}/readyz")
    check("G", "MCP up, signer absent: /healthz 200, /readyz 503", code == 503, {"readyz": code, "body": body})
    token = helper("mcp", "cat /d/secrets/mcp-http-token", ro=True).stdout.strip()
    code, _, _ = http("POST", f"http://127.0.0.1:{MCP_PORT}/mcp", b"{}", {"Content-Type": "application/json"})
    check("S", "the MCP on 0.0.0.0 generated its bearer token and refuses a request without it (401)", code == 401 and len(token) == 64, code)

    log("== witness + signer")
    run_witness()
    run_signer()
    wait_until(lambda: mcp_ready() == 200, 120, "MCP /readyz 200 (signer ready)")
    rz = json.loads(http("GET", f"http://127.0.0.1:{MCP_PORT}/readyz")[2])
    check("G", "signer + witness up: MCP /readyz 200 with node synced, keys unlocked, witness reachable",
          rz["ok"] and rz["signer_ready"]["node"]["synced"] and rz["signer_ready"]["unlocked"] and rz["signer_ready"]["witness"]["reachable"], rz)

    # --- S: static properties ----------------------------------------------------------------------------------
    for n in ("witness", "signer", "mcp"):
        wait_until(lambda: health(n) == "healthy", 90, f"{n} HEALTHCHECK healthy", every=2)
    ins = json.loads(docker("inspect", f"{P}-signer", f"{P}-witness", f"{P}-mcp").stdout)
    check("S", "signer, witness, MCP: non-root, read-only root filesystem, HEALTHCHECK healthy",
          all(i["Config"]["User"] not in ("", "root", "0") and i["HostConfig"]["ReadonlyRootfs"] and i["State"]["Health"]["Status"] == "healthy"
              for i in ins), [(i["Name"], i["Config"]["User"], i["HostConfig"]["ReadonlyRootfs"], i["State"]["Health"]["Status"]) for i in ins])
    perms = helper("signer", "stat -c '%a %u %n' /d /d/secrets /d/secrets/* /d/policy.json /d/.run/hot.json", ro=True).stdout.split("\n")
    perms_mcp = helper("mcp", "stat -c '%a %u %n' /d/secrets /d/secrets/mcp-http-token", ro=True).stdout.split("\n")
    wk = [p for p in perms if p.endswith("signer-wrap-key")]
    check("S", "first run: signer-wrap-key and mcp-http-token generated 0600 in 0700 dirs, owned by the service user",
          wk and wk[0].startswith("600 10001") and any(p.startswith("700 10001 /d/secrets") for p in perms)
          and any(p.startswith("600 10003") for p in perms_mcp), perms + perms_mcp)
    hot = helper("signer", "cat /d/.run/hot.json", ro=True).stdout
    check("S", "the hot key on disk is sealed (aes-256-gcm, kdf keyfile), no plaintext key", '"aes-256-gcm"' in hot and '"keyfile"' in hot, hot[:200])
    socks = docker("run", "--rm", "-v", f"{vol('run-signer')}:/s:ro", "-v", f"{vol('run-anchor')}:/a:ro", "debian:bookworm-slim",
                   "sh", "-c", "stat -c '%a %u:%g %n' /s /s/* /a /a/*").stdout.split("\n")
    check("S", "sockets 0660 in 0750 dirs (signer 10001:10001, witness 10002:10002); readiness file 0640",
          any(s.startswith("660 10001:10001 /s/signer.sock") for s in socks) and any(s.startswith("660 10002:10002 /a/anchor.sock") for s in socks)
          and any(s.startswith("640 10001:10001 /s/ready.json") for s in socks), socks)

    ref = []
    for img, env in (("xbt-wallet-mcp:agp038", "XBT_MCP_HTTP_TOKEN=plain"), ("xbt-signer:agp038", "B2_HOT_PASSPHRASE=plain"),
                     ("xbt402-hub:agp038", "XBT_SECRET_NODE_RPC_AUTH=xbt:plain")):
        r = docker("run", "--rm", "--network", "none", "--read-only", "-e", env, img, check_rc=False)
        ref.append((img, r.returncode, (r.stdout + r.stderr).strip()[-200:]))
    check("S", "production mode (the images' default): a secret as a plain env value is refused at start",
          all(rc != 0 and "refused in production mode" in out for _, rc, out in ref), ref)

    # --- P: fund the hot wallet, pay one xbt402 call through the MCP -------------------------------------------
    log("== P: pay one xbt402 call through the MCP over HTTP")
    ha = signer_call("hot_address")
    txid = cli("sendtoaddress", ha["hot_address"], "0.0005", wallet="faucet")
    mine(1)
    noticed = signer_call("notice_hot_txid", {"txid": txid})
    check("P", "hot wallet funded (50,000 sat) and noticed", noticed.get("balance_sats", noticed.get("hot_balance_sats")) == 50000
          or noticed.get("noticed"), noticed)
    mcp = Mcp(f"http://127.0.0.1:{MCP_PORT}/wallet", token)
    code, init = mcp.start()
    check("P", "MCP initialize over HTTP with the bearer token", code == 200 and init["result"]["serverInfo"], init)
    url = f"{PROVIDER}/v1/agp038"
    with Miner(2.0):
        r1 = mcp.tool("xbt402_pay", url=url, max_sats=1000)
    check("P", "xbt402_pay through the MCP: HTTP 200 from the provider, 150 sat charged, a channel",
          r1.get("status") == 200 and r1.get("charged_sats") == 150 and r1.get("chan"), r1)
    chans1 = mcp.tool("channels")
    log("   channels:", json.dumps(chans1)[:400])
    prov_ledger = helper("provider", "cat /d/ledger.jsonl 2>/dev/null || true", ro=True).stdout

    # --- R: kill and restart: state persists ---------------------------------------------------------------------
    log("== R: docker kill + start")
    time.sleep(6)   # one anchor interval, so the witness holds the latest head
    docker("kill", f"{P}-mcp", f"{P}-signer", f"{P}-witness")
    code_down = status(f"http://127.0.0.1:{MCP_PORT}/healthz")
    docker("start", f"{P}-witness")
    docker("start", f"{P}-signer")
    docker("start", f"{P}-mcp")
    wait_until(lambda: mcp_ready() == 200, 120, "MCP /readyz after the restart")
    token2 = helper("mcp", "cat /d/secrets/mcp-http-token", ro=True).stdout.strip()
    mcp = Mcp(f"http://127.0.0.1:{MCP_PORT}/wallet", token2)
    mcp.start()
    chans2 = mcp.tool("channels")
    ha2 = signer_call("hot_address")
    check("R", "after kill+start: same MCP token, same hot address, same channels (id, cum)",
          code_down == 0 and token2 == token and ha2["hot_address"] == ha["hot_address"] and chans2.get("channels") == chans1.get("channels"),
          {"healthz_while_down": code_down, "same_token": token2 == token, "hot": [ha["hot_address"], ha2["hot_address"]],
           "before": chans1, "after": chans2})
    slog = docker("logs", f"{P}-signer", check_rc=False)
    check("R", "the signer restarted with anchor_required and its log passed the witness check (no refusal), wrapping key read, not regenerated",
          "refusing" not in (slog.stdout + slog.stderr) and (slog.stdout + slog.stderr).count("generated /data/signer/secrets/signer-wrap-key") == 1,
          (slog.stdout + slog.stderr)[-1500:])
    r2 = mcp.tool("xbt402_pay", url=url, max_sats=1000)
    chans3 = mcp.tool("channels")
    spent = [c.get("spent_sats") for cs in (chans1, chans3) for c in cs.get("channels", []) if c.get("chan") == r1.get("chan")]
    # the first state carries the 546-sat dust floor (prepaid, CONTRACT §m): cum stays 546 while spent goes 150 -> 300
    check("R", "a second paid call after the restart reuses the channel (no new open): spent 150 -> 300, cum at the 546 floor",
          r2.get("status") == 200 and r2.get("chan") == r1.get("chan") and not r2.get("opened") and r2.get("charged_sats") == 150
          and spent == [150, 300] and r1.get("cum") == r2.get("cum") == 546, {"r1": r1, "r2": r2, "spent": spent})
    time.sleep(6)
    wc = docker("run", "--rm", "--user", "0", "--network", "none", "-v", f"{vol('witness')}:/data/witness:ro",
                "-v", f"{vol('signer')}:/data/signer:ro", "xbt-anchor-witness:agp038", "check", "--store", "/data/witness",
                "--log", "/data/signer/.run/signatures.jsonl", check_rc=False)
    check("R", "auditor: xbt-anchor-witness check of the signer's log against the persisted witness store", wc.returncode == 0, wc.stdout + wc.stderr)

    # --- G: readiness follows the witness and the node ----------------------------------------------------------------
    log("== G: /readyz gating")
    docker("stop", f"{P}-witness")
    wait_until(lambda: mcp_ready() == 503, 30, "MCP /readyz 503 with the witness stopped")
    rz = json.loads(http("GET", f"http://127.0.0.1:{MCP_PORT}/readyz")[2])
    check("G", "witness stopped: MCP /readyz 503 (witness unreachable), /healthz still 200",
          rz["signer_ready"]["witness"]["reachable"] is False and status(f"http://127.0.0.1:{MCP_PORT}/healthz") == 200, rz)
    docker("start", f"{P}-witness")
    wait_until(lambda: mcp_ready() == 200, 60, "MCP /readyz 200 with the witness back")
    check("G", "witness back: MCP /readyz 200", True)
    run_hub()
    wait_until(lambda: hub_ready() == 200, 60, "hub /readyz")
    hub1 = json.loads(http("GET", f"http://127.0.0.1:{HUB_PORT}/readyz")[2])
    check("H", "hub: /healthz 200, /readyz 200 (node synced), configured by env + data dir only",
          status(f"http://127.0.0.1:{HUB_PORT}/healthz") == 200 and hub1["ok"], hub1)
    # behind a proxy (Umbrel app_proxy / StartOS / Tor): the base path, and the 402's resource.url from X-Forwarded-*
    fwd = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "abcdefghij234567.onion"}
    c1, h1, b1 = http("GET", f"http://127.0.0.1:{HUB_PORT}/hub/x402/route", headers=fwd)
    c2, _, b2 = http("GET", f"http://127.0.0.1:{HUB_PORT}/x402/route", headers={**fwd, "X-Forwarded-Prefix": "/hub"})
    c3 = status(f"http://127.0.0.1:{HUB_PORT}/hub/healthz")
    u1 = json.loads(b1)["resource"]["url"] if c1 == 402 else b1
    u2 = json.loads(b2)["resource"]["url"] if c2 == 402 else b2
    check("H", "hub behind a proxy: /hub/healthz 200; the 402's resource.url is the client's https .onion URL (prefix kept or stripped)",
          c3 == 200 and u1 == u2 == "https://abcdefghij234567.onion/hub/x402/route", {"kept": [c1, u1], "stripped": [c2, u2], "healthz": c3})
    docker("stop", f"{P}-knots")
    wait_until(lambda: mcp_ready() == 503 and hub_ready() == 503, 60, "readyz 503 with the node stopped")
    rz = json.loads(http("GET", f"http://127.0.0.1:{MCP_PORT}/readyz")[2])
    hz = json.loads(http("GET", f"http://127.0.0.1:{HUB_PORT}/readyz")[2])
    check("G", "node stopped: MCP /readyz 503 (signer: node unreachable) and hub /readyz 503; both /healthz 200",
          rz["signer_ready"]["node"]["reachable"] is False and hz["node"]["reachable"] is False
          and status(f"http://127.0.0.1:{MCP_PORT}/healthz") == 200 and status(f"http://127.0.0.1:{HUB_PORT}/healthz") == 200, {"mcp": rz, "hub": hz})
    docker("start", f"{P}-knots")
    wait_until(lambda: mcp_ready() == 200 and hub_ready() == 200, 90, "readyz 200 with the node back")
    check("G", "node back: MCP and hub /readyz 200", True)
    docker("restart", f"{P}-hub")
    wait_until(lambda: hub_ready() == 200, 60, "hub /readyz after restart")
    hub2 = json.loads(http("GET", f"http://127.0.0.1:{HUB_PORT}/readyz")[2])
    hk = helper("hub", "stat -c '%a %u %n' /d/secrets/hub-payto-key", ro=True).stdout.strip()
    check("H", "hub restart: the same payTo (key generated once, 0600)", hub1["pay_to"] == hub2["pay_to"] and hk.startswith("600 10004"),
          {"before": hub1["pay_to"], "after": hub2["pay_to"], "key": hk})
    for n in ("witness", "signer", "mcp", "hub"):
        wait_until(lambda: health(n) == "healthy", 120, f"{n} healthy at the end", every=3)
    check("S", "every service HEALTHCHECK healthy at the end", True)
    with open(os.path.join(OUT, "facts.json"), "w") as f:
        json.dump({"r1": r1, "r2": r2, "channels_before": chans1, "channels_after_restart": chans2, "channels_after_r2": chans3, "hub": hub2, "provider_ledger": prov_ledger[-2000:]},
                  f, indent=1, default=str)


if __name__ == "__main__":
    rc = 0
    try:
        main()
    except Exception as e:  # noqa: BLE001
        check("X", "the run completed", False, repr(e))
    finally:
        teardown()
        with open(os.path.join(OUT, "results.json"), "w") as f:
            json.dump(RESULTS, f, indent=1, default=str)
        n_ok = sum(r["ok"] for r in RESULTS)
        log(f"== {n_ok}/{len(RESULTS)} checks passed")
        rc = 0 if RESULTS and n_ok == len(RESULTS) else 1
    sys.exit(rc)
