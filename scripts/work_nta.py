"""AGP-043: the live NTA regtest leg of xbt-work with the Rust side: the Rust provider on an XBT-NTA
chain, its signer stopped -> a signed `unattested` deferral line -> the Rust audit passes -> paid with
the carry; the Rust relay server in front of primed; the §13.1 caps holding and releasing credit.

Driven by scripts/work_nta.sh (CPU scope, port preflight, builds, logs on every exit). The stack is
AGP-011's flagship-pww-nta (sov-017 NTA regtest setup) with the Rust pieces swapped in:

  nodes a, b   Knots 29.4.2 + NTA (nta@111). a: primed's and the payer's; b: the provider's (its signer
               and its audit follow b)
  primed       rnd/agp-011: receipts, window statements with signed deferral lines, POST /nta/attest;
               pushes blinded receipts to the RUST relay's push listener
  relay        xbt-work-relay (Rust): public GET listener + separate push listener, disk store
  gateway      the payer's own split-only datum_gateway (FTE 121edd0 + rnd/agp-011's patch)
  provider     xbt-work-provider (Rust) --nta: its identity is a BIP86 P2TR address (nta-signer
               bip86-tweak); caps --cap-invoice 1 --cap-total 1 --max-carry-sats 1e9; audits over its
               admin endpoint (and on its own, one block deep)
  signer       nta-signer (rnd/agp-011) following node b, posting each tip to primed's /nta/attest
  payer        xbt-work-payer (Rust): `.pw-` invoice, receipts through the Rust relay, paid calls

Phases (on regtest each block is one diff-1 share = 1 work unit):
  B0  the first share credits the provider (1 unit, unaudited)
  A   signer attests; block pays the provider; its share is HELD (invoice cap 1 is full): a live call
      spends the credited unit, the next is refused `credit_cap`; the audit of A passes and releases it
  B   signer stopped, burn block, then the block carries the provider: a signed `unattested` deferral
      line; the Rust audit passes on it (and fails without it); owed carry 25 XBT > 10 XBT cap: new
      credit frozen (`carry_cap`), the B share is held, a live call is refused `carry_cap`
  C   signer back: the block pays share + carry; the audit passes; carry 0, unfrozen, held credit flows
  D   one more pool block (a miner outside the invoice): its audit covers C; nothing is held
  pay the Rust payer spends the rest (its refusal checks, payer- and provider-side audits)
Negatives: P2WPKH identity refused by the node (bad-nta-payee) and by the Rust provider under --nta;
the relay lists nothing and refuses pushes on its public listener.

usage: python3 scripts/work_nta.py <cfg.json>
"""
import base64
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

CFG = json.load(open(sys.argv[1]))
RUN, OUT, BASE = CFG["run"], CFG["out"], CFG["base"]
sys.path.insert(0, CFG["xbt053"])
import nta  # noqa: E402  (XBT-053: BIP340, BIP86, bech32m)
import receipts as ref_receipts  # noqa: E402  (XBT-053: the Python relay client, to cross-check the Rust relay)

NTA_HEIGHT = 111
MINE_TIMEOUT = int(os.environ.get("WORK_NTA_MINE_TIMEOUT", "1500"))
THREADS = os.environ.get("WORK_NTA_THREADS", "2")
RPC = {"a": BASE + 1, "b": BASE + 3}
P2P = {"a": BASE + 2, "b": BASE + 4}
API, PRIME, STATS, STRATUM, RELAY, PUSH = BASE + 12, BASE + 20, BASE + 21, BASE + 22, BASE + 24, BASE + 25
STATS_URL, API_URL, RELAY_URL = f"http://127.0.0.1:{STATS}", f"http://127.0.0.1:{API}", f"http://127.0.0.1:{RELAY}"
FEE_BPS, WINDOW_MIN_WORK, PER_TIP, JOB_REFRESH = 5000, 64, 4, 5
MAX_CARRY = 1_000_000_000
B = CFG["bins"]

procs, checks, fails, blocks = {}, [], [], []


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def check(ok, what, **data):
    checks.append({"ok": bool(ok), "what": what, **data})
    print(("  ok   " if ok else "  FAIL ") + what, flush=True)
    if not ok:
        fails.append(what)
    json.dump(checks, open(os.path.join(OUT, "checks.json"), "w"), indent=1)
    return bool(ok)


def wait_for(pred, secs=30, step=0.25):
    end = time.time() + secs
    while time.time() < end:
        try:
            if pred():
                return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(step)
    return False


def write_secret(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, text.encode())
    os.close(fd)


def logf(name):
    return open(os.path.join(RUN, name), "a")


# ------------------------------------------------------------------ nodes
def cookie(n):
    return os.path.join(RUN, f"node-{n}", "regtest", ".cookie")


def rpc(n, method, *params, timeout=120):
    auth = base64.b64encode(open(cookie(n), "rb").read().strip()).decode()
    body = json.dumps({"jsonrpc": "1.0", "id": 0, "method": method, "params": list(params)}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{RPC[n]}/", body, {"Authorization": "Basic " + auth})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)["result"]
    except urllib.error.HTTPError as e:
        raise RuntimeError(json.load(e).get("error")) from None


def start_node(n):
    d = os.path.join(RUN, f"node-{n}")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    args = [f"-datadir={d}", "-regtest", "-server", f"-rpcport={RPC[n]}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
            "-testactivationheight=blake2b@101", f"-testactivationheight=nta@{NTA_HEIGHT}",
            "-testcoinbasematuritylong=200:200:6680", "-rdtsexpiry=4102444800", "-disablewallet",
            f"-port={P2P[n]}", "-bind=127.0.0.1", "-listen=1", "-dnsseed=0", "-fixedseeds=0", "-listenonion=0",
            "-discover=0", "-whitelist=noban@127.0.0.1", "-printtoconsole=0", "-par=1", "-dbcache=64"]
    args += [f"-addnode=127.0.0.1:{P2P[m]}" for m in P2P if m != n]
    procs[f"node-{n}"] = subprocess.Popen([B["bitcoind"]] + args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def height(n="a"):
    return rpc(n, "getblockcount")


def synced():
    return rpc("a", "getbestblockhash") == rpc("b", "getbestblockhash")


def coinbase(h, n="a"):
    b = rpc(n, "getblock", rpc(n, "getblockhash", h), 2)
    outs = []
    for o in b["tx"][0]["vout"]:
        spk = o["scriptPubKey"]
        s = spk["hex"]
        kind = "nta" if s.startswith("6a444e544102") and len(s) == 140 else ("opret" if s.startswith("6a") else "pay")
        outs.append({"address": spk.get("address") or s, "sats": round(o["value"] * 1e8), "script": s, "kind": kind})
    return {"height": h, "hash": b["hash"], "outputs": outs}


def payees_and_atts(cb):
    payees = []
    for o in cb["outputs"]:
        if o["kind"] == "pay" and o["sats"] > 0 and o["script"] not in payees:
            payees.append(o["script"])
    return payees, sum(1 for o in cb["outputs"] if o["kind"] == "nta")


# ------------------------------------------------------------------ HTTP
def _body(b, raw):
    if raw:
        return b
    try:
        return json.loads(b) if b else {}
    except ValueError:
        return {"text": b.decode(errors="replace")}


def http(url, body=None, method=None, timeout=15, raw=False):
    data = body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode()
    req = urllib.request.Request(url, data, {"Content-Type": "application/json"} if data else {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, _body(r.read(), raw), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, _body(e.read(), raw), dict(e.headers)


def get(path):
    return http(STATS_URL + path)[1]


# ------------------------------------------------------------------ services
def start_relay():
    procs["relay"] = subprocess.Popen([B["relay"], "--bind", f"127.0.0.1:{RELAY}", "--push-bind", f"127.0.0.1:{PUSH}",
                                       "--store", os.path.join(RUN, "relay-blobs"), "--rate", "50", "--burst", "200"],
                                      stdout=logf("relay.log"), stderr=subprocess.STDOUT)
    if not wait_for(lambda: http(f"{RELAY_URL}/healthz")[0] == 200, 20):
        raise SystemExit("the Rust relay did not come up; see relay.log")


def prime_toml(pool_addr):
    d = os.path.join(RUN, "prime")
    return f"""listen = "127.0.0.1:{PRIME}"
stats-listen = "127.0.0.1:{STATS}"
advertise-address = "127.0.0.1:{PRIME}"
data-dir = "{d}"
motd = "xbt-work under XBT-NTA, Rust provider and relay (AGP-043)"
min-diff = 1
payout-address = "{pool_addr}"
coinbase-tag = "Lazarus"
prime-id = 70
window = 8
window-min-work = {WINDOW_MIN_WORK}  # regtest difficulty is tiny: hold the whole run in one window
min-payout = 546
fee-bps = {FEE_BPS}  # TIDES pays carry only out of the pool's remainder: room to repay it in one block
network = "regtest"
rpc = "http://127.0.0.1:{RPC['a']}"
rpc-cookie = "{cookie('a')}"
poll = 0.25
receipt-relay = "http://127.0.0.1:{PUSH}"
nta-height = {NTA_HEIGHT}
nta-pool-key-file = "{os.path.join(RUN, 'keys', 'pool.nta')}"
nta-attest-per-tip = {PER_TIP}
"""


def start_prime(pool_addr):
    os.makedirs(os.path.join(RUN, "prime"), exist_ok=True)
    path = os.path.join(RUN, "prime.toml")
    open(path, "w").write(prime_toml(pool_addr))
    subprocess.run([B["primed"], "-c", path, "check"], check=True, capture_output=True)
    pub = subprocess.check_output([B["primed"], "-c", path, "pubkey"], text=True).strip().split()[-1]
    procs["prime"] = subprocess.Popen([B["primed"], "-c", path, "run"], env=dict(os.environ, RUST_LOG="info"),
                                      stdout=logf("primed.log"), stderr=subprocess.STDOUT)
    if not wait_for(lambda: procs["prime"].poll() is None and http(STATS_URL + "/healthz")[0] == 200, 30):
        raise SystemExit("primed did not come up; see primed.log")
    return pub


def stratum_listening():
    return str(STRATUM) in subprocess.run(["ss", "-Hltn", f"( sport = :{STRATUM} )"], capture_output=True, text=True).stdout


def start_gateway(pool_pub, pool_main_addr):
    d = os.path.join(RUN, "gw")
    os.makedirs(d, exist_ok=True)
    conf = {
        "bitcoind": {"rpccookiefile": cookie("a"), "rpcurl": f"http://127.0.0.1:{RPC['a']}", "notify_fallback": True,
                     "work_update_seconds": JOB_REFRESH},
        "stratum": {"listen_addr": "127.0.0.1", "listen_port": STRATUM, "vardiff_min": 1},
        "mining": {"pool_address": pool_main_addr, "coinbase_tag_primary": "Lazarus",
                   "coinbase_tag_secondary": "xbt-work-payer", "pow_algorithm": "auto"},
        "api": {"listen_port": 0},
        "logger": {"log_to_console": True, "log_to_file": False, "log_level_console": 1},
        "datum": {"pool_host": "127.0.0.1", "pool_port": PRIME, "pool_pubkey": pool_pub,
                  "pool_pass_workers": True, "pool_pass_full_users": True, "pooled_mining_only": True,
                  "protocol_global_timeout": 60, "identity_key_file": os.path.join(d, "identity.key"), "lzt1_attest": False},
    }
    path = os.path.join(RUN, "gw.json")
    json.dump(conf, open(path, "w"), indent=1)
    for attempt in range(1, 4):
        with open(os.path.join(RUN, "gw.log"), "a") as f:
            f.write(f"--- gateway start {attempt}\n")
        procs["gw"] = subprocess.Popen([B["cgw"], "--config", path], cwd=d, stdout=logf("gw.log"), stderr=subprocess.STDOUT)

        def ready():
            s = get("/stats.json")
            return procs["gw"].poll() is None and s["gateways"] == 1 and s["totals"]["coinbasers"] >= 1 and stratum_listening()
        if wait_for(ready, 30, 0.5):
            time.sleep(1)
            if procs["gw"].poll() is None:
                return True
        stop("gw")   # AGP-012: a bind failure after the DATUM handshake kills the gateway; wait and retry
        subprocess.run([sys.executable, CFG["portcheck"], "wait", "--timeout", "75", str(STRATUM)])
    raise SystemExit("gateway failed to start 3 times; see gw.log")


def provider_args(identity, port):
    return [B["provider"], "--port", str(port), "--rpc-port", str(RPC["b"]), "--cookie", cookie("b"), "--identity", identity,
            "--prime-pubkey", PRIME_PUB, "--prime-id", "70", "--receipt-url", f"{STATS_URL}/receipt", "--relay-url", RELAY_URL,
            "--window-url", f"{STATS_URL}/window", "--nta", "--admin", "--pull-secs", "3",
            "--data-dir", os.path.join(RUN, f"provider-data-{port}"), "--state", os.path.join(RUN, f"provider-work-{port}.json" if port != API else "provider-work.json"),
            "--cap-invoice", "1", "--cap-total", "1", "--max-carry-sats", str(MAX_CARRY), "--audit-depth", "1"] + prime_terms()


def prime_terms():
    # AGP-065: the provider and payer hold window statements to the Prime's published terms
    return ["--prime-window", "8", "--prime-window-min-work", str(WINDOW_MIN_WORK), "--prime-fee-bps", str(FEE_BPS),
            "--prime-min-payout", "546"]


def start_signer():
    procs["signer"] = subprocess.Popen(
        [B["signer"], "run", "--rpc", f"http://127.0.0.1:{RPC['b']}", "--rpc-cookie", cookie("b"),
         "--key-file", os.path.join(RUN, "keys", "provider.nta"), "--prime", f"{STATS_URL}/nta/attest", "--poll-ms", "1000"],
        env=dict(os.environ, RUST_LOG="info"), stdout=logf("signer.log"), stderr=subprocess.STDOUT)


def stop(name, sig=signal.SIGTERM):
    p = procs.pop(name, None)
    if p is None:
        return
    try:
        p.send_signal(sig)
        p.wait(timeout=30)
    except Exception:  # noqa: BLE001
        p.kill()


def kill_group(p):
    for s in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(p.pid, s)
        except OSError:
            pass
        try:
            p.wait(timeout=5)
            return
        except Exception:  # noqa: BLE001
            pass


# ------------------------------------------------------------------ the provider, the payer
def report():
    return http(f"{API_URL}/admin/xbt-work/report")[1]


def admin_audit(h, **extra):
    st, v, _ = http(f"{API_URL}/admin/xbt-work/audit", {"from": h, "to": h, **extra}, timeout=60)
    res = next((r for r in v.get("results", []) if r.get("height") == h), {})
    return res, v


def payer_call(path):
    p = subprocess.run([B["payer"], "call", API_URL, path, "--state", PAYER_STATE], capture_output=True, text=True, timeout=120)
    try:
        return json.loads(p.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"status": None, "error": p.stderr[-300:]}


def relay_receipt(inv):
    """The Prime's latest receipt for the invoice, through the RUST relay, opened by the PYTHON client."""
    st, blob, hdr = http(f"{RELAY_URL}/{ref_receipts.relay_lookup(PROVIDER, inv)}", raw=True)
    if st != 200:
        return None, st, hdr
    return json.loads(ref_receipts.relay_open(blob, PROVIDER, inv).rstrip()), st, hdr


def held_is(n, secs=30):
    return wait_for(lambda: report()["credit"]["heldWork"] == n, secs, 1)


# ------------------------------------------------------------------ NTA book (primed)
def nta_tip(h):
    return next((t for t in get("/nta.json").get("tips", []) if t["height"] == h), None)


def direct_signed(h):
    t = nta_tip(h)
    return next((s["ms"] for s in (t or {}).get("signers", []) if s["script"] == PROV_SCRIPT and s["gateway"] == "direct"), None)


def listed(h, n):
    t = nta_tip(h)
    return t is not None and t.get("best_payees", 0) >= n


def coinbasers_for(h):
    return (nta_tip(h) or {}).get("coinbasers", 0)


def carry_of(identity):
    time.sleep(0.6)   # stats.json is cached for 500 ms

    def find(d):
        if isinstance(d, dict):
            for k, v in d.items():
                if k == "miners" and isinstance(v, list) and v and isinstance(v[0], dict) and "carry_sats" in v[0]:
                    return v
                r = find(v)
                if r is not None:
                    return r
        elif isinstance(d, list):
            for v in d:
                r = find(v)
                if r is not None:
                    return r
        return None
    return next((m.get("carry_sats", 0) for m in (find(get("/stats.json")) or []) if m.get("identity") == identity), 0)


def gw_mark():
    return os.path.getsize(os.path.join(RUN, "gw.log"))


def gw_jobs_after(mark, secs=30):
    path = os.path.join(RUN, "gw.log")

    def seen():
        with open(path, errors="replace") as f:
            f.seek(mark)
            return "needs a coinbaser" in f.read()
    ok = wait_for(seen, secs, 0.5)
    time.sleep(1.5)
    return ok


# ------------------------------------------------------------------ mining
def mine_one(user):
    want = height() + 1
    out = logf("miner.log")
    t0 = time.time()
    while time.time() - t0 < MINE_TIMEOUT and height() < want:
        left = int(MINE_TIMEOUT - (time.time() - t0)) + 1
        p = subprocess.Popen(["timeout", "-k", "10", str(left), B["grind"], "--host", "127.0.0.1", "--port", str(STRATUM),
                              "--user", user, "--threads", THREADS], stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
        procs["miner"] = p
        try:
            wait_for(lambda: height() >= want or p.poll() is not None or procs["gw"].poll() is not None, left + 5, 0.25)
        finally:
            kill_group(p)
            procs.pop("miner", None)
        if procs["gw"].poll() is not None:
            raise SystemExit("the payer's gateway exited while mining; see gw.log")
        if height() < want:
            log(f"  miner exited after {time.time() - t0:.0f}s; restarting")
    ok = height() >= want
    wait_for(synced, 60)
    return ok, round(time.time() - t0, 1), want


def statement(h):
    return wait_for(lambda: http(f"{STATS_URL}/window?height={h}")[0] == 200, 20) and http(f"{STATS_URL}/window?height={h}")[1]


def mined_block(phase, user):
    ok, secs, h = mine_one(user)
    row = {"phase": phase, "ok": ok, "secs": secs, "height": h}
    if not ok:
        blocks.append(row)
        check(False, f"{phase}: a block was found at {h} within {MINE_TIMEOUT}s")
        return row
    cb = coinbase(h)
    payees, atts = payees_and_atts(cb)
    stmt = statement(h) or {}
    paid = sum(o["sats"] for o in cb["outputs"] if o["address"] == PROVIDER)
    row.update(hash=cb["hash"], payees=payees, atts=atts, stmt=stmt, paid_provider=paid,
               accepted_by=[n for n in RPC if rpc(n, "getblockhash", h) == cb["hash"]])
    blocks.append(row)
    json.dump(blocks, open(os.path.join(OUT, "blocks.json"), "w"), indent=1)
    log(f"  {phase}: block {h} in {secs}s, provider paid {paid} sat, payees {len(payees)}, attestations {atts}")
    check(len(row["accepted_by"]) == 2 and atts == len(payees),
          f"{phase}: block {h} accepted by both NTA nodes, one attestation per payee ({atts} for {len(payees)})")
    return row


def receipt_for(h):
    """Wait until the relay holds the receipt whose last share is at `h`, and the provider pulled it."""
    ok = wait_for(lambda: (relay_receipt(INV)[0] or {}).get("receipt", {}).get("last_height", 0) >= h, 45, 1)
    time.sleep(4)   # the provider pulls every 3 s
    return ok


# ------------------------------------------------------------------ main
def main():
    os.makedirs(os.path.join(RUN, "keys"), exist_ok=True)
    try:
        return run()
    finally:
        if "miner" in procs:
            kill_group(procs.pop("miner"))
        for name in ["signer", "provider", "gw", "prime", "relay"]:
            stop(name)
        for name in list(procs):
            stop(name)


def run():
    global PRIME_PUB, PROVIDER, PROV_SCRIPT, INV, PAYER_STATE
    # ---- keys: the pool's NTA key; the provider's BIP86 wallet key -> the output key NTA signs with
    pool_sec = secrets.token_bytes(32)
    write_secret(os.path.join(RUN, "keys", "pool.nta"), pool_sec.hex())
    pool_k = nta.xonly(pool_sec)
    pool_addr, pool_main = nta.p2tr_address(pool_k, "bcrt"), nta.p2tr_address(pool_k, "bc")
    d = secrets.token_bytes(32)
    write_secret(os.path.join(RUN, "keys", "provider-internal.hex"), d.hex())
    subprocess.run([B["signer"], "bip86-tweak", "--internal-key-file", os.path.join(RUN, "keys", "provider-internal.hex"),
                    "--out", os.path.join(RUN, "keys", "provider.nta")], check=True, capture_output=True)
    internal = nta.xonly(d)
    K = nta.bip86_output_key(internal)
    PROVIDER, PROV_SCRIPT = nta.p2tr_address(K, "bcrt"), "5120" + K.hex()
    k_sec = open(os.path.join(RUN, "keys", "provider.nta")).read().strip()
    check(nta.xonly(bytes.fromhex(k_sec)) == K and k_sec == nta.bip86_output_secret(d).hex(),
          f"provider identity {PROVIDER}: BIP86 P2TR; nta-signer holds the output-key secret (d+t)")

    # ---- nodes
    for n in RPC:
        start_node(n)
    for n in RPC:
        if not wait_for(lambda: rpc(n, "getblockcount") is not None, 120, 0.5):
            raise SystemExit(f"node {n} did not start")
    check(wait_for(lambda: all(rpc(n, "getconnectioncount") >= 1 for n in RPC), 60), "nodes a and b are peers")
    rpc("a", "generatetodescriptor", NTA_HEIGHT - 1, "raw(51)")
    check(wait_for(synced, 120) and height() == NTA_HEIGHT - 1,
          f"{rpc('a', 'getnetworkinfo')['subversion']} at {NTA_HEIGHT - 1}; NTA enforced from {NTA_HEIGHT}")
    node_addr = rpc("a", "deriveaddresses", rpc("a", "getdescriptorinfo", f"tr({internal.hex()})")["descriptor"])[0]
    check(node_addr == PROVIDER, f"the node's own tr(P) derivation gives the same address: {node_addr}")
    cpub = bytes([2 + (nta.point_mul(int.from_bytes(d, 'big'))[1] & 1)]) + internal
    p2wpkh = rpc("a", "deriveaddresses", rpc("a", "getdescriptorinfo", f"wpkh({cpub.hex()})")["descriptor"])[0]
    try:
        r1 = rpc("a", "submitblock", rpc("a", "generateblock", p2wpkh, [], False)["hex"]) or "accepted"
    except RuntimeError as e:
        r1 = str(e)
    check("bad-nta-payee" in r1 and height() == NTA_HEIGHT - 1,
          f"negative: a coinbase paying the provider's P2WPKH identity is refused by the node: {r1}")

    # ---- the Rust relay, primed (pushing to it), the payer's gateway
    start_relay()
    PRIME_PUB = start_prime(pool_addr)
    start_gateway(PRIME_PUB, pool_main)
    check(True, f"Rust xbt-work-relay: public {RELAY_URL}, push :{PUSH} (primed's receipt-relay); primed rnd/agp-011 on "
                f"{PRIME}/{STATS} (NTA from {NTA_HEIGHT}, fee {FEE_BPS} bps); the payer's split-only gateway on {STRATUM}")
    st_l, _, _ = http(f"{RELAY_URL}/")
    st_p, _, _ = http(f"{RELAY_URL}/{'ab' * 32}", body=b"x" * 1052, method="PUT")
    check(st_l == 404 and st_p == 405, f"relay: GET / lists nothing ({st_l}); a push on the public listener is refused ({st_p})")

    # ---- the Rust provider: refuses a P2WPKH identity under --nta, runs on the P2TR one
    bad = subprocess.run(provider_args(p2wpkh, API + 1), capture_output=True, text=True, timeout=60)
    check(bad.returncode != 0 and "cannot be paid under payee attestation" in bad.stderr,
          f"negative: the Rust provider refuses its P2WPKH identity under --nta (exit {bad.returncode}): {bad.stderr.strip()[-120:]}")
    procs["provider"] = subprocess.Popen(provider_args(PROVIDER, API), stdout=logf("provider.log"), stderr=subprocess.STDOUT)
    if not wait_for(lambda: http(f"{API_URL}/")[0] == 200, 60, 0.5):
        raise SystemExit("the Rust provider did not come up; see provider.log")
    rep = report()
    check(rep["credit"]["capInvoiceWork"] == 1 and rep["credit"]["capTotalWork"] == 1 and rep["credit"]["maxOwedCarrySats"] == MAX_CARRY,
          f"Rust provider (xbt402 Provider + xbt-work, --nta) up with §13.1 caps: {rep['credit']}")
    start_signer()

    # ---- the Rust payer: a `.pw-` invoice from the 402
    PAYER_STATE = os.path.join(RUN, "payer-work.json")
    user = subprocess.run([B["payer"], "prepare", API_URL, "--state", PAYER_STATE], check=True, capture_output=True, text=True).stdout.strip()
    INV = user.split(".pw-")[1].split(".")[0]
    check(user.startswith(f"{PROVIDER}.pw-{INV}."), f"Rust payer mines as {user}")

    # ---- B0: the first share credits the provider
    log("== B0: bootstrap")
    b0 = mined_block("B0", user)
    check(b0["ok"] and receipt_for(b0["height"]), "B0: Prime receipted the first share; the Rust relay serves it (opened by the Python client)")
    doc, st, hdr = relay_receipt(INV)
    check(st == 200 and hdr.get("Cache-Control") == "no-store" and doc["message"].startswith(f"xbt-work-receipt/1|70|{PROVIDER}|{INV}|"),
          f"relay blob: 200, Cache-Control {hdr.get('Cache-Control')}, a Prime-signed receipt for the pair inside")
    rep = report()
    check(rep["credit"]["unauditedWork"] == 1 and rep["credit"]["heldWork"] == 0,
          f"B0: the provider credited 1 unit, unaudited: {rep['credit']}")

    # ---- A: attested; paid; the share is held by the invoice cap until the audit
    log("== A: the signer attests each tip through POST /nta/attest")
    hA = height() + 1
    check(wait_for(lambda: direct_signed(hA) is not None, 30), f"A: the signer filed the provider for block {hA}")
    lst = wait_for(lambda: listed(hA, 1), 45)
    mark = gw_mark()
    check(lst and gw_jobs_after(mark, 45), f"A: a coinbaser for {hA} lists the provider; the gateway published a job after it")
    time.sleep(1)
    a = mined_block("A", user)
    if a["ok"]:
        check(a["paid_provider"] > 0 and PROV_SCRIPT in a["payees"], f"A: block {a['height']} pays the provider {a['paid_provider']} sat")
        receipt_for(a["height"])
        check(held_is(1), f"A: the invoice cap (1 unaudited unit) holds the new share: {report()['credit']}")
        c1 = payer_call("/v1/pools?window=7d")
        c2 = payer_call("/v1/pool/lazarus")
        check(c1.get("status") == 200 and c2.get("code") == "credit_cap",
              f"A: live calls: the credited unit pays (HTTP {c1.get('status')}); the next is refused {c2.get('code')} "
              f"(the Rust payer: {str(c2.get('error'))[:90]})", calls=[c1, c2])
        res, _ = admin_audit(a["height"])
        rep = report()
        check(res.get("ok") is True and res.get("paidSats") == a["paid_provider"] and rep["credit"]["heldWork"] == 0
              and rep["credit"]["unauditedWork"] == 1,
              f"A: Rust audit PASS (paid {res.get('paidSats')} >= expected {res.get('expectedSats')}, proven {res.get('provenWork')}); "
              f"it covers B0's credit and releases the held unit: {rep['credit']}", audit=res)

    # ---- B: signer down; the block carries the provider
    log("== B: signer stopped; the tip moves on without it")
    stop("signer")
    burn = rpc("a", "generatetodescriptor", 1, "raw(6a)")[0]
    wait_for(synced, 60)
    hB = height() + 1
    wait_for(lambda: coinbasers_for(hB) >= 1, 45)
    mark = gw_mark()
    check(gw_jobs_after(mark, 45) and direct_signed(hB) is None and not listed(hB, 1),
          f"B: signer stopped, burn block {hB - 1} ({burn[:12]}..); nothing attested the provider for {hB}")
    carry0 = carry_of(PROVIDER)
    b = mined_block("B", user)
    if b["ok"]:
        dl = [x for x in b["stmt"].get("deferred", []) if x.get("identity") == PROVIDER]
        check(b["paid_provider"] == 0 and PROV_SCRIPT not in b["payees"], f"B: block {b['height']} pays the provider nothing")
        check(len(dl) == 1 and dl[0]["reason"] == "unattested" and dl[0]["sats"] > 0,
              f"B: the window statement signs the carry: {dl[0]['message'] if dl else 'no deferral line'}", deferral=dl)
        receipt_for(b["height"])
        res, v = admin_audit(b["height"], withoutDeferrals=b["height"])
        wd = v.get("withoutDeferrals", {})
        check(res.get("ok") is True and res.get("deferredSats") == (dl[0]["sats"] if dl else -1) and res.get("paidSats") == 0,
              f"B: Rust audit PASS on the signed deferral line (paid 0 + deferred {res.get('deferredSats')} >= expected "
              f"{res.get('expectedSats')}): carry is not a shortfall", audit=res)
        check(wd.get("ok") is False and wd.get("proofChecks") is True,
              "B: control: the same block audited without its deferral line is a fraud proof that checks from its signed contents",
              control={k: wd.get(k) for k in ("ok", "expectedSats", "proofChecks")})
        carry1 = carry_of(PROVIDER)
        rep = report()
        check(carry1 - carry0 == (dl[0]["sats"] if dl else -1) and rep["carry"]["owedSats"] == carry1,
              f"B: primed holds the provider's share as carry ({carry0} -> {carry1} sat); the Rust carry ledger agrees "
              f"(owed {rep['carry']['owedSats']})")
        check(rep["credit"]["frozen"] == "carry_cap" and rep["credit"]["heldWork"] == 1,
              f"B: owed carry {rep['carry']['owedSats']} > {MAX_CARRY}: new credit frozen, the B share held: {rep['credit']}")
        c3 = payer_call("/v1/pools?window=1d")
        c4 = payer_call("/v1/share-change?window=7d")
        check(c3.get("status") == 200 and c4.get("code") == "carry_cap",
              f"B: live calls: the credited unit pays (HTTP {c3.get('status')}); the next is refused {c4.get('code')}", calls=[c3, c4])

    # ---- C: signer back; paid with the carry
    log("== C: signer restarted")
    hC = height() + 1
    carry_before = carry_of(PROVIDER)
    start_signer()
    check(wait_for(lambda: direct_signed(hC) is not None, 30), f"C: the restarted signer files the provider for block {hC}")
    lst = wait_for(lambda: listed(hC, 1), 45)
    mark = gw_mark()
    check(lst and gw_jobs_after(mark, 45), f"C: a coinbaser for {hC} lists the provider again")
    time.sleep(1)
    c = mined_block("C", user)
    if c["ok"]:
        receipt_for(c["height"])
        res, _ = admin_audit(c["height"])
        carry_after = carry_of(PROVIDER)
        rep = report()
        check(c["paid_provider"] > 0 and carry_after < carry_before and c["paid_provider"] >= res.get("expectedSats", 0) + carry_before - carry_after - 1,
              f"C: block {c['height']} pays the provider {c['paid_provider']} sat: its share plus {carry_before - carry_after} sat of carry")
        check(res.get("ok") is True and rep["carry"]["owedSats"] == 0,
              f"C: Rust audit PASS (paid {res.get('paidSats')} >= expected {res.get('expectedSats')}); the carry ledger is released "
              f"(owed {rep['carry']['owedSats']}, released {rep['carry']['releasedSats']})", audit=res)
        # AGP-079: a pass covers only what the coinbase paid for. On regtest a call costs one unit and a paying
        # block pays for one: it covers A's unit, the B share takes the cap of 1, the C share stays held until D
        check(rep["credit"]["frozen"] is None and rep["credit"]["heldWork"] == 1 and rep["credit"]["unauditedWork"] == 1,
              f"C: unfrozen; the coinbase pays for one unit (A's), the B share takes the cap of 1, the C share is held: {rep['credit']}")

    # ---- D: one more pool block, mined outside the invoice: its coinbase pays for one more unit, the C share is credited
    log("== D: a pool block outside the invoice")
    d_row = mined_block("D", f"{pool_addr}.d")
    if d_row["ok"]:
        time.sleep(4)
        res, _ = admin_audit(d_row["height"])
        rep = report()
        check(res.get("ok") is True and rep["credit"]["heldWork"] == 0,
              f"D: block {d_row['height']} (paid {res.get('paidSats')}) audit PASS; every receipted unit is now credited: {rep['credit']}",
              audit=res)

    # ---- pay: the Rust payer spends the rest (all its checks, payer- and provider-side audits)
    rc = relay_receipt(INV)[0]["receipt"]
    spent = 2
    calls = max(1, rc["cum_work"] - spent)
    log(f"== pay: {calls} calls with the invoice's remaining receipted work")
    p = subprocess.run([B["payer"], "pay", API_URL, str(calls), "120", "--state", PAYER_STATE, "--rpc-port", str(RPC["a"]),
                        "--cookie", cookie("a"), "--window-url", f"{STATS_URL}/window", "--provider-admin"] + prime_terms(),
                       capture_output=True, text=True, timeout=600)
    sys.stdout.write(p.stderr)
    open(os.path.join(OUT, "payer.json"), "w").write(p.stdout)
    try:
        pww = json.loads(p.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        pww = {"ok": False, "checks": []}
    bad_checks = [x["what"] for x in pww.get("checks", []) if not x["ok"]]
    check(p.returncode == 0 and pww.get("ok"),
          f"pay: the Rust payer paid {calls} calls; its checks {sum(1 for x in pww.get('checks', []) if x['ok'])}/{len(pww.get('checks', []))}"
          + (f" (failed: {bad_checks})" if bad_checks else ""))

    # ---- the provider's own auto-audit (one block deep) agreed, and hygiene
    plog = open(os.path.join(RUN, "provider.log"), errors="replace").read()
    auto = sorted({int(l.split("audit: block ")[1].split(":")[0]) for l in plog.splitlines() if "audit: block " in l and ": PASS" in l})
    check(set(r["height"] for r in blocks if r["ok"] and r["phase"] != "D") <= set(auto) and "FAIL" not in
          "".join(l for l in plog.splitlines() if "audit: block " in l),
          f"the provider's own audit loop (--audit-depth 1) passed every pool block one deep: {auto}")
    rep = report()
    json.dump(rep, open(os.path.join(OUT, "provider-report.json"), "w"), indent=1)
    rlog = open(os.path.join(RUN, "relay.log"), errors="replace").read()
    plines = open(os.path.join(RUN, "primed.log"), errors="replace").read()
    check(ref_receipts.relay_lookup(PROVIDER, INV) not in rlog and "receipt relay PUT" not in plines,
          "the relay logged no lookup; primed logged no failed relay push")
    logs = "".join(open(os.path.join(RUN, f), errors="replace").read() for f in ("signer.log", "primed.log", "provider.log", "gw.log", "relay.log"))
    check(k_sec not in logs and d.hex() not in logs, "neither the provider's output secret nor its internal secret appears in any log")
    summary = {"task": "AGP-043", "result": "PASS" if not fails else "FAIL", "fails": fails, "provider": PROVIDER, "provider_p2wpkh": p2wpkh,
               "pool": pool_addr, "prime_pubkey": PRIME_PUB[:64], "invoice": INV, "user": user, "fee_bps": FEE_BPS,
               "caps": {"invoice": 1, "total": 1, "max_owed_carry_sats": MAX_CARRY},
               "blocks": [{k2: v for k2, v in r.items() if k2 != "stmt"} for r in blocks], "provider_report": rep}
    json.dump(summary, open(os.path.join(OUT, "summary.json"), "w"), indent=1)
    json.dump([b2.get("stmt") for b2 in blocks], open(os.path.join(OUT, "window-statements.json"), "w"), indent=1)
    print(f"{sum(1 for x in checks if x['ok'])}/{len(checks)} checks")
    print("RESULT " + ("PASS" if not fails else f"FAIL ({len(fails)})"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
