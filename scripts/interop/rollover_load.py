#!/usr/bin/env python3
"""AGP-053 rollover under load on regtest, driven by scripts/rollover_load_regtest.sh.

One hub (Rust or Python), one provider (Rust or Python, settleMultiple 2 so its ch2 is rolled over
every few seconds), and the Rust client (xbt402-rollover-load) paying one lock after every call at
LOAD_RATE locks/s (>= 10) for LOAD_SECONDS. A miner thread mines one block every LOAD_BLOCK_S. A
monitor reads the hub's out book (ch2.json) every 0.2 s: every rollover, and each next ch2's zero-conf
state. Runs (hub-provider):
  <H>-<P>         make-before-break (the default): several rollovers under load, ZERO refused locks
                  (no route_blocked, nothing a client would fail over on), every call 200, lock rate >= 10/s
  <H>-<P>-before  the provider takes no unconfirmed child (--zero-conf-max 0): the pre-AGP-053
                  break-before-make behaviour, measured (route_blocked refusals per rollover, gaps)
  <H>-<P>-stuck   fallback: the first rollover is kept out of blocks (empty blocks, generateblock ADDR []) for
                  LOAD_STUCK_S: locks go on over the unconfirmed child until the provider's zero-conf cap,
                  then the hub refuses (route_blocked) before sending anything (no provider refusal, the
                  child's signed state never above the cap); once it confirms, routing resumes
  <H>-<P>-reorg   a reorg across the switch: once a rollover's child is confirmed, the block holding it
                  is invalidated (the rollover is back in the mempool, the hub sees the child unconfirmed
                  again), the miner pauses LOAD_REORG_S, then the new chain confirms it. route_blocked
                  refusals are allowed only when every one is the zero-conf cap or close-margin reason
                  for that reorged ch2, and only between the reorg mark and that ch2 re-confirming (or
                  its next rollover). Counted as refusedDuringReorg. Plain <H>-<P> stays ZERO refusals.
                  Optional kinds (LOAD_ONLY): reorg-cap (pause until the cap is hit, then re-confirm;
                  asserts those refusals happen and stop) and reorg-zero (mine immediately; asserts zero)
  <H>-<P>-high    AGP-056, a high price: every lock (HIGH_LOCK sat) is above the provider's settle threshold
                  (2 x 600 net). The settle floor (settle_lock_multiple 4, the default) rolls the ch2 over
                  once per >= 4 locks, and the provider's zero-conf cap follows the lock size: ZERO refused
                  locks, every call 200, rollovers per paid lock <= 0.3. At LOAD_HIGH_RATE locks/s (2).
  <H>-<P>-high-nofloor  the same price with the floor off in hub and provider (settle_lock_multiple 0), the
                  pre-AGP-056 behaviour, measured: a rollover per paid lock, and route_blocked after each
                  (the next lock is above the 2,400 sat zero-conf cap until a block confirms the child)
  <H>-<P>-cmp     AGP-057, cmp's prices (CMP-149 R14): CMP_LOCK-sat locks (16,515: cap 132,120 = 2 x 4 x the lock)
                  on a 1,000,000-sat ch2, settleMultiple 20, at LOAD_CMP_RATE locks/s (2) for LOAD_CMP_SECONDS (28),
                  a miner that mines whenever the mempool is not empty (cmp's, every 0.4 s) and the hub's watcher
                  every second (cmp's swarm): ZERO refused locks
  <H>-<P>-cmp-lag the same with the hub's watcher every LOAD_CMP_LAG_S (5, the hub's own default): the child is
                  confirmed long before the watcher's next tick. ZERO refused locks (the hub looks at the chain
                  before it refuses on the cap); before AGP-057 it refused on its stale `confirmed` flag
  <H>-<P>-cmp-slow  a block only every LOAD_CMP_SLOW_S (6): more than the cap's 8 locks arrive while the child is
                  really unconfirmed. Refusals are expected (the provider's risk bound, documented sizing): every
                  one is the zero-conf cap, on a child that was unconfirmed on chain at that moment
  <H>-<P>-cmp-slow-sized  the same slow blocks with the provider's cap sized for them (--zero-conf-max
                  LOAD_CMP_RATE x LOAD_CMP_SLOW_S x 2 locks): ZERO refused locks
                  Every cmp run reports capDiagnosis: each cap refusal as hubLag (the child's rollover was in a
                  block already) or unconfirmed, and childCumCarried (the most any child's signed state was
                  above the sum of its own locks: 0 = the child's cum starts at 0, nothing carried).
  <H>-<P>-exhaust   AGP-057, exhaustion under load: EXH_LOCK-sat locks (3,000) at LOAD_EXH_RATE locks/s (2) for
                  LOAD_EXH_SECONDS (60) over a ch2 of EXH_CAP (120,000: 40 locks, about 20 s), so the line runs
                  out several times. refill_ahead_locks 16: the hub funds the next ch2 while the live one still
                  routes and switches to it: ZERO refused locks, every call 200, two live ch2s per origin seen
                  (never more than one next), the hub's coins never above liquidity_cap_sat (2 x EXH_CAP), and
                  every replaced ch2 closed on its signed state
  <H>-<P>-exhaust-before  the same with refill_ahead_locks 0, the pre-AGP-057 behaviour, measured: the refill
                  follows the close and opens at minConf (route_blocked until the next block)
Money checks for every run: each rollover tx pays the provider signed - closeFee (payee-pays) and the
next ch2 capacity - signed; the next ch2's capacity is that output; routed over all of the provider's
ch2s == what the client paid that shard; no lock pending or written off anywhere.
Env: XBT402_B1, XBT402_DATADIR, XBT402_RPCPORT, RS_BIN, PY, LOAD_PB, LOAD_RUN, LOAD_ONLY (e.g.
"RS-RS,PY-PY-before"), LOAD_SECONDS, LOAD_RATE, LOAD_BLOCK_S, LOAD_STUCK_S, LOAD_REORG_S, LOAD_REPORT,
LOAD_ROUTE_WAL=1 (AGP-054: both providers run a RouteWal, so every call's meter is durable before its answer),
LOAD_SPAN (the port span: under 100 the selected runs take two ports each from LOAD_PB + 4),
LOAD_CMP_LOCK, LOAD_CMP_RATE, LOAD_CMP_SECONDS, LOAD_CMP_LAG_S, LOAD_CMP_SLOW_S, LOAD_EXH_RATE, LOAD_EXH_SECONDS,
LOAD_EXH_CAP, LOAD_EXH_AHEAD."""
import http.client
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

B1 = os.environ["XBT402_B1"]
sys.path.insert(0, B1)
from xbt402.rpc import RPC  # noqa: E402
from xbt402.x402_channel import network_id, unb64json  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
RS = os.environ["RS_BIN"]
PY = os.environ.get("PY", sys.executable)
PB = int(os.environ.get("LOAD_PB", "34900"))
SPAN = int(os.environ.get("LOAD_SPAN", "100"))
RUN = os.environ["LOAD_RUN"]
SECONDS = float(os.environ.get("LOAD_SECONDS", "45"))
RATE = float(os.environ.get("LOAD_RATE", "15"))
BLOCK_S = float(os.environ.get("LOAD_BLOCK_S", "3"))
STUCK_S = float(os.environ.get("LOAD_STUCK_S", "20"))
REORG_S = float(os.environ.get("LOAD_REORG_S", "5"))
SOAK = ["systemd-run", "--user", "--scope", "-q", "-p", "CPUQuota=200%", "-p", "MemoryMax=4G", "nice", "-n", "19"]
PRICE = 24 * 10 ** 21                  # 24 sat a call: ch2 reaches 2 x closeFee net every ~5 s at 15 locks/s
SETTLE, CLOSE_FEE = 2, 600
HIGH_LOCK = 3_000                      # sat a call in the high-price runs (AGP-056): one lock > the 1,800 sat threshold
HIGH_RATE = float(os.environ.get("LOAD_HIGH_RATE", "2"))
CMP_LOCK = int(os.environ.get("LOAD_CMP_LOCK", "16515"))        # sat a call at cmp's R14 prices (CMP-149): cap 132,120
CMP_RATE = float(os.environ.get("LOAD_CMP_RATE", "2"))
CMP_SECONDS = float(os.environ.get("LOAD_CMP_SECONDS", "28"))    # 56 locks, 925k sat: inside one 1M ch2 line and ch1
CMP_LAG_S = float(os.environ.get("LOAD_CMP_LAG_S", "5"))         # the hub's own default watch_interval
CMP_SLOW_S = float(os.environ.get("LOAD_CMP_SLOW_S", "6"))
EXH_LOCK = HIGH_LOCK                   # AGP-057 exhaustion under load
EXH_RATE = float(os.environ.get("LOAD_EXH_RATE", "2"))
EXH_SECONDS = float(os.environ.get("LOAD_EXH_SECONDS", "60"))
EXH_CAP = int(os.environ.get("LOAD_EXH_CAP", "120000"))        # 40 locks: the line runs out about every 20 s
EXH_AHEAD = int(os.environ.get("LOAD_EXH_AHEAD", "16"))        # locks of room at which the next ch2 is funded: about
#                                                                 two block intervals of locks (6 a block at 2/s, 3 s)
LIVE = ("funding", "funded", "open")
MINE_EVERY_S = 0.4                     # cmp's miner (tools/swarm.py): a block whenever the mempool is not empty
SAT = 100_000_000


def reorg_allowed_refusal(code, detail):
    """True if this lock refusal is the intended safety stop on an unconfirmed rollover child."""
    d = (detail or "").lower()
    if code == "route_blocked":
        return "zero-conf cap" in d or "close margin" in d
    if code == "zero_conf_cap":
        return True
    return code == "unconfirmed" and ("close margin" in d or "rollover" in d)


def client_refusals(res):
    """Each refusal as {t, ts, code, detail}. Prefers the client's refusals list; falls back to timeline."""
    out = list(res.get("refusals") or [])
    if out:
        return out
    recs = []
    for x in res.get("timeline") or []:
        if not (isinstance(x, list) and len(x) >= 3 and x[1] == "refused"):
            continue
        third = x[2]
        if isinstance(third, dict):
            recs.append({"t": x[0], "ts": third.get("ts"), "code": third.get("code", ""), "detail": third.get("detail", "")})
        else:
            recs.append({"t": x[0], "ts": None, "code": third, "detail": ""})
    return recs


node = RPC.from_env()
W = node.wallet("w")
ADDR = W.getnewaddress()
NET = network_id(node.getblockhash(101))
COOKIE = os.path.join(os.environ["XBT402_DATADIR"], "regtest", ".cookie")
RPCPORT = os.environ["XBT402_RPCPORT"]
LOG = open(os.path.join(RUN, "rollover_load.log"), "a")


def spawn(cmd, **kw):
    return subprocess.Popen(SOAK + cmd, stdout=LOG, stderr=LOG, **kw)


def stop(p):
    if p and p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()


def wait_http(url, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except urllib.error.HTTPError:
            return True
        except (OSError, http.client.HTTPException):
            # HTTPException: nobody listens yet and the poll connected to itself (its source port was this
            # port: see `start`), reading its own request back
            time.sleep(0.2)
    return False


def log_size():
    LOG.flush()
    return os.path.getsize(LOG.name)


def said(marker, at):
    """A process wrote `marker` to the run's log after byte `at`."""
    with open(LOG.name, "rb") as f:
        f.seek(at)
        return marker.encode() in f.read()


def start(cmd, marker, timeout=60, **kw):
    """Start a process and wait for its ready line (`marker` in the run's log): it listens now, and its
    port is polled only after that. Returns (process, ready).

    A listener port inside the kernel's ephemeral range (a worker's port grant outside
    net.ipv4.ip_local_reserved_ports; the default base 349xx is inside it) can be the source port of any
    local connection for a moment, a poll of that very port included (it then connects to itself), and
    the process cannot bind it: `Address already in use`. One that exits before it is ready is started
    again (a hub finds the ch2 it funded in its book), for up to 75 s: a connection closed from its own
    side keeps its source port for a minute (TIME_WAIT)."""
    p = None
    for pause in (1, 2, 4, 8, 15, 15, 15, 15, 0):
        at = log_size()
        p = spawn(cmd, **kw)
        end = time.time() + timeout
        while time.time() < end and p.poll() is None:
            if said(marker, at):
                return p, True
            time.sleep(0.1)
        if p.poll() is None:
            return p, False                      # running and silent: not this
        LOG.write(f"rollover_load: {cmd[0]} exited {p.returncode} before it was ready; starting it again\n")
        LOG.flush()
        time.sleep(pause)
    return p, False


def routing(hub_url):
    try:
        urllib.request.urlopen(hub_url + "/x402/route", timeout=3)
    except urllib.error.HTTPError as e:
        if e.code == 402:
            return unb64json(e.headers["PAYMENT-REQUIRED"])["accepts"][0]["extra"]["routing"]
    except (OSError, http.client.HTTPException):
        pass
    return None


def book(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def records(b):
    return (list((b or {}).get("archived", [])) + list(((b or {}).get("chans") or {}).values())
            + list(((b or {}).get("next_chans") or {}).values()))


def mine_one(empty=False):
    """One block to a fresh address (after an invalidateblock the same template would rebuild the very
    block that was invalidated: duplicate-invalid); `empty`: no txs (a fee market that leaves them out)."""
    a = W.getnewaddress()
    return node.generateblock(a, []) if empty else node.generatetoaddress(1, a)


class Miner:
    """One block every `every` seconds (BLOCK_S), or with `mempool` whenever the mempool is not empty (looked
    at every `every` seconds: cmp's miner); `hold` pauses it, `empty` mines blocks without txs. `blocks` is
    every block it mined: hash -> the time generate returned (AGP-057: was a child confirmed at a refusal?)."""

    def __init__(self, every=None, mempool=False):
        self.stop, self.hold, self.empty = threading.Event(), threading.Event(), threading.Event()
        self.every, self.mempool, self.blocks = BLOCK_S if every is None else every, mempool, {}
        self.t = threading.Thread(target=self.run, daemon=True)
        self.t.start()

    def run(self):
        while not self.stop.wait(self.every):
            if self.hold.is_set():
                continue
            try:
                if self.mempool and not node.getmempoolinfo()["size"]:
                    continue
                r = mine_one(self.empty.is_set())
                for h in ([r["hash"]] if isinstance(r, dict) else r):
                    self.blocks[h] = time.time()
            except Exception as e:  # noqa: BLE001
                LOG.write(f"miner: {e}\n")


def cap_diagnosis(refusals, recs, live, blocks):
    """AGP-057 item A: why the hub refused on the provider's zero-conf cap. Each cap refusal is matched to the
    rollover child that was the live ch2 then (`live`: chan -> [first, last] time the monitor saw it in the
    book's chans) and to the block that confirmed that child's funding (`blocks`: the miner's log):
      hubLag       the rollover was in a block before the refusal: the hub's `confirmed` flag was stale
      unconfirmed  it was not in a block yet: the provider's bound on an unconfirmed child (sizing)
    childCumCarried: the most any child's signed state is above the sum of its own locks (the channel floor
    aside); 0 = a child's cum starts at 0 and nothing of the parent is carried into the cap."""
    children = {f"{r['params'].get('funding_txid')}:{r['params'].get('funding_vout')}": r for r in recs if r.get("rolled_from")}
    out = {"refusals": 0, "hubLag": 0, "unconfirmed": 0, "unattributed": 0, "rows": []}
    for rf in refusals:
        m = re.search(r"cum (\d+) > the provider's zero-conf cap (\d+)", rf.get("detail") or "")
        if not m:
            continue
        out["refusals"] += 1
        cum, cap, ts = int(m.group(1)), int(m.group(2)), float(rf.get("ts") or 0)
        capped = [c for c in live if c in children and int((children[c].get("zero_conf") or {}).get("maxCum", -1)) == cap]
        # the child that was live at the refusal; the monitor reads the book every 0.2 s, so a refusal just
        # outside every span goes to the nearest one within 0.5 s
        cands = [c for c in capped if live[c][0] <= ts <= live[c][1]] or [c for c in capped if live[c][0] - 0.5 <= ts <= live[c][1] + 0.5]
        if not cands:
            out["unattributed"] += 1
            continue
        chan = min(cands, key=lambda c: live[c][0])
        try:
            mined = blocks.get(node.getrawtransaction(chan.split(":")[0], True).get("blockhash"))
        except Exception:  # noqa: BLE001 - never mined (the run ended first)
            mined = None
        kind = "hubLag" if mined is not None and mined < ts else "unconfirmed"
        out[kind] += 1
        if len(out["rows"]) < 40:
            out["rows"].append({"t": rf.get("t"), "chan": chan[:16], "cum": cum, "cap": cap, "kind": kind,
                                "confirmedBefore": round(ts - mined, 3) if mined is not None and mined < ts else None})
    floor = max((int(r["params"].get("close_fee", 0)) + 546 for r in children.values()), default=0)
    carried = [max(0, int(r.get("signed", 0)) - max(int(r.get("routed", 0)), floor if r.get("signed") else 0)) for r in children.values()]
    out["childCumCarried"] = max(carried, default=0)
    out["children"] = len(children)
    return out


def scenario(i, name, j=0):
    parts = name.split("-")
    hub_impl, prov_impl, kind = parts[0], parts[1], ("-".join(parts[2:]) if len(parts) > 2 else "after")
    is_reorg = kind.startswith("reorg")
    is_high = kind.startswith("high")
    is_cmp = kind.startswith("cmp")
    is_exh = kind.startswith("exhaust")
    floor_k = 0 if kind == "high-nofloor" else 4
    price, rate = (HIGH_LOCK * 10 ** 21, HIGH_RATE) if is_high else (PRICE, RATE)
    seconds, settle, watch_s = SECONDS, SETTLE, 0.5
    if is_cmp:
        price, rate, seconds, settle = CMP_LOCK * 10 ** 21, CMP_RATE, CMP_SECONDS, 20
        watch_s = CMP_LAG_S if kind == "cmp-lag" else (1.0 if kind == "cmp" else 0.5)
    if is_exh:
        price, rate, seconds = EXH_LOCK * 10 ** 21, EXH_RATE, EXH_SECONDS
    # ten runs of 8 ports from PB+10; the AGP-056 runs take two each from PB+90 (all below PB+100)
    # (an optional LOAD_ONLY kind runs alone on the last pair). A span under 100 (AGP-057: a worker's port
    # grant): the j-th selected run takes two ports from PB+4
    base = PB + 10 + 8 * i if i < 10 else min(PB + 90 + 2 * (i - 10), PB + 98)
    if SPAN < 100:
        base = PB + 4 + 2 * j
        assert base + 1 < PB + SPAN, f"run {j} does not fit in {SPAN} ports from {PB}"
    hub_port, prov_port = base, base + 1
    d = os.path.join(RUN, name)
    os.makedirs(d, exist_ok=True)
    checks, marks = [], []
    t_start = [None]

    def check(what, ok, detail=""):
        checks.append({"check": what, "ok": bool(ok), "detail": detail})

    def mark(what, **kw):
        now = time.time()
        marks.append({"t": round(now - (t_start[0] or now), 3), "ts": now, "what": what, **kw})

    procs, miner, client = [], None, None
    zc = "0" if kind == "before" else "default"
    if kind == "cmp-slow-sized":          # the cap sized for the block interval: twice the locks of one interval
        zc = str(int(2 * CMP_RATE * CMP_SLOW_S) * CMP_LOCK)
    try:
        url = f"http://127.0.0.1:{prov_port}"
        sec = f"{secrets.randbelow(2 ** 255) + 1:064x}"
        if prov_impl == "RS":
            cmd = [f"{RS}/xbt402-route-provider", "--port", str(prov_port), "--rpc-port", RPCPORT, "--cookie", COOKIE, "--secret", sec,
                   "--amsat", str(price), "--settle-multiple", str(settle), "--watch-secs", "1", "--ledger", os.path.join(d, "prov.jsonl")]
            if zc != "default":
                cmd += ["--zero-conf-max", zc]
            if is_high or is_exh:
                cmd += ["--settle-lock-multiple", str(floor_k)]
        else:
            cmd = [PY, os.path.join(HERE, "py_route_provider.py"), str(prov_port), sec, str(price), str(settle), zc, "1"]
        penv = {**os.environ, "XBT402_SETTLE_LOCK_MULTIPLE": str(floor_k)} if (is_high or is_exh) and prov_impl == "PY" else None
        if os.environ.get("LOAD_ROUTE_WAL") == "1":
            wal = os.path.join(d, "prov.route-wal")
            if prov_impl == "RS":
                cmd += ["--route-wal", wal]
            else:
                penv = {**(penv or os.environ), "XBT402_ROUTE_WAL": wal}
        proc, ready = start(cmd, f"on {prov_port} ready", **({"env": penv} if penv else {}))
        procs.append(proc)
        assert ready and wait_http(url + "/x402/supported"), f"provider {url} did not come up"
        key = os.path.join(d, "hub.key")
        with open(key, "w") as f:
            f.write(f"{secrets.randbelow(2 ** 255) + 1:064x}")
        os.chmod(key, 0o600)
        hub_dir = os.path.join(d, "hub")
        conf = {"node": {"rpcport": int(RPCPORT), "cookie": COOKIE, "wallet": "w"}, "network": NET, "port": hub_port,
                "datadir": hub_dir, "pay_to_key_file": key, "connect": [url], "watch_interval": watch_s,
                "hub": {"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500,
                        "delta": 144, "reveal_timeout": 2.0, "ch2_capacity": 100000, "ch2_expiry_blocks": 1100,
                        "close_margin": 144, "policy": {"min_expiry_blocks": 1008, "max_expiry_blocks": 8640}}}
        if is_high:                       # room for the whole run on one ch2 line (a rollover adds no coins)
            conf["hub"].update(ch2_capacity=1_000_000, settle_lock_multiple=floor_k)
        if is_cmp:                        # cmp's hub (tests/routing_e2e.py HUB_CONFIG)
            conf["hub"].update(ch2_capacity=1_000_000, max_lock_sat=50_000)
        if is_exh:                        # a line of 40 locks, and room for the live and the next ch2, no more
            conf["hub"].update(ch2_capacity=EXH_CAP, settle_lock_multiple=floor_k, liquidity_cap_sat=2 * EXH_CAP,
                               refill_ahead_locks=0 if kind == "exhaust-before" else EXH_AHEAD)
        cpath = os.path.join(d, "hub.json")
        with open(cpath, "w") as f:
            json.dump(conf, f)
        hub_cmd = [f"{RS}/xbt402-hub", "--config", cpath] if hub_impl == "RS" else [PY, "-m", "xbt402.hub", "--config", cpath]
        proc, _ = start(hub_cmd, f"on 127.0.0.1:{hub_port} ", 90, cwd=B1)    # after its ch2 funding: the hub listens
        procs.append(proc)
        if is_cmp:
            miner = Miner(CMP_SLOW_S) if kind.startswith("cmp-slow") else Miner(MINE_EVERY_S, mempool=True)
        else:
            miner = Miner()
        hub_url = f"http://127.0.0.1:{hub_port}"
        end, r = time.time() + 90, None
        while time.time() < end:
            r = routing(hub_url)
            if r and r.get("providers"):
                break
            time.sleep(0.3)
        check("hub-funded ch2 open to the provider", r and r.get("providers"), str(r and r.get("providers")))
        ch2_path = os.path.join(hub_dir, "ch2.json")
        progress = os.path.join(d, "progress.json")
        out_path = os.path.join(d, "client.json")
        with open(out_path, "w") as out:
            client = subprocess.Popen(SOAK + [f"{RS}/xbt402-rollover-load", "--hub", hub_url, "--shard", url + "/v1/chunk", "--rpc-port", RPCPORT,
                                              "--cookie", COOKIE, "--seconds", str(seconds), "--rate", str(rate), "--progress", progress]
                                      + (["--capacity", "1000000"] if is_cmp else [])
                                      + (["--capacity", str(int(seconds * rate * EXH_LOCK * 1.5) + 100_000)] if is_exh else []),
                                      stdout=out, stderr=LOG)
        t_start[0] = time.time()
        seen, zc_seen, stuck, reorg = set(), {}, None, None
        max_unconf = {}                   # child chan -> (highest signed seen while unconfirmed, its cap)
        live = {}                         # chan -> [first, last] time it was the origin's ch2 in the book
        overlap, max_next, max_committed = set(), 0, 0   # AGP-057: next ch2s seen beside an open live one
        while client.poll() is None:
            b = book(ch2_path)
            nexts = ((b or {}).get("next_chans") or {})
            max_next = max(max_next, len(nexts))
            if b:
                held = [r for r in list((b.get("chans") or {}).values()) + list(nexts.values()) if r.get("state") in LIVE]
                held += [r for r in b.get("archived", []) if r.get("retired") and r.get("state") in LIVE]
                max_committed = max(max_committed, sum(int(r["params"]["capacity"]) for r in held))
            for o, nx in nexts.items():
                if ((b.get("chans") or {}).get(o) or {}).get("state") == "open" and nx.get("state") in LIVE:
                    overlap.add(f"{nx['params'].get('funding_txid')}:{nx['params'].get('funding_vout')}")
            for rec in ((b or {}).get("chans") or {}).values():
                now = time.time()
                live.setdefault(f"{rec['params'].get('funding_txid')}:{rec['params'].get('funding_vout')}", [now, now])[1] = now
            for rec in records(b):
                chan = f"{rec['params'].get('funding_txid')}:{rec['params'].get('funding_vout')}"
                if rec.get("state") == "rolled" and chan not in seen:
                    seen.add(chan)
                    mark("rollover", parent=chan, txid=rec.get("close_txid"), signed=rec.get("signed"))
                z = rec.get("zero_conf") or {}
                if z:
                    conf_now = bool(z.get("confirmed"))
                    if zc_seen.get(chan) != conf_now:
                        zc_seen[chan] = conf_now
                        mark("zero_conf_confirmed" if conf_now else "zero_conf_unconfirmed", chan=chan)
                    if not conf_now:
                        hi = max(max_unconf.get(chan, (0, 0))[0], int(rec.get("signed", 0)))
                        max_unconf[chan] = (hi, int(z.get("maxCum", 0)))
                if kind == "stuck" and stuck is None and rec.get("rolled_from") and rec.get("state") == "open" and z and not z.get("confirmed"):
                    txid = rec["params"]["funding_txid"]
                    miner.empty.set()
                    stuck = {"txid": txid, "chan": chan, "at": time.time()}
                    mark("stuck", txid=txid)
                if is_reorg and reorg is None and rec.get("rolled_from") and z.get("confirmed") and rec.get("state") == "open":
                    txid = rec["params"]["funding_txid"]
                    miner.hold.set()
                    blk = node.getrawtransaction(txid, True).get("blockhash")
                    node.invalidateblock(blk)
                    reorg = {"txid": txid, "chan": chan, "block": blk, "at": time.time(),
                             "signed": int(rec.get("signed", 0)), "maxCum": int(z.get("maxCum", 0))}
                    mark("invalidateblock", txid=txid, block=blk, inMempool=txid in node.getrawmempool(),
                         signed=reorg["signed"], maxCum=reorg["maxCum"])
                    if kind == "reorg-zero":
                        mine_one()
                        miner.hold.clear()
                        reorg["resumed"] = time.time()
                        mark("miner_resumed", why="reorg-zero immediate remine")
                if kind == "reorg-cap" and reorg and not reorg.get("resumed") and rec.get("rolled_from"):
                    rec_chan = f"{rec['params'].get('funding_txid')}:{rec['params'].get('funding_vout')}"
                    if rec_chan == reorg["chan"] and int(rec.get("signed", 0)) >= int((rec.get("zero_conf") or {}).get("maxCum") or reorg["maxCum"] or 0):
                        reorg["capHit"] = int(rec.get("signed", 0))
            if stuck and not stuck.get("released") and time.time() - stuck["at"] >= STUCK_S:
                miner.empty.clear()
                stuck["released"] = time.time()
                mark("released", txid=stuck["txid"])
            if reorg and not reorg.get("resumed"):
                hold_s = 20.0 if kind == "reorg-cap" else (0.0 if kind == "reorg-zero" else REORG_S)
                cap_done = kind == "reorg-cap" and reorg.get("capHit") and time.time() - reorg["at"] >= 1.0
                if kind != "reorg-zero" and (time.time() - reorg["at"] >= hold_s or cap_done):
                    miner.hold.clear()
                    reorg["resumed"] = time.time()
                    mark("miner_resumed", capHit=reorg.get("capHit"))
            time.sleep(0.2)
        res = json.load(open(out_path))
        miner.stop.set()
        mine_one()                        # the last rollover confirms; the watcher folds the last pass
        time.sleep(2.0)
        b = book(ch2_path)
        recs = records(b)
        for _ in range(4):
            # that block can make a ch2 due again (a child that filled while unconfirmed, AGP-056): the
            # rollover it triggers needs its own block before the money checks read it; so does the close
            # of a ch2 its next one replaced (AGP-057)
            pend = [r["close_txid"] for r in recs if r.get("state") == "rolled" and r.get("close_txid")
                    and not node.getrawtransaction(r["close_txid"], True).get("confirmations")]
            pend += [r for r in recs if r.get("state") == "closing" or (r.get("retired") and r.get("state") == "open" and r.get("signed"))]
            if not pend:
                break
            mine_one()
            time.sleep(2.0)
            recs = records(book(ch2_path))
        miner.stop.set()
        # --- checks ---------------------------------------------------------------------------------
        rolled = [r for r in recs if r.get("state") == "rolled"]
        refused, bad = res.get("refused", {}), res.get("badCalls", {})
        if kind not in ("stuck", "before") and not is_high and not is_cmp and not is_exh:  # before/stuck pause routing (block-interval gaps / the cap), so paid rate drops
            check(f"lock rate >= 10/s ({res.get('lockRate')})", res.get("lockRate", 0) >= 10, "")
        if kind == "after":
            check(f"rollovers under load ({len(rolled)})", len(rolled) >= 3, "")
            check("zero refused locks (no route_blocked, nothing to fail over on)", not refused, json.dumps(refused))
            check("every call 200 (no session stalled)", not bad, json.dumps(bad))
            zcs = [bool(r.get("zero_conf")) for r in recs if r.get("rolled_from")]
            check(f"next ch2s taken unconfirmed ({sum(zcs)} of {len(zcs)}; the rest confirmed before the open)", any(zcs), json.dumps(zcs))
        per_lock = round(len(rolled) / max(1, res.get("locksPaid", 0)), 3)
        if kind == "high":
            check(f"rollovers under load ({len(rolled)})", len(rolled) >= 2, "")
            check("zero refused locks at a high price", not refused, json.dumps(refused))
            check("every call 200 (no session stalled)", not bad, json.dumps(bad))
            check(f"settle floor: rollovers per paid lock <= 0.3 ({len(rolled)} / {res.get('locksPaid')} = {per_lock})",
                  res.get("locksPaid", 0) >= 8 and per_lock <= 0.3, "")
            zmax = [int((r.get("zero_conf") or {}).get("maxCum", 0)) for r in recs if r.get("zero_conf")]
            check(f"the provider's zero-conf cap follows the lock size (>= 2 x 4 x {HIGH_LOCK})",
                  bool(zmax) and all(z >= 8 * HIGH_LOCK for z in zmax), json.dumps(zmax))
        diag = None
        if is_cmp:
            diag = cap_diagnosis(client_refusals(res), recs, live, miner.blocks)
            check(f"rollovers under load ({len(rolled)})", len(rolled) >= 2, "")
            check(f"a rollover child's cum starts at 0: nothing of the parent is carried into the cap ({diag['childCumCarried']})",
                  diag["children"] > 0 and diag["childCumCarried"] == 0, "")
            zmax = [int((r.get("zero_conf") or {}).get("maxCum", 0)) for r in recs if r.get("zero_conf")]
            if kind != "cmp-slow-sized":      # above it after a refusal: the client's next lock pays what piled up
                check(f"the provider's zero-conf cap is 2 x 4 x the largest lock (>= {8 * CMP_LOCK})",
                      bool(zmax) and min(zmax) == 8 * CMP_LOCK, json.dumps(sorted(set(zmax))))
            if kind == "cmp-slow":
                check("slow blocks: only route_blocked refusals, calls stall (402) only past the cap",
                      set(refused) <= {"route_blocked"} and set(bad) <= {"402"}, json.dumps(refused) + json.dumps(bad))
                check(f"slow blocks: every refusal is the zero-conf cap of a child unconfirmed on chain then ({json.dumps({k: diag[k] for k in ('refusals', 'hubLag', 'unconfirmed', 'unattributed')})})",
                      diag["refusals"] == sum(refused.values()) and diag["hubLag"] == 0 and diag["unattributed"] == 0, "")
                check("slow blocks: no child's signed state above the provider's cap while unconfirmed",
                      all(hi <= cap for hi, cap in max_unconf.values()), json.dumps(list(max_unconf.values()))[:300])
            else:
                check(f"zero refused locks at cmp's prices ({json.dumps({k: diag[k] for k in ('refusals', 'hubLag', 'unconfirmed', 'unattributed')})})",
                      not refused, json.dumps(refused))
                check("every call 200 (no session stalled)", not bad, json.dumps(bad))
        if is_exh:
            took = [r for r in recs if not r.get("rolled_from") and (int(r.get("routed", 0)) > 0 or r.get("rolled_to"))]
            closes = [r for r in recs if r.get("state") in ("closing", "closed") and r.get("close_txid") and not r.get("rolled_to")]
            check(f"the ch2 line ran out under load: wallet-funded ch2s that took locks ({len(took)})", len(took) >= 3, "")
        if kind == "exhaust":
            check("zero refused locks through every exhaustion (make-before-break refill)", not refused, json.dumps(refused))
            check("every call 200 (no session stalled)", not bad, json.dumps(bad))
            check(f"two live ch2s per origin during the overlap: next ch2s seen beside the open live one ({len(overlap)})",
                  len(overlap) >= 2, "")
            check(f"never more than one next ch2 per origin ({max_next})", max_next == 1, "")
            check(f"the hub's coins never above liquidity_cap_sat ({max_committed} <= {2 * EXH_CAP})",
                  0 < max_committed <= 2 * EXH_CAP, "")
            bad_close = []
            for r in closes:
                tx = node.getrawtransaction(r["close_txid"], True)
                vals = [round(o["value"] * SAT) for o in tx["vout"]]
                if r["state"] != "closed" or not r.get("final") or not tx.get("confirmations") or vals[0] != r["signed"] - r["params"]["close_fee"]:
                    bad_close.append({"txid": r["close_txid"], "state": r["state"], "vals": vals, "signed": r["signed"]})
            check(f"every replaced ch2 closed on its signed state, the provider paid signed - closeFee, confirmed ({len(closes)})",
                  len(closes) >= 2 and not bad_close, json.dumps(bad_close)[:300])
        if kind == "exhaust-before":
            check("baseline: the refill follows the close and opens at minConf (route_blocked refusals)",
                  refused.get("route_blocked", 0) > 0, json.dumps(refused))
            check("baseline: no next ch2 was funded ahead", max_next == 0 and not overlap, f"{max_next} {len(overlap)}")
        if kind == "high-nofloor":
            check(f"baseline: a rollover per paid lock ({len(rolled)} / {res.get('locksPaid')} = {per_lock})",
                  len(rolled) >= 2 and per_lock >= 0.5, "")
            check("baseline: the next lock is refused until a block (route_blocked)", refused.get("route_blocked", 0) > 0,
                  json.dumps(refused))
        if kind == "before":
            check(f"rollovers under load ({len(rolled)})", len(rolled) >= 2, "")
            check("baseline: the gap is there (route_blocked refusals)", refused.get("route_blocked", 0) > 0, json.dumps(refused))
        refused_during_reorg = []
        if is_reorg:
            check(f"rollovers under load ({len(rolled)})", len(rolled) >= 1, "")
            check("every call 200 (no session stalled)", not bad, json.dumps(bad))
            zcs = [bool(r.get("zero_conf")) for r in recs if r.get("rolled_from")]
            check(f"next ch2s taken unconfirmed ({sum(zcs)} of {len(zcs)}; the rest confirmed before the open)", any(zcs), json.dumps(zcs))
            check("reorg: the hub saw the child unconfirmed again", reorg is not None and any(m["what"] == "zero_conf_unconfirmed" and m["chan"] == reorg["chan"]
                                                                                              and m["t"] >= reorg["at"] - t_start[0] for m in marks),
                  json.dumps(reorg))
            check("reorg: re-confirmed on the new chain", reorg is not None and zc_seen.get(reorg["chan"]) is True, "")
            start_ts = (reorg or {}).get("at")
            end_ts = None
            if reorg:
                for m in marks:
                    mts = m.get("ts")
                    if mts is None:
                        mts = (t_start[0] or 0) + m.get("t", 0)
                    if mts < start_ts:
                        continue
                    if m["what"] == "zero_conf_confirmed" and m.get("chan") == reorg["chan"]:
                        end_ts = mts
                        break
                    if m["what"] == "rollover" and m.get("parent") == reorg["chan"]:
                        end_ts = mts
                        break
            outside, bad_reason = [], []
            for rec in client_refusals(res):
                ts = rec.get("ts")
                if ts is None:
                    ts = (t_start[0] or 0) + float(rec.get("t") or 0)
                in_win = start_ts is not None and ts + 0.05 >= start_ts and (end_ts is None or ts <= end_ts + 0.5)
                if in_win:
                    refused_during_reorg.append(rec)
                    if not reorg_allowed_refusal(rec.get("code"), rec.get("detail")):
                        bad_reason.append(rec)
                else:
                    outside.append(rec)
            check("reorg: no refusals outside the reorg window (reorg mark → re-confirm or next rollover)",
                  not outside, json.dumps(outside)[:500])
            check("reorg: every refusal in the window is zero-conf cap or close-margin for the reorged ch2",
                  not bad_reason, json.dumps(bad_reason)[:500])
            if kind == "reorg-cap":
                check("reorg-cap: the pause exceeded headroom (cap refusals happened)", len(refused_during_reorg) > 0,
                      json.dumps(refused_during_reorg[:5])[:400])
            if kind == "reorg-zero":
                check("reorg-zero: the pause stayed under headroom (zero refusals)", not refused_during_reorg,
                      json.dumps(refused_during_reorg)[:400])

        if kind == "stuck":
            capped = [c for c, (hi, cap) in max_unconf.items() if stuck and c == stuck["chan"]]
            hi, cap = max_unconf.get(stuck["chan"], (0, 0)) if stuck else (0, 0)
            check("stuck: the child was used unconfirmed, never above the provider's cap", stuck is not None and 0 < hi <= cap,
                  f"signed {hi} cap {cap} {capped}")
            check("stuck: only route_blocked (the hub's own cap check), no provider refusal; calls stall (402) only past the cap",
                  set(refused) <= {"route_blocked"} and set(bad) <= {"402"}, json.dumps(refused) + json.dumps(bad))
            bad_t = [x[0] for x in res.get("timeline", []) if x[1] == "call"]
            check("stuck: stalled calls only while the rollover was held out of blocks",
                  stuck is not None and all(stuck["at"] - t_start[0] <= t <= stuck.get("released", time.time()) - t_start[0] + BLOCK_S + 3
                                            for t in bad_t), f"{bad_t[:3]}..{bad_t[-3:]}")
            first_ref = [x[0] for x in res.get("timeline", []) if x[1] == "refused"]
            check("stuck: refusals only while the rollover was held out of blocks",
                  stuck is not None and all(stuck["at"] - t_start[0] <= t <= stuck.get("released", time.time()) - t_start[0] + BLOCK_S + 3
                                            for t in first_ref), f"{first_ref[:3]}..{first_ref[-3:]}")
            check("stuck: routing resumed once it confirmed", stuck is not None and zc_seen.get(stuck["chan"]) is True
                  and any(m["what"] == "rollover" and m["t"] > stuck.get("released", 1e18) - t_start[0] for m in marks), "")
        # money: every rollover tx on chain, routed == paid, nothing pending or written off
        bad_roll = []
        by_txid = {r["params"]["funding_txid"]: r for r in recs}
        for r in rolled:
            p = r["params"]
            tx = node.getrawtransaction(r["close_txid"], True)
            vals = [round(o["value"] * SAT) for o in tx["vout"]]
            want = [r["signed"] - p["close_fee"], p["capacity"] - r["signed"]]
            nxt = by_txid.get(r["close_txid"])
            if vals != want or nxt is None or nxt["params"]["capacity"] != want[1] or not tx.get("confirmations"):
                bad_roll.append({"txid": r["close_txid"], "vals": vals, "want": want, "conf": tx.get("confirmations")})
        check("each rollover tx pays signed - closeFee to the provider and capacity - signed to the next ch2, confirmed",
              rolled and not bad_roll, json.dumps(bad_roll)[:300])
        routed = sum(int(r.get("routed", 0)) for r in recs)
        shards = res["summary"]["shards"]
        paid = sum(int(s["locked_sat"]) for s in shards.values())
        check(f"routed over all ch2s == what the client's locks paid ({routed} == {paid})", routed == paid and paid > 0, "")
        check("no ch2 lock pending or written off", all(not r.get("pending") and not r.get("stale") for r in recs), "")
        return {"run": name, "ok": all(c["ok"] for c in checks), "checks": checks, "rollovers": len(rolled), "rolloversPerLock": per_lock,
                "client": {k: res.get(k) for k in ("seconds", "calls", "locksPaid", "lockRate", "refused", "refusals", "badCalls",
                                                  "lockOther", "maxGapMs", "gapsOver1s", "gapP50Ms", "lockMs")},
                "refusedDuringReorg": refused_during_reorg, "refusedDuringReorgN": len(refused_during_reorg),
                **({"capDiagnosis": diag} if diag is not None else {}),
                **({"refill": {"aheadSeen": len(overlap), "maxNext": max_next, "maxCommitted": max_committed, "liquidityCap": 2 * EXH_CAP,
                               "walletFundedCh2s": len(took), "closes": len(closes)}} if is_exh else {}),
                "refusedPerRollover": round(sum(refused.values()) / max(1, len(rolled)), 2),
                "timeline": res.get("timeline", [])[:200], "marks": marks,
                "book": [{k: r.get(k) for k in ("state", "rolled_from", "zero_conf", "signed", "routed", "opened_at", "blocked", "close_txid", "retired")}
                         | {"chan": f"{r['params'].get('funding_txid')}:{r['params'].get('funding_vout')}"} for r in recs]}
    except Exception as e:  # noqa: BLE001
        check("scenario ran", False, f"{type(e).__name__}: {e}")
        return {"run": name, "ok": False, "checks": checks, "marks": marks}
    finally:
        if client is not None and client.poll() is None:
            client.kill()
        if miner:
            miner.stop.set()
        for p in reversed(procs):
            stop(p)


def main():
    runs = ["RS-RS", "PY-PY", "RS-PY", "PY-RS", "RS-RS-before", "PY-PY-before", "RS-RS-stuck", "PY-PY-stuck", "RS-RS-reorg", "PY-PY-reorg",
            "RS-RS-high", "PY-PY-high", "RS-RS-high-nofloor", "PY-PY-high-nofloor"]
    only = [x for x in os.environ.get("LOAD_ONLY", "").split(",") if x]
    for name in only:
        if name not in runs:
            runs.append(name)
    results = []
    for i, name in enumerate(runs):
        if only and name not in only:
            continue
        r = scenario(i, name, len(results))
        results.append(r)
        c = r.get("client") or {}
        print(f"  {name:16s} {'PASS' if r['ok'] else 'FAIL'}  rollovers {r.get('rollovers')}  locks/s {c.get('lockRate')}  "
              f"refused {c.get('refused')}  refusedDuringReorg {r.get('refusedDuringReorgN')}  "
              f"badCalls {c.get('badCalls')}  maxGapMs {c.get('maxGapMs')}  "
              f"refused/rollover {r.get('refusedPerRollover')}  rollovers/lock {r.get('rolloversPerLock')}", flush=True)
        if r.get("refill"):
            print(f"      refill {json.dumps(r['refill'])}", flush=True)
        if r.get("capDiagnosis"):
            print(f"      capDiagnosis {json.dumps({k: v for k, v in r['capDiagnosis'].items() if k != 'rows'})}", flush=True)
        for ch in r["checks"]:
            if not ch["ok"]:
                print(f"      FAIL {ch['check']}: {ch['detail']}", flush=True)
    rep = os.environ.get("LOAD_REPORT", os.path.join(RUN, "rollover_load.json"))
    with open(rep, "w") as f:
        json.dump({"seconds": SECONDS, "rate": RATE, "blockS": BLOCK_S, "stuckS": STUCK_S, "reorgS": REORG_S, "results": results}, f, indent=1)
    sys.exit(0 if results and all(r["ok"] for r in results) else 1)


if __name__ == "__main__":
    main()
