#!/usr/bin/env python3
"""AGP-040: the Umbrel apps on regtest, installed the way umbrelOS installs them (run by test-umbrel-apps.sh).

umbrelOS, simulated on plain Docker (no Umbrel dev environment runs rootless here):
  * each app's data dir is a copy of its folder (umbrelOS copies the app into app-data/<app-id>), owned by the
    box user (here mike, uid 1000: the bind-mount case CONTAINER.md leaves to packaging);
  * compose runs with --compatibility and the project name = the app id, so containers are <app-id>_<service>_1;
  * every app is on one shared network (umbrel_main_network), the environment has ${APP_DATA_DIR},
    ${APP_SEED}, ${APP_PASSWORD} and ${DEVICE_DOMAIN_NAME}, and each installed app's exports.sh is sourced
    with a derive_entropy() like umbrelOS's;
  * app_proxy is this driver's reverse proxy on 127.0.0.1:34080 (X-Forwarded-*), not a container;
  * a test overlay (regtest/*.yml) puts the node on the AGP-017 regtest chain (and its exported chain is
    "regtest"), and publishes the test ports on loopback (34000-34099). Nothing else in the apps changes.

Checks (results.json): I install and layout, S hardening, U the UI (no terminal: password, key, policy, token),
P an agent's xbt402 payment, R restart persistence, H the hub app, G /readyz gating, X uninstall.
    umbrel_regtest.py OUT RUN_INDEX
"""
import hashlib
import hmac
import json
import os
import re
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from regtest_lib import (agent_rotation_attempts, leaks, POLICY_BASE, Chain, Mcp, Miner, Ui, check, docker, ensure_provider_image, field, http, log, open_log,  # noqa: E402
                         owner_setup, root_helper, sh, start_proxy, status, wait_until, write_results)

OUT, RUN = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "1"
HERE = os.path.dirname(os.path.abspath(__file__))
STORE = os.path.dirname(HERE)
ROOT = os.path.dirname(os.path.dirname(STORE))
PID = os.getpid()
NET = f"agp040-umbrel-{PID}"
APPS_DIR = os.path.join(OUT, "app-data")
SEED = os.urandom(32).hex()
P_MCP = int(os.environ.get("UMBREL_TEST_MCP_PORT", "34010"))
P_HUB = int(os.environ.get("UMBREL_TEST_HUB_PORT", "34020"))
P_UI = int(os.environ.get("UMBREL_TEST_UI_PORT", "34030"))
P_PROXY = int(os.environ.get("UMBREL_TEST_PROXY_PORT", "34080"))
P_PROV = int(os.environ.get("UMBREL_TEST_PROV_PORT", "34040"))
HUB_ONION = os.environ.get("UMBREL_TEST_HUB_ONION", "http://agp042-hub.onion")
SIGN_BIN = os.path.join(ROOT, "dist/oci/ctx/bin/amd64/xbt-wallet-ui")
KNOTS, WALLET, HUB = "lazarus-xbt-knots", "lazarus-xbt-agent-wallet", "lazarus-xbt402-hub"
PROVIDER = "http://agp040-provider-%d:9500" % PID
open_log(os.path.join(OUT, "umbrel_regtest.log"))


def derive(label):
    """umbrelOS's derive_entropy: a per-box secret from the box seed and a label."""
    return hmac.new(SEED.encode(), label.encode(), hashlib.sha256).hexdigest()


def app_password(app_id):
    return derive(f"app-{app_id}-password")


def exports_env(installed):
    """Source every installed app's exports.sh with derive_entropy defined, as umbrelOS does."""
    script = "set -a\nderive_entropy() { printf '%s' \"$1\" | openssl dgst -sha256 -hmac \"$UMBREL_SEED_HEX\" -r | cut -d' ' -f1; }\n"
    for a in installed:
        script += f". '{os.path.join(STORE, a, 'exports.sh')}'\n"
    script += "env -0\n"
    r = sh("bash", "-c", script, env={"PATH": os.environ["PATH"], "UMBREL_SEED_HEX": SEED})
    return dict(kv.split("=", 1) for kv in r.stdout.split("\0") if "=" in kv and kv.split("=", 1)[0].startswith("APP_"))


INSTALLED = []


def compose(app, *args, check_rc=True):
    data = os.path.join(APPS_DIR, app)
    # the node app's regtest profile: its exports say the chain is regtest (the only exported value the test changes)
    env = {**os.environ, **exports_env(INSTALLED), "APP_XBT_KNOTS_CHAIN": "regtest", "APP_DATA_DIR": data, "APP_SEED": derive(f"app-{app}-seed"),
           "APP_PASSWORD": app_password(app), "DEVICE_DOMAIN_NAME": "127.0.0.1", "DEVICE_HOSTNAME": "umbrel",
           "APP_HIDDEN_SERVICE": HUB_ONION if app == HUB else "",
           "UMBREL_TEST_NET": NET, "UMBREL_TEST_CONF": HERE, "UMBREL_TEST_MCP_PORT": str(P_MCP), "UMBREL_TEST_UI_PORT": str(P_UI),
           "UMBREL_TEST_HUB_PORT": str(P_HUB)}
    return sh("docker", "compose", "--compatibility", "-p", app, "--project-directory", data,
              "-f", os.path.join(data, "docker-compose.yml"), "-f", os.path.join(HERE, "common.yml"), "-f", os.path.join(HERE, f"{app}.yml"),
              *args, env=env, check_rc=check_rc, timeout=900)


def install(app):
    """umbrelOS: copy the app into app-data/<id> (owned by the box user), source exports, compose up."""
    if app not in INSTALLED:
        INSTALLED.append(app)
    dst = os.path.join(APPS_DIR, app)
    if not os.path.exists(dst):
        shutil.copytree(os.path.join(STORE, app), dst)
    compose(app, "up", "-d")


def cname(app, svc):
    return f"{app}_{svc}_1"


def inspect(*names):
    return json.loads(docker("inspect", *names).stdout)


def mcp_token_from_ui(ui):
    page = ui.get("/agents")
    m = re.search(r'<code id="mcp-token">([0-9a-f]{64})</code>', page)
    return (m.group(1) if m else None), page


def main():
    t_install = time.time()
    os.makedirs(APPS_DIR, exist_ok=True)
    docker("network", "create", NET)
    ensure_provider_image()

    # --- the node app (the dependency) ---------------------------------------------------------------------
    log("== install lazarus-xbt-knots (the node dependency), regtest")
    install(KNOTS)
    ex = exports_env([KNOTS])
    chain = Chain(cname(KNOTS, "node"), ex["APP_XBT_KNOTS_RPC_USER"], ex["APP_XBT_KNOTS_RPC_PASS"])
    wait_until(lambda: chain.cli("getblockcount") == 0 or chain.cli("getblockcount") is not None, 90, "node RPC")
    check("I", "node app: RPC answers with the exported credentials (derive_entropy), container named <app-id>_node_1",
          ex["APP_XBT_KNOTS_NODE_HOST"] == cname(KNOTS, "node") and len(ex["APP_XBT_KNOTS_RPC_PASS"]) == 64, ex.get("APP_XBT_KNOTS_NODE_HOST"))
    chain.bootstrap()
    chain.cli("-named", "createwallet", "wallet_name=agent", "disable_private_keys=true", "blank=true", "descriptors=true")
    rest = docker("exec", cname(KNOTS, "node"), "bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8332; printf 'GET /rest/chaininfo.json HTTP/1.0\\r\\n\\r\\n' >&3; cat <&3",
                  check_rc=False).stdout
    check("I", "node app: the app_proxy page (/rest/chaininfo.json) is the chain status, no credentials needed",
          '"chain":"regtest"' in rest.replace(" ", "") and '"pruned":true' in rest.replace(" ", ""), rest[-300:])

    log("== provider (test fixture, 150 sat per call)")
    pv = os.path.join(OUT, "provider")
    os.makedirs(pv, exist_ok=True)
    root_helper(pv, f"printf '{chain.u}:{chain.p}' > /d/rpc-auth && chown -R 10009:10009 /d && chmod 600 /d/rpc-auth", ro=False)
    docker("run", "-d", "--name", f"agp040-provider-{PID}", "--network", NET, "--read-only", "-p", f"127.0.0.1:{P_PROV}:9500", "-v", f"{pv}:/p",
           "agp038-test-provider:1", "--port", "9500", "--bind", "0.0.0.0", "--rpc-host", cname(KNOTS, "node"), "--rpc-port", "8332",
           "--cookie", "/p/rpc-auth", "--ledger", "/p/ledger.jsonl")
    wait_until(lambda: status(f"http://127.0.0.1:{P_PROV}/x402/supported") == 200, 60, "the provider")

    # --- the wallet app ---------------------------------------------------------------------------------------
    log("== install lazarus-xbt-agent-wallet")
    t_wallet = time.time()
    install(WALLET)
    wdata = os.path.join(APPS_DIR, WALLET, "data")
    init_c = inspect(cname(WALLET, "init"))[0]
    rep = json.loads(docker("logs", cname(WALLET, "init")).stdout.strip().splitlines()[-1])
    check("I", "init (xbt-init) ran first and exited 0: the layout check passed, secrets provisioned (names only in its report)",
          init_c["State"]["ExitCode"] == 0 and rep["ok"] and {(s["component"], s["name"]) for s in rep["secrets"]} >= {
              ("signer", "node-rpc-auth"), ("ui", "xbt-ui-password"), ("ui", "run/ui/mcp-http-token")}
          and app_password(WALLET) not in json.dumps(rep) and chain.p not in json.dumps(rep), {"exit": init_c["State"]["ExitCode"], "report": rep})
    ls = root_helper(wdata, "stat -c '%u:%g %a %n' /d/signer /d/witness /d/mcp /d/ui /d/run/signer /d/run/anchor /d/signer/secrets/node-rpc-auth "
                            "/d/ui/secrets/xbt-ui-password /d/run/ui /d/run/ui/mcp-http-token").stdout.split("\n")
    want = ["10001:10001 700 /d/signer", "10002:10002 700 /d/witness", "10003:10003 700 /d/mcp", "10005:10005 700 /d/ui",
            "10001:10001 750 /d/run/signer", "10002:10002 750 /d/run/anchor", "10001:10001 600 /d/signer/secrets/node-rpc-auth",
            "10005:10005 600 /d/ui/secrets/xbt-ui-password", "10005:10005 750 /d/run/ui", "10005:10005 640 /d/run/ui/mcp-http-token"]
    check("I", "the bind mount (app-data copied as the box user, uid 1000) now has CONTAINER.md's owners: one uid per component",
          [x for x in ls if x] == want, ls)
    try:
        os.listdir(os.path.join(wdata, "signer"))
        box_user_reads = True
    except PermissionError:
        box_user_reads = False
    check("I", "the box user (uid 1000) can no longer read the signer's directory", not box_user_reads)

    wait_until(lambda: status(f"http://127.0.0.1:{P_MCP}/readyz") == 200 and status(f"http://127.0.0.1:{P_UI}/readyz") == 200, 180,
               "MCP and UI /readyz 200")
    t_ready = time.time() - t_wallet
    check("I", f"wallet ready (MCP and UI /readyz 200) {t_ready:.1f} s after install", True, t_ready)
    for s in ("witness", "signer", "mcp", "ui"):
        wait_until(lambda: inspect(cname(WALLET, s))[0]["State"].get("Health", {}).get("Status") == "healthy", 120, f"{s} healthy", every=2)
    ins = inspect(*[cname(WALLET, s) for s in ("witness", "signer", "mcp", "ui")])
    rows = [(i["Name"], i["Config"]["User"], i["HostConfig"]["ReadonlyRootfs"], i["HostConfig"]["CapDrop"], i["HostConfig"]["SecurityOpt"],
             i["HostConfig"]["NetworkMode"], i["State"]["Health"]["Status"]) for i in ins]
    check("S", "witness, signer, MCP, UI: each its own non-root user, read-only, cap_drop ALL, no-new-privileges, HEALTHCHECK healthy",
          all(r[1] not in ("", "0", "root") and r[2] and r[3] == ["ALL"] and any("no-new-privileges" in x for x in r[4] or []) and r[6] == "healthy"
              for r in rows) and len({r[1] for r in rows}) == 4, rows)
    caps = sorted(c.removeprefix("CAP_") for c in init_c["HostConfig"]["CapAdd"] or [])
    check("S", "the witness has no network; init had none and only CHOWN, FOWNER, DAC_OVERRIDE, as root",
          ins[0]["HostConfig"]["NetworkMode"] == "none" and init_c["HostConfig"]["NetworkMode"] == "none"
          and caps == ["CHOWN", "DAC_OVERRIDE", "FOWNER"] and init_c["HostConfig"]["CapDrop"] == ["ALL"] and init_c["Config"]["User"] in ("0:0", "0"),
          {"witness": ins[0]["HostConfig"]["NetworkMode"], "init": [init_c["HostConfig"]["NetworkMode"], init_c["HostConfig"]["CapAdd"]]})
    code, _, _ = http("POST", f"http://127.0.0.1:{P_MCP}/mcp", b"{}", {"Content-Type": "application/json"})
    check("S", "the MCP refuses a request without the bearer token (401)", code == 401, code)

    # --- U: the owner, in the UI, through the app_proxy stand-in ----------------------------------------------
    log("== U: the owner's first run in the UI (no terminal)")
    proxy = start_proxy(P_PROXY, P_UI, {"X-Forwarded-Proto": "http", "X-Forwarded-Host": "umbrel.local"})
    base = f"http://127.0.0.1:{P_PROXY}"
    check("U", "through the proxy: UI /healthz 200 and /readyz 200 (the signer answers)",
          status(base + "/healthz") == 200 and status(base + "/readyz") == 200)
    ui = Ui(base)
    st, loc = ui.login("not the password")
    st_ok, loc_ok = ui.login(app_password(WALLET))
    check("U", "login: a wrong password is refused, ${APP_PASSWORD} (the dashboard's password) is accepted",
          st == 401 and st_ok == 303 and ui.cookie.startswith("xbtui="), [st, st_ok, loc_ok])
    sec = Ui(f"http://127.0.0.1:{P_UI}", headers={"X-Forwarded-Proto": "https"})
    sec.login(app_password(WALLET))
    check("U", "behind an https proxy (Umbrel over Tor/https) the session cookie is Secure; HttpOnly and SameSite=Strict always",
          "Secure" in sec.last_set_cookie and "HttpOnly" in sec.last_set_cookie and "SameSite=Strict" in sec.last_set_cookie
          and "Secure" not in ui.last_set_cookie, [sec.last_set_cookie, ui.last_set_cookie])
    key = os.path.join(OUT, "device-human.key")
    with open(key, "w") as f:
        f.write(os.urandom(32).hex())
    os.chmod(key, 0o600)
    policy = dict(POLICY_BASE, allowlist=[PROVIDER])
    pub, f_enrol, f_apply = owner_setup(ui, SIGN_BIN, key, policy)
    check("U", "the owner enrols an approval key and signs a policy in the UI (allowlist: the provider)",
          "enrolled" in f_enrol.lower() and "applied" in f_apply.lower(), [f_enrol, f_apply])
    if "restarts" in f_apply:
        log("   the policy asks for a signer restart: restart the app's signer (Umbrel: restart the app)")
        compose(WALLET, "restart", "signer")
        wait_until(lambda: status(f"http://127.0.0.1:{P_MCP}/readyz") == 200, 120, "MCP ready after the signer restart")
    token, agents = mcp_token_from_ui(ui)
    disk_token = root_helper(wdata, "cat /d/run/ui/mcp-http-token").stdout.strip()
    check("U", "the Agents page gives the owner the MCP endpoint and the token the MCP server uses",
          token == disk_token and "http://127.0.0.1:33510/mcp" in agents, {"page_has_token": bool(token)})

    # --- P: an agent pays ----------------------------------------------------------------------------------
    log("== P: an agent pays one xbt402 call with the token from the Agents page")
    sc = lambda m, p=None: json.loads(docker("exec", cname(WALLET, "signer"), "/usr/bin/xbt-signer", "call", m, json.dumps(p or {})).stdout)  # noqa: E731
    ha = sc("hot_address")
    txid = chain.cli("sendtoaddress", ha["hot_address"], "0.0005", wallet="faucet")
    chain.mine(1)
    sc("notice_hot_txid", {"txid": txid})
    agent = Mcp(f"http://127.0.0.1:{P_MCP}", token)
    code, init = agent.start()
    check("P", "MCP initialize over HTTP with the token", code == 200 and isinstance(init, dict) and init.get("result", {}).get("serverInfo"), init)
    with Miner(chain, 2.0):
        r1 = agent.tool("xbt402_pay", url=f"{PROVIDER}/v1/agp040", max_sats=1000)
    check("P", "xbt402_pay: HTTP 200 from the provider, 150 sat charged, over a new channel",
          r1.get("status") == 200 and r1.get("charged_sats") == 150 and r1.get("chan"), r1)
    chans1 = agent.tool("channels")
    page = ui.get("/channels")
    check("P", "the UI's Channels page shows the agent's channel", str(r1.get("chan", "?"))[:16] in page or PROVIDER in page, page[-400:])

    # --- R: restart the app (umbrelOS: stop + start, or a reboot) -----------------------------------------------
    log("== R: restart the app")
    time.sleep(6)  # one anchor interval
    compose(WALLET, "stop")
    compose(WALLET, "up", "-d")
    wait_until(lambda: status(f"http://127.0.0.1:{P_MCP}/readyz") == 200, 180, "MCP /readyz after the restart")
    rep2 = json.loads(docker("logs", cname(WALLET, "init")).stdout.strip().splitlines()[-1])
    check("R", "init ran again: nothing to fix, every secret unchanged (the MCP token and the generated keys are never rewritten)",
          rep2["ok"] and all(s["result"] == "unchanged" for s in rep2["secrets"]) and all(d["chowned"] == 0 for d in rep2["dirs"]), rep2)
    ui2 = Ui(base)
    ui2.login(app_password(WALLET))
    token2, _ = mcp_token_from_ui(ui2)
    agent = Mcp(f"http://127.0.0.1:{P_MCP}", token2)
    agent.start()
    chans2 = agent.tool("channels")
    ha2 = sc("hot_address")
    check("R", "after the restart: the same token, hot address and channels (id, cum)",
          token2 == token and ha2["hot_address"] == ha["hot_address"] and chans2.get("channels") == chans1.get("channels"),
          {"token": token2 == token, "hot": [ha["hot_address"], ha2["hot_address"]], "before": chans1, "after": chans2})
    r2 = agent.tool("xbt402_pay", url=f"{PROVIDER}/v1/agp040", max_sats=1000)
    check("R", "a second paid call reuses the channel (no new open), 150 sat",
          r2.get("status") == 200 and r2.get("chan") == r1.get("chan") and not r2.get("opened") and r2.get("charged_sats") == 150, r2)
    log("== W: rotate the agent token in the UI (no restart); an agent cannot rotate it")
    mcp_base = f"http://127.0.0.1:{P_MCP}"
    tries = agent_rotation_attempts(mcp_base, [token])
    unchanged = root_helper(wdata, "cat /d/run/ui/mcp-http-token").stdout.strip() == token
    check("W", "an agent holding the token (and the old owner header) cannot rotate it: the MCP has no rotation endpoint",
          all(st in (401, 404, 405) for _, st, _, _ in tries) and unchanged, [(w, st) for w, st, _, _ in tries])
    agent_old = Mcp(mcp_base, token)
    agent_old.start()
    ui2.post("/agents", "/rotate-token", {"confirm": "1"})
    flash_rot = ui2.flash("/agents")
    new_token, _ = mcp_token_from_ui(ui2)
    st_old = Mcp(mcp_base, token).start()[0]
    st_old_session = agent_old.post({"jsonrpc": "2.0", "id": 99, "method": "tools/list"})[0]
    disk = root_helper(wdata, "stat -c '%u:%g %a' /d/run/ui/mcp-http-token; cat /d/run/ui/mcp-http-token; "
                              "ls -A /d/run/ui; ls /d/mcp/secrets /d/ui/secrets").stdout.split("\n")
    agent_new = Mcp(mcp_base, new_token or "")
    st_new = agent_new.start()[0]
    check("W", "Agents page rotate: the old token gets 401 at once (its open session too), the new one works, no restart; "
               "the UI's file is replaced atomically, 10005:10005 0640, no temp file, no stale copies",
          "rotated" in flash_rot.lower() and new_token and new_token != token and st_old == 401 and st_old_session == 401 and st_new == 200
          and disk[:3] == ["10005:10005 640", new_token, "mcp-http-token"] and "mcp-http-token" not in "\n".join(disk[3:]),
          {"flash": flash_rot, "old": st_old, "old_session": st_old_session, "new": st_new, "disk": [d if d != new_token else "<token>" for d in disk]})
    seen = agent_rotation_attempts(mcp_base, [token, new_token or ""])
    seen.append(("tools/list", *http("POST", agent_new.url, json.dumps({"jsonrpc": "2.0", "id": 5, "method": "tools/list"}).encode(),
                                     {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                                      "Authorization": f"Bearer {new_token}", "Mcp-Session-Id": agent_new.sid or ""})))
    for p in ("/healthz", "/readyz"):
        seen.append((p, *http("GET", mcp_base + p)))
    check("W", "after the rotation no MCP response (headers or body) carries the new token, and the file still holds it",
          not leaks(seen, new_token) and all(st in (401, 404, 405) for _, st, _, _ in seen[:8])
          and root_helper(wdata, "cat /d/run/ui/mcp-http-token").stdout.strip() == new_token,
          {"leaks": leaks(seen, new_token), "statuses": [(w, st) for w, st, _, _ in seen]})
    agent = Mcp(mcp_base, new_token)  # the paying agent now holds the new token
    agent.start()
    time.sleep(6)
    wc = docker("run", "--rm", "--user", "0", "--network", "none", "-v", f"{wdata}/witness:/data/witness:ro", "-v", f"{wdata}/signer:/data/signer:ro",
                "xbt-anchor-witness:0.1.0", "check", "--store", "/data/witness", "--log", "/data/signer/.run/signatures.jsonl", check_rc=False)
    check("R", "auditor: the witness's check of the signer's signature log passes", wc.returncode == 0, wc.stdout + wc.stderr)

    # --- H: the optional hub app ------------------------------------------------------------------------------
    log("== H: install lazarus-xbt402-hub")
    install(HUB)
    wait_until(lambda: status(f"http://127.0.0.1:{P_HUB}/readyz") == 200, 120, "hub /readyz")
    hub1 = json.loads(http("GET", f"http://127.0.0.1:{P_HUB}/readyz")[2])
    hk = root_helper(os.path.join(APPS_DIR, HUB, "data"), "stat -c '%u:%g %a %n' /d/hub /d/hub/secrets/hub-payto-key /d/hub/secrets/node-rpc-auth").stdout
    check("H", "hub app: init gave data/hub to uid 10004; /readyz 200 (node synced); payTo key generated 0600",
          hub1["ok"] and "10004:10004 700 /d/hub" in hk and "10004:10004 600 /d/hub/secrets/hub-payto-key" in hk, {"readyz": hub1, "stat": hk})
    w1 = hub1.get("wallet") or {}
    addr = w1.get("receive_address") or ""
    check("H", "hub created the node wallet named hub and persisted a receive address (no terminal)",
          w1.get("name") == "hub" and addr.startswith("bcrt1"), w1)
    check("H", "hub /readyz reports the Umbrel Tor onion (APP_HIDDEN_SERVICE on a second app)",
          hub1.get("tor") == HUB_ONION, hub1.get("tor"))
    hp = ui2.get("/hub")  # the session from after the app restart
    check("H", "the wallet UI's Hub page reaches the hub app at lazarus-xbt402-hub_hub_1:9480 (the box network)",
          '<span class="tag ok">200</span> <code>/readyz</code>' in hp, hp[-800:])
    check("H", "the Hub page shows the receive address and Tor onion (fund, no terminal)",
          f'id="hub-receive">{addr}' in hp and f'id="hub-tor">{HUB_ONION}' in hp, hp[-800:])
    compose(HUB, "stop")
    compose(HUB, "up", "-d")
    wait_until(lambda: status(f"http://127.0.0.1:{P_HUB}/readyz") == 200, 120, "hub /readyz after restart")
    hub2 = json.loads(http("GET", f"http://127.0.0.1:{P_HUB}/readyz")[2])
    check("H", "hub app restart: the same payTo and the same receive address",
          hub1["pay_to"] == hub2["pay_to"] and (hub2.get("wallet") or {}).get("receive_address") == addr,
          [hub1["pay_to"], hub2["pay_to"], addr, (hub2.get("wallet") or {}).get("receive_address")])

    # --- G: readiness follows the node ------------------------------------------------------------------------
    log("== G: /readyz follows the node app")
    compose(KNOTS, "stop")
    wait_until(lambda: status(f"http://127.0.0.1:{P_MCP}/readyz") == 503 and status(f"http://127.0.0.1:{P_HUB}/readyz") == 503, 90,
               "readyz 503 with the node stopped")
    check("G", "node app stopped: MCP and hub /readyz 503, /healthz 200",
          status(f"http://127.0.0.1:{P_MCP}/healthz") == 200 and status(f"http://127.0.0.1:{P_HUB}/healthz") == 200)
    compose(KNOTS, "up", "-d")
    wait_until(lambda: status(f"http://127.0.0.1:{P_MCP}/readyz") == 200 and status(f"http://127.0.0.1:{P_HUB}/readyz") == 200, 120,
               "readyz 200 with the node back")
    check("G", "node app back: MCP and hub /readyz 200", True)
    proxy.shutdown()
    with open(os.path.join(OUT, "facts.json"), "w") as f:
        json.dump({"run": RUN, "t_wallet_ready_s": t_ready, "t_total_s": time.time() - t_install, "r1": r1, "r2": r2, "hub": hub2,
                   "init_first": rep, "init_restart": rep2}, f, indent=1, default=str)


def teardown():
    for app in reversed(INSTALLED):
        with open(os.path.join(OUT, f"{app}.log"), "w") as f:
            r = compose(app, "logs", "--no-color", "--timestamps", check_rc=False)
            f.write(r.stdout + r.stderr)
        compose(app, "down", "--volumes", "--timeout", "10", check_rc=False)
    docker("rm", "-f", f"agp040-provider-{PID}", check_rc=False)
    docker("network", "rm", NET, check_rc=False)
    if not os.environ.get("UMBREL_TEST_KEEP"):
        # uninstall: umbrelOS deletes app-data/<id>; the files belong to the service uids, so as root
        root_helper(OUT, "rm -rf /d/app-data /d/provider", ro=False)
        check("X", "uninstall: every container, the network and the app data removed",
              not docker("ps", "-aq", "--filter", f"name=^{WALLET}_", "--filter", f"name=^{HUB}_").stdout.strip()
              and not os.path.exists(APPS_DIR))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        check("X", "the run completed", False, repr(e))
    finally:
        try:
            teardown()
        except Exception as e:  # noqa: BLE001
            check("X", "teardown", False, repr(e))
        ok = write_results(OUT)
    sys.exit(0 if ok else 1)
