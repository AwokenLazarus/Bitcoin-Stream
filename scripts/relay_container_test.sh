#!/bin/bash
# AGP-043: the xbt-work-relay image on Docker (amd64), configured only by env, a named volume and a secret file:
#   * refuses to start with its push listener off loopback and no push token;
#   * read-only root, tmpfs /tmp, cap_drop ALL, no-new-privileges, non-root (uid 10006);
#   * the Prime's push (PUT) needs the bearer token and is refused on the public listener;
#   * a blob sealed by the Python reference client (XBT-053 receipts.py) is served back byte for byte with
#     Cache-Control: no-store, opens, and GET / lists nothing;
#   * the image's own healthcheck (liveness and --ready) passes; blobs survive a container restart.
# Needs dist/oci/ctx from `scripts/oci_build.sh --only xbt-work-relay`. Ports 34340-34341. Prints RESULT PASS|FAIL.
set -euo pipefail
lazvault hold check --project xbt-agentpay || exit 75   # IMP-030: heavy entry point, refuses during a host hold
cd "$(dirname "$0")/.."
ROOT=$PWD
X053=${XBT053:-$HOME/xbt-rnd/XBT-053}
CTX=$ROOT/dist/oci/ctx
PUB=${RELAY_TEST_PORT:-34340}; PUSH=$((PUB + 1))
TAG=xbt-work-relay:agp043
NAME=agp043-relay-$$
VOL=agp043-relay-vol-$$
TMP=$(mktemp -d)
fails=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; fails=$((fails + 1)); }
cleanup() { docker rm -f "$NAME" "$NAME-open" >/dev/null 2>&1 || true; docker volume rm -f "$VOL" >/dev/null 2>&1 || true; rm -rf "$TMP"; }
trap cleanup EXIT

[ -f "$CTX/Dockerfile" ] && [ -x "$CTX/bin/amd64/xbt-work-relay" ] || { echo "run scripts/oci_build.sh --only xbt-work-relay first" >&2; exit 1; }
python3 "$HOME/xbt-rnd/xbt-063/tools/portcheck.py" wait --timeout 30 "$PUB" "$PUSH"
docker buildx build -q --platform linux/amd64 --target xbt-work-relay -t "$TAG" --load "$CTX" >/dev/null
echo "== $TAG ($(docker image inspect "$TAG" --format '{{.Id}}' | cut -c1-19), user $(docker image inspect "$TAG" --format '{{.Config.User}}'))"
docker volume create "$VOL" >/dev/null
RUNOPTS=(--read-only --tmpfs /tmp --security-opt no-new-privileges --cap-drop ALL -v "$VOL:/data")

# 1. no token, push listener on 0.0.0.0: refused
set +e
out=$(docker run --name "$NAME-open" "${RUNOPTS[@]}" "$TAG" 2>&1); rc=$?
set -e
[ $rc -ne 0 ] && grep -q "no relay-push-token" <<<"$out" && ok "no push token, push listener off loopback: refused (exit $rc)" \
  || bad "an open push listener started: rc $rc $out"
docker rm -f "$NAME-open" >/dev/null

# 2. with the token (a secret file)
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$TMP/token"; chmod 644 "$TMP/token"
docker run -d --name "$NAME" "${RUNOPTS[@]}" -v "$TMP/token:/run/secrets/relay-push-token:ro" \
  -e XBT_SECRET_RELAY_PUSH_TOKEN_FILE=/run/secrets/relay-push-token -p "127.0.0.1:$PUB:9490" -p "127.0.0.1:$PUSH:9491" "$TAG" >/dev/null
for _ in $(seq 40); do curl -sf "http://127.0.0.1:$PUB/healthz" >/dev/null && break; sleep 0.25; done
[ "$(docker inspect "$NAME" --format '{{.Config.User}} {{.HostConfig.ReadonlyRootfs}}')" = "xbt-work-relay true" ] \
  && ok "running as xbt-work-relay, read-only root, cap_drop ALL" || bad "user/readonly: $(docker inspect "$NAME" --format '{{.Config.User}} {{.HostConfig.ReadonlyRootfs}}')"

python3 - "$X053" "$PUB" "$PUSH" "$TMP/token" "$TMP" <<'PY' || fails=$((fails + 1))
import json, sys, urllib.request, urllib.error
x053, pub, push, tokf, tmp = sys.argv[1:]
sys.path.insert(0, x053)
from receipts import relay_lookup, relay_open, relay_seal
tok = open(tokf).read().strip()
ID, INV = "bcrt1pexampleprovideridentity0000000000000000000000000000000", "k6gwyymrpy3sliwtoi3n5fzzum"
doc = json.dumps({"message": f"xbt-work-receipt/1|70|{ID}|{INV}|1|1|1|111|111|1", "sig": "aa" * 64}).encode()
blob, lk = relay_seal(doc, ID, INV), relay_lookup(ID, INV)
def req(url, data=None, method="GET", hdr=None):
    r = urllib.request.Request(url, data, hdr or {}, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as x:
            return x.status, x.read(), dict(x.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)
fails = 0
def check(c, what):
    global fails
    print(("  ok   " if c else "  FAIL ") + what); fails += (not c)
check(req(f"http://127.0.0.1:{push}/{lk}", blob, "PUT")[0] == 401, "push without the token: 401")
check(req(f"http://127.0.0.1:{push}/{lk}", blob, "PUT", {"Authorization": "Bearer wrong"})[0] == 401, "push with a wrong token: 401")
check(req(f"http://127.0.0.1:{push}/{lk}", blob[:500], "PUT", {"Authorization": f"Bearer {tok}"})[0] == 400, "an unpadded blob: 400")
check(req(f"http://127.0.0.1:{pub}/{lk}", blob, "PUT", {"Authorization": f"Bearer {tok}"})[0] == 405, "a push on the public listener: 405")
check(req(f"http://127.0.0.1:{push}/{lk}", blob, "PUT", {"Authorization": f"Bearer {tok}"})[0] == 204, "the Prime's push with the token: 204")
st, body, h = req(f"http://127.0.0.1:{pub}/{lk}")
check(st == 200 and body == blob and h.get("Cache-Control") == "no-store", f"GET /<lookup>: {st}, byte-identical, Cache-Control {h.get('Cache-Control')}")
check(relay_open(body, ID, INV).rstrip() == doc, "the Python reference client opens it")
check(req(f"http://127.0.0.1:{pub}/")[0] == 404 and req(f"http://127.0.0.1:{pub}/work-receipts/v1/")[0] == 404, "GET / lists nothing")
check(req(f"http://127.0.0.1:{pub}/readyz")[0] == 200, "GET /readyz: 200 (the store is writable)")
open(f"{tmp}/blob", "wb").write(blob); open(f"{tmp}/lookup", "w").write(lk)
sys.exit(1 if fails else 0)
PY
docker exec "$NAME" /usr/bin/xbt-work-relay healthcheck && docker exec "$NAME" /usr/bin/xbt-work-relay healthcheck --ready \
  && ok "the image's healthcheck subcommand: liveness and --ready" || bad "healthcheck"
docker restart "$NAME" >/dev/null
for _ in $(seq 40); do curl -sf "http://127.0.0.1:$PUB/healthz" >/dev/null && break; sleep 0.25; done
curl -sf "http://127.0.0.1:$PUB/$(cat "$TMP/lookup")" -o "$TMP/after" && cmp -s "$TMP/blob" "$TMP/after" \
  && ok "after a restart the blob is still served (named volume, /data/relay/blobs)" || bad "blob lost across restart"
if docker logs "$NAME" 2>&1 | grep -q "$(cat "$TMP/lookup")"; then bad "the relay logged a lookup"; else ok "no lookup in the container log"; fi
echo "== $(docker logs "$NAME" 2>&1 | tail -1)"
[ $fails -eq 0 ] && echo "relay_container_test: RESULT PASS" || { echo "relay_container_test: RESULT FAIL ($fails)"; exit 1; }
