# Containers: the data dir, secrets, health and images (AGP-038)

Umbrel and StartOS (Start9) run our services as containers. This page is the **shared standard** for
xbt-agentpay and xbt-compute (cmp CONTRACT §U). cmp has no layout yet, so it adopts this one. Its
components already have their places here. agentpay implements it in `xbt-signer`,
`xbt-anchor-witness`, `xbt-wallet-mcp`, `xbt402-hub` and the wallet UI `xbt-wallet-ui` (AGP-039). The code is
in the `xbt-svc` crate. `scripts/container_test.sh` tests it on regtest. The Umbrel apps and the StartOS
package built on it (AGP-040) are in `packaging/` (README there).

Status: **proposal, pending cmp-lead's OK** (forwarded by agp-lead, 2026-09-28).

## 1. One data dir, one sub-dir per component

`XBT_DATA_DIR` (cmp: `CMP_DATA_DIR`) is mounted at **`/data`** in every image. On Umbrel it is
`${APP_DATA_DIR}/data`. On StartOS it is the package's `main` volume. Bare metal uses any directory.
Nothing is written outside `/data` and `/tmp`, so every container runs with `read_only: true` and a
tmpfs `/tmp`.

```
/data/
  signer/          agp  uid 10001  0700  policy.json, .run/ (B2 state: ledger, audit, sealed hot/channel keys,
                                         channels, routing, signatures.jsonl), secrets/
  witness/         agp  uid 10002  0700  anchors.jsonl, alerts.jsonl       (XBT_WITNESS_DIR: own mount, own owner)
  mcp/             agp  uid 10003  0700  secrets/, mcp-payer.jsonl (local payer mode)
  hub/             agp  uid 10004  0700  hub.json (optional), state/, secrets/
  ui/              agp  uid 10005  0700  password.scrypt (the login hash), setup-code (first run only), secrets/
  relay/           agp  uid 10006  0700  blobs/ (the xbt-work receipt relay's sealed blobs, one file each), secrets/
  cmp-node/        cmp  uid 10011  0700  operator key, operator service, merchant ledgers and meters, secrets/
  cmpd/            cmp  uid 10012  0700  device runtime state, secrets/
  cmpd-cache/      cmp  uid 10012  0700  the model span cache: LARGE, its own mount (CMP_CACHE_DIR), safe to prune
  cmp-client/      cmp  uid 10013  0700  client ledger, input logs, secrets/
  knots-xbt/       cmp  uid 10020  0700  the pruned XBT Knots node's datadir (cmp bundles the node image)
  run/<component>/ the server's uid and gid, 0750: its sockets (0660) and readiness file (0640)
     run/signer/   signer.sock, ready.json
     run/anchor/   anchor.sock
     run/ui/       mcp-http-token (0640): the MCP bearer token, owned by the UI, read by the MCP (AGP-042)
```

Rules:
- **A container mounts only its own sub-dir**, plus the `run/<peer>/` directories of the sockets it
  connects to. Read-only is enough to connect to a Unix socket.
  - The MCP mounts `mcp/` and `run/signer/` (ro). So does the UI, with `ui/`. With the UI, the MCP also
    mounts `run/ui/` (ro) and the UI mounts it read-write (AGP-042, §8).
  - The signer mounts `signer/`, `run/signer/` and `run/anchor/` (ro).
  - The witness mounts `witness/` and `run/anchor/`.
- **Separately mountable paths** have their own override variable, for another disk, another owner or
  pruning:
  - `XBT_WITNESS_DIR`: the witness store, which the signer's user must not be able to write.
  - `XBT_RUN_DIR`: the socket root.
  - `CMP_CACHE_DIR`: the span cache.
- **Owners:** each image's shared base layer carries the `/data` skeleton with the owners above. A
  Docker named volume mounted there takes its owner from the image on first use. A bind mount does not:
  Umbrel's `${APP_DATA_DIR}` arrives owned by the box user (1000), and a StartOS volume root-owned.
  **Decided (AGP-040): an init one-shot, `xbt-init`, keeps the per-component uids** (§8). It runs before
  the services on every start, as root with no network and only `CHOWN`, `FOWNER`, `DAC_OVERRIDE`, and
  gives each sub-dir (and, when its owner was wrong, everything under it, never following a symlink) to its
  component. One uid for everything (Umbrel's usual `user: 1000:1000`) would also run, but it loses the
  separation between the witness and the signer, and lets the MCP and the UI read the signer's sealed keys.
- **Socket groups:** a socket's group is its server's group, and each client is a member of it.
  `/etc/group` in the images:
  - `xbt-signer` group: `xbt-wallet-mcp` and `xbt-wallet-ui` are members;
  - `xbt-anchor-witness` group: `xbt-signer` is a member.

  So the MCP cannot reach the witness, and the witness cannot reach the signer.
- **State formats do not change.** `signer/` is exactly B2's signer root (`policy.json` + `.run/`), so
  B2's Python tools and an existing bare-metal wallet move in unchanged.

UID table (the images' `USER`; the cmp rows are reserved):

| uid/gid | user | image |
|---|---|---|
| 10001 | xbt-signer | xbt-signer |
| 10002 | xbt-anchor-witness | xbt-anchor-witness |
| 10003 | xbt-wallet-mcp | xbt-wallet-mcp |
| 10004 | xbt402-hub | xbt402-hub |
| 10005 | xbt-wallet-ui | xbt-wallet-ui |
| 10006 | xbt-work-relay | xbt-work-relay (AGP-043) |
| 0 | root | xbt-init (a one-shot that exits; §8) |
| 10011 | cmp-node | cmp-node (reserved) |
| 10012 | cmpd | cmpd-* (reserved) |
| 10013 | cmp-client | cmp-client (reserved) |
| 10020 | knots-xbt | knots-xbt (reserved) |

## 2. Secrets: one lookup, by name

A secret has a **name**, the same string everywhere: the file name in `$CREDENTIALS_DIRECTORY`, in
the data dir, and in the env variable (upper-cased, `-` → `_`). Lookup order (`xbt_svc::Secrets`):

1. `XBT_SECRET_<NAME>_FILE` (cmp: `CMP_SECRET_<NAME>_FILE`): an explicit path. StartOS config and
   secrets written to files use this, and so do compose and Docker secrets.
2. `$CREDENTIALS_DIRECTORY/<name>`: systemd `LoadCredential=`. cmp.keys already reads this.
3. `/data/<component>/secrets/<name>`: the file must be 0600 in a 0700 directory. Production refuses a
   secret readable by group or others. Wrapping keys, tokens and hub keys are **generated here on first
   run**: created exclusively, 0600, fsynced, never overwritten.
4. `XBT_SECRET_<NAME>`, a plain env value: **dev mode only**. Production refuses it at start, and so do
   the older env secrets `B2_HOT_PASSPHRASE`, `XBT_MCP_HTTP_TOKEN` and `B2_HOT_ALLOW_PLAINTEXT`.

`XBT_MODE=production|dev`. The images set `production`. If it is unset, the mode is production when
`XBT_DATA_DIR` is set, and dev otherwise, which keeps the pre-AGP-038 bare-metal behaviour.
`XBT_SECRETS_DIR` overrides step 3's directory.

| name | component | what | first run |
|---|---|---|---|
| `signer-wrap-key` | signer | 32-byte AES-256-GCM wrapping key for the sealed hot and channel keys (raw or 64 hex) | generated |
| `signer-passphrase` | signer | instead of the wrap key: scrypt passphrase (B2 format) | never generated |
| `node-rpc-auth` | signer, hub (cmp: any node client) | `user:password` in cookie format (a node's `.cookie` works as is) | provisioned by the installer |
| `mcp-http-token` | mcp (ui on a box) | bearer token for MCP over HTTP (64 hex) | generated when listening off loopback. On a box with the UI, `xbt-init` makes it `run/ui/mcp-http-token` instead: owned by the UI, 0640, the MCP reads it by group on every request and never writes it (AGP-042, §8) |
| `xbt-ui-password` | ui | the UI login password, when the platform sets it (Umbrel `${APP_PASSWORD}`, via `xbt-init`); otherwise the UI's own first-run setup code | never generated |
| `hub-payto-key` | hub | payTo secret (hex scalar) | generated |
| `relay-push-token` | relay | bearer token the Prime's pushes must carry (any string) | never generated: set it, or `XBT_RELAY_PUSH_ALLOW_OPEN=1` for a push port only the Prime reaches |
| `operator-passphrase` | cmp-node | cmp operator key passphrase (cmp.keys) | cmp's rule |
| `client-passphrase` | cmp-client | cmp client identity passphrase (cmp.keys) | cmp's rule |

cmp's existing `$CREDENTIALS_DIRECTORY/<name>` and passphrase-file handling is steps 2 and 1. Adding
step 3 and the `CMP_SECRET_*` names makes it this scheme. `--secrets-dir` (§U) is `XBT_SECRETS_DIR` /
`CMP_SECRETS_DIR`.

## 3. Health, readiness, status

Every HTTP service serves these without auth (probes cannot send tokens). The bodies hold no secrets:

- `GET /healthz`: the process is up. Returns `200 {"ok": true, "service": ...}`.
- `GET /readyz`: ready for work. Returns `200` or `503`, with JSON status in the body. The status always
  includes the node's `reachable`, `synced` and `sync_pct` (from `verificationprogress`), the same
  `xbt_svc::health::node_status` everywhere. The body *is* the service's status JSON, so a UI (the
  signer UI, AGP-039, linking to cmp's node/hub status page) reads `/readyz` and gets a 200 or 503
  plus the details. cmp may add `GET /status` returning the same document, always 200.
- Both are also served under the base path (`<base>/healthz`).

| service | /readyz is 200 when |
|---|---|
| `xbt-wallet-mcp` | the signer answers `health` on its socket, **and** the signer's readiness file is fresh and `ok` |
| `xbt402-hub` | the node is reachable and synced; the body also gives `pay_to`, the provider count, the node wallet named `hub` (created on start) with a stable receive address and balance, and `tor` when `XBT_HUB_ONION` / `APP_HIDDEN_SERVICE` is set |
| `xbt-signer` (socket only) | readiness **file** `run/signer/ready.json`, rewritten every `XBT_READY_INTERVAL` s (default 5), `ok` when all of these hold: node reachable and synced, keys unlocked, the witness answering `latest` (when anchoring is on), the signer's own socket answering `health` |
| `xbt-anchor-witness` (socket only) | `xbt-anchor-witness healthcheck`: the witness answers `latest` |
| `xbt-work-relay` | its blob store is writable (no node: the relay only stores what the Prime pushes) |

**Why the signer has a readiness file, not a health listener.** The signer holds every key. A file adds
no network surface at all, where a listener would add one, even on loopback. The file works in a
`FROM scratch` image (the binary's own `healthcheck` subcommand reads it). Other containers read it
through the shared `run/signer/` mount (group-readable, 0640). A stale file means the signer is gone or
wedged (the heartbeat stops), which a socket probe alone would not show before a timeout.

**Image HEALTHCHECK = liveness.** It runs the binary's own `healthcheck` subcommand: signer file fresh,
witness answering, MCP/hub `GET /healthz`. The binary is used because the images have no shell or curl.
`--ready` switches the subcommand to readiness, for StartOS health checks, or for compose
`depends_on: condition: service_healthy` when a stack should wait for sync. With readiness as the
default, a node doing hours of IBD would mark every service unhealthy.

## 4. Networking and reverse proxies

- **Bind addresses come from config.** In the images:
  - MCP: `XBT_MCP_HTTP=0.0.0.0:33510`;
  - hub: `XBT_HUB_BIND=0.0.0.0`, `XBT_HUB_PORT=9480`.

  Bare metal defaults to loopback.
- **Auth off loopback:** the MCP refuses a non-loopback listener without a bearer token. In data-dir mode
  it generates `mcp-http-token`. The signer has no HTTP API. The hub is a paid public service, so its
  auth is the payment.
- **Base path:** `XBT_BASE_PATH=/x`. Every endpoint answers both at `/x/...` (a proxy that keeps the
  prefix) and at `/...` (one that strips it).
- **Public URL:** used for the hub's 402 `resource.url`. Tor `.onion` and StartOS LAN/Tor interfaces work
  without configuration. In order:
  1. `XBT_PUBLIC_URL`;
  2. with `XBT_TRUST_FORWARDED=1`: `X-Forwarded-Proto` / `X-Forwarded-Host` / `X-Forwarded-Prefix`;
  3. otherwise the request's `Host`.

  **There is no hard-coded self-URL.** Umbrel's `app_proxy` and StartOS both set the forwarded headers.
  Trust them only behind such a proxy.

## 5. Configuration (env or file)

Every setting has an env variable. Files are optional.

| service | config |
|---|---|
| signer | B2's `B2_*` env (unchanged), plus `XBT_NODE_RPC_HOST`, `XBT_NODE_RPC_PORT`, `XBT_CHAIN`, `XBT_NODE_WALLET`. Policy: `XBT_SIGNER_POLICY` (JSON; authoritative, and rewrites `policy.json` when it changes), or `XBT_SIGNER_POLICY_FILE`, or the existing `policy.json`, or a default that pays nobody. `XBT_ANCHOR=off` runs without a witness. New knobs: `B2_RPCHOST`, `B2_RPCCOOKIE` (a credentials file), `B2_SIGNER_SOCK_MODE` (≤ 660). |
| witness | `XBT_WITNESS_DIR`, `XBT_ANCHOR_SOCK` (defaults under `/data`) |
| MCP | `XBT_MCP_HTTP`, `XBT_MCP_PATH`, `XBT_BASE_PATH`, `XBT_MCP_HTTP_ALLOW_REMOTE`, the existing `XBT_MCP_*` payer settings, and `B2_SIGNER_SOCK` (default `/data/run/signer/signer.sock`). `XBT_MCP_HTTP_TOKEN_FILE` (default `run/ui/mcp-http-token` when it exists): the UI-owned token, read on every request, fail closed. The MCP has no rotation endpoint (AGP-042). |
| relay | `XBT_RELAY_BIND` (image `0.0.0.0:9490`, public, GET only), `XBT_RELAY_PUSH_BIND` (image `0.0.0.0:9491`, the Prime's pushes; `off`), `XBT_RELAY_STORE` (default `/data/relay/blobs`), `XBT_RELAY_RATE`/`_BURST` (GETs per second per client, default 10/40), `XBT_RELAY_MAX_ENTRIES` (1,000,000), `XBT_RELAY_TTL_DAYS` (30), `XBT_RELAY_THREADS`, `XBT_RELAY_PUSH_ALLOW_OPEN`, `XBT_BASE_PATH`, `XBT_TRUST_FORWARDED` (count clients by the proxy's `X-Forwarded-For` hop) |
| hub | `hub.json` (`--config`, `XBT_HUB_CONFIG`, or `/data/hub/hub.json`), each field overridable: `XBT_NODE_RPC_HOST`, `XBT_NODE_RPC_PORT`, `XBT_HUB_WALLET`, `XBT_HUB_NETWORK` (default: derived from the node's anchor block), `XBT_HUB_BIND`, `XBT_HUB_PORT`, `XBT_HUB_DATADIR`, `XBT_HUB_CONNECT`, `XBT_HUB_JSON`, `XBT_HUB_WATCH_INTERVAL`, `XBT_HUB_THREADS`, `XBT_PUBLIC_URL`, `XBT_TRUST_FORWARDED`, `XBT_HUB_ONION` (or `APP_HIDDEN_SERVICE`: umbrelOS gives every app, including a second app, a hidden service) |

None of these binaries depends on systemd. `$CREDENTIALS_DIRECTORY` is just one secret source.

## 6. Images

`scripts/oci_build.sh` builds one image per binary for **linux/amd64, linux/arm64 and linux/arm/v7**:
`xbt-signer`, `xbt-anchor-witness`, `xbt-wallet-mcp`, `xbt402-hub`, `xbt-wallet-ui`, `xbt-init` and (AGP-043)
`xbt-work-relay` (`--only IMAGE,...` builds a subset; the binaries come from `$CARGO_TARGET_DIR`). Each
is `FROM scratch` with the static musl binary (built with zig). There is no `RUN`, so no emulator or
binfmt is needed. The images are saved as OCI archives in `dist/oci/*.tar` (never pushed), with digests
and sizes in `dist/oci/IMAGES.md`. `scripts/oci_inspect.py` checks every platform: architecture, static
ELF, non-root, HEALTHCHECK, two layers, and the shared base layer.

- **Layer 1** is shared and byte-identical in every image and platform, so it is stored once:
  `/etc/passwd`, `/etc/group`, `/tmp` (1777), and the `/data` skeleton with owners. It is generated
  deterministically by `container/mkbase.py`.
- **Layer 2** is the binary.
- **Config:**
  - `USER` is the component's user, never root (except `xbt-init`, §8);
  - `ENV XBT_DATA_DIR=/data XBT_MODE=production`;
  - `ENTRYPOINT` is the binary;
  - `HEALTHCHECK` runs the binary's own `healthcheck`.

  Run the containers with `read_only: true`, `tmpfs: /tmp` and `no-new-privileges`.
- **cmp's images follow the same pattern:**
  - `cmp-node` and `cmp-client` are one image each.
  - `cmpd` comes in **per-backend variants**: `cmpd-cpu` (static, the default on boxes, which are usually
    CPU-only), `cmpd-cuda`, `cmpd-vulkan` and `cmpd-rocm`. Every variant has the same data layout
    (`cmpd/`, `cmpd-cache/`), the same env, and the same health endpoints, so an app switches the backend
    only by changing the image name.
  - GPU variants cannot be `FROM scratch`: they need the vendor runtime libraries. The rule for them is
    the smallest base that carries those libraries, still non-root and with a read-only root filesystem.
  - `knots-xbt` is cmp's node image. agentpay's apps reference it, not an image of their own.

### Choices and comparisons

**Base image: scratch (chosen), distroless static, or alpine.**

| | scratch | distroless static-debian12 | alpine 3 |
|---|---|---|---|
| size | 0 (+ our 1 KB base layer) | ~2 MB | ~3.5 MB compressed, 8 MB unpacked |
| arm/v7 | yes | yes | yes |
| CA certs | not needed: rustls with webpki-roots compiled into the binaries | included | package |
| tzdata | not needed: everything is UTC/unix time | included | package |
| debug shell | none; `healthcheck` / `call` subcommands, or `docker run --volumes-from` a debug image | `:debug` variant | yes |
| attack surface | the binary only | minimal | a shell and busybox |
| pull from a registry | no (nothing to pull) | yes | yes |

scratch wins. The binaries are static and carry their own roots, and they need no zone data. The only
thing a base would add is a shell, and our own subcommands do that job without adding surface. It is
also the only option buildable here without pulling from a registry.

**Granularity: one image per binary (chosen), or one image with subcommands.**
- Per binary: the `USER`, `ENTRYPOINT` and `HEALTHCHECK` are each right for their service.
- Each container carries only its own binary (the witness image is about 0.36 MB compressed).
- Images can be pinned and upgraded independently.
- The duplication costs nothing, because the base layer is shared.
- A single image would need one generic HEALTHCHECK, one user for every service (breaking the
  witness/signer UID split), and would ship every binary in every container.
- cmp: the same choice, with `cmpd` per backend.

**Build tooling.** This host has no rootless Docker, podman or buildah. `docker buildx` runs through the
docker group (no sudo), and needs no binfmt because the Dockerfile has no `RUN`. The exports are
built for reproducibility: `SOURCE_DATE_EPOCH` is the commit time, `rewrite-timestamp` is set, and the base layer is
generated deterministically. The base layer digest was the same on every build. Byte-identical rebuilds of the
binary layers have not been verified yet.

## 7. Test

`scripts/container_test.sh` builds and inspects all the images, then runs the amd64 ones on a private
Docker network with a Knots regtest node. They are configured only by env and the data dir (named
volumes). The test:
1. pays an xbt402 call through the MCP over HTTP, behind a base path and with the bearer token;
2. kills and restarts the containers and checks that everything persists;
3. checks that `/readyz` follows the witness and the node;
4. checks the hub behind a proxy.

Ports 33700–33799. Evidence is written to `run/container-test/<stamp>/`.

## 8. Bind mounts and `xbt-init` (AGP-040)

`xbt-init` (in `xbt-svc`, image `xbt-init`) makes a data dir match §1 before the services start:

- creates `<component>/` and `<component>/secrets/` (0700) and `run/signer/`, `run/anchor/`, `run/ui/` (0750),
  owned by each component's uid;
- when a component dir had another owner, gives it and its contents to the component (`lchown`, no descent
  into symlinks); on a second start nothing changes;
- provisions the secrets an installer holds, from `XBT_INIT_*` (plain env values are fine here: it is the
  installer's step and exits before any service starts; the services still read files only):
  `XBT_INIT_NODE_RPC_AUTH[_FILE]` or `XBT_INIT_NODE_RPC_USER` + `_PASS` → `signer/` and `hub/secrets/node-rpc-auth`;
  `XBT_INIT_UI_PASSWORD[_FILE]` → `ui/secrets/xbt-ui-password`; the MCP token, generated once: with the UI,
  `run/ui/mcp-http-token` (uid 10005, 0640; an AGP-040 token in `mcp/secrets/` is moved there and the old
  copies removed, so agents keep working), without it `mcp/secrets/mcp-http-token`. A secret is rewritten only when its value changes, through an exclusively created temp
  file (a symlink a service planted is never followed);
- prints a JSON report (names, owners, modes; never a value); `xbt-init check` only reports.

Run it with `user: 0:0`, `network_mode: none`, `read_only`, `cap_drop: ALL` + `CHOWN`, `FOWNER`,
`DAC_OVERRIDE`, and `XBT_INIT_COMPONENTS` = the components the app runs. Each service then waits for it
(`depends_on: condition: service_completed_successfully`; a StartOS oneshot).

| option for a bind mount's owners | for | against |
|---|---|---|
| **an init one-shot (`xbt-init`, chosen)** | keeps every uid split (the witness store, the sealed keys); works the same on Umbrel, StartOS (volumes arrive root-owned on every start) and plain compose; also repairs a restore | one short-lived root container (no network, three capabilities) |
| one uid (`user: 1000:1000` everywhere) | no root container at all | the witness can be rewritten by the signer's user; the MCP and UI can read the signer's keys |
| an umbrelOS `hooks/pre-start` script | no extra image | Umbrel only (StartOS has no hooks), runs on the host as root with a full shell |
| named volumes only | Docker copies the image's owners | Umbrel apps keep data under `${APP_DATA_DIR}` (backups, uninstall); StartOS has its own volumes |

**Language for `xbt-init`: Rust (chosen)**, a 0.5 MB static binary in the same workspace, sharing the uid
table and the secret rules with the services, `FROM scratch` like every other image, for amd64, arm64 and
arm/v7. A busybox shell script would need a base image pulled from a registry and would duplicate the layout
in shell. Go would add a second toolchain for 300 lines.

## 9. The xbt-work receipt relay (AGP-043)

`xbt-work-relay` (crate `xbt-work-relay`, image `xbt-work-relay`, uid 10006) is the blinded receipt relay of
pay-with-work (xbt-work spec §11.1): the Prime pushes each invoice's latest signed receipt, sealed with a key only a
holder of the invoice can derive, and payers and providers fetch it by a 256-bit lookup. The relay holds no key and
parses nothing.

- **Two listeners.** `9490` is public and read-only: `GET /<lookup>` (also `/work-receipts/v1/<lookup>`, the Python
  reference's path) → `200` with the blob or `404`. `9491` takes the Prime's `PUT /<lookup>` (and `DELETE` to retire an
  invoice) and belongs on a private network. A push needs `Authorization: Bearer <relay-push-token>` when the secret
  is set. Without one, a push listener off loopback is refused at start unless `XBT_RELAY_PUSH_ALLOW_OPEN=1` (primed
  `rnd/agp-011` sends no token yet, so its push port must be reachable only from the Prime).
- **What the spec asks of it.** Blobs must be exactly 1,052 bytes (nonce + `pad₁₀₂₄` + tag), so every entry has one
  size. There is no listing route and `GET /` is `404`. Every response carries `Cache-Control: no-store`. GETs are
  rate-limited per client (a token bucket per address). No lookup is ever logged, only counters every 5 minutes.
- **Store.** One file per lookup under `/data/relay/blobs/<lookup[..2]>/<lookup>`, 0600, written through a temp file and a
  rename. It needs no in-memory index and survives a restart. It is bounded by `XBT_RELAY_MAX_ENTRIES` (a push of a new
  lookup beyond it is `507`) and by `XBT_RELAY_TTL_DAYS` (an entry not pushed again for that long expires and is swept).
- `/healthz`, `/readyz` (the store is writable), `/health` (the Python relay's probe), and `xbt-work-relay healthcheck
  [--ready]` for the image's HEALTHCHECK.
- Tests: `cargo test -p xbt-work-relay` (the store, the listeners, the token, the rate limit, and an HTTP round trip with
  the Rust relay client); `scripts/relay_container_test.sh` (the amd64 image on Docker); `scripts/work_nta.sh` (primed
  pushing to it live on an NTA regtest chain).

**Language and architecture: Rust (chosen).**

| option | performance, smallest target | reach | install | safety | fit | maintain |
|---|---|---|---|---|---|---|
| **Rust + std HTTP server (`xbt_svc::http` since AGP-072; was tiny_http), one static binary (chosen)** | 0.83–0.88 MB static binary, ~0.45 MB compressed image; threads, no GC, no runtime | amd64, arm64, arm/v7 images; every AGP-031 target | `FROM scratch`, like every other image; or one binary on bare metal | memory-safe; parses only a path and a length-checked body | shares `xbt-svc` (data dir, secrets, probes, base path) with the other services; tested against the Rust relay client in-process | the same workspace and CI as the rails |
| Python (XBT-053 `relay/`, kept as the reference) | an interpreter per box; in-memory only | wherever Python runs | a Python base image (~50 MB) and a venv | memory-safe | the reference, but no token, no size check, no rate limit, no persistence | a second service stack to maintain |
| Go | small static binary, GC | wide | `FROM scratch` possible | memory-safe | would duplicate the data-dir and secret rules in a new language | a second toolchain |
| A Cloudflare Worker + KV | no box at all | global edge | a Cloudflare account | memory-safe | a third party sees every lookup and its timing; unavailable to a box-only operator | a separate deployment path |
| nginx / Caddy serving a directory, WebDAV for pushes | small | wide | a stock image | mature | cannot enforce the exact blob size, would need care to hide the directory listing, and adds an image pulled from a registry | configuration, not code |

A relay is a small keyless blob store, so the choice follows the other services: the widest hardware reach with the
smallest image, no base image to pull, and the same secret and data-dir rules. The Python relay stays as the
reference, and each is tested against the other side's client.

## 10. MCP token rotation: the UI owns the token (AGP-042)

A leaked agent token must be revocable by the owner and by nobody else. So the thing that rotates it is
something agents never hold: the UI (uid 10005, behind the owner's login). The MCP has no rotation
endpoint at all; a bearer token cannot replace itself.

- `run/ui/mcp-http-token` is owned by `xbt-wallet-ui`, mode 0640, in `run/ui/` (0750). `xbt-wallet-mcp` is a
  member of the `xbt-wallet-ui` group (the base layer's `/etc/group`), mounts `run/ui/` read-only and reads
  the file on **every** request. An unreadable, empty, symlinked or world-readable file refuses every
  request (503); it never falls back to an older value.
- The Agents page's *Rotate the token* writes a new random token with `xbt_svc::replace_secret_file`: a
  randomly named temp file created exclusively (O_EXCL, never through a planted symlink) with mode 0600 in
  the same directory, written, fsynced, then given 0640, renamed over the token and the directory fsynced.
  No reader ever sees a partial token, and nobody outside the owner and its group can read it at any moment.
  The old token gets 401 on the next request, including on sessions it already opened.
- The new token is shown only on the owner's Agents page; the MCP never returns it.

Compared (the lead's options):

| option | rotation authorised by | agent can defeat it? | moving parts | chosen |
|---|---|---|---|---|
| (a) UI writes a file the MCP only reads | the owner's UI login (uid 10005 owns the file) | no: no endpoint, no write access | a group and a ro mount | **yes** |
| (b) owner rotation key, HMAC'd request to the MCP | a second key kept only by the UI | no, if the key and replay window are right | a key to provision, an HMAC + nonce store, still an endpoint | no: more crypto and an endpoint to get right, for the same result |
| (c) a human-signed signer method | the enrolled human key (like AGP-039's signed actions) | no | the signer would then have to own and push the MCP's token | no: the signer holds no MCP secret today; needs a signature for a routine, low-value action |

