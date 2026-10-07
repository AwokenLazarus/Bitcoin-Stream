# XBT Agent Wallet on Umbrel and StartOS (AGP-040)

Side-load packages of the agent wallet (signer, anchor witness, MCP server, web UI) and the optional xbt402
hub, built on the container standard in `docs/CONTAINER.md` and the one image set `scripts/oci_build.sh`
makes. **Local only:** nothing is pushed to a registry, and nothing is submitted to the Umbrel App Store or
the Start9 marketplace. That submission is Mike's call.

```
packaging/
  regtest_lib.py              helpers shared by both regtest drivers
  umbrel/                     a local Umbrel community store (id "lazarus", as SOV-005's)
    umbrel-app-store.yml
    lazarus-xbt-agent-wallet/ the wallet: init + witness + signer + MCP + UI, app_proxy -> UI
    lazarus-xbt402-hub/       the optional hub, its own app
    lazarus-xbt-knots/        a stand-in XBT node (pruned Knots 29.4.2) until xbt-compute's node-host app (CMP-098)
    lint.py                   manifest + compose + hardening lint
    regtest/                  the off-Umbrel overlays and the driver (umbrel_regtest.py)
    test-umbrel-apps.sh       verify: lint, then install from cold on regtest, twice
    bundle.sh                 side-load bundle: the store + docker-saved images (dist/umbrel/)
  startos/
    xbt-agent-wallet/         the StartOS package (start-sdk 2.0.9, TypeScript); startos/spec.ts is its containers as data
    build.sh                  tsc + the SDK's eslint + ncc + `start-cli s9pk pack` -> dist/startos/*_{x86_64,aarch64}.s9pk
    tools/tar2sqfs            a shim over mksquashfs -tar (pack needs tar2sqfs; this host has squashfs-tools)
    test/startos_regtest.py   the package's own containers on regtest, StartOS-shaped
    test-startos.sh           verify: build, inspect both .s9pk, then the regtest run
```

## Build and verify

```bash
scripts/oci_build.sh --load                # the six images for amd64, arm64, arm/v7, loaded as <image>:0.1.0
packaging/umbrel/test-umbrel-apps.sh       # RESULT PASS: lint + 2 cold regtest runs (ports 34000-34099)
packaging/startos/test-startos.sh          # RESULT PASS: build + inspect + regtest run (ports 34100-34199)
scripts/verify_agp040.sh                   # all of it, plus the unit tests and AGP-038's container test
```

The StartOS build needs `start-cli` 2.1.0 (`~/.local/opt/start-cli/start-cli`, from the start-technologies
releases) and a packaging workspace outside the repo (`~/.local/share/xbt-startos-ws`; its `.startos/` holds
the key that signs the package, so it is never committed).

## What the apps do on a box

Both platforms run the same containers, from the same images:

| container | image (user) | mounts (sub-dirs of the data dir) | network |
|---|---|---|---|
| init (one-shot) | `xbt-init` (root, CHOWN/FOWNER/DAC_OVERRIDE only) | the whole data dir | none |
| witness | `xbt-anchor-witness` (10002) | `witness/`, `run/anchor/` | none on Umbrel |
| signer | `xbt-signer` (10001) | `signer/`, `run/signer/`, `run/anchor/` ro | the node's RPC |
| MCP | `xbt-wallet-mcp` (10003) | `mcp/`, `run/signer/` ro, `run/ui/` ro | 33510, bearer token |
| UI | `xbt-wallet-ui` (10005) | `ui/`, `run/signer/` ro, `run/ui/` | 8480 behind the box's proxy |
| hub (optional) | `xbt402-hub` (10004) | `hub/` | 9480, paid public API |

`init` gives each sub-dir to its uid (Umbrel bind mounts arrive owned by uid 1000, StartOS volumes owned by
root), writes the node credentials, and makes the MCP token once, as the UI's `run/ui/mcp-http-token`
(0640; the MCP reads it by group and never writes it). The owner reads it on the UI's **Agents** page. That page is how a box with no terminal
connects an agent. The owner never needs a shell:

- **Umbrel:** log in with the password the dashboard shows (`${APP_PASSWORD}`, `deterministicPassword`).
  Then Setup: enrol the approval key (it stays in the browser) and sign a policy. Then Agents: copy the MCP
  endpoint `http://umbrel.local:33510/mcp` and the token. If the token leaks, rotate it on that same page
  (no terminal, no restart). The Hub page shows this box's hub receive address when the hub app is installed.
- **StartOS:** run the *Node connection* action (a critical task until done). Start the service. *Web UI
  setup code* gives the one-time code; in the UI, choose a password (only its scrypt hash is kept). Then
  the same Setup and Agents steps; *Agent connection* also shows the MCP addresses and token. The UI, the
  MCP and the hub are StartOS interfaces, on the LAN by default; the owner can add a Tor address to any of
  them.

### Readiness and health

- **Umbrel:** each container has its image's HEALTHCHECK (liveness).
- **StartOS:** each daemon's `ready` is its port listening, or the image's own `healthcheck` subcommand
  for the socket-only witness and signer. A `wallet-ready` health check reads the MCP's `/readyz`: success
  when the node is synced and the keys are unlocked, otherwise "loading" with the reason (node not
  reachable, syncing, witness down).

### Backups

- **StartOS:** backs up the `main` volume (sealed keys and their wrapping key, anchors, channels, ledgers,
  the UI's hash) and `startos` (the node connection). The backup is encrypted with the server's master
  password. After a restore, `init` puts the owners back.
- **Umbrel:** backs up `${APP_DATA_DIR}` the same way.
- **The wallet's own export:** the encrypted backup on the UI's Keys page, signed by the human, is still
  the portable one.

## Choices and comparisons (the stack rule)

**Bind-mount owners: an init one-shot (chosen)**, one uid for everything, an umbrelOS pre-start hook, or
named volumes. See `docs/CONTAINER.md` §8. Only the init one-shot keeps the witness/signer/MCP/UI
separation on both platforms (Umbrel bind mounts, StartOS root-owned volumes) and after a restore. It is
also the only one that runs identically in plain compose. Its language is Rust: a 0.5 MB static binary
sharing the uid table with the services, `FROM scratch`, on all three architectures.

**Node dependency.**

| option | chosen? | why |
|---|---|---|
| depend on an XBT node app that exports `APP_XBT_KNOTS_*` | yes | one node per box, shared with xbt-compute |
| bundle a node in the wallet app | no | a second node on a box that runs cmp's |
| an Electrum fallback | not possible yet | the Rust signer has no Electrum backend (AGP-028); B2's Python signer has one, but it is not the shipping signer |

The export contract is five variables: host, RPC port, chain, user, password. cmp's node-host app
(CMP-098) must export the same names. Until then `lazarus-xbt-knots` is a stand-in, reusing A3's
`xbt-a3-knots:29.4.2`, which is **amd64-only**. A Pi or other arm64/armv7 box has no stand-in node:
install CMP-098's real `knots-xbt` app when it exists (same `APP_XBT_KNOTS_*` names). Building Knots
29.4.2 for those arches under soak is not a packaging job. See `umbrel/lazarus-xbt-knots/README.md`.
StartOS has no XBT node package yet (Start9's bitcoind is the SHA256d chain), so the node there is an
external connection (the *Node connection* action). When CMP-099 exists, it becomes a declared
dependency next to "external".

**The optional hub.**

| platform | chosen | alternative |
|---|---|---|
| Umbrel | a separate app, installed only if wanted | a compose profile: umbrelOS never enables one, and there is no settings page to switch it |
| StartOS | a toggle action; its interface and daemon appear when it is on | |

**UI login.**

| platform | chosen | why |
|---|---|---|
| Umbrel | `${APP_PASSWORD}`, provisioned as a file by `init` | the password the dashboard already shows, behind Umbrel's own login at `app_proxy` |
| StartOS | the UI's own first-run setup code, shown by an action; the owner then chooses the password | only the scrypt hash is stored, as the StartOS recipe asks for app logins |

On StartOS, a generated password returned by an action was the alternative. It would keep a cleartext
password on a volume. The OS proxy's basic auth would also lock out the MCP's bearer clients if it were
applied there.

**Testing without the platforms.**

- **Umbrel:** umbrelOS's dev environment needs privileged Docker, not rootless, so `test-umbrel-apps.sh`
  reproduces umbrelOS's install instead:
  - the app folder is copied into `app-data/<id>` as the box user;
  - `docker compose --compatibility -p <id>` gives the `<id>_<service>_1` names;
  - one shared network;
  - `exports.sh` is sourced with a `derive_entropy`;
  - `${APP_PASSWORD}` and `${APP_SEED}` are set;
  - a reverse proxy adds X-Forwarded-*.
- **StartOS:** needs a VM (no KVM for this user). `test-startos.sh` builds and inspects the real `.s9pk`
  files, then runs the package's own container spec (`startos/spec.ts`, the data `main.ts` uses) on
  Docker as StartOS runs it:
  - one root-owned volume, mounted by sub-path;
  - one shared network namespace;
  - init as a one-shot;
  - image users.
- **Neither** replaces an install on a real box. That needs a box Mike chooses.

## Side-load (a pilot, when Mike approves)

- **Umbrel:** `packaging/umbrel/bundle.sh` writes `dist/umbrel/`: the store folder, `images-amd64.tar`,
  `images-arm64.tar` and `SHA256SUMS`. See its README.txt. umbrelOS adds community stores by git URL, so
  the store folder goes into a private repo on the LAN. That step is untested here.
- **StartOS:** in the StartOS UI, System → Sideload a service, with `dist/startos/xbt-agent-wallet_x86_64.s9pk`
  (or `_aarch64`). The package is signed with the workspace's developer key, not a Start9 registry key.

## Not done, and gaps

- No install on a real Umbrel or StartOS box (needs Mike). The StartOS build targets StartOS 0.4
  (`osVersion` 0.4.0-beta.10 in the manifest, start-sdk 2.0.9).
- The XBT node:
  - on Umbrel, a stand-in, **amd64-only**, until CMP-098 (documented dependency: same `APP_XBT_KNOTS_*`);
  - on StartOS, an external connection until CMP-099;
  - no Electrum fallback (AGP-028).
- The hub creates the node wallet named `hub` on start and shows a receive address on the wallet UI Hub
  page (and `/readyz`). Funding is send-to-address; no terminal.
- On Umbrel the hub reads `APP_HIDDEN_SERVICE` (umbrelOS gives every app, including a second app, a
  hidden service via app_proxy) and shows it as `tor` on `/readyz` and the Hub page. On StartOS, Tor is
  the owner's choice per interface.
- Token rotation: the wallet UI Agents page writes a new token into `run/ui/mcp-http-token`; the MCP reads
  it on every request, so the old token gets 401 at once. The MCP has no rotation endpoint (docs/CONTAINER.md
  §10). StartOS also keeps the delete-and-restart action.
- The StartOS package's text is English only; other locales fall back to it. Translations, gallery images
  and icons are store-submission work.
- The images are referenced by tag (`:0.1.0`) and side-loaded with `docker load`. A store needs registry
  images pinned by digest (`dist/oci/IMAGES.md` has the index digests).
