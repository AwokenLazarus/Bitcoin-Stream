# XBT Agent Wallet for StartOS

Technical reference for this package (AGP-040). The user guide is `instructions.md`; the design, the tests
and the choices are in `../../README.md` and the container standard in `docs/CONTAINER.md` (xbt-rs).

## Containers

`startos/spec.ts` lists them as data; `startos/main.ts` turns that into StartOS daemons, and
`../test/startos_regtest.py` runs the same spec on Docker. Volume `main` is the data dir (docs/CONTAINER.md §1);
volume `startos` holds `store.json` (the node connection, the hub switch) and is mounted by nothing.

| daemon | image | user | mounts of `main` | ready |
|---|---|---|---|---|
| init (oneshot) | xbt-init | root | all | exits 0 |
| witness | xbt-anchor-witness | xbt-anchor-witness | witness, run/anchor | `xbt-anchor-witness healthcheck` |
| signer | xbt-signer | xbt-signer | signer, run/signer, run/anchor (ro) | `xbt-signer healthcheck` |
| mcp | xbt-wallet-mcp | xbt-wallet-mcp | mcp, run/signer (ro), run/ui (ro) | port 33510 |
| ui | xbt-wallet-ui | xbt-wallet-ui | ui, run/signer (ro), run/ui | port 8480 |
| hub (if enabled) | xbt402-hub | xbt402-hub | hub | port 9480 |

Health check `wallet-ready`: the MCP's `/readyz` (200: synced and unlocked; 503: loading, with the reason).

## Interfaces

`ui` (web UI, port 8480, external 80), `mcp` (API, 33510, path `/mcp`, masked), `hub` (API, 9480, only when
enabled). StartOS terminates TLS and adds X-Forwarded-Proto, so the UI's cookie is `Secure` over https.

## Actions

| action | what |
|---|---|
| node-config | node RPC host, port, user, password, chain (a critical task until set) |
| ui-setup-code | the UI's one-time setup code (`main/ui/setup-code`), while no password is set |
| agent-connection | the MCP addresses and the bearer token (`main/run/ui/mcp-http-token`) |
| rotate-agent-token | delete the MCP token and restart: xbt-init makes a new one. The web UI Agents page rotates it with no restart (the UI owns the token; the MCP only reads it). |
| hub-toggle | enable or disable the xbt402 hub |
| reset-ui-password | delete `main/ui/password.scrypt` and restart |

## Build

`../build.sh` (needs the images loaded by `scripts/oci_build.sh --load`, start-cli 2.1.0 and the
`../tools/tar2sqfs` shim) writes `dist/startos/xbt-agent-wallet_{x86_64,aarch64}.s9pk`. Never `make publish`.
