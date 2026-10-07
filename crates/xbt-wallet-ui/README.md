# xbt-wallet-ui

The agent wallet's web UI, for a box with no terminal (Umbrel, StartOS), from AGP-039. It lets the owner:

- set and review the policy: budgets, per-counterparty caps, the allowlist, the human threshold, routing limits and the hot-key cap;
- approve or deny payments above the threshold (replacing `agentwallet-approve`);
- see balances and the hot-key cap status;
- see channels (open, pending, closed, refunded), with the close report (including `payeeFee`) and the refund ETA;
- see the signature log and its anchor verification;
- sweep and rotate the hot key, signed by the human;
- see the hub's status and the xbt-compute node/hub status, and fund this box's hub (receive address, no terminal);
- rotate the agent MCP token from the Agents page (no terminal, no restart);
- run a first-time setup wizard (the approval key, the policy template, the wrapping key and backup).

The UI is a separate process that talks only to the signer socket, as the MCP server does. It never
holds a wallet key or the approving key. The UI binary does not link the signer's key-handling code.

## Run

```bash
cargo build --release -p xbt-wallet-ui
XBT_UI_BIND=0.0.0.0:8480 XBT_UI_SIGNER_SOCK=~/wallet/.run/signer.sock XBT_UI_DATA_DIR=~/wallet-ui \
  XBT_UI_PASSWORD_FILE=/run/secrets/ui-password target/release/xbt-wallet-ui
```

Without a password source, the first start prints a one-time setup code and writes it to
`$XBT_UI_DATA_DIR/setup-code` (0600). The first visit needs that code to set the password.

| variable | default | meaning |
|---|---|---|
| `XBT_UI_BIND` | `127.0.0.1:8480` | listen address |
| `XBT_UI_SIGNER_SOCK` | `B2_SIGNER_SOCK`, else `$B2_ROOT/.run/signer.sock` | the signer socket (a path, or `tcp://127.0.0.1:PORT`) |
| `XBT_UI_DATA_DIR` | `$XBT_DATA_DIR/ui`, else `./xbt-wallet-ui` | the login hash and the setup code |
| `XBT_UI_PASSWORD_FILE` / `$CREDENTIALS_DIRECTORY/xbt-ui-password` / `XBT_UI_PASSWORD` | | the platform's password: a file (StartOS config, Docker secret), systemd `LoadCredential`, or env (Umbrel `${APP_PASSWORD}`; removed from the environment once read) |
| `XBT_UI_BASE_PATH` | `/` | a proxy's path prefix (the cookie path; prefixed and stripped request paths both work) |
| `XBT_UI_SESSION_IDLE_S` / `XBT_UI_SESSION_MAX_S` | 900 / 28800 | session lifetimes |
| `XBT_UI_SECURE_COOKIE` | auto | `Secure` cookie: `1` always, `0` never, auto when `X-Forwarded-Proto: https` |
| `XBT_UI_ALLOW_IPS` | all | peers allowed to connect (IPs or prefixes such as `10.21.0.`), e.g. only the box's app proxy |
| `XBT_UI_SETUP_OPEN` | 0 | `1`: the first-run password setup needs no code (the platform proxy already authenticated the owner) |
| `XBT_UI_HUB_URL` | | this box's xbt402 hub; its `/healthz`, `/readyz` and `/x402/supported` are shown on the Hub page |
| `XBT_UI_CMP_URL` | | xbt-compute's node/hub status page, linked from Overview and Hub |
| `XBT_UI_CMP_STATUS_URL` | | xbt-compute's status JSON (e.g. its `/readyz`, CONTRACT §U), shown as a compact tile |
| `XBT_UI_MCP_URL` | | MCP endpoint(s) shown on the Agents page |
| `XBT_UI_MCP_TOKEN_FILE` | `$XBT_DATA_DIR/run/ui/mcp-http-token`, else `<data dir>/secrets/mcp-http-token` | the bearer token shown on Agents. The UI owns it and rotates it there (atomic replace, mode kept, never world-readable); the MCP only reads it (AGP-042) |

`GET /healthz` is always 200. `GET /readyz` is 200 when the signer answers, else 503. Neither needs
a login, and neither reveals wallet state.

`xbt-wallet-ui sign --key FILE --message-hex HEX` and `xbt-wallet-ui pubkey --key FILE` let the owner
sign on another device, with the key's backup file (32 raw bytes or 64 hex, the format
`agentwallet-approve` uses).

The MCP server can wait for the approval: with `XBT_MCP_APPROVAL_WAIT_S=N`, an over-threshold
`xbt402_pay` waits up to N seconds. Once the owner approves in the UI, it returns the paid result.

## Stack: the options and the choice

| | server-rendered HTML from Rust (chosen) | a small SPA (Svelte/Preact) embedded as assets | a TUI in the browser (ttyd + xterm.js) |
|---|---|---|---|
| binary | 0.79 MB aarch64, 0.82 MB armv7, 0.88 MB x86_64 (static musl, `release-small`) | the same server plus a 40–150 kB JS bundle and a node toolchain at build time | a pty server plus about 300 kB of xterm.js, and a TUI to write |
| arm/v7 and small boxes | tiny_http, no async runtime; about 1 MB RSS idle | the same server; the phone does more work | a pty and a process per session |
| security surface | no JSON API for changes, only form POSTs with CSRF tokens; strict CSP (`script-src 'self'`, no inline script, no eval); one 20 kB script, used only for keys and signing | a JSON API, so CORS and CSRF on every endpoint; larger third-party dependency trees | a shell-like surface; hard to put behind the proxy's auth |
| accessibility | semantic HTML, labels, keyboard focus, readable without JS (JS is needed only to sign) | depends on care; broken without JS | poor: screen readers and phones |
| offline, Tor, proxies | relative URLs, no external resources; works on an .onion and under any prefix | the same only with care (router base paths) | WebSocket through Tor and proxies is fragile |
| maintenance | one Rust crate in the workspace; the pages are functions | two toolchains, a lockfile of npm dependencies | little code, but no real UI |

Templates are plain Rust with one escaping helper (`html::esc`). askama and maud were also available,
but they add proc-macro dependencies for about 15 pages. Everything user-controlled goes through
`esc`, and the CSP blocks any inline script that slipped through.

## Security model

- **Who can do what.** The UI login (scrypt, N=2^15; throttled at 5 failures a minute) lets someone
  see the wallet, deny requests, close channels and ask for refunds.

  Anything that raises what the wallet may spend, or moves or exports keys, also needs the human's
  ed25519 signature: approve, the policy, a new human key, a sweep, a rotation, the backup. The
  signer verifies that signature. The signer socket is shared with the model-facing MCP process, so
  these are new *signed* signer methods (`policy_set`, `human_key_rotate`, `rotate_hot_key_signed`,
  `backup_export`), not trust in the UI. A compromised UI process or MCP process cannot raise the
  budget or approve a payment.
- **Where the approving key lives: in the owner's browser.** The key is generated there with
  `crypto.getRandomValues` and kept in `localStorage`, XORed with a PBKDF2-HMAC-SHA512 pad of a
  passphrase (210,000 iterations, OWASP 2023+) and a MAC. New passphrases must be at least 12
  characters and are refused if they are only digits or a repeated pattern; the page shows a
  strength hint. A wrap stored at the AGP-039 cost (60,000) unlocks once and is re-wrapped at
  210,000. The owner writes down its 64-hex backup once. Only the public key goes to the box
  (`human_key_enroll`, trust on first use while no key is enrolled; after that, `human_key_rotate`
  signed by the old key).

  The message is signed in the page. `ui.js` rebuilds it from the fields shown; for a policy, it
  signs the text shown, and refuses if the displayed text differs.

  The same page accepts a signature made on another device (`xbt-wallet-ui sign`, the message's hex
  is shown), so B2's `agentwallet-approve` keys keep working.

  Options compared:

  | option | against |
  |---|---|
  | WebAuthn/passkeys | Needs a secure context (https or localhost), and Umbrel is plain http on the LAN. Authenticators sign `authenticatorData ‖ clientDataHash` with P-256 bound to an origin, not our ed25519 message, so the signer would need a WebAuthn verifier and an origin that changes with .onion and LAN names. |
  | WebCrypto Ed25519 | Also secure-context only. Pure JS works everywhere: `tests/js/crypto_test.mjs` checks it against RFC 8032, RFC 4231 and hashlib vectors, and `tests/crypto_js.rs` checks it against the signer's bytes and ed25519-dalek. |
  | a separate phone app | The strongest isolation, but a second app to build and ship. The paste-a-signature path supports it today. |

  KDF options for the wrap (AGP-041; measured on Node, Ryzen 9 9950X3D):

  | option | unlock (this host) | phone / Pi-served page | reach | install | safety | choice |
  |---|---|---|---|---|---|---|
  | **PBKDF2-SHA512 210k, already in ui.js** | 2.7 s | ~4–7 s estimated (over the ~2 s goal) | every browser, including plain-http Umbrel | none; the script is already there | OWASP 2023+; hashlib-tested | **chosen** |
  | PBKDF2-SHA512 60k (AGP-039) | 1.0 s | ~2–3 s | same | same | a 6-digit PIN is offline-bruteforceable | kept only as the migration source |
  | scrypt / argon2id in new pure JS | unknown; OWASP scrypt is 128 MB | worse on a phone tab | same if we write it | thousands of unaudited lines, no CDN | memory-hard, but new primitives (SHA-256, Salsa20) | rejected: no in-tree implementation, large audit surface |
  | WebCrypto PBKDF2 only | tens of ms | tens of ms | **secure context only** (https / localhost); Umbrel LAN is http | none | same count, native speed | rejected as the only path; Umbrel has no SubtleCrypto |

  The wrap stays pure JS so a phone on a Pi-served Umbrel page still unlocks. 210k in that JS is slower than ~2 s on a mid-range phone; that is the cost of OWASP's count without a CDN or a new KDF.

  The trade-off: the key protects against the model and agents, against a stolen or compromised box
  disk, and against the signer and MCP processes. It does not protect against a fully compromised
  UI server that serves malicious JavaScript to an unlocked browser. That process holds no key, is
  separate from the MCP, and serves only its embedded assets under a strict CSP. For the highest
  assurance, sign on another device.
- **Sessions and CSRF.** A 32-byte session id in an `HttpOnly; SameSite=Strict` cookie (`Secure`
  behind https). Sessions end after 15 minutes idle and 8 hours in total, with at most 16 live. Each
  session has its own CSRF token, checked on every POST, and a POST marked `Sec-Fetch-Site:
  cross-site` is refused.

  Headers: `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self';
  img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri
  'none'`, plus `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer` and `Cache-Control:
  no-store`. Bodies are capped at 256 kB.
- **Models and agents never reach the UI.** None of the UI's methods is an MCP tool: they are in the
  MCP's `FORBIDDEN` list, which its tests check. The UI has its own port, login and cookie; the MCP
  has none of them.

  On a box, bind it to the app proxy's network and set `XBT_UI_ALLOW_IPS` to the proxy. An agent
  that can reach the port still needs the password, and nothing it can do there spends without the
  human's key.
- **An xbt402 approval is a one-time grant.** The human signs (token, origin, max_sats, expiry). The
  signer marks the token approved. The agent's next `xbt402_pay` of the same URL, method and
  `max_sats` pays under it once, as B2's `approve` does (`human = true`), and the grant survives a
  "pending" first call while a channel's funding confirms. A deny or revoke drops it.

  Other tokens keep B2's `approve`, which pays at once.

## Tests

```bash
cargo test -p xbt-wallet-ui          # ui_http (auth, CSRF, headers, proxies, every action), crypto_js, browser (headless Chrome)
node crates/xbt-wallet-ui/tests/js/crypto_test.mjs
scripts/ui/regtest_ui.sh             # real regtest: MCP waits, the UI approves, paid, closed on chain
scripts/ui/verify_agp039.sh          # all of the above plus the signer and MCP suites
```
