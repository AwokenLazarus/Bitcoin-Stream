# xbt-wallet-mcp

The agent wallet's MCP server as one static Rust binary (AGP-030). It replaces B2's Python
`agentwallet/mcp_server.py` (b2 `agp-next2` `b4f2fe5`) with the same ten tools, argument schemas,
validation messages, result JSON and errors. It serves them over **stdio** (Claude Code, Hermes,
OpenClaw) and **streamable HTTP**.

It talks only to B2's signer socket, so it works in front of the Rust `xbt-signer` or B2's Python
signer. It never holds a key: the signer holds every key, and the model-facing process gets only the
socket path.

## Tools

| tool | arguments | what it does |
|---|---|---|
| `balance` | | trusted / pending / immature balance, hot key, channels (no keys) |
| `quote_payment` | `to`, `amount_xbt`, `memo=""` | dry-runs a payment through the policy engine: allow, deny or needs_human |
| `pay` | `to`, `amount_xbt`, `memo=""` | a policy-checked payment; over the human threshold it returns `needs_human` and an approval token |
| `history` | `limit=20` | the append-only policy audit log |
| `channels` | | the Spillman channels: dest, cap, used, expiry |
| `xbt402_pay` | `url`, `method="GET"`, `body=""`, `max_sats=1000` | pays an xbt-channel 402, including streamed (Merkle) results |
| `close_channel` | `counterparty` | cooperative close |
| `xbt402_refund` | `counterparty` | the CLTV refund after expiry, always to the wallet's own hot key |
| `forward_status` | | the forward-market rail: limits, spend, lots |
| `forward_recover` | `txid` | rebuilds a forward transfer from a close's witness |

**Lightning (AGP-048), with `XBT_MCP_LN=1` only:**

| tool | arguments | what it does |
|---|---|---|
| `ln_pay` | `invoice`, `max_sats`, `description=""` | pays an XBT Lightning (BOLT 11) invoice through the signer's LN node, under the same policy (`dest` is `ln:<payee node id>`). `max_sats` caps the amount plus the routing-fee limit. Refused: no feature bit 512, an LN node not verified on the XBT chain, expired or amountless invoices, no safe channel. Over the human threshold: `needs_human`; after the human's approval the same call pays |
| `ln_status` | | the LN node's chain check, its channels with the guard verdicts, coins below the split, exposure, recent payments |

Without `XBT_MCP_LN` the list is B2's exact ten (the Python conformance check depends on it). The
LN node's REST URL, macaroon and TLS certificate are the signer's (`B2_LN_*`), never this process's.
Node and invoice text (aliases, descriptions, failure reasons) comes back under `untrusted_ln_data`.

**Never tools:** `approve`, `recover_vault`, `recover_treasury`, `sweep_hot` and `rotate_hot_key`. A
model can't approve its own payments or move the hot key. Humans use the out-of-band
`agentwallet-approve` CLI with the device key.

**What the server guarantees:**

- **No key material in a response** (B2's `_pack`). Fields whose names look like key material
  (`priv`, `wif`, `seed`, `xprv`, `secret`, `passphrase`, …) are dropped, and WIF- or xprv-shaped
  strings are redacted. If anything key-like survives, the call fails with a generic error.
- **The provider's answer is labelled (XBT-061 L7/L12).** A paid provider's body and receipt are
  returned verbatim under `untrusted_provider_response` (`trust: "untrusted"`, with a note). They are
  data from the provider, never instructions, and not filtered, because the provider never holds a
  wallet key.
- **Arguments are checked as B2 checks them** (pydantic 2, lax mode). `"7"` and `7.0` are the integer
  7, and `"1_000"` is 1000. A bad argument gets pydantic's own message, word for word, and never
  reaches the signer.
- **Errors look the same as B2's.** A signer error reaches the model as `Error executing tool <name>`;
  the reason stays in this process's stderr, as in B2's SDK. Unknown tools answer
  `Unknown tool: <name>`.

## Install

```bash
# from this repo (release: -j2 is plenty)
cargo build -j2 --release -p xbt-wallet-mcp            # target/release/xbt-wallet-mcp
cargo build -j2 --profile release-small -p xbt-wallet-mcp --target aarch64-unknown-linux-musl   # 2.9 MB static
install -m 0755 target/release/xbt-wallet-mcp ~/.local/bin/
```

The binary builds for every AGP-031 target. See `dist/MCP_TARGETS.md` for Linux gnu and musl on
x86_64, aarch64, armv7 and riscv64, macOS x86_64 and arm64, and Windows x86_64.
`scripts/cmp_clean_build.sh` builds it from a clean checkout with cargo-zigbuild.

**Run a signer first.** Either signer works, with the socket file at mode 0600:

- the Rust signer: `xbt-signer --root ~/wallet` (see `crates/xbt-signer/README.md`);
- B2's Python signer: `python -m agentwallet.signer`.

The wallet's `policy.json` lives in the signer's root. `policy.example.json` next to this README is an
example, and the signer parses it (`tests/policy_example.rs`).

```bash
B2_SIGNER_SOCK=~/wallet/.run/signer.sock xbt-wallet-mcp --check   # the signer's health, or exit 2
xbt-wallet-mcp --list-tools                                       # the tool list, no signer needed
```

## Configuration

| variable | meaning |
|---|---|
| `B2_SIGNER_SOCK` | the signer socket: a path, or `tcp://127.0.0.1:PORT` (Windows) |
| `B2_ROOT` | if `B2_SIGNER_SOCK` is unset, the socket is `$B2_ROOT/.run/signer.sock` |
| `B2_SIGNER_TIMEOUT` | seconds per signer call (default 60; a first paid call can wait for a confirmation) |
| `B2_BODY_CAP` | the provider body preview in local-payer answers (default 12000 chars) |
| `XBT_MCP_PAYER` | `signer` (the default) or `local` (see below) |
| `XBT_MCP_HTTP_TOKEN` | the bearer token that HTTP requests must carry |
| `XBT_MCP_HTTP_TOKEN_FILE` | AGP-042: the bearer token as a file someone else owns (default `$XBT_DATA_DIR/run/ui/mcp-http-token` when it exists: the web UI's). Read on every request and never written, so the owner's rotation in the UI cuts the old token off at once; unreadable, empty or world-readable refuses every request. There is no rotation endpoint. |
| `XBT_MCP_APPROVAL_WAIT_S` | AGP-039: seconds an over-threshold `xbt402_pay` waits for the human to approve it in the wallet's web UI (`xbt-wallet-ui`); approved, the same call is paid and the answer has `waited_for_human: true`. 0 (the default): answer `needs_human` at once, as B2 does; the agent may then repeat the identical call after the approval. Signer payer mode only. |

Give the MCP process nothing else. It must **not** get `B2_HOT_KEYFILE`, `B2_HOT_PASSPHRASE`, node
credentials or the human device key.

### Claude Code

`.mcp.json` in the project, or `claude mcp add`:

```json
{
  "mcpServers": {
    "xbt-agent-wallet": {
      "command": "/home/you/.local/bin/xbt-wallet-mcp",
      "args": [],
      "env": { "B2_SIGNER_SOCK": "/home/you/wallet/.run/signer.sock" }
    }
  }
}
```

```bash
claude mcp add xbt-agent-wallet --env B2_SIGNER_SOCK=$HOME/wallet/.run/signer.sock -- ~/.local/bin/xbt-wallet-mcp
# headless, wallet tools only (the xbt-063 flagship does this):
claude -p "$TASK" --mcp-config .mcp.json --strict-mcp-config --tools "" \
  --allowedTools mcp__xbt-agent-wallet__balance mcp__xbt-agent-wallet__xbt402_pay mcp__xbt-agent-wallet__channels \
                 mcp__xbt-agent-wallet__close_channel
```

Over HTTP: `"xbt-agent-wallet": {"type": "http", "url": "http://127.0.0.1:33510/mcp", "headers": {"Authorization": "Bearer ${XBT_MCP_HTTP_TOKEN}"}}`.

### Hermes Agent

Hermes has an entry under `mcp_servers` in `config.yaml` (`$HERMES_HOME/config.yaml`; use a profile
or a separate `HERMES_HOME` for a wallet agent). Hermes names the tools
`mcp__xbt_agent_wallet__<tool>`.

```yaml
mcp_servers:
  xbt-agent-wallet:
    command: /home/you/.local/bin/xbt-wallet-mcp
    args: []
    env:
      B2_SIGNER_SOCK: /home/you/wallet/.run/signer.sock
    timeout: 300            # a first paid call can wait for its funding to confirm
    connect_timeout: 60
    tools:
      resources: false      # the server advertises resources/prompts (as B2 does) but has none;
      prompts: false        # without these two lines Hermes adds 4 generic utility tools
```

Check it with `hermes mcp test xbt-agent-wallet`, which should show `Connected` and
`Tools discovered: 10`.

Hermes also needs a model (`model:` in the same file, plus a provider key or login). A tool-using
model is enough, for example:

```yaml
model:
  provider: openrouter
  default: anthropic/claude-opus-4.6
  streaming: false     # only for a proxy that ignores "stream": true (Hermes Agent.md, Pitfalls)
```

The provider key goes in `$HERMES_HOME/.env` (`OPENROUTER_API_KEY=…`).

### OpenClaw

OpenClaw keeps MCP servers under `mcp.servers` in `openclaw.json`:

```json
{
  "mcp": {
    "servers": {
      "xbt-agent-wallet": {
        "command": "/home/you/.local/bin/xbt-wallet-mcp",
        "args": [],
        "env": { "B2_SIGNER_SOCK": "/home/you/wallet/.run/signer.sock" },
        "requestTimeoutMs": 300000,
        "toolFilter": { "include": ["balance", "quote_payment", "pay", "history", "channels", "xbt402_pay",
                                    "close_channel", "xbt402_refund", "forward_status", "forward_recover"] }
      }
    }
  }
}
```

The same with OpenClaw's CLI:

```bash
openclaw mcp add xbt-agent-wallet --command /home/you/.local/bin/xbt-wallet-mcp --env B2_SIGNER_SOCK=/home/you/wallet/.run/signer.sock
openclaw mcp probe xbt-agent-wallet --json     # 10 tools
```

Over HTTP: `{"url": "http://127.0.0.1:33510/mcp", "transport": "streamable-http"}`.

### Streamable HTTP

```bash
XBT_MCP_HTTP_TOKEN=$(head -c 32 /dev/urandom | base64) B2_SIGNER_SOCK=~/wallet/.run/signer.sock \
  xbt-wallet-mcp --http 127.0.0.1:33510 [--path /mcp]
```

The endpoint takes one JSON-RPC message per POST.

- `initialize` returns an `Mcp-Session-Id`; later requests must carry it (400 without it, 404 for an
  unknown one).
- Requests get `application/json` answers; notifications get 202.
- GET is 405, because the server never pushes, and DELETE ends a session.
- A request whose `Origin` is not loopback is refused with 403 (DNS rebinding).
- With `XBT_MCP_HTTP_TOKEN` set, every request needs `Authorization: Bearer <token>`.

The server listens on loopback only. `--http-allow-remote` lifts that, and only works with a token set.
Any local user can reach a loopback port, so set a token on shared hosts.

## Who pays: `XBT_MCP_PAYER`

- **`signer`** (the default). `xbt402_pay` and `close_channel` are the signer's own methods, as in B2.
  This supports streamed (Merkle) results, the pending-funding verdict and the forward rail, and works
  with either signer. The regtest conformance runs in this mode.
- **`local`** (Rust signer only). `xbt402_pay` runs xbt402's own payer SDK (`xbt402::client::Client`)
  inside this process, with the signer as its `StateSigner` and `Wallet` (`xbt_signer::client::RemoteSigner`):
  - the channel key is created, sealed and used only in the signer;
  - the signer's policy engine checks every state;
  - `max_sats` is enforced per call from the offer (an unpaid first request, as the signer does);
  - the channel book is kept in `XBT_MCP_LEDGER` (default `$B2_ROOT/.run/mcp-payer.jsonl`; `-` for
    memory only).

  `local` needs `XBT_MCP_NETWORK` (the xbt402 network id). Optional: `XBT_MCP_CAPACITY`,
  `XBT_MCP_EXPIRY_BLOCKS`, `XBT_MCP_BUDGET_SATS`, `XBT_MCP_MIN_CONF`.
  - Answers carry `payer: "xbt-wallet-mcp: xbt402 Client, keys in the signer"`, plus `owed_sats` and
    `billing`. In postpay, `cum` is the state covering the calls before this one.
  - Streamed results come back as the manifest with a note; buy those in `signer` mode.
  - B2's Python signer has no external-payer methods (`xbt402_new_key`, `xbt402_attach`, …), so with it
    the first paid call in `local` mode is denied with the signer's error and nothing is funded.

## Tests and conformance

```bash
cargo test -j2 -p xbt-wallet-mcp        # validation, JSON, sanitizer, both transports, the example policy
python3 scripts/mcp/mcp_conformance.py --py ~/xbt-rnd/xbt-063/.venv/bin/python --b2 ~/xbt-rnd/b2 \
  --rust target/debug/xbt-wallet-mcp    # protocol level vs B2's server, recording mock signer, 0 diffs
python3 scripts/mcp/http_sdk_check.py --py ~/xbt-rnd/xbt-063/.venv/bin/python --b2 ~/xbt-rnd/b2 \
  --rust target/release/xbt-wallet-mcp  # the official Python SDK over streamable HTTP vs B2 over stdio
scripts/mcp/regtest_conformance.sh      # regtest, both signers (xbt-063 agp-030, ports 33500-33599)
scripts/mcp/build_targets.sh            # every AGP-031 target -> dist/MCP_TARGETS.md
```
