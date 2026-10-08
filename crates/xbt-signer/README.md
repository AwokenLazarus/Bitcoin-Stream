# xbt-signer

B2's agent-wallet signer in Rust (AGP-027). One process holds every key. The model-facing process
(B2's Python MCP server, or a Rust payer through `client::RemoteSigner`) only calls its socket. The
signer carries:

- B2's policy engine;
- sealed hot and channel keys;
- the write-ahead channel open (P1) and the minConf wait (P2);
- refund custody at expiry (the watcher);
- the AGP-022 close-change retry;
- the hash-chained signature log, anchored with B2's witness.

It uses B2's socket protocol (`b2/docs/B2_SIGNER_API.md`) and B2's on-disk formats, so either signer
runs behind either client and opens the other's files.

Reference: B2 `agp-next2` `b4f2fe5` (`agentwallet/signer.py`, `channels.py`, `hot.py`, `keystore.py`,
`sigaudit.py`, `anchor.py`, `policy.py`, `routing.py`, `xbt402.py`, `stream.py`, `netparams.py`).

## Run

```bash
cargo build -j2 --release -p xbt-signer --bins
B2_HOT_KEYFILE=/secure/hot.key B2_ANCHOR_SOCK=/run/witness/w.sock B2_RPCPORT=8332 B2_DATADIR=~/.bitcoin \
  target/release/xbt-signer --root ~/wallet          # policy.json in ~/wallet, state in ~/wallet/.run
target/release/xbt-signer --root ~/wallet --check    # every start-up check (chain, P3, keys, anchor), then exit
target/release/xbt-anchor-witness serve --store /var/lib/witness --sock /run/witness/w.sock   # its own user
target/release/xbt-anchor-witness check --store /var/lib/witness --log ~/wallet/.run/signatures.jsonl
```

The environment is B2's:

- `B2_ROOT`, `B2_DATADIR`, `B2_RPCPORT`, `B2_WALLET`;
- `B2_CHAIN` (must agree with the node);
- `B2_SIGNER_SOCK`: a path, or `tcp://127.0.0.1:PORT` (see Portability);
- `B2_HOT_KEYFILE` or `B2_HOT_PASSPHRASE`: exactly one; the passphrase is removed from the environment once read;
- `B2_HOT_ALLOW_PLAINTEXT=1`: tests only;
- `B2_ANCHOR_SOCK`, `B2_WATCH_INTERVAL`, `B2_HOT_SCAN`, `B2_CALLS_JSONL`, `B2_BODY_DIR`, `B2_BODY_CAP`.

## Socket methods

### B2's methods

Every B2 method listed below behaves as in B2:

- `balance`, `quote_payment`, `pay`, `approve`, `history`;
- `health`, `chain_backend`, `channels`, `hot_address`, `notice_hot_txid`, `fund`;
- `open_channel`, `sign_state`, `xbt402_pay`;
- `xbt402_request_auth`, `xbt402_sign_state_a3`;
- `xbt402_sign_state_adaptor`, `xbt402_resolve_lock`, `xbt402_void_lock`, `xbt402_adopt_lock`, `xbt402_recover_lock` (below);
- `routing_status`, `close_channel`, `xbt402_refund` (alias `refund_channel`), `watch_tick`;
- `rotate_hot_key`, `sweep_hot`, `signatures`, `anchor_now`, `anchor_status`, `hot_reconcile`.

`xbt402_pay` includes streamed results (`xbt402-merkle-v1`).

### New for an external payer

These are B1's `ChannelSigner` interface, so a client never holds a payer key. Each one is
policy-checked where it raises the signed amount.

| method | params | result |
|---|---|---|
| `xbt402_new_key` | `origin` | `{pub}`: a fresh payer key, sealed on disk at once as `pending:<origin>` |
| `xbt402_attach` | `origin`, `params` (ChannelParams `to_dict`) | `{chan, dest}`: binds the issued key to the funded channel (open at once); `<origin>/next` is a rollover's successor |
| `xbt402_sign_state` (= `sign_state`) | `chan` or `dest`, `cum` | policy on `cum - used`, then `{verdict, chan, cum, sig}` |
| `xbt402_sign_rollover` | `chan`, `amount`, `next_spk`, `next_capacity` | policy on the increase, then `{sig}` (audit kind `channel_rollover`) |
| `xbt402_sign_conditional` | `chan`, `uncond`, `hash`, `amount`, `csv_delta` | policy on `uncond + amount - used`, then `{sig}` |
| `xbt402_sign_close` | `chan` | `{sig}` (close authorisation) |
| `xbt402_sign_refund` | `chan` | `{hex, expiry, to}`: the CLTV refund, always to the hot key |
| `xbt402_mark_closed` | `chan`, `txid` | the channel's record after its change was learned (AGP-022) |
| `tx_confirmations` | `txid`, `vout` | `{confirmations, height}` (read-only; for the payer's P2 wait) |

`client::RemoteSigner` implements `xbt402::signer::StateSigner` and `xbt402::client::Wallet` over
these methods: `Client::new(..).with_signer(Arc::new(RemoteSigner::new(sock)))`.

### Routed payments (AGP-034)

`client::RemoteSigner` also implements `xbt402::signer::RouteSigner` over B2's lock methods, so
`xbt402::route_client::RoutePayer::new(hub, cfg, Arc::new(remote.clone()), Arc::new(remote), ..)` routes
with every key in the signer. Before each pre-signature the signer applies the routing policy (hub
allowlist, fee cap with carry, `max_lock_sats`, the 24 h routed budget over resolved plus pending
locks) and then the policy engine on the increase. The crypto is `routing::Xbt402Adaptor`, xbt402's
ECDSA adaptor (AGP-026, wire-compatible with B1 `adaptor.py`), the default `channels::AdaptorScheme`.

| method | params | result |
|---|---|---|
| `xbt402_sign_state_adaptor` | `chan`, `cum`, `point` (T), `route` (`hub`, `amount`, `fee`, `lockId`) | routing policy, engine, then `{verdict, adaptor, point (T1), tweak (r), cum}`; the lock is written ahead |
| `xbt402_resolve_lock` | `chan`, `secret` (t + r or t) | `{t}` |
| `xbt402_void_lock` | `chan` | `{voided}` |
| `xbt402_adopt_lock` | `chan`, `cum` | `{adopted}` (only a given-up lock's own cum, with no lock pending) |
| `xbt402_recover_lock` | `chan`, `txid`, `blockhash`, or `hex` (new: the raw close) | `{t}`; only a secret opening the stored T1 counts |
| `routing_status` | | policy, 24 h spend, pending locks, `adaptor: available` |

### For the web UI (AGP-039)

These are the methods behind `xbt-wallet-ui` (see its README). Every one that raises what the wallet
may spend, or that moves or exports keys, needs a signature by the human's ed25519 key. The domains
are in `approval.rs`. None of these methods is an MCP tool.

| method | params | result |
|---|---|---|
| `approvals` | | pending, approved (xbt402 grants) and expired approval tokens with dest, amount, memo, url, expiry |
| `approval_status` | `token` | `pending`, `approved`, `used`, `denied`, `expired` or `unknown` |
| `deny_approval` | `token`, `reason`, `expiry`, `signature` | drops the token. AGP-063 W3: a live approval needs the human signature over `deny_message(token, expiry)`, so the agent cannot refuse for the owner; an expired one is dropped without one |
| `policy_get` / `policy_validate` | / `policy` | the file, its SHA-256 and the values in force; the validator's `errors` (the engine's parse errors first) and `warnings` |
| `policy_prepare` | `policy` | the canonical text, `prev_sha256`, `expiry`, the message to sign, and a diff; the human key is kept |
| `policy_set` | `text`, `prev_sha256`, `expiry`, `signature` | writes policy.json atomically (the old file is kept as `.prev`) and puts it in force without a restart; start-only keys are reported in `pending_restart` |
| `human_key_enroll` | `pubkey`, `code` | the first human key, only while none is enrolled. AGP-063 W4: `code` is the one-time enrolment code the signer prints to stderr (the Umbrel app log, StartOS Logs) and writes to `.run/enroll-code` (0600); five wrong codes replace it |
| `human_key_rotate` | `pubkey`, `expiry`, `signature` (by the current key) | the new human key |
| `rotate_hot_key_signed` | `expiry`, `signature` | `rotate_hot_key`, logged under `human:rotate_signature`. AGP-063 W3: `rotate_hot_key` itself is this method now |
| `backup_export` | `backup_pass`, `expiry`, `signature` | policy, sealed keys, books and logs, plus the wrapping secret sealed under the backup passphrase |
| `keystore_status`, `channel_reports` | | the wrapping-key source and mode; each close's report (AGP-029: cum, unpaidMsat, payeeFee, payeeNet) |

An over-threshold `xbt402_pay` stores its approval as `kind: "xbt402"` with its url and method.
`approve` of such a token grants it: nothing is paid yet. The agent's next `xbt402_pay` with the same
url, method and `max_sats` then pays under it once, with `human = true`, and returns `approved: true`.
Other tokens keep B2's `approve`, which pays at once. `close_channel` now returns B2's AGP-029
`close_report`.

### Lightning: `rail=ln` (AGP-048)

`ln_pay {invoice, max_sats, description?}` and `ln_status {}`. The signer pays XBT Lightning invoices
through a Lightning Fork (LND) node, under B2's policy: `dest` is `ln:<payee node id>` (put it on the
allowlist), and max_per_tx, the budgets, per-counterparty, velocity, split-bypass and the human
threshold apply to the invoice amount plus the routing-fee limit. An over-threshold invoice becomes an
approval token; the human's `approve` grants it and the agent's same `ln_pay` then pays, once.

Before anything reaches the router (`src/ln.rs`, `src/bolt11.rs`):

1. the invoice, decoded and signature-checked here: this chain's prefix (`lnbc` / `lnbcrt`), feature bit
   512 (`option_blake2b`; without it the invoice is SHA-256 Lightning's), an amount, at least
   `ln.min_expiry_s` left, `min_final_cltv` within `ln.max_cltv_blocks`, the caller's `description`
   (plain or hashed) when given;
2. the LN node's chain identity against the signer's own Knots node: its network, its hash at the
   anchor height (961,640 pinned on mainnet; `ln.anchor_height` / `ln.anchor_hash` elsewhere), its tip,
   its own bit 512, synced;
3. the node's `DecodePayReq` must match field by field;
4. only channels that are active, `unified_sigs`, not taproot, not zero-conf, and funded at or above
   the split (961,632 on mainnet; `ln.split_height` elsewhere) go in `outgoing_chan_ids`, and only once
   their **funding transaction is proven on the signer's own node** (AGP-049, `src/ln_funding.rs`): the
   transaction at the short channel id's block position is the channel point's, its output is the
   channel's P2WSH of its capacity, every input's signatures carry sighash **0x21** and every input's
   coin was confirmed at or above the split. LND's `unified_sigs` flag is not trusted for this. The
   signer's node needs `txindex=1` to look up the inputs; an unprovable channel carries nothing;
5. the node's exposure: while it holds more than `ln.exposure_cap_sats` (channel local balances, HTLCs
   in flight and its on-chain coins), `ln_pay` refuses (`ln_exposure_cap`); mainnet requires a cap;
6. the send rate: at most `ln.max_sends_per_hour` payments reach the router per hour, failed ones
   included (`ln_rate_limit`; LND has no per-macaroon rate limit);
7. the watchtowers (`GET /v2/watchtower/client`): Lightning Fork's wtclient identifies a tower's chain
   only by the genesis hash, which SHA-256 Bitcoin shares, and no tower advertises a chain feature, so
   every tower is unverified unless listed in `ln.trusted_towers`. `ln.tower_policy` `warn` (the default
   off mainnet: a loud warning in `ln_status` and `ln_pay`) or `refuse` (mainnet's default:
   `ln_tower_chain`);
8. the macaroon, read from the file (`src/macaroon.rs`): `ln_status` shows its permissions and
   caveats; on mainnet one granting `onchain:write`, `macaroon:*` or `signer:generate` is refused
   (`ln_macaroon`);
9. HTLCs under CLTV: outgoing HTLCs the node started that the wallet did not book (sent outside it)
   hold funds until their expiry and count against what is left of the daily and weekly budgets
   (`ln_htlc_lock`) until they resolve. The wallet's own in-flight payments stay booked, with the CLTV
   height they can hold funds until, and a FAILED payment with an HTLC still out stays booked.

The worst case is booked to the ledger and to `.run/ln_payments.json` before the send; a settled
payment's booking becomes what it cost, a failed one's goes (the audit log keeps `ln_amend`). A payment
left in flight is reconciled from the node's payment list (by `ln_status`, the next `ln_pay`, the
watcher) and blocks new LN payments until then. A booking released because the node had no record of it
(a crash before the send, or a send that errored) is watched until its invoice has expired (+10 min):
if the node records it late, it is booked again and settled or kept in flight (AGP-048 risk 7); one
whose HTLC is on a channel is not released at all. Each settled payment is a `ln_payment` line in the
signature log whose `sig_sha256` is the payment hash (the log holds the SHA-256 of the preimage).
The wallet never opens channels; `ln_status` lists the node's coins below the split, which must never
fund one.

policy.json `ln`: `enabled` (default off), `max_fee_base_sats` (10), `max_fee_ppm` (5000),
`min_expiry_s` (60), `max_cltv_blocks` (1008), `timeout_s` (60), `anchor_height`, `anchor_hash`,
`split_height`, `max_tip_lead` (2), `require_description` (false), `exposure_cap_sats` (0: none, not
allowed on mainnet), `max_sends_per_hour` (60; 0: none), `tower_policy` (`warn` / `refuse`; default
`refuse` on mainnet), `trusted_towers` (tower public keys, hex). Environment: `B2_LN_REST`
(`https://host:port`; plain http only on loopback), `B2_LN_MACAROON`, `B2_LN_TLS_CERT` (LND's
`tls.cert`: the connection is pinned to exactly that certificate). A bad LN configuration shuts the
rail (`ln_config`), not the signer. Regtest proof: `scripts/ln_rail_regtest.sh`.

**The macaroon.** Bake one with only what the rail needs and a lifetime:

    lncli bakemacaroon --save_to=rail.macaroon --timeout=2592000 info:read offchain:read offchain:write onchain:read

`offchain:read` also covers the watchtower list. **IP caveats do not bind REST callers.** LND checks
`ipaddr` / `iprange` against the gRPC peer, and its REST gateway is an in-process gRPC client dialling
`127.0.0.1`: over REST, `--ip_address=127.0.0.1` passes every caller and any other address refuses
every call (shown on the lab, S12; over gRPC the caveat binds). So for this REST client, restrict the
REST listener itself: bind `restlisten` to a private interface or loopback (with an SSH or WireGuard
tunnel) and firewall it to the signer's host. The signer's own `max_sends_per_hour` is the rate limit;
LND has none per macaroon.

## Budget integrity and privileged methods (AGP-063)

Every signature that raises the signed amount is booked as the signed delta (`xbt402:<chan>:<cum>`)
before it is sent, never the seller's `charged`. The budget sums are held to that increase,
including a channel's dust floor (`PolicyEngine::evaluate_booking`). `minCapacity` above the owner's cap is
`deny/min_capacity`. A negative payment or amend is refused. `fund`, `open_channel`,
`xbt402_attach` and `xbt402_sign_rollover` are bound to an issued key, the seller's verified payTo
and the owner's bounds. `rotate_hot_key` and a live `deny_approval` need the human signature, and
the first `human_key_enroll` needs the one-time code. Passphrase blobs use scrypt N=2^17 with
`log_n`. Details, error codes and the wire changes are in the workspace README section
"Agent-wallet budget integrity and privileged methods (AGP-063)".

## Files and durability (AGP-055)

One process owns a wallet directory. The files are B2's, byte format included: a directory written
by either signer opens in the other (`tests/custody_compat.rs`, `vectors/rust_routed_wallet.json`).

Per routed lock (pre-sign + resolve) the signer writes `channels.json` twice (temp file, fsync,
rename, fsync of the directory: the lock is durable before its pre-signature leaves) and appends one
line each to `.run/signatures.jsonl`, `.run/routing.json` and `.run/ledger.payments.jsonl`, and two
to `.run/audit.jsonl`: 9 fsyncs and 2 renames. `channel_keys.json` is rewritten only when a key is
added or dropped.

- `.run/routing.json` (routed spend, the 24 h routing budget) and `.run/ledger.payments.jsonl` (the
  policy ledger's payments) are append-only logs (`src/applog.rs`): a header line
  `{"kind":...,"v":1}`, then one JSON object per line, each fsynced. A last line without its newline
  is a crash mid-append and is cut at start; any other line that does not parse stops the signer
  from starting (it never reads as a shorter log). A log is compacted (temp file, fsync, rename)
  once it holds over twice the rows still in use plus 1,024: spend rows are in use for 7 days,
  payments for the policy's longest window plus a day. `.run/audit.jsonl` keeps every commit.
- `.run/ledger.json` holds the pending approvals and `"payments_log": "ledger.payments.jsonl"`; it
  has no `payments` key. A settled or failed Lightning booking is a line
  `{"amend": txid, "amount_sats": n | null}` in the payments log. Files from before AGP-055 are
  converted at the first start.
- A resolved lock is remembered in its channel record (`resolved`, the last 16, key
  `lock:<chan>:<cum>`) and booked once per key in both logs; a start books any that a crash left
  unbooked. In the ledger a routed lock's `txid` is that key.
- `src/fsx.rs` has the durable steps (write, fsync, rename, truncate, directory fsync) every file
  goes through, and `fsx::probe`, which counts them per thread and lets a test make any one the last
  thing the process does (`tests/lock_persist.rs`). Nothing in the signer arms it.

## Not ported

Each of these answers that it is unavailable:

- **The forward rail** (`forward.py`): `forward_status` answers `ported: false`, and `forward_recover`
  is refused. `xbt402_pay` refuses an offer with `extra.forward` before any payment
  (`deny/forward_disabled`).
- **The CSV treasury and the presigned vault**: `fund_treasury`, `recover_treasury` and
  `recover_vault` answer `ok: false`, and `balance` reports `vault`/`treasury` as null.
- **The Electrum light backend** (AGP-024). With `B2_CHAIN_BACKEND=electrum` the signer refuses to
  start; AGP-028 owns Electrum.

## Portability

The library has no platform-specific dependencies:

- No OpenSSL: HTTP is `ureq` with rustls/ring, the workspace's existing choice.
- No async runtime: blocking threads, like B2.
- File modes (0600/0640) are applied under `cfg(unix)` (`fsx.rs`).
- The socket (`ipc.rs`) is a Unix-domain socket on Unix, which is B2's protocol and is
  access-controlled by its 0600 mode. On every platform it can also be `tcp://127.0.0.1:PORT`,
  bound to loopback only.

`cargo check -p xbt-signer --bins` passes for:

- Linux on x86_64, aarch64, armv7 and riscv64 (glibc) and on x86_64, aarch64 and armv7 (musl);
- macOS on x86_64 and aarch64;
- Windows on x86_64 (gnu).

The C compiler for libsecp256k1 and ring is zig. An aarch64 binary links to 4.6 MB.

**What cannot be fully portable:** on Windows, std has no Unix sockets, so the signer listens on
loopback TCP. Any local user can connect to it, whereas a 0600 socket file restricts it to the
signer's user. Run it on a single-user host or firewall the port per user, until a named-pipe
transport is added. File modes are no-ops there; protect the run directory with ACLs.
