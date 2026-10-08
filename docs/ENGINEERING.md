# Engineering notes (xbt-rs)

Rust rails for XBT (Bitcoin with BLAKE2b proof of work): a shared chain-primitives crate and the
xbt402 payment-channel crate (the x402 v2 XBT binding of `batch-settlement`,
`extra.assetTransferMethod: "channel"`; `xbt-channel` accepted as an alias; spec v1.1 plus the v1.2
`closeFeePayer` additions). It ports the Python references and is byte-identical to them. Built for
xbt-compute's Rust device runtime (AGP-025, owned by xbt-agentpay).

Workspace crates:

| crate | what | published |
|---|---|---|
| `xbt-primitives` | tx (de)serialization with witness, scripts, bech32/bech32m per chain, UnifiedSighash 0x21/0xA3, strict-DER low-S ECDSA (libsecp256k1), BLAKE2b header v2 + PoW + Knots retarget + most-work header chain, network ids | library (for other projects too) |
| `xbt402` | channel params, payee tweak v2, funding script, states, close, rollover, refund, v1.2 payee-pays, conditional hash locks, the 402 wire, receipts, request auth, provider verifier, payer client, ledger; the signer seam (`StateSigner` + the routing extension `RouteSigner`); hub routing (AGP-026): ECDSA adaptor locks, provider route offers, `RouteHub` + the `xbt402-hub` service, `RoutePayer` | library (+ `xbt402-hub` bin) |
| `xbt-signer` | B2's agent-wallet signer (AGP-027): keys never in the client (xbt402 `StateSigner` and `RouteSigner`), B2's policy engine and routing policy, sealed hot/channel keys, write-ahead opens, refund custody, anchored signature log; B2's socket protocol and file formats. See `crates/xbt-signer/README.md` | binaries `xbt-signer`, `xbt-anchor-witness`, `xbt-signer-payer` |
| `xbt402` | channel params, payee tweak v2, funding script, states, close, rollover, refund, v1.2 payee-pays, conditional hash locks, the 402 wire, receipts, request auth, provider verifier, payer client, ledger | library |
| `xbt-wallet-mcp` | the agent wallet's MCP server (AGP-030): B2's ten tools (same names, schemas, validation, results and errors as `mcp_server.py`) over stdio and streamable HTTP, talking only to the B2 signer socket (Rust or Python signer), optional in-process xbt402 payer with keys in the signer. See `crates/xbt-wallet-mcp/README.md` (Claude Code, Hermes, OpenClaw config) | binary `xbt-wallet-mcp` |
| `xbt-electrum` | the light chain backend: Electrum servers (TCP/TLS, batching, several servers) checked against our own `HeaderChain` and Merkle proofs; `xbt402::ChainBackend`, a typed API, and the node-RPC surface of the client path | library |
| `xbt-svc` | container-ready service plumbing (AGP-038): one data dir, the secret source, readiness, proxy URLs, probes; see `docs/CONTAINER.md` | library |
| `xbt-work` | pay-with-work (AGP-032): the x402 scheme `xbt-work` v1 draft. Invoices (base32 ids, both usernames), the strict receipt grammar and Ed25519 verification, the provider's receipt book (delta credit, equivocation proofs, audit intervals), exact work-unit pricing per nBits epoch, the `auth` binding, the xbt-work offer beside the channel binding in the xbt402 Provider and a payer for the xbt402 Client, window statements and NTA deferral lines, the coinbase audit with fraud proofs and a carry ledger, the blinded relay client (ChaCha20-Poly1305), NTA attestation helpers | library (+ `xbt-work-{vectors,provider,payer}` with feature `tools`) |
| `xbt402-interop` | conformance suite, Rust→JSON vector emitter, regtest cross-implementation tools | no (`publish = false`) |

References: B1 and B2 are the Python reference implementations of the channel scheme and the agent wallet (not yet published).
The pinned vectors in `vectors/` are what the Rust is checked against. `lazarus-protocol` is the pool's Rust, in
[AwokenLazarus/Bitcoin](https://github.com/AwokenLazarus/Bitcoin) (`lazarus/protocol`).

## Build and verify

```bash
cargo test -j2 --workspace
cargo build -j2 --release --target aarch64-unknown-linux-gnu -p xbt402
./scripts/conformance.sh           # N/N byte-identical, both directions
./scripts/regtest_interop.sh       # Rust <-> Python on a private Knots 29.4.2 regtest node
./scripts/signer_interop.sh        # AGP-027: the AGP-017 runbook with the Rust signer behind B2's MCP, + a Rust payer
./scripts/route_interop.sh         # routed: every client x hub x provider (Rust/Python), the all-Rust demo, + a Rust payer on the Rust signer
cargo run --release -p xbt402 --example adaptor_bench
./scripts/build_matrix.sh          # every AGP-031 target; writes dist/MATRIX.md
./scripts/electrum_interop.sh      # the light Rust payer on real electrs (tcp + TLS) vs the Python provider
cargo test -j2 -p xbt402 --no-default-features --test cmp_surface   # AGP-035: what cmp links, no features
./scripts/cmp_clean_build.sh [REF] # AGP-035: clean clone, no .cargo, cargo-zigbuild, x86_64/aarch64/armv7 musl
scripts/cmp_keys_ecdsa.py          # AGP-035: xbt_primitives::ecdsa vs cmp/keys.py, byte for byte
cargo test -j2 --manifest-path tools/lazarus-crosscheck/Cargo.toml  # header/PoW vs the pool's lazarus-protocol
./scripts/oci_build.sh [--load]    # AGP-038: FROM scratch images, amd64/arm64/arm-v7, dist/oci/*.tar + IMAGES.md (docs/CONTAINER.md)
./scripts/work_conformance.sh      # AGP-032: xbt-work vectors, Rust -> XBT-053 and XBT-053 -> Rust
./scripts/work_interop.sh          # AGP-032: pay-with-work on regtest, Rust payer/provider vs primed rnd/agp-011 (PAYER=py / PROVIDER=py: vs the Python side)
./scripts/work_matrix.sh           # AGP-032: xbt-work on every AGP-031 target; writes dist/WORK_MATRIX.md
./scripts/container_test.sh         # AGP-038: the images on regtest (signer+witness+MCP+hub, env + data dir only), paid call, restart, /readyz
```

Run heavy work under a CPU and memory cap:
`systemd-run --user --scope -p CPUQuota=200% -p MemoryMax=4G nice -n 19 ...` (the scripts do).

**Cross builds (AGP-031).** There is no system cross toolchain on the build host, so zig is the C
compiler (libsecp256k1) and the rustc linker. Set it up once with
`python3 -m venv ~/.local/share/ziglang-venv && ~/.local/share/ziglang-venv/bin/pip install ziglang`.
`.cargo/config.toml` points every non-host target at `tools/zig-cc` (GNU/Linux glibc floor 2.28;
musl targets are statically linked). `scripts/build_matrix.sh` builds `xbt-primitives`, `xbt402`
and the offline `selftest` example in `release` and `release-small` (opt-level `z`, fat LTO) for
x86_64/aarch64/armv7/riscv64 Linux (glibc + static musl), macOS x86_64/arm64, and Windows x86_64,
and writes sizes plus status to `dist/MATRIX.md`. The self-test is executed on the host for
x86_64; other arches need a user-mode emulator already on PATH (the script never installs
binfmt/qemu).

Dependencies: `secp256k1` 0.29 (libsecp256k1, the global context), `sha2`, `ripemd`, `blake2`,
`hmac`, `ruint` (256-bit targets and work), `serde_json` with `preserve_order` (never
`arbitrary_precision`, AGP-035), `base64`, `thiserror`,
`getrandom`, `indexmap`. Optional: `ureq` (features `http-client`, `rpc`). The `http-server` feature is std only (AGP-068).
std only; no_std isn't a goal.

## API overview

### xbt-primitives

```rust
use xbt_primitives::{tx::Tx, sighash::*, ecdsa, header, address, network};

let tx = Tx::parse_hex(hex)?;                          // strict: no trailing bytes, bounded allocations
let msg = unified_sighash(&tx, &prevouts, 0, ScriptType::WitnessV0, &script, SIGHASH_ALL_UNIFIED, None)?;
let sig = ecdsa::sign(&sk, &msg);                       // RFC 6979, low S, DER (no hash-type byte)
assert!(ecdsa::verify(&pubkey, &msg, &sig));            // BIP66 strict DER + low S, never panics
let addr = address::segwit_address(network::Chain::Regtest.hrp(), &spk)?;   // bech32 v0 / bech32m v1+
let h = header::parse_header(&raw164)?;                 // BLAKE2b v2: hash, committed height, time
let mut chain = header::HeaderChain::with_system_clock("main", header::MAINNET_CHECKPOINT, Some(path))?;
chain.set_checkpoint(&cp_raw)?;
chain.connect(fork_height, &raws)?;                     // most work wins; every Knots rule checked
let net = network::network_id(&block_961640_hash);      // "bip122:0000000000000050c1e5f69672f45929"
```

Modules: `tx` (OutPoint, TxIn, TxOut, Tx, txid, vsize), `script` (push, script_num, p2wpkh/p2wsh/p2tr
spk, classify), `address` (bech32/bech32m, hrp check), `sighash` (UnifiedSighash, BIP143),
`ecdsa` (sign, verify, is_strict_der, ecdh_x, tweaks), `header` (v2 stages, bits/targets/work, check_pow,
ChainRules with the retarget, HeaderChain, merkle proofs with the txcount bound, blocks), `network`
(Chain, hrp, anchors, network ids), `amount`, `hash`, `encode`.

### xbt402

```rust
use xbt402::{channel::*, provider::*, client::*, ledger::Ledger};

// provider (resource server): transport-independent
let prov = Provider::new(chain_backend, pay_to_secret, ProviderConfig::new(&network), Ledger::open(path)?,
                         Box::new(|_method, _path| 150), Box::new(|m, p, body| my_api(m, p, body)))?;
let resp = prov.serve(method, path, &headers, &body, &url, None);   // 402s, open/close/rollover, paid calls
prov.close_due()?;                                                  // watcher tick (every block)

// payer
let mut client = Client::new(ClientConfig::new(&network), Box::new(UreqTransport::default()),
                             Box::new(my_wallet), Box::new(move || node.block_count()));
let r = client.request("POST", "https://api.example/v1/infer", body)?;   // opens on the first 402
let (r, plaintext) = client.request_conditional("GET", "https://api.example/v1/report", b"")?;
client.rollover(origin)?; /* mine */ client.open_rolled(origin)?;
client.close(origin)?;
```

* `channel`: `ChannelParams` (`derive`, `state_tx`, `state_tx_a3`, `rollover_tx`, `refund_tx`,
  `sighash`, `min_amount`/`max_amount`/`payee_value`, `close_fee_payer`, `to_json`/`from_json` in the
  reference's `to_dict` format), `Payer`, `Payee`, `channel_payee_pub`/`secret` (the tweak v2),
  `channel_auth_key` (ECDH), `settle_due`, `sign_p2wpkh`, `cpfp_child`, `canonical_chan`.
* `conditional`: `ConditionalParams` (hash-lock state, claim), `encrypt`/`decrypt`, `preimage_from_tx`.
* `wire`: `b64json`/`unb64json`, `request_digest`, `request_auth`, `receipt_message`, `close_message`,
  `settlement_response`, `receipt_of`, `facilitator_request`, `upstream_code`, and typed serde views
  (`PaymentRequired`, `PaymentRequirements`, `ChannelExtra`, `SchemePayload`, `Receipt`,
  `SettlementResponse`, `VerifyResponse`, `SupportedResponse`, `OpenChannel`, `OpenResponse`, `CloseResponse`).
* `provider`: `Provider` (serve, open, close, rollover, facilitator verify/settle/supported, terms,
  offer_conditional, close_due, close_channel, sweep_payee, recovered_reservations), `ProviderConfig`.
* `client`: `Client` (`request`/`request_with`, `close`/`close_with`), `CallOpts`, `ClientConfig`, and the two hooks the application supplies: `Transport` and `Wallet`;
  optionally a `ClientLedger` for the channel book (`Client::with_ledger`, `FileClientLedger`,
  `MemoryClientLedger`; AGP-035).
* `funding`: `ChainBackend` (the four node calls), `FundingPolicy`, `check_funding`.
* `ledger`: `ChannelState`, `Ledger` (in memory, or an fsynced append-only JSONL file).
* `json`: JSON written byte-exactly as Python's `json.dumps`, which the wire headers need, and read
  losslessly by `json::parse` (integers of any size, correctly rounded floats; see below).
* Features: `http-client` (`http::UreqTransport`), `http-server` (`http::serve_http`), `rpc`
  (`rpc::Rpc`: bitcoind JSON-RPC as `ChainBackend` and `Wallet`). cmp can bring its own transport.

Errors are `ChannelError { code, msg }` (`thiserror`). `code` is the wire error code
(`bad_sig`, `bad_amount`, `stale_amount`, `bad_auth`, ...). The library does not panic on
untrusted input: parsers and the provider are fuzzed with hostile bytes and JSON in the tests.

## Conformance statement

`scripts/conformance.sh` (2026-10-08, AGP-068):

The vectors come from our own Python references (B1, B2) and from Knots. B1 and B2 are not yet
published, so the B1/B2 groups show agreement between our two implementations, not conformance to
an outside implementation. The UnifiedSighash vectors are Knots' own file, byte for byte.

| group | vectors | source | result |
|---|---|---|---|
| xbt402 v1.1 to v1.3 (counted as `check_vectors.py` counts them) | 54 | B1 agp-068 `docs/x402/vectors.json` | 54/54 byte-identical |
| UnifiedSighash (Knots hf-sighash-opt-in reference) | 166 | B1 `tests/data/unified_sighash.json` | 166/166 |
| BLAKE2b header v2, every hash stage | 5 | B2 `tests/vectors/block_header_v2.json` | 5/5 |
| Knots BLAKE2b regtest capture: 24 headers across v1/v2, 3 blocks' merkle roots, a header chain | 28 | B2 `tests/vectors/blake2b_regtest.json` | 28/28 |
| **total** | **253** | | **253/253** |

It works in both directions:

* Rust → reference. The Rust emitter (`xbt402-vectors`) rebuilds the whole xbt402 vector file with
  the Rust crates, the Rust provider serving every round trip (402, open, 5 paid calls, replay,
  facilitator, close, settle, the conditional sale and its claim, the v1.2 section). Any difference
  from the published file is charged to the vector it belongs to. The generator-independent checks
  of `check_vectors.py`, ported to Rust, run over the published values: refusal codes, which key
  signed what, receipts, script layouts.
* Reference → Rust. B1's `check_vectors.py` checks the Rust-emitted file: `diff(python_generate(), rust)`
  plus `independent_checks(rust)`. The result is 50 vectors, 0 mismatches under both Python ECC
  backends (pure Python and coincurve/libsecp256k1).

Mutation tests prove each check bites: a tampered value fails exactly its own vector. The pinned
copies in `vectors/` are checked against the source files on every run.

The header/PoW code is also cross-checked against `lazarus-protocol`, the pool's Rust, through a
path dev-dependency of a standalone crate outside the workspace (`tools/lazarus-crosscheck`, so a
clean checkout never needs `~/Bitcoin`; nothing is written there). It covers 2,000 random profile-0 headers (pow hash, h2, time, height), the Knots-captured
v2 headers, more than 4,000 compact targets, and merkle roots. The mainnet retarget rule is checked on
400 cases recorded from B2's Python (`scripts/gen_retarget_cases.py` → `vectors/retarget_main_cases.json`).

## Cross-implementation on regtest

`scripts/regtest_interop.sh` runs on a private Knots 29.4.2 node (RDTS on, #419
`-testcoinbasematuritylong=200:200:6680`, `-testactivationheight=blake2b@101`), on ports 33030–33043.
It starts no miners. Each close is mined, then its outputs are checked exactly.

| | payer | provider | fee payer | what | result |
|---|---|---|---|---|---|
| A1 | Rust | Python B1 | payer (v1.1) | 10 calls + 1 hash-locked conditional call, close | payee 2100, payer 197300, fee 600 |
| A2 | Rust | Python B1 | payee (v1.2) | 10 calls, close | payee 900, payer 198500 |
| A3 | Rust | Python B1 | payer | 5 calls, rollover (the provider co-signs), 5 calls on the next channel, close | next channel 198650; payee 750, payer 197300 |
| B1 | Python B1 | Rust | payer | 10 calls + 1 conditional call, close | payee 2100, payer 197300 |
| B2 | Python B1 | Rust | payee | 10 calls, close | payee 900, payer 198500 |
| C1 | Rust | Rust | payee | 10 calls, close | payee 900, payer 198500 |

## Where the Rust differs from the reference (deliberately)

* **Ledger.** The reference uses SQLite (WAL, synchronous=FULL). The Rust ledger is an append-only
  JSONL log, fsynced per save, replayed and compacted at open. Each paid call is still O(1) writes.
* **Keys.** Payer and payee keys must be 33-byte compressed. The Python accepts any SEC1 encoding;
  an uncompressed key would change the funding script.
* **Parsing is stricter.** The segwit flag must be `0x01`, trailing bytes after a tx are refused, a
  mixed-case bech32 address is refused (BIP173), and bech32m/v1+ addresses are supported.
* **Routing keeps the last 256 lock answers per channel** (B1 keeps all). Only the pending lock is
  ever retried; an older lockId is refused as `bad_invoice`.
* **A paid invoice is never locked again** (AGP-026 fix, see below).
* **Not in this wave.** The Electrum light backend is AGP-028 and will reuse `header::HeaderChain`.

## The v1.2 payee-pays close report (AGP-029)

AGP-025 found that under v1.2 payee-pays the close answer reported `cum` as the payee's output **net
of its fee** (900 for a 1,500 state with a 600 fee) and `unpaidMsat` as `spent − that`, so the close
fee showed up as unpaid (600000); `/x402/settle`'s `amount` likewise. The on-chain amounts were right.
AGP-029 fixed the report in B1 and here, byte for byte: `cum` / `amount` are the gross state the
payer paid, `unpaidMsat` = `spent − cum × 1000`, and a payee-pays answer adds `payeeFee` and
`payeeNet` (in `/x402/settle`, inside `extra`). A payer-pays (v1.1) answer is unchanged. The vector
`payeePays.close` pins it (ten 150-sat calls closed at 1,500: `cum "1500"`, `unpaidMsat "0"`,
`payeeFee "600"`, `payeeNet "900"`), and the interop payers check it as `provider_report_gross` and
`provider_report_fee`.

## Hub routing (AGP-026)

> **Experimental.** The hub (`RouteHub`, `xbt402-hub`, `RoutePayer`'s routing) is not
> production-ready: do not route funds you cannot lose. `xbt402-hub` says so when it starts. No flag
> is needed, so the demos keep running. See "Hub routing safety (AGP-064)".

A port of B1 agp-023 `xbt402/adaptor.py`, `route.py`, `hub.py`, `route_client.py` and the provider's
routing endpoints (AGP-021 + AGP-023 v1.2), wire-compatible in every direction.

```rust
use xbt402::{adaptor, route::*, route_seller::RouteOffer, hub::{RouteHub, HubConfig}, route_client::*, signer::*};

// provider (shard server): sell a path through hubs, metered in amsat (1e-21 sat)
prov.offer_route(RouteOffer { window: 1.0, lock_wait: 2.0, invoice_ttl: 15.0, ..RouteOffer::new("/forward", amsat_per_call) });
// hub (merchant --hub mode): library, or `xbt402-hub --config hub.json` (B1's config format)
let hub = Arc::new(RouteHub::new(chain, spend_scan, wallet, transport, pay_to_secret, &network, Some(datadir), HubConfig::from_json(&conf)?)?);
hub.connect("http://shard:port", None, None)?; let _stop = hub.watch(Duration::from_secs(5));
xbt402::http::serve_service(hub.clone(), "127.0.0.1:9480", 16)?;
// client: one ch1 to the hub, per-window locks off the data path; keys behind RouteSigner
// (LocalSigner, or xbt_signer::client::RemoteSigner), ch1 funded by a Wallet
let payer = Arc::new(RoutePayer::new(hub_url, RoutePayerConfig::new(&network), signer, wallet, transport, height));
payer.open()?; let sh = payer.shard("http://shard:port/forward", "POST")?; payer.start(Duration::from_millis(500));
let r = payer.call(&sh, "POST", chunk)?;      // a 402 with error route_credit: the shard stopped serving
payer.stop(); payer.close()?;
```

* `adaptor`: pre-sign / pre-verify / adapt / extract with B1's DLEQ encoding. Every secret operation
  runs in libsecp256k1 (point multiplications, scalar products and sums via `seckey_tweak_mul/add`,
  inversions as a fixed ladder over n − 2), so unlike the Python there is no bigint remainder.
  `AdaptorBackend` is the seam for a libsecp256k1-zkp backend. Timings (`adaptor_bench`, x86_64):
  presign 99 µs, preverify 132 µs, adapt 22 µs, extract 42 µs (B1 Python + coincurve: 297/501/147/190).
* `route`: `route_ok`, `FeeQuote` + `fee_due` (carry in 1e-6 msat), `PriceQuote`, `Invoice`,
  ROUTE-STATE signatures, session/call/lock auth, `next_cum`, `SpendScan` (no txindex; `Rpc` has it).
* `route_seller`: route offers, sessions, ROUTE-AUTH/ROUTE-STATE, `POST /x402/xbt-channel/lock`
  (pre-verify, write-ahead, idempotent), hub binding, `close_now`.
* `hub`: `RouteHub`, `HubConfig` (fees, fee strategy flat/utilization/callable, liquidity cap, lock
  caps, reveal timeout, `ch1/ch2_close_fee_payer`), the 7 ordered checks with B1's codes, the watcher
  (open, retry, write-off, t from a ch2 close, rollover at the net threshold, ch1 margin).
* `route_client`: `RoutePayer`, over `signer::RouteSigner` (below) and a `client::Wallet`.
* `http::serve_service` serves a provider or a hub (`HttpService`).
* amsat prices exceed u64 and signed quotes must round-trip Python's ints exactly. Since AGP-035 that
  is `xbt402::json`'s job, not serde_json's `arbitrary_precision` (see "Linking xbt-rs from cmp").

**Routing conformance** (`conformance.sh` step 4): `scripts/route_vectors.py` generates
`vectors/xbt402_routing_vectors.json` from B1 (nonces injected, byte-identical under both B1 ECC
backends); the Rust emitter reproduces it byte for byte; Rust re-verifies it (79/79 checks) and B1
re-verifies the Rust file. It covers 5 adaptor cases, quotes (an amsat price above 2^64), invoices,
ROUTE-STATE, auths, `route_ok`/`next_cum` tables and one two-hop lock end to end.

**Routed cross-implementation** (`route_interop.sh`, ports 33100–33212; `XBT_RS_ROUTE_PORT_BASE=B
ROUTE_RSS_OFFSET=3` keeps every port in B..B+99): all 8 combinations of
client × hub × provider in Rust or Python, 2 providers each, exact amounts on chain for every ch1
and ch2 close; then `xbt402-route-demo`, the AGP-021 demo in Rust (4 providers, rollover, a
non-revealing provider, a withholding hub): see AGP-026's result for the tables.

**A client bug found here (fixed in Rust, present in B1).** A lock can complete while the client
still holds a ROUTE-STATE from before it, with the same invoice. Locking that invoice again gets the
hub's saved answer; a normal lock rejects it (it does not open the new T1), but a *floor* lock only
checks t·G == T and counted d + f twice, after which every lock on ch1 was `bad_amount`. The Rust
`RoutePayer` never locks an invoice it already paid (`ShardState::last_locked`, test
`a_paid_invoice_is_never_locked_again_even_a_floor_lock`). B1 `route_client.py` reproduces it
(client routed 10 sat, hub 7) and needs the same one-line guard.

## Hub and client leftovers (AGP-044)

The routing items AGP-035 and AGP-037 left open. Items 1 and 2 are the same in B1's `xbt402/hub.py`
(b1 `agp-044`).

**1. A stuck ch2 refund is bumped by RBF.** A hub refund that is still unconfirmed
`refund_bump_blocks` (default 3) after it was signed is signed again at a higher fee and replaces
itself. The new fee is the estimate, at least double the stuck fee, and at least the stuck fee
+ 1 sat/vB (BIP125's increment). It is capped by `refund_max_fee_sat` (default 5,000) and always
leaves dust. It pays the same destination as the version it replaces.
* Hub refunds signal replaceability: nSequence `RBF_SEQUENCE` = 0xFFFFFFFD, with nLockTime still
  enforced. `ChannelParams::refund_tx_seq` builds them; the client refund (`refund_tx`) and its
  vector are unchanged.
* Every version is written ahead and kept in `refund_prev` until one confirms. Whichever version
  confirms is the refund, and its fee is the one counted.
* Events: `ch2_refund_bump` (`replaces`, `feeFrom`), `ch2_refund_bump_capped`,
  `ch2_refund_bump_failed` (the node refused the replacement; both versions stay tracked), and
  `ch2_refund_confirmed` (with `versions`).

Why RBF and not CPFP:

| | RBF (chosen) | CPFP |
|---|---|---|
| who can sign | the hub alone: it holds the ch2 payer key, and the refund is 1-in-1-out | the owner of the refund output: with `refund_to` (a wallet address) the hub cannot, unless the `Wallet` trait grows a spend-this-UTXO call |
| extra chain use | none: the same tx at a higher fee | a second tx (~110 vB) whose fee must also cover the parent |
| a refund that left the mempool (too cheap to relay, evicted) | the higher-fee version simply goes out | no parent to attach to without package relay |
| cost | the txid changes: every version must be tracked | the parent's txid is stable |
| node support | a signalling refund replaces on any node | needs the parent in the mempool |

A refund the hub signed before AGP-044 (0xFFFFFFFE) is replaceable only where full-RBF is on. On
other nodes the replacement is refused (`ch2_refund_bump_failed`), and whichever version confirms
still counts.

**2. One live ch2 per origin** (was: per payTo; changed by AGP-056, see "Multi-process operators"
below). Origins are canonical (`route::canon_origin`: scheme and host lowercased, the default port and
trailing `/`s dropped), and `connect` to an origin that already has a live ch2 funds nothing: it
returns that ch2. The two-connects race is closed under the book lock (`ch2_funding`).

**3. The RoutePayer ledger seam.**
```rust
let payer = RoutePayer::new(hub_url, cfg, signer, wallet, transport, height)
    .with_ledger(Box::new(FileRouteLedger::open(&path)?))?;   // resumes whatever the file holds
payer.open()?;                          // {"resumed": true} with the same ch1
let sh = payer.shard(url, "POST")?;     // the same provider session (no new 402)
```
* The `RouteLedger` trait is the `ClientLedger` store: every `ClientLedger` is a `RouteLedger`.
  `FileRouteLedger` is JSON lines, fsynced, mode 0600, and compacts itself as it grows.
  `MemoryRouteLedger` keeps the records in memory.
* Records: `ch1`, `book` (counters, given-up locks, stats, quote), `pending`, and one `shard <url>`
  per session.
* Write-ahead: the lock and its ch1 seq before the request leaves, and a block of `SEQ_RESERVE`
  (16) call seqs before the first of them leaves. The meters are saved every `persist_every`
  answered calls (default 1).
* Resuming a pending lock: the same request is sent again with a fresh seq and auth. The hub
  answers a lock it completed with its saved answer, or takes a lock it never saw.
* A presignature the ledger never recorded never left, so it is voided in the signer. A lock the
  signer resolved just before the crash is committed on its secret (y opens T1, so t = y − r).
* Calls a crash left unanswered are in doubt. The provider's next signed total may exceed the
  client's meter by at most their count × the quoted price, and that gap is adopted
  (`meter_adopted`). A larger gap is not adopted (`meter_gap`), so the mismatch stays visible.
* No payer key, signature or refund is written: they stay in the signer (`xbt-signer`, or a
  `LocalSigner` that outlives the payer). The file does hold each session's call-auth key, as
  `FileClientLedger` holds `auth_key`. That key can make metered calls on its session; it can never
  sign a state.

**Tests.**
* Rust: `tests/hub_leftovers.rs` (18) and `tests/route_payer_restart.rs` (11). Python:
  `tests/security/test_agp044_hub_leftovers.py` (18, same names).
* `scripts/refund_bump_regtest.sh` runs both hubs on Knots regtest. A refund is left out of blocks
  with `generateblock ADDR []`, bumped 1 → 2 sat/vB, replaced in the node's mempool and confirmed.
  A second run is capped (122 → 244 → 427 sat), 11/11 checks per hub.
* `route_interop.sh` adds RSSR: the payer on xbt-signer with a route ledger is SIGKILLed mid-stream,
  restarted on the same ledger and signer, and every on-chain check still holds to the sat.

Fixed along the way: `xbt402-hub` (and B1 `python -m xbt402.hub`) asked the wallet for its default
address type as the refund destination. That type is legacy on the Knots node, so every refund failed
`bad_address`. Both now ask for `bech32`.

## RouteHub reconcile fixes (AGP-045)

Three items from cmp-lead's CMP-012 review of the hub (b1 `agp-037`). All three are the same in B1's
`xbt402/hub.py` (b1 `agp-045`), with the same record fields, states, events and test names.

**1. The refill hook is looked up at each refill.** `set_refill` may be called at any time (`None`
restores `connect`). The hook is now called with no hub lock held, so a hook may replace itself or
call back into the hub. Before, `close_ch2` held the refill mutex during the call, and such a hook
deadlocked. In B1, `hub.refill` is a property (`refill or self.connect`, looked up per call), so
assigning `hub.connect` after construction takes effect.

**2. A `funding` record is not reconciled by `scantxoutset` alone.** `scantxoutset` sees only the
confirmed UTXO set, so a funding still in the mempool at `funding_timeout_blocks` used to be
dropped and never refunded. The watcher now looks in this order:
* the sends the fund wallet knows to the ch2 address: `Wallet::wallet_sends_to` (`listtransactions`)
  and `Wallet::wallet_send` (`gettransaction`: vout, sats, confirmations, abandoned), with the
  record's own `fund_txid` first;
* each send's output via `gettxout` including the mempool, and the send via
  `SpendScan::in_mempool` (`getmempoolentry`);
* `scantxoutset` last, for a fund hook outside the wallet.

What happens next:
* Found in a block or the mempool: the record is `funded`, and it opens once it has minConf.
* Not found by `funding_timeout_blocks`: the record is `dropped`, with its key kept.
  * If the wallet still knows the send (not conflicted, not abandoned), `fund_txid`/`fund_vout` are
    kept and the archived record is watched. If the send confirms late, the record becomes `funded`
    in the archive (`ch2_funding_late`) and is refunded at expiry like any unused ch2. If the wallet
    later reports it conflicted or abandoned, it is final (`ch2_funding_failed`).
  * A send that failed outright (none known, conflicted or abandoned) is dropped and final.

The new trait methods have defaults (empty or false), so existing `Wallet` and `SpendScan`
implementations compile unchanged. `Rpc` implements them.

**3. A ch2 is `closed` only on a confirmed spender.** A new state, `closing`, is non-final and not
live: the hub never routes over it or rolls it over.
* A provider's close seen in the mempool makes the ch2 `closing` (`ch2_closing`, with
  `refundAtRisk` when a refund fee is booked). So does `close_ch2`'s good reply.
* Lock secrets are still read off the mempool close at once.
* Only a confirmed spender sets `closed` and `final` and takes the refund fee back (`ch2_closed`,
  `refundFeeReverted`). Until then the fee stays booked (`refund_fees_sat` counts a `closing` ch2
  whose `close_prev` is `refunded`).
* If the funding is unspent again (the close left the mempool), `ch2_close_vanished` fires:
  * a ch2 that was refunded goes back to `refunded`: its fee is booked again and the refund goes out
    again;
  * any other ch2 stays `closing` and is refunded at expiry unless the close returns.

New `ch2.json` fields (both languages): `close_prev`, `fund_txid`, `fund_vout`.

**For cmp.**
* Embedders that read `state == "closed"` right after a close should expect `closing` first.
* Pass the fund wallet's RPC handle: B1 `RouteHub(..., wallet=)`, Rust through the `Wallet`
  methods.
* Handle the events `ch2_closing`, `ch2_close_vanished`, `ch2_funding_late` and
  `ch2_funding_failed`.

Tests: `crates/xbt402-interop/tests/hub_reconcile.rs` (16), and B1
`tests/security/test_agp045_hub_reconcile.py` (16) with the same names. On regtest,
`scripts/funding_reconcile_regtest.sh` runs Knots 29.4.2 with the Rust hub
(`xbt402-funding-reconcile`) and the Python hub:
* a mempool funding past the timeout is recovered and opened;
* a conflicted funding is dropped but watched, then failed (`gettransaction` confirmations −1).

## Make-before-break ch2 rollover (AGP-053)

Before this, a ch2 rollover was break-before-make. The rollover tx pays the provider and funds the
next ch2 in one tx, but the next ch2 opened only once it had the provider's minConf. Until then the
hub refused every lock to that provider (`route_blocked`); on a real chain that lasts a block
interval (cmp CMP-024). Now the next ch2 is routed at once, before it confirms. B1's
`xbt402/hub.py` and `x402_channel.py` (b1 `agp-053`) do the same, with the same fields, events and
wire.

**Why this is safe for the provider.** The next ch2 spends the old ch2's funding. That funding is the
provider's own confirmed, hub-bound channel. Before its expiry, every spend of it needs the
provider's signature, so only the provider can sign a tx that conflicts with the rollover; the hub's
refund is valid only after expiry. The provider takes the unconfirmed child (`zero_conf` on its
ledger row) only when all of these hold:
* it is the `rollover_to` of one of its own channels, bound to the same hub;
* that parent has its `conf_for` confirmations;
* the tip is below the parent's close margin (`until` = parent expiry − close_margin).

While the child is unconfirmed, the provider takes locks only up to
`ProviderConfig::rollover_zero_conf_max` (cum; default 2 × settleMultiple × closeFee; 0 turns the
feature off) and only before `until`. Otherwise it refuses `zero_conf_cap` or `unconfirmed`. It also
refuses to roll over an unconfirmed child. The watcher recomputes all of this each tick, so a reorg
of the rollover applies the bounds again, and a reorg of the parent suspends the child.

**Wire.** The only change is an optional `zeroConf: {parent, maxCum (string), until}` in the
`/x402/xbt-channel/open` reply, plus the lock refusal code `zero_conf_cap`. The routing vectors and
`/terms` are unchanged. A provider without this feature refuses the unconfirmed open, and the hub
opens the child at minConf as before.

**Hub.**
* The hub calls `/open` for the child right after the provider's rollover reply, still holding that
  provider's busy flag. The next lock therefore goes over the child. It is not refused as `funded`:
  a route request that finds a rollover child waits for the flag and is checked again once the
  flag is free.
* `route` re-reads the ch2 under the busy flag and makes the channel checks again on the ch2 the
  lock will use: pending, open, blocked, the expiry rule and the zero-conf bounds.
* The hub keeps the provider's `maxCum` and `until`, so it refuses `route_blocked` before it signs
  or sends anything past them. It never rolls over an unconfirmed child.
* New record fields: `rolled_from` and `zero_conf` (`{parent, maxCum, until, confirmed}`).
* New config key: `zero_conf_rollover` (default true).
* New events:
  * `ch2_open` with `zeroConf`;
  * `ch2_zero_conf_confirmed` and `ch2_zero_conf_reorg`;
  * `ch2_rollover_vanished` / `ch2_rollover_back`: the rollover left the mempool and the parent is
    unspent. The child is blocked with `ROLLOVER_GONE` until the provider's watcher sends the
    rollover again.
  * `ch2_rollover_replaced`: another tx spent the parent. The child never existed, so it is
    `dropped` and final, and any secrets of the parent's written-off locks are read off that tx.
* The watcher no longer starves a provider that streams locks. A tick first tries each provider's
  flag without waiting, then waits for the skipped ones between two locks: 250 ms each, 1 s per tick
  in all. Before, a tick in step with the locks could miss every gap, and a due rollover waited a
  long time.
* Liquidity is unchanged: the child reuses the old ch2's coins, so there is still one live ch2 per
  payTo and `committed_sat` counts each coin once.

Tests: `crates/xbt402-interop/tests/hub_make_before_break.rs` (13), and B1
`tests/security/test_agp053_make_before_break.py` (15). `routing_checks` c5 now expects the next
ch2 to be open at once.

On regtest, `scripts/rollover_load_regtest.sh` (ports 34900–34999; driver
`scripts/interop/rollover_load.py`, client bin `xbt402-rollover-load`) runs one lock after every call
at 15/s, one block every 3 s, for 45 s. It covers every hub × provider pair of Rust and B1. The runs:
* 7–8 rollovers per run, with zero refused locks, every call 200, max gap between paid locks
  80–197 ms;
* the pre-AGP-053 baseline (`--zero-conf-max 0`): about 24 `route_blocked` per rollover and gaps of
  3.1 s;
* a rollover held out of blocks: locks run on the unconfirmed child up to the cap, then the hub
  holds until the rollover confirms;
* a reorg across the switch: zero refusals.

Every run also checks the money on chain. Each rollover tx pays signed − closeFee to the provider and
capacity − signed to the next ch2. The total routed over all ch2s equals what the client's locks
paid.

## Routed billing throughput (AGP-054)

Before this change, cmp measured routed decode at 0.742 of unpaid (CMP-024): about 4–5 ms of billing per stage per
token. With `RouteWal`, B1's 3-stage benchmark (`scripts/route_perf.py`, 3 × 300 tokens) went from
0.833 to 0.964 of unpaid (0.973 with no durability at all), and cmp's routed end-to-end gate
(CMP-027) measured 0.894–0.923. A profile of the per-call path traced most of it to one step. cmp's `RouteJournal`
fdatasyncs every routed call's meter after the handler, before the answer: 2.5 ms on the lab's
ext4, 66% of the provider-side cost. The rails' own work is small. ROUTE-STATE signing takes
0.12 ms and the client's verify 0.03 ms (B1 with coincurve).

**`RouteWal`** (`ProviderConfig::route_wal`, `RouteOffer::precharge`; B1 `route_wal=` and
`precharge=`, same file format and rules) makes that guarantee part of the rails, without an fsync
on the critical path:
* Before the handler runs, `reserve` counts the call in flight at its expected charge and queues
  the session's projected meter `{s, v, seq, calls, acc, us}`. The expected charge is the
  precharge, or `amsat_per_call` on a flat path.
* One writer thread appends the queue and syncs it (group commit) while the handler computes.
* `end_call_reserved` returns the ROUTE-STATE only once a snapshot covering it is durable. The
  state carries the session's *current* meter, which can already hold a concurrent call metered
  in memory, or a seq a later `begin_call` took:
  * when the charge is as projected, it waits for the session's *latest* snapshot if that covers
    the state (sequentially, the call's own reserved one), else it queues a fresh one;
  * any other charge writes a corrected snapshot, which costs one more fsync.
  * A refused call's 402 `routeState` (`refusal_state`) waits the same way.
* A write failure answers `500 route_wal_failed`, with no ROUTE-STATE and nothing billed. The
  exception is a call that a later state of the session already carries: it stays billed, like a
  call in flight at a crash, so no state goes backwards.
* The routes file keeps each session projected over its calls in flight, plus `walV`. A lock that
  completes during a call therefore covers that call's reservation.
* At start, a WAL snapshot wins over the routes file when its `v` is above `walV`. Versions resume
  above `walV` even if the log was lost.
* The log is compacted to one line per session past 1 MiB.
* The writer thread ends once its provider is dropped.

After a crash:
* every answered state survives;
* a seq is durable before its handler runs, so a ROUTE-AUTH is never served twice;
* the restart counts more only for calls in flight at the crash, once each, at their projected
  charge. Those are the in-doubt chunks a client already reconciles.

**RoutePayer.** A data call no longer resolves a lock whose POST to the hub is still out. The hub's
answer settles it off the data path, so the signer's and the ledger's write-ahead fsyncs no longer
land on a chunk. A hub refusal of a lock that the provider's signed ROUTE-STATE shows as paid now
resolves it through the provider instead of voiding it.

**ROUTE-STATE.** The window's invoice is signed once per window. The bytes are identical: ECDSA
signing is deterministic, so no vector changes.

Tests: `crates/xbt402-interop/tests/route_wal.rs` (12) and `routing_checks.rs` `agp054_*` (2). In B1:
`tests/security/test_agp054_route_wal.py` (16). The measurements are in
`docs/route-perf-agp054-2026-09-30.json`, from B1 `scripts/route_perf.py`.

## Multi-process operators, rollover relay and the settle floor (AGP-056)
From cmp's CMP-027 gate: after a hub ch2 rollover, locks to that provider were refused
`route_blocked` until the next block, on almost every lock. Four causes, three fixed here (hub and
provider, the same in B1 `agp-056`) and one in cmp.

**1. ch2 identity: one per provider process.** A ch2 lives in ONE provider process's ledger, with
that process's route sessions. AGP-044 kept one live ch2 per payTo and sent the locks of a second
origin under that key to the origin that opened the ch2. With two provider processes on one operator
key (cmp merchants) that process has no session for them: `unknown_session`, and the client sees
`route_failed`. The hub keys a ch2 by the canonical origin again.
* `connect(origin)` funds that origin's own ch2. A lock goes to the origin the client named, on its ch2.
* One payTo key holds at most `ch2_max_per_pay_to` live ch2s (default 8, 0: no bound). The next
  `connect` is refused `pay_to_limit` and nothing is funded. `liquidity_cap_sat` counts every ch2.
* `OutBook::live_for_pay_to` is gone (`live_keys(pay_to)` lists them); `key_for(origin)` and
  `RouteHub::ch2_for(origin)` return the origin's own ch2 only. The event `ch2_reuse` is gone.
* A refusal names its cause: `route_blocked` "no open channel to that provider: its payTo has a ch2
  at <origin>, another provider process ...".
* An operator who serves ONE provider process at two URLs should give the hub one of them: each URL
  would get its own ch2 (they work; the capital is split).

**2. Rollover relay.** The provider broadcasts a rollover on its own node. A hub with its own node
sees it only after P2P relay, and used to block the child as vanished (`ch2_rollover_vanished`) until
the next block. Now it blocks only if its node showed the rollover before (`fund_seen`), or still
does not `rollover_relay_grace` seconds (default 60) after it (`rolled_at`).

**3. Settle floor.** `settleMultiple × closeFee` (12,600 sat at the defaults) is when a settlement is
worth its fee to the provider. With locks larger than that the ch2 rolled over on every lock.
* Hub: a due rollover waits until the ch2 has taken `settle_lock_multiple` (k, default 4) × the
  largest lock routed to that provider (`max_lock`, carried over rollovers). It never waits past the
  point where another lock of that size would not fit, and not at all once the ch2 has had no lock
  for `settle_idle` seconds (default 600). `settle_lock_multiple: 0` is the old rule.
* A rollover child that could not take one more lock of that size is not made: the ch2 is closed
  and refilled (before, such a child sat exhausted and unsigned until its expiry).
* Provider: the default zero-conf cap of a rollover child is
  `max(2 × settleMultiple × closeFee, 2 × settle_lock_multiple × largest lock on the parent's line)`
  (`ProviderConfig::settle_lock_multiple`, `zero_conf_max_for`). An explicit `rollover_zero_conf_max`
  is used as it is.
* Why k = 4: at most one rollover per four of the largest locks (the provider's close fees and the
  unconfirmed windows fall by the same factor), and with a ch2 capacity of five such locks, the
  usual sizing (100k / 20k, 200k / 40k), it is the largest k that still leaves room for one more
  lock when the rollover is due.

**4. Refusal detail.** The hub's `route_failed` for a provider refusal now carries
`provider refused the lock: <code> (<the provider's detail, printable ASCII, bounded>)`. The Rust
`RoutePayer` already returned `detail`; B1's does now.

No wire change: no new field or message, and the conformance vectors are byte-identical.

Tests: `crates/xbt402-interop/tests/hub_multi_process.rs` (21; B1
`tests/security/test_agp056_multi_process.py`, 21), each checked against 12 mutations.
`scripts/rollover_load_regtest.sh` has two more kinds, `<H>-<P>-high` and `-high-nofloor`: at 3,000 sat
a lock the floor gives a rollover per four or more locks and zero refusals, and without it a
rollover and a refusal per lock.

## The embedder surface (AGP-059)
For an application that meters a channel itself (cmp, CMP-051). Before this, cmp's payer was built
on `channel` + `wire` because `Client` took no headers and signed only its own amount, and cmp's
provider repaired the ledger's `spent_msat` after a crash. The same surface is in B1 `agp-059`
(`docs/embedders.md` there).

**Payer: its own headers and its own cumulative amount.**

```rust
use xbt402::client::CallOpts;

let headers = [("X-CMP-Payer".to_string(), identity)];
let opts = CallOpts::new().headers(&headers).cum(meter.payer_sats());   // sats, cumulative
let resp = client.request_with("POST", &url, &frame, &opts)?;
let done = client.close_with(origin, &CallOpts::new().cum(meter.payer_sats()))?;
```

`request` and `close` are these with `CallOpts::new()`. The headers go with every request of the
call (the unpaid try and the paid retry); a `PAYMENT-SIGNATURE`, an empty name or a CR/LF/NUL is
`bad_header` and nothing is sent. A chosen `cum` replaces only the amount `Client` works out from
its receipts. Everything else `Client` does still happens: the offer checks, the price pinned at
open, request auth, the receipt checks, the ledger save. The amount is bounded before anything is
signed or a seq is spent:

| a chosen `cum` | answer |
|---|---|
| below the last signed state | `bad_amount` (a state never goes down) |
| above `max_amount()` (capacity less the payer's close fee) | `exhausted` |
| above `ceil(receipted spentMsat / 1000)` + one call at the price pinned at open | `too_expensive` |
| its increase over the last signed state exceeds what is left of `daily_budget` | `budget` |
| under `min_amount()` while nothing is signed yet | sent unsigned (cum 0): never rounded up |

The third bound is the one `Client` has always had implicitly: it signs what its verified receipts
show, plus (prepay) the call it is making. So a metering embedder can sign ahead of the receipts by
at most one call, which is what a lost answer needs. `CallOpts` is `#[non_exhaustive]`: build it
with `new()`.

**Provider: close one channel now.**

```rust
let st = provider.channel_state(&chan).ok_or(...)?;
if idle && provider.settle_due(&st.params, st.best_cum, Some(provider.height()?), 0) {
    match provider.close_channel(&chan) {
        Ok(r) => info!("closed {} by {}: cum {} unpaidMsat {}", r["chan"], r["txid"], r["cum"], r["unpaidMsat"]),
        Err(e) if matches!(e.code.as_str(), "call_in_flight" | "lock_pending" | "hub_channel" | "channel_closed" | "no_state") => {}
        Err(e) => return Err(e),
    }
}
```

It is the watcher's margin close for one named channel: the same write-ahead intent, broadcast,
record and hash-lock claim (`close_locked`), with the best signed state (the conditional state when
that pays more). The answer is the cooperative close's (`chan`, `txid`, `cum`, `unpaidMsat`, and
`payeeFee`/`payeeNet` under payee-pays). Refused, with nothing changed:

| code | when |
|---|---|
| `unknown_channel` | not in this provider's ledger |
| `channel_closed` | already closed or rolled over |
| `lock_pending` | a routed lock is open on it (`route_lock`, `stale_locks`: a hub's ch1) |
| `hub_channel` | a hub-funded ch2: its hub rolls it over or closes it, and the margin close still protects it |
| `call_in_flight` | a paid call is between its reservation and its settlement: the best state does not cover it yet |
| `no_state` | the payer has signed nothing |
| `close_failed` | the node refused the broadcast (the intent stays; a later call or the watcher adopts or replaces it) |

**Provider: the reservation crash window.** A direct call reserves its maximum price in
`spent_msat` before the handler runs (saved, with the payer's state and the seq) and refunds the
difference once the charge is known. A process that died in between restarted with `spent_msat`
above what it had billed; a payer signing its own meter was then refused `insufficient_payment` on
every later call. Now:

* A metered call (a provider with `with_charge`) records its reservation in the row:
  `extra.resv = {"<seq>": msat}`. Its settlement is always saved before the answer leaves (also
  when the charge equals the price), which removes the record.
* `Provider::new` refunds every reservation still recorded and saves the rows:
  `provider.recovered_reservations()` lists `(chan, msat)` for the operator's log. After a restart
  `spent_msat` is what was charged. A metered call in flight at the crash is charged nothing: its
  charge was never durable and its answer never left.
* An unmetered call's reservation is its exact charge, so nothing is recorded and a paid call is
  still one fsync. In flight at a crash it stays charged once at its price, as before.
* A handler or charge function that panics refunds its reservation (a guard dropped unsettled), and
  a failed settlement save answers `500 ledger_error` with nothing charged.

There is no setter for `spent_msat`, and none is needed: `reconcile_direct` in cmp can go. A ledger
row written by an older build that crashed mid-call still holds its reservation unrecorded; nothing
in the row tells it from a charge, so it is not touched.

API changes for embedders: all additive. `Client::request_with`, `Client::close_with`, `CallOpts`;
`Provider::close_channel`, `Provider::recovered_reservations`; `ChannelState::reserve`, `release`,
`reserved_msat`, `refund_reservations`. Behaviour: a metered provider saves once more per call when
the charge equals the price; a ledger row may carry `extra.resv` while a call is in flight (an older
build reading such a ledger after a crash sees the reservation as spent, as it always did).
Tests: `crates/xbt402/tests/lifecycle.rs` (the last seven).

## ch2 lifecycle under load: the zero-conf cap and make-before-break refill (AGP-057)
Two things still paused routing to a provider under load. Both are fixed in the hub (and one line in
the provider), the same in B1 `agp-057` (`docs/routing.md` there). No wire change.

### A. The zero-conf cap of a rollover child (cmp CMP-149)
cmp saw about 20 `route_blocked` per R14 replay: "the rollover funding this ch2 is unconfirmed: cum
134687 > the provider's zero-conf cap 132120". The cap is the provider's bound on what it takes over
a rollover child that is still unconfirmed (`rollover_zero_conf_max`; by default
`max(2 × settleMultiple × closeFee, 2 × settle_lock_multiple × the largest lock)`, here 8 × 16,515).

Reproduced at cmp's lock size with four new kinds of `scripts/rollover_load_regtest.sh`: 16,515-sat
locks at 2/s for 28 s on a 1,000,000-sat ch2, settleMultiple 20. `cmp`: cmp's own cadence (a block
whenever the mempool is not empty, looked at every 0.4 s; the hub's watcher every second). `cmp-lag`:
the watcher every 5 s (the hub's default). `cmp-slow`: a block only every 6 s. `cmp-slow-sized`: the
same with the provider's cap sized for it (`--zero-conf-max` 24 locks). Every cap refusal is
classified: was the child's rollover in a block already (the hub's flag was stale), or not.

| run | refused before (base `6b5af61`) | paid | max gap ms | refused after | paid | max gap ms |
|---|---|---|---|---|---|---|
| `RS-RS-cmp` | 0 | 56 | 529 | 0 | 56 | 521 |
| `PY-PY-cmp` | 0 | 56 | 525 | 0 | 56 | 547 |
| `RS-RS-cmp-lag` | 6 (6 stale flag, 0 unconfirmed) | 50 | 2,517 | 0 | 56 | 515 |
| `PY-PY-cmp-lag` | 2 (2 stale flag, 0 unconfirmed) | 54 | 1,517 | 0 | 56 | 515 |
| `RS-RS-cmp-slow` | 13 (1 stale flag, 12 unconfirmed) | 43 | 4,507 | 12 (0 stale flag, 12 unconfirmed) | 44 | 4,510 |
| `PY-PY-cmp-slow` | 13 (1 stale flag, 12 unconfirmed) | 43 | 4,497 | 12 (0 stale flag, 12 unconfirmed) | 44 | 4,493 |
| `RS-RS-cmp-slow-sized` | 0 | 56 | 532 | 0 | 56 | 519 |
| `PY-PY-cmp-slow-sized` | 0 | 56 | 556 | 0 | 56 | 524 |

Reports: `docs/rollover-load-agp057-cap-before-2026-10-03.json` and `...-cap-after-...` (each run's
`capDiagnosis` has the refusals one by one). The command, in a 20-port grant:

```sh
XBT_RS_LOAD_PORT_BASE=42000 XBT_RS_LOAD_PORT_SPAN=20 \
LOAD_ONLY=RS-RS-cmp,PY-PY-cmp,RS-RS-cmp-lag,PY-PY-cmp-lag,RS-RS-cmp-slow,PY-PY-cmp-slow,RS-RS-cmp-slow-sized,PY-PY-cmp-slow-sized \
  lazvault heavy --project xbt-agentpay -- ./scripts/rollover_load_regtest.sh
```
(the before column: the same command on the base commits, `XBT402_B1=~/xbt-rnd/b1`).

What the runs say:

* **Nothing of the parent is carried into the cap.** A child's cum starts at 0 in the hub and at the
  provider; `childCumCarried` is 0 in all 16 runs.
* **The hub's stale flag (fixed).** The hub refuses before it sends anything, on its own
  `zero_conf.confirmed`, and that flag was only the watcher's last look: a child that had confirmed
  was refused until the next tick. Before a lock is refused on either of the provider's bounds (the
  cap, the parent's close margin) the hub now looks at the chain itself, as the provider already did.
  A node that does not answer leaves the bound standing (`ch2_watch_error`, step `zero_conf`).
* **A block that lands while the provider checks the child (fixed).** Found by a `cmp-lag` run after
  the first fix. The provider read the child's funding unconfirmed; then the block with the rollover
  came, so the parent was spent in a block and the child was no zero-conf child any more. The open was
  refused `unconfirmed` although the child was confirmed, and the ch2 stayed `funded` until the hub's
  next tick (10 refusals at a 5 s watcher). `Provider::open` reads the funding once more before it
  refuses. A refused open is also written to the hub's stderr now.
* **The provider's own stale look at a lock (fixed).** The provider's watcher can meet the block the
  same way and leave a confirmed child `suspended` until its next tick: a lock in between was refused
  `unconfirmed` (two `route_failed` in a first `RS-RS-high-nofloor` run). Before it refuses a lock on
  a suspended rollover child the provider now reads the chain, as the hub does before it sends one.
  Any other suspended channel is refused as before.
* **A child that really is unconfirmed is still refused (sizing).** With more than the cap's 8 locks
  per block interval the hub refuses, as it should: that is the provider's risk bound (`cmp-slow`:
  12 of the 13 before, and all 12 after). How many depends on where the blocks fall. A provider paid faster than
  8 of its largest locks per block sets `rollover_zero_conf_max` to what it earns from one hub in a
  block interval or two (`cmp-slow-sized`: zero refusals).

Which of these cmp hit cannot be read off its logs (they carry no block times). Its topology (the
hub, the operator and the miner on three nodes) adds relay time to the first case.

### B. Make-before-break refill
A rollover adds no coins, so a ch2 line carries its capacity in locks and was then closed and
refilled. The refill is a wallet funding, which the provider cannot take unconfirmed (its payer could
spend it again), so it opened at minConf: a block without routing to that provider.

* **Funded ahead.** Once the live ch2's room is under `refill_ahead_locks` (N, default 4) × the
  largest lock routed to that provider, the watcher funds the origin's NEXT ch2
  (`OutBook::next_chans`, at most one per origin; `RouteHub::connect_next`). Room is what the line
  still takes: `max_amount − signed`, less the provider's `minCapacity` (a rollover child under it is
  not made). Not for a provider the hub stopped routing to, nor one with no lock for `settle_idle` s.
* **Usable** means open at the provider, at its minConf. The live ch2 keeps taking locks meanwhile,
  rollovers included.
* **The switch** (`ch2_switch`): with the first lock the live ch2 cannot take (exhausted, no longer
  open, or an unconfirmed rollover child at the provider's bounds); when the live ch2 is closed as
  too small to roll over (`close_ch2(.., true)` hands over instead of funding; while the next one is
  funded but not open yet and the live one still takes a lock, it is kept: `ch2_wait_next`); or once the live ch2
  has had no lock for `settle_idle` seconds, so two ch2s do not stay committed to an idle provider.
  Never while a lock is pending on the live ch2, and never because the hub stopped routing to the
  provider (a lock it did not reveal).
* **The old ch2** is `retired`: the watcher asks the provider to close it on its best state (once a
  block until it answers) and reconciles it like any archived ch2. One with nothing signed has
  nothing to close and is refunded at its expiry, as an unused ch2 always was.
* **Bounds.** Per origin: one live ch2 plus at most one next (the AGP-056 guard, widened). An origin
  counts once for `ch2_max_per_pay_to`. `committed_sat` counts the live ch2, the next one and a
  retired one until its close is out, so `liquidity_cap_sat` needs room for one more `ch2_capacity`
  than the hub has origins. Without it nothing is funded ahead (`ch2_refill_ahead_failed`, tried
  again next block) and the refill follows the close as before.
* **Sizing N.** N locks must cover what the provider is paid while a funding confirms and opens: the
  locks of one block interval plus one watcher tick. `refill_ahead_locks: 0` is the old behaviour.
* **Embedders.** `RouteHub::set_refill_ahead` replaces the default (`connect_next`). An embedder that
  set its own `refill` and no `refill_ahead` gets none: its path, lock and cap are never bypassed.
  `ch2.json` has a new key `next_chans`, and a record a new field `retired`.

Events: `ch2_refill_ahead` {live, next, room, maxLock, capacity}, `ch2_refill_ahead_failed`,
`ch2_switch` {from, to, why}, `ch2_wait_next`, `ch2_retire_failed`.

**Exhaustion under load** (`<H>-<P>-exhaust`): 3,000-sat locks at 2/s for 60 s over a ch2 of 120,000
sat (40 locks), a block every 3 s, `refill_ahead_locks` 16, `liquidity_cap_sat` 240,000. The line
runs out three times. `-exhaust-before` is the same with `refill_ahead_locks` 0.

| run | refused | paid | max gap ms | gaps > 1 s | wallet-funded ch2s | funded ahead | max committed sat | closes | rollovers |
|---|---|---|---|---|---|---|---|---|---|
| `RS-RS-exhaust` | 0 | 120 | 531 | 0 | 4 | 3 | 186,000 | 3 | 20 |
| `PY-PY-exhaust` | 0 | 120 | 525 | 0 | 4 | 3 | 186,000 | 3 | 20 |
| `RS-PY-exhaust` | 0 | 120 | 616 | 0 | 4 | 3 | 186,000 | 3 | 20 |
| `PY-RS-exhaust` | 0 | 120 | 525 | 0 | 4 | 4 | 189,000 | 3 | 20 |
| `RS-RS-exhaust-before` | 12 | 108 | 3,995 | 3 | 4 | 0 | 120,000 | 3 | 10 |
| `PY-PY-exhaust-before` | 11 | 109 | 3,494 | 3 | 4 | 0 | 120,000 | 3 | 9 |

```sh
XBT_RS_LOAD_PORT_BASE=42000 XBT_RS_LOAD_PORT_SPAN=20 \
LOAD_ONLY=RS-RS-exhaust,PY-PY-exhaust,RS-PY-exhaust,PY-RS-exhaust,RS-RS-exhaust-before,PY-PY-exhaust-before \
  lazvault heavy --project xbt-agentpay -- ./scripts/rollover_load_regtest.sh
```
Report: `docs/rollover-load-agp057-exhaust-2026-10-03.json`. Each run also checks the money: every
rollover tx pays the provider signed − closeFee, every replaced ch2 is closed on its signed state
and confirmed, routed over all ch2s equals what the client paid, nothing pending or written off.

Tests: `crates/xbt402-interop/tests/hub_refill_ahead.rs` (25; B1
`tests/security/test_agp057_refill_ahead.py`, 25, where 12 of 13 mutations of the hub are caught and
the 13th is equivalent). The older test worlds set `refill_ahead_locks: 0`, as they set
`settle_lock_multiple: 0`.

**The older runs, again** (the AGP-053 and AGP-056 kinds, on this commit; 45 s at 15 locks/s, the `high`
kinds at 2/s). The make-before-break runs still refuse nothing; `-before`, `-stuck` and `-high-nofloor`
are the baselines that refuse by design.

| run | refused | paid | max gap ms | rollovers | checks |
|---|---|---|---|---|---|
| `RS-RS` | 0 | 675 | 115 | 8 | PASS |
| `PY-PY` | 0 | 586 | 131 | 7 | PASS |
| `RS-PY` | 0 | 603 | 232 | 7 | PASS |
| `PY-RS` | 0 | 594 | 127 | 7 | PASS |
| `RS-RS-before` | 143 | 532 | 3,206 | 6 | PASS |
| `PY-PY-before` | 134 | 502 | 2,722 | 3 | PASS |
| `RS-RS-stuck` | 158 | 456 | 14,287 | 2 | PASS |
| `RS-RS-reorg-zero` | 0 | 656 | 123 | 8 | FAIL: reorg: the hub saw the child unconfirmed again |
| `PY-PY-stuck` | 193 | 389 | 14,034 | 2 | PASS |
| `RS-RS-reorg` | 35 (35 in the reorg window) | 640 | 2,299 | 5 | PASS |
| `PY-PY-reorg` | 32 (32 in the reorg window) | 592 | 1,535 | 5 | PASS |
| `RS-RS-high` | 0 | 90 | 554 | 16 | PASS |
| `PY-PY-high` | 0 | 90 | 525 | 16 | PASS |
| `RS-RS-high-nofloor` | 74 | 16 | 3,512 | 16 | PASS |
| `PY-PY-high-nofloor` | 74 | 16 | 3,503 | 16 | PASS |

Reports: `docs/rollover-load-agp057-a-2026-10-03.json` and `...-b-...` (two batches of the 20-port grant).

* The `reorg` runs refuse inside the reorg window, which their checks allow and earlier reports did
  not show (AGP-053: 0 and 0): here the first rollover waited a whole block interval (3.0 s) for its
  block, the reorg held it 5 s more, and at 15 locks/s the child's cap (100 locks) is 6.7 s of
  traffic. In AGP-053's report the block came 0.4 s after the rollover. So it is where the block
  clock falls against the first rollover (probably the driver's changed start-up timing; not
  isolated), and every refusal is the reorged child's zero-conf cap.
* `RS-RS-reorg-zero` is an optional kind added to the batch: zero refusals, re-confirmed. Its check
  "the hub saw the child unconfirmed again" fails: the block was re-mined 52 ms after the reorg,
  between two watcher ticks. Whether that check ever held for this kind was not measured on the base.

**The driver in a small port grant.** `XBT_RS_LOAD_PORT_SPAN` under 100 packs the selected runs two
ports each from base + 4 (8 runs in 20 ports). Such a grant (42000-42019 here) lies in the kernel's
ephemeral range (`ip_local_port_range` 32768-60999) and outside `ip_local_reserved_ports`
(30000-34999 on this host, where the default base 349xx is): any local connection can hold one of
its ports as its source port for a moment, a poll of that very port included, and a hub or provider
then cannot bind it (`Address already in use`; it cost three runs their start today). The driver
therefore waits for a process's "ready" line before it polls its port, and starts one that exited
before that line again.

## Hub routing safety (AGP-064)
From Chris Guida's external review of the hub: two High findings, H1 and H2, where the hub could pay a
provider on ch2 without being able to collect from the client on ch1. There was also a test-only
nonce API in the library. Both were still present on `main` (`c8d607b`), and the tests below
reproduce each one there. The same changes are in B1 `agp-064-w4`, with the same test names. The
hub is now marked **experimental** (above, and in `xbt402-hub`'s startup log).

**H1: a ch1 close while a lock is in flight.** `route()` writes ch1's `route_lock`, lets go of
ch1's ledger, and then forwards to the provider for up to `reveal_timeout`. A cooperative close in
that gap closed ch1 below the lock, and the provider was still paid on ch2.
* The provider's `POST /x402/xbt-channel/close` now refuses a close with `lock_pending` while ch1
  has a routed lock its best state does not cover: the lock in flight, or a written-off lock above
  `best_cum`. A written-off lock that `best_cum` covers does not block. `close_channel` (AGP-059)
  uses the same test.
* The margin close lets a lock in flight finish, but only in the first half of the margin (the
  lock takes seconds). It never waits for a written-off lock: a skipped margin close would let the
  payer refund the whole channel at expiry.
* A lock that completes after ch1 was closed below it (an operator's `close_now`, or a margin close
  past its wait) is never counted as routed. It is counted in `HubStats::uncollected`, and the
  event is `lock_uncollected`.
* A ch1 lock that no route is forwarding and that sits on no ch2 can never complete: the hub
  stopped between its two write-aheads, or the `withhold "all"` test hook was used. The hub drops
  it when the client asks to close (`orphan_lock_dropped`), so it does not keep ch1 from closing.
  This is checked under the provider's busy flag, which `route()` holds from before it writes the
  lock until its forward ends, so a lock in flight is never dropped.

**H2: written-off locks were superseded.** A lock is written off at `reveal_timeout`, or when the
provider refuses it. Its ch2 pre-signature may already be out: a slow honest provider can still
use t, and so can one that answers 400 and keeps the pre-signature. The client's next lock was
quoted on the old base, so its state did not include the written-off amount, and a t read later off
the ch2 close collected nothing.
* **Hold.** If the lock was pending on ch2 when it was written off (the pre-signature may have
  left), ch1's counters (`routed_sat`, `fee_units`, `fee_paid`) are raised to the lock's `after`.
  What was added is stored on the lock (`stale_locks[].hold`). Later locks are quoted above it, so
  a t read off the ch2 close later still collects. A write-off whose pre-signature never left
  ("ch2 exhausted", a failed pre-sign, a final ch2) holds nothing and is not kept.
* **Block.** No route over a ch2 with written-off locks (`route_blocked` "a written-off lock on
  this ch2 is unresolved"), and no rollover of it: `rollover()` refuses with `lock_pending`, and
  the watcher does not roll it over. The ch2's close shows whether t was used; its refund shows it
  was not.
* **Release.** A confirmed refund, or a confirmed provider close that does not reveal the lock's t,
  proves it unpaid. The hold leaves the base (`lock_released`), and the lockId goes on ch1's
  `released` list (the last 64). The client is then quoted below its signed state (the dust floor)
  until what it signed ahead for that lock is used.
* **`max_lock_sat`.** A written-off lock holds the client's base and blocks its ch2 until that ch2
  resolves, so a lock should be small next to a ch2. The default is now 20,000 sat (a fifth of the
  default `ch2_capacity`, was 50,000). `HubConfig::from_json` refuses 0 or more than half of
  `ch2_capacity` (`bad_config`).

**The client (`RoutePayer`).** A given-up lock now records the counters `before` it as well as
`after`, whether it was a floor lock, and whether the hub `held` it. Floor locks are recorded too:
the hub can hold one. `resync` adopts three hub views, each only when it matches a lock the client
gave up:
* completed: as before, the hub's best state is that lock (also after a hold);
* held: the hub's counters are the lock's `after`, ours are its `before`, and its lockId is in
  `held`;
* released: our counters minus the released holds equal the hub's.
A refusal that carries `held` is resynced at once. A held entry is kept until its release or
completion: the 16-entry list drops the oldest entry that is not held.

**Nonces.** `adaptor::presign_with_nonces` (caller-chosen k and w, for the routing vectors) is
compiled only under `cfg(test)` or the `vector-emitter` feature, which only `xbt402-interop`
enables. `presign` uses a private inner function. The routing vectors are byte-identical
(`conformance.sh` step 4, 79/79). B1's `presign` never took nonces.

**For embedders (cmp).** These are the wire and behaviour changes:
* `POST /x402/route` refusals with ch1's view (`bad_amount`, and now also the 502 `route_failed`
  of a held write-off) carry `held: [lockId]` and `released: [lockId]` beside `bestCum`,
  `routedSat`, `feeUnits` and `feePaid`. Before, the 502 `route_failed` carried only
  `providerError`. Old clients ignore the new fields.
* A client close of a ch1 with a routed lock open is refused `lock_pending` (400). Retry it after
  the lock resolves.
* After a write-off, that provider's ch2 is `route_blocked` until the ch2 closes or is refunded.
  The hub's switch to a ch2 funded ahead (AGP-057) can still take over.
* `RoutePayer`'s persisted ledger: entries in `given_up` gain `before`, `floor` and `held`. Older
  records load, with `before` taken as `after`.
* `max_lock_sat` above half of `ch2_capacity` is now a config error. The default is 20,000.
* `HubStats::uncollected`, and the events `lock_uncollected`, `lock_released`,
  `orphan_lock_dropped`, `resync_hold` and `resync_release`; `void` gains `held`.
* `presign_with_nonces` is gone from the default build (enable `vector-emitter` to get it).

Tests: `crates/xbt402-interop/tests/hub_routing_safety.rs` (8; B1
`tests/security/test_agp064_hub_safety.py`, the same 8 plus the config test). All of them fail on
`main` and pass here:
* H1: `h1_close_while_a_lock_is_in_flight_is_refused_either_order` (lock then close, and close
  then lock), `h1_a_lock_completed_after_ch1_closed_below_it_is_not_counted`,
  `h1_the_margin_close_lets_a_lock_in_flight_finish`,
  `h1_a_lock_the_hub_never_forwarded_does_not_keep_ch1_open`;
* H2, both unfriendly orders: `h2_a_slow_provider_stays_in_the_base_and_a_later_route_sits_above_it`
  (the answer lost, then t on the close) and
  `h2_a_refused_lock_stays_in_the_base_and_blocks_routing_and_rollover` (400 with the
  pre-signature kept: routing and rollover refused, then t on the close);
  `h2_a_refunded_ch2_gives_the_unpaid_hold_back` and
  `h2_a_void_whose_pre_signature_never_left_holds_nothing`;
* `hub::tests::max_lock_sat_defaults_small_and_is_at_most_half_of_ch2_capacity`.

The tests use a wrapper `HttpService` around the provider (it holds the provider's answer at a
gate, or turns it into a 400), so the shipping code has no new test hooks. Two existing tests
changed with H2, because a provider's refusal now blocks that ch2:
`hub_make_before_break::provider_enforces_its_cap_and_margin_itself` and
`hub_refill_ahead::a_child_the_providers_watcher_left_suspended_is_looked_at_before_a_lock_is_refused`
(the same two in B1).

**Trade-offs.**
* An honest slow provider, once written off, can leave the client paying the lock twice: once in
  the held base, and once by rerouting the same service. The provider's own meter credit is out of
  the hub's reach.
* A provider that refuses after taking the pre-signature stops its ch2 for that ch2's lifetime
  (close or refund). This is the spec's choice (no route over a stale ch2). The follow-up would be
  to close and refill such a ch2 early.

## Agent-wallet budget integrity and privileged methods (AGP-063)

Fixes for Chris Guida's agent-wallet findings W1-W4, X1 and K1, plus the library payer's watermark.
Each test fails on `main` and passes here (the run is in the task's `result.md`). Most are in
`crates/xbt-signer/tests/guida_w.rs`; B2's port (branch `agp-063`) has the same names in
`tests/test_guida_w.py`.

**W1: the wallet books what it signs.** `xbt402_pay` books the **signed delta**: the cumulative amount
signed after the call, minus what the policy ledger already holds for that channel
(`ledger_booked_sats`). It never books `charged` from the seller's PAYMENT-RESPONSE. The receipt is
still checked: the payee's signature, the request digest and channel, a `cum` no higher than the one
signed, and a `charged` that is neither negative nor above the quote. A bad receipt does not change
what is booked; the answer reports it as `receipt_error`. The answer also carries `booked_sats`.
- **When it books.** The `pay` channel rail, `sign_state`, `xbt402_sign_state_a3`, the rollover and
  `xbt402_sign_conditional` book before they sign, and take the row out again if signing fails.
  `xbt402_pay` books after the state is persisted and before it is sent; a crash in between is
  booked by the next call.
- **No double count.** The ledger txid is `xbt402:<chan>:<cum>`, so a restart books an increase once.
- **No lower state.** A lower `cum` is `deny/amount`.
- **No negative rows.** A negative payment or amend row is refused, both when written and when the log
  is loaded, so a row can never lower a daily, weekly or per-seller total.
- **Streams.** The stream budget is `max_sats` minus what was booked.
- **The budget check.** The per-tx limit, the human threshold and approvals still apply to the amount
  asked (`max_sats`, or `pay`'s `amount_sats`). The daily, weekly, per-seller and split sums apply to
  what the call can book (`PolicyEngine::evaluate_booking`). On an open channel that is known before the
  402: `next_cum(max_sats)` minus the booked amount. A call that fits the budget exactly is paid, even
  when `max_sats` alone would not fit.
- **The dust floor.** A new channel's first state signs the dust floor (546) when the price is below
  it. Those 546 sats are booked, and that first state is allowed even when `max_sats` is lower (500 in
  the runbook). When the floor is more than the amount asked, the budgets are checked again on the whole
  floor before anything is signed, on both rails (the session's `set_spend_check` hook for
  `xbt402_pay`). A floor that does not fit is refused with the budget's rule, and the reason names the
  dust floor. Tests: `w1_the_budget_is_checked_on_the_signed_increase_not_max_sats`,
  `w1_a_dust_floor_above_the_remaining_budget_is_refused` and
  `w1_the_dust_floor_on_the_pay_rail_is_held_to_the_budget`.
- **Old records.** A record from before this field loads as booked through `used_sats` and does not
  gain the key, so B2 still loads it.

**W2: the seller cannot raise the cap.** An offer whose `minCapacity` is above the owner's per-channel
cap (the cap plus the payer's close fee, which is what `minCapacity` bounds) is refused with
`deny/min_capacity` before any funding. The combined W1+W2 test (a huge `minCapacity` and a receipt
of zero) stops at the owner's cap.

**W3: what a process on the agent socket can still do.** The agent socket is shared with the
model-facing MCP process, so every method there either stays inside the owner's policy or needs the
human's ed25519 signature.
- **`fund`** pays only a channel for a payer key this signer issued (`xbt402_new_key`) to that origin,
  and only to the seller's verified terms. The verified payTo is the policy's
  `counterparties[origin].pay_to`, else the seller's `GET <origin>/x402/xbt-channel/terms`, which the
  signer fetches itself, only for an allowlisted origin or routing hub, and checks for the right
  network. The channel must also have:
  - the hot key's change script;
  - a close fee within `close_fee_max_sats`;
  - an expiry in (`refund_margin_blocks`, max(`channel_expiry_blocks`, 4032)] blocks;
  - a capacity within `per_counterparty_cap_sats` plus the payer's fee.

  The funded channel is written ahead as pending, so the watcher refunds it at expiry if no attach
  follows. Without `origin` and `params` the answer is `deny/fund_unbound`. Other codes:
  `bad_key`, `pay_to`, `payer_spk`, `close_fee`, `expiry`, `channel_cap`, `bad_address`,
  `channel_open`, `channel_pending`.
- **`open_channel`** takes payTo only from the policy; a different `pay_to` parameter is `deny/pay_to`.
  The dest must be allowlisted, and `cap_sats`, `expiry_blocks` and `close_fee` must stay inside the
  owner's bounds.
- **`xbt402_attach`** of a funded channel must match the pending record `fund` wrote. A `/next`
  channel passes the same checks as `fund`.
- **`xbt402_sign_rollover`** needs `next`: the unfunded params of the channel's own next channel. Its
  script must be `next_spk`; it must have the same close fee and fee payer; its capacity must be
  exactly `rollover_next_capacity(amount)`; and it passes the `fund` checks for `<origin>/next`.
  A bare `next_spk` is `deny/rollover_unbound`. Only the increase in the signed amount is booked, not
  the new channel's capacity, because that capacity is the wallet's own refundable channel and
  booking it as well would count the same sats twice.
- **`rotate_hot_key`** needs the human signature over `rotate_message(hot_address, expiry)`; it is
  the same method as `rotate_hot_key_signed`. Codes: `human_key`, `human_sig`, `expired`.
- **`deny_approval`** of an approval that has not expired needs the human signature over
  `deny_message(token, expiry)` (domain `xbt-agentwallet-deny-v1`), so the agent cannot refuse for
  the owner. An expired one can still be dropped without a signature. The UI signs it in the page,
  like approve.

**W4: the first human key.** While no human key is enrolled, the signer prints a one-time enrolment
code (`XXXX-XXXX-XXXX`, 60 bits) to stderr and writes it to `.run/enroll-code` (0600).
- **Enrolling.** `human_key_enroll` needs `code`. Five wrong codes replace it with a new one. Success
  removes the code and the file.
- **Where the owner finds it.** On Umbrel it is in the app's log (the app page, then Troubleshoot).
  On StartOS it is in the service's Logs. Elsewhere it is on the signer's stderr or in
  `.run/enroll-code`. The UI's enrolment form says so.
- **Host and Origin.** The UI answers only to IP literals, single-label names (`localhost`, a
  container name), `*.local`, `*.localhost`, `*.onion`, and the names in `XBT_UI_ALLOWED_HOSTS`;
  anything else is 421. A POST whose `Origin` is not one of those hosts is 403. `Origin: null` is
  accepted, because the UI sends `Referrer-Policy: no-referrer` and Chrome then sends `null` on
  same-origin form posts. The Host check is what stops DNS rebinding.

**X1: the MCP HTTP transport.**
- **The token is always required.** With a data dir it is the `mcp-http-token` secret, generated on
  first run. Without one it is `<signer socket dir>/mcp-http-token` (0600), generated on first run
  and read again on restart. A non-loopback listener with no token is refused at start.
- **Origin is checked whether or not `--http-allow-remote` is set.** It must be a loopback origin or
  one of `XBT_MCP_ALLOWED_ORIGINS` (comma-separated). There is no same-origin exception, because a
  DNS-rebound page has Origin equal to Host.
- **Local payer mode** checks the signer's allowlist before any request to a URL, so a refused origin
  is never probed.

**K1: key storage.**
- **scrypt cost.** A passphrase blob is sealed at scrypt N=2^17 (r=8, p=1, 128 MiB) and records
  `log_n`. A blob without `log_n` (B2 and older Rust files) opens at 2^15, and only 15..=18 are read.
  The measurements and the comparison with argon2id are in the task's `result.md`. The default
  (Umbrel/StartOS) wrapping key is a key file, which has no KDF.
- **Zeroised secrets.** Wrapping keys, the passphrase, derived keys and the key-file bytes are held in
  `Zeroizing` buffers.
- **Key file.** The key file (after symlinks are resolved) must be a regular file with no group or
  other bits; otherwise the signer refuses to start.
- **Durable approvals.** `PolicyStore::write` (the approvals document) writes a temp file, fsyncs
  it, renames it, fsyncs the directory and sets mode 0600.
- **xbt-svc ownership changes.** `xbt-svc` `own_dir`, `chown_tree` and `put_secret` open each entry
  with `O_NOFOLLOW` and chown or chmod it through that fd. Children are named through
  `/proc/self/fd/N`, so an entry swapped for a symlink during the walk is never followed.
- **Deferred: sealing the hub's ch2 payer keys.** They are still stored as hex in the hub state
  (AGP-064 is changing `hub.rs` now, and B1's `hub.py` shares the file format).

**The library payer's watermark.** `Payer::sign_state_a3` and `Payer::sign_conditional` refuse an
amount below the highest one signed (`stale_amount`) and advance it, as `sign_state` already did.

**Wire changes for embedders (cmp, B1 clients, scripts).**

| change | before | now |
|---|---|---|
| `fund` | `{address, sats}` | `{origin, params, address?, sats}`; `xbt402::client::Wallet::fund_channel` (`RemoteSigner` sends it) |
| `xbt402_sign_rollover` | `{chan, amount, next_spk, next_capacity}` | the same plus `next` (the next channel's params); `StateSigner::sign_rollover_next` |
| `xbt402_pay` answer | `charged_sats` | plus `booked_sats` and, for a bad receipt, `receipt_error` |
| `xbt402_pay` / `pay` budget | sums held to `max_sats` / `amount_sats` | sums held to the signed increase; a dust floor above the budget is `deny/<budget rule>` |
| `Session` (Rust) / `Xbt402Session` (B2) | `set_spend_book` | plus `set_spend_check(dest, max_sats, delta)` |
| `rotate_hot_key` | no params | `{expiry, signature}` |
| `deny_approval` | `{token, reason}` | plus `{expiry, signature}` while the approval is live |
| `human_key_enroll` | `{pubkey}` | `{pubkey, code}` |
| MCP HTTP | token optional on loopback | always a bearer token; Origin is checked; `XBT_MCP_ALLOWED_ORIGINS` |
| web UI | any Host | Host allow-list (`XBT_UI_ALLOWED_HOSTS`) and an Origin check on POST |
| keystore blob | no `log_n` | `"log_n": 17` on passphrase blobs |

## Request binding and the HTTP server (AGP-068)

Guida T1–T4. A few slow connections must not stall a provider, and a receipt binds one request and
the answer that was actually returned. B1 `x402_channel.py` on `agp-068` (`a495430`) does the same, and
`tests/test_agp068.py` there uses the same test names.

**Wire (v1.3).** `extra.derivation` is `"v3"`, and it is the only version signal: a v1.2 client
requires `"v2"` and refuses the offer before it funds. The payee key is still
`xbt-channel/payee/v2`. There is no separate binding flag, because an old client echoes whatever
terms it was given, so a server-side check of one would never fire.

- `request_digest_v2` is
  `tagged_hash("xbt402/req/v2", f(method) ‖ f(scheme) ‖ f(host) ‖ f(port) ‖ f(target) ‖ f(body))`
  with `f(x) = LE64(len(x)) ‖ x`. Scheme and host are lowercased, the port is decimal or the
  scheme's default, userinfo and fragment are dropped. A provider reached at another origin, or a
  `|` moved between target and body, gives another digest. A bare target binds no origin.
- The client binds `origin + path`, and the server binds the URL it rebuilt from the request.
- Receipts are `tagged_hash("xbt402/receipt/v2", …)` over the length-prefixed chan, seq, cum,
  charged, spentMsat, req, status and bodyHash (sha256 of the body sent). The client checks status
  and bodyHash against the bytes it received (`bad_receipt`). On a conditional call the hash lock
  stays pending until the receipt checks out, so after a `bad_receipt` `recover_conditional` still
  reads k from the provider's claim.
- `seq` is the call's own, and cum and spentMsat come from the call's reservation (less its own
  refund), not from whatever another call wrote meanwhile. A seq spent on a refusal is saved before
  the 402 goes out (a 500 if that save fails), so a replay after a restart is still `bad_auth`.
- The old `sha256(method|path|body)` remains as `request_digest_v1` for xbt-work's published
  XBT-053 vectors; xbt-work still speaks v1.

**HTTP server (`http-server` feature).** It is now `std::net`:

- header lines are capped at 8 KiB and the header block at 32 KiB (431);
- at most 64 connections, then 503;
- the head must arrive within 10 s (408) and the body within 30 s, both as absolute deadlines;
- only Content-Length bodies (Transfer-Encoding gives 501), and `Expect: 100-continue` is honoured;
- `Connection: close` on every answer;
- bodies are read on the connection thread, so a slow body cannot occupy a worker. Jobs go to the
  workers through a bounded queue, and a panicking handler costs a 500, not a worker.

The URL the digest is checked against is rebuilt from `Host`, the target and `X-Forwarded-Proto`
(`https` or `http`). Both headers are client-controlled, so trusting them gives an attacker nothing
it could not already send. Behind TLS, put a reverse proxy in front that overwrites both with the
URL the payer used. For example, with nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:8402;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_request_buffering on;     # the proxy, not this process, absorbs slow bodies
    client_max_body_size 1m;
}
```

**Client (T3).** The payer's `ureq` transport refuses a declared Content-Length over 64 MiB
(`response_too_large`) and a body shorter or longer than declared (`response_truncated`), instead
of returning a short buffer. B1's `_read_capped` uses the same codes.

Options weighed for the server (best-performing-stack rule):

| option | slowloris / long headers fixable | new dependency | other cost |
|---|---|---|---|
| keep `tiny_http`, wrap it | no: its listener thread reads heads with no deadline or line cap | none | the bug stays |
| vendor and patch `tiny_http` | yes | none (but a fork to carry) | maintaining a fork |
| `rouille` | no | yes | built on `tiny_http` |
| `hyper` | yes | yes, with an async runtime (tokio) | larger binary, a runtime on Pi-class devices |
| `may_minihttp` | partly | yes | coroutine runtime, heavy use of `unsafe` |
| **`std::net`, ~360 lines (chosen)** | yes | **none** (`tiny_http` dropped from xbt402) | ours to maintain; tested in `http_limits.rs` |

**Cost.** Pass line declared before measuring: (a) the added per-call hashing (the v2 digest twice
on the server, v2 receipt framing, bodyHash of a 4 KiB answer) is at most 5% of one ECDSA receipt
signature; (b) bodyHash on armv7 keeps up with a 100 Mbit/s link (12.5 MB/s).
`cargo run --release -p xbt402 --example binding_bench` on a Ryzen 9 9950X3D (SHA-NI) gives
digest v1 100 ns / v2 288 ns, receipt v1 345 ns / v2 445 ns, bodyHash 4 KiB 1.7 µs, ECDSA sign
16.2 µs, and SHA-256 at 2.5 GB/s:

- framing alone adds 0.48 µs, which is 2.9% of a signature and passes (a);
- framing plus a 4 KiB bodyHash adds 2.2 µs, which is 13.7% and **fails (a)**;
- the bodyHash part is one SHA-256 pass over the answer, which T4 requires and the payer repeats to
  check, and it grows with the answer size.

There was no armv7 box or emulator, so the armv7 figures are estimates. Software SHA-256 on a
Cortex-A7 at 900 MHz runs at about 25–35 cycles/byte, about 25–35 MB/s, so (b) passes with room to
spare. Signing on 32-bit libsecp256k1 slows down by roughly the same factor as hashing, so the
bodyHash share on armv7 is in the same 10–25% range: (a) fails there too for answers of a few KiB
and up.

**Embedders.**

- cmp, xbt-compute and anyone else who builds the payload themselves must bind
  `request_digest_v2(method, origin + target, body)` and verify receipts against the answer. A v1.2
  digest no longer authenticates.
- B5 and xbt-063 vendor pinned B1/B2 and are unaffected until they re-pin. On re-pin, B5
  `fwd/server.py` must add status and bodyHash to its receipts and use the v2 digest.
- The B2 wallet (`agp-068`, `8299cee`) binds the v2 digest, but as before it does not check receipts.
- xbt-wallet-ui, xbt-work-relay and xbt-wallet-mcp still serve with `tiny_http`, so they keep T1's
  slowloris exposure until they move to the same server. That is a follow-up, and so is moving
  xbt-work to v2.
- `scripts/conformance.sh` defaults to B1 at `~/xbt-rnd/b1-agp-068` until this merges.

Tests: `crates/xbt402/tests/http_limits.rs` (`slow_bodies_do_not_stall_the_server`,
`slow_heads_do_not_stall_the_server_and_are_cut_off`, `an_endless_header_line_is_refused`,
`an_oversized_response_is_an_error_not_a_truncated_body`, `a_body_cut_short_is_an_error`) and the
AGP-068 tests in `lifecycle.rs` (`a_payment_is_bound_to_one_request_and_one_origin`,
`concurrent_calls_get_the_numbers_of_their_own_reservation`,
`a_seq_spent_on_a_refusal_survives_a_restart`, `the_receipt_covers_the_response`,
`an_altered_conditional_answer_keeps_the_hash_lock`).

## Portability

No platform-specific dependencies: libsecp256k1 (C, via `secp256k1-sys`), pure-Rust hashes and JSON,
`getrandom`, std threads (no async runtime). The payer HTTP client uses `ureq` with rustls/ring
(no OpenSSL). The xbt402 server is std (`http-server`, AGP-068). wallet-ui, the work relay and MCP
still use `tiny_http`. `cargo check -p xbt402` (library, and all features + the hub binary)
passes for x86_64/aarch64 Linux gnu and musl, armv7 and riscv64 Linux, x86_64/aarch64 macOS and
x86_64 Windows (gnu), with zig as the cross C compiler; aarch64 links (`xbt402-hub` 4.5 MB).
Under v1.2 payee-pays, the close response reports `cum` as what the close pays the payee **net of
its fee** (900 for a 1500 state with a 600 fee), and `unpaidMsat` as `spent − that`. So it shows
the close fee as unpaid (600000), and `/x402/settle`'s `amount` likewise. The on-chain amounts are
right. B1 `x402_channel.py` does this (`_close_paid` sums the payee outputs), and the Rust port
matches it byte for byte. The interop run records it as `provider_report_as_reference`. Whether the
reference should report the gross `cum` is for the lead (AGP-023 follow-up), not this port.

## The light backend: xbt-electrum (AGP-028)

A client with no node: the xbt402 payer (and later the wallet) reads the chain from Electrum servers
and trusts only what it can check. A port of B2's `agentwallet/electrum.py` (AGP-024) with the same
trust rules; the threat model is in B2 `docs/B2_CHAIN_BACKEND.md` and the crate docs.

```rust
use xbt_electrum::{Config, ElectrumBackend};
let mut cfg = Config::new(&["tcp://127.0.0.1:50001", "ssl://electrum.example:50002"], "main");  // mainnet: checkpoint 961640
cfg.store_path = Some(run_dir.join("headers-main.bin"));        // verified headers, re-verified at load
let chain = std::sync::Arc::new(ElectrumBackend::new(cfg)?);      // or Config::from_env (B2's variables)
let n = chain.block_count()?;                                     // our verified tip
let out = chain.tx_out(txid, vout, true)?;                        // proven confirmations; a mempool spend never hides it
chain.watch(&[&funding_spk])?; chain.wait_for_change(timeout);    // scripthash/headers subscriptions wake a watcher
let prov = Provider::new(chain.clone(), ...);                     // any ChainBackend user
let v = chain.call("gettxout", &json!([txid, 0, true]))?;         // the node RPCs of the client path, answered as the node does
```

* **Headers**: `HeaderChain` from the pinned checkpoint (PoW, Knots retarget, linkage, height, time),
  most work wins, caught up in batches of 4x2016 headers per round trip. Servers that answer but
  cannot serve the checkpoint mean the wrong chain (`Kind::CheckpointMismatch`).
* **Transactions**: the raw tx must re-serialize and hash to the txid; confirmed only with a Merkle
  proof into our header whose committed txcount fixes the proof's depth and position bound.
* **Servers**: histories and unspent lists are the union over every live server (queried in
  parallel), broadcasts go to all, the fee estimate is the median (and marked unverified).
* **Refunds cannot be suppressed**: a spend seen only in a mempool never makes an output count as spent.
* Node-only calls (wallet, `getblock`, mining) are refused with `Kind::LightBackend`.

Tests: `crates/xbt-electrum/tests/backend.rs` runs every call, TLS, batching, persistence, reconnects
and subscriptions against a simulated chain and Electrum server (`sim` feature), and the lying servers:
a hidden tx, withheld headers and a stale tip, a lying fee, the wrong chain, a weaker and a stronger
(reorging) chain, three kinds of bad proof, a substituted tx, wrong heights, an invented spend that
tries to stop a refund, and broadcasts answered with another txid.

`scripts/electrum_interop.sh` (ports 33300-33399) runs a light Rust payer (its own hot key; every read
and broadcast through Electrum) against two patched electrs 0.11.1 (AGP-024), one behind TLS, both
required, on a Knots 29.4.2 regtest node, against the Python B1 provider. The node is only the faucet,
the miner, and the oracle every answer is compared with.

| | provider | what | result |
|---|---|---|---|
| E1 | Python B1, v1.1 payer-pays | open, 10 calls, close; the close change counted late (mempool hint, then proof after the block's notification) | payee 1500, payer 197900, 14/14 checks, 35/35 answers = node |
| E2 | Python B1, v1.2 payee-pays | same | payee 900, payer 198500, 14/14, 35/35 |
| E3 | Python B1 (then killed) | open, 3 calls, the provider vanishes; early refund refused (non-final); refund at expiry via Electrum, proven | refund 199400, 10/10, 18/18 |

Deliberately different from B2's Python: `gettxspendingprevout` reports mempool spends only, as
Knots does (the Python also reported confirmed spends; the typed `spending_tx` still does), and the
fee estimate is the median over servers (the Python took the first answer).

## Pay-with-work: xbt-work (AGP-032)

`crates/xbt-work` implements the x402 scheme `xbt-work` (v1 draft, XBT-053 `agp-011`
`docs/xbt-work-spec-v1-draft.md`): a client with hashrate pays by mining. It mines as
`<identity>.pw-<invoice>` so the Prime credits the provider, then presents the Prime's signed
cumulative receipt with each call. It ports XBT-053 `receipts.py`, `nta.py` and `relay/`, plus the
xbt-070 coinbase audit.

* **Provider.** `Provider::new(..).with_scheme(Arc::new(WorkScheme(Arc::new(WorkProvider::new(cfg)?))))`:
  every unpaid 402 lists `batch-settlement` and `xbt-work`. `POST /x402/xbt-work/invoice` issues invoices
  (`Cache-Control: no-store`, a bound on unfunded invoices, `429 too_many_invoices`). Payments are
  checked in the §9.1 order and debited durably (a 0600 state file, write+fsync+rename) before the
  handler runs. A handler answer ≥ 500 releases the debit. `refresh` pulls receipts through the
  blinded relay; `set_epoch` re-prices new 402s (§6.3). After an equivocation or a failed audit, the
  Prime's receipts are refused.
* **Payer.** `Client::new(..).with_payer(Arc::new(WorkPayer::new(cfg)?))`: on a 402 offering
  `xbt-work` it takes an invoice (`prepare` returns the username to mine as), fetches and verifies the
  latest receipt through the relay, and presents it with a fresh `n` and `auth`. It checks every
  `SettlementResponse`: the invoice, `req`, the charge within the quote, and `spentWork` growing by
  exactly `charged`. An optional pinned Prime key is checked against the offer.
* **Audit.** `WorkProvider::audit(window, deferrals, V, paid)` applies §10.3 with the provider's own
  intervals and counts signed deferral lines (NTA `unattested` carry) as debt. The carry ledger
  tracks what is owed. A failing block yields a §10.4 fraud proof that `check_fraud_proof` verifies
  from its signed contents alone. Per invoice, the proof carries the latest receipt and the in-span
  receipt that brackets the window, so a third party can prove the work.

Conformance (`scripts/work_conformance.sh`): the Rust emitter rebuilds XBT-053's `vectors.json`
byte for byte (`cmp`). The Rust checks pass 91/91 over the published file (16 sections recomputed,
75 independent checks). XBT-053's own `check_work_vectors.py` passes 124/124 over the Rust-emitted
file.

Regtest (`scripts/work_interop.sh`, ports 34100–34199) uses primed `rnd/agp-011`, the stock DATUM
gateway, stratum-grind and the XBT-053 relay. Results on 2026-09-29 (evidence in
`docs/work-interop-agp032-*.json`):

| payer | provider | checks |
|---|---|---|
| Rust (xbt402 Client + WorkPayer) | Rust (xbt402 Provider + WorkProvider) | 20/20, incl. the provider's own audit and both fraud proofs |
| Python (xbt-063 `pww_payer`) | Rust | 20/20 |
| Rust | Python (xbt-063 `flagship.server` WorkRail) | 18/18 |

Regtest's difficulty makes `8 × D` less than one share, so primed runs with `window-min-work = 64`.
Otherwise the window holds only the latest share and no receipted span can be proven inside it.

Portability (`scripts/work_matrix.sh` → `dist/WORK_MATRIX.md`): 20/20 builds (10 AGP-031 targets ×
release and release-small, 1.8–2.5 MB self-test). The self-test runs natively on x86_64 glibc and
musl. Pure-Rust Ed25519 (`ed25519-dalek`) and ChaCha20-Poly1305 (RustCrypto); libsecp256k1 only
through `xbt-primitives` (NTA BIP340).

## xbt-work follow-ups: caps, the Rust relay, a live NTA leg (AGP-043)

* **§13.1 credit caps.** `WorkConfig::caps` (`CreditCaps { per_invoice, total }`, work units) caps credit that
  no passing audit covers yet. Receipted work beyond the caps is **held**: kept in the book, not spendable, and
  credited once a coinbase audit passes above it. The audit intervals record every receipted increase whether
  credited or held, so the audit bound never depends on the caps. Owed carry counts as unaudited credit too:
  above `max_owed_carry_sats`, or growing over `carry_growth_blocks` audited blocks, no new credit is extended
  until carry is released. A call the held work would have paid is refused with `credit_cap`, `carry_cap` or
  `carry_growing` and the balances in `work` (`heldWork`, `unauditedWork`, the caps); the Rust payer reports
  that as its error instead of paying again. Auditing a block again replaces its verdict and carry. Without caps
  the book is the reference, byte for byte (the vectors are unchanged: 91/91 and 124/0).
  `xbt-work-provider`: `--cap-invoice[-sats]`, `--cap-total[-sats]` (sats are converted at each epoch's price),
  `--max-carry-sats`, `--carry-growth-blocks`, `--nta` (refuse an identity that is not key-path P2TR, §13.8),
  `--audit-depth K` (audit every pool block K deep on its own), `GET /admin/xbt-work/report`.
* **The Rust relay server.** `crates/xbt-work-relay`, binary and image `xbt-work-relay` (docs/CONTAINER.md §9): a
  keyless store of exactly-1,052-byte blobs; a public GET-only listener (no listing, `no-store`, a token bucket
  per client) and a separate push listener for the Prime (optional bearer token `relay-push-token`); one file
  per lookup on disk, bounded by count and age. `scripts/work_interop.sh` now uses it by default (`RELAY=py` for
  the XBT-053 relay); `scripts/relay_container_test.sh` tests the image.
* **The live NTA leg.** `scripts/work_nta.sh` (ports 34300–34349, ~20 min): AGP-011's NTA regtest stack with the
  Rust provider (`--nta`, caps 1/1, carry cap 10 XBT), the Rust payer and the Rust relay. A: paid, the cap holds
  the new share (`credit_cap` live), the audit releases it. B: signer stopped, a signed `unattested` deferral
  line, the Rust audit passes on it (a fraud proof without it), carry freezes new credit (`carry_cap` live). C:
  paid with the carry, released. D: a pool block outside the invoice covers the rest. Then the payer's 19 checks.
  42/42 on 2026-09-29 (`docs/work-nta-agp043-20260929-032035/`).

## The coinbase audit without trusting the Prime (AGP-065, Guida P1–P6)

Chris Guida reviewed the public snapshot (xbt-rs `ecdbb50`). His point: the §10.3 audit took every
number from the Prime's own window statement, so a Prime colluding with a payer could receipt work
nobody mined and then sign a statement that excused the unpaid coinbase. Every finding was still
present on `main` (`c8d607b`). Each now has a test in `crates/xbt-work/tests/guida_p.rs`; P1–P4 were
first run against `main` and failed there.

* **P1: the provider pins the Prime's terms.** `WorkConfig::terms` (`audit::PrimeTerms { window,
  window_min_work, window_tolerance_bps, fee_bps, max_min_payout }`) comes from the provider's config,
  never from a statement. `PrimeTerms::bounds(&ChainBlock)` turns it into `AuditBounds`:
  `window_work ≤ ⌈max(target(bits), target(prev_bits)) × (10⁴ + tolerance) / 10⁴⌉`, where
  `target(b) = max(⌈window × D(b)⌉, window_min_work)` (primed's own rule, `state.rs` 651–654) and `D` is
  the difficulty of the block's own nBits and of its parent's (the Prime may have built the window
  under either). `fee_bps` is capped at the advertised fee, and `min_payout` at `max_min_payout`.
  `audit_block` and `check_fraud_proof` both use `min(statement, bound)` for each value, so a third party
  holding the same terms convicts from the proof alone. A proof that needed a bound carries it under
  `"bounds"`; with no bound applied it is the AGP-032 document, byte for byte. A statement whose
  `window_start` is lower than that of an audited block beneath it is refused (`window_start_regressed`)
  and the block's credit stays held. A pass where `expected` fell below `min_payout` records the
  shortfall as owed carry (`belowMinSats`) instead of forgiving it. Tests:
  `p1_colluding_prime_statements_fail_the_audit` (`window_work = u64::MAX`, `fee_bps = 10000`,
  `min_payout = u64::MAX`), `p1_an_honest_statement_is_not_bounded`, `p1_window_start_is_monotonic`,
  `p1_a_below_min_pass_is_owed_carry`, `terms_bound_the_window`. Inside the bounds, the size of the
  window and who did the rest of its work are still the Prime's word.
  `docs/xbt-work-share-log-commitment.md` proposes a per-block commitment to the share log that a
  provider can sample (a spec proposal for XBT-053, not implemented).
* **Where the Prime validates shares.** The Prime is primed (`AwokenLazarus/Bitcoin`, branch `rnd/agp-011`,
  `91b2d8b`); no pool code changed. `prime/primed/src/session.rs` `on_pow` (about lines 1340–1575)
  takes the share's job and coinbase sections, then holds the job's height, parent and nBits to the pool
  node's tip (stale, wrong-bits and dead-parent shares are refused). `prime/wire/src/verify.rs` `verify`
  (about 420–600) rebuilds the coinbase (its BIP34 height must be the job's), refuses a coinbase that
  does not pay the split the Prime issued, rebuilds the BLAKE2b header from the merkle branches and the
  share's own fields, and checks the hash against the share target. Back in `on_pow`, a pool-wide set
  allows one credit per hash per height (about 1507–1527); then the TIDES ledger is credited and, for a
  `.pw-<invoice>` username, so is the receipt (`work_receipts.credit`, about 1563–1566). The audit does
  not re-check shares: it cannot see them. It bounds what the Prime can claim about them.
* **P2: a pass releases only what it covered.** The book keeps one `Span` per receipted increase:
  invoice, `lo..hi`, work, credited, coverage (`Open`, `Covered(h)`, `Skipped(h)`). A passing audit at `H`
  with window start `ws` covers only open spans with `lo > ws` and `hi < H`, exactly the intervals its
  bound counted. Spans at or below `ws` are `Skipped`: no later window can count them. Up to
  `CreditCaps::skipped` of skipped credit is forgiven; beyond that it counts against the total cap for good.
  Covered spans are credited in full, free of the caps. Tests: `p2_a_pass_releases_only_covered_credit`,
  `p2_skipped_credit_fills_the_total_cap`, `a_pass_covers_only_the_spans_its_bound_counts`.
* **P3: the statement must name the node's block.** The audit takes the block from the provider's node
  (`chain::ChainBlock { height, hash, value_sats, paid_sats, bits, prev_bits }`). A statement for another
  height or hash fails with `wrong_block` (`p3_statement_height_must_be_the_blocks`: `height = u32::MAX`
  and `height = window_start + 1`).
* **P4: a missing statement is never skipped.** `tools::window`: 200 is a statement, 404 (primed's
  "no window statement", `stats.rs` 434) is `Statement::Missing`, and anything else is an error.
  `WorkProvider::audit_chain`: a missing statement for a coinbase that paid the identity fails the
  audit and distrusts the Prime (`missing_statement`); for one that paid nothing it records nothing and
  the credit stays held. The audit loop stops at a Prime or node error and resumes at that block.
  Tests: `p4_a_statement_error_is_not_a_missing_statement`, `p4_a_missing_statement_fails_or_holds`.
* **P5: default caps.** With no cap flag, `xbt-work-provider` caps unaudited credit at 100 calls per invoice
  and 1,000 calls in total, and forgives at most 100 calls of skipped credit. `--cap-*-calls N` (new)
  sets a cap in calls at `--price`, and `off` removes a cap. The library's `CreditCaps::default()` is
  still uncapped (the reference's book, which the vectors pin). Test: `p5_the_binary_ships_non_zero_caps`.
* **P6: invoices, issuance, state, reorgs.**
  * An unfunded invoice past its TTL stays dormant for `invoice_grace_secs` (default 3600 s): its
    receipts are still pulled and a receipt with work still spends on it. Only a newer invoice that
    needs the room evicts it, oldest first (`p6_an_invoice_with_work_outlives_its_ttl`).
  * Issuance is limited per client (`max_unfunded_per_client`, default 16, `429 too_many_invoices`). The
    client is the TCP peer, which the xbt402 HTTP server now passes in `X-Xbt402-Peer`
    (`xbt402::provider::PEER_HEADER`; a client-sent copy is dropped). Behind a reverse proxy,
    `--trust-forwarded` takes the last `X-Forwarded-For` hop instead (`p6_issuance_is_limited_per_client`).
  * The state is snapshotted under the lock with a generation number and written (fsync, rename) outside
    it. A writer skips a snapshot older than the last one written; a failed write on the payment path
    rolls the debit back (`p6_concurrent_writes_keep_the_newest_state`).
  * Earlier receipts (`by_seq`) are persisted as `"receipts"` (state version 2), so a restart still
    detects an equivocation against them. AGP-043 state migrates on load
    (`earlier_receipts_survive_a_restart_and_agp043_state_migrates`). A state file that exists but
    cannot be read is now an error, not an empty book.
  * Reorgs: before each pass the audit loop compares the audited blocks with its node.
    `WorkProvider::orphaned(h)` undoes a reorged block's verdict and carry and reopens the spans it
    covered, so they count against the caps again (`p6_a_reorg_rolls_back_released_credit`). Audits deeper
    than `SETTLE_DEPTH` (144) settle: their spans and the receipts under their window are pruned.
* **DATUM usernames.** The Prime can only receipt `.pw-<invoice>` if the gateway passes the miner's
  username through. That needs `datum.pool_pass_full_users = true`, which is the DATUM gateway's
  default. With it false and `pool_pass_workers` on, the gateway sends `pool_address.<username>`; with
  both false, `pool_address` alone (`datum_protocol.c` 2720–2728). Either way the Prime credits the
  gateway's pool address and no receipt appears. `xbt-work-payer prepare --gateway-config FILE` refuses
  such a config (`payer::check_gateway_config`, `datum_gateway_must_pass_full_usernames`). If no
  receipt arrives within 5 minutes, `pay` prints a hint naming the setting. On regtest the first
  receipt can take longer than that, so the hint is advice, not an error.
* **M1: locked coinbases.** `chain::Maturity::from_deployments` reads Knots'
  `getdeploymentinfo.deployments.long_coinbase_maturity` (`coinbase_start_height`, `height`,
  `height_end`, `maturity`) from the node and is never hard-coded. A node without the deployment means
  ordinary maturity (100). The choice: a locked payout **counts as paid** in the audit, because the
  coinbase did pay the identity and the Prime cannot do better. It is reported apart as illiquid.
  `WorkProvider::payouts(tip, &maturity)` and `GET /admin/xbt-work/report` `payouts` split the audited
  payouts into `liquidSats` and `lockedSats`. A provider that sells credit against its payouts should
  count only the liquid part as money in hand, and its caps bound what it extends meanwhile.
  `relay_at(h)` is when a spend of the coinbase relays (mempool policy applies the long depth to every
  coinbase); `consensus_at(h)` is the consensus rule (`m1_locked_payouts_are_paid_but_illiquid`,
  `maturity_from_the_node`).

**For embedders (cmp and anyone linking `xbt-work`).** Wire and behaviour changes:

| change | before | now |
|---|---|---|
| `audit_block(book, sw, V, paid, deferred)` | statement on trust | `audit_block(book, sw, &ChainBlock, &AuditBounds, deferred)`; `AuditBounds::STATEMENT_ONLY` is the old check |
| `check_fraud_proof(proof, pk)` | | `check_fraud_proof(proof, pk, &ChainBlock, &AuditBounds)` |
| `WorkProvider::audit(sw, deferred, V, paid)` | | `audit(sw, deferred, &ChainBlock)`, plus `audit_chain(&ChainBlock, Statement)` |
| `AuditOutcome` | | adds `below_min_sats`, `window_work`, `fee_bps`, `min_payout`, `bounded` |
| `WorkConfig` | | adds `terms`, `invoice_grace_secs`, `max_unfunded_per_client`, `trust_forwarded` |
| `CreditCaps` | `per_invoice`, `total` | adds `skipped: u64` (default 0: nothing forgiven) |
| `tools::window` | any non-200 → `None` | 404 → `None`, other errors → `Err` |
| provider state file | version 1 | version 2 (`spans`, `settledSkipped`, `receipts`); version 1 loads |
| fraud proof JSON | | `"bounds"` added only when a bound applied |
| `xbt-work-provider` | caps off by default | 100/1,000/100 calls; Prime terms flags; reorg check; admin from loopback peers only |
| xbt402 HTTP server | | sets `X-Xbt402-Peer` to the TCP peer on every request |

The pricing fee is now `terms.fee_bps`, the fee the audit holds the Prime to. Python parity: the
same logic lives in XBT-053 (lazarus-xbt), and the spec diff is routed there. The vectors are unchanged
(`work_conformance.sh`: 91/91 and 124/0, byte-identical).

Results on 2026-10-08: `cargo test --workspace` (464 passed) and `scripts/conformance.sh`;
`scripts/work_interop.sh` Rust → Rust 20/20 with the provider and payer pinned to primed's regtest terms
(`--prime-window-min-work 64`), no honest statement bounded
(`docs/work-interop-agp065-2026-10-08-payer-rust-provider-rust.json`); `scripts/work_nta.sh` 42/42 with
primed's fee of 5,000 bps pinned (`docs/work-nta-agp065-2026-10-08/`). One NTA check changed with P2: at
C, block 115's pass covers the B share, which is now credited outside the caps (AGP-043 held it and
released it by cap), so nothing stays held.

CPU (`examples/audit_cost.rs`; armv7 musl under `qemu-arm-static` as the Pi-class figure, x86_64 native
beside it; pass lines declared before measuring):

| step | pass line (armv7) | armv7 | x86_64 |
|---|---|---|---|
| `PrimeTerms::bounds` (one block) | — | 2.2 µs | 0.1 µs |
| `audit_block`, 10 / 1,000 spans | ≤ 5 ms | 0.43 / 0.79 ms | 0.03 / 0.07 ms |
| credit room per paid call, 1,000 spans | ≤ 1 ms | 18 µs | 1.8 µs |
| `check_fraud_proof`, 1 / 100 invoices | ≤ 20 ms | 0.95 / 40 ms | 0.06 / 2.9 ms |

The fraud-proof check misses its line at 100 invoices: 200 Ed25519 receipt verifications (AGP-032), of
which the bounds add 2 µs. It runs once per disputed block, not per call. `ReceiptBook::credit` now
makes one pass over the spans; before, it recomputed the caps' room for each open span.

## Linking xbt-rs from cmp (AGP-035)

xbt-compute's Rust runtime pins this repo by full rev with `default-features = false`. What that
gets, and what it must not get:

**No `arbitrary_precision`.** Cargo unifies features, so a serde_json feature here would change
`serde_json::Number` in every crate cmp links. `cargo tree -e features -i serde_json` shows only
`default`, `std`, `preserve_order` and `indexmap`. Routed amsat prices and meters (above u64) are
still exact: `xbt402::json::parse` reads JSON without serde_json ever rounding a number through
f64, holding an integer beyond i64/u64 as a reserved one-key object `{"$xbt402::int": "<decimal>"}`
(`json::big_int`/`big_uint`/`as_big_int`/`int_text`), which `json::dumps`/`dumps_compact`/`canon`
write back as the bare integer. Floats are parsed with Rust's correctly rounded parser and written
as Python's `repr`. A document that contains the reserved key itself is refused. Every xbt402 input
goes through `json::parse`, and every output through `json::dumps`: the 253 + 79 vectors are
byte-identical both ways and `route_interop` is green. If cmp handles xbt402 JSON itself, it reads
with `xbt402::json::parse` and writes with `xbt402::json::dumps*`. `serde_json::to_string` would
print a big integer as the reserved object.

Options weighed for this (best-performing-stack rule):

| option | exact amsat | cmp's serde_json untouched | change in xbt-rs | risk |
|---|---|---|---|---|
| keep `arbitrary_precision` | yes | **no** (the reason for AGP-035) | none | changes cmp's numbers |
| a number newtype over `RawValue` (`raw_value` feature) | yes | yes (`raw_value` adds a type, changes no semantics) | typed structs instead of `Value` across hub, seller, route client and vectors (~4k lines) | large rewrite of byte-exact code |
| decimal strings at the Rust boundary | no: B1 signs amsat as a JSON *number*, a string canonicalises differently | yes | small | breaks signature interop |
| a canonical writer for the signed messages only | signing yes, but the parse is still lossy | yes | medium | quotes nested in 402 bodies are still rounded on read |
| **a lossless parse front end + reserved big-int object (chosen)** | yes, in both directions | yes, no serde_json features at all | `json.rs` (+ 25 call sites `serde_json::from_*` → `json::parse*`) | the reserved object must not leak through `serde_json::to_string`: every writer is `json::dumps*` |

**Clean-checkout builds.** `scripts/cmp_clean_build.sh [REF]` clones REF, deletes `.cargo/`, refuses
if any other cargo config or cross build variable is in effect, then runs `cargo zigbuild --release
--locked` (cargo-zigbuild 0.23.4 from `~/xbt-rnd/tools/zigbuild`, zig 0.16.0 from the ziglang venv)
of `-p xbt402 --no-default-features` and `-p xbt-signer` for x86_64/aarch64-unknown-linux-musl and
armv7-unknown-linux-musleabihf, checks each binary is a static ELF of its machine, and builds and runs
a cmp-shaped consumer that takes `xbt402` and `xbt-signer` as git dependencies. The one blocker was
here, not in the build: `xbt402-interop`'s path dev-dependency on `~/Bitcoin/lazarus/protocol` kept a
clean clone from even loading the workspace. That cross-check now lives in `tools/lazarus-crosscheck`.

**The surface with no features** (`crates/xbt402/tests/cmp_surface.rs`, run with
`--no-default-features` and only cmp-style `Transport`, `Wallet`, `ChainBackend` + `SpendScan` and a
signer):
* `Provider::new(chain, pay_to, cfg, ledger, price, handler)` takes its `Ledger`
  (`Ledger::open(path)` or `in_memory()`) and `Provider::serve(...)` is the whole HTTP surface.
* `Client::new(cfg, transport, wallet, height).with_signer(signer).with_ledger(ledger)?`: the
  channel book goes to any `ClientLedger` (`load`/`save` of keyed JSON records). `FileClientLedger` is
  an fsynced JSONL file, mode 0600, compacted on open; `MemoryClientLedger` is in memory. Every paid
  call, close and rollover saves what it touched (`Client::persist` after hand edits). A signer-held
  channel is stored as `"key": "signer"` and needs the same signer to load; a local key is stored as
  its secret. Additive: without `with_ledger` nothing changes.
* One process holds a Provider ledger and a Client ledger at once (the MoE dispatcher sells and buys).
  The test runs that, restarts the client from its file, and keeps paying on the same channels.
* `RoutePayer::new(hub, cfg, route_signer, wallet, transport, height)` pays two providers through
  one hub channel, one of them priced above u64 amsat.

**ECDSA vs `cmp/keys.py`.** `scripts/cmp_keys_ecdsa.py` (with cmp's venv; cmp's tree is only read,
no bytecode is written) signs 2,000 (secret, message) pairs with `OperatorKey(secret).sign(msg)` and with
`xbt_primitives::ecdsa::sign(secret, sha256(msg))` (via `xbt-ecdsa-cmp`). Edge keys 1, 2, 3, n−1,
n−2, 2^255 and messages from empty to 1 KiB give identical pubs and identical strict-DER low-S
signatures, and 4,000 cross-verifications agree.

### Micro-payments: 16–64 vendors at a few msat per call

**Direct channels (one per origin).** Numbers are the defaults (`ProviderConfig`, `ClientConfig`,
`channel.rs`):

| per origin | amount |
|---|---|
| funding tx (1 P2WPKH in → P2WSH + change) | ~153 vB; ~306 sat at 2 sat/vB |
| capacity locked | `ClientConfig.capacity` 200,000 sat (provider floor `min_capacity` 20,000) |
| first state (the least the vendor is ever paid) | `min_amount()` = DUST 546 sat (payer pays the close fee), 1,146 sat under v1.2 payee-pays |
| close | `STATE_VSIZE` 190 vB, `closeFeeSat` 600 sat |
| wait before the first paid call | `min_conf` 1 block (3 above 1,000,000 sat capacity) |

So each direct vendor costs at least 546 + 600 + ~306 ≈ 1,450 sat of floor plus fees over a
channel's life, whatever it is used for. Prices on direct channels are whole sats per call (`PriceFn`,
`ChargeFn`). The provider meters `spentMsat` and reports `owedMsat` = spent − 1000·cum. Postpay
signs a new state only when ⌈spentMsat/1000⌉ passes the last signed cum, so one floor state covers
the first 546 sat of use. A metered call can charge less than its price, but not
less than 1 sat. **Do not price a direct vendor below the DUST floor over the channel's life, and do
not use direct channels for sub-sat calls.**

**~64 channels in one Client:** memory is ~0.5 KB of struct plus ~1.9 KB of JSON per channel
(`accepted` terms, params, refund), about 160 KB for 64. Receipts are also kept per call (0.4 KB of
JSON each, more as a `Value`): 64 vendors × 10,000 calls is 640,000 receipts, so call
`Client::trim_receipts(n)` now and then. A `FileClientLedger` saves at most 16 receipts per channel,
about 8.7 KB per channel record. Opening means 64 fundings (~9,800 vB), 64 confirmations to wait for,
and 12.8 M sat locked at the default capacity. Note that the default `budget_sats` of 1,000,000 stops
at 5 channels: raise it. Closing means 64 × 190 vB ≈ 12,200 vB and 64 × 600 = 38,400 sat of close
fees, plus 64 × 546 = 34,944 sat of floors. In total that is ~22,000 vB on chain and ~93,000 sat of
fees and floors before any real use.

**Hub routing (the intended answer).** One ch1 to a hub (one funding, one close, one floor: ~340 vB
and ~1,450 sat in all) reaches every vendor. The hub runs the ch2s and charges `feeBaseMsat` +
`feePpm` per lock (defaults 1,000 msat + 2,000 ppm; carried exactly in 1e-6 msat, charged as the
ceil of the running total, never rounded per lock). Prices are amsat per call (1 sat = 10^21 amsat)
with exact meters on both sides and signed ROUTE-STATEs per call. Locks are per window (`window`
1 s) of ⌈owed⌉ sat, so at 5 msat per call a vendor is paid 1 sat per 200 calls, with no rounding lost.
`credit_msat` caps unpaid credit. That per-window lock *is* the aggregated per-N-calls payment. We
advise against a separate aggregation API: the window and the amsat meter already amortise it,
without giving up the per-call evidence.

