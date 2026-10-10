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
cargo deny check                   # AGP-075: licences (deny.toml), advisories, crates.io only
cargo clippy --workspace --all-targets --all-features -- -D warnings   # AGP-075: clean on main
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
From an external review of the hub: two High findings, H1 and H2, where the hub could pay a
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
  (AGP-073: the watcher sweeps these too, and holds one its ch2 wrote off.)
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
  (close or refund). This is the spec's choice (no route over a stale ch2). The follow-up was to
  close and refill such a ch2 early: AGP-073 does.

## Agent-wallet budget integrity and privileged methods (AGP-063)

Fixes for the external review's agent-wallet findings W1-W4, X1 and K1, plus the library payer's watermark.
Each test fails on `main` and passes here (the run is in the task's `result.md`). Most are in
`crates/xbt-signer/tests/review_w.rs`; B2's port (branch `agp-063`) has the same names in
`tests/test_review_w.py`.

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

review T1–T4. A few slow connections must not stall a provider, and a receipt binds one request and
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
- xbt-work moved to request binding v2 with the XBT-053 vectors (AGP-074): see "Embedders on
  xbt402 v1.3 (AGP-074)".

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
- The B2 wallet (`agp-068`, `8299cee`) binds the v2 digest. Since the AGP-063 merge it also checks the seller's receipt (request binding v2, status and bodyHash), as xbt-signer does.
- xbt-wallet-ui, xbt-work-relay and xbt-wallet-mcp still served with `tiny_http`, so they kept T1's
  slowloris exposure until AGP-072 moved them to the same server ("One bounded HTTP server for every service (AGP-072)"). Moving xbt-work
  to v2 is a follow-up.
- The interop scripts' B1 default went back to `~/xbt-rnd/b1` when this merged.

Tests: `crates/xbt402/tests/http_limits.rs` (`slow_bodies_do_not_stall_the_server`,
`slow_heads_do_not_stall_the_server_and_are_cut_off`, `an_endless_header_line_is_refused`,
`an_oversized_response_is_an_error_not_a_truncated_body`, `a_body_cut_short_is_an_error`) and the
AGP-068 tests in `lifecycle.rs` (`a_payment_is_bound_to_one_request_and_one_origin`,
`concurrent_calls_get_the_numbers_of_their_own_reservation`,
  `a_seq_spent_on_a_refusal_survives_a_restart`, `the_receipt_covers_the_response`,
`an_altered_conditional_answer_keeps_the_hash_lock`).

## Channel findings C1–C5 (AGP-067, external review)

The provider's close must confirm before the payer's refund is valid, the payer must not fund a
channel the seller then refuses, a rollover is the tx the payer signed, the payTo key and ledger
survive a restart, and one ledger file has one writer. B1 `x402_channel.py`/`ledger.py` on branch
`agp-067` does the same for C1, C2 and C5, and `tests/security/test_agp067_review_c.py` and
`test_agp067_review_c1.py` there use the test names of `review_c.rs` and `review_c1.rs`. C3 does not
apply to B1's client (it has no wire rollover; B1's hub already refuses `bad_rollover_reply`). C4 is
xbt-rs only (B1's launcher already seals its payTo key, P7). The conformance vectors are unchanged.

**Wire.**

- `/open` takes `"preflight": true` with a `channel` that has no `txid`/`vout`. The provider runs
  every check of a funded open that does not need the funding output (network, payTo, closeFeePayer,
  redeemScript, capacity and expiry against its policy). It records nothing and answers
  `{"preflight": true, "expiry", "maxCum", "minConf"}`, plus `closeFeePayer` and `minCum` under
  payee-pays, or the refusal the funded open would get. The Rust client, the B1 client and the
  xbt-signer session preflight before they fund. A provider from before AGP-067 answers
  `bad_request` (no `vout`), and only after its own terms checks have passed, so on `bad_request`
  the client funds and opens as before.
- The funded `/open` carries the same fields. In the Rust client `txid` and `vout` are now the last
  keys of `channel`, not the first (serde_json keeps insertion order); B1 keeps them first. JSON
  key order carries no meaning.
- A rollover reply is accepted only if `txid`, `nextChan` (`txid:1`) and `nextCapacity` match the
  rollover tx the payer computed and signed (`bad_rollover` otherwise). The next channel's refund
  is kept (`on_refund`) and its key bound before that check, so a provider that broadcast the real
  tx and lied about its id cannot strand the payer's refund.

**C1: the close bump.** The close pays the `closeFee` fixed at open (600 sat, about 3.5 sat/vB on a
171 vB close). Until now a fee spike through the close margin meant the close never confirmed and
the payer's refund took the whole channel back at expiry. Now the watcher (`close_due`, and
`close_locked` when the node refuses the close outright) works out the package feerate the close
needs for each block it is unconfirmed:

- the highest of `close_min_feerate`, the node's estimate for confirmation within a quarter of the
  blocks left (`estimatesmartfee`, clamped to 1–1008) and the mempool's floor
  (`max(mempoolminfee, minrelaytxfee)`);
- in the second half of the close margin, at least double the last send's rate once
  `close_bump_blocks` have passed without confirming (an estimate that lags the market).

If the close alone pays that, it is sent alone. Otherwise it goes out with a CPFP child that spends
the provider's own close output back to the same key (`submitpackage`), replacing the previous
child under BIP125 (the new child pays at least the old fee plus its own vsize). The child's fee is
capped at `close_bump_max_fee` and at the output less dust; at the cap the last child is rebroadcast.
`sweep_payee` spends the child's output when there is one. A node that answers `getrawtransaction`
for an evicted close does not fool the watcher: the close counts as in the mempool only while the
funding outpoint is spent there.

- `ProviderConfig`: `close_bump_max_fee` (default 10,000 sat; 0 is main's behaviour, the close
  rebroadcast and nothing else), `close_min_feerate` (1.0 sat/vB), `close_bump_blocks` (3).
- `ChainBackend` gains three methods with defaults, so existing backends compile unchanged:
  `estimate_fee_rate(target) -> Result<Option<f64>>` and `mempool_min_fee() -> Result<Option<f64>>`
  (both default to `None`, meaning no estimate) and `submit_package(&[hex])` (default: send each in
  order, only the last one's refusal counts). `Rpc` implements all three. An RPC error on the
  estimate or the floor counts as no estimate; `close_min_feerate` and the doubling still apply.
- The record is `extra.close_bump`: `{at, seen, rate, fee, txid, hex, capped, replaced:[[txid, fee]…]}`
  (`at` is the last send, `seen` the last block looked at). `close_failed` now names the bump's error
  after the close's own (`…; bump: close_bump_failed: …`).
- Limits. The child can only spend what the provider's output holds, so a small channel can only be
  bumped a little: a 2-call channel at 1,000 sat a call has 1,546 sat to give. Package relay (Knots
  and Core 28 and later) lets a close below the dynamic `mempoolminfee` in on its child's fee, but
  not one below the node's static `minrelaytxfee`: a node configured above 3.5 sat/vB refuses the
  close in any package. Payer-pays closes are bumped from the provider's output too.

Options weighed (best-performing-stack rule):

| option | wire change | needs | cost |
|---|---|---|---|
| raise the fixed `closeFee` | no | nothing | paid on every close in every market; still loses to a big enough spike |
| the 0xA3 fee-input close (SIGHASH_SINGLE\|ACP) | no | a provider wallet with spare UTXOs and their key on the watcher | a wallet hook per embedder, and UTXOs locked for every channel near its margin |
| anchors / TRUC (v3) closes | yes: a new state tx format both sides sign | v3 relay | a protocol version and new vectors |
| **CPFP from the provider's own close output (chosen)** | **no** | package relay (Knots 29 has it) | bounded by that output; one child sign per bump |

**Cost.** Per channel in its close margin, each block: up to three extra RPCs (estimate, mempool
info, `gettxout`) and at most one child signature. One ECDSA sign is 16.2 µs on the Ryzen 9 9950X3D
(`binding_bench`, AGP-068) and well under a millisecond on 32-bit libsecp256k1. Nothing is added
to a paid call.

**C2: preflight.** Options weighed: hand the provider a signed, unbroadcast funding tx to check (it
could broadcast and refuse, and every wallet would need a sign-without-broadcast hook), a separate
`/terms` endpoint (a second code path to drift from `/open`'s checks), or **the same `/open` with
`preflight` (chosen)**, which runs the exact checks of the funded open minus the outpoint. Cost: one
HTTP round trip per channel open (not per call), and no signature on either side.

**C3.** The client computes the rollover txid from the tx it signed (segwit: the witness is not in
the txid) and checks the reply against it. There is no wire change and no extra cost.

**C4: a provider that survives a restart.** `xbt-work-provider` and `xbt402-rust-provider` keep
their payTo key and their ledger under `--data-dir` (`XBT_WORK_DATA_DIR`; defaults
`./xbt-work-provider-data` and `./xbt402-rust-provider-data`). `xbt402-rust-provider --ledger FILE`
still overrides the ledger path. The key is `DIR/payto.key`, created once with mode 0600: it is
written to a temp file, hard-linked into place (a crash leaves no half-written key) and the
directory is fsynced. A key file with any group or other permission bit (`mode & 0o077`), or that
is not a key, is refused (error code `key_file`). `xbt-work-provider` runs a watcher (`close_due`) every `--watch-secs`
(`XBT_WORK_WATCH_SECS`, default 5), which closes channels before their payers' refunds and bumps
stuck closes. `load_or_create_secret(path)` is public for embedders. `xbt402-route-provider`
takes the same `--data-dir` (AGP-075; default `./xbt402-route-provider-data`); `--ledger FILE`
and `--secret HEX` still override the ledger and the key.

**C5: one opener per ledger.** `Ledger::open` and `FileClientLedger::open` take an exclusive
`flock(2)` on a sidecar `<path>.lock`, which holds the opener's pid. A second opener, in this
process or another, gets `ledger_locked` with the holder's pid. The lock goes with the ledger, and
with the process when it dies, so a crash never leaves a stale lock. B1's `Ledger` takes the same
lock with `fcntl.flock` (the same system call), and its `Ledger.close()` releases it. Options weighed:
the `fs2` or `fd-lock` crates (a new dependency for what std has done since 1.89), a lock on the
ledger file itself (the ledger is replaced by rename, which would drop the lock), a pid file without
a lock (stale after a crash, racy), or **std `File::try_lock` on a sidecar (chosen)**: no `unsafe`, no
new dependency, and it works on Linux, macOS and Windows. Cost: one syscall per ledger open. The
workspace MSRV is now **1.89**.

**Embedders.**

- A payer client from before AGP-067 talks to a new provider unchanged (it never preflights). A
  new client talks to an old provider through the `bad_request` fallback.
- Anything that opens one ledger file twice in one process (tests that "restart" a provider while
  the old instance is alive) now gets `ledger_locked`. Drop the old instance first, or copy the
  files the way a crash leaves them: `xbt402_interop::crash_copy(from, to)` copies a ledger file or
  directory and skips `.lock`. B1's tests use `sechelp.crashed(...)`, which releases the old
  instance's lock.
- A provider binary started without `--data-dir` now writes `./xbt*-provider-data` in its working
  directory instead of keeping everything in memory.
- Custom `ChainBackend`s get the defaults above. Override `submit_package` (and the estimate and
  floor) to get the bump through a package-relay node; with the defaults the close and child are
  sent one at a time, which works whenever the close alone clears the floor.

**Regtest.** `scripts/close_bump_regtest.sh` (ports 24860–24869) runs `xbt402-close-bump` against a
private Knots 29.4.2 node with `maxmempool=5`. A direct channel and a hub ch2 are each opened with
the bump on and off. Before the close margin the mempool is filled at 9.5 sat/vB until
`mempoolminfee` is 10.5 sat/vB, and from then on blocks take only packages paying 10 sat/vB or more.
Result (`run/close_bump.json`):

- with the bump, the direct and the ch2 close go in with a 2,351 sat child (package 10.50 sat/vB)
  and confirm in the first block after the margin, 19 blocks before expiry, paying the provider its
  best state;
- without it, both closes are refused (`mempool min fee not met`) until expiry. Then the payer's
  refund at 12 sat/vB and the hub's ch2 refund take both channels back.

Tests: `crates/xbt402/tests/review_c.rs` (`c2_a_refused_open_funds_nothing`,
`c2_the_preflight_records_nothing`, `c2_a_provider_without_preflight_still_opens`,
`c3_a_rollover_reply_naming_another_txid_is_refused`,
`c4_the_payto_key_persists_0600_and_a_loose_file_is_refused`,
`c4_a_restarted_provider_keeps_its_key_and_channels_and_closes_them`,
`c5_a_second_provider_on_one_ledger_is_refused`, `c5_a_second_client_on_one_client_ledger_is_refused`,
`c5_another_process_holding_the_lock_is_refused`) and `review_c1.rs`
(`c1_a_close_below_the_mempool_floor_goes_in_with_a_child`,
`c1_without_the_bump_the_close_never_confirms`,
`c1_the_bump_follows_the_estimate_and_escalates_near_expiry`,
`c1_the_child_never_pays_more_than_the_cap_or_the_output`,
`c1_the_payee_sweep_spends_the_child_after_a_bump`, `c1_a_close_that_pays_enough_is_left_alone`),
which run against a mempool model with a floor, full RBF, `submitpackage`, an estimate and
fee-market blocks.

## One bounded HTTP server for every service (AGP-072)

review T1 for the other servers. AGP-068 fixed xbt402's server only; xbt-wallet-ui, xbt-wallet-mcp
(streamable HTTP) and xbt-work-relay (both listeners) still served with `tiny_http` 0.12, with no
header-line cap and no read deadline, and the MCP started one thread per request with no limit.
All three, and xbt402, now listen with **`xbt_svc::http`**: the AGP-068 server, moved into xbt-svc
(which all four already depend on) behind a small `Handler` trait. `tiny_http` is gone from the
workspace (`Cargo.lock` loses it; `cargo tree -i tiny_http` finds nothing).

**Limits** (`xbt_svc::http::Limits::default()`, the same as AGP-068): 8 KiB header line and 32 KiB
head (431), the head within 10 s (408) and the body within 30 s, both absolute; at most 64
connections (503); Content-Length bodies only, at most the handler's `body_limit` (413 before a
body byte is read; Transfer-Encoding is 501); `Expect: 100-continue`; `Connection: close`.

**What changed in the server while moving it:**

- Connection threads are reused (an idle one waits 60 s for the next connection) instead of one
  spawned per connection. The accept thread only queues a connection, so it is no longer the cap.
- A complete request runs on its connection thread once one of `threads` handler slots is free,
  instead of being handed to a worker and back. The bound on concurrent handlers is the same;
  two thread switches per request are gone. A panicking handler still costs a 500 and its slot
  is given back.
- `HEAD` gets the headers and the length but no body; 1xx, 204 and 304 carry neither.
  `Content-Length`, `Connection` and `Transfer-Encoding` are the server's: a handler's copies are
  dropped, as before any header holding CR, LF or NUL.
- The server's own refusals (400, 408, 413, 431, 501, 503) are `text/plain` with `Cache-Control:
  no-store` and `nosniff`.
- An accept error (out of descriptors) backs off 10 ms instead of spinning; a failed thread
  spawn closes that connection.

**Per server.**

| server | handler slots | body limit | kept |
|---|---|---|---|
| xbt402 provider / hub | the caller's `threads` | the service's, per path | public API (`serve_http`, `serve_service`, `serve_listener`, `HttpService`), `X-Xbt402-Peer` from the socket only, `X-Forwarded-Proto` + `Host` URL, duplicate `PAYMENT-SIGNATURE` is 400 |
| xbt-wallet-ui | `XBT_UI_THREADS` (4) | 256 KiB | security headers on every app response, Host and Origin checks (AGP-063 W4), `Running` stops on drop |
| xbt-wallet-mcp | `HTTP_WORKERS` = 16 (was unbounded) | 1 MiB | bearer token and token file, Origin allowlist (AGP-063 X1), loopback guard; new `serve_listener` for a caller-bound listener |
| xbt-work-relay public | `--threads` (8) | 1052 B (a blob, so a misdirected push still gets 405) | rate limit per client, no-store, no listing |
| xbt-work-relay push | `--threads`, at most 4 | 1052 B | push token, exact blob length |

**Behaviour changes for operators and embedders.** Every answer closes the connection (browsers
and the MCP SDKs reconnect; `tiny_http` kept connections alive). A chunked request body is 501
(the MCP SDKs send Content-Length). Over-limit bodies get the server's plain-text 413 instead of
the app's (the MCP's was a JSON-RPC error). The MCP runs at most 16 requests at once; a paid tool
call waiting on a funding confirmation holds one, and further requests wait in their connection.
No wire change.

Options weighed (best-performing-stack rule):

| option | outcome |
|---|---|
| each crate depends on xbt402's `http-server` | links the provider and secp256k1 into the UI and the relay, which are meant to stay small and keyless |
| a new `xbt-http` crate | works, but xbt-svc already is the shared std-only service plumbing all four use |
| `hyper` / `axum` | an async runtime, ruled out for Pi-class boxes (AGP-068) |
| keep `tiny_http` behind a reverse proxy | the bare-metal default stays exposed |
| **move the AGP-068 server into xbt-svc (chosen)** | no new dependency, one implementation and one set of tests |

**Cost.** Pass line declared before measuring: (a) median latency of `GET /healthz` on loopback,
a fresh connection per request, served by xbt-work-relay, is at most `tiny_http`'s + 50 µs; (b) on
armv7 the extra per request is at most 0.5 ms. Measured with
`cargo run --release -p xbt-svc --example http_bench -- 127.0.0.1:29080 /healthz 5000 8` against
`xbt-work-relay --bind 127.0.0.1:29080 --push-bind off --memory` built from `main` (9ec4090) and
from this branch, on a Ryzen 9 9950X3D, two runs each:

| build | median | p99 | 8 clients |
|---|---|---|---|
| `tiny_http` (main) | 114 / 121 µs | 163 / 212 µs | 49.7k / 38.5k req/s |
| first cut: a thread spawned per connection, worker hand-off | 147 µs | 197 µs | 28.6k req/s |
| **reused connection threads, handler slots (shipped)** | **89 / 85 µs** | **143 / 125 µs** | **57.4k / 69.0k req/s** |

(a) passes: the shipped server is faster than `tiny_http`. The first cut passed (a) on latency but
halved throughput, because the accept thread spawned a thread per connection; that is why
connection threads are reused. (b) was not measured (no armv7 box or emulator, as in AGP-068).
With threads reused, a request costs the same kind of work as under `tiny_http` (a few syscalls,
one buffer), and no thread spawn, so (b) holds by construction. The three binaries cross-build for
`armv7-unknown-linux-musleabihf`, and the x86_64 relay binary shrinks from 1.12 MB to 0.77 MB.

Tests: the AGP-068 slowloris checks as shared functions in `crates/xbt-svc/tests/common/slowloris.rs`
(`slow_bodies_do_not_stall_and_are_cut_off`, `slow_heads_do_not_stall_and_are_cut_off`,
`an_endless_header_line_is_refused`), run by `tests/http_limits.rs` in xbt-wallet-ui (3 tests),
xbt-wallet-mcp (3) and xbt-work-relay (5, both listeners). All 11 fail on `main`: no 431 after
4 MiB of one header line, slow heads held for 20 s, slow bodies stall the UI and the relay, and
the MCP holds a body that never comes for over 60 s. The server's edges are in
`crates/xbt-svc/tests/http_server.rs` (HEAD and 204, header injection, a panicking handler, the
Content-Length rules and 100-continue, the socket peer, stop). xbt402's `http_limits.rs` passes
unchanged. Each slow-body test waits for the 30 s body deadline.

## Hub follow-ups: sealed ch2 keys, written-off ch2s, orphan locks, preflight (AGP-073)
Four follow-ups from AGP-063 (K1) and from the trade-offs of AGP-064 and AGP-067. The same changes
are in B1 `agp-073`, with the same test names. All the tests below fail on `main` (`4bbcefc`) and pass
here.

**K1: the ch2 payer keys are sealed at rest.** The hub's state file (`<datadir>/ch2.json`) held every
ch2 payer key in plaintext: the live and next ch2s, the archive, and a rollover's next ch2 written
ahead inside a record. Each key is now stored as `secret_sealed` in the B2 keystore's blob format:
`{"v":1,"alg":"aes-256-gcm","kdf":"keyfile","salt":"","nonce","ct","aad":"xbt402/hub-ch2"}`. The rest
of each record stays readable, for the operator and the reconcile tools.
* **The wrap key** is 32 random bytes, kept in a file of mode 0600 (32 raw bytes or 64 hex). It is
  made with `O_EXCL`, and a file that is not regular or is open to group or others is refused
  (`keystore`). `xbt402-hub` takes it from the config's `wrap_key_file`. Failing that, in a container
  or with `XBT_SECRETS_DIR`, it uses the secret `hub-wrap-key`, made on first start. Otherwise it uses
  `<datadir>/hub-wrap-key` and logs a warning: beside the file it seals, it only protects copies of
  `ch2.json` made without it.
* **On load**, every blob is opened with the wrap key. The hub refuses to start (`keystore`) if a blob
  does not open (another wrap key, a changed file), or if a key is not its record's `payer_pub` (a blob
  moved to another record; checked for every record not yet final).
* **A legacy file** with plaintext keys is read once and rewritten sealed at startup. The event is
  `ch2_keys_sealed {count}`, with a line on stderr. The old file's blocks and any backups still hold
  the keys.
* A save seals only keys it has not sealed before (each blob is cached in memory), so a write does no
  AES work once a ch2 is funded. The temp file is created 0600 before the rename.

Design comparison (the best-performing-stack rule):

| option | per-write cost | file readable | unattended restart |
|---|---|---|---|
| **per-key AES-256-GCM, cached blobs (chosen)** | a cache lookup per key (31 µs armv7, 10 records) | yes, except the keys | yes |
| whole-file AES-256-GCM | encrypt the whole file on every write, growing with the archive | no | yes |
| passphrase KDF (scrypt or Argon2) for the wrap key | as chosen | as chosen | no: an operator at every start |

Per key keeps the write path flat on small boards and the file inspectable. `kdf: "keyfile"` leaves
room for a passphrase later. The Rust side uses RustCrypto's `aes-gcm` and `zeroize`: pure Rust, no C,
builds for every target in the matrix, and already in the lock through `xbt-signer` (whose keystore
cannot be reused: `xbt-signer` depends on `xbt402`). No new duplicates in `cargo tree -d`. B1 uses
`cryptography` (now in `requirements.txt`; only `xbt402.hub_keys` imports it).

**A ch2 blocked by a written-off lock is closed early.** AGP-064 blocks routing and rollover over a ch2
with a written-off lock until the ch2 closes or is refunded, which could be its whole life. The
watcher now asks the provider to close that ch2 at once, once a block until it does, with the best
state (`ch2_close`, `why: "written_off"`). A close that shows t pays the held lock on ch1; one that
confirms without t releases the hold (AGP-064).
* After a **refusal** (the provider answered 400 after taking the pre-signature), the hub refills: its
  next ch2, if one was funded ahead and is open, takes over at once (`ch2_switch`, `why:
  "written_off"`) and the old one is closed as retired (AGP-057); otherwise a new ch2 is funded after
  the close.
* After a **timeout** (no reveal in time), the hub stopped routing to that provider (AGP-064), so it
  closes the ch2 and does not fund a new one.
* A ch2 with nothing signed but a written-off lock is closed too (before, a ch2 with nothing signed
  was "idle" and left to its refund). A failed close request is reported
  (`ch2_written_off_close_failed`) and asked again next block.

**Orphan ch1 locks are swept by the watcher.** A ch1 lock that no route is forwarding and that sits on
no ch2 (the hub stopped between its two write-aheads) was dropped only when the client asked to
close. The watcher now checks every open ch1 with a lock, each tick, before the margin close. The
check runs under the provider's busy flag, which `route()` holds from before it writes the lock until
its forward ends, so a lock in flight is never touched. AGP-064's drop had a gap: if the crash came
between a void's two writes, ch2 had the lock written off (its pre-signature may be out) while ch1
still had it as its lock, and the drop let ch1 close below it. Such a lock is now held in the base
like any written-off lock (`orphan_lock_held`), and the client's close is refused `lock_pending`
until it resolves. Other orphans are dropped as before (`orphan_lock_dropped`).

With the sweep, the hub now settles a lock's ch1 side before its ch2 side (the provider's answer,
and t read off a close). A stop between the two leaves the ch2 lock pending, which the provider's
answer or its close completes again; the other order left a ch1 lock with no ch2 lock, which the
sweep would drop unpaid. Completing a lock a second time returns the first result.

**C2: the routed funders ask before they broadcast.** AGP-067 made the payer client preflight
`/open`. `RoutePayer::open` (ch1, to the hub) and the hub's ch2 funding (`connect`, refills,
`fund_ch2`) funded first and asked afterwards. Both now send the same preflight (`"preflight": true`,
the terms, no funding outpoint) and fund only after a yes. A refusal is passed on with its code
(`ch2_preflight_refused` on the hub), and nothing is funded or written. A provider from before AGP-067
answers `bad_request`, and the funder goes on as before. B1's route payer already preflighted (its
open is `XbtChannelClient._open`); its hub did not.

**Cost.** Pass lines declared before measuring, armv7 musl release under `qemu-arm-static` as the
Pi-class figure, x86_64 native beside it (`hub::tests::seal_cost`, ignored by default: `cargo test -p
xbt402 --release --lib seal_cost -- --ignored --nocapture`):

| step | pass line (armv7) | armv7 | x86_64 |
|---|---|---|---|
| sealing step added to a state write (10 records, keys cached) | ≤ 100 µs | 29–31 µs | 7.2 µs |
| seal one new key (once per funded ch2) | ≤ 1 ms | 12 µs | 1.0 µs |
| open a 100-record file at startup (opens + `payer_pub` checks) | ≤ 500 ms | 16 ms | 1.3 ms |

For scale, serializing the same 10-record file costs 131 µs on armv7, before its fsync. The sweep is
one busy-flag try per open ch1 with a lock, per tick. The preflight is one HTTP round trip per funded
channel, not per call.

**For embedders (cmp).**
* `RouteHub::new` with a data dir makes `<datadir>/hub-wrap-key` if there is none. Use
  `RouteHub::new_with_wrap_key(.., Some(WrapKey::load_or_create(path)?))` to keep the wrap key off the
  data dir. In B1, pass `RouteHub(..., wrap_key=WrapKey.load_or_create(path))`. `OutBook::open` takes
  the wrap key and refuses a file without one.
* **Downgrade:** an older hub cannot read a sealed `ch2.json`. Old B1 fails at start (`TypeError` on
  `secret_sealed`); old Rust loads it with empty keys and cannot sign. Keep a copy from before the
  upgrade, plaintext keys and all, if a rollback is possible.
* The ch2 record's `secret` field is gone from the file (it is still in memory). Tools that read keys
  from `ch2.json` must open `secret_sealed` with the wrap key.
* A written-off ch2 is closed early, so the provider sees a cooperative close request soon after a
  refused or timed-out lock. A payee-pays ch2 pays its close fee then.
* The hub and the route payer send one more `/open` (the preflight) per channel.
* New events: `ch2_keys_sealed`, `ch2_written_off_close_failed`, `orphan_lock_held`,
  `ch2_preflight_refused`; `ch2_close` and `ch2_switch` can carry `why: "written_off"`.

Tests: `crates/xbt402-interop/tests/hub_followups.rs` (10; B1
`tests/security/test_agp073_hub_followups.py`, the same 10):
* K1: `k1_the_state_file_holds_no_plaintext_ch2_key`,
  `k1_a_legacy_plaintext_state_file_is_read_once_and_rewritten_sealed`,
  `k1_a_wrong_wrap_key_or_a_swapped_blob_is_refused`;
* written off: `written_off_a_refused_lock_ch2_is_closed_and_refilled`,
  `written_off_with_a_next_ch2_the_hub_switches_and_has_the_old_one_closed`,
  `written_off_on_a_timeout_the_ch2_is_closed_and_not_refilled`;
* orphans: `orphan_a_lock_a_crash_left_is_swept_by_the_watcher`,
  `orphan_a_lock_its_ch2_wrote_off_before_the_crash_is_held_not_dropped`;
* C2: `c2_the_route_payer_asks_the_hub_before_it_funds_ch1`,
  `c2_the_hub_asks_the_provider_before_it_funds_ch2`;
* `hub_keys` unit tests: the seal round trip and its refusals, the key file's forms, and its mode.

On `main`, 9 of the 10 fail; the tenth (the wrong-key test) needs the new API. In B1 master, 9 of 10
fail: the route payer test passes there, since B1's client already preflighted. Existing tests changed
with the new behaviour: `hub_money_safety::wa_the_key_is_on_disk_before_fund_runs` (the key is sealed),
`hub_reconcile::close_fields_round_trip`, and
`hub_routing_safety::h2_a_refused_lock_stays_in_the_base_and_blocks_routing_and_rollover` (the
watcher asks for the close itself). In B1: `test_agp037` (key on disk, rollover next key, the
unknown-spender reconcile), `test_agp053` `HubOff` (one more `/open`) and the same `test_agp064` H2
test.

**Trade-offs.**
* A refused first lock on a ch2 with nothing signed asks for a close every block until the provider
  closes or the refund comes, unless a next ch2 is open.
* The default wrap key beside the state file only protects copies of `ch2.json`. A secrets mount or
  `wrap_key_file` elsewhere is the real protection.
* The write does not fsync the directory after the rename, as before: no extra IO per call. A
  follow-up could add it.

## Portability

No platform-specific dependencies: libsecp256k1 (C, via `secp256k1-sys`), pure-Rust hashes and JSON,
`getrandom`, std threads (no async runtime). The payer HTTP client uses `ureq` with rustls/ring
(no OpenSSL). Every HTTP server (xbt402 `http-server`, wallet-ui, the work relay, the MCP) is
`xbt_svc::http`, std only (AGP-068, AGP-072). `cargo check -p xbt402` (library, and all features + the hub binary)
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

## Light client and consensus edges (AGP-069, review E1–E3, S1, M1)

The light backend now checks headers as Knots does from the first header above the checkpoint. It
withholds answers while its chain is not believable, and a lying server can neither stall callers
nor get a cheap fork believed. The hot wallet waits for the coinbase maturity the node reports. B2
`agentwallet/headers.py`, `electrum.py`, `maturity.py` and `hot.py` on `agp-069` (`24a0cd5`) and B1
`xbt402/tx.py` on `agp-069` (`fe96c67`) do the same, with the same test names (`test_` prefixed in
Python). Knots line numbers below are v29.4.2.

**Header rules (E3).** `HeaderChain` refuses:

- a header whose top two flag bits are set (`bad-flags-highbits`, validation.cpp:4431);
- a version below 4 once bit 31 is masked off (`bad-version`, 4757–4762);
- a time not above the median of the 11 before it, from the first header above the checkpoint on
  (4737);
- on regtest, nBits other than the min-difficulty walk-back gives (pow.cpp:42–56,
  `ChainRules::next_bits_with`);
- any block other than the pinned one at a pinned height (`ChainRules::pins`; on mainnet 964264,
  Knots' assumevalid block, chainparams.cpp:150).

The median and the walk-back need the 10 headers below the checkpoint, so
`set_checkpoint(raw, prior)` now takes `PRIOR_HEADERS` (10) 80-byte v1 headers. Each must hash-link
to the one above it, and the last to the checkpoint. The backend fetches them from the servers, and
they are never answered as ours. Testnet3, testnet4 (BIP94) and signet have no rules here, so
`ChainRules::for_chain` refuses them and no chain starts.

**Believable chain (E2).** On mainnet every chain answer fails with `Kind::Implausible` (B2:
`ImplausibleChain`, status `"implausible"`) until the verified chain:

- reaches every pinned block;
- carries Knots' nMinimumChainWork (chainparams.cpp:149, the chainwork of 964264) less the
  chainwork of 961640, which is 0x10c4284b5592c3c377 by Knots' `getblockheader`;
- trails one block per 600 s since the newest pinned block by at most 2016 blocks.

`Config.plausibility` overrides this (default `Plausibility::mainnet` on mainnet, none elsewhere)
and `Config.clock` sets the clock in tests. A checkpoint of unknown chainwork gets no minimum work,
but it still has to reach the pins.

**TLS (E2).** On mainnet every server must be `ssl://`. `tcp://` is allowed only to a loopback host
(`is_loopback_host`); anything else is `Kind::BadRequest` from `ElectrumBackend::new`.

**Lying servers (E1).**

- On mainnet a claimed tip is believed up to ours + (time since our tip / 150 s) + 2016
  (`TIP_CAP_SPACING_S`). Nothing above that is fetched, and the server is flagged.
  `Config.tip_cap_spacing_s` sets it; it is off by default elsewhere, because regtest mines blocks
  as fast as it is asked to (the interop run's electrs were flagged until it was).
- Each chunk is checked as it arrives (`HeaderChain::branch`, `Branch::extend`), so the first bad
  header stops that server's sync. The branch is adopted only if it has more work and our chain
  under it has not moved (`HeaderChain::adopt`).
- No lock is held across a network read. Servers sync in parallel. Once a chain is held, a caller
  that finds a sync running answers from the verified chain instead of waiting (a try-lock gate);
  only before the first chain do callers wait.
- Before a chain is held, a tip outside our powLimit means another chain: `Kind::CheckpointMismatch`,
  as for a missing checkpoint.

**Sighash (S1).** `unified_sighash_ext(…, SpendExt { annex, codesep_pos })` commits an annex as
`0x01 ‖ sha256(compact_size ‖ annex)` (interpreter.cpp:1730–1732, 2152) and the position of the
last executed OP_CODESEPARATOR after the leaf hash (1749). It refuses values the script type does not
commit to: an annex outside taproot, an annex without the 0x50 tag, and a position outside
tapscript. `unified_sighash` is `SpendExt::default()` and unchanged, so the 166 pinned vectors still
match. B1's `unified_sighash` takes keyword-only `annex=` and `codesep_pos=`. Knots' REDUCED_DATA
refuses any annex on mainnet until 2027-09-01 (2149–2150). For script type 0, `script_code` must
already have this signature's pushes removed: Knots still runs FindAndDelete there (345–349), and
the docs of both functions now say so. The 60 new vectors in `vectors/unified_sighash_ext.json`
were computed with Knots' own Python test framework (`scripts/gen_unified_sighash_ext.py`); main
matches 8 of them (the cases with neither an annex nor a codeseparator).

**Coinbase maturity (M1).** The hot wallet learns which coins are coinbase outputs from
`scantxoutset`, `gettxout`, and a funding transaction's `vin[0].coinbase`. Such a coin is spendable
once tip + 1 ≥ h + max(depth, 100), with the depth from the node's `getdeploymentinfo`
`long_coinbase_maturity` (Knots' mempool holds every coinbase spend to that depth,
validation.cpp:1021–1022). A node that cannot say holds them: the light backend has no
`getdeploymentinfo`, so a light hot wallet does not spend coinbase coins. `fund`, `rotate`, the
sweeps and `status` (`hot_coinbase_sats`) all use it. `Maturity` moved from xbt-work to
`xbt402::maturity` (xbt-work re-exports it), so the signer does not depend on xbt-work.

**CAIP-2.** `network.rs` now says why XBT's id is keyed to block 961640 and not genesis: a
genesis-keyed id would be Bitcoin's own.

**Embedders.**

| change | who must act |
|---|---|
| The header store records the priors; a store from an older release is ignored and the chain resyncs from the checkpoint once | nobody (one resync) |
| `set_checkpoint(raw, prior)`; `HeaderChain::new` takes `impl Fn() -> u64` (was `Box<dyn Fn>`); `Header` gains `version` and `flags` | anyone driving `HeaderChain` directly |
| Mainnet light backend: `ssl://` only, except loopback | configs listing `tcp://` mainnet servers |
| New `Kind::Implausible`: retry later, as for `NotFound` | exhaustive matches on `Kind` |
| Servers must serve the 10 v1 headers below the checkpoint (`blockchain.block.headers`; electrs does) | operators of other Electrum servers |
| Coin records gain `"coinbase": true, "height": h` (only on coinbase coins); spending them needs `getdeploymentinfo` | hot-wallet users with mined coins |
| `xbt_work::chain::Maturity` is `xbt402::maturity::Maturity` | nobody (re-exported) |

cmp, xbt-compute, B5 and xbt-063 pin their own copies and are unaffected until they re-pin.
Nothing on the xbt402 wire changes, and `scripts/conformance.sh` is unchanged (253/253).

Choices (best-performing-stack rule; the code ships in the existing Rust crates, with the Python
references kept in step, and adds no dependencies):

| question | options | chosen, and why |
|---|---|---|
| not stalling on a slow or lying server | one lock across reads (main); a background sync thread with a channel; a try-lock gate | **the gate**: no new thread or state, and callers keep answering from the verified chain |
| when headers are checked | after a whole batch (main); per chunk as it arrives; one request per header | **per chunk**: the first bad header ends the fetch, and the round trips stay batched |
| how high a claimed tip to believe | anything; a fixed cap; a cap from elapsed time | **elapsed time** (4× the target block rate, plus 2016): a real tip always fits |
| the headers under the checkpoint | skip the median for the first 10 (main); ship them in the binary; fetch and hash-link them | **fetch**: an operator checkpoint works too, and the hash link adds no trust in the server |
| coinbase depth | hard-code the #419 schedule; ask the node | **the node**: it is what the mempool enforces; unknown means hold |
| annex and codeseparator | more arguments on `unified_sighash`; a new function | **`unified_sighash_ext`**: no caller or pinned vector changes |

**Cost.** Pass line declared before measuring:

- (a) per 2016-header chunk, validation costs at most 10% more than on main;
- (b) on armv7 (Cortex-A7 class), the catch-up from 961640 to a tip about 10,000 headers above it
  takes at most 10 s of CPU, and the priors at most 10 ms;
- (c) the plausibility check on every answer costs at most 1 µs on x86.

`cargo run --release -p xbt-primitives --example header_cost` on a Ryzen 9 9950X3D, three runs
interleaved with the same example built on main:

| per header (8064 synthetic headers) | agp-069 | main |
|---|---|---|
| parse (BLAKE2b) and PoW alone | 810 ns | 820 ns |
| connect, mainnet's path (no min-difficulty walk) | 940–950 ns | 950–1004 ns |
| connect, regtest rules | 2176–2250 ns | 961–1011 ns |
| the 61 real mainnet headers from 961640, checkpoint included | 974–990 ns | 945–973 ns |

- Mainnet passes (a): no difference on its path, and +3% on the real headers.
- **Regtest fails (a) at +125%.** All of it is Knots' min-difficulty walk-back, which on regtest
  walks to the last 2016 boundary for every header. Mainnet never runs it. It is kept because it is
  the Knots rule; 8064 regtest headers still take 18 ms.
- The checkpoint with its priors costs 2.3 µs (main 0.9 µs). `branch()` at the tip copies the last
  2016 headers once per sync round, 31 µs. `implausible()` costs 8.4 ns per answer, which passes (c).
- There was no armv7 box or emulator, so (b) is an estimate. The armv7 build of the example
  compiles. BLAKE2b is 64-bit arithmetic, roughly 50–100× slower per header on a 900 MHz Cortex-A7,
  so 10,000 headers take about 0.5–1 s and the priors well under 1 ms. That passes.

**What this does not fix.**

- Above pin 964264 a fork is still cheap: difficulty there is `1a00f0b5`, about 2^53 hashes per
  block. The floor only raises the bar for a fork that also hides the real tip. Releases should bump
  the pins, and operators can set a later checkpoint.
- A call that fans out to every server waits for the slowest one, up to the timeout (no lock held).
- One batch can fetch up to 4×2016 junk headers before the first is checked (B2 fetches chunk by
  chunk).
- If blocks really did come much slower than one per 600 s for weeks, the floor would withhold
  answers until the pins are bumped.
- A light hot wallet cannot spend coinbase coins (fail closed).

Tests, each failing on main first:

- `crates/xbt-primitives/tests/header_chain.rs`: `e3_flags_highbits_and_version`,
  `e3_median_time_from_the_first_header`, `e3_min_difficulty_walk_back`,
  `pinned_heights_refuse_any_other_block`, `unsupported_test_networks_fail_closed`,
  `a_branch_validates_as_it_grows` and `mainnet_checkpoint_with_its_real_priors` (the 71 real
  headers 961630–961700 from xbt-snapshot, `vectors/mainnet_headers_961630.json`). Unit test: `mainnet_minimum_work`.
- `crates/xbt-electrum/tests/backend.rs`:
  - `mainnet_needs_tls`;
  - `hostile_lying_server_cannot_stall`: main gives no answer within 10 s, and a slow server holds a
    caller 1.2 s;
  - `hostile_cheap_fork_is_not_believed`: main shows 20 confirmations on the fork;
  - `tip_cap_is_mainnet_only`.
- `crates/xbt-primitives/tests/sighash_ext.rs`: `s1_annex_and_codesep_vectors_match_knots` and
  `s1_refuses_values_the_script_type_does_not_commit_to`.
- `crates/xbt-signer/tests/review_e.rs`: `m1_coinbase_waits_for_the_node_maturity`,
  `m1_coinbase_waits_when_the_node_cannot_say` and
  `m1_coinbase_flag_from_gettxout_and_the_transaction`. On main the wallet spends a block-200
  coinbase at block 299. Unit test: `maturity_from_the_node`.

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

## The coinbase audit without trusting the Prime (AGP-065, review P1–P6)

An external reviewer read the public snapshot (xbt-rs `ecdbb50`). The point: the §10.3 audit took every
number from the Prime's own window statement, so a Prime colluding with a payer could receipt work
nobody mined and then sign a statement that excused the unpaid coinbase. Every finding was still
present on `main` (`c8d607b`). Each now has a test in `crates/xbt-work/tests/review_p.rs`; P1–P4 were
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

## Lightning rail hardening (AGP-066, review L1–L5)

An external review of the public snapshot (xbt-rs `ecdbb50`) found five weaknesses in the payer-only
`rail=ln` (AGP-048/049, `crates/xbt-signer/src/ln.rs`). All five were still present on `main`
(`9ec4090`); since `ecdbb50`, the LN code had changed only in `7c90e17` (AGP-055, how the tests read
the ledger), which none of the findings depends on. Each
has a test in `crates/xbt-signer/tests/ln_rail.rs` that failed on `main`; commit `25f5ea8` holds the
tests alone. Neither Python reference has a Lightning rail (B1 `xbt402/` and B2 `agentwallet/` have
none), so there is no parity change and no vector changed.

Two design notes stand as before, and nothing below changes them:

* **The wallet's policy is advisory as far as LND is concerned.** The signer's checks bind what goes
  through the signer. Anyone holding a macaroon with more access (the node's `admin.macaroon`, `lncli`
  on its host) bypasses all of them. That is why mainnet requires `ln.exposure_cap_sats`: the LN node
  is trusted with everything it holds.
* **Everything rests on the Lightning Fork's behaviour.** Its unified signatures (`option_unified_sigs`,
  sighash 0x21) and its feature bit 512 (`option_blake2b`) are what keep a channel's transactions and
  invoices off SHA-256 Bitcoin. The signer checks that they are in use (L5 below tightens the funding
  proof) but cannot make the fork implement them correctly.

* **L1: plain http only to a loopback address.** `LndRest::new` cut the URL's host at the first `:`,
  so in `http://[::ffff:10.0.0.5]:8080` the leftover `[` passed as loopback, and the spending macaroon
  crossed the LAN in cleartext. The URL is now parsed with the `url` crate (the parser `ureq` itself
  uses, so the host checked is the host dialled). Plain http is allowed only to an IPv4 address in
  127.0.0.0/8, to `::1`, or to an IPv4-mapped address inside 127.0.0.0/8. A hostname, `localhost`
  included, needs https. Test: `l1_plain_http_only_to_a_loopback_address`: a table of URLs, then a
  property over 400 random IPv4 addresses (half in 127/8), their IPv4-mapped forms and 400 random
  IPv6 addresses (accepted exactly when in 127/8; random IPv6 never). On
  regtest, S18 starts a signer with that URL and checks it is refused.
* **L2: the mainnet macaroon check is an allowlist.** The check refused only `onchain:write`,
  `macaroon:*` and `signer:generate`. A macaroon granting `uri:/lnrpc.Lightning/SendCoins` (or
  `invoices:write`, `peers:write`, …) passed. Now, on mainnet, `ln_macaroon` refuses any permission
  beyond the rail's four (`info:read offchain:read offchain:write onchain:read`). It also refuses a
  macaroon whose permissions cannot be read (not an LND identifier), since one that cannot be read
  cannot be shown to be least privilege. Off mainnet the macaroon is reported, not refused: `ln_status`
  `macaroon.only_needed` and `excess_ops`. `dangerous_ops` stays in the report. (The field is not
  called `least_privilege`: the response sanitizer drops every key containing `priv`, and the regtest
  caught it.) Test:
  `l2_the_mainnet_macaroon_holds_only_the_rails_permissions`, plus the `macaroon.rs` unit test.
  Regtest: S17. An allowlist scoped by URI (accepting the rail's own URIs and nothing else) would also
  work; the entity allowlist is simpler and is what `lncli bakemacaroon` produces.
* **L3: a payment is looked up by its hash.** `lookup` scanned `GET /v1/payments` (the newest 1,000),
  so on a busy node an older settled payment looked like no payment, and reconcile released its
  booking. It now calls `GET /v2/router/track/{payment_hash}` (TrackPaymentV2, base64url hash), reads
  the first line of the stream, and checks that the record's hash is the one asked for. Only LND's
  "payment isn't initiated" answer means "no payment": grpc-gateway answers an unknown route with a 404
  too, so the status code alone proves nothing, and any other error stays an error (nothing is
  released). LND has no hash filter on `ListPayments`, and scanning all of its pages costs O(payments)
  on every reconcile; TrackPaymentV2 costs one call. It needs the node built with `routerrpc` (Lightning
  Fork releases are) and `offchain:read`, which the rail's macaroon already has. Tests:
  `l3_a_payment_is_looked_up_by_its_hash_not_among_the_newest_1000` and
  `l3_reconcile_does_not_release_a_settled_payment_on_a_busy_node`, against a fake REST LND on
  loopback that holds 1,001 payments. On regtest, S16 checks both answers on lf1, and S15's reconcile
  goes through the new lookup.
* **L4: a late rebook that breaks the policy halts the rail.** A booking released because the node had
  no record of it is watched; if the node records the payment late, it is booked again (`ln_rebook`).
  That booking discarded the policy's verdict, so a release, a new payment in the freed room, and the
  late settle could overspend the daily budget without anyone noticing. Now the rebook still books what
  was spent (the ledger is the truth), but asks `evaluate_booking` first. If the booking breaks the
  policy (or cannot be committed), the signer:
  * writes a halt to `.run/ln_halt.json` (atomic write, `0600`) and audits `ln_halted`;
  * refuses every `ln_pay` with `ln_halted` (nothing reaches the router), and `ln_status` shows
    `halted`, `ready: false` and a warning;
  * puts an approval of kind `ln_resume` (dest `ln:resume`, the amount rebooked) in the human's queue.
    It is renewed while the halt stands, one live request per halt. Only the human's ed25519 signature
    on it resumes the rail (`ln_resumed`). A wrong signature, or a token for an earlier halt, is refused.

  A halt file that cannot be read counts as a halt. The watch lasted until the invoice's expiry plus
  10 minutes, far shorter than an HTLC can stay out. It now lasts `ln.max_cltv_blocks` + 144 blocks
  (`REBOOK_WATCH_MARGIN_BLOCKS`), counted both in blocks from the tip at release
  (`watch_until_height`) and in time at 600 s a block. Tests:
  `l4_a_late_rebook_that_breaks_the_policy_halts_the_rail_until_the_human_resumes_it` and
  `l4_the_rebook_watch_lasts_as_long_as_the_htlc_can`. The AGP-048 test
  `a_payment_released_as_never_sent_and_settled_late_is_booked_again` now checks the longer window.
  The alert is the approval queue the human already watches: the wallet UI's card says the rail is
  halted and that approving pays nothing. No new message type or key was needed.
* **L5: the funding proof.**
  * **The cache is keyed on the block.** A `Proven` verdict was cached per channel point forever, so
    after a reorg removed the funding block the channel still carried payments. The signer now asks
    its node for the hash at the short channel id's height on every use, and a cached verdict counts
    only while that hash is the one it was reached on (`Funding::block_hash`, in the evidence as
    `block_hash`). After a reorg the channel is proven again from the new block. Test:
    `l5_a_proven_funding_is_proven_again_after_a_reorg` (refused while the block is gone, proven again
    when it returns).
  * **Which signatures count.** The proof read the sighash byte of every DER-shaped push, so a 0x21
    push that the script never checks (`OP_DROP OP_TRUE`, a taproot script path) "proved" the input.
    `ln_funding::checked_sighashes` now reads only spends whose sole condition is signatures: P2WPKH,
    P2SH-P2WPKH, P2PKH, P2WSH or P2SH-P2WSH whose witness script is `<key> CHECKSIG` or
    `m <keys> n CHECKMULTISIG` (with exactly its `m` signatures), and a taproot key path. Any other
    input leaves the channel unproven, and the refusal names the input and why. Tests:
    `l5_a_0x21_push_the_script_never_checks_proves_nothing` (an anyone-can-spend P2WSH and a taproot
    script path are refused; LND's 2-of-2 P2WSH and np2wkh spends are proven), the unit test
    `reads_sighash_bytes_by_input_kind`, and the property test `only_signature_only_scripts_are_read`
    (2,000 random P2WSH witnesses: one is read only if its script is a key-check template, and then
    yields exactly the `m` signatures that script checks).

**The replay-safety reasoning, corrected** (`ln_funding.rs` module documentation):

* A channel's transactions can replay on SHA-256 Bitcoin only if its funding transaction is valid
  there too. One input with a signature that its script checks, and that SHA-256 Bitcoin cannot verify,
  makes the transaction invalid there. The proof asks for that of every signature of every input.
* The earlier comment said SHA-256 Bitcoin rejects a 0x21 signature. It does not: its consensus accepts
  hash type 0x21 on legacy and segwit v0 inputs (the byte is only non-standard there; taproot does
  reject it). The protection is the digest. An XBT signer signs 0x21 over the unified message
  (`unified_sighash`: BIP341-shaped, committing to every input's amount and scriptPubKey). SHA-256
  Bitcoin checks the same signature against its own legacy or BIP143 message for hash type 0x21. One
  ECDSA signature valid under one key for both messages would need the two digests to be equal modulo
  the group order.
* **Why reading the bytes suffices, without verifying the signatures in the signer.** The funding
  transaction is read from a block on the signer's own node's best chain, at the position its short
  channel id names. That node's consensus has already verified every signature each input's script
  checks, against XBT's message for its hash type (below an `assumevalid` block, the network that built
  on it has). Verifying again in the signer would repeat that work and add a second ECDSA path to keep
  in step with Knots. What the bytes alone cannot tell is which pushes the script checks, so the fix is
  the template restriction above.
* **The height proves nothing on its own.** A coin confirmed at or above the split is not thereby
  XBT-only. A transaction valid on both chains (a 0x01 spend of pre-split coins, broadcast on both) has
  the same txid on each, so its outputs exist on SHA-256 Bitcoin too, however high it confirmed here.
  The signatures are the proof. The rule that every input's coin is confirmed at or above the split
  stays, as an extra, conservative rule: a channel opened after the split never needs older coins.

**For embedders (cmp and anyone linking `xbt-signer`).** Wire and behaviour changes:

| change | before | now |
|---|---|---|
| `B2_LN_REST` plain http | allowed to any host starting `127.`, `localhost`, or with a `[` (the bug) | only 127.0.0.0/8, `::1`, `::ffff:127.0.0.0/104`; `localhost` needs https |
| mainnet macaroon | refused if it grants `onchain:write`, `macaroon:*`, `signer:generate` | refused if it grants anything beyond the rail's 4 permissions, or cannot be read |
| `ln_status.macaroon` | | adds `only_needed` (bool) |
| payment lookup | `GET /v1/payments` (newest 1,000) | `GET /v2/router/track/{hash}`: needs `routerrpc` on the node |
| `ln_pay` | | new rule `ln_halted` (with `halted`, the halt record) |
| `ln_status` | | adds `halted` (`null` or `{halt_id, reason, payment_hash, dest, booked_sats, ts}`) |
| approvals | kinds `xbt402`, `ln`, payment | adds kind `ln_resume`, dest `ln:resume`; `approve` with the human's signature resumes the rail |
| audit log | | `ln_halted`, `ln_resumed`; `ln_rebooked` gains `breach` |
| `.run/` | | `ln_halt.json` while halted; `ln_payments.json` records gain `watch_until_height` |
| funding evidence | | adds `block_hash` |
| `LnBook::watched` | `watched(now)` | `watched(now, tip)` |
| `ln_funding` | `input_sighashes` | `checked_sighashes(&TxIn, prev_spk) -> Result<Vec<u8>, String>` |

New dependency: `url` 2.5, already in the tree through `ureq` 2.12 (`cargo tree -d` shows no new
duplicate).

Results on 2026-10-08: `cargo test --workspace` (517 passed) and `scripts/conformance.sh`;
`scripts/ln_rail_regtest.sh` 61/61 against Lightning Fork `dd659b3` (`docs/agp066_ln_rail_regtest.json`).
S16 shows the node's answer for an unknown hash: 404 `{"error": {"code": 5, "message": "payment isn't
initiated"}}`. Its first run also caught `least_privilege`, which the sanitizer had removed from every
response.

CPU (`crates/xbt-signer/examples/ln_funding_cost.rs`; armv7 musl under `qemu-arm-static` as the
Pi-class figure, x86_64 native beside it; pass line declared before measuring):

| step | pass line (armv7) | armv7 | x86_64 |
|---|---|---|---|
| `checked_sighashes`, one funding transaction of 10 inputs (P2WPKH, 2-of-3 P2WSH, P2SH-P2WPKH, P2TR key path) | ≤ 50 µs | 1.97 µs | 0.16 µs |

The L5 cache check adds one `getblockhash` RPC to the signer's own node per usable channel on each
`ln_pay` and `ln_status`: a loopback round trip, not CPU. TrackPaymentV2 replaces a 1,000-payment
listing with one record. The L1 parse runs once, at configuration.

## Embedders on xbt402 v1.3 (AGP-074)

AGP-068 changed the wire (derivation v3, request binding v2, receipt v2) and left the embedders on
their pins. This moves them.

**xbt-work speaks request binding v2.** `xbt_work::auth::request_digest` is now
`xbt402::wire::request_digest_v2`: the digest is the tagged hash of the length-prefixed method,
scheme, host, port, target and body, taken over the URL the payer sent the request to. A bare
target binds no origin, which is what the published vectors use. v1 (`request_digest_v1`) no longer
authenticates. The vectors are XBT-053's `vectors.json` with the `auth` section regenerated
(XBT-053 branch `agp-074`; `scripts/work_conformance.sh` still demands byte identity). The HMAC
over the digest is unchanged.

Options weighed for the binding (best-performing-stack rule): a digest of xbt-work's own (a second
definition to keep equal with xbt402's, forever), keeping v1 behind a version flag (two live
bindings, and a captured v1 header still spends), or **xbt402's v2 directly (chosen)**. One
function, the same one B1 and the channel scheme already verify, and the published vectors move
with it.

**Cost.** Declared before measuring: moving xbt-work's digest from v1 to v2 may add at most 50 µs
per paid call on the Ryzen 9 9950X3D, and at most 1 ms on the Pi 3's Cortex-A53. Measured with
`cargo run --release -p xbt402 --example binding_bench` (20,000 iterations, the bench's own empty
body): v1 98 ns, v2 273 ns, so +175 ns per call. The difference is the length prefix per field and
the origin split; both hash the same body bytes, and the bench's own line puts a 4 KiB body at
1,657 ns. On the Pi 3 the same SHA-256 is the cost, and 175 ns scaled by that core's gap to the
Ryzen stays far under 1 ms. Nothing is added per byte beyond what v1 already hashed.

**xbt-063.** `rehearsal/PINS` and `vendor/` move to the merged B1 and B2 masters. The flagship
refund probe's policy carries `allowlist` and `counterparties[probe].pay_to`, because AGP-063 (W3)
refuses an `open_channel` whose destination is not the policy's. `scripts/mcp/regtest_conformance.sh`
and `verify_agp030.sh` default to this xbt-063 tree.

**B5.** `vendor/` moves to the same masters, and `fwd/server.py` signs receipt v2: `status` and
`bodyHash` over the answer body, with `req` bound by `request_digest_v2`.

**B2.** `open_from_offer` posts the review C2 preflight `/open` (no outpoint) before it funds, as
`Payer::open` and the B1 client do. A refusal funds nothing; a provider from before the preflight
answers `bad_request` and the wallet funds as before.

`xbt-signer`'s `request_target` is gone: nothing called it once the binding moved to the full URL.

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

