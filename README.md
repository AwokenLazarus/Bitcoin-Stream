# Bitcoin Stream

Pay for a service piece by piece, as it arrives, over XBT (Bitcoin on BLAKE2b proof of work).
Lock coins once in a payment channel. For each piece delivered, the buyer signs a slightly larger
running total. The seller settles once, for the last total. Stop at any moment and nothing more is owed.

Whitepaper: **<https://lazarus-xbt.xyz/stream/>**

> **Status: test networks only.** Everything here runs on XBT regtest and a private test network.
> It has had an internal security review, not an independent audit. An outside review of this code
> (October 2026) found critical and high-severity issues in the agent wallet's budget accounting,
> the hub, the pay-with-work audit and the HTTP layer. Fixes for its findings are in this tree
> (`docs/ENGINEERING.md` has a section per group, with the limits that remain). Our own follow-up
> audit of those fixes found that some are incomplete; further fixes are in progress. None of the fixes has been
> re-reviewed by anyone outside the project; an independent audit is planned. Hub routing (`xbt402-hub`) is experimental. Conformance results in
> `docs/ENGINEERING.md` are measured against our own Python references, which are not yet
> published. Do not use it with mainnet funds.

## What is here

A Rust workspace: the channel protocol, an agent wallet that AI agents use over MCP, and the services
and packages around them.

| crate | what |
|---|---|
| `xbt-primitives` | XBT transactions, scripts, addresses, UnifiedSighash (0x21), strict ECDSA, BLAKE2b headers and proof of work |
| `xbt402` | the Stream channel: funding, signed states, close, rollover, refund, the HTTP 402 wire (x402 v2 `batch-settlement`), receipts, provider and payer, hub routing with adaptor signatures (`xbt402-hub`) |
| `xbt-signer` | the agent wallet's signer: keys never leave it; the owner's signed policy (budgets, per-seller caps, allowlist, human approval); a tamper-evident signature log; an optional Lightning rail |
| `xbt-wallet-mcp` | the wallet's MCP server, over stdio and streamable HTTP, so an AI agent can quote and pay without holding a key |
| `xbt-wallet-ui` | the owner's web UI: approvals, policy, channels, signature log |
| `xbt-electrum` | a light chain backend that trusts only what it can check (headers, PoW, Merkle proofs) |
| `xbt-work`, `xbt-work-relay` | pay with work: a miner pays with pool shares, settled in the coinbase and checked by an audit |
| `xbt-svc` | container plumbing: data dir, secrets, readiness |
| `xbt402-interop` | conformance vectors and cross-implementation tools |

`packaging/` holds the Umbrel and StartOS apps. `container/` and `docs/CONTAINER.md` cover the
images. `docs/ENGINEERING.md` has the detailed design notes, conformance results and measurements.

## Build

```bash
cargo test -j2 --workspace
cargo build --release -p xbt-signer -p xbt-wallet-mcp -p xbt402
```

Rust stable; libsecp256k1 is built from source. Cross builds (Linux x86_64, aarch64, armv7, riscv64,
macOS, Windows) use zig as the C compiler: see `docs/ENGINEERING.md`.

The regtest scripts in `scripts/` need a Bitcoin Knots 29.4.2 build for XBT (`XBT_BIN`), and the
cross-implementation ones also need the Python reference implementations, which are not published yet.

## License

Licensed under either of

* Apache License, Version 2.0 (`LICENSE-APACHE`)
* MIT license (`LICENSE-MIT`)

at your option. Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.

Code, data and libraries from others, with their licences: `THIRD_PARTY_NOTICES.md`.
