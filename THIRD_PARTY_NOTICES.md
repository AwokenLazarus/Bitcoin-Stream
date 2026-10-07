# Third-party notices

Bitcoin Stream is licensed under MIT or Apache-2.0, at your option (`LICENSE-MIT`, `LICENSE-APACHE`). It includes, links against, or builds on the work
below. Each keeps its own licence and copyright.

## Included in this repository

### Bitcoin Knots: UnifiedSighash test vectors

`vectors/unified_sighash.json` is copied unchanged from Bitcoin Knots,
`src/test/data/unified_sighash.json` (branch `29.x-knots`,
<https://github.com/bitcoinknots/bitcoin>). It is used under the MIT licence:

```text
The MIT License (MIT)

Copyright (c) 2009-2025 The Bitcoin Core developers
Copyright (c) 2009-2025 Bitcoin Developers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

`vectors/blake2b_regtest.json` holds block headers captured from a Bitcoin Knots BLAKE2b regtest node
(v29.4.1.knots20260508rc2): recorded chain data, used to test the header code.

### electrs: BLAKE2b header v2

The BLAKE2b header code (`crates/xbt-primitives/src/header.rs`) was written for this project. It
follows the header-v2 support we wrote as a patch to electrs (<https://github.com/romanz/electrs>,
MIT licence, Copyright (C) 2018, Roman Zeyde), by way of our Python reference implementation.
`crates/xbt-electrum` speaks the Electrum protocol that electrs serves.

### libsecp256k1

All secp256k1 signing and verification runs in libsecp256k1 (<https://github.com/bitcoin-core/secp256k1>,
MIT licence, Copyright (c) 2013 Pieter Wuille), which the `secp256k1-sys` crate bundles and builds
from source.

## Rust libraries

The binaries and libraries built from this workspace link the crates below (normal and build
dependencies, all targets). Their licence texts must accompany any binary you distribute. To
regenerate the list:

```bash
cargo tree --workspace --target all -e normal,build --prefix none --format '{p}|{l}|{r}'
```

| crate | version | licence |
|---|---|---|
| [adler2](https://github.com/oyvindln/adler2) | 2.0.1 | 0BSD OR MIT OR Apache-2.0 |
| [aead](https://github.com/RustCrypto/traits) | 0.5.2 | MIT OR Apache-2.0 |
| [aes](https://github.com/RustCrypto/block-ciphers) | 0.8.4 | MIT OR Apache-2.0 |
| [aes-gcm](https://github.com/RustCrypto/AEADs) | 0.10.3 | Apache-2.0 OR MIT |
| [ascii](https://github.com/tomprogrammer/rust-ascii) | 1.1.0 | Apache-2.0 OR MIT |
| [base64](https://github.com/marshallpierce/rust-base64) | 0.22.1 | MIT OR Apache-2.0 |
| [blake2](https://github.com/RustCrypto/hashes) | 0.10.6 | MIT OR Apache-2.0 |
| [block-buffer](https://github.com/RustCrypto/utils) | 0.10.4 | MIT OR Apache-2.0 |
| [cc](https://github.com/rust-lang/cc-rs) | 1.5.1 | MIT OR Apache-2.0 |
| [cfg-if](https://github.com/rust-lang/cfg-if) | 1.0.5 | MIT OR Apache-2.0 |
| [chacha20](https://github.com/RustCrypto/stream-ciphers) | 0.9.1 | Apache-2.0 OR MIT |
| [chacha20poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305) | 0.10.1 | Apache-2.0 OR MIT |
| [chunked_transfer](https://github.com/frewsxcv/rust-chunked-transfer) | 1.5.0 | MIT OR Apache-2.0 |
| [cipher](https://github.com/RustCrypto/traits) | 0.4.4 | MIT OR Apache-2.0 |
| [cpufeatures](https://github.com/RustCrypto/utils) | 0.2.17 | MIT OR Apache-2.0 |
| [crc32fast](https://github.com/srijs/rust-crc32fast) | 1.5.2 | MIT OR Apache-2.0 |
| [crypto-common](https://github.com/RustCrypto/traits) | 0.1.7 | MIT OR Apache-2.0 |
| [ctr](https://github.com/RustCrypto/block-modes) | 0.9.2 | MIT OR Apache-2.0 |
| [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek/tree/main/curve25519-dalek) | 4.1.3 | BSD-3-Clause |
| [curve25519-dalek-derive](https://github.com/dalek-cryptography/curve25519-dalek) | 0.1.1 | MIT/Apache-2.0 |
| [digest](https://github.com/RustCrypto/traits) | 0.10.7 | MIT OR Apache-2.0 |
| [displaydoc](https://github.com/yaahc/displaydoc) | 0.2.7 | MIT OR Apache-2.0 |
| [ed25519](https://github.com/RustCrypto/signatures/tree/master/ed25519) | 2.2.3 | Apache-2.0 OR MIT |
| [ed25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek/tree/main/ed25519-dalek) | 2.2.0 | BSD-3-Clause |
| [equivalent](https://github.com/indexmap-rs/equivalent) | 1.0.2 | Apache-2.0 OR MIT |
| [fiat-crypto](https://github.com/mit-plv/fiat-crypto) | 0.2.9 | MIT OR Apache-2.0 OR BSD-1-Clause |
| [find-msvc-tools](https://github.com/rust-lang/cc-rs) | 0.1.14 | MIT OR Apache-2.0 |
| [flate2](https://github.com/rust-lang/flate2-rs) | 1.1.10 | MIT OR Apache-2.0 |
| [form_urlencoded](https://github.com/servo/rust-url) | 1.2.2 | MIT OR Apache-2.0 |
| [generic-array](https://github.com/fizyk20/generic-array.git) | 0.14.7 | MIT |
| [getrandom](https://github.com/rust-random/getrandom) | 0.2.17 | MIT OR Apache-2.0 |
| [ghash](https://github.com/RustCrypto/universal-hashes) | 0.5.1 | Apache-2.0 OR MIT |
| [hashbrown](https://github.com/rust-lang/hashbrown) | 0.17.1 | MIT OR Apache-2.0 |
| [hex](https://github.com/KokaKiwi/rust-hex) | 0.4.3 | MIT OR Apache-2.0 |
| [hmac](https://github.com/RustCrypto/MACs) | 0.12.1 | MIT OR Apache-2.0 |
| [httpdate](https://github.com/pyfisch/httpdate) | 1.0.3 | MIT OR Apache-2.0 |
| [icu_collections](https://github.com/unicode-org/icu4x) | 2.3.0 | Unicode-3.0 |
| [icu_locale_core](https://github.com/unicode-org/icu4x) | 2.3.0 | Unicode-3.0 |
| [icu_normalizer](https://github.com/unicode-org/icu4x) | 2.3.0 | Unicode-3.0 |
| [icu_normalizer_data](https://github.com/unicode-org/icu4x) | 2.3.0 | Unicode-3.0 |
| [icu_properties](https://github.com/unicode-org/icu4x) | 2.3.0 | Unicode-3.0 |
| [icu_properties_data](https://github.com/unicode-org/icu4x) | 2.3.0 | Unicode-3.0 |
| [icu_provider](https://github.com/unicode-org/icu4x) | 2.3.1 | Unicode-3.0 |
| [idna](https://github.com/servo/rust-url/) | 1.1.0 | MIT OR Apache-2.0 |
| [idna_adapter](https://github.com/hsivonen/idna_adapter) | 1.2.2 | Apache-2.0 OR MIT |
| [indexmap](https://github.com/indexmap-rs/indexmap) | 2.14.2 | Apache-2.0 OR MIT |
| [inout](https://github.com/RustCrypto/utils) | 0.1.4 | MIT OR Apache-2.0 |
| [itoa](https://github.com/dtolnay/itoa) | 1.0.18 | MIT OR Apache-2.0 |
| [libc](https://github.com/rust-lang/libc) | 0.2.189 | MIT OR Apache-2.0 |
| [litemap](https://github.com/unicode-org/icu4x) | 0.8.3 | Unicode-3.0 |
| [log](https://github.com/rust-lang/log) | 0.4.34 | MIT OR Apache-2.0 |
| [memchr](https://github.com/BurntSushi/memchr) | 2.8.3 | Unlicense OR MIT |
| [miniz_oxide](https://github.com/Frommi/miniz_oxide/tree/master/miniz_oxide) | 0.9.1 | MIT OR Zlib OR Apache-2.0 |
| [once_cell](https://github.com/matklad/once_cell) | 1.21.4 | MIT OR Apache-2.0 |
| [opaque-debug](https://github.com/RustCrypto/utils) | 0.3.1 | MIT OR Apache-2.0 |
| [pbkdf2](https://github.com/RustCrypto/password-hashes/tree/master/pbkdf2) | 0.12.2 | MIT OR Apache-2.0 |
| [percent-encoding](https://github.com/servo/rust-url/) | 2.3.2 | MIT OR Apache-2.0 |
| [poly1305](https://github.com/RustCrypto/universal-hashes) | 0.8.0 | Apache-2.0 OR MIT |
| [polyval](https://github.com/RustCrypto/universal-hashes) | 0.6.2 | Apache-2.0 OR MIT |
| [potential_utf](https://github.com/unicode-org/icu4x) | 0.1.6 | Unicode-3.0 |
| [proc-macro2](https://github.com/dtolnay/proc-macro2) | 1.0.107 | MIT OR Apache-2.0 |
| [quote](https://github.com/dtolnay/quote) | 1.0.47 | MIT OR Apache-2.0 |
| [rand_core](https://github.com/rust-random/rand) | 0.6.4 | MIT OR Apache-2.0 |
| [ring](https://github.com/briansmith/ring) | 0.17.14 | Apache-2.0 AND ISC |
| [ripemd](https://github.com/RustCrypto/hashes) | 0.1.3 | MIT OR Apache-2.0 |
| [ruint](https://github.com/alloy-rs/ruint) | 1.20.1 | MIT |
| [ruint-macro](https://github.com/recmo/uint) | 1.2.1 | MIT |
| [rustc_version](https://github.com/djc/rustc-version-rs) | 0.4.1 | MIT OR Apache-2.0 |
| [rustls](https://github.com/rustls/rustls) | 0.23.45 | Apache-2.0 OR ISC OR MIT |
| [rustls-pki-types](https://github.com/rustls/pki-types) | 1.15.1 | MIT OR Apache-2.0 |
| [rustls-webpki](https://github.com/rustls/webpki) | 0.103.15 | ISC |
| [salsa20](https://github.com/RustCrypto/stream-ciphers) | 0.10.2 | MIT OR Apache-2.0 |
| [scrypt](https://github.com/RustCrypto/password-hashes/tree/master/scrypt) | 0.11.0 | MIT OR Apache-2.0 |
| [secp256k1](https://github.com/rust-bitcoin/rust-secp256k1/) | 0.29.1 | CC0-1.0 |
| [secp256k1-sys](https://github.com/rust-bitcoin/rust-secp256k1/) | 0.10.1 | CC0-1.0 |
| [semver](https://github.com/dtolnay/semver) | 1.0.28 | MIT OR Apache-2.0 |
| [serde](https://github.com/serde-rs/serde) | 1.0.229 | MIT OR Apache-2.0 |
| [serde_core](https://github.com/serde-rs/serde) | 1.0.229 | MIT OR Apache-2.0 |
| [serde_derive](https://github.com/serde-rs/serde) | 1.0.229 | MIT OR Apache-2.0 |
| [serde_json](https://github.com/serde-rs/json) | 1.0.151 | MIT OR Apache-2.0 |
| [sha2](https://github.com/RustCrypto/hashes) | 0.10.9 | MIT OR Apache-2.0 |
| [shlex](https://github.com/comex/rust-shlex) | 2.0.1 | MIT OR Apache-2.0 |
| [signature](https://github.com/RustCrypto/traits/tree/master/signature) | 2.2.0 | Apache-2.0 OR MIT |
| [simd-adler32](https://github.com/mcountryman/simd-adler32) | 0.3.10 | MIT |
| [smallvec](https://github.com/servo/rust-smallvec) | 1.16.2 | MIT OR Apache-2.0 |
| [stable_deref_trait](https://github.com/storyyeller/stable_deref_trait) | 1.2.1 | MIT OR Apache-2.0 |
| [subtle](https://github.com/dalek-cryptography/subtle) | 2.6.1 | BSD-3-Clause |
| [syn](https://github.com/dtolnay/syn) | 3.0.6 | MIT OR Apache-2.0 |
| [syn](https://github.com/dtolnay/syn) | 2.0.119 | MIT OR Apache-2.0 |
| [synstructure](https://github.com/mystor/synstructure) | 0.14.0 | MIT |
| [thiserror](https://github.com/dtolnay/thiserror) | 2.0.21 | MIT OR Apache-2.0 |
| [thiserror-impl](https://github.com/dtolnay/thiserror) | 2.0.21 | MIT OR Apache-2.0 |
| [tiny_http](https://github.com/tiny-http/tiny-http) | 0.12.0 | MIT OR Apache-2.0 |
| [tinystr](https://github.com/unicode-org/icu4x) | 0.8.4 | Unicode-3.0 |
| [typenum](https://github.com/paholg/typenum) | 1.20.1 | MIT OR Apache-2.0 |
| [unicode-ident](https://github.com/dtolnay/unicode-ident) | 1.0.26 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| [universal-hash](https://github.com/RustCrypto/traits) | 0.5.1 | MIT OR Apache-2.0 |
| [untrusted](https://github.com/briansmith/untrusted) | 0.9.0 | ISC |
| [ureq](https://github.com/algesten/ureq) | 2.12.1 | MIT OR Apache-2.0 |
| [url](https://github.com/servo/rust-url) | 2.5.8 | MIT OR Apache-2.0 |
| [utf8_iter](https://github.com/hsivonen/utf8_iter) | 1.0.4 | Apache-2.0 OR MIT |
| [version_check](https://github.com/SergioBenitez/version_check) | 0.9.5 | MIT/Apache-2.0 |
| [wasi](https://github.com/bytecodealliance/wasi) | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| [webpki-roots](https://github.com/rustls/webpki-roots) | 0.26.11 | CDLA-Permissive-2.0 |
| [webpki-roots](https://github.com/rustls/webpki-roots) | 1.0.9 | CDLA-Permissive-2.0 |
| [windows-sys](https://github.com/microsoft/windows-rs) | 0.52.0 | MIT OR Apache-2.0 |
| [windows-targets](https://github.com/microsoft/windows-rs) | 0.52.6 | MIT OR Apache-2.0 |
| [windows_aarch64_gnullvm](https://github.com/microsoft/windows-rs) | 0.52.6 | MIT OR Apache-2.0 |
| [windows_aarch64_msvc](https://github.com/microsoft/windows-rs) | 0.52.6 | MIT OR Apache-2.0 |
| [windows_i686_gnu](https://github.com/microsoft/windows-rs) | 0.52.6 | MIT OR Apache-2.0 |
| [windows_i686_gnullvm](https://github.com/microsoft/windows-rs) | 0.52.6 | MIT OR Apache-2.0 |
| [windows_i686_msvc](https://github.com/microsoft/windows-rs) | 0.52.6 | MIT OR Apache-2.0 |
| [windows_x86_64_gnu](https://github.com/microsoft/windows-rs) | 0.52.6 | MIT OR Apache-2.0 |
| [windows_x86_64_gnullvm](https://github.com/microsoft/windows-rs) | 0.52.6 | MIT OR Apache-2.0 |
| [windows_x86_64_msvc](https://github.com/microsoft/windows-rs) | 0.52.6 | MIT OR Apache-2.0 |
| [writeable](https://github.com/unicode-org/icu4x) | 0.6.4 | Unicode-3.0 |
| [yoke](https://github.com/unicode-org/icu4x) | 0.8.3 | Unicode-3.0 |
| [yoke-derive](https://github.com/unicode-org/icu4x) | 0.8.3 | Unicode-3.0 |
| [zerofrom](https://github.com/unicode-org/icu4x) | 0.1.8 | Unicode-3.0 |
| [zerofrom-derive](https://github.com/unicode-org/icu4x) | 0.1.8 | Unicode-3.0 |
| [zeroize](https://github.com/RustCrypto/utils) | 1.9.0 | Apache-2.0 OR MIT |
| [zerotrie](https://github.com/unicode-org/icu4x) | 0.2.5 | Unicode-3.0 |
| [zerovec](https://github.com/unicode-org/icu4x) | 0.11.8 | Unicode-3.0 |
| [zerovec-derive](https://github.com/unicode-org/icu4x) | 0.11.6 | Unicode-3.0 |
| [zmij](https://github.com/dtolnay/zmij) | 1.0.23 | MIT |

## StartOS package build tools

`packaging/startos/xbt-agent-wallet` is built with Start9's `@start9labs/start-sdk` (MIT,
<https://github.com/Start9Labs/start-sdk>). Its `Makefile` includes the SDK's `s9pk.mk`. These npm
packages are used to build the package and are not included in this repository:

| package | version | licence |
|---|---|---|
| @iarna/toml | 3.0.0 | ISC |
| @noble/curves | 1.9.7 | MIT |
| @noble/hashes | 1.8.0 | MIT |
| @nodable/entities | 2.2.0 | MIT |
| @start9labs/start-sdk | 2.0.9 | MIT |
| @types/ini | 4.1.1 | MIT |
| @types/node | 22.20.4 | MIT |
| @vercel/ncc | 0.38.4 | MIT |
| anynum | 1.0.1 | MIT |
| deep-equality-data-structures | 2.0.0 | MIT |
| fast-xml-builder | 1.3.1 | MIT |
| fast-xml-parser | 5.7.3 | MIT |
| ini | 5.0.0 | ISC |
| isomorphic-fetch | 3.0.0 | MIT |
| mime | 4.1.0 | MIT |
| node-fetch | 2.7.0 | MIT |
| object-hash | 3.0.0 | MIT |
| path-expression-matcher | 1.6.2 | MIT |
| prettier | 3.9.9 | MIT |
| strnum | 2.4.2 | MIT |
| tr46 | 0.0.3 | MIT |
| typescript | 6.0.3 | Apache-2.0 |
| undici-types | 6.21.0 | MIT |
| webidl-conversions | 3.0.1 | BSD-2-Clause |
| whatwg-fetch | 3.6.20 | MIT |
| whatwg-url | 5.0.0 | MIT |
| xml-naming | 0.3.0 | MIT |
| yaml | 2.9.1 | ISC |
| zod | 4.4.3 | MIT |
| zod-deep-partial | 1.4.4 | MIT |

## Standards and prior work

These are not code in this repository, but the design depends on them, and the credit is theirs.

* **Payment channels.** One-way channels in the style of Jeremy Spilman's 2013 proposal to the
  bitcoin-development list.
* **x402** (<https://github.com/coinbase/x402>), the HTTP 402 payment protocol by Coinbase. Stream is
  an XBT binding of its `batch-settlement` scheme.
* **Model Context Protocol** (<https://modelcontextprotocol.io>), the protocol the wallet's MCP
  server speaks.
* **Bitcoin Knots** (<https://github.com/bitcoinknots/bitcoin>): the BLAKE2b proof of work, the
  UnifiedSighash (0x21) replay protection, and the consensus rules this code follows.
* **Bitcoin Improvement Proposals:** BIP32, BIP39, BIP66, BIP86, BIP125, BIP143, BIP144, BIP173,
  BIP340, BIP341 and BIP350.
* **RFCs:** RFC 6979 (deterministic ECDSA), RFC 8032 (Ed25519), RFC 4648 (base encodings), RFC 8259 (JSON).
* **ECDSA adaptor signatures** with a DLEQ proof, from the published literature on scriptless scripts
  and adaptor signatures, also implemented in libsecp256k1-zkp's `ecdsa_adaptor` module
  (<https://github.com/BlockstreamResearch/secp256k1-zkp>).
* **Lightning:** BOLT 11 invoices (<https://github.com/lightning/bolts>), and LND's macaroon and REST
  formats as used by Lightning Fork (<https://github.com/paulscode/lightning-fork>), which the
  optional Lightning rail pays through.
* **Pay with work:** DATUM and TIDES (OCEAN), the mining and payout schemes the `xbt-work` receipts
  and coinbase audit are built around.
* **Packaging:** umbrelOS (<https://github.com/getumbrel/umbrel>) and StartOS
  (<https://github.com/Start9Labs/start-os>) app formats.
