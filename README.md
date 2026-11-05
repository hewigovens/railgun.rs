# railgun.rs

[![crates.io](https://img.shields.io/crates/v/rg-core.svg)](https://crates.io/crates/rg-core)
[![docs.rs](https://img.shields.io/docsrs/rg-core)](https://docs.rs/rg-core)
[![CI](https://github.com/hewigovens/railgun.rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hewigovens/railgun.rs/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/rustc-1.97.1+-blue.svg)](Cargo.toml)
[![License](https://img.shields.io/crates/l/rg-core.svg)](LICENSE)

A Rust implementation of a [Railgun](https://railgun.org) wallet: keys and 0zk addresses,
note encryption, chain sync and scanning, Groth16 proofs for private transfers and
unshields, Private Proof of Innocence (POI), broadcasters, and signing and sending. Swift
and Kotlin bindings come from UniFFI.

It is a library first. It replaces the TS engine and wallet SDK for apps that would
rather not ship Node.js, and its bytes match theirs. There is no app here; the `wallet`
example is a command line over the API.

> **Experimental.** It has moved real funds on Arbitrum. Codex and Claude have reviewed
> it for security; no human has audited it. Use small amounts.

## What works

- Keys from a BIP39 mnemonic, 0zk addresses, and a separate EVM account that pays gas.
- Sync from an RPC node, with the Railgun squid seeding pre-2023 leaves on mainnets and
  every tree's root checked against the contract after each batch of logs.
- Scanning and decryption of your notes, spent status, and history: shields, receipts,
  sends and unshields.
- Balances split by POI status (spendable, shield pending, missing POI and so on), from
  the POI aggregator.
- Private transfers and unshields, proved in Rust. Notes from several trees, or more than
  10, are split into several Railgun transactions in one call. They spend only notes whose
  POI is valid, as the TS SDK does.
- Native ETH: shielding it, and unshielding to it, through the RelayAdapt contract,
  with your own account or a broadcaster paying gas.
- Cross-contract calls through RelayAdapt, such as a swap: unshield, call, and shield the
  result back in one transaction, with your own account or a broadcaster paying gas. The
  caller builds the calls; there is no swap quoting here.
- View-only wallets from a shareable viewing key, in the engine's format.
- POI proofs, submitted to the aggregator, so recipients can spend what they receive.
- Broadcasters over Waku: signed fee offers, the fee note, pre-transaction POIs, and the
  encrypted request and answer, so no public account of yours pays gas or shows on chain.
- Shielding ERC-20 tokens, fee quotes, and EIP-1559 signing and sending.
- Checks for mnemonics, 0zk addresses and EIP-55 checksummed `0x` addresses.
- Ethereum, Arbitrum and Sepolia.

Checked against `@railgun-community/engine` 9.6.0 with its randomness pinned: keys,
ciphertexts, bound params, circuit inputs, calldata and witnesses match byte for byte.
The engine also gets the same trees, notes and balances for all of Sepolia's history up
to block 12031295. On Arbitrum, Rust-built transfers, an unshield and a two-input
transfer were mined and their POI proofs reached `Valid`. Anon wallet saw the funds as
spendable. So did an 11-note transfer split into two Railgun transactions, an unshield to
ETH through RelayAdapt, and a transfer and an unshield to ETH that broadcasters submitted
over Waku. A WETH to USDC swap on Uniswap through RelayAdapt, shielded back, was sent from
our own account and through a broadcaster, and both reached `Valid`.

## Crates

| Crate | What it holds |
| --- | --- |
| `rg‑primitives` | Field helpers, Poseidon (1 to 16 inputs), BabyJubJub, EdDSA, Ed25519 ECDH and blinding, AES, BLAKE-512, `PrivateKey` |
| `rg‑keys` | Railgun's BIP32 variant, wallet keys, 0zk addresses, the EVM gas account |
| `rg‑notes` | Token hashes, commitments, nullifiers, note and shield ciphertexts, memos |
| `rg‑tree` | The depth-16 Poseidon Merkle tree |
| `rg‑sync` | Event decoding, trees, nullifiers and root history; RPC and squid clients behind `rpc` |
| `rg‑wallet` | Trial decryption, TXOs, spent status, balances |
| `rg‑prover` | Circom witness from the circuit wasm (wasmi or wasmtime), snarkjs zkeys, Groth16 on arkworks |
| `rg‑tx` | Note selection, outputs, bound params, the spending signature, circuit inputs, calldata, shield, EIP-1559 |
| `rg‑poi` | Txid trees, blinded commitments, POI circuit inputs, the aggregator client |
| `rg‑broadcaster` | Broadcaster fee offers, sealed transact requests, and a Waku light client behind `waku` |
| `rg‑core` | `Client`: store, sync, scan, transfers, unshields, POI, sending, broadcasting |
| `rg‑uniffi` | Swift and Kotlin bindings over `rg-core` |

`docs/architecture.md` has the flows, `docs/protocol.md` the byte formats, and
`docs/engine-differences.md` where this library differs from the TS engine.

## Use from Rust

```toml
[dependencies]
rg-core = "0.1"
rg-keys = "0.1"
rg-sync = "0.1"
```

```rust
use rg_core::{Artifacts, Client, FileStore, Transfer};
use rg_keys::{EvmKey, WalletKeys};
use rg_sync::Network;

let keys = WalletKeys::from_mnemonic(&mnemonic, "", 0)?;
let store = FileStore::open("data/arbitrum")?;
let mut client = Client::open(Network::ARBITRUM, "https://arb1.arbitrum.io/rpc", store)?;
client.sync()?;
let balances = client.balances(&keys)?; // per token, by POI status
let history = client.history(&keys);

let transfer = Transfer { recipient: "0zk1...", token: weth, value: 10_000_000_000_000, memo: None };
let tx = client.build_transfer(&keys, &transfer, &Artifacts::new("data/artifacts"))?;
let gas = EvmKey::from_mnemonic(&mnemonic, "", 0)?;
let fee = client.quote_fee(&gas.address(), &tx)?; // show fee.max_cost() before sending
let hash = client.send(&gas, &tx, &fee)?;
```

The first sync on a mainnet seeds old leaves from the squid. Circuit artifacts download
the first time a proof needs them. After a transfer is mined, `client.prove_poi` and
`client.submit_poi` give it POI.

To send through a broadcaster instead, which pays the gas and takes its fee privately:

```rust
use rg_core::{Broadcasters, POI_LIST, Waku};

let mut broadcasters = Broadcasters::new(Waku::railgun()?, Network::ARBITRUM.chain_id);
let offer = broadcasters.best_offer(&weth, POI_LIST, None)?.ok_or("no broadcaster")?;
let artifacts = Artifacts::new("data/artifacts");
let tx = client.build_broadcast_transfer(&keys, &transfer, &offer, &artifacts)?; // show tx.fee
let hash = client.broadcast(&mut broadcasters, &tx)?;
```

`crates/rg-core/examples/wallet.rs` covers `sync`, `balance`, `history`, `transfer`,
`unshield`, `unshield-eth`, `shield`, `shield-eth`, `estimate`, `send`, `poi`,
`broadcasters`, `broadcast-transfer`, `broadcast-unshield`, `broadcast-unshield-eth` and
`swap`:

```sh
cargo run --release -p rg-core --example wallet -- arbitrum <rpc url> <data dir> <mnemonic file> balance
```

## Swift and Kotlin

`just ffi` writes the bindings to `build/bindings`. `just ffi-apple` builds an
XCFramework for macOS, iOS and the iOS simulator, and `just ffi-android` builds JNI
libraries. Every call blocks, so call from a background thread. Amounts are decimal
strings.

The smoke tests in `crates/rg-uniffi/tests` show how to use the bindings, including how
to pass a mnemonic as bytes and wipe it afterwards.

## Circuit artifacts

Railgun's circuits carry no license, so this repository does not include them. Like
every Railgun wallet, `rg_core::Artifacts` downloads them from IPFS the first time it
needs them. It checks each file against the hashes the wallet SDK publishes, and checks
again on every load.

## Not supported yet

- Running inside a real Android app, and timings on real phones.

Not planned: NFTs; legacy (pre-2023) events, so a wallet with notes from before the
squid seed cannot scan them; and Waku over WebSockets, since a browser wallet can use the
TS wallet SDK.

## Contributing

`CONTRIBUTING.md` has the commands, the test vectors, the TS harness, the checks that need
circuit artifacts or chain data, live runs, and measurements. `AGENTS.md` has the code
conventions.

## License

Copyright 2026 hewigovens. Licensed under the Apache License, Version 2.0; see `LICENSE`.

Parts come from other projects and keep their own licenses:

- `crates/rg-primitives/src/poseidon.rs` is a port of codex-storage/rs-poseidon
  (MIT OR Apache-2.0), and `poseidon_constants_opt.json` is vendored from it
  (circomlib's optimized Poseidon parameters).
- `crates/rg-prover/src/zkey.rs` and `qap.rs` are ported from ark-circom 0.5.0
  (MIT OR Apache-2.0, Copyright (c) 2021 Georgios Konstantopoulos).
- Vectors in `crates/rg-keys/tests/engine_vectors.rs` and
  `crates/rg-notes/tests/engine_vectors.rs` come from the Railgun engine's tests (MIT),
  and `crates/rg-core/src/artifact-v2-hashes.json` from the Railgun wallet SDK (MIT).

EdDSA is written from the circomlib scheme, and no circomlibjs (GPL-3.0) code is ported.
BLAKE-512 is written from the SHA-3 submission. The witness calculator follows
circom_runtime's calling convention and copies no code from it.
