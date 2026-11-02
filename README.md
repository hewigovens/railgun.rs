# railgun.rs

A Rust implementation of a [Railgun](https://railgun.org) wallet: keys and 0zk addresses,
note encryption, chain sync and scanning, Groth16 proofs for private transfers and
unshields, Private Proof of Innocence (POI), and signing and sending. Swift and Kotlin
bindings come from UniFFI.

It is a library first. It replaces the TS engine and wallet SDK for apps that would
rather not ship Node.js, and its bytes match theirs. There is no app here; the `wallet`
example is a command line over the API.

> **Experimental and unaudited.** It has moved real funds on Arbitrum, but nobody has
> reviewed it for security. Use small amounts.

## What works

- Keys from a BIP39 mnemonic, 0zk addresses, and a separate EVM account that pays gas.
- Sync from an RPC node, with the Railgun squid seeding pre-2023 leaves on mainnets and
  every root checked against the contract.
- Scanning and decryption of your notes, spent status and balances.
- Private transfers and unshields, with several inputs from one tree, proved in Rust.
- POI proofs, submitted to the aggregator, so recipients can spend what they receive.
- Shielding ERC-20 tokens, and EIP-1559 signing and sending.
- Ethereum, Arbitrum and Sepolia.

Checked against `@railgun-community/engine` 9.6.0 with its randomness pinned: keys,
ciphertexts, bound params, circuit inputs, calldata and witnesses match byte for byte.
The engine also gets the same trees, notes and balances for all of Sepolia's history up
to block 12031295. On Arbitrum, Rust-built transfers, an unshield and a two-input
transfer were mined and their POI proofs reached `Valid`. Anon wallet saw the funds as
spendable.

## Crates

| Crate | What it holds |
| --- | --- |
| `rg-primitives` | Field helpers, Poseidon (1 to 16 inputs), BabyJubJub, EdDSA, Ed25519 ECDH and blinding, AES, BLAKE-512, `PrivateKey` |
| `rg-keys` | Railgun's BIP32 variant, wallet keys, 0zk addresses, the EVM gas account |
| `rg-notes` | Token hashes, commitments, nullifiers, note and shield ciphertexts, memos |
| `rg-tree` | The depth-16 Poseidon Merkle tree |
| `rg-sync` | Event decoding, trees, nullifiers and root history; RPC and squid clients behind `rpc` |
| `rg-wallet` | Trial decryption, TXOs, spent status, balances |
| `rg-prover` | Circom witness from the circuit wasm (wasmi or wasmtime), snarkjs zkeys, Groth16 on arkworks |
| `rg-tx` | Note selection, outputs, bound params, the spending signature, circuit inputs, calldata, shield, EIP-1559 |
| `rg-poi` | Txid trees, blinded commitments, POI circuit inputs, the aggregator client |
| `rg-core` | `Client`: store, sync, scan, transfers, unshields, POI, sending |
| `rg-uniffi` | Swift and Kotlin bindings over `rg-core` |

`docs/architecture.md` has the flows, and `docs/protocol.md` the byte formats.

## Use from Rust

The crates are not on crates.io yet, so depend on them by git.

```rust
use rg_core::{Artifacts, Client, FileStore, Transfer};
use rg_keys::{EvmKey, WalletKeys};
use rg_sync::Network;

let keys = WalletKeys::from_mnemonic(&mnemonic, "", 0)?;
let store = FileStore::open("data/arbitrum")?;
let mut client = Client::open(Network::ARBITRUM, "https://arb1.arbitrum.io/rpc", store)?;
client.sync()?;
let balances = client.scan(&keys).balances();

let transfer = Transfer { recipient: "0zk1...", token: weth, value: 10_000_000_000_000, memo: None };
let tx = client.build_transfer(&keys, &transfer, &Artifacts::new("data/artifacts"))?;
let gas = EvmKey::from_mnemonic(&mnemonic, "", 0)?;
let hash = client.send(&gas, &tx)?;
```

The first sync on a mainnet seeds old leaves from the squid. Circuit artifacts download the first time a proof needs them. After a transfer
is mined, `client.prove_poi` and `client.submit_poi` give it POI.

`crates/rg-core/examples/wallet.rs` covers `sync`, `balance`, `transfer`, `unshield`,
`shield`, `send` and `poi`:

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

- Spending notes from more than one tree in one transfer.
- Native ETH: shielding it, or unshielding to it, needs the relay adapt contract.
- Broadcasters, so for now a public account pays gas and shows on chain.
- NFTs.
- Legacy (pre-2023) events, so a wallet with notes from before the squid seed cannot
  scan them.
- A view-only wallet.
- Running inside a real Android app, and timings on real phones.

## Known differences from the TS engine

- `mnemonic_to_seed` checks the BIP39 checksum; the engine does not.
- `AddressData.master_public_key` is a field element, so an address whose MPK is at or
  above the BN254 modulus decodes to the reduced value. A real MPK is a Poseidon output
  and never hits this; one engine test vector does, and the test notes it.
- `babyjubjub::Point::mul_le` is variable time and only used for public scalars
  (verification). Key derivation and signing use `mul_ct`, a Montgomery ladder that runs
  the same field operations for every scalar. arkworks' field arithmetic underneath is
  not audited for constant time.
- `ed25519::shared_key` accepts a non-canonical y encoding, as the engine's wasm path
  (curve25519-dalek) does; blinding and unblinding reject it, as noble-ed25519 does.
- `wallet_source::encode` rejects sources over 16 characters; the engine only enforces
  that when a wallet source is set, not when encoding.
- `memo::decrypt_annotation` returns none for annotation data under 32 bytes, where the
  engine would return truncated fields.
- `rg_wallet` drops a shield note whose note public key is not
  `poseidon(ourMPK, random)`; the engine keeps any shield whose random decrypts. Such a
  note could not be spent.
- `rg_tx::select_notes` spends from one tree, up to 10 notes.
- `rg_prover::Circuit::prove` checks the witness length against the zkey's variable
  count; ark-circom's matrices count one witness variable too many.

## Development

```sh
just test          # all workspace tests
just lint          # rustfmt, clippy, SwiftFormat, SwiftLint
just test-swift    # Swift smoke test
just test-kotlin   # Kotlin smoke test, needs Gradle
```

`docs/development.md` covers the test vectors, the TS harness, the checks that need
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
