# railgun-rust-core

A Rust core for a private Railgun wallet, meant to be exposed to Swift and Kotlin
through UniFFI. See `scope.md` for the plan and milestones.

## Status

- M0: `harness/` generates golden vectors from the TS engine
  (`@railgun-community/engine` 9.6.0) into `vectors/`.
- M1: `crates/rg-primitives` (Poseidon 1 to 16 inputs, BabyJubJub, field helpers) and
  `crates/rg-keys` (Railgun's BIP32 variant, spending, viewing, nullifying and master
  public keys, 0zk address encode and decode). Both are checked against the vectors and
  against the vectors in the engine's own tests.
- M2: `rg-primitives` adds EdDSA Poseidon signing and verification (constant-sequence
  ladder for secret scalars), Ed25519 ECDH and viewing-key blinding, and AES-256-GCM
  (16-byte IV) and CTR. `crates/rg-notes` has token hashes, note public keys,
  commitments, nullifiers, memo text, annotation data, V2 transact note ciphertexts
  (encrypt, decrypt as receiver, decrypt as sender) and shield ciphertexts. The harness
  pins every IV and random the engine draws, so ciphertexts compare byte for byte.
- M3: `crates/rg-tree` (depth-16 Poseidon Merkle tree, proofs), `crates/rg-sync`
  (V2.1 proxy event decoding with `alloy-sol-types`, trees and nullifiers rebuilt from
  logs, root history, `transact` calldata roots; optional `rpc` feature with a blocking
  JSON-RPC client) and `crates/rg-wallet` (trial decryption, TXOs, spent status, sent
  notes, balances). Checked on the full Sepolia history to block 12031295: every root
  a successful `transact` call used is in the rebuilt history, and the TS engine gets
  the same root, TXOs, spends and balances for the same wallet.

## Running the tests

```
CARGO_TARGET_DIR=/some/dir/outside/this/folder cargo test
```

Keep the target directory out of a synced folder; it gets large.

## Regenerating vectors

```
cd harness && npm install && npm run vectors
```

Or, with the engine already installed somewhere else:

```
HARNESS_NODE_MODULES=/path/to/node_modules node harness/gen-vectors.js vectors
```

Randomness in the harness is derived from a fixed seed, so a rerun gives the same files.
A change in `vectors/` after a rerun means the engine's behaviour changed.

## Sepolia sync check (M3)

`data/` is not committed. It holds the proxy's logs as JSONL (one `eth_getLogs` object
per line; Etherscan's logs API gives the same shape) and successful `transact` calls.

```
cargo run --release -p rg-sync --example check_roots -- data/sepolia-logs.jsonl data/sepolia-transact-calls.json
cargo run --release -p rg-wallet --example scan_file -- data/sepolia-logs.jsonl <mnemonic-file> > /tmp/rust-scan.json
HARNESS_NODE_MODULES=/path/to/node_modules node harness/m3.js data/sepolia-logs.jsonl <mnemonic-file> /tmp/rust-scan.json
cargo test --release -p rg-wallet -- --ignored   # full-history test, needs data/
```

`vectors/m3/` holds the first 200 Sepolia logs and the engine's result for them, which
the default test run checks.

## Rust to TS check

Rust-made ciphertexts and signatures, with randoms the engine never saw, decrypted and
verified by the engine:

```
cargo run -p rg-notes --example emit_ciphertexts > /tmp/rust-ciphertexts.json
HARNESS_NODE_MODULES=/path/to/node_modules node harness/check-rust.js /tmp/rust-ciphertexts.json
```

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
- `rg_sync` handles V2.1 events only (all Sepolia has). Legacy pre-March-2023 events on
  other chains, reorgs and persistent storage are not done yet.

## Licensing

MIT. `crates/rg-primitives/src/poseidon.rs` is a port of codex-storage/rs-poseidon
(MIT OR Apache-2.0), and `poseidon_constants_opt.json` is vendored from it (circomlib's
optimized Poseidon parameters). Vectors in `crates/rg-keys/tests/engine_vectors.rs`
and `crates/rg-notes/tests/engine_vectors.rs` are copied from the Railgun engine's
tests (MIT). EdDSA is written from the circomlib scheme; no circomlibjs (GPL-3.0) code
is ported.
