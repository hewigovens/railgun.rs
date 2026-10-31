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

## Known differences from the TS engine

- `mnemonic_to_seed` checks the BIP39 checksum; the engine does not.
- `AddressData.master_public_key` is a field element, so an address whose MPK is at or
  above the BN254 modulus decodes to the reduced value. A real MPK is a Poseidon output
  and never hits this; one engine test vector does, and the test notes it.
- `babyjubjub::Point::mul_le` is not constant time. That is fine for public key
  derivation from a key the caller already holds, but signing (M2) needs a
  constant-time ladder.

## Licensing

MIT. `crates/rg-primitives/src/poseidon.rs` is a port of codex-storage/rs-poseidon
(MIT OR Apache-2.0), and `poseidon_constants_opt.json` is vendored from it (circomlib's
optimized Poseidon parameters). Vectors in `crates/rg-keys/tests/engine_vectors.rs` are
copied from the Railgun engine's tests (MIT).
