# Development

`AGENTS.md` has the code conventions and `justfile` the commands. Keep the target
directory out of a synced folder, because it gets large.

## Tests

`just test` runs every test that needs only what is committed. A few more need local
files, and skip or are `#[ignore]`d without them:

| Test | Needs | Run with |
| --- | --- | --- |
| Full Sepolia history (`rg-wallet`) | `data/sepolia-logs.jsonl`, about 23 MB | `cargo test --release -p rg-wallet -- --ignored` |
| Witness and proof against snarkjs (`rg-tx`) | 1x2 circuit artifacts | `just test-proof <artifacts>` |
| Rebuilding the transfer vector from keys (`rg-tx`) | `.test-wallet/sepolia-test-mnemonic.txt` | `just test` |

`.test-wallet/` and `data/` are gitignored. Keep mnemonics and keys there, never in
source, logs or fixtures.

## Vectors

`harness/` runs the TS engine (`@railgun-community/engine` 9.6.0) on fixed inputs and
writes JSON into `vectors/` for the Rust tests to diff against. Randomness comes from a
fixed seed, so a rerun gives the same files, and a changed file means the engine's
behavior changed.

```sh
cd harness && npm install && npm run vectors
```

With the engine installed elsewhere:

```sh
HARNESS_NODE_MODULES=/path/to/node_modules node harness/gen-vectors.js vectors
```

The engine needs POI stubbed (`POI.init([], {isActive: () => false, isRequired: async
() => false})`) and a wallet source set, or `generateTransactions` throws.

### Sepolia sync and scan

`data/` holds the proxy's logs as JSONL, one `eth_getLogs` object per line, and the
successful `transact` calls. Etherscan's APIs give the same shapes.
`vectors/sepolia/` holds the first 200 logs and the engine's result for them, which
`just test` checks.

```sh
cargo run --release -p rg-sync --example check_roots -- data/sepolia-logs.jsonl data/sepolia-transact-calls.json
cargo run --release -p rg-wallet --example scan_file -- data/sepolia-logs.jsonl <mnemonic-file> > scan.json
HARNESS_NODE_MODULES=/path/to/node_modules node harness/scan.js data/sepolia-logs.jsonl <mnemonic-file> scan.json
```

### Transfer and proof

`vectors/transfer/` is the engine's 1x2 transfer from a throwaway Sepolia wallet,
spending a synthetic shield appended to the first 200 logs, with its randomness pinned.
The engine repository's `src/test/test-artifacts-lite/1x2/` has brotli-compressed
artifacts whose key equals the production one. Decompress them into
`<artifacts>/1x2/{circuit.wasm,circuit.zkey,vkey.json}`.

```sh
ARTIFACTS_DIR=<artifacts> HARNESS_NODE_MODULES=/path/to/node_modules \
  node harness/transfer.js vectors/sepolia/sepolia-head-200.jsonl <mnemonic-file> vectors/transfer
just test-proof <artifacts>
cargo run --release -p rg-prover --features wasmtime,parallel --example prove_1x2 -- <artifacts>/1x2 vectors/transfer/transfer.json
```

### Rust to TS

Ciphertexts and signatures that Rust made, with randoms the engine never saw, for the
engine to decrypt and verify:

```sh
cargo run -p rg-notes --example emit_ciphertexts > ciphertexts.json
HARNESS_NODE_MODULES=/path/to/node_modules node harness/check-rust.js ciphertexts.json
```

## Live runs

The `wallet` example runs everything against a real chain. With a mnemonic file, an EVM
key file holding one `0x` hex private key, and `$RECIPIENT` a 0zk address:

```sh
W="cargo run --release -p rg-core --example wallet -- arbitrum https://arb1.arbitrum.io/rpc data/chain <mnemonic-file>"
WETH=0x82aF49447D8a07e3bd95BD0d56f35241523fBab1
$W sync
$W balance                                # by POI status, from the aggregator
$W history
$W shield <evm-key-file> $WETH <value>   # approves if needed, then shields to this wallet
$W transfer $RECIPIENT $WETH <value> > transfer.jsonl
$W unshield <to> $WETH <value> > transfer.jsonl   # instead of transfer
$W estimate <from> transfer.jsonl         # fee quote
$W send <evm-key-file> transfer.jsonl
$W sync
$W poi <tx hash> --submit
```

`poi` needs the squid and the aggregator to have the transaction, which usually takes
under a minute. Do not leave a wallet with the same keys open in Railway, or it submits
POI first.

To test sending without spending, fork the chain with anvil
(`anvil --fork-url https://arb1.arbitrum.io/rpc`) and point the RPC at it. Anvil answers
1 gwei for the priority fee where Arbitrum answers 0, so fund the payer with
`anvil_setBalance` first.

The Swift and Kotlin smoke tests run a live part when `RG_MNEMONIC_FILE`, `RG_RPC`,
`RG_DATA`, `RG_FROM`, `RG_RECIPIENT` and `RG_TOKEN` are set, plus `RG_POI_TX` for POI.
That part sends nothing unless `RG_SEND_KEY_FILE` is set too, so point `RG_RPC` at a
fork when it is.

## Bindings

`just ffi` generates Swift and Kotlin (package `dev.hewig.railgun`) into
`build/bindings`. `just ffi-apple` builds `build/RailgunFFI.xcframework`, and
`just ffi-android` builds `build/android/jniLibs` for arm64-v8a and x86_64 with 16 KB
page alignment. It needs `ANDROID_NDK_HOME` and `cargo-ndk`; NDK 27.3 works. The bindings
use the wasmi witness backend, which needs no JIT, so it also runs on iOS.

So far the Swift bindings have run on macOS and an iOS simulator, and the Kotlin
bindings on the JVM. The `wallet` example, built with the NDK, ran on an Android 16
arm64 emulator. The Kotlin bindings have not run inside an Android app yet.

## Chain data and artifacts

`FileStore` keeps inputs (the seed, logs and a cursor) and replays them on open. Nothing
derived is stored. Each sync refetches the network's `reorg_window` of blocks, which
also clears anything a crash left past the cursor. `txid-leaves.txt` caches txid tree
leaves older than that window, which took a POI proof from about 29 s to 8 s.

A first sync on Ethereum or Arbitrum seeds leaf hashes from the squid, because `rg-sync`
does not decode legacy events, and checks the resulting root against the contract.

`Artifacts` checks files against `crates/rg-core/src/artifact-v2-hashes.json` (from
wallet SDK 11.2.0). Transact circuits come from
`QmUsmnK4PFc7zDp2cmC4wBZxYLjNyRgWfs5GNcJJ2uLcpU`, and POI circuits from
`QmZ2MyM6TKxffkv6stuo2hFwmUfs3q4xgMYN164Sje8new`, both through
`https://ipfs-lb.com/ipfs/`. The engine's lite `poi/` artifacts and the POI root in
engine 9.6.0 and wallet SDK 10.9.0 are stale, and the live aggregator rejects proofs made
with them. The current POI wasm needs two more runtime imports, which both witness
backends stub. Because the harness still pins engine 9.6.0, it does not match this POI
key.

`prove_poi` uses the 3x3 circuit for up to three inputs and outputs, and 13x13 above
that. A 13x13 proof of a two-note transfer verifies against the published key, but no
real transaction with four or more inputs has gone through it yet.

## Measurements

One 1x2 transfer in release mode on a 4-core 2.1 GHz Xeon:

| Step | Time |
| --- | --- |
| zkey load (6 MB, with curve checks) | 1.15 s |
| Witness, wasmi | 0.36 s |
| Witness, wasmtime | 0.04 to 0.06 s |
| Prove, one thread | 0.60 to 0.76 s |
| Prove, `parallel` (4 threads) | 0.19 s |
| Prove, snarkjs in Node | 1.4 to 1.6 s |

On an Android 16 arm64 emulator on an M4 Pro, against Arbitrum, with circuits and
leaves cached: sync 2.9 s, transfer with proof 2.9 s, POI 9.9 s. `FileStore` replays
Arbitrum's 133k leaves in about two seconds on an M-series Mac.

Gas on Arbitrum: approve about 53k, shield about 780k, and a 1x2 transfer or an unshield
about 1.0M to 1.1M.

## Things learned the hard way

- The `blake-hash` crate panics on aarch64, because ppv-lite86's generic backend leaves
  `shuffle1230` unimplemented. `rg_primitives::blake` replaces it.
- ark-circom's zkey matrices report one witness variable too many, so `Circuit::prove`
  checks the witness length against `pk.a_query.len()`.
- ark-circom 0.6 pulls ark 0.6, wasmer and ethers-core, so `zkey.rs` and `qap.rs` are
  ported from 0.5 onto ark 0.5.
- Bound params: the engine encodes `minGasPrice` as uint48 and the contract as uint72,
  which give the same bytes below 2^48. The hash is keccak of `abi.encode` of one
  dynamic tuple, which is alloy's `BoundParams::abi_encode()`.
- `formatProof` puts the imaginary part of each G2 coordinate first for the contract.
  So does `rg_tx::snark_proof`, and `verifying_key_from_contract` swaps them back.
- The engine draws randomness for a transfer in this order: sender random (if hidden),
  note random, change note random, one draw not used in outputs, then a GCM IV and a
  CTR IV per output. `plan_transfer`'s `fill` follows it, so the vectors reproduce.
- Rollup gas estimates move with the L1 fee, so `Client::send` adds 20% to the estimate.
