# Handoff (2026-11-02)

Read `AGENTS.md` for conventions, `scope.md` for the plan, `docs/architecture.md` for the
design and `README.md` for commands. This file is what those two
don't say.

## Where it stands

| Milestone | State |
| --- | --- |
| M0 vector harness | done |
| M1 keys, 0zk addresses | done, matches engine vectors |
| M2 notes, EdDSA, Ed25519 blinding, AES | done, byte-equal to the engine |
| M3 Sepolia sync, tree, scan | done, matches the engine on all of Sepolia to block 12031295 |
| M4 prove and submit one transfer | done on Arbitrum; the Anon wallet received it |
| M5 POI | done on Arbitrum: a Rust proof reached `Valid`, Anon shows the funds spendable |
| Unshield, several inputs | done on Arbitrum, each with POI `Valid` |
| Bindings | Swift through `rg-uniffi`, run on macOS and an iOS simulator against live Arbitrum |

Tests: `cargo test --workspace` gives 67 passed, 2 ignored (the M3 full-history test
needs Sepolia `data/`, the M4 witness and proof test needs circuit artifacts). Two tests
skip quietly without `.test-wallet/sepolia-test-mnemonic.txt`.

M4 checks that pass, against engine 9.6.0 with randoms pinned:
- circuit inputs, bound params and `transact` calldata identical
- Rust witness (wasmi and wasmtime) equals snarkjs's
- arkworks proof accepted by snarkjs and by the Sepolia contract's 1x2 key
- recipient decrypts the Rust-built note; change comes back to the sender
- `rg_core::Client::build_transfer` runs the whole path in Rust

Arbitrum transactions from Rust:

| Tx | What | Gas |
| --- | --- | --- |
| `0xb4988c76c999a60d702bff903a5f9934504eed945eb34a47466c9426f89f7db2` | first transfer, to Anon | 1,006,352 |
| `0x66b1c989088cc3cea55d6bab333ebcc86365ac3b34b763348d1c2d5013d15c1c` | unshield 0.00003 WETH to the EOA | 1,100,961 |
| `0xff75d2af67945181c1454117329deee14225b8a5891db1ce8c481f6dbe500155` | transfer to self, to split a note | 1,066,500 |
| `0x19cbad9383a44758b0ff7ce1934d8052d9d6a33567fe817a13c07e228083135a` | two notes in, 0.00011 WETH to Anon | 1,068,979 |

## Mainnet sync and sending

`rg_core::Client` is the API; `crates/rg-core/examples/wallet.rs` is a thin command line
over it. First sync on a mainnet seeds leaf hashes from the squid, because `rg_sync` does
not decode legacy events, and checks the root against the contract. A wallet's notes must
all come after that seed, which holds for the fresh wallets here. Checked: the lite 1x1,
1x2 and 1x3 keys equal Arbitrum's on-chain keys, and synced leaves match
`nextLeafIndex`. Shield fee is 0.25%.

Local state, all gitignored:

- `.test-wallet/test-mnemonic.txt` sender wallet, `recipient-mnemonic.txt` second wallet,
  `test-eoa.key` gas account, `addresses.txt` their public addresses (sender 0zk,
  recipient 0zk, EOA)
- `data/chain/arbitrum/`, `data/chain/artifacts/` (downloaded on demand), `data/artifacts/1x2`
  (lite, for the ignored M4 test)

Sender holds 0.00001 WETH. The EOA has about 0.00042 ETH and 0.000029925 WETH. With `harness` installed
(`npm install --ignore-scripts`) and `$RECIPIENT` a 0zk address:

```
W="cargo run --release -p rg-core --example wallet -- arbitrum https://arb1.arbitrum.io/rpc data/chain .test-wallet/test-mnemonic.txt"
WETH=0x82aF49447D8a07e3bd95BD0d56f35241523fBab1
$W sync
$W balance
$W transfer $RECIPIENT $WETH <value> > .test-wallet/transfer.jsonl
$W unshield <to> $WETH <value> > .test-wallet/transfer.jsonl   # instead of transfer
$W estimate <eoa> .test-wallet/transfer.jsonl
node harness/send.js send https://arb1.arbitrum.io/rpc .test-wallet/test-eoa.key .test-wallet/transfer.jsonl
$W sync
$W poi <tx hash> --submit
```

`poi` needs the squid and aggregator to have the transaction, usually under a minute. Do
not leave a wallet holding these keys open in Railway, or it submits POI first.

## Bindings

`just ffi` writes Swift bindings to `build/bindings`, and `just ffi-apple` also builds `build/RailgunFFI.xcframework` for macOS, iOS and the iOS simulator. `just test-swift` runs `crates/rg-uniffi/tests/swift/main.swift` offline; set `RG_MNEMONIC_FILE`, `RG_RPC`, `RG_DATA`, `RG_FROM`, `RG_RECIPIENT`, `RG_TOKEN` and optionally `RG_POI_TX` to run the live part, which sends nothing.

Android needs the NDK on the machine, because `ring` compiles C: `cargo check --target aarch64-linux-android` fails in its build script here. Kotlin bindings are not generated yet.

## Store

`rg_core::FileStore` keeps inputs (seed, logs, a cursor) and replays them on open: about
two seconds for Arbitrum's 133k leaves on an M-series Mac. `txid-leaves.txt` caches txid tree leaves older than the reorg window, which took a POI proof from about 29 s to 8 s. Nothing derived is stored, so a
real database can wait until this is too slow on a phone. Each sync refetches the
network's `reorg_window` of blocks, 64 or 2,400 on Arbitrum, which also clears anything a
crash left past the cursor.

## Artifacts

`rg_core::Artifacts` downloads a circuit the first time it is needed, checks it against
`crates/rg-core/src/artifact-v2-hashes.json` (from wallet 11.2.0) and rechecks the hash on
every load, so a damaged file is fetched again. Transact circuits come from
`QmUsmnK4PFc7zDp2cmC4wBZxYLjNyRgWfs5GNcJJ2uLcpU`, POI circuits from
`QmZ2MyM6TKxffkv6stuo2hFwmUfs3q4xgMYN164Sje8new`, both through `https://ipfs-lb.com/ipfs/`.

The engine's lite `poi/` folder and the POI root in engine 9.6.0 and wallet 10.9.0
(`QmZrP9zaZw2L...`) are stale, and the live aggregator answers `Invalid proof` to proofs
made with them. The current wasm needs two more runtime imports, stubbed in both witness
backends. The harness still pins engine 9.6.0, so it does not match this POI key.

`prove_poi` takes the 3x3 circuit for up to three inputs and outputs and 13x13 above that.
A 13x13 proof of a two-note transfer verifies against the published key, but no real
4+ input transaction has gone through it yet.

Tx `0x32383758ec908c66fea5299ef0456d97147117f8f1f507d3783026212adc1cb8` reached `Valid` from
a Rust proof with Railway closed. The first transfer's POI came from Railway.

## Lite artifacts

The ignored M4 test reads `<artifacts>/1x2/{circuit.wasm,circuit.zkey,vkey.json}`. The
engine repo's `src/test/test-artifacts-lite/1x2/` has them as brotli `wasm.br` and `zkey.br`.
The 1x2 zkey has the same hash as the production one.

## Things learned the hard way

- The `blake-hash` crate panics on aarch64 (ppv-lite86's generic backend leaves
  `shuffle1230` unimplemented), which the x86 cloud machine never hit. `rg_primitives::blake`
  replaces it.
- ark-circom's zkey matrices report one witness variable too many; `Circuit::prove`
  checks the witness length against `pk.a_query.len()` instead.
- ark-circom 0.6 pulls ark 0.6, wasmer and ethers-core, so `zkey.rs` and `qap.rs` were
  ported from 0.5 onto ark 0.5 (MIT OR Apache-2.0, credited in the files and README).
- Bound params: the engine encodes `minGasPrice` as uint48, the contract as uint72;
  same bytes below 2^48. The hash is keccak of `abi.encode` of one dynamic tuple, which
  is alloy's `BoundParams::abi_encode()`.
- `formatProof` swaps G2 coordinates for the contract (imaginary part first); so does
  `rg_tx::snark_proof`, and `verifying_key_from_contract` swaps them back.
- Engine randomness order for a transfer: sender random (if hidden), note random,
  change note random, one draw not used in outputs, then GCM IV and CTR IV per output.
  `plan_transfer`'s `fill` follows this so the M4 vectors reproduce exactly.
- The harness must stub POI (`POI.init([], {isActive: () => false, isRequired: async
  () => false})`) and set a wallet source, or `generateTransactions` throws.
- `rg_wallet` rejects a shield whose npk isn't `poseidon(ourMPK, random)`; stricter than
  the engine, and such a note can't be spent anyway.
- Release-mode timings, 4-core 2.1 GHz Xeon: zkey load 1.15 s (curve and subgroup checks;
  caching an unchecked serialized key should cut it), witness 0.05 s wasmtime / 0.36 s
  wasmi, prove 0.19 s with `parallel`, 0.6 s single-threaded, snarkjs 1.5 s.
- wasmi runs the witness without JIT, so it is an option on iOS instead of a hidden
  WKWebView. Not tried on a device.

## Not in git

- `data/`: chain data and artifacts, all refetchable with `wallet sync`. A fresh seed drops notes older than it, so keep `data/chain/` for live wallets. The M3 `sepolia-transact-calls.json` comes from Etherscan.
- `.test-wallet/`, circuit artifacts, `target/`.

## Open items

- Spending across trees, which needs one transaction per tree.
- Unshield to native ETH (relay adapt), broadcaster fees, NFTs.
- Decoding legacy (pre-V2.1) events, so older wallets can scan.
- Kotlin bindings and an Android build; timings on a real iPhone and Android device.
