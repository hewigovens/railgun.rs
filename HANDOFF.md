# Handoff (2026-11-01)

Picking this up on a local machine. Read `scope.md` for the plan and `README.md` for
commands. This file is what the cloud session knew that those two don't say.

## Where it stands

| Milestone | State |
| --- | --- |
| M0 vector harness | done |
| M1 keys, 0zk addresses | done, matches engine vectors |
| M2 notes, EdDSA, Ed25519 blinding, AES | done, byte-equal to the engine |
| M3 Sepolia sync, tree, scan | done, matches the engine on all of Sepolia to block 12031295 |
| M4 prove and submit one transfer | everything but the on-chain send |
| M5 POI | not started |

Tests: `cargo test --workspace` gives 48 passed, 2 ignored (the M3 full-history test
needs `data/`, the M4 witness and proof test needs circuit artifacts). Two of the 48
skip quietly without `.test-wallet/sepolia-test-mnemonic.txt`.

M4 checks that pass, against engine 9.6.0 with randoms pinned:
- circuit inputs, bound params and `transact` calldata identical
- Rust witness (wasmi and wasmtime) equals snarkjs's
- arkworks proof accepted by snarkjs and by the Sepolia contract's 1x2 key
- recipient decrypts the Rust-built note; change comes back to the sender
- `crates/rg-tx/examples/transfer.rs` runs the whole path in Rust

Not checked: the contract accepting a real transfer, and Railway decrypting it.

## Next step: the on-chain send

Nothing has been shielded to any test wallet yet. Plan:

1. Make a fresh test wallet locally (the cloud one's mnemonic stays in the cloud folder,
   and it holds nothing):
   `cargo run -p rg-keys --example new_wallet -- .test-wallet/test-mnemonic.txt`
   It refuses to overwrite and prints the 0zk address. `.test-wallet/` is gitignored.
2. Shield a little testnet ETH (wrapped to WETH) to that 0zk address. Anon wallet
   offers Arbitrum Sepolia and HyperEVM testnet. Sepolia itself is what all the code and
   vectors target. Arbitrum or HyperEVM testnet needs, first:
   - the Railgun proxy address and deployment block on that chain (not looked up yet)
   - a check that its events are V2.1 (`rg_sync` decodes nothing older) and that its
     `VerifyingKeySet` 1x2 key matches the lite artifacts, as Sepolia's does
   - the chain id in `TransferRequest.chain_id` (`chain_full_network_id(0, id)`)
3. Fetch the proxy's logs from the deployment block (JSONL, one `eth_getLogs` object per
   line), run `examples/transfer.rs` with your wallet, recipient 0zk, token and value.
   It prints `{to, data}` for the proxy; any funded account can send it (self-signed,
   no broadcaster). From the cloud there was no RPC (proxy refused every public
   Sepolia endpoint), which is why this stopped here.
4. Use your Railway 0zk as the recipient to close the "Railway decrypts" check. Expect
   Railway to hold it as pending until POI (M5).

## Circuit artifacts

Not in git (unlicensed). The engine repo's `src/test/test-artifacts-lite/<shape>/` has
brotli files `wasm.br`, `zkey.br`, `vkey.json`. Decompress into
`<artifacts>/<shape>/circuit.wasm`, `circuit.zkey`, `vkey.json`:

```
node -e "const z=require('zlib'),f=require('fs');for(const[a,b]of[['wasm.br','circuit.wasm'],['zkey.br','circuit.zkey']])f.writeFileSync(process.argv[2]+'/'+b,z.brotliDecompressSync(f.readFileSync(process.argv[1]+'/'+a)))" <engine>/src/test/test-artifacts-lite/1x2 <artifacts>/1x2
cp <engine>/src/test/test-artifacts-lite/1x2/vkey.json <artifacts>/1x2/
```

The lite 1x1, 1x2, 2x1 and 1x3 keys equal Sepolia's on-chain keys (set at block
10028485, IPFS hash QmWFEVTTH3kdFxA8GLUKnCNZe5JwTVy7nJi2HgnzbVBLF4). There is no 2x2
in the lite set, so `plan_transfer` spends one note only.

## Things learned the hard way

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

- `data/` (23 MB Sepolia logs and transact calls; refetch with Etherscan's logs API,
  proxy `0xeCFCf3b4eC647c4Ca6D49108b311b7a7C9543fea` from block 5784866).
- `.test-wallet/`, circuit artifacts, `target/`.

## Open items

- On-chain send (above), then M5 POI.
- Several inputs (2x2 needs production artifacts from IPFS), unshield, relay adapt,
  broadcaster fees.
- Legacy (pre-V2.1) events for mainnet chains, reorg handling, persistent storage.
- UniFFI bindings; device timings on iPhone, Mac and Android.
