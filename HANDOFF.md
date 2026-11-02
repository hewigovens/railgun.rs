# Handoff (2026-11-02)

Read `scope.md` for the plan, `docs/architecture.md` for the design and `README.md` for
commands. This file is what those two
don't say.

## Where it stands

| Milestone | State |
| --- | --- |
| M0 vector harness | done |
| M1 keys, 0zk addresses | done, matches engine vectors |
| M2 notes, EdDSA, Ed25519 blinding, AES | done, byte-equal to the engine |
| M3 Sepolia sync, tree, scan | done, matches the engine on all of Sepolia to block 12031295 |
| M4 prove and submit one transfer | done on Arbitrum; the Anon wallet received it |
| M5 POI | done on Arbitrum for transfers: a Rust proof reached `Valid`, Anon shows the funds spendable |

Tests: `cargo test --workspace` gives 56 passed, 2 ignored (the M3 full-history test
needs Sepolia `data/`, the M4 witness and proof test needs circuit artifacts). Two tests
skip quietly without `.test-wallet/sepolia-test-mnemonic.txt`.

M4 checks that pass, against engine 9.6.0 with randoms pinned:
- circuit inputs, bound params and `transact` calldata identical
- Rust witness (wasmi and wasmtime) equals snarkjs's
- arkworks proof accepted by snarkjs and by the Sepolia contract's 1x2 key
- recipient decrypts the Rust-built note; change comes back to the sender
- `crates/rg-tx/examples/transfer.rs` runs the whole path in Rust

First real transfer: Arbitrum tx
`0xb4988c76c999a60d702bff903a5f9934504eed945eb34a47466c9426f89f7db2`, block 520397232,
1,006,352 gas, 0.00025 WETH to the Anon 0zk with the change back to the sender.

## Mainnet sync and sending

Mainnets have legacy events `rg_sync` does not decode, so `fetch_leaves` seeds the tree
with hashes from Railgun's squid and checks the root against the contract; logs take over
from the block it prints. A wallet's notes must all come after that block, which holds
for the fresh wallets here. Checked: the lite 1x1, 1x2 and 1x3 keys equal Arbitrum's
on-chain keys, and seed plus live logs reproduced `merkleRoot()` exactly (1,946 leaves in
tree 2, a real V2.1 shield included). Shield fee is 0.25%.

Local state, all gitignored:

- `.test-wallet/test-mnemonic.txt` sender wallet, `recipient-mnemonic.txt` second wallet,
  `test-eoa.key` gas account, `addresses.txt` their
  public addresses (sender 0zk, recipient 0zk, EOA)
- `data/arbitrum-leaves.txt`, `data/arbitrum-logs.jsonl`,
  `data/artifacts/{1x1,1x2,1x3,poi-3x3}`

To send again, with `harness` installed (`npm install --ignore-scripts`). The sender holds
0.00025 WETH and the EOA 0.00048 ETH:

```
RPC=https://arb1.arbitrum.io/rpc
WETH=0x82aF49447D8a07e3bd95BD0d56f35241523fBab1
cargo run --release -p rg-sync --features rpc --example fetch_logs -- arbitrum $RPC data/arbitrum-logs.jsonl
cargo run --release -p rg-wallet --example scan_file -- data/arbitrum-logs.jsonl .test-wallet/test-mnemonic.txt 0 data/arbitrum-leaves.txt
cargo run --release -p rg-tx --example transfer -- arbitrum data/arbitrum-leaves.txt data/arbitrum-logs.jsonl \
  .test-wallet/test-mnemonic.txt data/artifacts $RECIPIENT $WETH <value> > .test-wallet/transfer.json
python3 -c "import json;d=json.load(open('.test-wallet/transfer.json'));print(json.dumps({'label':'transact','to':d['to'],'value':'0','data':d['data']}))" > .test-wallet/transfer.jsonl
node harness/send.js send $RPC .test-wallet/test-eoa.key .test-wallet/transfer.jsonl
```

ethers estimates gas before sending, so a transaction the contract would reject fails
without spending anything. Then run `submit_poi` (below) once the squid and the aggregator
have the transaction, or the recipient holds the funds as pending. The `shield` example
also takes a network if a wallet-free shield is wanted.

## M5 state

`crates/rg-poi` and its `submit_poi` example. Arbitrum tx
`0x32383758ec908c66fea5299ef0456d97147117f8f1f507d3783026212adc1cb8` got both outputs to
`Valid` from a Rust proof with `--submit`, within a minute, with Railway closed.

POI artifacts: the engine's lite `poi/` folder and the IPFS root in engine 9.6.0 and wallet
10.9.0 (`QmZrP9zaZw2L...`) are stale, and the live aggregator answers `Invalid proof` to
proofs made with them. Railway's wallet 11.2.0 uses
`QmZ2MyM6TKxffkv6stuo2hFwmUfs3q4xgMYN164Sje8new`, with `circuits/03x03/{vkey.json,zkey.br}`
and `prover/snarkjs/03x03.wasm.br` on `https://ipfs-lb.com/ipfs/`. Decompress into
`data/artifacts/poi-3x3/{circuit.wasm,circuit.zkey}`. Only the 3x3 set is fetched. Their
wasm needs two more runtime imports, now stubbed in both backends. The harness still pins
engine 9.6.0, so it does not match this POI key.

The first transfer's POI was made by Railway, after importing the sender mnemonic.

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

- `data/`: chain data and artifacts, all refetchable with `fetch_leaves`, `fetch_logs` and
  the artifact notes here. The M3 `sepolia-transact-calls.json` comes from Etherscan.
- `.test-wallet/`, circuit artifacts, `target/`.

## Open items

- POI for shields and unshields; 13x13 for larger transactions; polling built into the flow.
- Several inputs (2x2 needs production artifacts from IPFS), unshield, relay adapt,
  broadcaster fees.
- Decoding legacy (pre-V2.1) events, so older wallets can scan; reorg handling, persistent
  storage.
- UniFFI bindings; device timings on iPhone, Mac and Android.
