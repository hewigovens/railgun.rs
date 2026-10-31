# Railgun Rust core: scope

Read 2026-10-31. Goal: a Rust core (UniFFI to iOS/Android, GemWallet style) that replaces the Railgun TS SDK + nodejs-mobile. First milestone: derive keys and 0zk address from a mnemonic, sync the UTXO tree and decrypt your own notes, prove and submit one private transfer against the existing circuits.

## Verdict

Feasible, and smaller than it looks. The protocol surface for "keys + scan + one transfer" is about 3k lines of TS, all MIT licensed, built from standard primitives (Poseidon over BN254, circomlib BabyJubJub EdDSA, Ed25519 ECDH, AES-256-GCM, keccak/ABI). Every primitive has a Rust crate. The engine repo ships unit-test vectors for most of them.

The biggest risk is not the crypto. It is the circuits: `circuits-v2` and `circuits-ppoi` carry "No License is provided for any party under any circumstances", and witness generation has to run either the published `.wasm` (fine at runtime: a hidden WKWebView on iOS, wasmtime on macOS) or something derived from that unlicensed source. Second risk is POI: without it, a transfer you prove and submit is valid on chain but other Railgun wallets will hold the received funds as pending until a POI proof is submitted.

Byte-level, the risky spots are few and concrete (ranked list below): BabyJubJub curve form, Poseidon width up to 16, AES-GCM with a 16-byte IV, the ABI encoding of bound params, and some sloppy-but-frozen hex packing in annotation data and addresses.

## Sources read

Cloned to a scratch dir (not kept), all `--depth 1`:

| Repo | Commit | Version | License |
|---|---|---|---|
| Railgun-Community/engine | 6e2614d (2026-06-18) | 9.6.0 | MIT |
| Railgun-Community/wallet | 5c9d04c (2026-06-19) | 10.9.0 | MIT |
| Railgun-Community/shared-models | b37e643 (2026-05-12) | 8.0.1 | MIT |
| Railgun-Community/poseidon-hash-wasm | 33febd2 (2026-05-12) | Rust, uses codex-storage/rs-poseidon | MIT |
| Railgun-Community/curve25519-scalarmult-wasm | 20aac34 (2023-07-10) | Rust, curve25519-dalek 3 | MIT |
| Railgun-Community/circomlibjs (fork) | 242968f (2024-04-03) | 0.0.8 | GPL-3.0 |
| Railgun-Privacy/circuits-v2 | 0aa2d13 (2025-08-22) | joinsplit circuits | "No License is provided" |
| Railgun-Privacy/circuits-ppoi | 18530c6 (2026-08-14) | POI circuits | "No License is provided" |
| Railgun-Privacy/contract | 36bcf5e (2026-08-15) | Solidity | UNLICENSED |
| codex-storage/rs-poseidon | HEAD | Poseidon BN254, ark-ff 0.3 | MIT or Apache-2.0 |

Not found publicly: the native prover (`@railgun-privacy/native-prover`, IPFS tarball only) and any `poseidon-hash-rs` repo. IPFS artifact gateways were unreachable from the sandbox, so circuit sizes and proving times below are unmeasured.

Paths below are relative to `engine/src` unless noted.

## Licensing

- Engine, wallet SDK, shared-models, Railgun's two Rust wasm crates: MIT. You can port line by line with the MIT notice. This is the main win over forking Railway (AGPL).
- circomlibjs fork: GPL-3.0. Don't port its code. Implement BabyJubJub EdDSA from the circomlib spec or use a permissive crate (babyjubjub-rs is Apache-2.0 on crates.io at 0.0.11).
- circuits-v2 / circuits-ppoi: no license granted. Reading them to understand the witness layout is fine; compiling or redistributing them, or code generated from them, is the open question. Every Railgun wallet downloads the trusted-setup artifacts (`zkey`, `wasm`, `dat`) from IPFS at first run and checks sha256 hashes from `wallet/src/services/artifacts/json/artifact-v2-hashes.json`. Doing the same keeps you in the same position as other wallets. Bundling artifacts into the app binary, or transpiling the `.wasm` to native code (rust-witness), is a distribution of something derived from them; get a view on that before choosing it. This is not legal advice.
- contract: UNLICENSED. Use only the ABI (interface facts); engine already ships typechain ABIs under MIT in `abi/`.
- Crates proposed below are MIT/Apache/BSD; UniFFI is MPL-2.0 (file-level copyleft, normal for apps).

## Proposed crate layout

```
railgun-core/
  rg-primitives   poseidon, babyjubjub eddsa, ed25519 ecdh/blinding, aes/chacha wrappers, field utils
  rg-keys         mnemonic -> spending/viewing/nullifying keys, MPK, 0zk address codec
  rg-notes        note model, token hash, commitment, nullifier, V2 encrypt/decrypt, shield ciphertext, memo/annotation
  rg-tree         Poseidon Merkle tree (depth 16, multi-tree), proofs, storage trait
  rg-sync         event fetch (RPC getLogs + optional squid GraphQL), event decoding, root validation
  rg-wallet       scan/trial-decrypt, TXO store, balances, spent tracking
  rg-tx           UTXO selection, transaction request, bound params hash, signature, railgun txid
  rg-prover       artifact download/cache/verify, circom-wasm witness runner, Groth16 (arkworks; rapidsnark optional)
  rg-poi          txid tree, blinded commitments, POI proof inputs, aggregator client   (milestone 5)
  rg-ffi          UniFFI surface for Swift/Kotlin
```

Use one arkworks version (0.5 line) across everything; rs-poseidon pins ark-ff 0.3, so either port its constants onto ark-bn254 0.5 (small job, constants are a JSON file) or keep the U256 boundary and accept two ark versions in the tree.

## Module by module

### 1. Key derivation and addresses

What: mnemonic to spending key (BabyJubJub), viewing key (Ed25519), nullifying key, master public key, `0zk` address.

Exact format (`key-derivation/wallet-node.ts`, `bip32.ts`, `bip39.ts`, `bech32.ts`, `utils/keys-utils.ts`, `chain/chain.ts`):
- Seed: standard BIP39 `mnemonicToSeed(mnemonic, password)`.
- Master node: `I = HMAC-SHA512(key = utf8("babyjubjub seed"), data = seed)`; chainKey = I[0..32], chainCode = I[32..64]. Same algorithm as SLIP-0010 with a different seed string.
- Child (hardened only): `I = HMAC-SHA512(chainCode, 0x00 || chainKey || be32(index + 0x80000000))`. No non-hardened path exists.
- Paths: spending `m/44'/1984'/0'/0'/{i}'`, viewing `m/420'/1984'/0'/0'/{i}'`.
- Spending pubkey: circomlib `eddsa.prv2pub(chainKey)` = `Base8 * (prune(blake512(prv)[0..32]) >> 3)` where blake512 is the original BLAKE (not BLAKE2) and prune clears low 3 bits, clears bit 255, sets bit 254.
- Viewing pubkey: Ed25519 public key of the 32-byte viewing chainKey (noble ed25519 v1, standard RFC 8032).
- Nullifying key: `poseidon([bigint(viewingPrivateKey)])` (input reduced mod p).
- MPK: `poseidon([Ax, Ay, nullifyingKey])`.
- Address: bech32m, HRP `0zk`, limit 127 chars, payload 73 bytes = `0x01 || mpk(32 BE) || networkID(8) || viewingPub(32)`. networkID = `chainType(1) || chainId(7 BE)`, or `ffffffffffffffff` for all chains, then XORed with `utf8("railgun")` (7 bytes) via buffer-xor 2.0.2, which XORs to the longer length, so byte 8 passes through unchanged.

Rust: `bip39`, `hmac` + `sha2`, `blake-hash` (Blake512), BabyJubJub (see 2), `ed25519-dalek` or `curve25519-dalek` for the viewing pubkey, `bech32` (rust-bitcoin, needs custom length limit 127 since BIP173's 90 is too short), rs-poseidon.

Compat risk: low once the curve form (below) and the XOR quirk are right. Engine tests have direct vectors: `key-derivation/__tests__/key-derivation.test.ts` (abandon...about, private keys, pubkeys, nullifying keys), `bip32-babyjubjub.test.ts`, `bech32-encode.test.ts`.

### 2. Poseidon and BabyJubJub EdDSA

Poseidon (`utils/poseidon.ts`): circomlib Poseidon over BN254 Fr. Engine uses Railgun's own Rust wasm (`poseidon-hash-wasm`, which is codex-storage `rs-poseidon`) and falls back to circomlibjs; inputs are reduced mod p first. Widths needed: 1, 2, 3, 5 (blinded commitments, eddsa hm), 13 (railgun txid), and `2 + nIn + nOut` up to 16 for the transaction signature message. light-poseidon tops out at 12 inputs, so it does not fit. Use rs-poseidon (supports 1..16, MIT/Apache, the exact implementation Railgun ships) or poseidon-rs.

EdDSA (`utils/keys-utils.ts` signEDDSA, circomlibjs `src/eddsa.js` signPoseidon): `h1 = blake512(prv)`, `s = prune(h1[0..32])` LE, `A = Base8 * (s >> 3)`, `r = blake512(h1[32..64] || le32(msg)) mod subOrder`, `R8 = Base8 * r`, `hm = poseidon([R8x, R8y, Ax, Ay, msg])`, `S = r + hm * s mod subOrder`. Signed message in `wallet/railgun-wallet.ts`: `poseidon([merkleRoot, boundParamsHash, ...nullifiers, ...commitmentsOut])`.

Rust: babyjubjub-rs (Apache-2.0, circomlib compatible, but old `ff_ce` deps) or write it on arkworks. If you use `ark-ed-on-bn254`, note it uses the isomorphic `a = 1, d = 168696/168700` form (checked in 0.5.0 source), while circomlib uses `a = 168700, d = 168696`. Coordinates differ, so define your own `TECurveConfig` with circomlib's a, d and Base8, or convert at the boundary. TaceoLabs also publishes a babyjubjub EdDSA crate (MIT/Apache) worth checking against circomlib vectors.

Compat risk: high until tested (curve form, Blake-512 vs BLAKE2, LE vs BE, `s` vs `s >> 3`), trivial after. Signature equality is deterministic, so diff byte for byte against circomlibjs.

### 3. Viewing-key ECDH and note blinding

`utils/keys-utils.ts`, `utils/scalar-multiply.ts`:
- Shared key: `scalar = (clamp(sha512(viewPriv)[0..32]) as LE int) mod l` (if 0 use l); `point = scalar * decompress(blindedPubB)` on Edwards25519; key = `sha256(compress(point))`. This is Ed25519 point math, not X25519.
- Blinding: `finalRandom = be32(int(noteRandom 16B) XOR int(senderRandom 15B))`, `blindingScalar = int(sha512(finalRandom)) mod l`; blinded sender/receiver viewing keys = each viewing pubkey times blindingScalar. Unblind multiplies by the inverse mod l.
- Receiver decrypts with `ECDH(ownViewPriv, blindedSenderViewingKey)`; sender re-derives with `ECDH(ownViewPriv, blindedReceiverViewingKey)`.

Rust: `curve25519-dalek` (Railgun's own wasm uses dalek 3 with `Scalar::from_bytes_mod_order` on the reversed BE bytes; copy that).

Compat risk: medium. Vectors: `utils/__tests__/keys-utils.test.ts`, `scalar-multiply.test.ts`. Legacy (pre-Mar-2023) notes use `utils/keys-utils-legacy.ts`; skip until someone needs old history.

### 4. Note format and encryption

All live networks have `supportsV3: false` in shared-models, so V2 is the only ciphertext format that matters now. V3 (XChaCha20-Poly1305) can wait.

Transact note V2 (`note/transact-note.ts` encryptV2/decrypt, `utils/encryption/aes.ts`, `transaction/transaction.ts`):
- AES-256-GCM, key = shared key, IV = 16 random bytes (not the usual 12; Node derives J0 via GHASH), 16-byte tag. Plaintext blocks: `encodedMPK(32)`, `tokenHash(32)`, `random(16) || value(16 BE)`, then UTF-8 memo text. One GCM stream over all blocks.
- encodedMPK = receiverMPK XOR senderMPK when the sender is visible (senderRandom = 15 zero bytes), else receiverMPK.
- On chain: `ciphertext: bytes32[4] = [iv||tag, c0, c1, c2]`, memo bytes = ciphertext of the memo block, `blindedSenderViewingKey`, `blindedReceiverViewingKey`, `annotationData`.
- annotationData (`note/memo.ts`): AES-256-CTR keyed with the sender's viewing private key, 16-byte IV, blocks `outputType(1)||senderRandom(15)`, 15 zero bytes, walletSource base-37 left-padded to 15 bytes. The decoder slices 16/16/16 bytes, which only works because CTR is a stream and the wallet-source field is left padded. Replicate exactly. Wallet source encoding is in `wallet/wallet-info.ts` (base 37 over `' 0123456789abcdefghijklmnopqrstuvwxyz'`, max 16 chars; its even-length padding branch is inverted, also frozen behaviour).
- After decrypt, the engine recomputes the note hash and drops the note if it doesn't equal the on-chain commitment (`wallet/abstract-wallet.ts` createScannedDBCommitments). Keep that check.

Shield ciphertext (`note/shield-note.ts`): sharedKey = ECDH(shieldPrivateKey, receiverViewingPub). `encryptedBundle[0] = iv||tag` (GCM of random), `[1] = encRandom(16) || ctrIV(16)`, `[2]` = CTR-encrypted receiver viewing pubkey keyed with shieldPrivateKey; `shieldKey` = Ed25519 pubkey of shieldPrivateKey. Receiver tries GCM-decrypting the random with ECDH(viewPriv, shieldKey). shieldPrivateKey is caller-supplied 32 bytes; the SDK exposes the message constant `RAILGUN_SHIELD` for deriving it from an EOA signature.

Rust: `aes-gcm` with `AesGcm<Aes256, U16>` nonce size, `aes` + `ctr`, `chacha20poly1305` (XChaCha, later; V3 derives the 24-byte nonce as `sha256(utf8(hexNonceString))[0..24]`, another frozen quirk).

Compat risk: high for the 16-byte IV and annotation layout, medium elsewhere. Vectors: `note/__tests__/transact-note.test.ts`, `shield-note.test.ts`, `memo.test.ts`, `utils/__tests__/ecies.test.ts`. Best test: TS encrypts, Rust decrypts, and the reverse.

### 5. Commitments, token hash, nullifiers

`note/note-util.ts`, `note/transact-note.ts`, `transaction/transaction.ts`:
- npk = `poseidon([MPK, random])`; commitment = `poseidon([npk, tokenHash, value])`.
- tokenHash: ERC20 = address left-padded to 32 bytes; ERC721/1155 = `keccak256(be32(type) || pad32(address) || be32(subID)) mod p`.
- Nullifier = `poseidon([nullifyingKey, leafIndex])` (index within its tree).
- Values are 120-bit in the circuit (Num2Bits(120)), stored as 16 bytes.
- Unshield note: npk = recipient EOA address as a field element, same commitment formula, last output of the transaction.

Rust: rs-poseidon, `alloy-primitives`/`tiny-keccak`. Compat risk: low.

### 6. Event sync and UTXO Merkle tree

`merkletree/merkletree.ts`, `merkletree/utxo-merkletree.ts`, `models/merkletree-types.ts`, `contracts/railgun-smart-wallet/V2/*`:
- Binary Poseidon(2) tree, depth 16 (65,536 leaves per tree, then a new tree number). Zero leaf = `keccak256(utf8("Railgun")) mod p`, zeros[i] = H(zeros[i-1], zeros[i-1]).
- Events from RailgunSmartWallet proxy: `Shield`, `Transact` (treeNumber, startPosition, hashes, ciphertexts), `Unshield`, `Nullified`; plus legacy pre-Mar-2023 `GeneratedCommitmentBatch`, `CommitmentBatch`, `Nullifiers` and a legacy Shield ABI. Ethereum, BSC, Polygon and Arbitrum all have legacy history; Sepolia (proxy 0xeCFCf3b4eC647c4Ca6D49108b311b7a7C9543fea, deployment block 5784866) is a clean V2 test target.
- Roots are validated against `rootHistory(tree, root)` on the contract before trusting the tree.
- The SDK's quick sync pulls events from Subsquid GraphQL (`rail-squid.squids.live/squid-railgun-{chain}-v2/graphql`, `wallet/src/services/railgun/quick-sync/V2`) and falls back to RPC getLogs. A Rust core can do RPC only at first and add GraphQL for speed.

Rust: `alloy` (provider, `sol!` event decoding with the engine's ABI JSON), storage behind a trait (SQLite/rusqlite or redb). Compat risk: low for hashing; the real work is event edge cases (legacy formats, reorgs, batch boundaries crossing trees). Vector: compute root at block N and compare with `rootHistory` and with the TS engine.

### 7. Scanning your own notes

`wallet/abstract-wallet.ts` (scanLeaves, createScannedDBCommitments, ~3.3k lines, most of it bookkeeping):
- Every transact commitment costs two ECDH + up to two GCM attempts (receive and sent-by-me); every shield costs one. No view tags, so trial decryption over all leaves since wallet creation block.
- Spent detection: compare stored TXO nullifiers against `Nullified` events.
- Balances are bucketed by POI status (Spendable, ShieldPending, MissingInternalPOI, etc., `poi/poi.ts` getBalanceBucket).

Rust: `rayon` for parallel trial decryption; dalek scalar mults are tens of microseconds, so scanning is CPU-cheap compared with the TS path. Compat risk: low, given 3 and 4.

### 8. Transaction building

`transaction/transaction.ts`, `transaction/transaction-batch.ts`, `transaction/bound-params.ts`, `transaction/railgun-txid.ts`, `solutions/*`:
- One `Transaction` per token and spending tree, up to 5 outputs including the unshield note. Published artifacts cover every `nIn + nOut <= 14` (01x01 through 13x01, 93 variants plus POI_3x3 and POI_13x13), but the wallet SDK refuses native artifacts beyond 3 outputs ("native-prover-small"), so plan around 1..10 inputs and 1..3 outputs on mobile.
- boundParams V2: `(uint16 treeNumber, uint48 minGasPrice, uint8 unshield, uint64 chainID, address adaptContract, bytes32 adaptParams, (bytes32[4] ciphertext, bytes32 blindedSenderViewingKey, bytes32 blindedReceiverViewingKey, bytes annotationData, bytes memo)[] commitmentCiphertext)`; hash = `keccak256(abi.encode(tuple)) mod p`, encoded the way ethers `AbiCoder.encode(['tuple(...)'], [x])` does (a one-element parameter list holding a dynamic tuple, so the head carries an offset). The contract declares minGasPrice as uint72; both widths pad to one 32-byte word, so the hash is the same for any value under 2^48 (checked in M4).
- railgunTxid = `poseidon([poseidon(nullifiers padded to 13 with MERKLE_ZERO), poseidon(commitments padded to 13), boundParamsHash])`.
- Circuit inputs (`prover/prover.ts` formatRailgunInputs): merkleRoot, boundParamsHash, nullifiers, commitmentsOut, token, publicKey[2], signature[3] (R8x, R8y, S), randomIn, valueIn, pathElements (flattened), leavesIndices, nullifyingKey, npkOut, valueOut.
- Submit: `transact(Transaction[])` on the proxy with `{proof, merkleRoot, nullifiers, commitments, boundParams, unshieldPreimage}`; proof formatted with pi_b coordinates swapped (`Prover.formatProof`).

Rust: `alloy-sol-types` for encoding and calls. Compat risk: high on the ABI encoding (`abi_encode` vs `abi_encode_params` vs `abi_encode_sequence` give different bytes for a dynamic tuple), low elsewhere. Vectors: `transaction/__tests__/railgun-txid.test.ts`, `transaction-erc20.test.ts`; dump `boundParamsHash` from TS for a fixed request.

### 9. Witness and proof

What exists: per-circuit `zkey` (snarkjs format), `vkey.json`, snarkjs `.wasm` witness calculator, and circom C++ `.dat` (needs the matching generated C++, which is not public), brotli-compressed on IPFS (`wallet/src/services/artifacts/artifact-util.ts`, root `QmUsmnK4PFc7zDp2cmC4wBZxYLjNyRgWfs5GNcJJ2uLcpU`, POI root `QmZrP9zaZw2LwErT2yA6VpMWm65UdToQiKj4DtStVsUJHr`), with sha256 hashes in the SDK.

Witness generation, decided per platform (Tao, 2026-10-31). All paths run the downloaded snarkjs `.wasm`; proving stays in Rust everywhere.
- iOS: hidden WKWebView runs the witness wasm. WebKit's WebContent process holds the JIT entitlement, so wasm is JIT-compiled there (an in-process JSContext or a Rust interpreter is not). Swift passes the input JSON in, gets witness bytes back, hands them to the Rust prover.
- macOS: native, no WebView. `wasmtime` with JIT inside the Rust core (hardened runtime needs the `com.apple.security.cs.allow-jit` entitlement).
- Android: native `wasmtime` as well (JIT allowed), unless benchmarks say otherwise.
- `wasmi` runner (pure Rust interpreter, circom wasm ABI: init, getFieldNumLen32, setInputSignal, getWitnessSize, getWitness, shared RW memory, four runtime imports) for CI tests and as a fallback.
- Not planned: rust-witness or circom-witnesscalc (bake circuit-derived code into the binary; see Licensing).

Proving: `ark-circom` (zkey reader, `CircomReduction`) + `ark-groth16` 0.5/0.6, or mopro's `circom-prover` crate which wraps arkworks and rapidsnark backends with witness adapters. Convert the zkey once to arkworks' own serialization and cache it, because parsing snarkjs zkeys on mobile is slow. Verify locally against vkey before submitting, as the engine does.

Compat risk: medium. Input JSON must match circom signal names and ordering exactly; witness bytes can be diffed against snarkjs `wtns`. Proofs aren't deterministic, so the test is "verifies with vkey and is accepted by the contract".

### 10. POI (Private Proof of Innocence)

`poi/*`, `merkletree/txid-merkletree.ts`, `validation/*`, `prover/prover.ts` provePOI, circuits-ppoi `src/library/poi-transaction.circom`:
- POI is live on Ethereum, BSC, Polygon, Arbitrum and Sepolia (launch blocks in shared-models). Contracts don't enforce it; wallets and broadcasters do. A received note is "spendable" only when every required list reports Valid for its blinded commitment `poseidon([commitmentHash, npk, tree * 65536 + index])`.
- After a self-signed transfer the sender must sync the railgun txid tree (also depth 16, synced from the squid GraphQL), build a POI proof (POI_3x3 or POI_13x13 artifacts) proving each input's blinded commitment sits in each list's POI tree, and submit it to the aggregator (`ppoi.fdi.network` per Railway's config). Broadcaster transactions use a pre-transaction POI variant with hardcoded position 199999.
- Node API surface: `getPOIsPerList`, `getPOIMerkleProofs`, `validatePOIMerkleroots`, `submitPOI`, `submitLegacyTransactProofs` (`poi/poi-node-interface.ts`).

Rust: same prover stack, `reqwest` JSON-RPC client. Compat risk: medium, mostly protocol plumbing.

### 11. Relaying

Out of the first milestones. Self-signing from an EOA works today but links the EOA paying gas to the transaction. Broadcasters talk over Waku (`waku-broadcaster-client`); Rust options are FFI bindings to nwaku/go-waku or Waku's REST API through a node you trust (Railway's Android build already uses "RPC Waku"). Unshield-to-native and DeFi go through RelayAdapt (`contracts/relay-adapt/*`), also later.

## Byte-compat risks, ranked

1. BabyJubJub curve form and EdDSA details (circomlib a/d vs arkworks a=1; Blake-512; `s >> 3` for A but `s` in S; LE scalars).
2. Poseidon arity up to 16 (light-poseidon can't; rs-poseidon can).
3. ABI encoding of boundParams for the hash (must match ethers' single dynamic tuple param).
4. AES-256-GCM with a 16-byte IV and one stream across chunked blocks, memo as the fourth block.
5. annotationData CTR layout (16/15/15 written, 16/16/16 read) and inverted wallet-source padding.
6. Ed25519 ECDH: scalar from clamped sha512 reduced mod l, sha256 of the compressed point; blinding scalar from BE XOR of randoms.
7. Address networkID XOR with the 7-byte "railgun" over 8 bytes.
8. Circuit input JSON naming/ordering and proof point ordering (pi_b swap).
9. V3 XChaCha nonce from sha256 of a hex string (deferred, V3 not live).

## Milestones

Harness first (M0): a small Node script pinned to `@railgun-community/engine` 9.6.0 that emits golden JSON for fixed inputs (keys, addresses, poseidon at every width 1..16, signatures, shared keys, blinded keys, ciphertexts with fixed IVs, token hashes, bound params hashes, txids, formatted circuit inputs). Rust tests load the JSON. Add a differential fuzz mode that feeds random inputs to both. Port the engine's own `__tests__` vectors (MIT) as Rust unit tests.

M1, keys and addresses. Mnemonic to spending/viewing/nullifying keys, MPK, 0zk address for any chain and all-chains. Pass: engine `key-derivation.test.ts`, `bip32-babyjubjub.test.ts`, `bech32-encode.test.ts`, `bip39.test.ts`; plus your own test mnemonic matching the address Railway shows.

M2, primitives and notes. Poseidon 1..16, EdDSA sign/verify, ECDH, blinding/unblinding, V2 note encrypt/decrypt including memo and annotationData, shield ciphertext decrypt, token hash, commitment, nullifier. Pass: golden JSON byte equality; TS-encrypt/Rust-decrypt and Rust-encrypt/TS-decrypt round trips; engine `keys-utils`, `transact-note`, `shield-note`, `memo`, `poseidon` tests.

M3, sync and scan on Sepolia. RPC getLogs from block 5784866, build trees, validate roots via `rootHistory`, scan a test wallet funded with shields and transfers made from Railway desktop. Pass: Merkle root equals the TS engine's at the same block; TXO set, balances and spent status equal the TS SDK's for the same mnemonic.

M4, prove and submit one private transfer. Select UTXOs (1x2 or 2x2: recipient + change), build bound params, sign, generate witness from the downloaded `.wasm` (hidden WKWebView on iOS, wasmtime on macOS and Android), prove with arkworks, verify with vkey, submit self-signed on Sepolia. Pass: formatted inputs JSON identical to TS for the same UTXOs with randoms pinned; witness equals snarkjs `wtns`; contract accepts; a Railway wallet for the recipient decrypts the note. Measure witness and proof time on a real iPhone, Mac and Android device here; proof time decides arkworks or rapidsnark.

M5, POI so the transfer is usable. Txid tree sync, POI_3x3 proof, submit to the aggregator, poll list status. Pass: recipient's Railway shows the funds as spendable rather than pending.

Later: unshield (and to native via RelayAdapt), multi-token batches and note selection parity, broadcasters over Waku, legacy pre-2023 notes for older wallets, V3 if it ships, UniFFI surface and GemWallet integration.

## Open questions

- Legal read on circuit artifacts: runtime download only, or is bundling / transpiling acceptable?
- Mobile proving time with arkworks for 1x2/2x2 and POI_3x3, and witness time in WKWebView (iOS) and wasmtime (macOS, Android). Not measured (IPFS unreachable from here).
- Which POI lists are required per chain at the time you test (the SDK reads them from the aggregator).
- Where the native prover source lives, if anywhere; not needed if arkworks is fast enough.
- RPC privacy: getLogs and balance calls from a mobile client leak interest to the RPC provider; plan your own endpoint or the squid GraphQL.
