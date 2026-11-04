# Protocol notes

The byte formats this core reproduces, written down while reading the TS sources. Paths
are relative to the engine's `src/` unless noted. Sources read:

| Repository | Version | License |
| --- | --- | --- |
| Railgun-Community/engine | 9.6.0 | MIT |
| Railgun-Community/wallet | 10.9.0 | MIT |
| Railgun-Community/shared-models | 8.0.1 | MIT |
| Railgun-Community/poseidon-hash-wasm | uses codex-storage/rs-poseidon | MIT |
| Railgun-Community/curve25519-scalarmult-wasm | curve25519-dalek 3 | MIT |
| Railgun-Community/circomlibjs (fork) | 0.0.8 | GPL-3.0, read only, not ported |
| Railgun-Privacy/circuits-v2, circuits-ppoi | | no license granted |
| Railgun-Privacy/contract | | UNLICENSED; only the ABI is used |

## Keys and addresses

`key-derivation/wallet-node.ts`, `bip32.ts`, `bip39.ts`, `bech32.ts`, `utils/keys-utils.ts`, `chain/chain.ts`:

- Seed: standard BIP39 `mnemonicToSeed(mnemonic, password)`.
- Master node: `I = HMAC-SHA512(key = utf8("babyjubjub seed"), data = seed)`; chainKey = `I[0..32]`, chainCode = `I[32..64]`. This is SLIP-0010 with a different seed string.
- Child (hardened only): `I = HMAC-SHA512(chainCode, 0x00 || chainKey || be32(index + 0x80000000))`. There is no non-hardened path.
- Paths: spending `m/44'/1984'/0'/0'/{i}'`, viewing `m/420'/1984'/0'/0'/{i}'`.
- Spending public key: circomlib `eddsa.prv2pub(chainKey)` = `Base8 * (prune(blake512(prv)[0..32]) >> 3)`. blake512 is the original BLAKE, not BLAKE2; prune clears the low 3 bits and bit 255, and sets bit 254.
- Viewing public key: the RFC 8032 Ed25519 public key of the 32-byte viewing chainKey.
- Nullifying key: `poseidon([bigint(viewingPrivateKey)])`, input reduced mod p.
- Master public key (MPK): `poseidon([Ax, Ay, nullifyingKey])`.
- Address: bech32m, HRP `0zk`, length limit 127, payload 73 bytes = `0x01 || mpk(32 BE) || networkID(8) || viewingPub(32)`. networkID is `chainType(1) || chainId(7 BE)`, or `ffffffffffffffff` for all chains, XORed with `utf8("railgun")` (7 bytes) by buffer-xor 2.0.2, which XORs to the longer length, so byte 8 passes through unchanged.

Engine vectors: `key-derivation/__tests__/key-derivation.test.ts`, `bip32-babyjubjub.test.ts`, `bech32-encode.test.ts`.

## Poseidon and BabyJubJub EdDSA

Poseidon (`utils/poseidon.ts`) is circomlib's over BN254 Fr, with inputs reduced mod p. Widths in use: 1, 2, 3, 5, 13 (Railgun txid), and `2 + nIn + nOut` up to 16 for the transaction signature message.

EdDSA (`utils/keys-utils.ts` signEDDSA, circomlibjs `src/eddsa.js` signPoseidon):

- `h1 = blake512(prv)`, `s = prune(h1[0..32])` little-endian, `A = Base8 * (s >> 3)`.
- `r = blake512(h1[32..64] || le32(msg)) mod subOrder`, `R8 = Base8 * r`.
- `hm = poseidon([R8x, R8y, Ax, Ay, msg])`, `S = r + hm * s mod subOrder`.
- The signed message (`wallet/railgun-wallet.ts`) is `poseidon([merkleRoot, boundParamsHash, ...nullifiers, ...commitmentsOut])`.

circomlib's curve is `a = 168700, d = 168696`. `ark-ed-on-bn254` uses the isomorphic `a = 1` form, so its coordinates differ; `rg_primitives::babyjubjub` uses circomlib's form.

## Viewing-key ECDH and note blinding

`utils/keys-utils.ts`, `utils/scalar-multiply.ts`:

- Shared key: `scalar = (clamp(sha512(viewPriv)[0..32]) as LE int) mod l`, or l if that is 0; `point = scalar * decompress(blindedPubB)` on Edwards25519; key = `sha256(compress(point))`. This is Ed25519 point math, not X25519.
- Blinding: `finalRandom = be32(int(noteRandom 16B) XOR int(senderRandom 15B))`, `blindingScalar = int(sha512(finalRandom)) mod l`; the blinded sender and receiver viewing keys are each viewing public key times blindingScalar. Unblinding multiplies by the inverse mod l.
- The receiver decrypts with `ECDH(ownViewPriv, blindedSenderViewingKey)`, and the sender re-derives with `ECDH(ownViewPriv, blindedReceiverViewingKey)`.

Railgun's wasm reduces with curve25519-dalek's `Scalar::from_bytes_mod_order` on the reversed big-endian bytes. Notes from before March 2023 use `utils/keys-utils-legacy.ts`, which this core does not implement.

## Note format and encryption

Every live network has `supportsV3: false` in shared-models, so V2 is the only ciphertext format in use.

Transact note V2 (`note/transact-note.ts`, `utils/encryption/aes.ts`, `transaction/transaction.ts`):

- AES-256-GCM, key = shared key, a 16-byte IV (not the usual 12; GCM derives J0 by GHASH), 16-byte tag. Plaintext blocks: `encodedMPK(32)`, `tokenHash(32)`, `random(16) || value(16 BE)`, then the UTF-8 memo. One GCM stream covers all blocks.
- encodedMPK = receiverMPK XOR senderMPK when the sender is visible (senderRandom is 15 zero bytes), and receiverMPK otherwise.
- On chain: `ciphertext: bytes32[4] = [iv||tag, c0, c1, c2]`, memo bytes = the ciphertext of the memo block, `blindedSenderViewingKey`, `blindedReceiverViewingKey`, `annotationData`.
- annotationData (`note/memo.ts`): AES-256-CTR keyed with the sender's viewing private key, 16-byte IV, blocks `outputType(1) || senderRandom(15)`, 15 zero bytes, and the wallet source in base 37, left-padded to 15 bytes. The decoder slices 16/16/16 bytes, which works only because CTR is a stream and the wallet source is left-padded. Wallet source encoding (`wallet/wallet-info.ts`) is base 37 over `' 0123456789abcdefghijklmnopqrstuvwxyz'`, at most 16 characters, and its even-length padding branch is inverted.
- After decrypting, the engine recomputes the note hash and drops the note unless it equals the on-chain commitment (`wallet/abstract-wallet.ts` createScannedDBCommitments).

Shield ciphertext (`note/shield-note.ts`): sharedKey = `ECDH(shieldPrivateKey, receiverViewingPub)`. `encryptedBundle[0] = iv||tag` (GCM of the random), `[1] = encRandom(16) || ctrIV(16)`, `[2]` = the receiver viewing public key, CTR-encrypted with shieldPrivateKey. `shieldKey` is the Ed25519 public key of shieldPrivateKey. The receiver GCM-decrypts the random with `ECDH(viewPriv, shieldKey)`. The SDK derives shieldPrivateKey from an EOA signature of the message `RAILGUN_SHIELD`.

Engine vectors: `note/__tests__/transact-note.test.ts`, `shield-note.test.ts`, `memo.test.ts`, `utils/__tests__/ecies.test.ts`.

## Commitments, token hashes and nullifiers

`note/note-util.ts`, `note/transact-note.ts`, `transaction/transaction.ts`:

- npk = `poseidon([MPK, random])`; commitment = `poseidon([npk, tokenHash, value])`.
- tokenHash: for an ERC-20, the address left-padded to 32 bytes; for ERC-721 and ERC-1155, `keccak256(be32(type) || pad32(address) || be32(subID)) mod p`.
- Nullifier = `poseidon([nullifyingKey, leafIndex])`, with the index inside its tree.
- Values are 120 bits in the circuit (Num2Bits(120)) and 16 bytes on the wire.
- Unshield note: npk = the recipient address as a field element, the same commitment formula, and the last output of the transaction.

## Event sync and the UTXO tree

`merkletree/merkletree.ts`, `merkletree/utxo-merkletree.ts`, `models/merkletree-types.ts`, `contracts/railgun-smart-wallet/V2/*`:

- A binary Poseidon(2) tree of depth 16: 65,536 leaves per tree, then the next tree number. The zero leaf is `keccak256(utf8("Railgun")) mod p`, and `zeros[i] = H(zeros[i-1], zeros[i-1])`.
- Events from the RailgunSmartWallet proxy: `Shield`, `Transact` (treeNumber, startPosition, hashes, ciphertexts), `Unshield` and `Nullified`. Before March 2023 there were also `GeneratedCommitmentBatch`, `CommitmentBatch`, `Nullifiers` and an older Shield ABI. Ethereum, BSC, Polygon and Arbitrum have that legacy history; Sepolia (proxy `0xeCFCf3b4eC647c4Ca6D49108b311b7a7C9543fea`, deployed at block 5784866) does not.
- Roots are checked against the contract's `rootHistory(tree, root)` before the tree is trusted.
- The SDK's quick sync reads events from the Subsquid GraphQL API (`rail-squid.squids.live/squid-railgun-{chain}-v2/graphql`) and falls back to `eth_getLogs`.

## Scanning

`wallet/abstract-wallet.ts`. There are no view tags, so every transact commitment since the wallet's creation costs two ECDH and up to two GCM attempts (as receiver and as sender), and every shield costs one. A note is spent when its nullifier appears in a `Nullified` event. Balances are bucketed by POI status (`poi/poi.ts` getBalanceBucket).

## Transactions

`transaction/transaction.ts`, `transaction-batch.ts`, `bound-params.ts`, `railgun-txid.ts`:

- One transaction per token and spending tree, with up to 5 outputs including the unshield. Published artifacts cover every `nIn + nOut <= 14` (93 variants), plus POI 3x3 and 13x13.
- boundParams V2: `(uint16 treeNumber, uint48 minGasPrice, uint8 unshield, uint64 chainID, address adaptContract, bytes32 adaptParams, (bytes32[4] ciphertext, bytes32 blindedSenderViewingKey, bytes32 blindedReceiverViewingKey, bytes annotationData, bytes memo)[] commitmentCiphertext)`. The hash is `keccak256(abi.encode(tuple)) mod p`, encoded as ethers `AbiCoder.encode(['tuple(...)'], [x])` does: a one-element parameter list holding a dynamic tuple, so the head carries an offset.
- railgunTxid = `poseidon([poseidon(nullifiers padded to 13 with MERKLE_ZERO), poseidon(commitments padded to 13), boundParamsHash])`.
- Circuit inputs (`prover/prover.ts` formatRailgunInputs): merkleRoot, boundParamsHash, nullifiers, commitmentsOut, token, publicKey[2], signature[3] (R8x, R8y, S), randomIn, valueIn, pathElements (flattened), leavesIndices, nullifyingKey, npkOut, valueOut.
- Submission: `transact(Transaction[])` on the proxy with `{proof, merkleRoot, nullifiers, commitments, boundParams, unshieldPreimage}`, and the proof's pi_b coordinates swapped (`Prover.formatProof`).

## Witness and proof

Each circuit has a snarkjs `zkey`, a `vkey.json` and a snarkjs `.wasm` witness calculator, brotli-compressed on IPFS with sha256 hashes in the wallet SDK (`wallet/src/services/artifacts/`). `rg-prover` runs that wasm on wasmi or wasmtime through the circom runtime ABI (init, getFieldNumLen32, setInputSignal, getWitnessSize, getWitness, shared memory, and runtime imports), then proves with arkworks. The circuits carry no license, so nothing derived from them, such as a witness generator compiled to native code, is built here.

Proofs are not deterministic, so the test is that the verifying key and the contract accept them. Witness bytes compare against snarkjs's `wtns`.

## POI

`poi/*`, `merkletree/txid-merkletree.ts`, `prover/prover.ts` provePOI, circuits-ppoi `src/library/poi-transaction.circom`:

- POI is live on Ethereum, BSC, Polygon, Arbitrum and Sepolia. Contracts do not enforce it; wallets and broadcasters do. A received note is spendable once every required list reports `Valid` for its blinded commitment `poseidon([commitmentHash, npk, tree * 65536 + index])`.
- After a self-signed transaction the sender syncs the Railgun txid tree (also depth 16, from the squid), proves with the POI 3x3 or 13x13 circuit that each input's blinded commitment is in each list's POI tree, and submits to the aggregator (`ppoi.fdi.network`). Broadcaster transactions use a pre-transaction variant with the fixed position 199999.
- Aggregator calls (`poi/poi-node-interface.ts`): `getPOIsPerList`, `getPOIMerkleProofs`, `validatePOIMerkleroots`, `submitPOI`, `submitLegacyTransactProofs`.

## Relaying

A self-signed transaction links the account paying gas to it. Native ETH and DeFi calls go through RelayAdapt (`contracts/relay-adapt/*`). A relay's action is `{random, requireSuccess, minGasLimit, calls}`; for cross-contract calls the calls are the caller's, then `shield` of each token with value 0, which shields RelayAdapt's whole balance, and `minGasLimit` is the requested gas, 3,200,000 by default, less 150,000.

Broadcasters (`waku-broadcaster-client` 10.0.1, shared-models 8.2.1):

- Waku cluster 5, shard 1, pubsub topic `/waku/2/rs/5/1`. Content topics `/railgun/v2/0-{chainId}-fees/json`, `-transact/json` and `-transact-response/json`. Store v3 `/vac/waku/store-query/3.0.0` and light push v3 `/vac/waku/lightpush/3.0.0` over TCP, Noise and yamux, with timestamps in nanoseconds. Nodes ask `/vac/waku/metadata/1.0.0` for the cluster and drop peers on another. The fleet's ENR tree is `enrtree://APMYHUVNQWHJNPI5L2KQ765EMCKUAMRWPUH3U2QIKPK6XEV3OW442@discovery.rootedinprivacy.com`, and the `waku2` field's bits are relay, store, filter, light push.
- A fee message is `{data, signature}`: `data` is the hex of the offer's UTF-8 JSON, and `signature` is Ed25519 over those bytes by the viewing key in the offer's `railgunAddress`. Offers carry `fees` (token to per-gas rate, hex, scaled by 10^18), `feeExpiration` (ms), `feesID`, `availableWallets`, `version` (8.0.0 to 8.999.0 accepted), `relayAdapt`, `requiredPOIListKeys` and `reliability`.
- A request is `{method: "transact", params: {pubkey, encryptedData}}`. `pubkey` is a one-time Ed25519 public key, and the shared key is noble-ed25519's `getSharedSecret`: X25519 of the clamped sha512 head of the one-time key with the broadcaster's viewing key in Montgomery form, unhashed. `encryptedData` is `[0x ‖ iv ‖ tag, 0x ‖ ciphertext]`, AES-256-GCM with a 16-byte IV, of the JSON `{txidVersion, to, data, broadcasterViewingKey, chainID, chainType, feesID, useRelayAdapt, devLog, minVersion, maxVersion, preTransactionPOIsPerTxidLeafPerList, transactType: "COMMON", minGasPrice}`.
- The answer is `{result: encryptedData}` under the same key, holding `{txHash}` or `{error}`.
- `preTransactionPOIsPerTxidLeafPerList` maps list key to txid leaf hash (64 hex digits) to `{snarkProof, txidMerkleroot, poiMerkleroots, blindedCommitmentsOut, railgunTxidIfHasUnshield}`. The leaf is `poseidon(txid, treeIn, P)` with P = 199999 × 65536 + 199999, the txid proof is `createDummyMerkleProof` (index 0, sixteen zero siblings), and output i is blinded at P + i.
- The fee note is the first output of the first transaction, type `BroadcasterFee`, sender hidden.
- Through RelayAdapt, `to` is the RelayAdapt contract, `data` is `relay(transactions, action)` and `useRelayAdapt` is true. Broadcasters refuse an action with `requireSuccess` set. The client only picks offers whose `relayAdapt` is in the network's `relayAdaptHistory`.

## Where bytes went wrong most easily

1. BabyJubJub curve form and EdDSA details: circomlib's a and d, BLAKE-512, `s >> 3` for A but `s` in S, little-endian scalars.
2. Poseidon with up to 16 inputs.
3. The ABI encoding of boundParams for its hash: one dynamic tuple parameter.
4. AES-256-GCM with a 16-byte IV, one stream across blocks, and the memo as the fourth block.
5. The annotationData CTR layout (written 16/15/15, read 16/16/16) and the inverted wallet-source padding.
6. Ed25519 ECDH: a scalar from clamped sha512 reduced mod l, sha256 of the compressed point, and a blinding scalar from the XOR of randoms.
7. The address networkID XOR with the 7-byte "railgun" over 8 bytes.
8. Circuit input names and order, and the pi_b swap.
