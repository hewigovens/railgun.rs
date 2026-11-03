# Architecture

A Rust core for a private Railgun wallet, written to replace the TS SDK on mobile through
UniFFI. `rg-core` is the API, and `rg-uniffi` exposes it to Swift and Kotlin with no logic of its own.

## Crates

```mermaid
flowchart BT
    primitives["rg-primitives<br/>Poseidon, BabyJubJub, EdDSA,<br/>Ed25519, AES, BLAKE-512"]
    keys["rg-keys<br/>BIP32 variant, wallet keys,<br/>0zk addresses"]
    notes["rg-notes<br/>commitments, nullifiers,<br/>note and shield ciphertexts"]
    tree["rg-tree<br/>depth-16 Poseidon Merkle tree"]
    sync["rg-sync<br/>events, squid, RPC,<br/>trees and nullifier state"]
    wallet["rg-wallet<br/>trial decryption, TXOs, balances"]
    prover["rg-prover<br/>circom witness, zkey,<br/>Groth16 on arkworks"]
    tx["rg-tx<br/>transfer plan, bound params,<br/>signature, calldata, shield"]
    poi["rg-poi<br/>txid trees, blinded commitments,<br/>POI inputs, aggregator client"]
    broadcaster["rg-broadcaster<br/>fee offers, sealed requests,<br/>Waku light client"]

    keys --> primitives
    notes --> primitives
    tree --> primitives
    sync --> notes
    sync --> tree
    sync --> primitives
    wallet --> keys
    wallet --> notes
    wallet --> sync
    wallet --> primitives
    tx --> keys
    tx --> notes
    tx --> sync
    tx --> tree
    tx --> wallet
    tx --> prover
    tx --> primitives
    poi --> tree
    poi --> primitives
    broadcaster --> keys
    broadcaster --> primitives
    core["rg-core<br/>Client: store, sync, scan,<br/>transfers, unshields, POI"]
    core --> tx
    core --> poi
    core --> wallet
    core --> sync
    core --> prover
    core --> broadcaster
    uniffi["rg-uniffi<br/>Swift and Kotlin bindings"]
    uniffi --> core
```

`rg-poi` stays independent of the wallet and prover: it builds circuit inputs, and `rg-core`
joins them. `rg-broadcaster` knows message formats and transport, not transactions. `rg-prover` knows nothing about Railgun
and takes named signals, which is why both the transfer and POI circuits run on it.

## External systems

```mermaid
flowchart LR
    core["rg-core"]
    rpc["EVM RPC<br/>logs, rootHistory"]
    squid["Railgun squid<br/>leaf hashes, transactions"]
    proxy["Railgun proxy contract<br/>verifies Groth16, keeps roots"]
    node["POI aggregator<br/>ppoi.fdi.network"]
    ipfs["IPFS<br/>circuit artifacts"]
    eoa["Funded EOA or wallet<br/>signs and pays gas"]
    waku["Waku fleet<br/>store and light push"]
    broadcaster["Broadcaster<br/>pays gas"]

    rpc --> core
    squid --> core
    ipfs --> core
    core <--> node
    core -->|calldata| eoa
    eoa -->|transact| proxy
    core <-->|offers, sealed batch| waku
    waku <--> broadcaster
    broadcaster -->|transact| proxy
    proxy -->|events| rpc
```

Artifacts are downloaded when a circuit is first needed and hash-checked on every load.
`Client::send` signs an EIP-1559 transaction with an `EvmKey` and sends it. That account pays
gas and is public: it is derived on the standard path `m/44'/60'/0'/0/i` or loaded from a key,
and never from Railgun's spending or viewing keys. A broadcaster hides it, below.
`UnsignedTx` stays available for any other wallet to send.

## Sync and scan

```mermaid
flowchart TD
    A{"Chain has legacy events?"}
    A -->|"yes: Arbitrum, Ethereum"| B["First sync: leaf hashes from the squid"]
    B --> C["Rebuild trees, check the root against rootHistory"]
    C --> D["Logs from the block after the last leaf"]
    A -->|"no: Sepolia"| E["Logs from deployment"]
    D --> F["SyncState: trees, nullifiers, root history"]
    E --> F
    F --> G["Scanner: trial-decrypt each note"]
    G --> H{"Recomputed commitment<br/>matches the leaf?"}
    H -->|no| I["Not ours"]
    H -->|yes| J["TXO or sent note"]
    J --> K["Spent if its nullifier was published"]
```

`Client::sync` refetches a reorg window each time. `FileStore` keeps the seed, logs and a
cursor, and `Client::open` replays them. Seeded leaves are hashes only, so a wallet's notes
must all come after the seed. A nullifier
hashes only the leaf position, so lookups are always scoped to a tree.

## A private transfer

```mermaid
sequenceDiagram
    participant W as rg-wallet
    participant T as rg-tx
    participant P as rg-prover
    participant E as EOA
    participant C as Proxy contract
    participant R as Recipient

    W->>T: unspent note, Merkle proof
    T->>T: recipient and change outputs, ciphertexts
    T->>T: bound params hash, EdDSA signature
    T->>P: circuit inputs
    P->>P: witness from circuit wasm, Groth16 proof
    P-->>T: proof, checked against the key
    T->>E: transact calldata
    E->>C: transact
    C->>C: check root, nullifiers, proof
    C-->>R: Transact and Nullified events
    R->>R: scan, decrypt note, status pending
```

An unshield is the same flow with one more output: a commitment whose npk is the public
address, last in the list, with no ciphertext and no tree position. The contract pays it
out, less its fee, and the POI proof carries the Railgun txid in place of a blinded note.

A transaction proves against one tree's root and takes at most 10 notes. When the notes
that cover an amount span trees, or there are more than 10, `select_notes` groups them and
each group becomes its own Railgun transaction in the same `transact` call. Every group
pays the recipient, or the unshield, its share, and the last one carries the change. POI
is proved and submitted per Railgun transaction.

Native ETH goes through the RelayAdapt contract. A shield is `multicall(wrapBase, shield)`
sent with the ETH, so it needs no approval. An unshield to ETH unshields the wrapped token
to RelayAdapt, and the bound params commit to RelayAdapt and to a hash of the nullifiers
and the follow-up calls, `unwrapBase` and a transfer of the ETH to the recipient. The
nullifiers are known before proving, so no dummy proof is needed to make that hash.

## A broadcast transfer

A broadcaster sends the batch from its own account, so no account of the user's shows on
chain, and takes its fee as a private note.

```mermaid
sequenceDiagram
    participant C as rg-core
    participant W as Waku store and light push
    participant B as Broadcaster
    participant N as Node RPC
    participant P as Proxy contract

    B->>W: signed fee offers, every few seconds
    C->>W: offers from the last minute
    C->>C: verify signatures, pick the cheapest live one
    C->>N: estimate gas with empty proofs, from 0x…dEaD
    C->>C: fee note first, re-plan until the circuits settle
    C->>C: prove the batch and a pre-transaction POI per transaction
    C->>W: batch, encrypted to the broadcaster's viewing key
    W->>B: request
    B->>B: check fee note and POIs
    B->>P: transact
    B->>W: hash, encrypted under the same key
    C->>W: poll for the answer
```

The fee is the offer's per-gas rate times the gas limit and price, over 10^18, the way the
SDK prices it. The request names that price as `minGasPrice`, and the broadcaster sends a
type-1 transaction at it, after checking it is not far below the going rate. Gas is estimated before proving because the contract skips proof checks
for `0x000000000000000000000000000000000000dEaD`. On Ethereum and Sepolia the batch also
commits to the gas price it was priced at, which the contract holds the broadcaster to;
on Arbitrum it does not, as `tx.gasprice` there is not the price offered.

A pre-transaction POI is the usual POI proof made before the transaction exists: its txid
leaf sits first in a stand-in tree of zeros, and its outputs at the fixed position
199999 × 65536 + 199999. The broadcaster checks it before paying gas. Its positions are
stand-ins, so once the transaction is mined the sender proves and submits POI as for any
other send.

An unshield to ETH through a broadcaster is sent to RelayAdapt with `useRelayAdapt`, and
the fee note is in wrapped ETH. Only offers whose `relayAdapt` is this network's
RelayAdapt are taken. The nullifiers, and so the relay hash the transactions commit to,
change with every re-plan, so each round binds them again before estimating. Broadcasters
refuse a relay whose calls must succeed, so, as in the engine, a failed unwrap or send
leaves the ETH in RelayAdapt: the recipient must accept ETH.

`Waku` is a light client. It never joins the relay mesh. It reads offers and answers
with store queries, and hands requests to a node with light push. It finds nodes through
the fleet's ENR tree in DNS, checked against the tree's pinned key, falling back to the
nodes it shipped with.

The contract never sees amounts, owners or the token of a private transfer. It learns that a
valid proof spent some unspent notes under a known root.

## POI

```mermaid
sequenceDiagram
    participant S as Sender (rg-poi)
    participant Q as Squid
    participant A as POI aggregator
    participant L as List provider
    participant R as Recipient wallet

    S->>Q: all Railgun transactions
    S->>S: rebuild txid tree
    S->>A: is this txid root validated?
    S->>A: Merkle proofs for spent notes in the list
    S->>S: POI proof, spent notes in list and outputs correct
    S->>A: blinded outputs, proof, roots
    A->>A: verify proof
    A->>L: queue blinded commitments
    L-->>A: signed list events
    R->>A: status of my blinded commitment
    A-->>R: Valid
    R->>R: note is spendable
```

The contract does not enforce any of this; wallets and broadcasters do. `Client::balances`
asks the aggregator for the status of every unspent note and splits balances the way the
engine's `getBalanceBucket` does. Transfers and unshields spend only notes it reports
`Valid`: a pending note would pass on chain, but the POI proof for that transaction could
not be made, so the recipient's funds would stay pending. Blinded commitments
are `poseidon(commitment, npk, global position)`, so the list holds no amounts or addresses.

POI artifacts are versioned apart from the engine, and the live aggregator rejects proofs
made with older keys. `docs/development.md` records the current IPFS root.

## Key material

The core never stores a key. `FileStore` holds chain data only, and a shell keeps the mnemonic in the iOS Keychain or behind the Android Keystore, device-only and unlocked-only, then builds a `Wallet` when it needs one.

| Secret | Handling |
| --- | --- |
| Spending and viewing keys | `PrivateKey`: not `Copy`, never printed, wiped on drop. Only `expose()` reads them. |
| `WalletKeys` | Not `Clone`, wiped on drop, and `Debug` shows only the master public key. `Wallet` drops it on Kotlin's `close()` or Swift's last release. |
| `ViewOnlyKeys` and the shareable viewing key | The viewing key, nullifying key and public keys, wiped on drop. `WalletKeys` holds one and derefs to it, so scanning, balances and history take either. The shareable key reveals every note and transaction, so it crosses as bytes and is returned as `Zeroizing`. |
| Seed, BIP32 nodes, BIP39 entropy and words | Wiped on drop. |
| `EvmKey`, the gas account | k256 `SigningKey`, wiped on drop, `Debug` shows only the address. |
| Broadcaster request keys | The one-time key and the key shared with the broadcaster, wiped on drop. The shared key lives as long as the `SealedRequest`, to read the answer. |
| EdDSA and Ed25519 working values, including the signing nonce | Wiped when the call returns. |
| Mnemonic entering the core | `&[u8]` borrows the shell's own `Data` or direct `ByteBuffer`, with no UniFFI copy. The shell wipes that buffer after the call. |

What this does not cover:

- `generateMnemonic` returns through a UniFFI buffer that is freed without a wipe, and showing the words needs a platform string that cannot be wiped. Both happen once, at wallet creation.
- `nullifying_key` is copied into nullifiers, circuit inputs and the circom wasm memory. It reveals which notes are spent, not how to spend them.
- Per-note shared keys, decrypted notes and note randoms live as long as a scan result.
- HMAC, SHA-512, PBKDF2, AES and Poseidon internals, and moves of a value on the stack, are outside what `zeroize` can reach.
- Pages are not locked, so the OS may swap them or include them in a dump.

Wiping shortens how long a secret sits in memory. It does not protect a compromised process.
