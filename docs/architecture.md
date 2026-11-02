# Architecture

A Rust core for a private Railgun wallet, written to replace the TS SDK on mobile through
UniFFI. `rg-core` is the API those bindings will sit on; the FFI layer itself is not
written yet (see "Open items" in `HANDOFF.md`).

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
    core["rg-core<br/>Client: store, sync, scan,<br/>transfers, unshields, POI"]
    core --> tx
    core --> poi
    core --> wallet
    core --> sync
    core --> prover
```

`rg-poi` stays independent of the wallet and prover: it builds circuit inputs, and `rg-core`
joins them. `rg-prover` knows nothing about Railgun
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

    rpc --> core
    squid --> core
    ipfs --> core
    core <--> node
    core -->|calldata| eoa
    eoa -->|transact| proxy
    proxy -->|events| rpc
```

The core never signs EVM transactions. It prints calldata, and `harness/send.js` or any
wallet sends it.

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

The contract does not enforce any of this; wallets and broadcasters do. Blinded commitments
are `poseidon(commitment, npk, global position)`, so the list holds no amounts or addresses.

POI artifacts are versioned apart from the engine, and the live aggregator rejects proofs
made with older keys. `HANDOFF.md` records the current IPFS root.
