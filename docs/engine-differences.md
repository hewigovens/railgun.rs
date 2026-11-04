# Differences from the TS engine

`@railgun-community/engine` 9.6.0 is the reference, and bytes on the wire match it. These
are the places where this library behaves differently, mostly by rejecting input the
engine accepts. Missing features are in the README under "Not supported yet".

- `mnemonic_to_seed` rejects unknown words and a bad BIP39 checksum. The engine has
  `Mnemonic.validate` but never calls it when creating a wallet: `Mnemonic.toSeed` runs
  PBKDF2 on any words, and wallet SDK 11.2.0 passes the mnemonic straight through. Both
  NFKD-normalize the mnemonic and password first, so a non-ASCII password gives the same
  seed either way.
- `decode_address` also rejects a viewing key that is not a curve point or has small
  order: every sender's shared key with such a key is the same public value, so anything
  sent to it is readable by all. The engine encrypts to it.
- The scanner drops a received note whose token hash is not reduced mod p. The commitment
  reduces it, so such a note matches its leaf, but the engine would file it under a token
  that does not exist and never spend it.
- A cross-contract relay needs a gas limit of at least 3,200,000, the engine's default;
  the engine takes any `minGasLimit` above 150,000. Every unshielded token is shielded
  back, and a token listed twice is merged.
- `decode_address` rejects an address whose master public key is at or above the BN254
  modulus; the engine reads any 256-bit value. A real MPK is a Poseidon output and never
  is, so such an address belongs to nobody. One engine test vector has one.
- `babyjubjub::Point::mul_le` is variable time and only used for public scalars
  (verification). Key derivation and signing use `mul_ct`, a Montgomery ladder that runs
  the same field operations for every scalar. arkworks' field arithmetic underneath is
  not audited for constant time.
- `ed25519::shared_key` accepts a non-canonical y encoding, as the engine's wasm path
  (curve25519-dalek) does; blinding and unblinding reject it, as noble-ed25519 does. This
  matches the engine on purpose: rejecting more would hide notes the engine shows.
- `wallet_source::encode` rejects sources over 16 characters; the engine only enforces
  that when a wallet source is set, not when encoding.
- `memo::decrypt_annotation` returns none for annotation data under 32 bytes, where the
  engine would return truncated fields.
- `rg_wallet` drops a shield note whose note public key is not
  `poseidon(ourMPK, random)`; the engine keeps any shield whose random decrypts. Such a
  note could not be spent.
- `select_notes` takes the smallest single note that covers the amount, then the fewest of
  a tree's largest notes, and only then splits across trees or past 10 notes, filling each
  group from the largest notes. The engine fills groups from the smallest notes up, which
  spends dust but can need more proofs.
- Unshielding to ETH uses the RelayAdapt contract, as engine 9.6.0 does. Wallet SDK 11.2.0
  prefers an EIP-7702 path through an ephemeral account where a network has one; RelayAdapt
  still works on Ethereum, Arbitrum and Sepolia.
- A broadcaster relay's gas estimate requires its calls to succeed. The engine does so for
  cross-contract calls but not for an unshield to ETH, where a recipient that refuses ETH
  only shows once the broadcaster has sent it and the ETH sits in RelayAdapt.
- A broadcast transfer or unshield split into several transactions goes through
  RelayAdapt with no calls, which binds them together; the engine sends them straight to
  the Railgun contract, where a broadcaster could submit only the one with its fee.
- After a batch goes to a broadcaster, a later spend of the same token must spend one of
  its notes until a sync shows them spent, so a withheld batch and a retry cannot both
  land. The engine has no such hold.
- A sent note counts only in a transaction that spent this wallet's notes. Anyone can write
  an output that decrypts as sent by a given wallet, which would put a forged send in its
  history.
- History is simpler than the SDK's: shields, receipts, sends and unshields per token and
  transaction. Change and transfers to yourself are left out, and an unshield's value is
  what it took from the wallet, before the contract's fee.
- Broadcaster fee offers are checked with Ed25519 `verify_strict`, which rejects the
  non-canonical signatures and small-order keys noble-ed25519 1.7 accepts. A broadcaster
  signing with the SDK never makes one.
- The Waku client reads offers and answers with store queries instead of filter
  subscriptions. Discovery checks the ENR tree root's signature against the pinned tree
  key and every entry against its hash label, and falls back to the shipped nodes on any
  failure; it does not check each ENR's own signature, which the hash chain already covers.
- Pre-transaction POIs are made for the one required list. Offers that require any other
  list are skipped.
