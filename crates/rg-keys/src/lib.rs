//! Railgun key derivation and `0zk` address encoding, byte compatible with `@railgun-community/engine` (src/key-derivation, src/utils/keys-utils.ts).

pub mod address;
pub mod bip32;
mod error;
pub mod keys;

pub use address::{AddressData, Chain, decode_address, encode_address};
pub use error::Error;
pub use keys::{WalletKeys, generate_mnemonic};
pub use rg_primitives::{PrivateKey, Zeroizing};
