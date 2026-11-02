//! Railgun key derivation and `0zk` address encoding, byte compatible with `@railgun-community/engine` (src/key-derivation, src/utils/keys-utils.ts).

pub mod address;
pub mod bip32;
mod error;
mod evm_address;
mod evm_key;
pub mod keys;

pub use address::{AddressData, Chain, decode_address, encode_address};
pub use error::Error;
pub use evm_address::EvmAddress;
pub use evm_key::{EvmKey, EvmSignature};
pub use keys::{WalletKeys, generate_mnemonic, validate_mnemonic};
pub use rg_primitives::{PrivateKey, Zeroizing};
