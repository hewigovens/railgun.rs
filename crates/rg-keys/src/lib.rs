//! Railgun key derivation and `0zk` address encoding, byte compatible with
//! `@railgun-community/engine` (src/key-derivation, src/utils/keys-utils.ts).

pub mod address;
pub mod bip32;
pub mod keys;

pub use address::{decode_address, encode_address, AddressData, Chain};
pub use keys::WalletKeys;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid derivation path")]
    InvalidPath,
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),
    #[error("invalid address: {0}")]
    InvalidAddress(&'static str),
    #[error("incorrect address version {0}")]
    AddressVersion(u8),
}
