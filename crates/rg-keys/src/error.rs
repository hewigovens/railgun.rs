#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid derivation path")]
    InvalidPath,
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),
    #[error("invalid address: {0}")]
    InvalidAddress(&'static str),
    #[error("invalid shareable viewing key")]
    InvalidViewingKey,
    #[error("incorrect address version {0}")]
    AddressVersion(u8),
    #[error("invalid EVM address: {0}")]
    InvalidEvmAddress(&'static str),
    #[error("invalid EVM key")]
    InvalidEvmKey,
    #[error("signing failed")]
    Signing,
}
