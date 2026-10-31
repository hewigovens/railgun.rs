//! Railgun notes matching the TS engine (V2, the format all live networks use):
//! token hashes, note public keys, commitments, nullifiers, memo text,
//! annotation data, transact note ciphertexts and shield ciphertexts.
//!
//! Every random value (note random, sender random, IVs) is a parameter, so the
//! caller owns randomness and tests can pin it.

pub mod memo;
pub mod note;
pub mod shield;
pub mod token;
pub mod transact;
pub mod wallet_source;

pub use memo::{AnnotationData, OutputType};
pub use token::{TokenData, TokenType};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("not a valid Ed25519 point")]
    InvalidPoint,
    #[error("unable to decrypt ciphertext")]
    Decrypt,
    #[error("invalid wallet source: {0}")]
    WalletSource(String),
}

impl From<rg_primitives::aes::DecryptError> for Error {
    fn from(_: rg_primitives::aes::DecryptError) -> Self {
        Error::Decrypt
    }
}
