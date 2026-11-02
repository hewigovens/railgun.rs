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
