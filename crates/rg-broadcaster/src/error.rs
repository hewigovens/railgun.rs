#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("fee message: {0}")]
    BadFeeMessage(&'static str),
    #[error("fee message signature does not verify")]
    BadSignature,
    #[error("broadcaster version {0} is outside the supported range")]
    Version(String),
    #[error("broadcaster address: {0}")]
    Address(#[from] rg_keys::Error),
    #[error("broadcaster viewing key is not a curve point")]
    BadViewingKey,
    #[error("waku: {0}")]
    Waku(String),
    #[error("ENR: {0}")]
    Enr(&'static str),
    #[error("no Waku peer offers {0}")]
    NoPeer(&'static str),
    #[error("no answer from the broadcaster")]
    Timeout,
}
