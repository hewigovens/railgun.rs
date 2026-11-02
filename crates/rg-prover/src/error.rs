#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("witness: {0}")]
    Witness(String),
    #[error("zkey: {0}")]
    Zkey(String),
    #[error("json: {0}")]
    Json(String),
    #[error("prove: {0}")]
    Prove(String),
}
