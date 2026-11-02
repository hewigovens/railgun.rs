#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("poseidon takes 1 to 16 inputs, got {0}")]
    PoseidonArity(usize),
    #[error("invalid packed point")]
    InvalidPoint,
}
