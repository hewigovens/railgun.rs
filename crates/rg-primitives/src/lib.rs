//! Field, Poseidon and BabyJubJub primitives matching the Railgun TS engine.

pub mod aes;
pub mod babyjubjub;
pub mod blake;
pub mod ed25519;
pub mod eddsa;
pub mod field;
pub mod poseidon;

pub use ark_bn254::Fr;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("poseidon takes 1 to 16 inputs, got {0}")]
    PoseidonArity(usize),
    #[error("invalid packed point")]
    InvalidPoint,
}
