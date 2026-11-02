//! Railgun notes matching the TS engine (V2, the format all live networks use):
//! token hashes, note public keys, commitments, nullifiers, memo text, annotation data, transact note ciphertexts and shield ciphertexts.
//!
//! Every random value (note random, sender random, IVs) is a parameter, so the caller owns randomness and tests can pin it.

mod error;
pub mod memo;
pub mod note;
pub mod shield;
pub mod token;
pub mod transact;
pub mod wallet_source;

pub use error::Error;
pub use memo::{AnnotationData, OutputType};
pub use token::{TokenData, TokenType};
