uniffi::setup_scaffolding!();

mod client;
mod error;
mod types;
mod wallet;

pub use client::{PoiSubmission, RailgunClient};
pub use error::RailgunError;
pub use types::*;
pub use wallet::{Wallet, generate_mnemonic};
