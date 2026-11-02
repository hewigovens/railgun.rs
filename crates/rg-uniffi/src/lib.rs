uniffi::setup_scaffolding!();

mod client;
mod error;
mod evm_account;
mod poi_submission;
mod types;
mod wallet;

pub use client::RailgunClient;
pub use error::RailgunError;
pub use evm_account::EvmAccount;
pub use poi_submission::PoiSubmission;
pub use types::*;
pub use wallet::{Wallet, generate_mnemonic};
