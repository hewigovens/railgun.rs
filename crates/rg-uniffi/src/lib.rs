uniffi::setup_scaffolding!();

mod broadcast_transaction;
mod broadcaster_offer;
mod broadcasters;
mod client;
mod error;
mod evm_account;
mod fee_quote;
mod poi_submission;
mod types;
mod validation;
mod wallet;

pub use broadcast_transaction::BroadcastTransaction;
pub use broadcaster_offer::BroadcasterOffer;
pub use broadcasters::RailgunBroadcasters;
pub use client::RailgunClient;
pub use error::RailgunError;
pub use evm_account::EvmAccount;
pub use fee_quote::FeeQuote;
pub use poi_submission::PoiSubmission;
pub use types::*;
pub use validation::{is_valid_evm_address, is_valid_mnemonic, is_valid_railgun_address};
pub use wallet::{Wallet, generate_mnemonic};
