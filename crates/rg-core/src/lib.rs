//! The wallet API: everything a binding needs, over blocking calls. A [`Client`] owns one network's chain data; keys are passed per call, so one client can serve several wallets.

mod artifacts;
mod balance;
mod client;
mod error;
mod fee_quote;
mod poi;
mod send;
mod store;
mod sync;
mod transfer;

pub use artifacts::{Artifacts, Circuit};
pub use balance::{Balance, NoteStatus};
pub use client::Client;
pub use error::Error;
pub use fee_quote::FeeQuote;
pub use poi::{PoiProof, PoiStatus};
pub use rg_sync::rpc::Receipt;
pub use rg_tx::Error as TxError;
pub use rg_wallet::{HistoryEntry, HistoryKind};
pub use send::Shield;
pub use store::{ChainStore, FileStore};
pub use sync::SyncReport;
pub use transfer::{Transfer, Unshield, UnsignedTx};
