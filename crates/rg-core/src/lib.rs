//! The wallet API: everything a binding needs, over blocking calls. A [`Client`] owns one network's chain data; keys are passed per call, so one client can serve several wallets.

mod artifacts;
mod balance;
mod broadcast;
mod client;
mod error;
mod fee_quote;
mod poi;
mod route;
mod send;
mod store;
mod sync;
mod transfer;

pub use artifacts::{Artifacts, Circuit};
pub use balance::{Balance, NoteStatus};
pub use broadcast::BroadcastTx;
pub use client::Client;
pub use error::Error;
pub use fee_quote::FeeQuote;
pub use poi::{PoiProof, PoiStatus};
pub use rg_broadcaster::{BroadcasterFees, Broadcasters, Waku};
/// The POI list every wallet and broadcaster requires.
pub use rg_poi::node::REQUIRED_LIST as POI_LIST;
pub use rg_sync::rpc::Receipt;
pub use rg_tx::Error as TxError;
pub use rg_wallet::{HistoryEntry, HistoryKind};
pub use send::Shield;
pub use store::{ChainStore, FileStore};
pub use sync::SyncReport;
pub use transfer::{Transfer, Unshield, UnshieldBaseToken, UnsignedTx};
