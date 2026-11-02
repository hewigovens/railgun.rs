//! The wallet API: everything a binding needs, over blocking calls. A [`Client`] owns one network's chain data; keys are passed per call, so one client can serve several wallets.

mod artifacts;
mod client;
mod error;
mod poi;
mod send;
mod store;
mod sync;
mod transfer;

pub use artifacts::{Artifacts, Circuit};
pub use client::Client;
pub use error::Error;
pub use poi::{PoiProof, PoiStatus};
pub use rg_sync::rpc::Receipt;
pub use rg_tx::Error as TxError;
pub use send::Shield;
pub use store::{ChainStore, FileStore};
pub use sync::SyncReport;
pub use transfer::{Transfer, Unshield, UnsignedTx};
