//! Railgun event sync: decode the proxy's logs, rebuild the commitment trees, keep the nullifier set and the root after every insertion.
//!
//! Logs come from any source that yields `eth_getLogs` objects (an RPC node, a saved file, an indexer). The `rpc` feature adds a blocking JSON-RPC client. `rg-core` refetches recent blocks, which is what handles reorgs.

pub mod abi;
mod error;
pub mod events;
pub mod log;
pub mod network;
#[cfg(feature = "rpc")]
pub mod rpc;
#[cfg(feature = "rpc")]
pub mod squid;
pub mod state;

pub use error::Error;
pub use events::{
    RailgunEvent, ShieldCommitment, TransactCommitment, TransactionRoot, decode_log,
    decode_transact_call,
};
pub use log::RawLog;
pub use network::Network;
pub use state::{Commitment, Leaf, NullifierRecord, SyncState};
