//! Railgun event sync: decode the proxy's logs, rebuild the commitment trees,
//! keep the nullifier set and the root after every insertion.
//!
//! Logs come from any source that yields `eth_getLogs` objects (an RPC node,
//! a saved file, an indexer). The `rpc` feature adds a blocking JSON-RPC
//! client. Reorgs are not handled yet: apply only logs you consider final.

pub mod abi;
pub mod events;
pub mod log;
pub mod network;
#[cfg(feature = "rpc")]
pub mod rpc;
#[cfg(feature = "rpc")]
pub mod squid;
pub mod state;

pub use events::{
    decode_log, decode_transact_call, RailgunEvent, ShieldCommitment, TransactCommitment,
    TransactionRoot,
};
pub use log::RawLog;
pub use network::Network;
pub use state::{Commitment, Leaf, NullifierRecord, SyncState};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bad log: {0}")]
    BadLog(String),
    #[error("abi decode: {0}")]
    Abi(String),
    #[error("value out of range: {0}")]
    Range(&'static str),
    #[error("unknown token type {0}")]
    TokenType(u8),
    #[error("tree: {0}")]
    Tree(#[from] rg_tree::Error),
    #[error(
        "log out of order: block {block} index {index} after block {last_block} index {last_index}"
    )]
    OutOfOrder {
        block: u64,
        index: u64,
        last_block: u64,
        last_index: u64,
    },
    #[error("rpc: {0}")]
    Rpc(String),
}
