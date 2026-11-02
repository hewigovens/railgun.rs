//! The wallet API: everything a binding needs, over blocking calls. A
//! [`Client`] owns one network's chain data; keys are passed per call, so one
//! client can serve several wallets.

mod poi;
mod store;
mod sync;
mod transfer;

use rg_sync::rpc::RpcClient;
use rg_sync::{Network, SyncState};

pub use poi::{PoiProof, PoiStatus};
pub use store::{ChainStore, FileStore};
pub use sync::SyncReport;
pub use transfer::{Transfer, UnsignedTx};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("store: {0}")]
    Io(#[from] std::io::Error),
    #[error("stored {0} is corrupt")]
    Corrupt(&'static str),
    #[error("sync: {0}")]
    Sync(#[from] rg_sync::Error),
    #[error("transaction: {0}")]
    Tx(#[from] rg_tx::Error),
    #[error("prover: {0}")]
    Prover(#[from] rg_prover::Error),
    #[error("poi: {0}")]
    Poi(#[from] rg_poi::Error),
    #[error("aggregator: {0}")]
    Node(#[from] rg_poi::node::NodeError),
    #[error("keys: {0}")]
    Keys(#[from] rg_keys::Error),
    #[error("seed root {0} is not in the contract's history")]
    UnknownSeedRoot(String),
    #[error("{0} has no indexer and legacy events cannot be decoded")]
    NoSquid(&'static str),
    #[error("proof does not verify against the artifacts' key")]
    BadProof,
    #[error("transaction {0} is not one this wallet can prove: {1}")]
    NotProvable(String, &'static str),
}

pub struct Client<S = FileStore> {
    network: Network,
    rpc: RpcClient,
    store: S,
    state: SyncState,
}

impl<S: ChainStore> Client<S> {
    /// Rebuilds state from the store. Does not touch the network.
    pub fn open(network: Network, rpc_url: &str, store: S) -> Result<Self, Error> {
        let mut client = Client {
            network,
            rpc: RpcClient::new(rpc_url),
            store,
            state: SyncState::new(),
        };
        client.reload()?;
        Ok(client)
    }

    fn reload(&mut self) -> Result<(), Error> {
        let mut state = SyncState::new();
        if let Some(seed) = self.store.seed()? {
            state.seed_from_text(&seed)?;
        }
        state.apply_all(&self.store.logs()?)?;
        self.state = state;
        Ok(())
    }

    pub fn state(&self) -> &SyncState {
        &self.state
    }

    pub fn network(&self) -> Network {
        self.network
    }
}
