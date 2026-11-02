use rg_sync::rpc::RpcClient;
use rg_sync::{Network, SyncState};

use crate::{ChainStore, Error, FileStore};

pub struct Client<S = FileStore> {
    pub(crate) network: Network,
    pub(crate) rpc: RpcClient,
    pub(crate) store: S,
    pub(crate) state: SyncState,
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

    pub(crate) fn reload(&mut self) -> Result<(), Error> {
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
