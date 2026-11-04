use rg_sync::rpc::RpcClient;
use rg_sync::{Network, SyncState};

use crate::{ChainStore, Error, FileStore};

/// Plain HTTP only to this machine: elsewhere the node, or anyone on the path, would see the wallet's queries and could alter its answers.
fn is_private_url(url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(url) else {
        return false;
    };
    match url.scheme() {
        "https" => true,
        "http" => matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")),
        _ => false,
    }
}

pub struct Client<S = FileStore> {
    pub(crate) network: Network,
    pub(crate) rpc: RpcClient,
    pub(crate) store: S,
    pub(crate) state: SyncState,
}

impl<S: ChainStore> Client<S> {
    /// Rebuilds state from the store. Does not touch the network.
    pub fn open(network: Network, rpc_url: &str, store: S) -> Result<Self, Error> {
        if !is_private_url(rpc_url) {
            return Err(Error::InsecureRpc);
        }
        let mut client = Client {
            network,
            rpc: RpcClient::new(rpc_url),
            store,
            state: SyncState::new(),
        };
        client.reload()?;
        Ok(client)
    }

    /// Rebuilds the state from the store. Earlier versions stored logs before applying them, so a log that does not apply is dropped with everything after it, to be fetched again, rather than failing every launch.
    pub(crate) fn reload(&mut self) -> Result<(), Error> {
        loop {
            let mut state = SyncState::new();
            if let Some(seed) = self.store.seed()? {
                state.seed_from_text(&seed)?;
            }
            let logs = self.store.logs()?;
            match logs.iter().find(|log| state.apply(log).is_err()) {
                None => {
                    self.state = state;
                    return Ok(());
                }
                Some(bad) => {
                    self.store.truncate_logs(bad.block_number)?;
                    self.store.set_cursor(bad.block_number)?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rg_sync::RawLog;

    fn log(block: u64) -> RawLog {
        RawLog {
            address: [1; 20],
            topics: vec![[2; 32]],
            data: vec![],
            block_number: block,
            transaction_hash: [4; 32],
            log_index: 0,
        }
    }

    #[test]
    fn a_stored_log_that_does_not_apply_is_dropped_on_open() {
        let dir = std::env::temp_dir().join(format!("rg-core-reload-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = FileStore::open(&dir).unwrap();
        // The repeated (block, index) is out of order, as a dropped or replayed log would leave it.
        store
            .append_logs(&[log(1), log(2), log(2), log(3)])
            .unwrap();
        store.set_cursor(4).unwrap();
        let client = Client::open(Network::SEPOLIA, "http://localhost:1", store).unwrap();
        assert_eq!(client.store.logs().unwrap(), vec![log(1)]);
        assert_eq!(client.store.cursor().unwrap(), Some(2));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn only_https_or_this_machine() {
        assert!(is_private_url("https://arb1.arbitrum.io/rpc"));
        assert!(is_private_url("http://localhost:8545"));
        assert!(is_private_url("http://127.0.0.1:8545"));
        assert!(!is_private_url("http://localhost.example.com"));
        assert!(!is_private_url("http://10.0.0.2:8545"));
        assert!(!is_private_url("ws://localhost:8545"));
    }
}
