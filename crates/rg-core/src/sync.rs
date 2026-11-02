use rg_keys::WalletKeys;
use rg_primitives::field;
use rg_sync::squid;
use rg_wallet::{ScanResult, Scanner};

use crate::{ChainStore, Client, Error};

/// `eth_getLogs` range that public RPCs accept.
const LOG_CHUNK: u64 = 50_000;
/// Stay behind the head so the contract has the root the seed ends on.
const SEED_BEHIND_HEAD: u64 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncReport {
    pub head: u64,
    pub new_logs: usize,
    pub leaves: usize,
}

impl<S: ChainStore> Client<S> {
    /// Seeds on a network with legacy events, once, and checks the seed's root
    /// against the contract. The seed has no ciphertexts or nullifiers, so a
    /// wallet's notes must all come after it.
    fn bootstrap(&mut self, head: u64) -> Result<u64, Error> {
        let Some(url) = self.network.squid else {
            return Ok(self.network.deployment_block);
        };
        let leaves = squid::fetch_leaves(url, head - SEED_BEHIND_HEAD)?;
        let mut text = String::new();
        for l in &leaves {
            text.push_str(&format!(
                "{} {} {}\n",
                l.tree,
                l.position,
                hex::encode(l.hash)
            ));
        }
        // Fresh state: a crash can leave a seed stored with no cursor yet.
        self.state = Default::default();
        self.state.seed_from_text(&text)?;
        let tree = self.state.trees.len().saturating_sub(1) as u32;
        let root = self
            .state
            .root(tree)
            .ok_or(Error::NoSquid(self.network.name))?;
        let root = field::to_be_bytes(&root);
        if !self
            .rpc
            .root_history(self.network.proxy, tree, root, None)?
        {
            self.state = Default::default();
            return Err(Error::UnknownSeedRoot(hex::encode(root)));
        }
        self.store.save_seed(&text)?;
        // Not the block queried: the squid may lag, and it indexes whole blocks.
        let last = leaves.iter().map(|l| l.block_number).max().unwrap_or(0);
        Ok(last + 1)
    }

    /// Brings the store and state up to the chain head. Refetches the last
    /// `reorg_window` blocks each time, so a reorged log does not survive.
    pub fn sync(&mut self) -> Result<SyncReport, Error> {
        let head = self.rpc.block_number()?;
        let start = match self.store.cursor()? {
            Some(cursor) => cursor.saturating_sub(self.network.reorg_window),
            None => self.bootstrap(head)?,
        };

        // Also clears logs a crash left past the cursor.
        if self.store.truncate_logs(start)? > 0 {
            self.reload()?;
        }

        let mut new_logs = 0;
        let mut from = start;
        while from <= head {
            let to = (from + LOG_CHUNK - 1).min(head);
            let logs = self.rpc.get_logs(self.network.proxy, from, to, LOG_CHUNK)?;
            self.store.append_logs(&logs)?;
            self.store.set_cursor(to + 1)?;
            self.state.apply_all(&logs)?;
            new_logs += logs.len();
            from = to + 1;
        }
        Ok(SyncReport {
            head,
            new_logs,
            leaves: self.state.leaf_count(),
        })
    }

    pub fn scan(&self, keys: &WalletKeys) -> ScanResult {
        Scanner::new(keys.clone()).scan(&self.state)
    }
}
