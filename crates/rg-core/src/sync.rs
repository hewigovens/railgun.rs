use rg_keys::ViewOnlyKeys;
use rg_primitives::field;
use rg_sync::squid;
use rg_wallet::{HistoryEntry, ScanResult, Scanner};

use crate::{ChainStore, Client, Error};

/// `eth_getLogs` range that public RPCs accept.
const LOG_CHUNK: u64 = 50_000;
/// Stay behind the head so the contract has the root the seed ends on.
const SEED_BEHIND_HEAD: u64 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncReport {
    pub head: u64,
    pub new_logs: u64,
    pub leaves: u64,
}

impl<S: ChainStore> Client<S> {
    /// Seeds on a network with legacy events, once, and checks the seed's root against the contract. The seed has no ciphertexts or nullifiers, so a wallet's notes must all come after it.
    fn bootstrap(&mut self, head: u64) -> Result<u64, Error> {
        let Some(url) = self.network.squid else {
            return Ok(self.network.deployment_block);
        };
        let leaves = squid::fetch_leaves(url, head.saturating_sub(SEED_BEHIND_HEAD))?;
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
        let tree = self.state.trees.len().saturating_sub(1);
        if self.state.root(tree as u32).is_none() {
            return Err(Error::NoSquid(self.network.name));
        }
        if let Err(e) = self.check_roots(&[tree]) {
            self.state = Default::default();
            return Err(e);
        }
        // Not the block queried: the squid may lag, and it indexes whole blocks.
        let last = leaves.iter().map(|l| l.block_number).max().unwrap_or(0);
        if last > head {
            self.state = Default::default();
            return Err(Error::Sync(rg_sync::Error::Range("squid block number")));
        }
        self.store.save_seed(&text)?;
        Ok(last + 1)
    }

    /// Checks each tree's current root against the contract's `rootHistory`, through the same node, so a dropped or altered log shows up instead of skewing the tree. It cannot catch a node that lies about the root too, or hides a `Nullified` event.
    fn check_roots(&self, trees: &[usize]) -> Result<(), Error> {
        for &tree in trees {
            let Some(root) = self.state.root(tree as u32) else {
                continue;
            };
            let root = field::to_be_bytes(&root);
            if !self
                .rpc
                .root_history(self.network.proxy, tree as u32, root, None)?
            {
                return Err(Error::UnknownRoot(tree as u32, hex::encode(root)));
            }
        }
        Ok(())
    }

    /// Applies a chunk of logs and checks the roots it changed, and only then stores it, so a log that does not apply never reaches the store, which every launch replays.
    fn apply_chunk(&mut self, logs: &[rg_sync::RawLog], next: u64) -> Result<(), Error> {
        let before: Vec<usize> = self.state.leaves.iter().map(Vec::len).collect();
        let applied = self
            .state
            .apply_all(logs)
            .map_err(Error::from)
            .and_then(|()| {
                let changed: Vec<usize> = (0..self.state.leaves.len())
                    .filter(|&t| before.get(t) != Some(&self.state.leaves[t].len()))
                    .collect();
                self.check_roots(&changed)
            });
        if let Err(e) = applied {
            self.reload()?;
            return Err(e);
        }
        self.store.append_logs(logs)?;
        self.store.set_cursor(next)
    }

    /// Brings the store and state up to the chain head. Refetches the last `reorg_window` blocks each time, so a reorged log does not survive.
    pub fn sync(&mut self) -> Result<SyncReport, Error> {
        let chain_id = self.rpc.chain_id()?;
        if chain_id != self.network.chain_id {
            return Err(Error::WrongNode(chain_id, self.network.chain_id));
        }
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
            self.apply_chunk(&logs, to + 1)?;
            new_logs += logs.len() as u64;
            from = to + 1;
        }
        self.release_spent()?;
        Ok(SyncReport {
            head,
            new_logs,
            leaves: self.state.leaf_count() as u64,
        })
    }

    pub fn scan(&self, keys: &ViewOnlyKeys) -> ScanResult {
        Scanner::new(keys).scan(&self.state)
    }

    /// Shields, receipts, sends and unshields as of the last sync, newest first.
    pub fn history(&self, keys: &ViewOnlyKeys) -> Vec<HistoryEntry> {
        self.scan(keys).history(&keys.master_public_key)
    }
}
