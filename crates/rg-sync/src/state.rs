//! Trees, leaves, nullifiers and root history rebuilt from events.

use std::collections::{HashMap, HashSet};

use rg_primitives::{field, Fr};
use rg_tree::MerkleTree;

use crate::events::{decode_log, RailgunEvent, ShieldCommitment, TransactCommitment};
use crate::log::RawLog;
use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Commitment {
    Shield(ShieldCommitment),
    Transact(TransactCommitment),
}

impl Commitment {
    pub fn hash(&self) -> Fr {
        match self {
            Commitment::Shield(s) => s.hash(),
            Commitment::Transact(t) => field::from_be_bytes_mod_order(&t.hash),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    pub commitment: Commitment,
    pub block_number: u64,
    pub transaction_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NullifierRecord {
    pub block_number: u64,
    pub transaction_hash: [u8; 32],
}

#[derive(Clone, Debug, Default)]
pub struct SyncState {
    pub trees: Vec<MerkleTree>,
    /// Same shape as `trees`: `leaves[tree][position]`.
    pub leaves: Vec<Vec<Leaf>>,
    /// Keyed by (tree, nullifier).
    pub nullifiers: HashMap<(u16, [u8; 32]), NullifierRecord>,
    /// Every root a tree has had after an insertion, as the contract's
    /// `rootHistory` records them. Includes each empty tree's root.
    pub root_history: HashSet<(u32, [u8; 32])>,
    /// Number of each tracked event applied, for reporting.
    pub counts: EventCounts,
    last: Option<(u64, u64)>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EventCounts {
    pub shield: usize,
    pub transact: usize,
    pub nullified: usize,
    pub unshield: usize,
    pub other: usize,
}

impl SyncState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Last applied (block, log index).
    pub fn last_applied(&self) -> Option<(u64, u64)> {
        self.last
    }

    pub fn leaf_count(&self) -> usize {
        self.leaves.iter().map(Vec::len).sum()
    }

    pub fn is_known_root(&self, tree: u32, root: &[u8; 32]) -> bool {
        self.root_history.contains(&(tree, *root))
    }

    pub fn root(&self, tree: u32) -> Option<Fr> {
        self.trees.get(tree as usize).map(MerkleTree::root)
    }

    fn tree_mut(&mut self, tree: u32) -> &mut MerkleTree {
        while self.trees.len() <= tree as usize {
            let t = MerkleTree::new();
            let n = self.trees.len() as u32;
            self.root_history.insert((n, field::to_be_bytes(&t.root())));
            self.trees.push(t);
            self.leaves.push(Vec::new());
        }
        &mut self.trees[tree as usize]
    }

    fn insert(&mut self, tree: u32, start: u32, leaves: Vec<Leaf>) -> Result<(), Error> {
        let hashes: Vec<Fr> = leaves.iter().map(|l| l.commitment.hash()).collect();
        let t = self.tree_mut(tree);
        t.insert(start as usize, &hashes)?;
        let root = field::to_be_bytes(&t.root());
        self.root_history.insert((tree, root));
        self.leaves[tree as usize].extend(leaves);
        Ok(())
    }

    /// Applies one log. Logs must arrive in (block, log index) order.
    pub fn apply(&mut self, log: &RawLog) -> Result<(), Error> {
        let key = (log.block_number, log.log_index);
        if let Some(last) = self.last {
            if key <= last {
                return Err(Error::OutOfOrder {
                    block: key.0,
                    index: key.1,
                    last_block: last.0,
                    last_index: last.1,
                });
            }
        }
        let leaf = |commitment| Leaf {
            commitment,
            block_number: log.block_number,
            transaction_hash: log.transaction_hash,
        };
        match decode_log(log)? {
            Some(RailgunEvent::Shield {
                tree,
                start,
                commitments,
            }) => {
                self.counts.shield += 1;
                let leaves = commitments
                    .into_iter()
                    .map(|c| leaf(Commitment::Shield(c)))
                    .collect();
                self.insert(tree, start, leaves)?;
            }
            Some(RailgunEvent::Transact {
                tree,
                start,
                commitments,
            }) => {
                self.counts.transact += 1;
                let leaves = commitments
                    .into_iter()
                    .map(|c| leaf(Commitment::Transact(c)))
                    .collect();
                self.insert(tree, start, leaves)?;
            }
            Some(RailgunEvent::Nullified { tree, nullifiers }) => {
                self.counts.nullified += 1;
                for n in nullifiers {
                    self.nullifiers.insert(
                        (tree, n),
                        NullifierRecord {
                            block_number: log.block_number,
                            transaction_hash: log.transaction_hash,
                        },
                    );
                }
            }
            Some(RailgunEvent::Unshield { .. }) => self.counts.unshield += 1,
            None => self.counts.other += 1,
        }
        self.last = Some(key);
        Ok(())
    }

    pub fn apply_all<'a>(
        &mut self,
        logs: impl IntoIterator<Item = &'a RawLog>,
    ) -> Result<(), Error> {
        for l in logs {
            self.apply(l)?;
        }
        Ok(())
    }
}
