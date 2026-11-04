//! Trees, leaves, nullifiers and root history rebuilt from events.

use std::collections::{HashMap, HashSet};

use rg_primitives::{Fr, field};
use rg_tree::MerkleTree;

use crate::Error;
use crate::events::{RailgunEvent, ShieldCommitment, TransactCommitment, decode_log};
use crate::log::RawLog;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Commitment {
    Shield(ShieldCommitment),
    Transact(TransactCommitment),
    /// A leaf seeded from an indexer: its hash and nothing else. Mainnets have pre-2023 events this crate does not decode; a wallet created after the seed owns none of these leaves, so it only needs them for the tree.
    Opaque([u8; 32]),
}

impl Commitment {
    pub fn hash(&self) -> Fr {
        match self {
            Commitment::Shield(s) => s.hash(),
            Commitment::Transact(t) => field::from_be_bytes_mod_order(&t.hash),
            Commitment::Opaque(hash) => field::from_be_bytes_mod_order(hash),
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
    /// Every root a tree has had after an insertion, as the contract's `rootHistory` records them. Includes each empty tree's root.
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

    /// The contract opens trees one at a time, so a tree number past the next one is a forged or out-of-order log, and creating every tree up to it could exhaust memory.
    fn tree_mut(&mut self, tree: u32) -> Result<&mut MerkleTree, Error> {
        let tree = tree as usize;
        if tree > self.trees.len() {
            return Err(Error::Range("tree number"));
        }
        if tree == self.trees.len() {
            let t = MerkleTree::new();
            self.root_history
                .insert((tree as u32, field::to_be_bytes(&t.root())));
            self.trees.push(t);
            self.leaves.push(Vec::new());
        }
        Ok(&mut self.trees[tree])
    }

    fn insert(&mut self, tree: u32, start: u32, mut leaves: Vec<Leaf>) -> Result<(), Error> {
        let len = self.tree_mut(tree)?.len();
        let mut start = start as usize;
        if start < len {
            // Sync refetches recent blocks, which can reach back into leaves the indexer seeded: the log fills in those bare hashes.
            let seeded = &mut self.leaves[tree as usize][start..len.min(start + leaves.len())];
            let fills = seeded.iter().zip(&leaves).all(|(have, new)| {
                matches!(have.commitment, Commitment::Opaque(_))
                    && have.commitment.hash() == new.commitment.hash()
            });
            if !fills {
                return Err(rg_tree::Error::NotContiguous { start, len }.into());
            }
            let rest = leaves.split_off(seeded.len());
            seeded.clone_from_slice(&leaves);
            if rest.is_empty() {
                return Ok(());
            }
            (start, leaves) = (start + seeded.len(), rest);
        }
        let hashes: Vec<Fr> = leaves.iter().map(|l| l.commitment.hash()).collect();
        let t = self.tree_mut(tree)?;
        t.insert(start, &hashes)?;
        let root = field::to_be_bytes(&t.root());
        self.root_history.insert((tree, root));
        self.leaves[tree as usize].extend(leaves);
        Ok(())
    }

    /// Inserts hash-only leaves. Check the resulting root against the contract before trusting it: nothing here proves that the indexer told the truth.
    pub fn seed(&mut self, tree: u32, start: u32, hashes: &[[u8; 32]]) -> Result<(), Error> {
        let leaves = hashes
            .iter()
            .map(|hash| Leaf {
                commitment: Commitment::Opaque(*hash),
                block_number: 0,
                transaction_hash: [0; 32],
            })
            .collect();
        self.insert(tree, start, leaves)
    }

    /// Seeds from text with one `<tree> <position> <hash hex>` per line, sorted.
    pub fn seed_from_text(&mut self, text: &str) -> Result<(), Error> {
        let bad = |line: &str| Error::BadLog(format!("seed line: {line}"));
        let mut batch: Option<(u32, u32, Vec<[u8; 32]>)> = None;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let mut parts = line.split_whitespace();
            let (Some(tree), Some(position), Some(hash)) =
                (parts.next(), parts.next(), parts.next())
            else {
                return Err(bad(line));
            };
            let tree: u32 = tree.parse().map_err(|_| bad(line))?;
            let position: u32 = position.parse().map_err(|_| bad(line))?;
            let hash: [u8; 32] = hex::decode(hash)
                .ok()
                .and_then(|h| h.try_into().ok())
                .ok_or_else(|| bad(line))?;
            match &mut batch {
                Some((t, start, hashes))
                    if *t == tree && position as usize == *start as usize + hashes.len() =>
                {
                    hashes.push(hash)
                }
                _ => {
                    if let Some((t, start, hashes)) = batch.take() {
                        self.seed(t, start, &hashes)?;
                    }
                    batch = Some((tree, position, vec![hash]));
                }
            }
        }
        if let Some((t, start, hashes)) = batch {
            self.seed(t, start, &hashes)?;
        }
        Ok(())
    }

    /// Applies one log. Logs must arrive in (block, log index) order.
    pub fn apply(&mut self, log: &RawLog) -> Result<(), Error> {
        let key = (log.block_number, log.log_index);
        if let Some(last) = self.last
            && key <= last
        {
            return Err(Error::OutOfOrder {
                block: key.0,
                index: key.1,
                last_block: last.0,
                last_index: last.1,
            });
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

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(n: u8) -> String {
        hex::encode([n; 32])
    }

    #[test]
    fn seeded_tree_has_the_root_of_the_same_leaves() {
        let text = format!("0 0 {}\n0 1 {}\n1 0 {}\n", hash(1), hash(2), hash(3));
        let mut state = SyncState::new();
        state.seed_from_text(&text).unwrap();

        let mut tree = MerkleTree::new();
        let leaves = [[1u8; 32], [2; 32]].map(|h| field::from_be_bytes_mod_order(&h));
        tree.insert(0, &leaves).unwrap();
        assert_eq!(state.root(0), Some(tree.root()));
        assert_eq!(state.leaves[1].len(), 1);
        assert!(state.is_known_root(0, &field::to_be_bytes(&tree.root())));
    }

    #[test]
    fn a_tree_past_the_next_one_is_an_error() {
        let text = format!("0 0 {}\n4000000000 0 {}\n", hash(1), hash(2));
        let mut state = SyncState::new();
        let err = state.seed_from_text(&text).unwrap_err();
        assert!(matches!(err, Error::Range("tree number")));
        assert_eq!(state.trees.len(), 1);
    }

    #[test]
    fn a_log_over_seeded_leaves_fills_them_in_and_appends_the_rest() {
        let text = format!("0 0 {}\n0 1 {}\n", hash(1), hash(2));
        let mut state = SyncState::new();
        state.seed_from_text(&text).unwrap();
        let leaf = |n: u8| Leaf {
            commitment: Commitment::Opaque([n; 32]),
            block_number: 9,
            transaction_hash: [n; 32],
        };
        assert!(state.insert(0, 1, vec![leaf(9)]).is_err());
        state.insert(0, 0, vec![leaf(1)]).unwrap();
        state.insert(0, 1, vec![leaf(2), leaf(3)]).unwrap();

        let blocks: Vec<u64> = state.leaves[0].iter().map(|l| l.block_number).collect();
        assert_eq!(blocks, vec![9, 9, 9]);
        let mut tree = MerkleTree::new();
        let leaves = [[1u8; 32], [2; 32], [3; 32]].map(|h| field::from_be_bytes_mod_order(&h));
        tree.insert(0, &leaves).unwrap();
        assert_eq!(state.root(0), Some(tree.root()));
        assert!(state.insert(0, 5, vec![leaf(5)]).is_err());
    }

    #[test]
    fn a_gap_in_the_seed_is_an_error() {
        let text = format!("0 0 {}\n0 2 {}\n", hash(1), hash(2));
        let err = SyncState::new().seed_from_text(&text).unwrap_err();
        assert!(matches!(err, Error::Tree(_)));
    }
}
