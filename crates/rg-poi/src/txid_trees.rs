use rg_primitives::Fr;
use rg_tree::{MerkleProof, MerkleTree, TREE_CAPACITY};

use crate::Error;

/// The txid trees: one leaf per Railgun transaction, in chain order.
#[derive(Clone, Debug, Default)]
pub struct TxidTrees {
    trees: Vec<MerkleTree>,
}

impl TxidTrees {
    /// Appends leaves, opening a new tree whenever one fills.
    pub fn extend(&mut self, mut leaves: &[Fr]) -> Result<(), Error> {
        while !leaves.is_empty() {
            if self.trees.last().is_none_or(|t| t.len() == TREE_CAPACITY) {
                self.trees.push(MerkleTree::new());
            }
            let tree = self.trees.last_mut().expect("just pushed");
            let (now, later) = leaves.split_at(leaves.len().min(TREE_CAPACITY - tree.len()));
            tree.insert(tree.len(), now)?;
            leaves = later;
        }
        Ok(())
    }

    /// Global index of the newest leaf.
    pub fn latest_index(&self) -> Option<u64> {
        let last = self.trees.last()?;
        let full = (self.trees.len() - 1) as u64 * TREE_CAPACITY as u64;
        Some(full + last.len() as u64 - 1)
    }

    pub fn root(&self, tree: usize) -> Option<Fr> {
        self.trees.get(tree).map(MerkleTree::root)
    }

    /// Proof for a global index, against that tree's current root.
    pub fn proof(&self, global_index: u64) -> Result<MerkleProof, Error> {
        let tree = (global_index / TREE_CAPACITY as u64) as usize;
        let index = (global_index % TREE_CAPACITY as u64) as usize;
        let tree = self
            .trees
            .get(tree)
            .ok_or(Error::Tree(rg_tree::Error::MissingLeaf(index)))?;
        Ok(tree.proof(index)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txid_trees_roll_over_when_full() {
        let leaves: Vec<Fr> = (0..TREE_CAPACITY as u64 + 3).map(Fr::from).collect();
        let mut bulk = TxidTrees::default();
        bulk.extend(&leaves).unwrap();
        assert_eq!(bulk.latest_index(), Some(TREE_CAPACITY as u64 + 2));

        let mut second = MerkleTree::new();
        second.insert(0, &leaves[TREE_CAPACITY..]).unwrap();
        assert_eq!(bulk.root(1), Some(second.root()));

        let proof = bulk.proof(TREE_CAPACITY as u64 + 1).unwrap();
        assert!(proof.verify());
        assert_eq!(proof.leaf, leaves[TREE_CAPACITY + 1]);
    }
}
