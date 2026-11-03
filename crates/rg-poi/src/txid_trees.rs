use rg_primitives::Fr;
use rg_tree::{MerkleProof, MerkleTree, TREE_CAPACITY, TREE_DEPTH, hash_left_right};

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

    /// `createDummyMerkleProof`: `leaf` first in a tree of zeros (0, not the Merkle zero), which is what a pre-transaction POI proves against, since its txid is in no tree yet.
    pub fn dummy_proof(leaf: Fr) -> MerkleProof {
        let elements = [Fr::from(0u64); TREE_DEPTH];
        let root = elements
            .iter()
            .fold(leaf, |node, sibling| hash_left_right(&node, sibling));
        MerkleProof {
            leaf,
            elements,
            indices: 0,
            root,
        }
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

        let mut second = MerkleTree::new();
        second.insert(0, &leaves[TREE_CAPACITY..]).unwrap();
        assert_eq!(bulk.root(1), Some(second.root()));

        let proof = bulk.proof(TREE_CAPACITY as u64 + 1).unwrap();
        assert!(proof.verify());
        assert_eq!(proof.leaf, leaves[TREE_CAPACITY + 1]);
    }

    // Engine 9.6.0 `createDummyMerkleProof` of the txid in `txid.rs`'s test.
    #[test]
    fn dummy_proof_matches_the_engine() {
        let txid = "21f03b068a26fd888a053c3318f9bdb2abe393a61a1c54da8e906b49fa607d29";
        let leaf = rg_primitives::field::from_be_bytes_mod_order(&hex::decode(txid).unwrap());
        let proof = TxidTrees::dummy_proof(leaf);
        assert!(proof.verify());
        assert_eq!(
            hex::encode(rg_primitives::field::to_be_bytes(&proof.root)),
            "03bff6e840d4c99138c3a4096b48cd5d40efa808f9b5e54bbaf17a2d5f29a05b"
        );
    }
}
