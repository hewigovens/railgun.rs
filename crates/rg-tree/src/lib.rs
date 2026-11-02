//! Railgun's commitment Merkle tree (engine `merkletree/merkletree.ts`).
//!
//! Binary, depth 16, `poseidon([left, right])` at each node. Empty leaves hold `keccak256("Railgun") mod p`, and an empty subtree at level `i` hashes to `zeros[i]`. When a tree fills, the contract starts tree number + 1; an insertion never spans two trees.

mod error;
mod tree;

pub use error::Error;
pub use tree::{
    MerkleProof, MerkleTree, TREE_CAPACITY, TREE_DEPTH, hash_left_right, zero_value, zeros,
};
