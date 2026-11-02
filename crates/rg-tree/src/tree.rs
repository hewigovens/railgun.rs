use std::sync::OnceLock;

use rg_primitives::{Fr, field, poseidon};
use tiny_keccak::{Hasher, Keccak};

use crate::Error;

pub const TREE_DEPTH: usize = 16;
pub const TREE_CAPACITY: usize = 1 << TREE_DEPTH;

/// `keccak256(utf8("Railgun")) mod p`.
pub fn zero_value() -> Fr {
    let mut h = Keccak::v256();
    h.update(b"Railgun");
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    field::from_be_bytes_mod_order(&out)
}

/// `zeros[0..=16]`: the root of an empty subtree at each level.
pub fn zeros() -> &'static [Fr; TREE_DEPTH + 1] {
    static Z: OnceLock<[Fr; TREE_DEPTH + 1]> = OnceLock::new();
    Z.get_or_init(|| {
        let mut z = [zero_value(); TREE_DEPTH + 1];
        for i in 1..=TREE_DEPTH {
            z[i] = hash_left_right(&z[i - 1], &z[i - 1]);
        }
        z
    })
}

pub fn hash_left_right(left: &Fr, right: &Fr) -> Fr {
    poseidon::hash(&[*left, *right]).expect("arity 2")
}

/// One tree. Level 0 holds the leaves; each level stores only the nodes that have at least one leaf under them, so memory grows with the leaf count.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    levels: Vec<Vec<Fr>>,
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Sibling path for a leaf, bottom to top. `indices` is the leaf position; bit `i` says whether the node at level `i` is a right child.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub leaf: Fr,
    pub elements: [Fr; TREE_DEPTH],
    pub indices: u64,
    pub root: Fr,
}

impl MerkleProof {
    pub fn verify(&self) -> bool {
        let mut node = self.leaf;
        for (level, sibling) in self.elements.iter().enumerate() {
            node = if (self.indices >> level) & 1 == 1 {
                hash_left_right(sibling, &node)
            } else {
                hash_left_right(&node, sibling)
            };
        }
        node == self.root
    }
}

impl MerkleTree {
    pub fn new() -> Self {
        MerkleTree {
            levels: vec![Vec::new(); TREE_DEPTH + 1],
        }
    }

    pub fn len(&self) -> usize {
        self.levels[0].len()
    }

    pub fn is_empty(&self) -> bool {
        self.levels[0].is_empty()
    }

    pub fn leaf(&self, index: usize) -> Option<&Fr> {
        self.levels[0].get(index)
    }

    /// Appends leaves at `start`, which must equal the current length, and rehashes the nodes above them.
    pub fn insert(&mut self, start: usize, leaves: &[Fr]) -> Result<(), Error> {
        if start != self.len() {
            return Err(Error::NotContiguous {
                start,
                len: self.len(),
            });
        }
        if start + leaves.len() > TREE_CAPACITY {
            return Err(Error::Overflow {
                start,
                count: leaves.len(),
            });
        }
        if leaves.is_empty() {
            return Ok(());
        }
        self.levels[0].extend_from_slice(leaves);
        let zeros = zeros();
        let (mut lo, mut hi) = (start, start + leaves.len() - 1);
        for level in 0..TREE_DEPTH {
            let (below, above) = self.levels.split_at_mut(level + 1);
            let children = &below[level];
            let parents = &mut above[0];
            let (plo, phi) = (lo >> 1, hi >> 1);
            if parents.len() <= phi {
                parents.resize(phi + 1, zeros[level + 1]);
            }
            for (p, slot) in parents.iter_mut().enumerate().take(phi + 1).skip(plo) {
                let left = children.get(2 * p).unwrap_or(&zeros[level]);
                let right = children.get(2 * p + 1).unwrap_or(&zeros[level]);
                *slot = hash_left_right(left, right);
            }
            lo = plo;
            hi = phi;
        }
        Ok(())
    }

    pub fn root(&self) -> Fr {
        self.levels[TREE_DEPTH]
            .first()
            .copied()
            .unwrap_or(zeros()[TREE_DEPTH])
    }

    pub fn proof(&self, index: usize) -> Result<MerkleProof, Error> {
        let leaf = *self.leaf(index).ok_or(Error::MissingLeaf(index))?;
        let zeros = zeros();
        let mut elements = [Fr::from(0u64); TREE_DEPTH];
        let mut i = index;
        for (level, el) in elements.iter_mut().enumerate() {
            *el = *self.levels[level].get(i ^ 1).unwrap_or(&zeros[level]);
            i >>= 1;
        }
        Ok(MerkleProof {
            leaf,
            elements,
            indices: index as u64,
            root: self.root(),
        })
    }
}
