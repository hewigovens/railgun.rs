//! Private Proof of Innocence (engine `poi/*`, `transaction/railgun-txid.ts`).
//!
//! After a transaction, its sender proves that every note it spent sits in a
//! POI list, and that the transaction's outputs are the blinded commitments
//! it claims. The aggregator then adds those to the list, which is what makes
//! the recipient's note spendable in other wallets. The contract knows nothing
//! of this.

use rg_primitives::{poseidon, Fr};
use rg_tree::{hash_left_right, zero_value, MerkleProof, MerkleTree, TREE_CAPACITY, TREE_DEPTH};

#[cfg(feature = "rpc")]
pub mod node;

/// The txid hash pads to 13 no matter which POI circuit proves it.
const TXID_MAX_ITEMS: usize = 13;
pub const CIRCUIT_INPUTS: usize = 3;
pub const CIRCUIT_OUTPUTS: usize = 3;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("tree: {0}")]
    Tree(#[from] rg_tree::Error),
    #[error("{0} inputs and {1} outputs need the 13x13 circuit")]
    TooLarge(usize, usize),
    #[error("{0} of {1} inputs have a POI merkle proof")]
    ProofCount(usize, usize),
    #[error("invalid merkle proof: {0}")]
    BadProof(&'static str),
}

pub fn global_tree_position(tree: u32, index: u32) -> u64 {
    tree as u64 * TREE_CAPACITY as u64 + index as u64
}

/// The fixed output position of a pre-transaction POI proof, which is made
/// before the transaction has a real one.
pub fn pre_transaction_position() -> u64 {
    const HARDCODED: u32 = 199_999;
    global_tree_position(HARDCODED, HARDCODED)
}

/// `createDummyMerkleProof`: a pre-transaction proof's txid path, all zeros.
pub fn dummy_txid_proof(leaf: Fr) -> MerkleProof {
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

pub fn blinded_commitment(commitment: &Fr, npk: &Fr, global_position: u64) -> Fr {
    poseidon::hash(&[*commitment, *npk, Fr::from(global_position)]).expect("arity 3")
}

fn hash_padded(items: &[Fr]) -> Fr {
    let mut padded = items.to_vec();
    padded.resize(TXID_MAX_ITEMS, zero_value());
    poseidon::hash(&padded).expect("arity 13")
}

pub fn railgun_txid(nullifiers: &[Fr], commitments: &[Fr], bound_params_hash: &Fr) -> Fr {
    poseidon::hash(&[
        hash_padded(nullifiers),
        hash_padded(commitments),
        *bound_params_hash,
    ])
    .expect("arity 3")
}

pub fn txid_leaf(railgun_txid: &Fr, utxo_tree_in: u32, global_position_out: u64) -> Fr {
    poseidon::hash(&[
        *railgun_txid,
        Fr::from(utxo_tree_in),
        Fr::from(global_position_out),
    ])
    .expect("arity 3")
}

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

    /// Index of the newest leaf over all trees.
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

/// A spent note: enough to rebuild its commitment inside the circuit.
#[derive(Clone, Debug)]
pub struct SpentNote {
    pub random: Fr,
    pub value: u128,
    pub position: u32,
}

/// A created note. Unshields are not supported yet.
#[derive(Clone, Debug)]
pub struct OutputNote {
    pub npk: Fr,
    pub value: u128,
}

/// A list's sibling path for one spent note, from the aggregator.
#[derive(Clone, Debug)]
pub struct ListProof {
    pub root: Fr,
    pub indices: Fr,
    pub elements: [Fr; TREE_DEPTH],
}

/// `POIEngineProofInputs` for a transaction without an unshield.
#[derive(Clone, Debug)]
pub struct ProofInputs {
    pub txid_proof: MerkleProof,
    pub bound_params_hash: Fr,
    pub nullifiers: Vec<Fr>,
    pub commitments_out: Vec<Fr>,
    pub spending_public_key: [Fr; 2],
    pub nullifying_key: Fr,
    pub token_hash: Fr,
    pub spent: Vec<SpentNote>,
    pub utxo_tree_in: u32,
    pub outputs: Vec<OutputNote>,
    pub global_position_out: u64,
    pub list_proofs: Vec<ListProof>,
}

fn pad(values: Vec<Fr>, len: usize, with: Fr) -> Vec<Fr> {
    let mut out = values;
    out.resize(len, with);
    out
}

impl ProofInputs {
    /// The 3x3 circuit's input signals (`Prover.formatPOIInputs`). Empty slots
    /// hold the Merkle zero, except values and POI indices, which hold 0.
    pub fn circuit_inputs(&self) -> Result<Vec<(String, Vec<Fr>)>, Error> {
        let (ins, outs) = (self.nullifiers.len(), self.commitments_out.len());
        if ins > CIRCUIT_INPUTS || outs > CIRCUIT_OUTPUTS {
            return Err(Error::TooLarge(ins, outs));
        }
        if self.list_proofs.len() != ins {
            return Err(Error::ProofCount(self.list_proofs.len(), ins));
        }
        if !self.txid_proof.verify() {
            return Err(Error::BadProof("txid"));
        }
        let zero = zero_value();
        let none = Fr::from(0u64);
        let fr = |v: u128| Fr::from(v);
        let mut path_elements = Vec::with_capacity(CIRCUIT_INPUTS * TREE_DEPTH);
        for p in &self.list_proofs {
            path_elements.extend_from_slice(&p.elements);
        }
        path_elements.resize(CIRCUIT_INPUTS * TREE_DEPTH, zero);

        let spent = |f: &dyn Fn(&SpentNote) -> Fr| self.spent.iter().map(f).collect::<Vec<_>>();
        let out = |f: &dyn Fn(&OutputNote) -> Fr| self.outputs.iter().map(f).collect::<Vec<_>>();
        let list =
            |f: &dyn Fn(&ListProof) -> Fr| self.list_proofs.iter().map(f).collect::<Vec<_>>();
        let signal = |name: &str, values: Vec<Fr>| (name.to_string(), values);

        Ok(vec![
            signal(
                "anyRailgunTxidMerklerootAfterTransaction",
                vec![self.txid_proof.root],
            ),
            signal("boundParamsHash", vec![self.bound_params_hash]),
            signal(
                "nullifiers",
                pad(self.nullifiers.clone(), CIRCUIT_INPUTS, zero),
            ),
            signal(
                "commitmentsOut",
                pad(self.commitments_out.clone(), CIRCUIT_OUTPUTS, zero),
            ),
            signal("spendingPublicKey", self.spending_public_key.to_vec()),
            signal("nullifyingKey", vec![self.nullifying_key]),
            signal("token", vec![self.token_hash]),
            signal("randomsIn", pad(spent(&|s| s.random), CIRCUIT_INPUTS, zero)),
            signal(
                "valuesIn",
                pad(spent(&|s| fr(s.value)), CIRCUIT_OUTPUTS, none),
            ),
            signal(
                "utxoPositionsIn",
                pad(spent(&|s| Fr::from(s.position)), CIRCUIT_INPUTS, zero),
            ),
            signal("utxoTreeIn", vec![Fr::from(self.utxo_tree_in)]),
            signal("npksOut", pad(out(&|o| o.npk), CIRCUIT_OUTPUTS, zero)),
            signal(
                "valuesOut",
                pad(out(&|o| fr(o.value)), CIRCUIT_OUTPUTS, none),
            ),
            signal(
                "utxoBatchGlobalStartPositionOut",
                vec![Fr::from(self.global_position_out)],
            ),
            signal("railgunTxidIfHasUnshield", vec![none]),
            signal(
                "railgunTxidMerkleProofIndices",
                vec![Fr::from(self.txid_proof.indices)],
            ),
            signal(
                "railgunTxidMerkleProofPathElements",
                self.txid_proof.elements.to_vec(),
            ),
            signal(
                "poiMerkleroots",
                pad(list(&|p| p.root), CIRCUIT_INPUTS, zero),
            ),
            signal(
                "poiInMerkleProofIndices",
                pad(list(&|p| p.indices), CIRCUIT_INPUTS, none),
            ),
            signal("poiInMerkleProofPathElements", path_elements),
        ])
    }

    /// Public signals the circuit should produce, given the blinded commitments.
    pub fn public_inputs(&self, blinded_out: &[Fr]) -> Vec<Fr> {
        let zero = zero_value();
        let mut out = pad(blinded_out.to_vec(), CIRCUIT_OUTPUTS, Fr::from(0u64));
        out.push(self.txid_proof.root);
        out.push(Fr::from(0u64));
        let roots = self.list_proofs.iter().map(|p| p.root).collect();
        out.extend(pad(roots, CIRCUIT_INPUTS, zero));
        out
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

    #[test]
    fn dummy_proof_verifies() {
        assert!(dummy_txid_proof(Fr::from(5u64)).verify());
    }

    #[test]
    fn global_position_counts_full_trees() {
        assert_eq!(global_tree_position(2, 2032), 2 * 65536 + 2032);
    }
}
