use rg_primitives::Fr;
use rg_tree::{MerkleProof, TREE_DEPTH, zero_value};

use crate::Error;

/// POI circuits take n inputs and n outputs: 3 or 13.
pub const MINI_CIRCUIT: usize = 3;

pub const FULL_CIRCUIT: usize = 13;

/// A spent note: enough to rebuild its commitment inside the circuit.
#[derive(Clone, Debug)]
pub struct SpentNote {
    pub random: Fr,
    pub value: u128,
    pub position: u32,
}

/// A created note; an unshield has none, so it is not one of these.
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

/// `POIEngineProofInputs`.
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
    /// The Railgun txid, when the last commitment is an unshield.
    pub unshield_txid: Option<Fr>,
    pub list_proofs: Vec<ListProof>,
}

fn pad(values: Vec<Fr>, len: usize, with: Fr) -> Vec<Fr> {
    let mut out = values;
    out.resize(len, with);
    out
}

impl ProofInputs {
    /// Input signals for an n x n circuit (`Prover.formatPOIInputs`). Empty slots hold the Merkle zero, except values and POI indices, which hold 0.
    pub fn circuit_inputs(&self, n: usize) -> Result<Vec<(String, Vec<Fr>)>, Error> {
        let (ins, outs) = (self.nullifiers.len(), self.commitments_out.len());
        if ins > n || outs > n {
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
        let mut path_elements = Vec::with_capacity(n * TREE_DEPTH);
        for p in &self.list_proofs {
            path_elements.extend_from_slice(&p.elements);
        }
        path_elements.resize(n * TREE_DEPTH, zero);

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
            signal("nullifiers", pad(self.nullifiers.clone(), n, zero)),
            signal("commitmentsOut", pad(self.commitments_out.clone(), n, zero)),
            signal("spendingPublicKey", self.spending_public_key.to_vec()),
            signal("nullifyingKey", vec![self.nullifying_key]),
            signal("token", vec![self.token_hash]),
            signal("randomsIn", pad(spent(&|s| s.random), n, zero)),
            signal("valuesIn", pad(spent(&|s| fr(s.value)), n, none)),
            signal(
                "utxoPositionsIn",
                pad(spent(&|s| Fr::from(s.position)), n, zero),
            ),
            signal("utxoTreeIn", vec![Fr::from(self.utxo_tree_in)]),
            signal("npksOut", pad(out(&|o| o.npk), n, zero)),
            signal("valuesOut", pad(out(&|o| fr(o.value)), n, none)),
            signal(
                "utxoBatchGlobalStartPositionOut",
                vec![Fr::from(self.global_position_out)],
            ),
            signal(
                "railgunTxidIfHasUnshield",
                vec![self.unshield_txid.unwrap_or(none)],
            ),
            signal(
                "railgunTxidMerkleProofIndices",
                vec![Fr::from(self.txid_proof.indices)],
            ),
            signal(
                "railgunTxidMerkleProofPathElements",
                self.txid_proof.elements.to_vec(),
            ),
            signal("poiMerkleroots", pad(list(&|p| p.root), n, zero)),
            signal(
                "poiInMerkleProofIndices",
                pad(list(&|p| p.indices), n, none),
            ),
            signal("poiInMerkleProofPathElements", path_elements),
        ])
    }

    /// Public signals the circuit should produce, given the blinded commitments.
    pub fn public_inputs(&self, n: usize, blinded_out: &[Fr]) -> Vec<Fr> {
        let zero = zero_value();
        let mut out = pad(blinded_out.to_vec(), n, Fr::from(0u64));
        out.push(self.txid_proof.root);
        out.push(self.unshield_txid.unwrap_or(Fr::from(0u64)));
        let roots = self.list_proofs.iter().map(|p| p.root).collect();
        out.extend(pad(roots, n, zero));
        out
    }
}

#[cfg(test)]
mod tests {
    use rg_tree::MerkleTree;

    use super::*;

    #[test]
    fn an_unshield_puts_its_txid_in_the_public_signals() {
        let leaf = Fr::from(1u64);
        let mut tree = MerkleTree::new();
        tree.insert(0, &[leaf]).unwrap();
        let txid = Fr::from(9u64);
        let inputs = ProofInputs {
            txid_proof: tree.proof(0).unwrap(),
            bound_params_hash: Fr::from(0u64),
            nullifiers: Vec::new(),
            commitments_out: Vec::new(),
            spending_public_key: [Fr::from(0u64); 2],
            nullifying_key: Fr::from(0u64),
            token_hash: Fr::from(0u64),
            spent: Vec::new(),
            utxo_tree_in: 0,
            outputs: Vec::new(),
            global_position_out: 0,
            unshield_txid: Some(txid),
            list_proofs: Vec::new(),
        };
        // Three blinded outputs, the txid root, then the unshield signal.
        assert_eq!(inputs.public_inputs(MINI_CIRCUIT, &[])[4], txid);
    }
}
