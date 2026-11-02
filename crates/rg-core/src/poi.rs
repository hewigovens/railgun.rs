use std::collections::BTreeMap;
use std::path::Path;

use rg_keys::WalletKeys;
use rg_notes::note::note_public_key;
use rg_poi::node::{blinded_hex, Node, AGGREGATOR, REQUIRED_LIST};
use rg_poi::{
    blinded_commitment, global_tree_position, railgun_txid, txid_leaf, OutputNote, ProofInputs,
    SpentNote, TxidTrees, MINI_CIRCUIT,
};
use rg_primitives::{field, Fr};
use rg_sync::squid::{fetch_transactions, SquidTransaction};
use serde_json::{json, Value};

use crate::transfer::prove;
use crate::{ChainStore, Client, Error};

/// Blinded commitment to the aggregator's word for it.
pub type PoiStatus = BTreeMap<String, String>;

/// A POI proof ready to submit. `data` is `TransactProofData`.
#[derive(Clone, Debug)]
pub struct PoiProof {
    /// What to ask the aggregator about: blinded commitment and its kind.
    pub blinded: Vec<(String, &'static str)>,
    pub data: Value,
}

fn fr(b: &[u8]) -> Fr {
    field::from_be_bytes_mod_order(b)
}

fn frs(items: &[[u8; 32]]) -> Vec<Fr> {
    items.iter().map(|x| fr(x)).collect()
}

fn hex32(x: &Fr) -> String {
    hex::encode(field::to_be_bytes(x))
}

fn txid_trees(txs: &[SquidTransaction]) -> Result<TxidTrees, Error> {
    let leaves: Vec<Fr> = txs
        .iter()
        .map(|t| {
            let txid = railgun_txid(
                &frs(&t.nullifiers),
                &frs(&t.commitments),
                &fr(&t.bound_params_hash),
            );
            let out = global_tree_position(t.utxo_tree_out, t.utxo_batch_start_position_out);
            txid_leaf(&txid, t.utxo_tree_in, out)
        })
        .collect();
    let mut trees = TxidTrees::default();
    trees.extend(&leaves)?;
    Ok(trees)
}

impl<S: ChainStore> Client<S> {
    fn node(&self) -> Node {
        Node::new(AGGREGATOR, self.network.chain_id)
    }

    /// Proves POI for a transaction this wallet sent. `dir` holds the POI
    /// 3x3 `circuit.wasm` and `circuit.zkey`. The wallet must be synced past the
    /// transaction, and every note it spent must already be in the list.
    pub fn prove_poi(
        &self,
        keys: &WalletKeys,
        tx_hash: &[u8; 32],
        dir: &Path,
    ) -> Result<PoiProof, Error> {
        let unprovable = |why| Error::NotProvable(hex::encode(tx_hash), why);
        let url = self
            .network
            .squid
            .ok_or(Error::NoSquid(self.network.name))?;
        let txs = fetch_transactions(url)?;
        let index = txs
            .iter()
            .position(|t| &t.transaction_hash == tx_hash)
            .ok_or_else(|| unprovable("not indexed yet"))?;
        let tx = &txs[index];
        let trees = txid_trees(&txs)?;

        let scan = self.scan(keys);
        let spent = scan
            .txos_for_nullifiers(tx.utxo_tree_in, &tx.nullifiers)
            .ok_or_else(|| unprovable("a spent note is not ours"))?;
        let blinded_in: Vec<String> = spent
            .iter()
            .map(|t| {
                let npk = note_public_key(&keys.master_public_key, &t.random);
                let at = global_tree_position(t.tree, t.position);
                blinded_hex(&blinded_commitment(&fr(&t.commitment), &npk, at))
            })
            .collect();

        let notes_out = &tx.commitments[..tx.commitments.len() - usize::from(tx.has_unshield)];
        let start = tx.utxo_batch_start_position_out;
        let sent = notes_out
            .iter()
            .enumerate()
            .map(|(i, c)| {
                scan.sent.iter().find(|s| {
                    s.tree == tx.utxo_tree_out
                        && s.position == start + i as u32
                        && &s.commitment == c
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| unprovable("an output is not ours"))?;
        let outputs: Vec<OutputNote> = sent
            .iter()
            .map(|s| OutputNote {
                npk: note_public_key(&s.receiver_master_public_key, &s.random),
                value: s.value,
            })
            .collect();
        let start_out = global_tree_position(tx.utxo_tree_out, start);
        let blinded_out: Vec<Fr> = sent
            .iter()
            .zip(&outputs)
            .enumerate()
            .map(|(i, (s, o))| blinded_commitment(&fr(&s.commitment), &o.npk, start_out + i as u64))
            .collect();

        let unshield_txid = tx.has_unshield.then(|| {
            railgun_txid(
                &frs(&tx.nullifiers),
                &frs(&tx.commitments),
                &fr(&tx.bound_params_hash),
            )
        });
        let inputs = ProofInputs {
            txid_proof: trees.proof(index as u64)?,
            bound_params_hash: fr(&tx.bound_params_hash),
            nullifiers: frs(&tx.nullifiers),
            commitments_out: frs(&tx.commitments),
            spending_public_key: [keys.spending_public_key.x, keys.spending_public_key.y],
            nullifying_key: keys.nullifying_key,
            token_hash: fr(&spent[0].token_hash),
            spent: spent
                .iter()
                .map(|t| SpentNote {
                    random: fr(&t.random),
                    value: t.value,
                    position: t.position,
                })
                .collect(),
            utxo_tree_in: tx.utxo_tree_in,
            outputs,
            global_position_out: start_out,
            unshield_txid,
            list_proofs: self.node().merkle_proofs(REQUIRED_LIST, &blinded_in)?,
        };

        let (proof, public) = prove(dir, &inputs.circuit_inputs(MINI_CIRCUIT)?)?;
        if public != inputs.public_inputs(MINI_CIRCUIT, &blinded_out) {
            return Err(Error::BadProof);
        }

        // snarkjs's projective third coordinate is dropped, as the engine does.
        let p = rg_prover::proof_to_json(&proof);
        let two = |v: &Value| json!(v.as_array().map(|a| &a[..2]));
        let blinded_out: Vec<String> = blinded_out.iter().map(blinded_hex).collect();
        // The aggregator tracks an unshield by its txid (`getForUnshield`).
        let unshield = unshield_txid.as_ref().map(blinded_hex);
        let data = json!({
            "snarkProof": {"pi_a": two(&p["pi_a"]), "pi_b": two(&p["pi_b"]), "pi_c": two(&p["pi_c"])},
            "poiMerkleroots": inputs.list_proofs.iter().map(|l| hex32(&l.root)).collect::<Vec<_>>(),
            "txidMerkleroot": hex32(&inputs.txid_proof.root),
            "txidMerklerootIndex": txs.len() - 1,
            "blindedCommitmentsOut": blinded_out,
            "railgunTxidIfHasUnshield": unshield.as_deref().unwrap_or("0x00"),
        });
        let blinded = blinded_out
            .into_iter()
            .map(|b| (b, "Transact"))
            .chain(unshield.map(|b| (b, "Unshield")))
            .collect();
        Ok(PoiProof { blinded, data })
    }

    pub fn submit_poi(&self, proof: &PoiProof) -> Result<(), Error> {
        Ok(self
            .node()
            .submit_transact_proof(REQUIRED_LIST, proof.data.clone())?)
    }

    pub fn poi_status(&self, proof: &PoiProof) -> Result<PoiStatus, Error> {
        Ok(self.node().pois_per_list(REQUIRED_LIST, &proof.blinded)?)
    }
}
