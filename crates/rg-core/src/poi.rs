use std::collections::BTreeMap;

use rg_keys::{ViewOnlyKeys, WalletKeys};
use rg_notes::note::note_public_key;
use rg_poi::node::{AGGREGATOR, Node, REQUIRED_LIST, blinded_hex};
use rg_poi::{
    FULL_CIRCUIT, MINI_CIRCUIT, OutputNote, PRE_TRANSACTION_POSITION, ProofInputs, SpentNote,
    TxidTrees, blinded_commitment, global_tree_position, railgun_txid, txid_leaf,
};
use rg_primitives::{Fr, field};
use rg_sync::squid::{SquidTransaction, fetch_transactions_after, fetch_transactions_in_blocks};
use rg_tree::TREE_CAPACITY;
use rg_tx::TransferParams;
use rg_wallet::{ScanResult, Txo};
use serde_json::{Value, json};

use crate::transfer::prove;
use crate::{Artifacts, ChainStore, Circuit, Client, Error};

/// Blinded commitment to the aggregator's word for it.
pub type PoiStatus = BTreeMap<String, String>;

/// POI proofs for one EVM transaction, one per Railgun transaction in it, ready to submit. Each `data` is a `TransactProofData`.
#[derive(Clone, Debug)]
pub struct PoiProof {
    /// What to ask the aggregator about: blinded commitment and its kind.
    pub blinded: Vec<(String, &'static str)>,
    pub data: Vec<Value>,
}

/// Every txid leaf, and the tree over them.
struct Txids {
    leaves: Vec<Fr>,
    trees: TxidTrees,
}

impl Txids {
    fn latest(&self) -> u64 {
        self.leaves.len() as u64 - 1
    }
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

fn leaf(t: &SquidTransaction) -> Fr {
    let txid = railgun_txid(
        &frs(&t.nullifiers),
        &frs(&t.commitments),
        &fr(&t.bound_params_hash),
    );
    let out = global_tree_position(t.utxo_tree_out, t.utxo_batch_start_position_out);
    txid_leaf(&txid, t.utxo_tree_in, out)
}

/// Proves on the smallest circuit that fits, unless `size` is given, and checks the public signals. snarkjs's projective third coordinate is dropped, as the engine does.
fn prove_poi_inputs(
    inputs: &ProofInputs,
    blinded_out: &[Fr],
    size: Option<usize>,
    artifacts: &Artifacts,
) -> Result<Value, Error> {
    let fits = inputs.nullifiers.len().max(inputs.commitments_out.len()) <= MINI_CIRCUIT;
    let n = size.unwrap_or(if fits { MINI_CIRCUIT } else { FULL_CIRCUIT });
    let (proof, public) = prove(artifacts, Circuit::Poi(n), &inputs.circuit_inputs(n)?)?;
    if public != inputs.public_inputs(n, blinded_out) {
        return Err(Error::BadProof);
    }
    let p = rg_prover::proof_to_json(&proof);
    let two = |v: &Value| json!(v.as_array().map(|a| &a[..2]));
    Ok(json!({"pi_a": two(&p["pi_a"]), "pi_b": two(&p["pi_b"]), "pi_c": two(&p["pi_c"])}))
}

/// The blinded commitment the aggregator files a note under: `poseidon(commitment, npk, global position)`.
pub(crate) fn blinded_input(keys: &ViewOnlyKeys, t: &Txo) -> String {
    let npk = note_public_key(&keys.master_public_key, &t.random);
    let at = global_tree_position(t.tree, t.position);
    blinded_hex(&blinded_commitment(&fr(&t.commitment), &npk, at))
}

/// Blocks per window a transaction is looked up in, aligned so the window does not point at the block.
const LOOKUP_BLOCKS: u64 = 100_000;

struct TxidFetch {
    leaves: Vec<Fr>,
    settled: Vec<(String, [u8; 32])>,
    recent: Vec<SquidTransaction>,
}

impl<S: ChainStore> Client<S> {
    pub(crate) fn node(&self) -> Node {
        Node::new(AGGREGATOR, self.network.chain_id)
    }

    /// Every txid leaf, the transactions behind the ones not stored yet, and the leaves to store once the aggregator has validated the root. Hashing leaves is the slow part of a POI proof, so leaves past the reorg window are stored and later runs fetch only what came after.
    fn txid_leaves(&self, url: &str) -> Result<TxidFetch, Error> {
        let (stored, last_id) = self.store.txid_leaves()?;
        let recent = fetch_transactions_after(url, last_id.as_deref().unwrap_or(""))?;
        let final_block = self
            .rpc
            .block_number()?
            .saturating_sub(self.network.reorg_window);

        let mut leaves: Vec<Fr> = stored.iter().map(|l| fr(l)).collect();
        let mut settled = Vec::new();
        for t in &recent {
            let hash = leaf(t);
            leaves.push(hash);
            if t.block_number <= final_block {
                settled.push((t.id.clone(), field::to_be_bytes(&hash)));
            }
        }
        Ok(TxidFetch {
            leaves,
            settled,
            recent,
        })
    }

    /// The Railgun transactions in `tx_hash`, from those just fetched or else from a fixed window of blocks around it, never by the hash itself.
    fn transactions_in(
        &self,
        url: &str,
        tx_hash: &[u8; 32],
        recent: Vec<SquidTransaction>,
    ) -> Result<Vec<SquidTransaction>, Error> {
        let ours = |txs: Vec<SquidTransaction>| -> Vec<SquidTransaction> {
            txs.into_iter()
                .filter(|t| &t.transaction_hash == tx_hash)
                .collect()
        };
        let txs = ours(recent);
        if !txs.is_empty() {
            return Ok(txs);
        }
        let Some(block) = self
            .state
            .nullifiers
            .values()
            .find(|r| &r.transaction_hash == tx_hash)
            .map(|r| r.block_number)
        else {
            return Ok(Vec::new());
        };
        let from = block - block % LOOKUP_BLOCKS;
        Ok(ours(fetch_transactions_in_blocks(
            url,
            from,
            from + LOOKUP_BLOCKS - 1,
        )?))
    }

    /// Proves POI for a transaction this wallet sent, on the smallest circuit that fits. The wallet must be synced past the transaction, and every note it spent must already be in the list.
    pub fn prove_poi(
        &mut self,
        keys: &WalletKeys,
        tx_hash: &[u8; 32],
        artifacts: &Artifacts,
    ) -> Result<PoiProof, Error> {
        self.prove_poi_on(keys, tx_hash, artifacts, None)
    }

    /// `prove_poi` with the circuit size forced, as the engine's `provePOIForInputsOutputs` allows. Both sizes are valid for a small transaction.
    pub fn prove_poi_on(
        &mut self,
        keys: &WalletKeys,
        tx_hash: &[u8; 32],
        artifacts: &Artifacts,
        size: Option<usize>,
    ) -> Result<PoiProof, Error> {
        let unprovable = |why| Error::NotProvable(hex::encode(tx_hash), why);
        let url = self
            .network
            .squid
            .ok_or(Error::NoSquid(self.network.name))?;
        let TxidFetch {
            leaves,
            settled,
            recent,
        } = self.txid_leaves(url)?;
        let txs = self.transactions_in(url, tx_hash, recent)?;
        if txs.is_empty() {
            return Err(unprovable("not synced or not indexed yet"));
        }
        let mut trees = TxidTrees::default();
        trees.extend(&leaves)?;
        let txids = Txids { leaves, trees };

        let capacity = TREE_CAPACITY as u64;
        let latest = txids.latest();
        let (tree, position) = ((latest / capacity) as u32, (latest % capacity) as u32);
        let root = txids.trees.root(tree as usize).ok_or(Error::BadProof)?;
        if !self
            .node()
            .validate_txid_merkleroot(tree, position, &root)?
        {
            return Err(unprovable(
                "the aggregator has not validated this txid root yet",
            ));
        }
        // Only now, so leaves the aggregator would reject never reach the store.
        self.store.append_txid_leaves(&settled)?;

        let scan = self.scan(keys);
        let mut proof = PoiProof {
            blinded: Vec::new(),
            data: Vec::new(),
        };
        for tx in &txs {
            let one = self.prove_railgun_transaction(keys, &scan, tx, &txids, artifacts, size)?;
            proof.blinded.extend(one.blinded);
            proof.data.extend(one.data);
        }
        Ok(proof)
    }

    /// The POI proof for one Railgun transaction.
    fn prove_railgun_transaction(
        &self,
        keys: &WalletKeys,
        scan: &ScanResult,
        tx: &SquidTransaction,
        txids: &Txids,
        artifacts: &Artifacts,
        size: Option<usize>,
    ) -> Result<PoiProof, Error> {
        let unprovable = |why| Error::NotProvable(hex::encode(tx.transaction_hash), why);
        let tx_leaf = leaf(tx);
        let index = txids
            .leaves
            .iter()
            .position(|l| l == &tx_leaf)
            .ok_or_else(|| unprovable("not in the txid tree yet"))? as u64;

        let spent = scan
            .txos_for_nullifiers(tx.utxo_tree_in, &tx.nullifiers)
            .ok_or_else(|| unprovable("a spent note is not ours"))?;
        let blinded_in: Vec<String> = spent.iter().map(|t| blinded_input(keys, t)).collect();

        let notes_out = tx
            .commitments
            .len()
            .checked_sub(usize::from(tx.has_unshield))
            .map(|n| &tx.commitments[..n])
            .ok_or_else(|| unprovable("an unshield with no commitment"))?;
        let token_hash = spent
            .first()
            .map(|t| fr(&t.token_hash))
            .ok_or_else(|| unprovable("no notes spent"))?;
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
            txid_proof: txids.trees.proof(index)?,
            bound_params_hash: fr(&tx.bound_params_hash),
            nullifiers: frs(&tx.nullifiers),
            commitments_out: frs(&tx.commitments),
            spending_public_key: [keys.spending_public_key.x, keys.spending_public_key.y],
            nullifying_key: keys.nullifying_key,
            token_hash,
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

        let snark_proof = prove_poi_inputs(&inputs, &blinded_out, size, artifacts)?;
        let blinded_out: Vec<String> = blinded_out.iter().map(blinded_hex).collect();
        // The aggregator tracks an unshield by its txid (`getForUnshield`).
        let unshield = unshield_txid.as_ref().map(blinded_hex);
        let data = json!({
            "snarkProof": snark_proof,
            "poiMerkleroots": inputs.list_proofs.iter().map(|l| hex32(&l.root)).collect::<Vec<_>>(),
            "txidMerkleroot": hex32(&inputs.txid_proof.root),
            "txidMerklerootIndex": txids.latest(),
            "blindedCommitmentsOut": blinded_out,
            "railgunTxidIfHasUnshield": unshield.as_deref().unwrap_or("0x00"),
        });
        let blinded = blinded_out
            .into_iter()
            .map(|b| (b, "Transact"))
            .chain(unshield.map(|b| (b, "Unshield")))
            .collect();
        Ok(PoiProof {
            blinded,
            data: vec![data],
        })
    }

    /// A pre-transaction POI for a planned transaction (`generatePreTransactionPOI`): the same proof, made before the transaction exists, against a stand-in txid tree and output position. A broadcaster checks it, and passes it to the aggregator, before it pays gas. Returns the txid leaf hash the proof is filed under.
    pub(crate) fn prove_pre_transaction(
        &self,
        keys: &WalletKeys,
        params: &TransferParams,
        artifacts: &Artifacts,
    ) -> Result<(String, Value), Error> {
        let prepared = params.prepare(keys)?;
        let txid = railgun_txid(
            &prepared.nullifiers,
            &prepared.commitments,
            &prepared.bound_params_hash,
        );
        let tree = u32::from(params.tree);
        let leaf = txid_leaf(&txid, tree, PRE_TRANSACTION_POSITION);
        let blinded_in: Vec<String> = params
            .inputs
            .iter()
            .map(|i| {
                let npk = note_public_key(&keys.master_public_key, &i.random);
                let at = global_tree_position(tree, i.position as u32);
                blinded_hex(&blinded_commitment(&i.proof.leaf, &npk, at))
            })
            .collect();
        let outputs: Vec<OutputNote> = params
            .outputs
            .iter()
            .map(|o| OutputNote {
                npk: o.note.note_public_key(),
                value: o.note.value,
            })
            .collect();
        let blinded_out: Vec<Fr> = prepared
            .commitments
            .iter()
            .zip(&outputs)
            .enumerate()
            .map(|(i, (c, o))| blinded_commitment(c, &o.npk, PRE_TRANSACTION_POSITION + i as u64))
            .collect();
        let unshield_txid = params.unshield.is_some().then_some(txid);
        let inputs = ProofInputs {
            txid_proof: TxidTrees::dummy_proof(leaf),
            bound_params_hash: prepared.bound_params_hash,
            nullifiers: prepared.nullifiers,
            commitments_out: prepared.commitments,
            spending_public_key: [keys.spending_public_key.x, keys.spending_public_key.y],
            nullifying_key: keys.nullifying_key,
            token_hash: fr(&params.token_hash),
            spent: params
                .inputs
                .iter()
                .map(|i| SpentNote {
                    random: fr(&i.random),
                    value: i.value,
                    position: i.position as u32,
                })
                .collect(),
            utxo_tree_in: tree,
            outputs,
            global_position_out: PRE_TRANSACTION_POSITION,
            unshield_txid,
            list_proofs: self.node().merkle_proofs(REQUIRED_LIST, &blinded_in)?,
        };
        let snark_proof = prove_poi_inputs(&inputs, &blinded_out, None, artifacts)?;
        let unshield = unshield_txid.as_ref().map(blinded_hex);
        let data = json!({
            "snarkProof": snark_proof,
            "txidMerkleroot": hex32(&inputs.txid_proof.root),
            "poiMerkleroots": inputs.list_proofs.iter().map(|l| hex32(&l.root)).collect::<Vec<_>>(),
            "blindedCommitmentsOut": blinded_out.iter().map(blinded_hex).collect::<Vec<_>>(),
            "railgunTxidIfHasUnshield": unshield.as_deref().unwrap_or("0x00"),
        });
        Ok((hex32(&leaf), data))
    }

    /// Submits each Railgun transaction's proof.
    pub fn submit_poi(&self, proof: &PoiProof) -> Result<(), Error> {
        for data in &proof.data {
            self.node()
                .submit_transact_proof(REQUIRED_LIST, data.clone())?;
        }
        Ok(())
    }

    pub fn poi_status(&self, proof: &PoiProof) -> Result<PoiStatus, Error> {
        Ok(self.node().pois_per_list(REQUIRED_LIST, &proof.blinded)?)
    }
}
