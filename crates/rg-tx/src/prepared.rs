use alloy_primitives::{Address, B256, Bytes, U256};
use ark_bn254::Bn254;
use rg_keys::WalletKeys;
use rg_notes::note;
use rg_notes::transact::{ViewingKeys, create_commitment_ciphertext_v2};
use rg_primitives::Fr;
use rg_primitives::eddsa::{self, Signature};
use rg_primitives::field::from_be_bytes_mod_order;
use rg_prover::ark_types::Proof;
use rg_sync::abi;
use rg_tree::TREE_DEPTH;

use crate::unshield::address_field;
use crate::{
    Error, TransferParams, UnshieldOutput, circuit_exists, fr_to_b256, hash_bound_params,
    signature_message, snark_proof,
};

#[derive(Clone)]
pub struct Prepared {
    pub merkle_root: Fr,
    pub bound_params: abi::BoundParams,
    pub bound_params_hash: Fr,
    pub nullifiers: Vec<Fr>,
    pub commitments: Vec<Fr>,
    pub signature: Signature,
    pub unshield: Option<UnshieldOutput>,
    /// Signal name and values, in `formatRailgunInputs` order.
    pub circuit_inputs: Vec<(String, Vec<Fr>)>,
}

impl TransferParams<'_> {
    pub fn prepare(&self, keys: &WalletKeys) -> Result<Prepared, Error> {
        let p = self;
        let (ni, no) = (p.inputs.len(), p.outputs.len() + p.unshield.iter().len());
        if !circuit_exists(ni, no) {
            return Err(Error::Shape(ni, no));
        }
        for i in &p.inputs {
            let npk = note::note_public_key(&keys.master_public_key, &i.random);
            let leaf = note::commitment(&npk, &p.token_hash, i.value);
            if i.proof.leaf != leaf
                || i.proof.root != p.merkle_root
                || i.proof.indices != i.position
                || !i.proof.verify()
            {
                return Err(Error::BadProof);
            }
        }
        let nullifiers: Vec<Fr> = p
            .inputs
            .iter()
            .map(|i| note::nullifier(&keys.nullifying_key, i.position))
            .collect();
        let mut commitments: Vec<Fr> = p.outputs.iter().map(|o| o.note.commitment()).collect();
        commitments.extend(p.unshield.iter().map(UnshieldOutput::commitment));

        let sender = ViewingKeys {
            viewing_private_key: &keys.viewing_private_key,
            viewing_public_key: keys.viewing_public_key,
            master_public_key: keys.master_public_key,
        };
        let mut ciphertexts = Vec::with_capacity(p.outputs.len());
        for o in &p.outputs {
            let c = create_commitment_ciphertext_v2(&sender, &o.note, &o.gcm_iv, &o.ctr_iv)?;
            ciphertexts.push(abi::CommitmentCiphertext {
                ciphertext: c.ciphertext.map(B256::from),
                blindedSenderViewingKey: B256::from(c.blinded_sender_viewing_key),
                blindedReceiverViewingKey: B256::from(c.blinded_receiver_viewing_key),
                annotationData: Bytes::from(c.annotation_data),
                memo: Bytes::from(c.memo),
            });
        }
        let bound_params = abi::BoundParams {
            treeNumber: p.tree,
            minGasPrice: alloy_primitives::Uint::from(p.min_gas_price),
            unshield: u8::from(p.unshield.is_some()),
            chainID: p.chain_id,
            adaptContract: Address::ZERO,
            adaptParams: B256::ZERO,
            commitmentCiphertext: ciphertexts,
        };
        let bound_params_hash = hash_bound_params(&bound_params);
        let msg = signature_message(
            &p.merkle_root,
            &bound_params_hash,
            &nullifiers,
            &commitments,
        )?;
        let signature = eddsa::sign(keys.spending_private_key.expose(), &msg);

        let fr16 = |b: &[u8; 16]| from_be_bytes_mod_order(b);
        let mut path = Vec::with_capacity(ni * TREE_DEPTH);
        for i in &p.inputs {
            path.extend_from_slice(&i.proof.elements);
        }
        let named = |n: &str, v: Vec<Fr>| (n.to_string(), v);
        let circuit_inputs = vec![
            named("merkleRoot", vec![p.merkle_root]),
            named("boundParamsHash", vec![bound_params_hash]),
            named("nullifiers", nullifiers.clone()),
            named("commitmentsOut", commitments.clone()),
            named("token", vec![from_be_bytes_mod_order(&p.token_hash)]),
            named(
                "publicKey",
                vec![keys.spending_public_key.x, keys.spending_public_key.y],
            ),
            named(
                "signature",
                vec![signature.r8.x, signature.r8.y, signature.s_field()],
            ),
            named(
                "randomIn",
                p.inputs.iter().map(|i| fr16(&i.random)).collect(),
            ),
            named(
                "valueIn",
                p.inputs.iter().map(|i| Fr::from(i.value)).collect(),
            ),
            named("pathElements", path),
            named(
                "leavesIndices",
                p.inputs.iter().map(|i| Fr::from(i.position)).collect(),
            ),
            named("nullifyingKey", vec![keys.nullifying_key]),
            named(
                "npkOut",
                p.outputs
                    .iter()
                    .map(|o| o.note.note_public_key())
                    .chain(p.unshield.iter().map(|u| address_field(&u.to)))
                    .collect(),
            ),
            named(
                "valueOut",
                p.outputs
                    .iter()
                    .map(|o| Fr::from(o.note.value))
                    .chain(p.unshield.iter().map(|u| Fr::from(u.value)))
                    .collect(),
            ),
        ];
        Ok(Prepared {
            merkle_root: p.merkle_root,
            bound_params,
            bound_params_hash,
            nullifiers,
            commitments,
            signature,
            unshield: p.unshield,
            circuit_inputs,
        })
    }
}

impl Prepared {
    /// The circuit's public inputs: root, bound params hash, nullifiers, commitments.
    pub fn public_inputs(&self) -> Vec<Fr> {
        let mut v = vec![self.merkle_root, self.bound_params_hash];
        v.extend_from_slice(&self.nullifiers);
        v.extend_from_slice(&self.commitments);
        v
    }

    pub fn transaction(&self, proof: &Proof<Bn254>) -> abi::Transaction {
        abi::Transaction {
            proof: snark_proof(proof),
            merkleRoot: fr_to_b256(&self.merkle_root),
            nullifiers: self.nullifiers.iter().map(fr_to_b256).collect(),
            commitments: self.commitments.iter().map(fr_to_b256).collect(),
            boundParams: self.bound_params.clone(),
            unshieldPreimage: self.unshield.as_ref().map_or_else(
                || abi::CommitmentPreimage {
                    npk: B256::ZERO,
                    token: abi::TokenData {
                        tokenType: 0,
                        tokenAddress: Address::ZERO,
                        tokenSubID: U256::ZERO,
                    },
                    value: alloy_primitives::Uint::ZERO,
                },
                UnshieldOutput::preimage,
            ),
        }
    }
}
