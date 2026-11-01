//! Railgun private transfers (V2): the engine's `transaction/transaction.ts`,
//! `transaction-batch.ts`, `bound-params.ts` and `prover.ts` formatting.
//!
//! [`plan_transfer`] picks a note and builds the outputs (recipient plus
//! change), [`prepare`] makes bound params, nullifiers, commitments, the
//! spending signature and the circuit inputs, and [`Prepared::transaction`]
//! wraps a proof into the contract's `Transaction` for [`transact_calldata`].
//! Proving lives in `rg-prover`; this crate never touches the network.

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{SolCall, SolValue};
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField, Zero};
use rg_keys::{AddressData, WalletKeys};
use rg_notes::transact::{create_commitment_ciphertext_v2, OutputNote, ViewingKeys};
use rg_notes::{note, OutputType};
use rg_primitives::eddsa::{self, Signature};
use rg_primitives::field::{from_be_bytes_mod_order, to_be_bytes};
use rg_primitives::{poseidon, Fr};
use rg_prover::ark_types::{Proof, VerifyingKey};
use rg_sync::abi;
use rg_tree::{MerkleProof, TREE_DEPTH};
use tiny_keccak::{Hasher, Keccak};

mod shield;
pub use shield::shield_calldata;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("note: {0}")]
    Note(#[from] rg_notes::Error),
    #[error("tree: {0:?}")]
    Tree(rg_tree::Error),
    #[error("no single unspent note of this token covers {0}")]
    InsufficientNote(u128),
    #[error("value must be above zero")]
    ZeroValue,
    #[error("{0} inputs and {1} outputs: no such circuit")]
    Shape(usize, usize),
    #[error("Merkle proof does not match the root or the note")]
    BadProof,
    #[error("bad verifying key: {0}")]
    BadKey(&'static str),
}

/// `getChainFullNetworkID`: chain type in the top byte, then the chain id.
pub fn chain_full_network_id(chain_type: u8, chain_id: u64) -> u64 {
    ((chain_type as u64) << 56) | chain_id
}

pub fn fr_to_b256(x: &Fr) -> B256 {
    B256::from(to_be_bytes(x))
}

pub fn b256_to_fr(x: &B256) -> Fr {
    from_be_bytes_mod_order(x.as_slice())
}

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(data);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

/// `hashBoundParamsV2`: keccak of `abi.encode(boundParams)`, mod the field.
/// The engine encodes minGasPrice as uint48 where the contract says uint72;
/// both pad to one 32-byte word, so the bytes match below 2^48.
pub fn hash_bound_params(bp: &abi::BoundParams) -> Fr {
    from_be_bytes_mod_order(&keccak(&bp.abi_encode()))
}

/// The message the spending key signs: Poseidon over the root, the bound
/// params hash, the nullifiers and the commitments.
pub fn signature_message(
    merkle_root: &Fr,
    bound_params_hash: &Fr,
    nullifiers: &[Fr],
    commitments: &[Fr],
) -> Result<Fr, Error> {
    let mut items = vec![*merkle_root, *bound_params_hash];
    items.extend_from_slice(nullifiers);
    items.extend_from_slice(commitments);
    poseidon::hash(&items).map_err(|_| Error::Shape(nullifiers.len(), commitments.len()))
}

/// A note being spent, with its proof against the root the transfer uses.
#[derive(Clone, Debug)]
pub struct SpendNote {
    pub position: u64,
    pub random: [u8; 16],
    pub value: u128,
    pub proof: MerkleProof,
}

/// One output and the IVs for its ciphertext and annotation data.
#[derive(Clone, Debug)]
pub struct OutputPlan<'a> {
    pub note: OutputNote<'a>,
    pub gcm_iv: [u8; 16],
    pub ctr_iv: [u8; 16],
}

/// Everything one transaction needs, with its randomness already drawn.
#[derive(Clone, Debug)]
pub struct TransferParams<'a> {
    pub tree: u16,
    pub merkle_root: Fr,
    pub token_hash: [u8; 32],
    pub chain_id: u64,
    pub min_gas_price: u128,
    pub inputs: Vec<SpendNote>,
    pub outputs: Vec<OutputPlan<'a>>,
}

/// Circuits Railgun deploys (nullifiers x commitments).
pub fn circuit_exists(inputs: usize, outputs: usize) -> bool {
    matches!(
        (inputs, outputs),
        (1, 1..=3) | (1, 5) | (1, 10) | (1, 13) | (2..=10, 1..=5) | (11..=13, 1)
    )
}

#[derive(Clone, Debug)]
pub struct Prepared {
    pub merkle_root: Fr,
    pub bound_params: abi::BoundParams,
    pub bound_params_hash: Fr,
    pub nullifiers: Vec<Fr>,
    pub commitments: Vec<Fr>,
    pub signature: Signature,
    /// Signal name and values, in `formatRailgunInputs` order.
    pub circuit_inputs: Vec<(String, Vec<Fr>)>,
}

pub fn prepare(keys: &WalletKeys, p: &TransferParams) -> Result<Prepared, Error> {
    let (ni, no) = (p.inputs.len(), p.outputs.len());
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
    let commitments: Vec<Fr> = p.outputs.iter().map(|o| o.note.commitment()).collect();

    let sender = ViewingKeys {
        viewing_private_key: keys.viewing_private_key,
        viewing_public_key: keys.viewing_public_key,
        master_public_key: keys.master_public_key,
    };
    let mut ciphertexts = Vec::with_capacity(no);
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
        unshield: 0,
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
    let signature = eddsa::sign(&keys.spending_private_key, &msg);

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
            p.outputs.iter().map(|o| o.note.note_public_key()).collect(),
        ),
        named(
            "valueOut",
            p.outputs.iter().map(|o| Fr::from(o.note.value)).collect(),
        ),
    ];
    Ok(Prepared {
        merkle_root: p.merkle_root,
        bound_params,
        bound_params_hash,
        nullifiers,
        commitments,
        signature,
        circuit_inputs,
    })
}

impl Prepared {
    /// The circuit's public inputs: root, bound params hash, nullifiers,
    /// commitments.
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
            unshieldPreimage: abi::CommitmentPreimage {
                npk: B256::ZERO,
                token: abi::TokenData {
                    tokenType: 0,
                    tokenAddress: Address::ZERO,
                    tokenSubID: U256::ZERO,
                },
                value: alloy_primitives::Uint::ZERO,
            },
        }
    }
}

fn u256<F: PrimeField>(x: &F) -> U256 {
    U256::from_be_slice(&x.into_bigint().to_bytes_be())
}

/// `formatProof`: the contract takes G2 coordinates imaginary part first.
pub fn snark_proof(p: &Proof<Bn254>) -> abi::SnarkProof {
    abi::SnarkProof {
        a: abi::G1Point {
            x: u256(&p.a.x),
            y: u256(&p.a.y),
        },
        b: abi::G2Point {
            x: [u256(&p.b.x.c1), u256(&p.b.x.c0)],
            y: [u256(&p.b.y.c1), u256(&p.b.y.c0)],
        },
        c: abi::G1Point {
            x: u256(&p.c.x),
            y: u256(&p.c.y),
        },
    }
}

pub fn transact_calldata(txs: Vec<abi::Transaction>) -> Vec<u8> {
    abi::transactCall { _transactions: txs }.abi_encode()
}

fn fq(x: &U256) -> Result<Fq, Error> {
    let b: [u8; 32] = x.to_be_bytes();
    let v = Fq::from_be_bytes_mod_order(&b);
    if u256(&v) != *x {
        return Err(Error::BadKey("coordinate above the field modulus"));
    }
    Ok(v)
}

fn g1(p: &abi::G1Point) -> Result<G1Affine, Error> {
    let (x, y) = (fq(&p.x)?, fq(&p.y)?);
    if x.is_zero() && y.is_zero() {
        return Ok(G1Affine::identity());
    }
    let pt = G1Affine::new_unchecked(x, y);
    if !pt.is_on_curve() {
        return Err(Error::BadKey("G1 point not on the curve"));
    }
    Ok(pt)
}

fn g2(p: &abi::G2Point) -> Result<G2Affine, Error> {
    let x = Fq2::new(fq(&p.x[1])?, fq(&p.x[0])?);
    let y = Fq2::new(fq(&p.y[1])?, fq(&p.y[0])?);
    let pt = G2Affine::new_unchecked(x, y);
    if !pt.is_on_curve() || !pt.is_in_correct_subgroup_assuming_on_curve() {
        return Err(Error::BadKey("G2 point not on the curve"));
    }
    Ok(pt)
}

/// A verifying key as the contract stores it (from `VerifyingKeySet`).
pub fn verifying_key_from_contract(vk: &abi::VerifyingKey) -> Result<VerifyingKey<Bn254>, Error> {
    Ok(VerifyingKey {
        alpha_g1: g1(&vk.alpha1)?,
        beta_g2: g2(&vk.beta2)?,
        gamma_g2: g2(&vk.gamma2)?,
        delta_g2: g2(&vk.delta2)?,
        gamma_abc_g1: vk.ic.iter().map(g1).collect::<Result<_, _>>()?,
    })
}

/// A transfer to one recipient from a wallet scan.
pub struct TransferRequest<'a> {
    pub recipient: &'a AddressData,
    pub token_hash: [u8; 32],
    pub value: u128,
    pub memo_text: Option<&'a str>,
    pub show_sender_to_recipient: bool,
    pub wallet_source: &'a str,
    pub chain_id: u64,
    pub min_gas_price: u128,
}

/// Picks the smallest unspent note of the token that covers the value (one
/// input), and builds the recipient output and, when there is change, a
/// change output that shows the sender (as the engine's change does).
/// `fill` supplies randomness in the engine's order: sender random (when
/// hidden) and note random per output,
/// then the GCM and CTR IVs per ciphertext.
pub fn plan_transfer<'a>(
    keys: &WalletKeys,
    state: &rg_sync::SyncState,
    scan: &rg_wallet::ScanResult,
    req: &TransferRequest<'a>,
    mut fill: impl FnMut(&mut [u8]),
) -> Result<TransferParams<'a>, Error> {
    if req.value == 0 {
        return Err(Error::ZeroValue);
    }
    let txo = scan
        .unspent()
        .filter(|t| t.token_hash == req.token_hash && t.value >= req.value)
        .min_by_key(|t| (t.value, t.tree, t.position))
        .ok_or(Error::InsufficientNote(req.value))?;
    let tree = state.trees.get(txo.tree as usize).ok_or(Error::BadProof)?;
    let proof = tree.proof(txo.position as usize).map_err(Error::Tree)?;
    let change = txo.value - req.value;

    let mut sender_random = rg_notes::transact::SENDER_RANDOM_NULL;
    if !req.show_sender_to_recipient {
        fill(&mut sender_random);
    }
    let mut random = [0u8; 16];
    fill(&mut random);
    let mut notes = vec![OutputNote {
        receiver_master_public_key: req.recipient.master_public_key,
        receiver_viewing_public_key: req.recipient.viewing_public_key,
        token_hash: req.token_hash,
        value: req.value,
        random,
        sender_random,
        output_type: OutputType::Transfer,
        wallet_source: req.wallet_source,
        memo_text: req.memo_text,
    }];
    if change > 0 {
        let mut random = [0u8; 16];
        fill(&mut random);
        notes.push(OutputNote {
            receiver_master_public_key: keys.master_public_key,
            receiver_viewing_public_key: keys.viewing_public_key,
            token_hash: req.token_hash,
            value: change,
            random,
            sender_random: rg_notes::transact::SENDER_RANDOM_NULL,
            output_type: OutputType::Change,
            wallet_source: req.wallet_source,
            memo_text: None,
        });
    }
    let outputs = notes
        .into_iter()
        .map(|note| {
            let mut gcm_iv = [0u8; 16];
            let mut ctr_iv = [0u8; 16];
            fill(&mut gcm_iv);
            fill(&mut ctr_iv);
            OutputPlan {
                note,
                gcm_iv,
                ctr_iv,
            }
        })
        .collect();
    Ok(TransferParams {
        tree: txo.tree as u16,
        merkle_root: proof.root,
        token_hash: req.token_hash,
        chain_id: req.chain_id,
        min_gas_price: req.min_gas_price,
        inputs: vec![SpendNote {
            position: txo.position as u64,
            random: txo.random,
            value: txo.value,
            proof,
        }],
        outputs,
    })
}
