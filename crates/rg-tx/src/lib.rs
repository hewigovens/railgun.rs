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
    #[error("no one tree holds {0} of this token in at most {MAX_INPUTS} unspent notes")]
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

/// An ERC20 leaving the pool. The contract takes its fee out of `value`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnshieldOutput {
    pub to: [u8; 20],
    pub token: [u8; 20],
    pub value: u128,
}

fn address_field(address: &[u8; 20]) -> Fr {
    from_be_bytes_mod_order(address)
}

impl UnshieldOutput {
    /// `UnshieldNote`: the npk is the address, the rest is a normal commitment.
    pub fn commitment(&self) -> Fr {
        let token_hash = rg_notes::TokenData::erc20(self.token).hash();
        note::commitment(&address_field(&self.to), &token_hash, self.value)
    }

    fn preimage(&self) -> abi::CommitmentPreimage {
        abi::CommitmentPreimage {
            npk: fr_to_b256(&address_field(&self.to)),
            token: abi::TokenData {
                tokenType: 0,
                tokenAddress: Address::from(self.token),
                tokenSubID: U256::ZERO,
            },
            value: alloy_primitives::Uint::from(self.value),
        }
    }
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
    pub unshield: Option<UnshieldOutput>,
}

/// Circuits Railgun deploys (nullifiers x commitments): every shape of at most
/// 14 signals. Checked against the published hashes in `rg-core`, and the
/// Arbitrum contract has no key for 10x5.
pub fn circuit_exists(inputs: usize, outputs: usize) -> bool {
    inputs >= 1 && outputs >= 1 && inputs + outputs <= 14
}

#[derive(Clone, Debug)]
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

pub fn prepare(keys: &WalletKeys, p: &TransferParams) -> Result<Prepared, Error> {
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
        viewing_private_key: keys.viewing_private_key,
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

/// An unshield of an ERC20 from a wallet scan.
pub struct UnshieldRequest<'a> {
    pub to: [u8; 20],
    pub token: [u8; 20],
    pub value: u128,
    pub wallet_source: &'a str,
    pub chain_id: u64,
    pub min_gas_price: u128,
}

/// Most inputs in one transaction, the engine's limit.
pub const MAX_INPUTS: usize = 10;

/// The notes to spend: the smallest single note that covers `value`, else the
/// largest notes of one tree, since a transaction proves against one root.
/// The tree needing the fewest notes wins.
pub fn select_notes<'s>(
    unspent: impl Iterator<Item = &'s rg_wallet::Txo>,
    token_hash: &[u8; 32],
    value: u128,
) -> Option<Vec<&'s rg_wallet::Txo>> {
    let notes: Vec<_> = unspent.filter(|t| &t.token_hash == token_hash).collect();
    if let Some(one) = notes
        .iter()
        .filter(|t| t.value >= value)
        .min_by_key(|t| (t.value, t.tree, t.position))
    {
        return Some(vec![*one]);
    }
    let mut trees: Vec<u32> = notes.iter().map(|t| t.tree).collect();
    trees.sort_unstable();
    trees.dedup();
    trees
        .into_iter()
        .filter_map(|tree| {
            let mut in_tree: Vec<_> = notes.iter().copied().filter(|t| t.tree == tree).collect();
            in_tree.sort_by_key(|t| (std::cmp::Reverse(t.value), t.position));
            let mut sum = 0u128;
            let count = in_tree.iter().take(MAX_INPUTS).position(|t| {
                sum += t.value;
                sum >= value
            })?;
            in_tree.truncate(count + 1);
            Some(in_tree)
        })
        .min_by_key(Vec::len)
}

/// Proofs for the chosen notes, their total and their tree's root.
fn spend_notes(
    state: &rg_sync::SyncState,
    notes: &[&rg_wallet::Txo],
) -> Result<(Vec<SpendNote>, u128), Error> {
    let tree = state
        .trees
        .get(notes[0].tree as usize)
        .ok_or(Error::BadProof)?;
    let inputs = notes
        .iter()
        .map(|t| {
            Ok(SpendNote {
                position: t.position as u64,
                random: t.random,
                value: t.value,
                proof: tree.proof(t.position as usize).map_err(Error::Tree)?,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok((inputs, notes.iter().map(|t| t.value).sum()))
}

/// Picks the notes to spend, and builds the recipient output and, when there
/// is change, a change output that shows the sender (as the engine's change does).
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
    let notes = select_notes(scan.unspent(), &req.token_hash, req.value)
        .ok_or(Error::InsufficientNote(req.value))?;
    let (inputs, total) = spend_notes(state, &notes)?;
    let change = total - req.value;

    let mut sender_random = rg_notes::transact::SENDER_RANDOM_NULL;
    if !req.show_sender_to_recipient {
        fill(&mut sender_random);
    }
    let mut random = [0u8; 16];
    fill(&mut random);
    let mut outs = vec![OutputNote {
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
        outs.push(change_note(
            keys,
            &req.token_hash,
            change,
            req.wallet_source,
            &mut fill,
        ));
    }
    let root = inputs[0].proof.root;
    Ok(TransferParams {
        tree: notes[0].tree as u16,
        merkle_root: root,
        token_hash: req.token_hash,
        chain_id: req.chain_id,
        min_gas_price: req.min_gas_price,
        inputs,
        outputs: with_ivs(outs, &mut fill),
        unshield: None,
    })
}

fn change_note<'a>(
    keys: &WalletKeys,
    token_hash: &[u8; 32],
    value: u128,
    wallet_source: &'a str,
    fill: &mut impl FnMut(&mut [u8]),
) -> OutputNote<'a> {
    let mut random = [0u8; 16];
    fill(&mut random);
    OutputNote {
        receiver_master_public_key: keys.master_public_key,
        receiver_viewing_public_key: keys.viewing_public_key,
        token_hash: *token_hash,
        value,
        random,
        sender_random: rg_notes::transact::SENDER_RANDOM_NULL,
        output_type: OutputType::Change,
        wallet_source,
        memo_text: None,
    }
}

fn with_ivs<'a>(
    notes: Vec<OutputNote<'a>>,
    fill: &mut impl FnMut(&mut [u8]),
) -> Vec<OutputPlan<'a>> {
    notes
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
        .collect()
}

/// Picks notes for an unshield. Any remainder comes back as a change note.
pub fn plan_unshield<'a>(
    keys: &WalletKeys,
    state: &rg_sync::SyncState,
    scan: &rg_wallet::ScanResult,
    req: &UnshieldRequest<'a>,
    mut fill: impl FnMut(&mut [u8]),
) -> Result<TransferParams<'a>, Error> {
    if req.value == 0 {
        return Err(Error::ZeroValue);
    }
    let token_hash = rg_notes::TokenData::erc20(req.token).hash();
    let notes = select_notes(scan.unspent(), &token_hash, req.value)
        .ok_or(Error::InsufficientNote(req.value))?;
    let (inputs, total) = spend_notes(state, &notes)?;
    let change = total - req.value;
    let mut outs = Vec::new();
    if change > 0 {
        outs.push(change_note(
            keys,
            &token_hash,
            change,
            req.wallet_source,
            &mut fill,
        ));
    }
    let root = inputs[0].proof.root;
    Ok(TransferParams {
        tree: notes[0].tree as u16,
        merkle_root: root,
        token_hash,
        chain_id: req.chain_id,
        min_gas_price: req.min_gas_price,
        inputs,
        outputs: with_ivs(outs, &mut fill),
        unshield: Some(UnshieldOutput {
            to: req.to,
            token: req.token,
            value: req.value,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rg_wallet::{Txo, TxoSource};

    fn txo(tree: u32, position: u32, value: u128) -> Txo {
        Txo {
            tree,
            position,
            commitment: [0; 32],
            token_hash: [1; 32],
            value,
            random: [0; 16],
            nullifier: [0; 32],
            source: TxoSource::Shield,
            block_number: 0,
            transaction_hash: [0; 32],
            spent: None,
            memo_text: None,
            sender_master_public_key: None,
        }
    }

    fn picked(notes: &[Txo], value: u128) -> Option<Vec<(u32, u32)>> {
        select_notes(notes.iter(), &[1; 32], value)
            .map(|v| v.iter().map(|t| (t.tree, t.position)).collect())
    }

    #[test]
    fn one_covering_note_beats_several() {
        let notes = [txo(0, 0, 5), txo(0, 1, 9), txo(1, 0, 7)];
        assert_eq!(picked(&notes, 6), Some(vec![(1, 0)]));
    }

    #[test]
    fn several_notes_come_from_the_tree_needing_fewest() {
        let notes = [
            txo(0, 0, 5),
            txo(0, 1, 3),
            txo(0, 2, 2),
            txo(1, 0, 6),
            txo(1, 1, 4),
        ];
        assert_eq!(picked(&notes, 10), Some(vec![(1, 0), (1, 1)]));
    }

    #[test]
    fn notes_split_across_trees_cannot_be_combined() {
        let notes = [txo(0, 0, 5), txo(1, 0, 5)];
        assert_eq!(picked(&notes, 9), None);
    }

    #[test]
    fn more_than_the_input_limit_is_refused() {
        let notes: Vec<_> = (0..=MAX_INPUTS as u32).map(|i| txo(0, i, 1)).collect();
        assert_eq!(picked(&notes, MAX_INPUTS as u128 + 1), None);
        assert_eq!(
            picked(&notes, MAX_INPUTS as u128).map(|v| v.len()),
            Some(MAX_INPUTS)
        );
    }

    // Expected value from engine 9.6.0's UnshieldNoteERC20.
    #[test]
    fn unshield_commitment_matches_the_engine() {
        let hex20 = |s: &str| -> [u8; 20] { hex::decode(s).unwrap().try_into().unwrap() };
        let unshield = UnshieldOutput {
            to: hex20("e28386e8b1dfdd13bedd548ac4e8e3d9736cbc28"),
            token: hex20("82af49447d8a07e3bd95bd0d56f35241523fbab1"),
            value: 30_000_000_000_000,
        };
        assert_eq!(
            hex::encode(fr_to_b256(&unshield.commitment())),
            "2ebd3cd6284519fb18f94eb02e1ac3a8c83077595ec775e4c513505f6af083df"
        );
    }
}
