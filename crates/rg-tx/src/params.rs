use rg_notes::transact::OutputNote;
use rg_primitives::Fr;
use rg_tree::MerkleProof;

use crate::{AdaptId, UnshieldOutput};

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
    pub unshield: Option<UnshieldOutput>,
    pub adapt: AdaptId,
}

/// Circuits Railgun deploys (nullifiers x commitments): every shape of at most 14 signals. Checked against the published hashes in `rg-core`, and the Arbitrum contract has no key for 10x5.
pub fn circuit_exists(inputs: usize, outputs: usize) -> bool {
    inputs >= 1 && outputs >= 1 && inputs + outputs <= 14
}
