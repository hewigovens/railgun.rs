use alloy_primitives::B256;
use alloy_sol_types::SolValue;
use rg_primitives::field::{from_be_bytes_mod_order, to_be_bytes};
use rg_primitives::{Fr, poseidon};
use rg_sync::abi;
use tiny_keccak::{Hasher, Keccak};

use crate::Error;

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

/// `hashBoundParamsV2`: keccak of `abi.encode(boundParams)`, mod the field. The engine encodes minGasPrice as uint48 where the contract says uint72; both pad to one 32-byte word, so the bytes match below 2^48.
pub fn hash_bound_params(bp: &abi::BoundParams) -> Fr {
    from_be_bytes_mod_order(&keccak(&bp.abi_encode()))
}

/// The message the spending key signs: Poseidon over the root, the bound params hash, the nullifiers and the commitments.
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
