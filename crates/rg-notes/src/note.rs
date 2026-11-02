//! Note public keys, commitments and nullifiers.

use rg_primitives::field::from_be_bytes_mod_order;
use rg_primitives::{Fr, poseidon};

fn hash(inputs: &[Fr]) -> Fr {
    poseidon::hash(inputs).expect("arity within 1..16")
}

/// npk = poseidon(MPK, random).
pub fn note_public_key(master_public_key: &Fr, random: &[u8; 16]) -> Fr {
    hash(&[*master_public_key, from_be_bytes_mod_order(random)])
}

/// commitment = poseidon(npk, tokenHash, value). Shield commitments use the value after the shield fee.
pub fn commitment(note_public_key: &Fr, token_hash: &[u8; 32], value: u128) -> Fr {
    hash(&[
        *note_public_key,
        from_be_bytes_mod_order(token_hash),
        Fr::from(value),
    ])
}

/// nullifier = poseidon(nullifyingKey, leafIndex).
pub fn nullifier(nullifying_key: &Fr, leaf_index: u64) -> Fr {
    hash(&[*nullifying_key, Fr::from(leaf_index)])
}
