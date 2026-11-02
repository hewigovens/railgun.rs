use rg_primitives::{Fr, poseidon};
use rg_tree::{TREE_CAPACITY, zero_value};

/// The txid hash pads to 13 no matter which POI circuit proves it.
const TXID_MAX_ITEMS: usize = 13;

pub fn global_tree_position(tree: u32, index: u32) -> u64 {
    tree as u64 * TREE_CAPACITY as u64 + index as u64
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

#[cfg(test)]
mod tests {
    use super::*;

    fn word(hex_str: &str) -> Fr {
        let bytes = hex::decode(hex_str).unwrap();
        rg_primitives::field::from_be_bytes_mod_order(&bytes)
    }

    // A real Arbitrum transfer; expected values come from engine 9.6.0.
    #[test]
    fn hashes_match_the_engine() {
        let nullifiers = [word(
            "04a3e901b6e4ab058abc67ea2fd4ec4c4e1b12fc89a9f3504a9de141f627cff7",
        )];
        let commitments = [
            word("07868110513d971a71d4dc8ed968eb04f2d5e64fd685e11ddc1a405432bdd3d3"),
            word("082dcc027dd8878e8567141d07165a6fb70fcb11d53b5a3a0b5764b519958f0a"),
        ];
        let bound = word("0e2be211983ba0e160139bd2b8f8386467d2631ab30b4143ade2a35b1bb8f3ed");
        let txid = railgun_txid(&nullifiers, &commitments, &bound);
        assert_eq!(
            txid,
            word("21f03b068a26fd888a053c3318f9bdb2abe393a61a1c54da8e906b49fa607d29")
        );
        let position = global_tree_position(2, 2034);
        assert_eq!(
            txid_leaf(&txid, 2, position),
            word("2fcb8b9b0fc541ad47f4b653a33a9b8085f4a65e31985f1d3a15cf47b267ece1")
        );
        assert_eq!(
            blinded_commitment(&commitments[0], &Fr::from(12345u64), position),
            word("23e2b3c6bd1a0c1e4c01ee9458517c85a0544ddcd52575d1e57f6217b89ec7a4")
        );
    }
}
