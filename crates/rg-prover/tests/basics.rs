//! Checks that need no circuit artifacts. The full witness and proof checks against snarkjs are in rg-tx's engine_transfer tests.

use rg_prover::witness::signal_hash;
use rg_prover::{proof_from_json, proof_to_json};
use serde_json::Value;

/// circom_runtime's fnvHash("merkleRoot") is 7221b8af4b93a6c3.
#[test]
fn signal_hash_matches_circom_runtime() {
    assert_eq!(
        signal_hash("merkleRoot"),
        (0x7221b8afu32 as i32, 0x4b93a6c3u32 as i32)
    );
    assert_eq!(
        signal_hash("pathElements"),
        (0x4099e7b7u32 as i32, 0x11de8b07u32 as i32)
    );
}

/// A snarkjs proof parses (with curve and subgroup checks) and prints back the same.
#[test]
fn snarkjs_proof_json_round_trips() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/transfer/transfer.json"
    );
    let t: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let theirs = &t["snarkjsProof"];
    let proof = proof_from_json(theirs).unwrap();
    assert_eq!(&proof_to_json(&proof), theirs);

    let mut bad = theirs.clone();
    bad["pi_a"][1] = Value::String("1".into());
    assert!(proof_from_json(&bad).is_err());
}
