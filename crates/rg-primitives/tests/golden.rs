//! Diff against vectors produced by harness/gen-vectors.js from the TS engine.

use rg_primitives::babyjubjub::{self, Point};
use rg_primitives::field::{from_decimal, to_decimal};
use rg_primitives::poseidon;
use serde::Deserialize;

#[derive(Deserialize)]
struct File<T> {
    data: T,
}

fn load<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = format!("{}/../../vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str::<File<T>>(&text).unwrap().data
}

#[derive(Deserialize)]
struct PoseidonVector {
    inputs: Vec<String>,
    output: String,
}

#[test]
fn poseidon_matches_engine_widths_1_to_16() {
    let vectors: Vec<PoseidonVector> = load("poseidon.json");
    assert_eq!(vectors.len(), 48);
    for v in &vectors {
        // from_decimal reduces mod p, as the engine does before hashing.
        let inputs: Vec<_> = v.inputs.iter().map(|s| from_decimal(s).unwrap()).collect();
        let out = poseidon::hash(&inputs).unwrap();
        assert_eq!(to_decimal(&out), v.output, "width {}", inputs.len());
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BjjVector {
    private_key: String,
    public_key: [String; 2],
    packed: String,
}

#[test]
fn babyjubjub_prv2pub_and_pack_match_circomlibjs() {
    let vectors: Vec<BjjVector> = load("babyjubjub.json");
    assert!(!vectors.is_empty());
    for v in &vectors {
        let prv: [u8; 32] = hex::decode(&v.private_key).unwrap().try_into().unwrap();
        let p = babyjubjub::private_to_public(&prv);
        assert_eq!(to_decimal(&p.x), v.public_key[0]);
        assert_eq!(to_decimal(&p.y), v.public_key[1]);
        assert!(p.is_on_curve());
        assert_eq!(hex::encode(p.pack()), v.packed);
        let packed: [u8; 32] = hex::decode(&v.packed).unwrap().try_into().unwrap();
        assert_eq!(Point::unpack(&packed).unwrap(), p);
    }
}
