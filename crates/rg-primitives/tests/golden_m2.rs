//! M2 primitives against harness vectors and the engine's own keys-utils test.

use ark_ff::PrimeField;
use rg_primitives::Fr;
use rg_primitives::babyjubjub::{Point, private_to_public};
use rg_primitives::ed25519::{blind_keys, private_scalar, public_key, shared_key, unblind_key};
use rg_primitives::eddsa::{Signature, sign, verify};
use rg_primitives::field::{from_decimal, to_decimal};
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

fn h<const N: usize>(s: &str) -> [u8; N] {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn dec(s: &str) -> Fr {
    from_decimal(s).unwrap()
}

#[derive(Deserialize)]
struct SigJson {
    #[serde(rename = "R8")]
    r8: [String; 2],
    #[serde(rename = "S")]
    s: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EddsaVector {
    private_key: String,
    message: String,
    public_key: [String; 2],
    signature: SigJson,
}

#[test]
fn eddsa_poseidon_signatures_match_circomlibjs() {
    let vectors: Vec<EddsaVector> = load("eddsa.json");
    assert_eq!(vectors.len(), 16);
    for v in &vectors {
        let prv = h::<32>(&v.private_key);
        let msg = dec(&v.message);
        let pubkey = private_to_public(&prv);
        assert_eq!(
            pubkey,
            Point {
                x: dec(&v.public_key[0]),
                y: dec(&v.public_key[1])
            }
        );

        let sig = sign(&prv, &msg);
        assert_eq!(to_decimal(&sig.r8.x), v.signature.r8[0]);
        assert_eq!(to_decimal(&sig.r8.y), v.signature.r8[1]);
        assert_eq!(to_decimal(&sig.s_field()), v.signature.s);

        let parsed = Signature::new(
            Point {
                x: dec(&v.signature.r8[0]),
                y: dec(&v.signature.r8[1]),
            },
            dec(&v.signature.s),
        )
        .unwrap();
        assert_eq!(parsed, sig);
        assert!(verify(&msg, &parsed, &pubkey));
        assert!(!verify(&(msg + Fr::from(1u64)), &parsed, &pubkey));
        assert!(!verify(&msg, &parsed, &Point::identity()));
        let other = Point {
            x: pubkey.x,
            y: pubkey.y + Fr::from(1u64),
        };
        assert!(!verify(&msg, &parsed, &other));
    }
}

#[test]
fn signature_rejects_s_at_or_above_subgroup_order() {
    let l = dec("2736030358979909402780800718157159386076813972158567259200215660948447373041");
    assert!(Signature::new(Point::identity(), l).is_none());
    assert!(Signature::new(Point::identity(), l - Fr::from(1u64)).is_some());
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScalarVector {
    private_key: String,
    scalar: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlindingVector {
    sender_viewing_private_key: String,
    sender_viewing_public_key: String,
    receiver_viewing_private_key: String,
    receiver_viewing_public_key: String,
    random: String,
    sender_random: String,
    blinded_sender_viewing_key: String,
    blinded_receiver_viewing_key: String,
    shared_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ed25519File {
    scalars: Vec<ScalarVector>,
    blinding: Vec<BlindingVector>,
    invalid_point: String,
}

#[test]
fn ed25519_scalars_blinding_and_shared_keys_match_engine() {
    let f: Ed25519File = load("ed25519.json");
    for v in &f.scalars {
        let s = private_scalar(&h(&v.private_key));
        // l is below the BN254 modulus, so Fr prints the scalar unchanged.
        assert_eq!(
            to_decimal(&Fr::from_le_bytes_mod_order(&s.to_bytes())),
            v.scalar
        );
    }
    assert_eq!(f.blinding.len(), 12);
    for v in &f.blinding {
        let spub = h::<32>(&v.sender_viewing_public_key);
        let rpub = h::<32>(&v.receiver_viewing_public_key);
        assert_eq!(public_key(&h(&v.sender_viewing_private_key)), spub);
        assert_eq!(public_key(&h(&v.receiver_viewing_private_key)), rpub);
        let random = h::<16>(&v.random);
        let sender_random = h::<15>(&v.sender_random);
        let b = blind_keys(&spub, &rpub, &random, &sender_random).unwrap();
        assert_eq!(
            hex::encode(b.blinded_sender_viewing_key),
            v.blinded_sender_viewing_key
        );
        assert_eq!(
            hex::encode(b.blinded_receiver_viewing_key),
            v.blinded_receiver_viewing_key
        );
        let k1 = shared_key(
            &h(&v.sender_viewing_private_key),
            &b.blinded_receiver_viewing_key,
        );
        let k2 = shared_key(
            &h(&v.receiver_viewing_private_key),
            &b.blinded_sender_viewing_key,
        );
        assert_eq!(hex::encode(k1.unwrap()), v.shared_key);
        assert_eq!(k1, k2);
        assert_eq!(
            unblind_key(&b.blinded_sender_viewing_key, &random, &sender_random),
            Some(spub)
        );
        assert_eq!(
            unblind_key(&b.blinded_receiver_viewing_key, &random, &sender_random),
            Some(rpub)
        );
    }
    assert_eq!(shared_key(&[7u8; 32], &h(&f.invalid_point)), None);
}

#[test]
fn engine_shared_key_vector() {
    // keys-utils.test.ts, "Should get expected symmetric keys from WASM and Javascript".
    let k = shared_key(
        &h("0123456789012345678901234567890123456789012345678901234567891234"),
        &h("0987654321098765432109876543210987654321098765432109876543210987"),
    );
    assert_eq!(
        hex::encode(k.unwrap()),
        "fbb71adfede43b8a756939500c810d85b16cfbead66d126065639c0cec1fea56"
    );
}

#[test]
fn engine_poseidon_vector() {
    // poseidon.test.ts: poseidon([0, 1]).
    let out = rg_primitives::poseidon::hash(&[Fr::from(0u64), Fr::from(1u64)]).unwrap();
    assert_eq!(
        to_decimal(&out),
        "12583541437132735734108669866114103169564651237895298778035846191048104863326"
    );
    assert_eq!(
        hex::encode(rg_primitives::field::to_be_bytes(&out)),
        "1bd20834f5de9830c643778a2e88a3a1363c8b9ac083d36d75bf87c49953e65e"
    );
}
