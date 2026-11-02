//! Diff against vectors produced by harness/gen-vectors.js from the TS engine.

use rg_keys::bip32::KeyNode;
use rg_keys::keys::mnemonic_to_seed;
use rg_keys::{AddressData, Chain, WalletKeys, decode_address, encode_address};
use rg_primitives::field::to_decimal;
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
#[serde(rename_all = "camelCase")]
struct Node {
    seed: String,
    chain_key: String,
    chain_code: String,
    #[serde(default)]
    path: Option<String>,
}

#[derive(Deserialize)]
struct Bip32File {
    master: Node,
    paths: Vec<Node>,
}

#[test]
fn bip32_master_and_paths() {
    let f: Bip32File = load("bip32.json");
    let seed = hex::decode(&f.master.seed).unwrap();
    let master = KeyNode::master(&seed);
    assert_eq!(hex::encode(master.chain_key), f.master.chain_key);
    assert_eq!(hex::encode(master.chain_code), f.master.chain_code);
    for v in &f.paths {
        let node = master.derive_path(v.path.as_deref().unwrap()).unwrap();
        assert_eq!(hex::encode(node.chain_key), v.chain_key, "{:?}", v.path);
        assert_eq!(hex::encode(node.chain_code), v.chain_code, "{:?}", v.path);
    }
}

#[derive(Deserialize, Clone, Copy)]
struct ChainJson {
    #[serde(rename = "type")]
    chain_type: u8,
    id: u64,
}

#[derive(Deserialize)]
struct AddressJson {
    chain: Option<ChainJson>,
    address: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletJson {
    mnemonic: String,
    password: String,
    index: u32,
    seed: String,
    spending_private_key: String,
    spending_public_key: [String; 2],
    viewing_private_key: String,
    viewing_public_key: String,
    nullifying_key: String,
    master_public_key: String,
    addresses: Vec<AddressJson>,
}

#[test]
fn wallet_keys_and_addresses_match_engine() {
    let wallets: Vec<WalletJson> = load("keys.json");
    assert_eq!(wallets.len(), 54);
    let mut addresses_checked = 0;
    for w in &wallets {
        let ctx = format!("{} / {:?} / {}", w.mnemonic, w.password, w.index);
        let seed = mnemonic_to_seed(&w.mnemonic, &w.password).unwrap();
        assert_eq!(hex::encode(seed), w.seed, "seed {ctx}");

        let k = WalletKeys::from_mnemonic(&w.mnemonic, &w.password, w.index).unwrap();
        assert_eq!(
            hex::encode(k.spending_private_key.expose()),
            w.spending_private_key,
            "spend prv {ctx}"
        );
        assert_eq!(
            to_decimal(&k.spending_public_key.x),
            w.spending_public_key[0],
            "Ax {ctx}"
        );
        assert_eq!(
            to_decimal(&k.spending_public_key.y),
            w.spending_public_key[1],
            "Ay {ctx}"
        );
        assert_eq!(
            hex::encode(k.viewing_private_key.expose()),
            w.viewing_private_key,
            "view prv {ctx}"
        );
        assert_eq!(
            hex::encode(k.viewing_public_key),
            w.viewing_public_key,
            "view pub {ctx}"
        );
        assert_eq!(to_decimal(&k.nullifying_key), w.nullifying_key, "nk {ctx}");
        assert_eq!(
            to_decimal(&k.master_public_key),
            w.master_public_key,
            "mpk {ctx}"
        );

        for a in &w.addresses {
            let chain = a.chain.map(|c| Chain {
                chain_type: c.chain_type,
                id: c.id,
            });
            let data = AddressData {
                master_public_key: k.master_public_key,
                viewing_public_key: k.viewing_public_key,
                chain,
                version: 1,
            };
            assert_eq!(
                encode_address(&data).unwrap(),
                a.address,
                "encode {ctx} {chain:?}"
            );
            assert_eq!(
                decode_address(&a.address).unwrap(),
                data,
                "decode {ctx} {chain:?}"
            );
            addresses_checked += 1;
        }
    }
    assert_eq!(addresses_checked, 54 * 7);
}
