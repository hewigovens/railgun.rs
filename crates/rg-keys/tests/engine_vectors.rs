//! Vectors copied from the engine's own tests (MIT), engine 6e2614d:
//! src/key-derivation/__tests__/{bip32-babyjubjub,key-derivation,bech32-encode}.test.ts

use rg_keys::bip32::KeyNode;
use rg_keys::keys::{mnemonic_to_seed, nullifying_key, viewing_public_key};
use rg_keys::{AddressData, Chain, Error, decode_address, encode_address};
use rg_primitives::babyjubjub::private_to_public;
use rg_primitives::field::{from_be_bytes_mod_order, to_decimal};

// BN254 scalar field modulus, big-endian.
const MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

#[test]
fn bip32_master_vectors() {
    let vectors = [
        (
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            "30d550bc2f61a7c206a1eba3704502da77f366fe69721265b3b7e2c7f05eeabc",
            "1fafc64161d1807e294cc9fded180ca2009aaaedf4cbd7359d4aaa3bb462f411",
        ),
        (
            "d8c228addf9a9cfe5b7934223737815e2f709b3ac12b0c1b2aaec921e5d3a2e8aeea1df817af8159f981798dacd5a930a1fcd8570ba4845078c1b1d09fa060cb",
            "b37268d31994f4bbe422feffb3e1dcb35b61b76c0c1ebea2ded5fb0e37aa0809",
            "c544e07e1007d25b6a3a7ddba8f1e20c2c23c9baec8e9a6200dd6c3b2f8df6a5",
        ),
        (
            "243c1266228fc9ff370d567ba4f805dfacc516375aecf4657cf870a4b551020d92d9b45a8181154f531c1358f742f42078a1620fca6251b1c4ec5fa6e1cf5c3a",
            "8bf4df70930efcf3ce0e8501464891837fa591b3b0924d9110b18152b8a85d37",
            "73eb04585b9ecc409c76a2949f099193be82198eb6abab1594be4138070f19d6",
        ),
        (
            "87ec3e2ae9294cb5500698e6e6ee8357aa56222badae0e6b4150492c95ede7ddfca27c952afafb388453def93fac72f5d7e099debd79e85c2088f9b3e7a65df6",
            "5a7496d62dab5d3bef668bcff39eef421ea6b9544dba30805858989dc6611e36",
            "5c8f71501f449b499feddb89d865f15d35d24586b6447b7c9b7385d0bf217fd4",
        ),
    ];
    for (seed, chain_code, chain_key) in vectors {
        let m = KeyNode::master(&hex::decode(seed).unwrap());
        assert_eq!(hex::encode(m.chain_code), chain_code);
        assert_eq!(hex::encode(m.chain_key), chain_key);
    }
}

#[test]
fn bip32_child_vectors() {
    let vectors = [
        (
            "30d550bc2f61a7c206a1eba3704502da77f366fe69721265b3b7e2c7f05eeabc",
            "1fafc64161d1807e294cc9fded180ca2009aaaedf4cbd7359d4aaa3bb462f411",
            0,
            "e8e6a1bbce8bab145fe8225435dc98d20d53bd32318ce3ede560b8feef3394a5",
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        ),
        (
            "30d550bc2f61a7c206a1eba3704502da77f366fe69721265b3b7e2c7f05eeabc",
            "1fafc64161d1807e294cc9fded180ca2009aaaedf4cbd7359d4aaa3bb462f411",
            12,
            "ff90a1dcb6531d437dc959b6e03f308dd4d9db7e489bdb30d8b4b1894a9e1344",
            "9606ae0c844601e0af4d518dce577983ad756dea08726d92c080ed2ca3f5f31d",
        ),
        (
            "b37268d31994f4bbe422feffb3e1dcb35b61b76c0c1ebea2ded5fb0e37aa0809",
            "c544e07e1007d25b6a3a7ddba8f1e20c2c23c9baec8e9a6200dd6c3b2f8df6a5",
            1,
            "30c3769638ef70c9179a7b18a507318d2353831c2d7990056334cbf14ed4a2cf",
            "0b20d68e515add21c2686d88b8ae02d82912741ed66cb776b6a2eec628ce5fef",
        ),
    ];
    for (pcode, pkey, index, ccode, ckey) in vectors {
        let parent = KeyNode {
            chain_key: h32(pkey),
            chain_code: h32(pcode),
        };
        let child = parent.child_hardened(index).unwrap();
        assert_eq!(hex::encode(child.chain_code), ccode);
        assert_eq!(hex::encode(child.chain_key), ckey);
    }
}

#[test]
fn key_derivation_vectors() {
    // (mnemonic, path, spending private key, Ax, Ay, viewing public key, nullifying key)
    let vectors = [
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "m/0'",
            [
                103u8, 215, 209, 157, 0, 230, 227, 179, 81, 127, 230, 138, 196, 101, 5, 221, 32,
                125, 246, 232, 254, 58, 160, 107, 163, 250, 206, 53, 46, 117, 153, 239,
            ],
            "1700559105542139805112168139351320601853033442476682590258553412078471731431",
            "20772987336827599306927277921643441679141423747083423413320022373456048866305",
            [
                13u8, 235, 247, 125, 142, 148, 54, 252, 7, 160, 220, 63, 232, 189, 144, 194, 245,
                146, 160, 140, 171, 141, 190, 95, 151, 42, 71, 131, 70, 92, 214, 212,
            ],
            "12835268173099116305231859677177501123414588269721547120001227054861606950622",
        ),
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "m/0'/1'",
            [
                52u8, 40, 207, 201, 57, 50, 3, 40, 80, 17, 116, 164, 231, 110, 134, 145, 151, 255,
                200, 148, 181, 141, 191, 77, 14, 149, 60, 72, 77, 102, 203, 94,
            ],
            "16684668252477829187059584092631702151145377657154285130424212860540363370357",
            "12981690610069374219327647242965768905998412239681315744257339323456415609107",
            [
                188u8, 10, 133, 20, 54, 28, 82, 39, 129, 118, 54, 192, 105, 143, 30, 183, 217, 77,
                82, 240, 122, 203, 88, 224, 107, 241, 219, 145, 159, 230, 69, 20,
            ],
            "12433581129726328896745774227574786958991377531034322249715552469191536529193",
        ),
        (
            "culture flower sunny seat maximum begin design magnet side permit coin dial alter insect whisper series desk power cream afford regular strike poem ostrich",
            "m/1984'/0'/1'/1'",
            [
                174u8, 161, 99, 229, 87, 84, 149, 94, 180, 249, 130, 131, 138, 60, 244, 236, 172,
                83, 232, 9, 167, 168, 25, 67, 167, 236, 115, 134, 66, 111, 157, 93,
            ],
            "14701770942636881946891894801429513727414463095087240498212571459549371788442",
            "6562351643365832094839703629534233618348049923815027910705830997906348902485",
            [
                28u8, 112, 24, 121, 34, 161, 22, 10, 20, 98, 221, 72, 216, 131, 91, 146, 55, 237,
                168, 255, 121, 6, 217, 124, 152, 150, 232, 196, 138, 161, 179, 243,
            ],
            "16602386444438786679333393766394518037774007889700655746209679443354561523707",
        ),
    ];
    for (mnemonic, path, prv, ax, ay, vpub, nk) in vectors {
        let seed = mnemonic_to_seed(mnemonic, "").unwrap();
        let node = KeyNode::master(&seed).derive_path(path).unwrap();
        assert_eq!(node.chain_key, prv, "{path}");
        let a = private_to_public(&node.chain_key);
        assert_eq!(to_decimal(&a.x), ax);
        assert_eq!(to_decimal(&a.y), ay);
        assert_eq!(viewing_public_key(&node.chain_key), vpub);
        assert_eq!(to_decimal(&nullifying_key(&node.chain_key)), nk);
    }
}

#[test]
fn bech32_vectors() {
    let vectors = [
        (
            "00000000",
            Some(Chain {
                chain_type: 0,
                id: 1,
            }),
            "0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca",
        ),
        (
            "01bfd5681c0479be9a8ef8dd8baadd97115899a9af30b3d2455843afb41b",
            Some(Chain {
                chain_type: 0,
                id: 56,
            }),
            "0zk1qyqqqqdl645pcpreh6dga7xa3w4dm9c3tzv6ntesk0fy2kzr476pkunpd9kxwatw8qqqqqdl645pcpreh6dga7xa3w4dm9c3tzv6ntesk0fy2kzr476pkcsu8tp",
        ),
        (
            "01bfd5681c0479be9a8ef8dd8baadd97115899a9af30b3d2455843afb41b",
            Some(Chain {
                chain_type: 1,
                id: 56,
            }),
            "0zk1qyqqqqdl645pcpreh6dga7xa3w4dm9c3tzv6ntesk0fy2kzr476pkumpd9kxwatw8qqqqqdl645pcpreh6dga7xa3w4dm9c3tzv6ntesk0fy2kzr476pkwrfm4m",
        ),
        (
            "ee6b4c702f8070c8ddea1cbb8b0f6a4a518b77fa8d3f9b68617b664550e75f64",
            None,
            "0zk1q8hxknrs97q8pjxaagwthzc0df99rzmhl2xnlxmgv9akv32sua0kfrv7j6fe3z53llhxknrs97q8pjxaagwthzc0df99rzmhl2xnlxmgv9akv32sua0kg0zpzts",
        ),
    ];
    for (pubkey, chain, address) in vectors {
        let padded = format!("{pubkey:0>64}");
        let bytes = h32(&padded);
        let data = AddressData {
            master_public_key: from_be_bytes_mod_order(&bytes),
            viewing_public_key: bytes,
            chain,
            version: 1,
        };
        assert_eq!(decode_address(address).unwrap(), data);
        // The last vector's "MPK" is above the field modulus, which a real MPK (a Poseidon output) never is. The engine writes it unreduced; an Fr can't hold it, so only the decode side is comparable there.
        if bytes > MODULUS_BE {
            continue;
        }
        let encoded = encode_address(&data).unwrap();
        assert_eq!(encoded, address);
        assert_eq!(encoded.len(), 127);
    }
}

#[test]
fn bech32_rejects_bad_checksum_and_prefix() {
    assert!(matches!(
        decode_address("rgany1pnj7u66vwqhcquxgmh4pewutpa4y55vtwlag60umdpshkej92rn47ey76ges3t3enn"),
        Err(Error::InvalidAddress(_))
    ));
    assert!(matches!(
        decode_address(
            "rg1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsfhuuw"
        ),
        Err(Error::InvalidAddress(_))
    ));
}
