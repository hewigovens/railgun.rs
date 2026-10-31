//! Vectors copied from the engine's own tests (MIT), engine 6e2614d:
//! src/note/__tests__/{note-util,memo,transact-note,shield-note}.test.ts

use rg_keys::decode_address;
use rg_notes::memo::{decode_text, decrypt_annotation, encode_text, encrypt_annotation_v2};
use rg_notes::note::{commitment, note_public_key, nullifier};
use rg_notes::shield::SHIELD_PRIVATE_KEY_SIGNATURE_MESSAGE;
use rg_notes::{OutputType, TokenData, TokenType};
use rg_primitives::aes::decrypt_gcm;
use rg_primitives::field::{from_be_bytes_mod_order, to_be_bytes};

fn h<const N: usize>(s: &str) -> [u8; N] {
    hex::decode(s).unwrap().try_into().unwrap()
}

#[test]
fn token_data_hashes() {
    // note-util.test.ts: tokenSubID "1" for all three types.
    let mut sub_id = [0u8; 32];
    sub_id[31] = 1;
    let address = h("1234567890123456789012345678901234567890");
    let token = |token_type| TokenData {
        token_type,
        address,
        sub_id,
    };
    assert_eq!(
        hex::encode(token(TokenType::Erc20).hash()),
        "0000000000000000000000001234567890123456789012345678901234567890"
    );
    assert_eq!(
        hex::encode(token(TokenType::Erc721).hash()),
        "075b737079de804169d5e006add4da4942063ab4fce32268c469c49460e52be0"
    );
    assert_eq!(
        hex::encode(token(TokenType::Erc1155).hash()),
        "2d0c48e5b759b13bea21d65719c47747f857f47be541ddb0df54fa0a040a7bed"
    );
}

#[test]
fn memo_text_encoding() {
    assert!(encode_text(None).is_empty());
    assert_eq!(decode_text(&[]), None);
    let long = "A really long memo with emojis 😐👩🏾‍🔧😎 and other text !@#$%^&*() Private memo field 🤡🙀🥰👩🏿‍🚒🧞 🤡 🙀 🥰 👩🏿‍🚒 🧞, in order to test a major memo for a real live production use case.";
    let encoded = encode_text(Some(long));
    assert_eq!(hex::encode(&encoded), "41207265616c6c79206c6f6e67206d656d6f207769746820656d6f6a697320f09f9890f09f91a9f09f8fbee2808df09f94a7f09f988e20616e64206f7468657220746578742021402324255e262a28292050726976617465206d656d6f206669656c6420f09fa4a1f09f9980f09fa5b0f09f91a9f09f8fbfe2808df09f9a92f09fa79e20f09fa4a120f09f998020f09fa5b020f09f91a9f09f8fbfe2808df09f9a9220f09fa79e2c20696e206f7264657220746f20746573742061206d616a6f72206d656d6f20666f722061207265616c206c6976652070726f64756374696f6e2075736520636173652e");
    assert_eq!(decode_text(&encoded).as_deref(), Some(long));
    let short = "Private memo field 🤡🙀🥰👩🏿‍🚒🧞 🤡 🙀 🥰 👩🏿‍🚒 🧞,";
    assert_eq!(hex::encode(encode_text(Some(short))), "50726976617465206d656d6f206669656c6420f09fa4a1f09f9980f09fa5b0f09f91a9f09f8fbfe2808df09f9a92f09fa79e20f09fa4a120f09f998020f09fa5b020f09f91a9f09f8fbfe2808df09f9a9220f09fa79e2c");
}

#[test]
fn annotation_data_round_trip() {
    // memo.test.ts: BroadcasterFee, senderRandom 1234567890abcde1234567890abcde, "memo wallet".
    let key = [0x42u8; 32];
    let data = encrypt_annotation_v2(
        OutputType::BroadcasterFee,
        &h("1234567890abcde1234567890abcde"),
        "memo wallet",
        &key,
        &[9u8; 16],
    )
    .unwrap();
    let got = decrypt_annotation(&data, &key).unwrap();
    assert_eq!(got.output_type, OutputType::BroadcasterFee);
    assert_eq!(
        hex::encode(got.sender_random),
        "1234567890abcde1234567890abcde"
    );
    assert_eq!(got.wallet_source.as_deref(), Some("memo wallet"));
}

#[test]
fn shield_signature_message() {
    assert_eq!(SHIELD_PRIVATE_KEY_SIGNATURE_MESSAGE, "RAILGUN_SHIELD");
}

#[test]
fn legacy_notes_random_npk_and_hash() {
    // transact-note.test.ts "Should serialize and deserialize notes": the random is
    // AES-256-GCM encrypted under the viewing private key, iv || tag then data.
    let address = "0zk1qxvsy4jxshey7wtzv0ry7kp24x58fxtsg5yuvzrzjv93l8mayk8garv7j6fe3z53l7vsy4jxshey7wtzv0ry7kp24x58fxtsg5yuvzrzjv93l8mayk8guau6ef8";
    let mpk = decode_address(address).unwrap().master_public_key;
    // (npk, tokenHash, value, encryptedRandom[0], encryptedRandom[1], random, vpk, hash)
    let vectors = [
        (
            "23da85e72baa8d77f476a893de0964ce1ec2957d056b591a19d05bb4b9a549ed",
            "0000000000000000000000007f4925cdf66ddf5b88016df1fe915e68eff8f192",
            "0000000000000000086aa1ade61ccb53",
            "5c4a783fd15546fbad149c673b7139790a9cf62ec849a5a8e6a167815ee2d08d",
            "260693ec8dd38f5be7758b6786bc579e",
            "85b08a7cd73ee433072f1d410aeb4801",
            "0b252eea1d78ff7b2ad19ea161dfe380686a099f9713719d2eff85196a607685",
            "29decce78b2f43c718ebb7c6825617ea6881836d88d9551dd2530c44f0d790c5",
        ),
        (
            "21eacdfdbe32555ed1c08c4872e73da1e59cb47f7f9d886f702b0e0e6399474c",
            "000000000000000000000000df0fa4124c8a5feec8efcb0e0142d3e04a9e0fbf",
            "000000000000000007cf6b5ae17ae75a",
            "f401e001c520b9f40d37736c0ef2309fa9b2dc97bf1634ac1443fc2fe5359f69",
            "093481f1f6ab744d9f937e6ec796e300",
            "f7c477afb5a3eb31dbb96295cdbcf165",
            "0a13664024e298e53bf01342e2111ae314f9595b12107e85cf0066e4b04cb3a3",
            "2d78128d8bd632fa45e76906b6d58bbb7b581d28a040565b688adb498b8e37db",
        ),
        (
            "24203d63bb50c2cfc256c405b81147058ded5ab422c97489dddef7a2486217d7",
            "00000000000000000000000034e34b5d8e848f9d20d9bd8e1e48e24c3b87c396",
            "00000000000000000b9df0087cbbd709",
            "4b0b63e8f573bf29cabc8e840c5db89892c0acc3f30bbdf6ad9d39ac9485fa49",
            "cbfb4c84c0669aaf184a621c9d21e9ae",
            "6d8a7e26de6b0638cd092c2a2b524705",
            "099ba7ffc589df18402385d7c0d4771555dffd2a6514fc136c565ea1ee3bb520",
            "0d046f7423d5e69726cf2d98d2c5c3fe089f3151f9ac968e2314696efa833f62",
        ),
        (
            "099729608f0c9671590c98730a40b7da122808b9691582a423526ec45f8b1b04",
            "0000000000000000000000009b71cad96341485290d3f1376fb9e969a632694d",
            "00000000000000000ac76747c40dda3a",
            "e9abf13a310d1910d3010a1cf8b5c03a50c228f1fe81de21734479398973ec77",
            "00b0994bd02746fc55c1ff8c75aeb285",
            "f13666966cffa395e3d412ea4e20480f",
            "0c78af78aea7d17b6d9d57fedede59f83c782b562542f9f4ed0900f18d034103",
            "0884efbb8db3db4eca63150fb2f51882ffffdaa9b70b57a3f2e1dd672d028991",
        ),
        (
            "239ca439444c50907c4259e200b4314d19fed2ab7bcc2b236e60f90d5962ca8e",
            "00000000000000000000000089d21609e4ea344c576d1692ceca0f0e0bf4b771",
            "00000000000000000475d82f700206b8",
            "7462849ef8b7bdbb9deeae7983f84334d934d129bd7a7e926bd87b6cf0053e0d",
            "da7cd10423b3d1e48bb7dd47062ac632",
            "0bf6750e00739619a1a00f9b8f1bc2be",
            "0fc2d4688b94afa262226b601dd3f9fe955a2bd7310ac01f02e8d1a62e35c0a1",
            "03d83b5835628196b3ccf557e0ae2b0e933b95fedcc48b7ae36bbb85f9a0b385",
        ),
        (
            "058075b59e688d3e879a72e97e3a68de05cc4d7f76bb8e4246ac4a9a9700698b",
            "0000000000000000000000006f2870a30f4ff19f073fe894d6fe881f0c04657f",
            "000000000000000003426801bd08640b",
            "e501c3195c8a4cc2134ed19d69ba1208a4c7f4ef6f33c2c5e51655f919d4855e",
            "e533c677c5fa66c511a70125edfcd2ac",
            "d8c0caf1b041611d408b5f01e7eae957",
            "0b49b73e4c7c184aff7c99af820be7f8a32a602724f58abbfef38494931e5405",
            "2dad5a92aa41aa8166507524eae1fda360f69daff11c0058a312c8c2cd431fe9",
        ),
        (
            "2856460b27f8896e81009b2a0d0760bc03c07cd854570018cd0b53061f697acf",
            "0000000000000000000000004224904029a556a7cd0bc78d81b165c391fffb45",
            "000000000000000003449e13312815a6",
            "1bef951429c37eaa69190cb635591d122ffe959d690366876e9f1704aa37bb18",
            "8ae56f06a6fe0c39b47f8b28c178f3e0",
            "44a514b4db4659e8520d570f3252c0cf",
            "0f6344893b62deb6c83178aa6883192941eae50eb8eec2854ad0c942b4a2a241",
            "2ee5f10f4db3ab2beab040e49cef37bc3f87852bacb6c66b6176a1ded3e33a2a",
        ),
        (
            "03c8d39bf8186f0d478a853b7102c0bec63e1fbb4ce2d6e8d289cc698e116fc0",
            "000000000000000000000000480bdc4d52df318db7b458b171540a936dc39a07",
            "000000000000000008d210fd771f72ab",
            "789ee74fc10fd3b8daac3846b307d7d20db76ca9d5b6894c78f58b2ebc0303e4",
            "35a7d7e3b7c178dbf3ff6c985bceeee6",
            "77c31ed0577a986750c8dce8804af5b9",
            "08baacccf37c1de3edc6e0a0270d8f999b9d7ed5ea7dbae68015b0dade2d5d65",
            "00eb817d3790cdb84dc2f4c8cc4f1ee9f4c6b737f6d036e4516037d059100472",
        ),
        (
            "2edc5f1181d22381b83db79e558bbe6e7739da59dc71d31dff3074d4bec38f3b",
            "0000000000000000000000008afe4263f81c6d01cb6ea2548132a82d4c5b16e8",
            "0000000000000000060c736c94f022c6",
            "82df79ed67267bd528f0302a95129bbb56d04fab22f95af35b03d2c07ac75737",
            "273588a6fab60d09b7f4155e2bf4aded",
            "6478eea9c496942f0f25967c11fc4bbd",
            "08abd3c723fd7fc91b183a32a48205acd6cecb452d36d23a9273fc46f22abe60",
            "162cd1401ab95aed7ed1b60ec661331d6fb9f632431bef43fcd5e14f7f876b4b",
        ),
        (
            "10cd7f88b213cb9efcd58f7a45eed24e39513b640e913aa48de129d2685199b1",
            "0000000000000000000000004f53cbc84f501847cf42bd9fb14d63be21dcffc8",
            "0000000000000000005589f7d39c59bf",
            "4732f678e893c09c6393be8f8fcc5eee1d9a1078a16151dcae2d65f2d78edc4b",
            "c675ab6de72d03033cf0bafaa0391b2e",
            "2e16e1cdda5f94ddb9981d3811924b05",
            "092547b5af1fa658e03433596910f8ea42419998b61f09f55b3cd1c85a7da620",
            "29a0dfbe68f52c2ddc7a772785a4751adb6e846dc6b1fcf79872aae0c5700f53",
        ),
    ];
    for (npk, token_hash, value, iv_tag, data, random, vpk, hash) in vectors {
        let iv_tag = h::<32>(iv_tag);
        let got = decrypt_gcm(
            &h(vpk),
            &iv_tag[..16].try_into().unwrap(),
            &iv_tag[16..].try_into().unwrap(),
            &hex::decode(data).unwrap(),
        )
        .unwrap();
        assert_eq!(hex::encode(&got), random);
        let n = note_public_key(&mpk, &h(random));
        assert_eq!(hex::encode(to_be_bytes(&n)), npk);
        let value = u128::from_be_bytes(h(value));
        assert_eq!(
            hex::encode(to_be_bytes(&commitment(&n, &h(token_hash), value))),
            hash
        );
    }
}

#[test]
fn nullifiers() {
    // transact-note.test.ts "Should calculate nullifiers": (key, position, nullifier).
    let vectors = [
        (
            "08ad9143ae793cdfe94b77e4e52bc4e9f13666966cffa395e3d412ea4e20480f",
            0,
            "03f68801f3ee2ed10178c162b4f7f1bd466bc9718f4f98175fc04934c5caba6e",
        ),
        (
            "11299eb10424d82de500a440a2874d12f7c477afb5a3eb31dbb96295cdbcf165",
            12,
            "1aeadb64bf8faff93dfe26bcf0b2e2d0e9724293cc7a455f028b6accabee13b8",
        ),
        (
            "09b57736523cda7412ddfed0d2f1f4a86d8a7e26de6b0638cd092c2a2b524705",
            6500,
            "091961ce11c244db49a25668e57dfa2b5ffb1fe63055dd64a14af6f2be58b0e7",
        ),
    ];
    for (key, position, want) in vectors {
        let got = nullifier(&from_be_bytes_mod_order(&h::<32>(key)), position);
        assert_eq!(hex::encode(to_be_bytes(&got)), want);
    }
}
