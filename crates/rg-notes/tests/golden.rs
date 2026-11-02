//! rg-notes against vectors produced by harness/m2.js from the TS engine.

use rg_notes::memo::{decode_text, decrypt_annotation, encode_text, encrypt_annotation_v2};
use rg_notes::note::{commitment, note_public_key, nullifier};
use rg_notes::shield::{decrypt_as_receiver as shield_decrypt, encrypt_shield};
use rg_notes::transact::{
    DecryptedNote, OutputNote, ViewingKeys, create_commitment_ciphertext_v2, decrypt_as_receiver,
    decrypt_as_sender,
};
use rg_notes::{OutputType, TokenData, TokenType, wallet_source};
use rg_primitives::Fr;
use rg_primitives::ed25519::shared_key;
use rg_primitives::field::{from_decimal, to_be_bytes, to_decimal};
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

fn output_type(v: u8) -> OutputType {
    OutputType::try_from(v).unwrap()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenJson {
    token_type: u8,
    token_address: String,
    #[serde(rename = "tokenSubID")]
    token_sub_id: String,
    token_hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommitmentJson {
    master_public_key: String,
    random: String,
    token_hash: String,
    value: String,
    note_public_key: String,
    commitment: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NullifierJson {
    nullifying_key: String,
    leaf_index: u64,
    nullifier: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletSourceJson {
    wallet_source: String,
    encoded: String,
}

#[derive(Deserialize)]
struct MemoJson {
    text: String,
    encoded: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AnnotationDecrypted {
    output_type: u8,
    sender_random: String,
    wallet_source: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AnnotationJson {
    viewing_private_key: String,
    output_type: u8,
    sender_random: String,
    wallet_source: String,
    iv: String,
    annotation_data: String,
    decrypted: AnnotationDecrypted,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NoteView {
    receiver_master_public_key: String,
    receiver_viewing_public_key: String,
    sender_master_public_key: Option<String>,
    sender_viewing_public_key: Option<String>,
    random: String,
    value: String,
    token_hash: String,
    memo_text: Option<String>,
    output_type: Option<u8>,
    wallet_source: Option<String>,
    sender_random: Option<String>,
    commitment: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactJson {
    sender_viewing_private_key: String,
    sender_viewing_public_key: String,
    sender_master_public_key: String,
    receiver_viewing_private_key: String,
    receiver_viewing_public_key: String,
    receiver_master_public_key: String,
    token_hash: String,
    value: String,
    random: String,
    sender_random: String,
    output_type: u8,
    wallet_source: String,
    memo_text: Option<String>,
    gcm_iv: String,
    ctr_iv: String,
    note_public_key: String,
    commitment: String,
    blinded_sender_viewing_key: String,
    blinded_receiver_viewing_key: String,
    shared_key: String,
    ciphertext: [String; 4],
    memo: String,
    annotation_data: String,
    decrypted_by_receiver: NoteView,
    decrypted_by_sender: NoteView,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShieldJson {
    receiver_viewing_private_key: String,
    receiver_viewing_public_key: String,
    receiver_master_public_key: String,
    shield_private_key: String,
    random: String,
    value: String,
    token_address: String,
    token_hash: String,
    gcm_iv: String,
    ctr_iv: String,
    note_public_key: String,
    commitment: String,
    shield_key: String,
    encrypted_bundle: [String; 3],
    shared_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NotesFile {
    tokens: Vec<TokenJson>,
    commitments: Vec<CommitmentJson>,
    nullifiers: Vec<NullifierJson>,
    wallet_sources: Vec<WalletSourceJson>,
    memos: Vec<MemoJson>,
    annotations: Vec<AnnotationJson>,
    transact_notes: Vec<TransactJson>,
    shields: Vec<ShieldJson>,
}

fn notes() -> NotesFile {
    load("notes.json")
}

#[test]
fn token_hashes() {
    let f = notes();
    assert_eq!(f.tokens.len(), 8);
    for t in &f.tokens {
        let token_type = match t.token_type {
            0 => TokenType::Erc20,
            1 => TokenType::Erc721,
            2 => TokenType::Erc1155,
            _ => unreachable!(),
        };
        let data = TokenData {
            token_type,
            address: h(&t.token_address),
            sub_id: h(&t.token_sub_id),
        };
        assert_eq!(hex::encode(data.hash()), t.token_hash);
    }
}

#[test]
fn note_public_keys_commitments_and_nullifiers() {
    let f = notes();
    for c in &f.commitments {
        let npk = note_public_key(&dec(&c.master_public_key), &h(&c.random));
        assert_eq!(to_decimal(&npk), c.note_public_key);
        let value: u128 = c.value.parse().unwrap();
        assert_eq!(
            to_decimal(&commitment(&npk, &h(&c.token_hash), value)),
            c.commitment
        );
    }
    assert_eq!(f.nullifiers.len(), 16);
    for n in &f.nullifiers {
        let got = nullifier(&dec(&n.nullifying_key), n.leaf_index);
        assert_eq!(to_decimal(&got), n.nullifier);
    }
}

#[test]
fn wallet_sources_and_memo_text() {
    let f = notes();
    for w in &f.wallet_sources {
        assert_eq!(
            wallet_source::encode_hex(&w.wallet_source).unwrap(),
            w.encoded
        );
        let n = wallet_source::encode(&w.wallet_source).unwrap();
        assert_eq!(
            wallet_source::decode(&n.to_be_bytes()),
            w.wallet_source.to_lowercase()
        );
    }
    assert!(wallet_source::encode("seventeen chars!!").is_err());
    assert!(wallet_source::encode("no_underscores").is_err());
    for m in &f.memos {
        assert_eq!(hex::encode(encode_text(Some(&m.text))), m.encoded);
        let decoded = decode_text(&hex::decode(&m.encoded).unwrap());
        assert_eq!(decoded, (!m.text.is_empty()).then(|| m.text.clone()));
    }
    assert!(encode_text(None).is_empty());
}

#[test]
fn annotation_data_matches_engine_layout() {
    let f = notes();
    assert_eq!(f.annotations.len(), 12);
    for a in &f.annotations {
        let key = h::<32>(&a.viewing_private_key);
        let data = encrypt_annotation_v2(
            output_type(a.output_type),
            &h(&a.sender_random),
            &a.wallet_source,
            &key,
            &h(&a.iv),
        )
        .unwrap();
        assert_eq!(hex::encode(&data), a.annotation_data);
        let got = decrypt_annotation(&data, &key).unwrap();
        assert_eq!(got.output_type as u8, a.decrypted.output_type);
        assert_eq!(hex::encode(got.sender_random), a.decrypted.sender_random);
        assert_eq!(got.wallet_source, a.decrypted.wallet_source);
    }
}

fn check_view(got: &DecryptedNote, want: &NoteView, ctx: &str) {
    assert_eq!(
        to_decimal(&got.receiver_master_public_key),
        want.receiver_master_public_key,
        "{ctx}"
    );
    assert_eq!(
        got.receiver_viewing_public_key
            .map(hex::encode)
            .unwrap_or_default(),
        want.receiver_viewing_public_key,
        "{ctx}"
    );
    assert_eq!(
        got.sender_master_public_key.map(|k| to_decimal(&k)),
        want.sender_master_public_key,
        "{ctx}"
    );
    // The engine stores an empty key when it can't unblind; the vectors print that as "".
    let sender_vpk = want
        .sender_viewing_public_key
        .as_ref()
        .map(|s| (!s.is_empty()).then(|| s.clone()));
    assert_eq!(
        got.sender_master_public_key
            .map(|_| got.sender_viewing_public_key.map(hex::encode)),
        sender_vpk,
        "{ctx}"
    );
    assert_eq!(hex::encode(got.random), want.random, "{ctx}");
    assert_eq!(got.value.to_string(), want.value, "{ctx}");
    assert_eq!(hex::encode(got.token_hash), want.token_hash, "{ctx}");
    assert_eq!(got.memo_text, want.memo_text, "{ctx}");
    assert_eq!(
        got.annotation.as_ref().map(|a| a.output_type as u8),
        want.output_type,
        "{ctx}"
    );
    assert_eq!(
        got.annotation
            .as_ref()
            .and_then(|a| a.wallet_source.clone()),
        want.wallet_source,
        "{ctx}"
    );
    assert_eq!(
        got.annotation
            .as_ref()
            .map(|a| hex::encode(a.sender_random)),
        want.sender_random,
        "{ctx}"
    );
    assert_eq!(to_decimal(&got.commitment()), want.commitment, "{ctx}");
}

#[test]
fn transact_note_ciphertexts_match_engine_and_decrypt_both_ways() {
    let f = notes();
    assert_eq!(f.transact_notes.len(), 12);
    for (i, t) in f.transact_notes.iter().enumerate() {
        let ctx = format!("note {i}");
        let sender = ViewingKeys {
            viewing_private_key: h(&t.sender_viewing_private_key),
            viewing_public_key: h(&t.sender_viewing_public_key),
            master_public_key: dec(&t.sender_master_public_key),
        };
        let receiver = ViewingKeys {
            viewing_private_key: h(&t.receiver_viewing_private_key),
            viewing_public_key: h(&t.receiver_viewing_public_key),
            master_public_key: dec(&t.receiver_master_public_key),
        };
        let note = OutputNote {
            receiver_master_public_key: receiver.master_public_key,
            receiver_viewing_public_key: receiver.viewing_public_key,
            token_hash: h(&t.token_hash),
            value: t.value.parse().unwrap(),
            random: h(&t.random),
            sender_random: h(&t.sender_random),
            output_type: output_type(t.output_type),
            wallet_source: &t.wallet_source,
            memo_text: t.memo_text.as_deref(),
        };
        assert_eq!(
            to_decimal(&note.note_public_key()),
            t.note_public_key,
            "{ctx}"
        );
        assert_eq!(to_decimal(&note.commitment()), t.commitment, "{ctx}");

        let c =
            create_commitment_ciphertext_v2(&sender, &note, &h(&t.gcm_iv), &h(&t.ctr_iv)).unwrap();
        assert_eq!(
            hex::encode(c.blinded_sender_viewing_key),
            t.blinded_sender_viewing_key,
            "{ctx}"
        );
        assert_eq!(
            hex::encode(c.blinded_receiver_viewing_key),
            t.blinded_receiver_viewing_key,
            "{ctx}"
        );
        let key = shared_key(&sender.viewing_private_key, &c.blinded_receiver_viewing_key).unwrap();
        assert_eq!(hex::encode(key), t.shared_key, "{ctx}");
        for (k, block) in c.ciphertext.iter().enumerate() {
            assert_eq!(hex::encode(block), t.ciphertext[k], "{ctx} block {k}");
        }
        assert_eq!(hex::encode(&c.memo), t.memo, "{ctx}");
        assert_eq!(hex::encode(&c.annotation_data), t.annotation_data, "{ctx}");

        check_view(
            &decrypt_as_receiver(&receiver, &c).unwrap(),
            &t.decrypted_by_receiver,
            &ctx,
        );
        check_view(
            &decrypt_as_sender(&sender, &c).unwrap(),
            &t.decrypted_by_sender,
            &ctx,
        );

        // A third wallet can't decrypt it, and a flipped bit fails the tag.
        let other = f.transact_notes[(i + 1) % f.transact_notes.len()]
            .receiver_viewing_private_key
            .clone();
        if other != t.receiver_viewing_private_key && other != t.sender_viewing_private_key {
            let stranger = ViewingKeys {
                viewing_private_key: h(&other),
                ..receiver
            };
            assert!(decrypt_as_receiver(&stranger, &c).is_err(), "{ctx}");
        }
        let mut tampered = c.clone();
        tampered.ciphertext[2][0] ^= 1;
        assert!(decrypt_as_receiver(&receiver, &tampered).is_err(), "{ctx}");
    }
}

#[test]
fn shield_ciphertexts_match_engine() {
    let f = notes();
    assert_eq!(f.shields.len(), 8);
    for s in &f.shields {
        let token = TokenData::erc20(h(&s.token_address));
        assert_eq!(hex::encode(token.hash()), s.token_hash);
        let npk = note_public_key(&dec(&s.receiver_master_public_key), &h(&s.random));
        assert_eq!(hex::encode(to_be_bytes(&npk)), s.note_public_key);
        let value: u128 = s.value.parse().unwrap();
        assert_eq!(
            to_decimal(&commitment(&npk, &token.hash(), value)),
            s.commitment
        );

        let c = encrypt_shield(
            &h(&s.shield_private_key),
            &h(&s.receiver_viewing_public_key),
            &h(&s.random),
            &h(&s.gcm_iv),
            &h(&s.ctr_iv),
        )
        .unwrap();
        assert_eq!(hex::encode(c.shield_key), s.shield_key);
        for k in 0..3 {
            assert_eq!(hex::encode(c.encrypted_bundle[k]), s.encrypted_bundle[k]);
        }
        let key = shared_key(&h(&s.receiver_viewing_private_key), &c.shield_key).unwrap();
        assert_eq!(hex::encode(key), s.shared_key);
        assert_eq!(
            hex::encode(shield_decrypt(&h(&s.receiver_viewing_private_key), &c).unwrap()),
            s.random
        );
        assert!(shield_decrypt(&h(&s.shield_private_key), &c).is_err());
    }
}
