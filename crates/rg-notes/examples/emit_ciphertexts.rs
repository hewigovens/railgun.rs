//! Writes Rust-made note ciphertexts, shield ciphertexts and EdDSA signatures
//! as JSON, with randoms the TS engine never saw, for harness/check-rust.js to
//! decrypt and verify with the engine:
//!
//!     cargo run -p rg-notes --example emit_ciphertexts > /tmp/rust-ciphertexts.json
//!     node harness/check-rust.js /tmp/rust-ciphertexts.json

use rg_keys::WalletKeys;
use rg_notes::shield::encrypt_shield;
use rg_notes::transact::{
    create_commitment_ciphertext_v2, OutputNote, ViewingKeys, SENDER_RANDOM_NULL,
};
use rg_notes::{OutputType, TokenData};
use rg_primitives::eddsa::sign;
use rg_primitives::field::{from_be_bytes_mod_order, to_decimal};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

struct Rng(u64);

impl Rng {
    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        let mut filled = 0;
        while filled < N {
            let block = Sha256::digest(format!("rust-emit-v1:{}", self.0));
            self.0 += 1;
            let n = (N - filled).min(32);
            out[filled..filled + n].copy_from_slice(&block[..n]);
            filled += n;
        }
        out
    }
}

const MNEMONICS: [&str; 2] = [
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "test test test test test test test test test test test junk",
];

fn main() {
    let mut rng = Rng(0);
    let wallets: Vec<(&str, u32, WalletKeys)> = MNEMONICS
        .iter()
        .flat_map(|m| [0u32, 3].map(|i| (*m, i, WalletKeys::from_mnemonic(m, "", i).unwrap())))
        .collect();
    let view = |k: &WalletKeys| ViewingKeys {
        viewing_private_key: k.viewing_private_key,
        viewing_public_key: k.viewing_public_key,
        master_public_key: k.master_public_key,
    };
    let wallet_json = |(m, i, _): &(&str, u32, WalletKeys)| json!({ "mnemonic": m, "index": i });

    let memos = [None, Some("hi from rust"), Some("ラーメン 🍜")];
    let sources = ["gem wallet", "", "rust core 1"];
    let mut notes = Vec::new();
    for i in 0..8 {
        let s = &wallets[i % wallets.len()];
        let r = &wallets[(i + 1) % wallets.len()];
        let token = TokenData::erc20(rng.bytes());
        let value = u128::from_be_bytes(rng.bytes()) >> (i * 8);
        let sender_random = if i % 2 == 0 {
            SENDER_RANDOM_NULL
        } else {
            rng.bytes()
        };
        let note = OutputNote {
            receiver_master_public_key: r.2.master_public_key,
            receiver_viewing_public_key: r.2.viewing_public_key,
            token_hash: token.hash(),
            value,
            random: rng.bytes(),
            sender_random,
            output_type: OutputType::try_from((i % 3) as u8).unwrap(),
            wallet_source: sources[i % 3],
            memo_text: memos[i % 3],
        };
        let c = create_commitment_ciphertext_v2(&view(&s.2), &note, &rng.bytes(), &rng.bytes())
            .unwrap();
        notes.push(json!({
            "sender": wallet_json(s),
            "receiver": wallet_json(r),
            "tokenHash": hex::encode(note.token_hash),
            "value": value.to_string(),
            "random": hex::encode(note.random),
            "senderRandom": hex::encode(sender_random),
            "outputType": note.output_type as u8,
            "walletSource": note.wallet_source,
            "memoText": note.memo_text,
            "commitment": to_decimal(&note.commitment()),
            "ciphertext": c.ciphertext.iter().map(hex::encode).collect::<Vec<_>>(),
            "blindedSenderViewingKey": hex::encode(c.blinded_sender_viewing_key),
            "blindedReceiverViewingKey": hex::encode(c.blinded_receiver_viewing_key),
            "annotationData": hex::encode(&c.annotation_data),
            "memo": hex::encode(&c.memo),
        }));
    }

    let mut shields = Vec::new();
    for i in 0..4 {
        let r = &wallets[i % wallets.len()];
        let random: [u8; 16] = rng.bytes();
        let c = encrypt_shield(
            &rng.bytes(),
            &r.2.viewing_public_key,
            &random,
            &rng.bytes(),
            &rng.bytes(),
        )
        .unwrap();
        shields.push(json!({
            "receiver": wallet_json(r),
            "random": hex::encode(random),
            "encryptedBundle": c.encrypted_bundle.iter().map(hex::encode).collect::<Vec<_>>(),
            "shieldKey": hex::encode(c.shield_key),
        }));
    }

    let mut signatures = Vec::new();
    for _ in 0..8 {
        let prv: [u8; 32] = rng.bytes();
        let msg = from_be_bytes_mod_order(&rng.bytes::<32>());
        let sig = sign(&prv, &msg);
        signatures.push(json!({
            "privateKey": hex::encode(prv),
            "message": to_decimal(&msg),
            "R8": [to_decimal(&sig.r8.x), to_decimal(&sig.r8.y)],
            "S": to_decimal(&sig.s_field()),
        }));
    }

    let out: Value = json!({ "notes": notes, "shields": shields, "signatures": signatures });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
