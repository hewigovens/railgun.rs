//! V2 transact note ciphertexts (`note/transact-note.ts` encryptV2/decrypt and the output loop in `transaction/transaction.ts`).
//!
//! Plaintext, one AES-256-GCM stream with a 16-byte IV: encodedMPK(32), tokenHash(32), random(16) || value(16, big-endian), then the memo text. The first three blocks go into `ciphertext[1..4]` with `iv || tag` in `ciphertext[0]`; the memo's ciphertext travels separately.

use ark_ff::PrimeField;
use rg_primitives::aes::{decrypt_gcm, encrypt_gcm};
use rg_primitives::ed25519::{blind_keys, shared_key, unblind_key};
use rg_primitives::field::{from_be_bytes_mod_order, to_be_bytes};
use rg_primitives::{Fr, PrivateKey};

use crate::memo::{decode_text, decrypt_annotation, encode_text, encrypt_annotation_v2};
use crate::{AnnotationData, Error, OutputType, note};

/// The sender random of a note whose sender address is visible to the receiver.
pub const SENDER_RANDOM_NULL: [u8; 15] = [0; 15];

/// The receiver sees the sender's MPK when the sender random is null: the note then carries receiverMPK XOR senderMPK instead of receiverMPK.
pub fn encode_master_public_key(
    receiver_master_public_key: &Fr,
    sender_master_public_key: &Fr,
    sender_random: &[u8; 15],
) -> [u8; 32] {
    let mut out = to_be_bytes(receiver_master_public_key);
    if *sender_random == SENDER_RANDOM_NULL {
        for (o, s) in out.iter_mut().zip(to_be_bytes(sender_master_public_key)) {
            *o ^= s;
        }
    }
    out
}

fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = *a;
    for (o, x) in out.iter_mut().zip(b) {
        *o ^= x;
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteCiphertextV2 {
    /// `[iv || tag, block0, block1, block2]`.
    pub ciphertext: [[u8; 32]; 4],
    pub memo: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotePlaintextV2 {
    pub encoded_master_public_key: [u8; 32],
    pub token_hash: [u8; 32],
    pub random: [u8; 16],
    pub value: u128,
    pub memo_text: Option<String>,
}

pub fn encrypt_note_v2(
    shared_key: &[u8; 32],
    plaintext: &NotePlaintextV2,
    iv: &[u8; 16],
) -> NoteCiphertextV2 {
    let memo = encode_text(plaintext.memo_text.as_deref());
    let mut plain = Vec::with_capacity(96 + memo.len());
    plain.extend_from_slice(&plaintext.encoded_master_public_key);
    plain.extend_from_slice(&plaintext.token_hash);
    plain.extend_from_slice(&plaintext.random);
    plain.extend_from_slice(&plaintext.value.to_be_bytes());
    plain.extend_from_slice(&memo);
    let (ct, tag) = encrypt_gcm(shared_key, iv, &plain);
    let mut ciphertext = [[0u8; 32]; 4];
    ciphertext[0][..16].copy_from_slice(iv);
    ciphertext[0][16..].copy_from_slice(&tag);
    for i in 0..3 {
        ciphertext[i + 1].copy_from_slice(&ct[i * 32..(i + 1) * 32]);
    }
    NoteCiphertextV2 {
        ciphertext,
        memo: ct[96..].to_vec(),
    }
}

pub fn decrypt_note_v2(
    shared_key: &[u8; 32],
    note: &NoteCiphertextV2,
) -> Result<NotePlaintextV2, Error> {
    let iv: [u8; 16] = note.ciphertext[0][..16].try_into().unwrap();
    let tag: [u8; 16] = note.ciphertext[0][16..].try_into().unwrap();
    let mut ct = Vec::with_capacity(96 + note.memo.len());
    for block in &note.ciphertext[1..] {
        ct.extend_from_slice(block);
    }
    ct.extend_from_slice(&note.memo);
    let plain = decrypt_gcm(shared_key, &iv, &tag, &ct)?;
    Ok(NotePlaintextV2 {
        encoded_master_public_key: plain[..32].try_into().unwrap(),
        token_hash: plain[32..64].try_into().unwrap(),
        random: plain[64..80].try_into().unwrap(),
        value: u128::from_be_bytes(plain[80..96].try_into().unwrap()),
        memo_text: decode_text(&plain[96..]),
    })
}

/// What a contract `CommitmentCiphertext` (V2) holds for one output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentCiphertextV2 {
    pub ciphertext: [[u8; 32]; 4],
    pub blinded_sender_viewing_key: [u8; 32],
    pub blinded_receiver_viewing_key: [u8; 32],
    pub annotation_data: Vec<u8>,
    pub memo: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct ViewingKeys<'a> {
    pub viewing_private_key: &'a PrivateKey,
    pub viewing_public_key: [u8; 32],
    pub master_public_key: Fr,
}

#[derive(Clone, Debug)]
pub struct OutputNote<'a> {
    pub receiver_master_public_key: Fr,
    pub receiver_viewing_public_key: [u8; 32],
    pub token_hash: [u8; 32],
    pub value: u128,
    pub random: [u8; 16],
    /// `SENDER_RANDOM_NULL` shows the sender's address to the receiver.
    pub sender_random: [u8; 15],
    pub output_type: OutputType,
    pub wallet_source: &'a str,
    pub memo_text: Option<&'a str>,
}

impl OutputNote<'_> {
    pub fn note_public_key(&self) -> Fr {
        note::note_public_key(&self.receiver_master_public_key, &self.random)
    }

    pub fn commitment(&self) -> Fr {
        note::commitment(&self.note_public_key(), &self.token_hash, self.value)
    }
}

/// Builds one output's ciphertext the way the engine's transaction does:
/// blind both viewing keys, ECDH with the blinded receiver key, encrypt the note, and encrypt annotation data for the sender.
pub fn create_commitment_ciphertext_v2(
    sender: &ViewingKeys,
    note: &OutputNote,
    gcm_iv: &[u8; 16],
    ctr_iv: &[u8; 16],
) -> Result<CommitmentCiphertextV2, Error> {
    let blinded = blind_keys(
        &sender.viewing_public_key,
        &note.receiver_viewing_public_key,
        &note.random,
        &note.sender_random,
    )
    .ok_or(Error::InvalidPoint)?;
    let key = shared_key(
        sender.viewing_private_key.expose(),
        &blinded.blinded_receiver_viewing_key,
    )
    .ok_or(Error::InvalidPoint)?;
    let plaintext = NotePlaintextV2 {
        encoded_master_public_key: encode_master_public_key(
            &note.receiver_master_public_key,
            &sender.master_public_key,
            &note.sender_random,
        ),
        token_hash: note.token_hash,
        random: note.random,
        value: note.value,
        memo_text: note.memo_text.map(str::to_string),
    };
    let enc = encrypt_note_v2(&key, &plaintext, gcm_iv);
    let annotation_data = encrypt_annotation_v2(
        note.output_type,
        &note.sender_random,
        note.wallet_source,
        sender.viewing_private_key.expose(),
        ctr_iv,
    )?;
    Ok(CommitmentCiphertextV2 {
        ciphertext: enc.ciphertext,
        blinded_sender_viewing_key: blinded.blinded_sender_viewing_key,
        blinded_receiver_viewing_key: blinded.blinded_receiver_viewing_key,
        annotation_data,
        memo: enc.memo,
    })
}

/// A decrypted note. Viewing public keys are none where the engine leaves a dummy empty key (unblinding impossible or not attempted).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptedNote {
    pub receiver_master_public_key: Fr,
    pub receiver_viewing_public_key: Option<[u8; 32]>,
    pub sender_master_public_key: Option<Fr>,
    pub sender_viewing_public_key: Option<[u8; 32]>,
    pub token_hash: [u8; 32],
    pub random: [u8; 16],
    pub value: u128,
    pub memo_text: Option<String>,
    /// Only for notes this wallet sent.
    pub annotation: Option<AnnotationData>,
}

impl DecryptedNote {
    pub fn note_public_key(&self) -> Fr {
        note::note_public_key(&self.receiver_master_public_key, &self.random)
    }

    pub fn commitment(&self) -> Fr {
        note::commitment(&self.note_public_key(), &self.token_hash, self.value)
    }
}

fn note_ciphertext(c: &CommitmentCiphertextV2) -> NoteCiphertextV2 {
    NoteCiphertextV2 {
        ciphertext: c.ciphertext,
        memo: c.memo.clone(),
    }
}

/// Trial-decrypts an output as its receiver. Fails when the note is not ours.
pub fn decrypt_as_receiver(
    wallet: &ViewingKeys,
    c: &CommitmentCiphertextV2,
) -> Result<DecryptedNote, Error> {
    let key = shared_key(
        wallet.viewing_private_key.expose(),
        &c.blinded_sender_viewing_key,
    )
    .ok_or(Error::InvalidPoint)?;
    let p = decrypt_note_v2(&key, &note_ciphertext(c))?;
    let own = to_be_bytes(&wallet.master_public_key);
    // The engine compares integers; an encoded MPK equal to ours means the sender hid their address.
    let sender_visible = p.encoded_master_public_key != own;
    let (sender_mpk, sender_vpk) = if sender_visible {
        (
            Some(from_be_bytes_mod_order(&xor32(
                &p.encoded_master_public_key,
                &own,
            ))),
            unblind_key(
                &c.blinded_sender_viewing_key,
                &p.random,
                &SENDER_RANDOM_NULL,
            ),
        )
    } else {
        (None, None)
    };
    Ok(DecryptedNote {
        receiver_master_public_key: wallet.master_public_key,
        receiver_viewing_public_key: Some(wallet.viewing_public_key),
        sender_master_public_key: sender_mpk,
        sender_viewing_public_key: sender_vpk,
        token_hash: p.token_hash,
        random: p.random,
        value: p.value,
        memo_text: p.memo_text,
        annotation: None,
    })
}

/// Decrypts an output this wallet sent, recovering the receiver.
pub fn decrypt_as_sender(
    wallet: &ViewingKeys,
    c: &CommitmentCiphertextV2,
) -> Result<DecryptedNote, Error> {
    let key = shared_key(
        wallet.viewing_private_key.expose(),
        &c.blinded_receiver_viewing_key,
    )
    .ok_or(Error::InvalidPoint)?;
    let p = decrypt_note_v2(&key, &note_ciphertext(c))?;
    let annotation = decrypt_annotation(&c.annotation_data, wallet.viewing_private_key.expose());
    let sender_random = annotation.as_ref().map(|a| a.sender_random);
    let receiver_mpk = match sender_random {
        Some(r) if r != SENDER_RANDOM_NULL => p.encoded_master_public_key,
        _ => xor32(
            &p.encoded_master_public_key,
            &to_be_bytes(&wallet.master_public_key),
        ),
    };
    let receiver_vpk =
        sender_random.and_then(|r| unblind_key(&c.blinded_receiver_viewing_key, &p.random, &r));
    Ok(DecryptedNote {
        receiver_master_public_key: Fr::from_be_bytes_mod_order(&receiver_mpk),
        receiver_viewing_public_key: receiver_vpk,
        sender_master_public_key: Some(wallet.master_public_key),
        sender_viewing_public_key: Some(wallet.viewing_public_key),
        token_hash: p.token_hash,
        random: p.random,
        value: p.value,
        memo_text: p.memo_text,
        annotation,
    })
}
