//! Shield ciphertexts (`note/shield-note.ts`).
//!
//! `encryptedBundle[0] = iv || tag` of the GCM-encrypted note random,
//! `[1] = encryptedRandom(16) || ctrIV(16)`, `[2]` = the receiver's viewing
//! public key under AES-256-CTR keyed with the shield private key.
//! `shieldKey` is the Ed25519 public key of the shield private key; the
//! receiver gets the shared key from its viewing private key and `shieldKey`.

use rg_primitives::aes::{apply_ctr, decrypt_gcm, encrypt_gcm};
use rg_primitives::ed25519::{public_key, shared_key};

use crate::Error;

/// Message whose wallet signature the SDK uses to derive a shield private key.
pub const SHIELD_PRIVATE_KEY_SIGNATURE_MESSAGE: &str = "RAILGUN_SHIELD";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldCiphertext {
    pub encrypted_bundle: [[u8; 32]; 3],
    pub shield_key: [u8; 32],
}

pub fn encrypt_shield(
    shield_private_key: &[u8; 32],
    receiver_viewing_public_key: &[u8; 32],
    random: &[u8; 16],
    gcm_iv: &[u8; 16],
    ctr_iv: &[u8; 16],
) -> Result<ShieldCiphertext, Error> {
    let key =
        shared_key(shield_private_key, receiver_viewing_public_key).ok_or(Error::InvalidPoint)?;
    let (enc_random, tag) = encrypt_gcm(&key, gcm_iv, random);
    let enc_receiver = apply_ctr(shield_private_key, ctr_iv, receiver_viewing_public_key);
    let mut bundle = [[0u8; 32]; 3];
    bundle[0][..16].copy_from_slice(gcm_iv);
    bundle[0][16..].copy_from_slice(&tag);
    bundle[1][..16].copy_from_slice(&enc_random);
    bundle[1][16..].copy_from_slice(ctr_iv);
    bundle[2].copy_from_slice(&enc_receiver);
    Ok(ShieldCiphertext {
        encrypted_bundle: bundle,
        shield_key: public_key(shield_private_key),
    })
}

/// `ShieldNote.decryptRandom`.
pub fn decrypt_random(bundle: &[[u8; 32]; 3], shared_key: &[u8; 32]) -> Result<[u8; 16], Error> {
    let iv: [u8; 16] = bundle[0][..16].try_into().unwrap();
    let tag: [u8; 16] = bundle[0][16..].try_into().unwrap();
    let plain = decrypt_gcm(shared_key, &iv, &tag, &bundle[1][..16])?;
    Ok(plain.try_into().unwrap())
}

/// Trial-decrypts a shield as a possible receiver.
pub fn decrypt_as_receiver(
    viewing_private_key: &[u8; 32],
    ciphertext: &ShieldCiphertext,
) -> Result<[u8; 16], Error> {
    let key = shared_key(viewing_private_key, &ciphertext.shield_key).ok_or(Error::InvalidPoint)?;
    decrypt_random(&ciphertext.encrypted_bundle, &key)
}
