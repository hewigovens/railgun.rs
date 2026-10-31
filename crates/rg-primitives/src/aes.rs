//! AES-256 as the engine uses it (`utils/encryption/aes.ts`): GCM with a
//! 16-byte IV and 16-byte tag, and CTR with a 16-byte big-endian counter.
//! The engine encrypts a list of blocks through one cipher stream, so the
//! ciphertext of the blocks is the ciphertext of their concatenation.

use aes::Aes256;
use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{AesGcm, Nonce, Tag};
use ctr::cipher::{KeyIvInit, StreamCipher};

type Gcm16 = AesGcm<Aes256, U16>;
type Ctr = ctr::Ctr128BE<Aes256>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("unable to decrypt ciphertext")]
pub struct DecryptError;

/// Returns (ciphertext, tag).
pub fn encrypt_gcm(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let cipher = Gcm16::new(key.into());
    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::<U16>::from_slice(iv), b"", &mut buf)
        .expect("gcm input under the length limit");
    (buf, tag.into())
}

pub fn decrypt_gcm(
    key: &[u8; 32],
    iv: &[u8; 16],
    tag: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    let cipher = Gcm16::new(key.into());
    let mut buf = ciphertext.to_vec();
    cipher
        .decrypt_in_place_detached(
            Nonce::<U16>::from_slice(iv),
            b"",
            &mut buf,
            Tag::from_slice(tag),
        )
        .map_err(|_| DecryptError)?;
    Ok(buf)
}

/// CTR encryption and decryption are the same operation.
pub fn apply_ctr(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut buf = data.to_vec();
    Ctr::new(key.into(), iv.into()).apply_keystream(&mut buf);
    buf
}
