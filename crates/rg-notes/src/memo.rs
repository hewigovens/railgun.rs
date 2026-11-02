//! Memo text and note annotation data (`note/memo.ts`).

use rg_primitives::aes::apply_ctr;

use crate::{Error, wallet_source};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OutputType {
    Transfer = 0,
    BroadcasterFee = 1,
    Change = 2,
}

impl TryFrom<u8> for OutputType {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, ()> {
        match v {
            0 => Ok(OutputType::Transfer),
            1 => Ok(OutputType::BroadcasterFee),
            2 => Ok(OutputType::Change),
            _ => Err(()),
        }
    }
}

/// Memo text as UTF-8 bytes; none is empty.
pub fn encode_text(text: Option<&str>) -> Vec<u8> {
    text.map(|t| t.as_bytes().to_vec()).unwrap_or_default()
}

/// Empty bytes decode to none. Invalid UTF-8 becomes U+FFFD, like TextDecoder.
pub fn decode_text(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(bytes).into_owned())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnnotationData {
    pub output_type: OutputType,
    pub sender_random: [u8; 15],
    pub wallet_source: Option<String>,
}

/// `createEncryptedNoteAnnotationDataV2`: AES-256-CTR keyed with the sender's viewing private key over `outputType(1) || senderRandom(15)`, 15 zero bytes, and the wallet source left-padded to 15 bytes. Returns `iv || ciphertext` (62 bytes).
pub fn encrypt_annotation_v2(
    output_type: OutputType,
    sender_random: &[u8; 15],
    wallet_source: &str,
    viewing_private_key: &[u8; 32],
    iv: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    let mut plain = [0u8; 46];
    plain[0] = output_type as u8;
    plain[1..16].copy_from_slice(sender_random);
    let ws = wallet_source::encode(wallet_source)?.to_be_bytes();
    plain[31..46].copy_from_slice(&ws[1..]);
    let mut out = iv.to_vec();
    out.extend(apply_ctr(viewing_private_key, iv, &plain));
    Ok(out)
}

/// `decryptNoteAnnotationData`. The engine reads the ciphertext back as 16, 16 and 16 bytes although it wrote 16, 15 and 15; CTR is a stream, so this only drops the wallet source's leading byte, which is zero for any source of 16 characters or fewer. Mirrored here slice for slice.
pub fn decrypt_annotation(data: &[u8], viewing_private_key: &[u8; 32]) -> Option<AnnotationData> {
    if data.len() < 32 {
        return None;
    }
    let iv: [u8; 16] = data[..16].try_into().ok()?;
    let has_wallet_source = data.len() > 32;
    let end = if has_wallet_source { 64 } else { 32 }.min(data.len());
    let plain = apply_ctr(viewing_private_key, &iv, &data[16..end]);
    let output_type = OutputType::try_from(plain[0]).ok()?;
    let wallet_source = if has_wallet_source && plain.len() > 32 {
        Some(wallet_source::decode(&plain[32..plain.len().min(48)]))
    } else {
        None
    };
    Some(AnnotationData {
        output_type,
        sender_random: plain[1..16].try_into().ok()?,
        wallet_source,
    })
}
