//! Railgun's hardened-only BIP32 variant (engine src/key-derivation/bip32.ts). Same algorithm as SLIP-0010 with the HMAC key "babyjubjub seed".

use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::Error;

const CURVE_SEED: &[u8] = b"babyjubjub seed";
const HARDENED_OFFSET: u32 = 0x8000_0000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyNode {
    pub chain_key: [u8; 32],
    pub chain_code: [u8; 32],
}

fn hmac_split(key: &[u8], data: &[&[u8]]) -> KeyNode {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("hmac takes any key length");
    for part in data {
        mac.update(part);
    }
    let i = mac.finalize().into_bytes();
    let mut chain_key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    chain_key.copy_from_slice(&i[..32]);
    chain_code.copy_from_slice(&i[32..]);
    KeyNode {
        chain_key,
        chain_code,
    }
}

impl KeyNode {
    /// `getMasterKeyFromSeed`.
    pub fn master(seed: &[u8]) -> Self {
        hmac_split(CURVE_SEED, &[seed])
    }

    /// `childKeyDerivationHardened`: `HMAC(chainCode, 0x00 || chainKey || be32(index + 2^31))`.
    pub fn child_hardened(&self, index: u32) -> Result<Self, Error> {
        if index >= HARDENED_OFFSET {
            return Err(Error::InvalidPath);
        }
        let index_be = (index + HARDENED_OFFSET).to_be_bytes();
        Ok(hmac_split(
            &self.chain_code,
            &[&[0u8], &self.chain_key, &index_be],
        ))
    }

    /// Derive along a path like `m/44'/1984'/0'/0'/0'`. Every segment must be hardened.
    pub fn derive_path(&self, path: &str) -> Result<Self, Error> {
        parse_path(path)?
            .into_iter()
            .try_fold(self.clone(), |node, index| node.child_hardened(index))
    }
}

/// `getPathSegments`, which accepts only `^m(/[0-9]+')+$`.
pub fn parse_path(path: &str) -> Result<Vec<u32>, Error> {
    let mut parts = path.split('/');
    if parts.next() != Some("m") {
        return Err(Error::InvalidPath);
    }
    let segments: Vec<u32> = parts
        .map(|seg| {
            let digits = seg.strip_suffix('\'').ok_or(Error::InvalidPath)?;
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::InvalidPath);
            }
            digits.parse::<u32>().map_err(|_| Error::InvalidPath)
        })
        .collect::<Result<_, _>>()?;
    if segments.is_empty() {
        return Err(Error::InvalidPath);
    }
    Ok(segments)
}
