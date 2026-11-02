//! Wallet keys from a mnemonic (engine src/key-derivation/wallet-node.ts).

use std::fmt;

use ed25519_dalek::SigningKey;
use rand::RngCore;
use rand::rngs::OsRng;
use rg_primitives::babyjubjub::{self, Point};
use rg_primitives::{Fr, PrivateKey, field, poseidon};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Error;
use crate::address::{ADDRESS_VERSION, AddressData, encode_address};
use crate::bip32::KeyNode;

pub const SPENDING_PATH_PREFIX: &str = "m/44'/1984'/0'/0'/";
pub const VIEWING_PATH_PREFIX: &str = "m/420'/1984'/0'/0'/";

pub fn spending_path(index: u32) -> String {
    format!("{SPENDING_PATH_PREFIX}{index}'")
}

pub fn viewing_path(index: u32) -> String {
    format!("{VIEWING_PATH_PREFIX}{index}'")
}

/// All keys of one Railgun wallet index, wiped on drop. Not `Clone`, so one value holds them; borrow it.
#[derive(ZeroizeOnDrop)]
pub struct WalletKeys {
    pub spending_private_key: PrivateKey,
    #[zeroize(skip)]
    pub spending_public_key: Point,
    pub viewing_private_key: PrivateKey,
    #[zeroize(skip)]
    pub viewing_public_key: [u8; 32],
    pub nullifying_key: Fr,
    #[zeroize(skip)]
    pub master_public_key: Fr,
}

impl fmt::Debug for WalletKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletKeys")
            .field("master_public_key", &self.master_public_key)
            .finish_non_exhaustive()
    }
}

/// BIP39 seed. The engine's `Mnemonic.toSeed` does not check the checksum; this parses the mnemonic and rejects bad checksums, which is stricter.
pub fn mnemonic_to_seed(mnemonic: &str, password: &str) -> Result<Zeroizing<[u8; 64]>, Error> {
    let m = bip39::Mnemonic::parse_normalized(mnemonic)
        .map_err(|e| Error::InvalidMnemonic(e.to_string()))?;
    Ok(Zeroizing::new(m.to_seed_normalized(password)))
}

/// Checks the words and the checksum without deriving the seed, which is slow.
pub fn validate_mnemonic(mnemonic: &str) -> Result<(), Error> {
    bip39::Mnemonic::parse_normalized(mnemonic)
        .map(drop)
        .map_err(|e| Error::InvalidMnemonic(e.to_string()))
}

/// A fresh 12-word mnemonic from the OS random source.
pub fn generate_mnemonic() -> Zeroizing<String> {
    let mut entropy = Zeroizing::new([0u8; 16]);
    OsRng.fill_bytes(&mut *entropy);
    let mnemonic =
        bip39::Mnemonic::from_entropy(&*entropy).expect("16 bytes is a valid entropy length");
    Zeroizing::new(mnemonic.to_string())
}

impl WalletKeys {
    /// The 0zk address, valid on every chain.
    pub fn address(&self) -> Result<String, Error> {
        encode_address(&AddressData {
            master_public_key: self.master_public_key,
            viewing_public_key: self.viewing_public_key,
            chain: None,
            version: ADDRESS_VERSION,
        })
    }

    pub fn from_mnemonic(mnemonic: &str, password: &str, index: u32) -> Result<Self, Error> {
        Self::from_seed(&*mnemonic_to_seed(mnemonic, password)?, index)
    }

    pub fn from_seed(seed: &[u8], index: u32) -> Result<Self, Error> {
        let master = KeyNode::master(seed);
        let spending = master.derive_path(&spending_path(index))?;
        let viewing = master.derive_path(&viewing_path(index))?;
        Ok(Self::from_private_keys(
            PrivateKey::new(spending.chain_key),
            PrivateKey::new(viewing.chain_key),
        ))
    }

    pub fn from_private_keys(
        spending_private_key: PrivateKey,
        viewing_private_key: PrivateKey,
    ) -> Self {
        let spending_public_key = babyjubjub::private_to_public(spending_private_key.expose());
        let viewing_public_key = viewing_public_key(viewing_private_key.expose());
        let nullifying_key = nullifying_key(viewing_private_key.expose());
        let master_public_key = master_public_key(&spending_public_key, &nullifying_key);
        WalletKeys {
            spending_private_key,
            spending_public_key,
            viewing_private_key,
            viewing_public_key,
            nullifying_key,
            master_public_key,
        }
    }
}

/// Ed25519 public key of the viewing key (noble `getPublicKey`, RFC 8032).
pub fn viewing_public_key(viewing_private_key: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(viewing_private_key)
        .verifying_key()
        .to_bytes()
}

/// `poseidon([viewingPrivateKey as big-endian integer])`.
pub fn nullifying_key(viewing_private_key: &[u8; 32]) -> Fr {
    let mut x = field::from_be_bytes_mod_order(viewing_private_key);
    let key = poseidon::hash(&[x]).expect("arity 1");
    x.zeroize();
    key
}

/// `poseidon([Ax, Ay, nullifyingKey])`.
pub fn master_public_key(spending_public_key: &Point, nullifying_key: &Fr) -> Fr {
    poseidon::hash(&[
        spending_public_key.x,
        spending_public_key.y,
        *nullifying_key,
    ])
    .expect("arity 3")
}

#[cfg(test)]
mod tests {
    use std::mem::ManuallyDrop;

    use super::*;

    fn keys() -> WalletKeys {
        WalletKeys::from_private_keys(PrivateKey::new([1; 32]), PrivateKey::new([2; 32]))
    }

    #[test]
    fn drop_wipes_every_secret() {
        let mut keys = ManuallyDrop::new(keys());
        let public = keys.master_public_key;
        // SAFETY: the fields are plain bytes, which stay readable after the drop glue runs, and `ManuallyDrop` stops a second drop.
        unsafe { ManuallyDrop::drop(&mut keys) };
        assert_eq!(keys.spending_private_key.expose(), &[0; 32]);
        assert_eq!(keys.viewing_private_key.expose(), &[0; 32]);
        assert_eq!(keys.nullifying_key, Fr::from(0u64));
        assert_eq!(keys.master_public_key, public);
    }

    #[test]
    fn debug_output_has_no_secrets() {
        let keys = keys();
        let printed = format!("{keys:?}");
        assert!(!printed.contains(&keys.nullifying_key.to_string()));
        assert!(!printed.contains("1, 1, 1"));
        assert!(!printed.contains("2, 2, 2"));
    }
}
