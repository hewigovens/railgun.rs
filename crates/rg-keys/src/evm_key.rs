use std::fmt;

use bip32::{DerivationPath, XPrv};
use k256::ecdsa::SigningKey;
use zeroize::Zeroizing;

use crate::Error;
use crate::evm_address::{EvmAddress, keccak256};
use crate::keys::mnemonic_to_seed;

/// A public Ethereum account for paying gas, wiped on drop. Keep it apart from [`crate::WalletKeys`]: everything it sends is public.
pub struct EvmKey(SigningKey);

/// `r`, `s` and the parity of the signature point's y, with `s` in the lower half as Ethereum requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub y_parity: bool,
}

impl EvmKey {
    /// The standard account `m/44'/60'/0'/0/index`, as MetaMask derives it.
    pub fn from_mnemonic(mnemonic: &str, password: &str, index: u32) -> Result<Self, Error> {
        let seed = mnemonic_to_seed(mnemonic, password)?;
        let path: DerivationPath = format!("m/44'/60'/0'/0/{index}")
            .parse()
            .map_err(|_| Error::InvalidPath)?;
        let key =
            XPrv::derive_from_path(seed.as_slice(), &path).map_err(|_| Error::InvalidEvmKey)?;
        Ok(EvmKey(key.private_key().clone()))
    }

    pub fn from_bytes(key: &[u8; 32]) -> Result<Self, Error> {
        SigningKey::from_slice(key)
            .map(EvmKey)
            .map_err(|_| Error::InvalidEvmKey)
    }

    pub fn address(&self) -> [u8; 20] {
        let point = self.0.verifying_key().to_encoded_point(false);
        let hash = keccak256(&point.as_bytes()[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        address
    }

    /// Signs a 32-byte hash, with the nonce from RFC 6979.
    pub fn sign_hash(&self, hash: &[u8; 32]) -> Result<EvmSignature, Error> {
        let (signature, recovery) = self
            .0
            .sign_prehash_recoverable(hash)
            .map_err(|_| Error::Signing)?;
        let bytes = Zeroizing::new(signature.to_bytes());
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        Ok(EvmSignature {
            r,
            s,
            y_parity: recovery.is_y_odd(),
        })
    }
}

impl fmt::Debug for EvmKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EvmKey({})", EvmAddress(self.address()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MNEMONIC: &str = "test test test test test test test test test test test junk";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn derives_the_standard_accounts() {
        let address = |index| {
            hex(&EvmKey::from_mnemonic(MNEMONIC, "", index)
                .unwrap()
                .address())
        };
        assert_eq!(address(0), "f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        assert_eq!(address(1), "70997970c51812dc3a010c7d01b50e0d17dc79c8");
    }

    #[test]
    fn rejects_a_zero_key() {
        assert_eq!(
            EvmKey::from_bytes(&[0; 32]).unwrap_err(),
            Error::InvalidEvmKey
        );
    }
}
