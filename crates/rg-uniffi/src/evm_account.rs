use std::sync::Arc;

use rg_keys::{EvmAddress, EvmKey};

use crate::RailgunError;

/// A public Ethereum account that pays gas. It is linked to nothing private on chain, but everything it sends is visible.
#[derive(uniffi::Object)]
pub struct EvmAccount {
    pub(crate) key: EvmKey,
}

#[uniffi::export]
impl EvmAccount {
    /// The standard account `m/44'/60'/0'/0/index`. `mnemonic` crosses as in `Wallet.from_mnemonic`.
    #[uniffi::constructor]
    pub fn from_mnemonic(mnemonic: &[u8], index: u32) -> Result<Arc<Self>, RailgunError> {
        let mnemonic = std::str::from_utf8(mnemonic)
            .map_err(|_| RailgunError::invalid("mnemonic is not UTF-8"))?;
        let key = EvmKey::from_mnemonic(mnemonic, "", index)?;
        Ok(Arc::new(EvmAccount { key }))
    }

    /// `private_key` is 32 raw bytes and crosses by reference.
    #[uniffi::constructor]
    pub fn from_private_key(private_key: &[u8]) -> Result<Arc<Self>, RailgunError> {
        let key = private_key
            .try_into()
            .map_err(|_| RailgunError::invalid("private key is not 32 bytes"))?;
        let key = EvmKey::from_bytes(key)?;
        Ok(Arc::new(EvmAccount { key }))
    }

    /// EIP-55 checksummed.
    pub fn address(&self) -> String {
        EvmAddress(self.key.address()).to_string()
    }
}
