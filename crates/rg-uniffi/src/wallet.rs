use std::sync::Arc;

use rg_keys::WalletKeys;

use crate::RailgunError;

#[uniffi::export]
pub fn generate_mnemonic() -> String {
    rg_keys::generate_mnemonic()
}

/// Spending and viewing keys. A shell keeps the mnemonic in its keychain and builds this when needed.
#[derive(uniffi::Object)]
pub struct Wallet {
    pub(crate) keys: WalletKeys,
}

#[uniffi::export]
impl Wallet {
    #[uniffi::constructor]
    pub fn from_mnemonic(mnemonic: String, index: u32) -> Result<Arc<Self>, RailgunError> {
        let keys = WalletKeys::from_mnemonic(&mnemonic, "", index)?;
        Ok(Arc::new(Wallet { keys }))
    }

    pub fn address(&self) -> Result<String, RailgunError> {
        Ok(self.keys.address()?)
    }
}
