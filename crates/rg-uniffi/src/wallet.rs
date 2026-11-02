use std::sync::Arc;

use rg_keys::WalletKeys;

use crate::RailgunError;

/// A fresh 12-word mnemonic as UTF-8 bytes, so a shell can wipe it after storing it. The core wipes its own copy, but UniFFI's return buffer is freed without a wipe, so call this once, when creating a wallet.
#[uniffi::export]
pub fn generate_mnemonic() -> Vec<u8> {
    rg_keys::generate_mnemonic().as_bytes().to_vec()
}

/// Spending and viewing keys, wiped when the last reference drops: `close()` in Kotlin, the last release in Swift. A shell keeps the mnemonic in its keychain and builds this when needed.
#[derive(uniffi::Object)]
pub struct Wallet {
    pub(crate) keys: WalletKeys,
}

#[uniffi::export]
impl Wallet {
    /// `mnemonic` is UTF-8 and crosses by reference, so the only copy outside the core is the shell's buffer, which it wipes after this returns. Pass `Data` in Swift and a direct `ByteBuffer` in Kotlin, never a `String`.
    #[uniffi::constructor]
    pub fn from_mnemonic(mnemonic: &[u8], index: u32) -> Result<Arc<Self>, RailgunError> {
        let mnemonic = std::str::from_utf8(mnemonic)
            .map_err(|_| RailgunError::invalid("mnemonic is not UTF-8"))?;
        let keys = WalletKeys::from_mnemonic(mnemonic, "", index)?;
        Ok(Arc::new(Wallet { keys }))
    }

    pub fn address(&self) -> Result<String, RailgunError> {
        Ok(self.keys.address()?)
    }
}
