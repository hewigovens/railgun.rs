use std::sync::Arc;

use rg_keys::{ViewOnlyKeys, WalletKeys};

use crate::RailgunError;

/// A fresh 12-word mnemonic as UTF-8 bytes, so a shell can wipe it after storing it. The core wipes its own copy, but UniFFI's return buffer is freed without a wipe, so call this once, when creating a wallet.
#[uniffi::export]
pub fn generate_mnemonic() -> Vec<u8> {
    rg_keys::generate_mnemonic().as_bytes().to_vec()
}

enum Keys {
    Spending(WalletKeys),
    ViewOnly(ViewOnlyKeys),
}

/// Spending and viewing keys, or viewing keys alone for a view-only wallet, wiped when the last reference drops: `close()` in Kotlin, the last release in Swift. A shell keeps the mnemonic or shareable viewing key in its keychain and builds this when needed.
#[derive(uniffi::Object)]
pub struct Wallet {
    keys: Keys,
}

impl Wallet {
    pub(crate) fn view(&self) -> &ViewOnlyKeys {
        match &self.keys {
            Keys::Spending(keys) => keys,
            Keys::ViewOnly(view) => view,
        }
    }

    pub(crate) fn spending(&self) -> Result<&WalletKeys, RailgunError> {
        match &self.keys {
            Keys::Spending(keys) => Ok(keys),
            Keys::ViewOnly(_) => Err(RailgunError::invalid(
                "a view-only wallet cannot spend or prove POI",
            )),
        }
    }
}

#[uniffi::export]
impl Wallet {
    /// `mnemonic` is UTF-8 and crosses by reference, so the only copy outside the core is the shell's buffer, which it wipes after this returns. Pass `Data` in Swift and a direct `ByteBuffer` in Kotlin, never a `String`.
    #[uniffi::constructor]
    pub fn from_mnemonic(mnemonic: &[u8], index: u32) -> Result<Arc<Self>, RailgunError> {
        let mnemonic = std::str::from_utf8(mnemonic)
            .map_err(|_| RailgunError::invalid("mnemonic is not UTF-8"))?;
        let keys = WalletKeys::from_mnemonic(mnemonic, "", index)?;
        Ok(Arc::new(Wallet {
            keys: Keys::Spending(keys),
        }))
    }

    /// A view-only wallet from a shareable viewing key (as from Railway or `shareable_viewing_key`): it scans, shows balances and history, and cannot spend. The key crosses by reference like a mnemonic.
    #[uniffi::constructor]
    pub fn from_shareable_viewing_key(key: &[u8]) -> Result<Arc<Self>, RailgunError> {
        let key = std::str::from_utf8(key)
            .map_err(|_| RailgunError::invalid("viewing key is not UTF-8"))?;
        let view = ViewOnlyKeys::from_shareable_viewing_key(key)?;
        Ok(Arc::new(Wallet {
            keys: Keys::ViewOnly(view),
        }))
    }

    pub fn address(&self) -> Result<String, RailgunError> {
        Ok(self.view().address()?)
    }

    pub fn is_view_only(&self) -> bool {
        matches!(self.keys, Keys::ViewOnly(_))
    }

    /// The shareable viewing key as UTF-8 bytes. It shows whoever holds it every note and transaction of this wallet, so wipe the buffer once it is stored or shown. As with `generate_mnemonic`, UniFFI frees its return buffer without a wipe.
    pub fn shareable_viewing_key(&self) -> Vec<u8> {
        self.view().shareable_viewing_key().as_bytes().to_vec()
    }
}
