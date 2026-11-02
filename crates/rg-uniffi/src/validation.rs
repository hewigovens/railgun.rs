use rg_keys::{EvmAddress, decode_address, validate_mnemonic};

/// Checks the words and the checksum. `mnemonic` crosses as in `Wallet.from_mnemonic`.
#[uniffi::export]
pub fn is_valid_mnemonic(mnemonic: &[u8]) -> bool {
    std::str::from_utf8(mnemonic).is_ok_and(|m| validate_mnemonic(m).is_ok())
}

/// A `0zk` address.
#[uniffi::export]
pub fn is_valid_railgun_address(address: String) -> bool {
    decode_address(&address).is_ok()
}

/// A `0x` address, with its EIP-55 checksum checked when the letters are mixed case.
#[uniffi::export]
pub fn is_valid_evm_address(address: String) -> bool {
    address.parse::<EvmAddress>().is_ok()
}
