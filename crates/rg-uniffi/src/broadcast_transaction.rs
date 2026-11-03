use rg_keys::EvmAddress;

/// A batch proved for one broadcaster, from `build_broadcast_transfer` or `build_broadcast_unshield`. Show the fee, then pass it to `broadcast`.
#[derive(uniffi::Object)]
pub struct BroadcastTransaction {
    pub(crate) tx: rg_core::BroadcastTx,
}

#[uniffi::export]
impl BroadcastTransaction {
    /// The checksummed token the fee is paid in.
    pub fn token(&self) -> String {
        EvmAddress(self.tx.token).to_string()
    }

    /// What the broadcaster gets from the private balance, on top of the amount sent, as a decimal string.
    pub fn fee(&self) -> String {
        self.tx.fee.to_string()
    }

    pub fn gas_estimate(&self) -> u64 {
        self.tx.gas_estimate
    }
}
