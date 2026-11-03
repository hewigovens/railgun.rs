/// A call to sign and send. `value` is the wei it sends along, as a decimal string, and only a native ETH shield sets it.
#[derive(uniffi::Record)]
pub struct UnsignedTx {
    pub chain_id: u64,
    pub to: String,
    pub value: String,
    pub data: Vec<u8>,
}

impl From<rg_core::UnsignedTx> for UnsignedTx {
    fn from(tx: rg_core::UnsignedTx) -> Self {
        UnsignedTx {
            chain_id: tx.chain_id,
            to: tx.to,
            value: tx.value.to_string(),
            data: tx.data,
        }
    }
}

impl TryFrom<UnsignedTx> for rg_core::UnsignedTx {
    type Error = crate::RailgunError;

    fn try_from(tx: UnsignedTx) -> Result<Self, Self::Error> {
        Ok(rg_core::UnsignedTx {
            chain_id: tx.chain_id,
            to: tx.to,
            value: crate::client::amount(&tx.value)?,
            data: tx.data,
        })
    }
}
