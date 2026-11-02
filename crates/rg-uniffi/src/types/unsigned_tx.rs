pub use rg_core::UnsignedTx;

#[uniffi::remote(Record)]
pub struct UnsignedTx {
    pub chain_id: u64,
    pub to: String,
    pub data: Vec<u8>,
}
