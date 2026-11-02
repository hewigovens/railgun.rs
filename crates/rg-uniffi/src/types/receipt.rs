pub use rg_core::Receipt;

#[uniffi::remote(Record)]
pub struct Receipt {
    pub success: bool,
    pub block_number: u64,
    pub gas_used: u64,
}
