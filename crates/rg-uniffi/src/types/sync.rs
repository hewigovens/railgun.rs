pub use rg_core::SyncReport;

#[uniffi::remote(Record)]
pub struct SyncReport {
    pub head: u64,
    pub new_logs: u64,
    pub leaves: u64,
}
