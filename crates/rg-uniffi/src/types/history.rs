use rg_core::{HistoryEntry, HistoryKind};
use rg_keys::EvmAddress;

#[uniffi::remote(Enum)]
pub enum HistoryKind {
    Shield,
    Receive,
    Send,
    Unshield,
}

/// One kind of movement of one token in one transaction. `value` is a decimal string, and an unshield's is before the contract's fee.
#[derive(uniffi::Record)]
pub struct HistoryItem {
    pub transaction_hash: String,
    pub block_number: u64,
    pub kind: HistoryKind,
    pub token: String,
    pub value: String,
    pub memo: Option<String>,
}

impl From<HistoryEntry> for HistoryItem {
    fn from(e: HistoryEntry) -> Self {
        let token: [u8; 20] = e.token_hash[12..].try_into().expect("20 bytes");
        HistoryItem {
            transaction_hash: format!("0x{}", hex::encode(e.transaction_hash)),
            block_number: e.block_number,
            kind: e.kind,
            token: EvmAddress(token).to_string(),
            value: e.value.to_string(),
            memo: e.memo,
        }
    }
}
