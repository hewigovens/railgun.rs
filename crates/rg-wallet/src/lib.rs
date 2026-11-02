//! Wallet scan over a [`SyncState`] (engine `wallet/abstract-wallet.ts` `createScannedDBCommitments`): trial-decrypt every commitment with the viewing key, keep notes whose recomputed commitment matches the leaf, mark them spent from the nullifier set, and sum unspent values per token.

mod scan_result;
mod scanner;

pub use scan_result::{ScanResult, SentNote, Txo, TxoSource};
pub use scanner::Scanner;
