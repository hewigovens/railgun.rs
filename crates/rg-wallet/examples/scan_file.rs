//! Sync from a JSONL file of proxy logs and scan one wallet.
//!
//! cargo run --release -p rg-wallet --example scan_file -- <logs.jsonl> <mnemonic-file> [index]
//!
//! Prints JSON: event counts, per-tree leaf counts and roots, and the
//! wallet's TXOs, sent notes and balances.

use rg_keys::WalletKeys;
use rg_primitives::field;
use rg_sync::{RawLog, SyncState};
use rg_wallet::{Scanner, TxoSource};
use serde_json::json;

fn h(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let logs = RawLog::parse_jsonl(&std::fs::read_to_string(&args[1]).unwrap()).unwrap();
    let mnemonic = std::fs::read_to_string(&args[2]).unwrap();
    let index: u32 = args.get(3).map_or(0, |s| s.parse().unwrap());

    let t0 = std::time::Instant::now();
    let mut state = SyncState::new();
    state.apply_all(&logs).unwrap();
    let sync_ms = t0.elapsed().as_millis();

    let keys = WalletKeys::from_mnemonic(mnemonic.trim(), "", index).unwrap();
    let t1 = std::time::Instant::now();
    let scan = Scanner::new(keys).scan(&state);
    let scan_ms = t1.elapsed().as_millis();

    let out = json!({
        "logs": logs.len(),
        "lastBlock": state.last_applied().map(|l| l.0),
        "counts": {
            "shield": state.counts.shield,
            "transact": state.counts.transact,
            "nullified": state.counts.nullified,
            "unshield": state.counts.unshield,
            "other": state.counts.other,
        },
        "nullifiers": state.nullifiers.len(),
        "trees": state.trees.iter().map(|t| json!({"leaves": t.len(), "root": h(&field::to_be_bytes(&t.root()))})).collect::<Vec<_>>(),
        "txos": scan.txos.iter().map(|t| json!({
            "tree": t.tree,
            "position": t.position,
            "commitment": h(&t.commitment),
            "tokenHash": h(&t.token_hash),
            "value": t.value.to_string(),
            "nullifier": h(&t.nullifier),
            "source": match t.source { TxoSource::Shield => "shield", TxoSource::Transact => "transact" },
            "blockNumber": t.block_number,
            "txid": h(&t.transaction_hash),
            "spentTxid": t.spent.map(|s| h(&s.transaction_hash)),
            "memoText": t.memo_text,
        })).collect::<Vec<_>>(),
        "sent": scan.sent.iter().map(|s| json!({
            "tree": s.tree,
            "position": s.position,
            "tokenHash": h(&s.token_hash),
            "value": s.value.to_string(),
            "receiverMasterPublicKey": h(&field::to_be_bytes(&s.receiver_master_public_key)),
            "txid": h(&s.transaction_hash),
        })).collect::<Vec<_>>(),
        "balances": scan.balances().iter().map(|(k, v)| (h(k), v.to_string())).collect::<std::collections::BTreeMap<_, _>>(),
        "timingMs": {"sync": sync_ms, "scan": scan_ms},
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
