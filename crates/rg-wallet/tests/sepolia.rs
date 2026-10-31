//! Sync and scan against the TS engine on real Sepolia logs.
//!
//! The wallet is the well-known public test mnemonic, which has notes on
//! Sepolia. `vectors/m3/sepolia-head-200.engine.json` is the engine's result
//! for the first 200 proxy logs (harness/m3.js).

use std::path::Path;

use rg_keys::WalletKeys;
use rg_primitives::field;
use rg_sync::{RawLog, SyncState};
use rg_wallet::{ScanResult, Scanner};
use serde_json::Value;

const MNEMONIC: &str = "test test test test test test test test test test test junk";

fn h(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn root_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
}

fn sync(path: &Path) -> SyncState {
    let logs = RawLog::parse_jsonl(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut state = SyncState::new();
    state.apply_all(&logs).unwrap();
    state
}

fn scan(state: &SyncState) -> ScanResult {
    Scanner::new(WalletKeys::from_mnemonic(MNEMONIC, "", 0).unwrap()).scan(state)
}

#[test]
fn head_200_matches_engine() {
    let dir = root_dir().join("vectors/m3");
    let state = sync(&dir.join("sepolia-head-200.jsonl"));
    let want: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("sepolia-head-200.engine.json")).unwrap(),
    )
    .unwrap();

    assert_eq!(
        state.counts.shield as u64,
        want["counts"]["shield"].as_u64().unwrap()
    );
    assert_eq!(
        state.counts.transact as u64,
        want["counts"]["transact"].as_u64().unwrap()
    );
    assert_eq!(
        state.counts.nullified as u64,
        want["counts"]["nullified"].as_u64().unwrap()
    );
    assert_eq!(
        state.nullifiers.len() as u64,
        want["nullifiers"].as_u64().unwrap()
    );

    let trees: Vec<(u64, String)> = state
        .trees
        .iter()
        .map(|t| (t.len() as u64, h(&field::to_be_bytes(&t.root()))))
        .collect();
    let want_trees: Vec<(u64, String)> = want["trees"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| {
            (
                t["leaves"].as_u64().unwrap(),
                t["root"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(trees, want_trees);

    let result = scan(&state);
    let txos: Vec<Value> = result
        .txos
        .iter()
        .map(|t| {
            serde_json::json!({
                "tree": t.tree,
                "position": t.position,
                "tokenHash": h(&t.token_hash),
                "value": t.value.to_string(),
                "nullifier": h(&t.nullifier),
                "spentTxid": t.spent.map(|s| h(&s.transaction_hash)),
            })
        })
        .collect();
    assert_eq!(Value::Array(txos), want["txos"]);

    let sent: Vec<Value> = result
        .sent
        .iter()
        .map(|s| {
            serde_json::json!({
                "tree": s.tree,
                "position": s.position,
                "tokenHash": h(&s.token_hash),
                "value": s.value.to_string(),
            })
        })
        .collect();
    assert_eq!(Value::Array(sent), want["sent"]);

    let balances: serde_json::Map<String, Value> = result
        .balances()
        .iter()
        .map(|(k, v)| (h(k), Value::String(v.to_string())))
        .collect();
    assert_eq!(Value::Object(balances), want["balances"]);

    // Every TXO has a valid Merkle proof against the current root.
    for t in &result.txos {
        let p = state.trees[t.tree as usize]
            .proof(t.position as usize)
            .unwrap();
        assert!(p.verify());
        assert_eq!(field::to_be_bytes(&p.leaf), t.commitment);
    }
}

/// Full Sepolia history to block 12031295, if `data/sepolia-logs.jsonl` is
/// present (it is not committed; ~23 MB). Expected values are the engine's
/// (harness/m3.js on the same file). Slow in debug builds, so ignored by
/// default: `cargo test --release -p rg-wallet -- --ignored`.
#[test]
#[ignore]
fn full_sepolia_matches_engine_when_data_present() {
    let path = root_dir().join("data/sepolia-logs.jsonl");
    if !path.exists() {
        eprintln!("skipped: {} not present", path.display());
        return;
    }
    let state = sync(&path);
    assert_eq!(state.leaf_count(), 11_423);
    assert_eq!(
        h(&field::to_be_bytes(&state.trees[0].root())),
        "0x0f65d1a1c615b46d955255ac37118cdf77191b71e3821718ab9703dfe54cf3b5"
    );
    let result = scan(&state);
    assert_eq!(result.txos.len(), 73);
    assert_eq!(result.sent.len(), 23);
    assert_eq!(result.unspent().count(), 24);
}
