//! Replays proxy logs and checks that every root a successful `transact` call proved against was already in the rebuilt root history before that call's block. The contract rejects unknown roots, so every root in a successful call is a real historical root.
//!
//! cargo run --release -p rg-sync --example check_roots -- <logs.jsonl> <calls.json>
//! calls.json: [{"hash", "blockNumber", "input"}], as Etherscan's txlist gives them.

use rg_sync::{RawLog, SyncState, decode_transact_call};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let logs = RawLog::parse_jsonl(&std::fs::read_to_string(&args[1]).unwrap()).unwrap();
    let calls: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&args[2]).unwrap()).unwrap();
    let mut calls: Vec<(u64, String, Vec<u8>)> = calls
        .iter()
        .map(|c| {
            (
                c["blockNumber"].as_u64().unwrap(),
                c["hash"].as_str().unwrap().to_string(),
                hex::decode(c["input"].as_str().unwrap().trim_start_matches("0x")).unwrap(),
            )
        })
        .collect();
    calls.sort();

    let mut state = SyncState::new();
    let mut li = 0;
    let (mut checked, mut missing) = (0usize, Vec::new());
    for (block, hash, input) in &calls {
        while li < logs.len() && logs[li].block_number < *block {
            state.apply(&logs[li]).unwrap();
            li += 1;
        }
        for r in decode_transact_call(input).unwrap().unwrap() {
            checked += 1;
            if !state.is_known_root(r.tree as u32, &r.root) {
                missing.push((hash.clone(), r.tree, hex::encode(r.root)));
            }
        }
    }
    println!(
        "calls {} transactions {} roots found {} missing {}",
        calls.len(),
        checked,
        checked - missing.len(),
        missing.len()
    );
    for m in missing.iter().take(10) {
        println!("missing {m:?}");
    }
    std::process::exit(if missing.is_empty() { 0 } else { 1 });
}
