use std::path::Path;

use rg_sync::{decode_log, decode_transact_call, Error, RailgunEvent, RawLog, SyncState};

fn vectors() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/m3")
}

fn head() -> Vec<RawLog> {
    RawLog::parse_jsonl(&std::fs::read_to_string(vectors().join("sepolia-head-200.jsonl")).unwrap())
        .unwrap()
}

#[test]
fn parses_etherscan_and_rpc_shapes() {
    let etherscan = serde_json::json!({
        "address": "0xecfcf3b4ec647c4ca6d49108b311b7a7c9543fea",
        "topics": ["0x781745c57906dc2f175fec80a9c691744c91c48a34a83672c41c2604774eb11f"],
        "data": "0x",
        "blockNumber": "0x5b2d1a",
        "transactionHash": format!("0x{}", "11".repeat(32)),
        "logIndex": "0x",
        "timeStamp": "0x66"
    });
    let l = RawLog::from_json(&etherscan).unwrap();
    assert_eq!(l.log_index, 0);
    assert_eq!(l.block_number, 0x5b2d1a);
    assert!(RawLog::from_json(&serde_json::json!({"address": "0x00"})).is_err());
}

#[test]
fn decodes_every_head_log_contiguously() {
    let mut next = 0u32;
    let mut seen = [0usize; 4];
    for l in head() {
        match decode_log(&l).unwrap() {
            Some(RailgunEvent::Shield {
                tree,
                start,
                commitments,
            }) => {
                assert_eq!((tree, start), (0, next));
                next += commitments.len() as u32;
                seen[0] += 1;
            }
            Some(RailgunEvent::Transact {
                tree,
                start,
                commitments,
            }) => {
                assert_eq!((tree, start), (0, next));
                next += commitments.len() as u32;
                seen[1] += 1;
            }
            Some(RailgunEvent::Nullified { .. }) => seen[2] += 1,
            Some(RailgunEvent::Unshield { .. }) => seen[3] += 1,
            None => {}
        }
    }
    assert_eq!(next, 141);
    assert!(seen.iter().all(|&n| n > 0));
}

#[test]
fn rejects_out_of_order_logs() {
    let logs = head();
    let mut state = SyncState::new();
    state.apply(&logs[1]).unwrap();
    assert!(matches!(
        state.apply(&logs[0]),
        Err(Error::OutOfOrder { .. })
    ));
    assert!(matches!(
        state.apply(&logs[1]),
        Err(Error::OutOfOrder { .. })
    ));
}

#[test]
fn rejects_gaps() {
    let logs = head();
    let mut state = SyncState::new();
    // Skip the first commitment-carrying log, so the next one starts past 0.
    let first = logs
        .iter()
        .position(|l| {
            matches!(
                decode_log(l).unwrap(),
                Some(RailgunEvent::Shield { .. } | RailgunEvent::Transact { .. })
            )
        })
        .unwrap();
    let second = logs
        .iter()
        .skip(first + 1)
        .find(|l| {
            matches!(
                decode_log(l).unwrap(),
                Some(RailgunEvent::Shield { .. } | RailgunEvent::Transact { .. })
            )
        })
        .unwrap();
    assert!(matches!(state.apply(second), Err(Error::Tree(_))));
}

#[test]
fn decodes_transact_calldata() {
    let v: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(vectors().join("sepolia-transact-call.json")).unwrap(),
    )
    .unwrap();
    let input = hex::decode(v["input"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let roots = decode_transact_call(&input).unwrap().unwrap();
    assert!(!roots.is_empty());
    assert!(roots.iter().all(|r| r.tree == 0));
    assert_eq!(decode_transact_call(&[0u8; 4]).unwrap(), None);
    assert!(decode_transact_call(&input[..100]).is_err());
}
