//! Fetch a proxy's logs into a JSONL file. Resumes from the last block in the
//! file, so rerunning brings it up to the chain head. An empty file starts at
//! `from block`, by default the proxy's deployment.
//!
//! cargo run --release -p rg-sync --features rpc --example fetch_logs -- \
//!   <network> <rpc url> <logs.jsonl> [from block]

use std::io::Write;

use rg_sync::rpc::RpcClient;
use rg_sync::{Network, RawLog};

const CHUNK: u64 = 50_000;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let network = Network::by_name(&a[1]).expect("unknown network");
    let (url, path) = (&a[2], &a[3]);
    let from = a
        .get(4)
        .map_or(network.deployment_block, |b| b.parse().unwrap());
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let known = RawLog::parse_jsonl(&existing).unwrap();

    let rpc = RpcClient::new(url.as_str());
    let head = rpc.block_number().unwrap();
    let mut start = known.last().map_or(from, |l| l.block_number + 1);
    let mut out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    let mut added = 0;
    while start <= head {
        let end = (start + CHUNK - 1).min(head);
        // Whole chunks only: a partly written block would be skipped on resume.
        let logs = rpc.get_logs(network.proxy, start, end, CHUNK).unwrap();
        for log in &logs {
            writeln!(out, "{}", log.to_json()).unwrap();
        }
        added += logs.len();
        start = end + 1;
    }
    eprintln!("{} logs in {path}, to block {head}", known.len() + added);
}
