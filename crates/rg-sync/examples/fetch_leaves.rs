//! Fetch every leaf hash from the squid up to a block, rebuild the trees and
//! check the last root against the contract, then write the seed that
//! `SyncState::seed_from_text` reads. The block printed is where proxy logs
//! must start. Seeded leaves carry no ciphertexts or nullifiers, so a wallet's
//! notes must all be after that block.
//!
//! cargo run --release -p rg-sync --features rpc --example fetch_leaves -- \
//!   <network> <rpc url> <seed.txt>

use std::fmt::Write;

use rg_primitives::field;
use rg_sync::rpc::RpcClient;
use rg_sync::{squid, Network, SyncState};

/// Stay behind the head so the contract has the root at the chosen block.
const BEHIND_HEAD: u64 = 1_000;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let network = Network::by_name(&a[1]).expect("unknown network");
    let rpc = RpcClient::new(a[2].as_str());
    let url = network.squid.expect("this network has no squid");
    let to_block = rpc.block_number().unwrap() - BEHIND_HEAD;

    let leaves = squid::fetch_leaves(url, to_block).unwrap();
    let mut text = String::new();
    for l in &leaves {
        writeln!(text, "{} {} {}", l.tree, l.position, hex::encode(l.hash)).unwrap();
    }
    let mut state = SyncState::new();
    state.seed_from_text(&text).unwrap();

    let tree = (state.trees.len() - 1) as u32;
    let root = field::to_be_bytes(&state.root(tree).unwrap());
    assert!(
        rpc.root_history(network.proxy, tree, root, None).unwrap(),
        "tree {tree} root {} is not in the contract's history",
        hex::encode(root)
    );
    std::fs::write(&a[3], text).unwrap();
    println!(
        "{} leaves, tree {tree} root 0x{} known to the contract",
        leaves.len(),
        hex::encode(root)
    );
    let last = leaves.iter().map(|l| l.block_number).max().unwrap();
    // Not `to_block + 1`: the squid may lag, and it indexes whole blocks.
    println!("start logs at block {}", last + 1);
}
