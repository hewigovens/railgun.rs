//! A thin command line over [`rg_core::Client`].
//!
//! cargo run --release -p rg-core --example wallet -- <network> <rpc url> <data dir> <mnemonic-file> <command>
//!
//!   sync
//!   balance
//!   transfer <artifacts dir> <recipient 0zk> <token> <value> [memo]   prints JSONL for harness/send.js
//!   estimate <from> <transfer jsonl>
//!   poi <artifacts dir>/poi-3x3 <tx hash> [--submit]
//!   poi-status <blinded commitment>...

use std::path::Path;

use rg_core::{Client, FileStore, Transfer};
use rg_keys::WalletKeys;
use rg_sync::Network;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<String> = std::env::args().collect();
    let network = Network::by_name(&a[1]).ok_or("unknown network")?;
    let store = FileStore::open(Path::new(&a[3]).join(network.name))?;
    let mut client = Client::open(network, &a[2], store)?;
    let mnemonic = std::fs::read_to_string(&a[4])?;
    let keys = WalletKeys::from_mnemonic(mnemonic.trim(), "", 0)?;
    let hash = |s: &str| -> Result<[u8; 32], Box<dyn std::error::Error>> {
        hex::decode(s.trim_start_matches("0x"))?
            .try_into()
            .map_err(|_| "expected 32 bytes".into())
    };

    match a[5].as_str() {
        "sync" => println!("{:?}", client.sync()?),
        "balance" => {
            for (token, value) in client.scan(&keys).balances() {
                println!("0x{} {value}", hex::encode(&token[12..]));
            }
        }
        "transfer" => {
            let token = hex::decode(a[8].trim_start_matches("0x"))?;
            let tx = client.build_transfer(
                &keys,
                &Transfer {
                    recipient: &a[7],
                    token: token.try_into().map_err(|_| "expected 20 bytes")?,
                    value: a[9].parse()?,
                    memo: a.get(10).map(String::as_str),
                },
                Path::new(&a[6]),
            )?;
            println!(
                "{}",
                serde_json::json!({"label": "transact", "to": tx.to, "value": "0", "data": tx.data_hex()})
            );
        }
        "estimate" => {
            let tx: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&a[7])?)?;
            let data = hex::decode(
                tx["data"]
                    .as_str()
                    .ok_or("no data")?
                    .trim_start_matches("0x"),
            )?;
            let tx = rg_core::UnsignedTx {
                chain_id: network.chain_id,
                to: network.proxy.to_string(),
                data,
            };
            println!("{} gas", client.estimate_gas(&a[6], &tx)?);
        }
        "poi" => {
            let proof = client.prove_poi(&keys, &hash(&a[7])?, Path::new(&a[6]))?;
            println!("before: {:?}", client.poi_status(&proof.blinded_out)?);
            if a.get(8).is_some_and(|s| s == "--submit") {
                client.submit_poi(&proof)?;
                println!("after: {:?}", client.poi_status(&proof.blinded_out)?);
            }
        }
        "poi-status" => println!("{:?}", client.poi_status(&a[6..])?),
        other => return Err(format!("unknown command {other}").into()),
    }
    Ok(())
}
