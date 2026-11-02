//! A thin command line over [`rg_core::Client`].
//!
//! cargo run --release -p rg-core --example wallet -- <network> <rpc url> <data dir> <mnemonic-file> <command>
//!
//!   sync
//!   balance
//!   transfer <recipient 0zk> <token> <value> [memo]   prints the call as JSON
//!   unshield <to> <token> <value>                     prints the same
//!   estimate <from> <transaction json>
//!   send <evm key file> <transaction json>           signs, sends and waits
//!   shield <evm key file> <token> <value>             approves if needed, then shields to this wallet
//!
//! An EVM key file holds one `0x` hex private key. That account pays gas and is public.
//!   poi <tx hash> [--submit | --full]
//!
//! Artifacts download into `<data dir>/artifacts` when first needed.

use std::path::Path;

use rg_core::{
    Artifacts, ChainStore, Client, FileStore, Receipt, Shield, Transfer, Unshield, UnsignedTx,
};
use rg_keys::{EvmKey, WalletKeys, Zeroizing};
use rg_sync::Network;

/// Reads a `0x` hex private key file.
fn evm_key(path: &str) -> Result<EvmKey, Box<dyn std::error::Error>> {
    let text = Zeroizing::new(std::fs::read_to_string(path)?);
    let bytes = Zeroizing::new(hex::decode(text.trim().trim_start_matches("0x"))?);
    let key: &[u8; 32] = bytes.as_slice().try_into()?;
    Ok(EvmKey::from_bytes(key)?)
}

/// Sends and waits for the receipt, and fails on a revert.
fn send_and_wait<S: ChainStore>(
    client: &Client<S>,
    key: &EvmKey,
    tx: &UnsignedTx,
) -> Result<Receipt, Box<dyn std::error::Error>> {
    let hash = client.send(key, tx)?;
    println!("0x{}", hex::encode(hash));
    for _ in 0..120 {
        if let Some(receipt) = client.receipt(&hash)? {
            println!("{receipt:?}");
            return if receipt.success {
                Ok(receipt)
            } else {
                Err("reverted".into())
            };
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Err("no receipt after two minutes".into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<String> = std::env::args().collect();
    let network = Network::by_name(&a[1]).ok_or("unknown network")?;
    let data = Path::new(&a[3]);
    let store = FileStore::open(data.join(network.name))?;
    let artifacts = Artifacts::new(data.join("artifacts"));
    let mut client = Client::open(network, &a[2], store)?;
    let mnemonic = Zeroizing::new(std::fs::read_to_string(&a[4])?);
    let keys = WalletKeys::from_mnemonic(mnemonic.trim(), "", 0)?;
    let hash = |s: &str| -> Result<[u8; 32], Box<dyn std::error::Error>> {
        hex::decode(s.trim_start_matches("0x"))?
            .try_into()
            .map_err(|_| "expected 32 bytes".into())
    };

    let address = |s: &str| -> Result<[u8; 20], Box<dyn std::error::Error>> {
        hex::decode(s.trim_start_matches("0x"))?
            .try_into()
            .map_err(|_| "expected 20 bytes".into())
    };
    let print_tx = |tx: &UnsignedTx| {
        println!(
            "{}",
            serde_json::json!({"label": "transact", "to": tx.to, "value": "0", "data": tx.data_hex()})
        );
    };

    match a[5].as_str() {
        "sync" => println!("{:?}", client.sync()?),
        "balance" => {
            for (token, value) in client.scan(&keys).balances() {
                println!("0x{} {value}", hex::encode(&token[12..]));
            }
        }
        "transfer" => {
            let tx = client.build_transfer(
                &keys,
                &Transfer {
                    recipient: &a[6],
                    token: address(&a[7])?,
                    value: a[8].parse()?,
                    memo: a.get(9).map(String::as_str),
                },
                &artifacts,
            )?;
            print_tx(&tx);
        }
        "unshield" => {
            let tx = client.build_unshield(
                &keys,
                &Unshield {
                    to: address(&a[6])?,
                    token: address(&a[7])?,
                    value: a[8].parse()?,
                },
                &artifacts,
            )?;
            print_tx(&tx);
        }
        "shield" => {
            // shield <evm-key-file> <token> <value>, to this wallet.
            let key = evm_key(&a[6])?;
            let (token, value) = (address(&a[7])?, a[8].parse()?);
            if client.allowance(&key.address(), &token)? < value {
                send_and_wait(&client, &key, &client.build_approve(token, value)?)?;
            }
            let receiver = keys.address()?;
            let shield = Shield {
                receiver: &receiver,
                token,
                value,
            };
            send_and_wait(&client, &key, &client.build_shield(&shield)?)?;
        }
        "send" => {
            // send <evm-key-file> <tx.jsonl>, from `transfer` or `unshield`.
            let key = evm_key(&a[6])?;
            let tx: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&a[7])?)?;
            let data = tx["data"].as_str().ok_or("no data")?;
            let tx = UnsignedTx {
                chain_id: network.chain_id,
                to: tx["to"].as_str().ok_or("no to")?.to_string(),
                data: hex::decode(data.trim_start_matches("0x"))?,
            };
            send_and_wait(&client, &key, &tx)?;
        }
        "estimate" => {
            let tx: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&a[7])?)?;
            let data = hex::decode(
                tx["data"]
                    .as_str()
                    .ok_or("no data")?
                    .trim_start_matches("0x"),
            )?;
            let tx = UnsignedTx {
                chain_id: network.chain_id,
                to: network.proxy.to_string(),
                data,
            };
            println!("{} gas", client.estimate_gas(&a[6], &tx)?);
        }
        "poi" => {
            let flag = a.get(7).map(String::as_str);
            let size = (flag == Some("--full")).then_some(rg_poi::FULL_CIRCUIT);
            let proof = client.prove_poi_on(&keys, &hash(&a[6])?, &artifacts, size)?;
            println!("before: {:?}", client.poi_status(&proof)?);
            if flag == Some("--submit") {
                client.submit_poi(&proof)?;
                println!("after: {:?}", client.poi_status(&proof)?);
            }
        }
        other => return Err(format!("unknown command {other}").into()),
    }
    Ok(())
}
