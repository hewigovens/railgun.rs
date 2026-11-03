//! A thin command line over [`rg_core::Client`].
//!
//! cargo run --release -p rg-core --example wallet -- <network> <rpc url> <data dir> <mnemonic-file> <command>
//!
//!   sync
//!   balance                                           by POI status, from the aggregator
//!   history
//!   transfer <recipient 0zk> <token> <value> [memo]   prints the call as JSON
//!   unshield <to> <token> <value>                     prints the same
//!   unshield-eth <to> <value>                         wrapped ETH out as ETH, prints the call
//!   estimate <from> <transaction json>               prints the fee quote
//!   send <evm key file> <transaction json>           quotes, signs, sends and waits
//!   shield <evm key file> <token> <value>             approves if needed, then shields to this wallet
//!   shield-eth <evm key file> <wei>                   shields ETH to this wallet as wrapped ETH
//!   broadcasters <token>                              live offers for the token, cheapest first
//!   broadcast-transfer <recipient 0zk> <token> <value> [--send]
//!   broadcast-unshield <to> <token> <value> [--send]  through the cheapest broadcaster, which pays gas:
//!                                                     proves and prints the fee, and with --send hands it over
//!
//! An EVM key file holds one `0x` hex private key. That account pays gas and is public.
//!   poi <tx hash> [--submit | --full]
//!
//! Artifacts download into `<data dir>/artifacts` when first needed.

use std::path::Path;

use rg_core::{
    Artifacts, BroadcasterFees, Broadcasters, ChainStore, Client, FileStore, POI_LIST, Receipt,
    Shield, Transfer, Unshield, UnshieldBaseToken, UnsignedTx, Waku,
};
use rg_keys::{EvmAddress, EvmKey, WalletKeys, Zeroizing};
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
    let fee = client.quote_fee(&key.address(), tx)?;
    println!("{fee:?}, at most {} wei", fee.max_cost());
    let hash = client.send(key, tx, &fee)?;
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

/// Reads a call that `transfer` or `unshield` printed.
fn read_tx(path: &str, chain_id: u64) -> Result<UnsignedTx, Box<dyn std::error::Error>> {
    let tx: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let data = tx["data"].as_str().ok_or("no data")?;
    Ok(UnsignedTx {
        chain_id,
        to: tx["to"].as_str().ok_or("no to")?.to_string(),
        value: tx["value"].as_str().unwrap_or("0").parse()?,
        data: hex::decode(data.trim_start_matches("0x"))?,
    })
}

fn token(hash: &[u8; 32]) -> Result<EvmAddress, Box<dyn std::error::Error>> {
    Ok(EvmAddress(hash[12..].try_into()?))
}

fn print_balances<S: ChainStore>(
    client: &Client<S>,
    keys: &WalletKeys,
) -> Result<(), Box<dyn std::error::Error>> {
    for b in client.balances(keys)? {
        println!("{} {b:?}", token(&b.token_hash)?);
    }
    Ok(())
}

fn print_history<S: ChainStore>(
    client: &Client<S>,
    keys: &WalletKeys,
) -> Result<(), Box<dyn std::error::Error>> {
    for e in client.history(keys) {
        let memo = e.memo.as_deref().unwrap_or("");
        println!(
            "{} 0x{} {:?} {} {} {memo}",
            e.block_number,
            hex::encode(e.transaction_hash),
            e.kind,
            token(&e.token_hash)?,
            e.value
        );
    }
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// `broadcasters`, `broadcast-transfer` and `broadcast-unshield`.
fn broadcast_command<S: ChainStore>(
    client: &Client<S>,
    keys: &WalletKeys,
    artifacts: &Artifacts,
    a: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let chain_id = Network::by_name(&a[1]).ok_or("unknown network")?.chain_id;
    let mut broadcasters = Broadcasters::new(Waku::railgun()?, chain_id);
    let at = if a[5] == "broadcasters" { 6 } else { 7 };
    let token = a[at].parse::<EvmAddress>()?.0;
    if a[5] == "broadcasters" {
        let mut live: Vec<BroadcasterFees> = broadcasters
            .offers()?
            .into_iter()
            .filter(|o| o.is_live(now_ms()) && o.fees.contains_key(&token))
            .collect();
        live.sort_by_key(|o| o.fees[&token]);
        for o in live {
            let id = o.identifier.as_deref().unwrap_or("");
            println!(
                "{} {} {id} v{} reliability {}",
                o.fees[&token], o.railgun_address, o.version, o.reliability
            );
        }
        return Ok(());
    }
    let offer = broadcasters
        .best_offer(&token, POI_LIST)?
        .ok_or("no live broadcaster takes this token")?;
    let tx = if a[5] == "broadcast-transfer" {
        let transfer = Transfer {
            recipient: &a[6],
            token,
            value: a[8].parse()?,
            memo: None,
        };
        client.build_broadcast_transfer(keys, &transfer, &offer, artifacts)?
    } else {
        let unshield = Unshield {
            to: a[6].parse::<EvmAddress>()?.0,
            token,
            value: a[8].parse()?,
        };
        client.build_broadcast_unshield(keys, &unshield, &offer, artifacts)?
    };
    println!(
        "fee {} to {} ({} gas at {} wei)",
        tx.fee, offer.railgun_address, tx.gas_estimate, tx.gas_price
    );
    if a.get(9).map(String::as_str) == Some("--send") {
        println!(
            "0x{}",
            hex::encode(client.broadcast(&mut broadcasters, &tx)?)
        );
    }
    Ok(())
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
        Ok(s.parse::<EvmAddress>()?.0)
    };
    let print_tx = |tx: &UnsignedTx| {
        println!(
            "{}",
            serde_json::json!({"label": "transact", "to": tx.to, "value": tx.value.to_string(), "data": tx.data_hex()})
        );
    };

    match a[5].as_str() {
        "sync" => println!("{:?}", client.sync()?),
        "balance" => print_balances(&client, &keys)?,
        "history" => print_history(&client, &keys)?,
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
        "unshield-eth" => {
            let unshield = UnshieldBaseToken {
                to: address(&a[6])?,
                value: a[7].parse()?,
            };
            print_tx(&client.build_unshield_base_token(&keys, &unshield, &artifacts)?);
        }
        "shield-eth" => {
            // shield-eth <evm-key-file> <wei>, to this wallet; needs no approval.
            let tx = client.build_shield_base_token(&keys.address()?, a[7].parse()?)?;
            send_and_wait(&client, &evm_key(&a[6])?, &tx)?;
        }
        "send" => {
            // send <evm-key-file> <tx.jsonl>, from `transfer` or `unshield`.
            let tx = read_tx(&a[7], network.chain_id)?;
            send_and_wait(&client, &evm_key(&a[6])?, &tx)?;
        }
        "estimate" => {
            let tx = read_tx(&a[7], network.chain_id)?;
            println!("{:?}", client.quote_fee(&address(&a[6])?, &tx)?);
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
        "broadcasters" | "broadcast-transfer" | "broadcast-unshield" => {
            broadcast_command(&client, &keys, &artifacts, &a)?;
        }
        other => return Err(format!("unknown command {other}").into()),
    }
    Ok(())
}
