//! Print, as JSONL, the three calls that shield `value` wei of the base token
//! into a 0zk address as its wrapped token: wrap, approve the proxy, shield.
//! Nothing is sent; harness/send.js can send them.
//!
//! cargo run --release -p rg-tx --example shield -- <network> <recipient 0zk> <value in wei>

use rand::RngCore;
use rg_keys::decode_address;
use rg_sync::Network;
use rg_tx::shield_calldata;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let network = Network::by_name(&a[1]).expect("unknown network");
    let receiver = decode_address(&a[2]).unwrap();
    let value: u128 = a[3].parse().unwrap();
    let weth = network.wrapped_token;
    let token: [u8; 20] = hex::decode(weth.trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap();
    let proxy = network.proxy;

    let mut rng = rand::rngs::OsRng;
    let shield = shield_calldata(&receiver, token, value, |b| rng.fill_bytes(b)).unwrap();

    let wrap = serde_json::json!({
        "label": "wrap", "to": weth, "value": value.to_string(), "data": "0xd0e30db0",
    });
    let approve = serde_json::json!({
        "label": "approve",
        "to": weth,
        "value": "0",
        "data": format!(
            "0x095ea7b3{:0>64}{value:064x}",
            proxy.trim_start_matches("0x").to_lowercase()
        ),
    });
    let shield = serde_json::json!({
        "label": "shield", "to": proxy, "value": "0", "data": format!("0x{}", hex::encode(shield)),
    });
    for tx in [wrap, approve, shield] {
        println!("{tx}");
    }
}
