//! Print, as JSONL, the three Sepolia calls that shield `value` wei of ETH as
//! WETH into a 0zk address: wrap, approve the proxy, shield. Nothing is sent;
//! harness/send.js can send them.
//!
//! cargo run --release -p rg-tx --example shield -- <recipient 0zk> <value in wei>

use rand::RngCore;
use rg_keys::decode_address;
use rg_tx::shield_calldata;

const WETH: &str = "fff9976782d46cc05630d1f6ebab18b2324d6b14";

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let receiver = decode_address(&a[1]).unwrap();
    let value: u128 = a[2].parse().unwrap();
    let token: [u8; 20] = hex::decode(WETH).unwrap().try_into().unwrap();
    let proxy = rg_sync::SEPOLIA_PROXY;

    let mut rng = rand::rngs::OsRng;
    let shield = shield_calldata(&receiver, token, value, |b| rng.fill_bytes(b)).unwrap();

    let wrap = serde_json::json!({
        "label": "wrap", "to": format!("0x{WETH}"), "value": value.to_string(), "data": "0xd0e30db0",
    });
    let approve = serde_json::json!({
        "label": "approve",
        "to": format!("0x{WETH}"),
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
