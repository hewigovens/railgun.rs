//! Build and prove one private transfer entirely in Rust, and print the
//! transact calldata for the Railgun proxy. Nothing is signed for the EVM or
//! sent: broadcasting is a separate step.
//!
//! cargo run --release -p rg-tx --example transfer -- \
//!   <network> <seed leaves or -> <logs.jsonl> <mnemonic-file> <artifacts dir> \
//!   <recipient 0zk> <token address> <value> [memo]
//!
//! The artifacts dir holds `<n>x<m>/circuit.wasm`, `circuit.zkey`. On Sepolia
//! the proof is also checked against the key the contract set (vectors/m4).
//! The seed comes from the fetch_leaves example, for chains with legacy events.

use std::time::Instant;

use alloy_sol_types::SolEvent;
use rand::RngCore;
use rg_keys::{decode_address, WalletKeys};
use rg_sync::{abi, Network, RawLog, SyncState};
use rg_tx::*;
use rg_wallet::Scanner;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let network = Network::by_name(&a[1]).expect("unknown network");
    let logs = RawLog::parse_jsonl(&std::fs::read_to_string(&a[3]).unwrap()).unwrap();
    let mnemonic = std::fs::read_to_string(&a[4]).unwrap();
    let artifacts = std::path::Path::new(&a[5]);
    let recipient = decode_address(&a[6]).unwrap();
    let token: [u8; 20] = hex::decode(a[7].trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap();
    let value: u128 = a[8].parse().unwrap();
    let memo = a.get(9).map(String::as_str);

    let t = Instant::now();
    let mut state = SyncState::new();
    if a[2] != "-" {
        state
            .seed_from_text(&std::fs::read_to_string(&a[2]).unwrap())
            .unwrap();
    }
    state.apply_all(&logs).unwrap();
    let keys = WalletKeys::from_mnemonic(mnemonic.trim(), "", 0).unwrap();
    let scan = Scanner::new(keys.clone()).scan(&state);
    eprintln!("sync and scan: {:?}", t.elapsed());

    let req = TransferRequest {
        recipient: &recipient,
        token_hash: rg_notes::TokenData::erc20(token).hash(),
        value,
        memo_text: memo,
        show_sender_to_recipient: false,
        wallet_source: "rgrustcore",
        chain_id: chain_full_network_id(0, network.chain_id),
        min_gas_price: 0,
    };
    let mut rng = rand::rngs::OsRng;
    let params = plan_transfer(&keys, &state, &scan, &req, |b| rng.fill_bytes(b)).unwrap();
    let prepared = prepare(&keys, &params).unwrap();
    let shape = format!("{}x{}", params.inputs.len(), params.outputs.len());
    let dir = artifacts.join(&shape);

    let t = Instant::now();
    let wasm = std::fs::read(dir.join("circuit.wasm")).unwrap();
    let circuit =
        rg_prover::Circuit::from_zkey(&std::fs::read(dir.join("circuit.zkey")).unwrap()).unwrap();
    eprintln!("load {shape} artifacts: {:?}", t.elapsed());
    let t = Instant::now();
    let witness = rg_prover::WasmiCircuit::new(&wasm)
        .unwrap()
        .calculator()
        .unwrap()
        .calculate(&prepared.circuit_inputs)
        .unwrap();
    eprintln!("witness: {:?}", t.elapsed());
    let t = Instant::now();
    let (proof, public) = circuit.prove(&witness, &mut rng).unwrap();
    eprintln!("prove: {:?}", t.elapsed());
    assert_eq!(public, prepared.public_inputs());
    assert!(rg_prover::verify(&circuit.pk.vk, &public, &proof).unwrap());

    if shape == "1x2" && network.chain_id == Network::SEPOLIA.chain_id {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/m4/sepolia-vkey-1x2.json"
        );
        let log =
            RawLog::from_json(&serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap())
                .unwrap();
        let topics = log.topics.iter().map(|t| alloy_primitives::B256::from(*t));
        let ev = abi::VerifyingKeySet::decode_raw_log(topics, &log.data).unwrap();
        let vk = verifying_key_from_contract(&ev.verifyingKey).unwrap();
        assert!(rg_prover::verify(&vk, &public, &proof).unwrap());
        eprintln!("proof verifies against the Sepolia contract's 1x2 key");
    }
    let calldata = transact_calldata(vec![prepared.transaction(&proof)]);
    println!(
        "{}",
        serde_json::json!({
            "to": network.proxy,
            "chainId": network.chain_id,
            "value": "0",
            "data": format!("0x{}", hex::encode(calldata)),
            "merkleRoot": format!("{}", fr_to_b256(&prepared.merkle_root)),
            "tree": params.tree,
        })
    );
}
