//! One 1x2 private transfer against the TS engine (harness/transfer.js).
//!
//! `vectors/transfer/transfer.json` is the engine's transfer from the throwaway Sepolia test wallet (index 0 to index 1) spending a synthetic shield appended to the first 200 Sepolia logs, with the engine's randomness pinned. `sepolia-vkey-1x2.json` is the contract's VerifyingKeySet log for the 1x2 circuit.
//!
//! Tests that need the wallet's keys read `.test-wallet/sepolia-test-mnemonic.txt` (gitignored) and skip without it. Tests that need the circuit artifacts are ignored by default; run them with `RG_ARTIFACTS_DIR=<dir with 1x2/> cargo test -p rg-tx --release -- --ignored`.

use std::path::{Path, PathBuf};

use alloy_primitives::B256;
use alloy_sol_types::{SolCall, SolEvent};
use rg_keys::{WalletKeys, decode_address};
use rg_primitives::Fr;
use rg_primitives::babyjubjub::Point;
use rg_primitives::eddsa;
use rg_primitives::field::from_decimal;
use rg_sync::{RawLog, SyncState, abi};
use rg_tx::*;
use rg_wallet::Scanner;
use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json(rel: &str) -> Value {
    serde_json::from_slice(&std::fs::read(root().join(rel)).unwrap()).unwrap()
}

fn transfer() -> Value {
    read_json("vectors/transfer/transfer.json")
}

fn fr(v: &Value) -> Fr {
    from_decimal(v.as_str().unwrap()).unwrap()
}

fn frs(v: &Value) -> Vec<Fr> {
    match v {
        Value::Array(a) => a.iter().map(fr).collect(),
        x => vec![fr(x)],
    }
}

fn engine_inputs(t: &Value) -> Vec<(String, Vec<Fr>)> {
    t["formattedInputs"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), frs(v)))
        .collect()
}

fn engine_call(t: &Value) -> abi::transactCall {
    let data = hex::decode(t["calldata"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    abi::transactCall::abi_decode(&data).unwrap()
}

fn onchain_vkey() -> rg_prover::ark_types::VerifyingKey<rg_prover::ark_types::Bn254> {
    let log = RawLog::from_json(&read_json("vectors/transfer/sepolia-vkey-1x2.json")).unwrap();
    let topics = log.topics.iter().map(|t| B256::from(*t));
    let ev = abi::VerifyingKeySet::decode_raw_log(topics, &log.data).unwrap();
    assert_eq!(
        (ev.nullifiers.to::<u64>(), ev.commitments.to::<u64>()),
        (1, 2)
    );
    verifying_key_from_contract(&ev.verifyingKey).unwrap()
}

fn test_mnemonic() -> Option<String> {
    let p = root().join(".test-wallet/sepolia-test-mnemonic.txt");
    match std::fs::read_to_string(&p) {
        Ok(s) => Some(s.trim().to_string()),
        Err(_) => {
            eprintln!("skipped: no {}", p.display());
            None
        }
    }
}

/// Bound params hash of the engine's call equals its circuit input, and the calldata re-encodes byte for byte.
#[test]
fn bound_params_hash_and_calldata_match_engine() {
    let t = transfer();
    let call = engine_call(&t);
    let tx = &call._transactions[0];
    assert_eq!(
        hash_bound_params(&tx.boundParams),
        fr(&t["formattedInputs"]["boundParamsHash"])
    );
    assert_eq!(tx.boundParams.chainID, chain_full_network_id(0, 11_155_111));
    let again = transact_calldata(call._transactions.clone());
    assert_eq!(
        format!("0x{}", hex::encode(again)),
        t["calldata"].as_str().unwrap()
    );
}

/// The engine's signature verifies over the message built here.
#[test]
fn signature_message_matches_engine() {
    let t = transfer();
    let i = &t["formattedInputs"];
    let msg = signature_message(
        &fr(&i["merkleRoot"]),
        &fr(&i["boundParamsHash"]),
        &frs(&i["nullifiers"]),
        &frs(&i["commitmentsOut"]),
    )
    .unwrap();
    let pk = frs(&i["publicKey"]);
    let s = frs(&i["signature"]);
    let sig = eddsa::Signature::new(Point { x: s[0], y: s[1] }, s[2]).unwrap();
    assert!(eddsa::verify(&msg, &sig, &Point { x: pk[0], y: pk[1] }));
}

/// The snarkjs proof verifies against the key the Sepolia contract holds, and formatProof's G2 swap matches what the engine put in the call.
#[test]
fn snarkjs_proof_verifies_against_onchain_key() {
    let t = transfer();
    let vk = onchain_vkey();
    let proof = rg_prover::proof_from_json(&t["snarkjsProof"]).unwrap();
    let i = &t["formattedInputs"];
    let mut public = vec![fr(&i["merkleRoot"]), fr(&i["boundParamsHash"])];
    public.extend(frs(&i["nullifiers"]));
    public.extend(frs(&i["commitmentsOut"]));
    assert!(rg_prover::verify(&vk, &public, &proof).unwrap());
    let mut wrong = public.clone();
    wrong[1] += Fr::from(1u8);
    assert!(!rg_prover::verify(&vk, &wrong, &proof).unwrap());
    assert_eq!(engine_call(&t)._transactions[0].proof, snark_proof(&proof));
}

fn engine_state() -> SyncState {
    let mut logs = RawLog::parse_jsonl(
        &std::fs::read_to_string(root().join("vectors/sepolia/sepolia-head-200.jsonl")).unwrap(),
    )
    .unwrap();
    logs.push(RawLog::from_json(&read_json("vectors/transfer/shield-log.json")).unwrap());
    let mut state = SyncState::new();
    state.apply_all(&logs).unwrap();
    state
}

/// Engine draws in the order plan_transfer asks: sender random, recipient note random, change note random, then GCM and CTR IVs per output. Draws 0 to 5 belong to wallet setup and the shield; draw 9 is not used in the transaction's outputs.
fn engine_fill(t: &Value) -> impl FnMut(&mut [u8]) {
    let draws: Vec<Vec<u8>> = t["randomDraws"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| hex::decode(d.as_str().unwrap()).unwrap())
        .collect();
    let mut queue: Vec<Vec<u8>> = [6, 7, 8, 10, 11, 12, 13]
        .iter()
        .map(|&i| draws[i].clone())
        .collect();
    queue.reverse();
    move |buf: &mut [u8]| {
        let d = queue.pop().expect("more randomness than the engine drew");
        assert_eq!(d.len(), buf.len());
        buf.copy_from_slice(&d);
    }
}

fn rust_prepared(t: &Value, mnemonic: &str) -> (WalletKeys, Prepared) {
    let keys = WalletKeys::from_mnemonic(mnemonic, "", 0).unwrap();
    let state = engine_state();
    let scan = Scanner::new(&keys).scan(&state);
    let recipient = decode_address(t["receiverAddress"].as_str().unwrap()).unwrap();
    let token = rg_notes::TokenData::erc20(
        hex::decode(
            t["shield"]["token"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap()
        .try_into()
        .unwrap(),
    );
    let req = TransferRequest {
        recipient: &recipient,
        token_hash: token.hash(),
        value: t["send"]["value"].as_str().unwrap().parse().unwrap(),
        memo_text: t["send"]["memo"].as_str(),
        show_sender_to_recipient: t["send"]["showSender"].as_bool().unwrap(),
        wallet_source: t["send"]["walletSource"].as_str().unwrap(),
        chain_id: chain_full_network_id(0, 11_155_111),
        min_gas_price: 0,
    };
    let [params] = &plan_transfer(&keys, &state, &scan, &req, engine_fill(t)).unwrap()[..] else {
        panic!("one note covers the engine's transfer");
    };
    let prepared = params.prepare(&keys).unwrap();
    (keys, prepared)
}

/// Key order of the engine's `formatRailgunInputs`.
const FORMAT_ORDER: [&str; 14] = [
    "merkleRoot",
    "boundParamsHash",
    "nullifiers",
    "commitmentsOut",
    "token",
    "publicKey",
    "signature",
    "randomIn",
    "valueIn",
    "pathElements",
    "leavesIndices",
    "nullifyingKey",
    "npkOut",
    "valueOut",
];

/// With the engine's randomness, the Rust transfer has the same formatted inputs and the same bound params (ciphertexts byte for byte).
#[test]
fn transfer_inputs_match_engine() {
    let Some(mnemonic) = test_mnemonic() else {
        return;
    };
    let t = transfer();
    let (_, prepared) = rust_prepared(&t, &mnemonic);
    let ours: Vec<(String, Vec<String>)> = prepared
        .circuit_inputs
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                v.iter().map(rg_primitives::field::to_decimal).collect(),
            )
        })
        .collect();
    let names: Vec<&str> = ours.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(names, FORMAT_ORDER);
    let theirs: std::collections::BTreeMap<String, Vec<String>> = engine_inputs(&t)
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                v.iter().map(rg_primitives::field::to_decimal).collect(),
            )
        })
        .collect();
    let ours: std::collections::BTreeMap<String, Vec<String>> = ours.into_iter().collect();
    assert_eq!(ours, theirs);
    assert_eq!(
        prepared.bound_params,
        engine_call(&t)._transactions[0].boundParams
    );
}

/// The recipient (wallet index 1) and the sender's change both decrypt from the Rust-built ciphertexts once the commitments are on a tree.
#[test]
fn recipient_decrypts_rust_transfer() {
    let Some(mnemonic) = test_mnemonic() else {
        return;
    };
    let t = transfer();
    let (_, prepared) = rust_prepared(&t, &mnemonic);
    let tx = engine_call(&t)._transactions[0].clone();
    let commitments: Vec<B256> = prepared.commitments.iter().map(fr_to_b256).collect();
    assert_eq!(commitments, tx.commitments);

    // Append the events the contract would emit: Nullified for the spent note, then Transact with the Rust commitments and ciphertexts.
    let mut state = engine_state();
    let ev = abi::Transact {
        treeNumber: alloy_primitives::U256::ZERO,
        startPosition: alloy_primitives::U256::from(state.leaf_count()),
        hash: commitments,
        ciphertext: prepared.bound_params.commitmentCiphertext.clone(),
    };
    let nullified = abi::Nullified {
        treeNumber: 0,
        nullifier: prepared.nullifiers.iter().map(fr_to_b256).collect(),
    };
    let (last_block, _) = state.last_applied().unwrap();
    let proxy: [u8; 20] = hex::decode("eCFCf3b4eC647c4Ca6D49108b311b7a7C9543fea")
        .unwrap()
        .try_into()
        .unwrap();
    for (i, (topic, data)) in [
        (abi::Nullified::SIGNATURE_HASH.0, nullified.encode_data()),
        (abi::Transact::SIGNATURE_HASH.0, ev.encode_data()),
    ]
    .into_iter()
    .enumerate()
    {
        let log = RawLog {
            address: proxy,
            topics: vec![topic],
            data,
            block_number: last_block + 1,
            transaction_hash: [7; 32],
            log_index: i as u64,
        };
        state.apply(&log).unwrap();
    }

    let receiver = WalletKeys::from_mnemonic(&mnemonic, "", 1).unwrap();
    let got = Scanner::new(&receiver).scan(&state);
    assert_eq!(got.txos.len(), 1);
    let note = &got.txos[0];
    assert_eq!(note.value.to_string(), t["send"]["value"].as_str().unwrap());
    assert_eq!(note.memo_text.as_deref(), t["send"]["memo"].as_str());
    assert_eq!(note.sender_master_public_key, None);

    let sender = WalletKeys::from_mnemonic(&mnemonic, "", 0).unwrap();
    let mine = Scanner::new(&sender).scan(&state);
    let change: Vec<_> = mine.unspent().collect();
    assert_eq!(change.len(), 1);
    assert_eq!(change[0].value, 7_000_000_000_000_000);
}

fn artifacts() -> PathBuf {
    PathBuf::from(std::env::var("RG_ARTIFACTS_DIR").expect("set RG_ARTIFACTS_DIR")).join("1x2")
}

/// The Rust witness equals snarkjs's, and an arkworks proof from it verifies against the on-chain key and goes into the call like the engine's.
#[test]
#[ignore = "needs RG_ARTIFACTS_DIR with the 1x2 circuit"]
fn rust_witness_and_proof_match() {
    let t = transfer();
    let wasm = std::fs::read(artifacts().join("circuit.wasm")).unwrap();
    let zkey = std::fs::read(artifacts().join("circuit.zkey")).unwrap();
    let mut calc = rg_prover::WasmiCircuit::new(&wasm)
        .unwrap()
        .calculator()
        .unwrap();
    let witness = calc.calculate(&engine_inputs(&t)).unwrap();
    let expected = frs(&read_json("vectors/transfer/witness.json"));
    assert_eq!(witness.len(), expected.len());
    assert!(witness == expected, "witness differs from snarkjs");

    let circuit = rg_prover::Circuit::from_zkey(&zkey).unwrap();
    let vk = onchain_vkey();
    assert!(circuit.pk.vk == vk, "zkey key differs from the contract's");
    let (proof, public) = circuit.prove(&witness, &mut rand_core_rng()).unwrap();
    assert!(rg_prover::verify(&vk, &public, &proof).unwrap());

    let mut tx = engine_call(&t)._transactions[0].clone();
    tx.proof = snark_proof(&proof);
    let calldata = transact_calldata(vec![tx]);
    assert_eq!(&calldata[..4], &abi::transactCall::SELECTOR);
}

fn rand_core_rng() -> impl rand::RngCore + rand::CryptoRng {
    rand::rngs::OsRng
}
