//! Witness, prove and verify one formatted-inputs JSON, with timings.
//!
//! cargo run --release -p rg-prover --example prove_1x2 [--features wasmtime] -- \
//!   <artifacts/1x2 dir> <transfer.json>

use std::time::Instant;

use rg_prover::{Circuit, parse_fr, proof_from_json, proof_to_json, verify, vkey_from_json};
use serde_json::Value;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = std::path::Path::new(&args[1]);
    let transfer: Value = serde_json::from_slice(&std::fs::read(&args[2]).unwrap()).unwrap();
    let inputs: Vec<(String, Vec<rg_prover::ark_types::Fr>)> = transfer["formattedInputs"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| {
            let vals = match v {
                Value::Array(a) => a.iter().map(|x| parse_fr(x).unwrap()).collect(),
                x => vec![parse_fr(x).unwrap()],
            };
            (k.clone(), vals)
        })
        .collect();

    let wasm = std::fs::read(dir.join("circuit.wasm")).unwrap();
    let zkey = std::fs::read(dir.join("circuit.zkey")).unwrap();
    let vkey: Value =
        serde_json::from_slice(&std::fs::read(dir.join("vkey.json")).unwrap()).unwrap();

    let t = Instant::now();
    let circuit = Circuit::from_zkey(&zkey).unwrap();
    println!("zkey load: {:?}", t.elapsed());

    #[cfg(feature = "wasmtime")]
    let (label, compiled) = ("wasmtime", rg_prover::WasmtimeCircuit::new(&wasm).unwrap());
    #[cfg(not(feature = "wasmtime"))]
    let (label, compiled) = ("wasmi", rg_prover::WasmiCircuit::new(&wasm).unwrap());
    let t = Instant::now();
    let mut calc = compiled.calculator().unwrap();
    let witness = calc.calculate(&inputs).unwrap();
    println!(
        "witness ({label}, {} signals): {:?}",
        witness.len(),
        t.elapsed()
    );

    let t = Instant::now();
    let (proof, public) = circuit.prove(&witness, &mut rand::thread_rng()).unwrap();
    println!("prove: {:?}", t.elapsed());

    let vk = vkey_from_json(&vkey).unwrap();
    let t = Instant::now();
    let ok = verify(&vk, &public, &proof).unwrap();
    println!("verify against vkey.json: {ok} ({:?})", t.elapsed());
    println!("zkey vk equals vkey.json: {}", circuit.pk.vk == vk);
    let theirs = proof_from_json(&transfer["snarkjsProof"]).unwrap();
    println!(
        "snarkjs proof verifies in Rust: {}",
        verify(&vk, &public, &theirs).unwrap()
    );
    println!("{}", serde_json::to_string(&proof_to_json(&proof)).unwrap());
}
