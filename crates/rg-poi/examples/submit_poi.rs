//! Prove POI for one transaction this wallet sent, and optionally submit it.
//!
//! cargo run --release -p rg-poi --features rpc --example submit_poi -- \
//!   <network> <seed leaves> <logs.jsonl> <mnemonic-file> <artifacts/poi-3x3> <tx hash> [--submit]
//!
//! Without --submit it stops after printing statuses and the proof.

use rand::rngs::OsRng;
use rg_keys::WalletKeys;
use rg_poi::node::{blinded_hex, Node};
use rg_poi::{
    blinded_commitment, global_tree_position, railgun_txid, txid_leaf, OutputNote, ProofInputs,
    SpentNote, TxidTrees,
};
use rg_primitives::{field, Fr};
use rg_sync::squid::fetch_transactions;
use rg_sync::{Network, RawLog, SyncState};
use rg_wallet::Scanner;
use serde_json::json;

const NODE: &str = "https://ppoi.fdi.network";
const LIST: &str = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";

fn fr(b: &[u8]) -> Fr {
    field::from_be_bytes_mod_order(b)
}

fn dec2(a: String, b: String) -> serde_json::Value {
    json!([a, b])
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let network = Network::by_name(&a[1]).expect("unknown network");
    let tx_hash: [u8; 32] = hex::decode(a[6].trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap();
    let submit = a.get(7).is_some_and(|s| s == "--submit");
    let node = Node::new(NODE, network.chain_id);

    let mut state = SyncState::new();
    state
        .seed_from_text(&std::fs::read_to_string(&a[2]).unwrap())
        .unwrap();
    let logs = RawLog::parse_jsonl(&std::fs::read_to_string(&a[3]).unwrap()).unwrap();
    state.apply_all(&logs).unwrap();
    let keys =
        WalletKeys::from_mnemonic(std::fs::read_to_string(&a[4]).unwrap().trim(), "", 0).unwrap();
    let scan = Scanner::new(keys.clone()).scan(&state);

    let txs = fetch_transactions(network.squid.expect("no squid")).unwrap();
    let leaves: Vec<Fr> = txs
        .iter()
        .map(|t| {
            let nullifiers: Vec<Fr> = t.nullifiers.iter().map(|n| fr(n)).collect();
            let commitments: Vec<Fr> = t.commitments.iter().map(|c| fr(c)).collect();
            let txid = railgun_txid(&nullifiers, &commitments, &fr(&t.bound_params_hash));
            let out = global_tree_position(t.utxo_tree_out, t.utxo_batch_start_position_out);
            txid_leaf(&txid, t.utxo_tree_in, out)
        })
        .collect();
    let mut trees = TxidTrees::default();
    trees.extend(&leaves).unwrap();
    let latest = trees.latest_index().unwrap();
    let (tree, index) = ((latest / 65536) as u32, (latest % 65536) as u32);
    let root = trees.root(tree as usize).unwrap();
    println!(
        "txid tree: {} transactions, root {}",
        txs.len(),
        hex::encode(field::to_be_bytes(&root))
    );
    println!("aggregator validated: {}", node.validated_txid().unwrap());
    println!(
        "aggregator knows root at {tree}/{index}: {}",
        node.validate_txid_merkleroot(tree, index, &root).unwrap()
    );

    let position = txs
        .iter()
        .position(|t| t.transaction_hash == tx_hash)
        .expect("transaction not in the squid");
    let tx = &txs[position];

    // Spent notes, in the transaction's nullifier order.
    let spent: Vec<_> = tx
        .nullifiers
        .iter()
        .map(|n| {
            scan.txos
                .iter()
                .find(|t| &t.nullifier == n)
                .expect("spent note not ours")
        })
        .collect();
    let npk = |random: &[u8; 16]| rg_notes::note::note_public_key(&keys.master_public_key, random);
    let blinded_in: Vec<Fr> = spent
        .iter()
        .map(|t| {
            blinded_commitment(
                &fr(&t.commitment),
                &npk(&t.random),
                global_tree_position(t.tree, t.position),
            )
        })
        .collect();
    let blinded_in_hex: Vec<String> = blinded_in.iter().map(blinded_hex).collect();

    let start = tx.utxo_batch_start_position_out;
    let sent: Vec<_> = tx
        .commitments
        .iter()
        .enumerate()
        .map(|(i, c)| {
            scan.sent
                .iter()
                .find(|s| {
                    s.tree == tx.utxo_tree_out
                        && s.position == start + i as u32
                        && &s.commitment == c
                })
                .expect("output not ours")
        })
        .collect();
    let outputs: Vec<OutputNote> = sent
        .iter()
        .map(|s| OutputNote {
            npk: rg_notes::note::note_public_key(&s.receiver_master_public_key, &s.random),
            value: s.value,
        })
        .collect();
    let start_out = global_tree_position(tx.utxo_tree_out, start);
    let blinded_out: Vec<Fr> = sent
        .iter()
        .zip(&outputs)
        .enumerate()
        .map(|(i, (s, o))| blinded_commitment(&fr(&s.commitment), &o.npk, start_out + i as u64))
        .collect();
    let blinded_out_hex: Vec<String> = blinded_out.iter().map(blinded_hex).collect();

    let status = |list: &[String]| {
        let items: Vec<_> = list.iter().map(|b| (b.clone(), "Transact")).collect();
        node.pois_per_list(LIST, &items).unwrap()
    };
    println!("inputs: {:?}", status(&blinded_in_hex));
    println!("outputs: {:?}", status(&blinded_out_hex));

    let list_proofs = node.merkle_proofs(LIST, &blinded_in_hex).unwrap();
    let inputs = ProofInputs {
        txid_proof: trees.proof(position as u64).unwrap(),
        bound_params_hash: fr(&tx.bound_params_hash),
        nullifiers: tx.nullifiers.iter().map(|n| fr(n)).collect(),
        commitments_out: tx.commitments.iter().map(|c| fr(c)).collect(),
        spending_public_key: [keys.spending_public_key.x, keys.spending_public_key.y],
        nullifying_key: keys.nullifying_key,
        token_hash: fr(&spent[0].token_hash),
        spent: spent
            .iter()
            .map(|t| SpentNote {
                random: fr(&t.random),
                value: t.value,
                position: t.position,
            })
            .collect(),
        utxo_tree_in: tx.utxo_tree_in,
        outputs,
        global_position_out: start_out,
        list_proofs,
    };

    let dir = std::path::Path::new(&a[5]);
    let n = if a[5].ends_with("13x13") {
        rg_poi::FULL_CIRCUIT
    } else {
        rg_poi::MINI_CIRCUIT
    };
    let wasm = std::fs::read(dir.join("circuit.wasm")).unwrap();
    let circuit =
        rg_prover::Circuit::from_zkey(&std::fs::read(dir.join("circuit.zkey")).unwrap()).unwrap();
    let t = std::time::Instant::now();
    let witness = rg_prover::WasmiCircuit::new(&wasm)
        .unwrap()
        .calculator()
        .unwrap()
        .calculate(&inputs.circuit_inputs(n).unwrap())
        .unwrap();
    eprintln!("witness: {:?}", t.elapsed());
    let t = std::time::Instant::now();
    let (proof, public) = circuit.prove(&witness, &mut OsRng).unwrap();
    eprintln!("prove: {:?}", t.elapsed());
    assert_eq!(
        public,
        inputs.public_inputs(n, &blinded_out),
        "public signals"
    );
    assert!(rg_prover::verify(&circuit.pk.vk, &public, &proof).unwrap());
    println!("proof verifies against the POI key");

    let p = rg_prover::proof_to_json(&proof);
    let s = |v: &serde_json::Value| v.as_str().unwrap().to_string();
    let snark_proof = json!({
        "pi_a": dec2(s(&p["pi_a"][0]), s(&p["pi_a"][1])),
        "pi_b": [
            dec2(s(&p["pi_b"][0][0]), s(&p["pi_b"][0][1])),
            dec2(s(&p["pi_b"][1][0]), s(&p["pi_b"][1][1])),
        ],
        "pi_c": dec2(s(&p["pi_c"][0]), s(&p["pi_c"][1])),
    });
    let hex32 = |x: &Fr| hex::encode(field::to_be_bytes(x));
    let data = json!({
        "snarkProof": snark_proof,
        "poiMerkleroots": inputs.list_proofs.iter().map(|l| hex32(&l.root)).collect::<Vec<_>>(),
        "txidMerkleroot": hex32(&inputs.txid_proof.root),
        "txidMerklerootIndex": latest,
        "blindedCommitmentsOut": blinded_out_hex,
        "railgunTxidIfHasUnshield": "0x00",
    });
    println!("{data}");
    if submit {
        node.submit_transact_proof(LIST, data).unwrap();
        println!("submitted");
        println!("outputs now: {:?}", status(&blinded_out_hex));
    }
}
