use std::path::Path;

use rand::RngCore;
use rg_keys::{decode_address, WalletKeys};
use rg_primitives::Fr;
use rg_prover::ark_types::{Bn254, Proof};
use rg_prover::Circuit;
use rg_tx::{chain_full_network_id, plan_transfer, prepare, transact_calldata, TransferRequest};

use crate::{ChainStore, Client, Error};

const WALLET_SOURCE: &str = "rgrustcore";

pub struct Transfer<'a> {
    /// 0zk address.
    pub recipient: &'a str,
    pub token: [u8; 20],
    pub value: u128,
    pub memo: Option<&'a str>,
}

/// A call for any funded account to sign and send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedTx {
    pub chain_id: u64,
    pub to: String,
    pub data: Vec<u8>,
}

impl UnsignedTx {
    pub fn data_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.data))
    }
}

/// Runs a circuit's witness wasm and proves. `dir` holds `circuit.wasm` and
/// `circuit.zkey`.
pub(crate) fn prove(
    dir: &Path,
    inputs: &[(String, Vec<Fr>)],
) -> Result<(Proof<Bn254>, Vec<Fr>), Error> {
    let wasm = std::fs::read(dir.join("circuit.wasm"))?;
    let circuit = Circuit::from_zkey(&std::fs::read(dir.join("circuit.zkey"))?)?;
    let witness = rg_prover::WasmiCircuit::new(&wasm)?
        .calculator()?
        .calculate(inputs)?;
    let (proof, public) = circuit.prove(&witness, &mut rand::rngs::OsRng)?;
    if !rg_prover::verify(&circuit.pk.vk, &public, &proof)? {
        return Err(Error::BadProof);
    }
    Ok((proof, public))
}

impl<S: ChainStore> Client<S> {
    /// Plans and proves a private transfer. `artifacts` holds one `<n>x<m>`
    /// directory per circuit.
    pub fn build_transfer(
        &self,
        keys: &WalletKeys,
        transfer: &Transfer,
        artifacts: &Path,
    ) -> Result<UnsignedTx, Error> {
        let recipient = decode_address(transfer.recipient)?;
        let request = TransferRequest {
            recipient: &recipient,
            token_hash: rg_notes::TokenData::erc20(transfer.token).hash(),
            value: transfer.value,
            memo_text: transfer.memo,
            show_sender_to_recipient: false,
            wallet_source: WALLET_SOURCE,
            chain_id: chain_full_network_id(0, self.network.chain_id),
            min_gas_price: 0,
        };
        let scan = self.scan(keys);
        let mut rng = rand::rngs::OsRng;
        let params = plan_transfer(keys, &self.state, &scan, &request, |b| rng.fill_bytes(b))?;
        let prepared = prepare(keys, &params)?;
        let shape = format!("{}x{}", params.inputs.len(), params.outputs.len());
        let (proof, public) = prove(&artifacts.join(shape), &prepared.circuit_inputs)?;
        if public != prepared.public_inputs() {
            return Err(Error::BadProof);
        }
        Ok(UnsignedTx {
            chain_id: self.network.chain_id,
            to: self.network.proxy.to_string(),
            data: transact_calldata(vec![prepared.transaction(&proof)]),
        })
    }

    /// Asks the node whether `from` could send this now.
    pub fn estimate_gas(&self, from: &str, tx: &UnsignedTx) -> Result<u64, Error> {
        Ok(self.rpc.estimate_gas(from, &tx.to, &tx.data_hex())?)
    }
}
