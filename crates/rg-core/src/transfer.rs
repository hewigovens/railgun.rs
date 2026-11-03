use rand::RngCore;
use rg_keys::{WalletKeys, decode_address};
use rg_primitives::Fr;
use rg_prover::Circuit;
use rg_prover::ark_types::{Bn254, Proof};
use rg_tx::{
    TransferParams, TransferRequest, UnshieldRequest, chain_full_network_id, plan_transfer,
    plan_unshield, transact_calldata,
};
use rg_wallet::ScanResult;

use crate::{Artifacts, ChainStore, Client, Error};

const WALLET_SOURCE: &str = "rgrustcore";

pub struct Transfer<'a> {
    /// 0zk address.
    pub recipient: &'a str,
    pub token: [u8; 20],
    pub value: u128,
    pub memo: Option<&'a str>,
}

/// Out of the pool to a public address. The contract keeps its fee, so `to` receives slightly less than `value`.
pub struct Unshield {
    pub to: [u8; 20],
    pub token: [u8; 20],
    pub value: u128,
}

/// A call for any funded account to sign and send; [`Client::send`] does both.
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

/// Runs a circuit's witness wasm and proves.
pub(crate) fn prove(
    artifacts: &Artifacts,
    which: crate::Circuit,
    inputs: &[(String, Vec<Fr>)],
) -> Result<(Proof<Bn254>, Vec<Fr>), Error> {
    let loaded = artifacts.load(which)?;
    let circuit = Circuit::from_zkey(&loaded.zkey)?;
    let witness = rg_prover::WasmiCircuit::new(&loaded.wasm)?
        .calculator()?
        .calculate(inputs)?;
    let (proof, public) = circuit.prove(&witness, &mut rand::rngs::OsRng)?;
    if !rg_prover::verify(&circuit.pk.vk, &public, &proof)? {
        return Err(Error::BadProof);
    }
    Ok((proof, public))
}

impl<S: ChainStore> Client<S> {
    /// Plans and proves a private transfer.
    pub fn build_transfer(
        &self,
        keys: &WalletKeys,
        transfer: &Transfer,
        artifacts: &Artifacts,
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
        let params = self.plan(keys, &request.token_hash, request.value, |scan| {
            plan_transfer(keys, &self.state, scan, &request, |b| {
                rand::rngs::OsRng.fill_bytes(b)
            })
        })?;
        self.prove_transactions(keys, &params, artifacts)
    }

    /// Plans and proves an unshield.
    pub fn build_unshield(
        &self,
        keys: &WalletKeys,
        unshield: &Unshield,
        artifacts: &Artifacts,
    ) -> Result<UnsignedTx, Error> {
        let request = UnshieldRequest {
            to: unshield.to,
            token: unshield.token,
            value: unshield.value,
            wallet_source: WALLET_SOURCE,
            chain_id: chain_full_network_id(0, self.network.chain_id),
            min_gas_price: 0,
        };
        let token_hash = rg_notes::TokenData::erc20(unshield.token).hash();
        let params = self.plan(keys, &token_hash, unshield.value, |scan| {
            plan_unshield(keys, &self.state, scan, &request, |b| {
                rand::rngs::OsRng.fill_bytes(b)
            })
        })?;
        self.prove_transactions(keys, &params, artifacts)
    }

    /// Plans against spendable notes only. When notes still waiting for POI would have covered `value`, says so rather than reporting a shortfall.
    fn plan<'a>(
        &self,
        keys: &WalletKeys,
        token_hash: &[u8; 32],
        value: u128,
        plan: impl FnOnce(&ScanResult) -> Result<Vec<TransferParams<'a>>, rg_tx::Error>,
    ) -> Result<Vec<TransferParams<'a>>, Error> {
        let spendable = self.spendable_scan(keys)?;
        match plan(&spendable) {
            Err(rg_tx::Error::InsufficientNote(_)) => {
                let of = |scan: &ScanResult| scan.balances().get(token_hash).copied().unwrap_or(0);
                if of(&spendable) < value && value <= of(&self.scan(keys)) {
                    Err(Error::AwaitingPoi(value))
                } else {
                    Err(rg_tx::Error::InsufficientNote(value).into())
                }
            }
            planned => Ok(planned?),
        }
    }

    /// Proves each planned transaction, and puts them all in one `transact` call.
    fn prove_transactions(
        &self,
        keys: &WalletKeys,
        planned: &[TransferParams],
        artifacts: &Artifacts,
    ) -> Result<UnsignedTx, Error> {
        let transactions = planned
            .iter()
            .map(|params| {
                let prepared = params.prepare(keys)?;
                let circuit = crate::Circuit::Transact {
                    inputs: prepared.nullifiers.len(),
                    outputs: prepared.commitments.len(),
                };
                let (proof, public) = prove(artifacts, circuit, &prepared.circuit_inputs)?;
                if public != prepared.public_inputs() {
                    return Err(Error::BadProof);
                }
                Ok(prepared.transaction(&proof))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(UnsignedTx {
            chain_id: self.network.chain_id,
            to: self.network.proxy.to_string(),
            data: transact_calldata(transactions),
        })
    }

    /// Asks the node whether `from` could send this now.
    pub fn estimate_gas(&self, from: &str, tx: &UnsignedTx) -> Result<u64, Error> {
        Ok(self.rpc.estimate_gas(from, &tx.to, &tx.data_hex())?)
    }
}
