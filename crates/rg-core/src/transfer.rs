use rand::RngCore;
use rg_keys::{AddressData, WalletKeys, decode_address};
use rg_primitives::Fr;
use rg_prover::Circuit;
use rg_prover::ark_types::{Bn254, Proof};
use rg_sync::abi;
use rg_tx::{
    BroadcasterFee, TransferParams, TransferRequest, UnshieldRequest, chain_full_network_id,
    plan_transfer, plan_unshield, unshield_base_token_action,
};
use rg_wallet::ScanResult;

use crate::route::Route;
use crate::send::address;
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

/// Out of the pool as native ETH: wrapped ETH is unshielded and unwrapped on the way. The contract keeps its fee, so `to` receives slightly less than `value`.
pub struct UnshieldBaseToken {
    pub to: [u8; 20],
    pub value: u128,
}

/// A call for any funded account to sign and send; [`Client::send`] does both. `value` is the wei it sends along, which only a native ETH shield needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedTx {
    pub chain_id: u64,
    pub to: String,
    pub value: u128,
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

/// Proves each planned transaction for the contract.
fn prove_all(
    keys: &WalletKeys,
    planned: &[TransferParams],
    artifacts: &Artifacts,
) -> Result<Vec<abi::Transaction>, Error> {
    planned
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
        .collect()
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
        let params = self.plan_transfer(keys, transfer, &recipient, None, 0)?;
        self.transact(keys, &params, &Route::direct(self.network.proxy), artifacts)
    }

    pub(crate) fn plan_transfer<'a>(
        &self,
        keys: &WalletKeys,
        transfer: &Transfer<'a>,
        recipient: &'a AddressData,
        broadcaster_fee: Option<BroadcasterFee>,
        min_gas_price: u128,
    ) -> Result<Vec<TransferParams<'a>>, Error> {
        let fee = broadcaster_fee.as_ref().map_or(0, |f| f.value);
        let request = TransferRequest {
            recipient,
            token_hash: rg_notes::TokenData::erc20(transfer.token).hash(),
            value: transfer.value,
            memo_text: transfer.memo,
            show_sender_to_recipient: false,
            wallet_source: WALLET_SOURCE,
            chain_id: chain_full_network_id(0, self.network.chain_id),
            min_gas_price,
            broadcaster_fee,
        };
        self.plan(keys, &request.token_hash, request.value + fee, |scan| {
            plan_transfer(keys, &self.state, scan, &request, |b| {
                rand::rngs::OsRng.fill_bytes(b)
            })
        })
    }

    /// Plans and proves an unshield.
    pub fn build_unshield(
        &self,
        keys: &WalletKeys,
        unshield: &Unshield,
        artifacts: &Artifacts,
    ) -> Result<UnsignedTx, Error> {
        let params = self.plan_unshield(keys, unshield, None, 0)?;
        self.transact(keys, &params, &Route::direct(self.network.proxy), artifacts)
    }

    /// Plans and proves an unshield of wrapped ETH that arrives at `to` as ETH: the transactions unshield to RelayAdapt, which unwraps it and sends it on, all in one `relay` call. The contract's fee comes out of `value`.
    pub fn build_unshield_base_token(
        &self,
        keys: &WalletKeys,
        unshield: &UnshieldBaseToken,
        artifacts: &Artifacts,
    ) -> Result<UnsignedTx, Error> {
        let (to_relay_adapt, route) = self.base_token_route(unshield, true)?;
        let mut params = self.plan_unshield(keys, &to_relay_adapt, None, 0)?;
        route.bind(keys, &mut params);
        self.transact(keys, &params, &route, artifacts)
    }

    /// The wrapped-token unshield to RelayAdapt, and the route that unwraps it and sends the ETH to `unshield.to`.
    pub(crate) fn base_token_route(
        &self,
        unshield: &UnshieldBaseToken,
        require_success: bool,
    ) -> Result<(Unshield, Route), Error> {
        let relay_adapt = address(self.network.relay_adapt)?;
        let to_relay_adapt = Unshield {
            to: relay_adapt,
            token: address(self.network.wrapped_token)?,
            value: unshield.value,
        };
        let mut random = [0u8; 31];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let action = unshield_base_token_action(relay_adapt, unshield.to, random, require_success);
        let route = Route::relay(self.network.relay_adapt, relay_adapt, action);
        Ok((to_relay_adapt, route))
    }

    pub(crate) fn plan_unshield(
        &self,
        keys: &WalletKeys,
        unshield: &Unshield,
        broadcaster_fee: Option<BroadcasterFee>,
        min_gas_price: u128,
    ) -> Result<Vec<TransferParams<'static>>, Error> {
        let fee = broadcaster_fee.as_ref().map_or(0, |f| f.value);
        let request = UnshieldRequest {
            to: unshield.to,
            token: unshield.token,
            value: unshield.value,
            wallet_source: WALLET_SOURCE,
            chain_id: chain_full_network_id(0, self.network.chain_id),
            min_gas_price,
            broadcaster_fee,
        };
        let token_hash = rg_notes::TokenData::erc20(unshield.token).hash();
        self.plan(keys, &token_hash, unshield.value + fee, |scan| {
            plan_unshield(keys, &self.state, scan, &request, |b| {
                rand::rngs::OsRng.fill_bytes(b)
            })
        })
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

    /// One call along `route` with every planned transaction, proved.
    pub(crate) fn transact(
        &self,
        keys: &WalletKeys,
        planned: &[TransferParams],
        route: &Route,
        artifacts: &Artifacts,
    ) -> Result<UnsignedTx, Error> {
        Ok(UnsignedTx {
            chain_id: self.network.chain_id,
            to: route.to.to_string(),
            value: 0,
            data: route.calldata(prove_all(keys, planned, artifacts)?),
        })
    }

    /// Asks the node whether `from` could send this now.
    pub fn estimate_gas(&self, from: &str, tx: &UnsignedTx) -> Result<u64, Error> {
        Ok(self
            .rpc
            .estimate_gas(from, &tx.to, tx.value, &tx.data_hex())?)
    }
}
