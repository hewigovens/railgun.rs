use std::time::Duration;

use rand::RngCore;
use rg_broadcaster::{BroadcasterFees, Broadcasters, TransactRequest, TransactResponse};
use rg_keys::{WalletKeys, decode_address};
use rg_prover::ark_types::Proof;
use rg_tx::{BroadcasterFee, TransferParams};
use serde_json::{Map, Value, json};

use crate::route::Route;
use crate::{
    Artifacts, ChainStore, Client, Error, POI_LIST, Transfer, Unshield, UnshieldBaseToken,
    UnsignedTx,
};

/// The contract skips proof checks when the sender is this, so gas can be estimated before proving (`DUMMY_FROM_ADDRESS`).
const ESTIMATE_FROM: &str = "0x000000000000000000000000000000000000dEaD";

/// The fee can change the circuits, and so the gas, so it is re-estimated up to this many times (`MAX_ITERATIONS_BROADCASTER_FEE_REESTIMATION`).
const FEE_ROUNDS: usize = 5;

const ANSWER_TIMEOUT: Duration = Duration::from_secs(120);

/// A batch proved for one broadcaster to submit, with its fee note inside.
#[derive(Clone, Debug)]
pub struct BroadcastTx {
    pub tx: UnsignedTx,
    pub token: [u8; 20],
    /// What the broadcaster gets, from the private balance, on top of the amount sent.
    pub fee: u128,
    pub gas_estimate: u64,
    /// The gas price the fee was worked out at, and the one the broadcaster sends with.
    pub gas_price: u128,
    /// List key to txid leaf hash to proof.
    pub pre_transaction_pois: Value,
    pub broadcaster_viewing_key: [u8; 32],
    pub fees_id: String,
    /// Sent to RelayAdapt rather than the Railgun contract.
    pub use_relay_adapt: bool,
}

fn shape(planned: &[TransferParams]) -> Vec<(usize, usize)> {
    planned
        .iter()
        .map(|p| (p.inputs.len(), p.outputs.len() + p.unshield.iter().len()))
        .collect()
}

impl<S: ChainStore> Client<S> {
    /// Plans and proves a transfer for `offer`'s broadcaster to submit, paying it in the token sent.
    pub fn build_broadcast_transfer(
        &self,
        keys: &WalletKeys,
        transfer: &Transfer,
        offer: &BroadcasterFees,
        artifacts: &Artifacts,
    ) -> Result<BroadcastTx, Error> {
        let recipient = decode_address(transfer.recipient)?;
        self.build_broadcast(
            keys,
            transfer.token,
            offer,
            &Route::direct(self.network.proxy),
            artifacts,
            |fee, min_gas_price| {
                self.plan_transfer(keys, transfer, &recipient, Some(fee), min_gas_price)
            },
        )
    }

    /// Plans and proves an unshield for `offer`'s broadcaster to submit, paying it in the token unshielded.
    pub fn build_broadcast_unshield(
        &self,
        keys: &WalletKeys,
        unshield: &Unshield,
        offer: &BroadcasterFees,
        artifacts: &Artifacts,
    ) -> Result<BroadcastTx, Error> {
        self.build_broadcast(
            keys,
            unshield.token,
            offer,
            &Route::direct(self.network.proxy),
            artifacts,
            |fee, min_gas_price| self.plan_unshield(keys, unshield, Some(fee), min_gas_price),
        )
    }

    /// Plans and proves an unshield of wrapped ETH that arrives at `unshield.to` as ETH, through RelayAdapt, for `offer`'s broadcaster to submit. It is paid in wrapped ETH, and must submit through this network's RelayAdapt. As in the engine, the unwrap and send may fail without reverting, which leaves the ETH in RelayAdapt, so `to` must accept ETH.
    pub fn build_broadcast_unshield_base_token(
        &self,
        keys: &WalletKeys,
        unshield: &UnshieldBaseToken,
        offer: &BroadcasterFees,
        artifacts: &Artifacts,
    ) -> Result<BroadcastTx, Error> {
        let (to_relay_adapt, route) = self.base_token_route(unshield, false)?;
        if offer.relay_adapt != Some(to_relay_adapt.to) {
            return Err(Error::NotOffered);
        }
        self.build_broadcast(
            keys,
            to_relay_adapt.token,
            offer,
            &route,
            artifacts,
            |fee, min_gas_price| {
                self.plan_unshield(keys, &to_relay_adapt, Some(fee), min_gas_price)
            },
        )
    }

    /// Prices the fee from a gas estimate with stand-in proofs, re-plans until the circuits stop changing, then proves the batch and its pre-transaction POIs (`gasEstimateResponseDummyProofIterativeBroadcasterFee`).
    fn build_broadcast<'a>(
        &self,
        keys: &WalletKeys,
        token: [u8; 20],
        offer: &BroadcasterFees,
        route: &Route,
        artifacts: &Artifacts,
        plan: impl Fn(BroadcasterFee, u128) -> Result<Vec<TransferParams<'a>>, Error>,
    ) -> Result<BroadcastTx, Error> {
        let broadcaster = decode_address(&offer.railgun_address)?;
        if !offer.fees.contains_key(&token) {
            return Err(Error::NotOffered);
        }
        let (gas_price, min_gas_price) = if self.network.broadcaster_min_gas_price {
            let price = self.rpc.gas_price()?;
            (price, price)
        } else {
            (self.rpc.base_fee()? * 2 + self.rpc.priority_fee()?, 0)
        };
        let fee_of = |value| BroadcasterFee {
            recipient: broadcaster.clone(),
            value,
        };
        let plan_bound = |fee| {
            let mut planned = plan(fee_of(fee), min_gas_price)?;
            route.bind(keys, &mut planned);
            Ok::<_, Error>(planned)
        };
        let mut planned = plan_bound(0)?;
        let mut gas_estimate = self.estimate_unproved(keys, &planned, route)?;
        let mut fee = 0;
        for _ in 0..FEE_ROUNDS {
            let gas_limit = u128::from(gas_estimate + gas_estimate / 5);
            fee = offer
                .fee(&token, gas_limit * gas_price)
                .ok_or(Error::NotOffered)?;
            let next = plan_bound(fee)?;
            let same = shape(&next) == shape(&planned);
            planned = next;
            if same {
                break;
            }
            gas_estimate = self.estimate_unproved(keys, &planned, route)?;
        }

        let mut by_leaf = Map::new();
        for params in &planned {
            let (leaf, proof) = self.prove_pre_transaction(keys, params, artifacts)?;
            by_leaf.insert(leaf, proof);
        }
        Ok(BroadcastTx {
            tx: self.transact(keys, &planned, route, artifacts)?,
            token,
            fee,
            gas_estimate,
            gas_price,
            pre_transaction_pois: json!({ (POI_LIST): by_leaf }),
            broadcaster_viewing_key: offer.viewing_public_key,
            fees_id: offer.fees_id.clone(),
            use_relay_adapt: route.is_relay(),
        })
    }

    /// Gas for the batch with empty proofs, sent from the address the contract does not check proofs for.
    fn estimate_unproved(
        &self,
        keys: &WalletKeys,
        planned: &[TransferParams],
        route: &Route,
    ) -> Result<u64, Error> {
        let txs = planned
            .iter()
            .map(|p| Ok(p.prepare(keys)?.transaction(&Proof::default())))
            .collect::<Result<Vec<_>, Error>>()?;
        let data = format!("0x{}", hex::encode(route.calldata(txs)));
        Ok(self.rpc.estimate_gas(ESTIMATE_FROM, route.to, 0, &data)?)
    }

    /// Sends the batch to its broadcaster and waits for the hash of the transaction it submitted.
    pub fn broadcast(
        &self,
        broadcasters: &mut Broadcasters,
        tx: &BroadcastTx,
    ) -> Result<[u8; 32], Error> {
        self.check_chain(&tx.tx)?;
        let request = TransactRequest {
            chain_id: tx.tx.chain_id,
            to: &tx.tx.to,
            data: &tx.tx.data,
            broadcaster_viewing_key: tx.broadcaster_viewing_key,
            fees_id: &tx.fees_id,
            min_gas_price: tx.gas_price,
            use_relay_adapt: tx.use_relay_adapt,
            pre_transaction_pois: &tx.pre_transaction_pois,
        };
        let sealed = request.seal(|b| rand::rngs::OsRng.fill_bytes(b))?;
        match broadcasters.submit(&sealed, ANSWER_TIMEOUT)? {
            TransactResponse::Submitted(hash) => Ok(hash),
            TransactResponse::Refused(why) => Err(Error::Refused(why)),
        }
    }
}
