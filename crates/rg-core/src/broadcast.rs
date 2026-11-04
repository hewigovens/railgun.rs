use std::time::Duration;

use rand::RngCore;
use rg_broadcaster::{BroadcasterFees, Broadcasters, TransactRequest, TransactResponse};
use rg_keys::{WalletKeys, decode_address};
use rg_prover::ark_types::Proof;
use rg_tx::{BroadcasterFee, TransferParams, bind_together_action};
use serde_json::{Map, Value, json};

use crate::fee_quote::plausible_price;
use crate::pending_spends::{Spend, spends};
use crate::route::Route;
use crate::send::address;
use crate::{
    Artifacts, ChainStore, Client, CrossContractCalls, Error, POI_LIST, Transfer, Unshield,
    UnshieldBaseToken, UnsignedTx,
};

/// The contract skips proof checks when the sender is this, so gas can be estimated before proving (`DUMMY_FROM_ADDRESS`).
const ESTIMATE_FROM: &str = "0x000000000000000000000000000000000000dEaD";

/// The fee can change the circuits, and so the gas, so it is re-estimated up to this many times (`MAX_ITERATIONS_BROADCASTER_FEE_REESTIMATION`).
const FEE_ROUNDS: usize = 5;

const ANSWER_TIMEOUT: Duration = Duration::from_secs(120);

/// Seconds to wait for the node to see a broadcaster's transaction before taking its word for the hash.
const SUBMITTED_CHECKS: usize = 10;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

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
    /// The notes it spends, held once it is handed over.
    pub spends: Vec<Spend>,
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

    /// Plans and proves an unshield of wrapped ETH that arrives at `unshield.to` as ETH, through RelayAdapt, for `offer`'s broadcaster to submit. It is paid in wrapped ETH, and must submit through this network's RelayAdapt. As in the engine, the unwrap and send may fail without reverting, which leaves the ETH in RelayAdapt, so `to` must accept ETH. The relay must be sent with all the gas they need.
    pub fn build_broadcast_unshield_base_token(
        &self,
        keys: &WalletKeys,
        unshield: &UnshieldBaseToken,
        offer: &BroadcasterFees,
        artifacts: &Artifacts,
    ) -> Result<BroadcastTx, Error> {
        let (to_relay_adapt, route) = self.base_token_route(unshield, false)?;
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

    /// Plans and proves unshields and calls for `offer`'s broadcaster to submit through this network's RelayAdapt, paying it in the first token unshielded. The calls may fail without reverting, so the fee is paid either way; the shields still run and take back what RelayAdapt holds of the listed tokens.
    pub fn build_broadcast_cross_contract_calls(
        &self,
        keys: &WalletKeys,
        calls: &CrossContractCalls,
        offer: &BroadcasterFees,
        artifacts: &Artifacts,
    ) -> Result<BroadcastTx, Error> {
        let (unshields, route) = self.cross_contract_route(calls, false)?;
        let token = unshields.first().ok_or(Error::NotOffered)?.token;
        self.build_broadcast(
            keys,
            token,
            offer,
            &route,
            artifacts,
            |fee, min_gas_price| self.plan_unshields(keys, &unshields, Some(fee), min_gas_price),
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
        if !offer.fees.contains_key(&token) || !offer.is_live(now_ms()) {
            return Err(Error::NotOffered);
        }
        // Sent straight to the Railgun contract, each transaction of a batch could be submitted alone, so the broadcaster could take its fee from the first and hold back the rest.
        let together = match route.relay_adapt() {
            Some(_) => None,
            None => Some(self.bound_together_route()?),
        };
        let route_for = |planned: &[TransferParams]| match &together {
            Some(together) if planned.len() > 1 => together,
            _ => route,
        };
        // Bounded, so the products below cannot overflow and a lying node cannot set the fee at will.
        let (gas_price, min_gas_price) = if self.network.broadcaster_min_gas_price {
            let price = plausible_price(self.rpc.gas_price()?)?;
            (price, price)
        } else {
            let base_fee = plausible_price(self.rpc.base_fee()?)?;
            (base_fee * 2 + plausible_price(self.rpc.priority_fee()?)?, 0)
        };
        let fee_of = |value| BroadcasterFee {
            recipient: broadcaster.clone(),
            value,
        };
        let plan_bound = |fee| {
            let mut planned = plan(fee_of(fee), min_gas_price)?;
            let route = self.gas_floor(keys, &planned, route_for(&planned))?;
            route.bind(keys, &mut planned);
            let gas_estimate = self.estimate_unproved(keys, &planned, &route)?;
            Ok::<_, Error>((planned, route, gas_estimate))
        };
        let (mut planned, mut route, mut gas_estimate) = plan_bound(0)?;
        let mut fee = 0;
        for _ in 0..FEE_ROUNDS {
            let gas_limit = u128::from(gas_estimate + gas_estimate / 5);
            fee = offer
                .fee(&token, gas_limit * gas_price)
                .ok_or(Error::NotOffered)?;
            let (next, next_route, next_estimate) = plan_bound(fee)?;
            let same = shape(&next) == shape(&planned);
            (planned, route) = (next, next_route);
            if same {
                break;
            }
            gas_estimate = next_estimate;
        }
        let route = &route;
        let through = route.relay_adapt();
        if through.is_some() && offer.relay_adapt != through {
            return Err(Error::NotOffered);
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
            use_relay_adapt: through.is_some(),
            spends: spends(keys, &planned),
        })
    }

    fn bound_together_route(&self) -> Result<Route, Error> {
        let mut random = [0u8; 31];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let action = bind_together_action(random);
        let relay_adapt = address(self.network.relay_adapt)?;
        Ok(Route::relay(self.network.relay_adapt, relay_adapt, action))
    }

    /// `route`, requiring at least the gas the whole batch takes to be left when the relay starts, so a broadcaster cannot send enough for the transactions and its fee but too little for the calls.
    fn gas_floor(
        &self,
        keys: &WalletKeys,
        planned: &[TransferParams],
        route: &Route,
    ) -> Result<Route, Error> {
        if !route.has_calls() {
            return Ok(route.clone());
        }
        let needs = self.estimate_unproved(keys, planned, &route.with_min_gas_limit(0))?;
        Ok(route.with_min_gas_limit(needs.max(route.min_gas_limit())))
    }

    /// Gas for the batch with empty proofs, sent from the address the contract does not check proofs for. It fails if a relay's calls would.
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
        let data = format!("0x{}", hex::encode(route.estimate_calldata(txs)));
        self.node_estimate(ESTIMATE_FROM, route.to, 0, &data)
    }

    /// Sends the batch to its broadcaster and waits for the hash of the transaction it submitted. Its notes stay held until a sync shows them spent, whatever the answer, since the broadcaster can submit it later.
    pub fn broadcast(
        &mut self,
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
        self.hold(&tx.spends)?;
        match broadcasters.submit(&sealed, ANSWER_TIMEOUT)? {
            TransactResponse::Submitted(hash) => {
                self.check_submitted(&hash, &tx.tx)?;
                Ok(hash)
            }
            TransactResponse::Refused(why) => Err(Error::Refused(why)),
        }
    }

    /// The hash is the broadcaster's word. When the node already has that transaction, it must carry this batch, or the broadcaster has answered with another one.
    fn check_submitted(&self, hash: &[u8; 32], tx: &UnsignedTx) -> Result<(), Error> {
        for _ in 0..SUBMITTED_CHECKS {
            if let Some((to, data)) = self.rpc.transaction_call(hash)? {
                return if to.eq_ignore_ascii_case(&tx.to) && data == tx.data {
                    Ok(())
                } else {
                    Err(Error::WrongTransaction)
                };
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use rg_sync::Network;

    use super::*;
    use crate::FileStore;

    /// A node that answers every request with `gas` as its estimate.
    fn node(gas: u64) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let _ = stream.read(&mut [0; 1 << 16]);
                let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":"0x{gas:x}"}}"#);
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        url
    }

    #[test]
    fn a_relay_with_calls_must_start_with_the_gas_the_batch_takes() {
        let dir = std::env::temp_dir().join(format!("rg-core-floor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = FileStore::open(&dir).unwrap();
        let client = Client::open(Network::ARBITRUM, &node(700_000), store).unwrap();
        let keys = WalletKeys::from_mnemonic(
            "test test test test test test test test test test test junk",
            "",
            0,
        )
        .unwrap();
        let unshield = UnshieldBaseToken {
            to: [1; 20],
            value: 1,
        };
        let (_, to_eth) = client.base_token_route(&unshield, false).unwrap();
        let floored = client.gas_floor(&keys, &[], &to_eth).unwrap();
        assert_eq!(floored.min_gas_limit(), 700_000);

        let together = client.bound_together_route().unwrap();
        let floored = client.gas_floor(&keys, &[], &together).unwrap();
        assert_eq!(floored.min_gas_limit(), 0);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
