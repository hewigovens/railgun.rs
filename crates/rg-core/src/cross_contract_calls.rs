use rand::RngCore;
use rg_keys::{WalletKeys, decode_address};
use rg_tx::{
    BroadcasterFee, ContractCall, TransferParams, cross_contract_calls_action, relay_shield_request,
};

use crate::route::Route;
use crate::send::address;
use crate::{Artifacts, ChainStore, Client, Error, Unshield, UnsignedTx};

/// Tokens unshielded to RelayAdapt, calls it then makes with them, such as a swap, and the tokens whose whole balance it shields back afterwards, all in one `relay` (the wallet SDK's cross-contract calls).
pub struct CrossContractCalls<'a> {
    /// Token and value. The contract keeps its fee, so RelayAdapt receives slightly less than each value.
    pub unshields: Vec<([u8; 20], u128)>,
    /// Made from RelayAdapt's address, so it approves any spender itself, with a call to the token.
    pub calls: Vec<ContractCall>,
    /// Tokens RelayAdapt shields all it holds of once the calls are done, usually what the calls bought and what they left over.
    pub shields: Vec<[u8; 20]>,
    /// 0zk address the shields go to.
    pub shield_receiver: &'a str,
    /// The least gas the relay is sent with: [`crate::CROSS_CONTRACT_MIN_GAS_LIMIT`] unless the calls need more.
    pub min_gas_limit: u64,
}

impl<S: ChainStore> Client<S> {
    /// Plans and proves the unshields and calls, to send from your own account.
    pub fn build_cross_contract_calls(
        &self,
        keys: &WalletKeys,
        calls: &CrossContractCalls,
        artifacts: &Artifacts,
    ) -> Result<UnsignedTx, Error> {
        let (unshields, route) = self.cross_contract_route(calls, true)?;
        let mut params = self.plan_unshields(keys, &unshields, None, 0)?;
        route.bind(keys, &mut params);
        self.transact(keys, &params, &route, artifacts)
    }

    /// The unshields to RelayAdapt, and the route that makes the calls and shields back.
    pub(crate) fn cross_contract_route(
        &self,
        calls: &CrossContractCalls,
        require_success: bool,
    ) -> Result<(Vec<Unshield>, Route), Error> {
        let relay_adapt = address(self.network.relay_adapt)?;
        let receiver = decode_address(calls.shield_receiver)?;
        let mut rng = rand::rngs::OsRng;
        let shields = calls
            .shields
            .iter()
            .map(|token| relay_shield_request(&receiver, *token, |b| rng.fill_bytes(b)))
            .collect::<Result<Vec<_>, _>>()?;
        let mut random = [0u8; 31];
        rng.fill_bytes(&mut random);
        let action = cross_contract_calls_action(
            relay_adapt,
            &calls.calls,
            shields,
            random,
            require_success,
            calls.min_gas_limit,
        );
        let unshields = calls
            .unshields
            .iter()
            .map(|&(token, value)| Unshield {
                to: relay_adapt,
                token,
                value,
            })
            .collect();
        let route = Route::relay(self.network.relay_adapt, relay_adapt, action);
        Ok((unshields, route))
    }

    /// Each unshield's transactions, with the broadcaster's fee note in the first one's.
    pub(crate) fn plan_unshields(
        &self,
        keys: &WalletKeys,
        unshields: &[Unshield],
        broadcaster_fee: Option<BroadcasterFee>,
        min_gas_price: u128,
    ) -> Result<Vec<TransferParams<'static>>, Error> {
        let mut fee = broadcaster_fee;
        let mut planned = Vec::new();
        for unshield in unshields {
            planned.extend(self.plan_unshield(keys, unshield, fee.take(), min_gas_price)?);
        }
        Ok(planned)
    }
}
