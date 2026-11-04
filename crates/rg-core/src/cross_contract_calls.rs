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
    /// Token and value. The contract keeps its fee, so RelayAdapt receives slightly less than each value. A token listed twice is unshielded once, for the sum.
    pub unshields: Vec<([u8; 20], u128)>,
    /// Made from RelayAdapt's address, so it approves any spender itself, with a call to the token.
    pub calls: Vec<ContractCall>,
    /// Tokens RelayAdapt shields all it holds of once the calls are done, usually what the calls bought. Every unshielded token is shielded back too, since anyone can take what is left in RelayAdapt.
    pub shields: Vec<[u8; 20]>,
    /// 0zk address the shields go to.
    pub shield_receiver: &'a str,
    /// The least gas the relay is sent with: at least [`crate::CROSS_CONTRACT_MIN_GAS_LIMIT`], more if the calls need it.
    pub min_gas_limit: u64,
}

impl CrossContractCalls<'_> {
    /// One unshield per token, to RelayAdapt, so the same notes are never picked twice.
    fn unshields_to(&self, relay_adapt: [u8; 20]) -> Result<Vec<Unshield>, Error> {
        let mut unshields: Vec<Unshield> = Vec::new();
        for &(token, value) in &self.unshields {
            match unshields.iter_mut().find(|u| u.token == token) {
                Some(u) => {
                    u.value = u
                        .value
                        .checked_add(value)
                        .ok_or(rg_tx::Error::OutOfRange("value"))?;
                }
                None => unshields.push(Unshield {
                    to: relay_adapt,
                    token,
                    value,
                }),
            }
        }
        Ok(unshields)
    }

    /// The listed tokens, then any unshielded token not among them, once each.
    fn shield_tokens(&self) -> Vec<[u8; 20]> {
        let mut tokens: Vec<[u8; 20]> = Vec::new();
        for token in self
            .shields
            .iter()
            .chain(self.unshields.iter().map(|(t, _)| t))
        {
            if !tokens.contains(token) {
                tokens.push(*token);
            }
        }
        tokens
    }
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
        let unshields = calls.unshields_to(relay_adapt)?;
        let tokens = calls.shield_tokens();
        let shields = tokens
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
        )?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unshields_merge_by_token_and_all_come_back() {
        let (a, b, c) = ([1; 20], [2; 20], [3; 20]);
        let calls = CrossContractCalls {
            unshields: vec![(a, 5), (b, 1), (a, 7)],
            calls: vec![],
            shields: vec![c, c],
            shield_receiver: "",
            min_gas_limit: crate::CROSS_CONTRACT_MIN_GAS_LIMIT,
        };
        let merged: Vec<_> = calls
            .unshields_to([9; 20])
            .unwrap()
            .iter()
            .map(|u| (u.token, u.value))
            .collect();
        assert_eq!(merged, vec![(a, 12), (b, 1)]);
        assert_eq!(calls.shield_tokens(), vec![c, a, b]);
    }
}
