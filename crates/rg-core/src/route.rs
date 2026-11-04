use rg_keys::WalletKeys;
use rg_sync::abi;
use rg_tx::{AdaptId, TransferParams, relay_adapt_params, relay_calldata, transact_calldata};

/// Where a batch is sent: straight to the Railgun contract, or to RelayAdapt with an action bound into every transaction.
pub(crate) struct Route {
    pub(crate) to: &'static str,
    relay: Option<([u8; 20], abi::ActionData)>,
}

impl Route {
    pub(crate) fn direct(proxy: &'static str) -> Self {
        Route {
            to: proxy,
            relay: None,
        }
    }

    pub(crate) fn relay(to: &'static str, relay_adapt: [u8; 20], action: abi::ActionData) -> Self {
        Route {
            to,
            relay: Some((relay_adapt, action)),
        }
    }

    /// The RelayAdapt contract the batch goes through, if any.
    pub(crate) fn relay_adapt(&self) -> Option<[u8; 20]> {
        self.relay.as_ref().map(|(contract, _)| *contract)
    }

    /// Commits each transaction to the action and its batch's nullifiers, so only RelayAdapt can submit them, and only with that action.
    pub(crate) fn bind(&self, keys: &WalletKeys, planned: &mut [TransferParams]) {
        let Some((contract, action)) = &self.relay else {
            return;
        };
        let nullifiers: Vec<_> = planned
            .iter()
            .map(|p| p.nullifiers(&keys.nullifying_key))
            .collect();
        let adapt = AdaptId {
            contract: *contract,
            parameters: relay_adapt_params(&nullifiers, action),
        };
        for p in planned {
            p.adapt = adapt;
        }
    }

    pub(crate) fn calldata(&self, transactions: Vec<abi::Transaction>) -> Vec<u8> {
        match &self.relay {
            Some((_, action)) => relay_calldata(transactions, action.clone()),
            None => transact_calldata(transactions),
        }
    }

    /// As [`Route::calldata`], but with the calls required to succeed, so a gas estimate fails where they would, as the engine does for cross-contract calls. Estimates skip the adapt params check, so this does not change what the batch is bound to.
    pub(crate) fn estimate_calldata(&self, transactions: Vec<abi::Transaction>) -> Vec<u8> {
        match &self.relay {
            Some((_, action)) => relay_calldata(
                transactions,
                abi::ActionData {
                    requireSuccess: true,
                    ..action.clone()
                },
            ),
            None => self.calldata(transactions),
        }
    }
}
