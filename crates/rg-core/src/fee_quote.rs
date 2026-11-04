use rg_keys::EvmAddress;
use rg_tx::decode_call_failed;
use serde_json::Value;

use crate::{ChainStore, Client, Error, UnsignedTx};

/// Far past any Railgun batch, so a node's estimate above it is a lie, and products with it cannot overflow.
const MAX_GAS: u64 = 30_000_000;
/// 10,000 gwei, far past any fee a chain has charged.
const MAX_GAS_PRICE: u128 = 10_000_000_000_000;

/// Rejects a gas price no honest node reports, which would otherwise make the fee whatever the node chose.
pub(crate) fn plausible_price(price: u128) -> Result<u128, Error> {
    if price > MAX_GAS_PRICE {
        return Err(Error::Implausible("gas price"));
    }
    Ok(price)
}

/// A relay's `CallFailed` revert, from the node's error, as which call failed and why.
fn call_failed(error: rg_sync::Error) -> Error {
    let rg_sync::Error::Refused(ref detail) = error else {
        return error.into();
    };
    let revert = serde_json::from_str::<Value>(detail)
        .ok()
        .and_then(|v| hex::decode(v["data"].as_str()?.trim_start_matches("0x")).ok());
    match revert.as_deref().and_then(decode_call_failed) {
        Some((index, reason)) => Error::CallFailed(index, reason),
        None => error.into(),
    }
}

/// What sending a transaction may cost, fixed before signing so the user approves the limit that is signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeQuote {
    /// The node's estimate.
    pub gas_estimate: u64,
    /// The estimate plus a margin, because rollup estimates move with the L1 fee. Unused gas is not charged.
    pub gas_limit: u64,
    pub base_fee_per_gas: u128,
    /// Twice the base fee plus the tip, so the transaction survives a few blocks of rising fees.
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

impl FeeQuote {
    /// The most the sender can pay, in wei.
    pub fn max_cost(&self) -> u128 {
        u128::from(self.gas_limit) * self.max_fee_per_gas
    }

    /// The likely cost in wei: the estimate at the current base fee plus the tip.
    pub fn expected_cost(&self) -> u128 {
        u128::from(self.gas_estimate) * (self.base_fee_per_gas + self.max_priority_fee_per_gas)
    }
}

impl<S: ChainStore> Client<S> {
    /// The node's gas estimate, with a failed relay call named and an implausible estimate rejected.
    pub(crate) fn node_estimate(
        &self,
        from: &str,
        to: &str,
        value: u128,
        data: &str,
    ) -> Result<u64, Error> {
        let gas = self
            .rpc
            .estimate_gas(from, to, value, data)
            .map_err(call_failed)?;
        if gas > MAX_GAS {
            return Err(Error::Implausible("gas estimate"));
        }
        Ok(gas)
    }

    /// Estimates gas for `from` sending `tx` and prices it at the current fees.
    pub fn quote_fee(&self, from: &[u8; 20], tx: &UnsignedTx) -> Result<FeeQuote, Error> {
        self.check_chain(tx)?;
        let gas_estimate = self.estimate_gas(&EvmAddress(*from).to_string(), tx)?;
        let base_fee_per_gas = plausible_price(self.rpc.base_fee()?)?;
        let max_priority_fee_per_gas = plausible_price(self.rpc.priority_fee()?)?;
        Ok(FeeQuote {
            gas_estimate,
            gas_limit: gas_estimate + gas_estimate / 5,
            base_fee_per_gas,
            max_fee_per_gas: base_fee_per_gas * 2 + max_priority_fee_per_gas,
            max_priority_fee_per_gas,
        })
    }
}
