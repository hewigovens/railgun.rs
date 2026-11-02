use rg_keys::EvmAddress;

use crate::{ChainStore, Client, Error, UnsignedTx};

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
    /// Estimates gas for `from` sending `tx` and prices it at the current fees.
    pub fn quote_fee(&self, from: &[u8; 20], tx: &UnsignedTx) -> Result<FeeQuote, Error> {
        self.check_chain(tx)?;
        let gas_estimate = self.estimate_gas(&EvmAddress(*from).to_string(), tx)?;
        let base_fee_per_gas = self.rpc.base_fee()?;
        let max_priority_fee_per_gas = self.rpc.priority_fee()?;
        Ok(FeeQuote {
            gas_estimate,
            gas_limit: gas_estimate + gas_estimate / 5,
            base_fee_per_gas,
            max_fee_per_gas: base_fee_per_gas * 2 + max_priority_fee_per_gas,
            max_priority_fee_per_gas,
        })
    }
}
