/// A fee quote from `RailgunClient.quote_fee`, to show before sending and then pass to `send`, so what is signed is what the user saw. Amounts are decimal strings in wei.
#[derive(uniffi::Object)]
pub struct FeeQuote {
    pub(crate) quote: rg_core::FeeQuote,
}

#[uniffi::export]
impl FeeQuote {
    pub fn gas_limit(&self) -> u64 {
        self.quote.gas_limit
    }

    pub fn max_fee_per_gas(&self) -> String {
        self.quote.max_fee_per_gas.to_string()
    }

    pub fn max_priority_fee_per_gas(&self) -> String {
        self.quote.max_priority_fee_per_gas.to_string()
    }

    /// The likely cost.
    pub fn expected_cost(&self) -> String {
        self.quote.expected_cost().to_string()
    }

    /// The most the account can be charged.
    pub fn max_cost(&self) -> String {
        self.quote.max_cost().to_string()
    }
}
