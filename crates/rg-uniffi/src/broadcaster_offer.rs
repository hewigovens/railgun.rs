use rg_keys::EvmAddress;

use crate::RailgunError;

/// One broadcaster's signed fee offer, from `RailgunBroadcasters`. Pass it to `build_broadcast_transfer` or `build_broadcast_unshield` while it is live.
#[derive(uniffi::Object)]
pub struct BroadcasterOffer {
    pub(crate) offer: rg_core::BroadcasterFees,
}

#[uniffi::export]
impl BroadcasterOffer {
    /// The 0zk address the fee goes to.
    pub fn railgun_address(&self) -> String {
        self.offer.railgun_address.clone()
    }

    pub fn identifier(&self) -> Option<String> {
        self.offer.identifier.clone()
    }

    pub fn version(&self) -> String {
        self.offer.version.clone()
    }

    pub fn reliability(&self) -> f64 {
        self.offer.reliability
    }

    pub fn fee_expiration_ms(&self) -> u64 {
        self.offer.fee_expiration_ms
    }

    /// The checksummed tokens it takes fees in.
    pub fn tokens(&self) -> Vec<String> {
        self.offer
            .fees
            .keys()
            .map(|t| EvmAddress(*t).to_string())
            .collect()
    }

    /// Fee per unit of gas in `token`, scaled by 10^18, as a decimal string.
    pub fn fee_per_unit_gas(&self, token: String) -> Result<Option<String>, RailgunError> {
        let token = token.parse::<EvmAddress>()?.0;
        Ok(self.offer.fees.get(&token).map(u128::to_string))
    }
}
