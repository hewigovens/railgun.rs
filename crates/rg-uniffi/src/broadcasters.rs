use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rg_core::{Broadcasters, POI_LIST, Waku};
use rg_keys::EvmAddress;
use rg_sync::Network;

use crate::{BroadcasterOffer, RailgunError};

/// The broadcasters of one network, over Railgun's Waku fleet. Every method blocks on the network.
#[derive(uniffi::Object)]
pub struct RailgunBroadcasters {
    pub(crate) broadcasters: Mutex<Broadcasters>,
    relay_adapt: [u8; 20],
}

impl RailgunBroadcasters {
    pub(crate) fn lock(&self) -> MutexGuard<'_, Broadcasters> {
        self.broadcasters
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

#[uniffi::export]
impl RailgunBroadcasters {
    /// Finds the fleet through DNS, falling back to the nodes known when this was built.
    #[uniffi::constructor]
    pub fn connect(network: String) -> Result<Arc<Self>, RailgunError> {
        let network = Network::by_name(&network)
            .ok_or_else(|| RailgunError::invalid(format!("unknown network: {network}")))?;
        let relay_adapt = network.relay_adapt.parse::<EvmAddress>()?.0;
        let waku = Waku::railgun().map_err(rg_core::Error::from)?;
        Ok(Arc::new(RailgunBroadcasters {
            broadcasters: Mutex::new(Broadcasters::new(waku, network.chain_id)),
            relay_adapt,
        }))
    }

    /// Valid offers from the last minute, the newest per broadcaster wallet.
    pub fn offers(&self) -> Result<Vec<Arc<BroadcasterOffer>>, RailgunError> {
        let offers = self.lock().offers().map_err(rg_core::Error::from)?;
        Ok(offers
            .into_iter()
            .map(|offer| Arc::new(BroadcasterOffer { offer }))
            .collect())
    }

    /// The cheapest live offer for `token`, if any. With `relay_adapt`, only from broadcasters that submit through this network's RelayAdapt, as an unshield to ETH needs.
    pub fn best_offer(
        &self,
        token: String,
        relay_adapt: bool,
    ) -> Result<Option<Arc<BroadcasterOffer>>, RailgunError> {
        let token = token.parse::<EvmAddress>()?.0;
        let offer = self
            .lock()
            .best_offer(&token, POI_LIST, relay_adapt.then_some(&self.relay_adapt))
            .map_err(rg_core::Error::from)?;
        Ok(offer.map(|offer| Arc::new(BroadcasterOffer { offer })))
    }
}
