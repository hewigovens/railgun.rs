use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rg_core::{Broadcasters, POI_LIST, Waku};
use rg_keys::EvmAddress;
use rg_sync::Network;

use crate::{BroadcasterOffer, RailgunError};

/// The broadcasters of one network, over Railgun's Waku fleet. Every method blocks on the network.
#[derive(uniffi::Object)]
pub struct RailgunBroadcasters {
    pub(crate) broadcasters: Mutex<Broadcasters>,
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
        let waku = Waku::railgun().map_err(rg_core::Error::from)?;
        Ok(Arc::new(RailgunBroadcasters {
            broadcasters: Mutex::new(Broadcasters::new(waku, network.chain_id)),
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

    /// The cheapest live offer for `token`, if any.
    pub fn best_offer(&self, token: String) -> Result<Option<Arc<BroadcasterOffer>>, RailgunError> {
        let token = token.parse::<EvmAddress>()?.0;
        let offer = self
            .lock()
            .best_offer(&token, POI_LIST)
            .map_err(rg_core::Error::from)?;
        Ok(offer.map(|offer| Arc::new(BroadcasterOffer { offer })))
    }
}
