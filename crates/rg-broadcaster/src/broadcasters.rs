use std::collections::BTreeMap;
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::waku::{Waku, now_ns};
use crate::{
    BroadcasterFees, Error, SealedRequest, TransactResponse, best_offer, fees_topic,
    transact_response_topic, transact_topic,
};

/// How far back fee offers are read (`BroadcasterConfig.historicalLookBackTime`).
const FEES_LOOK_BACK: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_secs(2);
const CLOCK_SKEW: Duration = Duration::from_secs(60);
/// Sent again once if nothing has answered by then, as the client resends early on.
const RESEND_AFTER: Duration = Duration::from_secs(10);

/// The broadcasters of one chain, over Waku.
pub struct Broadcasters {
    waku: Waku,
    chain_id: u64,
}

impl Broadcasters {
    pub fn new(waku: Waku, chain_id: u64) -> Self {
        Broadcasters { waku, chain_id }
    }

    /// Every valid offer from the last minute, the newest per broadcaster wallet. Messages that fail their signature or version check are skipped.
    pub fn offers(&mut self) -> Result<Vec<BroadcasterFees>, Error> {
        let since = now_ns() - FEES_LOOK_BACK.as_nanos() as i64;
        let messages = self.waku.query(&fees_topic(self.chain_id), since)?;
        let mut newest = BTreeMap::new();
        for offer in messages
            .iter()
            .filter_map(|m| BroadcasterFees::from_message(&m.payload).ok())
        {
            let key = (offer.railgun_address.clone(), offer.identifier.clone());
            let older = newest
                .get(&key)
                .is_some_and(|o: &BroadcasterFees| o.fee_expiration_ms >= offer.fee_expiration_ms);
            if !older {
                newest.insert(key, offer);
            }
        }
        Ok(newest.into_values().collect())
    }

    /// The cheapest live offer for `token`, from a fresh read of the offers. See [`best_offer`].
    pub fn best_offer(
        &mut self,
        token: &[u8; 20],
        poi_list: &str,
        relay_adapt: Option<&[u8; 20]>,
    ) -> Result<Option<BroadcasterFees>, Error> {
        let offers = self.offers()?;
        let now_ms = (now_ns() / 1_000_000) as u64;
        Ok(best_offer(&offers, token, now_ms, poi_list, relay_adapt).cloned())
    }

    /// Sends the request and waits up to `timeout` for the broadcaster's answer.
    pub fn submit(
        &mut self,
        request: &SealedRequest,
        timeout: Duration,
    ) -> Result<TransactResponse, Error> {
        // Answers carry the broadcaster's clock, so look back further than the request; others' answers do not decrypt.
        let since = now_ns() - CLOCK_SKEW.as_nanos() as i64;
        let start = Instant::now();
        self.waku
            .push(&transact_topic(self.chain_id), &request.payload)?;
        let mut resent = false;
        while start.elapsed() < timeout {
            sleep(POLL);
            let answers = self
                .waku
                .query(&transact_response_topic(self.chain_id), since)?;
            if let Some(answer) = answers
                .iter()
                .find_map(|m| request.open_response(&m.payload))
            {
                return Ok(answer);
            }
            if !resent && start.elapsed() >= RESEND_AFTER {
                self.waku
                    .push(&transact_topic(self.chain_id), &request.payload)?;
                resent = true;
            }
        }
        Err(Error::Timeout)
    }
}
