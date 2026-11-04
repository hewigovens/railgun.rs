use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::futures::StreamExt;
use libp2p::request_response::{self as rr, OutboundRequestId, ProtocolSupport};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{StreamProtocol, Swarm, identify, noise, tcp, yamux};
use tokio::runtime::Runtime;

use crate::Error;
use crate::waku::codec::ProtoCodec;
use crate::waku::peer::{ENR_TREE, FALLBACK_ENRS, Peer, discover};
use crate::waku::proto::{
    LightPushRequest, LightPushResponse, Metadata, StoreQueryRequest, StoreQueryResponse,
};

/// Railgun's Waku cluster and shard (`WAKU_RAILGUN_PUB_SUB_TOPIC`).
const CLUSTER: u32 = 5;
const SHARD: u32 = 1;
const PUBSUB_TOPIC: &str = "/waku/2/rs/5/1";

const STORE: &str = "/vac/waku/store-query/3.0.0";
const LIGHT_PUSH: &str = "/vac/waku/lightpush/3.0.0";
const METADATA: &str = "/vac/waku/metadata/1.0.0";

const PAGE: u64 = 100;
const MAX_PAGES: usize = 20;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// A message as the store returned it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WakuMessage {
    pub payload: Vec<u8>,
    pub timestamp_ns: i64,
}

impl StoreQueryResponse {
    /// Its messages and the cursor to the next page. A peer may put any number in a page, and keeping more than were asked for would let it fill memory.
    fn page(self, limit: u64) -> Result<(Vec<WakuMessage>, Option<Vec<u8>>), Error> {
        if self.status_code != Some(200) {
            return Err(Error::Waku(format!(
                "store: {}",
                self.status_desc.unwrap_or_default()
            )));
        }
        if self.messages.len() as u64 > limit {
            return Err(Error::Waku("store: more messages than asked for".into()));
        }
        let messages = self
            .messages
            .into_iter()
            .filter_map(|kv| {
                let m = kv.message?;
                Some(WakuMessage {
                    payload: m.payload,
                    timestamp_ns: m.timestamp.unwrap_or(0),
                })
            })
            .collect();
        Ok((messages, self.pagination_cursor))
    }
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    store: rr::Behaviour<ProtoCodec<StoreQueryRequest, StoreQueryResponse>>,
    light_push: rr::Behaviour<ProtoCodec<LightPushRequest, LightPushResponse>>,
    metadata: rr::Behaviour<ProtoCodec<Metadata, Metadata>>,
    identify: identify::Behaviour,
}

enum Answer {
    Store(StoreQueryResponse),
    Push(LightPushResponse),
}

/// A Waku light client: it asks service nodes for stored messages and hands them messages to relay. It never joins the relay mesh. Calls block on an internal runtime.
pub struct Waku {
    runtime: Runtime,
    swarm: Swarm<Behaviour>,
    peers: Vec<Peer>,
}

pub(crate) fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as i64)
}

fn waku_error(e: impl std::fmt::Display) -> Error {
    Error::Waku(e.to_string())
}

fn our_metadata() -> Metadata {
    Metadata {
        cluster_id: Some(CLUSTER),
        shards: vec![SHARD],
    }
}

fn swarm() -> Result<Swarm<Behaviour>, Error> {
    let config = rr::Config::default().with_request_timeout(REQUEST_TIMEOUT);
    let outbound = |p: &'static str| [(StreamProtocol::new(p), ProtocolSupport::Outbound)];
    Ok(libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(waku_error)?
        .with_behaviour(|key| Behaviour {
            store: rr::Behaviour::new(outbound(STORE), config.clone()),
            light_push: rr::Behaviour::new(outbound(LIGHT_PUSH), config.clone()),
            metadata: rr::Behaviour::new(
                [(StreamProtocol::new(METADATA), ProtocolSupport::Full)],
                config.clone(),
            ),
            identify: identify::Behaviour::new(identify::Config::new(
                "/ipfs/id/1.0.0".into(),
                key.public(),
            )),
        })
        .map_err(waku_error)?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build())
}

/// Drives the swarm until `id` is answered, answering metadata requests meanwhile.
async fn answer(
    swarm: &mut Swarm<Behaviour>,
    id: OutboundRequestId,
) -> Result<Answer, rr::OutboundFailure> {
    loop {
        let SwarmEvent::Behaviour(event) = swarm.select_next_some().await else {
            continue;
        };
        match event {
            BehaviourEvent::Store(rr::Event::Message {
                message:
                    rr::Message::Response {
                        request_id,
                        response,
                    },
                ..
            }) if request_id == id => return Ok(Answer::Store(response)),
            BehaviourEvent::LightPush(rr::Event::Message {
                message:
                    rr::Message::Response {
                        request_id,
                        response,
                    },
                ..
            }) if request_id == id => return Ok(Answer::Push(response)),
            BehaviourEvent::Store(rr::Event::OutboundFailure {
                request_id, error, ..
            })
            | BehaviourEvent::LightPush(rr::Event::OutboundFailure {
                request_id, error, ..
            }) if request_id == id => {
                return Err(error);
            }
            BehaviourEvent::Metadata(rr::Event::Message {
                message: rr::Message::Request { channel, .. },
                ..
            }) => {
                let _ = swarm
                    .behaviour_mut()
                    .metadata
                    .send_response(channel, our_metadata());
            }
            _ => {}
        }
    }
}

fn runtime() -> Result<Runtime, Error> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(waku_error)
}

impl Waku {
    /// A client for these service nodes. Nothing connects until the first call.
    pub fn new(peers: Vec<Peer>) -> Result<Self, Error> {
        let runtime = runtime()?;
        let mut swarm = swarm()?;
        for p in &peers {
            swarm.add_peer_address(p.id, p.address.clone());
        }
        Ok(Waku {
            runtime,
            swarm,
            peers,
        })
    }

    /// A client for Railgun's fleet, found through its ENR tree in DNS, or the nodes it had when this was written if that fails.
    pub fn railgun() -> Result<Self, Error> {
        let found = runtime()?.block_on(discover(ENR_TREE)).unwrap_or_default();
        let peers = if found.is_empty() {
            FALLBACK_ENRS
                .iter()
                .map(|e| Peer::from_enr(e))
                .collect::<Result<_, _>>()?
        } else {
            found
        };
        Self::new(peers)
    }

    pub fn peers(&self) -> &[Peer] {
        &self.peers
    }

    /// Sends a request and waits for its answer, once more if the node had dropped the connection in between.
    fn ask(
        &mut self,
        mut send: impl FnMut(&mut Behaviour) -> OutboundRequestId,
    ) -> Result<Answer, Error> {
        let mut retried = false;
        loop {
            let id = send(self.swarm.behaviour_mut());
            match self.runtime.block_on(answer(&mut self.swarm, id)) {
                Err(rr::OutboundFailure::ConnectionClosed) if !retried => retried = true,
                result => return result.map_err(waku_error),
            }
        }
    }

    /// Stored messages on `content_topic` since `since_ns`, oldest first, from the first store node that answers.
    pub fn query(&mut self, content_topic: &str, since_ns: i64) -> Result<Vec<WakuMessage>, Error> {
        let stores: Vec<_> = self
            .peers
            .iter()
            .filter(|p| p.store)
            .map(|p| p.id)
            .collect();
        let mut last = Error::NoPeer("store");
        for peer in stores {
            match self.query_peer(peer, content_topic, since_ns) {
                Ok(messages) => return Ok(messages),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn query_peer(
        &mut self,
        peer: libp2p::PeerId,
        content_topic: &str,
        since_ns: i64,
    ) -> Result<Vec<WakuMessage>, Error> {
        let mut messages = Vec::new();
        let mut cursor = None;
        let end = now_ns();
        for page in 0..MAX_PAGES {
            let request = StoreQueryRequest {
                request_id: page.to_string(),
                include_data: true,
                pubsub_topic: Some(PUBSUB_TOPIC.into()),
                content_topics: vec![content_topic.into()],
                time_start: Some(since_ns),
                time_end: Some(end),
                pagination_cursor: cursor.take(),
                pagination_forward: true,
                pagination_limit: Some(PAGE),
            };
            let Answer::Store(response) =
                self.ask(|b| b.store.send_request(&peer, request.clone()))?
            else {
                unreachable!("a store request gets a store answer");
            };
            let (page, next) = response.page(PAGE)?;
            messages.extend(page);
            cursor = next;
            if cursor.is_none() {
                break;
            }
        }
        Ok(messages)
    }

    /// Hands a message to the light-push nodes in turn until one accepts it.
    pub fn push(&mut self, content_topic: &str, payload: &[u8]) -> Result<(), Error> {
        let pushers: Vec<_> = self
            .peers
            .iter()
            .filter(|p| p.light_push)
            .map(|p| p.id)
            .collect();
        let mut last = Error::NoPeer("light push");
        for (i, peer) in pushers.into_iter().enumerate() {
            let request = LightPushRequest {
                request_id: i.to_string(),
                pubsub_topic: Some(PUBSUB_TOPIC.into()),
                message: Some(crate::waku::proto::WakuMessage {
                    payload: payload.to_vec(),
                    content_topic: content_topic.into(),
                    version: Some(0),
                    timestamp: Some(now_ns()),
                    meta: None,
                    ephemeral: None,
                }),
            };
            match self.ask(|b| b.light_push.send_request(&peer, request.clone())) {
                Ok(Answer::Push(r)) if r.status_code == 200 => return Ok(()),
                Ok(Answer::Push(r)) => {
                    last = Error::Waku(format!(
                        "light push {}: {}",
                        r.status_code,
                        r.status_desc.unwrap_or_default()
                    ));
                }
                Ok(Answer::Store(_)) => unreachable!("a push gets a push answer"),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waku::proto::{MessageKeyValue, WakuMessage as Stored};

    #[test]
    fn a_store_page_with_more_messages_than_asked_for_is_refused() {
        let response = |n| StoreQueryResponse {
            status_code: Some(200),
            messages: vec![
                MessageKeyValue {
                    message: Some(Stored::default()),
                    ..MessageKeyValue::default()
                };
                n
            ],
            ..StoreQueryResponse::default()
        };
        assert_eq!(
            response(PAGE as usize).page(PAGE).unwrap().0.len(),
            PAGE as usize
        );
        assert!(matches!(
            response(PAGE as usize + 1).page(PAGE),
            Err(Error::Waku(_))
        ));
    }
}
