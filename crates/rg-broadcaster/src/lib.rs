//! Railgun broadcasters (`@railgun-community/waku-broadcaster-client`): a broadcaster signs a fee offer per chain and token, takes a proved transaction encrypted to its viewing key, submits it from its own account, and answers with the transaction hash. Messages travel over Waku; the `waku` feature adds a light client for that.

mod broadcaster_fees;
#[cfg(feature = "waku")]
mod broadcasters;
mod error;
mod sealed_request;
mod topic;
#[cfg(feature = "waku")]
mod waku;

pub use broadcaster_fees::{BroadcasterFees, best_offer};
#[cfg(feature = "waku")]
pub use broadcasters::Broadcasters;
pub use error::Error;
pub use sealed_request::{SealedRequest, TransactRequest, TransactResponse};
pub use topic::{fees_topic, transact_response_topic, transact_topic};
#[cfg(feature = "waku")]
pub use waku::{Peer, Waku, WakuMessage};
