//! The Waku protobufs a light client needs (`@waku/proto`: message, store v3, light push v3, metadata).

#[derive(Clone, PartialEq, prost::Message)]
pub struct WakuMessage {
    #[prost(bytes = "vec", tag = "1")]
    pub payload: Vec<u8>,
    #[prost(string, tag = "2")]
    pub content_topic: String,
    #[prost(uint32, optional, tag = "3")]
    pub version: Option<u32>,
    /// Nanoseconds since the epoch.
    #[prost(sint64, optional, tag = "10")]
    pub timestamp: Option<i64>,
    #[prost(bytes = "vec", optional, tag = "11")]
    pub meta: Option<Vec<u8>>,
    #[prost(bool, optional, tag = "31")]
    pub ephemeral: Option<bool>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct MessageKeyValue {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub message_hash: Option<Vec<u8>>,
    #[prost(message, optional, tag = "2")]
    pub message: Option<WakuMessage>,
    #[prost(string, optional, tag = "3")]
    pub pubsub_topic: Option<String>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct StoreQueryRequest {
    #[prost(string, tag = "1")]
    pub request_id: String,
    #[prost(bool, tag = "2")]
    pub include_data: bool,
    #[prost(string, optional, tag = "10")]
    pub pubsub_topic: Option<String>,
    #[prost(string, repeated, tag = "11")]
    pub content_topics: Vec<String>,
    #[prost(sint64, optional, tag = "12")]
    pub time_start: Option<i64>,
    #[prost(sint64, optional, tag = "13")]
    pub time_end: Option<i64>,
    #[prost(bytes = "vec", optional, tag = "51")]
    pub pagination_cursor: Option<Vec<u8>>,
    #[prost(bool, tag = "52")]
    pub pagination_forward: bool,
    #[prost(uint64, optional, tag = "53")]
    pub pagination_limit: Option<u64>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct StoreQueryResponse {
    #[prost(string, tag = "1")]
    pub request_id: String,
    #[prost(uint32, optional, tag = "10")]
    pub status_code: Option<u32>,
    #[prost(string, optional, tag = "11")]
    pub status_desc: Option<String>,
    #[prost(message, repeated, tag = "20")]
    pub messages: Vec<MessageKeyValue>,
    #[prost(bytes = "vec", optional, tag = "51")]
    pub pagination_cursor: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct LightPushRequest {
    #[prost(string, tag = "1")]
    pub request_id: String,
    #[prost(string, optional, tag = "20")]
    pub pubsub_topic: Option<String>,
    #[prost(message, optional, tag = "21")]
    pub message: Option<WakuMessage>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct LightPushResponse {
    #[prost(string, tag = "1")]
    pub request_id: String,
    #[prost(uint32, tag = "10")]
    pub status_code: u32,
    #[prost(string, optional, tag = "11")]
    pub status_desc: Option<String>,
    #[prost(uint32, optional, tag = "12")]
    pub relay_peer_count: Option<u32>,
}

/// Request and response share this shape. A node drops peers on another cluster, so the client answers with Railgun's.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Metadata {
    #[prost(uint32, optional, tag = "1")]
    pub cluster_id: Option<u32>,
    #[prost(uint32, repeated, packed = "false", tag = "2")]
    pub shards: Vec<u32>,
}
