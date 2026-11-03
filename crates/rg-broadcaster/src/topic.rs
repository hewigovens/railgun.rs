//! Waku content topics (`waku-topics.ts`). The chain type is 0, EVM, for every network here.

pub fn fees_topic(chain_id: u64) -> String {
    format!("/railgun/v2/0-{chain_id}-fees/json")
}

pub fn transact_topic(chain_id: u64) -> String {
    format!("/railgun/v2/0-{chain_id}-transact/json")
}

pub fn transact_response_topic(chain_id: u64) -> String {
    format!("/railgun/v2/0-{chain_id}-transact-response/json")
}
