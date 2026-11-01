//! Leaf hashes from Railgun's Subsquid indexer, which also covers the legacy
//! events `decode_log` does not read.

use serde_json::{json, Value};

use crate::Error;

const PAGE: usize = 10_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SquidLeaf {
    pub tree: u32,
    pub position: u32,
    pub hash: [u8; 32],
    pub block_number: u64,
}

fn leaf(v: &Value) -> Option<SquidLeaf> {
    let hash: alloy_primitives::U256 = v["hash"].as_str()?.parse().ok()?;
    Some(SquidLeaf {
        tree: v["treeNumber"].as_u64()? as u32,
        position: v["treePosition"].as_u64()? as u32,
        hash: hash.to_be_bytes(),
        block_number: v["blockNumber"].as_str()?.parse().ok()?,
    })
}

/// Every leaf at or before `to_block`, ordered by tree and position.
pub fn fetch_leaves(url: &str, to_block: u64) -> Result<Vec<SquidLeaf>, Error> {
    let http = reqwest::blocking::Client::new();
    let mut out = Vec::new();
    loop {
        let query = format!(
            "{{ commitments(limit: {PAGE}, offset: {}, \
             where: {{blockNumber_lte: \"{to_block}\"}}, \
             orderBy: [treeNumber_ASC, treePosition_ASC]) \
             {{ hash treeNumber treePosition blockNumber }} }}",
            out.len()
        );
        let resp: Value = http
            .post(url)
            .json(&json!({ "query": query }))
            .send()
            .and_then(|r| r.json())
            .map_err(|e| Error::Rpc(e.to_string()))?;
        let page = resp["data"]["commitments"]
            .as_array()
            .ok_or_else(|| Error::Rpc(format!("squid: {resp}")))?;
        let before = out.len();
        for v in page {
            out.push(leaf(v).ok_or_else(|| Error::Rpc(format!("squid leaf: {v}")))?);
        }
        if out.len() - before < PAGE {
            return Ok(out);
        }
    }
}
