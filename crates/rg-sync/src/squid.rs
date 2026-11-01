//! Leaf hashes from Railgun's Subsquid indexer, which also covers the legacy
//! events `decode_log` does not read.

use serde_json::{json, Value};

use crate::Error;

const PAGE: usize = 10_000;

/// A Railgun transaction as the squid records it, legacy ones included. Their
/// order by id is the order of the txid tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SquidTransaction {
    pub transaction_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub commitments: Vec<[u8; 32]>,
    pub bound_params_hash: [u8; 32],
    pub block_number: u64,
    pub utxo_tree_in: u32,
    pub utxo_tree_out: u32,
    pub utxo_batch_start_position_out: u32,
}

fn word(v: &Value) -> Option<[u8; 32]> {
    let n: alloy_primitives::U256 = v.as_str()?.parse().ok()?;
    Some(n.to_be_bytes())
}

fn words(v: &Value) -> Option<Vec<[u8; 32]>> {
    v.as_array()?.iter().map(word).collect()
}

fn number(v: &Value) -> Option<u64> {
    v.as_str()?.parse().ok()
}

fn transaction(v: &Value) -> Option<SquidTransaction> {
    Some(SquidTransaction {
        transaction_hash: word(&v["transactionHash"])?,
        nullifiers: words(&v["nullifiers"])?,
        commitments: words(&v["commitments"])?,
        bound_params_hash: word(&v["boundParamsHash"])?,
        block_number: number(&v["blockNumber"])?,
        utxo_tree_in: number(&v["utxoTreeIn"])? as u32,
        utxo_tree_out: number(&v["utxoTreeOut"])? as u32,
        utxo_batch_start_position_out: number(&v["utxoBatchStartPositionOut"])? as u32,
    })
}

fn query(http: &reqwest::blocking::Client, url: &str, query: String) -> Result<Value, Error> {
    http.post(url)
        .json(&json!({ "query": query }))
        .send()
        .and_then(|r| r.json())
        .map_err(|e| Error::Rpc(e.to_string()))
}

/// Every Railgun transaction, in txid tree order.
pub fn fetch_transactions(url: &str) -> Result<Vec<SquidTransaction>, Error> {
    let http = reqwest::blocking::Client::new();
    let mut out = Vec::new();
    let mut last_id = String::new();
    loop {
        let q = format!(
            "{{ transactions(orderBy: id_ASC, limit: {PAGE}, where: {{id_gt: \"{last_id}\"}}) \
             {{ id transactionHash nullifiers commitments boundParamsHash blockNumber \
             utxoTreeIn utxoTreeOut utxoBatchStartPositionOut }} }}"
        );
        let resp = query(&http, url, q)?;
        let page = resp["data"]["transactions"]
            .as_array()
            .ok_or_else(|| Error::Rpc(format!("squid: {resp}")))?;
        for v in page {
            out.push(transaction(v).ok_or_else(|| Error::Rpc(format!("squid tx: {v}")))?);
        }
        match page.last().and_then(|v| v["id"].as_str()) {
            Some(id) if page.len() == PAGE => last_id = id.to_string(),
            _ => return Ok(out),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SquidLeaf {
    pub tree: u32,
    pub position: u32,
    pub hash: [u8; 32],
    pub block_number: u64,
}

fn leaf(v: &Value) -> Option<SquidLeaf> {
    Some(SquidLeaf {
        tree: v["treeNumber"].as_u64()? as u32,
        position: v["treePosition"].as_u64()? as u32,
        hash: word(&v["hash"])?,
        block_number: number(&v["blockNumber"])?,
    })
}

/// Every leaf at or before `to_block`, ordered by tree and position.
pub fn fetch_leaves(url: &str, to_block: u64) -> Result<Vec<SquidLeaf>, Error> {
    let http = reqwest::blocking::Client::new();
    let mut out = Vec::new();
    loop {
        let q = format!(
            "{{ commitments(limit: {PAGE}, offset: {}, \
             where: {{blockNumber_lte: \"{to_block}\"}}, \
             orderBy: [treeNumber_ASC, treePosition_ASC]) \
             {{ hash treeNumber treePosition blockNumber }} }}",
            out.len()
        );
        let resp = query(&http, url, q)?;
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
