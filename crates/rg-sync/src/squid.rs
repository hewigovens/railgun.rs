//! Leaf hashes from Railgun's Subsquid indexer, which also covers the legacy events `decode_log` does not read.

use serde_json::{Value, json};

use crate::Error;
use crate::http::post_json;

const PAGE: usize = 10_000;

/// A million leaves or transactions, several times what any chain has.
const MAX_PAGES: usize = 100;

/// A Railgun transaction as the squid records it, legacy ones included. Their order by id is the order of the txid tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SquidTransaction {
    pub id: String,
    pub block_number: u64,
    pub transaction_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    /// With an unshield, its commitment comes last and takes no tree position.
    pub commitments: Vec<[u8; 32]>,
    pub has_unshield: bool,
    pub bound_params_hash: [u8; 32],
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

/// Ids are 0x-hex; anything else could break the next query, which quotes the last one, or the store's lines.
fn id(v: &Value) -> Option<String> {
    let id = v.as_str()?;
    let digits = id.strip_prefix("0x")?;
    (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_hexdigit())).then(|| id.to_string())
}

fn transaction(v: &Value) -> Option<SquidTransaction> {
    Some(SquidTransaction {
        id: id(&v["id"])?,
        block_number: number(&v["blockNumber"])?,
        transaction_hash: word(&v["transactionHash"])?,
        nullifiers: words(&v["nullifiers"])?,
        commitments: words(&v["commitments"])?,
        has_unshield: v["hasUnshield"].as_bool()?,
        bound_params_hash: word(&v["boundParamsHash"])?,
        utxo_tree_in: number(&v["utxoTreeIn"])?.try_into().ok()?,
        utxo_tree_out: number(&v["utxoTreeOut"])?.try_into().ok()?,
        utxo_batch_start_position_out: number(&v["utxoBatchStartPositionOut"])?.try_into().ok()?,
    })
}

fn query(http: &reqwest::blocking::Client, url: &str, query: String) -> Result<Value, Error> {
    post_json(http, url, &json!({ "query": query }))
}

const TRANSACTION_FIELDS: &str = "id blockNumber transactionHash nullifiers commitments \
     hasUnshield boundParamsHash utxoTreeIn utxoTreeOut utxoBatchStartPositionOut";

/// Reads pages until a short one; `page` gets what was read so far. A squid that repeats a page or never stops would fill memory, so a page that does not move on from the last, or more pages than any chain has, is refused.
fn read_pages<T>(
    mut page: impl FnMut(&[T]) -> Result<Vec<T>, Error>,
    moved_on: impl Fn(&T, &T) -> bool,
) -> Result<Vec<T>, Error> {
    let mut out: Vec<T> = Vec::new();
    for _ in 0..MAX_PAGES {
        let next = page(&out)?;
        if let (Some(last), Some(first)) = (out.last(), next.first())
            && !moved_on(last, first)
        {
            return Err(Error::Rpc("squid: a page repeats".into()));
        }
        let full = next.len() >= PAGE;
        out.extend(next);
        if !full {
            return Ok(out);
        }
    }
    Err(Error::Rpc("squid: more pages than any chain has".into()))
}

/// Railgun transactions after the id `after`, and matching `filter`, in txid tree order.
fn fetch_transactions(
    url: &str,
    after: &str,
    filter: &str,
) -> Result<Vec<SquidTransaction>, Error> {
    let http = reqwest::blocking::Client::new();
    read_pages(
        |read: &[SquidTransaction]| {
            let last_id = read.last().map_or(after, |t| &t.id);
            let q = format!(
                "{{ transactions(orderBy: id_ASC, limit: {PAGE}, where: {{id_gt: \"{last_id}\"{filter}}}) \
                 {{ {TRANSACTION_FIELDS} }} }}"
            );
            let resp = query(&http, url, q)?;
            let page = resp["data"]["transactions"]
                .as_array()
                .ok_or_else(|| Error::Rpc(format!("squid: {resp}")))?;
            page.iter()
                .map(|v| transaction(v).ok_or_else(|| Error::Rpc(format!("squid tx: {v}"))))
                .collect()
        },
        |last, first| first.id != last.id,
    )
}

/// Railgun transactions after the id `after`, in txid tree order. An empty id reads from the start.
pub fn fetch_transactions_after(url: &str, after: &str) -> Result<Vec<SquidTransaction>, Error> {
    fetch_transactions(url, after, "")
}

/// Railgun transactions in blocks `from..=to`, in txid tree order. Asking for a range rather than one hash keeps the squid from learning which transaction is the caller's.
pub fn fetch_transactions_in_blocks(
    url: &str,
    from: u64,
    to: u64,
) -> Result<Vec<SquidTransaction>, Error> {
    fetch_transactions(
        url,
        "",
        &format!(", blockNumber_gte: \"{from}\", blockNumber_lte: \"{to}\""),
    )
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
        tree: v["treeNumber"].as_u64()?.try_into().ok()?,
        position: v["treePosition"].as_u64()?.try_into().ok()?,
        hash: word(&v["hash"])?,
        block_number: number(&v["blockNumber"])?,
    })
}

/// Every leaf at or before `to_block`, ordered by tree and position.
pub fn fetch_leaves(url: &str, to_block: u64) -> Result<Vec<SquidLeaf>, Error> {
    let http = reqwest::blocking::Client::new();
    read_pages(
        |read: &[SquidLeaf]| {
            let q = format!(
                "{{ commitments(limit: {PAGE}, offset: {}, \
                 where: {{blockNumber_lte: \"{to_block}\"}}, \
                 orderBy: [treeNumber_ASC, treePosition_ASC]) \
                 {{ hash treeNumber treePosition blockNumber }} }}",
                read.len()
            );
            let resp = query(&http, url, q)?;
            let page = resp["data"]["commitments"]
                .as_array()
                .ok_or_else(|| Error::Rpc(format!("squid: {resp}")))?;
            page.iter()
                .map(|v| leaf(v).ok_or_else(|| Error::Rpc(format!("squid leaf: {v}"))))
                .collect()
        },
        |last, first| (first.tree, first.position) > (last.tree, last.position),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_squid_that_repeats_or_never_ends_is_refused() {
        let full = |from: usize| (from..from + PAGE).collect::<Vec<_>>();
        let repeat = read_pages(|_| Ok(full(0)), |last, first| first > last);
        assert!(matches!(repeat, Err(Error::Rpc(_))));
        let endless = read_pages(|read| Ok(full(read.len())), |last, first| first > last);
        assert!(matches!(endless, Err(Error::Rpc(_))));

        let pages = read_pages(
            |read| Ok(if read.is_empty() { full(0) } else { vec![PAGE] }),
            |last, first| first > last,
        );
        assert_eq!(pages.unwrap().len(), PAGE + 1);
    }
}
