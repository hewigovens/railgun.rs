//! A log as `eth_getLogs` returns it. Etherscan's logs API uses the same field
//! names (plus some extras, ignored here) but writes index 0 as `"0x"`.

use serde::Deserialize;

use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawLog {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
    pub block_number: u64,
    pub transaction_hash: [u8; 32],
    pub log_index: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonLog {
    address: String,
    topics: Vec<String>,
    data: String,
    block_number: String,
    transaction_hash: String,
    log_index: String,
}

fn strip(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

fn quantity(s: &str) -> Result<u64, Error> {
    let s = strip(s);
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 16).map_err(|e| Error::BadLog(format!("quantity {s}: {e}")))
}

fn bytes(s: &str) -> Result<Vec<u8>, Error> {
    hex::decode(strip(s)).map_err(|e| Error::BadLog(format!("hex: {e}")))
}

fn fixed<const N: usize>(s: &str) -> Result<[u8; N], Error> {
    bytes(s)?
        .try_into()
        .map_err(|_| Error::BadLog(format!("expected {N} bytes: {s}")))
}

impl RawLog {
    pub fn from_json(value: &serde_json::Value) -> Result<Self, Error> {
        let j: JsonLog =
            serde_json::from_value(value.clone()).map_err(|e| Error::BadLog(e.to_string()))?;
        Ok(RawLog {
            address: fixed(&j.address)?,
            topics: j
                .topics
                .iter()
                .map(|t| fixed(t))
                .collect::<Result<_, _>>()?,
            data: bytes(&j.data)?,
            block_number: quantity(&j.block_number)?,
            transaction_hash: fixed(&j.transaction_hash)?,
            log_index: quantity(&j.log_index)?,
        })
    }

    /// One JSON log per line.
    pub fn parse_jsonl(text: &str) -> Result<Vec<Self>, Error> {
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let v: serde_json::Value =
                    serde_json::from_str(l).map_err(|e| Error::BadLog(e.to_string()))?;
                Self::from_json(&v)
            })
            .collect()
    }
}
