//! JSON over HTTP with a size cap, so a hostile node or indexer cannot exhaust memory, and errors without the URL, which can carry an API key.

use std::io::Read;

use serde_json::Value;

use crate::Error;

/// Far above any honest answer: a 10,000-transaction squid page or a chunk of logs is a few MB.
const MAX_RESPONSE: u64 = 256 << 20;

/// Posts `body` and reads a JSON answer of at most [`MAX_RESPONSE`] bytes.
pub(crate) fn post_json(
    http: &reqwest::blocking::Client,
    url: &str,
    body: &Value,
) -> Result<Value, Error> {
    let rpc = |e: reqwest::Error| Error::Rpc(e.without_url().to_string());
    let response = http.post(url).json(body).send().map_err(rpc)?;
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::Rpc(e.to_string()))?;
    if bytes.len() as u64 > MAX_RESPONSE {
        return Err(Error::Rpc("response too large".into()));
    }
    serde_json::from_slice(&bytes).map_err(|e| Error::Rpc(e.to_string()))
}
