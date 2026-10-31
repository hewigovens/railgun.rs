//! Minimal blocking JSON-RPC client: `eth_blockNumber`, `eth_getLogs` in
//! block chunks, and `rootHistory(tree, root)` via `eth_call`.

use alloy_primitives::{B256, U256};
use alloy_sol_types::SolCall;
use serde_json::{json, Value};

use crate::abi;
use crate::log::RawLog;
use crate::Error;

pub struct RpcClient {
    url: String,
    http: reqwest::blocking::Client,
}

impl RpcClient {
    pub fn new(url: impl Into<String>) -> Self {
        RpcClient {
            url: url.into(),
            http: reqwest::blocking::Client::new(),
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let resp: Value = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .and_then(|r| r.json())
            .map_err(|e| Error::Rpc(e.to_string()))?;
        if let Some(err) = resp.get("error") {
            return Err(Error::Rpc(err.to_string()));
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| Error::Rpc("missing result".into()))
    }

    pub fn block_number(&self) -> Result<u64, Error> {
        let v = self.call("eth_blockNumber", json!([]))?;
        let s = v
            .as_str()
            .ok_or_else(|| Error::Rpc("bad block number".into()))?;
        u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| Error::Rpc(e.to_string()))
    }

    /// Logs of `address` in `[from, to]`, fetched `chunk` blocks at a time,
    /// sorted by (block, log index).
    pub fn get_logs(
        &self,
        address: &str,
        from: u64,
        to: u64,
        chunk: u64,
    ) -> Result<Vec<RawLog>, Error> {
        let mut out = Vec::new();
        let mut start = from;
        while start <= to {
            let end = (start + chunk.max(1) - 1).min(to);
            let v = self.call(
                "eth_getLogs",
                json!([{"address": address, "fromBlock": format!("{start:#x}"), "toBlock": format!("{end:#x}")}]),
            )?;
            let logs = v
                .as_array()
                .ok_or_else(|| Error::Rpc("logs not an array".into()))?;
            for l in logs {
                out.push(RawLog::from_json(l)?);
            }
            start = end + 1;
        }
        out.sort_by_key(|l| (l.block_number, l.log_index));
        Ok(out)
    }

    /// The contract's `rootHistory(tree, root)` at `block` (or latest).
    pub fn root_history(
        &self,
        proxy: &str,
        tree: u32,
        root: [u8; 32],
        block: Option<u64>,
    ) -> Result<bool, Error> {
        let data = abi::rootHistoryCall {
            tree: U256::from(tree),
            root: B256::from(root),
        }
        .abi_encode();
        let tag = block.map_or_else(|| "latest".to_string(), |b| format!("{b:#x}"));
        let v = self.call(
            "eth_call",
            json!([{"to": proxy, "data": format!("0x{}", hex::encode(data))}, tag]),
        )?;
        let s = v
            .as_str()
            .ok_or_else(|| Error::Rpc("bad eth_call result".into()))?;
        let bytes =
            hex::decode(s.trim_start_matches("0x")).map_err(|e| Error::Rpc(e.to_string()))?;
        let ret = abi::rootHistoryCall::abi_decode_returns(&bytes)
            .map_err(|e| Error::Abi(e.to_string()))?;
        Ok(ret)
    }
}
