//! Minimal blocking JSON-RPC client: chain reads, `eth_getLogs` in block chunks, contract views through `eth_call`, and sending a signed transaction.

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolCall;
use serde_json::{Value, json};

use crate::Error;
use crate::abi;
use crate::log::RawLog;

/// What became of a mined transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub success: bool,
    pub block_number: u64,
    pub gas_used: u64,
}

fn quantity(value: &Value, what: &str) -> Result<u128, Error> {
    value
        .as_str()
        .and_then(|s| u128::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .ok_or_else(|| Error::Rpc(format!("bad {what}: {value}")))
}

fn address_hex(address: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(address))
}

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
            return Err(Error::Refused(err.to_string()));
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| Error::Rpc("missing result".into()))
    }

    /// Runs a call against the node, as the sender would. A transaction the contract would reject comes back as an error, at no cost.
    pub fn estimate_gas(
        &self,
        from: &str,
        to: &str,
        value: u128,
        data: &str,
    ) -> Result<u64, Error> {
        let value = format!("0x{value:x}");
        let v = self.call(
            "eth_estimateGas",
            json!([{"from": from, "to": to, "value": value, "data": data}]),
        )?;
        Ok(quantity(&v, "gas estimate")? as u64)
    }

    pub fn block_number(&self) -> Result<u64, Error> {
        let v = self.call("eth_blockNumber", json!([]))?;
        Ok(quantity(&v, "block number")? as u64)
    }

    /// Logs of `address` in `[from, to]`, fetched `chunk` blocks at a time, sorted by (block, log index).
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
        let bytes = self.view(proxy, &data, &tag)?;
        let ret = abi::rootHistoryCall::abi_decode_returns(&bytes)
            .map_err(|e| Error::Abi(e.to_string()))?;
        Ok(ret)
    }

    fn view(&self, to: &str, data: &[u8], tag: &str) -> Result<Vec<u8>, Error> {
        let v = self.call(
            "eth_call",
            json!([{"to": to, "data": format!("0x{}", hex::encode(data))}, tag]),
        )?;
        let s = v
            .as_str()
            .ok_or_else(|| Error::Rpc("bad eth_call result".into()))?;
        hex::decode(s.trim_start_matches("0x")).map_err(|e| Error::Rpc(e.to_string()))
    }

    fn view_amount(&self, token: &[u8; 20], data: &[u8]) -> Result<u128, Error> {
        let bytes = self.view(&address_hex(token), data, "latest")?;
        let value =
            U256::try_from_be_slice(&bytes).ok_or_else(|| Error::Rpc("bad token amount".into()))?;
        Ok(value.saturating_to())
    }

    /// `token.allowance(owner, spender)`, capped at `u128::MAX`, which is what an unlimited approval reads as.
    pub fn allowance(
        &self,
        token: &[u8; 20],
        owner: &[u8; 20],
        spender: &[u8; 20],
    ) -> Result<u128, Error> {
        let data = abi::allowanceCall {
            owner: Address::from(*owner),
            spender: Address::from(*spender),
        }
        .abi_encode();
        self.view_amount(token, &data)
    }

    /// `token.balanceOf(owner)`, capped at `u128::MAX`.
    pub fn token_balance(&self, token: &[u8; 20], owner: &[u8; 20]) -> Result<u128, Error> {
        let data = abi::balanceOfCall {
            owner: Address::from(*owner),
        }
        .abi_encode();
        self.view_amount(token, &data)
    }

    pub fn native_balance(&self, owner: &[u8; 20]) -> Result<u128, Error> {
        let v = self.call("eth_getBalance", json!([address_hex(owner), "latest"]))?;
        quantity(&v, "balance")
    }

    /// The next nonce, counting transactions still in the mempool.
    pub fn nonce(&self, owner: &[u8; 20]) -> Result<u64, Error> {
        let v = self.call(
            "eth_getTransactionCount",
            json!([address_hex(owner), "pending"]),
        )?;
        Ok(quantity(&v, "nonce")? as u64)
    }

    pub fn base_fee(&self) -> Result<u128, Error> {
        let v = self.call("eth_getBlockByNumber", json!(["latest", false]))?;
        quantity(&v["baseFeePerGas"], "base fee")
    }

    pub fn priority_fee(&self) -> Result<u128, Error> {
        let v = self.call("eth_maxPriorityFeePerGas", json!([]))?;
        quantity(&v, "priority fee")
    }

    pub fn send_raw_transaction(&self, raw: &[u8]) -> Result<(), Error> {
        let raw = format!("0x{}", hex::encode(raw));
        self.call("eth_sendRawTransaction", json!([raw]))?;
        Ok(())
    }

    /// None until the transaction is mined.
    pub fn receipt(&self, hash: &[u8; 32]) -> Result<Option<Receipt>, Error> {
        let hash = format!("0x{}", hex::encode(hash));
        let v = self.call("eth_getTransactionReceipt", json!([hash]))?;
        if v.is_null() {
            return Ok(None);
        }
        Ok(Some(Receipt {
            success: quantity(&v["status"], "status")? == 1,
            block_number: quantity(&v["blockNumber"], "block number")? as u64,
            gas_used: quantity(&v["gasUsed"], "gas used")? as u64,
        }))
    }
}
