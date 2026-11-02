//! Aggregator JSON-RPC (wallet `poi-node-request.ts`).

use std::collections::BTreeMap;

use rg_primitives::{field, Fr};
use rg_tree::TREE_DEPTH;
use serde_json::{json, Value};

use crate::ListProof;

const TXID_VERSION: &str = "V2_PoseidonMerkle";

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("{method}: {detail}")]
    Rpc {
        method: &'static str,
        detail: String,
    },
}

pub struct Node {
    url: String,
    chain_id: u64,
    http: reqwest::blocking::Client,
}

fn hex32(x: &Fr) -> String {
    hex::encode(field::to_be_bytes(x))
}

/// Blinded commitments travel 0x-prefixed; `formatHash` in the engine.
pub fn blinded_hex(x: &Fr) -> String {
    format!("0x{}", hex32(x))
}

fn parse_fr(v: &Value) -> Option<Fr> {
    let s = v.as_str()?;
    let bytes = hex::decode(format!("{:0>64}", s.trim_start_matches("0x"))).ok()?;
    Some(field::from_be_bytes_mod_order(&bytes))
}

impl Node {
    pub fn new(url: impl Into<String>, chain_id: u64) -> Self {
        Node {
            url: url.into(),
            chain_id,
            http: reqwest::blocking::Client::new(),
        }
    }

    fn call(&self, method: &'static str, mut params: Value) -> Result<Value, NodeError> {
        params["chainType"] = json!("0");
        params["chainID"] = json!(self.chain_id.to_string());
        params["txidVersion"] = json!(TXID_VERSION);
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let resp: Value = self.http.post(&self.url).json(&body).send()?.json()?;
        if let Some(err) = resp.get("error") {
            return Err(NodeError::Rpc {
                method,
                detail: err.to_string(),
            });
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Status per list per blinded commitment. `kind` is "Transact" or "Shield".
    pub fn pois_per_list(
        &self,
        list_key: &str,
        blinded: &[(String, &str)],
    ) -> Result<BTreeMap<String, String>, NodeError> {
        let datas: Vec<Value> = blinded
            .iter()
            .map(|(b, kind)| json!({"blindedCommitment": b, "type": kind}))
            .collect();
        let v = self.call(
            "ppoi_pois_per_list",
            json!({"listKeys": [list_key], "blindedCommitmentDatas": datas}),
        )?;
        let mut out = BTreeMap::new();
        for (b, lists) in v.as_object().into_iter().flatten() {
            let status = lists[list_key].as_str().unwrap_or("?").to_string();
            out.insert(b.clone(), status);
        }
        Ok(out)
    }

    pub fn merkle_proofs(
        &self,
        list_key: &str,
        blinded: &[String],
    ) -> Result<Vec<ListProof>, NodeError> {
        let v = self.call(
            "ppoi_merkle_proofs",
            json!({"listKey": list_key, "blindedCommitments": blinded}),
        )?;
        let bad = |what: &str| NodeError::Rpc {
            method: "ppoi_merkle_proofs",
            detail: format!("{what}: {v}"),
        };
        let items = v.as_array().ok_or_else(|| bad("not an array"))?;
        items
            .iter()
            .map(|p| {
                let elements: Vec<Fr> = p["elements"]
                    .as_array()
                    .ok_or_else(|| bad("elements"))?
                    .iter()
                    .map(|e| parse_fr(e).ok_or_else(|| bad("element")))
                    .collect::<Result<_, _>>()?;
                let elements: [Fr; TREE_DEPTH] =
                    elements.try_into().map_err(|_| bad("path length"))?;
                Ok(ListProof {
                    root: parse_fr(&p["root"]).ok_or_else(|| bad("root"))?,
                    indices: parse_fr(&p["indices"]).ok_or_else(|| bad("indices"))?,
                    elements,
                })
            })
            .collect()
    }

    pub fn validate_txid_merkleroot(
        &self,
        tree: u32,
        index: u32,
        root: &Fr,
    ) -> Result<bool, NodeError> {
        let v = self.call(
            "ppoi_validate_txid_merkleroot",
            json!({"tree": tree, "index": index, "merkleroot": hex32(root)}),
        )?;
        Ok(v.as_bool().unwrap_or(false))
    }

    pub fn validated_txid(&self) -> Result<Value, NodeError> {
        self.call("ppoi_validated_txid", json!({}))
    }

    pub fn submit_transact_proof(
        &self,
        list_key: &str,
        transact_proof_data: Value,
    ) -> Result<(), NodeError> {
        self.call(
            "ppoi_submit_transact_proof",
            json!({"listKey": list_key, "transactProofData": transact_proof_data}),
        )?;
        Ok(())
    }
}
