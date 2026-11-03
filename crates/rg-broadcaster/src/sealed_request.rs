use rg_primitives::aes::{decrypt_gcm, encrypt_gcm};
use rg_primitives::ed25519::{public_key, x25519_shared_secret};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::Error;

/// `BroadcasterConfig.MINIMUM_BROADCASTER_VERSION` and `MAXIMUM_BROADCASTER_VERSION`, sent so an incompatible broadcaster declines.
const MIN_VERSION: &str = "8.0.0";
const MAX_VERSION: &str = "8.999.0";

/// What a broadcaster needs to submit a proved batch (`BroadcasterRawParamsTransact`, common type).
pub struct TransactRequest<'a> {
    pub chain_id: u64,
    /// The contract to call, EIP-55 checksummed.
    pub to: &'a str,
    pub data: &'a [u8],
    pub broadcaster_viewing_key: [u8; 32],
    pub fees_id: &'a str,
    /// The legacy gas price the broadcaster sends at, which the fee must cover. Batches on L1 also commit to it in their bound params.
    pub min_gas_price: u128,
    pub use_relay_adapt: bool,
    /// List key to txid leaf hash to proof, so the broadcaster can check spendability before it pays gas.
    pub pre_transaction_pois: &'a Value,
}

/// A request encrypted to one broadcaster, and the key its answer comes back under.
pub struct SealedRequest {
    /// The Waku message for the transact topic.
    pub payload: Vec<u8>,
    shared_key: Zeroizing<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactResponse {
    Submitted([u8; 32]),
    Refused(String),
}

/// `encryptJSONDataWithSharedKey`: `[iv ‖ tag, data]` as 0x-hex, AES-256-GCM with a 16-byte IV.
fn encrypt_json(value: &Value, key: &[u8; 32], iv: &[u8; 16]) -> Value {
    let plaintext = Zeroizing::new(value.to_string().into_bytes());
    let (data, tag) = encrypt_gcm(key, iv, &plaintext);
    json!([
        format!("0x{}{}", hex::encode(iv), hex::encode(tag)),
        format!("0x{}", hex::encode(data))
    ])
}

/// `tryDecryptJSONDataWithSharedKey`; None when it is not for this key.
fn decrypt_json(value: &Value, key: &[u8; 32]) -> Option<Value> {
    let part = |i: usize| hex::decode(value.get(i)?.as_str()?.trim_start_matches("0x")).ok();
    let (iv_tag, data) = (part(0)?, part(1)?);
    let iv: [u8; 16] = iv_tag.get(..16)?.try_into().ok()?;
    let tag: [u8; 16] = iv_tag.get(16..)?.try_into().ok()?;
    let plaintext = Zeroizing::new(decrypt_gcm(key, &iv, &tag, &data).ok()?);
    serde_json::from_slice(&plaintext).ok()
}

impl TransactRequest<'_> {
    fn body(&self) -> Value {
        json!({
            "txidVersion": "V2_PoseidonMerkle",
            "to": self.to,
            "data": format!("0x{}", hex::encode(self.data)),
            "broadcasterViewingKey": hex::encode(self.broadcaster_viewing_key),
            "chainID": self.chain_id,
            "chainType": 0,
            "feesID": self.fees_id,
            "useRelayAdapt": self.use_relay_adapt,
            "devLog": false,
            "minVersion": MIN_VERSION,
            "maxVersion": MAX_VERSION,
            "preTransactionPOIsPerTxidLeafPerList": self.pre_transaction_pois,
            "transactType": "COMMON",
            "minGasPrice": self.min_gas_price.to_string(),
        })
    }

    /// Encrypts to the broadcaster under a one-time key (`encryptDataWithSharedKey`). `fill` supplies the one-time private key, then the IV.
    pub fn seal(&self, mut fill: impl FnMut(&mut [u8])) -> Result<SealedRequest, Error> {
        let mut one_time = Zeroizing::new([0u8; 32]);
        fill(&mut *one_time);
        let mut iv = [0u8; 16];
        fill(&mut iv);
        let shared_key = Zeroizing::new(
            x25519_shared_secret(&one_time, &self.broadcaster_viewing_key)
                .ok_or(Error::BadViewingKey)?,
        );
        let message = json!({
            "method": "transact",
            "params": {
                "pubkey": hex::encode(public_key(&one_time)),
                "encryptedData": encrypt_json(&self.body(), &shared_key, &iv),
            },
        });
        Ok(SealedRequest {
            payload: message.to_string().into_bytes(),
            shared_key,
        })
    }
}

impl SealedRequest {
    /// Reads a message from the transact-response topic; None when it answers someone else.
    pub fn open_response(&self, payload: &[u8]) -> Option<TransactResponse> {
        let message: Value = serde_json::from_slice(payload).ok()?;
        let answer = decrypt_json(message.get("result")?, &self.shared_key)?;
        if let Some(hash) = answer.get("txHash").and_then(Value::as_str) {
            let hash = hex::decode(hash.trim_start_matches("0x")).ok()?;
            return Some(TransactResponse::Submitted(hash.try_into().ok()?));
        }
        let error = answer.get("error")?;
        Some(TransactResponse::Refused(
            error
                .as_str()
                .map_or_else(|| error.to_string(), str::to_string),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Engine 9.6.0 with noble-ed25519 1.7.5: `getSharedSecret([1; 32], getPublicKey([2; 32]))` and `encryptJSONDataWithSharedKey` under it, of `{n: 1, s, txHash}` with its keys in the order serde_json writes them.
    const SHARED: &str = "4181d7302557342bdb6d061c4b1eebea828ecb625c3368b7111680793307220b";
    const ENCRYPTED: [&str; 2] = [
        "0x4785ab27463d4579147387179ad4753960f89af95113a78b77df9906d92af4b8",
        "0x59013f4ba701589b652214a2a8172b755273a696577804636ef893e096a2af2f067770d6bafcccbd8cd08699267f0d7c9c2bf48f45b501ba7607c1f6e4e6afe8c68154cd1dad10",
    ];

    fn broadcaster() -> [u8; 32] {
        public_key(&[2; 32])
    }

    #[test]
    fn shared_key_and_encryption_match_the_engine() {
        let shared = x25519_shared_secret(&[1; 32], &broadcaster()).unwrap();
        assert_eq!(hex::encode(shared), SHARED);
        let decrypted = decrypt_json(&json!(ENCRYPTED), &shared).unwrap();
        assert_eq!(decrypted["txHash"], "0xabc");
        let iv: [u8; 16] = hex::decode(&ENCRYPTED[0][2..34])
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(encrypt_json(&decrypted, &shared, &iv), json!(ENCRYPTED));
    }

    #[test]
    fn reads_only_the_answer_to_its_own_request() {
        let pois = json!({});
        let request = TransactRequest {
            chain_id: 42_161,
            to: "0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9",
            data: &[0xab],
            broadcaster_viewing_key: broadcaster(),
            fees_id: "id",
            min_gas_price: 0,
            use_relay_adapt: false,
            pre_transaction_pois: &pois,
        };
        let sealed = request.seal(|b| b.fill(1)).unwrap();
        let message: Value = serde_json::from_slice(&sealed.payload).unwrap();
        // The broadcaster's side: its viewing key and the one-time public key give the same key.
        let pubkey: [u8; 32] = hex::decode(message["params"]["pubkey"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let theirs = x25519_shared_secret(&[2; 32], &pubkey).unwrap();
        assert_eq!(theirs, *sealed.shared_key);
        let body = decrypt_json(&message["params"]["encryptedData"], &theirs).unwrap();
        assert_eq!(body["data"], "0xab");

        let hash = format!("0x{}", "11".repeat(32));
        let answer = |key: &[u8; 32]| {
            let result = encrypt_json(&json!({ "txHash": hash }), key, &[7; 16]);
            json!({ "result": result }).to_string().into_bytes()
        };
        assert_eq!(
            sealed.open_response(&answer(&theirs)),
            Some(TransactResponse::Submitted([0x11; 32]))
        );
        assert_eq!(sealed.open_response(&answer(&[9; 32])), None);
    }
}
