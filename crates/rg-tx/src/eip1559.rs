use alloy_primitives::keccak256;
use alloy_rlp::{Encodable, Header};
use rg_keys::{EvmKey, EvmSignature};

use crate::Error;

const TX_TYPE: u8 = 2;

/// An EIP-1559 call that moves no native value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eip1559Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTx {
    pub raw: Vec<u8>,
    pub hash: [u8; 32],
}

fn minimal(bytes: &[u8; 32]) -> &[u8] {
    let zeros = bytes.iter().take_while(|b| **b == 0).count();
    &bytes[zeros..]
}

impl Eip1559Tx {
    fn fields(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.data.len() + 128);
        self.chain_id.encode(&mut out);
        self.nonce.encode(&mut out);
        self.max_priority_fee_per_gas.encode(&mut out);
        self.max_fee_per_gas.encode(&mut out);
        self.gas_limit.encode(&mut out);
        self.to.encode(&mut out);
        0u8.encode(&mut out);
        self.data.as_slice().encode(&mut out);
        Header {
            list: true,
            payload_length: 0,
        }
        .encode(&mut out);
        out
    }

    fn envelope(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(payload.len() + 8);
        out.push(TX_TYPE);
        Header {
            list: true,
            payload_length: payload.len(),
        }
        .encode(&mut out);
        out.extend_from_slice(payload);
        out
    }

    pub fn signing_hash(&self) -> [u8; 32] {
        keccak256(Self::envelope(&self.fields())).0
    }

    fn with_signature(&self, signature: &EvmSignature) -> SignedTx {
        let mut payload = self.fields();
        signature.y_parity.encode(&mut payload);
        minimal(&signature.r).encode(&mut payload);
        minimal(&signature.s).encode(&mut payload);
        let raw = Self::envelope(&payload);
        let hash = keccak256(&raw).0;
        SignedTx { raw, hash }
    }

    pub fn sign(&self, key: &EvmKey) -> Result<SignedTx, Error> {
        Ok(self.with_signature(&key.sign_hash(&self.signing_hash())?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAILGUN: [u8; 20] = alloy_primitives::hex!("FA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9");
    const WETH: [u8; 20] = alloy_primitives::hex!("82aF49447D8a07e3bd95BD0d56f35241523fBab1");

    /// `ethers` 6.14 `Wallet.signTransaction` on the same transactions, from `0x1111...11`.
    #[test]
    fn signs_the_same_bytes_as_ethers() {
        let key = EvmKey::from_bytes(&[0x11; 32]).unwrap();
        let approve = crate::approve_calldata(RAILGUN, 100);
        let cases: [(Eip1559Tx, &str); 3] = [
            (
                Eip1559Tx {
                    chain_id: 42_161,
                    nonce: 0,
                    max_priority_fee_per_gas: 0,
                    max_fee_per_gas: 20_000_000,
                    gas_limit: 1_200_000,
                    to: RAILGUN,
                    data: vec![],
                },
                "34ed64a70586d3bc8ea3d6b41de7f2aca70c55974c6c4bc4511ac4ae5e8894e8",
            ),
            (
                Eip1559Tx {
                    chain_id: 42_161,
                    nonce: 7,
                    max_priority_fee_per_gas: 1_000_000,
                    max_fee_per_gas: 40_000_000,
                    gas_limit: 61_234,
                    to: WETH,
                    data: approve,
                },
                "e9c1115ab852a5ae4fd5831152de8cab0197614887758b86da18bdf273c2a97e",
            ),
            (
                Eip1559Tx {
                    chain_id: 1,
                    nonce: 300,
                    max_priority_fee_per_gas: 2_000_000_000,
                    max_fee_per_gas: 90_000_000_000,
                    gas_limit: 1_000_000,
                    to: RAILGUN,
                    data: vec![0xab; 300],
                },
                "126a96b7111bdf6d9ecb653be0fcd9fd6eaaa0405b0d300e5089da602134553d",
            ),
        ];
        for (tx, hash) in cases {
            assert_eq!(hex::encode(tx.sign(&key).unwrap().hash), hash);
        }
    }

    #[test]
    fn drops_leading_zeros_from_signature_values() {
        let tx = Eip1559Tx {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 1,
            gas_limit: 21_000,
            to: RAILGUN,
            data: vec![],
        };
        let mut r = [0u8; 32];
        r[31] = 1;
        let signed = tx.with_signature(&EvmSignature {
            r,
            s: r,
            y_parity: false,
        });
        assert!(signed.raw.ends_with(&[0x80, 0x01, 0x01]));
    }
}
