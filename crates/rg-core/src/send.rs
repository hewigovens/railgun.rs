use rand::RngCore;
use rg_keys::{EvmKey, decode_address};
use rg_sync::rpc::Receipt;
use rg_tx::{Eip1559Tx, approve_calldata, shield_calldata};

use crate::{ChainStore, Client, Error, UnsignedTx};

fn address(value: &str) -> Result<[u8; 20], Error> {
    hex::decode(value.trim_start_matches("0x"))
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error::BadAddress(value.to_string()))
}

/// Public tokens into the pool. `value` is what leaves the sender; the contract keeps its fee, so `receiver` gets slightly less.
pub struct Shield<'a> {
    /// 0zk address.
    pub receiver: &'a str,
    pub token: [u8; 20],
    pub value: u128,
}

impl<S: ChainStore> Client<S> {
    /// Needs the contract approved for `value` of the token first.
    pub fn build_shield(&self, shield: &Shield) -> Result<UnsignedTx, Error> {
        let receiver = decode_address(shield.receiver)?;
        let mut rng = rand::rngs::OsRng;
        let data = shield_calldata(&receiver, shield.token, shield.value, |b| rng.fill_bytes(b))?;
        Ok(UnsignedTx {
            chain_id: self.network.chain_id,
            to: self.network.proxy.to_string(),
            data,
        })
    }

    pub fn build_approve(&self, token: [u8; 20], value: u128) -> Result<UnsignedTx, Error> {
        Ok(UnsignedTx {
            chain_id: self.network.chain_id,
            to: format!("0x{}", hex::encode(token)),
            data: approve_calldata(address(self.network.proxy)?, value),
        })
    }

    /// What the Railgun contract may take of `owner`'s `token`.
    pub fn allowance(&self, owner: &[u8; 20], token: &[u8; 20]) -> Result<u128, Error> {
        let proxy = address(self.network.proxy)?;
        Ok(self.rpc.allowance(token, owner, &proxy)?)
    }

    pub fn token_balance(&self, token: &[u8; 20], owner: &[u8; 20]) -> Result<u128, Error> {
        Ok(self.rpc.token_balance(token, owner)?)
    }

    pub fn native_balance(&self, owner: &[u8; 20]) -> Result<u128, Error> {
        Ok(self.rpc.native_balance(owner)?)
    }

    /// Signs and sends, and returns the hash without waiting. The node's estimate moves with the L1 fee on rollups, so the limit gets a margin; unused gas is refunded.
    pub fn send(&self, key: &EvmKey, tx: &UnsignedTx) -> Result<[u8; 32], Error> {
        if tx.chain_id != self.network.chain_id {
            return Err(Error::WrongChain(tx.chain_id, self.network.chain_id));
        }
        let from = key.address();
        let estimate = self.estimate_gas(&format!("0x{}", hex::encode(from)), tx)?;
        let priority = self.rpc.priority_fee()?;
        let signed = Eip1559Tx {
            chain_id: tx.chain_id,
            nonce: self.rpc.nonce(&from)?,
            max_priority_fee_per_gas: priority,
            max_fee_per_gas: self.rpc.base_fee()? * 2 + priority,
            gas_limit: estimate + estimate / 5,
            to: address(&tx.to)?,
            data: tx.data.clone(),
        }
        .sign(key)?;
        self.rpc.send_raw_transaction(&signed.raw)?;
        Ok(signed.hash)
    }

    pub fn receipt(&self, hash: &[u8; 32]) -> Result<Option<Receipt>, Error> {
        Ok(self.rpc.receipt(hash)?)
    }
}
