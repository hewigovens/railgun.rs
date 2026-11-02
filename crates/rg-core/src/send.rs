use rand::RngCore;
use rg_keys::{EvmAddress, EvmKey, decode_address};
use rg_sync::rpc::Receipt;
use rg_tx::{Eip1559Tx, approve_calldata, shield_calldata};

use crate::{ChainStore, Client, Error, FeeQuote, UnsignedTx};

fn address(value: &str) -> Result<[u8; 20], Error> {
    value
        .parse::<EvmAddress>()
        .map(|a| a.0)
        .map_err(|e| Error::BadAddress(format!("{value}: {e}")))
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

    pub(crate) fn check_chain(&self, tx: &UnsignedTx) -> Result<(), Error> {
        if tx.chain_id != self.network.chain_id {
            return Err(Error::WrongChain(tx.chain_id, self.network.chain_id));
        }
        Ok(())
    }

    /// Signs with the quoted fees and sends, and returns the hash without waiting.
    pub fn send(&self, key: &EvmKey, tx: &UnsignedTx, fee: &FeeQuote) -> Result<[u8; 32], Error> {
        self.check_chain(tx)?;
        let signed = Eip1559Tx {
            chain_id: tx.chain_id,
            nonce: self.rpc.nonce(&key.address())?,
            max_priority_fee_per_gas: fee.max_priority_fee_per_gas,
            max_fee_per_gas: fee.max_fee_per_gas,
            gas_limit: fee.gas_limit,
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
