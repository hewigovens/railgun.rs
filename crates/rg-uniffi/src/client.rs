use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rg_core::{Artifacts, Client, FileStore, Receipt, Shield, Transfer, Unshield, UnsignedTx};
use rg_sync::Network;

use crate::{EvmAccount, PoiSubmission, RailgunError, SyncReport, TokenBalance, Wallet};

fn hex_bytes<const N: usize>(value: &str) -> Result<[u8; N], RailgunError> {
    hex::decode(value.trim_start_matches("0x"))
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| RailgunError::invalid(format!("expected {N} hex bytes: {value}")))
}

fn amount(value: &str) -> Result<u128, RailgunError> {
    value
        .parse()
        .map_err(|_| RailgunError::invalid(format!("not an amount: {value}")))
}

/// One network's chain data. Every method blocks on disk or the network, and calls run one at a time, so call them off the UI thread.
#[derive(uniffi::Object)]
pub struct RailgunClient {
    client: Mutex<Client>,
    artifacts: Artifacts,
}

impl RailgunClient {
    fn client(&self) -> MutexGuard<'_, Client> {
        self.client.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[uniffi::export]
impl RailgunClient {
    /// `network` is `arbitrum`, `ethereum` or `sepolia`. `data_dir` holds chain data and circuit artifacts.
    #[uniffi::constructor]
    pub fn open(
        network: String,
        rpc_url: String,
        data_dir: String,
    ) -> Result<Arc<Self>, RailgunError> {
        let network = Network::by_name(&network)
            .ok_or_else(|| RailgunError::invalid(format!("unknown network: {network}")))?;
        let data_dir = PathBuf::from(data_dir);
        let store = FileStore::open(data_dir.join(network.name)).map_err(RailgunError::from)?;
        Ok(Arc::new(RailgunClient {
            client: Mutex::new(Client::open(network, &rpc_url, store)?),
            artifacts: Artifacts::new(data_dir.join("artifacts")),
        }))
    }

    pub fn sync(&self) -> Result<SyncReport, RailgunError> {
        Ok(self.client().sync()?)
    }

    /// Unspent ERC20 balances as of the last sync. Token addresses are lowercase hex.
    pub fn balances(&self, wallet: &Wallet) -> Vec<TokenBalance> {
        self.client()
            .scan(&wallet.keys)
            .balances()
            .into_iter()
            .map(|(token, value)| TokenBalance {
                token: format!("0x{}", hex::encode(&token[12..])),
                value: value.to_string(),
            })
            .collect()
    }

    pub fn build_transfer(
        &self,
        wallet: &Wallet,
        recipient: String,
        token: String,
        value: String,
        memo: Option<String>,
    ) -> Result<UnsignedTx, RailgunError> {
        let transfer = Transfer {
            recipient: &recipient,
            token: hex_bytes(&token)?,
            value: amount(&value)?,
            memo: memo.as_deref(),
        };
        Ok(self
            .client()
            .build_transfer(&wallet.keys, &transfer, &self.artifacts)?)
    }

    pub fn build_unshield(
        &self,
        wallet: &Wallet,
        to: String,
        token: String,
        value: String,
    ) -> Result<UnsignedTx, RailgunError> {
        let unshield = Unshield {
            to: hex_bytes(&to)?,
            token: hex_bytes(&token)?,
            value: amount(&value)?,
        };
        Ok(self
            .client()
            .build_unshield(&wallet.keys, &unshield, &self.artifacts)?)
    }

    /// The contract keeps its fee, so `receiver` gets slightly less than `value`. `value` needs an allowance first: see `build_approve`.
    pub fn build_shield(
        &self,
        receiver: String,
        token: String,
        value: String,
    ) -> Result<UnsignedTx, RailgunError> {
        let shield = Shield {
            receiver: &receiver,
            token: hex_bytes(&token)?,
            value: amount(&value)?,
        };
        Ok(self.client().build_shield(&shield)?)
    }

    /// Lets the Railgun contract take `value` of `token`.
    pub fn build_approve(&self, token: String, value: String) -> Result<UnsignedTx, RailgunError> {
        Ok(self
            .client()
            .build_approve(hex_bytes(&token)?, amount(&value)?)?)
    }

    /// What the Railgun contract may take of `owner`'s `token`.
    pub fn allowance(&self, owner: String, token: String) -> Result<String, RailgunError> {
        let allowance = self
            .client()
            .allowance(&hex_bytes(&owner)?, &hex_bytes(&token)?)?;
        Ok(allowance.to_string())
    }

    pub fn token_balance(&self, owner: String, token: String) -> Result<String, RailgunError> {
        let balance = self
            .client()
            .token_balance(&hex_bytes(&token)?, &hex_bytes(&owner)?)?;
        Ok(balance.to_string())
    }

    pub fn native_balance(&self, owner: String) -> Result<String, RailgunError> {
        Ok(self
            .client()
            .native_balance(&hex_bytes(&owner)?)?
            .to_string())
    }

    pub fn estimate_gas(&self, from: String, tx: UnsignedTx) -> Result<u64, RailgunError> {
        Ok(self.client().estimate_gas(&from, &tx)?)
    }

    /// Signs `tx` with `account`, which pays the gas, and sends it. Returns the transaction hash at once; poll `receipt` for the result. The account is public, and it shows on chain as the sender.
    pub fn send(&self, account: &EvmAccount, tx: UnsignedTx) -> Result<String, RailgunError> {
        let hash = self.client().send(&account.key, &tx)?;
        Ok(format!("0x{}", hex::encode(hash)))
    }

    /// None until the transaction is mined.
    pub fn receipt(&self, tx_hash: String) -> Result<Option<Receipt>, RailgunError> {
        Ok(self.client().receipt(&hex_bytes(&tx_hash)?)?)
    }

    /// Proves POI for a sent transaction. Sync past it first.
    pub fn prove_poi(
        &self,
        wallet: &Wallet,
        tx_hash: String,
    ) -> Result<Arc<PoiSubmission>, RailgunError> {
        let proof =
            self.client()
                .prove_poi(&wallet.keys, &hex_bytes(&tx_hash)?, &self.artifacts)?;
        Ok(Arc::new(PoiSubmission { proof }))
    }

    pub fn submit_poi(&self, submission: &PoiSubmission) -> Result<(), RailgunError> {
        Ok(self.client().submit_poi(&submission.proof)?)
    }

    /// True once the aggregator lists every output as valid.
    pub fn poi_is_valid(&self, submission: &PoiSubmission) -> Result<bool, RailgunError> {
        let status = self.client().poi_status(&submission.proof)?;
        Ok(status.len() == submission.proof.blinded.len() && status.values().all(|s| s == "Valid"))
    }
}
