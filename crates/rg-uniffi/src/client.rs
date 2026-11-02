use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rg_core::{Artifacts, Client, FileStore, Receipt, Shield, Transfer, Unshield, UnsignedTx};
use rg_keys::EvmAddress;
use rg_sync::Network;

use crate::{
    EvmAccount, FeeQuote, HistoryItem, PoiSubmission, RailgunError, SyncReport, TokenBalance,
    Wallet,
};

fn hash(value: &str) -> Result<[u8; 32], RailgunError> {
    hex::decode(value.trim_start_matches("0x"))
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| RailgunError::invalid(format!("expected a 32-byte hash: {value}")))
}

fn address(value: &str) -> Result<[u8; 20], RailgunError> {
    Ok(value.parse::<EvmAddress>()?.0)
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

    /// Unspent ERC20 balances as of the last sync, by POI status, which comes from the aggregator. Token addresses are checksummed.
    pub fn balances(&self, wallet: &Wallet) -> Result<Vec<TokenBalance>, RailgunError> {
        let balances = self.client().balances(&wallet.keys)?;
        Ok(balances.into_iter().map(TokenBalance::from).collect())
    }

    /// Shields, receipts, sends and unshields as of the last sync, newest first. Change is left out.
    pub fn history(&self, wallet: &Wallet) -> Vec<HistoryItem> {
        let history = self.client().history(&wallet.keys);
        history.into_iter().map(HistoryItem::from).collect()
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
            token: address(&token)?,
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
            to: address(&to)?,
            token: address(&token)?,
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
            token: address(&token)?,
            value: amount(&value)?,
        };
        Ok(self.client().build_shield(&shield)?)
    }

    /// Lets the Railgun contract take `value` of `token`.
    pub fn build_approve(&self, token: String, value: String) -> Result<UnsignedTx, RailgunError> {
        Ok(self
            .client()
            .build_approve(address(&token)?, amount(&value)?)?)
    }

    /// What the Railgun contract may take of `owner`'s `token`.
    pub fn allowance(&self, owner: String, token: String) -> Result<String, RailgunError> {
        let allowance = self
            .client()
            .allowance(&address(&owner)?, &address(&token)?)?;
        Ok(allowance.to_string())
    }

    pub fn token_balance(&self, owner: String, token: String) -> Result<String, RailgunError> {
        let balance = self
            .client()
            .token_balance(&address(&token)?, &address(&owner)?)?;
        Ok(balance.to_string())
    }

    pub fn native_balance(&self, owner: String) -> Result<String, RailgunError> {
        Ok(self.client().native_balance(&address(&owner)?)?.to_string())
    }

    /// Estimates and prices sending `tx` from the `from` address, which needs no key. Fails if the node expects it to revert.
    pub fn quote_fee(&self, from: String, tx: UnsignedTx) -> Result<Arc<FeeQuote>, RailgunError> {
        let quote = self.client().quote_fee(&address(&from)?, &tx)?;
        Ok(Arc::new(FeeQuote { quote }))
    }

    /// Signs `tx` with `account` at the quoted fees, and sends it. Returns the transaction hash at once; poll `receipt` for the result. The account is public, and it shows on chain as the sender.
    pub fn send(
        &self,
        account: &EvmAccount,
        tx: UnsignedTx,
        fee: &FeeQuote,
    ) -> Result<String, RailgunError> {
        let hash = self.client().send(&account.key, &tx, &fee.quote)?;
        Ok(format!("0x{}", hex::encode(hash)))
    }

    /// None until the transaction is mined.
    pub fn receipt(&self, tx_hash: String) -> Result<Option<Receipt>, RailgunError> {
        Ok(self.client().receipt(&hash(&tx_hash)?)?)
    }

    /// Proves POI for a sent transaction. Sync past it first.
    pub fn prove_poi(
        &self,
        wallet: &Wallet,
        tx_hash: String,
    ) -> Result<Arc<PoiSubmission>, RailgunError> {
        let proof = self
            .client()
            .prove_poi(&wallet.keys, &hash(&tx_hash)?, &self.artifacts)?;
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
