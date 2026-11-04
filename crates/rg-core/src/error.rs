#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("store: {0}")]
    Io(#[from] std::io::Error),
    #[error("no artifact hashes for circuit {0}")]
    UnknownCircuit(String),
    #[error("downloading {0}: {1}")]
    Download(String, String),
    #[error("{0} does not match its published hash")]
    ArtifactHash(String),
    #[error("stored {0} is corrupt")]
    Corrupt(&'static str),
    #[error("sync: {0}")]
    Sync(#[from] rg_sync::Error),
    #[error("transaction: {0}")]
    Tx(#[from] rg_tx::Error),
    #[error("prover: {0}")]
    Prover(#[from] rg_prover::Error),
    #[error("poi: {0}")]
    Poi(#[from] rg_poi::Error),
    #[error("aggregator: {0}")]
    Node(#[from] rg_poi::node::NodeError),
    #[error("keys: {0}")]
    Keys(#[from] rg_keys::Error),
    #[error("tree {0} root {1} is not in the contract's history")]
    UnknownRoot(u32, String),
    #[error("relay call {0} failed: {1}")]
    CallFailed(u64, String),
    #[error("the node's {0} is implausible")]
    Implausible(&'static str),
    #[error("the broadcaster answered with a transaction that is not this one")]
    WrongTransaction,
    #[error("the RPC URL must use https, or plain http to this machine")]
    InsecureRpc,
    #[error("the node is on chain {0}, not this network's chain {1}")]
    WrongNode(u64, u64),
    #[error("{0} has no indexer and legacy events cannot be decoded")]
    NoSquid(&'static str),
    #[error("proof does not verify against the artifacts' key")]
    BadProof,
    #[error("not an address: {0}")]
    BadAddress(String),
    #[error("transaction is for chain {0}, this client is on chain {1}")]
    WrongChain(u64, u64),
    #[error("{0} of this token is waiting for POI, so the spendable notes do not cover it yet")]
    AwaitingPoi(u128),
    #[error("broadcaster: {0}")]
    Broadcaster(#[from] rg_broadcaster::Error),
    #[error("the broadcaster takes no fee in this token")]
    NotOffered,
    #[error("the broadcaster refused the transaction: {0}")]
    Refused(String),
    #[error("transaction {0} is not one this wallet can prove: {1}")]
    NotProvable(String, &'static str),
}
