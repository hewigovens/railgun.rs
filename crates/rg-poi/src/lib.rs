//! Private Proof of Innocence (engine `poi/*`, `transaction/railgun-txid.ts`).
//!
//! After a transaction, its sender proves that every note it spent sits in a POI list, and that the transaction's outputs are the blinded commitments it claims. The aggregator then adds those to the list, which is what makes the recipient's note spendable in other wallets. The contract knows nothing of this.

mod error;
#[cfg(feature = "rpc")]
pub mod node;
mod proof_inputs;
mod txid;
mod txid_trees;

pub use error::Error;
pub use proof_inputs::{FULL_CIRCUIT, ListProof, MINI_CIRCUIT, OutputNote, ProofInputs, SpentNote};
pub use txid::{
    PRE_TRANSACTION_POSITION, blinded_commitment, global_tree_position, railgun_txid, txid_leaf,
};
pub use txid_trees::TxidTrees;
