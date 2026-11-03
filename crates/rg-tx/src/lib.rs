//! Railgun private transfers (V2): the engine's `transaction/transaction.ts`, `transaction-batch.ts`, `bound-params.ts` and `prover.ts` formatting.
//!
//! [`plan_transfer`] picks notes and builds the outputs (recipient plus change), one transaction per group of notes from one tree, [`TransferParams::prepare`] makes bound params, nullifiers, commitments, the spending signature and the circuit inputs, and [`Prepared::transaction`] wraps a proof into the contract's `Transaction` for [`transact_calldata`]. Proving lives in `rg-prover`; this crate never touches the network.

mod contract;
mod eip1559;
mod error;
mod hashing;
mod params;
mod plan;
mod prepared;
mod relay_adapt;
mod shield;
mod unshield;

pub use contract::{snark_proof, transact_calldata, verifying_key_from_contract};
pub use eip1559::{Eip1559Tx, SignedTx};
pub use error::Error;
pub use hashing::{chain_full_network_id, fr_to_b256, hash_bound_params, signature_message};
pub use params::{OutputPlan, SpendNote, TransferParams, circuit_exists};
pub use plan::{
    MAX_INPUTS, TransferRequest, UnshieldRequest, plan_transfer, plan_unshield, select_notes,
};
pub use prepared::Prepared;
pub use relay_adapt::{
    AdaptId, relay_adapt_params, relay_calldata, shield_base_token_calldata,
    unshield_base_token_action,
};
pub use shield::{approve_calldata, shield_calldata};
pub use unshield::UnshieldOutput;
