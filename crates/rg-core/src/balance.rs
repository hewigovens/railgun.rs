use std::collections::BTreeMap;

use rg_keys::WalletKeys;
use rg_poi::node::REQUIRED_LIST;
use rg_wallet::{ScanResult, Txo, TxoSource};

use crate::poi::blinded_input;
use crate::{ChainStore, Client, Error};

/// The aggregator answers at most this many blinded commitments per call.
const STATUS_BATCH: usize = 1000;

/// Whether an unspent note can be spent, from its POI status (engine `POI.getBalanceBucket`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NoteStatus {
    Spendable,
    /// A shield the list provider has not screened yet.
    ShieldPending,
    /// A shield the list provider refused.
    ShieldBlocked,
    /// A POI proof is in, and the list has not added the note yet.
    ProofSubmitted,
    /// From a transaction this wallet sent, with no POI proof yet: `Client::prove_poi` fixes it.
    MissingInternal,
    /// From another wallet that has not submitted its POI proof.
    MissingExternal,
}

impl NoteStatus {
    /// `status` is the required list's answer, if it gave one. `internal` means this wallet sent the transaction that made the note.
    pub fn new(status: Option<&str>, source: TxoSource, internal: bool) -> Self {
        let missing = if internal {
            NoteStatus::MissingInternal
        } else {
            NoteStatus::MissingExternal
        };
        match (status, source) {
            (Some("Valid"), _) => NoteStatus::Spendable,
            (Some("ShieldBlocked"), _) => NoteStatus::ShieldBlocked,
            (_, TxoSource::Shield) => NoteStatus::ShieldPending,
            (Some("ProofSubmitted"), _) => NoteStatus::ProofSubmitted,
            _ => missing,
        }
    }
}

/// One token's unspent value by status.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Balance {
    pub token_hash: [u8; 32],
    pub spendable: u128,
    pub shield_pending: u128,
    pub shield_blocked: u128,
    pub proof_submitted: u128,
    pub missing_internal: u128,
    pub missing_external: u128,
}

impl Balance {
    fn add(&mut self, status: NoteStatus, value: u128) {
        *match status {
            NoteStatus::Spendable => &mut self.spendable,
            NoteStatus::ShieldPending => &mut self.shield_pending,
            NoteStatus::ShieldBlocked => &mut self.shield_blocked,
            NoteStatus::ProofSubmitted => &mut self.proof_submitted,
            NoteStatus::MissingInternal => &mut self.missing_internal,
            NoteStatus::MissingExternal => &mut self.missing_external,
        } += value;
    }
}

impl<S: ChainStore> Client<S> {
    /// Each unspent note with its status, asked of the POI aggregator.
    pub fn note_statuses<'a>(
        &self,
        keys: &WalletKeys,
        scan: &'a ScanResult,
    ) -> Result<Vec<(&'a Txo, NoteStatus)>, Error> {
        let ours = scan.spending_transactions();
        let unspent: Vec<&Txo> = scan.unspent().collect();
        let blinded: Vec<(String, &'static str)> = unspent
            .iter()
            .map(|t| {
                let kind = match t.source {
                    TxoSource::Shield => "Shield",
                    TxoSource::Transact => "Transact",
                };
                (blinded_input(keys, t), kind)
            })
            .collect();
        let mut answers = BTreeMap::new();
        for batch in blinded.chunks(STATUS_BATCH) {
            answers.extend(self.node().pois_per_list(REQUIRED_LIST, batch)?);
        }
        Ok(unspent
            .into_iter()
            .zip(&blinded)
            .map(|(t, (b, _))| {
                let internal = ours.contains(&t.transaction_hash);
                let status =
                    NoteStatus::new(answers.get(b).map(String::as_str), t.source, internal);
                (t, status)
            })
            .collect())
    }

    /// Unspent value per token, split by POI status.
    pub fn balances(&self, keys: &WalletKeys) -> Result<Vec<Balance>, Error> {
        let scan = self.scan(keys);
        let mut out: BTreeMap<[u8; 32], Balance> = BTreeMap::new();
        for (t, status) in self.note_statuses(keys, &scan)? {
            out.entry(t.token_hash)
                .or_insert_with(|| Balance {
                    token_hash: t.token_hash,
                    ..Balance::default()
                })
                .add(status, t.value);
        }
        Ok(out.into_values().collect())
    }

    /// The scan with only spendable notes left unspent, for choosing what a transaction spends: a note without POI can be spent on chain, but the POI proof for that transaction would then fail.
    pub(crate) fn spendable_scan(&self, keys: &WalletKeys) -> Result<ScanResult, Error> {
        let scan = self.scan(keys);
        let spendable: Vec<Txo> = self
            .note_statuses(keys, &scan)?
            .into_iter()
            .filter(|(_, status)| *status == NoteStatus::Spendable)
            .map(|(t, _)| t.clone())
            .collect();
        Ok(ScanResult {
            txos: spendable,
            sent: scan.sent,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_the_engine_buckets() {
        use NoteStatus::*;
        let status = |answer, source, internal| NoteStatus::new(answer, source, internal);
        assert_eq!(status(Some("Valid"), TxoSource::Transact, false), Spendable);
        assert_eq!(
            status(Some("ShieldBlocked"), TxoSource::Shield, false),
            ShieldBlocked
        );
        assert_eq!(status(None, TxoSource::Shield, false), ShieldPending);
        assert_eq!(
            status(Some("ProofSubmitted"), TxoSource::Shield, false),
            ShieldPending
        );
        assert_eq!(
            status(Some("ProofSubmitted"), TxoSource::Transact, true),
            ProofSubmitted
        );
        assert_eq!(
            status(Some("Missing"), TxoSource::Transact, true),
            MissingInternal
        );
        assert_eq!(status(None, TxoSource::Transact, false), MissingExternal);
    }
}
