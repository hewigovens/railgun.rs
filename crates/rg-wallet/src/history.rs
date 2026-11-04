use std::collections::{BTreeMap, BTreeSet};

use rg_primitives::Fr;

use crate::{ScanResult, TxoSource};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HistoryKind {
    /// Public tokens into this wallet.
    Shield,
    /// A private transfer from another wallet.
    Receive,
    /// A private transfer this wallet sent to another.
    Send,
    /// Out of the pool to a public address, before the contract's fee.
    Unshield,
}

/// One kind of movement of one token in one transaction. Change and transfers to this wallet's own address are left out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryEntry {
    pub transaction_hash: [u8; 32],
    pub block_number: u64,
    pub kind: HistoryKind,
    pub token_hash: [u8; 32],
    pub value: u128,
    /// The first memo among the entry's notes.
    pub memo: Option<String>,
}

type Key = ([u8; 32], HistoryKind, [u8; 32]);

impl ScanResult {
    /// Transactions that spent this wallet's notes, which makes this wallet their sender.
    pub fn spending_transactions(&self) -> BTreeSet<[u8; 32]> {
        self.txos
            .iter()
            .filter_map(|t| t.spent.map(|s| s.transaction_hash))
            .collect()
    }

    /// Movements newest first. An unshield's value is what this wallet spent less what it sent and kept as private notes in that transaction.
    pub fn history(&self, own_master_public_key: &Fr) -> Vec<HistoryEntry> {
        let ours = self.spending_transactions();
        let mut entries: BTreeMap<Key, HistoryEntry> = BTreeMap::new();
        let mut add =
            |tx: [u8; 32], block, kind, token: [u8; 32], value: u128, memo: &Option<String>| {
                let entry = entries.entry((tx, kind, token)).or_insert(HistoryEntry {
                    transaction_hash: tx,
                    block_number: block,
                    kind,
                    token_hash: token,
                    value: 0,
                    memo: None,
                });
                entry.value = entry.value.saturating_add(value);
                if entry.memo.is_none() {
                    entry.memo.clone_from(memo);
                }
            };

        let mut unshielded: BTreeMap<([u8; 32], [u8; 32]), (u64, i128)> = BTreeMap::new();
        for t in &self.txos {
            match t.source {
                TxoSource::Shield => add(
                    t.transaction_hash,
                    t.block_number,
                    HistoryKind::Shield,
                    t.token_hash,
                    t.value,
                    &t.memo_text,
                ),
                TxoSource::Transact if !ours.contains(&t.transaction_hash) => add(
                    t.transaction_hash,
                    t.block_number,
                    HistoryKind::Receive,
                    t.token_hash,
                    t.value,
                    &t.memo_text,
                ),
                TxoSource::Transact => {}
            }
            if let Some(spent) = t.spent {
                let e = unshielded
                    .entry((spent.transaction_hash, t.token_hash))
                    .or_insert((spent.block_number, 0));
                e.1 = e.1.saturating_add(t.value as i128);
            }
        }
        for s in &self.sent {
            if &s.receiver_master_public_key != own_master_public_key {
                add(
                    s.transaction_hash,
                    s.block_number,
                    HistoryKind::Send,
                    s.token_hash,
                    s.value,
                    &s.memo_text,
                );
            }
            if let Some(e) = unshielded.get_mut(&(s.transaction_hash, s.token_hash)) {
                e.1 = e.1.saturating_sub(s.value as i128);
            }
        }
        for ((tx, token), (block, value)) in unshielded {
            if value > 0 {
                add(
                    tx,
                    block,
                    HistoryKind::Unshield,
                    token,
                    value as u128,
                    &None,
                );
            }
        }

        let mut out: Vec<HistoryEntry> = entries.into_values().collect();
        out.sort_by(|a, b| {
            (b.block_number, b.transaction_hash, a.kind).cmp(&(
                a.block_number,
                a.transaction_hash,
                b.kind,
            ))
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use rg_sync::NullifierRecord;

    use super::*;
    use crate::{SentNote, Txo};

    const ME: u64 = 1;
    const THEM: u64 = 2;

    fn txo(tx: u8, source: TxoSource, value: u128, spent_in: Option<u8>) -> Txo {
        Txo {
            tree: 0,
            position: 0,
            commitment: [0; 32],
            token_hash: [9; 32],
            value,
            random: [0; 16],
            nullifier: [0; 32],
            source,
            block_number: tx as u64,
            transaction_hash: [tx; 32],
            spent: spent_in.map(|s| NullifierRecord {
                block_number: s as u64,
                transaction_hash: [s; 32],
            }),
            memo_text: None,
            sender_master_public_key: None,
        }
    }

    fn sent(tx: u8, to: u64, value: u128, memo: Option<&str>) -> SentNote {
        SentNote {
            tree: 0,
            position: 0,
            receiver_master_public_key: Fr::from(to),
            commitment: [0; 32],
            token_hash: [9; 32],
            value,
            random: [0; 16],
            memo_text: memo.map(str::to_string),
            block_number: tx as u64,
            transaction_hash: [tx; 32],
        }
    }

    fn kinds(scan: &ScanResult) -> Vec<(u8, HistoryKind, u128, Option<String>)> {
        scan.history(&Fr::from(ME))
            .into_iter()
            .map(|e| (e.transaction_hash[0], e.kind, e.value, e.memo))
            .collect()
    }

    #[test]
    fn names_each_movement_and_hides_change() {
        // 1: shield 100. 2: receive 50. 3: spend the shield, send 30 with change 70.
        // 4: spend the change and the receipt, unshield 100 with change 20.
        let scan = ScanResult {
            txos: vec![
                txo(1, TxoSource::Shield, 100, Some(3)),
                txo(2, TxoSource::Transact, 50, Some(4)),
                txo(3, TxoSource::Transact, 70, Some(4)),
                txo(4, TxoSource::Transact, 20, None),
            ],
            sent: vec![
                sent(3, THEM, 30, Some("thanks")),
                sent(3, ME, 70, None),
                sent(4, ME, 20, None),
            ],
        };
        use HistoryKind::*;
        assert_eq!(
            kinds(&scan),
            vec![
                (4, Unshield, 100, None),
                (3, Send, 30, Some("thanks".into())),
                (2, Receive, 50, None),
                (1, Shield, 100, None),
            ]
        );
    }

    #[test]
    fn totals_saturate_instead_of_overflowing() {
        let huge = (1u128 << 120) - 1;
        let scan = ScanResult {
            txos: (0..300)
                .map(|_| txo(1, TxoSource::Shield, huge, Some(2)))
                .collect(),
            sent: Vec::new(),
        };
        use HistoryKind::*;
        assert_eq!(
            kinds(&scan),
            vec![
                (2, Unshield, i128::MAX as u128, None),
                (1, Shield, u128::MAX, None)
            ]
        );
    }
}
