use std::collections::BTreeMap;

use rg_primitives::Fr;
use rg_sync::NullifierRecord;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxoSource {
    Shield,
    Transact,
}

/// A note this wallet received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Txo {
    pub tree: u32,
    pub position: u32,
    pub commitment: [u8; 32],
    pub token_hash: [u8; 32],
    pub value: u128,
    pub random: [u8; 16],
    pub nullifier: [u8; 32],
    pub source: TxoSource,
    pub block_number: u64,
    pub transaction_hash: [u8; 32],
    /// Where the nullifier was published, if it has been.
    pub spent: Option<NullifierRecord>,
    pub memo_text: Option<String>,
    /// For transfers whose sender chose to be visible.
    pub sender_master_public_key: Option<Fr>,
}

/// An output this wallet created (including change to itself).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentNote {
    pub tree: u32,
    pub position: u32,
    pub receiver_master_public_key: Fr,
    pub commitment: [u8; 32],
    pub token_hash: [u8; 32],
    pub value: u128,
    pub random: [u8; 16],
    pub memo_text: Option<String>,
    pub block_number: u64,
    pub transaction_hash: [u8; 32],
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanResult {
    pub txos: Vec<Txo>,
    pub sent: Vec<SentNote>,
}

impl ScanResult {
    pub fn unspent(&self) -> impl Iterator<Item = &Txo> {
        self.txos.iter().filter(|t| t.spent.is_none())
    }

    /// The notes a transaction spent, in its nullifier order. `None` if one is not ours. A nullifier hashes only the leaf's position, so the same value recurs across trees and the lookup has to be scoped to `tree`.
    pub fn txos_for_nullifiers(&self, tree: u32, nullifiers: &[[u8; 32]]) -> Option<Vec<&Txo>> {
        nullifiers
            .iter()
            .map(|n| {
                self.txos
                    .iter()
                    .find(|t| t.tree == tree && &t.nullifier == n)
            })
            .collect()
    }

    /// Unspent value per token hash.
    pub fn balances(&self) -> BTreeMap<[u8; 32], u128> {
        let mut out = BTreeMap::new();
        for t in self.unspent() {
            *out.entry(t.token_hash).or_insert(0u128) += t.value;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn txo(tree: u32, nullifier: u8) -> Txo {
        Txo {
            tree,
            position: 0,
            commitment: [0; 32],
            token_hash: [0; 32],
            value: tree as u128,
            random: [0; 16],
            nullifier: [nullifier; 32],
            source: TxoSource::Shield,
            block_number: 0,
            transaction_hash: [0; 32],
            spent: None,
            memo_text: None,
            sender_master_public_key: None,
        }
    }

    #[test]
    fn nullifier_lookup_stays_in_its_tree() {
        let scan = ScanResult {
            txos: vec![txo(1, 7), txo(2, 7), txo(2, 8)],
            sent: Vec::new(),
        };
        let found = scan.txos_for_nullifiers(2, &[[8; 32], [7; 32]]).unwrap();
        assert_eq!((found[0].nullifier, found[1].tree), ([8; 32], 2));
        assert!(scan.txos_for_nullifiers(3, &[[7; 32]]).is_none());
    }
}
