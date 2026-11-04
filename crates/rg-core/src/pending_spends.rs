use std::collections::HashSet;

use rg_keys::WalletKeys;
use rg_primitives::field;
use rg_tx::TransferParams;
use rg_wallet::ScanResult;

use crate::{ChainStore, Client, Error};

/// A note a batch spends: its tree and nullifier.
pub type Spend = (u16, [u8; 32]);

/// What `planned` spends.
pub(crate) fn spends(keys: &WalletKeys, planned: &[TransferParams]) -> Vec<Spend> {
    planned
        .iter()
        .flat_map(|p| {
            p.nullifiers(&keys.nullifying_key)
                .into_iter()
                .map(|n| (p.tree, field::to_be_bytes(&n)))
        })
        .collect()
}

impl<S: ChainStore> Client<S> {
    /// Notes a broadcaster was handed, recorded before the hand-over: it may submit the batch at any time, even after it answered with nothing or a hash no node has.
    pub(crate) fn hold(&mut self, batch: &[Spend]) -> Result<(), Error> {
        let mut held = self.store.pending_spends()?;
        held.push(batch.to_vec());
        self.store.save_pending_spends(&held)
    }

    /// Lets go of batches whose notes the chain shows spent: by the batch, or by one that conflicts with it.
    pub(crate) fn release_spent(&mut self) -> Result<(), Error> {
        let held = self.store.pending_spends()?;
        let open: Vec<_> = held
            .iter()
            .filter(|batch| !batch.iter().any(|s| self.state.nullifiers.contains_key(s)))
            .cloned()
            .collect();
        if open.len() != held.len() {
            self.store.save_pending_spends(&open)?;
        }
        Ok(())
    }

    /// Forgets every batch handed to a broadcaster and not yet seen on chain, so later spends may use other notes. Should a broadcaster still submit one, both it and the later spend land.
    pub fn forget_pending_broadcasts(&mut self) -> Result<(), Error> {
        self.store.save_pending_spends(&[])
    }

    /// A later spend of a token a held batch spends must spend one of that batch's notes too, so at most one of the two lands. Re-plans from the held notes alone when the first plan does not.
    pub(crate) fn spend_held_notes_first<'a>(
        &self,
        keys: &WalletKeys,
        token_hash: &[u8; 32],
        spendable: &ScanResult,
        planned: Vec<TransferParams<'a>>,
        plan: impl Fn(&ScanResult) -> Result<Vec<TransferParams<'a>>, rg_tx::Error>,
    ) -> Result<Vec<TransferParams<'a>>, Error> {
        let of_token: HashSet<Spend> = spendable
            .unspent()
            .filter(|t| &t.token_hash == token_hash)
            .map(|t| (t.tree as u16, t.nullifier))
            .collect();
        let held: Vec<Vec<Spend>> = self
            .store
            .pending_spends()?
            .into_iter()
            .filter(|batch| {
                batch.iter().any(|s| of_token.contains(s))
                    && !batch.iter().any(|s| self.state.nullifiers.contains_key(s))
            })
            .collect();
        let conflicts = |planned: &[TransferParams]| {
            let spent = spends(keys, planned);
            held.iter()
                .all(|batch| batch.iter().any(|s| spent.contains(s)))
        };
        if conflicts(&planned) {
            return Ok(planned);
        }
        let notes: HashSet<&Spend> = held.iter().flatten().collect();
        let only_held = ScanResult {
            txos: spendable
                .txos
                .iter()
                .filter(|t| notes.contains(&(t.tree as u16, t.nullifier)))
                .cloned()
                .collect(),
            sent: Vec::new(),
        };
        match plan(&only_held) {
            Ok(planned) if conflicts(&planned) => Ok(planned),
            _ => Err(Error::HeldByBroadcaster),
        }
    }
}

#[cfg(test)]
mod tests {
    use rg_keys::WalletKeys;
    use rg_notes::note;
    use rg_primitives::Fr;
    use rg_sync::{Network, NullifierRecord};
    use rg_tree::MerkleTree;
    use rg_tx::{AdaptId, SpendNote, select_notes};
    use rg_wallet::{Txo, TxoSource};

    use super::*;
    use crate::FileStore;

    const TOKEN: [u8; 32] = [7; 32];

    fn txo(keys: &WalletKeys, position: u32, value: u128) -> Txo {
        Txo {
            tree: 0,
            position,
            commitment: [0; 32],
            token_hash: TOKEN,
            value,
            random: [0; 16],
            nullifier: field::to_be_bytes(&note::nullifier(&keys.nullifying_key, position.into())),
            source: TxoSource::Shield,
            block_number: 1,
            transaction_hash: [1; 32],
            spent: None,
            memo_text: None,
            sender_master_public_key: None,
        }
    }

    /// Spends the notes `select_notes` picks for `value`.
    fn plan(scan: &ScanResult, value: u128) -> Result<Vec<TransferParams<'static>>, rg_tx::Error> {
        let mut tree = MerkleTree::new();
        tree.insert(0, &[Fr::from(0u64), Fr::from(1u64)]).unwrap();
        let notes = select_notes(scan.unspent(), &TOKEN, value)
            .ok_or(rg_tx::Error::InsufficientNote(value))?;
        Ok(vec![TransferParams {
            tree: 0,
            merkle_root: tree.root(),
            token_hash: TOKEN,
            chain_id: 0,
            min_gas_price: 0,
            inputs: notes[0]
                .iter()
                .map(|t| SpendNote {
                    position: t.position.into(),
                    random: t.random,
                    value: t.value,
                    proof: tree.proof(t.position as usize).unwrap(),
                })
                .collect(),
            outputs: Vec::new(),
            unshield: None,
            adapt: AdaptId::default(),
        }])
    }

    #[test]
    fn a_later_spend_takes_a_held_note_or_is_refused() {
        let dir = std::env::temp_dir().join(format!("rg-core-held-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = FileStore::open(&dir).unwrap();
        let mut client = Client::open(Network::SEPOLIA, "http://localhost:1", store).unwrap();
        let keys = WalletKeys::from_mnemonic(
            "test test test test test test test test test test test junk",
            "",
            0,
        )
        .unwrap();
        let (small, large) = (txo(&keys, 0, 10), txo(&keys, 1, 20));
        let scan = ScanResult {
            txos: vec![small.clone(), large.clone()],
            sent: Vec::new(),
        };
        let spends_of = |client: &Client, value| {
            let planned = plan(&scan, value).unwrap();
            client
                .spend_held_notes_first(&keys, &TOKEN, &scan, planned, |s| plan(s, value))
                .map(|p| spends(&keys, &p))
        };
        let large_spend = (0, large.nullifier);

        client.hold(&[large_spend]).unwrap();
        // 5 alone would take the small note; the held large one covers it too.
        assert_eq!(spends_of(&client, 5).unwrap(), vec![large_spend]);

        client.forget_pending_broadcasts().unwrap();
        client.hold(&[(0, small.nullifier)]).unwrap();
        assert!(matches!(
            spends_of(&client, 15),
            Err(Error::HeldByBroadcaster)
        ));

        let spent = NullifierRecord {
            block_number: 2,
            transaction_hash: [2; 32],
        };
        client.state.nullifiers.insert((0, small.nullifier), spent);
        client.release_spent().unwrap();
        assert_eq!(
            client.store.pending_spends().unwrap(),
            Vec::<Vec<Spend>>::new()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
