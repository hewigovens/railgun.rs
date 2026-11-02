use rg_keys::WalletKeys;
use rg_notes::transact::{ViewingKeys, decrypt_as_receiver, decrypt_as_sender};
use rg_notes::{note, shield};
use rg_primitives::{Fr, field};
use rg_sync::{Commitment, Leaf, SyncState};

use crate::{ScanResult, SentNote, Txo, TxoSource};

pub struct Scanner<'a> {
    keys: &'a WalletKeys,
    viewing: ViewingKeys<'a>,
}

impl<'a> Scanner<'a> {
    pub fn new(keys: &'a WalletKeys) -> Self {
        let viewing = ViewingKeys {
            viewing_private_key: &keys.viewing_private_key,
            viewing_public_key: keys.viewing_public_key,
            master_public_key: keys.master_public_key,
        };
        Scanner { keys, viewing }
    }

    /// Scans every leaf of every tree.
    pub fn scan(&self, state: &SyncState) -> ScanResult {
        let mut out = ScanResult::default();
        for (tree, leaves) in state.leaves.iter().enumerate() {
            for (position, leaf) in leaves.iter().enumerate() {
                self.scan_leaf(state, tree as u32, position as u32, leaf, &mut out);
            }
        }
        out
    }

    fn txo(
        &self,
        state: &SyncState,
        tree: u32,
        position: u32,
        leaf: &Leaf,
        commitment: Fr,
        fields: TxoFields,
    ) -> Txo {
        let nullifier =
            field::to_be_bytes(&note::nullifier(&self.keys.nullifying_key, position as u64));
        Txo {
            tree,
            position,
            commitment: field::to_be_bytes(&commitment),
            token_hash: fields.token_hash,
            value: fields.value,
            random: fields.random,
            nullifier,
            source: fields.source,
            block_number: leaf.block_number,
            transaction_hash: leaf.transaction_hash,
            spent: state.nullifiers.get(&(tree as u16, nullifier)).copied(),
            memo_text: fields.memo_text,
            sender_master_public_key: fields.sender,
        }
    }

    fn scan_leaf(
        &self,
        state: &SyncState,
        tree: u32,
        position: u32,
        leaf: &Leaf,
        out: &mut ScanResult,
    ) {
        let leaf_hash = leaf.commitment.hash();
        match &leaf.commitment {
            Commitment::Shield(s) => {
                let Ok(random) = shield::decrypt_as_receiver(
                    self.keys.viewing_private_key.expose(),
                    &s.ciphertext,
                ) else {
                    return;
                };
                // The engine trusts the GCM tag here; also require the note public key to be ours, or the note could never be spent.
                let npk = note::note_public_key(&self.keys.master_public_key, &random);
                if field::to_be_bytes(&npk) != s.npk {
                    return;
                }
                let txo = self.txo(
                    state,
                    tree,
                    position,
                    leaf,
                    leaf_hash,
                    TxoFields {
                        token_hash: s.token.hash(),
                        value: s.value,
                        random,
                        source: TxoSource::Shield,
                        memo_text: None,
                        sender: None,
                    },
                );
                out.txos.push(txo);
            }
            Commitment::Opaque(_) => {}
            Commitment::Transact(t) => {
                if let Ok(n) = decrypt_as_receiver(&self.viewing, &t.ciphertext)
                    && n.commitment() == leaf_hash
                {
                    let txo = self.txo(
                        state,
                        tree,
                        position,
                        leaf,
                        leaf_hash,
                        TxoFields {
                            token_hash: n.token_hash,
                            value: n.value,
                            random: n.random,
                            source: TxoSource::Transact,
                            memo_text: n.memo_text,
                            sender: n.sender_master_public_key,
                        },
                    );
                    out.txos.push(txo);
                }
                if let Ok(n) = decrypt_as_sender(&self.viewing, &t.ciphertext)
                    && n.commitment() == leaf_hash
                {
                    out.sent.push(SentNote {
                        tree,
                        position,
                        receiver_master_public_key: n.receiver_master_public_key,
                        commitment: field::to_be_bytes(&leaf_hash),
                        token_hash: n.token_hash,
                        value: n.value,
                        random: n.random,
                        memo_text: n.memo_text,
                        block_number: leaf.block_number,
                        transaction_hash: leaf.transaction_hash,
                    });
                }
            }
        }
    }
}

struct TxoFields {
    token_hash: [u8; 32],
    value: u128,
    random: [u8; 16],
    source: TxoSource,
    memo_text: Option<String>,
    sender: Option<Fr>,
}
