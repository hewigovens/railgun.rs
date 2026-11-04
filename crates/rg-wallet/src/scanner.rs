use rg_keys::ViewOnlyKeys;
use rg_notes::transact::{ViewingKeys, decrypt_as_receiver, decrypt_as_sender};
use rg_notes::{note, shield};
use rg_primitives::{Fr, field};
use rg_sync::{Commitment, Leaf, SyncState};

use crate::{ScanResult, SentNote, Txo, TxoSource};

fn is_canonical(bytes: &[u8; 32]) -> bool {
    field::to_be_bytes(&field::from_be_bytes_mod_order(bytes)) == *bytes
}

pub struct Scanner<'a> {
    keys: &'a ViewOnlyKeys,
    viewing: ViewingKeys<'a>,
}

impl<'a> Scanner<'a> {
    pub fn new(keys: &'a ViewOnlyKeys) -> Self {
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
        // Anyone can write an output this wallet decrypts as its sender, so only a transaction that spent its notes is one it sent.
        let ours = out.spending_transactions();
        out.sent.retain(|s| ours.contains(&s.transaction_hash));
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
                // The commitment reduces the token hash, so a sender could write an unreduced one that still matches and file the note under a token that does not exist.
                if let Ok(n) = decrypt_as_receiver(&self.viewing, &t.ciphertext)
                    && n.commitment() == leaf_hash
                    && is_canonical(&n.token_hash)
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

#[cfg(test)]
mod tests {
    use rg_keys::WalletKeys;
    use rg_notes::OutputType;
    use rg_notes::transact::{OutputNote, create_commitment_ciphertext_v2};
    use rg_sync::{NullifierRecord, TransactCommitment};

    use super::*;

    fn output(from: &ViewOnlyKeys, to: &ViewOnlyKeys, tx: u8) -> Leaf {
        let note = OutputNote {
            receiver_master_public_key: to.master_public_key,
            receiver_viewing_public_key: to.viewing_public_key,
            token_hash: [0; 32],
            value: 5,
            random: [tx; 16],
            sender_random: [tx; 15],
            output_type: OutputType::Transfer,
            wallet_source: "test",
            memo_text: None,
        };
        let viewing = ViewingKeys {
            viewing_private_key: &from.viewing_private_key,
            viewing_public_key: from.viewing_public_key,
            master_public_key: from.master_public_key,
        };
        Leaf {
            commitment: Commitment::Transact(TransactCommitment {
                hash: field::to_be_bytes(&note.commitment()),
                ciphertext: create_commitment_ciphertext_v2(&viewing, &note, &[1; 16], &[2; 16])
                    .unwrap(),
            }),
            block_number: tx as u64,
            transaction_hash: [tx; 32],
        }
    }

    #[test]
    fn an_output_is_sent_only_by_a_transaction_that_spent_our_notes() {
        let mnemonic = "test test test test test test test test test test test junk";
        let (me, them) = (
            WalletKeys::from_mnemonic(mnemonic, "", 0).unwrap(),
            WalletKeys::from_mnemonic(mnemonic, "", 1).unwrap(),
        );
        let mut state = SyncState::new();
        // Ours from them in transaction 1, then an output that decrypts as ours to them in transaction 2.
        state.leaves = vec![vec![output(&them, &me, 1), output(&me, &them, 2)]];
        assert!(Scanner::new(&me).scan(&state).sent.is_empty());

        let nullifier = field::to_be_bytes(&note::nullifier(&me.nullifying_key, 0));
        let spent = NullifierRecord {
            block_number: 2,
            transaction_hash: [2; 32],
        };
        state.nullifiers.insert((0, nullifier), spent);
        assert_eq!(Scanner::new(&me).scan(&state).sent.len(), 1);
    }

    #[test]
    fn a_token_hash_past_the_modulus_is_not_canonical() {
        let mut token = [0u8; 32];
        token[12..].copy_from_slice(&[0xaf; 20]);
        assert!(is_canonical(&token));
        // BN254's scalar modulus, which reduces to zero: the same field element as the zero hash.
        let p = hex::decode("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")
            .unwrap();
        assert!(!is_canonical(&p.try_into().unwrap()));
    }
}
