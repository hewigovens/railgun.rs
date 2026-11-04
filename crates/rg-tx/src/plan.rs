use rg_keys::{AddressData, WalletKeys};
use rg_notes::OutputType;
use rg_notes::transact::OutputNote;

use crate::{AdaptId, Error, OutputPlan, SpendNote, TransferParams, UnshieldOutput};

/// A transfer to one recipient from a wallet scan.
pub struct TransferRequest<'a> {
    pub recipient: &'a AddressData,
    pub token_hash: [u8; 32],
    pub value: u128,
    pub memo_text: Option<&'a str>,
    pub show_sender_to_recipient: bool,
    pub wallet_source: &'a str,
    pub chain_id: u64,
    pub min_gas_price: u128,
    pub broadcaster_fee: Option<BroadcasterFee>,
}

/// An unshield of an ERC20 from a wallet scan.
pub struct UnshieldRequest<'a> {
    pub to: [u8; 20],
    pub token: [u8; 20],
    pub value: u128,
    pub wallet_source: &'a str,
    pub chain_id: u64,
    pub min_gas_price: u128,
    pub broadcaster_fee: Option<BroadcasterFee>,
}

/// What a broadcaster charges for submitting the batch, paid in the token being spent: the first output of the first transaction, where the broadcaster looks for it.
#[derive(Clone, Debug)]
pub struct BroadcasterFee {
    pub recipient: AddressData,
    pub value: u128,
}

/// Most inputs in one transaction, the engine's limit.
pub const MAX_INPUTS: usize = 10;

fn total(notes: &[&rg_wallet::Txo]) -> u128 {
    notes.iter().map(|t| t.value).sum()
}

/// The notes to spend, in groups that each become one transaction: a transaction proves against one root, so a group is from one tree, and holds at most `MAX_INPUTS` notes. The smallest single note that covers `value` wins, then the tree needing the fewest of its largest notes, else several groups of the largest notes, fewest groups first. The engine also splits like this, but fills groups from the smallest notes up.
pub fn select_notes<'s>(
    unspent: impl Iterator<Item = &'s rg_wallet::Txo>,
    token_hash: &[u8; 32],
    value: u128,
) -> Option<Vec<Vec<&'s rg_wallet::Txo>>> {
    let notes: Vec<_> = unspent.filter(|t| &t.token_hash == token_hash).collect();
    if let Some(one) = notes
        .iter()
        .filter(|t| t.value >= value)
        .min_by_key(|t| (t.value, t.tree, t.position))
    {
        return Some(vec![vec![*one]]);
    }
    let mut trees: Vec<u32> = notes.iter().map(|t| t.tree).collect();
    trees.sort_unstable();
    trees.dedup();
    let mut groups: Vec<Vec<_>> = Vec::new();
    for tree in trees {
        let mut in_tree: Vec<_> = notes.iter().copied().filter(|t| t.tree == tree).collect();
        in_tree.sort_by_key(|t| (std::cmp::Reverse(t.value), t.position));
        groups.extend(in_tree.chunks(MAX_INPUTS).map(<[_]>::to_vec));
    }
    let single = groups
        .iter()
        .filter_map(|group| {
            let mut sum = 0u128;
            let count = group.iter().position(|t| {
                sum += t.value;
                sum >= value
            })?;
            Some(group[..=count].to_vec())
        })
        .min_by_key(Vec::len);
    if let Some(group) = single {
        return Some(vec![group]);
    }

    groups.sort_by_key(|g| std::cmp::Reverse(total(g)));
    let mut chosen = Vec::new();
    let mut sum = 0u128;
    for group in groups {
        if sum >= value {
            break;
        }
        sum += total(&group);
        chosen.push(group);
    }
    if sum < value {
        return None;
    }
    // Only the last group can overshoot: drop the smallest notes it does not need.
    let last = chosen.last_mut()?;
    while let Some(smallest) = last.last().filter(|_| last.len() > 1) {
        if sum - smallest.value < value {
            break;
        }
        sum -= smallest.value;
        last.pop();
    }
    Some(chosen)
}

/// Proofs for the chosen notes, their total and their tree's root.
fn spend_notes(
    state: &rg_sync::SyncState,
    notes: &[&rg_wallet::Txo],
) -> Result<(Vec<SpendNote>, u128), Error> {
    let tree = state
        .trees
        .get(notes[0].tree as usize)
        .ok_or(Error::BadProof)?;
    let inputs = notes
        .iter()
        .map(|t| {
            Ok(SpendNote {
                position: t.position as u64,
                random: t.random,
                value: t.value,
                proof: tree.proof(t.position as usize).map_err(Error::Tree)?,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok((inputs, total(notes)))
}

/// What a transfer and an unshield share.
struct Spend<'a> {
    token_hash: [u8; 32],
    value: u128,
    wallet_source: &'a str,
    chain_id: u64,
    min_gas_price: u128,
    broadcaster_fee: Option<BroadcasterFee>,
}

type Fill<'f> = &'f mut dyn FnMut(&mut [u8]);

/// Note values are 120 bits on chain.
pub(crate) const MAX_NOTE_VALUE: u128 = (1 << 120) - 1;

/// One transaction per note group. The first group pays the broadcaster fee first, `pay` makes the outputs that pay out a group's share, and whatever the last group has left over goes back to this wallet as change.
fn plan_spend<'a>(
    keys: &WalletKeys,
    state: &rg_sync::SyncState,
    scan: &rg_wallet::ScanResult,
    spend: &Spend<'a>,
    fill: Fill,
    mut pay: impl FnMut(u128, Fill) -> (Vec<OutputNote<'a>>, Option<UnshieldOutput>),
) -> Result<Vec<TransferParams<'a>>, Error> {
    if spend.value == 0 {
        return Err(Error::ZeroValue);
    }
    let fee = spend.broadcaster_fee.as_ref().map_or(0, |f| f.value);
    let needed = spend
        .value
        .checked_add(fee)
        .filter(|v| *v <= MAX_NOTE_VALUE)
        .ok_or(Error::OutOfRange("value"))?;
    let groups = select_notes(scan.unspent(), &spend.token_hash, needed)
        .ok_or(Error::InsufficientNote(needed))?;
    let mut left = needed;
    let mut planned = Vec::with_capacity(groups.len());
    for (index, notes) in groups.iter().enumerate() {
        let (inputs, total) = spend_notes(state, notes)?;
        let taken = total.min(left);
        left -= taken;
        let mut outs = Vec::new();
        let mut share = taken;
        if let Some(fee) = spend.broadcaster_fee.as_ref().filter(|_| index == 0) {
            share = share
                .checked_sub(fee.value)
                .ok_or(Error::InsufficientNote(needed))?;
            outs.push(fee_note(
                fee,
                &spend.token_hash,
                spend.wallet_source,
                &mut *fill,
            ));
        }
        let (paid, unshield) = if share > 0 {
            pay(share, &mut *fill)
        } else {
            (Vec::new(), None)
        };
        outs.extend(paid);
        if total > taken {
            outs.push(change_note(
                keys,
                &spend.token_hash,
                total - taken,
                spend.wallet_source,
                &mut *fill,
            ));
        }
        planned.push(TransferParams {
            tree: notes[0].tree as u16,
            merkle_root: inputs[0].proof.root,
            token_hash: spend.token_hash,
            chain_id: spend.chain_id,
            min_gas_price: spend.min_gas_price,
            inputs,
            outputs: with_ivs(outs, &mut *fill),
            unshield,
            adapt: AdaptId::default(),
        });
    }
    Ok(planned)
}

/// Picks the notes to spend, and builds the recipient output and, when there is change, a change output that shows the sender (as the engine's change does). Notes from several trees, or more than `MAX_INPUTS` of them, make several transactions, each paying the recipient its part. `fill` supplies randomness in the engine's order, per transaction: sender random (when hidden) and note random per output, then the GCM and CTR IVs per ciphertext.
pub fn plan_transfer<'a>(
    keys: &WalletKeys,
    state: &rg_sync::SyncState,
    scan: &rg_wallet::ScanResult,
    req: &TransferRequest<'a>,
    mut fill: impl FnMut(&mut [u8]),
) -> Result<Vec<TransferParams<'a>>, Error> {
    let spend = Spend {
        token_hash: req.token_hash,
        value: req.value,
        wallet_source: req.wallet_source,
        chain_id: req.chain_id,
        min_gas_price: req.min_gas_price,
        broadcaster_fee: req.broadcaster_fee.clone(),
    };
    plan_spend(keys, state, scan, &spend, &mut fill, |value, fill| {
        let mut sender_random = rg_notes::transact::SENDER_RANDOM_NULL;
        if !req.show_sender_to_recipient {
            fill(&mut sender_random);
        }
        let mut random = [0u8; 16];
        fill(&mut random);
        let note = OutputNote {
            receiver_master_public_key: req.recipient.master_public_key,
            receiver_viewing_public_key: req.recipient.viewing_public_key,
            token_hash: req.token_hash,
            value,
            random,
            sender_random,
            output_type: OutputType::Transfer,
            wallet_source: req.wallet_source,
            memo_text: req.memo_text,
        };
        (vec![note], None)
    })
}

/// Never shows the sender, as the engine's fee notes do not.
fn fee_note<'a>(
    fee: &BroadcasterFee,
    token_hash: &[u8; 32],
    wallet_source: &'a str,
    fill: Fill,
) -> OutputNote<'a> {
    let mut sender_random = [0u8; 15];
    fill(&mut sender_random);
    let mut random = [0u8; 16];
    fill(&mut random);
    OutputNote {
        receiver_master_public_key: fee.recipient.master_public_key,
        receiver_viewing_public_key: fee.recipient.viewing_public_key,
        token_hash: *token_hash,
        value: fee.value,
        random,
        sender_random,
        output_type: OutputType::BroadcasterFee,
        wallet_source,
        memo_text: None,
    }
}

fn change_note<'a>(
    keys: &WalletKeys,
    token_hash: &[u8; 32],
    value: u128,
    wallet_source: &'a str,
    fill: Fill,
) -> OutputNote<'a> {
    let mut random = [0u8; 16];
    fill(&mut random);
    OutputNote {
        receiver_master_public_key: keys.master_public_key,
        receiver_viewing_public_key: keys.viewing_public_key,
        token_hash: *token_hash,
        value,
        random,
        sender_random: rg_notes::transact::SENDER_RANDOM_NULL,
        output_type: OutputType::Change,
        wallet_source,
        memo_text: None,
    }
}

fn with_ivs<'a>(notes: Vec<OutputNote<'a>>, fill: Fill) -> Vec<OutputPlan<'a>> {
    notes
        .into_iter()
        .map(|note| {
            let mut gcm_iv = [0u8; 16];
            let mut ctr_iv = [0u8; 16];
            fill(&mut gcm_iv);
            fill(&mut ctr_iv);
            OutputPlan {
                note,
                gcm_iv,
                ctr_iv,
            }
        })
        .collect()
}

/// Picks notes for an unshield, one transaction per note group, each unshielding its part to `to`. Any remainder comes back as a change note.
pub fn plan_unshield<'a>(
    keys: &WalletKeys,
    state: &rg_sync::SyncState,
    scan: &rg_wallet::ScanResult,
    req: &UnshieldRequest<'a>,
    mut fill: impl FnMut(&mut [u8]),
) -> Result<Vec<TransferParams<'a>>, Error> {
    let spend = Spend {
        token_hash: rg_notes::TokenData::erc20(req.token).hash(),
        value: req.value,
        wallet_source: req.wallet_source,
        chain_id: req.chain_id,
        min_gas_price: req.min_gas_price,
        broadcaster_fee: req.broadcaster_fee.clone(),
    };
    plan_spend(keys, state, scan, &spend, &mut fill, |value, _| {
        let unshield = UnshieldOutput {
            to: req.to,
            token: req.token,
            value,
        };
        (Vec::new(), Some(unshield))
    })
}

#[cfg(test)]
mod tests {
    use rg_wallet::{Txo, TxoSource};

    use super::*;
    use crate::fr_to_b256;

    fn txo(tree: u32, position: u32, value: u128) -> Txo {
        Txo {
            tree,
            position,
            commitment: [0; 32],
            token_hash: [1; 32],
            value,
            random: [0; 16],
            nullifier: [0; 32],
            source: TxoSource::Shield,
            block_number: 0,
            transaction_hash: [0; 32],
            spent: None,
            memo_text: None,
            sender_master_public_key: None,
        }
    }

    fn picked(notes: &[Txo], value: u128) -> Option<Vec<Vec<(u32, u32)>>> {
        select_notes(notes.iter(), &[1; 32], value).map(|groups| {
            groups
                .iter()
                .map(|g| g.iter().map(|t| (t.tree, t.position)).collect())
                .collect()
        })
    }

    #[test]
    fn one_covering_note_beats_several() {
        let notes = [txo(0, 0, 5), txo(0, 1, 9), txo(1, 0, 7)];
        assert_eq!(picked(&notes, 6), Some(vec![vec![(1, 0)]]));
    }

    #[test]
    fn several_notes_come_from_the_tree_needing_fewest() {
        let notes = [
            txo(0, 0, 5),
            txo(0, 1, 3),
            txo(0, 2, 2),
            txo(1, 0, 6),
            txo(1, 1, 4),
        ];
        assert_eq!(picked(&notes, 10), Some(vec![vec![(1, 0), (1, 1)]]));
    }

    #[test]
    fn notes_across_trees_make_one_transaction_per_tree() {
        let notes = [txo(0, 0, 5), txo(0, 1, 1), txo(1, 0, 4), txo(1, 1, 2)];
        assert_eq!(
            picked(&notes, 9),
            Some(vec![vec![(0, 0), (0, 1)], vec![(1, 0)]])
        );
        assert_eq!(picked(&notes, 13), None);
    }

    #[test]
    fn more_than_the_input_limit_splits_into_transactions() {
        let notes: Vec<_> = (0..=MAX_INPUTS as u32).map(|i| txo(0, i, 1)).collect();
        assert_eq!(
            picked(&notes, MAX_INPUTS as u128).map(|g| g[0].len()),
            Some(MAX_INPUTS)
        );
        let split = picked(&notes, MAX_INPUTS as u128 + 1).unwrap();
        assert_eq!(
            split.iter().map(Vec::len).collect::<Vec<_>>(),
            [MAX_INPUTS, 1]
        );
    }

    #[test]
    fn each_transaction_pays_its_part_and_the_last_keeps_the_change() {
        let keys = rg_keys::WalletKeys::from_private_keys(
            rg_primitives::PrivateKey::new([1; 32]),
            rg_primitives::PrivateKey::new([2; 32]),
        );
        let token = [7u8; 20];
        let token_hash = rg_notes::TokenData::erc20(token).hash();
        let mut state = rg_sync::SyncState::default();
        let mut txos = Vec::new();
        for (tree, value) in [(0u32, 6u128), (1, 5)] {
            let random = [tree as u8 + 1; 16];
            let npk = rg_notes::note::note_public_key(&keys.master_public_key, &random);
            let leaf = rg_notes::note::commitment(&npk, &token_hash, value);
            let mut merkle = rg_tree::MerkleTree::default();
            merkle.insert(0, &[leaf]).unwrap();
            state.trees.push(merkle);
            txos.push(Txo {
                tree,
                token_hash,
                value,
                random,
                ..txo(tree, 0, value)
            });
        }
        let scan = rg_wallet::ScanResult {
            txos,
            sent: Vec::new(),
        };
        let req = UnshieldRequest {
            to: [9; 20],
            token,
            value: 8,
            wallet_source: "test",
            chain_id: 1,
            min_gas_price: 0,
            broadcaster_fee: None,
        };
        let shape = |req: &UnshieldRequest| {
            let planned = plan_unshield(&keys, &state, &scan, req, |b| b.fill(3)).unwrap();
            for p in &planned {
                p.prepare(&keys).unwrap();
            }
            planned
                .iter()
                .map(|p| {
                    let notes = p.outputs.iter().map(|o| (o.note.output_type, o.note.value));
                    (p.tree, p.unshield.unwrap().value, notes.collect())
                })
                .collect::<Vec<(u16, u128, Vec<_>)>>()
        };
        assert_eq!(
            shape(&req),
            [(0, 6, vec![]), (1, 2, vec![(OutputType::Change, 3)])]
        );

        let fee = BroadcasterFee {
            recipient: rg_keys::decode_address(&keys.address().unwrap()).unwrap(),
            value: 2,
        };
        let with_fee = UnshieldRequest {
            value: 7,
            broadcaster_fee: Some(fee),
            ..req
        };
        assert_eq!(
            shape(&with_fee),
            [
                (0, 4, vec![(OutputType::BroadcasterFee, 2)]),
                (1, 3, vec![(OutputType::Change, 2)])
            ]
        );
    }

    // Expected value from engine 9.6.0's UnshieldNoteERC20.
    #[test]
    fn unshield_commitment_matches_the_engine() {
        let hex20 = |s: &str| -> [u8; 20] { hex::decode(s).unwrap().try_into().unwrap() };
        let unshield = UnshieldOutput {
            to: hex20("e28386e8b1dfdd13bedd548ac4e8e3d9736cbc28"),
            token: hex20("82af49447d8a07e3bd95bd0d56f35241523fbab1"),
            value: 30_000_000_000_000,
        };
        assert_eq!(
            hex::encode(fr_to_b256(&unshield.commitment())),
            "2ebd3cd6284519fb18f94eb02e1ac3a8c83077595ec775e4c513505f6af083df"
        );
    }
}
