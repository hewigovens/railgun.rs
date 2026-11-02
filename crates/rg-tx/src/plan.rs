use rg_keys::{AddressData, WalletKeys};
use rg_notes::OutputType;
use rg_notes::transact::OutputNote;

use crate::{Error, OutputPlan, SpendNote, TransferParams, UnshieldOutput};

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
}

/// An unshield of an ERC20 from a wallet scan.
pub struct UnshieldRequest<'a> {
    pub to: [u8; 20],
    pub token: [u8; 20],
    pub value: u128,
    pub wallet_source: &'a str,
    pub chain_id: u64,
    pub min_gas_price: u128,
}

/// Most inputs in one transaction, the engine's limit.
pub const MAX_INPUTS: usize = 10;

/// The notes to spend: the smallest single note that covers `value`, else the largest notes of one tree, since a transaction proves against one root. The tree needing the fewest notes wins.
pub fn select_notes<'s>(
    unspent: impl Iterator<Item = &'s rg_wallet::Txo>,
    token_hash: &[u8; 32],
    value: u128,
) -> Option<Vec<&'s rg_wallet::Txo>> {
    let notes: Vec<_> = unspent.filter(|t| &t.token_hash == token_hash).collect();
    if let Some(one) = notes
        .iter()
        .filter(|t| t.value >= value)
        .min_by_key(|t| (t.value, t.tree, t.position))
    {
        return Some(vec![*one]);
    }
    let mut trees: Vec<u32> = notes.iter().map(|t| t.tree).collect();
    trees.sort_unstable();
    trees.dedup();
    trees
        .into_iter()
        .filter_map(|tree| {
            let mut in_tree: Vec<_> = notes.iter().copied().filter(|t| t.tree == tree).collect();
            in_tree.sort_by_key(|t| (std::cmp::Reverse(t.value), t.position));
            let mut sum = 0u128;
            let count = in_tree.iter().take(MAX_INPUTS).position(|t| {
                sum += t.value;
                sum >= value
            })?;
            in_tree.truncate(count + 1);
            Some(in_tree)
        })
        .min_by_key(Vec::len)
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
    Ok((inputs, notes.iter().map(|t| t.value).sum()))
}

/// Picks the notes to spend, and builds the recipient output and, when there is change, a change output that shows the sender (as the engine's change does). `fill` supplies randomness in the engine's order: sender random (when hidden) and note random per output, then the GCM and CTR IVs per ciphertext.
pub fn plan_transfer<'a>(
    keys: &WalletKeys,
    state: &rg_sync::SyncState,
    scan: &rg_wallet::ScanResult,
    req: &TransferRequest<'a>,
    mut fill: impl FnMut(&mut [u8]),
) -> Result<TransferParams<'a>, Error> {
    if req.value == 0 {
        return Err(Error::ZeroValue);
    }
    let notes = select_notes(scan.unspent(), &req.token_hash, req.value)
        .ok_or(Error::InsufficientNote(req.value))?;
    let (inputs, total) = spend_notes(state, &notes)?;
    let change = total - req.value;

    let mut sender_random = rg_notes::transact::SENDER_RANDOM_NULL;
    if !req.show_sender_to_recipient {
        fill(&mut sender_random);
    }
    let mut random = [0u8; 16];
    fill(&mut random);
    let mut outs = vec![OutputNote {
        receiver_master_public_key: req.recipient.master_public_key,
        receiver_viewing_public_key: req.recipient.viewing_public_key,
        token_hash: req.token_hash,
        value: req.value,
        random,
        sender_random,
        output_type: OutputType::Transfer,
        wallet_source: req.wallet_source,
        memo_text: req.memo_text,
    }];
    if change > 0 {
        outs.push(change_note(
            keys,
            &req.token_hash,
            change,
            req.wallet_source,
            &mut fill,
        ));
    }
    let root = inputs[0].proof.root;
    Ok(TransferParams {
        tree: notes[0].tree as u16,
        merkle_root: root,
        token_hash: req.token_hash,
        chain_id: req.chain_id,
        min_gas_price: req.min_gas_price,
        inputs,
        outputs: with_ivs(outs, &mut fill),
        unshield: None,
    })
}

fn change_note<'a>(
    keys: &WalletKeys,
    token_hash: &[u8; 32],
    value: u128,
    wallet_source: &'a str,
    fill: &mut impl FnMut(&mut [u8]),
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

fn with_ivs<'a>(
    notes: Vec<OutputNote<'a>>,
    fill: &mut impl FnMut(&mut [u8]),
) -> Vec<OutputPlan<'a>> {
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

/// Picks notes for an unshield. Any remainder comes back as a change note.
pub fn plan_unshield<'a>(
    keys: &WalletKeys,
    state: &rg_sync::SyncState,
    scan: &rg_wallet::ScanResult,
    req: &UnshieldRequest<'a>,
    mut fill: impl FnMut(&mut [u8]),
) -> Result<TransferParams<'a>, Error> {
    if req.value == 0 {
        return Err(Error::ZeroValue);
    }
    let token_hash = rg_notes::TokenData::erc20(req.token).hash();
    let notes = select_notes(scan.unspent(), &token_hash, req.value)
        .ok_or(Error::InsufficientNote(req.value))?;
    let (inputs, total) = spend_notes(state, &notes)?;
    let change = total - req.value;
    let mut outs = Vec::new();
    if change > 0 {
        outs.push(change_note(
            keys,
            &token_hash,
            change,
            req.wallet_source,
            &mut fill,
        ));
    }
    let root = inputs[0].proof.root;
    Ok(TransferParams {
        tree: notes[0].tree as u16,
        merkle_root: root,
        token_hash,
        chain_id: req.chain_id,
        min_gas_price: req.min_gas_price,
        inputs,
        outputs: with_ivs(outs, &mut fill),
        unshield: Some(UnshieldOutput {
            to: req.to,
            token: req.token,
            value: req.value,
        }),
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

    fn picked(notes: &[Txo], value: u128) -> Option<Vec<(u32, u32)>> {
        select_notes(notes.iter(), &[1; 32], value)
            .map(|v| v.iter().map(|t| (t.tree, t.position)).collect())
    }

    #[test]
    fn one_covering_note_beats_several() {
        let notes = [txo(0, 0, 5), txo(0, 1, 9), txo(1, 0, 7)];
        assert_eq!(picked(&notes, 6), Some(vec![(1, 0)]));
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
        assert_eq!(picked(&notes, 10), Some(vec![(1, 0), (1, 1)]));
    }

    #[test]
    fn notes_split_across_trees_cannot_be_combined() {
        let notes = [txo(0, 0, 5), txo(1, 0, 5)];
        assert_eq!(picked(&notes, 9), None);
    }

    #[test]
    fn more_than_the_input_limit_is_refused() {
        let notes: Vec<_> = (0..=MAX_INPUTS as u32).map(|i| txo(0, i, 1)).collect();
        assert_eq!(picked(&notes, MAX_INPUTS as u128 + 1), None);
        assert_eq!(
            picked(&notes, MAX_INPUTS as u128).map(|v| v.len()),
            Some(MAX_INPUTS)
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
