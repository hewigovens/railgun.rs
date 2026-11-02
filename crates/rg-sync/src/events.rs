//! Decoded RailgunSmartWallet events (V2.1, the only format on Sepolia; the legacy pre-March-2023 events of other chains are not handled yet).

use alloy_primitives::U256;
use alloy_sol_types::{SolCall, SolEvent};
use rg_notes::shield::ShieldCiphertext;
use rg_notes::transact::CommitmentCiphertextV2;
use rg_notes::{TokenData, TokenType};
use rg_primitives::{Fr, field};

use crate::Error;
use crate::abi;
use crate::log::RawLog;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldCommitment {
    pub npk: [u8; 32],
    pub token: TokenData,
    /// Value after the shield fee.
    pub value: u128,
    pub ciphertext: ShieldCiphertext,
    /// Big-endian; zero when the event has no fee for this entry.
    pub fee: [u8; 32],
}

impl ShieldCommitment {
    /// `poseidon([npk, tokenHash, value])`.
    pub fn hash(&self) -> Fr {
        rg_notes::note::commitment(
            &field::from_be_bytes_mod_order(&self.npk),
            &self.token.hash(),
            self.value,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactCommitment {
    pub hash: [u8; 32],
    pub ciphertext: CommitmentCiphertextV2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RailgunEvent {
    Shield {
        tree: u32,
        start: u32,
        commitments: Vec<ShieldCommitment>,
    },
    Transact {
        tree: u32,
        start: u32,
        commitments: Vec<TransactCommitment>,
    },
    Nullified {
        tree: u16,
        nullifiers: Vec<[u8; 32]>,
    },
    Unshield {
        to: [u8; 20],
        token: TokenData,
        amount: [u8; 32],
        fee: [u8; 32],
    },
}

fn small(v: U256, what: &'static str) -> Result<u32, Error> {
    u32::try_from(v).map_err(|_| Error::Range(what))
}

fn token(t: &abi::TokenData) -> Result<TokenData, Error> {
    let token_type = match t.tokenType {
        0 => TokenType::Erc20,
        1 => TokenType::Erc721,
        2 => TokenType::Erc1155,
        x => return Err(Error::TokenType(x)),
    };
    Ok(TokenData {
        token_type,
        address: t.tokenAddress.into_array(),
        sub_id: t.tokenSubID.to_be_bytes(),
    })
}

fn ciphertext(c: &abi::CommitmentCiphertext) -> CommitmentCiphertextV2 {
    CommitmentCiphertextV2 {
        ciphertext: c.ciphertext.map(|w| w.0),
        blinded_sender_viewing_key: c.blindedSenderViewingKey.0,
        blinded_receiver_viewing_key: c.blindedReceiverViewingKey.0,
        annotation_data: c.annotationData.to_vec(),
        memo: c.memo.to_vec(),
    }
}

fn abi_err(e: alloy_sol_types::Error) -> Error {
    Error::Abi(e.to_string())
}

/// Decodes one proxy log. Events this crate does not track decode to none.
pub fn decode_log(log: &RawLog) -> Result<Option<RailgunEvent>, Error> {
    let Some(topic0) = log.topics.first() else {
        return Ok(None);
    };
    let topics = log.topics.iter().map(|t| alloy_primitives::B256::from(*t));
    let ev = if *topic0 == abi::Shield::SIGNATURE_HASH.0 {
        let e = abi::Shield::decode_raw_log(topics, &log.data).map_err(abi_err)?;
        if e.commitments.len() != e.shieldCiphertext.len() {
            return Err(Error::Abi(
                "shield commitments and ciphertexts differ in length".into(),
            ));
        }
        let commitments = e
            .commitments
            .iter()
            .zip(&e.shieldCiphertext)
            .enumerate()
            .map(|(i, (p, c))| {
                Ok(ShieldCommitment {
                    npk: p.npk.0,
                    token: token(&p.token)?,
                    value: p.value.to::<u128>(),
                    ciphertext: ShieldCiphertext {
                        encrypted_bundle: c.encryptedBundle.map(|w| w.0),
                        shield_key: c.shieldKey.0,
                    },
                    fee: e.fees.get(i).copied().unwrap_or_default().to_be_bytes(),
                })
            })
            .collect::<Result<_, Error>>()?;
        RailgunEvent::Shield {
            tree: small(e.treeNumber, "tree number")?,
            start: small(e.startPosition, "start position")?,
            commitments,
        }
    } else if *topic0 == abi::Transact::SIGNATURE_HASH.0 {
        let e = abi::Transact::decode_raw_log(topics, &log.data).map_err(abi_err)?;
        if e.hash.len() != e.ciphertext.len() {
            return Err(Error::Abi(
                "transact hashes and ciphertexts differ in length".into(),
            ));
        }
        RailgunEvent::Transact {
            tree: small(e.treeNumber, "tree number")?,
            start: small(e.startPosition, "start position")?,
            commitments: e
                .hash
                .iter()
                .zip(&e.ciphertext)
                .map(|(h, c)| TransactCommitment {
                    hash: h.0,
                    ciphertext: ciphertext(c),
                })
                .collect(),
        }
    } else if *topic0 == abi::Nullified::SIGNATURE_HASH.0 {
        let e = abi::Nullified::decode_raw_log(topics, &log.data).map_err(abi_err)?;
        RailgunEvent::Nullified {
            tree: e.treeNumber,
            nullifiers: e.nullifier.iter().map(|n| n.0).collect(),
        }
    } else if *topic0 == abi::Unshield::SIGNATURE_HASH.0 {
        let e = abi::Unshield::decode_raw_log(topics, &log.data).map_err(abi_err)?;
        RailgunEvent::Unshield {
            to: e.to.into_array(),
            token: token(&e.token)?,
            amount: e.amount.to_be_bytes(),
            fee: e.fee.to_be_bytes(),
        }
    } else {
        return Ok(None);
    };
    Ok(Some(ev))
}

/// The Merkle root each transaction in a `transact` call proved against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionRoot {
    pub tree: u16,
    pub root: [u8; 32],
}

/// Decodes `transact(Transaction[])` calldata into the roots it uses. Returns none when the input is not a `transact` call.
pub fn decode_transact_call(input: &[u8]) -> Result<Option<Vec<TransactionRoot>>, Error> {
    if input.len() < 4 || input[..4] != abi::transactCall::SELECTOR {
        return Ok(None);
    }
    let call = abi::transactCall::abi_decode(input).map_err(abi_err)?;
    Ok(Some(
        call._transactions
            .iter()
            .map(|t| TransactionRoot {
                tree: t.boundParams.treeNumber,
                root: t.merkleRoot.0,
            })
            .collect(),
    ))
}
