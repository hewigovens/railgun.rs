use alloy_primitives::{Address, U256};
use rg_notes::note;
use rg_primitives::Fr;
use rg_primitives::field::from_be_bytes_mod_order;
use rg_sync::abi;

use crate::fr_to_b256;

/// An ERC20 leaving the pool. The contract takes its fee out of `value`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnshieldOutput {
    pub to: [u8; 20],
    pub token: [u8; 20],
    pub value: u128,
}

pub(crate) fn address_field(address: &[u8; 20]) -> Fr {
    from_be_bytes_mod_order(address)
}

impl UnshieldOutput {
    /// `UnshieldNote`: the npk is the address, the rest is a normal commitment.
    pub fn commitment(&self) -> Fr {
        let token_hash = rg_notes::TokenData::erc20(self.token).hash();
        note::commitment(&address_field(&self.to), &token_hash, self.value)
    }

    pub(crate) fn preimage(&self) -> abi::CommitmentPreimage {
        abi::CommitmentPreimage {
            npk: fr_to_b256(&address_field(&self.to)),
            token: abi::TokenData {
                tokenType: 0,
                tokenAddress: Address::from(self.token),
                tokenSubID: U256::ZERO,
            },
            value: alloy_primitives::Uint::from(self.value),
        }
    }
}
