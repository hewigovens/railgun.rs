//! Token data and its hash (`note/note-util.ts`).

use ark_ff::{BigInteger, PrimeField};
use rg_primitives::Fr;
use tiny_keccak::{Hasher, Keccak};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TokenType {
    Erc20 = 0,
    Erc721 = 1,
    Erc1155 = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenData {
    pub token_type: TokenType,
    pub address: [u8; 20],
    /// Big-endian; zero for ERC20.
    pub sub_id: [u8; 32],
}

impl TokenData {
    pub fn erc20(address: [u8; 20]) -> Self {
        TokenData {
            token_type: TokenType::Erc20,
            address,
            sub_id: [0; 32],
        }
    }

    /// ERC20: the address left-padded to 32 bytes. NFTs:
    /// `keccak256(be32(type) || pad32(address) || subID) mod p`.
    pub fn hash(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        match self.token_type {
            TokenType::Erc20 => out[12..].copy_from_slice(&self.address),
            TokenType::Erc721 | TokenType::Erc1155 => {
                let mut pre = [0u8; 96];
                pre[31] = self.token_type as u8;
                pre[44..64].copy_from_slice(&self.address);
                pre[64..].copy_from_slice(&self.sub_id);
                let mut k = Keccak::v256();
                k.update(&pre);
                let mut h = [0u8; 32];
                k.finalize(&mut h);
                let reduced = Fr::from_be_bytes_mod_order(&h).into_bigint().to_bytes_be();
                out.copy_from_slice(&reduced);
            }
        }
        out
    }
}
