//! `0zk` addresses (engine src/key-derivation/bech32.ts).
//!
//! Payload, 73 bytes: `version(1) || mpk(32 BE) || networkID(8) || viewingPub(32)`,
//! bech32m with HRP `0zk`. networkID is `chainType(1) || chainId(7 BE)`, or eight
//! 0xff bytes for "all chains", XORed with the 7 bytes of "railgun". The engine's
//! buffer-xor 2.0.2 XORs to the longer length, so the 8th byte passes through.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};
use rg_primitives::{field, Fr};

use crate::Error;

pub const ADDRESS_VERSION: u8 = 1;
pub const ADDRESS_LENGTH_LIMIT: usize = 127;
const PREFIX: &str = "0zk";
const PAYLOAD_LEN: usize = 73;
const ALL_CHAINS: [u8; 8] = [0xff; 8];
const XOR_MASK: &[u8; 7] = b"railgun";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chain {
    /// 0 = EVM.
    pub chain_type: u8,
    /// Encoded in 7 bytes.
    pub id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressData {
    pub master_public_key: Fr,
    pub viewing_public_key: [u8; 32],
    pub chain: Option<Chain>,
    pub version: u8,
}

fn network_id(chain: Option<Chain>) -> Result<[u8; 8], Error> {
    match chain {
        None => Ok(ALL_CHAINS),
        Some(c) => {
            if c.id >= 1 << 56 {
                return Err(Error::InvalidAddress("chain id exceeds 7 bytes"));
            }
            let mut out = [0u8; 8];
            out[0] = c.chain_type;
            out[1..].copy_from_slice(&c.id.to_be_bytes()[1..]);
            Ok(out)
        }
    }
}

fn xor_network_id(mut id: [u8; 8]) -> [u8; 8] {
    for (b, m) in id.iter_mut().zip(XOR_MASK) {
        *b ^= m;
    }
    id
}

pub fn encode_address(data: &AddressData) -> Result<String, Error> {
    let mut payload = Vec::with_capacity(PAYLOAD_LEN);
    // The engine always writes version 01, whatever AddressData.version says.
    payload.push(ADDRESS_VERSION);
    payload.extend_from_slice(&field::to_be_bytes(&data.master_public_key));
    payload.extend_from_slice(&xor_network_id(network_id(data.chain)?));
    payload.extend_from_slice(&data.viewing_public_key);
    let hrp = Hrp::parse(PREFIX).expect("valid hrp");
    let s =
        bech32::encode::<Bech32m>(hrp, &payload).map_err(|_| Error::InvalidAddress("encode"))?;
    debug_assert!(s.len() <= ADDRESS_LENGTH_LIMIT);
    Ok(s)
}

pub fn decode_address(address: &str) -> Result<AddressData, Error> {
    if address.len() > ADDRESS_LENGTH_LIMIT {
        return Err(Error::InvalidAddress("too long"));
    }
    let checked = CheckedHrpstring::new::<Bech32m>(address)
        .map_err(|_| Error::InvalidAddress("invalid checksum"))?;
    if checked.hrp().as_str() != PREFIX {
        return Err(Error::InvalidAddress("invalid prefix"));
    }
    let payload: Vec<u8> = checked.byte_iter().collect();
    if payload.len() != PAYLOAD_LEN {
        return Err(Error::InvalidAddress("wrong payload length"));
    }
    let version = payload[0];
    if version != ADDRESS_VERSION {
        return Err(Error::AddressVersion(version));
    }
    // The engine reads the mpk as a raw 256-bit integer; we reduce it into the field.
    let master_public_key = field::from_be_bytes_mod_order(&payload[1..33]);
    let mut net = [0u8; 8];
    net.copy_from_slice(&payload[33..41]);
    let net = xor_network_id(net);
    let chain = if net == ALL_CHAINS {
        None
    } else {
        let mut id = [0u8; 8];
        id[1..].copy_from_slice(&net[1..]);
        Some(Chain {
            chain_type: net[0],
            id: u64::from_be_bytes(id),
        })
    };
    let mut viewing_public_key = [0u8; 32];
    viewing_public_key.copy_from_slice(&payload[41..73]);
    Ok(AddressData {
        master_public_key,
        viewing_public_key,
        chain,
        version,
    })
}
