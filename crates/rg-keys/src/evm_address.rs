use std::fmt;
use std::str::FromStr;

use tiny_keccak::{Hasher, Keccak};

use crate::Error;

/// A 20-byte Ethereum address. Parses `0x` hex, and checks the EIP-55 checksum when the letters are mixed case; displays checksummed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EvmAddress(pub [u8; 20]);

pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    let mut keccak = Keccak::v256();
    keccak.update(data);
    keccak.finalize(&mut hash);
    hash
}

impl EvmAddress {
    /// EIP-55: a hex letter is upper case when the matching nibble of keccak256(lowercase hex) is 8 or more.
    fn checksummed(lower: &str) -> String {
        let hash = keccak256(lower.as_bytes());
        lower
            .chars()
            .enumerate()
            .map(|(i, c)| {
                let nibble = (hash[i / 2] >> (4 * (1 - i % 2))) & 0xf;
                if nibble >= 8 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect()
    }
}

impl FromStr for EvmAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let bad = |why| Error::InvalidEvmAddress(why);
        let digits = s.strip_prefix("0x").ok_or(bad("no 0x prefix"))?;
        if digits.len() != 40 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(bad("not 40 hex digits"));
        }
        let lower = digits.to_ascii_lowercase();
        let mixed = digits != lower && digits != digits.to_ascii_uppercase();
        if mixed && digits != Self::checksummed(&lower) {
            return Err(bad("checksum does not match"));
        }
        let mut bytes = [0u8; 20];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&lower[2 * i..2 * i + 2], 16).map_err(|_| bad("not hex"))?;
        }
        Ok(EvmAddress(bytes))
    }
}

impl fmt::Display for EvmAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lower: String = self.0.iter().map(|b| format!("{b:02x}")).collect();
        write!(f, "0x{}", Self::checksummed(&lower))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // From EIP-55.
    const CHECKSUMMED: [&str; 4] = [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ];

    #[test]
    fn round_trips_eip55_addresses() {
        for s in CHECKSUMMED {
            assert_eq!(s.parse::<EvmAddress>().unwrap().to_string(), s);
        }
    }

    #[test]
    fn accepts_one_case_and_rejects_a_bad_checksum() {
        let s = CHECKSUMMED[0];
        let address: EvmAddress = s.parse().unwrap();
        assert_eq!(s.to_lowercase().parse::<EvmAddress>().unwrap(), address);
        assert_eq!(
            format!("0x{}", s[2..].to_uppercase())
                .parse::<EvmAddress>()
                .unwrap(),
            address
        );
        let flipped = s.replacen('a', "A", 1);
        assert!(flipped.parse::<EvmAddress>().is_err());
        assert!(
            "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
                .parse::<EvmAddress>()
                .is_err()
        );
        assert!(
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeA"
                .parse::<EvmAddress>()
                .is_err()
        );
    }
}
