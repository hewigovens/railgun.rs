//! BN254 scalar field helpers. Railgun treats 32-byte values as big-endian
//! integers and reduces them mod p wherever they enter a hash.

use ark_ff::{BigInteger, PrimeField};

use crate::Fr;

/// Big-endian bytes to a field element, reduced mod p.
pub fn from_be_bytes_mod_order(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// Field element to 32 big-endian bytes.
pub fn to_be_bytes(value: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&value.into_bigint().to_bytes_be());
    out
}

/// Field element to 32 little-endian bytes.
pub fn to_le_bytes(value: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&value.into_bigint().to_bytes_le());
    out
}

/// Decimal string to a field element, reduced mod p. Used by tests and vectors.
pub fn from_decimal(s: &str) -> Option<Fr> {
    let mut acc = Fr::from(0u64);
    let ten = Fr::from(10u64);
    if s.is_empty() {
        return None;
    }
    for c in s.chars() {
        let d = c.to_digit(10)?;
        acc = acc * ten + Fr::from(u64::from(d));
    }
    Some(acc)
}

/// Field element to its canonical decimal string.
pub fn to_decimal(value: &Fr) -> String {
    value.into_bigint().to_string()
}
