//! Wallet source names (`wallet/wallet-info.ts`): lowercase base 37 over
//! `' 0123456789abcdefghijklmnopqrstuvwxyz'`, at most 16 characters.
//! Leading spaces don't survive a round trip, as in the engine.

use crate::Error;

const CHARSET: &[u8; 37] = b" 0123456789abcdefghijklmnopqrstuvwxyz";
pub const MAX_LENGTH: usize = 16;

/// The wallet source as an integer (37^16 < 2^84). The empty string is 0.
pub fn encode(source: &str) -> Result<u128, Error> {
    let lower = source.to_lowercase();
    if lower.chars().count() > MAX_LENGTH {
        return Err(Error::WalletSource(source.to_string()));
    }
    let mut n: u128 = 0;
    for c in lower.chars() {
        let i = CHARSET
            .iter()
            .position(|&b| c.is_ascii() && b == c as u8)
            .ok_or_else(|| Error::WalletSource(source.to_string()))?;
        n = n * 37 + i as u128;
    }
    Ok(n)
}

/// The engine's hex string for a wallet source. Its padding branch is inverted,
/// so non-empty results always have odd length; frozen behaviour.
pub fn encode_hex(source: &str) -> Result<String, Error> {
    if source.is_empty() {
        return Ok(String::new());
    }
    let h = format!("{:x}", encode(source)?);
    Ok(if h.len() % 2 == 1 { h } else { format!("0{h}") })
}

/// Decodes a big-endian integer of any length.
pub fn decode(bytes_be: &[u8]) -> String {
    let mut digits = bytes_be.to_vec();
    let mut out = Vec::new();
    while digits.iter().any(|&b| b != 0) {
        let mut rem = 0u32;
        for d in digits.iter_mut() {
            let cur = (rem << 8) | *d as u32;
            *d = (cur / 37) as u8;
            rem = cur % 37;
        }
        out.push(CHARSET[rem as usize]);
    }
    out.reverse();
    String::from_utf8(out).expect("ascii charset")
}
