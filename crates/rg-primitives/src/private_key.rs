use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// 32 secret bytes. Unlike `[u8; 32]` it is not `Copy` and never prints, and it is wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey([u8; 32]);

impl PrivateKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        PrivateKey(bytes)
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(..)")
    }
}
