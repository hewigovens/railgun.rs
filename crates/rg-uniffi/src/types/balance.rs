use rg_core::Balance;
use rg_keys::EvmAddress;

/// One token's unspent value by POI status, as decimal strings: amounts are `u128`, which UniFFI does not carry. Only `spendable` can go into a transfer or an unshield.
#[derive(uniffi::Record)]
pub struct TokenBalance {
    pub token: String,
    pub spendable: String,
    /// Shields the list provider has not screened yet, usually within an hour.
    pub shield_pending: String,
    pub shield_blocked: String,
    /// POI submitted, not yet in the list.
    pub proof_submitted: String,
    /// From this wallet's own transactions with no POI proof yet: `prove_poi` and `submit_poi` fix it.
    pub missing_internal: String,
    /// From other wallets that have not submitted POI.
    pub missing_external: String,
}

impl From<Balance> for TokenBalance {
    fn from(b: Balance) -> Self {
        let token: [u8; 20] = b.token_hash[12..].try_into().expect("20 bytes");
        TokenBalance {
            token: EvmAddress(token).to_string(),
            spendable: b.spendable.to_string(),
            shield_pending: b.shield_pending.to_string(),
            shield_blocked: b.shield_blocked.to_string(),
            proof_submitted: b.proof_submitted.to_string(),
            missing_internal: b.missing_internal.to_string(),
            missing_external: b.missing_external.to_string(),
        }
    }
}
