/// `value` is a decimal string: amounts are `u128`, which UniFFI does not carry.
#[derive(uniffi::Record)]
pub struct TokenBalance {
    pub token: String,
    pub value: String,
}
