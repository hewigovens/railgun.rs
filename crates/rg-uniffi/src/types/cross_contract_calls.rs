use rg_core::ContractCall;

use crate::RailgunError;
use crate::client::{address, amount};

/// A token and an amount, as a decimal string.
#[derive(uniffi::Record)]
pub struct TokenAmount {
    pub token: String,
    pub value: String,
}

/// A call RelayAdapt makes from its own address. `value` is the wei it sends along, as a decimal string.
#[derive(uniffi::Record)]
pub struct RelayCall {
    pub to: String,
    pub data: Vec<u8>,
    pub value: String,
}

/// Tokens unshielded to RelayAdapt, the calls it then makes with them, such as an approve and a swap, and the tokens whose whole balance it shields back to `shield_receiver`. The contract keeps its fee from each unshield, so RelayAdapt receives slightly less. `min_gas_limit` is the least gas the relay is sent with: at least 3,200,000, more if the calls need it.
#[derive(uniffi::Record)]
pub struct CrossContractCalls {
    pub unshields: Vec<TokenAmount>,
    pub calls: Vec<RelayCall>,
    pub shields: Vec<String>,
    pub shield_receiver: String,
    pub min_gas_limit: u64,
}

impl CrossContractCalls {
    pub(crate) fn to_core(&self) -> Result<rg_core::CrossContractCalls<'_>, RailgunError> {
        Ok(rg_core::CrossContractCalls {
            unshields: self
                .unshields
                .iter()
                .map(|u| Ok((address(&u.token)?, amount(&u.value)?)))
                .collect::<Result<_, RailgunError>>()?,
            calls: self
                .calls
                .iter()
                .map(|c| {
                    Ok(ContractCall {
                        to: address(&c.to)?,
                        data: c.data.clone(),
                        value: amount(&c.value)?,
                    })
                })
                .collect::<Result<_, RailgunError>>()?,
            shields: self
                .shields
                .iter()
                .map(|t| address(t))
                .collect::<Result<_, _>>()?,
            shield_receiver: &self.shield_receiver,
            min_gas_limit: self.min_gas_limit,
        })
    }
}
