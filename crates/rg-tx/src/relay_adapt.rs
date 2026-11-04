//! The RelayAdapt contract (engine `relay-adapt-helper.ts` and `RelayAdaptV2Contract`): it wraps ETH before a shield, unwraps after an unshield to itself, and runs other contracts' calls between an unshield and a shield.

use alloy_primitives::{Address, B256, Bytes, FixedBytes, U256, keccak256};
use alloy_sol_types::{SolCall, SolValue};
use rg_keys::AddressData;
use rg_primitives::Fr;
use rg_sync::abi;

use crate::shield::shield_request;
use crate::{Error, fr_to_b256};

/// `MINIMUM_RELAY_ADAPT_CROSS_CONTRACT_CALLS_GAS_LIMIT_V2`: gas a relay with calls is sent with, so a broadcaster cannot starve the calls and still take its fee.
pub const CROSS_CONTRACT_MIN_GAS_LIMIT: u64 = 3_200_000;

/// `getMinimumGasLimitForContract`: the relay spends about this much before it checks `gasleft()` against the action's `minGasLimit`.
const RELAY_GAS_OVERHEAD: u64 = 150_000;

/// A call RelayAdapt makes during a relay, from its own address, with the tokens unshielded to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractCall {
    pub to: [u8; 20],
    pub data: Vec<u8>,
    /// Wei sent along, out of the ETH RelayAdapt holds.
    pub value: u128,
}

/// The adapt contract and parameters a transaction's bound params commit to, so only that contract can submit it, and only with those calls. Zero for a plain transaction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AdaptId {
    pub contract: [u8; 20],
    pub parameters: [u8; 32],
}

fn call(relay_adapt: [u8; 20], data: Vec<u8>) -> abi::Call {
    abi::Call {
        to: Address::from(relay_adapt),
        data: Bytes::from(data),
        value: U256::ZERO,
    }
}

/// `multicall(true, [wrapBase(value), shield([request])])`, to send to the RelayAdapt contract with `value` wei: it wraps the ETH and shields the wrapped token to `receiver`.
pub fn shield_base_token_calldata(
    relay_adapt: [u8; 20],
    receiver: &AddressData,
    wrapped_token: [u8; 20],
    value: u128,
    fill: impl FnMut(&mut [u8]),
) -> Result<Vec<u8>, Error> {
    let request = shield_request(receiver, wrapped_token, value, fill)?;
    let wrap = abi::wrapBaseCall {
        _amount: U256::from(value),
    };
    let shield = abi::shieldCall {
        _shieldRequests: vec![request],
    };
    Ok(abi::multicallCall {
        _requireSuccess: true,
        _calls: vec![
            call(relay_adapt, wrap.abi_encode()),
            call(relay_adapt, shield.abi_encode()),
        ],
    }
    .abi_encode())
}

/// What the RelayAdapt contract does once the transactions have unshielded the wrapped token to it: unwrap all of it, then send all its ETH to `to` (`getOrderedCallsForUnshieldBaseToken`). Broadcasters refuse a relay whose calls must succeed, so the engine requires success only when the sender pays gas from a public wallet.
pub fn unshield_base_token_action(
    relay_adapt: [u8; 20],
    to: [u8; 20],
    random: [u8; 31],
    require_success: bool,
) -> abi::ActionData {
    let unwrap = abi::unwrapBaseCall {
        _amount: U256::ZERO,
    };
    let send = abi::transferCall {
        _transfers: vec![abi::TokenTransfer {
            token: abi::TokenData {
                tokenType: 0,
                tokenAddress: Address::ZERO,
                tokenSubID: U256::ZERO,
            },
            to: Address::from(to),
            value: U256::ZERO,
        }],
    };
    abi::ActionData {
        random: FixedBytes::from(random),
        requireSuccess: require_success,
        minGasLimit: U256::ZERO,
        calls: vec![
            call(relay_adapt, unwrap.abi_encode()),
            call(relay_adapt, send.abi_encode()),
        ],
    }
}

/// A shield of RelayAdapt's whole balance of `token` to `receiver`, for the end of a relay (`createRelayShieldRequestsERC20s`).
pub fn relay_shield_request(
    receiver: &AddressData,
    token: [u8; 20],
    fill: impl FnMut(&mut [u8]),
) -> Result<abi::ShieldRequest, Error> {
    shield_request(receiver, token, 0, fill)
}

/// `getOrderedCallsForCrossContractCalls`: `calls`, then a shield of each of `shields`. The engine requires success except when a broadcaster submits, so the fee and shields still go through if a call fails; `min_gas_limit` is the gas the relay must be sent with.
pub fn cross_contract_calls_action(
    relay_adapt: [u8; 20],
    calls: &[ContractCall],
    shields: Vec<abi::ShieldRequest>,
    random: [u8; 31],
    require_success: bool,
    min_gas_limit: u64,
) -> abi::ActionData {
    let mut ordered: Vec<abi::Call> = calls
        .iter()
        .map(|c| abi::Call {
            to: Address::from(c.to),
            data: Bytes::from(c.data.clone()),
            value: U256::from(c.value),
        })
        .collect();
    if !shields.is_empty() {
        let shield = abi::shieldCall {
            _shieldRequests: shields,
        };
        ordered.push(call(relay_adapt, shield.abi_encode()));
    }
    abi::ActionData {
        random: FixedBytes::from(random),
        requireSuccess: require_success,
        minGasLimit: U256::from(min_gas_limit.saturating_sub(RELAY_GAS_OVERHEAD)),
        calls: ordered,
    }
}

/// `getRelayAdaptParams`: keccak of `abi.encode(nullifiers of each transaction, transaction count, action)`.
pub fn relay_adapt_params(nullifiers: &[Vec<Fr>], action: &abi::ActionData) -> [u8; 32] {
    let nullifiers: Vec<Vec<B256>> = nullifiers
        .iter()
        .map(|n| n.iter().map(fr_to_b256).collect())
        .collect();
    let count = U256::from(nullifiers.len());
    keccak256((nullifiers, count, action.clone()).abi_encode_params()).0
}

/// `relay(transactions, action)` for the RelayAdapt contract.
pub fn relay_calldata(transactions: Vec<abi::Transaction>, action: abi::ActionData) -> Vec<u8> {
    abi::relayCall {
        _transactions: transactions,
        _actionData: action,
    }
    .abi_encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Engine 9.6.0 `RelayAdaptHelper.getRelayAdaptParams` with the same calls, nullifiers and random.
    #[test]
    fn adapt_params_match_the_engine() {
        let relay = alloy_primitives::hex!("B4F2d77bD12c6b548Ae398244d7FAD4ABCE4D89b");
        let action = unshield_base_token_action(relay, [0x11; 20], [0xab; 31], true);
        let n = |b: u8| rg_primitives::field::from_be_bytes_mod_order(&[b; 32]);
        let params = relay_adapt_params(&[vec![n(1), n(2)], vec![n(3)]], &action);
        assert_eq!(
            hex::encode(params),
            "1a71bcd6f00496237ccfdbcd7908cb8a0fb1dbbb638e4b4adf0b0c72fb6b10c6"
        );
    }

    // Engine 9.6.0 `RelayAdaptV2Contract.getRelayAdaptParamsCrossContractCalls` with the same call, shield request, nullifiers and random, and its default gas limit, for a broadcaster and then for a public wallet.
    #[test]
    fn cross_contract_calls_match_the_engine() {
        let relay = alloy_primitives::hex!("B4F2d77bD12c6b548Ae398244d7FAD4ABCE4D89b");
        let calls = [ContractCall {
            to: [0x22; 20],
            data: vec![0xde, 0xad],
            value: 5,
        }];
        let shield = abi::ShieldRequest {
            preimage: abi::CommitmentPreimage {
                npk: B256::repeat_byte(0x44),
                token: abi::TokenData {
                    tokenType: 0,
                    tokenAddress: Address::repeat_byte(0x33),
                    tokenSubID: U256::ZERO,
                },
                value: alloy_primitives::Uint::ZERO,
            },
            ciphertext: abi::ShieldCiphertext {
                encryptedBundle: [0x55, 0x66, 0x77].map(B256::repeat_byte),
                shieldKey: B256::repeat_byte(0x88),
            },
        };
        let n = |b: u8| rg_primitives::field::from_be_bytes_mod_order(&[b; 32]);
        let nullifiers = [vec![n(1), n(2)], vec![n(3)]];
        let params = |require_success| {
            let action = cross_contract_calls_action(
                relay,
                &calls,
                vec![shield.clone()],
                [0xab; 31],
                require_success,
                CROSS_CONTRACT_MIN_GAS_LIMIT,
            );
            hex::encode(relay_adapt_params(&nullifiers, &action))
        };
        assert_eq!(
            params(false),
            "23769efa2431743f580de0aadcf75c31a7f390378fbda5e5f71afa215a85dd74"
        );
        assert_eq!(
            params(true),
            "d52c6cc044e50786f4370c05c8a8577a49fd6dcae5849986598ba01f1f51e7ca"
        );
    }
}
