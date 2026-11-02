//! Calldata to shield an ERC20 into a 0zk address.

use alloy_primitives::{Address, B256, FixedBytes, U256};
use alloy_sol_types::SolCall;
use rg_keys::AddressData;
use rg_notes::note::note_public_key;
use rg_notes::shield::encrypt_shield;
use rg_primitives::field::to_be_bytes;
use rg_sync::abi;

use crate::Error;

/// `proxy.shield([...])` for `value` of `token`, payable to `receiver`. The caller must have approved the proxy for `value`. `fill` supplies randomness.
///
/// The SDK derives the shield key from a wallet signature so the shielder can find its own shield later. The receiver does not need it, so here it is random.
pub fn shield_calldata(
    receiver: &AddressData,
    token: [u8; 20],
    value: u128,
    mut fill: impl FnMut(&mut [u8]),
) -> Result<Vec<u8>, Error> {
    let (mut shield_key, mut random, mut gcm_iv, mut ctr_iv) =
        ([0u8; 32], [0u8; 16], [0u8; 16], [0u8; 16]);
    fill(&mut shield_key);
    fill(&mut random);
    fill(&mut gcm_iv);
    fill(&mut ctr_iv);

    let npk = note_public_key(&receiver.master_public_key, &random);
    let cipher = encrypt_shield(
        &shield_key,
        &receiver.viewing_public_key,
        &random,
        &gcm_iv,
        &ctr_iv,
    )?;
    let request = abi::ShieldRequest {
        preimage: abi::CommitmentPreimage {
            npk: B256::from(to_be_bytes(&npk)),
            token: abi::TokenData {
                tokenType: 0,
                tokenAddress: Address::from(token),
                tokenSubID: U256::ZERO,
            },
            value: alloy_primitives::Uint::from(value),
        },
        ciphertext: abi::ShieldCiphertext {
            encryptedBundle: cipher.encrypted_bundle.map(FixedBytes::from),
            shieldKey: B256::from(cipher.shield_key),
        },
    };
    Ok(abi::shieldCall {
        _shieldRequests: vec![request],
    }
    .abi_encode())
}

/// `token.approve(spender, value)`.
pub fn approve_calldata(spender: [u8; 20], value: u128) -> Vec<u8> {
    abi::approveCall {
        spender: Address::from(spender),
        amount: U256::from(value),
    }
    .abi_encode()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rg_keys::WalletKeys;
    use rg_notes::shield::decrypt_random;
    use rg_primitives::ed25519::shared_key;

    #[test]
    fn receiver_recovers_the_note_random() {
        let keys = WalletKeys::from_mnemonic(
            "test test test test test test test test test test test junk",
            "",
            0,
        )
        .unwrap();
        let receiver = AddressData {
            master_public_key: keys.master_public_key,
            viewing_public_key: keys.viewing_public_key,
            chain: None,
            version: rg_keys::address::ADDRESS_VERSION,
        };
        let mut n = 0u8;
        let data = shield_calldata(&receiver, [7; 20], 1000, |b| {
            b.iter_mut().for_each(|x| {
                n = n.wrapping_add(1);
                *x = n
            })
        })
        .unwrap();

        let call = abi::shieldCall::abi_decode(&data).unwrap();
        let req = &call._shieldRequests[0];
        assert_eq!(req.preimage.value.to::<u128>(), 1000);
        let bundle = req.ciphertext.encryptedBundle.map(|b| b.0);
        let key = shared_key(
            keys.viewing_private_key.expose(),
            &req.ciphertext.shieldKey.0,
        )
        .unwrap();
        let random = decrypt_random(&bundle, &key).unwrap();
        let npk = note_public_key(&keys.master_public_key, &random);
        assert_eq!(req.preimage.npk.0, to_be_bytes(&npk));
    }
}
