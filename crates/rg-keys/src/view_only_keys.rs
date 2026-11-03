use std::fmt;

use rg_primitives::babyjubjub::{self, Point};
use rg_primitives::{Fr, PrivateKey};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Error;
use crate::address::{ADDRESS_VERSION, AddressData, encode_address};
use crate::keys::{master_public_key, nullifying_key, viewing_public_key};

/// What a wallet needs to find and read its notes, without the spending key: scanning, balances, history and the address, but no transfers or POI proofs. Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ViewOnlyKeys {
    pub viewing_private_key: PrivateKey,
    #[zeroize(skip)]
    pub viewing_public_key: [u8; 32],
    pub nullifying_key: Fr,
    #[zeroize(skip)]
    pub spending_public_key: Point,
    #[zeroize(skip)]
    pub master_public_key: Fr,
}

impl fmt::Debug for ViewOnlyKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ViewOnlyKeys")
            .field("master_public_key", &self.master_public_key)
            .finish_non_exhaustive()
    }
}

impl ViewOnlyKeys {
    pub fn new(viewing_private_key: PrivateKey, spending_public_key: Point) -> Self {
        let viewing_public_key = viewing_public_key(viewing_private_key.expose());
        let nullifying_key = nullifying_key(viewing_private_key.expose());
        let master_public_key = master_public_key(&spending_public_key, &nullifying_key);
        ViewOnlyKeys {
            viewing_private_key,
            viewing_public_key,
            nullifying_key,
            spending_public_key,
            master_public_key,
        }
    }

    /// The 0zk address, valid on every chain.
    pub fn address(&self) -> Result<String, Error> {
        encode_address(&AddressData {
            master_public_key: self.master_public_key,
            viewing_public_key: self.viewing_public_key,
            chain: None,
            version: ADDRESS_VERSION,
        })
    }

    /// The engine's shareable viewing key: hex of the msgpack map `{vpriv, spub}`, each a 64-digit hex string, `spub` the packed spending public key. It reveals every note and transaction of the wallet.
    pub fn shareable_viewing_key(&self) -> Zeroizing<String> {
        let vpriv = Zeroizing::new(hex::encode(self.viewing_private_key.expose()));
        let spub = hex::encode(self.spending_public_key.pack());
        let mut packed = Zeroizing::new(vec![0x82]);
        for (key, value) in [("vpriv", vpriv.as_str()), ("spub", spub.as_str())] {
            packed.push(0xa0 | key.len() as u8);
            packed.extend_from_slice(key.as_bytes());
            packed.extend_from_slice(&[0xd9, value.len() as u8]);
            packed.extend_from_slice(value.as_bytes());
        }
        Zeroizing::new(hex::encode(&*packed))
    }

    pub fn from_shareable_viewing_key(key: &str) -> Result<Self, Error> {
        let packed = Zeroizing::new(hex::decode(key).map_err(|_| Error::InvalidViewingKey)?);
        let (vpriv, spub) = shareable_fields(&packed).ok_or(Error::InvalidViewingKey)?;
        let spending_public_key =
            babyjubjub::Point::unpack(&spub).map_err(|_| Error::InvalidViewingKey)?;
        Ok(ViewOnlyKeys::new(vpriv, spending_public_key))
    }
}

/// `vpriv` and `spub` from the msgpack map, which must hold exactly those two.
fn shareable_fields(packed: &[u8]) -> Option<(PrivateKey, [u8; 32])> {
    let (mut vpriv, mut spub) = (None, None);
    let mut rest = packed.strip_prefix(&[0x82])?;
    for _ in 0..2 {
        let (name, after) = msgpack_str(rest)?;
        let (value, after) = msgpack_str(after)?;
        rest = after;
        let bytes: [u8; 32] = Zeroizing::new(hex::decode(value).ok()?)
            .as_slice()
            .try_into()
            .ok()?;
        match name {
            b"vpriv" => vpriv = Some(PrivateKey::new(bytes)),
            b"spub" => spub = Some(bytes),
            _ => return None,
        }
    }
    rest.is_empty().then_some(())?;
    Some((vpriv?, spub?))
}

/// One msgpack string (fixstr, str8 or str16) and what follows it.
fn msgpack_str(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let (len, rest) = match tag {
        0xa0..=0xbf => (usize::from(tag & 0x1f), rest),
        0xd9 => (usize::from(*rest.first()?), &rest[1..]),
        0xda => (
            usize::from(u16::from_be_bytes([*rest.first()?, *rest.get(1)?])),
            &rest[2..],
        ),
        _ => return None,
    };
    (rest.len() >= len).then(|| rest.split_at(len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WalletKeys;

    // Engine 9.6.0 `generateShareableViewingKey` for the Hardhat test mnemonic.
    const SHAREABLE: &str = "82a57670726976d94039646134623466306235343933613662613366376466303631316333653038343266376532626233643634306633313362323335663162373563316438306239a473707562d94030346164336335393738653064646561373030613336393932313861333461616336663736303437646661656131323966643530313464636338306534333961";

    #[test]
    fn shareable_viewing_key_matches_the_engine() {
        let keys = WalletKeys::from_mnemonic(
            "test test test test test test test test test test test junk",
            "",
            0,
        )
        .unwrap();
        assert_eq!(keys.shareable_viewing_key().as_str(), SHAREABLE);
        let view = ViewOnlyKeys::from_shareable_viewing_key(SHAREABLE).unwrap();
        assert_eq!(view.master_public_key, keys.master_public_key);
        assert_eq!(view.address().unwrap(), keys.address().unwrap());
    }

    #[test]
    fn rejects_a_malformed_key() {
        assert!(
            ViewOnlyKeys::from_shareable_viewing_key(&SHAREABLE[..SHAREABLE.len() - 2]).is_err()
        );
        assert!(ViewOnlyKeys::from_shareable_viewing_key("zz").is_err());
        let renamed = SHAREABLE.replacen("73707562", "73707563", 1);
        assert!(ViewOnlyKeys::from_shareable_viewing_key(&renamed).is_err());
    }
}
