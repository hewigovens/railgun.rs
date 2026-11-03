use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};
use rg_keys::decode_address;
use serde::Deserialize;

use crate::Error;

/// Broadcasters the client talks to (`BroadcasterConfig.MINIMUM_BROADCASTER_VERSION` and `MAXIMUM_BROADCASTER_VERSION`).
const VERSIONS: ([u32; 3], [u32; 3]) = ([8, 0, 0], [8, 999, 0]);

/// An offer must outlive this, so it does not expire while the transaction is proved (`FEE_EXPIRATION_MINIMUM_MSEC`).
const EXPIRY_MARGIN_MS: u64 = 40_000;

/// One broadcaster's signed offer for a chain (`BroadcasterFeeMessageData`), checked against the viewing key in its 0zk address.
#[derive(Clone, Debug, PartialEq)]
pub struct BroadcasterFees {
    /// 0zk address; the fee note goes here.
    pub railgun_address: String,
    pub viewing_public_key: [u8; 32],
    /// Several wallets behind one address tell themselves apart by this.
    pub identifier: Option<String>,
    /// Token to its fee per unit of gas, scaled by 10^18: the fee is this times the gas cost in wei, over 10^18.
    pub fees: BTreeMap<[u8; 20], u128>,
    pub fee_expiration_ms: u64,
    /// Echoed in the request, so the broadcaster knows which offer it accepts.
    pub fees_id: String,
    pub available_wallets: u32,
    pub version: String,
    /// The RelayAdapt contract it submits ETH unshields and other relayed calls to.
    pub relay_adapt: Option<[u8; 20]>,
    /// POI lists the broadcaster requires proofs for.
    pub required_poi_list_keys: Vec<String>,
    pub reliability: f64,
}

#[derive(Deserialize)]
struct Signed {
    data: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Data {
    fees: BTreeMap<String, String>,
    fee_expiration: u64,
    #[serde(rename = "feesID")]
    fees_id: String,
    railgun_address: String,
    identifier: Option<String>,
    available_wallets: u32,
    version: String,
    relay_adapt: Option<String>,
    #[serde(rename = "requiredPOIListKeys", default)]
    required_poi_list_keys: Vec<String>,
    #[serde(default)]
    reliability: f64,
}

fn parse_version(v: &str) -> Option<[u32; 3]> {
    let mut parts = v.split('.').map(|p| p.parse().ok());
    let version = [parts.next()??, parts.next()??, parts.next()??];
    parts.next().is_none().then_some(version)
}

fn evm_address(address: &str) -> Option<[u8; 20]> {
    hex::decode(address.strip_prefix("0x")?)
        .ok()?
        .try_into()
        .ok()
}

fn fee(hex: &str) -> Option<u128> {
    u128::from_str_radix(hex.strip_prefix("0x")?, 16).ok()
}

impl BroadcasterFees {
    /// Parses a Waku fees message, `{data, signature}` with `data` the hex of the offer's JSON, and checks the Ed25519 signature over those bytes and the version range.
    pub fn from_message(payload: &[u8]) -> Result<Self, Error> {
        let bad = Error::BadFeeMessage;
        let signed: Signed = serde_json::from_slice(payload).map_err(|_| bad("not JSON"))?;
        let bytes = hex::decode(&signed.data).map_err(|_| bad("data is not hex"))?;
        let data: Data = serde_json::from_slice(&bytes).map_err(|_| bad("unexpected data"))?;

        let range = parse_version(&data.version).filter(|v| (VERSIONS.0..=VERSIONS.1).contains(v));
        if range.is_none() {
            return Err(Error::Version(data.version));
        }
        let viewing_public_key = decode_address(&data.railgun_address)?.viewing_public_key;
        let signature: [u8; 64] = hex::decode(&signed.signature)
            .ok()
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::BadSignature)?;
        VerifyingKey::from_bytes(&viewing_public_key)
            .and_then(|key| key.verify_strict(&bytes, &Signature::from_bytes(&signature)))
            .map_err(|_| Error::BadSignature)?;

        let fees = data
            .fees
            .iter()
            .map(|(t, f)| Some((evm_address(t)?, fee(f)?)))
            .collect::<Option<_>>()
            .ok_or(bad("unexpected fee entry"))?;
        Ok(BroadcasterFees {
            railgun_address: data.railgun_address,
            viewing_public_key,
            identifier: data.identifier,
            fees,
            fee_expiration_ms: data.fee_expiration,
            fees_id: data.fees_id,
            available_wallets: data.available_wallets,
            version: data.version,
            relay_adapt: data.relay_adapt.as_deref().and_then(evm_address),
            required_poi_list_keys: data.required_poi_list_keys,
            reliability: data.reliability,
        })
    }

    /// What the broadcaster takes in `token` for a transaction that may cost `max_gas_cost` wei (`calculateBroadcasterFeeERC20Amount`).
    pub fn fee(&self, token: &[u8; 20], max_gas_cost: u128) -> Option<u128> {
        let per_unit = self.fees.get(token)?;
        Some(per_unit.checked_mul(max_gas_cost)? / 10u128.pow(18))
    }

    /// Has a free wallet and stays valid long enough to prove against.
    pub fn is_live(&self, now_ms: u64) -> bool {
        self.available_wallets > 0 && self.fee_expiration_ms >= now_ms + EXPIRY_MARGIN_MS
    }
}

/// The cheapest live offer for `token` that needs no POI list but `poi_list`, the more reliable on a tie (`findBestBroadcaster`). With `relay_adapt`, only broadcasters that submit through that RelayAdapt contract.
pub fn best_offer<'a>(
    offers: &'a [BroadcasterFees],
    token: &[u8; 20],
    now_ms: u64,
    poi_list: &str,
    relay_adapt: Option<&[u8; 20]>,
) -> Option<&'a BroadcasterFees> {
    offers
        .iter()
        .filter(|o| o.is_live(now_ms) && o.fees.contains_key(token))
        .filter(|o| o.required_poi_list_keys.iter().all(|k| k == poi_list))
        .filter(|o| relay_adapt.is_none_or(|r| o.relay_adapt.as_ref() == Some(r)))
        .min_by(|a, b| {
            a.fees[token]
                .cmp(&b.fees[token])
                .then(b.reliability.total_cmp(&a.reliability))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const WETH: [u8; 20] = [
        0x82, 0xaf, 0x49, 0x44, 0x7d, 0x8a, 0x07, 0xe3, 0xbd, 0x95, 0xbd, 0x0d, 0x56, 0xf3, 0x52,
        0x41, 0x52, 0x3f, 0xba, 0xb1,
    ];

    // A fee message from the Railgun Waku network, on Arbitrum.
    fn message() -> Vec<u8> {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/arbitrum-fees.json"
        ))
        .unwrap()
    }

    #[test]
    fn reads_a_live_fee_message() {
        let offer = BroadcasterFees::from_message(&message()).unwrap();
        assert_eq!(offer.fees[&WETH], 10u128.pow(18));
        assert_eq!(offer.fee(&WETH, 3_000), Some(3_000));
        assert_eq!(offer.version, "8.3.0");
        assert!(offer.is_live(offer.fee_expiration_ms - EXPIRY_MARGIN_MS));
        assert!(!offer.is_live(offer.fee_expiration_ms));
    }

    #[test]
    fn rejects_a_changed_offer() {
        let mut signed: serde_json::Value = serde_json::from_slice(&message()).unwrap();
        let data = hex::decode(signed["data"].as_str().unwrap()).unwrap();
        let cheaper = String::from_utf8(data)
            .unwrap()
            .replace("0xde0b6b3a7640000", "0x1");
        signed["data"] = hex::encode(cheaper).into();
        let tampered = serde_json::to_vec(&signed).unwrap();
        assert!(matches!(
            BroadcasterFees::from_message(&tampered),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn picks_the_cheapest_live_offer_without_other_lists() {
        let offer = BroadcasterFees::from_message(&message()).unwrap();
        let now = offer.fee_expiration_ms - EXPIRY_MARGIN_MS;
        let list = &offer.required_poi_list_keys[0];
        let with_fee = |fee: u128, reliability: f64| {
            let mut o = offer.clone();
            o.fees.insert(WETH, fee);
            o.reliability = reliability;
            o
        };
        let mut other_list = with_fee(1, 1.0);
        other_list.required_poi_list_keys = vec!["ab".into()];
        let mut busy = with_fee(1, 1.0);
        busy.available_wallets = 0;
        let mut other_relay_adapt = with_fee(2, 1.0);
        other_relay_adapt.relay_adapt = Some([1; 20]);
        let offers = [
            with_fee(5, 0.9),
            with_fee(3, 0.5),
            with_fee(3, 0.8),
            other_list,
            busy,
            other_relay_adapt,
        ];
        let relay_adapt = offer.relay_adapt.unwrap();
        let best = best_offer(&offers, &WETH, now, list, Some(&relay_adapt)).unwrap();
        assert_eq!((best.fees[&WETH], best.reliability), (3, 0.8));
        assert_eq!(
            best_offer(&offers, &WETH, now, list, None).unwrap().fees[&WETH],
            2
        );
        assert!(best_offer(&offers, &[0; 20], now, list, None).is_none());
    }
}
