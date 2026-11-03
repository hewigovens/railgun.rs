use std::collections::VecDeque;
use std::net::Ipv4Addr;

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RData;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use libp2p::identity::{PublicKey, secp256k1};
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use tiny_keccak::{Hasher, Keccak};

use crate::Error;

/// The Railgun fleet's ENR tree (`WAKU_RAILGUN_DEFAULT_ENR_TREE_URL`): its domain, and the base32 secp256k1 key that signs its root.
pub(crate) const ENR_TREE: (&str, &str) = (
    "discovery.rootedinprivacy.com",
    "APMYHUVNQWHJNPI5L2KQ765EMCKUAMRWPUH3U2QIKPK6XEV3OW442",
);

/// The tree's nodes when this was written, for when DNS fails.
pub(crate) const FALLBACK_ENRS: [&str; 3] = [
    "enr:-Ju4QEq9uBOE9JpIV2VmUZOkoe4XLYwE9yZCADzGKlamFXAne4iLrywhlVvN2EFnATiI0yNIvFcyG8FmOTkiKjEQsmwFgmlkgnY0gmlwhC1MEgeCcnOFAAUBAAGJc2VjcDI1NmsxoQPINxGpL7qbuxD1DOa63SD6Ud3o9fpolgZrhissV_Scw4N0Y3CCdmCDdWRwgnZghXdha3UyDw",
    "enr:-Ju4QFfQHInJUCE4wlYiT8-W9lih6s5pbe8ru_ODqpja1EXrKCAAHwDAKNmFwafOIlHSAkJu_-5iUFdRRqS0zAthNxAFgmlkgnY0gmlwhGjPiwqCcnOFAAUBAAGJc2VjcDI1NmsxoQOHDqHvwha9awE06OV6mBsCbIqP5MfiRn_tja56J_wawIN0Y3CCdmCDdWRwgnZghXdha3UyDQ",
    "enr:-Ju4QMnC1dVtQfky46PO2aaxPV8v_-WV_auWs9s090X2hHomAvaP3LxJM-cCl-EoGfioG6X0MTZdWxLgdLy3ghixJV8FgmlkgnY0gmlwhC1M5v2CcnOFAAUBAAGJc2VjcDI1NmsxoQJajleHSEmeargTe6xYQRQcZmso81vII1CGAv1YuTxg34N0Y3CCdmCDdWRwgnZghXdha3UyDQ",
];

/// `waku2` capability bits (nwaku `Capabilities`).
const STORE: u8 = 1 << 1;
const LIGHT_PUSH: u8 = 1 << 3;

/// Most TXT lookups one discovery makes.
const MAX_LOOKUPS: usize = 64;

/// A Waku service node and what it serves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub id: PeerId,
    pub address: Multiaddr,
    pub store: bool,
    pub light_push: bool,
}

/// One RLP item and what follows it.
fn rlp_item(data: &[u8]) -> Option<(bool, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let long = |n: u8, rest: &[u8]| -> Option<(usize, usize)> {
        let n = usize::from(n);
        let len = rest
            .get(..n)?
            .iter()
            .fold(0usize, |l, b| (l << 8) | usize::from(*b));
        Some((n, len))
    };
    let (list, skip, len) = match tag {
        0x00..=0x7f => return Some((false, &data[..1], rest)),
        0x80..=0xb7 => (false, 0, usize::from(tag - 0x80)),
        0xb8..=0xbf => {
            let (n, len) = long(tag - 0xb7, rest)?;
            (false, n, len)
        }
        0xc0..=0xf7 => (true, 0, usize::from(tag - 0xc0)),
        0xf8..=0xff => {
            let (n, len) = long(tag - 0xf7, rest)?;
            (true, n, len)
        }
    };
    let body = rest.get(skip..skip.checked_add(len)?)?;
    Some((list, body, &rest[skip + len..]))
}

impl Peer {
    /// A node from its ENR (EIP-778): RLP of the signature, the sequence number, then sorted key-value pairs. The record's own signature is not checked: discovery authenticates it through the tree's hashes, the fallback records ship with the code, and Noise proves the node holds the key the address names.
    pub fn from_enr(text: &str) -> Result<Peer, Error> {
        let bad = Error::Enr;
        let encoded = text.strip_prefix("enr:").ok_or(bad("not an ENR"))?;
        let raw = base64_url(encoded).ok_or(bad("not base64url"))?;
        let (true, mut items, _) = rlp_item(&raw).ok_or(bad("not RLP"))? else {
            return Err(bad("not a list"));
        };
        let mut fields = Vec::new();
        while !items.is_empty() {
            let (_, value, rest) = rlp_item(items).ok_or(bad("not RLP"))?;
            fields.push(value);
            items = rest;
        }
        let get = |key: &[u8]| {
            fields
                .iter()
                .skip(2)
                .step_by(2)
                .position(|k| *k == key)
                .and_then(|i| fields.get(3 + 2 * i).copied())
        };
        if get(b"id") != Some(b"v4") {
            return Err(bad("not a v4 identity"));
        }
        let ip: [u8; 4] = get(b"ip")
            .and_then(|ip| ip.try_into().ok())
            .ok_or(bad("no IPv4 address"))?;
        let port = get(b"tcp")
            .filter(|p| p.len() <= 2)
            .map(|p| p.iter().fold(0u16, |n, b| (n << 8) | u16::from(*b)))
            .ok_or(bad("no TCP port"))?;
        let key = get(b"secp256k1")
            .and_then(|k| secp256k1::PublicKey::try_from_bytes(k).ok())
            .ok_or(bad("no secp256k1 key"))?;
        let id = PeerId::from_public_key(&PublicKey::from(key));
        let flags = get(b"waku2").and_then(|f| f.first().copied()).unwrap_or(0);
        let address = Multiaddr::empty()
            .with(Protocol::Ip4(Ipv4Addr::from(ip)))
            .with(Protocol::Tcp(port))
            .with(Protocol::P2p(id));
        Ok(Peer {
            id,
            address,
            store: flags & STORE != 0,
            light_push: flags & LIGHT_PUSH != 0,
        })
    }
}

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(data);
    k.finalize(&mut out);
    out
}

/// Unpadded RFC 4648 base32, as ENR tree keys and labels use.
fn base32(text: &str) -> Option<Vec<u8>> {
    let mut bits = 0u64;
    let mut count = 0;
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        bits = (bits << 5) | u64::from(v);
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    Some(out)
}

/// The label an entry is filed under: base32 of the first 16 bytes of its keccak256.
fn label_matches(label: &str, entry: &str) -> bool {
    base32(label).is_some_and(|l| l == keccak(entry.as_bytes())[..16])
}

/// The `e=` branch of a root signed by `key` (EIP-1459): the signature is over keccak256 of the record up to ` sig=`.
fn signed_branch<'r>(root: &'r str, key: &VerifyingKey) -> Result<&'r str, Error> {
    let bad = Error::Enr;
    let (content, sig) = root
        .split_once(" sig=")
        .ok_or(bad("unsigned ENR tree root"))?;
    let sig = base64_url(sig)
        .filter(|s| s.len() == 65)
        .ok_or(bad("bad root signature"))?;
    let sig = Signature::from_slice(&sig[..64]).map_err(|_| bad("bad root signature"))?;
    let sig = sig.normalize_s().unwrap_or(sig);
    key.verify_prehash(&keccak(content.as_bytes()), &sig)
        .map_err(|_| bad("ENR tree root signature does not verify"))?;
    content
        .strip_prefix("enrtree-root:v1 ")
        .and_then(|r| r.split(' ').find_map(|f| f.strip_prefix("e=")))
        .ok_or(bad("not an ENR tree root"))
}

/// Unpadded base64url, as ENRs and ENR tree entries use.
fn base64_url(text: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(v);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    Some(out)
}

/// Every node in an EIP-1459 ENR tree: the root must be signed by the tree's key, and every entry must hash to the label it was fetched under, so DNS cannot substitute nodes.
pub(crate) async fn discover((domain, key): (&str, &str)) -> Result<Vec<Peer>, Error> {
    let key = base32(key)
        .and_then(|k| VerifyingKey::from_sec1_bytes(&k).ok())
        .ok_or(Error::Enr("bad ENR tree key"))?;
    let resolver = TokioResolver::builder_tokio()
        .map_err(|e| Error::Waku(format!("DNS: {e}")))?
        .build()
        .map_err(|e| Error::Waku(format!("DNS: {e}")))?;
    let txt = async |name: String| -> Result<String, Error> {
        let lookup = resolver
            .txt_lookup(name.as_str())
            .await
            .map_err(|e| Error::Waku(format!("DNS {name}: {e}")))?;
        let text = lookup
            .answers()
            .iter()
            .find_map(|r| match &r.data {
                RData::TXT(t) => Some(t.txt_data.concat()),
                _ => None,
            })
            .ok_or(Error::Enr("no TXT record"))?;
        String::from_utf8(text).map_err(|_| Error::Enr("TXT record is not text"))
    };

    let root = txt(domain.to_string()).await?;
    let mut queue = VecDeque::from([signed_branch(&root, &key)?.to_string()]);
    let mut peers = Vec::new();
    let mut lookups = 0;
    while let Some(label) = queue.pop_front() {
        lookups += 1;
        if lookups > MAX_LOOKUPS {
            break;
        }
        let entry = txt(format!("{label}.{domain}")).await?;
        if !label_matches(&label, &entry) {
            return Err(Error::Enr("ENR tree entry does not match its hash"));
        }
        if let Some(children) = entry.strip_prefix("enrtree-branch:") {
            queue.extend(
                children
                    .split(',')
                    .filter(|c| !c.is_empty())
                    .map(str::to_string),
            );
        } else if entry.starts_with("enr:") {
            peers.push(Peer::from_enr(&entry)?);
        }
    }
    Ok(peers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_fleet_enrs() {
        let peers: Vec<Peer> = FALLBACK_ENRS
            .iter()
            .map(|e| Peer::from_enr(e).unwrap())
            .collect();
        assert_eq!(
            peers[0].address.to_string(),
            "/ip4/45.76.18.7/tcp/30304/p2p/16Uiu2HAmS8YbNhE1rJGBQ3VaubZjM1iAR7zVvtLf6CrEB3Hc9Krr"
        );
        let serves: Vec<_> = peers.iter().map(|p| (p.store, p.light_push)).collect();
        assert_eq!(serves, [(true, true), (false, true), (false, true)]);
        assert!(Peer::from_enr(&FALLBACK_ENRS[0][..60]).is_err());
    }

    // The fleet's TXT records when this was written.
    const ROOT: &str = "enrtree-root:v1 e=OTRYTEZTQ5IVGIT7A3VUAVSXAY l=FDXN3SN67NA5DKA4J2GOK7BVQI seq=60 sig=84d4-tgILUjz0qoGDt-hsDnfm7fPirOc-L2NqGfqz6UZBSJCRAdI-pEyYvAEVULiN4hObF0D7zFLyivh9bm8ngA";
    const BRANCH: &str = "enrtree-branch:5ZCFH3XHSTRUIBR73DYGGOUJIQ,VJRBLD37PLZYVHQFMYYP3OAKQI,PU6WILDG333LK7JHZSNYC5KFNI";

    #[test]
    fn authenticates_the_tree_from_its_key() {
        let key = VerifyingKey::from_sec1_bytes(&base32(ENR_TREE.1).unwrap()).unwrap();
        assert_eq!(
            signed_branch(ROOT, &key).unwrap(),
            "OTRYTEZTQ5IVGIT7A3VUAVSXAY"
        );
        assert!(signed_branch(&ROOT.replace("seq=60", "seq=61"), &key).is_err());
        assert!(label_matches("OTRYTEZTQ5IVGIT7A3VUAVSXAY", BRANCH));
        assert!(label_matches(
            "5ZCFH3XHSTRUIBR73DYGGOUJIQ",
            FALLBACK_ENRS[0]
        ));
        assert!(!label_matches(
            "5ZCFH3XHSTRUIBR73DYGGOUJIQ",
            FALLBACK_ENRS[1]
        ));
    }
}
