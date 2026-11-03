//! Ed25519 pieces of Railgun note encryption: viewing-key ECDH and the blinding of sender and receiver viewing keys (`utils/keys-utils.ts`).

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

/// `getPrivateScalarFromPrivateKey`: clamped sha512(prv)[0..32], little-endian, mod l. The engine maps 0 to l, which is the same point multiple.
pub fn private_scalar(private_key: &[u8; 32]) -> Zeroizing<Scalar> {
    let mut h = Sha512::digest(private_key);
    let mut head = Zeroizing::new([0u8; 32]);
    head.copy_from_slice(&h[..32]);
    h.as_mut_slice().zeroize();
    head[0] &= 0b1111_1000;
    head[31] &= 0b0111_1111;
    head[31] |= 0b0100_0000;
    Zeroizing::new(Scalar::from_bytes_mod_order(*head))
}

/// The Ed25519 public key of a 32-byte private key (viewing key, shield key).
pub fn public_key(private_key: &[u8; 32]) -> [u8; 32] {
    (ED25519_BASEPOINT_TABLE * &*private_scalar(private_key))
        .compress()
        .to_bytes()
}

/// `getSharedSymmetricKey`: sha256 of the compressed point `pub * scalar(prv)`. None when `public_key` is not a curve point. Like the engine's wasm path (curve25519-dalek), a non-canonical y encoding is accepted.
pub fn shared_key(private_key: &[u8; 32], public_key: &[u8; 32]) -> Option<[u8; 32]> {
    let point = CompressedEdwardsY(*public_key).decompress()?;
    let shared = (point * *private_scalar(private_key)).compress();
    Some(Sha256::digest(shared.as_bytes()).into())
}

/// noble-ed25519's `getSharedSecret`, which keys broadcaster messages: X25519 of the clamped sha512(prv)[0..32] with `public_key` mapped to Montgomery form. None when `public_key` is not a curve point or the result is zero.
pub fn x25519_shared_secret(private_key: &[u8; 32], public_key: &[u8; 32]) -> Option<[u8; 32]> {
    let point = CompressedEdwardsY(*public_key).decompress()?;
    let mut h = Sha512::digest(private_key);
    let mut head = Zeroizing::new([0u8; 32]);
    head.copy_from_slice(&h[..32]);
    h.as_mut_slice().zeroize();
    let shared = point.mul_clamped(*head).to_montgomery().to_bytes();
    (shared != [0; 32]).then_some(shared)
}

/// `getBlindingScalar`: the note random (16 bytes) and sender random (15 bytes) XORed as big-endian integers, written as 32 bytes, then sha512 of that read big-endian mod l.
pub fn blinding_scalar(random: &[u8; 16], sender_random: &[u8; 15]) -> Scalar {
    let mut seed = [0u8; 32];
    seed[16..].copy_from_slice(random);
    for (i, b) in sender_random.iter().enumerate() {
        seed[17 + i] ^= b;
    }
    let h = Sha512::digest(seed);
    let mut wide = [0u8; 64];
    for (i, b) in h.iter().enumerate() {
        wide[63 - i] = *b;
    }
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Decodes like noble-ed25519's strict `Point.fromHex`, which the engine uses for blinding: y must be below p.
fn decode_strict(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    const P_LE: [u8; 32] = {
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        p
    };
    let mut y = *bytes;
    y[31] &= 0x7f;
    // y < p, compared as little-endian integers.
    let canonical = y
        .iter()
        .rev()
        .zip(P_LE.iter().rev())
        .find(|(a, b)| a != b)
        .is_some_and(|(a, b)| a < b);
    if !canonical {
        return None;
    }
    CompressedEdwardsY(*bytes).decompress()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlindedKeys {
    pub blinded_sender_viewing_key: [u8; 32],
    pub blinded_receiver_viewing_key: [u8; 32],
}

/// `getNoteBlindingKeys`: both viewing public keys times the blinding scalar.
pub fn blind_keys(
    sender_viewing_public_key: &[u8; 32],
    receiver_viewing_public_key: &[u8; 32],
    random: &[u8; 16],
    sender_random: &[u8; 15],
) -> Option<BlindedKeys> {
    let k = blinding_scalar(random, sender_random);
    if k == Scalar::ZERO {
        return None;
    }
    let sender = decode_strict(sender_viewing_public_key)?;
    let receiver = decode_strict(receiver_viewing_public_key)?;
    Some(BlindedKeys {
        blinded_sender_viewing_key: (sender * k).compress().to_bytes(),
        blinded_receiver_viewing_key: (receiver * k).compress().to_bytes(),
    })
}

/// `unblindNoteKey`: multiplies by the inverse of the blinding scalar.
pub fn unblind_key(
    blinded_key: &[u8; 32],
    random: &[u8; 16],
    sender_random: &[u8; 15],
) -> Option<[u8; 32]> {
    let k = blinding_scalar(random, sender_random);
    if k == Scalar::ZERO {
        return None;
    }
    let point = decode_strict(blinded_key)?;
    Some((point * k.invert()).compress().to_bytes())
}
