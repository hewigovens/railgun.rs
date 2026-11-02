//! EdDSA over BabyJubJub with Poseidon, as circomlib `signPoseidon` and `verifyPoseidon`, which the Railgun circuits check. Written from the circomlib scheme, not ported from the GPL circomlibjs code.
//!
//! sign(prv, msg):
//!   h = blake512(prv); s = prune(h[0..32]) as LE integer; A = Base8 * (s >> 3)
//!   r = blake512(h[32..64] || le32(msg)) as LE integer mod l; R8 = Base8 * r
//!   S = r + poseidon(R8x, R8y, Ax, Ay, msg) * s mod l

use ark_ed_on_bn254::Fr as SubgroupScalar;
use ark_ff::{BigInteger, PrimeField};

use crate::babyjubjub::{BASE8, Point, prune, shr3_le};
use crate::blake::blake512;
use crate::field::to_le_bytes;
use crate::{Fr, poseidon};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r8: Point,
    /// S, below the subgroup order l.
    pub s: SubgroupScalar,
}

impl Signature {
    /// Builds a signature from S given as a BN254 field element, which is how circuit inputs carry it. Fails when S is not below l.
    pub fn new(r8: Point, s: Fr) -> Option<Self> {
        let big = s.into_bigint();
        if big >= SubgroupScalar::MODULUS {
            return None;
        }
        Some(Signature {
            r8,
            s: SubgroupScalar::from_bigint(big)?,
        })
    }

    /// S as a BN254 field element, for circuit inputs.
    pub fn s_field(&self) -> Fr {
        Fr::from_le_bytes_mod_order(&self.s.into_bigint().to_bytes_le())
    }
}

fn to_subgroup(x: &Fr) -> SubgroupScalar {
    SubgroupScalar::from_le_bytes_mod_order(&to_le_bytes(x))
}

fn le32(x: &SubgroupScalar) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&x.into_bigint().to_bytes_le());
    out
}

pub fn sign(private_key: &[u8; 32], message: &Fr) -> Signature {
    let h = blake512(private_key);
    let mut head = [0u8; 32];
    head.copy_from_slice(&h[..32]);
    let s_bytes = prune(head);
    let a = BASE8.mul_ct(&shr3_le(&s_bytes));

    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(&h[32..]);
    preimage[32..].copy_from_slice(&to_le_bytes(message));
    let r = SubgroupScalar::from_le_bytes_mod_order(&blake512(&preimage));
    let r8 = BASE8.mul_ct(&le32(&r));

    let hm = poseidon::hash(&[r8.x, r8.y, a.x, a.y, *message]).expect("arity 5");
    let s = SubgroupScalar::from_le_bytes_mod_order(&s_bytes);
    Signature {
        r8,
        s: r + to_subgroup(&hm) * s,
    }
}

/// circomlib `verifyPoseidon`: both points on the curve, S below l (enforced by the type), and Base8 * S == R8 + A * (8 * hm) with hm as a full integer.
pub fn verify(message: &Fr, signature: &Signature, public_key: &Point) -> bool {
    if !signature.r8.is_on_curve() || !public_key.is_on_curve() {
        return false;
    }
    let Ok(hm) = poseidon::hash(&[
        signature.r8.x,
        signature.r8.y,
        public_key.x,
        public_key.y,
        *message,
    ]) else {
        return false;
    };
    // 8 * hm without reducing, as circomlib multiplies by the integer.
    let mut hm8 = [0u8; 33];
    let hm_le = to_le_bytes(&hm);
    let mut carry = 0u8;
    for i in 0..32 {
        hm8[i] = (hm_le[i] << 3) | carry;
        carry = hm_le[i] >> 5;
    }
    hm8[32] = carry;
    let left = BASE8.mul_le(&le32(&signature.s));
    let right = signature.r8.add(&public_key.mul_le(&hm8));
    left == right
}
