//! BabyJubJub in circomlib's twisted Edwards form (a = 168700, d = 168696)
//! and circomlib's key derivation. Note `ark-ed-on-bn254` uses the
//! isomorphic a = 1 form, whose coordinates differ, so it is not used here.
//!
//! Scalar multiplication here is not constant time. Fine for public data and
//! tests; signing with the spending key needs a constant-time path (M2).

use std::sync::LazyLock;

use ark_ff::{Field, One, Zero};
use blake_hash::{Blake512, Digest};

use crate::field::{from_decimal, to_le_bytes};
use crate::{Error, Fr};

static A: LazyLock<Fr> = LazyLock::new(|| Fr::from(168_700u64));
static D: LazyLock<Fr> = LazyLock::new(|| Fr::from(168_696u64));

/// circomlib `Base8`, the generator of the prime-order subgroup.
pub static BASE8: LazyLock<Point> = LazyLock::new(|| Point {
    x: from_decimal("5299619240641551281634865583518297030282874472190772894086521144482721001553")
        .unwrap(),
    y: from_decimal(
        "16950150798460657717958625567821834550301663161624707787222815936182638968203",
    )
    .unwrap(),
});

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: Fr,
    pub y: Fr,
}

impl Point {
    pub fn identity() -> Self {
        Point {
            x: Fr::zero(),
            y: Fr::one(),
        }
    }

    /// circomlib `addPoint` (affine twisted Edwards addition).
    pub fn add(&self, other: &Point) -> Point {
        let beta = self.x * other.y;
        let gamma = self.y * other.x;
        let delta = (self.y - *A * self.x) * (other.x + other.y);
        let dtau = *D * beta * gamma;
        let x = (beta + gamma) * (Fr::one() + dtau).inverse().expect("complete addition");
        let y =
            (delta + *A * beta - gamma) * (Fr::one() - dtau).inverse().expect("complete addition");
        Point { x, y }
    }

    /// Double-and-add over a little-endian scalar, like circomlib `mulPointEscalar`.
    pub fn mul_le(&self, scalar_le: &[u8]) -> Point {
        let mut acc = Point::identity();
        let mut base = *self;
        for byte in scalar_le {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    acc = acc.add(&base);
                }
                base = base.add(&base);
            }
        }
        acc
    }

    pub fn is_on_curve(&self) -> bool {
        let x2 = self.x.square();
        let y2 = self.y.square();
        *A * x2 + y2 == Fr::one() + *D * x2 * y2
    }

    /// circomlib `packPoint`: y little-endian, top bit set when x > (p-1)/2.
    pub fn pack(&self) -> [u8; 32] {
        let mut out = to_le_bytes(&self.y);
        if is_negative(&self.x) {
            out[31] |= 0x80;
        }
        out
    }

    /// circomlib `unpackPoint`.
    pub fn unpack(packed: &[u8; 32]) -> Result<Point, Error> {
        let mut bytes = *packed;
        let sign = bytes[31] & 0x80 != 0;
        bytes[31] &= 0x7f;
        let y = <Fr as ark_ff::PrimeField>::from_le_bytes_mod_order(&bytes);
        if to_le_bytes(&y) != bytes {
            return Err(Error::InvalidPoint);
        }
        let y2 = y.square();
        let num = Fr::one() - y2;
        let den = *A - *D * y2;
        let mut x = (num * den.inverse().ok_or(Error::InvalidPoint)?)
            .sqrt()
            .ok_or(Error::InvalidPoint)?;
        // Match circomlib: take the root as returned, negate when the sign bit is set.
        // ffjavascript's sqrt returns the "positive" root.
        if is_negative(&x) {
            x = -x;
        }
        if sign {
            x = -x;
        }
        Ok(Point { x, y })
    }
}

/// ffjavascript's signed view: values above (p-1)/2 are negative.
fn is_negative(x: &Fr) -> bool {
    use ark_ff::PrimeField;
    x.into_bigint() > Fr::MODULUS_MINUS_ONE_DIV_TWO
}

/// circomlib `pruneBuffer`.
pub fn prune(mut buf: [u8; 32]) -> [u8; 32] {
    buf[0] &= 0xf8;
    buf[31] &= 0x7f;
    buf[31] |= 0x40;
    buf
}

/// Blake-512 (original BLAKE, as circomlib's `blake-hash` package) of the key.
pub fn blake512(data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(&Blake512::digest(data));
    out
}

/// circomlib `eddsa.prv2pub`: `Base8 * (prune(blake512(prv)[0..32]) >> 3)`.
pub fn private_to_public(private_key: &[u8; 32]) -> Point {
    let h = blake512(private_key);
    let mut s = [0u8; 32];
    s.copy_from_slice(&h[..32]);
    let s = shr3_le(&prune(s));
    BASE8.mul_le(&s)
}

/// Right shift a 256-bit little-endian integer by 3 bits.
fn shr3_le(v: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = if i + 1 < 32 { v[i + 1] } else { 0 };
        out[i] = (v[i] >> 3) | (hi << 5);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base8_on_curve() {
        assert!(BASE8.is_on_curve());
        assert!(Point::identity().is_on_curve());
    }

    #[test]
    fn shr3() {
        let mut v = [0u8; 32];
        v[1] = 0b0000_0001; // 256
        let r = shr3_le(&v);
        assert_eq!(r[0], 32);
    }
}
