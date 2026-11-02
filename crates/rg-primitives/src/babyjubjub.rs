//! BabyJubJub in circomlib's twisted Edwards form (a = 168700, d = 168696) and circomlib's key derivation. Note `ark-ed-on-bn254` uses the isomorphic a = 1 form, whose coordinates differ, so it is not used here.
//!
//! Two scalar multiplications: `mul_le` (double-and-add, variable time, for public scalars) and `mul_ct` (fixed-sequence Montgomery ladder in projective coordinates, for secret scalars). The ladder runs the same field operations for every scalar; arkworks' field arithmetic itself is not audited for constant time.

use std::sync::LazyLock;

use ark_ff::{Field, One, Zero};

use crate::blake::blake512;
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

    /// Montgomery ladder over all 256 bits of a little-endian scalar, with branchless swaps and complete projective addition, for secret scalars. Same result as `mul_le` for any scalar.
    pub fn mul_ct(&self, scalar_le: &[u8; 32]) -> Point {
        let mut r0 = Projective::identity();
        let mut r1 = Projective::from_affine(self);
        for i in (0..256).rev() {
            let bit = Fr::from((scalar_le[i / 8] >> (i % 8)) & 1);
            Projective::cswap(&mut r0, &mut r1, bit);
            r1 = r0.add(&r1);
            r0 = r0.add(&r0);
            Projective::cswap(&mut r0, &mut r1, bit);
        }
        r0.to_affine()
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
        // Match circomlib: take the root as returned, negate when the sign bit is set. ffjavascript's sqrt returns the "positive" root.
        if is_negative(&x) {
            x = -x;
        }
        if sign {
            x = -x;
        }
        Ok(Point { x, y })
    }
}

/// Projective twisted Edwards point (X : Y : Z), x = X/Z, y = Y/Z.
#[derive(Clone, Copy)]
struct Projective {
    x: Fr,
    y: Fr,
    z: Fr,
}

impl Projective {
    fn identity() -> Self {
        Projective {
            x: Fr::zero(),
            y: Fr::one(),
            z: Fr::one(),
        }
    }

    fn from_affine(p: &Point) -> Self {
        Projective {
            x: p.x,
            y: p.y,
            z: Fr::one(),
        }
    }

    /// add-2008-bbjlp; complete because a is a square and d is not.
    fn add(&self, o: &Projective) -> Projective {
        let a = self.z * o.z;
        let b = a.square();
        let c = self.x * o.x;
        let d = self.y * o.y;
        let e = *D * c * d;
        let f = b - e;
        let g = b + e;
        let x = a * f * ((self.x + self.y) * (o.x + o.y) - c - d);
        let y = a * g * (d - *A * c);
        Projective { x, y, z: f * g }
    }

    /// Swap when `bit` is one, using arithmetic instead of a branch.
    fn cswap(p: &mut Projective, q: &mut Projective, bit: Fr) {
        let dx = bit * (q.x - p.x);
        let dy = bit * (q.y - p.y);
        let dz = bit * (q.z - p.z);
        p.x += dx;
        p.y += dy;
        p.z += dz;
        q.x -= dx;
        q.y -= dy;
        q.z -= dz;
    }

    /// Inverts Z by Fermat (fixed exponent) rather than the variable-time extended Euclid behind `Field::inverse`.
    fn to_affine(self) -> Point {
        use ark_ff::{BigInteger, PrimeField};
        let mut exp = Fr::MODULUS;
        exp.sub_with_borrow(&2u64.into());
        let zinv = self.z.pow(exp);
        Point {
            x: self.x * zinv,
            y: self.y * zinv,
        }
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

/// circomlib `eddsa.prv2pub`: `Base8 * (prune(blake512(prv)[0..32]) >> 3)`.
pub fn private_to_public(private_key: &[u8; 32]) -> Point {
    let h = blake512(private_key);
    let mut s = [0u8; 32];
    s.copy_from_slice(&h[..32]);
    let s = shr3_le(&prune(s));
    BASE8.mul_ct(&s)
}

/// Right shift a 256-bit little-endian integer by 3 bits.
pub(crate) fn shr3_le(v: &[u8; 32]) -> [u8; 32] {
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
    fn ladder_matches_double_and_add() {
        let mut k = [0u8; 32];
        for i in 0..40u8 {
            for (j, b) in k.iter_mut().enumerate() {
                *b = b.wrapping_mul(31).wrapping_add(i ^ j as u8).wrapping_add(7);
            }
            assert_eq!(BASE8.mul_ct(&k), BASE8.mul_le(&k));
        }
        assert_eq!(BASE8.mul_ct(&[0u8; 32]), Point::identity());
    }

    #[test]
    fn shr3() {
        let mut v = [0u8; 32];
        v[1] = 0b0000_0001; // 256
        let r = shr3_le(&v);
        assert_eq!(r[0], 32);
    }
}
