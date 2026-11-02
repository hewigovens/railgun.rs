use alloy_primitives::U256;
use alloy_sol_types::SolCall;
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField, Zero};
use rg_prover::ark_types::{Proof, VerifyingKey};
use rg_sync::abi;

use crate::Error;

fn u256<F: PrimeField>(x: &F) -> U256 {
    U256::from_be_slice(&x.into_bigint().to_bytes_be())
}

/// `formatProof`: the contract takes G2 coordinates imaginary part first.
pub fn snark_proof(p: &Proof<Bn254>) -> abi::SnarkProof {
    abi::SnarkProof {
        a: abi::G1Point {
            x: u256(&p.a.x),
            y: u256(&p.a.y),
        },
        b: abi::G2Point {
            x: [u256(&p.b.x.c1), u256(&p.b.x.c0)],
            y: [u256(&p.b.y.c1), u256(&p.b.y.c0)],
        },
        c: abi::G1Point {
            x: u256(&p.c.x),
            y: u256(&p.c.y),
        },
    }
}

pub fn transact_calldata(txs: Vec<abi::Transaction>) -> Vec<u8> {
    abi::transactCall { _transactions: txs }.abi_encode()
}

fn fq(x: &U256) -> Result<Fq, Error> {
    let b: [u8; 32] = x.to_be_bytes();
    let v = Fq::from_be_bytes_mod_order(&b);
    if u256(&v) != *x {
        return Err(Error::BadKey("coordinate above the field modulus"));
    }
    Ok(v)
}

fn g1(p: &abi::G1Point) -> Result<G1Affine, Error> {
    let (x, y) = (fq(&p.x)?, fq(&p.y)?);
    if x.is_zero() && y.is_zero() {
        return Ok(G1Affine::identity());
    }
    let pt = G1Affine::new_unchecked(x, y);
    if !pt.is_on_curve() {
        return Err(Error::BadKey("G1 point not on the curve"));
    }
    Ok(pt)
}

fn g2(p: &abi::G2Point) -> Result<G2Affine, Error> {
    let x = Fq2::new(fq(&p.x[1])?, fq(&p.x[0])?);
    let y = Fq2::new(fq(&p.y[1])?, fq(&p.y[0])?);
    let pt = G2Affine::new_unchecked(x, y);
    if !pt.is_on_curve() || !pt.is_in_correct_subgroup_assuming_on_curve() {
        return Err(Error::BadKey("G2 point not on the curve"));
    }
    Ok(pt)
}

/// A verifying key as the contract stores it (from `VerifyingKeySet`).
pub fn verifying_key_from_contract(vk: &abi::VerifyingKey) -> Result<VerifyingKey<Bn254>, Error> {
    Ok(VerifyingKey {
        alpha_g1: g1(&vk.alpha1)?,
        beta_g2: g2(&vk.beta2)?,
        gamma_g2: g2(&vk.gamma2)?,
        delta_g2: g2(&vk.delta2)?,
        gamma_abc_g1: vk.ic.iter().map(g1).collect::<Result<_, _>>()?,
    })
}
