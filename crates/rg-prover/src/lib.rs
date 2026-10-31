//! Groth16 proving for Railgun's circom circuits with arkworks.
//!
//! - [`witness`]: runs the circuit's witness wasm (wasmi by default, wasmtime
//!   with the `wasmtime` feature) and returns the full witness.
//! - [`zkey`] and [`qap`]: snarkjs zkey loading and snarkjs's R1CS-to-QAP
//!   reduction, ported from ark-circom 0.5 (MIT OR Apache-2.0).
//! - [`prove`] and [`verify`], with snarkjs JSON for keys and proofs.
//!
//! Artifacts (wasm, zkey, vkey) are passed in at runtime; none ship here.

pub mod qap;
pub mod witness;
pub mod zkey;

#[cfg(feature = "wasmi")]
mod wasmi_backend;
#[cfg(feature = "wasmi")]
pub use wasmi_backend::{WasmiCircuit, WasmiInstance};
#[cfg(feature = "wasmtime")]
mod wasmtime_backend;
#[cfg(feature = "wasmtime")]
pub use wasmtime_backend::{WasmtimeCircuit, WasmtimeInstance};

use std::str::FromStr;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintMatrices;
use rand::{CryptoRng, RngCore};
use serde_json::Value;

pub use qap::CircomReduction;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("witness: {0}")]
    Witness(String),
    #[error("zkey: {0}")]
    Zkey(String),
    #[error("json: {0}")]
    Json(String),
    #[error("prove: {0}")]
    Prove(String),
}

/// A proving key with the constraint matrices snarkjs's reduction needs.
pub struct Circuit {
    pub pk: ProvingKey<Bn254>,
    pub matrices: ConstraintMatrices<Fr>,
}

impl Circuit {
    pub fn from_zkey(bytes: &[u8]) -> Result<Self, Error> {
        let mut cur = std::io::Cursor::new(bytes);
        let (pk, matrices) = zkey::read_zkey(&mut cur).map_err(|e| Error::Zkey(e.to_string()))?;
        Ok(Self { pk, matrices })
    }

    /// Public inputs, not counting the constant 1.
    pub fn num_public(&self) -> usize {
        self.matrices.num_instance_variables - 1
    }

    /// Prove from a full witness (witness[0] is 1). Returns the proof and its
    /// public inputs (witness[1..=num_public]).
    pub fn prove<R: RngCore + CryptoRng>(
        &self,
        witness: &[Fr],
        rng: &mut R,
    ) -> Result<(Proof<Bn254>, Vec<Fr>), Error> {
        let m = &self.matrices;
        // ark-circom's matrices count one witness variable too many, so take
        // the variable count from the key's A query (one point per variable).
        if witness.len() != self.pk.a_query.len() {
            return Err(Error::Prove(format!(
                "witness has {} values, circuit needs {}",
                witness.len(),
                self.pk.a_query.len()
            )));
        }
        let r = Fr::rand(rng);
        let s = Fr::rand(rng);
        let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
            &self.pk,
            r,
            s,
            m,
            m.num_instance_variables,
            m.num_constraints,
            witness,
        )
        .map_err(|e| Error::Prove(e.to_string()))?;
        Ok((proof, witness[1..m.num_instance_variables].to_vec()))
    }
}

pub fn prepare(vk: &VerifyingKey<Bn254>) -> PreparedVerifyingKey<Bn254> {
    ark_groth16::prepare_verifying_key(vk)
}

pub fn verify(
    vk: &VerifyingKey<Bn254>,
    public: &[Fr],
    proof: &Proof<Bn254>,
) -> Result<bool, Error> {
    if public.len() + 1 != vk.gamma_abc_g1.len() {
        return Err(Error::Prove(format!(
            "{} public inputs, key takes {}",
            public.len(),
            vk.gamma_abc_g1.len() - 1
        )));
    }
    Groth16::<Bn254>::verify_proof(&prepare(vk), proof, public)
        .map_err(|e| Error::Prove(e.to_string()))
}

// snarkjs JSON ------------------------------------------------------------

fn jerr(what: &str) -> Error {
    Error::Json(what.to_string())
}

fn dec_str(v: &Value) -> Result<&str, Error> {
    v.as_str().ok_or_else(|| jerr("expected a decimal string"))
}

fn parse_fq(v: &Value) -> Result<Fq, Error> {
    Fq::from_str(dec_str(v)?).map_err(|_| jerr("bad base field element"))
}

pub fn parse_fr(v: &Value) -> Result<Fr, Error> {
    Fr::from_str(dec_str(v)?).map_err(|_| jerr("bad scalar"))
}

fn idx(v: &Value, i: usize) -> Result<&Value, Error> {
    v.get(i).ok_or_else(|| jerr("array too short"))
}

fn parse_g1(v: &Value) -> Result<G1Affine, Error> {
    let x = parse_fq(idx(v, 0)?)?;
    let y = parse_fq(idx(v, 1)?)?;
    let z = parse_fq(idx(v, 2)?)?;
    if z.is_zero() {
        return Ok(G1Affine::identity());
    }
    if z != Fq::from(1u8) {
        return Err(jerr("G1 point not in affine form"));
    }
    let p = G1Affine::new_unchecked(x, y);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(jerr("G1 point not on the curve"));
    }
    Ok(p)
}

fn parse_g2(v: &Value) -> Result<G2Affine, Error> {
    let f2 = |w: &Value| -> Result<Fq2, Error> {
        Ok(Fq2::new(parse_fq(idx(w, 0)?)?, parse_fq(idx(w, 1)?)?))
    };
    let x = f2(idx(v, 0)?)?;
    let y = f2(idx(v, 1)?)?;
    let z = f2(idx(v, 2)?)?;
    if z.is_zero() {
        return Ok(G2Affine::identity());
    }
    if z != Fq2::new(Fq::from(1u8), Fq::zero()) {
        return Err(jerr("G2 point not in affine form"));
    }
    let p = G2Affine::new_unchecked(x, y);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(jerr("G2 point not on the curve"));
    }
    Ok(p)
}

/// snarkjs `verification_key.json`.
pub fn vkey_from_json(v: &Value) -> Result<VerifyingKey<Bn254>, Error> {
    if v["protocol"] != "groth16" || v["curve"] != "bn128" {
        return Err(jerr("not a groth16 bn128 key"));
    }
    let ic = v["IC"].as_array().ok_or_else(|| jerr("IC"))?;
    let vk = VerifyingKey {
        alpha_g1: parse_g1(&v["vk_alpha_1"])?,
        beta_g2: parse_g2(&v["vk_beta_2"])?,
        gamma_g2: parse_g2(&v["vk_gamma_2"])?,
        delta_g2: parse_g2(&v["vk_delta_2"])?,
        gamma_abc_g1: ic.iter().map(parse_g1).collect::<Result<_, _>>()?,
    };
    if let Some(n) = v["nPublic"].as_u64() {
        if n as usize + 1 != vk.gamma_abc_g1.len() {
            return Err(jerr("nPublic does not match IC"));
        }
    }
    Ok(vk)
}

/// snarkjs proof JSON (`pi_a`, `pi_b`, `pi_c`).
pub fn proof_from_json(v: &Value) -> Result<Proof<Bn254>, Error> {
    Ok(Proof {
        a: parse_g1(&v["pi_a"])?,
        b: parse_g2(&v["pi_b"])?,
        c: parse_g1(&v["pi_c"])?,
    })
}

fn dec<F: PrimeField>(x: &F) -> Value {
    Value::String(x.into_bigint().to_string())
}

pub fn proof_to_json(p: &Proof<Bn254>) -> Value {
    serde_json::json!({
        "pi_a": [dec(&p.a.x), dec(&p.a.y), "1"],
        "pi_b": [[dec(&p.b.x.c0), dec(&p.b.x.c1)], [dec(&p.b.y.c0), dec(&p.b.y.c1)], ["1", "0"]],
        "pi_c": [dec(&p.c.x), dec(&p.c.y), "1"],
        "protocol": "groth16",
        "curve": "bn128",
    })
}

/// The arkworks types this crate's API uses.
pub mod ark_types {
    pub use ark_bn254::{Bn254, Fr};
    pub use ark_groth16::{Proof, VerifyingKey};
}
