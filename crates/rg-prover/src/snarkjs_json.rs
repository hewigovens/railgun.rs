use std::str::FromStr;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{PrimeField, Zero};
use ark_groth16::{Proof, VerifyingKey};
use serde_json::Value;

use crate::Error;

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
    if let Some(n) = v["nPublic"].as_u64()
        && n as usize + 1 != vk.gamma_abc_g1.len()
    {
        return Err(jerr("nPublic does not match IC"));
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
