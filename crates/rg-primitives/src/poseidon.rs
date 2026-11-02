//! circomlib-compatible Poseidon over BN254, 1 to 16 inputs.
//!
//! Port of codex-storage/rs-poseidon (MIT OR Apache-2.0), the implementation Railgun's own poseidon-hash-wasm uses, moved onto arkworks 0.5 with the constants parsed once instead of cloned per call. Constants are circomlib's optimized parameter set, vendored from rs-poseidon.

use std::sync::LazyLock;

use ark_ff::{Field, PrimeField, Zero};

use crate::{Error, Fr};

const N_ROUNDS_F: usize = 8;
const N_ROUNDS_P: [usize; 16] = [
    56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
];
const CONSTANTS_JSON: &str = include_str!("poseidon_constants_opt.json");

struct Params {
    c: Vec<Fr>,
    s: Vec<Fr>,
    m: Vec<Vec<Fr>>,
    p: Vec<Vec<Fr>>,
}

static PARAMS: LazyLock<Vec<Params>> = LazyLock::new(|| {
    let json: serde_json::Value = serde_json::from_str(CONSTANTS_JSON).expect("poseidon constants");
    let parse = |v: &serde_json::Value| -> Fr {
        let s = v.as_str().expect("hex constant");
        let digits = s.strip_prefix("0x").unwrap_or(s);
        let bytes = decode_hex_padded(digits);
        Fr::from_be_bytes_mod_order(&bytes)
    };
    let vec1 = |v: &serde_json::Value| v.as_array().unwrap().iter().map(parse).collect::<Vec<_>>();
    let vec2 = |v: &serde_json::Value| v.as_array().unwrap().iter().map(vec1).collect::<Vec<_>>();
    (0..N_ROUNDS_P.len())
        .map(|i| Params {
            c: vec1(&json["C"][i]),
            s: vec1(&json["S"][i]),
            m: vec2(&json["M"][i]),
            p: vec2(&json["P"][i]),
        })
        .collect()
});

fn decode_hex_padded(digits: &str) -> Vec<u8> {
    let padded = if digits.len() % 2 == 1 {
        format!("0{digits}")
    } else {
        digits.to_string()
    };
    (0..padded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&padded[i..i + 2], 16).expect("hex digit"))
        .collect()
}

fn arc(state: &mut [Fr], c: &[Fr]) {
    for (a, ci) in state.iter_mut().zip(c) {
        *a += ci;
    }
}

fn sbox(state: &mut [Fr]) {
    for a in state.iter_mut() {
        *a = a.pow([5]);
    }
}

fn mix(state: &mut [Fr], m: &[Vec<Fr>]) {
    let t = state.len();
    let mut next = vec![Fr::zero(); t];
    for (i, out) in next.iter_mut().enumerate() {
        for j in 0..t {
            *out += m[j][i] * state[j];
        }
    }
    state.copy_from_slice(&next);
}

/// Poseidon hash of 1 to 16 field elements.
pub fn hash(inputs: &[Fr]) -> Result<Fr, Error> {
    if inputs.is_empty() || inputs.len() > N_ROUNDS_P.len() {
        return Err(Error::PoseidonArity(inputs.len()));
    }
    let t = inputs.len() + 1;
    let half_f = N_ROUNDS_F / 2;
    let n_rounds_p = N_ROUNDS_P[t - 2];
    let Params { c, s, m, p } = &PARAMS[t - 2];

    let mut state = Vec::with_capacity(t);
    state.push(Fr::zero());
    state.extend_from_slice(inputs);

    arc(&mut state, &c[0..t]);
    for r in 0..half_f {
        sbox(&mut state);
        arc(&mut state, &c[(r + 1) * t..(r + 2) * t]);
        mix(&mut state, if r == half_f - 1 { p } else { m });
    }

    for r in 0..n_rounds_p {
        state[0] = state[0].pow([5]);
        state[0] += c[(half_f + 1) * t + r];
        let base = (t * 2 - 1) * r;
        let mut s0 = Fr::zero();
        for i in 0..t {
            s0 += s[base + i] * state[i];
        }
        let x0 = state[0];
        for k in 1..t {
            state[k] += x0 * s[base + t + k - 1];
        }
        state[0] = s0;
    }

    for r in 0..half_f - 1 {
        let start = (half_f + 1) * t + n_rounds_p + r * t;
        sbox(&mut state);
        arc(&mut state, &c[start..start + t]);
        mix(&mut state, m);
    }

    sbox(&mut state);
    mix(&mut state, m);
    Ok(state[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::to_be_bytes;

    fn h(inputs: &[u64]) -> String {
        let v: Vec<Fr> = inputs.iter().map(|&x| Fr::from(x)).collect();
        hex::encode(to_be_bytes(&hash(&v).unwrap()))
    }

    // Vectors from rs-poseidon's own tests.
    #[test]
    fn known_values() {
        assert_eq!(
            h(&[0]),
            "2a09a9fd93c590c26b91effbb2499f07e8f7aa12e2b4940a3aed2411cb65e11c"
        );
        assert_eq!(
            h(&[0, 0]),
            "2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864"
        );
        assert_eq!(
            h(&[1, 2]),
            "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a"
        );
        assert_eq!(
            h(&[1, 2, 3, 4]),
            "299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465"
        );
        assert_eq!(
            h(&[0, 0, 0]),
            "0bc188d27dcceadc1dcfb6af0a7af08fe2864eecec96c5ae7cee6db31ba599aa"
        );
        assert_eq!(
            h(&[31213, 132]),
            "303f59cd0831b5633bcda50514521b33776b5d4280eb5868ba1dbbe2e4d76ab5"
        );
    }

    #[test]
    fn arity_limits() {
        assert_eq!(hash(&[]), Err(Error::PoseidonArity(0)));
        assert_eq!(hash(&[Fr::zero(); 17]), Err(Error::PoseidonArity(17)));
        assert!(hash(&[Fr::zero(); 16]).is_ok());
    }
}
