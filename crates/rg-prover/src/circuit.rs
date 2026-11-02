use ark_bn254::{Bn254, Fr};
use ark_ff::UniformRand;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintMatrices;
use rand::{CryptoRng, RngCore};

use crate::{CircomReduction, Error, zkey};

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

    /// Prove from a full witness (witness[0] is 1). Returns the proof and its public inputs (witness[1..=num_public]).
    pub fn prove<R: RngCore + CryptoRng>(
        &self,
        witness: &[Fr],
        rng: &mut R,
    ) -> Result<(Proof<Bn254>, Vec<Fr>), Error> {
        let m = &self.matrices;
        // ark-circom's matrices count one witness variable too many, so take the variable count from the key's A query (one point per variable).
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
