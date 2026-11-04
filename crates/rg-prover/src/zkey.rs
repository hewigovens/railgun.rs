// Ported from ark-circom 0.5.0 (src/zkey.rs), https://github.com/arkworks-rs/circom-compat,
// Copyright (c) 2021 Georgios Konstantopoulos, licensed MIT OR Apache-2.0.
// Changes: byteorder replaced with std reads, section lookups return errors instead of panicking, the header keeps n_public for callers, tests dropped.
//! ZKey Parsing
//!
//! Each ZKey file is broken into sections:
//!  Header(1)
//!       Prover Type 1 Groth
//!  HeaderGroth(2)
//!       n8q
//!       q
//!       n8r
//!       r
//!       NVars
//!       NPub
//!       DomainSize  (multiple of 2
//!       alpha1
//!       beta1
//!       delta1
//!       beta2
//!       gamma2
//!       delta2
//!  IC(3)  Coefs(4)  PointsA(5)  PointsB1(6)  PointsB2(7)  PointsC(8)  PointsH(9)  Contributions(10)
use ark_ff::{BigInteger256, PrimeField};
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, SerializationError};
use ark_std::log2;

use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom},
};

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::Zero;
use ark_groth16::{ProvingKey, VerifyingKey};

type IoResult<T> = Result<T, SerializationError>;

trait ReadLe: Read {
    fn read_u32_le(&mut self) -> std::io::Result<u32> {
        let mut b = [0u8; 4];
        self.read_exact(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn read_u64_le(&mut self) -> std::io::Result<u64> {
        let mut b = [0u8; 8];
        self.read_exact(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
}
impl<R: Read + ?Sized> ReadLe for R {}

#[derive(Clone, Debug)]
struct Section {
    position: u64,
    #[allow(dead_code)]
    size: usize,
}

/// Reads a SnarkJS ZKey file into an Arkworks ProvingKey.
pub fn read_zkey<R: Read + Seek>(
    reader: &mut R,
) -> IoResult<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)> {
    let mut binfile = BinFile::new(reader)?;
    let proving_key = binfile.proving_key()?;
    let matrices = binfile.matrices()?;
    Ok((proving_key, matrices))
}

#[derive(Debug)]
struct BinFile<'a, R> {
    #[allow(dead_code)]
    ftype: String,
    #[allow(dead_code)]
    version: u32,
    sections: HashMap<u32, Vec<Section>>,
    reader: &'a mut R,
}

impl<'a, R: Read + Seek> BinFile<'a, R> {
    fn new(reader: &'a mut R) -> IoResult<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;

        let version = reader.read_u32_le()?;

        let num_sections = reader.read_u32_le()?;

        let mut sections = HashMap::new();
        for _ in 0..num_sections {
            let section_id = reader.read_u32_le()?;
            let section_length = reader.read_u64_le()?;

            let section = sections.entry(section_id).or_insert_with(Vec::new);
            section.push(Section {
                position: reader.stream_position()?,
                size: section_length as usize,
            });

            reader.seek(SeekFrom::Current(section_length as i64))?;
        }

        if &magic != b"zkey" {
            return Err(SerializationError::InvalidData);
        }
        Ok(Self {
            ftype: String::from_utf8_lossy(&magic[..]).to_string(),
            version,
            sections,
            reader,
        })
    }

    fn proving_key(&mut self) -> IoResult<ProvingKey<Bn254>> {
        let header = self.groth_header()?;
        let ic = self.ic(header.n_public)?;

        let a_query = self.a_query(header.n_vars)?;
        let b_g1_query = self.b_g1_query(header.n_vars)?;
        let b_g2_query = self.b_g2_query(header.n_vars)?;
        let l_len = header
            .n_vars
            .checked_sub(header.n_public + 1)
            .ok_or(SerializationError::InvalidData)?;
        let l_query = self.l_query(l_len)?;
        let h_query = self.h_query(header.domain_size as usize)?;

        let vk = VerifyingKey::<Bn254> {
            alpha_g1: header.verifying_key.alpha_g1,
            beta_g2: header.verifying_key.beta_g2,
            gamma_g2: header.verifying_key.gamma_g2,
            delta_g2: header.verifying_key.delta_g2,
            gamma_abc_g1: ic,
        };

        let pk = ProvingKey::<Bn254> {
            vk,
            beta_g1: header.verifying_key.beta_g1,
            delta_g1: header.verifying_key.delta_g1,
            a_query,
            b_g1_query,
            b_g2_query,
            h_query,
            l_query,
        };

        Ok(pk)
    }

    fn get_section(&self, id: u32) -> IoResult<Section> {
        self.sections
            .get(&id)
            .and_then(|s| s.first())
            .cloned()
            .ok_or(SerializationError::InvalidData)
    }

    fn groth_header(&mut self) -> IoResult<HeaderGroth> {
        let section = self.get_section(2)?;
        let header = HeaderGroth::new(&mut self.reader, &section)?;
        Ok(header)
    }

    fn ic(&mut self, n_public: usize) -> IoResult<Vec<G1Affine>> {
        // the range is non-inclusive so we do +1 to get all inputs
        self.g1_section(n_public + 1, 3)
    }

    /// Returns the [`ConstraintMatrices`] corresponding to the zkey
    pub fn matrices(&mut self) -> IoResult<ConstraintMatrices<Fr>> {
        let header = self.groth_header()?;

        let section = self.get_section(4)?;
        self.reader.seek(SeekFrom::Start(section.position))?;
        let num_coeffs: u32 = self.reader.read_u32_le()?;

        // insantiate AB
        let mut matrices = vec![vec![vec![]; header.domain_size as usize]; 2];
        let mut max_constraint_index = 0;
        for _ in 0..num_coeffs {
            let matrix: u32 = self.reader.read_u32_le()?;
            let constraint: u32 = self.reader.read_u32_le()?;
            let signal: u32 = self.reader.read_u32_le()?;

            let value: Fr = deserialize_field_fr(&mut self.reader)?;
            max_constraint_index = std::cmp::max(max_constraint_index, constraint);
            let row = matrices
                .get_mut(matrix as usize)
                .and_then(|m| m.get_mut(constraint as usize))
                .ok_or(SerializationError::InvalidData)?;
            row.push((value, signal as usize));
        }

        let num_constraints = (max_constraint_index as usize)
            .checked_sub(header.n_public)
            .ok_or(SerializationError::InvalidData)?;
        // Remove the public input constraints, Arkworks adds them later
        matrices.iter_mut().for_each(|m| {
            m.truncate(num_constraints);
        });
        // This is taken from Arkworks' to_matrices() function
        let a = matrices[0].clone();
        let b = matrices[1].clone();
        let a_num_non_zero: usize = a.iter().map(|lc| lc.len()).sum();
        let b_num_non_zero: usize = b.iter().map(|lc| lc.len()).sum();
        let matrices = ConstraintMatrices {
            num_instance_variables: header.n_public + 1,
            num_witness_variables: header.n_vars - header.n_public,
            num_constraints,

            a_num_non_zero,
            b_num_non_zero,
            c_num_non_zero: 0,

            a,
            b,
            c: vec![],
        };

        Ok(matrices)
    }

    fn a_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 5)
    }

    fn b_g1_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 6)
    }

    fn b_g2_query(&mut self, n_vars: usize) -> IoResult<Vec<G2Affine>> {
        self.g2_section(n_vars, 7)
    }

    fn l_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 8)
    }

    fn h_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 9)
    }

    fn g1_section(&mut self, num: usize, section_id: usize) -> IoResult<Vec<G1Affine>> {
        let section = self.get_section(section_id as u32)?;
        self.reader.seek(SeekFrom::Start(section.position))?;
        deserialize_g1_vec(self.reader, num as u32)
    }

    fn g2_section(&mut self, num: usize, section_id: usize) -> IoResult<Vec<G2Affine>> {
        let section = self.get_section(section_id as u32)?;
        self.reader.seek(SeekFrom::Start(section.position))?;
        deserialize_g2_vec(self.reader, num as u32)
    }
}

#[derive(Default, Clone, Debug, CanonicalDeserialize)]
pub struct ZVerifyingKey {
    alpha_g1: G1Affine,
    beta_g1: G1Affine,
    beta_g2: G2Affine,
    gamma_g2: G2Affine,
    delta_g1: G1Affine,
    delta_g2: G2Affine,
}

impl ZVerifyingKey {
    fn new<R: Read>(reader: &mut R) -> IoResult<Self> {
        let alpha_g1 = deserialize_g1(reader)?;
        let beta_g1 = deserialize_g1(reader)?;
        let beta_g2 = deserialize_g2(reader)?;
        let gamma_g2 = deserialize_g2(reader)?;
        let delta_g1 = deserialize_g1(reader)?;
        let delta_g2 = deserialize_g2(reader)?;

        Ok(Self {
            alpha_g1,
            beta_g1,
            beta_g2,
            gamma_g2,
            delta_g1,
            delta_g2,
        })
    }
}

#[derive(Clone, Debug)]
struct HeaderGroth {
    #[allow(dead_code)]
    n8q: u32,
    #[allow(dead_code)]
    q: BigInteger256,
    #[allow(dead_code)]
    n8r: u32,
    #[allow(dead_code)]
    r: BigInteger256,

    n_vars: usize,
    n_public: usize,

    domain_size: u32,
    #[allow(dead_code)]
    power: u32,

    verifying_key: ZVerifyingKey,
}

impl HeaderGroth {
    fn new<R: Read + Seek>(reader: &mut R, section: &Section) -> IoResult<Self> {
        reader.seek(SeekFrom::Start(section.position))?;
        Self::read(reader)
    }

    fn read<R: Read>(mut reader: &mut R) -> IoResult<Self> {
        // TODO: Impl From<u32> in Arkworks
        let n8q: u32 = u32::deserialize_uncompressed(&mut reader)?;
        // group order r of Bn254
        let q = BigInteger256::deserialize_uncompressed(&mut reader)?;

        let n8r: u32 = u32::deserialize_uncompressed(&mut reader)?;
        // Prime field modulus
        let r = BigInteger256::deserialize_uncompressed(&mut reader)?;

        let n_vars = u32::deserialize_uncompressed(&mut reader)? as usize;
        let n_public = u32::deserialize_uncompressed(&mut reader)? as usize;

        let domain_size: u32 = u32::deserialize_uncompressed(&mut reader)?;
        let power = log2(domain_size as usize);

        let verifying_key = ZVerifyingKey::new(&mut reader)?;

        Ok(Self {
            n8q,
            q,
            n8r,
            r,
            n_vars,
            n_public,
            domain_size,
            power,
            verifying_key,
        })
    }
}

// need to divide by R, since snarkjs outputs the zkey with coefficients multiplieid by R^2
fn deserialize_field_fr<R: Read>(reader: &mut R) -> IoResult<Fr> {
    let bigint = BigInteger256::deserialize_uncompressed(reader)?;
    Ok(Fr::new_unchecked(Fr::new_unchecked(bigint).into_bigint()))
}

// skips the multiplication by R because Circom points are already in Montgomery form
fn deserialize_field<R: Read>(reader: &mut R) -> IoResult<Fq> {
    let bigint = BigInteger256::deserialize_uncompressed(reader)?;
    // if you use Fq::new it multiplies by R
    Ok(Fq::new_unchecked(bigint))
}

pub fn deserialize_field2<R: Read>(reader: &mut R) -> IoResult<Fq2> {
    let c0 = deserialize_field(reader)?;
    let c1 = deserialize_field(reader)?;
    Ok(Fq2::new(c0, c1))
}

fn deserialize_g1<R: Read>(reader: &mut R) -> IoResult<G1Affine> {
    let x = deserialize_field(reader)?;
    let y = deserialize_field(reader)?;
    let infinity = x.is_zero() && y.is_zero();
    if infinity {
        Ok(G1Affine::identity())
    } else {
        Ok(G1Affine::new(x, y))
    }
}

fn deserialize_g2<R: Read>(reader: &mut R) -> IoResult<G2Affine> {
    let f1 = deserialize_field2(reader)?;
    let f2 = deserialize_field2(reader)?;
    let infinity = f1.is_zero() && f2.is_zero();
    if infinity {
        Ok(G2Affine::identity())
    } else {
        Ok(G2Affine::new(f1, f2))
    }
}

fn deserialize_g1_vec<R: Read>(reader: &mut R, n_vars: u32) -> IoResult<Vec<G1Affine>> {
    (0..n_vars).map(|_| deserialize_g1(reader)).collect()
}

fn deserialize_g2_vec<R: Read>(reader: &mut R, n_vars: u32) -> IoResult<Vec<G2Affine>> {
    (0..n_vars).map(|_| deserialize_g2(reader)).collect()
}
