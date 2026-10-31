//! Circom 2 witness calculator: runs the circuit's wasm and reads the witness
//! back, following circom_runtime's WitnessCalculatorCircom2.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

use crate::Error;

/// FNV-1a 64 of a signal name, split into (MSB, LSB) words as the wasm wants.
pub fn signal_hash(name: &str) -> (i32, i32) {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for b in name.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    ((h >> 32) as u32 as i32, h as u32 as i32)
}

/// The calls a Circom 2 witness wasm exports.
pub trait CircomInstance {
    fn get_version(&mut self) -> Result<u32, Error>;
    fn get_field_num_len32(&mut self) -> Result<u32, Error>;
    fn get_raw_prime(&mut self) -> Result<(), Error>;
    fn read_shared_rw_memory(&mut self, i: u32) -> Result<u32, Error>;
    fn write_shared_rw_memory(&mut self, i: u32, v: u32) -> Result<(), Error>;
    fn init(&mut self, sanity_check: bool) -> Result<(), Error>;
    fn get_input_signal_size(&mut self, h_msb: i32, h_lsb: i32) -> Result<i32, Error>;
    fn set_input_signal(&mut self, h_msb: i32, h_lsb: i32, i: u32) -> Result<(), Error>;
    fn get_input_size(&mut self) -> Result<u32, Error>;
    fn get_witness_size(&mut self) -> Result<u32, Error>;
    fn get_witness(&mut self, i: u32) -> Result<(), Error>;
}

pub fn exception_message(code: i32) -> &'static str {
    match code {
        1 => "signal not found",
        2 => "too many signals set",
        3 => "signal already set",
        4 => "assert failed",
        5 => "not enough memory",
        6 => "input signal array access exceeds the size",
        _ => "unknown error",
    }
}

/// Witness calculator over any backend.
pub struct WitnessCalculator<I: CircomInstance> {
    instance: I,
    n32: u32,
    witness_size: u32,
}

impl<I: CircomInstance> WitnessCalculator<I> {
    pub fn new(mut instance: I) -> Result<Self, Error> {
        let version = instance.get_version()?;
        if version != 2 {
            return Err(Error::Witness(format!(
                "circom wasm version {version}, need 2"
            )));
        }
        let n32 = instance.get_field_num_len32()?;
        if n32 != 8 {
            return Err(Error::Witness(format!("field of {n32} words, need 8")));
        }
        instance.get_raw_prime()?;
        let mut prime = [0u8; 32];
        for j in 0..n32 {
            let w = instance.read_shared_rw_memory(j)?;
            prime[(j * 4) as usize..(j * 4 + 4) as usize].copy_from_slice(&w.to_le_bytes());
        }
        if prime[..] != Fr::MODULUS.to_bytes_le()[..] {
            return Err(Error::Witness(
                "circuit prime is not BN254's scalar field".into(),
            ));
        }
        let witness_size = instance.get_witness_size()?;
        Ok(Self {
            instance,
            n32,
            witness_size,
        })
    }

    pub fn witness_size(&self) -> usize {
        self.witness_size as usize
    }

    /// `inputs` are (signal name, flattened values) in any order.
    pub fn calculate(&mut self, inputs: &[(String, Vec<Fr>)]) -> Result<Vec<Fr>, Error> {
        let inst = &mut self.instance;
        inst.init(false)?;
        let mut count = 0u32;
        for (name, values) in inputs {
            let (msb, lsb) = signal_hash(name);
            let size = inst.get_input_signal_size(msb, lsb)?;
            if size < 0 {
                return Err(Error::Witness(format!("signal {name} not found")));
            }
            if values.len() != size as usize {
                return Err(Error::Witness(format!(
                    "signal {name} takes {size} values, got {}",
                    values.len()
                )));
            }
            for (i, v) in values.iter().enumerate() {
                let limbs = v.into_bigint().0;
                for j in 0..self.n32 {
                    let limb = limbs[(j / 2) as usize];
                    let word = if j % 2 == 0 {
                        limb as u32
                    } else {
                        (limb >> 32) as u32
                    };
                    inst.write_shared_rw_memory(j, word)?;
                }
                inst.set_input_signal(msb, lsb, i as u32)?;
                count += 1;
            }
        }
        let needed = inst.get_input_size()?;
        if count < needed {
            return Err(Error::Witness(format!(
                "only {count} of {needed} inputs set"
            )));
        }
        let mut out = Vec::with_capacity(self.witness_size as usize);
        let mut bytes = [0u8; 32];
        for i in 0..self.witness_size {
            inst.get_witness(i)?;
            for j in 0..self.n32 {
                let w = inst.read_shared_rw_memory(j)?;
                bytes[(j * 4) as usize..(j * 4 + 4) as usize].copy_from_slice(&w.to_le_bytes());
            }
            out.push(Fr::from_le_bytes_mod_order(&bytes));
        }
        Ok(out)
    }
}
