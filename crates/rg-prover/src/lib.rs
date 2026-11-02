//! Groth16 proving for Railgun's circom circuits with arkworks.
//!
//! - [`witness`]: runs the circuit's witness wasm (wasmi by default, wasmtime
//!   with the `wasmtime` feature) and returns the full witness.
//! - [`zkey`] and [`qap`]: snarkjs zkey loading and snarkjs's R1CS-to-QAP
//!   reduction, ported from ark-circom 0.5 (MIT OR Apache-2.0).
//! - [`prove`] and [`verify`], with snarkjs JSON for keys and proofs.
//!
//! Artifacts (wasm, zkey, vkey) are passed in at runtime; none ship here.

mod circuit;
mod error;
pub mod qap;
mod snarkjs_json;
#[cfg(feature = "wasmi")]
mod wasmi_backend;
#[cfg(feature = "wasmtime")]
mod wasmtime_backend;
pub mod witness;
pub mod zkey;

pub use circuit::{Circuit, prepare, verify};
pub use error::Error;
pub use qap::CircomReduction;
pub use snarkjs_json::{parse_fr, proof_from_json, proof_to_json, vkey_from_json};
#[cfg(feature = "wasmi")]
pub use wasmi_backend::{WasmiCircuit, WasmiInstance};
#[cfg(feature = "wasmtime")]
pub use wasmtime_backend::{WasmtimeCircuit, WasmtimeInstance};

/// The arkworks types this crate's API uses.
pub mod ark_types {
    pub use ark_bn254::{Bn254, Fr};
    pub use ark_groth16::{Proof, VerifyingKey};
}
