//! Witness wasm on wasmtime (Cranelift JIT), for macOS and Android.

use wasmtime::{Caller, Engine, Linker, Module, Store, TypedFunc};

use crate::witness::{exception_message, CircomInstance, WitnessCalculator};
use crate::Error;

fn err(e: impl std::fmt::Display) -> Error {
    Error::Witness(e.to_string())
}

/// Compiled witness module; instantiate once per witness.
pub struct WasmtimeCircuit {
    engine: Engine,
    module: Module,
}

impl WasmtimeCircuit {
    pub fn new(wasm: &[u8]) -> Result<Self, Error> {
        let engine = Engine::default();
        let module = Module::new(&engine, wasm).map_err(err)?;
        Ok(Self { engine, module })
    }

    pub fn calculator(&self) -> Result<WitnessCalculator<WasmtimeInstance>, Error> {
        let mut store = Store::new(&self.engine, ());
        let mut linker = Linker::<()>::new(&self.engine);
        linker
            .func_wrap(
                "runtime",
                "exceptionHandler",
                |_: Caller<'_, ()>, code: i32| {
                    Err::<(), _>(wasmtime::Error::msg(format!(
                        "circuit exception {code}: {}",
                        exception_message(code)
                    )))
                },
            )
            .map_err(err)?;
        linker
            .func_wrap("runtime", "showSharedRWMemory", |_: Caller<'_, ()>| {})
            .map_err(err)?;
        // Debug output from newer circom versions, which nothing here reads.
        for name in ["printErrorMessage", "writeBufferMessage"] {
            linker
                .func_wrap("runtime", name, |_: Caller<'_, ()>| {})
                .map_err(err)?;
        }
        let instance = linker.instantiate(&mut store, &self.module).map_err(err)?;
        macro_rules! f {
            ($name:literal) => {
                instance.get_typed_func(&mut store, $name).map_err(err)?
            };
        }
        let inst = WasmtimeInstance {
            get_version: f!("getVersion"),
            get_field_num_len32: f!("getFieldNumLen32"),
            get_raw_prime: f!("getRawPrime"),
            read_shared: f!("readSharedRWMemory"),
            write_shared: f!("writeSharedRWMemory"),
            init: f!("init"),
            get_input_signal_size: f!("getInputSignalSize"),
            set_input_signal: f!("setInputSignal"),
            get_input_size: f!("getInputSize"),
            get_witness_size: f!("getWitnessSize"),
            get_witness: f!("getWitness"),
            store,
        };
        WitnessCalculator::new(inst)
    }
}

pub struct WasmtimeInstance {
    store: Store<()>,
    get_version: TypedFunc<(), i32>,
    get_field_num_len32: TypedFunc<(), i32>,
    get_raw_prime: TypedFunc<(), ()>,
    read_shared: TypedFunc<i32, i32>,
    write_shared: TypedFunc<(i32, i32), ()>,
    init: TypedFunc<i32, ()>,
    get_input_signal_size: TypedFunc<(i32, i32), i32>,
    set_input_signal: TypedFunc<(i32, i32, i32), ()>,
    get_input_size: TypedFunc<(), i32>,
    get_witness_size: TypedFunc<(), i32>,
    get_witness: TypedFunc<i32, ()>,
}

impl CircomInstance for WasmtimeInstance {
    fn get_version(&mut self) -> Result<u32, Error> {
        self.get_version
            .call(&mut self.store, ())
            .map(|v| v as u32)
            .map_err(err)
    }
    fn get_field_num_len32(&mut self) -> Result<u32, Error> {
        self.get_field_num_len32
            .call(&mut self.store, ())
            .map(|v| v as u32)
            .map_err(err)
    }
    fn get_raw_prime(&mut self) -> Result<(), Error> {
        self.get_raw_prime.call(&mut self.store, ()).map_err(err)
    }
    fn read_shared_rw_memory(&mut self, i: u32) -> Result<u32, Error> {
        self.read_shared
            .call(&mut self.store, i as i32)
            .map(|v| v as u32)
            .map_err(err)
    }
    fn write_shared_rw_memory(&mut self, i: u32, v: u32) -> Result<(), Error> {
        self.write_shared
            .call(&mut self.store, (i as i32, v as i32))
            .map_err(err)
    }
    fn init(&mut self, sanity_check: bool) -> Result<(), Error> {
        self.init
            .call(&mut self.store, sanity_check as i32)
            .map_err(err)
    }
    fn get_input_signal_size(&mut self, h_msb: i32, h_lsb: i32) -> Result<i32, Error> {
        self.get_input_signal_size
            .call(&mut self.store, (h_msb, h_lsb))
            .map_err(err)
    }
    fn set_input_signal(&mut self, h_msb: i32, h_lsb: i32, i: u32) -> Result<(), Error> {
        self.set_input_signal
            .call(&mut self.store, (h_msb, h_lsb, i as i32))
            .map_err(err)
    }
    fn get_input_size(&mut self) -> Result<u32, Error> {
        self.get_input_size
            .call(&mut self.store, ())
            .map(|v| v as u32)
            .map_err(err)
    }
    fn get_witness_size(&mut self) -> Result<u32, Error> {
        self.get_witness_size
            .call(&mut self.store, ())
            .map(|v| v as u32)
            .map_err(err)
    }
    fn get_witness(&mut self, i: u32) -> Result<(), Error> {
        self.get_witness
            .call(&mut self.store, i as i32)
            .map_err(err)
    }
}
