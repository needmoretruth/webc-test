//! `webc-vm`: a deterministic, gas-metered WebAssembly execution engine for the
//! WEBC blockchain's contract runtime.
//!
//! This crate is a self-contained wasm sandbox. It does **not** depend on the
//! chain; instead it exposes a narrow capability seam — [`VmHost`] — that the
//! chain implements as a thin adapter over its `ContractContext` (declared
//! footprint state + block epoch) and `GasMeter` (checked, fail-closed
//! metering). Given a module, an input, a host, and [`VmLimits`], the VM runs the
//! guest's `webc_call` entry point and returns the bytes it submits, or a typed
//! [`VmError`]. There is no reachable panic path from hostile input.
//!
//! # Determinism
//!
//! Every node must compute identical results, so the engine is stripped of all
//! sources of divergence:
//!
//! - **Interpreter, not JIT.** Execution uses `wasmi` `0.46` (a pure-Rust
//!   interpreter), which is deterministic by construction — no codegen, no
//!   platform-specific behavior.
//! - **Fuel, not time.** Metering is fuel-based (per executed instruction), never
//!   wall-clock; fuel exhaustion fails closed as [`VmError::OutOfGas`].
//! - **No floats.** `f32`/`f64` types and instructions are rejected at compile
//!   time (`Config::floats(false)`). Wasm float *arithmetic* is spec-deterministic,
//!   but NaN payload bits are not fully pinned across producers, so floats are
//!   forbidden outright rather than canonicalized — contracts use integer
//!   arithmetic only.
//! - **No nondeterministic or ambient features.** [`validate_module`] rejects
//!   SIMD, threads/atomics, shared/64-bit memory, custom page sizes, bulk-memory,
//!   reference types, tail calls, extended-const, the component model, imported
//!   memories/tables/globals, and imports from any module other than `"webc"`. It
//!   fails closed on anything the deterministic engine does not recognize.
//! - **No clock, network, files, or randomness.** The only imports available to
//!   the guest are the [`execute`] host functions.
//!
//! # Example
//!
//! ```no_run
//! use webc_vm::{execute, VmError, VmHost, VmLimits};
//! use webc_crypto::Hash256;
//!
//! # struct MyHost;
//! # impl VmHost for MyHost {
//! #     fn get(&mut self, _k: &Hash256) -> Result<Option<Vec<u8>>, VmError> { Ok(None) }
//! #     fn set(&mut self, _k: Hash256, _v: Vec<u8>) -> Result<(), VmError> { Ok(()) }
//! #     fn epoch(&self) -> u64 { 0 }
//! #     fn charge_gas(&mut self, _u: u64) -> Result<(), VmError> { Ok(()) }
//! # }
//! # fn run(module: &[u8]) -> Result<Vec<u8>, VmError> {
//! let limits = VmLimits::default();
//! let mut host = MyHost;
//! let output = execute(module, b"input", &mut host, &limits)?;
//! # Ok(output)
//! # }
//! ```

#![forbid(unsafe_code)]

mod engine;
mod error;
mod execute;
mod host;
mod limits;
mod validate;

pub use error::VmError;
pub use execute::execute;
pub use host::VmHost;
pub use limits::{VmLimits, KEY_LEN};
pub use validate::validate_module;
