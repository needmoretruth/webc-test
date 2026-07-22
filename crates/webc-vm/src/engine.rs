//! The single deterministic engine configuration shared by validation and
//! execution.
//!
//! Using one `Config` for both guarantees that whatever
//! [`crate::validate_module`] accepts is exactly what [`crate::execute`] will
//! run, and vice versa. Every nondeterministic or unbounded proposal is disabled
//! here; `wasmi` (a pure-Rust interpreter) has no SIMD, threads/atomics, or
//! host-randomness surface to begin with, so the remaining knobs close the gaps.

use wasmi::{Config, Engine};

/// Builds the deterministic wasm configuration used everywhere in the crate.
///
/// Determinism measures encoded here:
/// - **Fuel metering ON** (`consume_fuel`): execution cost is a deterministic
///   function of executed instructions, never wall-clock time.
/// - **Floats OFF** (`floats(false)`): `f32`/`f64` types and instructions are
///   rejected at compile time. Wasm float *arithmetic* is spec-deterministic,
///   but NaN payload bits are not fully pinned across producers; forbidding
///   floats outright removes that ambiguity with zero runtime cost. Contracts
///   use integer arithmetic only.
/// - **No reference types, no bulk-memory, no tail calls, no extended-const**:
///   these either widen the host/nondeterminism surface or are simply
///   unnecessary for contract logic, so they are turned off and any module using
///   them fails to compile.
/// - **Only sign-extension, mutable-global, saturating-float-to-int, and
///   multi-value** remain enabled — all spec-deterministic, purely numeric
///   proposals. (`saturating_float_to_int` is inert while floats are disabled.)
///
/// SIMD, the threads/atomics proposal, GC, exceptions, and memory64 are not
/// supported by this `wasmi` line at all, so modules using them are rejected
/// during compilation — the engine fails closed on anything it does not
/// recognize.
pub(crate) fn deterministic_config() -> Config {
    let mut config = Config::default();
    config
        .consume_fuel(true)
        .floats(false)
        .wasm_mutable_global(true)
        .wasm_sign_extension(true)
        .wasm_saturating_float_to_int(true)
        .wasm_multi_value(true)
        .wasm_bulk_memory(false)
        .wasm_reference_types(false)
        .wasm_tail_call(false)
        .wasm_extended_const(false);
    config
}

/// Constructs a fresh [`Engine`] from [`deterministic_config`].
pub(crate) fn deterministic_engine() -> Engine {
    Engine::new(&deterministic_config())
}
