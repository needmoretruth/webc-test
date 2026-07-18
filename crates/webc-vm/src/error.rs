//! Typed, fail-closed errors surfaced by the VM.
//!
//! Every fallible path in [`crate::validate_module`] and [`crate::execute`]
//! terminates in one of these variants. There is deliberately no panic path a
//! hostile module can reach: out-of-bounds guest pointers, missing exports,
//! traps, and over-cap outputs all map to a typed error here, so a caller on the
//! consensus hot path can turn any failure into a deterministic, atomic rollback.

use thiserror::Error;

/// An error produced while validating or executing a WebAssembly contract module.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VmError {
    /// The module failed validation: malformed bytes, a forbidden/nondeterministic
    /// feature (SIMD, threads/atomics, bulk-memory, reference types, floats, …), or
    /// anything the deterministic engine refuses to compile.
    #[error("invalid wasm module: {0}")]
    InvalidModule(String),

    /// The module is larger than [`crate::VmLimits::max_module_bytes`].
    #[error("wasm module is {actual} bytes, above the maximum of {max}")]
    ModuleTooLarge {
        /// Actual module size in bytes.
        actual: usize,
        /// Configured maximum module size in bytes.
        max: usize,
    },

    /// The `input` handed to [`crate::execute`] exceeds
    /// [`crate::VmLimits::max_input_bytes`].
    #[error("input is {actual} bytes, above the maximum of {max}")]
    InputTooLarge {
        /// Actual input size in bytes.
        actual: usize,
        /// Configured maximum input size in bytes.
        max: usize,
    },

    /// The module declares more linear-memory pages than
    /// [`crate::VmLimits::max_memory_pages`] allows.
    #[error("wasm module requests {pages} memory pages, above the maximum of {max}")]
    MemoryLimitExceeded {
        /// Requested pages (initial or declared maximum, whichever is larger).
        pages: u64,
        /// Configured maximum pages.
        max: u32,
    },

    /// Instantiation failed (e.g. an import could not be satisfied or the start
    /// function trapped).
    #[error("failed to instantiate wasm module: {0}")]
    InstantiationFailed(String),

    /// A required guest export (`memory` or the `webc_call` entry point) is absent
    /// or has the wrong type.
    #[error("wasm module is missing the required export `{0}`")]
    MissingExport(String),

    /// The guest trapped during execution (unreachable, integer divide-by-zero,
    /// indirect-call type mismatch, an explicit guest abort, …).
    #[error("wasm execution trapped: {0}")]
    Trap(String),

    /// Metered work exceeded the available budget: wasm fuel was exhausted, or a
    /// host-op / fuel-reconciliation gas charge failed closed.
    #[error("out of gas")]
    OutOfGas,

    /// Gas accounting overflowed `u64`.
    #[error("gas accounting overflowed")]
    GasOverflow,

    /// A guest pointer/length pair addressed memory outside the linear memory
    /// bounds. No copy is performed; the call is trapped.
    #[error("guest memory access is out of bounds")]
    MemoryOutOfBounds,

    /// The guest tried to submit more output than
    /// [`crate::VmLimits::max_output_bytes`].
    #[error("guest output exceeds the maximum of {max} bytes")]
    OutputTooLarge {
        /// Configured maximum output size in bytes.
        max: usize,
    },

    /// The host (the chain adapter over `ContractContext` + `GasMeter`) denied an
    /// operation — e.g. a state key outside the declared footprint, or an
    /// over-cap value. The underlying reason is carried as text.
    #[error("host denied the operation: {0}")]
    HostDenied(String),

    /// A key passed to `webc_get`/`webc_set` was not exactly 32 bytes.
    #[error("key length must be exactly 32 bytes, got {0}")]
    KeyLengthInvalid(usize),
}
