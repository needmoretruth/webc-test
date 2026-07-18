//! The capability interface the VM calls into.
//!
//! [`VmHost`] is the *only* seam between the deterministic wasm engine and the
//! outside world. The WEBC chain implements it as a thin adapter over
//! `ContractContext` (declared-footprint state access + block epoch) and
//! `GasMeter` (checked, fail-closed metering); tests implement it over an
//! in-memory map. The VM never reads a clock, the network, files, or randomness
//! — every side effect and every observable input flows through this trait, which
//! is what keeps execution reproducible across nodes.

use crate::error::VmError;
use webc_crypto::Hash256;

/// Host capabilities exposed to a running contract.
///
/// All methods are fallible with [`VmError`]. An `Err` returned here is bubbled
/// out of [`crate::execute`] unchanged (a footprint denial surfaces as
/// [`VmError::HostDenied`], a metering failure as [`VmError::OutOfGas`] /
/// [`VmError::GasOverflow`]), so the host stays the single authority over access
/// control and gas.
pub trait VmHost {
    /// Reads the value stored under a 32-byte key hash, or `None` if absent.
    ///
    /// The chain adapter enforces that `key` lies within the contract's declared
    /// footprint and returns [`VmError::HostDenied`] otherwise.
    fn get(&mut self, key: &Hash256) -> Result<Option<Vec<u8>>, VmError>;

    /// Writes `value` under a 32-byte key hash.
    ///
    /// The chain adapter enforces the declared footprint and the per-value byte
    /// cap, failing closed with [`VmError::HostDenied`] on violation.
    fn set(&mut self, key: Hash256, value: Vec<u8>) -> Result<(), VmError>;

    /// The current block epoch injected into the deterministic environment.
    fn epoch(&self) -> u64;

    /// Charges `units` of gas, failing closed on exhaustion or overflow.
    ///
    /// Maps to `GasMeter::charge`. The VM calls this for every host operation and
    /// once at the end to reconcile consumed wasm fuel into gas, so total metered
    /// work — compute plus host effects — is bounded by the caller's gas limit.
    fn charge_gas(&mut self, units: u64) -> Result<(), VmError>;
}
