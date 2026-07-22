//! Configurable, deterministic resource limits and the host-op gas schedule.
//!
//! Defaults mirror the WEBC native contract runtime (`webc-chain`'s
//! `contract` module): the per-value byte cap and per-invocation input cap match
//! `MAX_CONTRACT_STATE_VALUE_BYTES` / `MAX_CONTRACT_INPUT_BYTES` (4 KiB), and the
//! host-op costs echo its state read/write schedule. Every field is public and
//! overridable; nothing here reads ambient state, so identical limits on every
//! node yield identical metering.

/// The exact byte length of a state key hash (`webc_crypto::Hash256`).
pub const KEY_LEN: usize = 32;

/// Resource bounds and gas costs applied to a single contract execution.
///
/// Clone-cheap and fully declarative. Construct with [`VmLimits::default`] and
/// override individual fields, or build one explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLimits {
    /// Maximum accepted module size, in bytes. Larger modules are rejected by
    /// [`crate::validate_module`] before any parsing work.
    pub max_module_bytes: usize,
    /// Maximum linear-memory pages the module may declare (1 page = 64 KiB).
    /// Kept deliberately small so a hostile module cannot request large
    /// allocations.
    pub max_memory_pages: u32,
    /// Maximum `input` bytes delivered to the guest.
    pub max_input_bytes: usize,
    /// Maximum bytes of a single state value written via `webc_set`. Mirrors the
    /// chain's per-value cap.
    pub max_value_bytes: usize,
    /// Maximum bytes the guest may submit via `webc_output`.
    pub max_output_bytes: usize,

    /// Total wasm fuel budget. Fuel is charged per executed instruction by the
    /// interpreter; exhaustion fails closed as [`crate::VmError::OutOfGas`].
    pub fuel: u64,
    /// Fuel units that reconcile to one gas unit at the end of a run. Consumed
    /// fuel is divided by this (rounding up) and charged through
    /// `VmHost::charge_gas`, so compute work is reflected in the gas meter. A
    /// value of `0` is treated as `1` (1 gas per fuel unit).
    pub fuel_per_gas: u64,

    /// Gas charged per `webc_get` call.
    pub gas_get: u64,
    /// Base gas charged per `webc_set` call.
    pub gas_set_base: u64,
    /// Additional gas charged per value byte written by `webc_set`.
    pub gas_set_per_byte: u64,
    /// Gas charged per `webc_epoch` call.
    pub gas_epoch: u64,
    /// Base gas charged per `webc_input_read` call.
    pub gas_input_base: u64,
    /// Additional gas charged per input byte delivered by `webc_input_read`.
    pub gas_input_per_byte: u64,
    /// Base gas charged per `webc_output` call.
    pub gas_output_base: u64,
    /// Additional gas charged per output byte submitted by `webc_output`.
    pub gas_output_per_byte: u64,
}

impl Default for VmLimits {
    fn default() -> Self {
        Self {
            // 256 KiB: generous for a hand-written contract, far below anything
            // that would strain the interpreter.
            max_module_bytes: 256 * 1024,
            // 16 pages = 1 MiB of linear memory.
            max_memory_pages: 16,
            // Mirror MAX_CONTRACT_INPUT_BYTES.
            max_input_bytes: 4 * 1024,
            // Mirror MAX_CONTRACT_STATE_VALUE_BYTES.
            max_value_bytes: 4 * 1024,
            // A contract result is bounded like a state value by default.
            max_output_bytes: 4 * 1024,
            // 100M fuel: ample for bounded contract logic, hard-caps runaway loops.
            fuel: 100_000_000,
            // Reconcile ~1000 executed instructions to 1 gas unit.
            fuel_per_gas: 1_000,
            // Costs echo the chain's contract gas schedule.
            gas_get: 500,
            gas_set_base: 1_000,
            gas_set_per_byte: 8,
            gas_epoch: 10,
            gas_input_base: 100,
            gas_input_per_byte: 4,
            gas_output_base: 100,
            gas_output_per_byte: 8,
        }
    }
}

impl VmLimits {
    /// Reconciles consumed wasm `fuel` into a gas charge, rounding up so any
    /// nonzero compute costs at least one gas unit. `fuel_per_gas == 0` is
    /// treated as `1`.
    pub(crate) fn reconcile_fuel(&self, fuel: u64) -> u64 {
        let per = self.fuel_per_gas.max(1);
        // Ceiling division: any nonzero fuel costs at least one gas unit.
        fuel.div_ceil(per)
    }
}
