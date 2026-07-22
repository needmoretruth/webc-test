//! Deterministic execution of a validated contract module and the `webc` host
//! ABI the guest imports.
//!
//! # Host ABI (module `"webc"`)
//!
//! The guest **exports** `memory` (its linear memory) and `webc_call` (a no-arg,
//! no-result entry point), and **imports** the following functions. Every pointer
//! and length is bounds-checked against the current linear-memory size before any
//! copy; a hostile offset traps as [`VmError::MemoryOutOfBounds`] rather than
//! panicking.
//!
//! | Import | Signature | Meaning |
//! |---|---|---|
//! | `webc_input_len` | `() -> i32` | Byte length of `input`. |
//! | `webc_input_read` | `(ptr: i32)` | Copy all `input` bytes into guest memory at `ptr`. |
//! | `webc_get` | `(key_ptr: i32, key_len: i32, out_ptr: i32, out_cap: i32) -> i32` | Look up a 32-byte key; copy the value into `[out_ptr, out_ptr+cap)` and return its length; `-1` if absent, `-2` if the buffer is too small (no copy). |
//! | `webc_set` | `(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32) -> i32` | Write a 32-byte key to a value; returns `0`, or `-2` if the value exceeds the cap. |
//! | `webc_epoch` | `() -> i64` | The current block epoch. |
//! | `webc_output` | `(ptr: i32, len: i32)` | Submit `len` result bytes (bounded by `max_output_bytes`). Last call wins. |
//!
//! `key_len` must be exactly 32 ([`VmError::KeyLengthInvalid`]). Host-op gas is
//! charged through [`VmHost::charge_gas`] before the effect; on return, consumed
//! wasm fuel is reconciled into gas so total metered work — compute plus host
//! effects — is bounded by the caller's gas limit.

use wasmi::core::{Trap, TrapCode};
use wasmi::{Caller, Extern, Linker, Memory, Store, StoreLimits, StoreLimitsBuilder};
use webc_crypto::Hash256;

use crate::error::VmError;
use crate::host::VmHost;
use crate::limits::{VmLimits, KEY_LEN};
use crate::validate::{compile_checked, HOST_MODULE};

/// The wasm linear-memory page size, in bytes (fixed by the wasm spec).
const WASM_PAGE_BYTES: usize = 64 * 1024;

/// Mutable per-invocation state owned by the wasm [`Store`] and reachable from
/// every host function via [`Caller`].
struct VmState<'a, H: VmHost> {
    host: &'a mut H,
    limits: &'a VmLimits,
    input: &'a [u8],
    /// Result bytes submitted by the guest through `webc_output` (last call wins).
    output: Option<Vec<u8>>,
    /// A typed reason recorded when a host function aborts the guest, so the
    /// outer trap can be mapped back to a precise [`VmError`].
    trap_reason: Option<VmError>,
    /// Caps linear-memory growth at RUN TIME (see [`memory_limiter`]). Held in the
    /// store's data so the [`Store::limiter`] hook can borrow it each grow.
    limiter: StoreLimits,
}

/// Builds a store resource limiter that caps linear-memory growth at
/// `max_memory_pages`, enforced by the engine at run time regardless of what the
/// module declares.
///
/// [`validate_module`](crate::validate_module) only bounds a memory's *declared*
/// initial/maximum pages; a module may legally declare a small initial memory
/// with **no maximum** and then `memory.grow` toward the wasm32 4 GiB ceiling for
/// a single instruction's fuel. This limiter closes that at the source: a grow
/// that would exceed the cap fails (`memory.grow` returns `-1`) before any
/// allocation, so the 16-page / 1 MiB budget documented in [`VmLimits`] actually
/// holds. It is deterministic — every node denies the same grow identically —
/// with no trap, matching the wasm spec's grow-failure value.
fn memory_limiter(limits: &VmLimits) -> StoreLimits {
    let max_bytes = (limits.max_memory_pages as usize).saturating_mul(WASM_PAGE_BYTES);
    StoreLimitsBuilder::new().memory_size(max_bytes).build()
}

/// Executes a WEBC contract module and returns its submitted output bytes.
///
/// The module is validated (fail closed) before instantiation, run under
/// deterministic fuel metering with only the `webc` host imports available, and
/// any trap, out-of-bounds access, missing export, over-cap output, or host
/// denial is returned as a typed [`VmError`] — never a panic.
pub fn execute<H: VmHost>(
    module_bytes: &[u8],
    input: &[u8],
    host: &mut H,
    limits: &VmLimits,
) -> Result<Vec<u8>, VmError> {
    if input.len() > limits.max_input_bytes {
        return Err(VmError::InputTooLarge {
            actual: input.len(),
            max: limits.max_input_bytes,
        });
    }

    // Size + structural + full deterministic-engine validation, yielding the
    // compiled module (single compile, shared with `validate_module`).
    let (engine, module) = compile_checked(module_bytes, limits)?;

    let state = VmState {
        host,
        limits,
        input,
        output: None,
        trap_reason: None,
        limiter: memory_limiter(limits),
    };
    let mut store = Store::new(&engine, state);
    // Enforce the linear-memory page budget at run time, not just at validation:
    // a module with no declared memory maximum cannot grow past the cap.
    store.limiter(|state| &mut state.limiter);
    // Fuel metering is enabled in the engine config; seed the budget.
    store
        .add_fuel(limits.fuel)
        .map_err(|err| VmError::InstantiationFailed(err.to_string()))?;

    let mut linker: Linker<VmState<H>> = Linker::new(&engine);
    register_host(&mut linker)?;

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|err| VmError::InstantiationFailed(err.to_string()))?
        .start(&mut store)
        .map_err(map_start_error)?;

    if instance.get_memory(&store, "memory").is_none() {
        return Err(VmError::MissingExport("memory".to_string()));
    }
    let entry = instance
        .get_typed_func::<(), ()>(&store, "webc_call")
        .map_err(|_| VmError::MissingExport("webc_call".to_string()))?;

    if let Err(trap) = entry.call(&mut store, ()) {
        // A host function may have recorded a precise reason before trapping.
        if let Some(reason) = store.data_mut().trap_reason.take() {
            return Err(reason);
        }
        return Err(map_run_error(&trap));
    }

    // Reconcile consumed compute fuel into gas so the meter accounts for it.
    let consumed_fuel = store.fuel_consumed().unwrap_or(0);
    let gas = limits.reconcile_fuel(consumed_fuel);
    if gas > 0 {
        store.data_mut().host.charge_gas(gas)?;
    }

    Ok(store.data_mut().output.take().unwrap_or_default())
}

/// Registers the `webc` host module functions on `linker`.
fn register_host<H: VmHost>(linker: &mut Linker<VmState<H>>) -> Result<(), VmError> {
    let define = |linker: &mut Linker<VmState<H>>| -> Result<(), wasmi::errors::LinkerError> {
        linker.func_wrap(
            HOST_MODULE,
            "webc_input_len",
            |caller: Caller<'_, VmState<H>>| -> i32 {
                i32::try_from(caller.data().input.len()).unwrap_or(i32::MAX)
            },
        )?;

        linker.func_wrap(
            HOST_MODULE,
            "webc_input_read",
            |mut caller: Caller<'_, VmState<H>>, ptr: i32| -> Result<(), Trap> {
                let (base, per) = {
                    let l = caller.data().limits;
                    (l.gas_input_base, l.gas_input_per_byte)
                };
                let input = caller.data().input.to_vec();
                let cost = base.saturating_add(per.saturating_mul(input.len() as u64));
                charge(&mut caller, cost)?;

                let memory = memory_export(&mut caller)?;
                let offset = match usize_offset(ptr) {
                    Some(o) => o,
                    None => return Err(abort(&mut caller, VmError::MemoryOutOfBounds)),
                };
                if memory.write(&mut caller, offset, &input).is_err() {
                    return Err(abort(&mut caller, VmError::MemoryOutOfBounds));
                }
                Ok(())
            },
        )?;

        linker.func_wrap(
            HOST_MODULE,
            "webc_get",
            |mut caller: Caller<'_, VmState<H>>,
             key_ptr: i32,
             key_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> Result<i32, Trap> {
                if key_len != KEY_LEN_I32 {
                    let reported = usize::try_from(key_len).unwrap_or(0);
                    return Err(abort(&mut caller, VmError::KeyLengthInvalid(reported)));
                }
                let cost = caller.data().limits.gas_get;
                charge(&mut caller, cost)?;

                let memory = memory_export(&mut caller)?;
                let key_bytes = {
                    let data = memory.data(&caller);
                    read_guest(data, key_ptr, KEY_LEN)
                };
                let key = match key_bytes {
                    Some(bytes) => match <[u8; KEY_LEN]>::try_from(bytes.as_slice()) {
                        Ok(arr) => Hash256(arr),
                        Err(_) => return Err(abort(&mut caller, VmError::MemoryOutOfBounds)),
                    },
                    None => return Err(abort(&mut caller, VmError::MemoryOutOfBounds)),
                };

                let value = match caller.data_mut().host.get(&key) {
                    Ok(v) => v,
                    Err(err) => return Err(abort(&mut caller, err)),
                };
                let value = match value {
                    Some(v) => v,
                    None => return Ok(-1),
                };

                let cap = match usize::try_from(out_cap) {
                    Ok(c) => c,
                    Err(_) => return Err(abort(&mut caller, VmError::MemoryOutOfBounds)),
                };
                if value.len() > cap {
                    return Ok(-2);
                }
                let offset = match usize_offset(out_ptr) {
                    Some(o) => o,
                    None => return Err(abort(&mut caller, VmError::MemoryOutOfBounds)),
                };
                if memory.write(&mut caller, offset, &value).is_err() {
                    return Err(abort(&mut caller, VmError::MemoryOutOfBounds));
                }
                Ok(i32::try_from(value.len()).unwrap_or(i32::MAX))
            },
        )?;

        linker.func_wrap(
            HOST_MODULE,
            "webc_set",
            |mut caller: Caller<'_, VmState<H>>,
             key_ptr: i32,
             key_len: i32,
             val_ptr: i32,
             val_len: i32|
             -> Result<i32, Trap> {
                if key_len != KEY_LEN_I32 {
                    let reported = usize::try_from(key_len).unwrap_or(0);
                    return Err(abort(&mut caller, VmError::KeyLengthInvalid(reported)));
                }
                let vlen = match usize::try_from(val_len) {
                    Ok(v) => v,
                    Err(_) => return Err(abort(&mut caller, VmError::MemoryOutOfBounds)),
                };
                if vlen > caller.data().limits.max_value_bytes {
                    return Ok(-2);
                }
                let (base, per) = {
                    let l = caller.data().limits;
                    (l.gas_set_base, l.gas_set_per_byte)
                };
                let cost = base.saturating_add(per.saturating_mul(vlen as u64));
                charge(&mut caller, cost)?;

                let memory = memory_export(&mut caller)?;
                let pair = {
                    let data = memory.data(&caller);
                    match (
                        read_guest(data, key_ptr, KEY_LEN),
                        read_guest(data, val_ptr, vlen),
                    ) {
                        (Some(k), Some(v)) => Some((k, v)),
                        _ => None,
                    }
                };
                let (key_bytes, value) = match pair {
                    Some(kv) => kv,
                    None => return Err(abort(&mut caller, VmError::MemoryOutOfBounds)),
                };
                let key = match <[u8; KEY_LEN]>::try_from(key_bytes.as_slice()) {
                    Ok(arr) => Hash256(arr),
                    Err(_) => return Err(abort(&mut caller, VmError::MemoryOutOfBounds)),
                };

                match caller.data_mut().host.set(key, value) {
                    Ok(()) => Ok(0),
                    Err(err) => Err(abort(&mut caller, err)),
                }
            },
        )?;

        linker.func_wrap(
            HOST_MODULE,
            "webc_epoch",
            |mut caller: Caller<'_, VmState<H>>| -> Result<i64, Trap> {
                let cost = caller.data().limits.gas_epoch;
                charge(&mut caller, cost)?;
                let epoch = caller.data().host.epoch();
                Ok(i64::try_from(epoch).unwrap_or(i64::MAX))
            },
        )?;

        linker.func_wrap(
            HOST_MODULE,
            "webc_output",
            |mut caller: Caller<'_, VmState<H>>, ptr: i32, len: i32| -> Result<(), Trap> {
                let olen = match usize::try_from(len) {
                    Ok(v) => v,
                    Err(_) => return Err(abort(&mut caller, VmError::MemoryOutOfBounds)),
                };
                let max_out = caller.data().limits.max_output_bytes;
                if olen > max_out {
                    return Err(abort(&mut caller, VmError::OutputTooLarge { max: max_out }));
                }
                let (base, per) = {
                    let l = caller.data().limits;
                    (l.gas_output_base, l.gas_output_per_byte)
                };
                let cost = base.saturating_add(per.saturating_mul(olen as u64));
                charge(&mut caller, cost)?;

                let memory = memory_export(&mut caller)?;
                let out = {
                    let data = memory.data(&caller);
                    read_guest(data, ptr, olen)
                };
                let out = match out {
                    Some(v) => v,
                    None => return Err(abort(&mut caller, VmError::MemoryOutOfBounds)),
                };
                caller.data_mut().output = Some(out);
                Ok(())
            },
        )?;

        Ok(())
    };

    define(linker).map_err(|err| VmError::InstantiationFailed(err.to_string()))
}

/// `KEY_LEN` as an `i32` for guest-supplied length comparisons.
const KEY_LEN_I32: i32 = KEY_LEN as i32;

/// Records `err` as the guest's abort reason and returns a wasm trap to unwind.
fn abort<H: VmHost>(caller: &mut Caller<'_, VmState<H>>, err: VmError) -> Trap {
    caller.data_mut().trap_reason = Some(err);
    Trap::new("webc: host aborted execution")
}

/// Charges host-op gas through the [`VmHost`], aborting the guest on failure.
fn charge<H: VmHost>(caller: &mut Caller<'_, VmState<H>>, units: u64) -> Result<(), Trap> {
    match caller.data_mut().host.charge_gas(units) {
        Ok(()) => Ok(()),
        Err(err) => Err(abort(caller, err)),
    }
}

/// Resolves the guest's exported `memory`, aborting if it is absent.
fn memory_export<H: VmHost>(caller: &mut Caller<'_, VmState<H>>) -> Result<Memory, Trap> {
    match caller.get_export("memory").and_then(Extern::into_memory) {
        Some(memory) => Ok(memory),
        None => Err(abort(caller, VmError::MissingExport("memory".to_string()))),
    }
}

/// Converts a guest `i32` offset to a `usize`, rejecting negatives.
fn usize_offset(ptr: i32) -> Option<usize> {
    usize::try_from(ptr).ok()
}

/// Copies `len` bytes from guest memory starting at `ptr`, bounds-checked.
/// Returns `None` (never panics) on a negative offset or any out-of-range span.
fn read_guest(data: &[u8], ptr: i32, len: usize) -> Option<Vec<u8>> {
    let start = usize::try_from(ptr).ok()?;
    let end = start.checked_add(len)?;
    data.get(start..end).map(<[u8]>::to_vec)
}

/// Maps a start-function error: fuel exhaustion is [`VmError::OutOfGas`],
/// anything else is an instantiation failure.
fn map_start_error(err: wasmi::Error) -> VmError {
    if let wasmi::Error::Trap(trap) = &err {
        if trap_is_out_of_fuel(trap) {
            return VmError::OutOfGas;
        }
    }
    VmError::InstantiationFailed(err.to_string())
}

/// Maps a run trap: fuel exhaustion is [`VmError::OutOfGas`], any other trap is
/// [`VmError::Trap`].
fn map_run_error(trap: &Trap) -> VmError {
    if trap_is_out_of_fuel(trap) {
        VmError::OutOfGas
    } else {
        VmError::Trap(trap.to_string())
    }
}

/// Whether a trap is the fuel-exhaustion trap. `TrapCode` does not implement
/// `PartialEq`, so the code is matched structurally.
fn trap_is_out_of_fuel(trap: &Trap) -> bool {
    matches!(trap.trap_code(), Some(TrapCode::OutOfFuel))
}
