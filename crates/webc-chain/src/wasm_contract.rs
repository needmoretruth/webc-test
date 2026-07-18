//! Untrusted-bytecode contract path (Phase 7b, ADR-0014 path (a)): run a
//! deployer-supplied **WebAssembly** module behind the exact same
//! declared-access + deterministic-gas + atomic-rollback discipline the interim
//! native handlers (`contract` module) already enforce.
//!
//! # What this module is
//!
//! A thin, self-contained *adapter* between two stable seams, and nothing more:
//!
//! - **the chain runtime** — the [`Contract`] trait, the bounded
//!   [`ContractContext`] (declared-footprint state + injected block epoch), and
//!   the checked [`crate::GasMeter`]; and
//! - **the execution engine** — the deterministic, gas-metered [`webc_vm`] crate
//!   (a `wasmi` interpreter today), reached only through its narrow [`VmHost`]
//!   capability seam and [`execute`] entry point.
//!
//! The engine lives behind the `webc-vm` crate boundary, so it can be swapped for
//! a JIT (e.g. `wasmtime`) later **without touching this crate**: the manifest
//! schema, the contract ABI, and the gas model here stay fixed across engines.
//! That swappability is the whole design goal of keeping the VM in its own crate
//! and this file as the only bridge to it.
//!
//! # One gas meter, no double counting
//!
//! Every unit of work a WASM contract does is charged against the **same**
//! [`crate::GasMeter`] the surrounding transaction already funds and caps at the
//! sender's `gas_limit`, so an over-gas call fails closed into the identical
//! atomic rollback the native path uses:
//!
//! - **compute** — `wasmi` fuel consumed by executed instructions is reconciled
//!   into gas by the engine and charged through [`VmHost::charge_gas`], which this
//!   adapter routes to [`ContractContext::step`];
//! - **state reads/writes** — metered once, by [`ContractContext`] itself
//!   (`CONTRACT_STATE_READ_UNITS` / `CONTRACT_STATE_WRITE_UNITS`, shared with the
//!   native path). The engine's own per-op *state* gas is therefore set to zero in
//!   [`wasm_vm_limits`] so a wasm state access is never charged twice;
//! - **input delivery, epoch reads, output** — small host-op costs owned by the
//!   engine's gas schedule (not metered anywhere else), also via `charge_gas`.
//!
//! # Determinism & security boundary
//!
//! The engine is deterministic by construction (interpreter, fuel not wall-clock,
//! no floats/SIMD/threads/ambient imports — see [`webc_vm`]). This adapter adds no
//! nondeterminism: it reads only the injected epoch and the contract's declared
//! footprint, and every fallible path returns a typed [`ContractError`] that rolls
//! the whole transaction back — there is no reachable panic from hostile bytecode
//! or hostile input. All state access still flows through [`ContractContext`], so
//! a module that reaches for an undeclared key fails closed exactly like a native
//! handler; the module bytes themselves are validated (fail-closed) at
//! registration and re-validated defensively before execution.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use webc_crypto::{Address, Hash256};
use webc_vm::{execute, validate_module, VmError, VmHost, VmLimits};

use crate::contract::{Contract, ContractContext, ContractError, MAX_CONTRACT_FOOTPRINT_KEYS};
use crate::ChainError;

/// Current ABI / manifest schema version for the WASM contract path.
///
/// Bumped when [`WasmContractManifest`] or the guest calling convention changes,
/// so a node never interprets a future manifest with today's rules. Independent
/// of the native `CONTRACT_ABI_VERSION` because the two paths version separately.
pub const WASM_CONTRACT_ABI_VERSION: u16 = 1;

/// Current gas-schedule version the WASM host-op costs are priced against.
///
/// The manifest pins the schedule it was priced against so a future re-pricing
/// stays version-legible; the actual unit costs are protocol-fixed (in
/// [`wasm_vm_limits`] and [`ContractContext`]), never manifest-supplied, so a
/// deployer cannot under-price its own contract.
pub const WASM_GAS_SCHEDULE_VERSION: u16 = 1;

/// Maximum stored module size, in bytes. Mirrors the engine's default module cap
/// ([`VmLimits::max_module_bytes`]); a larger upload is rejected at registration
/// before any parsing or storage work.
pub const MAX_WASM_MODULE_BYTES: usize = 256 * 1024;

/// Domain tag for the WASM contract-registry Merkle sub-root committed by the
/// state root. Each `(code_id, WasmContractManifest)` entry is a leaf under this
/// domain, so registering a WASM contract changes the state root. Bumping this is
/// a consensus-format change.
pub const WASM_CONTRACT_LEAF_DOMAIN: &[u8] = b"WEBC_WASM_CONTRACT_LEAF_V1";

/// Domain tag for the WASM bytecode Merkle sub-root committed by the state root.
/// Each `(code_id, WasmBytecode)` entry is a leaf under this domain, so uploading
/// bytecode changes the state root. Bumping this is a consensus-format change.
pub const WASM_CODE_LEAF_DOMAIN: &[u8] = b"WEBC_WASM_CODE_LEAF_V1";

/// Domain separator for the content hash that binds a manifest to its bytecode.
const WASM_CODE_HASH_DOMAIN: &[u8] = b"WEBC_WASM_CODE_HASH_V1";

// ----- interim admission gas model (benchmark-tunable placeholders) -----
//
// Protocol-fixed values (not owner policy, not manifest-supplied) so a contract
// cannot under-price itself, centralized here exactly like the native contract
// costs in `contract.rs`. A wasm *invocation* reuses the native invoke schedule
// (`CONTRACT_INVOKE_BASE_UNITS` + input + declared keys); only registration adds
// a wasm-specific term for the bytecode upload.

/// Base admission units for `RegisterWasmContract` (validates a manifest + module
/// and writes the manifest and code records). Mirrors the native registration
/// class (`Operation::RegisterContract`).
pub const WASM_REGISTER_BASE_UNITS: u64 = 30_000;

/// Additional admission units charged per byte of uploaded module, bounding the
/// upload + validation + storage work a registration can demand.
pub const WASM_CODE_BYTE_UNITS: u64 = 4;

/// Bounded WASM module bytes uploaded with a registration.
///
/// Stored in `ChainState::wasm_code` keyed by the owning contract's `code_id`
/// (each contract owns its own immutable code entry under `StateKey::module`, so
/// no cross-contract sharing or content-address bookkeeping is needed). Encoded as
/// lowercase hex in the human-readable (canonical JSON) form — matching contract
/// state values and bridge byte fields — and as raw bytes in the binary form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WasmBytecode(#[serde(with = "crate::hex_bytes")] pub Vec<u8>);

impl WasmBytecode {
    /// The content hash that a manifest commits to. Domain-separated so it can
    /// never collide with any other hashed structure in the protocol.
    pub fn code_hash(&self) -> Hash256 {
        Hash256::digest_many([WASM_CODE_HASH_DOMAIN, self.0.as_slice()])
    }

    /// Module size in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the module is empty (always invalid; a real module has a header).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// On-chain committed record describing one registered WASM contract.
///
/// Mirrors the native [`crate::ContractManifest`] field-for-field, except the
/// audited built-in selector is replaced by a `code_hash` that binds this record
/// to the uploaded [`WasmBytecode`]. Keyed in `ChainState::wasm_contracts` by
/// `code_id` and addressed for declared access by `StateKey::module(code_id)`;
/// its state lives under `StateKey::application(namespace, key_hash)` for each
/// `key_hash` in `footprint`, physically in the SAME `contract_state` map the
/// native path uses (namespaces are collision-resistant, so the two paths never
/// alias).
///
/// Invariants (all enforced by [`WasmContractManifest::validate`] before the
/// record is committed):
/// - `abi_version == WASM_CONTRACT_ABI_VERSION` and
///   `gas_schedule_version == WASM_GAS_SCHEDULE_VERSION`;
/// - `footprint` is non-empty, at most [`MAX_CONTRACT_FOOTPRINT_KEYS`], strictly
///   ascending and therefore duplicate-free;
/// - `owner` is the registrant;
/// - `code_hash` equals the uploaded bytecode's [`WasmBytecode::code_hash`], and
///   that bytecode is within the size cap and accepted by the deterministic
///   engine's validator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmContractManifest {
    /// ABI / manifest schema version this record is written against.
    pub abi_version: u16,
    /// Gas-schedule version this contract was priced against.
    pub gas_schedule_version: u16,
    /// Caller-chosen collision-resistant on-chain identity (the registry key and
    /// the `StateKey::module` address).
    pub code_id: Hash256,
    /// Application namespace this contract's state is isolated under (§8).
    pub namespace: Hash256,
    /// Content hash binding this manifest to its uploaded module bytes.
    pub code_hash: Hash256,
    /// Declared application key-hashes this contract may read and write, strictly
    /// ascending. Each becomes a `StateKey::application(namespace, key_hash)` in an
    /// invocation's signed access list, enforced by `StateAccessRecorder`.
    pub footprint: Vec<Hash256>,
    /// Account that registered (and owns) this contract record.
    pub owner: Address,
}

impl WasmContractManifest {
    /// Constructs a manifest at the current ABI/gas-schedule versions.
    ///
    /// The `footprint` is sorted and de-duplicated so callers need not pre-sort;
    /// [`WasmContractManifest::validate`] still independently rejects a malformed
    /// footprint on hostile wire input.
    pub fn new(
        code_id: Hash256,
        namespace: Hash256,
        code_hash: Hash256,
        footprint: impl IntoIterator<Item = Hash256>,
        owner: Address,
    ) -> Self {
        let sorted: BTreeSet<Hash256> = footprint.into_iter().collect();
        Self {
            abi_version: WASM_CONTRACT_ABI_VERSION,
            gas_schedule_version: WASM_GAS_SCHEDULE_VERSION,
            code_id,
            namespace,
            code_hash,
            footprint: sorted.into_iter().collect(),
            owner,
        }
    }

    /// Validates a hostile manifest and its uploaded bytecode before either may be
    /// committed. Fails closed with a typed [`ChainError`]; never panics.
    ///
    /// Order matters: cheap structural checks first, the deterministic-engine
    /// validation of the module bytes last (it is the most expensive step).
    pub fn validate(&self, registrant: Address, code: &WasmBytecode) -> Result<(), ChainError> {
        if self.abi_version != WASM_CONTRACT_ABI_VERSION
            || self.gas_schedule_version != WASM_GAS_SCHEDULE_VERSION
        {
            return Err(ChainError::UnsupportedContractAbiVersion {
                actual: self.abi_version,
            });
        }
        if self.owner != registrant {
            return Err(ChainError::InvalidContractManifest);
        }
        if self.footprint.is_empty() || self.footprint.len() > MAX_CONTRACT_FOOTPRINT_KEYS {
            return Err(ChainError::InvalidContractManifest);
        }
        // Strictly ascending guarantees a canonical order and rejects duplicates,
        // so the committed leaf and derived access list are deterministic and a
        // padded footprint cannot manufacture false scheduling conflicts.
        if !self.footprint.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ChainError::InvalidContractManifest);
        }
        if code.len() > MAX_WASM_MODULE_BYTES {
            return Err(ChainError::WasmModuleTooLarge {
                actual: code.len(),
                maximum: MAX_WASM_MODULE_BYTES,
            });
        }
        // The manifest must commit to exactly the bytes uploaded, so the committed
        // leaf and every later invocation run the audited-at-registration module.
        if self.code_hash != code.code_hash() {
            return Err(ChainError::WasmCodeHashMismatch);
        }
        // Fail closed on any module the deterministic engine will not accept
        // (forbidden feature, foreign import, oversized memory, malformed bytes),
        // so an invalid module is never stored and never reaches execution.
        validate_module(&code.0, &wasm_vm_limits()).map_err(|_| ChainError::InvalidWasmModule)?;
        Ok(())
    }
}

/// The resource limits and gas schedule the chain runs WASM contracts under.
///
/// Starts from the engine defaults (which already mirror the native contract
/// bounds — 4 KiB input/value/output, 256 KiB module, 16 memory pages) and makes
/// exactly one deliberate change: the per-op **state** gas is zeroed, because a
/// wasm state access is metered by [`ContractContext`] (the single authority for
/// per-key read/write cost, shared with the native path). Zeroing it here is what
/// prevents a state access from being charged twice. Compute (fuel), input,
/// epoch, and output remain metered by the engine's own schedule.
///
/// Returned by value and fully declarative, so a caller (or a future re-pricing)
/// can start from this and override individual fields.
pub fn wasm_vm_limits() -> VmLimits {
    VmLimits {
        // State reads/writes are metered by ContractContext, not the engine.
        gas_get: 0,
        gas_set_base: 0,
        gas_set_per_byte: 0,
        ..VmLimits::default()
    }
}

/// A registered WASM contract's handler: an adapter that runs the module bytes on
/// the [`webc_vm`] engine, presented to the chain as an ordinary [`Contract`].
///
/// Borrows the module bytes (loaded from committed state by the caller) so no
/// copy is made per invocation. Construct with [`WasmContract::new`] for the
/// protocol gas schedule, or [`WasmContract::with_limits`] to supply an explicit
/// [`VmLimits`] (tests, or a future governance-tunable schedule).
pub struct WasmContract<'code> {
    module: &'code [u8],
    limits: VmLimits,
}

impl<'code> WasmContract<'code> {
    /// Builds a handler over `module` using the protocol WASM gas schedule.
    pub fn new(module: &'code [u8]) -> Self {
        Self {
            module,
            limits: wasm_vm_limits(),
        }
    }

    /// Builds a handler over `module` with explicit limits (flexibility / tests).
    pub fn with_limits(module: &'code [u8], limits: VmLimits) -> Self {
        Self { module, limits }
    }
}

impl Contract for WasmContract<'_> {
    fn call(&self, ctx: &mut ContractContext, input: &[u8]) -> Result<Vec<u8>, ContractError> {
        // The engine drives all effects through `host`; `host` owns the borrow of
        // `ctx`, so state, epoch, and gas all reach the surrounding transaction.
        let mut host = ContractVmHost { ctx, pending: None };
        match execute(self.module, input, &mut host, &self.limits) {
            Ok(output) => Ok(output),
            // A host denial was collapsed to a coarse `VmError` by the engine; the
            // precise typed cause was stashed in `pending`, so prefer it. A fault
            // that did NOT originate in the host (a guest trap, a bad module) has no
            // stashed error and is mapped from the `VmError`.
            Err(vm_err) => Err(host.pending.take().unwrap_or_else(|| map_vm_error(&vm_err))),
        }
    }
}

/// The [`VmHost`] the engine calls into — a bridge over one [`ContractContext`].
///
/// Every capability the engine exposes to a guest maps 1:1 onto the bounded
/// contract environment: `get`/`set` onto the declared-footprint accessors (which
/// enforce access control and meter state ops), `epoch` onto the injected block
/// epoch, and `charge_gas` onto [`ContractContext::step`] (the transaction's gas
/// meter). Because the engine collapses a host `Err` into a coarse [`VmError`],
/// the precise typed [`ContractError`] is stashed in `pending` and re-surfaced by
/// [`WasmContract::call`], so the receipt and rollback reason stay exact.
struct ContractVmHost<'a, 'ctx> {
    ctx: &'a mut ContractContext<'ctx>,
    pending: Option<ContractError>,
}

impl ContractVmHost<'_, '_> {
    /// Records the precise `err` (keeping the first, which is the one that traps
    /// the guest) and returns the coarse [`VmError`] the engine expects.
    fn stash(&mut self, err: ContractError) -> VmError {
        let vm = match &err {
            ContractError::OutOfGas => VmError::OutOfGas,
            ContractError::GasOverflow => VmError::GasOverflow,
            other => VmError::HostDenied(other.to_string()),
        };
        if self.pending.is_none() {
            self.pending = Some(err);
        }
        vm
    }
}

impl VmHost for ContractVmHost<'_, '_> {
    fn get(&mut self, key: &Hash256) -> Result<Option<Vec<u8>>, VmError> {
        // Copy the value out so the borrow of `ctx` is released immediately.
        match self.ctx.get(*key) {
            Ok(value) => Ok(value.map(<[u8]>::to_vec)),
            Err(err) => Err(self.stash(err)),
        }
    }

    fn set(&mut self, key: Hash256, value: Vec<u8>) -> Result<(), VmError> {
        match self.ctx.set(key, value) {
            Ok(()) => Ok(()),
            Err(err) => Err(self.stash(err)),
        }
    }

    fn epoch(&self) -> u64 {
        self.ctx.epoch()
    }

    fn charge_gas(&mut self, units: u64) -> Result<(), VmError> {
        match self.ctx.step(units) {
            Ok(()) => Ok(()),
            Err(err) => Err(self.stash(err)),
        }
    }
}

/// Maps a [`VmError`] that did NOT originate in the host (so no precise
/// [`ContractError`] was stashed) to a typed, text-free contract failure.
///
/// Text-free on purpose: the resulting receipt error must be byte-identical on
/// every node, so no engine-produced string is embedded in a consensus-visible
/// value. `VmError` is `#[non_exhaustive]`, hence the catch-all trap arm.
fn map_vm_error(err: &VmError) -> ContractError {
    match err {
        VmError::OutOfGas => ContractError::OutOfGas,
        VmError::GasOverflow => ContractError::GasOverflow,
        VmError::OutputTooLarge { .. } => ContractError::WasmOutputTooLarge,
        VmError::InvalidModule(_)
        | VmError::ModuleTooLarge { .. }
        | VmError::MemoryLimitExceeded { .. }
        | VmError::InputTooLarge { .. } => ContractError::WasmInvalidModule,
        // Trap / MemoryOutOfBounds / MissingExport / InstantiationFailed /
        // KeyLengthInvalid / (unexpected) HostDenied → a run-time trap.
        _ => ContractError::WasmTrap,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{ContractWorkingSet, GasMeter};
    use crate::state_key::StateAccessRecorder;
    use crate::StateKey;
    use std::collections::BTreeMap;

    fn key(n: u8) -> Hash256 {
        Hash256([n; 32])
    }

    fn owner() -> Address {
        webc_crypto::Keypair::from_seed([7u8; 32]).address()
    }

    /// A real, minimal WASM contract in WAT: it copies the call `input` into the
    /// single declared footprint key (`key(0xa1)`, baked into a data segment) and
    /// echoes it back as output. Exercises input, `webc_set`, and `webc_output`.
    fn store_and_echo_wat() -> Vec<u8> {
        let key_hex: String = key(0xa1).0.iter().map(|b| format!("\\{b:02x}")).collect();
        let wat = format!(
            r#"(module
              (import "webc" "webc_input_len" (func $input_len (result i32)))
              (import "webc" "webc_input_read" (func $input_read (param i32)))
              (import "webc" "webc_set" (func $set (param i32 i32 i32 i32) (result i32)))
              (import "webc" "webc_output" (func $output (param i32 i32)))
              (memory (export "memory") 1)
              ;; 32-byte declared key at offset 0.
              (data (i32.const 0) "{key_hex}")
              (func (export "webc_call")
                (local $len i32)
                (local.set $len (call $input_len))
                ;; Copy input to offset 64, then store it under the declared key.
                (call $input_read (i32.const 64))
                (drop (call $set (i32.const 0) (i32.const 32) (i32.const 64) (local.get $len)))
                (call $output (i32.const 64) (local.get $len))))"#
        );
        wat::parse_str(&wat).expect("valid WAT fixture")
    }

    /// Drives a handler through a real [`ContractContext`] over an access list
    /// built from the footprint, mirroring how `state` invokes a contract.
    fn run(
        handler: &dyn Contract,
        footprint: &[Hash256],
        namespace: Hash256,
        working: ContractWorkingSet,
        input: &[u8],
        gas_limit: u64,
    ) -> Result<(Vec<u8>, ContractWorkingSet, u64), ContractError> {
        let declared: Vec<StateKey> = footprint
            .iter()
            .map(|kh| StateKey::application(namespace, *kh))
            .collect();
        let mut recorder = StateAccessRecorder::new(&[], &declared).expect("recorder");
        let mut meter = GasMeter::new(gas_limit, 0).expect("meter");
        let mut ctx =
            ContractContext::new(namespace, footprint, working, &mut recorder, &mut meter, 9);
        let output = handler.call(&mut ctx, input)?;
        let writes = ctx.into_writes()?;
        let consumed = meter.consumed();
        recorder.finish().expect("declared footprint fully used");
        Ok((output, writes, consumed))
    }

    #[test]
    fn code_hash_is_deterministic_and_binds_bytes() {
        let a = WasmBytecode(vec![0, 1, 2, 3]);
        let b = WasmBytecode(vec![0, 1, 2, 3]);
        let c = WasmBytecode(vec![0, 1, 2, 4]);
        assert_eq!(a.code_hash(), b.code_hash());
        assert_ne!(a.code_hash(), c.code_hash());
    }

    #[test]
    fn wasm_vm_limits_zero_only_state_gas() {
        let l = wasm_vm_limits();
        assert_eq!(l.gas_get, 0);
        assert_eq!(l.gas_set_base, 0);
        assert_eq!(l.gas_set_per_byte, 0);
        // Compute and I/O metering are untouched.
        assert!(l.fuel > 0 && l.fuel_per_gas > 0);
        assert!(l.gas_output_base > 0);
        assert_eq!(l.max_value_bytes, VmLimits::default().max_value_bytes);
    }

    #[test]
    fn manifest_validate_accepts_and_rejects() {
        let code = WasmBytecode(store_and_echo_wat());
        let good =
            WasmContractManifest::new(key(0xc0), key(0x11), code.code_hash(), [key(0xa1)], owner());
        good.validate(owner(), &code).expect("well-formed manifest");

        // Wrong registrant.
        let other = webc_crypto::Keypair::from_seed([8u8; 32]).address();
        assert!(matches!(
            good.validate(other, &code),
            Err(ChainError::InvalidContractManifest)
        ));
        // Code hash that does not match the bytes.
        let mut mismatched = good.clone();
        mismatched.code_hash = key(0xff);
        assert!(matches!(
            mismatched.validate(owner(), &code),
            Err(ChainError::WasmCodeHashMismatch)
        ));
        // Bytes the engine refuses (not a wasm module at all).
        let garbage = WasmBytecode(vec![0, 1, 2, 3, 4]);
        let bad = WasmContractManifest::new(
            key(0xc0),
            key(0x11),
            garbage.code_hash(),
            [key(0xa1)],
            owner(),
        );
        assert!(matches!(
            bad.validate(owner(), &garbage),
            Err(ChainError::InvalidWasmModule)
        ));
        // Empty footprint.
        let mut empty = good.clone();
        empty.footprint = Vec::new();
        assert!(matches!(
            empty.validate(owner(), &code),
            Err(ChainError::InvalidContractManifest)
        ));
    }

    #[test]
    fn wasm_contract_stores_input_and_echoes_it() {
        let module = store_and_echo_wat();
        let handler = WasmContract::new(&module);
        let footprint = vec![key(0xa1)];
        let (output, writes, gas) = run(
            &handler,
            &footprint,
            key(0x11),
            BTreeMap::new(),
            b"hello wasm",
            10_000_000,
        )
        .expect("wasm call");
        // Output echoes the input, and the declared key now holds it.
        assert_eq!(output, b"hello wasm");
        assert_eq!(writes.get(&key(0xa1)), Some(&Some(b"hello wasm".to_vec())));
        // Real work was metered against the shared gas meter.
        assert!(gas > 0);
    }

    #[test]
    fn wasm_contract_out_of_gas_fails_closed() {
        let module = store_and_echo_wat();
        let handler = WasmContract::new(&module);
        let footprint = vec![key(0xa1)];
        // A gas budget too small to cover compute + the state write.
        let result = run(
            &handler,
            &footprint,
            key(0x11),
            BTreeMap::new(),
            b"hello",
            200,
        );
        assert!(matches!(result, Err(ContractError::OutOfGas)));
    }

    #[test]
    fn wasm_contract_undeclared_key_fails_closed() {
        // The module writes key(0xa1); declaring a DIFFERENT footprint makes that
        // write undeclared, so the ContractContext rejects it fail-closed.
        let module = store_and_echo_wat();
        let handler = WasmContract::new(&module);
        let footprint = vec![key(0xb2)];
        let result = run(
            &handler,
            &footprint,
            key(0x11),
            BTreeMap::new(),
            b"hi",
            10_000_000,
        );
        assert!(matches!(result, Err(ContractError::UndeclaredKey { .. })));
    }
}
