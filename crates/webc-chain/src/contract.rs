//! Interim native (Rust-authored) contract runtime framework (Phase 7a, ADR-0014
//! interim path (c); WEBC-DEFINITION §15.41 machine manifest).
//!
//! Purpose: run application logic authored *off-chain* behind the SAME
//! declared-access + deterministic-gas + atomic-rollback discipline the native
//! operations already enforce, without yet admitting any untrusted bytecode. A
//! "contract" here is an audited Rust handler ([`Contract`]) selected by an
//! on-chain [`ContractManifest`]; the manifest describes the contract's identity,
//! its application namespace, its declared state footprint, and the ABI/gas
//! schedule versions it was authored against. This is the recommended first step
//! of ADR-0014 — it lets the manifest schema, the state-access extension, the gas
//! model, and the whole contract seam be built and frozen against native Rust the
//! node already trusts, before any WASM engine or untrusted-code loading is added
//! (both are explicitly deferred to later ADR-0014 steps and are NOT built here).
//!
//! Responsibilities: define the committed [`ContractManifest`] record and its
//! validation, the built-in handler registry ([`BuiltinContract`] /
//! [`builtin_contract`]), the [`Contract`] trait and the bounded execution
//! environment ([`ContractContext`]) a handler may touch, the deterministic gas
//! meter ([`GasMeter`]), the typed [`ContractError`], the bounded on-chain state
//! value ([`ContractStateValue`]), the Merkle sub-root domains that commit the
//! contract registry and contract state to the state root, and one built-in
//! example contract ([`KeyValueContract`]) that proves the framework end-to-end.
//!
//! Non-responsibilities: this module never moves native supply, never touches
//! accounts, and never reads a wall clock, network, files, or randomness. The
//! `state` module owns the committed maps (`contracts`, `contract_state`), the
//! register/invoke state transitions, the fee burn, and the
//! state-commitment/access-list wiring; it drives the pure logic here through a
//! [`StateAccessRecorder`] so a contract fails closed on any undeclared access
//! exactly like a native operation.
//!
//! Determinism: no wall clock, RNG, or float on any path. Block epoch is injected
//! as an input (never read). Every collection in the hashed/consensus path is a
//! `BTreeMap`/`BTreeSet`; every arithmetic is checked; hostile input never panics
//! (bounded input, bounded state values, explicit length checks before slicing).
//! No `unsafe`. A handler observes only its declared footprint keys under its own
//! namespace and consumes units from the sender's authorized `gas_limit`, so two
//! contracts in disjoint namespaces stay parallel-schedulable and an over-gas or
//! undeclared-access call rolls the whole transaction back atomically.
//!
//! Security boundary: every input (a submitted manifest, a call's `input` bytes,
//! a declared footprint) is untrusted. The manifest is validated (supported ABI
//! and gas-schedule versions, a bounded, sorted, de-duplicated, non-empty
//! footprint, registrant ownership) before it is committed; a duplicate `code_id`
//! is rejected. At invocation the signed operation is bound to the committed
//! manifest (namespace and declared footprint must match exactly), the declared
//! footprint is recorded through the shared [`StateAccessRecorder`] (so an
//! omitted or padded access list fails closed), and the handler can reach state
//! only through [`ContractContext`], which refuses any key outside the footprint.
//! The only trust surface is this audited framework and its built-in handlers.
//!
//! ABI / manifest versioning: [`ContractManifest::abi_version`] and
//! [`ContractManifest::gas_schedule_version`] pin the versioned seam ADR-0014
//! describes, so the interim native path (c) can migrate to a WASM engine (a)
//! under the SAME manifest schema without a breaking change: the built-in
//! [`BuiltinContract`] selector is later replaced by an artifact reference while
//! `code_id`, `namespace`, `footprint`, and the version fields keep their meaning.

use crate::state_key::StateAccessRecorder;
use crate::{Amount, ChainError, StateKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use webc_crypto::{Address, Hash256};

/// Current contract ABI / manifest schema version.
///
/// Bumped when the [`ContractManifest`] shape or the entrypoint calling
/// convention changes. A manifest declaring an unsupported version is rejected at
/// registration, so a node never interprets a future manifest with today's rules.
pub const CONTRACT_ABI_VERSION: u16 = 1;

/// Current interim gas-schedule version the cost constants in this module define.
///
/// The manifest pins the schedule it was priced against so fee estimation and a
/// future re-pricing stay version-legible; the actual unit costs are
/// protocol-fixed (below), not owner- or manifest-supplied, so a deployer cannot
/// under-price its own contract.
pub const CONTRACT_GAS_SCHEDULE_VERSION: u16 = 1;

/// Maximum declared footprint keys one contract may register.
///
/// Bounds the per-invocation access-list size (each footprint key becomes one
/// `read_write` `StateKey::application` entry) and the whole-footprint load, so a
/// hostile manifest cannot inflate scheduling or execution work. Well within
/// [`crate::MAX_TRANSACTION_STATE_KEYS`].
pub const MAX_CONTRACT_FOOTPRINT_KEYS: usize = 32;

/// Maximum bytes of `input` one contract invocation may carry.
///
/// Checked before the handler runs so hostile input cannot exhaust memory or CPU.
pub const MAX_CONTRACT_INPUT_BYTES: usize = 4 * 1024;

/// Maximum bytes one contract state value ([`ContractStateValue`]) may hold.
///
/// A handler write above this bound fails closed and rolls the transaction back.
pub const MAX_CONTRACT_STATE_VALUE_BYTES: usize = 4 * 1024;

/// Domain tag for the contract-registry Merkle sub-root committed by the state
/// root.
///
/// Each `(code_id, ContractManifest)` entry is a leaf under this domain, so
/// registering a contract changes the state root. Bumping this constant is a
/// consensus-format change.
pub const CONTRACT_LEAF_DOMAIN: &[u8] = b"WEBC_CONTRACT_LEAF_V1";

/// Domain tag for the contract-state Merkle sub-root committed by the state root.
///
/// Each `((namespace, key_hash), ContractStateValue)` entry is a leaf under this
/// domain, so any contract write changes the state root. Bumping this constant is
/// a consensus-format change.
pub const CONTRACT_STATE_LEAF_DOMAIN: &[u8] = b"WEBC_CONTRACT_STATE_LEAF_V1";

// ----- interim gas cost model (benchmark-tunable placeholders) -----
//
// These are prototype placeholders, centralized here exactly like
// `Operation::required_units` so future benchmarking can tune them without
// scattering magic constants. They are protocol-fixed values, not owner policy
// and not manifest-supplied, so a contract cannot under-price itself.

/// Base admission units charged for any `InvokeContract` (priced by
/// `Operation::required_units`, settled as the transaction fee up front).
pub const CONTRACT_INVOKE_BASE_UNITS: u64 = 20_000;

/// Additional admission units charged per byte of call `input`.
pub const CONTRACT_INPUT_BYTE_UNITS: u64 = 4;

/// Additional admission units charged per declared footprint key.
pub const CONTRACT_DECLARED_KEY_UNITS: u64 = 200;

/// Metered units for loading/locking one declared footprint state key.
pub const CONTRACT_STATE_READ_UNITS: u64 = 500;

/// Metered units for writing one declared footprint state key (base cost).
pub const CONTRACT_STATE_WRITE_UNITS: u64 = 1_000;

/// Metered units charged per byte of a written state value.
pub const CONTRACT_STATE_WRITE_BYTE_UNITS: u64 = 8;

/// Metered units for one contract compute step (a handler command).
pub const CONTRACT_STEP_UNITS: u64 = 50;

/// Which audited built-in Rust handler a registered contract runs.
///
/// For the interim native path (c) the deployed "artifact" is one of these
/// audited, in-tree handlers; the manifest names it here. When a general WASM
/// engine lands (ADR-0014 path (a)) this selector is replaced by an artifact hash
/// reference under the same manifest schema, so the migration needs no schema
/// break. Serialized by name, so adding a variant never moves an existing
/// manifest's committed leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum BuiltinContract {
    /// A minimal key/value store with a counter, proving the framework
    /// end-to-end ([`KeyValueContract`]).
    KeyValue,
}

/// Returns the audited built-in handler for `kind`.
///
/// A pure static dispatch: the returned reference is fixed at compile time, so
/// every node runs byte-identical handler code. No I/O, no allocation.
pub fn builtin_contract(kind: BuiltinContract) -> &'static dyn Contract {
    match kind {
        // Rvalue static promotion: `&KeyValueContract` (a zero-sized unit struct)
        // has 'static lifetime, so no runtime allocation is needed.
        BuiltinContract::KeyValue => &KeyValueContract,
    }
}

/// On-chain committed record describing one registered contract.
///
/// Keyed in [`crate::ChainState::contracts`] by `code_id` and addressed for
/// declared access by the reserved `StateKey::module(code_id)` key. Its state
/// lives under `StateKey::application(namespace, key_hash)` for each `key_hash`
/// in `footprint`. Committed by the state root through the contract registry
/// sub-root ([`CONTRACT_LEAF_DOMAIN`]), so registering a contract changes the
/// state root.
///
/// Invariants (all enforced by [`ContractManifest::validate`] before the record
/// is committed):
/// - `abi_version == CONTRACT_ABI_VERSION` and
///   `gas_schedule_version == CONTRACT_GAS_SCHEDULE_VERSION`;
/// - `footprint` is non-empty, at most [`MAX_CONTRACT_FOOTPRINT_KEYS`], strictly
///   ascending and therefore duplicate-free (a canonical, deterministic order);
/// - `owner` is the account that registered the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractManifest {
    /// ABI / manifest schema version this record is written against.
    pub abi_version: u16,
    /// Gas-schedule version this contract was priced against.
    pub gas_schedule_version: u16,
    /// Caller-chosen collision-resistant on-chain identity (the registry key and
    /// the `StateKey::module` address). Distinct from the handler selector so
    /// several independent contracts may share one built-in handler in different
    /// namespaces.
    pub code_id: Hash256,
    /// Application namespace this contract's state is isolated under (§8).
    pub namespace: Hash256,
    /// Audited built-in handler that implements this contract's logic.
    pub builtin: BuiltinContract,
    /// The declared application key-hashes this contract may read and write,
    /// strictly ascending. Each becomes a `StateKey::application(namespace,
    /// key_hash)` in an invocation's signed access list, so the contract's whole
    /// declared footprint is enforced by [`StateAccessRecorder`].
    pub footprint: Vec<Hash256>,
    /// Account that registered (and owns) this contract record.
    pub owner: Address,
}

impl ContractManifest {
    /// Constructs a manifest at the current ABI/gas-schedule versions.
    ///
    /// The `footprint` is sorted and de-duplicated so callers need not pre-sort;
    /// [`ContractManifest::validate`] still independently rejects a malformed
    /// footprint on hostile wire input.
    pub fn new(
        code_id: Hash256,
        namespace: Hash256,
        builtin: BuiltinContract,
        footprint: impl IntoIterator<Item = Hash256>,
        owner: Address,
    ) -> Self {
        let sorted: BTreeSet<Hash256> = footprint.into_iter().collect();
        Self {
            abi_version: CONTRACT_ABI_VERSION,
            gas_schedule_version: CONTRACT_GAS_SCHEDULE_VERSION,
            code_id,
            namespace,
            builtin,
            footprint: sorted.into_iter().collect(),
            owner,
        }
    }

    /// Validates a hostile manifest before it may be committed.
    ///
    /// Rejects an unsupported ABI or gas-schedule version, an empty / oversized /
    /// unsorted / duplicated footprint, or a manifest whose `owner` is not the
    /// registrant. Fails closed with a typed error; never panics.
    pub fn validate(&self, registrant: Address) -> Result<(), ChainError> {
        if self.abi_version != CONTRACT_ABI_VERSION
            || self.gas_schedule_version != CONTRACT_GAS_SCHEDULE_VERSION
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
        // so the committed leaf and the derived access list are deterministic and
        // a padded footprint cannot manufacture false scheduling conflicts.
        if !self.footprint.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ChainError::InvalidContractManifest);
        }
        Ok(())
    }
}

/// Protocol parameters for the interim contract runtime.
///
/// The launch value is a **testnet-measured placeholder**, not a promise — the
/// method (a flat, burned registration fee, exactly like feed creation) is fixed;
/// the number moves with data. `#[serde(default)]` via the derived [`Default`]
/// keeps a genesis written before the runtime decodable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractRuntimeConfig {
    /// Flat fee, in native base units, charged to register a contract and
    /// **burned** (liquid → burned), so registration is never free spam and is
    /// supply-neutral. Placeholder.
    pub registration_fee: Amount,
}

impl Default for ContractRuntimeConfig {
    fn default() -> Self {
        Self {
            // 1e-3 WEBC: a small anti-spam registration fee, matching the oracle
            // feed-creation fee class. Measurement-tuned (§15.35).
            registration_fee: Amount::from_units(1_000_000_000),
        }
    }
}

/// Bounded opaque bytes stored under one contract state key.
///
/// Stored in [`crate::ChainState::contract_state`] keyed by `(namespace,
/// key_hash)`. Encoded as lowercase hex in the human-readable (canonical JSON)
/// form — matching object payloads and bridge byte fields — so a browser SDK can
/// mirror the committed leaf, and as raw bytes in the binary at-rest/wire form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContractStateValue(#[serde(with = "crate::hex_bytes")] pub Vec<u8>);

/// Deterministic gas meter bounding one contract invocation.
///
/// Seeded with the operation's admission units (already settled as the fee) and
/// hard-capped at the sender's authorized `gas_limit`. Every host cost is charged
/// through [`GasMeter::charge`] with checked arithmetic; exceeding the cap fails
/// closed with [`ContractError::OutOfGas`], which the caller turns into an atomic
/// rollback — no partial contract state survives.
pub struct GasMeter {
    limit: u64,
    consumed: u64,
}

impl GasMeter {
    /// Creates a meter capped at `limit` with `initial` units already consumed.
    ///
    /// `initial` is the base admission cost the fee already covers; charging it
    /// here makes the cap account for both admission and metered execution.
    /// Fails closed if the admission cost alone exceeds the authorized cap.
    pub fn new(limit: u64, initial: u64) -> Result<Self, ContractError> {
        if initial > limit {
            return Err(ContractError::OutOfGas);
        }
        Ok(Self {
            limit,
            consumed: initial,
        })
    }

    /// Charges `units`, failing closed if the running total exceeds the cap.
    pub fn charge(&mut self, units: u64) -> Result<(), ContractError> {
        let next = self
            .consumed
            .checked_add(units)
            .ok_or(ContractError::GasOverflow)?;
        if next > self.limit {
            return Err(ContractError::OutOfGas);
        }
        self.consumed = next;
        Ok(())
    }

    /// Total units consumed so far (admission plus metered execution).
    pub fn consumed(&self) -> u64 {
        self.consumed
    }
}

/// A registered contract's audited Rust handler.
///
/// A handler is pure application logic: it may read/write only its declared
/// footprint through `ctx`, read the injected block epoch, meter its own compute
/// steps, and return bounded output bytes. It must not read a wall clock, RNG,
/// files, or the network, must use checked arithmetic, and must never panic on
/// hostile `input`. All of that is enforced structurally — the handler is handed
/// only a [`ContractContext`] and a `&[u8]`, and returns a typed [`ContractError`].
pub trait Contract {
    /// Executes one call. Returns bounded output bytes or a typed error that
    /// rolls the whole transaction back atomically.
    fn call(&self, ctx: &mut ContractContext, input: &[u8]) -> Result<Vec<u8>, ContractError>;
}

/// The bounded execution environment a [`Contract`] handler may touch.
///
/// Routes every state access through the shared [`StateAccessRecorder`] against
/// the manifest's declared footprint under the contract's namespace, so a handler
/// that reaches for an undeclared key — or whose signed access list omits a
/// declared key — fails closed exactly like native execution. Working values are
/// loaded from committed state before the handler runs and returned by
/// [`ContractContext::into_writes`] afterward; the caller persists them only on
/// success.
pub struct ContractContext<'a> {
    namespace: Hash256,
    footprint: &'a [Hash256],
    working: BTreeMap<Hash256, Option<Vec<u8>>>,
    touched: BTreeSet<Hash256>,
    recorder: &'a mut StateAccessRecorder,
    meter: &'a mut GasMeter,
    epoch: u64,
}

impl<'a> ContractContext<'a> {
    /// Builds a context over a contract's loaded working set.
    ///
    /// `working` holds the current value (or `None` if absent) of every footprint
    /// key, loaded from committed state by the caller. `recorder` is the same
    /// access recorder the surrounding native transaction uses, so contract
    /// access enforcement reuses the native path exactly.
    pub(crate) fn new(
        namespace: Hash256,
        footprint: &'a [Hash256],
        working: BTreeMap<Hash256, Option<Vec<u8>>>,
        recorder: &'a mut StateAccessRecorder,
        meter: &'a mut GasMeter,
        epoch: u64,
    ) -> Self {
        Self {
            namespace,
            footprint,
            working,
            touched: BTreeSet::new(),
            recorder,
            meter,
            epoch,
        }
    }

    /// The consensus epoch of the block executing this call (injected block env).
    ///
    /// This is the only ambient environment a contract may read: a committed
    /// integer, never a wall clock or RNG, so execution stays deterministic.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Records the first touch of `key_hash`: rejects an undeclared key, binds the
    /// declared key through the recorder, and meters one state read.
    fn touch(&mut self, key_hash: Hash256) -> Result<(), ContractError> {
        if !self.footprint.contains(&key_hash) {
            return Err(ContractError::UndeclaredKey { key_hash });
        }
        if self.touched.insert(key_hash) {
            // Route the access through the shared recorder against the signed
            // access list. Footprint keys are declared read_write, so a correct
            // access list accepts this; an omitted key fails closed here.
            self.recorder
                .write(StateKey::application(self.namespace, key_hash))
                .map_err(|_| ContractError::UndeclaredKey { key_hash })?;
            self.meter.charge(CONTRACT_STATE_READ_UNITS)?;
        }
        Ok(())
    }

    /// Reads a declared key's current value, or `None` if unset.
    ///
    /// Fails closed if `key_hash` is outside the contract's footprint.
    pub fn get(&mut self, key_hash: Hash256) -> Result<Option<&[u8]>, ContractError> {
        self.touch(key_hash)?;
        Ok(self
            .working
            .get(&key_hash)
            .and_then(|value| value.as_deref()))
    }

    /// Writes a declared key's value, bounded by [`MAX_CONTRACT_STATE_VALUE_BYTES`].
    ///
    /// Fails closed on an undeclared key or an oversized value; meters the write.
    pub fn set(&mut self, key_hash: Hash256, value: Vec<u8>) -> Result<(), ContractError> {
        if value.len() > MAX_CONTRACT_STATE_VALUE_BYTES {
            return Err(ContractError::StateValueTooLarge {
                actual: value.len(),
                maximum: MAX_CONTRACT_STATE_VALUE_BYTES,
            });
        }
        self.touch(key_hash)?;
        let write_bytes = u64::try_from(value.len()).unwrap_or(u64::MAX);
        self.meter.charge(CONTRACT_STATE_WRITE_UNITS)?;
        self.meter
            .charge(write_bytes.saturating_mul(CONTRACT_STATE_WRITE_BYTE_UNITS))?;
        self.working.insert(key_hash, Some(value));
        Ok(())
    }

    /// Removes a declared key's value.
    ///
    /// Fails closed on an undeclared key; meters the write.
    pub fn remove(&mut self, key_hash: Hash256) -> Result<(), ContractError> {
        self.touch(key_hash)?;
        self.meter.charge(CONTRACT_STATE_WRITE_UNITS)?;
        self.working.insert(key_hash, None);
        Ok(())
    }

    /// Charges `units` of contract compute against the gas cap.
    pub fn step(&mut self, units: u64) -> Result<(), ContractError> {
        self.meter.charge(units)
    }

    /// Consumes the context, recording every not-yet-touched footprint key and
    /// returning the full working set for the caller to persist.
    ///
    /// Recording the untouched footprint keys makes the observed access exactly
    /// equal the declared access, so the surrounding transaction's
    /// [`StateAccessRecorder::finish`] check (every declared key must be used)
    /// passes — the contract's declared footprint is always fully accounted, which
    /// is what keeps two invocations of the same contract serializable.
    pub(crate) fn into_writes(mut self) -> Result<BTreeMap<Hash256, Option<Vec<u8>>>, ContractError> {
        let untouched: Vec<Hash256> = self
            .footprint
            .iter()
            .filter(|key_hash| !self.touched.contains(*key_hash))
            .copied()
            .collect();
        for key_hash in untouched {
            self.touch(key_hash)?;
        }
        Ok(self.working)
    }
}

/// Typed contract-execution failure.
///
/// Every variant rolls the whole transaction back atomically (no partial contract
/// state persists) and maps to a [`ChainError`] via `From`. None is ever produced
/// by a panic — hostile input is validated before it can allocate, slice, or
/// overflow.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ContractError {
    /// The call consumed more than the authorized `gas_limit`.
    #[error("contract call exceeded its gas limit")]
    OutOfGas,
    /// Gas accounting overflowed `u64` (an astronomically large charge).
    #[error("contract gas accounting overflowed")]
    GasOverflow,
    /// The handler touched a state key outside its declared footprint.
    #[error("contract touched an undeclared state key")]
    UndeclaredKey { key_hash: Hash256 },
    /// A written state value exceeded the per-value byte bound.
    #[error("contract state value has {actual} bytes, above the maximum of {maximum}")]
    StateValueTooLarge { actual: usize, maximum: usize },
    /// The call `input` bytes were malformed for the handler's command set.
    #[error("contract input is malformed")]
    InvalidInput,
    /// A checked arithmetic operation inside the handler overflowed.
    #[error("contract arithmetic overflowed")]
    ArithmeticOverflow,
}

impl From<ContractError> for ChainError {
    fn from(error: ContractError) -> Self {
        match error {
            ContractError::OutOfGas | ContractError::GasOverflow => ChainError::ContractOutOfGas,
            ContractError::UndeclaredKey { .. } => ChainError::ContractUndeclaredKey,
            ContractError::StateValueTooLarge { actual, maximum } => {
                ChainError::ContractStateValueTooLarge { actual, maximum }
            }
            ContractError::InvalidInput => ChainError::ContractInvalidInput,
            ContractError::ArithmeticOverflow => ChainError::ArithmeticOverflow,
        }
    }
}

// ----- built-in example contract: a minimal key/value store with a counter -----

/// Command opcode: set a key to a value. Layout: `[0x01][key_hash:32][value..]`.
const KV_SET: u8 = 0x01;
/// Command opcode: read a key. Layout: `[0x02][key_hash:32]`. Returns the value
/// (or empty bytes if unset).
const KV_GET: u8 = 0x02;
/// Command opcode: delete a key. Layout: `[0x03][key_hash:32]`.
const KV_DELETE: u8 = 0x03;
/// Command opcode: add to a 16-byte big-endian `u128` counter. Layout:
/// `[0x04][key_hash:32][delta:16]`. Returns the new counter (16 bytes). An unset
/// key starts at zero; overflow fails closed.
const KV_INCREMENT: u8 = 0x04;

/// A minimal key/value store proving the interim contract framework end-to-end.
///
/// Deliberately tiny: its only purpose is to exercise register → invoke →
/// declared-access enforcement → gas metering → state commit. It stores bounded
/// values under keys drawn from its declared footprint and supports set / get /
/// delete plus an increment command that treats a value as a 16-byte big-endian
/// `u128` counter. It is strictly value-neutral — it moves no native units — so
/// the supply invariant is untouched by any invocation.
///
/// The command bytes are decoded by an explicit, bounds-checked hand parser (no
/// dependency, no recursion), so malformed hostile `input` yields
/// [`ContractError::InvalidInput`] rather than a panic. Every key referenced by a
/// command must lie in the contract's declared footprint, or the access fails
/// closed through [`ContractContext`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyValueContract;

impl KeyValueContract {
    /// Reads a 32-byte key hash from `bytes[offset..offset+32]`, or fails closed.
    fn read_key(bytes: &[u8], offset: usize) -> Result<Hash256, ContractError> {
        let end = offset.checked_add(32).ok_or(ContractError::InvalidInput)?;
        let slice = bytes.get(offset..end).ok_or(ContractError::InvalidInput)?;
        let array: [u8; 32] = slice.try_into().map_err(|_| ContractError::InvalidInput)?;
        Ok(Hash256(array))
    }
}

impl Contract for KeyValueContract {
    fn call(&self, ctx: &mut ContractContext, input: &[u8]) -> Result<Vec<u8>, ContractError> {
        // One compute step per command keeps the trivial handler metered.
        ctx.step(CONTRACT_STEP_UNITS)?;
        let (&opcode, rest) = input.split_first().ok_or(ContractError::InvalidInput)?;
        match opcode {
            KV_SET => {
                let key = Self::read_key(input, 1)?;
                // Everything after the key is the value (bounded by ctx.set).
                let value = rest.get(32..).ok_or(ContractError::InvalidInput)?.to_vec();
                ctx.set(key, value)?;
                Ok(Vec::new())
            }
            KV_GET => {
                if rest.len() != 32 {
                    return Err(ContractError::InvalidInput);
                }
                let key = Self::read_key(input, 1)?;
                Ok(ctx.get(key)?.map(<[u8]>::to_vec).unwrap_or_default())
            }
            KV_DELETE => {
                if rest.len() != 32 {
                    return Err(ContractError::InvalidInput);
                }
                let key = Self::read_key(input, 1)?;
                ctx.remove(key)?;
                Ok(Vec::new())
            }
            KV_INCREMENT => {
                // key (32) + delta (16).
                if rest.len() != 48 {
                    return Err(ContractError::InvalidInput);
                }
                let key = Self::read_key(input, 1)?;
                let delta_bytes: [u8; 16] = input
                    .get(33..49)
                    .ok_or(ContractError::InvalidInput)?
                    .try_into()
                    .map_err(|_| ContractError::InvalidInput)?;
                let delta = u128::from_be_bytes(delta_bytes);
                let current = match ctx.get(key)? {
                    Some(bytes) => {
                        let array: [u8; 16] =
                            bytes.try_into().map_err(|_| ContractError::InvalidInput)?;
                        u128::from_be_bytes(array)
                    }
                    None => 0,
                };
                let next = current
                    .checked_add(delta)
                    .ok_or(ContractError::ArithmeticOverflow)?;
                let encoded = next.to_be_bytes().to_vec();
                ctx.set(key, encoded.clone())?;
                Ok(encoded)
            }
            _ => Err(ContractError::InvalidInput),
        }
    }
}

/// Convenience command builders for the [`KeyValueContract`], shared by callers,
/// tests, and a future browser SDK mirror so the wire command bytes have one
/// authoritative encoder.
pub mod kv_command {
    use super::{KV_DELETE, KV_GET, KV_INCREMENT, KV_SET};
    use webc_crypto::Hash256;

    /// Encodes a `set key = value` command.
    pub fn set(key: Hash256, value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(33 + value.len());
        bytes.push(KV_SET);
        bytes.extend_from_slice(&key.0);
        bytes.extend_from_slice(value);
        bytes
    }

    /// Encodes a `get key` command.
    pub fn get(key: Hash256) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(33);
        bytes.push(KV_GET);
        bytes.extend_from_slice(&key.0);
        bytes
    }

    /// Encodes a `delete key` command.
    pub fn delete(key: Hash256) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(33);
        bytes.push(KV_DELETE);
        bytes.extend_from_slice(&key.0);
        bytes
    }

    /// Encodes an `increment key by delta` command.
    pub fn increment(key: Hash256, delta: u128) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(49);
        bytes.push(KV_INCREMENT);
        bytes.extend_from_slice(&key.0);
        bytes.extend_from_slice(&delta.to_be_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StateKey;

    fn key(n: u8) -> Hash256 {
        Hash256([n; 32])
    }

    fn owner() -> Address {
        webc_crypto::Keypair::from_seed([1u8; 32]).address()
    }

    fn manifest(footprint: Vec<Hash256>) -> ContractManifest {
        ContractManifest::new(
            key(0xc0),
            key(0x11),
            BuiltinContract::KeyValue,
            footprint,
            owner(),
        )
    }

    #[test]
    fn manifest_new_sorts_and_dedups_footprint() {
        let m = manifest(vec![key(3), key(1), key(2), key(1)]);
        assert_eq!(m.footprint, vec![key(1), key(2), key(3)]);
        m.validate(owner()).expect("well-formed manifest validates");
    }

    #[test]
    fn manifest_validate_rejects_malformed_input() {
        // Empty footprint.
        assert!(matches!(
            manifest(vec![]).validate(owner()),
            Err(ChainError::InvalidContractManifest)
        ));
        // Wrong owner.
        let other = webc_crypto::Keypair::from_seed([2u8; 32]).address();
        assert!(matches!(
            manifest(vec![key(1)]).validate(other),
            Err(ChainError::InvalidContractManifest)
        ));
        // Unsupported ABI version.
        let mut bad = manifest(vec![key(1)]);
        bad.abi_version = CONTRACT_ABI_VERSION + 1;
        assert!(matches!(
            bad.validate(owner()),
            Err(ChainError::UnsupportedContractAbiVersion { .. })
        ));
        // Unsorted footprint constructed directly on the wire type.
        let mut unsorted = manifest(vec![key(1), key(2)]);
        unsorted.footprint = vec![key(2), key(1)];
        assert!(matches!(
            unsorted.validate(owner()),
            Err(ChainError::InvalidContractManifest)
        ));
        // Oversized footprint.
        let oversized: Vec<Hash256> = (0..=MAX_CONTRACT_FOOTPRINT_KEYS)
            .map(|n| Hash256([u8::try_from(n).unwrap_or(u8::MAX); 32]))
            .collect();
        let mut big = manifest(vec![key(1)]);
        big.footprint = oversized;
        assert!(matches!(
            big.validate(owner()),
            Err(ChainError::InvalidContractManifest)
        ));
    }

    #[test]
    fn manifest_round_trips_and_rejects_unknown_fields() {
        let m = manifest(vec![key(1), key(2)]);
        let text = serde_json::to_string(&m).expect("serializes");
        assert_eq!(serde_json::from_str::<ContractManifest>(&text).unwrap(), m);
        let mut value = serde_json::to_value(&m).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ContractManifest>(value).is_err());
    }

    #[test]
    fn state_value_serializes_as_hex() {
        let v = ContractStateValue(vec![0, 1, 255, 32]);
        assert_eq!(serde_json::to_string(&v).unwrap(), r#""0001ff20""#);
        let decoded: ContractStateValue = serde_json::from_str(r#""0001ff20""#).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn gas_meter_charges_and_fails_closed() {
        let mut meter = GasMeter::new(1_000, 100).expect("admission within cap");
        meter.charge(400).expect("within cap");
        assert_eq!(meter.consumed(), 500);
        assert!(matches!(meter.charge(600), Err(ContractError::OutOfGas)));
        // Admission above the cap is rejected outright.
        assert!(matches!(GasMeter::new(10, 20), Err(ContractError::OutOfGas)));
    }

    /// Drives the key/value handler directly through a context with a real
    /// recorder over an access list built from the footprint, mirroring how the
    /// `state` module invokes it.
    fn run_kv(
        footprint: &[Hash256],
        working: BTreeMap<Hash256, Option<Vec<u8>>>,
        input: &[u8],
        gas_limit: u64,
    ) -> Result<(Vec<u8>, BTreeMap<Hash256, Option<Vec<u8>>>, u64), ContractError> {
        let namespace = key(0x11);
        let declared: Vec<StateKey> = footprint
            .iter()
            .map(|kh| StateKey::application(namespace, *kh))
            .collect();
        let mut recorder = StateAccessRecorder::new(&[], &declared).expect("recorder");
        let mut meter = GasMeter::new(gas_limit, 0).expect("meter");
        let mut ctx =
            ContractContext::new(namespace, footprint, working, &mut recorder, &mut meter, 7);
        let output = KeyValueContract.call(&mut ctx, input)?;
        let writes = ctx.into_writes()?;
        let consumed = meter.consumed();
        recorder.finish().expect("every declared footprint key was used");
        Ok((output, writes, consumed))
    }

    #[test]
    fn key_value_set_get_delete_and_increment() {
        let k = key(1);
        let footprint = vec![k];

        // Set then the working set carries the value.
        let (_out, writes, _) = run_kv(
            &footprint,
            BTreeMap::new(),
            &kv_command::set(k, b"hello"),
            1_000_000,
        )
        .expect("set");
        assert_eq!(writes.get(&k), Some(&Some(b"hello".to_vec())));

        // Increment from zero.
        let (out, writes, _) = run_kv(
            &footprint,
            BTreeMap::new(),
            &kv_command::increment(k, 5),
            1_000_000,
        )
        .expect("increment");
        assert_eq!(out, 5u128.to_be_bytes().to_vec());
        assert_eq!(writes.get(&k), Some(&Some(5u128.to_be_bytes().to_vec())));

        // Increment an existing counter.
        let mut working = BTreeMap::new();
        working.insert(k, Some(5u128.to_be_bytes().to_vec()));
        let (out, _writes, _) =
            run_kv(&footprint, working, &kv_command::increment(k, 37), 1_000_000).expect("inc2");
        assert_eq!(out, 42u128.to_be_bytes().to_vec());

        // Delete.
        let mut working = BTreeMap::new();
        working.insert(k, Some(b"hello".to_vec()));
        let (_out, writes, _) =
            run_kv(&footprint, working, &kv_command::delete(k), 1_000_000).expect("delete");
        assert_eq!(writes.get(&k), Some(&None));
    }

    #[test]
    fn key_value_rejects_undeclared_key_and_malformed_input() {
        let declared = key(1);
        let footprint = vec![declared];
        // A command referencing a key outside the footprint fails closed.
        let stranger = key(9);
        assert!(matches!(
            run_kv(
                &footprint,
                BTreeMap::new(),
                &kv_command::set(stranger, b"x"),
                1_000_000
            ),
            Err(ContractError::UndeclaredKey { .. })
        ));
        // Empty input.
        assert!(matches!(
            run_kv(&footprint, BTreeMap::new(), &[], 1_000_000),
            Err(ContractError::InvalidInput)
        ));
        // Truncated key.
        assert!(matches!(
            run_kv(&footprint, BTreeMap::new(), &[KV_GET, 1, 2, 3], 1_000_000),
            Err(ContractError::InvalidInput)
        ));
        // Unknown opcode.
        let mut bad = vec![0xff];
        bad.extend_from_slice(&declared.0);
        assert!(matches!(
            run_kv(&footprint, BTreeMap::new(), &bad, 1_000_000),
            Err(ContractError::InvalidInput)
        ));
    }

    #[test]
    fn key_value_increment_overflow_fails_closed() {
        let k = key(1);
        let footprint = vec![k];
        let mut working = BTreeMap::new();
        working.insert(k, Some(u128::MAX.to_be_bytes().to_vec()));
        assert!(matches!(
            run_kv(&footprint, working, &kv_command::increment(k, 1), 1_000_000),
            Err(ContractError::ArithmeticOverflow)
        ));
    }

    #[test]
    fn out_of_gas_fails_closed() {
        let k = key(1);
        let footprint = vec![k];
        // A tiny gas budget cannot cover the step + read + write of a set.
        assert!(matches!(
            run_kv(&footprint, BTreeMap::new(), &kv_command::set(k, b"hello"), 100),
            Err(ContractError::OutOfGas)
        ));
    }
}
