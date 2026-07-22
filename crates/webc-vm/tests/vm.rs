//! End-to-end tests for the deterministic contract VM.
//!
//! WAT fixtures are compiled to wasm in-test via the `wat` crate. A `MockHost`
//! (a `BTreeMap` plus a fail-closed gas counter mirroring `GasMeter`) stands in
//! for the chain's `ContractContext` + `GasMeter` adapter.

use std::collections::BTreeMap;

use webc_crypto::Hash256;
use webc_vm::{execute, validate_module, VmError, VmHost, VmLimits};

/// The fixed 32-byte key used by the counter/kv fixture (`0x11` repeated).
const FIXTURE_KEY: Hash256 = Hash256([0x11; 32]);

/// An in-memory [`VmHost`] recording writes and metering gas fail-closed.
struct MockHost {
    store: BTreeMap<Hash256, Vec<u8>>,
    epoch: u64,
    gas_used: u64,
    gas_limit: u64,
    /// When set, every `get`/`set` is denied, simulating a footprint violation.
    deny: bool,
}

impl MockHost {
    fn new() -> Self {
        Self {
            store: BTreeMap::new(),
            epoch: 7,
            gas_used: 0,
            gas_limit: 1_000_000_000,
            deny: false,
        }
    }
}

impl VmHost for MockHost {
    fn get(&mut self, key: &Hash256) -> Result<Option<Vec<u8>>, VmError> {
        if self.deny {
            return Err(VmError::HostDenied(
                "key outside declared footprint".to_string(),
            ));
        }
        Ok(self.store.get(key).cloned())
    }

    fn set(&mut self, key: Hash256, value: Vec<u8>) -> Result<(), VmError> {
        if self.deny {
            return Err(VmError::HostDenied(
                "key outside declared footprint".to_string(),
            ));
        }
        self.store.insert(key, value);
        Ok(())
    }

    fn epoch(&self) -> u64 {
        self.epoch
    }

    fn charge_gas(&mut self, units: u64) -> Result<(), VmError> {
        let next = self
            .gas_used
            .checked_add(units)
            .ok_or(VmError::GasOverflow)?;
        if next > self.gas_limit {
            return Err(VmError::OutOfGas);
        }
        self.gas_used = next;
        Ok(())
    }
}

/// A kv contract: read `input`, `webc_set` it under the fixture key, `webc_get`
/// it back, then `webc_output` the retrieved bytes.
fn counter_module() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
          (import "webc" "webc_input_len"  (func $input_len (result i32)))
          (import "webc" "webc_input_read" (func $input_read (param i32)))
          (import "webc" "webc_set" (func $set (param i32 i32 i32 i32) (result i32)))
          (import "webc" "webc_get" (func $get (param i32 i32 i32 i32) (result i32)))
          (import "webc" "webc_output" (func $output (param i32 i32)))
          (memory (export "memory") 1)
          ;; 32-byte key (0x11 repeated) at offset 0.
          (data (i32.const 0)
            "\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11")
          (func (export "webc_call")
            (local $len i32)
            (local $glen i32)
            (call $input_read (i32.const 256))
            (local.set $len (call $input_len))
            (drop (call $set (i32.const 0) (i32.const 32) (i32.const 256) (local.get $len)))
            (local.set $glen (call $get (i32.const 0) (i32.const 32) (i32.const 512) (i32.const 256)))
            (call $output (i32.const 512) (local.get $glen))))
        "#,
    )
    .expect("counter fixture is valid wat")
}

#[test]
fn counter_roundtrip_records_write_and_returns_value() {
    let module = counter_module();
    let limits = VmLimits::default();
    let mut host = MockHost::new();
    let input = b"hello webc";

    let output = execute(&module, input, &mut host, &limits).expect("execution succeeds");

    assert_eq!(output, input, "output echoes the round-tripped value");
    assert_eq!(
        host.store.get(&FIXTURE_KEY).map(Vec::as_slice),
        Some(input.as_slice()),
        "the mock host recorded the write under the fixture key"
    );
    assert!(host.gas_used > 0, "gas was metered");
}

#[test]
fn deterministic_same_module_input_and_state() {
    let module = counter_module();
    let limits = VmLimits::default();
    let input = b"deterministic";

    let mut host_a = MockHost::new();
    let out_a = execute(&module, input, &mut host_a, &limits).expect("run a");

    let mut host_b = MockHost::new();
    let out_b = execute(&module, input, &mut host_b, &limits).expect("run b");

    assert_eq!(out_a, out_b, "identical inputs yield identical output");
    assert_eq!(
        host_a.gas_used, host_b.gas_used,
        "metered gas is identical across runs"
    );
    assert_eq!(host_a.store, host_b.store, "recorded state is identical");
}

#[test]
fn out_of_fuel_fails_closed_as_out_of_gas() {
    let module = counter_module();
    let limits = VmLimits {
        fuel: 8,
        ..VmLimits::default()
    };
    let mut host = MockHost::new();

    let err = execute(&module, b"x", &mut host, &limits).expect_err("tiny fuel exhausts");
    assert!(matches!(err, VmError::OutOfGas), "got {err:?}");
}

#[test]
fn host_op_gas_exhaustion_fails_closed() {
    // Ample fuel, but a gas limit too small to cover the first host op.
    let module = counter_module();
    let limits = VmLimits::default();
    let mut host = MockHost::new();
    host.gas_limit = 1;

    let err = execute(&module, b"x", &mut host, &limits).expect_err("host gas exhausts");
    assert!(matches!(err, VmError::OutOfGas), "got {err:?}");
}

#[test]
fn out_of_bounds_pointer_traps_without_panic() {
    // Memory is one 64 KiB page; write output past the end with an in-cap length.
    let module = wat::parse_str(
        r#"
        (module
          (import "webc" "webc_output" (func $output (param i32 i32)))
          (memory (export "memory") 1)
          (func (export "webc_call")
            (call $output (i32.const 65000) (i32.const 1000))))
        "#,
    )
    .expect("oob fixture is valid wat");

    let limits = VmLimits::default();
    let mut host = MockHost::new();
    let err = execute(&module, b"", &mut host, &limits).expect_err("oob write traps");
    assert!(matches!(err, VmError::MemoryOutOfBounds), "got {err:?}");
}

#[test]
fn output_over_cap_is_rejected() {
    let module = wat::parse_str(
        r#"
        (module
          (import "webc" "webc_output" (func $output (param i32 i32)))
          (memory (export "memory") 1)
          (func (export "webc_call")
            (call $output (i32.const 0) (i32.const 5000))))
        "#,
    )
    .expect("over-cap fixture is valid wat");

    let limits = VmLimits::default(); // max_output_bytes = 4096
    let mut host = MockHost::new();
    let err = execute(&module, b"", &mut host, &limits).expect_err("over-cap output rejected");
    assert!(
        matches!(err, VmError::OutputTooLarge { max: 4096 }),
        "got {err:?}"
    );
}

#[test]
fn missing_entry_export_is_rejected() {
    let module = wat::parse_str(r#"(module (memory (export "memory") 1))"#)
        .expect("no-entry fixture is valid wat");
    let limits = VmLimits::default();
    let mut host = MockHost::new();
    let err = execute(&module, b"", &mut host, &limits).expect_err("missing entry");
    assert!(
        matches!(err, VmError::MissingExport(ref name) if name == "webc_call"),
        "got {err:?}"
    );
}

#[test]
fn host_denial_bubbles_as_host_denied() {
    let module = counter_module();
    let limits = VmLimits::default();
    let mut host = MockHost::new();
    host.deny = true;

    let err = execute(&module, b"x", &mut host, &limits).expect_err("footprint denial");
    assert!(matches!(err, VmError::HostDenied(_)), "got {err:?}");
}

#[test]
fn key_length_must_be_32() {
    // Call webc_get with key_len = 16.
    let module = wat::parse_str(
        r#"
        (module
          (import "webc" "webc_get" (func $get (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "webc_call")
            (drop (call $get (i32.const 0) (i32.const 16) (i32.const 64) (i32.const 32)))))
        "#,
    )
    .expect("bad-key fixture is valid wat");

    let limits = VmLimits::default();
    let mut host = MockHost::new();
    let err = execute(&module, b"", &mut host, &limits).expect_err("bad key length");
    assert!(matches!(err, VmError::KeyLengthInvalid(16)), "got {err:?}");
}

#[test]
fn validate_accepts_the_counter_module() {
    assert!(validate_module(&counter_module(), &VmLimits::default()).is_ok());
}

#[test]
fn validate_rejects_simd() {
    let module = wat::parse_str(
        r#"
        (module
          (memory (export "memory") 1)
          (func (export "webc_call")
            (drop (v128.load (i32.const 0)))))
        "#,
    )
    .expect("simd fixture is valid wat");
    let err = validate_module(&module, &VmLimits::default()).expect_err("simd rejected");
    assert!(matches!(err, VmError::InvalidModule(_)), "got {err:?}");
}

#[test]
fn validate_rejects_shared_memory_threads() {
    let module = wat::parse_str(r#"(module (memory (export "memory") 1 1 shared))"#)
        .expect("threads fixture is valid wat");
    let err = validate_module(&module, &VmLimits::default()).expect_err("shared memory rejected");
    assert!(matches!(err, VmError::InvalidModule(_)), "got {err:?}");
}

#[test]
fn validate_rejects_floats() {
    let module = wat::parse_str(
        r#"
        (module
          (func (export "webc_call") (result f32)
            (f32.const 1)))
        "#,
    )
    .expect("float fixture is valid wat");
    let err = validate_module(&module, &VmLimits::default()).expect_err("floats rejected");
    assert!(matches!(err, VmError::InvalidModule(_)), "got {err:?}");
}

#[test]
fn validate_rejects_oversized_module() {
    let module = counter_module();
    let limits = VmLimits {
        max_module_bytes: 8,
        ..VmLimits::default()
    };
    let err = validate_module(&module, &limits).expect_err("oversized rejected");
    assert!(
        matches!(err, VmError::ModuleTooLarge { max: 8, .. }),
        "got {err:?}"
    );
}

#[test]
fn validate_rejects_excess_memory_pages() {
    // Declares 32 pages against a 16-page cap.
    let module = wat::parse_str(r#"(module (memory (export "memory") 32))"#)
        .expect("big-mem fixture is valid wat");
    let err = validate_module(&module, &VmLimits::default()).expect_err("too many pages");
    assert!(
        matches!(err, VmError::MemoryLimitExceeded { pages: 32, max: 16 }),
        "got {err:?}"
    );
}

#[test]
fn runtime_memory_growth_is_capped_without_a_declared_maximum() {
    // A module declaring memory with NO maximum (so validation checks only the
    // initial page) then growing far past the 16-page cap. The run-time limiter
    // must DENY the grow (memory.grow returns -1) rather than allocating ~4 GiB —
    // otherwise one invocation is a memory-exhaustion DoS and RAM-constrained
    // validators diverge from well-provisioned ones.
    let module = wat::parse_str(
        r#"
        (module
          (import "webc" "webc_output" (func $output (param i32 i32)))
          (memory (export "memory") 1)
          (func (export "webc_call")
            (i32.store (i32.const 0) (memory.grow (i32.const 100)))
            (call $output (i32.const 0) (i32.const 4))))
        "#,
    )
    .expect("grow fixture is valid wat");
    // The no-maximum module still validates (only the declared initial is bounded).
    validate_module(&module, &VmLimits::default()).expect("no-maximum module validates");
    let mut host = MockHost::new();
    let output = execute(&module, b"", &mut host, &VmLimits::default()).expect("runs");
    // memory.grow failed -> -1 (0xffffffff little-endian), NOT the old page count.
    assert_eq!(
        output,
        vec![0xff, 0xff, 0xff, 0xff],
        "grow past the page cap is denied at run time"
    );
}

#[test]
fn runtime_memory_growth_within_cap_succeeds() {
    // A grow that stays within the 16-page cap succeeds (returns the previous size
    // in pages), so the limiter does not over-restrict legitimate growth.
    let module = wat::parse_str(
        r#"
        (module
          (import "webc" "webc_output" (func $output (param i32 i32)))
          (memory (export "memory") 1)
          (func (export "webc_call")
            (i32.store (i32.const 0) (memory.grow (i32.const 4)))
            (call $output (i32.const 0) (i32.const 4))))
        "#,
    )
    .expect("grow fixture is valid wat");
    let mut host = MockHost::new();
    let output = execute(&module, b"", &mut host, &VmLimits::default()).expect("runs");
    // 1 -> 5 pages (within 16) returns the old size, 1.
    assert_eq!(output, vec![1, 0, 0, 0], "grow within the cap succeeds");
}

#[test]
fn validate_rejects_foreign_imports() {
    // Imports from a module other than `webc`.
    let module = wat::parse_str(
        r#"
        (module
          (import "env" "sneaky" (func))
          (memory (export "memory") 1))
        "#,
    )
    .expect("foreign-import fixture is valid wat");
    let err = validate_module(&module, &VmLimits::default()).expect_err("foreign import rejected");
    assert!(matches!(err, VmError::InvalidModule(_)), "got {err:?}");
}

#[test]
fn input_over_cap_is_rejected() {
    let module = counter_module();
    let limits = VmLimits {
        max_input_bytes: 4,
        ..VmLimits::default()
    };
    let mut host = MockHost::new();
    let err = execute(&module, b"too long", &mut host, &limits).expect_err("input too large");
    assert!(
        matches!(err, VmError::InputTooLarge { actual: 8, max: 4 }),
        "got {err:?}"
    );
}

#[test]
fn epoch_is_visible_to_guest() {
    // Guest reads epoch and outputs it as 8 little-endian bytes.
    let module = wat::parse_str(
        r#"
        (module
          (import "webc" "webc_epoch" (func $epoch (result i64)))
          (import "webc" "webc_output" (func $output (param i32 i32)))
          (memory (export "memory") 1)
          (func (export "webc_call")
            (i64.store (i32.const 0) (call $epoch))
            (call $output (i32.const 0) (i32.const 8))))
        "#,
    )
    .expect("epoch fixture is valid wat");

    let limits = VmLimits::default();
    let mut host = MockHost::new();
    host.epoch = 0x0102_0304_0506_0708;
    let output = execute(&module, b"", &mut host, &limits).expect("epoch run");
    assert_eq!(output, host.epoch.to_le_bytes().to_vec());
}

/// A genuine counter: `webc_get` the current u32 (0 if absent, i.e. the `-1`
/// return path), increment it, `webc_set` it back, and `webc_output` the new
/// value as little-endian bytes.
fn increment_counter_module() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
          (import "webc" "webc_get" (func $get (param i32 i32 i32 i32) (result i32)))
          (import "webc" "webc_set" (func $set (param i32 i32 i32 i32) (result i32)))
          (import "webc" "webc_output" (func $output (param i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 0)
            "\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11")
          (func (export "webc_call")
            (local $glen i32)
            (local $cur i32)
            (local.set $glen
              (call $get (i32.const 0) (i32.const 32) (i32.const 512) (i32.const 4)))
            (local.set $cur
              (if (result i32) (i32.ge_s (local.get $glen) (i32.const 0))
                (then (i32.load (i32.const 512)))
                (else (i32.const 0))))
            (i32.store (i32.const 256) (i32.add (local.get $cur) (i32.const 1)))
            (drop (call $set (i32.const 0) (i32.const 32) (i32.const 256) (i32.const 4)))
            (call $output (i32.const 256) (i32.const 4))))
        "#,
    )
    .expect("counter fixture is valid wat")
}

#[test]
fn counter_increments_across_invocations_with_persistent_state() {
    let module = increment_counter_module();
    let limits = VmLimits::default();
    let mut host = MockHost::new();

    for expected in 1u32..=3 {
        let output = execute(&module, b"", &mut host, &limits).expect("counter run");
        assert_eq!(
            output,
            expected.to_le_bytes().to_vec(),
            "invocation {expected} returns the incremented value"
        );
    }

    let stored = host.store.get(&FIXTURE_KEY).expect("counter persisted");
    assert_eq!(stored.as_slice(), 3u32.to_le_bytes().as_slice());
}

#[test]
fn webc_get_returns_negative_one_when_absent() {
    // Guest gets a never-written key and outputs the (negative) return code as
    // 4 little-endian bytes.
    let module = wat::parse_str(
        r#"
        (module
          (import "webc" "webc_get" (func $get (param i32 i32 i32 i32) (result i32)))
          (import "webc" "webc_output" (func $output (param i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 0)
            "\22\22\22\22\22\22\22\22\22\22\22\22\22\22\22\22\22\22\22\22\22\22\22\22\22\22\22\22\22\22\22\22")
          (func (export "webc_call")
            (i32.store (i32.const 64)
              (call $get (i32.const 0) (i32.const 32) (i32.const 128) (i32.const 32)))
            (call $output (i32.const 64) (i32.const 4))))
        "#,
    )
    .expect("absent-get fixture is valid wat");

    let limits = VmLimits::default();
    let mut host = MockHost::new();
    let output = execute(&module, b"", &mut host, &limits).expect("absent get run");
    assert_eq!(
        i32::from_le_bytes(output.try_into().expect("4 bytes")),
        -1,
        "absent key returns -1"
    );
}

#[test]
fn webc_get_returns_negative_two_when_buffer_too_small() {
    // Pre-populate a 32-byte value, then get it with an 8-byte output buffer.
    let module = wat::parse_str(
        r#"
        (module
          (import "webc" "webc_get" (func $get (param i32 i32 i32 i32) (result i32)))
          (import "webc" "webc_output" (func $output (param i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 0)
            "\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11")
          (func (export "webc_call")
            (i32.store (i32.const 64)
              (call $get (i32.const 0) (i32.const 32) (i32.const 128) (i32.const 8)))
            (call $output (i32.const 64) (i32.const 4))))
        "#,
    )
    .expect("small-buffer fixture is valid wat");

    let limits = VmLimits::default();
    let mut host = MockHost::new();
    host.store.insert(FIXTURE_KEY, vec![0xAB; 32]);
    let output = execute(&module, b"", &mut host, &limits).expect("small buffer run");
    assert_eq!(
        i32::from_le_bytes(output.try_into().expect("4 bytes")),
        -2,
        "too-small buffer returns -2"
    );
}

#[test]
fn compute_only_module_still_charges_gas_via_fuel_reconciliation() {
    // No host ops at all: a bounded loop, then return. Gas must still be > 0,
    // proving consumed fuel is reconciled into the gas meter.
    let module = wat::parse_str(
        r#"
        (module
          (memory (export "memory") 1)
          (func (export "webc_call")
            (local $i i32)
            (local.set $i (i32.const 1000))
            (block $done
              (loop $loop
                (br_if $done (i32.eqz (local.get $i)))
                (local.set $i (i32.sub (local.get $i) (i32.const 1)))
                (br $loop)))))
        "#,
    )
    .expect("loop fixture is valid wat");

    let limits = VmLimits::default();
    let mut host = MockHost::new();
    let output = execute(&module, b"", &mut host, &limits).expect("loop run");
    assert!(output.is_empty(), "no output submitted");
    assert!(host.gas_used > 0, "fuel reconciled into gas");
}
