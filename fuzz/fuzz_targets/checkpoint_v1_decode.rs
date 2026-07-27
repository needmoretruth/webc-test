//! Fuzz the bounded protocol-2 checkpoint JSON boundary.
//!
//! Purpose: exercise hostile checkpoint bytes through exact schema, header,
//! authority-set, certificate, chain, height, and epoch validation.
//! Non-responsibilities: choosing source trust, fetching a checkpoint, or
//! mutating chain state. Data flow is arbitrary fuzzer bytes into the production
//! decoder under fixed devnet acceptance requirements. Security boundary: the
//! 8 MiB outer limit and nested authority/vote limits must reject before
//! unbounded work, and no malformed input may panic or hang.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use webc_proof::{CheckpointRequirementsV1, CheckpointV1};

/// Builds one valid shared-fixture seed and its exact acceptance floor once.
fn context() -> &'static (CheckpointRequirementsV1, Vec<u8>) {
    static CONTEXT: OnceLock<(CheckpointRequirementsV1, Vec<u8>)> = OnceLock::new();
    CONTEXT.get_or_init(|| {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../fixtures/finalized-transaction-proof-v1.json"
        ))
        .expect("committed finalized-proof fixture is valid JSON");
        let checkpoint_value = fixture
            .get("checkpoint_candidate")
            .expect("fixture carries a checkpoint")
            .clone();
        let checkpoint: CheckpointV1 =
            serde_json::from_value(checkpoint_value.clone()).expect("fixture checkpoint decodes");
        let requirements = CheckpointRequirementsV1::new(
            checkpoint.header.chain_id.clone(),
            checkpoint.header.height,
            checkpoint.header.epoch,
        );
        let bytes = serde_json::to_vec(&checkpoint_value).expect("fixture checkpoint serializes");
        (requirements, bytes)
    })
}

fuzz_target!(|data: &[u8]| {
    let (requirements, valid_checkpoint_bytes) = context();
    let candidate = if data.is_empty() {
        valid_checkpoint_bytes.as_slice()
    } else {
        data
    };
    let _ = CheckpointV1::decode_json(candidate, requirements);
});
