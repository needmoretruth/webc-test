//! Fuzz the complete checkpoint-relative finalized-proof JSON boundary.
//!
//! Purpose: drive arbitrary bytes through bounded transition, certificate,
//! authority, V5 transaction, receipt, and indexed-Merkle decoding followed by
//! full cryptographic verification. Non-responsibilities: selecting checkpoint
//! source trust, HTTP retrieval, or executing a block. Data flow uses the exact
//! shared Rust/browser checkpoint fixture as a fixed accepted anchor, while the
//! proof bytes remain entirely fuzzer-controlled. Security boundary: outer and
//! nested collection limits must precede attacker-sized work; no input may
//! panic, hang, or mutate the fixed validation context.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use webc_proof::{
    validate_checkpoint_v1, CheckpointRequirementsV1, CheckpointV1,
    FinalizedTransactionProofRequirementsV1, FinalizedTransactionProofV1, ValidatedCheckpointV1,
};

/// Builds the exact cross-language anchor and request context once per process.
fn context() -> &'static (
    ValidatedCheckpointV1,
    FinalizedTransactionProofRequirementsV1,
    Vec<u8>,
) {
    static CONTEXT: OnceLock<(
        ValidatedCheckpointV1,
        FinalizedTransactionProofRequirementsV1,
        Vec<u8>,
    )> = OnceLock::new();
    CONTEXT.get_or_init(|| {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../fixtures/finalized-transaction-proof-v1.json"
        ))
        .expect("committed finalized-proof fixture is valid JSON");
        let checkpoint: CheckpointV1 = serde_json::from_value(
            fixture
                .get("checkpoint_candidate")
                .expect("fixture carries a checkpoint")
                .clone(),
        )
        .expect("fixture checkpoint decodes");
        let checkpoint_requirements = CheckpointRequirementsV1::new(
            checkpoint.header.chain_id.clone(),
            checkpoint.header.height,
            checkpoint.header.epoch,
        );
        let checkpoint = validate_checkpoint_v1(checkpoint, &checkpoint_requirements)
            .expect("fixture checkpoint validates");
        let proof_value = fixture
            .get("proof")
            .expect("fixture carries a proof")
            .clone();
        let valid_proof_bytes = serde_json::to_vec(&proof_value).expect("fixture proof serializes");
        let proof: FinalizedTransactionProofV1 =
            serde_json::from_value(proof_value).expect("fixture proof decodes");
        let transaction_id = proof
            .transaction
            .transaction_id()
            .expect("fixture transaction has an identity");
        let blocks_per_epoch = fixture
            .get("requirements")
            .and_then(|requirements| requirements.get("blocks_per_epoch"))
            .and_then(serde_json::Value::as_str)
            .expect("fixture carries blocks-per-epoch")
            .parse()
            .expect("fixture blocks-per-epoch is a u64");
        let requirements = FinalizedTransactionProofRequirementsV1::new(
            checkpoint.header().chain_id.clone(),
            transaction_id,
            blocks_per_epoch,
        );
        (checkpoint, requirements, valid_proof_bytes)
    })
}

fuzz_target!(|data: &[u8]| {
    let (checkpoint, requirements, valid_proof_bytes) = context();
    // libFuzzer always explores the empty input. Route that one case through
    // the exact valid cross-language proof so smoke runs cover the deepest
    // success path even before a persistent mutation corpus has accumulated.
    let candidate = if data.is_empty() {
        valid_proof_bytes.as_slice()
    } else {
        data
    };
    let _ = FinalizedTransactionProofV1::decode_json(candidate, checkpoint, requirements);
});
