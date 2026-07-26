//! Pure transparent-proof schemas and verification for WEBC.
//!
//! Purpose: provide bounded, versioned proof types whose validation is shared
//! by full nodes, light clients, and later browser-compatible implementations.
//! Responsibilities: proof structure, hostile-input limits, deterministic
//! builders, and pure verification. Non-responsibilities: network retrieval,
//! filesystem/database access, consensus mutation, checkpoint-source policy,
//! and succinct-proof backends. Data flow: callers supply already-domain-
//! separated leaf digests and an expected root; this crate validates tree shape
//! before hashing and returns a typed result without mutation. Security
//! boundary: every proof is hostile, so count/index/depth bounds are checked
//! before path work and no caller-provided direction bit is trusted.

#![forbid(unsafe_code)]

mod checkpoint;
mod finalized_transaction;
mod indexed_merkle;

pub use checkpoint::{
    validate_checkpoint_v1, verify_authority_set_transition_v1, AuthoritySetTransitionV1,
    AuthorityTransitionAnchorV1, CheckpointErrorV1, CheckpointRequirementsV1, CheckpointV1,
    ValidatedCheckpointV1, AUTHORITY_SET_TRANSITION_V1, AUTHORITY_SET_TRANSITION_V1_DOMAIN,
    CHECKPOINT_V1, CHECKPOINT_V1_DOMAIN, MAX_AUTHORITY_SET_TRANSITION_V1_JSON_BYTES,
    MAX_CHECKPOINT_V1_JSON_BYTES,
};
pub use finalized_transaction::{
    verify_finalized_transaction_proof_v1, FinalizedTransactionProofErrorV1,
    FinalizedTransactionProofRequirementsV1, FinalizedTransactionProofV1,
    VerifiedFinalizedTransactionV1, FINALIZED_TRANSACTION_PROOF_V1,
    FINALIZED_TRANSACTION_PROOF_V1_DOMAIN, MAX_AUTHORITY_TRANSITIONS_V1,
    MAX_FINALIZED_TRANSACTION_PROOF_V1_JSON_BYTES,
};
pub use indexed_merkle::{
    build_indexed_merkle_proof, verify_indexed_merkle_proof, IndexedMerkleProofError,
    IndexedMerkleProofV1, MerkleLeafCount, MerkleLeafIndex, MAX_INDEXED_MERKLE_SIBLINGS,
};
