//! Checkpoint-anchored finalized transaction and receipt inclusion proofs.
//!
//! Purpose: let a light client authenticate one V5 transaction and V1 receipt
//! without trusting the node that served them. Responsibilities: proof byte and
//! collection limits, checkpoint-floor enforcement, authority-transition and
//! target-certificate verification, indexed transaction/receipt membership,
//! exact cross-object binding, and fee reconciliation. Non-responsibilities:
//! checkpoint-source trust, HTTP/storage retrieval, execution replay, or state
//! mutation. Data flow: a separately accepted checkpoint anchors a bounded list
//! of epoch transitions; the resulting authority root certifies the target V4
//! header, whose two Merkle roots authenticate the requested transaction and
//! receipt. Security boundary: all proof fields are hostile and fail closed in
//! size/count, schema/domain, authority, certificate, Merkle, then receipt order.

use std::{fmt, marker::PhantomData};

use serde::{de::SeqAccess, de::Visitor, Deserialize, Deserializer, Serialize};
use webc_chain::{
    canonical::canonical_json_bytes, transaction_leaf_v1, verify_transaction_receipt_pair_v1,
    BlockHeaderV4, BlockPositionV1, ChainId, FinalityAuthoritySetV1, FinalityCertificate,
    ReceiptV1, TransactionId, TransactionV5, MAX_CONSENSUS_VOTES_PER_PROOF,
    MAX_FINALITY_AUTHORITIES_V1,
};
use webc_crypto::Hash256;

use crate::{
    checkpoint::{verify_authority_domain, verify_certified_header_v1},
    verify_authority_set_transition_v1, verify_indexed_merkle_proof, AuthoritySetTransitionV1,
    CheckpointErrorV1, IndexedMerkleProofV1, MerkleLeafIndex, ValidatedCheckpointV1,
    MAX_INDEXED_MERKLE_SIBLINGS,
};

/// Schema version carried by a finalized transaction proof.
pub const FINALIZED_TRANSACTION_PROOF_V1: u16 = 1;

/// Domain separating complete finalized-proof digests from component objects.
pub const FINALIZED_TRANSACTION_PROOF_V1_DOMAIN: &str = "WEBC_FINALIZED_TRANSACTION_PROOF_V1";

/// Absolute hostile-input byte cap for one finalized transaction proof.
pub const MAX_FINALIZED_TRANSACTION_PROOF_V1_JSON_BYTES: usize = 16 * 1024 * 1024;

/// Maximum authority transitions accepted between a checkpoint and target.
pub const MAX_AUTHORITY_TRANSITIONS_V1: usize = 64;

/// Transparent proof from an accepted checkpoint to one finalized transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedTransactionProofV1 {
    /// Must equal [`FINALIZED_TRANSACTION_PROOF_V1`].
    pub version: u16,
    /// Only the epoch changes required after the separately accepted checkpoint.
    #[serde(deserialize_with = "bounded_transitions::deserialize")]
    pub authority_transitions: Vec<AuthoritySetTransitionV1>,
    /// V4 header committing the transaction and receipt roots.
    pub target_header: BlockHeaderV4,
    /// Quorum certificate over the exact target header hash.
    pub target_certificate: FinalityCertificate,
    /// Authority set matching the target header's current authority root.
    pub target_authority_set: FinalityAuthoritySetV1,
    /// Complete signed transaction requested by the client.
    pub transaction: TransactionV5,
    /// Complete finalized receipt paired with `transaction`.
    pub receipt: ReceiptV1,
    /// Indexed membership path into `target_header.tx_root`.
    pub transaction_proof: IndexedMerkleProofV1,
    /// Indexed membership path into `target_header.receipt_root`.
    pub receipt_proof: IndexedMerkleProofV1,
}

impl FinalizedTransactionProofV1 {
    /// Decodes hostile JSON under the outer 16 MiB cap, then verifies the proof.
    pub fn decode_json(
        bytes: &[u8],
        checkpoint: &ValidatedCheckpointV1,
        requirements: &FinalizedTransactionProofRequirementsV1,
    ) -> Result<VerifiedFinalizedTransactionV1, FinalizedTransactionProofErrorV1> {
        if bytes.len() > MAX_FINALIZED_TRANSACTION_PROOF_V1_JSON_BYTES {
            return Err(FinalizedTransactionProofErrorV1::ProofTooLarge {
                actual: bytes.len(),
                maximum: MAX_FINALIZED_TRANSACTION_PROOF_V1_JSON_BYTES,
            });
        }
        let proof = serde_json::from_slice(bytes)
            .map_err(|_| FinalizedTransactionProofErrorV1::MalformedProof)?;
        verify_finalized_transaction_proof_v1(&proof, checkpoint, requirements)
    }

    /// Returns the canonical domain-separated digest of this transport object.
    pub fn digest(&self) -> Result<Hash256, FinalizedTransactionProofErrorV1> {
        #[derive(Serialize)]
        struct DigestPayload<'a> {
            domain: &'static str,
            proof: &'a FinalizedTransactionProofV1,
        }
        canonical_json_bytes(&DigestPayload {
            domain: FINALIZED_TRANSACTION_PROOF_V1_DOMAIN,
            proof: self,
        })
        .map(Hash256::digest)
        .map_err(|_| FinalizedTransactionProofErrorV1::CanonicalEncoding)
    }
}

/// Trusted request context that is intentionally absent from served proof bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedTransactionProofRequirementsV1 {
    /// Expected genesis-fixed network replay domain.
    pub chain_id: ChainId,
    /// Transaction identity requested by the caller, not chosen by the server.
    pub transaction_id: TransactionId,
    /// Genesis-fixed block count per epoch used to validate transition boundaries.
    pub blocks_per_epoch: u64,
}

impl FinalizedTransactionProofRequirementsV1 {
    /// Constructs explicit finalized-proof verification requirements.
    pub const fn new(
        chain_id: ChainId,
        transaction_id: TransactionId,
        blocks_per_epoch: u64,
    ) -> Self {
        Self {
            chain_id,
            transaction_id,
            blocks_per_epoch,
        }
    }
}

/// Authenticated result returned after every proof layer succeeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedFinalizedTransactionV1 {
    /// Caller-requested identity authenticated by the transaction Merkle root.
    pub transaction_id: TransactionId,
    /// Exact finalized block position shared by both Merkle leaves.
    pub position: BlockPositionV1,
    /// Hash authenticated by the target finality certificate.
    pub block_hash: Hash256,
    /// Separately accepted weak-subjectivity anchor used for verification.
    pub checkpoint_digest: Hash256,
}

/// Verifies a complete finalized proof against a separately accepted checkpoint.
///
/// The operation is pure. It never retrieves missing data, reads a local clock,
/// or mutates state. The request supplies the expected transaction ID so a
/// malicious server cannot return a valid proof for a different transaction.
pub fn verify_finalized_transaction_proof_v1(
    proof: &FinalizedTransactionProofV1,
    checkpoint: &ValidatedCheckpointV1,
    requirements: &FinalizedTransactionProofRequirementsV1,
) -> Result<VerifiedFinalizedTransactionV1, FinalizedTransactionProofErrorV1> {
    validate_proof_bounds(proof)?;
    let canonical = canonical_json_bytes(proof)
        .map_err(|_| FinalizedTransactionProofErrorV1::CanonicalEncoding)?;
    if canonical.len() > MAX_FINALIZED_TRANSACTION_PROOF_V1_JSON_BYTES {
        return Err(FinalizedTransactionProofErrorV1::ProofTooLarge {
            actual: canonical.len(),
            maximum: MAX_FINALIZED_TRANSACTION_PROOF_V1_JSON_BYTES,
        });
    }
    if proof.version != FINALIZED_TRANSACTION_PROOF_V1 {
        return Err(FinalizedTransactionProofErrorV1::UnsupportedProofVersion {
            actual: proof.version,
        });
    }
    proof
        .target_header
        .validate()
        .map_err(|_| FinalizedTransactionProofErrorV1::InvalidTargetHeader)?;
    if requirements.chain_id != checkpoint.header().chain_id
        || proof.target_header.chain_id != requirements.chain_id
    {
        return Err(FinalizedTransactionProofErrorV1::WrongChain);
    }
    if proof.target_header.height < checkpoint.header().height {
        return Err(FinalizedTransactionProofErrorV1::TargetBeforeCheckpoint);
    }
    if proof.receipt.position.height != proof.target_header.height {
        return Err(FinalizedTransactionProofErrorV1::PositionHeightMismatch);
    }

    verify_target_authority(proof, checkpoint, requirements.blocks_per_epoch)?;

    proof
        .transaction
        .verify_for_chain(&requirements.chain_id)
        .map_err(|_| FinalizedTransactionProofErrorV1::InvalidTransaction)?;
    if !proof
        .transaction
        .validity
        .contains(proof.target_header.height)
    {
        return Err(FinalizedTransactionProofErrorV1::TransactionOutsideValidity);
    }
    let transaction_id = proof
        .transaction
        .transaction_id()
        .map_err(|_| FinalizedTransactionProofErrorV1::InvalidTransaction)?;
    if transaction_id != requirements.transaction_id {
        return Err(FinalizedTransactionProofErrorV1::UnexpectedTransactionId);
    }
    if proof.receipt.transaction_id != transaction_id {
        return Err(FinalizedTransactionProofErrorV1::ReceiptTransactionMismatch);
    }

    let expected_index = u64::from(proof.receipt.position.transaction_index.get());
    if proof.transaction_proof.leaf_index != MerkleLeafIndex::new(expected_index)
        || proof.receipt_proof.leaf_index != MerkleLeafIndex::new(expected_index)
        || proof.transaction_proof.leaf_count != proof.receipt_proof.leaf_count
    {
        return Err(FinalizedTransactionProofErrorV1::MerklePositionMismatch);
    }
    let transaction_leaf = transaction_leaf_v1(proof.receipt.position, transaction_id)
        .map_err(|_| FinalizedTransactionProofErrorV1::InvalidTransactionLeaf)?;
    if proof.transaction_proof.leaf != transaction_leaf {
        return Err(FinalizedTransactionProofErrorV1::InvalidTransactionLeaf);
    }
    verify_indexed_merkle_proof(proof.target_header.tx_root, &proof.transaction_proof)
        .map_err(|_| FinalizedTransactionProofErrorV1::InvalidTransactionProof)?;

    let receipt_leaf = proof
        .receipt
        .leaf()
        .map_err(|_| FinalizedTransactionProofErrorV1::InvalidReceipt)?;
    if proof.receipt_proof.leaf != receipt_leaf {
        return Err(FinalizedTransactionProofErrorV1::InvalidReceiptLeaf);
    }
    verify_indexed_merkle_proof(proof.target_header.receipt_root, &proof.receipt_proof)
        .map_err(|_| FinalizedTransactionProofErrorV1::InvalidReceiptProof)?;
    verify_transaction_receipt_pair_v1(&proof.transaction, &proof.receipt)
        .map_err(|_| FinalizedTransactionProofErrorV1::ReceiptTransactionMismatch)?;

    let block_hash = proof
        .target_header
        .hash()
        .map_err(|_| FinalizedTransactionProofErrorV1::InvalidTargetHeader)?;
    Ok(VerifiedFinalizedTransactionV1 {
        transaction_id,
        position: proof.receipt.position,
        block_hash,
        checkpoint_digest: checkpoint.digest(),
    })
}

fn verify_target_authority(
    proof: &FinalizedTransactionProofV1,
    checkpoint: &ValidatedCheckpointV1,
    blocks_per_epoch: u64,
) -> Result<(), FinalizedTransactionProofErrorV1> {
    if proof.target_header.height == checkpoint.header().height {
        if !proof.authority_transitions.is_empty() || proof.target_header != *checkpoint.header() {
            return Err(FinalizedTransactionProofErrorV1::CheckpointTargetMismatch);
        }
        verify_authority_domain(
            &proof.target_authority_set,
            &proof.target_header.chain_id,
            proof.target_header.protocol_version,
            proof.target_header.epoch,
        )
        .map_err(FinalizedTransactionProofErrorV1::Checkpoint)?;
        if proof
            .target_authority_set
            .commitment()
            .map_err(|_| FinalizedTransactionProofErrorV1::InvalidTargetAuthoritySet)?
            != proof.target_header.finality_authority_set_root
        {
            return Err(FinalizedTransactionProofErrorV1::TargetAuthorityMismatch);
        }
        return verify_certified_header_v1(
            &proof.target_header,
            &proof.target_certificate,
            &proof.target_authority_set,
        )
        .map_err(FinalizedTransactionProofErrorV1::Checkpoint);
    }

    let mut anchor = checkpoint
        .next_anchor(blocks_per_epoch)
        .map_err(FinalizedTransactionProofErrorV1::Checkpoint)?;
    for transition in &proof.authority_transitions {
        if transition.header.height >= proof.target_header.height {
            return Err(FinalizedTransactionProofErrorV1::TransitionAtOrAfterTarget);
        }
        anchor = verify_authority_set_transition_v1(transition, &anchor)
            .map_err(FinalizedTransactionProofErrorV1::Checkpoint)?;
    }
    if proof.target_header.height <= anchor.minimum_height()
        || proof.target_header.epoch != anchor.epoch()
        || proof.target_header.finality_authority_set_root != anchor.authority_root()
    {
        return Err(FinalizedTransactionProofErrorV1::TargetAuthorityMismatch);
    }
    verify_authority_domain(
        &proof.target_authority_set,
        anchor.chain_id(),
        proof.target_header.protocol_version,
        anchor.epoch(),
    )
    .map_err(FinalizedTransactionProofErrorV1::Checkpoint)?;
    if proof
        .target_authority_set
        .commitment()
        .map_err(|_| FinalizedTransactionProofErrorV1::InvalidTargetAuthoritySet)?
        != anchor.authority_root()
    {
        return Err(FinalizedTransactionProofErrorV1::TargetAuthorityMismatch);
    }
    verify_certified_header_v1(
        &proof.target_header,
        &proof.target_certificate,
        &proof.target_authority_set,
    )
    .map_err(FinalizedTransactionProofErrorV1::Checkpoint)
}

fn validate_proof_bounds(
    proof: &FinalizedTransactionProofV1,
) -> Result<(), FinalizedTransactionProofErrorV1> {
    if proof.authority_transitions.len() > MAX_AUTHORITY_TRANSITIONS_V1 {
        return Err(FinalizedTransactionProofErrorV1::TooManyTransitions {
            actual: proof.authority_transitions.len(),
            maximum: MAX_AUTHORITY_TRANSITIONS_V1,
        });
    }
    if proof.target_authority_set.authorities.len() > MAX_FINALITY_AUTHORITIES_V1 {
        return Err(FinalizedTransactionProofErrorV1::TooManyAuthorities);
    }
    if proof.target_certificate.precommits.len() > MAX_CONSENSUS_VOTES_PER_PROOF {
        return Err(FinalizedTransactionProofErrorV1::TooManyCertificateVotes);
    }
    for transition in &proof.authority_transitions {
        if transition.outgoing_authority_set.authorities.len() > MAX_FINALITY_AUTHORITIES_V1
            || transition.incoming_authority_set.authorities.len() > MAX_FINALITY_AUTHORITIES_V1
        {
            return Err(FinalizedTransactionProofErrorV1::TooManyAuthorities);
        }
        if transition.certificate.precommits.len() > MAX_CONSENSUS_VOTES_PER_PROOF {
            return Err(FinalizedTransactionProofErrorV1::TooManyCertificateVotes);
        }
    }
    for siblings in [
        &proof.transaction_proof.siblings,
        &proof.receipt_proof.siblings,
    ] {
        if siblings.len() > MAX_INDEXED_MERKLE_SIBLINGS {
            return Err(FinalizedTransactionProofErrorV1::TooManyMerkleSiblings);
        }
    }
    Ok(())
}

mod bounded_transitions {
    use super::*;

    pub(super) fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Vec<AuthoritySetTransitionV1>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TransitionVisitor(PhantomData<AuthoritySetTransitionV1>);

        impl<'de> Visitor<'de> for TransitionVisitor {
            type Value = Vec<AuthoritySetTransitionV1>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("at most 64 ordered authority transitions")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if sequence
                    .size_hint()
                    .is_some_and(|hint| hint > MAX_AUTHORITY_TRANSITIONS_V1)
                {
                    return Err(serde::de::Error::custom(
                        "finalized proof has too many authority transitions",
                    ));
                }
                let mut transitions = Vec::with_capacity(
                    sequence
                        .size_hint()
                        .unwrap_or(0)
                        .min(MAX_AUTHORITY_TRANSITIONS_V1),
                );
                while let Some(transition) = sequence.next_element()? {
                    if transitions.len() == MAX_AUTHORITY_TRANSITIONS_V1 {
                        return Err(serde::de::Error::custom(
                            "finalized proof has too many authority transitions",
                        ));
                    }
                    transitions.push(transition);
                }
                Ok(transitions)
            }
        }

        deserializer.deserialize_seq(TransitionVisitor(PhantomData))
    }
}

/// Typed rejection from finalized transaction proof verification.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FinalizedTransactionProofErrorV1 {
    /// Proof JSON is not the strict outer V1 schema.
    #[error("finalized transaction proof JSON is malformed")]
    MalformedProof,
    /// Proof bytes exceed the absolute hostile-input cap.
    #[error("finalized proof size {actual} exceeds maximum {maximum}")]
    ProofTooLarge {
        /// Observed byte length.
        actual: usize,
        /// Absolute accepted byte length.
        maximum: usize,
    },
    /// Authority transition count exceeds the absolute cap.
    #[error("finalized proof has {actual} transitions; maximum is {maximum}")]
    TooManyTransitions {
        /// Observed transition count.
        actual: usize,
        /// Absolute accepted transition count.
        maximum: usize,
    },
    /// An authority set exceeds its entry cap.
    #[error("finalized proof authority set exceeds its entry limit")]
    TooManyAuthorities,
    /// A certificate exceeds its vote cap.
    #[error("finalized proof certificate exceeds its vote limit")]
    TooManyCertificateVotes,
    /// A Merkle path exceeds its sibling cap.
    #[error("finalized proof Merkle path exceeds its sibling limit")]
    TooManyMerkleSiblings,
    /// Proof schema version is unknown.
    #[error("unsupported finalized transaction proof version {actual}")]
    UnsupportedProofVersion {
        /// Rejected version.
        actual: u16,
    },
    /// Target V4 header fails structural validation or hashing.
    #[error("finalized proof target header is invalid")]
    InvalidTargetHeader,
    /// Checkpoint, requirements, and target do not share one chain.
    #[error("finalized proof belongs to another chain")]
    WrongChain,
    /// Target predates the separately accepted checkpoint floor.
    #[error("finalized proof target predates the checkpoint")]
    TargetBeforeCheckpoint,
    /// Same-height proof does not reproduce the checkpoint header exactly.
    #[error("same-height target does not match the checkpoint")]
    CheckpointTargetMismatch,
    /// A transition is not strictly before the target block.
    #[error("authority transition is at or after the target")]
    TransitionAtOrAfterTarget,
    /// Target authority root/epoch does not follow the checkpoint transitions.
    #[error("target authority does not follow the checkpoint")]
    TargetAuthorityMismatch,
    /// Target authority set fails shape or commitment validation.
    #[error("target authority set is invalid")]
    InvalidTargetAuthoritySet,
    /// Nested checkpoint/certificate/transition verification failed.
    #[error("checkpoint or authority proof failed: {0}")]
    Checkpoint(CheckpointErrorV1),
    /// Receipt height differs from the target header height.
    #[error("receipt position height does not match target header")]
    PositionHeightMismatch,
    /// Signed transaction structure or signature is invalid.
    #[error("finalized proof transaction is invalid")]
    InvalidTransaction,
    /// Transaction validity range excludes the target height.
    #[error("finalized transaction is outside its signed validity range")]
    TransactionOutsideValidity,
    /// Server returned a proof for a transaction other than the requested ID.
    #[error("finalized proof transaction ID does not match the request")]
    UnexpectedTransactionId,
    /// Transaction leaf cannot be constructed or differs from the proof leaf.
    #[error("finalized proof transaction leaf is invalid")]
    InvalidTransactionLeaf,
    /// Transaction Merkle path does not match the target root.
    #[error("finalized proof transaction path is invalid")]
    InvalidTransactionProof,
    /// Receipt schema or fee arithmetic is invalid.
    #[error("finalized proof receipt is invalid")]
    InvalidReceipt,
    /// Receipt leaf differs from the proof leaf.
    #[error("finalized proof receipt leaf is invalid")]
    InvalidReceiptLeaf,
    /// Receipt Merkle path does not match the target root.
    #[error("finalized proof receipt path is invalid")]
    InvalidReceiptProof,
    /// Transaction and receipt do not describe the same execution.
    #[error("finalized proof transaction and receipt do not match")]
    ReceiptTransactionMismatch,
    /// Transaction and receipt paths disagree with their shared block position.
    #[error("finalized proof Merkle positions or counts do not match")]
    MerklePositionMismatch,
    /// Canonical bytes could not be produced.
    #[error("finalized transaction proof cannot be canonically encoded")]
    CanonicalEncoding,
}
