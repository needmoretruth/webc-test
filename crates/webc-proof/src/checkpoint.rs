//! Weak-subjectivity checkpoints and protocol-2 authority-set transitions.
//!
//! Purpose: authenticate a recent V4 header and advance its committed finality
//! authority root across epoch boundaries. Responsibilities: hostile-input
//! bounds, schema/chain/floor checks, authority commitments, exact certificate
//! binding, transition ordering, and domain-separated checkpoint digests.
//! Non-responsibilities: selecting checkpoint sources, network retrieval,
//! storage, fork choice, or mutating consensus state. Data flow: an operator or
//! source policy supplies checkpoint bytes; validation yields an immutable
//! digest and anchor; each transition consumes one anchor and returns the next.
//! Security boundary: all decoded values are hostile. Collection and byte caps
//! are checked before signatures, the local clock is never read, and only an
//! outgoing quorum may authorize the next epoch's authority commitment.

use serde::{Deserialize, Serialize};
use webc_chain::{
    canonical::canonical_json_bytes, BlockHeaderV4, BlockHeight, ChainId, Epoch,
    FinalityAuthoritySetV1, FinalityCertificate, ProtocolVersion, MAX_CONSENSUS_VOTES_PER_PROOF,
    MAX_FINALITY_AUTHORITIES_V1, TRANSACTION_V5_PROTOCOL_VERSION,
};
use webc_crypto::Hash256;

/// Schema version carried by a weak-subjectivity checkpoint.
pub const CHECKPOINT_V1: u16 = 1;

/// Domain separating checkpoint digests from headers and authority sets.
pub const CHECKPOINT_V1_DOMAIN: &str = "WEBC_CHECKPOINT_V1";

/// Schema version carried by an authority-set transition.
pub const AUTHORITY_SET_TRANSITION_V1: u16 = 1;

/// Domain separating authority-transition digests from their component header.
pub const AUTHORITY_SET_TRANSITION_V1_DOMAIN: &str = "WEBC_AUTHORITY_SET_TRANSITION_V1";

/// Absolute hostile-input byte cap for one checkpoint.
pub const MAX_CHECKPOINT_V1_JSON_BYTES: usize = 8 * 1024 * 1024;

/// Absolute hostile-input byte cap for one standalone authority transition.
pub const MAX_AUTHORITY_SET_TRANSITION_V1_JSON_BYTES: usize = 8 * 1024 * 1024;

/// A recent finalized V4 header anchored by its outgoing authority set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointV1 {
    /// Must equal [`CHECKPOINT_V1`].
    pub version: u16,
    /// Finalized protocol-2 header chosen as the weak-subjectivity floor.
    pub header: BlockHeaderV4,
    /// Quorum certificate over the exact `header` hash.
    pub certificate: FinalityCertificate,
    /// Outgoing authority set committed by `header` and signing `certificate`.
    pub authority_set: FinalityAuthoritySetV1,
}

impl CheckpointV1 {
    /// Decodes hostile JSON under the outer byte cap, then fully validates it.
    pub fn decode_json(
        bytes: &[u8],
        requirements: &CheckpointRequirementsV1,
    ) -> Result<ValidatedCheckpointV1, CheckpointErrorV1> {
        if bytes.len() > MAX_CHECKPOINT_V1_JSON_BYTES {
            return Err(CheckpointErrorV1::CheckpointTooLarge {
                actual: bytes.len(),
                maximum: MAX_CHECKPOINT_V1_JSON_BYTES,
            });
        }
        let checkpoint =
            serde_json::from_slice(bytes).map_err(|_| CheckpointErrorV1::MalformedCheckpoint)?;
        validate_checkpoint_v1(checkpoint, requirements)
    }
}

/// Local, deterministic acceptance floor for a checkpoint candidate.
///
/// Height and epoch are explicit operator/network configuration. Validation
/// never derives freshness from wall-clock time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointRequirementsV1 {
    /// Expected genesis-fixed network replay domain.
    pub chain_id: ChainId,
    /// Lowest acceptable finalized height, inclusive.
    pub minimum_height: BlockHeight,
    /// Lowest acceptable authority epoch, inclusive.
    pub minimum_epoch: Epoch,
}

impl CheckpointRequirementsV1 {
    /// Constructs an explicit checkpoint validation policy.
    pub const fn new(chain_id: ChainId, minimum_height: BlockHeight, minimum_epoch: Epoch) -> Self {
        Self {
            chain_id,
            minimum_height,
            minimum_epoch,
        }
    }
}

/// A checkpoint whose bytes, authority commitment, and certificate are valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedCheckpointV1 {
    /// Fully validated checkpoint value.
    pub checkpoint: CheckpointV1,
    /// Domain-separated canonical digest used by source agreement policies.
    pub digest: Hash256,
}

impl ValidatedCheckpointV1 {
    /// Returns the authority root and epoch that may certify the next height.
    ///
    /// An epoch-boundary checkpoint commits the incoming set by root but does
    /// not need to carry it: the next target or transition supplies the set and
    /// proves that its commitment matches this anchor.
    pub fn next_anchor(
        &self,
        blocks_per_epoch: u64,
    ) -> Result<AuthorityTransitionAnchorV1, CheckpointErrorV1> {
        let header = &self.checkpoint.header;
        let next_epoch =
            if header.next_finality_authority_set_root == header.finality_authority_set_root {
                header.epoch
            } else {
                header
                    .epoch
                    .checked_next()
                    .ok_or(CheckpointErrorV1::EpochExhausted)?
            };
        Ok(AuthorityTransitionAnchorV1::new(
            header.chain_id.clone(),
            header.next_finality_authority_set_root,
            next_epoch,
            header.height,
            blocks_per_epoch,
        ))
    }
}

/// A certified epoch-boundary header and the outgoing/incoming authority sets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySetTransitionV1 {
    /// Must equal [`AUTHORITY_SET_TRANSITION_V1`].
    pub version: u16,
    /// Epoch-boundary V4 header signed by the outgoing set.
    pub header: BlockHeaderV4,
    /// Certificate over the exact transition header.
    pub certificate: FinalityCertificate,
    /// Set whose root is `header.finality_authority_set_root`.
    pub outgoing_authority_set: FinalityAuthoritySetV1,
    /// Set whose root is `header.next_finality_authority_set_root`.
    pub incoming_authority_set: FinalityAuthoritySetV1,
}

impl AuthoritySetTransitionV1 {
    /// Decodes hostile JSON under the standalone transition byte cap and
    /// advances `anchor` only after complete validation.
    pub fn decode_json(
        bytes: &[u8],
        anchor: &AuthorityTransitionAnchorV1,
    ) -> Result<AuthorityTransitionAnchorV1, CheckpointErrorV1> {
        if bytes.len() > MAX_AUTHORITY_SET_TRANSITION_V1_JSON_BYTES {
            return Err(CheckpointErrorV1::TransitionTooLarge {
                actual: bytes.len(),
                maximum: MAX_AUTHORITY_SET_TRANSITION_V1_JSON_BYTES,
            });
        }
        let transition =
            serde_json::from_slice(bytes).map_err(|_| CheckpointErrorV1::MalformedTransition)?;
        verify_authority_set_transition_v1(&transition, anchor)
    }

    /// Returns the canonical domain-separated transition digest.
    pub fn digest(&self) -> Result<Hash256, CheckpointErrorV1> {
        #[derive(Serialize)]
        struct DigestPayload<'a> {
            domain: &'static str,
            transition: &'a AuthoritySetTransitionV1,
        }
        canonical_json_bytes(&DigestPayload {
            domain: AUTHORITY_SET_TRANSITION_V1_DOMAIN,
            transition: self,
        })
        .map(Hash256::digest)
        .map_err(|_| CheckpointErrorV1::CanonicalEncoding)
    }
}

/// Trusted root/epoch position consumed and advanced by transition verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityTransitionAnchorV1 {
    chain_id: ChainId,
    authority_root: Hash256,
    epoch: Epoch,
    minimum_height: BlockHeight,
    blocks_per_epoch: u64,
}

impl AuthorityTransitionAnchorV1 {
    /// Constructs an anchor from validated chain configuration and history.
    pub const fn new(
        chain_id: ChainId,
        authority_root: Hash256,
        epoch: Epoch,
        minimum_height: BlockHeight,
        blocks_per_epoch: u64,
    ) -> Self {
        Self {
            chain_id,
            authority_root,
            epoch,
            minimum_height,
            blocks_per_epoch,
        }
    }

    /// Returns the expected network replay domain.
    pub const fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the authority commitment trusted for the next certificate.
    pub const fn authority_root(&self) -> Hash256 {
        self.authority_root
    }

    /// Returns the authority epoch trusted for the next certificate.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the greatest already authenticated transition/header height.
    pub const fn minimum_height(&self) -> BlockHeight {
        self.minimum_height
    }

    /// Returns the configured number of finalized blocks per epoch.
    pub const fn blocks_per_epoch(&self) -> u64 {
        self.blocks_per_epoch
    }
}

/// Validates a checkpoint and returns its immutable agreement digest.
pub fn validate_checkpoint_v1(
    checkpoint: CheckpointV1,
    requirements: &CheckpointRequirementsV1,
) -> Result<ValidatedCheckpointV1, CheckpointErrorV1> {
    validate_collection_bounds(&checkpoint.authority_set, &checkpoint.certificate)?;
    let canonical =
        canonical_json_bytes(&checkpoint).map_err(|_| CheckpointErrorV1::CanonicalEncoding)?;
    if canonical.len() > MAX_CHECKPOINT_V1_JSON_BYTES {
        return Err(CheckpointErrorV1::CheckpointTooLarge {
            actual: canonical.len(),
            maximum: MAX_CHECKPOINT_V1_JSON_BYTES,
        });
    }
    if checkpoint.version != CHECKPOINT_V1 {
        return Err(CheckpointErrorV1::UnsupportedCheckpointVersion {
            actual: checkpoint.version,
        });
    }
    checkpoint
        .header
        .validate()
        .map_err(|_| CheckpointErrorV1::InvalidHeader)?;
    if checkpoint.header.chain_id != requirements.chain_id {
        return Err(CheckpointErrorV1::WrongChain);
    }
    if checkpoint.header.height < requirements.minimum_height {
        return Err(CheckpointErrorV1::CheckpointBelowHeightFloor);
    }
    if checkpoint.header.epoch < requirements.minimum_epoch {
        return Err(CheckpointErrorV1::CheckpointBelowEpochFloor);
    }
    verify_authority_domain(
        &checkpoint.authority_set,
        &checkpoint.header.chain_id,
        checkpoint.header.protocol_version,
        checkpoint.header.epoch,
    )?;
    if checkpoint
        .authority_set
        .commitment()
        .map_err(|_| CheckpointErrorV1::InvalidAuthoritySet)?
        != checkpoint.header.finality_authority_set_root
    {
        return Err(CheckpointErrorV1::AuthorityCommitmentMismatch);
    }
    verify_certified_header_v1(
        &checkpoint.header,
        &checkpoint.certificate,
        &checkpoint.authority_set,
    )?;

    #[derive(Serialize)]
    struct DigestPayload<'a> {
        domain: &'static str,
        checkpoint: &'a CheckpointV1,
    }
    let digest = canonical_json_bytes(&DigestPayload {
        domain: CHECKPOINT_V1_DOMAIN,
        checkpoint: &checkpoint,
    })
    .map(Hash256::digest)
    .map_err(|_| CheckpointErrorV1::CanonicalEncoding)?;
    Ok(ValidatedCheckpointV1 { checkpoint, digest })
}

/// Verifies one certified epoch transition and returns the next trusted anchor.
pub fn verify_authority_set_transition_v1(
    transition: &AuthoritySetTransitionV1,
    anchor: &AuthorityTransitionAnchorV1,
) -> Result<AuthorityTransitionAnchorV1, CheckpointErrorV1> {
    validate_collection_bounds(&transition.outgoing_authority_set, &transition.certificate)?;
    if transition.incoming_authority_set.authorities.len() > MAX_FINALITY_AUTHORITIES_V1 {
        return Err(CheckpointErrorV1::TooManyAuthorities);
    }
    let canonical =
        canonical_json_bytes(transition).map_err(|_| CheckpointErrorV1::CanonicalEncoding)?;
    if canonical.len() > MAX_AUTHORITY_SET_TRANSITION_V1_JSON_BYTES {
        return Err(CheckpointErrorV1::TransitionTooLarge {
            actual: canonical.len(),
            maximum: MAX_AUTHORITY_SET_TRANSITION_V1_JSON_BYTES,
        });
    }
    if transition.version != AUTHORITY_SET_TRANSITION_V1 {
        return Err(CheckpointErrorV1::UnsupportedTransitionVersion {
            actual: transition.version,
        });
    }
    transition
        .header
        .validate()
        .map_err(|_| CheckpointErrorV1::InvalidHeader)?;
    if transition.header.chain_id != anchor.chain_id {
        return Err(CheckpointErrorV1::WrongChain);
    }
    if transition.header.height <= anchor.minimum_height {
        return Err(CheckpointErrorV1::TransitionHeightNotIncreasing);
    }
    if anchor.blocks_per_epoch == 0
        || !transition
            .header
            .height
            .get()
            .is_multiple_of(anchor.blocks_per_epoch)
    {
        return Err(CheckpointErrorV1::NotEpochBoundary);
    }
    if transition.header.epoch != anchor.epoch {
        return Err(CheckpointErrorV1::UnexpectedAuthorityEpoch);
    }
    if transition.header.finality_authority_set_root != anchor.authority_root {
        return Err(CheckpointErrorV1::AuthorityCommitmentMismatch);
    }
    verify_authority_domain(
        &transition.outgoing_authority_set,
        &anchor.chain_id,
        transition.header.protocol_version,
        anchor.epoch,
    )?;
    if transition
        .outgoing_authority_set
        .commitment()
        .map_err(|_| CheckpointErrorV1::InvalidAuthoritySet)?
        != anchor.authority_root
    {
        return Err(CheckpointErrorV1::AuthorityCommitmentMismatch);
    }
    let incoming_epoch = anchor
        .epoch
        .checked_next()
        .ok_or(CheckpointErrorV1::EpochExhausted)?;
    verify_authority_domain(
        &transition.incoming_authority_set,
        &anchor.chain_id,
        transition.header.protocol_version,
        incoming_epoch,
    )?;
    let incoming_root = transition
        .incoming_authority_set
        .commitment()
        .map_err(|_| CheckpointErrorV1::InvalidAuthoritySet)?;
    if incoming_root != transition.header.next_finality_authority_set_root
        || incoming_root == anchor.authority_root
    {
        return Err(CheckpointErrorV1::NextAuthorityCommitmentMismatch);
    }
    verify_certified_header_v1(
        &transition.header,
        &transition.certificate,
        &transition.outgoing_authority_set,
    )?;

    Ok(AuthorityTransitionAnchorV1::new(
        anchor.chain_id.clone(),
        incoming_root,
        incoming_epoch,
        transition.header.height,
        anchor.blocks_per_epoch,
    ))
}

pub(crate) fn verify_certified_header_v1(
    header: &BlockHeaderV4,
    certificate: &FinalityCertificate,
    authority_set: &FinalityAuthoritySetV1,
) -> Result<(), CheckpointErrorV1> {
    validate_collection_bounds(authority_set, certificate)?;
    if certificate.protocol_version != TRANSACTION_V5_PROTOCOL_VERSION
        || certificate.protocol_version != header.protocol_version
        || certificate.chain_id != header.chain_id
        || certificate.height != header.height.get()
    {
        return Err(CheckpointErrorV1::CertificateDomainMismatch);
    }
    let header_hash = header
        .hash()
        .map_err(|_| CheckpointErrorV1::InvalidHeader)?;
    if certificate.block_hash != header_hash {
        return Err(CheckpointErrorV1::CertificateBlockMismatch);
    }
    let validator_set = authority_set
        .to_validator_set()
        .map_err(|_| CheckpointErrorV1::InvalidAuthoritySet)?;
    certificate
        .verify(&validator_set, header.protocol_version, &header.chain_id)
        .map_err(|_| CheckpointErrorV1::CertificateInvalid)
}

pub(crate) fn verify_authority_domain(
    authority_set: &FinalityAuthoritySetV1,
    chain_id: &ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
) -> Result<(), CheckpointErrorV1> {
    authority_set
        .validate()
        .map_err(|_| CheckpointErrorV1::InvalidAuthoritySet)?;
    if authority_set.protocol_version != protocol_version
        || authority_set.chain_id != *chain_id
        || authority_set.epoch != epoch
    {
        return Err(CheckpointErrorV1::AuthorityDomainMismatch);
    }
    Ok(())
}

fn validate_collection_bounds(
    authority_set: &FinalityAuthoritySetV1,
    certificate: &FinalityCertificate,
) -> Result<(), CheckpointErrorV1> {
    if authority_set.authorities.len() > MAX_FINALITY_AUTHORITIES_V1 {
        return Err(CheckpointErrorV1::TooManyAuthorities);
    }
    if certificate.precommits.len() > MAX_CONSENSUS_VOTES_PER_PROOF {
        return Err(CheckpointErrorV1::TooManyCertificateVotes);
    }
    Ok(())
}

/// Typed rejection from checkpoint or authority-transition validation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointErrorV1 {
    /// Checkpoint JSON is not the strict outer V1 schema.
    #[error("checkpoint JSON is malformed")]
    MalformedCheckpoint,
    /// Transition JSON is not the strict outer V1 schema.
    #[error("authority transition JSON is malformed")]
    MalformedTransition,
    /// Checkpoint bytes exceed the absolute hostile-input cap.
    #[error("checkpoint size {actual} exceeds maximum {maximum}")]
    CheckpointTooLarge {
        /// Observed byte length.
        actual: usize,
        /// Absolute accepted byte length.
        maximum: usize,
    },
    /// Transition bytes exceed the absolute hostile-input cap.
    #[error("authority transition size {actual} exceeds maximum {maximum}")]
    TransitionTooLarge {
        /// Observed byte length.
        actual: usize,
        /// Absolute accepted byte length.
        maximum: usize,
    },
    /// Authority entry count exceeds the absolute cap.
    #[error("authority set exceeds its entry limit")]
    TooManyAuthorities,
    /// Certificate vote count exceeds the absolute cap.
    #[error("finality certificate exceeds its vote limit")]
    TooManyCertificateVotes,
    /// Checkpoint schema version is unknown.
    #[error("unsupported checkpoint version {actual}")]
    UnsupportedCheckpointVersion {
        /// Rejected version.
        actual: u16,
    },
    /// Transition schema version is unknown.
    #[error("unsupported authority transition version {actual}")]
    UnsupportedTransitionVersion {
        /// Rejected version.
        actual: u16,
    },
    /// Header fails protocol-2 structural validation or hashing.
    #[error("checkpoint or transition header is invalid")]
    InvalidHeader,
    /// Candidate belongs to another genesis replay domain.
    #[error("checkpoint or transition belongs to another chain")]
    WrongChain,
    /// Candidate height is older than the configured floor.
    #[error("checkpoint height is below the configured floor")]
    CheckpointBelowHeightFloor,
    /// Candidate epoch is older than the configured floor.
    #[error("checkpoint epoch is below the configured floor")]
    CheckpointBelowEpochFloor,
    /// Authority entries, ordering, keys, or power are invalid.
    #[error("finality authority set is invalid")]
    InvalidAuthoritySet,
    /// Authority set has the wrong protocol, chain, or epoch.
    #[error("finality authority set domain does not match the header")]
    AuthorityDomainMismatch,
    /// Current authority root does not match the trusted/header commitment.
    #[error("current finality authority commitment does not match")]
    AuthorityCommitmentMismatch,
    /// Incoming authority root does not match the transition header.
    #[error("next finality authority commitment does not match")]
    NextAuthorityCommitmentMismatch,
    /// Certificate protocol, chain, or height differs from the header.
    #[error("finality certificate domain does not match the header")]
    CertificateDomainMismatch,
    /// Certificate names a block hash other than the exact header hash.
    #[error("finality certificate does not identify the header")]
    CertificateBlockMismatch,
    /// Certificate signatures, voter uniqueness, or quorum are invalid.
    #[error("finality certificate is invalid")]
    CertificateInvalid,
    /// Transition height did not advance beyond the authenticated history.
    #[error("authority transition height must increase")]
    TransitionHeightNotIncreasing,
    /// Transition header is not at the configured epoch boundary.
    #[error("authority transition is not at an epoch boundary")]
    NotEpochBoundary,
    /// Transition skipped or repeated the expected outgoing epoch.
    #[error("authority transition has an unexpected outgoing epoch")]
    UnexpectedAuthorityEpoch,
    /// Epoch arithmetic cannot advance without wrapping.
    #[error("authority epoch is exhausted")]
    EpochExhausted,
    /// Canonical bytes could not be produced.
    #[error("checkpoint or transition cannot be canonically encoded")]
    CanonicalEncoding,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use webc_chain::{Amount, SignedVote, ValidatorPower, ValidatorSet, Vote, VoteType};
    use webc_crypto::{Address, Keypair};

    fn authority(seed: u8, epoch: u64) -> (Keypair, FinalityAuthoritySetV1) {
        let key = Keypair::from_seed([seed; 32]);
        let mut validators = BTreeMap::new();
        validators.insert(
            key.address(),
            ValidatorPower {
                validator: key.address(),
                power: Amount::from_units(100),
                consensus_key: key.public_key(),
            },
        );
        let set = ValidatorSet {
            validators,
            total_power: Amount::from_units(100),
        };
        let authority_set = FinalityAuthoritySetV1::from_validator_set(
            TRANSACTION_V5_PROTOCOL_VERSION,
            ChainId::devnet(),
            Epoch::new(epoch),
            &set,
        )
        .expect("fixture authority set");
        (key, authority_set)
    }

    fn header(
        height: u64,
        epoch: u64,
        current: &FinalityAuthoritySetV1,
        next: &FinalityAuthoritySetV1,
        proposer: Address,
    ) -> BlockHeaderV4 {
        BlockHeaderV4 {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            height: BlockHeight::new(height),
            epoch: Epoch::new(epoch),
            previous_hash: Hash256::digest(b"previous"),
            state_root: Hash256::digest(b"state"),
            account_root: Hash256::digest(b"accounts"),
            tx_root: Hash256::ZERO,
            receipt_root: Hash256::ZERO,
            evidence_root: Hash256::ZERO,
            finality_authority_set_root: current.commitment().expect("current root"),
            next_finality_authority_set_root: next.commitment().expect("next root"),
            proposer,
            timestamp_ms: height * 1_000,
            base_fee_per_unit: 1,
        }
    }

    fn certificate(header: &BlockHeaderV4, signer: &Keypair) -> FinalityCertificate {
        let block_hash = header.hash().expect("header hash");
        let vote = SignedVote::sign(
            Vote {
                protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
                chain_id: header.chain_id.clone(),
                height: header.height.get(),
                round: 0,
                vote_type: VoteType::Precommit,
                block_hash,
                validator: signer.address(),
            },
            signer,
        )
        .expect("fixture vote");
        FinalityCertificate {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            chain_id: header.chain_id.clone(),
            height: header.height.get(),
            round: 0,
            block_hash,
            precommits: vec![vote],
        }
    }

    fn checkpoint() -> CheckpointV1 {
        let (key, authority_set) = authority(1, 0);
        let header = header(9, 0, &authority_set, &authority_set, key.address());
        let certificate = certificate(&header, &key);
        CheckpointV1 {
            version: CHECKPOINT_V1,
            header,
            certificate,
            authority_set,
        }
    }

    fn requirements() -> CheckpointRequirementsV1 {
        CheckpointRequirementsV1::new(ChainId::devnet(), BlockHeight::new(9), Epoch::new(0))
    }

    #[test]
    fn checkpoint_validates_and_has_a_stable_domain_digest() {
        let validated = validate_checkpoint_v1(checkpoint(), &requirements()).expect("valid");
        assert_ne!(
            validated.digest,
            validated.checkpoint.header.hash().unwrap()
        );
        assert_eq!(
            validated.next_anchor(10).unwrap(),
            AuthorityTransitionAnchorV1::new(
                ChainId::devnet(),
                validated.checkpoint.header.next_finality_authority_set_root,
                Epoch::new(0),
                BlockHeight::new(9),
                10,
            )
        );
    }

    #[test]
    fn checkpoint_rejects_floor_chain_root_and_certificate_tampering() {
        let mut stale = requirements();
        stale.minimum_height = BlockHeight::new(10);
        assert_eq!(
            validate_checkpoint_v1(checkpoint(), &stale),
            Err(CheckpointErrorV1::CheckpointBelowHeightFloor)
        );

        let mut wrong_chain = requirements();
        wrong_chain.chain_id = ChainId::new("webc-other-1").unwrap();
        assert_eq!(
            validate_checkpoint_v1(checkpoint(), &wrong_chain),
            Err(CheckpointErrorV1::WrongChain)
        );

        let mut wrong_root = checkpoint();
        wrong_root.header.finality_authority_set_root = Hash256::digest(b"wrong");
        assert_eq!(
            validate_checkpoint_v1(wrong_root, &requirements()),
            Err(CheckpointErrorV1::AuthorityCommitmentMismatch)
        );

        let mut wrong_certificate = checkpoint();
        wrong_certificate.certificate.block_hash = Hash256::digest(b"wrong");
        assert_eq!(
            validate_checkpoint_v1(wrong_certificate, &requirements()),
            Err(CheckpointErrorV1::CertificateBlockMismatch)
        );

        let mut duplicate_vote = checkpoint();
        duplicate_vote
            .certificate
            .precommits
            .push(duplicate_vote.certificate.precommits[0].clone());
        assert_eq!(
            validate_checkpoint_v1(duplicate_vote, &requirements()),
            Err(CheckpointErrorV1::CertificateInvalid)
        );
    }

    #[test]
    fn certified_transition_advances_exactly_one_epoch() {
        let validated = validate_checkpoint_v1(checkpoint(), &requirements()).unwrap();
        let anchor = validated.next_anchor(10).unwrap();
        let (outgoing_key, outgoing) = authority(1, 0);
        let (_, incoming) = authority(2, 1);
        let header = header(10, 0, &outgoing, &incoming, outgoing_key.address());
        let transition = AuthoritySetTransitionV1 {
            version: AUTHORITY_SET_TRANSITION_V1,
            certificate: certificate(&header, &outgoing_key),
            header,
            outgoing_authority_set: outgoing,
            incoming_authority_set: incoming.clone(),
        };

        let next = verify_authority_set_transition_v1(&transition, &anchor).expect("transition");
        assert_eq!(next.epoch(), Epoch::new(1));
        assert_eq!(next.minimum_height(), BlockHeight::new(10));
        assert_eq!(next.authority_root(), incoming.commitment().unwrap());
        assert_ne!(
            transition.digest().unwrap(),
            transition.header.hash().unwrap()
        );
    }

    #[test]
    fn transition_rejects_non_boundary_skipped_epoch_and_wrong_outgoing_root() {
        let validated = validate_checkpoint_v1(checkpoint(), &requirements()).unwrap();
        let anchor = validated.next_anchor(10).unwrap();
        let (outgoing_key, outgoing) = authority(1, 0);
        let (_, incoming) = authority(2, 1);
        let valid_header = header(10, 0, &outgoing, &incoming, outgoing_key.address());
        let mut transition = AuthoritySetTransitionV1 {
            version: AUTHORITY_SET_TRANSITION_V1,
            certificate: certificate(&valid_header, &outgoing_key),
            header: valid_header,
            outgoing_authority_set: outgoing,
            incoming_authority_set: incoming,
        };

        transition.header.height = BlockHeight::new(11);
        transition.certificate = certificate(&transition.header, &outgoing_key);
        assert_eq!(
            verify_authority_set_transition_v1(&transition, &anchor),
            Err(CheckpointErrorV1::NotEpochBoundary)
        );

        transition.header.height = BlockHeight::new(10);
        transition.header.epoch = Epoch::new(1);
        transition.certificate = certificate(&transition.header, &outgoing_key);
        assert_eq!(
            verify_authority_set_transition_v1(&transition, &anchor),
            Err(CheckpointErrorV1::UnexpectedAuthorityEpoch)
        );

        transition.header.epoch = Epoch::new(0);
        transition.header.finality_authority_set_root = Hash256::digest(b"foreign root");
        transition.certificate = certificate(&transition.header, &outgoing_key);
        assert_eq!(
            verify_authority_set_transition_v1(&transition, &anchor),
            Err(CheckpointErrorV1::AuthorityCommitmentMismatch)
        );
    }

    #[test]
    fn outer_json_caps_reject_before_decode() {
        let oversized = vec![b' '; MAX_CHECKPOINT_V1_JSON_BYTES + 1];
        assert_eq!(
            CheckpointV1::decode_json(&oversized, &requirements()),
            Err(CheckpointErrorV1::CheckpointTooLarge {
                actual: MAX_CHECKPOINT_V1_JSON_BYTES + 1,
                maximum: MAX_CHECKPOINT_V1_JSON_BYTES,
            })
        );
    }
}
