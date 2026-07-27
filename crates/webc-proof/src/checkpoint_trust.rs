//! Replaceable source and trust-policy boundaries for first checkpoints.
//!
//! Purpose: turn independently retrieved checkpoint candidates into one visibly
//! trusted checkpoint without coupling proof verification to URLs, publishers,
//! or a fixed governance service. Responsibilities: bounded configured source
//! identities, explicit availability observations, candidate validation,
//! fail-closed multi-source agreement, and permanently labelled operator trust.
//! Non-responsibilities: HTTP/filesystem retrieval implementations, peer
//! discovery, source-independence claims, consensus mutation, or proof checks
//! after acceptance. Data flow: configured adapters return hostile candidates;
//! callers record one observation per configured source; a replaceable policy
//! validates every candidate and returns an immutable accepted checkpoint.
//! Security boundary: discovered identities are never admitted implicitly,
//! missing sources cannot silently disappear, one invalid/disagreeing candidate
//! stops agreement, and source count never substitutes for source independence.

use std::{collections::BTreeSet, fmt, future::Future, pin::Pin};

use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use webc_crypto::Hash256;

use crate::{
    validate_checkpoint_v1, CheckpointErrorV1, CheckpointRequirementsV1, CheckpointV1,
    ValidatedCheckpointV1,
};

/// Maximum configured sources or observations accepted by a V1 policy.
pub const MAX_CHECKPOINT_SOURCES_V1: usize = 64;
/// Maximum byte length of a stable configured source identity.
pub const MAX_SOURCE_IDENTITY_V1_BYTES: usize = 128;
/// Maximum byte length of an explicit operator trust label.
pub const MAX_OPERATOR_TRUST_LABEL_V1_BYTES: usize = 128;

/// Stable configured identity for one independently operated checkpoint source.
///
/// This is a local configuration label, not a network-discovered peer identity
/// and not proof that two sources are operationally independent.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct SourceIdentityV1(String);

impl SourceIdentityV1 {
    /// Creates a bounded ASCII identifier such as `community-node-1`.
    pub fn new(value: impl Into<String>) -> Result<Self, CheckpointTrustConfigErrorV1> {
        let value = value.into();
        if !valid_source_identity(&value) {
            return Err(CheckpointTrustConfigErrorV1::InvalidSourceIdentity);
        }
        Ok(Self(value))
    }

    /// Returns the configured source label.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SourceIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl<'de> Deserialize<'de> for SourceIdentityV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

fn valid_source_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SOURCE_IDENTITY_V1_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
}

/// Human-visible label explaining which explicit operator input was trusted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct OperatorTrustLabelV1(String);

impl OperatorTrustLabelV1 {
    /// Creates a non-empty, trimmed printable-ASCII operator label.
    pub fn new(value: impl Into<String>) -> Result<Self, CheckpointTrustConfigErrorV1> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_OPERATOR_TRUST_LABEL_V1_BYTES
            || value.trim() != value
            || !value
                .bytes()
                .all(|byte| byte == b' ' || byte.is_ascii_graphic())
        {
            return Err(CheckpointTrustConfigErrorV1::InvalidOperatorTrustLabel);
        }
        Ok(Self(value))
    }

    /// Returns the exact human-visible operator label.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for OperatorTrustLabelV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// Opaque retrieval failure; transport details stay outside proof semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("checkpoint source is unavailable")]
pub struct CheckpointSourceUnavailableV1;

/// Boxed retrieval future used by replaceable node-side source adapters.
pub type CheckpointSourceFutureV1<'a> =
    Pin<Box<dyn Future<Output = Result<CheckpointV1, CheckpointSourceUnavailableV1>> + 'a>>;

/// Retrieval boundary implemented by HTTP, file, or explicit-input adapters.
///
/// The proof crate defines only the narrow interface. Implementations own all
/// I/O, authentication, timeouts, and transport limits outside this crate.
pub trait CheckpointSourceV1 {
    /// Returns the preconfigured identity counted by trust policy.
    fn identity(&self) -> &SourceIdentityV1;

    /// Retrieves one hostile candidate or reports explicit unavailability.
    fn retrieve(&self) -> CheckpointSourceFutureV1<'_>;
}

/// One explicit result for one configured source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckpointSourceResultV1 {
    /// Source returned bytes decoded as a checkpoint candidate.
    Candidate(Box<CheckpointV1>),
    /// Source failed within its adapter's bounded retrieval policy.
    Unavailable,
}

/// Source identity paired with its candidate or explicit unavailability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointSourceObservationV1 {
    source: SourceIdentityV1,
    result: CheckpointSourceResultV1,
}

impl CheckpointSourceObservationV1 {
    /// Records a candidate returned by `source`.
    pub fn candidate(source: SourceIdentityV1, candidate: CheckpointV1) -> Self {
        Self {
            source,
            result: CheckpointSourceResultV1::Candidate(Box::new(candidate)),
        }
    }

    /// Records bounded retrieval failure for `source`.
    pub const fn unavailable(source: SourceIdentityV1) -> Self {
        Self {
            source,
            result: CheckpointSourceResultV1::Unavailable,
        }
    }

    /// Returns the configured source identity.
    pub const fn source(&self) -> &SourceIdentityV1 {
        &self.source
    }

    /// Returns the explicit retrieval result.
    pub const fn result(&self) -> &CheckpointSourceResultV1 {
        &self.result
    }
}

/// Retrieves one source and preserves its configured identity in an observation.
pub async fn observe_checkpoint_source_v1(
    source: &dyn CheckpointSourceV1,
) -> CheckpointSourceObservationV1 {
    let identity = source.identity().clone();
    match source.retrieve().await {
        Ok(candidate) => CheckpointSourceObservationV1::candidate(identity, candidate),
        Err(CheckpointSourceUnavailableV1) => CheckpointSourceObservationV1::unavailable(identity),
    }
}

/// Visible reason an accepted checkpoint was trusted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CheckpointTrustLabelV1 {
    /// At least the configured threshold of distinct sources agreed.
    QuorumAgreementV1 {
        /// Threshold configured by the operator.
        required_agreements: u16,
        /// Number of available valid sources that agreed exactly.
        observed_agreements: u16,
    },
    /// The operator deliberately trusted one named input.
    ExplicitOperatorTrustV1 {
        /// Human-visible reason/name configured by the operator.
        label: OperatorTrustLabelV1,
    },
}

/// Checkpoint accepted by one explicit, replaceable trust policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedCheckpointV1 {
    checkpoint: ValidatedCheckpointV1,
    trust: CheckpointTrustLabelV1,
    agreeing_sources: Vec<SourceIdentityV1>,
}

impl AcceptedCheckpointV1 {
    /// Returns the fully validated checkpoint used by proof verification.
    pub const fn validated_checkpoint(&self) -> &ValidatedCheckpointV1 {
        &self.checkpoint
    }

    /// Returns the domain-separated digest agreed by the accepted sources.
    pub const fn digest(&self) -> Hash256 {
        self.checkpoint.digest()
    }

    /// Returns the visible trust policy result.
    pub const fn trust(&self) -> &CheckpointTrustLabelV1 {
        &self.trust
    }

    /// Returns deterministic configured identities that supplied the candidate.
    pub fn agreeing_sources(&self) -> &[SourceIdentityV1] {
        &self.agreeing_sources
    }
}

/// Replaceable acceptance boundary over already-retrieved source observations.
pub trait CheckpointTrustPolicyV1 {
    /// Validates all candidates and accepts exactly one checkpoint or fails shut.
    fn accept(
        &self,
        observations: Vec<CheckpointSourceObservationV1>,
        requirements: &CheckpointRequirementsV1,
    ) -> Result<AcceptedCheckpointV1, CheckpointTrustErrorV1>;
}

/// Initial policy requiring exact agreement among configured distinct sources.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumAgreementV1 {
    configured_sources: BTreeSet<SourceIdentityV1>,
    required_agreements: usize,
}

impl QuorumAgreementV1 {
    /// Creates a policy with 2..=64 required agreements and configured sources.
    pub fn new(
        configured_sources: Vec<SourceIdentityV1>,
        required_agreements: usize,
    ) -> Result<Self, CheckpointTrustConfigErrorV1> {
        if configured_sources.len() < 2 || configured_sources.len() > MAX_CHECKPOINT_SOURCES_V1 {
            return Err(CheckpointTrustConfigErrorV1::InvalidConfiguredSourceCount);
        }
        if required_agreements < 2 || required_agreements > configured_sources.len() {
            return Err(CheckpointTrustConfigErrorV1::InvalidRequiredAgreements);
        }
        let source_count = configured_sources.len();
        let configured_sources = configured_sources.into_iter().collect::<BTreeSet<_>>();
        if configured_sources.len() != source_count {
            return Err(CheckpointTrustConfigErrorV1::DuplicateConfiguredSource);
        }
        Ok(Self {
            configured_sources,
            required_agreements,
        })
    }
}

impl CheckpointTrustPolicyV1 for QuorumAgreementV1 {
    fn accept(
        &self,
        observations: Vec<CheckpointSourceObservationV1>,
        requirements: &CheckpointRequirementsV1,
    ) -> Result<AcceptedCheckpointV1, CheckpointTrustErrorV1> {
        validate_observation_shape(&observations, &self.configured_sources)?;

        let mut accepted: Option<(SourceIdentityV1, ValidatedCheckpointV1)> = None;
        let mut agreeing_sources = BTreeSet::new();
        for observation in observations {
            let CheckpointSourceResultV1::Candidate(candidate) = observation.result else {
                continue;
            };
            let validated = validate_checkpoint_v1(*candidate, requirements).map_err(|error| {
                CheckpointTrustErrorV1::InvalidCandidate {
                    source_id: observation.source.clone(),
                    error,
                }
            })?;
            if let Some((first_source, first)) = &accepted {
                if first.digest() != validated.digest() {
                    return Err(CheckpointTrustErrorV1::SourceDisagreement {
                        first_source: first_source.clone(),
                        first_digest: first.digest(),
                        conflicting_source: observation.source,
                        conflicting_digest: validated.digest(),
                    });
                }
            } else {
                accepted = Some((observation.source.clone(), validated));
            }
            agreeing_sources.insert(observation.source);
        }

        if agreeing_sources.len() < self.required_agreements {
            return Err(CheckpointTrustErrorV1::InsufficientAgreement {
                required: self.required_agreements,
                available: agreeing_sources.len(),
            });
        }
        let (_, checkpoint) = accepted.ok_or(CheckpointTrustErrorV1::InsufficientAgreement {
            required: self.required_agreements,
            available: 0,
        })?;
        let required_agreements = u16::try_from(self.required_agreements)
            .map_err(|_| CheckpointTrustErrorV1::CountConversion)?;
        let observed_agreements = u16::try_from(agreeing_sources.len())
            .map_err(|_| CheckpointTrustErrorV1::CountConversion)?;
        Ok(AcceptedCheckpointV1 {
            checkpoint,
            trust: CheckpointTrustLabelV1::QuorumAgreementV1 {
                required_agreements,
                observed_agreements,
            },
            agreeing_sources: agreeing_sources.into_iter().collect(),
        })
    }
}

/// Policy accepting exactly one explicitly configured operator-trusted input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplicitOperatorTrustV1 {
    source: SourceIdentityV1,
    label: OperatorTrustLabelV1,
}

impl ExplicitOperatorTrustV1 {
    /// Creates an explicitly labelled single-source policy.
    pub const fn new(source: SourceIdentityV1, label: OperatorTrustLabelV1) -> Self {
        Self { source, label }
    }
}

impl CheckpointTrustPolicyV1 for ExplicitOperatorTrustV1 {
    fn accept(
        &self,
        observations: Vec<CheckpointSourceObservationV1>,
        requirements: &CheckpointRequirementsV1,
    ) -> Result<AcceptedCheckpointV1, CheckpointTrustErrorV1> {
        if observations.len() != 1 {
            return Err(CheckpointTrustErrorV1::ExplicitObservationCount);
        }
        let observation = observations
            .into_iter()
            .next()
            .ok_or(CheckpointTrustErrorV1::ExplicitObservationCount)?;
        if observation.source != self.source {
            return Err(CheckpointTrustErrorV1::UnexpectedSource {
                source_id: observation.source,
            });
        }
        let CheckpointSourceResultV1::Candidate(candidate) = observation.result else {
            return Err(CheckpointTrustErrorV1::ExplicitSourceUnavailable);
        };
        let checkpoint = validate_checkpoint_v1(*candidate, requirements).map_err(|error| {
            CheckpointTrustErrorV1::InvalidCandidate {
                source_id: self.source.clone(),
                error,
            }
        })?;
        Ok(AcceptedCheckpointV1 {
            checkpoint,
            trust: CheckpointTrustLabelV1::ExplicitOperatorTrustV1 {
                label: self.label.clone(),
            },
            agreeing_sources: vec![self.source.clone()],
        })
    }
}

fn validate_observation_shape(
    observations: &[CheckpointSourceObservationV1],
    configured_sources: &BTreeSet<SourceIdentityV1>,
) -> Result<(), CheckpointTrustErrorV1> {
    if observations.len() > MAX_CHECKPOINT_SOURCES_V1 {
        return Err(CheckpointTrustErrorV1::TooManyObservations);
    }
    let mut observed_sources = BTreeSet::new();
    for observation in observations {
        if !configured_sources.contains(&observation.source) {
            return Err(CheckpointTrustErrorV1::UnexpectedSource {
                source_id: observation.source.clone(),
            });
        }
        if !observed_sources.insert(observation.source.clone()) {
            return Err(CheckpointTrustErrorV1::DuplicateObservation {
                source_id: observation.source.clone(),
            });
        }
    }
    if let Some(missing) = configured_sources.difference(&observed_sources).next() {
        return Err(CheckpointTrustErrorV1::MissingObservation {
            source_id: missing.clone(),
        });
    }
    Ok(())
}

/// Invalid local configuration rejected before any source retrieval.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointTrustConfigErrorV1 {
    /// Source identities must be 1..=128 bytes of the documented ASCII subset.
    #[error("checkpoint source identity is invalid")]
    InvalidSourceIdentity,
    /// Human-visible explicit trust label is empty, untrimmed, or non-printable.
    #[error("explicit operator trust label is invalid")]
    InvalidOperatorTrustLabel,
    /// Quorum policy requires 2..=64 configured sources.
    #[error("configured checkpoint source count is outside 2..=64")]
    InvalidConfiguredSourceCount,
    /// Required agreements must be at least two and no more than configured.
    #[error("required checkpoint agreements are invalid")]
    InvalidRequiredAgreements,
    /// The same configured source appeared more than once.
    #[error("configured checkpoint sources must be distinct")]
    DuplicateConfiguredSource,
}

/// Fail-closed rejection while applying a checkpoint trust policy.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointTrustErrorV1 {
    /// More observations were supplied than the V1 absolute cap.
    #[error("checkpoint source observations exceed their limit")]
    TooManyObservations,
    /// An observation did not belong to the configured source set.
    #[error("unexpected checkpoint source {source_id}")]
    UnexpectedSource {
        /// Unconfigured source identity.
        source_id: SourceIdentityV1,
    },
    /// A configured identity supplied multiple observations.
    #[error("duplicate checkpoint observation from {source_id}")]
    DuplicateObservation {
        /// Repeated source identity.
        source_id: SourceIdentityV1,
    },
    /// A configured source was omitted instead of marked unavailable.
    #[error("missing checkpoint observation for {source_id}")]
    MissingObservation {
        /// Omitted configured source identity.
        source_id: SourceIdentityV1,
    },
    /// A returned candidate failed strict checkpoint validation.
    #[error("checkpoint candidate from {source_id} is invalid: {error}")]
    InvalidCandidate {
        /// Source that returned the invalid candidate.
        source_id: SourceIdentityV1,
        /// Pure structural/cryptographic validation failure.
        error: CheckpointErrorV1,
    },
    /// Two structurally valid configured candidates differed.
    #[error("configured checkpoint sources disagree")]
    SourceDisagreement {
        /// First valid source used for comparison.
        first_source: SourceIdentityV1,
        /// First source's domain-separated digest.
        first_digest: Hash256,
        /// Source returning a different valid checkpoint.
        conflicting_source: SourceIdentityV1,
        /// Conflicting domain-separated digest.
        conflicting_digest: Hash256,
    },
    /// Too few configured sources were available and agreed.
    #[error("checkpoint agreement has {available} candidates but requires {required}")]
    InsufficientAgreement {
        /// Configured agreement threshold.
        required: usize,
        /// Available valid candidates sharing the same digest.
        available: usize,
    },
    /// Explicit trust accepts exactly one observation.
    #[error("explicit operator trust requires exactly one source observation")]
    ExplicitObservationCount,
    /// Explicitly trusted source was unavailable.
    #[error("explicitly trusted checkpoint source is unavailable")]
    ExplicitSourceUnavailable,
    /// A bounded source count unexpectedly failed its lossless u16 conversion.
    #[error("checkpoint source count cannot be represented")]
    CountConversion,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use webc_chain::{
        Amount, BlockHeaderV4, BlockHeight, ChainId, Epoch, FinalityAuthoritySetV1,
        FinalityCertificate, SignedVote, ValidatorPower, ValidatorSet, Vote, VoteType,
        TRANSACTION_V5_PROTOCOL_VERSION,
    };
    use webc_crypto::{Address, Keypair};

    fn source(value: &str) -> SourceIdentityV1 {
        SourceIdentityV1::new(value).expect("source fixture is valid")
    }

    fn authority() -> (Keypair, FinalityAuthoritySetV1) {
        let key = Keypair::from_seed([0x31; 32]);
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
            Epoch::new(0),
            &set,
        )
        .expect("authority fixture is valid");
        (key, authority_set)
    }

    fn header(
        height: u64,
        authority_set: &FinalityAuthoritySetV1,
        proposer: Address,
    ) -> BlockHeaderV4 {
        let root = authority_set.commitment().expect("authority root");
        BlockHeaderV4 {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            height: BlockHeight::new(height),
            epoch: Epoch::new(0),
            previous_hash: Hash256::digest(b"previous"),
            state_root: Hash256::digest(b"state"),
            account_root: Hash256::digest(b"accounts"),
            tx_root: Hash256::ZERO,
            receipt_root: Hash256::ZERO,
            evidence_root: Hash256::ZERO,
            finality_authority_set_root: root,
            next_finality_authority_set_root: root,
            proposer,
            timestamp_ms: height * 1_000,
            base_fee_per_unit: 1,
        }
    }

    fn certificate(header: &BlockHeaderV4, signer: &Keypair) -> FinalityCertificate {
        let block_hash = header.hash().expect("header hashes");
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
        .expect("vote signs");
        FinalityCertificate {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            chain_id: header.chain_id.clone(),
            height: header.height.get(),
            round: 0,
            block_hash,
            precommits: vec![vote],
        }
    }

    fn checkpoint(height: u64) -> CheckpointV1 {
        let (key, authority_set) = authority();
        let header = header(height, &authority_set, key.address());
        let certificate = certificate(&header, &key);
        CheckpointV1 {
            version: crate::CHECKPOINT_V1,
            header,
            certificate,
            authority_set,
        }
    }

    fn requirements() -> CheckpointRequirementsV1 {
        CheckpointRequirementsV1::new(ChainId::devnet(), BlockHeight::new(9), Epoch::new(0))
    }

    #[test]
    fn identities_and_policy_configuration_are_bounded_and_unambiguous() {
        assert_eq!(source("community-node:1").as_str(), "community-node:1");
        for invalid in ["", " leading", "node/one", "node one", "node?one"] {
            assert_eq!(
                SourceIdentityV1::new(invalid),
                Err(CheckpointTrustConfigErrorV1::InvalidSourceIdentity)
            );
        }
        assert_eq!(
            OperatorTrustLabelV1::new(" operator supplied "),
            Err(CheckpointTrustConfigErrorV1::InvalidOperatorTrustLabel)
        );
        assert_eq!(
            QuorumAgreementV1::new(vec![source("a"), source("a")], 2),
            Err(CheckpointTrustConfigErrorV1::DuplicateConfiguredSource)
        );
        assert_eq!(
            QuorumAgreementV1::new(vec![source("a"), source("b")], 1),
            Err(CheckpointTrustConfigErrorV1::InvalidRequiredAgreements)
        );
    }

    #[test]
    fn quorum_accepts_exact_agreement_and_keeps_unavailability_visible() {
        let policy = QuorumAgreementV1::new(
            vec![
                source("official"),
                source("community-a"),
                source("community-b"),
            ],
            2,
        )
        .expect("policy config is valid");
        let candidate = checkpoint(9);
        let expected = validate_checkpoint_v1(candidate.clone(), &requirements())
            .expect("checkpoint fixture validates");
        let accepted = policy
            .accept(
                vec![
                    CheckpointSourceObservationV1::candidate(
                        source("community-b"),
                        candidate.clone(),
                    ),
                    CheckpointSourceObservationV1::unavailable(source("official")),
                    CheckpointSourceObservationV1::candidate(source("community-a"), candidate),
                ],
                &requirements(),
            )
            .expect("two configured sources agree");
        assert_eq!(accepted.digest(), expected.digest());
        assert_eq!(
            accepted.trust(),
            &CheckpointTrustLabelV1::QuorumAgreementV1 {
                required_agreements: 2,
                observed_agreements: 2,
            }
        );
        assert_eq!(
            accepted.agreeing_sources(),
            &[source("community-a"), source("community-b")]
        );
    }

    #[test]
    fn quorum_stops_on_valid_disagreement_or_any_invalid_candidate() {
        let policy = QuorumAgreementV1::new(vec![source("one"), source("two"), source("three")], 2)
            .expect("policy config is valid");
        let disagreement = policy.accept(
            vec![
                CheckpointSourceObservationV1::candidate(source("one"), checkpoint(9)),
                CheckpointSourceObservationV1::candidate(source("two"), checkpoint(10)),
                CheckpointSourceObservationV1::unavailable(source("three")),
            ],
            &requirements(),
        );
        assert!(matches!(
            disagreement,
            Err(CheckpointTrustErrorV1::SourceDisagreement { .. })
        ));

        let valid = checkpoint(9);
        let mut invalid = valid.clone();
        invalid.certificate.block_hash = Hash256::digest(b"tampered");
        let rejected = policy.accept(
            vec![
                CheckpointSourceObservationV1::candidate(source("one"), valid.clone()),
                CheckpointSourceObservationV1::candidate(source("two"), valid),
                CheckpointSourceObservationV1::candidate(source("three"), invalid),
            ],
            &requirements(),
        );
        assert!(matches!(
            rejected,
            Err(CheckpointTrustErrorV1::InvalidCandidate { source_id, .. })
                if source_id == source("three")
        ));
    }

    #[test]
    fn quorum_never_silently_omits_or_duplicates_a_configured_source() {
        let policy = QuorumAgreementV1::new(vec![source("one"), source("two")], 2)
            .expect("policy config is valid");
        assert_eq!(
            policy.accept(
                vec![CheckpointSourceObservationV1::candidate(
                    source("one"),
                    checkpoint(9),
                )],
                &requirements(),
            ),
            Err(CheckpointTrustErrorV1::MissingObservation {
                source_id: source("two")
            })
        );
        assert_eq!(
            policy.accept(
                vec![
                    CheckpointSourceObservationV1::candidate(source("one"), checkpoint(9)),
                    CheckpointSourceObservationV1::unavailable(source("one")),
                ],
                &requirements(),
            ),
            Err(CheckpointTrustErrorV1::DuplicateObservation {
                source_id: source("one")
            })
        );
        assert_eq!(
            policy.accept(
                vec![
                    CheckpointSourceObservationV1::candidate(source("one"), checkpoint(9)),
                    CheckpointSourceObservationV1::unavailable(source("two")),
                ],
                &requirements(),
            ),
            Err(CheckpointTrustErrorV1::InsufficientAgreement {
                required: 2,
                available: 1,
            })
        );
    }

    #[test]
    fn quorum_propagates_stale_and_wrong_chain_candidate_rejections() {
        let policy = QuorumAgreementV1::new(vec![source("one"), source("two")], 2)
            .expect("policy config is valid");
        let stale_requirements =
            CheckpointRequirementsV1::new(ChainId::devnet(), BlockHeight::new(10), Epoch::new(0));
        assert!(matches!(
            policy.accept(
                vec![
                    CheckpointSourceObservationV1::candidate(source("one"), checkpoint(9)),
                    CheckpointSourceObservationV1::candidate(source("two"), checkpoint(9)),
                ],
                &stale_requirements,
            ),
            Err(CheckpointTrustErrorV1::InvalidCandidate {
                error: CheckpointErrorV1::CheckpointBelowHeightFloor,
                ..
            })
        ));

        let wrong_chain_requirements = CheckpointRequirementsV1::new(
            ChainId::new("webc-other-1").expect("other chain ID is valid"),
            BlockHeight::new(9),
            Epoch::new(0),
        );
        assert!(matches!(
            policy.accept(
                vec![
                    CheckpointSourceObservationV1::candidate(source("one"), checkpoint(9)),
                    CheckpointSourceObservationV1::candidate(source("two"), checkpoint(9)),
                ],
                &wrong_chain_requirements,
            ),
            Err(CheckpointTrustErrorV1::InvalidCandidate {
                error: CheckpointErrorV1::WrongChain,
                ..
            })
        ));
    }

    #[test]
    fn explicit_operator_trust_is_permanently_labelled_and_fail_closed() {
        let label = OperatorTrustLabelV1::new("air-gapped operator input")
            .expect("operator label is valid");
        let policy = ExplicitOperatorTrustV1::new(source("operator-usb"), label.clone());
        let accepted = policy
            .accept(
                vec![CheckpointSourceObservationV1::candidate(
                    source("operator-usb"),
                    checkpoint(9),
                )],
                &requirements(),
            )
            .expect("explicit valid input is accepted");
        assert_eq!(
            accepted.trust(),
            &CheckpointTrustLabelV1::ExplicitOperatorTrustV1 { label }
        );
        assert_eq!(accepted.agreeing_sources(), &[source("operator-usb")]);
        assert_eq!(
            policy.accept(
                vec![CheckpointSourceObservationV1::unavailable(source(
                    "operator-usb",
                ))],
                &requirements(),
            ),
            Err(CheckpointTrustErrorV1::ExplicitSourceUnavailable)
        );
    }
}
