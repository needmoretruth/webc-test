//! Objective signed slashing evidence and deterministic penalty calculation.
//!
//! Only conflicting consensus votes signed by the registered validator
//! consensus key are currently accepted. Labels for invalid blocks, bridge
//! fraud, downtime, or majority attacks cannot slash stake until their complete
//! objective artifact and verification path is implemented.

use crate::{
    canonical, Amount, ChainError, ChainId, DoubleVoteEvidence, ProtocolVersion, Validator,
    ValidatorStatus,
};
use serde::{Deserialize, Serialize};
use webc_crypto::{Address, Hash256};

/// Objective evidence that can be verified by the chain.
///
/// Avoid subjective slashing. Even a so-called 51% attack must be represented as
/// cryptographic evidence, such as conflicting signatures or invalid block
/// signatures, before the protocol can punish it safely.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashingEvidence {
    /// Two valid signatures for different blocks in the same chain/height/round/stage.
    DoubleVote(DoubleVoteEvidence),
}

impl SlashingEvidence {
    /// Computes an order-independent replay identity for the signed artifacts.
    pub fn hash(&self) -> Result<Hash256, ChainError> {
        match self {
            Self::DoubleVote(evidence) => {
                let mut votes = [
                    canonical::canonical_json_bytes(&evidence.first)?,
                    canonical::canonical_json_bytes(&evidence.second)?,
                ];
                votes.sort();
                Ok(Hash256::digest_many([
                    b"WEBC_DOUBLE_VOTE_EVIDENCE_V1".as_slice(),
                    votes[0].as_slice(),
                    votes[1].as_slice(),
                ]))
            }
        }
    }

    /// Verifies structural conflict and both registered-key signatures.
    pub fn verify(
        &self,
        protocol_version: ProtocolVersion,
        chain_id: &ChainId,
        registered_consensus_key: &webc_crypto::PublicKeyBytes,
    ) -> Result<(), ChainError> {
        match self {
            Self::DoubleVote(evidence) => {
                let first = &evidence.first.payload;
                let second = &evidence.second.payload;
                if first.validator != second.validator
                    || first.protocol_version != second.protocol_version
                    || first.chain_id != second.chain_id
                    || first.height != second.height
                    || first.round != second.round
                    || first.vote_type != second.vote_type
                    || first.block_hash == second.block_hash
                {
                    return Err(ChainError::InvalidSlashingEvidence);
                }
                evidence
                    .first
                    .verify(protocol_version, chain_id, registered_consensus_key)?;
                evidence
                    .second
                    .verify(protocol_version, chain_id, registered_consensus_key)
            }
        }
    }

    /// Returns the validator identity named consistently by both artifacts.
    pub fn validator(&self) -> Address {
        match self {
            Self::DoubleVote(evidence) => evidence.first.payload.validator,
        }
    }

    /// Returns a deterministic human-readable reason after verification.
    pub fn reason(&self) -> String {
        match self {
            Self::DoubleVote(evidence) => format!(
                "double-vote at height {} round {} {:?}",
                evidence.first.payload.height,
                evidence.first.payload.round,
                evidence.first.payload.vote_type
            ),
        }
    }
}

/// Slashing severity, in basis points. **The numbers here are PROVISIONAL
/// placeholders, not final** (owner direction 2026-07-17): they are to be
/// finalized against the Ethereum/Solana/Sui/Polkadot/Cardano comparison in
/// ADR-0012, which found isolated faults are usually light and severity is
/// driven by _correlation_. The structure is deliberately kept as flexible config
/// so the values can change without touching the slashing mechanism.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingPolicy {
    pub double_sign_bps: u16,
    pub invalid_block_bps: u16,
    pub bridge_fraud_bps: u16,
    pub downtime_bps_per_missed_slot: u16,
    pub downtime_max_bps: u16,
}

impl Default for SlashingPolicy {
    fn default() -> Self {
        // PROVISIONAL — see the struct doc and ADR-0012. These are the current
        // placeholders, kept flexible pending the owner's finalization.
        Self {
            double_sign_bps: 8_000,
            invalid_block_bps: 9_000,
            bridge_fraud_bps: 10_000,
            downtime_bps_per_missed_slot: 5,
            downtime_max_bps: 500,
        }
    }
}

/// Inactivity-leak configuration (ADR-0012, owner-directed 2026-07-17). **Opt-in
/// and disabled by default** (`ChainConfig.inactivity_leak` is `None`): the leak
/// math below is design-complete and testable, but wiring it into consensus (the
/// participation record + recovery mode that lets a > 1/3-offline chain drain
/// offline weight without a 2/3 quorum) is the careful consensus-safety work
/// gated on the owner confirming ADR-0012's recovery family and constants. Until
/// then WEBC keeps vanilla Tendermint liveness plus the ADR-0011 weak-subjectivity
/// restart fallback.
///
/// The per-epoch drain of a non-participating validator is an Ethereum-style
/// quadratic leak: the `inactivity_score` grows each stalled epoch, so the
/// cumulative drain grows with the square of stalled time, bounded per epoch.
/// Drained units are burned (moved to the `slashed_units` sink).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InactivityLeakConfig {
    /// Epochs of stalled finality after which the leak activates.
    pub activation_epochs: u64,
    /// Leak quotient (Ethereum `INACTIVITY_PENALTY_QUOTIENT` analogue): larger =
    /// slower leak. Must be non-zero.
    pub penalty_quotient: u64,
    /// Hard cap, in basis points, on the fraction of a validator's stake that may
    /// leak in a single epoch.
    pub max_leak_bps_per_epoch: u16,
}

impl InactivityLeakConfig {
    /// Whether the configuration is well-formed (non-zero quotient).
    pub fn is_valid(&self) -> bool {
        self.penalty_quotient != 0
    }

    /// The per-epoch leak for a non-participating validator holding `stake` at the
    /// given `inactivity_score`: `min(stake · score / penalty_quotient, stake ·
    /// max_leak_bps / 10_000)`. The quadratic cumulative behavior comes from the
    /// score growing each stalled epoch; this function is the single-epoch step.
    pub fn epoch_leak(&self, stake: Amount, inactivity_score: u64) -> Result<Amount, ChainError> {
        if self.penalty_quotient == 0 {
            return Err(ChainError::InvalidInactivityLeakConfig);
        }
        let scored_units = stake
            .0
            .checked_mul(u128::from(inactivity_score))
            .ok_or(ChainError::ArithmeticOverflow)?
            / u128::from(self.penalty_quotient);
        let scored = Amount::from_units(scored_units);
        let cap = stake
            .checked_mul_bps(self.max_leak_bps_per_epoch)
            .ok_or(ChainError::ArithmeticOverflow)?;
        // Bounded by both the cap and the validator's stake.
        let bounded = if scored < cap { scored } else { cap };
        Ok(if bounded < stake { bounded } else { stake })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingOutcome {
    pub validator: Address,
    pub self_slashed: Amount,
    pub delegated_slashed: Amount,
    pub jailed: bool,
    pub tombstoned: bool,
    pub reason: String,
}

/// Returns the deterministic penalty rate in basis points for verified evidence.
pub(crate) fn slashing_bps(evidence: &SlashingEvidence, policy: &SlashingPolicy) -> u16 {
    match evidence {
        SlashingEvidence::DoubleVote(_) => (policy.double_sign_bps, true),
    }
    .0
}

/// Applies operator and precomputed delegation losses to one validator aggregate.
pub(crate) fn slash_validator_with_delegation_loss(
    validator: &mut Validator,
    evidence: &SlashingEvidence,
    policy: &SlashingPolicy,
    delegated_slashed: Amount,
) -> Result<SlashingOutcome, ChainError> {
    let (bps, tombstone) = match evidence {
        SlashingEvidence::DoubleVote(_) => (policy.double_sign_bps, true),
    };

    if delegated_slashed > validator.delegated_stake {
        return Err(ChainError::ArithmeticOverflow);
    }
    let self_slashed = validator
        .self_stake
        .checked_mul_bps(bps)
        .ok_or(ChainError::ArithmeticOverflow)?;
    validator.self_stake = validator
        .self_stake
        .checked_sub(self_slashed)
        .ok_or(ChainError::ArithmeticOverflow)?;
    validator.delegated_stake = validator
        .delegated_stake
        .checked_sub(delegated_slashed)
        .ok_or(ChainError::ArithmeticOverflow)?;

    let reason = evidence.reason();
    validator.status = if tombstone {
        ValidatorStatus::Tombstoned {
            reason: reason.clone(),
        }
    } else {
        ValidatorStatus::Jailed {
            reason: reason.clone(),
        }
    };

    Ok(SlashingOutcome {
        validator: validator.operator,
        self_slashed,
        delegated_slashed,
        jailed: !tombstone,
        tombstoned: tombstone,
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::staking::Validator;
    use crate::{SignedVote, Vote, VoteType, CURRENT_PROTOCOL_VERSION};
    use webc_crypto::{Keypair, PublicKeyBytes, SignatureBytes};

    #[test]
    fn verified_double_vote_slashes_harshly() {
        let key = Keypair::from_seed([7u8; 32]);
        let mut validator = Validator {
            operator: key.address(),
            consensus_key: PublicKeyBytes([9u8; 32]),
            self_stake: Amount::from_webc(100),
            delegated_stake: Amount::from_webc(100),
            commission_bps: 500,
            status: ValidatorStatus::Active,
            bootstrap: false,
            accumulated_rewards: Amount::ZERO,
        };
        let vote = |block_hash| Vote {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            height: 10,
            round: 0,
            vote_type: VoteType::Precommit,
            block_hash,
            validator: validator.operator,
        };
        let evidence = SlashingEvidence::DoubleVote(DoubleVoteEvidence {
            first: SignedVote::sign(vote(Hash256::digest(b"a")), &key).expect("first vote signs"),
            second: SignedVote::sign(vote(Hash256::digest(b"b")), &key).expect("second vote signs"),
        });
        evidence
            .verify(
                CURRENT_PROTOCOL_VERSION,
                &ChainId::devnet(),
                &key.public_key(),
            )
            .expect("objective double vote verifies");
        let delegated_loss = validator
            .delegated_stake
            .checked_mul_bps(8_000)
            .expect("checked test penalty");
        let outcome = slash_validator_with_delegation_loss(
            &mut validator,
            &evidence,
            &SlashingPolicy::default(),
            delegated_loss,
        )
        .expect("checked penalty");
        assert!(outcome.tombstoned);
        assert_eq!(validator.self_stake, Amount::from_webc(20));
    }

    #[test]
    fn inactivity_leak_epoch_step_scales_with_score_and_caps() {
        let config = InactivityLeakConfig {
            activation_epochs: 4,
            penalty_quotient: 1_000,
            max_leak_bps_per_epoch: 500, // 5% per-epoch cap
        };
        assert!(config.is_valid());
        let stake = Amount::from_webc(100);

        // Score 0 => no leak. Score grows the per-epoch drain (quadratic cumulative
        // comes from the score itself growing each stalled epoch).
        assert_eq!(config.epoch_leak(stake, 0).unwrap(), Amount::ZERO);
        // score/quotient = 10/1000 = 1% of stake, below the 5% cap.
        assert_eq!(
            config.epoch_leak(stake, 10).unwrap(),
            Amount::from_units(stake.0 / 100)
        );
        // A large score is bounded by the 5% per-epoch cap, never more.
        assert_eq!(
            config.epoch_leak(stake, 1_000_000).unwrap(),
            stake.checked_mul_bps(500).unwrap()
        );

        // A zero quotient is rejected, not a divide-by-zero.
        let invalid = InactivityLeakConfig {
            penalty_quotient: 0,
            ..config
        };
        assert!(!invalid.is_valid());
        assert!(matches!(
            invalid.epoch_leak(stake, 1),
            Err(ChainError::InvalidInactivityLeakConfig)
        ));
    }

    #[test]
    fn evidence_replay_hash_matches_browser_fixture_and_vote_order() {
        let validator = Keypair::from_seed([2u8; 32]);
        let vote = |block_hash, signature| SignedVote {
            payload: Vote {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                chain_id: ChainId::devnet(),
                height: 9,
                round: 1,
                vote_type: VoteType::Precommit,
                block_hash,
                validator: validator.address(),
            },
            signature,
        };
        let first = vote(Hash256([0x10; 32]), SignatureBytes([0x55; 64]));
        let second = vote(Hash256([0x20; 32]), SignatureBytes([0x66; 64]));
        let forward = SlashingEvidence::DoubleVote(DoubleVoteEvidence {
            first: first.clone(),
            second: second.clone(),
        });
        let reverse = SlashingEvidence::DoubleVote(DoubleVoteEvidence {
            first: second,
            second: first,
        });
        assert_eq!(
            forward.hash().expect("fixture hashes"),
            reverse.hash().expect("reverse hashes")
        );
        assert_eq!(
            forward.hash().expect("fixture hashes").to_hex(),
            "4e38c4f195837efcb43185bb5237c15ccccd1f1e372e9df834b654bcec6be3ac"
        );
    }
}
