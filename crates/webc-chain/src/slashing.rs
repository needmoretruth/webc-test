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
        Self {
            double_sign_bps: 8_000,
            invalid_block_bps: 9_000,
            bridge_fraud_bps: 10_000,
            downtime_bps_per_missed_slot: 5,
            downtime_max_bps: 500,
        }
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
