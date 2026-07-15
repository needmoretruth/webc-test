//! Consensus vote and stake-snapshot primitives.
//!
//! This module owns deterministic voting-power calculations, the deterministic
//! stake-weighted leader schedule, and conflict detection. It does not perform
//! networking, persistence, or block execution.
//! Vote payloads are signed over an explicit domain, protocol version, and chain
//! ID. This module verifies cryptographic authenticity but does not implement
//! networking, committee membership, finality rounds, or durable vote storage.

use crate::{canonical, Amount, ChainError, ChainId, ChainState, ProtocolVersion, ValidatorStatus};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use webc_crypto::{verify_signature, Address, Hash256, Keypair, PublicKeyBytes, SignatureBytes};

/// Domain separator for version-1 consensus vote signatures.
pub const CONSENSUS_VOTE_DOMAIN: &str = "WEBC_CONSENSUS_VOTE_V1";

/// Domain separator for the version-1 deterministic leader schedule.
pub const LEADER_SCHEDULE_DOMAIN: &str = "WEBC_LEADER_SCHEDULE_V1";

/// Voting power assigned to one validator for BFT consensus.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorPower {
    /// Validator-pool operator identity.
    pub validator: Address,
    /// Active voting power in native base units for this immutable snapshot.
    pub power: Amount,
}

/// Deterministic validator set snapshot for a height/epoch.
///
/// Production consensus must use a fixed snapshot per height/epoch so validators
/// cannot change voting power in the middle of a vote. This prototype struct is
/// intentionally immutable once built.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSet {
    /// Deterministically ordered operator-to-power map.
    pub validators: BTreeMap<Address, ValidatorPower>,
    /// Checked sum of every included validator's voting power.
    pub total_power: Amount,
}

impl ValidatorSet {
    /// Builds a validator set from current chain state.
    ///
    /// Only active pools with non-zero on-chain stake enter the snapshot. There
    /// is no bootstrap or synthetic voting power.
    pub fn from_state(state: &ChainState) -> Result<Self, ChainError> {
        let mut validators = BTreeMap::new();
        let mut total_power = Amount::ZERO;

        for validator in state.validators.values() {
            if !matches!(validator.status, ValidatorStatus::Active) {
                continue;
            }
            let stake_power = validator.total_stake()?;
            let power = stake_power;
            if power.is_zero() {
                continue;
            }
            total_power = total_power
                .checked_add(power)
                .ok_or(ChainError::ArithmeticOverflow)?;
            validators.insert(
                validator.operator,
                ValidatorPower {
                    validator: validator.operator,
                    power,
                },
            );
        }

        Ok(Self {
            validators,
            total_power,
        })
    }

    /// Deterministically selects the block proposer for a height and round,
    /// weighted by each validator's snapshot voting power.
    ///
    /// This is consensus-critical: every honest node must compute the identical
    /// proposer from the same snapshot. It therefore reads no clock and draws its
    /// only randomness from a domain-separated hash of `(height, round)`. A
    /// validator with more stake is proportionally more likely to be chosen, and
    /// the round input lets a stuck height rotate to a different proposer.
    ///
    /// Returns `None` only for an empty or zero-power set. The committee for this
    /// prototype is the whole active validator set; stake-weighted sub-committee
    /// sampling for very large sets is a later refinement.
    pub fn proposer_for(&self, height: u64, round: u32) -> Option<Address> {
        if self.validators.is_empty() || self.total_power.is_zero() {
            return None;
        }
        // Draw a value in `[0, total_power)`. Sixteen bytes of the hash form a
        // u128, matching the base-unit width of voting power.
        let seed = Hash256::digest_many([
            LEADER_SCHEDULE_DOMAIN.as_bytes(),
            &height.to_le_bytes(),
            &round.to_le_bytes(),
        ]);
        let draw_source = u128::from_le_bytes(
            seed.0[..16]
                .try_into()
                .expect("16 bytes fit a u128 from a 32-byte hash"),
        );
        let draw = draw_source % self.total_power.0;
        // Walk validators in their deterministic address order, accumulating
        // power until the running total passes the drawn point.
        let mut cumulative: u128 = 0;
        for entry in self.validators.values() {
            cumulative = cumulative.saturating_add(entry.power.0);
            if draw < cumulative {
                return Some(entry.validator);
            }
        }
        // Unreachable while `total_power` equals the summed powers, but fall back
        // deterministically to the last validator rather than returning `None`.
        self.validators.values().last().map(|entry| entry.validator)
    }

    /// Returns snapshot voting power, or zero when the validator is absent.
    pub fn power_of(&self, validator: Address) -> Amount {
        self.validators
            .get(&validator)
            .map(|entry| entry.power)
            .unwrap_or(Amount::ZERO)
    }

    /// Returns true when `power` is strictly greater than 2/3 of total power.
    ///
    /// BFT finality generally requires more than two thirds, not merely equal to
    /// two thirds, to preserve safety under Byzantine faults.
    pub fn has_two_thirds_power(&self, power: Amount) -> bool {
        if self.total_power.is_zero() {
            return false;
        }
        let whole = self.total_power.0 / 3;
        let remainder = self.total_power.0 % 3;
        let threshold = whole * 2 + (remainder * 2) / 3;
        power.0 > threshold
    }

    /// Checks whether unique matching votes represent strictly over two thirds.
    ///
    /// This arithmetic helper assumes signatures and snapshot membership were
    /// verified by the caller; Phase 4 consensus must enforce both before use.
    pub fn has_quorum_for(
        &self,
        votes: &[SignedVote],
        vote_type: VoteType,
        block_hash: Hash256,
    ) -> bool {
        let mut seen = BTreeSet::new();
        let mut power = Amount::ZERO;
        for vote in votes.iter().filter(|vote| {
            vote.payload.vote_type == vote_type && vote.payload.block_hash == block_hash
        }) {
            if seen.insert(vote.payload.validator) {
                let Some(next) = power.checked_add(self.power_of(vote.payload.validator)) else {
                    return false;
                };
                power = next;
            }
        }
        self.has_two_thirds_power(power)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum VoteType {
    Prevote,
    Precommit,
}

/// Consensus vote payload committed by a validator consensus key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    /// Protocol configuration schema signed by the validator.
    pub protocol_version: ProtocolVersion,
    /// Network replay-protection domain.
    pub chain_id: ChainId,
    /// Proposed block height counted from genesis.
    pub height: u64,
    /// BFT round number at this height.
    pub round: u32,
    /// Prevote or precommit stage.
    pub vote_type: VoteType,
    /// Exact proposed block hash.
    pub block_hash: Hash256,
    /// Validator-pool operator identity whose consensus key must verify.
    pub validator: Address,
}

impl Vote {
    fn signing_bytes(&self) -> Result<Vec<u8>, ChainError> {
        #[derive(Serialize)]
        struct SigningPayload<'a> {
            domain: &'static str,
            vote: &'a Vote,
        }
        canonical::canonical_json_bytes(&SigningPayload {
            domain: CONSENSUS_VOTE_DOMAIN,
            vote: self,
        })
    }
}

/// Vote plus the Ed25519 signature produced by the registered consensus key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedVote {
    /// Domain-separated payload covered by `signature`.
    pub payload: Vote,
    /// Ed25519 signature from the validator's registered consensus key.
    pub signature: SignatureBytes,
}

impl SignedVote {
    /// Signs one explicit vote payload with a validator consensus key.
    pub fn sign(payload: Vote, consensus_key: &Keypair) -> Result<Self, ChainError> {
        let signature = consensus_key.sign(&payload.signing_bytes()?);
        Ok(Self { payload, signature })
    }

    /// Verifies domain, chain, protocol version, registered key, and signature.
    pub fn verify(
        &self,
        expected_protocol_version: ProtocolVersion,
        expected_chain_id: &ChainId,
        registered_consensus_key: &PublicKeyBytes,
    ) -> Result<(), ChainError> {
        if self.payload.protocol_version != expected_protocol_version
            || &self.payload.chain_id != expected_chain_id
        {
            return Err(ChainError::InvalidSlashingEvidence);
        }
        verify_signature(
            registered_consensus_key,
            &self.payload.signing_bytes()?,
            &self.signature,
        )
        .map_err(|_| ChainError::InvalidSlashingEvidence)
    }
}

/// Two signed votes that may prove equivocation in one exact BFT step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoubleVoteEvidence {
    /// First signed vote observed for the step.
    pub first: SignedVote,
    /// Conflicting signed vote observed for the same step.
    pub second: SignedVote,
}

/// Detects validators that voted for conflicting blocks in the same step.
///
/// The function only detects conflicts in already-verified vote payloads. Future
/// consensus code must verify signatures before passing votes here.
pub fn detect_double_votes(votes: &[SignedVote]) -> Vec<DoubleVoteEvidence> {
    let mut first_seen: BTreeMap<
        (ProtocolVersion, ChainId, Address, u64, u32, VoteType),
        SignedVote,
    > = BTreeMap::new();
    let mut evidence = Vec::new();

    for vote in votes {
        let key = (
            vote.payload.protocol_version,
            vote.payload.chain_id.clone(),
            vote.payload.validator,
            vote.payload.height,
            vote.payload.round,
            vote.payload.vote_type,
        );
        if let Some(first) = first_seen.get(&key) {
            if first.payload.block_hash != vote.payload.block_hash {
                evidence.push(DoubleVoteEvidence {
                    first: first.clone(),
                    second: vote.clone(),
                });
            }
        } else {
            first_seen.insert(key, vote.clone());
        }
    }

    evidence
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Amount, Validator};
    use webc_crypto::{Keypair, PublicKeyBytes};

    fn vote(validator: &Keypair, block_hash: Hash256) -> SignedVote {
        SignedVote::sign(
            Vote {
                protocol_version: crate::CURRENT_PROTOCOL_VERSION,
                chain_id: ChainId::devnet(),
                height: 1,
                round: 0,
                vote_type: VoteType::Precommit,
                block_hash,
                validator: validator.address(),
            },
            validator,
        )
        .expect("deterministic test vote signs")
    }

    #[test]
    fn quorum_requires_more_than_two_thirds() {
        let a = Keypair::from_seed([1u8; 32]).address();
        let b = Keypair::from_seed([2u8; 32]).address();
        let c = Keypair::from_seed([3u8; 32]).address();
        let mut validators = BTreeMap::new();
        for address in [a, b, c] {
            validators.insert(
                address,
                ValidatorPower {
                    validator: address,
                    power: Amount::from_units(1),
                },
            );
        }
        let set = ValidatorSet {
            validators,
            total_power: Amount::from_units(3),
        };
        let block = Hash256::digest(b"block");
        assert!(!set.has_quorum_for(
            &[
                vote(&Keypair::from_seed([1u8; 32]), block),
                vote(&Keypair::from_seed([2u8; 32]), block)
            ],
            VoteType::Precommit,
            block
        ));
        assert!(set.has_quorum_for(
            &[
                vote(&Keypair::from_seed([1u8; 32]), block),
                vote(&Keypair::from_seed([2u8; 32]), block),
                vote(&Keypair::from_seed([3u8; 32]), block),
            ],
            VoteType::Precommit,
            block
        ));
    }

    fn set_with_powers(powers: &[(Address, u128)]) -> ValidatorSet {
        let mut validators = BTreeMap::new();
        let mut total = 0u128;
        for (address, power) in powers {
            total += *power;
            validators.insert(
                *address,
                ValidatorPower {
                    validator: *address,
                    power: Amount::from_units(*power),
                },
            );
        }
        ValidatorSet {
            validators,
            total_power: Amount::from_units(total),
        }
    }

    #[test]
    fn proposer_is_deterministic_and_within_the_set() {
        let a = Keypair::from_seed([1u8; 32]).address();
        let b = Keypair::from_seed([2u8; 32]).address();
        let c = Keypair::from_seed([3u8; 32]).address();
        let set = set_with_powers(&[(a, 1), (b, 1), (c, 1)]);

        for height in 0..25u64 {
            for round in 0..4u32 {
                let first = set.proposer_for(height, round).unwrap();
                // Identical inputs always yield the identical proposer.
                assert_eq!(set.proposer_for(height, round), Some(first));
                // The chosen proposer is always a member of the set.
                assert!([a, b, c].contains(&first));
            }
        }
    }

    #[test]
    fn empty_or_zero_power_set_has_no_proposer() {
        let empty = ValidatorSet {
            validators: BTreeMap::new(),
            total_power: Amount::ZERO,
        };
        assert_eq!(empty.proposer_for(0, 0), None);

        let a = Keypair::from_seed([1u8; 32]).address();
        let zero = set_with_powers(&[(a, 0)]);
        assert_eq!(zero.proposer_for(0, 0), None);
    }

    #[test]
    fn single_validator_always_proposes() {
        let only = Keypair::from_seed([5u8; 32]).address();
        let set = set_with_powers(&[(only, 42)]);
        for height in 0..10u64 {
            assert_eq!(set.proposer_for(height, 0), Some(only));
        }
    }

    #[test]
    fn proposer_selection_is_stake_weighted() {
        // A validator with ~9x the stake should be proposer far more often.
        let heavy = Keypair::from_seed([10u8; 32]).address();
        let light = Keypair::from_seed([11u8; 32]).address();
        let set = set_with_powers(&[(heavy, 90), (light, 10)]);

        let mut heavy_count = 0u32;
        let samples = 1_000u64;
        for height in 0..samples {
            if set.proposer_for(height, 0) == Some(heavy) {
                heavy_count += 1;
            }
        }
        // Expect roughly 900/1000; assert a wide band to stay robust while still
        // proving weighting works (a fair coin would land near 500).
        assert!(
            (820..=960).contains(&heavy_count),
            "heavy validator won {heavy_count}/1000, expected ~900"
        );
    }

    #[test]
    fn round_change_can_rotate_the_proposer() {
        // Across rounds at one height, more than one distinct proposer appears in
        // a balanced set, so a stuck round can hand off to someone else.
        let a = Keypair::from_seed([1u8; 32]).address();
        let b = Keypair::from_seed([2u8; 32]).address();
        let c = Keypair::from_seed([3u8; 32]).address();
        let set = set_with_powers(&[(a, 1), (b, 1), (c, 1)]);
        let distinct: BTreeSet<Address> = (0..12u32)
            .filter_map(|round| set.proposer_for(7, round))
            .collect();
        assert!(distinct.len() >= 2, "rounds never rotated the proposer");
    }

    #[test]
    fn detects_double_votes() {
        let validator = Keypair::from_seed([9u8; 32]);
        let votes = vec![
            vote(&validator, Hash256::digest(b"block-a")),
            vote(&validator, Hash256::digest(b"block-b")),
        ];
        let evidence = detect_double_votes(&votes);
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].first.payload.validator, validator.address());
    }

    #[test]
    fn vote_signing_payload_is_stable_across_languages() {
        let validator = Keypair::from_seed([1u8; 32]);
        let vote = Vote {
            protocol_version: crate::CURRENT_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            height: 42,
            round: 3,
            vote_type: VoteType::Precommit,
            block_hash: Hash256::digest(b"block-a"),
            validator: validator.address(),
        };
        let actual = String::from_utf8(vote.signing_bytes().expect("payload serializes"))
            .expect("canonical JSON is UTF-8");
        assert_eq!(
            actual,
            r#"{"domain":"WEBC_CONSENSUS_VOTE_V1","vote":{"block_hash":"1ca3c063ae95ef8d4f6d50f694a5df3b47df5a4aec6dada057c85c5dfdff0090","chain_id":"webc-devnet-1","height":42,"protocol_version":1,"round":3,"validator":"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3","vote_type":"Precommit"}}"#
        );
    }

    #[test]
    fn validator_set_ignores_unstaked_legacy_bootstrap_records() {
        let key = Keypair::from_seed([7u8; 32]);
        let mut state = ChainState::default();
        state.validators.insert(
            key.address(),
            Validator {
                operator: key.address(),
                consensus_key: PublicKeyBytes([1u8; 32]),
                self_stake: Amount::ZERO,
                delegated_stake: Amount::ZERO,
                commission_bps: 500,
                status: ValidatorStatus::Active,
                bootstrap: true,
                accumulated_rewards: Amount::ZERO,
            },
        );

        let set = ValidatorSet::from_state(&state).expect("validator set builds");
        assert_eq!(set.total_power, Amount::ZERO);
        assert_eq!(set.power_of(key.address()), Amount::ZERO);
    }
}
