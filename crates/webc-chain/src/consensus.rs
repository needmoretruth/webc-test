//! Consensus vote and stake-snapshot primitives.
//!
//! This module owns deterministic voting-power calculations, the deterministic
//! stake-weighted leader schedule, and conflict detection. It does not perform
//! networking, persistence, or block execution.
//! Vote payloads are signed over an explicit domain, protocol version, and chain
//! ID. This module verifies cryptographic authenticity but does not implement
//! networking, committee membership, finality rounds, or durable vote storage.

use crate::{
    canonical, Amount, Block, ChainError, ChainId, ChainState, ProtocolVersion, ValidatorStatus,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use webc_crypto::{verify_signature, Address, Hash256, Keypair, PublicKeyBytes, SignatureBytes};

/// Domain separator for version-1 consensus vote signatures.
pub const CONSENSUS_VOTE_DOMAIN: &str = "WEBC_CONSENSUS_VOTE_V1";

/// Domain separator for the version-1 deterministic leader schedule.
pub const LEADER_SCHEDULE_DOMAIN: &str = "WEBC_LEADER_SCHEDULE_V1";

/// Domain separator for version-1 signed block proposals.
pub const CONSENSUS_PROPOSAL_DOMAIN: &str = "WEBC_CONSENSUS_PROPOSAL_V1";

/// Maximum independently signed votes accepted in one proof or certificate.
///
/// A valid proof never needs more entries than the maximum finality-authority
/// set. Enforcing the same ceiling while deserializing prevents a hostile
/// length prefix from reserving an attacker-chosen collection and bounds the
/// later signature-verification loop.
pub const MAX_CONSENSUS_VOTES_PER_PROOF: usize =
    crate::finality_authority::MAX_FINALITY_AUTHORITIES_V1;

/// Voting power assigned to one validator for BFT consensus.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorPower {
    /// Validator-pool operator identity.
    pub validator: Address,
    /// Active voting power in native base units for this immutable snapshot.
    pub power: Amount,
    /// Registered Ed25519 consensus key that must sign this validator's votes and
    /// proposals. Carrying it inside the snapshot makes a finality certificate
    /// self-verifiable: a light client can check every signature against the
    /// snapshot alone, without a full copy of validator state.
    pub consensus_key: PublicKeyBytes,
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
                    consensus_key: validator.consensus_key,
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

    /// Returns the registered consensus key of a snapshot member, if present.
    pub fn consensus_key_of(&self, validator: Address) -> Option<PublicKeyBytes> {
        self.validators
            .get(&validator)
            .map(|entry| entry.consensus_key)
    }

    /// Verifies a signed vote against this snapshot: the validator must be a
    /// member and the signature must match the member's registered consensus key.
    ///
    /// This binds vote authenticity to the immutable snapshot, so a caller can
    /// trust a vote's voting power without a separate lookup into live state.
    pub fn verify_vote(
        &self,
        vote: &SignedVote,
        expected_protocol_version: ProtocolVersion,
        expected_chain_id: &ChainId,
    ) -> Result<(), ChainError> {
        let key = self
            .consensus_key_of(vote.payload.validator)
            .ok_or(ChainError::ConsensusValidatorNotInSet)?;
        vote.verify(expected_protocol_version, expected_chain_id, &key)
            .map_err(|_| ChainError::ConsensusSignatureInvalid)
    }

    /// Returns true when `power` is strictly greater than 2/3 of total power.
    ///
    /// BFT finality generally requires more than two thirds, not merely equal to
    /// two thirds, to preserve safety under Byzantine faults. A zero-power set
    /// can never reach quorum. See `strictly_exceeds_fraction` for the
    /// overflow-safe threshold arithmetic (finding C8).
    pub fn has_two_thirds_power(&self, power: Amount) -> bool {
        if self.total_power.is_zero() {
            return false;
        }
        strictly_exceeds_fraction(power.0, self.total_power.0, 2, 3)
    }

    /// Returns true when `power` is strictly greater than 1/3 of total power.
    ///
    /// This is the `f + 1` threshold: any set with more than one third of the
    /// power must contain at least one honest validator (given less than one
    /// third is Byzantine). Consensus uses it to safely catch up to a higher
    /// round that a super-minority has already advanced to.
    pub fn has_one_third_power(&self, power: Amount) -> bool {
        if self.total_power.is_zero() {
            return false;
        }
        strictly_exceeds_fraction(power.0, self.total_power.0, 1, 3)
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

/// A block proposal payload signed by the scheduled leader's consensus key.
///
/// The signature covers the proposed block *hash* (not the full block bytes), so
/// a verifier recomputes the block hash and checks it equals `block_hash` before
/// trusting the signature. Round is a consensus artifact and is not part of the
/// block header, so it is bound here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    /// Protocol configuration schema signed by the proposer.
    pub protocol_version: ProtocolVersion,
    /// Network replay-protection domain.
    pub chain_id: ChainId,
    /// Proposed block height counted from genesis.
    pub height: u64,
    /// BFT round number at this height.
    pub round: u32,
    /// Hash of the exact proposed block.
    pub block_hash: Hash256,
    /// The round in which this block previously gathered a prevote quorum (its
    /// proof-of-lock round), or `None` for a fresh proposal. A validator locked on
    /// a value in an earlier round may re-prevote a re-proposed block only when
    /// this authenticated round justifies it, which is what makes round changes
    /// both safe and live.
    pub valid_round: Option<u32>,
    /// Validator-pool operator identity that must be the scheduled leader.
    pub proposer: Address,
}

impl Proposal {
    fn signing_bytes(&self) -> Result<Vec<u8>, ChainError> {
        #[derive(Serialize)]
        struct SigningPayload<'a> {
            domain: &'static str,
            proposal: &'a Proposal,
        }
        canonical::canonical_json_bytes(&SigningPayload {
            domain: CONSENSUS_PROPOSAL_DOMAIN,
            proposal: self,
        })
    }
}

/// A [`Proposal`] plus the carried block, the proposer's consensus signature,
/// and — for a re-proposal — the proof-of-lock that authenticates its
/// `valid_round`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedProposal {
    /// Domain-separated payload covered by `signature`.
    pub payload: Proposal,
    /// The exact block whose hash must equal `payload.block_hash`.
    pub block: Block,
    /// Ed25519 signature from the proposer's registered consensus key.
    pub signature: SignatureBytes,
    /// The prevote quorum proving `payload.valid_round` legitimately locked
    /// `payload.block_hash` (the proof-of-lock, Tendermint rule 28). Empty for a
    /// fresh proposal (`valid_round == None`); for a re-proposal it carries a
    /// strictly-over-two-thirds set of prevotes for `(height, valid_round,
    /// block_hash)`. Each prevote is independently signed, so this set is
    /// self-authenticating and is deliberately **not** covered by the proposer's
    /// signature — a relay cannot forge it (that needs 2f+1 real signatures) and
    /// cannot repoint it (verification binds it to the signed `valid_round` and
    /// `block_hash`). Carrying it lets a node that missed round `valid_round`
    /// still follow the lock instead of prevoting nil forever (the C5 liveness
    /// fix).
    #[serde(default)]
    #[serde(deserialize_with = "bounded_votes::deserialize")]
    pub proof_of_lock: Vec<SignedVote>,
}

impl SignedProposal {
    /// Signs a fresh block proposal (no proof-of-lock) with the proposer's key.
    ///
    /// Use this only for a first proposal (`valid_round == None`). A re-proposal
    /// must carry its lock proof via [`Self::sign_with_proof_of_lock`], or
    /// [`Self::verify_in_set`] rejects it.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        protocol_version: ProtocolVersion,
        chain_id: ChainId,
        height: u64,
        round: u32,
        valid_round: Option<u32>,
        block: Block,
        proposer: Address,
        consensus_key: &Keypair,
    ) -> Result<Self, ChainError> {
        Self::sign_with_proof_of_lock(
            protocol_version,
            chain_id,
            height,
            round,
            valid_round,
            block,
            proposer,
            consensus_key,
            Vec::new(),
        )
    }

    /// Signs a proposal that carries a proof-of-lock prevote set (a re-proposal).
    ///
    /// The prevotes authenticate `valid_round`; they are self-signed and are not
    /// covered by the proposer's signature (see the field docs).
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_proof_of_lock(
        protocol_version: ProtocolVersion,
        chain_id: ChainId,
        height: u64,
        round: u32,
        valid_round: Option<u32>,
        block: Block,
        proposer: Address,
        consensus_key: &Keypair,
        proof_of_lock: Vec<SignedVote>,
    ) -> Result<Self, ChainError> {
        let block_hash = block.hash()?;
        let payload = Proposal {
            protocol_version,
            chain_id,
            height,
            round,
            block_hash,
            valid_round,
            proposer,
        };
        let signature = consensus_key.sign(&payload.signing_bytes()?);
        Ok(Self {
            payload,
            block,
            signature,
            proof_of_lock,
        })
    }

    /// Verifies the proposal against a snapshot: configuration match, that the
    /// carried block hashes to `payload.block_hash`, that the proposer is the
    /// scheduled leader for `(height, round)`, that the signature matches the
    /// proposer's registered consensus key, and that the proof-of-lock is
    /// consistent with `valid_round` (empty iff `None`, else a real 2f+1 prevote
    /// quorum for the cited round and this block).
    pub fn verify_in_set(
        &self,
        set: &ValidatorSet,
        expected_protocol_version: ProtocolVersion,
        expected_chain_id: &ChainId,
    ) -> Result<(), ChainError> {
        if self.payload.protocol_version != expected_protocol_version
            || &self.payload.chain_id != expected_chain_id
        {
            return Err(ChainError::ConsensusConfigMismatch);
        }
        // The signature only covers the hash, so bind the carried block to it.
        if self.block.hash()? != self.payload.block_hash {
            return Err(ChainError::ConsensusProposalBlockMismatch);
        }
        // Only the deterministically scheduled leader may propose this slot.
        if set.proposer_for(self.payload.height, self.payload.round) != Some(self.payload.proposer)
        {
            return Err(ChainError::ConsensusProposalNotFromLeader);
        }
        let key = set
            .consensus_key_of(self.payload.proposer)
            .ok_or(ChainError::ConsensusValidatorNotInSet)?;
        verify_signature(&key, &self.payload.signing_bytes()?, &self.signature)
            .map_err(|_| ChainError::ConsensusSignatureInvalid)?;
        self.verify_proof_of_lock(set, expected_protocol_version, expected_chain_id)
    }

    /// Verifies the proof-of-lock invariant (C5).
    ///
    /// A fresh proposal (`valid_round == None`) must carry no prevotes. A
    /// re-proposal (`valid_round == Some(vr)`) must cite an earlier round
    /// (`vr < round`) and attach a strictly-over-two-thirds prevote quorum for
    /// exactly `(height, vr, block_hash)`, each prevote from a distinct snapshot
    /// member with a valid signature.
    fn verify_proof_of_lock(
        &self,
        set: &ValidatorSet,
        expected_protocol_version: ProtocolVersion,
        expected_chain_id: &ChainId,
    ) -> Result<(), ChainError> {
        verify_proof_of_lock(
            set,
            expected_protocol_version,
            expected_chain_id,
            self.payload.height,
            self.payload.round,
            self.payload.valid_round,
            self.payload.block_hash,
            &self.proof_of_lock,
        )
    }
}

/// Verifies the proof-of-lock rule shared by legacy and protocol-2 proposals.
///
/// The proposal containers and their signing domains remain version-specific;
/// only this Tendermint safety rule is shared so the V4 path cannot drift from
/// the already-tested quorum semantics.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_proof_of_lock(
    set: &ValidatorSet,
    expected_protocol_version: ProtocolVersion,
    expected_chain_id: &ChainId,
    height: u64,
    proposal_round: u32,
    valid_round: Option<u32>,
    block_hash: Hash256,
    proof_of_lock: &[SignedVote],
) -> Result<(), ChainError> {
    if proof_of_lock.len() > MAX_CONSENSUS_VOTES_PER_PROOF {
        return Err(ChainError::ConsensusProofOfLockInvalid);
    }
    match valid_round {
        None => {
            if proof_of_lock.is_empty() {
                Ok(())
            } else {
                Err(ChainError::ConsensusProofOfLockInvalid)
            }
        }
        Some(valid_round) => {
            if valid_round >= proposal_round {
                return Err(ChainError::ConsensusProofOfLockInvalid);
            }
            let mut seen = BTreeSet::new();
            let mut power = Amount::ZERO;
            for vote in proof_of_lock {
                if vote.payload.vote_type != VoteType::Prevote
                    || vote.payload.height != height
                    || vote.payload.round != valid_round
                    || vote.payload.block_hash != block_hash
                    || vote.payload.protocol_version != expected_protocol_version
                    || &vote.payload.chain_id != expected_chain_id
                {
                    return Err(ChainError::ConsensusProofOfLockInvalid);
                }
                set.verify_vote(vote, expected_protocol_version, expected_chain_id)
                    .map_err(|_| ChainError::ConsensusProofOfLockInvalid)?;
                if !seen.insert(vote.payload.validator) {
                    return Err(ChainError::ConsensusProofOfLockInvalid);
                }
                power = power
                    .checked_add(set.power_of(vote.payload.validator))
                    .ok_or(ChainError::ArithmeticOverflow)?;
            }
            if !set.has_two_thirds_power(power) {
                return Err(ChainError::ConsensusProofOfLockInvalid);
            }
            Ok(())
        }
    }
}

/// A finality certificate: an aggregate of precommit votes proving that strictly
/// more than two thirds of a height's snapshot voting power committed to one
/// block at one round.
///
/// Together with the validator-set snapshot it is self-verifying, so a light
/// client can confirm a block is final without replaying execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityCertificate {
    /// Protocol configuration schema the precommits were signed under.
    pub protocol_version: ProtocolVersion,
    /// Network replay-protection domain.
    pub chain_id: ChainId,
    /// Finalized block height.
    pub height: u64,
    /// Round at which finality was reached.
    pub round: u32,
    /// Finalized block hash.
    pub block_hash: Hash256,
    /// Precommit votes, each for exactly this height/round/block.
    #[serde(deserialize_with = "bounded_votes::deserialize")]
    pub precommits: Vec<SignedVote>,
}

impl FinalityCertificate {
    /// Assembles a certificate from a pool of votes if the qualifying precommits
    /// reach quorum against `set`. Returns `None` when quorum is not met.
    ///
    /// Only precommits matching this exact height/round/block and verifying
    /// against a snapshot member's registered key are included, at most one per
    /// validator. This is the honest path a node uses once it observes quorum.
    pub fn build(
        set: &ValidatorSet,
        protocol_version: ProtocolVersion,
        chain_id: ChainId,
        height: u64,
        round: u32,
        block_hash: Hash256,
        pool: &[SignedVote],
    ) -> Option<Self> {
        let mut seen = BTreeSet::new();
        let mut precommits = Vec::new();
        let mut power = Amount::ZERO;
        for vote in pool {
            if vote.payload.vote_type != VoteType::Precommit
                || vote.payload.height != height
                || vote.payload.round != round
                || vote.payload.block_hash != block_hash
                || vote.payload.protocol_version != protocol_version
                || vote.payload.chain_id != chain_id
            {
                continue;
            }
            if set.verify_vote(vote, protocol_version, &chain_id).is_err() {
                continue;
            }
            if !seen.insert(vote.payload.validator) {
                continue;
            }
            power = power.checked_add(set.power_of(vote.payload.validator))?;
            precommits.push(vote.clone());
        }
        if !set.has_two_thirds_power(power) {
            return None;
        }
        Some(Self {
            protocol_version,
            chain_id,
            height,
            round,
            block_hash,
            precommits,
        })
    }

    /// Independently verifies a received certificate against a snapshot.
    ///
    /// Every precommit must match the certificate's exact fields and verify
    /// against a distinct snapshot member's registered consensus key, and the
    /// aggregate power must exceed two thirds. Any mismatch, foreign validator,
    /// duplicate, or bad signature rejects the whole certificate.
    pub fn verify(
        &self,
        set: &ValidatorSet,
        expected_protocol_version: ProtocolVersion,
        expected_chain_id: &ChainId,
    ) -> Result<(), ChainError> {
        if self.protocol_version != expected_protocol_version || &self.chain_id != expected_chain_id
        {
            return Err(ChainError::ConsensusConfigMismatch);
        }
        if self.precommits.len() > MAX_CONSENSUS_VOTES_PER_PROOF {
            return Err(ChainError::FinalityQuorumNotReached);
        }
        let mut seen = BTreeSet::new();
        let mut power = Amount::ZERO;
        for vote in &self.precommits {
            if vote.payload.vote_type != VoteType::Precommit
                || vote.payload.height != self.height
                || vote.payload.round != self.round
                || vote.payload.block_hash != self.block_hash
                || vote.payload.protocol_version != self.protocol_version
                || vote.payload.chain_id != self.chain_id
            {
                return Err(ChainError::ConsensusHeightRoundMismatch);
            }
            set.verify_vote(vote, expected_protocol_version, expected_chain_id)?;
            if !seen.insert(vote.payload.validator) {
                // A duplicated validator cannot pad power; reject the whole cert.
                return Err(ChainError::ConsensusValidatorNotInSet);
            }
            power = power
                .checked_add(set.power_of(vote.payload.validator))
                .ok_or(ChainError::ArithmeticOverflow)?;
        }
        if !set.has_two_thirds_power(power) {
            return Err(ChainError::FinalityQuorumNotReached);
        }
        Ok(())
    }
}

/// Serde visitor that enforces the vote-count ceiling before retaining entries.
pub(crate) mod bounded_votes {
    use std::{fmt, marker::PhantomData};

    use serde::de::{SeqAccess, Visitor};
    use serde::Deserializer;

    use super::{SignedVote, MAX_CONSENSUS_VOTES_PER_PROOF};

    /// Deserializes a vote sequence without trusting its advertised length.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<SignedVote>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VotesVisitor(PhantomData<SignedVote>);

        impl<'de> Visitor<'de> for VotesVisitor {
            type Value = Vec<SignedVote>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded consensus vote array")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if sequence
                    .size_hint()
                    .is_some_and(|hint| hint > MAX_CONSENSUS_VOTES_PER_PROOF)
                {
                    return Err(serde::de::Error::custom("too many consensus votes"));
                }
                let mut votes = Vec::with_capacity(
                    sequence
                        .size_hint()
                        .unwrap_or(0)
                        .min(MAX_CONSENSUS_VOTES_PER_PROOF),
                );
                while let Some(vote) = sequence.next_element()? {
                    if votes.len() == MAX_CONSENSUS_VOTES_PER_PROOF {
                        return Err(serde::de::Error::custom("too many consensus votes"));
                    }
                    votes.push(vote);
                }
                Ok(votes)
            }
        }

        deserializer.deserialize_seq(VotesVisitor(PhantomData))
    }
}

/// Returns whether `power` is strictly greater than `numerator/denominator` of
/// `total`, using overflow-safe integer arithmetic (finding C8).
///
/// The naive form `power * denominator > total * numerator` overflows `u128`
/// when `total` is near `u128::MAX` (for the 2/3 quorum, `total * 2`). This
/// instead computes `floor(total * numerator / denominator)` via the split
/// `(total / d) * n + ((total % d) * n) / d`. With `numerator < denominator`
/// (true for the 1/3 and 2/3 quorums) `(total / d) * n < total`, so no
/// intermediate exceeds `total` and nothing overflows. `power` strictly
/// exceeding that floor is exactly `power * d > total * n`, the intended strict
/// fraction test.
///
/// Precondition: `0 < numerator < denominator` and `denominator > 0`. Callers
/// pass only `(2, 3)` and `(1, 3)`.
fn strictly_exceeds_fraction(power: u128, total: u128, numerator: u128, denominator: u128) -> bool {
    let whole = total / denominator;
    let remainder = total % denominator;
    let threshold = whole * numerator + (remainder * numerator) / denominator;
    power > threshold
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Amount, Validator};
    use proptest::prelude::*;
    use webc_crypto::{Keypair, PublicKeyBytes};

    #[test]
    fn bounded_vote_decoder_rejects_declared_oversize_before_elements() {
        #[derive(Debug, Deserialize)]
        struct VoteList {
            #[serde(deserialize_with = "bounded_votes::deserialize")]
            #[allow(dead_code)]
            votes: Vec<SignedVote>,
        }
        #[derive(Serialize)]
        struct HostileList {
            votes: Vec<u8>,
        }

        // The element bytes intentionally are not SignedVote values. A bounded
        // visitor rejects the advertised count before attempting to decode even
        // the first element; without the size-hint check this would fail later
        // only after trusting the hostile collection length.
        let bytes = bincode::serialize(&HostileList {
            votes: vec![0; MAX_CONSENSUS_VOTES_PER_PROOF + 1],
        })
        .expect("hostile sequence encodes");
        let error = bincode::deserialize::<VoteList>(&bytes)
            .expect_err("oversized declared vote sequence must fail");
        assert!(error.to_string().contains("too many consensus votes"));
    }

    proptest! {
        // C8: the overflow-safe threshold matches the naive reference across the
        // range where the reference itself does not overflow.
        #[test]
        fn two_thirds_threshold_matches_reference(
            total in 0u128..=(u128::MAX / 3),
            power in 0u128..=(u128::MAX / 3),
        ) {
            prop_assert_eq!(
                strictly_exceeds_fraction(power, total, 2, 3),
                3 * power > 2 * total
            );
        }

        #[test]
        fn one_third_threshold_matches_reference(
            total in 0u128..=(u128::MAX / 3),
            power in 0u128..=(u128::MAX / 3),
        ) {
            prop_assert_eq!(
                strictly_exceeds_fraction(power, total, 1, 3),
                3 * power > total
            );
        }
    }

    #[test]
    fn two_thirds_threshold_does_not_overflow_near_u128_max() {
        // The naive `total * 2` would overflow here; the split form must not.
        let total = u128::MAX;
        // Exactly half the power is below the 2/3 line.
        assert!(!strictly_exceeds_fraction(total / 2, total, 2, 3));
        // All of it, and one below all of it, are above the 2/3 line.
        assert!(strictly_exceeds_fraction(total, total, 2, 3));
        assert!(strictly_exceeds_fraction(total - 1, total, 2, 3));
    }

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
                    // has_quorum_for assumes pre-verified votes, so a placeholder
                    // consensus key is sufficient here.
                    consensus_key: PublicKeyBytes([0u8; 32]),
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
                    // Proposer-weighting tests never verify signatures.
                    consensus_key: PublicKeyBytes([0u8; 32]),
                },
            );
        }
        ValidatorSet {
            validators,
            total_power: Amount::from_units(total),
        }
    }

    /// Builds a snapshot whose members carry their real consensus keys, so
    /// proposal and certificate signatures actually verify against it.
    fn set_with_keys(members: &[(&Keypair, u128)]) -> ValidatorSet {
        let mut validators = BTreeMap::new();
        let mut total = 0u128;
        for (keypair, power) in members {
            total += *power;
            let address = keypair.address();
            validators.insert(
                address,
                ValidatorPower {
                    validator: address,
                    power: Amount::from_units(*power),
                    consensus_key: keypair.public_key(),
                },
            );
        }
        ValidatorSet {
            validators,
            total_power: Amount::from_units(total),
        }
    }

    fn precommit(validator: &Keypair, height: u64, round: u32, block_hash: Hash256) -> SignedVote {
        SignedVote::sign(
            Vote {
                protocol_version: crate::CURRENT_PROTOCOL_VERSION,
                chain_id: ChainId::devnet(),
                height,
                round,
                vote_type: VoteType::Precommit,
                block_hash,
                validator: validator.address(),
            },
            validator,
        )
        .expect("deterministic precommit signs")
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

    /// A minimal well-formed block that hashes deterministically. It carries no
    /// transactions; consensus signing binds only to its header hash.
    fn sample_block(proposer: Address, height: u64, epoch: u64) -> Block {
        Block {
            header: crate::BlockHeader {
                protocol_version: crate::CURRENT_PROTOCOL_VERSION,
                chain_id: ChainId::devnet(),
                height,
                epoch,
                previous_hash: Hash256([0u8; 32]),
                state_root: Hash256([0x11; 32]),
                account_root: Hash256([0x22; 32]),
                tx_root: Hash256([0x33; 32]),
                receipt_root: Hash256([0x44; 32]),
                evidence_root: Hash256([0x55; 32]),
                proposer,
                timestamp_ms: 1_700_000_000_000,
                base_fee_per_unit: 1,
            },
            transactions: Vec::new(),
            receipts: Vec::new(),
            evidence: Vec::new(),
        }
    }

    #[test]
    fn signed_proposal_verifies_only_for_the_scheduled_leader() {
        let a = Keypair::from_seed([1u8; 32]);
        let b = Keypair::from_seed([2u8; 32]);
        let c = Keypair::from_seed([3u8; 32]);
        let set = set_with_keys(&[(&a, 1), (&b, 1), (&c, 1)]);
        let height = 5;
        let round = 0;
        let leader_addr = set.proposer_for(height, round).unwrap();
        let leader = [&a, &b, &c]
            .into_iter()
            .find(|k| k.address() == leader_addr)
            .unwrap();

        let block = sample_block(leader.address(), height, 0);
        let proposal = SignedProposal::sign(
            crate::CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            height,
            round,
            None,
            block,
            leader.address(),
            leader,
        )
        .unwrap();
        assert!(proposal
            .verify_in_set(&set, crate::CURRENT_PROTOCOL_VERSION, &ChainId::devnet())
            .is_ok());
    }

    #[test]
    fn signed_proposal_from_non_leader_is_rejected() {
        let a = Keypair::from_seed([1u8; 32]);
        let b = Keypair::from_seed([2u8; 32]);
        let c = Keypair::from_seed([3u8; 32]);
        let set = set_with_keys(&[(&a, 1), (&b, 1), (&c, 1)]);
        let height = 5;
        let round = 0;
        let leader_addr = set.proposer_for(height, round).unwrap();
        // Pick a non-leader signer and have it claim to propose.
        let usurper = [&a, &b, &c]
            .into_iter()
            .find(|k| k.address() != leader_addr)
            .unwrap();
        let block = sample_block(usurper.address(), height, 0);
        let proposal = SignedProposal::sign(
            crate::CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            height,
            round,
            None,
            block,
            usurper.address(),
            usurper,
        )
        .unwrap();
        assert!(matches!(
            proposal
                .verify_in_set(&set, crate::CURRENT_PROTOCOL_VERSION, &ChainId::devnet())
                .unwrap_err(),
            ChainError::ConsensusProposalNotFromLeader
        ));
    }

    #[test]
    fn signed_proposal_rejects_a_swapped_block() {
        let a = Keypair::from_seed([1u8; 32]);
        let set = set_with_keys(&[(&a, 1)]);
        let height = 1;
        let round = 0;
        let block = sample_block(a.address(), height, 0);
        let mut proposal = SignedProposal::sign(
            crate::CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            height,
            round,
            None,
            block,
            a.address(),
            &a,
        )
        .unwrap();
        // Swap in a different block whose hash no longer matches the signed hash.
        proposal.block = sample_block(a.address(), height, 9);
        assert!(matches!(
            proposal
                .verify_in_set(&set, crate::CURRENT_PROTOCOL_VERSION, &ChainId::devnet())
                .unwrap_err(),
            ChainError::ConsensusProposalBlockMismatch
        ));
    }

    #[test]
    fn certificate_builds_and_verifies_at_quorum() {
        let a = Keypair::from_seed([1u8; 32]);
        let b = Keypair::from_seed([2u8; 32]);
        let c = Keypair::from_seed([3u8; 32]);
        let set = set_with_keys(&[(&a, 1), (&b, 1), (&c, 1)]);
        let block_hash = Hash256::digest(b"finalized-block");
        let (height, round) = (10, 0);

        // Two of three validators precommit: 2/3 is NOT strictly greater than 2/3.
        let two = vec![
            precommit(&a, height, round, block_hash),
            precommit(&b, height, round, block_hash),
        ];
        assert!(FinalityCertificate::build(
            &set,
            crate::CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            height,
            round,
            block_hash,
            &two,
        )
        .is_none());

        // All three precommit: strictly greater than 2/3 -> a certificate forms.
        let three = vec![
            precommit(&a, height, round, block_hash),
            precommit(&b, height, round, block_hash),
            precommit(&c, height, round, block_hash),
        ];
        let cert = FinalityCertificate::build(
            &set,
            crate::CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            height,
            round,
            block_hash,
            &three,
        )
        .expect("quorum forms a certificate");
        assert!(cert
            .verify(&set, crate::CURRENT_PROTOCOL_VERSION, &ChainId::devnet())
            .is_ok());
    }

    #[test]
    fn certificate_rejects_a_foreign_validator_precommit() {
        let a = Keypair::from_seed([1u8; 32]);
        let b = Keypair::from_seed([2u8; 32]);
        let c = Keypair::from_seed([3u8; 32]);
        let outsider = Keypair::from_seed([99u8; 32]);
        let set = set_with_keys(&[(&a, 1), (&b, 1), (&c, 1)]);
        let block_hash = Hash256::digest(b"finalized-block");
        let (height, round) = (10, 0);

        // A hand-assembled certificate that pads power with a non-member vote.
        let cert = FinalityCertificate {
            protocol_version: crate::CURRENT_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            height,
            round,
            block_hash,
            precommits: vec![
                precommit(&a, height, round, block_hash),
                precommit(&b, height, round, block_hash),
                precommit(&outsider, height, round, block_hash),
            ],
        };
        assert!(matches!(
            cert.verify(&set, crate::CURRENT_PROTOCOL_VERSION, &ChainId::devnet())
                .unwrap_err(),
            ChainError::ConsensusValidatorNotInSet
        ));
    }

    #[test]
    fn certificate_rejects_a_duplicated_validator() {
        let a = Keypair::from_seed([1u8; 32]);
        let b = Keypair::from_seed([2u8; 32]);
        let c = Keypair::from_seed([3u8; 32]);
        let set = set_with_keys(&[(&a, 1), (&b, 1), (&c, 1)]);
        let block_hash = Hash256::digest(b"finalized-block");
        let (height, round) = (10, 0);
        // `a` counted twice must not manufacture quorum from a 1-of-3 minority.
        let cert = FinalityCertificate {
            protocol_version: crate::CURRENT_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            height,
            round,
            block_hash,
            precommits: vec![
                precommit(&a, height, round, block_hash),
                precommit(&a, height, round, block_hash),
                precommit(&b, height, round, block_hash),
            ],
        };
        assert!(cert
            .verify(&set, crate::CURRENT_PROTOCOL_VERSION, &ChainId::devnet())
            .is_err());
    }

    #[test]
    fn certificate_rejects_a_precommit_for_another_block() {
        let a = Keypair::from_seed([1u8; 32]);
        let b = Keypair::from_seed([2u8; 32]);
        let c = Keypair::from_seed([3u8; 32]);
        let set = set_with_keys(&[(&a, 1), (&b, 1), (&c, 1)]);
        let block_hash = Hash256::digest(b"finalized-block");
        let other_hash = Hash256::digest(b"other-block");
        let (height, round) = (10, 0);
        let cert = FinalityCertificate {
            protocol_version: crate::CURRENT_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            height,
            round,
            block_hash,
            precommits: vec![
                precommit(&a, height, round, block_hash),
                precommit(&b, height, round, block_hash),
                // A precommit for a different block hash smuggled into the cert.
                precommit(&c, height, round, other_hash),
            ],
        };
        assert!(matches!(
            cert.verify(&set, crate::CURRENT_PROTOCOL_VERSION, &ChainId::devnet())
                .unwrap_err(),
            ChainError::ConsensusHeightRoundMismatch
        ));
    }
}
