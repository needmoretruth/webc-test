//! Protocol-2 signed V4 consensus proposals.
//!
//! Purpose: carry one V4 block and the concrete authority snapshot committed for
//! its successor under a proposal signature domain that legacy nodes can never
//! reinterpret. Responsibilities: bind proposal metadata to the V4 header,
//! validate current/next authority commitments, enforce proposer scheduling,
//! authenticate the proposer, and reuse the established proof-of-lock quorum
//! rule. Non-responsibilities: run consensus rounds, execute blocks, persist a
//! certificate, select transactions, or perform networking.
//!
//! Data flow: a leader builds a deterministic [`BlockV4`] and its derived next
//! authority set, then signs their committed block hash with [`SignedProposalV1`].
//! A validator checks this envelope against the current immutable authority set
//! before replaying the block or voting. The next set is transported as data but
//! trusted only after its commitment and epoch transition validate.
//!
//! Security boundary: proposals are hostile. Bounded collection visitors reject
//! oversized authority and lock-proof arrays during decoding; verification then
//! performs cheap domain/header/commitment checks before signature loops. The V2
//! domain deliberately differs from frozen legacy proposal bytes.

use serde::{Deserialize, Serialize};
use webc_crypto::{verify_signature, Keypair, SignatureBytes};

use crate::{
    canonical::canonical_json_bytes, consensus::verify_proof_of_lock, BlockV4, BlockV4Error,
    ChainError, FinalityAuthoritySetErrorV1, FinalityAuthoritySetV1, Proposal, SignedVote,
    TRANSACTION_V5_PROTOCOL_VERSION,
};

/// Domain separator for protocol-2 proposals carrying V4 blocks.
pub const CONSENSUS_PROPOSAL_V2_DOMAIN: &str = "WEBC_CONSENSUS_PROPOSAL_V2";

/// A protocol-2 proposal plus its V4 block and concrete successor authority set.
///
/// The signature covers [`Proposal`], whose `block_hash` is the V4 header hash.
/// That header commits the next authority-set root, so a relay cannot substitute
/// either the block or authority set without invalidating verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedProposalV1 {
    /// Domain-separated proposal metadata covered by `signature`.
    pub payload: Proposal,
    /// Exact protocol-2 block whose header hash equals `payload.block_hash`.
    pub block: BlockV4,
    /// Concrete set committed by `block.header.next_finality_authority_set_root`.
    pub next_authority_set: FinalityAuthoritySetV1,
    /// Signature from the scheduled proposer's registered consensus key.
    pub signature: SignatureBytes,
    /// Self-authenticating prevote quorum for `payload.valid_round`.
    #[serde(default)]
    #[serde(deserialize_with = "crate::consensus::bounded_votes::deserialize")]
    pub proof_of_lock: Vec<SignedVote>,
}

impl SignedProposalV1 {
    /// Signs a fresh V4 proposal with no proof-of-lock.
    ///
    /// Protocol, chain, height, proposer, and block hash are derived from the
    /// validated block rather than accepted as duplicate caller inputs.
    pub fn sign(
        round: u32,
        block: BlockV4,
        next_authority_set: FinalityAuthoritySetV1,
        consensus_key: &Keypair,
    ) -> Result<Self, ProposalV1Error> {
        Self::sign_with_proof_of_lock(
            round,
            None,
            block,
            next_authority_set,
            None,
            consensus_key,
            Vec::new(),
        )
    }

    /// Signs a V4 re-proposal carrying the prevote quorum for `valid_round`.
    ///
    /// The lock votes remain independently signed and are intentionally outside
    /// the proposer signature; verification binds every vote to the signed hash,
    /// height, chain, protocol, and cited earlier round.
    pub fn sign_with_proof_of_lock(
        round: u32,
        valid_round: Option<u32>,
        block: BlockV4,
        next_authority_set: FinalityAuthoritySetV1,
        reproposer: Option<webc_crypto::Address>,
        consensus_key: &Keypair,
        proof_of_lock: Vec<SignedVote>,
    ) -> Result<Self, ProposalV1Error> {
        if proof_of_lock.len() > crate::MAX_CONSENSUS_VOTES_PER_PROOF {
            return Err(ProposalV1Error::ProofOfLockInvalid);
        }
        block.validate()?;
        validate_next_authority_binding(&block, &next_authority_set)?;
        let proposer = reproposer.unwrap_or(block.header.proposer);
        if valid_round.is_none() && proposer != block.header.proposer {
            return Err(ProposalV1Error::HeaderBindingMismatch);
        }
        let payload = Proposal {
            protocol_version: block.header.protocol_version,
            chain_id: block.header.chain_id.clone(),
            height: block.header.height.get(),
            round,
            block_hash: block.header.hash()?,
            valid_round,
            proposer,
        };
        let signature = consensus_key.sign(&proposal_signing_bytes(&payload)?);
        Ok(Self {
            payload,
            block,
            next_authority_set,
            signature,
            proof_of_lock,
        })
    }

    /// Verifies this proposal against the exact outgoing authority snapshot.
    ///
    /// This method verifies structure and cryptographic consensus placement; it
    /// does not execute the block. Callers must replay the validated block against
    /// committed state before prevoting it.
    pub fn verify_in_authority_set(
        &self,
        current_authority_set: &FinalityAuthoritySetV1,
    ) -> Result<(), ProposalV1Error> {
        if self.proof_of_lock.len() > crate::MAX_CONSENSUS_VOTES_PER_PROOF {
            return Err(ProposalV1Error::ProofOfLockInvalid);
        }
        current_authority_set.validate()?;
        if self.payload.protocol_version != TRANSACTION_V5_PROTOCOL_VERSION
            || self.block.header.protocol_version != TRANSACTION_V5_PROTOCOL_VERSION
            || self.payload.chain_id != current_authority_set.chain_id
            || self.block.header.chain_id != current_authority_set.chain_id
        {
            return Err(ProposalV1Error::ConfigurationMismatch);
        }
        self.block.validate()?;
        if self.payload.height != self.block.header.height.get()
            || (self.payload.valid_round.is_none()
                && self.payload.proposer != self.block.header.proposer)
        {
            return Err(ProposalV1Error::HeaderBindingMismatch);
        }
        if self.payload.block_hash != self.block.header.hash()? {
            return Err(ProposalV1Error::BlockHashMismatch);
        }
        if current_authority_set.epoch != self.block.header.epoch
            || current_authority_set.commitment()? != self.block.header.finality_authority_set_root
        {
            return Err(ProposalV1Error::CurrentAuthoritySetMismatch);
        }
        validate_next_authority_binding(&self.block, &self.next_authority_set)?;
        if self.next_authority_set.epoch == current_authority_set.epoch
            && self.next_authority_set != *current_authority_set
        {
            return Err(ProposalV1Error::NextAuthoritySetMismatch);
        }

        let validator_set = current_authority_set.to_validator_set()?;
        if validator_set.proposer_for(self.payload.height, self.payload.round)
            != Some(self.payload.proposer)
        {
            return Err(ProposalV1Error::NotScheduledLeader);
        }
        let key = validator_set
            .consensus_key_of(self.payload.proposer)
            .ok_or(ProposalV1Error::NotCurrentAuthority)?;
        verify_signature(
            &key,
            &proposal_signing_bytes(&self.payload)?,
            &self.signature,
        )
        .map_err(|_| ProposalV1Error::InvalidSignature)?;
        verify_proof_of_lock(
            &validator_set,
            TRANSACTION_V5_PROTOCOL_VERSION,
            &current_authority_set.chain_id,
            self.payload.height,
            self.payload.round,
            self.payload.valid_round,
            self.payload.block_hash,
            &self.proof_of_lock,
        )
        .map_err(|_| ProposalV1Error::ProofOfLockInvalid)
    }
}

fn validate_next_authority_binding(
    block: &BlockV4,
    next_authority_set: &FinalityAuthoritySetV1,
) -> Result<(), ProposalV1Error> {
    next_authority_set.validate()?;
    if next_authority_set.protocol_version != TRANSACTION_V5_PROTOCOL_VERSION
        || next_authority_set.chain_id != block.header.chain_id
    {
        return Err(ProposalV1Error::ConfigurationMismatch);
    }
    let epoch_is_current = next_authority_set.epoch == block.header.epoch;
    let epoch_is_next = block
        .header
        .epoch
        .checked_next()
        .is_some_and(|next| next_authority_set.epoch == next);
    if !epoch_is_current && !epoch_is_next {
        return Err(ProposalV1Error::InvalidNextEpoch);
    }
    if next_authority_set.commitment()? != block.header.next_finality_authority_set_root {
        return Err(ProposalV1Error::NextAuthoritySetMismatch);
    }
    Ok(())
}

fn proposal_signing_bytes(payload: &Proposal) -> Result<Vec<u8>, ProposalV1Error> {
    #[derive(Serialize)]
    struct SigningPayload<'a> {
        domain: &'static str,
        proposal: &'a Proposal,
    }
    canonical_json_bytes(&SigningPayload {
        domain: CONSENSUS_PROPOSAL_V2_DOMAIN,
        proposal: payload,
    })
    .map_err(ProposalV1Error::CanonicalEncoding)
}

/// Fail-closed protocol-2 proposal validation errors.
#[derive(Debug, thiserror::Error)]
pub enum ProposalV1Error {
    /// Proposal, block, and authority snapshots disagree on protocol or chain.
    #[error("protocol-2 proposal configuration does not match its authority set")]
    ConfigurationMismatch,
    /// Proposal height/proposer does not match the carried V4 header.
    #[error("protocol-2 proposal metadata does not match its V4 header")]
    HeaderBindingMismatch,
    /// Signed proposal hash does not equal the carried V4 header hash.
    #[error("protocol-2 proposal hash does not match its V4 block")]
    BlockHashMismatch,
    /// Current authority epoch or commitment does not match the V4 header.
    #[error("protocol-2 proposal current authority commitment is invalid")]
    CurrentAuthoritySetMismatch,
    /// Carried successor authority set does not match the signed header.
    #[error("protocol-2 proposal next authority commitment is invalid")]
    NextAuthoritySetMismatch,
    /// Successor set epoch is neither the current epoch nor its single successor.
    #[error("protocol-2 proposal next authority epoch is invalid")]
    InvalidNextEpoch,
    /// Claimed proposer is not present in the outgoing authority set.
    #[error("protocol-2 proposal proposer is not a current authority")]
    NotCurrentAuthority,
    /// Claimed proposer is not scheduled for this height and round.
    #[error("protocol-2 proposal was not signed by the scheduled leader")]
    NotScheduledLeader,
    /// Proposer signature is invalid under the registered consensus key.
    #[error("protocol-2 proposal signature is invalid")]
    InvalidSignature,
    /// Proof-of-lock is oversized, malformed, mismatched, duplicated, or lacks quorum.
    #[error("protocol-2 proposal proof-of-lock is invalid")]
    ProofOfLockInvalid,
    /// Carried V4 block failed structural/signature/root validation.
    #[error("protocol-2 proposal block is invalid: {0}")]
    Block(#[source] Box<BlockV4Error>),
    /// Current or next finality authority snapshot is malformed.
    #[error("protocol-2 proposal authority set is invalid: {0}")]
    Authority(#[from] FinalityAuthoritySetErrorV1),
    /// Canonical proposal signing bytes could not be produced.
    #[error("protocol-2 proposal signing bytes are invalid: {0}")]
    CanonicalEncoding(ChainError),
}

impl From<BlockV4Error> for ProposalV1Error {
    fn from(error: BlockV4Error) -> Self {
        Self::Block(Box::new(error))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use webc_crypto::{Address, Hash256, Keypair};

    use super::*;
    use crate::{
        evidence_root, receipt_root_v1, transaction_root_v1, Amount, BlockHeaderV4, BlockHeight,
        ChainId, Epoch, ValidatorPower, ValidatorSet, Vote, VoteType,
    };

    fn fixture() -> (Vec<Keypair>, FinalityAuthoritySetV1, BlockV4, usize) {
        let keys = vec![
            Keypair::from_seed([1; 32]),
            Keypair::from_seed([2; 32]),
            Keypair::from_seed([3; 32]),
        ];
        let validators = keys
            .iter()
            .map(|key| {
                (
                    key.address(),
                    ValidatorPower {
                        validator: key.address(),
                        power: Amount::from_units(1),
                        consensus_key: key.public_key(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let set = ValidatorSet {
            validators,
            total_power: Amount::from_units(3),
        };
        let authority = FinalityAuthoritySetV1::from_validator_set(
            TRANSACTION_V5_PROTOCOL_VERSION,
            ChainId::devnet(),
            Epoch::new(0),
            &set,
        )
        .expect("authority fixture validates");
        let height = BlockHeight::new(1);
        let round = 0;
        let proposer = set
            .proposer_for(height.get(), round)
            .expect("non-empty set has proposer");
        let leader_index = keys
            .iter()
            .position(|key| key.address() == proposer)
            .expect("proposer key is present");
        let block = BlockV4 {
            header: BlockHeaderV4 {
                protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
                chain_id: ChainId::devnet(),
                height,
                epoch: Epoch::new(0),
                previous_hash: Hash256::digest(b"parent"),
                state_root: Hash256::digest(b"state"),
                account_root: Hash256::digest(b"accounts"),
                tx_root: transaction_root_v1(height, &[]).expect("empty tx root"),
                receipt_root: receipt_root_v1(&[]).expect("empty receipt root"),
                evidence_root: evidence_root(&[]).expect("empty evidence root"),
                finality_authority_set_root: authority.commitment().expect("current root"),
                next_finality_authority_set_root: authority.commitment().expect("next root"),
                proposer,
                timestamp_ms: 1,
                base_fee_per_unit: 1,
            },
            transactions: Vec::new(),
            receipts: Vec::new(),
            evidence: Vec::new(),
        };
        (keys, authority, block, leader_index)
    }

    #[test]
    fn v4_proposal_verifies_under_distinct_v2_domain() {
        let (keys, authority, block, leader_index) = fixture();
        let proposal = SignedProposalV1::sign(0, block, authority.clone(), &keys[leader_index])
            .expect("proposal signs");
        proposal
            .verify_in_authority_set(&authority)
            .expect("proposal verifies");
        let signing_json = String::from_utf8(
            proposal_signing_bytes(&proposal.payload).expect("signing bytes encode"),
        )
        .expect("canonical JSON is UTF-8");
        assert!(signing_json.contains("WEBC_CONSENSUS_PROPOSAL_V2"));
        assert!(!signing_json.contains("WEBC_CONSENSUS_PROPOSAL_V1"));
    }

    #[test]
    fn proposal_rejects_wrong_next_authority_commitment() {
        let (keys, authority, block, leader_index) = fixture();
        let mut proposal = SignedProposalV1::sign(0, block, authority.clone(), &keys[leader_index])
            .expect("proposal signs");
        proposal.next_authority_set.authorities[0].voting_power = Amount::from_units(2);
        proposal.next_authority_set.total_power = Amount::from_units(4);
        assert!(matches!(
            proposal.verify_in_authority_set(&authority),
            Err(ProposalV1Error::NextAuthoritySetMismatch)
        ));
    }

    #[test]
    fn proposal_rejects_header_metadata_substitution() {
        let (keys, authority, block, leader_index) = fixture();
        let mut proposal = SignedProposalV1::sign(0, block, authority.clone(), &keys[leader_index])
            .expect("proposal signs");
        proposal.payload.height = 2;
        assert!(matches!(
            proposal.verify_in_authority_set(&authority),
            Err(ProposalV1Error::HeaderBindingMismatch)
        ));
    }

    #[test]
    fn reproposal_accepts_only_matching_quorum_lock_proof() {
        let (keys, authority, block, _) = fixture();
        let block_hash = block.header.hash().expect("block hashes");
        let proof = keys
            .iter()
            .map(|key| {
                SignedVote::sign(
                    Vote {
                        protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
                        chain_id: ChainId::devnet(),
                        height: 1,
                        round: 0,
                        vote_type: VoteType::Prevote,
                        block_hash,
                        validator: key.address(),
                    },
                    key,
                )
                .expect("vote signs")
            })
            .collect();
        let set = authority.to_validator_set().expect("set converts");
        let original_proposer = block.header.proposer;
        let round = (1..=32)
            .find(|round| set.proposer_for(1, *round) != Some(original_proposer))
            .expect("later round rotates to a different proposer");
        let leader = set.proposer_for(1, round).expect("leader exists");
        let leader_key = keys
            .iter()
            .find(|key| key.address() == leader)
            .expect("leader key exists");
        let proposal = SignedProposalV1::sign_with_proof_of_lock(
            round,
            Some(0),
            block,
            authority.clone(),
            Some(leader),
            leader_key,
            proof,
        )
        .expect("reproposal signs");
        proposal
            .verify_in_authority_set(&authority)
            .expect("quorum lock proof verifies");
        assert_ne!(proposal.payload.proposer, proposal.block.header.proposer);
    }

    #[test]
    fn proposal_rejects_non_leader_even_with_valid_consensus_key() {
        let (keys, authority, mut block, leader_index) = fixture();
        let usurper = (leader_index + 1) % keys.len();
        block.header.proposer = keys[usurper].address();
        let proposal = SignedProposalV1::sign(0, block, authority.clone(), &keys[usurper])
            .expect("shape can be signed");
        assert!(matches!(
            proposal.verify_in_authority_set(&authority),
            Err(ProposalV1Error::NotScheduledLeader)
        ));
    }

    #[test]
    fn same_epoch_next_set_must_equal_current_set() {
        let (keys, authority, mut block, leader_index) = fixture();
        let mut other = authority.clone();
        other.authorities[0].voting_power = Amount::from_units(2);
        other.total_power = Amount::from_units(4);
        block.header.next_finality_authority_set_root = other.commitment().expect("other root");
        let proposal = SignedProposalV1::sign(0, block, other, &keys[leader_index])
            .expect("committed alternate set signs");
        assert!(matches!(
            proposal.verify_in_authority_set(&authority),
            Err(ProposalV1Error::NextAuthoritySetMismatch)
        ));
    }

    #[test]
    fn wrong_chain_is_rejected_before_signature_verification() {
        let (keys, authority, block, leader_index) = fixture();
        let mut proposal = SignedProposalV1::sign(0, block, authority.clone(), &keys[leader_index])
            .expect("proposal signs");
        proposal.payload.chain_id = ChainId::new("webc-foreign-1").expect("valid chain id");
        assert!(matches!(
            proposal.verify_in_authority_set(&authority),
            Err(ProposalV1Error::ConfigurationMismatch)
        ));
    }

    #[test]
    fn invalid_signature_is_rejected() {
        let (keys, authority, block, leader_index) = fixture();
        let mut proposal = SignedProposalV1::sign(0, block, authority.clone(), &keys[leader_index])
            .expect("proposal signs");
        proposal.signature.0[0] ^= 1;
        assert!(matches!(
            proposal.verify_in_authority_set(&authority),
            Err(ProposalV1Error::InvalidSignature)
        ));
    }

    #[test]
    fn current_authority_commitment_is_checked() {
        let (keys, authority, mut block, leader_index) = fixture();
        block.header.finality_authority_set_root = Hash256::digest(b"wrong set");
        let proposal = SignedProposalV1::sign(0, block, authority.clone(), &keys[leader_index])
            .expect("proposal signs");
        assert!(matches!(
            proposal.verify_in_authority_set(&authority),
            Err(ProposalV1Error::CurrentAuthoritySetMismatch)
        ));
    }

    #[test]
    fn fixture_has_expected_operator_identity() {
        let (_, authority, block, _) = fixture();
        let operators = authority
            .authorities
            .iter()
            .map(|entry| entry.validator_id.operator())
            .collect::<Vec<Address>>();
        assert!(operators.contains(&block.header.proposer));
    }
}
