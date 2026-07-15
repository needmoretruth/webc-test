//! Deterministic single-height BFT round state machine.
//!
//! Purpose: drive one consensus height through the happy-path sequence
//! propose -> prevote -> precommit -> commit, producing a [`FinalityCertificate`]
//! when strictly more than two thirds of the snapshot's voting power precommits
//! one block. It is a pure state machine: it reads no clock, performs no
//! networking or persistence, and returns the messages a driver should broadcast
//! and the block a driver should commit. This keeps the consensus-critical logic
//! deterministic and unit-testable, with the async driver (in `webc-node`) as a
//! thin shell around it.
//!
//! Boundaries and scope: this is Phase 4 A-2 — the honest, single-round core.
//! Timeouts, round changes, locking/valid-round rules, fork choice, and state
//! sync are Phase 4 A-3 and deliberately absent here. Because there is no round
//! change yet, a stalled proposer stalls the height; that is acceptable for the
//! A-2 convergence milestone and is the first thing A-3 removes.
//!
//! Security rules enforced here:
//! - every proposal and vote is verified against the immutable height snapshot
//!   (registered consensus key, scheduled-leader identity for proposals) before
//!   it can influence the machine;
//! - a validator is counted at most once per step (first vote wins), so a later
//!   equivocating vote cannot change this node's tally;
//! - a block is committed only when its finality certificate independently
//!   reaches quorum, and only when the machine actually holds that block.

use crate::{
    Block, ChainError, ChainId, DoubleVoteEvidence, FinalityCertificate, ProtocolVersion,
    SignedProposal, SignedVote, ValidatorSet, Vote, VoteType,
};
use std::collections::{BTreeMap, BTreeSet};
use webc_crypto::{Address, Keypair};

/// The BFT step this node currently occupies within one height/round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Awaiting a valid proposal from the scheduled leader.
    Propose,
    /// Proposal accepted; collecting prevotes.
    Prevote,
    /// Prevote quorum reached; collecting precommits.
    Precommit,
    /// Precommit quorum reached; the block is finalized.
    Committed,
}

/// This node's validator identity, if it is a voting member. Observers
/// (verification nodes) pass `None` and still follow finality without voting.
pub struct ValidatorIdentity {
    /// Operator address that must be present in the height snapshot.
    pub address: Address,
    /// Consensus keypair whose public half is registered in the snapshot.
    pub consensus_key: Keypair,
}

/// A consensus message exchanged between nodes for one height.
#[derive(Clone, Debug)]
pub enum ConsensusMessage {
    /// The leader's signed block proposal.
    Proposal(Box<SignedProposal>),
    /// A signed prevote or precommit.
    Vote(SignedVote),
}

/// An instruction the driver must carry out on the machine's behalf.
#[derive(Clone, Debug)]
pub enum ConsensusAction {
    /// Gossip this message to peers (it has already been applied locally).
    Broadcast(ConsensusMessage),
    /// Finalize this block; its certificate independently proves quorum.
    Commit {
        /// The finalized block.
        block: Box<Block>,
        /// The proof that strictly over two thirds precommitted it.
        certificate: Box<FinalityCertificate>,
    },
    /// A validator equivocated (signed two conflicting votes in one step). The
    /// driver should include this objective evidence in a future block, where the
    /// existing verified slashing path penalizes the offender exactly once.
    Equivocation(Box<DoubleVoteEvidence>),
}

/// A single-height, single-round BFT state machine over an immutable snapshot.
pub struct RoundState {
    protocol_version: ProtocolVersion,
    chain_id: ChainId,
    set: ValidatorSet,
    height: u64,
    round: u32,
    step: Step,
    identity: Option<ValidatorIdentity>,
    /// The accepted proposal for this height/round, once seen.
    proposal: Option<SignedProposal>,
    /// First prevote seen per validator (later equivocations are ignored).
    prevotes: BTreeMap<Address, SignedVote>,
    /// First precommit seen per validator.
    precommits: BTreeMap<Address, SignedVote>,
    /// Whether this node has already broadcast its own prevote.
    prevote_cast: bool,
    /// Whether this node has already broadcast its own precommit.
    precommit_cast: bool,
    /// Validators already reported for equivocation in a step, so each conflict
    /// is surfaced as evidence at most once.
    reported_equivocators: BTreeSet<(Address, VoteType)>,
    /// The finality certificate, once the block is committed.
    certificate: Option<FinalityCertificate>,
}

impl RoundState {
    /// Creates a state machine for one height and round over `set`.
    ///
    /// `identity` is `Some` for a voting validator and `None` for an observer.
    pub fn new(
        protocol_version: ProtocolVersion,
        chain_id: ChainId,
        set: ValidatorSet,
        height: u64,
        round: u32,
        identity: Option<ValidatorIdentity>,
    ) -> Self {
        Self {
            protocol_version,
            chain_id,
            set,
            height,
            round,
            step: Step::Propose,
            identity,
            proposal: None,
            prevotes: BTreeMap::new(),
            precommits: BTreeMap::new(),
            prevote_cast: false,
            precommit_cast: false,
            reported_equivocators: BTreeSet::new(),
            certificate: None,
        }
    }

    /// The address scheduled to propose this height/round.
    pub fn proposer(&self) -> Option<Address> {
        self.set.proposer_for(self.height, self.round)
    }

    /// Whether this node is the scheduled proposer for this height/round.
    pub fn is_proposer(&self) -> bool {
        match (&self.identity, self.proposer()) {
            (Some(identity), Some(proposer)) => identity.address == proposer,
            _ => false,
        }
    }

    /// The current BFT step.
    pub fn step(&self) -> Step {
        self.step
    }

    /// The finality certificate, present once the block is committed.
    pub fn certificate(&self) -> Option<&FinalityCertificate> {
        self.certificate.as_ref()
    }

    /// Called by the driver when this node is the leader: signs `block` as the
    /// proposal, applies it locally, and returns the messages to broadcast
    /// (the proposal plus this node's own prevote).
    ///
    /// Errors if this node is not the scheduled proposer or the block cannot be
    /// signed. Idempotent guards prevent a second proposal at the same round.
    pub fn propose(&mut self, block: Block) -> Result<Vec<ConsensusAction>, ChainError> {
        if !self.is_proposer() {
            return Err(ChainError::ConsensusProposalNotFromLeader);
        }
        if self.proposal.is_some() {
            // Already proposed at this round; do not double-propose.
            return Ok(Vec::new());
        }
        let identity = self
            .identity
            .as_ref()
            .ok_or(ChainError::ConsensusProposalNotFromLeader)?;
        let signed = SignedProposal::sign(
            self.protocol_version,
            self.chain_id.clone(),
            self.height,
            self.round,
            block,
            identity.address,
            &identity.consensus_key,
        )?;
        let mut actions = vec![ConsensusAction::Broadcast(ConsensusMessage::Proposal(
            Box::new(signed.clone()),
        ))];
        self.apply_proposal(signed, &mut actions)?;
        Ok(actions)
    }

    /// Applies an inbound consensus message, returning any follow-on actions.
    ///
    /// Messages for another height or round are ignored (empty result), since
    /// gossip legitimately carries messages this node is not acting on. A message
    /// for this height/round that fails verification returns an error so the
    /// driver can penalize the peer.
    pub fn on_message(
        &mut self,
        message: ConsensusMessage,
    ) -> Result<Vec<ConsensusAction>, ChainError> {
        if self.step == Step::Committed {
            return Ok(Vec::new());
        }
        let mut actions = Vec::new();
        match message {
            ConsensusMessage::Proposal(signed) => {
                if signed.payload.height != self.height || signed.payload.round != self.round {
                    return Ok(Vec::new());
                }
                signed.verify_in_set(&self.set, self.protocol_version, &self.chain_id)?;
                self.apply_proposal(*signed, &mut actions)?;
            }
            ConsensusMessage::Vote(vote) => {
                if vote.payload.height != self.height || vote.payload.round != self.round {
                    return Ok(Vec::new());
                }
                self.set
                    .verify_vote(&vote, self.protocol_version, &self.chain_id)?;
                if let Some(evidence) = self.record_vote(vote) {
                    actions.push(ConsensusAction::Equivocation(Box::new(evidence)));
                }
                self.maybe_advance(&mut actions)?;
            }
        }
        Ok(actions)
    }

    /// Accepts a verified proposal: stores it (once), moves out of Propose, and
    /// lets the machine cast this node's prevote and re-evaluate thresholds.
    fn apply_proposal(
        &mut self,
        signed: SignedProposal,
        actions: &mut Vec<ConsensusAction>,
    ) -> Result<(), ChainError> {
        if self.proposal.is_some() {
            return Ok(());
        }
        self.proposal = Some(signed);
        if self.step == Step::Propose {
            self.step = Step::Prevote;
        }
        self.maybe_advance(actions)
    }

    /// Records a verified vote, keeping only the first per validator and step so a
    /// later equivocating vote cannot change this node's tally.
    ///
    /// Returns objective double-vote evidence the first time a validator is seen
    /// voting for a *different* block in the same step. Both votes are already
    /// signature-verified against the snapshot, so the returned evidence is
    /// directly usable by the existing slashing path.
    fn record_vote(&mut self, vote: SignedVote) -> Option<DoubleVoteEvidence> {
        let vote_type = vote.payload.vote_type;
        let validator = vote.payload.validator;
        let map = match vote_type {
            VoteType::Prevote => &mut self.prevotes,
            VoteType::Precommit => &mut self.precommits,
        };
        match map.get(&validator) {
            Some(existing) => {
                // A conflicting vote for the same step is equivocation. Keep the
                // first vote for the tally and surface the conflict once.
                if existing.payload.block_hash != vote.payload.block_hash
                    && self.reported_equivocators.insert((validator, vote_type))
                {
                    return Some(DoubleVoteEvidence {
                        first: existing.clone(),
                        second: vote,
                    });
                }
                None
            }
            None => {
                map.insert(validator, vote);
                None
            }
        }
    }

    /// Drives step transitions after any state change, emitting this node's own
    /// votes and, at precommit quorum, the commit action.
    fn maybe_advance(&mut self, actions: &mut Vec<ConsensusAction>) -> Result<(), ChainError> {
        let Some(block_hash) = self.proposal.as_ref().map(|p| p.payload.block_hash) else {
            // Without the proposal block there is nothing to vote for or commit.
            return Ok(());
        };

        // Cast this node's prevote once it is in (or past) the Prevote step.
        if self.step == Step::Prevote {
            self.cast_vote(VoteType::Prevote, block_hash, actions)?;
        }

        // Prevote quorum for the proposed block advances to Precommit.
        if self.step == Step::Prevote && self.has_quorum(VoteType::Prevote, block_hash) {
            self.step = Step::Precommit;
        }

        // Cast this node's precommit once it is in the Precommit step.
        if self.step == Step::Precommit {
            self.cast_vote(VoteType::Precommit, block_hash, actions)?;
        }

        // Precommit quorum finalizes the block with a certificate. This is
        // independent of the local step: an observer (or a node that never saw a
        // prevote quorum) still finalizes as soon as it holds the block and sees
        // strictly over two thirds of precommit power, since that alone proves
        // finality.
        if self.step != Step::Committed && self.has_quorum(VoteType::Precommit, block_hash) {
            if let Some(certificate) = self.build_certificate(block_hash) {
                let block = self
                    .proposal
                    .as_ref()
                    .map(|p| p.block.clone())
                    .expect("proposal present when block_hash is known");
                self.certificate = Some(certificate.clone());
                self.step = Step::Committed;
                actions.push(ConsensusAction::Commit {
                    block: Box::new(block),
                    certificate: Box::new(certificate),
                });
            }
        }
        Ok(())
    }

    /// Signs and locally applies this node's own vote for `block_hash`, then
    /// queues it for broadcast. No-op for observers or a repeated vote.
    fn cast_vote(
        &mut self,
        vote_type: VoteType,
        block_hash: webc_crypto::Hash256,
        actions: &mut Vec<ConsensusAction>,
    ) -> Result<(), ChainError> {
        let already_cast = match vote_type {
            VoteType::Prevote => self.prevote_cast,
            VoteType::Precommit => self.precommit_cast,
        };
        if already_cast {
            return Ok(());
        }
        let Some(identity) = self.identity.as_ref() else {
            return Ok(());
        };
        // Only registered snapshot members carry voting power.
        if self.set.consensus_key_of(identity.address).is_none() {
            return Ok(());
        }
        let vote = SignedVote::sign(
            Vote {
                protocol_version: self.protocol_version,
                chain_id: self.chain_id.clone(),
                height: self.height,
                round: self.round,
                vote_type,
                block_hash,
                validator: identity.address,
            },
            &identity.consensus_key,
        )?;
        match vote_type {
            VoteType::Prevote => self.prevote_cast = true,
            VoteType::Precommit => self.precommit_cast = true,
        }
        // Count our own vote locally so single-validator sets can reach quorum.
        // This node votes once per step, so it never equivocates against itself.
        let _ = self.record_vote(vote.clone());
        actions.push(ConsensusAction::Broadcast(ConsensusMessage::Vote(vote)));
        Ok(())
    }

    /// Whether votes of `vote_type` for `block_hash` exceed two thirds of power.
    fn has_quorum(&self, vote_type: VoteType, block_hash: webc_crypto::Hash256) -> bool {
        let map = match vote_type {
            VoteType::Prevote => &self.prevotes,
            VoteType::Precommit => &self.precommits,
        };
        let mut power = crate::Amount::ZERO;
        for vote in map.values() {
            if vote.payload.block_hash != block_hash {
                continue;
            }
            match power.checked_add(self.set.power_of(vote.payload.validator)) {
                Some(next) => power = next,
                None => return false,
            }
        }
        self.set.has_two_thirds_power(power)
    }

    /// Builds the finality certificate from the collected precommits.
    fn build_certificate(&self, block_hash: webc_crypto::Hash256) -> Option<FinalityCertificate> {
        let pool: Vec<SignedVote> = self.precommits.values().cloned().collect();
        FinalityCertificate::build(
            &self.set,
            self.protocol_version,
            self.chain_id.clone(),
            self.height,
            self.round,
            block_hash,
            &pool,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::ValidatorPower;
    use crate::{Amount, BlockHeader, CURRENT_PROTOCOL_VERSION};
    use std::collections::BTreeMap as Map;
    use webc_crypto::Hash256;

    fn set_with_keys(members: &[(&Keypair, u128)]) -> ValidatorSet {
        let mut validators = Map::new();
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

    fn candidate_block(proposer: Address, height: u64) -> Block {
        Block {
            header: BlockHeader {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                chain_id: ChainId::devnet(),
                height,
                epoch: 0,
                previous_hash: Hash256([0u8; 32]),
                state_root: Hash256([0x11; 32]),
                account_root: Hash256([0x22; 32]),
                tx_root: Hash256([0x33; 32]),
                receipt_root: Hash256([0x44; 32]),
                proposer,
                timestamp_ms: 1_700_000_000_000,
                base_fee_per_unit: 1,
            },
            transactions: Vec::new(),
            receipts: Vec::new(),
            evidence: Vec::new(),
        }
    }

    /// Extracts every message queued for broadcast by a batch of actions.
    fn broadcasts(actions: &[ConsensusAction]) -> Vec<ConsensusMessage> {
        actions
            .iter()
            .filter_map(|a| match a {
                ConsensusAction::Broadcast(m) => Some(m.clone()),
                _ => None,
            })
            .collect()
    }

    fn commit_of(actions: &[ConsensusAction]) -> Option<(Block, FinalityCertificate)> {
        actions.iter().find_map(|a| match a {
            ConsensusAction::Commit { block, certificate } => {
                Some(((**block).clone(), (**certificate).clone()))
            }
            _ => None,
        })
    }

    fn identity(keypair: &Keypair) -> ValidatorIdentity {
        ValidatorIdentity {
            address: keypair.address(),
            consensus_key: Keypair::from_seed(*seed_of(keypair)),
        }
    }

    // Test keypairs are built from fixed seeds; recover the seed by identity.
    fn seed_of(keypair: &Keypair) -> &'static [u8; 32] {
        for seed in SEEDS {
            if Keypair::from_seed(*seed).address() == keypair.address() {
                return seed;
            }
        }
        panic!("unknown test keypair");
    }

    const SEEDS: &[[u8; 32]] = &[[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

    #[test]
    fn single_validator_finalizes_its_own_proposal() {
        let a = Keypair::from_seed([1u8; 32]);
        let set = set_with_keys(&[(&a, 1)]);
        let height = 1;
        let round = 0;
        let mut engine = RoundState::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set,
            height,
            round,
            Some(identity(&a)),
        );
        assert!(engine.is_proposer());

        let actions = engine
            .propose(candidate_block(a.address(), height))
            .unwrap();
        // A single validator's own prevote and precommit reach quorum instantly.
        let (block, cert) = commit_of(&actions).expect("single validator commits");
        assert_eq!(engine.step(), Step::Committed);
        assert_eq!(block.header.height, height);
        assert_eq!(cert.block_hash, block.hash().unwrap());
    }

    #[test]
    fn three_validators_converge_on_one_block() {
        // Deterministically deliver every broadcast message to every peer and
        // prove all three reach the identical finalized block and certificate.
        let a = Keypair::from_seed([1u8; 32]);
        let b = Keypair::from_seed([2u8; 32]);
        let c = Keypair::from_seed([3u8; 32]);
        let set = set_with_keys(&[(&a, 1), (&b, 1), (&c, 1)]);
        let height = 1;
        let round = 0;

        let mut engines: Vec<RoundState> = [&a, &b, &c]
            .iter()
            .map(|k| {
                RoundState::new(
                    CURRENT_PROTOCOL_VERSION,
                    ChainId::devnet(),
                    set.clone(),
                    height,
                    round,
                    Some(identity(k)),
                )
            })
            .collect();

        let leader_addr = set.proposer_for(height, round).unwrap();
        let leader_index = [&a, &b, &c]
            .iter()
            .position(|k| k.address() == leader_addr)
            .unwrap();

        // A simple in-memory bus: queue of (message) to broadcast to all peers.
        let block = candidate_block(leader_addr, height);
        let mut queue: Vec<ConsensusMessage> = Vec::new();
        let mut commits: Vec<Option<(Block, FinalityCertificate)>> = vec![None, None, None];

        let start = engines[leader_index].propose(block).unwrap();
        record_commit(&mut commits, leader_index, &start);
        queue.extend(broadcasts(&start));

        // Drain the bus to a fixed point.
        let mut guard = 0;
        while let Some(message) = queue.pop() {
            guard += 1;
            assert!(guard < 1_000, "message bus did not converge");
            for (index, engine) in engines.iter_mut().enumerate() {
                let actions = engine.on_message(message.clone()).unwrap();
                record_commit(&mut commits, index, &actions);
                queue.extend(broadcasts(&actions));
            }
        }

        // All three finalized, and on the identical block and certificate hash.
        let first = commits[0].clone().expect("validator 0 commits");
        for slot in &commits {
            let (block, cert) = slot.clone().expect("each validator commits");
            assert_eq!(block.hash().unwrap(), first.0.hash().unwrap());
            assert_eq!(cert.block_hash, first.1.block_hash);
            // The certificate independently verifies against the snapshot.
            assert!(cert
                .verify(&set, CURRENT_PROTOCOL_VERSION, &ChainId::devnet())
                .is_ok());
        }
    }

    fn record_commit(
        commits: &mut [Option<(Block, FinalityCertificate)>],
        index: usize,
        actions: &[ConsensusAction],
    ) {
        if let Some(commit) = commit_of(actions) {
            commits[index] = Some(commit);
        }
    }

    #[test]
    fn observer_follows_finality_without_voting() {
        let a = Keypair::from_seed([1u8; 32]);
        let b = Keypair::from_seed([2u8; 32]);
        let c = Keypair::from_seed([3u8; 32]);
        let set = set_with_keys(&[(&a, 1), (&b, 1), (&c, 1)]);
        let height = 1;
        let round = 0;

        // The observer has no identity: it must never emit a Broadcast.
        let mut observer = RoundState::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set.clone(),
            height,
            round,
            None,
        );

        let leader_addr = set.proposer_for(height, round).unwrap();
        let leader = [&a, &b, &c]
            .into_iter()
            .find(|k| k.address() == leader_addr)
            .unwrap();
        let block = candidate_block(leader_addr, height);
        let signed = SignedProposal::sign(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            height,
            round,
            block,
            leader_addr,
            leader,
        )
        .unwrap();

        // Feed the proposal and all three precommits directly to the observer.
        let out = observer
            .on_message(ConsensusMessage::Proposal(Box::new(signed.clone())))
            .unwrap();
        assert!(broadcasts(&out).is_empty(), "observer must not broadcast");

        let block_hash = signed.payload.block_hash;
        for keypair in [&a, &b, &c] {
            let precommit = SignedVote::sign(
                Vote {
                    protocol_version: CURRENT_PROTOCOL_VERSION,
                    chain_id: ChainId::devnet(),
                    height,
                    round,
                    vote_type: VoteType::Precommit,
                    block_hash,
                    validator: keypair.address(),
                },
                keypair,
            )
            .unwrap();
            let out = observer
                .on_message(ConsensusMessage::Vote(precommit))
                .unwrap();
            assert!(broadcasts(&out).is_empty(), "observer must not broadcast");
        }
        assert_eq!(observer.step(), Step::Committed);
        assert!(observer.certificate().is_some());
    }

    #[test]
    fn equivocating_validator_is_surfaced_as_evidence() {
        // A validator that prevotes two different blocks in the same step must be
        // caught, and the emitted evidence must satisfy the existing slashing
        // path's verification.
        let a = Keypair::from_seed([1u8; 32]);
        let b = Keypair::from_seed([2u8; 32]);
        let c = Keypair::from_seed([3u8; 32]);
        let set = set_with_keys(&[(&a, 1), (&b, 1), (&c, 1)]);
        let height = 1;
        let round = 0;
        // Observe as a non-voting node so only the injected votes are in play.
        let mut engine = RoundState::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set.clone(),
            height,
            round,
            None,
        );

        let prevote = |validator: &Keypair, hash| {
            SignedVote::sign(
                Vote {
                    protocol_version: CURRENT_PROTOCOL_VERSION,
                    chain_id: ChainId::devnet(),
                    height,
                    round,
                    vote_type: VoteType::Prevote,
                    block_hash: hash,
                    validator: validator.address(),
                },
                validator,
            )
            .unwrap()
        };

        let hash_a = Hash256::digest(b"block-a");
        let hash_b = Hash256::digest(b"block-b");
        // First prevote: no conflict yet.
        let out = engine
            .on_message(ConsensusMessage::Vote(prevote(&b, hash_a)))
            .unwrap();
        assert!(!out
            .iter()
            .any(|a| matches!(a, ConsensusAction::Equivocation(_))));

        // Second, conflicting prevote from the same validator: evidence emitted.
        let out = engine
            .on_message(ConsensusMessage::Vote(prevote(&b, hash_b)))
            .unwrap();
        let evidence = out
            .iter()
            .find_map(|a| match a {
                ConsensusAction::Equivocation(ev) => Some((**ev).clone()),
                _ => None,
            })
            .expect("equivocation surfaced");
        assert_eq!(evidence.first.payload.validator, b.address());

        // The evidence plugs straight into the slashing path: both votes verify
        // against the offender's registered consensus key.
        let slashing = crate::SlashingEvidence::DoubleVote(evidence);
        assert!(slashing
            .verify(
                CURRENT_PROTOCOL_VERSION,
                &ChainId::devnet(),
                &b.public_key()
            )
            .is_ok());

        // A third conflicting prevote does not re-report the same offender.
        let out = engine
            .on_message(ConsensusMessage::Vote(prevote(&b, Hash256::digest(b"c"))))
            .unwrap();
        assert!(!out
            .iter()
            .any(|a| matches!(a, ConsensusAction::Equivocation(_))));
    }

    #[test]
    fn non_leader_cannot_propose() {
        let a = Keypair::from_seed([1u8; 32]);
        let b = Keypair::from_seed([2u8; 32]);
        let set = set_with_keys(&[(&a, 1), (&b, 1)]);
        let height = 1;
        let round = 0;
        let leader_addr = set.proposer_for(height, round).unwrap();
        let non_leader = if leader_addr == a.address() { &b } else { &a };
        let mut engine = RoundState::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set,
            height,
            round,
            Some(identity(non_leader)),
        );
        assert!(!engine.is_proposer());
        assert!(matches!(
            engine
                .propose(candidate_block(non_leader.address(), height))
                .unwrap_err(),
            ChainError::ConsensusProposalNotFromLeader
        ));
    }

    #[test]
    fn messages_for_another_height_are_ignored() {
        let a = Keypair::from_seed([1u8; 32]);
        let set = set_with_keys(&[(&a, 1)]);
        let mut engine = RoundState::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set,
            5,
            0,
            Some(identity(&a)),
        );
        // A proposal for a different height must not move this machine.
        let other = SignedProposal::sign(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            6,
            0,
            candidate_block(a.address(), 6),
            a.address(),
            &a,
        )
        .unwrap();
        let out = engine
            .on_message(ConsensusMessage::Proposal(Box::new(other)))
            .unwrap();
        assert!(out.is_empty());
        assert_eq!(engine.step(), Step::Propose);
    }
}
