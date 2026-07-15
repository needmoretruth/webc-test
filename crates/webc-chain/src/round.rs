//! Deterministic multi-round BFT consensus machine for one block height.
//!
//! Purpose: drive one consensus height to a finalized block through the
//! Tendermint-style sequence propose -> prevote -> precommit, with safe round
//! changes when a round fails to decide. It is a pure state machine: it reads no
//! clock, performs no networking or persistence, and never executes blocks. It
//! consumes [`ConsensusEvent`]s (received messages and fired timeouts) and
//! returns [`ConsensusAction`]s a driver carries out (broadcast a message, arm a
//! timeout, request a candidate block, or commit a finalized block). This keeps
//! the safety-critical logic deterministic and unit-testable, with the async
//! driver (in `webc-node`) as a thin shell.
//!
//! Model: this follows Buchman/Kwon/Milosevic Tendermint (arXiv:1807.04938,
//! Algorithm 1), adapted to WEBC types. The safety-critical invariants are:
//! - a validator **locks** a value when it precommits it, and thereafter only
//!   prevotes that value (or nil) unless an authenticated proof-of-lock from a
//!   later round justifies changing — so honest nodes never contribute prevotes
//!   to two different blocks, and two blocks can never both reach a precommit
//!   quorum;
//! - "more than two thirds" (`2f+1`) is required to lock, decide, or advance a
//!   step; "more than one third" (`f+1`) — which must include an honest node —
//!   is required to catch up to a higher round.
//!
//! A nil vote (a prevote/precommit for "no block") is encoded as a vote whose
//! `block_hash` is the reserved all-zero sentinel [`webc_crypto::Hash256::ZERO`].
//! A real block hash is the digest of non-empty canonical JSON and can never be
//! all zeros, and the codebase already treats all-zeros as a reserved sentinel
//! (the genesis parent hash), so this is unambiguous and needs no wire change.
//!
//! Block validity: the machine treats every carried proposal block as valid; a
//! driver that can execute blocks should re-validate a received proposal (via
//! `apply_block`) before feeding it, and the committing node re-validates on
//! import. This keeps the consensus machine free of execution.
//!
//! Deferred: dynamic timeout durations, gossiping the full vote set for faster
//! catch-up, and sub-committee sampling are driver/refinement concerns, not part
//! of this safety core.

use crate::{
    Block, ChainError, ChainId, DoubleVoteEvidence, FinalityCertificate, ProtocolVersion,
    SignedProposal, SignedVote, ValidatorSet, Vote, VoteType,
};
use std::collections::{BTreeMap, BTreeSet};
use webc_crypto::{Address, Hash256, Keypair};

/// The reserved sentinel identifying a nil vote (a vote for "no block").
const NIL: Hash256 = Hash256::ZERO;

/// The BFT step this node occupies within its current round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Awaiting the round's proposal (or a propose timeout).
    Propose,
    /// Collecting prevotes.
    Prevote,
    /// Collecting precommits.
    Precommit,
}

/// The three consensus timeouts a driver arms and fires back as events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutKind {
    /// No proposal arrived in time; prevote nil.
    Propose,
    /// A prevote quorum formed without a single-block majority; precommit nil.
    Prevote,
    /// A precommit quorum formed without a decision; move to the next round.
    Precommit,
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
    /// The scheduled leader's signed block proposal.
    Proposal(Box<SignedProposal>),
    /// A signed prevote or precommit (nil is the all-zero sentinel hash).
    Vote(SignedVote),
}

/// An input to the machine: a received message or a fired timeout.
#[derive(Clone, Debug)]
pub enum ConsensusEvent {
    /// A message received from a peer (or produced locally).
    Message(ConsensusMessage),
    /// A timeout the driver previously armed has fired.
    Timeout {
        /// Which timeout fired.
        kind: TimeoutKind,
        /// The round the timeout was armed for.
        round: u32,
    },
}

/// An instruction the driver must carry out on the machine's behalf.
#[derive(Clone, Debug)]
pub enum ConsensusAction {
    /// Gossip this message to peers (it has already been applied locally).
    Broadcast(ConsensusMessage),
    /// Arm this timeout; fire it back as a [`ConsensusEvent::Timeout`] on expiry.
    ScheduleTimeout {
        /// Which timeout to arm.
        kind: TimeoutKind,
        /// The round this timeout belongs to.
        round: u32,
    },
    /// This node is the proposer for `round` and has no locked value to
    /// re-propose: the driver should build a candidate block and hand it back via
    /// [`ConsensusMachine::provide_block`].
    NeedProposalBlock {
        /// The round the block is needed for.
        round: u32,
    },
    /// Finalize this block; its certificate independently proves quorum.
    Commit {
        /// The finalized block.
        block: Box<Block>,
        /// The proof that strictly over two thirds precommitted it.
        certificate: Box<FinalityCertificate>,
    },
    /// A validator equivocated (signed two conflicting votes in one step/round).
    /// The driver should include this objective evidence in a future block, where
    /// the existing verified slashing path penalizes the offender exactly once.
    Equivocation(Box<DoubleVoteEvidence>),
}

/// Which votes a power tally counts: any hash, or exactly one hash.
#[derive(Clone, Copy)]
enum HashFilter {
    Any,
    Exactly(Hash256),
}

/// Per-round, once-only rule guards, keyed by `(rule id, round)`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Guard {
    PrevoteSent,
    PrecommitSent,
    PrevoteTimeoutScheduled,
    PrecommitTimeoutScheduled,
    ValidValueUpdated,
}

/// A single-height, multi-round Tendermint-style BFT state machine.
pub struct ConsensusMachine {
    protocol_version: ProtocolVersion,
    chain_id: ChainId,
    set: ValidatorSet,
    height: u64,
    identity: Option<ValidatorIdentity>,

    round: u32,
    step: Step,

    /// The value this node precommitted and the round it did so (its lock).
    locked_value: Option<Block>,
    locked_round: Option<u32>,
    /// The latest value this node saw reach a prevote quorum, and its round.
    valid_value: Option<Block>,
    valid_round: Option<u32>,

    /// One accepted proposal per round, from that round's scheduled leader.
    proposals: BTreeMap<u32, SignedProposal>,
    /// First prevote per `(round, validator)`.
    prevotes: BTreeMap<(u32, Address), SignedVote>,
    /// First precommit per `(round, validator)`.
    precommits: BTreeMap<(u32, Address), SignedVote>,

    /// Offenders already reported per `(round, step)`, so each conflict is
    /// surfaced as evidence at most once.
    reported_equivocators: BTreeSet<(u32, Address, VoteType)>,
    /// Fired once-only rule guards.
    guards: BTreeSet<(Guard, u32)>,

    /// The finalized block and its certificate, once decided.
    decision: Option<(Block, FinalityCertificate)>,
}

impl ConsensusMachine {
    /// Creates a machine for `height` over the immutable snapshot `set`.
    ///
    /// The machine starts at round 0 in the Propose step. Call [`Self::start`]
    /// once to emit the round-0 startup actions (propose or arm a timeout).
    pub fn new(
        protocol_version: ProtocolVersion,
        chain_id: ChainId,
        set: ValidatorSet,
        height: u64,
        identity: Option<ValidatorIdentity>,
    ) -> Self {
        Self {
            protocol_version,
            chain_id,
            set,
            height,
            identity,
            round: 0,
            step: Step::Propose,
            locked_value: None,
            locked_round: None,
            valid_value: None,
            valid_round: None,
            proposals: BTreeMap::new(),
            prevotes: BTreeMap::new(),
            precommits: BTreeMap::new(),
            reported_equivocators: BTreeSet::new(),
            guards: BTreeSet::new(),
            decision: None,
        }
    }

    /// Emits the startup actions for round 0. Call exactly once after [`Self::new`].
    pub fn start(&mut self) -> Result<Vec<ConsensusAction>, ChainError> {
        let mut actions = Vec::new();
        self.start_round(0, &mut actions)?;
        Ok(actions)
    }

    /// The address scheduled to propose `round`.
    pub fn proposer(&self, round: u32) -> Option<Address> {
        self.set.proposer_for(self.height, round)
    }

    /// Whether this node is the scheduled proposer for `round`.
    pub fn is_proposer(&self, round: u32) -> bool {
        match (&self.identity, self.proposer(round)) {
            (Some(identity), Some(proposer)) => identity.address == proposer,
            _ => false,
        }
    }

    /// The current round.
    pub fn round(&self) -> u32 {
        self.round
    }

    /// The current step.
    pub fn step(&self) -> Step {
        self.step
    }

    /// The finalized block, once decided.
    pub fn decided_block(&self) -> Option<&Block> {
        self.decision.as_ref().map(|(block, _)| block)
    }

    /// The finality certificate, once decided.
    pub fn certificate(&self) -> Option<&FinalityCertificate> {
        self.decision.as_ref().map(|(_, cert)| cert)
    }

    /// The driver's response to [`ConsensusAction::NeedProposalBlock`]: supplies a
    /// freshly built candidate block for `round`, which the machine signs,
    /// broadcasts, and applies. A stale or unsolicited block is ignored.
    pub fn provide_block(
        &mut self,
        round: u32,
        block: Block,
    ) -> Result<Vec<ConsensusAction>, ChainError> {
        let mut actions = Vec::new();
        if self.decision.is_some()
            || round != self.round
            || !self.is_proposer(round)
            || self.proposals.contains_key(&round)
        {
            return Ok(actions);
        }
        // A freshly built block has no proof-of-lock round.
        self.emit_proposal(round, block, None, &mut actions)?;
        self.drive(&mut actions)?;
        Ok(actions)
    }

    /// Applies one event and returns the resulting actions.
    ///
    /// Messages for another height are ignored. A message for this height that
    /// fails verification returns an error so the driver can penalize the peer.
    /// Once the height is decided, further events are ignored.
    pub fn on_event(&mut self, event: ConsensusEvent) -> Result<Vec<ConsensusAction>, ChainError> {
        let mut actions = Vec::new();
        if self.decision.is_some() {
            return Ok(actions);
        }
        match event {
            ConsensusEvent::Message(ConsensusMessage::Proposal(signed)) => {
                if signed.payload.height != self.height {
                    return Ok(actions);
                }
                signed.verify_in_set(&self.set, self.protocol_version, &self.chain_id)?;
                // Keep one proposal per round (the first from its valid leader).
                self.proposals
                    .entry(signed.payload.round)
                    .or_insert(*signed);
            }
            ConsensusEvent::Message(ConsensusMessage::Vote(vote)) => {
                if vote.payload.height != self.height {
                    return Ok(actions);
                }
                self.set
                    .verify_vote(&vote, self.protocol_version, &self.chain_id)?;
                if let Some(evidence) = self.record_vote(vote) {
                    actions.push(ConsensusAction::Equivocation(Box::new(evidence)));
                }
            }
            ConsensusEvent::Timeout { kind, round } => {
                self.on_timeout(kind, round, &mut actions)?;
            }
        }
        self.drive(&mut actions)?;
        Ok(actions)
    }

    /// Begins a round: resets the step and either proposes (if this node leads and
    /// has a value) or arms the propose timeout.
    fn start_round(
        &mut self,
        round: u32,
        actions: &mut Vec<ConsensusAction>,
    ) -> Result<(), ChainError> {
        self.round = round;
        self.step = Step::Propose;
        if self.is_proposer(round) {
            match self.valid_value.clone() {
                // Re-propose a value that already reached a prevote quorum, citing
                // the round it did so as the authenticated proof-of-lock.
                Some(value) => {
                    let valid_round = self.valid_round;
                    self.emit_proposal(round, value, valid_round, actions)?;
                }
                // No value to re-propose: ask the driver for a fresh candidate.
                None => actions.push(ConsensusAction::NeedProposalBlock { round }),
            }
        } else {
            actions.push(ConsensusAction::ScheduleTimeout {
                kind: TimeoutKind::Propose,
                round,
            });
        }
        Ok(())
    }

    /// Signs, stores, and broadcasts this node's proposal for `round`.
    fn emit_proposal(
        &mut self,
        round: u32,
        block: Block,
        valid_round: Option<u32>,
        actions: &mut Vec<ConsensusAction>,
    ) -> Result<(), ChainError> {
        let identity = self
            .identity
            .as_ref()
            .ok_or(ChainError::ConsensusProposalNotFromLeader)?;
        let signed = SignedProposal::sign(
            self.protocol_version,
            self.chain_id.clone(),
            self.height,
            round,
            valid_round,
            block,
            identity.address,
            &identity.consensus_key,
        )?;
        self.proposals.insert(round, signed.clone());
        actions.push(ConsensusAction::Broadcast(ConsensusMessage::Proposal(
            Box::new(signed),
        )));
        Ok(())
    }

    /// Handles a fired timeout for its round and step.
    fn on_timeout(
        &mut self,
        kind: TimeoutKind,
        round: u32,
        actions: &mut Vec<ConsensusAction>,
    ) -> Result<(), ChainError> {
        if round != self.round {
            return Ok(());
        }
        match kind {
            TimeoutKind::Propose if self.step == Step::Propose => {
                self.cast_prevote(NIL, actions)?;
                self.step = Step::Prevote;
            }
            TimeoutKind::Prevote if self.step == Step::Prevote => {
                self.cast_precommit(NIL, actions)?;
                self.step = Step::Precommit;
            }
            TimeoutKind::Precommit => {
                self.start_round(round + 1, actions)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Re-evaluates every level-triggered consensus rule until nothing changes.
    ///
    /// Rules are checked in the paper's order. A round advance (from a precommit
    /// timeout or catch-up) re-arms the per-round guards, so the loop terminates
    /// because rounds only ever increase.
    fn drive(&mut self, actions: &mut Vec<ConsensusAction>) -> Result<(), ChainError> {
        let mut passes = 0;
        loop {
            passes += 1;
            debug_assert!(passes < 1_000, "consensus rule loop failed to settle");
            if passes >= 1_000 {
                break;
            }
            let mut changed = false;
            changed |= self.rule_propose(actions)?;
            changed |= self.rule_prevote_timeout(actions);
            changed |= self.rule_prevote_quorum(actions)?;
            changed |= self.rule_prevote_nil(actions)?;
            changed |= self.rule_precommit_timeout(actions);
            changed |= self.rule_decide(actions)?;
            changed |= self.rule_catch_up(actions)?;
            if !changed {
                break;
            }
        }
        Ok(())
    }

    /// Rules 22 and 28: on the current round's proposal while in Propose, prevote
    /// the block (subject to the lock) or nil, and move to Prevote.
    fn rule_propose(&mut self, actions: &mut Vec<ConsensusAction>) -> Result<bool, ChainError> {
        if self.step != Step::Propose {
            return Ok(false);
        }
        let Some(proposal) = self.proposals.get(&self.round).cloned() else {
            return Ok(false);
        };
        let block_hash = proposal.payload.block_hash;
        match proposal.payload.valid_round {
            // Rule 22: a fresh proposal.
            None => {
                let prevote = if self.locked_round.is_none()
                    || self.locked_value_hash() == Some(block_hash)
                {
                    block_hash
                } else {
                    NIL
                };
                self.cast_prevote(prevote, actions)?;
                self.step = Step::Prevote;
                Ok(true)
            }
            // Rule 28: a re-proposal citing a proof-of-lock round `vr < round`.
            Some(vr)
                if vr < self.round
                    && self.has_prevote_quorum(vr, HashFilter::Exactly(block_hash)) =>
            {
                let prevote = if self.locked_round.map(|lr| lr <= vr).unwrap_or(true)
                    || self.locked_value_hash() == Some(block_hash)
                {
                    block_hash
                } else {
                    NIL
                };
                self.cast_prevote(prevote, actions)?;
                self.step = Step::Prevote;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Rule 34: once a prevote quorum (any value) forms for the current round in
    /// the Prevote step, arm the prevote timeout (once).
    fn rule_prevote_timeout(&mut self, actions: &mut Vec<ConsensusAction>) -> bool {
        if self.step != Step::Prevote
            || self.guard_set(Guard::PrevoteTimeoutScheduled)
            || !self.has_prevote_quorum(self.round, HashFilter::Any)
        {
            return false;
        }
        self.set_guard(Guard::PrevoteTimeoutScheduled);
        actions.push(ConsensusAction::ScheduleTimeout {
            kind: TimeoutKind::Prevote,
            round: self.round,
        });
        true
    }

    /// Rule 36: on the current round's proposal plus a prevote quorum for its
    /// block while in Prevote or later — lock and precommit it (if still in
    /// Prevote) and record it as the valid value.
    fn rule_prevote_quorum(
        &mut self,
        actions: &mut Vec<ConsensusAction>,
    ) -> Result<bool, ChainError> {
        if self.step == Step::Propose || self.guard_set(Guard::ValidValueUpdated) {
            return Ok(false);
        }
        let Some(proposal) = self.proposals.get(&self.round).cloned() else {
            return Ok(false);
        };
        let block_hash = proposal.payload.block_hash;
        if !self.has_prevote_quorum(self.round, HashFilter::Exactly(block_hash)) {
            return Ok(false);
        }
        if self.step == Step::Prevote {
            self.locked_value = Some(proposal.block.clone());
            self.locked_round = Some(self.round);
            self.cast_precommit(block_hash, actions)?;
            self.step = Step::Precommit;
        }
        self.valid_value = Some(proposal.block.clone());
        self.valid_round = Some(self.round);
        self.set_guard(Guard::ValidValueUpdated);
        Ok(true)
    }

    /// Rule 44: on a prevote quorum for nil in the current round while in Prevote,
    /// precommit nil and move to Precommit.
    fn rule_prevote_nil(&mut self, actions: &mut Vec<ConsensusAction>) -> Result<bool, ChainError> {
        if self.step != Step::Prevote
            || !self.has_prevote_quorum(self.round, HashFilter::Exactly(NIL))
        {
            return Ok(false);
        }
        self.cast_precommit(NIL, actions)?;
        self.step = Step::Precommit;
        Ok(true)
    }

    /// Rule 47: once a precommit quorum (any value) forms for the current round,
    /// arm the precommit timeout (once).
    fn rule_precommit_timeout(&mut self, actions: &mut Vec<ConsensusAction>) -> bool {
        if self.guard_set(Guard::PrecommitTimeoutScheduled)
            || !self.has_precommit_quorum(self.round, HashFilter::Any)
        {
            return false;
        }
        self.set_guard(Guard::PrecommitTimeoutScheduled);
        actions.push(ConsensusAction::ScheduleTimeout {
            kind: TimeoutKind::Precommit,
            round: self.round,
        });
        true
    }

    /// Rule 49: for any round whose proposal has a precommit quorum for its block,
    /// decide that block. This can finalize a block proposed in an earlier round.
    fn rule_decide(&mut self, actions: &mut Vec<ConsensusAction>) -> Result<bool, ChainError> {
        if self.decision.is_some() {
            return Ok(false);
        }
        // Find a round whose proposed block has a precommit quorum.
        let rounds: Vec<u32> = self.proposals.keys().copied().collect();
        for round in rounds {
            let proposal = self.proposals.get(&round).cloned().expect("round present");
            let block_hash = proposal.payload.block_hash;
            if !self.has_precommit_quorum(round, HashFilter::Exactly(block_hash)) {
                continue;
            }
            let Some(certificate) = self.build_certificate(round, block_hash) else {
                continue;
            };
            self.decision = Some((proposal.block.clone(), certificate.clone()));
            actions.push(ConsensusAction::Commit {
                block: Box::new(proposal.block),
                certificate: Box::new(certificate),
            });
            return Ok(true);
        }
        Ok(false)
    }

    /// Rule 55: if more than one third of the power has sent any message for a
    /// round greater than the current one, jump to that round (an honest node is
    /// necessarily among a `f+1` set, so this cannot be forced by faults alone).
    fn rule_catch_up(&mut self, actions: &mut Vec<ConsensusAction>) -> Result<bool, ChainError> {
        // Highest future round with f+1 total participation.
        let mut target: Option<u32> = None;
        let mut future: BTreeSet<u32> = BTreeSet::new();
        for (round, _) in self.prevotes.keys() {
            if *round > self.round {
                future.insert(*round);
            }
        }
        for (round, _) in self.precommits.keys() {
            if *round > self.round {
                future.insert(*round);
            }
        }
        for round in future {
            if self.has_one_third_participation(round) {
                target = Some(target.map_or(round, |t| t.max(round)));
            }
        }
        if let Some(round) = target {
            self.start_round(round, actions)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Records a verified vote, keeping the first per `(round, validator, type)`.
    /// Returns objective evidence the first time a validator is seen voting for a
    /// different block in the same round and step.
    fn record_vote(&mut self, vote: SignedVote) -> Option<DoubleVoteEvidence> {
        let vote_type = vote.payload.vote_type;
        let round = vote.payload.round;
        let validator = vote.payload.validator;
        let map = match vote_type {
            VoteType::Prevote => &mut self.prevotes,
            VoteType::Precommit => &mut self.precommits,
        };
        match map.get(&(round, validator)) {
            Some(existing) => {
                if existing.payload.block_hash != vote.payload.block_hash
                    && self
                        .reported_equivocators
                        .insert((round, validator, vote_type))
                {
                    return Some(DoubleVoteEvidence {
                        first: existing.clone(),
                        second: vote,
                    });
                }
                None
            }
            None => {
                map.insert((round, validator), vote);
                None
            }
        }
    }

    /// Signs, records, and queues this node's prevote for the current round once.
    fn cast_prevote(
        &mut self,
        block_hash: Hash256,
        actions: &mut Vec<ConsensusAction>,
    ) -> Result<(), ChainError> {
        self.cast_vote(VoteType::Prevote, Guard::PrevoteSent, block_hash, actions)
    }

    /// Signs, records, and queues this node's precommit for the current round once.
    fn cast_precommit(
        &mut self,
        block_hash: Hash256,
        actions: &mut Vec<ConsensusAction>,
    ) -> Result<(), ChainError> {
        self.cast_vote(
            VoteType::Precommit,
            Guard::PrecommitSent,
            block_hash,
            actions,
        )
    }

    /// Shared vote casting: no-op for observers, non-members, or a repeated vote
    /// of this type in this round.
    fn cast_vote(
        &mut self,
        vote_type: VoteType,
        guard: Guard,
        block_hash: Hash256,
        actions: &mut Vec<ConsensusAction>,
    ) -> Result<(), ChainError> {
        if self.guard_set(guard) {
            return Ok(());
        }
        let Some(identity) = self.identity.as_ref() else {
            return Ok(());
        };
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
        self.set_guard(guard);
        // Count our own vote locally so single-validator sets can reach quorum.
        let _ = self.record_vote(vote.clone());
        actions.push(ConsensusAction::Broadcast(ConsensusMessage::Vote(vote)));
        Ok(())
    }

    /// Hash of this node's locked value, if any.
    fn locked_value_hash(&self) -> Option<Hash256> {
        // The locked value equals the proposal it was locked from; its hash is the
        // block hash. Recomputing is cheap and avoids storing it separately.
        self.locked_value.as_ref().and_then(|b| b.hash().ok())
    }

    /// Whether prevotes at `round` matching `filter` exceed two thirds of power.
    fn has_prevote_quorum(&self, round: u32, filter: HashFilter) -> bool {
        self.set
            .has_two_thirds_power(self.tally(&self.prevotes, round, filter))
    }

    /// Whether precommits at `round` matching `filter` exceed two thirds of power.
    fn has_precommit_quorum(&self, round: u32, filter: HashFilter) -> bool {
        self.set
            .has_two_thirds_power(self.tally(&self.precommits, round, filter))
    }

    /// Whether any messages at `round` exceed one third of power (union of the
    /// distinct validators that prevoted or precommitted at that round).
    fn has_one_third_participation(&self, round: u32) -> bool {
        let mut voters: BTreeSet<Address> = BTreeSet::new();
        for (r, v) in self.prevotes.keys() {
            if *r == round {
                voters.insert(*v);
            }
        }
        for (r, v) in self.precommits.keys() {
            if *r == round {
                voters.insert(*v);
            }
        }
        let mut power = crate::Amount::ZERO;
        for voter in voters {
            match power.checked_add(self.set.power_of(voter)) {
                Some(next) => power = next,
                None => return false,
            }
        }
        self.set.has_one_third_power(power)
    }

    /// Sums the snapshot power of validators whose vote at `round` matches `filter`.
    fn tally(
        &self,
        votes: &BTreeMap<(u32, Address), SignedVote>,
        round: u32,
        filter: HashFilter,
    ) -> crate::Amount {
        let mut power = crate::Amount::ZERO;
        for ((r, validator), vote) in votes {
            if *r != round {
                continue;
            }
            if let HashFilter::Exactly(hash) = filter {
                if vote.payload.block_hash != hash {
                    continue;
                }
            }
            match power.checked_add(self.set.power_of(*validator)) {
                Some(next) => power = next,
                None => return crate::Amount::ZERO,
            }
        }
        power
    }

    /// Builds the finality certificate from `round`'s precommits for `block_hash`.
    fn build_certificate(&self, round: u32, block_hash: Hash256) -> Option<FinalityCertificate> {
        let pool: Vec<SignedVote> = self
            .precommits
            .iter()
            .filter(|((r, _), _)| *r == round)
            .map(|(_, vote)| vote.clone())
            .collect();
        FinalityCertificate::build(
            &self.set,
            self.protocol_version,
            self.chain_id.clone(),
            self.height,
            round,
            block_hash,
            &pool,
        )
    }

    fn guard_set(&self, guard: Guard) -> bool {
        self.guards.contains(&(guard, self.round))
    }

    fn set_guard(&mut self, guard: Guard) {
        self.guards.insert((guard, self.round));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::ValidatorPower;
    use crate::{Amount, BlockHeader, CURRENT_PROTOCOL_VERSION};
    use std::collections::BTreeMap as Map;

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

    fn candidate_block(proposer: Address, height: u64, salt: u64) -> Block {
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
                // Salt the receipt root so different proposers yield distinct blocks.
                receipt_root: Hash256([salt as u8; 32]),
                evidence_root: Hash256::ZERO,
                proposer,
                timestamp_ms: 1_700_000_000_000,
                base_fee_per_unit: 1,
            },
            transactions: Vec::new(),
            receipts: Vec::new(),
            evidence: Vec::new(),
        }
    }

    fn identity(keypair: &Keypair) -> ValidatorIdentity {
        ValidatorIdentity {
            address: keypair.address(),
            consensus_key: Keypair::from_seed(*seed_of(keypair)),
        }
    }

    fn seed_of(keypair: &Keypair) -> &'static [u8; 32] {
        for seed in SEEDS {
            if Keypair::from_seed(*seed).address() == keypair.address() {
                return seed;
            }
        }
        panic!("unknown test keypair");
    }

    const SEEDS: &[[u8; 32]] = &[[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

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

    /// Drives a set of machines over a deterministic in-memory bus: every
    /// broadcast reaches every node, a proposer's block request is honored unless
    /// that proposer is marked silent for the round, and armed timeouts fire in
    /// step order once the message bus goes quiet. This models "time advances only
    /// when nothing else is happening", which is exactly what forces a stuck round
    /// to change.
    struct Harness {
        machines: Vec<ConsensusMachine>,
        keys: Vec<Keypair>,
        height: u64,
        /// `(proposer index, round)` pairs a "crashed" proposer stays silent for.
        silent: std::collections::BTreeSet<(usize, u32)>,
        /// Timeouts each node has armed but not yet fired.
        armed: Vec<std::collections::BTreeSet<(u8, u32)>>,
        commits: Vec<Option<(Block, FinalityCertificate)>>,
    }

    fn timeout_tag(kind: TimeoutKind) -> u8 {
        match kind {
            TimeoutKind::Propose => 0,
            TimeoutKind::Prevote => 1,
            TimeoutKind::Precommit => 2,
        }
    }

    fn timeout_of(tag: u8) -> TimeoutKind {
        match tag {
            0 => TimeoutKind::Propose,
            1 => TimeoutKind::Prevote,
            _ => TimeoutKind::Precommit,
        }
    }

    impl Harness {
        fn new(keys: Vec<Keypair>, set: &ValidatorSet, height: u64) -> Self {
            let machines = keys
                .iter()
                .map(|k| {
                    ConsensusMachine::new(
                        CURRENT_PROTOCOL_VERSION,
                        ChainId::devnet(),
                        set.clone(),
                        height,
                        Some(identity(k)),
                    )
                })
                .collect();
            let n = keys.len();
            Self {
                machines,
                keys,
                height,
                silent: std::collections::BTreeSet::new(),
                armed: vec![std::collections::BTreeSet::new(); n],
                commits: vec![None; n],
            }
        }

        fn handle(
            &mut self,
            queue: &mut Vec<ConsensusMessage>,
            index: usize,
            actions: Vec<ConsensusAction>,
        ) {
            if let Some(commit) = commit_of(&actions) {
                self.commits[index] = Some(commit);
            }
            for action in actions {
                match action {
                    ConsensusAction::Broadcast(m) => queue.push(m),
                    ConsensusAction::NeedProposalBlock { round } => {
                        if self.silent.contains(&(index, round)) {
                            continue;
                        }
                        let block = candidate_block(
                            self.keys[index].address(),
                            self.height,
                            round as u64 + 1,
                        );
                        let out = self.machines[index].provide_block(round, block).unwrap();
                        self.handle(queue, index, out);
                    }
                    ConsensusAction::ScheduleTimeout { kind, round } => {
                        self.armed[index].insert((timeout_tag(kind), round));
                    }
                    ConsensusAction::Commit { .. } | ConsensusAction::Equivocation(_) => {}
                }
            }
        }

        fn drain(&mut self, queue: &mut Vec<ConsensusMessage>) {
            let mut guard = 0;
            while let Some(message) = queue.pop() {
                guard += 1;
                assert!(guard < 100_000, "bus failed to converge");
                for index in 0..self.machines.len() {
                    let out = self.machines[index]
                        .on_event(ConsensusEvent::Message(message.clone()))
                        .unwrap();
                    self.handle(queue, index, out);
                }
            }
        }

        /// Fires every armed timeout whose round matches its node's current round,
        /// returning whether anything fired.
        fn fire_timeouts(&mut self, queue: &mut Vec<ConsensusMessage>) -> bool {
            let mut fired = false;
            for index in 0..self.machines.len() {
                let current = self.machines[index].round();
                let ready: Vec<(u8, u32)> = self.armed[index]
                    .iter()
                    .copied()
                    .filter(|(_, round)| *round == current)
                    .collect();
                for tag in ready {
                    self.armed[index].remove(&tag);
                    fired = true;
                    let out = self.machines[index]
                        .on_event(ConsensusEvent::Timeout {
                            kind: timeout_of(tag.0),
                            round: tag.1,
                        })
                        .unwrap();
                    self.handle(queue, index, out);
                }
            }
            fired
        }

        fn run(&mut self) {
            let mut queue: Vec<ConsensusMessage> = Vec::new();
            for index in 0..self.machines.len() {
                let out = self.machines[index].start().unwrap();
                self.handle(&mut queue, index, out);
            }
            let mut ticks = 0;
            loop {
                ticks += 1;
                assert!(ticks < 10_000, "consensus did not settle");
                self.drain(&mut queue);
                if self.commits.iter().filter(|c| c.is_some()).count() == self.machines.len() {
                    break;
                }
                // Time advances only when the bus is quiet.
                if !self.fire_timeouts(&mut queue) {
                    break;
                }
            }
        }
    }

    #[test]
    fn single_validator_finalizes_its_own_proposal() {
        let a = Keypair::from_seed([1u8; 32]);
        let set = set_with_keys(&[(&a, 1)]);
        let mut machine = ConsensusMachine::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set,
            1,
            Some(identity(&a)),
        );
        let mut actions = machine.start().unwrap();
        // The sole proposer is asked for a block; supply it and it self-finalizes.
        assert!(matches!(
            actions.first(),
            Some(ConsensusAction::NeedProposalBlock { round: 0 })
        ));
        actions = machine
            .provide_block(0, candidate_block(a.address(), 1, 1))
            .unwrap();
        let (_, cert) = commit_of(&actions).expect("single validator commits");
        assert!(cert
            .verify(
                &set_with_keys(&[(&a, 1)]),
                CURRENT_PROTOCOL_VERSION,
                &ChainId::devnet()
            )
            .is_ok());
        assert!(machine.decided_block().is_some());
    }

    #[test]
    fn three_validators_converge_happy_path() {
        let keys = vec![
            Keypair::from_seed([1u8; 32]),
            Keypair::from_seed([2u8; 32]),
            Keypair::from_seed([3u8; 32]),
        ];
        let set = set_with_keys(&[(&keys[0], 1), (&keys[1], 1), (&keys[2], 1)]);
        let mut harness = Harness::new(keys, &set, 1);
        harness.run();
        let first = harness.commits[0].clone().expect("node 0 commits");
        for slot in &harness.commits {
            let (block, cert) = slot.clone().expect("each node commits");
            assert_eq!(block.hash().unwrap(), first.0.hash().unwrap());
            assert!(cert
                .verify(&set, CURRENT_PROTOCOL_VERSION, &ChainId::devnet())
                .is_ok());
        }
    }

    #[test]
    fn round_changes_when_the_round_zero_proposer_is_silent() {
        // Four validators; the round-0 proposer stays silent. The others must
        // change round and finalize under the round-1 proposer.
        let keys = vec![
            Keypair::from_seed([1u8; 32]),
            Keypair::from_seed([2u8; 32]),
            Keypair::from_seed([3u8; 32]),
            Keypair::from_seed([4u8; 32]),
        ];
        let set = set_with_keys(&[(&keys[0], 1), (&keys[1], 1), (&keys[2], 1), (&keys[3], 1)]);
        // Identify the round-0 leader before moving `keys` into the harness.
        let leader0 = set.proposer_for(1, 0).unwrap();
        let r0 = keys.iter().position(|k| k.address() == leader0).unwrap();
        let mut harness = Harness::new(keys, &set, 1);
        // Silence whoever leads round 0.
        harness.silent.insert((r0, 0));
        harness.run();

        // Every non-silent node finalized the same block at a round >= 1.
        let decided: Vec<_> = harness.commits.iter().flatten().collect();
        assert!(
            decided.len() >= 3,
            "at least the three responsive nodes finalize"
        );
        let first_hash = decided[0].0.hash().unwrap();
        for (block, cert) in &decided {
            assert_eq!(block.hash().unwrap(), first_hash);
            assert!(cert
                .verify(&set, CURRENT_PROTOCOL_VERSION, &ChainId::devnet())
                .is_ok());
        }
        // The decision happened after a round change.
        assert!(harness.machines.iter().any(|m| m.round() >= 1));
    }

    #[test]
    fn a_locked_validator_will_not_prevote_a_conflicting_block() {
        // Safety unit test: once a node locks block X in round 0, a round-1
        // proposal for a different block Y (with no proof-of-lock) draws a nil
        // prevote, never a prevote for Y.
        let a = Keypair::from_seed([1u8; 32]);
        let b = Keypair::from_seed([2u8; 32]);
        let c = Keypair::from_seed([3u8; 32]);
        let set = set_with_keys(&[(&a, 1), (&b, 1), (&c, 1)]);
        // Drive node A as the machine under test.
        let mut node = ConsensusMachine::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set.clone(),
            1,
            Some(identity(&a)),
        );
        node.start().unwrap();

        // Build round-0 proposal from the actual round-0 leader for block X.
        let leader0 = set.proposer_for(1, 0).unwrap();
        let leader0_key = [&a, &b, &c]
            .into_iter()
            .find(|k| k.address() == leader0)
            .unwrap();
        let block_x = candidate_block(leader0, 1, 1);
        let hash_x = block_x.hash().unwrap();
        let prop0 = SignedProposal::sign(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            1,
            0,
            None,
            block_x,
            leader0,
            leader0_key,
        )
        .unwrap();
        node.on_event(ConsensusEvent::Message(ConsensusMessage::Proposal(
            Box::new(prop0),
        )))
        .unwrap();
        // Deliver round-0 prevotes for X from B and C so A locks X.
        for k in [&b, &c] {
            let pv = SignedVote::sign(
                Vote {
                    protocol_version: CURRENT_PROTOCOL_VERSION,
                    chain_id: ChainId::devnet(),
                    height: 1,
                    round: 0,
                    vote_type: VoteType::Prevote,
                    block_hash: hash_x,
                    validator: k.address(),
                },
                k,
            )
            .unwrap();
            node.on_event(ConsensusEvent::Message(ConsensusMessage::Vote(pv)))
                .unwrap();
        }
        assert_eq!(
            node.step(),
            Step::Precommit,
            "A should have locked and precommitted X"
        );

        // Force A into round 1 via a precommit timeout, then feed a round-1
        // proposal for a DIFFERENT block Y from the round-1 leader.
        node.on_event(ConsensusEvent::Timeout {
            kind: TimeoutKind::Precommit,
            round: 0,
        })
        .unwrap();
        assert_eq!(node.round(), 1);
        let leader1 = set.proposer_for(1, 1).unwrap();
        let leader1_key = [&a, &b, &c]
            .into_iter()
            .find(|k| k.address() == leader1)
            .unwrap();
        let block_y = candidate_block(leader1, 1, 9);
        let hash_y = block_y.hash().unwrap();
        assert_ne!(hash_x, hash_y);
        let prop1 = SignedProposal::sign(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            1,
            1,
            None,
            block_y,
            leader1,
            leader1_key,
        )
        .unwrap();
        let actions = node
            .on_event(ConsensusEvent::Message(ConsensusMessage::Proposal(
                Box::new(prop1),
            )))
            .unwrap();
        // A's round-1 prevote must be nil, never Y.
        let prevote_hashes: Vec<Hash256> = broadcasts(&actions)
            .into_iter()
            .filter_map(|m| match m {
                ConsensusMessage::Vote(v) if v.payload.vote_type == VoteType::Prevote => {
                    Some(v.payload.block_hash)
                }
                _ => None,
            })
            .collect();
        assert!(
            prevote_hashes.iter().all(|h| *h == NIL),
            "a node locked on X must not prevote a conflicting Y"
        );
    }

    #[test]
    fn equivocating_validator_is_surfaced_as_evidence() {
        let a = Keypair::from_seed([1u8; 32]);
        let b = Keypair::from_seed([2u8; 32]);
        let c = Keypair::from_seed([3u8; 32]);
        let set = set_with_keys(&[(&a, 1), (&b, 1), (&c, 1)]);
        let mut engine =
            ConsensusMachine::new(CURRENT_PROTOCOL_VERSION, ChainId::devnet(), set, 1, None);
        engine.start().unwrap();

        let prevote = |validator: &Keypair, hash| {
            SignedVote::sign(
                Vote {
                    protocol_version: CURRENT_PROTOCOL_VERSION,
                    chain_id: ChainId::devnet(),
                    height: 1,
                    round: 0,
                    vote_type: VoteType::Prevote,
                    block_hash: hash,
                    validator: validator.address(),
                },
                validator,
            )
            .unwrap()
        };
        engine
            .on_event(ConsensusEvent::Message(ConsensusMessage::Vote(prevote(
                &b,
                Hash256::digest(b"x"),
            ))))
            .unwrap();
        let out = engine
            .on_event(ConsensusEvent::Message(ConsensusMessage::Vote(prevote(
                &b,
                Hash256::digest(b"y"),
            ))))
            .unwrap();
        let evidence = out
            .iter()
            .find_map(|a| match a {
                ConsensusAction::Equivocation(ev) => Some((**ev).clone()),
                _ => None,
            })
            .expect("equivocation surfaced");
        let slashing = crate::SlashingEvidence::DoubleVote(evidence);
        assert!(slashing
            .verify(
                CURRENT_PROTOCOL_VERSION,
                &ChainId::devnet(),
                &b.public_key()
            )
            .is_ok());
    }
}
