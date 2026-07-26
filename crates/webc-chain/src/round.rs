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
//! Crash safety (the C4 write-ahead journal): signing the same (height, round,
//! step) twice with different content is objective, slashable equivocation, so
//! a validator must never forget what it already signed. The machine itself
//! stays free of I/O; instead it exposes its own signed messages and lock state
//! as a [`ConsensusWalRecord`] via [`ConsensusMachine::wal_record`], and the
//! driver MUST persist that record durably *before* broadcasting each own
//! message and feed it back through [`ConsensusMachine::restore`] when it
//! rebuilds a machine for the same height after a restart. A restored machine
//! re-enters the journaled round, never re-signs a recorded step, and keeps its
//! lock, so an honest restart can neither self-equivocate nor violate lock
//! safety. If the journal cannot be read or fails validation, the driver must
//! fail closed and run the height without a voting identity.
//!
//! Memory bounds (C3): every per-round map is keyed by a peer-chosen `u32`
//! round, so ingestion ignores messages more than [`MAX_FUTURE_ROUNDS`] above
//! the current round and each round change evicts storage more than
//! [`MAX_PAST_ROUNDS`] below it. A staked attacker can therefore never size
//! this machine's memory with signed votes or full-block proposals for
//! arbitrary rounds; the machine holds at most a fixed window of rounds.
//!
//! Deferred: dynamic timeout durations, gossiping the full vote set for faster
//! catch-up, and sub-committee sampling are driver/refinement concerns, not part
//! of this safety core.

use crate::{
    Block, BuiltBlockV4, ChainError, ChainId, DoubleVoteEvidence, FinalityAuthoritySetV1,
    FinalityCertificate, Proposal, ProtocolVersion, SignedProposal, SignedProposalV1, SignedVote,
    ValidatorSet, Vote, VoteType,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use webc_crypto::{Address, Hash256, Keypair};

/// The reserved sentinel identifying a nil vote (a vote for "no block").
const NIL: Hash256 = Hash256::ZERO;

/// How far above the current round a received consensus message may be before
/// it is ignored (C3 memory bound).
///
/// Vote and proposal storage is keyed by a peer-chosen `u32` round; without a
/// horizon, any snapshot member could sign votes for rounds `0..2^32` (and a
/// scheduled leader full-block proposals for its slots) and exhaust memory.
/// The window must stay large enough for the `f+1` round catch-up (rule 55) to
/// function across ordinary delays; a node that falls further behind within
/// one height recovers at the next height via certificate-verified state sync
/// instead. Rounds only ever increase, so the horizon slides forward.
pub const MAX_FUTURE_ROUNDS: u32 = 32;

/// How many rounds below the current round remain stored (C3 memory bound).
///
/// Past-round votes are kept so a quorum that completes late can still decide
/// an earlier round (paper rule 49); keeping a bounded window instead of
/// everything caps memory at `MAX_PAST_ROUNDS + MAX_FUTURE_ROUNDS + 1` rounds
/// per validator. A decide missed because its round was evicted is recovered
/// via state sync from peers that did decide. The node's own lock and valid
/// value live in dedicated fields and are never evicted, so lock safety does
/// not depend on this window.
pub const MAX_PAST_ROUNDS: u32 = 32;

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

/// Version-parameterized consensus message exchanged for one height.
#[derive(Clone, Debug)]
pub enum ConsensusMessageCore<P> {
    /// The scheduled leader's signed block proposal.
    Proposal(Box<P>),
    /// A signed prevote or precommit (nil is the all-zero sentinel hash).
    Vote(SignedVote),
}

/// Version-parameterized input to a machine.
#[derive(Clone, Debug)]
pub enum ConsensusEventCore<P> {
    /// A message received from a peer (or produced locally).
    Message(ConsensusMessageCore<P>),
    /// A timeout the driver previously armed has fired.
    Timeout {
        /// Which timeout fired.
        kind: TimeoutKind,
        /// The round the timeout was armed for.
        round: u32,
    },
}

/// Version-parameterized instruction emitted by the safety core.
#[derive(Clone, Debug)]
pub enum ConsensusActionCore<P, B> {
    /// Gossip this message to peers (it has already been applied locally).
    Broadcast(ConsensusMessageCore<P>),
    /// Arm this timeout; fire it back as a [`ConsensusEvent::Timeout`] on expiry.
    ScheduleTimeout {
        /// Which timeout to arm.
        kind: TimeoutKind,
        /// The round this timeout belongs to.
        round: u32,
    },
    /// This node is the proposer for `round` and has no locked value to
    /// re-propose: the driver should build a candidate block and hand it back via
    /// the matching machine's `provide_block` method.
    NeedProposalBlock {
        /// The round the block is needed for.
        round: u32,
    },
    /// Finalize this block; its certificate independently proves quorum.
    Commit {
        /// The finalized block.
        block: Box<B>,
        /// The proof that strictly over two thirds precommitted it.
        certificate: Box<FinalityCertificate>,
    },
    /// A validator equivocated (signed two conflicting votes in one step/round).
    /// The driver should include this objective evidence in a future block, where
    /// the existing verified slashing path penalizes the offender exactly once.
    Equivocation(Box<DoubleVoteEvidence>),
}

/// Everything a validator must remember across a crash to avoid signing a
/// conflicting consensus message for a step it already signed (the C4
/// write-ahead journal, following Tendermint's persisted
/// `(height, round, step, lock, last-signed vote)` requirement).
///
/// The driver persists this record durably **before** broadcasting each own
/// signed message and replays it into a fresh machine for the same height via
/// [`ConsensusMachine::restore`]. All fields are this validator's *own*
/// artifacts; peer votes are deliberately excluded (losing them costs liveness
/// only, never safety). Invariant: `votes` never contains two entries for one
/// `(round, vote_type)` with different block hashes — `restore` rejects such a
/// journal as corrupt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusWalRecordCore<P, B> {
    /// The single consensus height this journal covers.
    pub height: u64,
    /// Every proposal this validator signed at this height, in signing order.
    pub proposals: Vec<P>,
    /// Every vote this validator signed at this height, in signing order.
    pub votes: Vec<SignedVote>,
    /// The round this node locked in, if any (present iff `locked_value` is).
    pub locked_round: Option<u32>,
    /// The block this node locked (precommitted), if any.
    pub locked_value: Option<B>,
    /// The round of the latest observed prevote quorum, if any (present iff
    /// `valid_value` is).
    pub valid_round: Option<u32>,
    /// The latest block observed to reach a prevote quorum, if any.
    pub valid_value: Option<B>,
}

/// Frozen protocol-1 consensus message.
pub type ConsensusMessage = ConsensusMessageCore<SignedProposal>;
/// Protocol-2 V4 consensus message.
pub type ConsensusMessageV1 = ConsensusMessageCore<SignedProposalV1>;
/// Frozen protocol-1 consensus event.
pub type ConsensusEvent = ConsensusEventCore<SignedProposal>;
/// Protocol-2 V4 consensus event.
pub type ConsensusEventV1 = ConsensusEventCore<SignedProposalV1>;
/// Frozen protocol-1 consensus action.
pub type ConsensusAction = ConsensusActionCore<SignedProposal, Block>;
/// Protocol-2 V4 consensus action.
pub type ConsensusActionV1 = ConsensusActionCore<SignedProposalV1, BuiltBlockV4>;
/// Frozen protocol-1 crash-safety record.
pub type ConsensusWalRecord = ConsensusWalRecordCore<SignedProposal, Block>;
/// Protocol-2 V4 crash-safety record.
pub type ConsensusWalRecordV1 = ConsensusWalRecordCore<SignedProposalV1, BuiltBlockV4>;

/// Adapter between the shared BFT safety core and a versioned proposal format.
///
/// Implementations own proposal signing/verification and value hashing; round,
/// lock, vote, quorum, timeout, equivocation, and WAL rules remain one code path.
#[doc(hidden)]
pub trait ConsensusProposalScheme {
    /// Full value retained while locked and returned on finality.
    type Value: Clone + Debug + PartialEq + Eq;
    /// Signed proposal envelope exchanged with peers.
    type SignedProposal: Clone + Debug + PartialEq + Eq;
    /// Immutable proposal verification context for this height.
    type Context: Clone;

    /// Returns the common signed metadata used by the safety rules.
    fn payload(proposal: &Self::SignedProposal) -> &Proposal;
    /// Reconstructs the full consensus value carried by a proposal.
    fn value(proposal: &Self::SignedProposal) -> Self::Value;
    /// Returns the independently signed proof-of-lock votes.
    fn proof_of_lock(proposal: &Self::SignedProposal) -> &[SignedVote];
    /// Computes the value identifier votes certify.
    fn value_hash(value: &Self::Value) -> Result<Hash256, ChainError>;
    /// Verifies a received proposal against this height's immutable context.
    fn verify(
        proposal: &Self::SignedProposal,
        set: &ValidatorSet,
        protocol_version: ProtocolVersion,
        chain_id: &ChainId,
        context: &Self::Context,
    ) -> Result<(), ChainError>;
    /// Signs a proposal using the version-specific envelope and domain.
    #[allow(clippy::too_many_arguments)]
    fn sign(
        protocol_version: ProtocolVersion,
        chain_id: ChainId,
        height: u64,
        round: u32,
        valid_round: Option<u32>,
        value: Self::Value,
        proposer: Address,
        consensus_key: &Keypair,
        proof_of_lock: Vec<SignedVote>,
        context: &Self::Context,
    ) -> Result<Self::SignedProposal, ChainError>;
}

type MachineActions<S> = Vec<
    ConsensusActionCore<
        <S as ConsensusProposalScheme>::SignedProposal,
        <S as ConsensusProposalScheme>::Value,
    >,
>;

/// Adapter preserving the frozen legacy proposal behavior and bytes.
#[derive(Clone, Copy, Debug)]
#[doc(hidden)]
pub struct LegacyConsensusScheme;

impl ConsensusProposalScheme for LegacyConsensusScheme {
    type Value = Block;
    type SignedProposal = SignedProposal;
    type Context = ();

    fn payload(proposal: &Self::SignedProposal) -> &Proposal {
        &proposal.payload
    }

    fn value(proposal: &Self::SignedProposal) -> Self::Value {
        proposal.block.clone()
    }

    fn proof_of_lock(proposal: &Self::SignedProposal) -> &[SignedVote] {
        &proposal.proof_of_lock
    }

    fn value_hash(value: &Self::Value) -> Result<Hash256, ChainError> {
        value.hash()
    }

    fn verify(
        proposal: &Self::SignedProposal,
        set: &ValidatorSet,
        protocol_version: ProtocolVersion,
        chain_id: &ChainId,
        _context: &Self::Context,
    ) -> Result<(), ChainError> {
        proposal.verify_in_set(set, protocol_version, chain_id)
    }

    fn sign(
        protocol_version: ProtocolVersion,
        chain_id: ChainId,
        height: u64,
        round: u32,
        valid_round: Option<u32>,
        value: Self::Value,
        proposer: Address,
        consensus_key: &Keypair,
        proof_of_lock: Vec<SignedVote>,
        _context: &Self::Context,
    ) -> Result<Self::SignedProposal, ChainError> {
        SignedProposal::sign_with_proof_of_lock(
            protocol_version,
            chain_id,
            height,
            round,
            valid_round,
            value,
            proposer,
            consensus_key,
            proof_of_lock,
        )
    }
}

/// Adapter binding the shared BFT rules to V4 proposal/authority semantics.
#[derive(Clone, Copy, Debug)]
#[doc(hidden)]
pub struct Protocol2ConsensusScheme;

impl ConsensusProposalScheme for Protocol2ConsensusScheme {
    type Value = BuiltBlockV4;
    type SignedProposal = SignedProposalV1;
    type Context = FinalityAuthoritySetV1;

    fn payload(proposal: &Self::SignedProposal) -> &Proposal {
        &proposal.payload
    }

    fn value(proposal: &Self::SignedProposal) -> Self::Value {
        BuiltBlockV4 {
            block: proposal.block.clone(),
            next_authority_set: proposal.next_authority_set.clone(),
        }
    }

    fn proof_of_lock(proposal: &Self::SignedProposal) -> &[SignedVote] {
        &proposal.proof_of_lock
    }

    fn value_hash(value: &Self::Value) -> Result<Hash256, ChainError> {
        value
            .block
            .header
            .hash()
            .map_err(|_| ChainError::ConsensusProtocol2ProposalInvalid)
    }

    fn verify(
        proposal: &Self::SignedProposal,
        _set: &ValidatorSet,
        _protocol_version: ProtocolVersion,
        _chain_id: &ChainId,
        context: &Self::Context,
    ) -> Result<(), ChainError> {
        proposal
            .verify_in_authority_set(context)
            .map_err(|_| ChainError::ConsensusProtocol2ProposalInvalid)
    }

    fn sign(
        _protocol_version: ProtocolVersion,
        _chain_id: ChainId,
        _height: u64,
        round: u32,
        valid_round: Option<u32>,
        value: Self::Value,
        _proposer: Address,
        consensus_key: &Keypair,
        proof_of_lock: Vec<SignedVote>,
        _context: &Self::Context,
    ) -> Result<Self::SignedProposal, ChainError> {
        SignedProposalV1::sign_with_proof_of_lock(
            round,
            valid_round,
            value.block,
            value.next_authority_set,
            consensus_key,
            proof_of_lock,
        )
        .map_err(|_| ChainError::ConsensusProtocol2ProposalInvalid)
    }
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
pub struct ConsensusMachineCore<S: ConsensusProposalScheme> {
    protocol_version: ProtocolVersion,
    chain_id: ChainId,
    set: ValidatorSet,
    height: u64,
    identity: Option<ValidatorIdentity>,
    proposal_context: S::Context,

    round: u32,
    step: Step,

    /// The value this node precommitted and the round it did so (its lock).
    locked_value: Option<S::Value>,
    locked_round: Option<u32>,
    /// The latest value this node saw reach a prevote quorum, and its round.
    valid_value: Option<S::Value>,
    valid_round: Option<u32>,

    /// One accepted proposal per round, from that round's scheduled leader.
    proposals: BTreeMap<u32, S::SignedProposal>,
    /// First prevote per `(round, validator)`.
    prevotes: BTreeMap<(u32, Address), SignedVote>,
    /// First precommit per `(round, validator)`.
    precommits: BTreeMap<(u32, Address), SignedVote>,

    /// Offenders already reported per `(round, step)`, so each conflict is
    /// surfaced as evidence at most once.
    reported_equivocators: BTreeSet<(u32, Address, VoteType)>,
    /// Fired once-only rule guards.
    guards: BTreeSet<(Guard, u32)>,

    /// Every proposal this node signed at this height, in signing order — the
    /// proposal half of the crash-safety journal (see [`ConsensusWalRecord`]).
    own_proposals: Vec<S::SignedProposal>,
    /// Every vote this node signed at this height, in signing order — the vote
    /// half of the crash-safety journal.
    own_votes: Vec<SignedVote>,
    /// Whether this machine was rebuilt from a journal; [`Self::start`] then
    /// re-enters the journaled round instead of starting round 0 fresh.
    restored: bool,

    /// The finalized block and its certificate, once decided.
    decision: Option<(S::Value, FinalityCertificate)>,
}

/// Frozen protocol-1 BFT machine.
pub type ConsensusMachine = ConsensusMachineCore<LegacyConsensusScheme>;
/// Protocol-2 V4 BFT machine using the identical round/lock/quorum core.
pub type ConsensusMachineV1 = ConsensusMachineCore<Protocol2ConsensusScheme>;

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
        Self::new_core(protocol_version, chain_id, set, height, identity, ())
    }
}

impl ConsensusMachineV1 {
    /// Creates a protocol-2 machine from the exact outgoing authority snapshot.
    ///
    /// The snapshot supplies protocol, chain, epoch commitment context, leader
    /// schedule, and vote keys. Proposal execution remains a driver concern.
    pub fn new(
        current_authority_set: FinalityAuthoritySetV1,
        height: u64,
        identity: Option<ValidatorIdentity>,
    ) -> Result<Self, ChainError> {
        let protocol_version = current_authority_set.protocol_version;
        let chain_id = current_authority_set.chain_id.clone();
        let set = current_authority_set
            .to_validator_set()
            .map_err(|_| ChainError::ConsensusProtocol2ProposalInvalid)?;
        Ok(Self::new_core(
            protocol_version,
            chain_id,
            set,
            height,
            identity,
            current_authority_set,
        ))
    }
}

impl<S: ConsensusProposalScheme> ConsensusMachineCore<S> {
    fn new_core(
        protocol_version: ProtocolVersion,
        chain_id: ChainId,
        set: ValidatorSet,
        height: u64,
        identity: Option<ValidatorIdentity>,
        proposal_context: S::Context,
    ) -> Self {
        Self {
            protocol_version,
            chain_id,
            set,
            height,
            identity,
            proposal_context,
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
            own_proposals: Vec::new(),
            own_votes: Vec::new(),
            restored: false,
            decision: None,
        }
    }

    /// Emits the startup actions. Call exactly once after [`Self::new`] (and
    /// after [`Self::restore`], when a journal exists).
    ///
    /// Fresh machine: starts round 0 (propose or arm the propose timeout).
    /// Restored machine: re-enters the journaled round *without signing
    /// anything new for it* and arms a precommit timeout, so the node moves to
    /// the next (fresh) round if the network cannot re-complete the journaled
    /// one. Never re-proposing or re-voting a journaled step is exactly the
    /// anti-self-equivocation guarantee of the journal.
    pub fn start(&mut self) -> Result<MachineActions<S>, ChainError> {
        let mut actions = Vec::new();
        if self.restored {
            actions.push(ConsensusActionCore::ScheduleTimeout {
                kind: TimeoutKind::Precommit,
                round: self.round,
            });
            self.drive(&mut actions)?;
            return Ok(actions);
        }
        self.start_round(0, &mut actions)?;
        Ok(actions)
    }

    /// Snapshot of everything this node has signed at this height plus its lock
    /// state — the crash-safety journal a driver must persist durably before
    /// each own broadcast. See [`ConsensusWalRecord`].
    pub fn wal_record(&self) -> ConsensusWalRecordCore<S::SignedProposal, S::Value> {
        ConsensusWalRecordCore {
            height: self.height,
            proposals: self.own_proposals.clone(),
            votes: self.own_votes.clone(),
            locked_round: self.locked_round,
            locked_value: self.locked_value.clone(),
            valid_round: self.valid_round,
            valid_value: self.valid_value.clone(),
        }
    }

    /// Replays a persisted journal into a freshly created machine, so a
    /// validator restarting mid-height never signs a conflicting message for a
    /// (round, step) it already signed and never abandons its lock.
    ///
    /// Call after [`Self::new`] and before [`Self::start`], only on a machine
    /// with a voting identity. The journal is validated as hostile input even
    /// though it is local storage: every entry must be this validator's own,
    /// signature-verified message for exactly this height, the journal must not
    /// itself contain conflicting votes, and the lock/valid pairs must be
    /// internally consistent. Any violation returns
    /// [`ChainError::ConsensusWalMismatch`] with the machine unchanged; the
    /// caller must then fail closed (run the height without a voting identity),
    /// because a journal that cannot be trusted means the node no longer knows
    /// what it already signed.
    pub fn restore(
        &mut self,
        record: ConsensusWalRecordCore<S::SignedProposal, S::Value>,
    ) -> Result<(), ChainError> {
        // Only a machine that has done nothing yet can be restored: replaying
        // into a live machine could erase signing guards.
        if self.restored
            || self.decision.is_some()
            || self.round != 0
            || self.step != Step::Propose
            || !self.own_proposals.is_empty()
            || !self.own_votes.is_empty()
        {
            return Err(ChainError::ConsensusWalMismatch);
        }
        if record.height != self.height {
            return Err(ChainError::ConsensusWalMismatch);
        }
        let identity_address = self
            .identity
            .as_ref()
            .map(|identity| identity.address)
            .ok_or(ChainError::ConsensusWalMismatch)?;

        // Validate everything before mutating anything, so a corrupt journal
        // leaves the machine untouched.
        for proposal in &record.proposals {
            let payload = S::payload(proposal);
            if payload.height != self.height || payload.proposer != identity_address {
                return Err(ChainError::ConsensusWalMismatch);
            }
            S::verify(
                proposal,
                &self.set,
                self.protocol_version,
                &self.chain_id,
                &self.proposal_context,
            )?;
        }
        let mut first_hash_per_step: BTreeMap<(u32, VoteType), Hash256> = BTreeMap::new();
        for vote in &record.votes {
            if vote.payload.height != self.height || vote.payload.validator != identity_address {
                return Err(ChainError::ConsensusWalMismatch);
            }
            self.set
                .verify_vote(vote, self.protocol_version, &self.chain_id)?;
            // A journal that already contains two conflicting votes for one
            // step records an equivocation that has already happened; nothing
            // safe can be replayed from it.
            match first_hash_per_step.entry((vote.payload.round, vote.payload.vote_type)) {
                std::collections::btree_map::Entry::Occupied(existing) => {
                    if *existing.get() != vote.payload.block_hash {
                        return Err(ChainError::ConsensusWalMismatch);
                    }
                }
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(vote.payload.block_hash);
                }
            }
        }
        if record.locked_round.is_some() != record.locked_value.is_some()
            || record.valid_round.is_some() != record.valid_value.is_some()
        {
            return Err(ChainError::ConsensusWalMismatch);
        }

        // Apply: re-insert own messages so tallies still count this node, and
        // re-arm the per-round "already signed" guards so no recorded step can
        // be signed again.
        let mut max_round = 0u32;
        let mut any_activity = false;
        for proposal in record.proposals {
            let round = S::payload(&proposal).round;
            max_round = max_round.max(round);
            any_activity = true;
            self.own_proposals.push(proposal.clone());
            self.proposals.entry(round).or_insert(proposal);
        }
        for vote in record.votes {
            let round = vote.payload.round;
            max_round = max_round.max(round);
            any_activity = true;
            let guard = match vote.payload.vote_type {
                VoteType::Prevote => Guard::PrevoteSent,
                VoteType::Precommit => Guard::PrecommitSent,
            };
            self.guards.insert((guard, round));
            self.own_votes.push(vote.clone());
            let _ = self.record_vote(vote);
        }
        self.locked_value = record.locked_value;
        self.locked_round = record.locked_round;
        self.valid_value = record.valid_value;
        self.valid_round = record.valid_round;
        if any_activity {
            self.round = max_round;
            self.step = if self.guards.contains(&(Guard::PrecommitSent, max_round)) {
                Step::Precommit
            } else if self.guards.contains(&(Guard::PrevoteSent, max_round)) {
                Step::Prevote
            } else {
                Step::Propose
            };
        }
        self.restored = true;
        Ok(())
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
    pub fn decided_block(&self) -> Option<&S::Value> {
        self.decision.as_ref().map(|(block, _)| block)
    }

    /// The finality certificate, once decided.
    pub fn certificate(&self) -> Option<&FinalityCertificate> {
        self.decision.as_ref().map(|(_, cert)| cert)
    }

    /// The driver's response to `NeedProposalBlock`: supplies a
    /// freshly built candidate block for `round`, which the machine signs,
    /// broadcasts, and applies. A stale or unsolicited block is ignored.
    pub fn provide_block(
        &mut self,
        round: u32,
        block: S::Value,
    ) -> Result<MachineActions<S>, ChainError> {
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
    pub fn on_event(
        &mut self,
        event: ConsensusEventCore<S::SignedProposal>,
    ) -> Result<MachineActions<S>, ChainError> {
        let mut actions = Vec::new();
        if self.decision.is_some() {
            return Ok(actions);
        }
        match event {
            ConsensusEventCore::Message(ConsensusMessageCore::Proposal(signed)) => {
                let payload = S::payload(&signed);
                if payload.height != self.height || self.beyond_future_horizon(payload.round) {
                    return Ok(actions);
                }
                S::verify(
                    &signed,
                    &self.set,
                    self.protocol_version,
                    &self.chain_id,
                    &self.proposal_context,
                )?;
                // C5: a re-proposal carries a verified proof-of-lock — the 2f+1
                // prevotes for its `valid_round`. Absorb them into this node's
                // own prevote tally (they are already snapshot-verified) so a
                // node that missed those prevotes can now satisfy the rule-28
                // guard and follow the lock instead of prevoting nil forever.
                self.absorb_proof_of_lock(S::proof_of_lock(&signed));
                // Keep one proposal per round (the first from its valid leader).
                self.proposals.entry(payload.round).or_insert(*signed);
            }
            ConsensusEventCore::Message(ConsensusMessageCore::Vote(vote)) => {
                if vote.payload.height != self.height
                    || self.beyond_future_horizon(vote.payload.round)
                {
                    return Ok(actions);
                }
                self.set
                    .verify_vote(&vote, self.protocol_version, &self.chain_id)?;
                if let Some(evidence) = self.record_vote(vote) {
                    actions.push(ConsensusActionCore::Equivocation(Box::new(evidence)));
                }
            }
            ConsensusEventCore::Timeout { kind, round } => {
                self.on_timeout(kind, round, &mut actions)?;
            }
        }
        self.drive(&mut actions)?;
        Ok(actions)
    }

    /// Whether a message's round is too far above the current round to store
    /// (C3): storage keyed by a peer-chosen round must stay inside a sliding
    /// window or a staked attacker can exhaust memory with valid signatures.
    fn beyond_future_horizon(&self, round: u32) -> bool {
        round > self.round.saturating_add(MAX_FUTURE_ROUNDS)
    }

    /// Drops per-round storage for rounds below the past window (C3). Rounds
    /// only ever increase, and this node signs only at `self.round`, so
    /// evicted guards can never re-enable signing an old step; the lock and
    /// valid value live in dedicated fields and are untouched. The cost of
    /// eviction is only that a quorum completing extremely late cannot decide
    /// that old round locally — state sync recovers the height instead.
    fn evict_stale_rounds(&mut self) {
        let keep_from = self.round.saturating_sub(MAX_PAST_ROUNDS);
        self.proposals.retain(|round, _| *round >= keep_from);
        self.prevotes.retain(|(round, _), _| *round >= keep_from);
        self.precommits.retain(|(round, _), _| *round >= keep_from);
        self.reported_equivocators
            .retain(|(round, _, _)| *round >= keep_from);
        self.guards.retain(|(_, round)| *round >= keep_from);
    }

    /// Begins a round: resets the step and either proposes (if this node leads and
    /// has a value) or arms the propose timeout.
    fn start_round(
        &mut self,
        round: u32,
        actions: &mut MachineActions<S>,
    ) -> Result<(), ChainError> {
        self.round = round;
        self.step = Step::Propose;
        self.evict_stale_rounds();
        if self.is_proposer(round) {
            match self.valid_value.clone() {
                // Re-propose a value that already reached a prevote quorum, citing
                // the round it did so as the authenticated proof-of-lock.
                Some(value) => {
                    let valid_round = self.valid_round;
                    self.emit_proposal(round, value, valid_round, actions)?;
                }
                // No value to re-propose: ask the driver for a fresh candidate.
                None => actions.push(ConsensusActionCore::NeedProposalBlock { round }),
            }
        } else {
            actions.push(ConsensusActionCore::ScheduleTimeout {
                kind: TimeoutKind::Propose,
                round,
            });
        }
        Ok(())
    }

    /// Signs, stores, and broadcasts this node's proposal for `round`.
    ///
    /// For a re-proposal (`valid_round = Some(vr)`) this attaches the
    /// proof-of-lock: the 2f+1 prevotes this node recorded for `(vr, block)`
    /// (C5). A fresh proposal (`valid_round = None`) carries no lock proof. If
    /// the lock prevotes are somehow unavailable (they always are for a value
    /// this node marked valid), it degrades to a fresh proposal rather than
    /// emitting an unprovable re-proposal.
    fn emit_proposal(
        &mut self,
        round: u32,
        block: S::Value,
        valid_round: Option<u32>,
        actions: &mut MachineActions<S>,
    ) -> Result<(), ChainError> {
        let identity = self
            .identity
            .as_ref()
            .ok_or(ChainError::ConsensusProposalNotFromLeader)?;
        let block_hash = S::value_hash(&block)?;
        // Assemble the proof-of-lock for a re-proposal. `valid_round` is a round
        // this node observed reach a prevote quorum, so it holds the prevotes.
        let (valid_round, proof_of_lock) = match valid_round {
            Some(vr) => {
                let prevotes = self.prevote_quorum_for(vr, block_hash);
                if self.set.has_two_thirds_power(self.prevote_power(&prevotes)) {
                    (Some(vr), prevotes)
                } else {
                    // Cannot prove the lock; propose fresh rather than emit an
                    // unverifiable re-proposal every peer would reject.
                    (None, Vec::new())
                }
            }
            None => (None, Vec::new()),
        };
        let signed = S::sign(
            self.protocol_version,
            self.chain_id.clone(),
            self.height,
            round,
            valid_round,
            block,
            identity.address,
            &identity.consensus_key,
            proof_of_lock,
            &self.proposal_context,
        )?;
        // Journal before queueing the broadcast: the driver persists
        // `wal_record()` durably before this message reaches the wire.
        self.own_proposals.push(signed.clone());
        self.proposals.insert(round, signed.clone());
        actions.push(ConsensusActionCore::Broadcast(
            ConsensusMessageCore::Proposal(Box::new(signed)),
        ));
        Ok(())
    }

    /// Collects this node's recorded prevotes for `(round, block_hash)`, one per
    /// validator — the raw material for a proof-of-lock (C5).
    fn prevote_quorum_for(&self, round: u32, block_hash: Hash256) -> Vec<SignedVote> {
        self.prevotes
            .iter()
            .filter(|((r, _), vote)| *r == round && vote.payload.block_hash == block_hash)
            .map(|(_, vote)| vote.clone())
            .collect()
    }

    /// Sums the snapshot power of the distinct validators behind `prevotes`.
    fn prevote_power(&self, prevotes: &[SignedVote]) -> crate::Amount {
        let mut seen = BTreeSet::new();
        let mut power = crate::Amount::ZERO;
        for vote in prevotes {
            if seen.insert(vote.payload.validator) {
                match power.checked_add(self.set.power_of(vote.payload.validator)) {
                    Some(next) => power = next,
                    None => return crate::Amount::ZERO,
                }
            }
        }
        power
    }

    /// Records the verified prevotes carried by a re-proposal's proof-of-lock
    /// into this node's own prevote tally, first-vote-wins per (round,
    /// validator) (C5). The prevotes were already snapshot-verified by
    /// [`SignedProposal::verify_in_set`], so this only needs to insert absent
    /// entries; it never overwrites a locally-observed vote and never emits
    /// equivocation evidence (that path stays owned by live vote ingestion).
    fn absorb_proof_of_lock(&mut self, prevotes: &[SignedVote]) {
        for vote in prevotes {
            // Ignore anything outside the retained round window so this cannot
            // reintroduce evicted state (C3 bound).
            if self.beyond_future_horizon(vote.payload.round) {
                continue;
            }
            let key = (vote.payload.round, vote.payload.validator);
            self.prevotes.entry(key).or_insert_with(|| vote.clone());
        }
    }

    /// Handles a fired timeout for its round and step.
    fn on_timeout(
        &mut self,
        kind: TimeoutKind,
        round: u32,
        actions: &mut MachineActions<S>,
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
    fn drive(&mut self, actions: &mut MachineActions<S>) -> Result<(), ChainError> {
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
    fn rule_propose(&mut self, actions: &mut MachineActions<S>) -> Result<bool, ChainError> {
        if self.step != Step::Propose {
            return Ok(false);
        }
        let Some(proposal) = self.proposals.get(&self.round).cloned() else {
            return Ok(false);
        };
        let payload = S::payload(&proposal);
        let block_hash = payload.block_hash;
        match payload.valid_round {
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
    fn rule_prevote_timeout(&mut self, actions: &mut MachineActions<S>) -> bool {
        if self.step != Step::Prevote
            || self.guard_set(Guard::PrevoteTimeoutScheduled)
            || !self.has_prevote_quorum(self.round, HashFilter::Any)
        {
            return false;
        }
        self.set_guard(Guard::PrevoteTimeoutScheduled);
        actions.push(ConsensusActionCore::ScheduleTimeout {
            kind: TimeoutKind::Prevote,
            round: self.round,
        });
        true
    }

    /// Rule 36: on the current round's proposal plus a prevote quorum for its
    /// block while in Prevote or later — lock and precommit it (if still in
    /// Prevote) and record it as the valid value.
    fn rule_prevote_quorum(&mut self, actions: &mut MachineActions<S>) -> Result<bool, ChainError> {
        if self.step == Step::Propose || self.guard_set(Guard::ValidValueUpdated) {
            return Ok(false);
        }
        let Some(proposal) = self.proposals.get(&self.round).cloned() else {
            return Ok(false);
        };
        let block_hash = S::payload(&proposal).block_hash;
        if !self.has_prevote_quorum(self.round, HashFilter::Exactly(block_hash)) {
            return Ok(false);
        }
        if self.step == Step::Prevote {
            self.locked_value = Some(S::value(&proposal));
            self.locked_round = Some(self.round);
            self.cast_precommit(block_hash, actions)?;
            self.step = Step::Precommit;
        }
        self.valid_value = Some(S::value(&proposal));
        self.valid_round = Some(self.round);
        self.set_guard(Guard::ValidValueUpdated);
        Ok(true)
    }

    /// Rule 44: on a prevote quorum for nil in the current round while in Prevote,
    /// precommit nil and move to Precommit.
    fn rule_prevote_nil(&mut self, actions: &mut MachineActions<S>) -> Result<bool, ChainError> {
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
    fn rule_precommit_timeout(&mut self, actions: &mut MachineActions<S>) -> bool {
        if self.guard_set(Guard::PrecommitTimeoutScheduled)
            || !self.has_precommit_quorum(self.round, HashFilter::Any)
        {
            return false;
        }
        self.set_guard(Guard::PrecommitTimeoutScheduled);
        actions.push(ConsensusActionCore::ScheduleTimeout {
            kind: TimeoutKind::Precommit,
            round: self.round,
        });
        true
    }

    /// Rule 49: for any round whose proposal has a precommit quorum for its block,
    /// decide that block. This can finalize a block proposed in an earlier round.
    fn rule_decide(&mut self, actions: &mut MachineActions<S>) -> Result<bool, ChainError> {
        if self.decision.is_some() {
            return Ok(false);
        }
        // Find a round whose proposed block has a precommit quorum.
        let rounds: Vec<u32> = self.proposals.keys().copied().collect();
        for round in rounds {
            let Some(proposal) = self.proposals.get(&round).cloned() else {
                continue;
            };
            let block_hash = S::payload(&proposal).block_hash;
            if !self.has_precommit_quorum(round, HashFilter::Exactly(block_hash)) {
                continue;
            }
            let Some(certificate) = self.build_certificate(round, block_hash) else {
                continue;
            };
            let value = S::value(&proposal);
            self.decision = Some((value.clone(), certificate.clone()));
            actions.push(ConsensusActionCore::Commit {
                block: Box::new(value),
                certificate: Box::new(certificate),
            });
            return Ok(true);
        }
        Ok(false)
    }

    /// Rule 55: if more than one third of the power has sent any message for a
    /// round greater than the current one, jump to that round (an honest node is
    /// necessarily among a `f+1` set, so this cannot be forced by faults alone).
    fn rule_catch_up(&mut self, actions: &mut MachineActions<S>) -> Result<bool, ChainError> {
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
        actions: &mut MachineActions<S>,
    ) -> Result<(), ChainError> {
        self.cast_vote(VoteType::Prevote, Guard::PrevoteSent, block_hash, actions)
    }

    /// Signs, records, and queues this node's precommit for the current round once.
    fn cast_precommit(
        &mut self,
        block_hash: Hash256,
        actions: &mut MachineActions<S>,
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
        actions: &mut MachineActions<S>,
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
        // Journal before queueing the broadcast: the driver persists
        // `wal_record()` durably before this vote reaches the wire, so a crash
        // can never forget a vote that peers may have seen.
        self.own_votes.push(vote.clone());
        // Count our own vote locally so single-validator sets can reach quorum.
        let _ = self.record_vote(vote.clone());
        actions.push(ConsensusActionCore::Broadcast(ConsensusMessageCore::Vote(
            vote,
        )));
        Ok(())
    }

    /// Hash of this node's locked value, if any.
    fn locked_value_hash(&self) -> Option<Hash256> {
        // The locked value equals the proposal it was locked from; its hash is the
        // block hash. Recomputing is cheap and avoids storing it separately.
        self.locked_value
            .as_ref()
            .and_then(|value| S::value_hash(value).ok())
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
    use crate::{
        Amount, BlockHeader, BlockHeaderV4, BlockHeight, Epoch, CURRENT_PROTOCOL_VERSION,
        TRANSACTION_V5_PROTOCOL_VERSION,
    };
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

    fn authority_v1(set: &ValidatorSet) -> FinalityAuthoritySetV1 {
        FinalityAuthoritySetV1::from_validator_set(
            TRANSACTION_V5_PROTOCOL_VERSION,
            ChainId::devnet(),
            Epoch::new(0),
            set,
        )
        .expect("protocol-2 authority fixture validates")
    }

    fn candidate_v1(
        authority: &FinalityAuthoritySetV1,
        proposer: Address,
        height: u64,
        salt: u8,
    ) -> BuiltBlockV4 {
        let commitment = authority.commitment().expect("authority commits");
        BuiltBlockV4 {
            block: crate::BlockV4 {
                header: BlockHeaderV4 {
                    protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
                    chain_id: ChainId::devnet(),
                    height: BlockHeight::new(height),
                    epoch: Epoch::new(0),
                    previous_hash: Hash256::ZERO,
                    state_root: Hash256([salt; 32]),
                    account_root: Hash256([salt.wrapping_add(1); 32]),
                    tx_root: Hash256::ZERO,
                    receipt_root: Hash256::ZERO,
                    evidence_root: Hash256::ZERO,
                    finality_authority_set_root: commitment,
                    next_finality_authority_set_root: commitment,
                    proposer,
                    timestamp_ms: u64::from(salt) + 1,
                    base_fee_per_unit: 1,
                },
                transactions: Vec::new(),
                receipts: Vec::new(),
                evidence: Vec::new(),
            },
            next_authority_set: authority.clone(),
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
    fn protocol2_single_validator_uses_shared_core_and_finalizes_v4() {
        let validator = Keypair::from_seed([1; 32]);
        let set = set_with_keys(&[(&validator, 1)]);
        let authority = authority_v1(&set);
        let mut machine = ConsensusMachineV1::new(authority.clone(), 1, Some(identity(&validator)))
            .expect("protocol-2 machine builds");
        let initial = machine.start().expect("machine starts");
        assert!(matches!(
            initial.first(),
            Some(ConsensusActionV1::NeedProposalBlock { round: 0 })
        ));
        let candidate = candidate_v1(&authority, validator.address(), 1, 7);
        let expected_hash = candidate.block.header.hash().expect("candidate hashes");
        let actions = machine
            .provide_block(0, candidate)
            .expect("shared core accepts V4 value");
        let (committed, certificate) = actions
            .iter()
            .find_map(|action| match action {
                ConsensusActionV1::Commit { block, certificate } => {
                    Some(((**block).clone(), (**certificate).clone()))
                }
                _ => None,
            })
            .expect("single validator finalizes V4");
        assert_eq!(committed.block.header.hash().unwrap(), expected_hash);
        certificate
            .verify(&set, TRANSACTION_V5_PROTOCOL_VERSION, &ChainId::devnet())
            .expect("protocol-2 certificate verifies");
        assert!(actions.iter().any(|action| matches!(
            action,
            ConsensusActionV1::Broadcast(ConsensusMessageV1::Proposal(proposal))
                if proposal.payload.block_hash == expected_hash
        )));
    }

    #[test]
    fn protocol2_wal_restart_replays_without_resigning_the_round() {
        let keys = [
            Keypair::from_seed([1; 32]),
            Keypair::from_seed([2; 32]),
            Keypair::from_seed([3; 32]),
        ];
        let set = set_with_keys(&[(&keys[0], 1), (&keys[1], 1), (&keys[2], 1)]);
        let authority = authority_v1(&set);
        let proposer = set.proposer_for(1, 0).expect("round has proposer");
        let proposer_key = keys
            .iter()
            .find(|key| key.address() == proposer)
            .expect("proposer key exists");
        let mut original =
            ConsensusMachineV1::new(authority.clone(), 1, Some(identity(proposer_key)))
                .expect("machine builds");
        assert!(matches!(
            original.start().unwrap().first(),
            Some(ConsensusActionV1::NeedProposalBlock { round: 0 })
        ));
        let actions = original
            .provide_block(0, candidate_v1(&authority, proposer, 1, 9))
            .expect("leader proposes");
        assert!(actions.iter().any(|action| matches!(
            action,
            ConsensusActionV1::Broadcast(ConsensusMessageV1::Proposal(_))
        )));
        let record = original.wal_record();
        assert_eq!(record.proposals.len(), 1);
        assert_eq!(record.votes.len(), 1);

        let bytes = bincode::serialize(&record).expect("protocol-2 WAL serializes");
        let decoded: ConsensusWalRecordV1 =
            bincode::deserialize(&bytes).expect("protocol-2 WAL decodes");
        let mut restarted = ConsensusMachineV1::new(authority, 1, Some(identity(proposer_key)))
            .expect("restart machine builds");
        restarted.restore(decoded).expect("valid WAL restores");
        let restart_actions = restarted.start().expect("restored machine starts");
        assert!(restart_actions
            .iter()
            .all(|action| !matches!(action, ConsensusActionV1::Broadcast(_))));
        assert_eq!(restarted.wal_record(), record);
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
    fn less_than_one_third_byzantine_power_cannot_finalize_conflicting_blocks() {
        // Four equal-power validators give the attacker 25% of the snapshot.
        // The attacker is selected as round-0 proposer so it can equivocate at
        // every available layer: conflicting proposals, prevotes, and
        // precommits are delivered selectively across two network partitions.
        let keys: Vec<Keypair> = SEEDS.iter().map(|seed| Keypair::from_seed(*seed)).collect();
        let attacker = &keys[3];
        let set = set_with_keys(&[(&keys[0], 1), (&keys[1], 1), (&keys[2], 1), (attacker, 1)]);
        let height = (1..=4_096)
            .find(|height| {
                set.proposer_for(*height, 0) == Some(attacker.address())
                    && set.proposer_for(*height, 1) != Some(attacker.address())
            })
            .expect("test schedule contains an attacker-led round followed by an honest leader");

        // Designate the round-1 honest leader as C (the initially-unlocked
        // partition) and the other two honest validators as A/B (the X-locked
        // partition). This lets the attacker make the strongest possible
        // cross-round attempt at finalizing a different value.
        let c_address = set.proposer_for(height, 1).unwrap();
        let c = keys[..3]
            .iter()
            .find(|key| key.address() == c_address)
            .unwrap();
        let locked: Vec<&Keypair> = keys[..3]
            .iter()
            .filter(|key| key.address() != c_address)
            .collect();
        let a = locked[0];
        let b = locked[1];

        let mut machine_a = ConsensusMachine::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set.clone(),
            height,
            Some(identity(a)),
        );
        let mut machine_b = ConsensusMachine::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set.clone(),
            height,
            Some(identity(b)),
        );
        let mut machine_c = ConsensusMachine::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set.clone(),
            height,
            Some(identity(c)),
        );
        let mut observer = ConsensusMachine::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set.clone(),
            height,
            None,
        );
        machine_a.start().unwrap();
        machine_b.start().unwrap();
        machine_c.start().unwrap();
        observer.start().unwrap();

        let sign_vote = |key: &Keypair, round: u32, vote_type: VoteType, block_hash: Hash256| {
            SignedVote::sign(
                Vote {
                    protocol_version: CURRENT_PROTOCOL_VERSION,
                    chain_id: ChainId::devnet(),
                    height,
                    round,
                    vote_type,
                    block_hash,
                    validator: key.address(),
                },
                key,
            )
            .unwrap()
        };
        let vote_from = |actions: &[ConsensusAction], vote_type: VoteType, block_hash: Hash256| {
            broadcasts(actions)
                .into_iter()
                .find_map(|message| match message {
                    ConsensusMessage::Vote(vote)
                        if vote.payload.vote_type == vote_type
                            && vote.payload.block_hash == block_hash =>
                    {
                        Some(vote)
                    }
                    _ => None,
                })
                .expect("machine broadcasts the expected vote")
        };
        let deliver_votes = |machine: &mut ConsensusMachine, votes: &[SignedVote]| {
            let mut actions = Vec::new();
            for vote in votes {
                actions.extend(
                    machine
                        .on_event(ConsensusEvent::Message(ConsensusMessage::Vote(
                            vote.clone(),
                        )))
                        .unwrap(),
                );
            }
            actions
        };

        // Round 0: the Byzantine proposer sends X to A/B and an observer, but Y
        // to C. Its equivocating prevotes let A/B reach the 3-of-4 quorum for X;
        // C's Y partition has only two votes and cannot lock.
        let block_x = candidate_block(attacker.address(), height, 1);
        let hash_x = block_x.hash().unwrap();
        let proposal_x = SignedProposal::sign(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            height,
            0,
            None,
            block_x,
            attacker.address(),
            attacker,
        )
        .unwrap();
        let block_y0 = candidate_block(attacker.address(), height, 2);
        let hash_y0 = block_y0.hash().unwrap();
        let proposal_y0 = SignedProposal::sign(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            height,
            0,
            None,
            block_y0,
            attacker.address(),
            attacker,
        )
        .unwrap();
        assert_ne!(hash_x, hash_y0);

        let actions_a = machine_a
            .on_event(ConsensusEvent::Message(ConsensusMessage::Proposal(
                Box::new(proposal_x.clone()),
            )))
            .unwrap();
        let actions_b = machine_b
            .on_event(ConsensusEvent::Message(ConsensusMessage::Proposal(
                Box::new(proposal_x.clone()),
            )))
            .unwrap();
        let actions_c = machine_c
            .on_event(ConsensusEvent::Message(ConsensusMessage::Proposal(
                Box::new(proposal_y0),
            )))
            .unwrap();
        observer
            .on_event(ConsensusEvent::Message(ConsensusMessage::Proposal(
                Box::new(proposal_x),
            )))
            .unwrap();
        let prevote_a = vote_from(&actions_a, VoteType::Prevote, hash_x);
        let prevote_b = vote_from(&actions_b, VoteType::Prevote, hash_x);
        let prevote_c = vote_from(&actions_c, VoteType::Prevote, hash_y0);
        let attacker_prevote_x = sign_vote(attacker, 0, VoteType::Prevote, hash_x);
        let attacker_prevote_y = sign_vote(attacker, 0, VoteType::Prevote, hash_y0);

        let lock_actions_a = deliver_votes(
            &mut machine_a,
            &[prevote_b.clone(), attacker_prevote_x.clone()],
        );
        let lock_actions_b = deliver_votes(
            &mut machine_b,
            &[prevote_a.clone(), attacker_prevote_x.clone()],
        );
        deliver_votes(&mut machine_c, &[prevote_c, attacker_prevote_y]);
        let precommit_a = vote_from(&lock_actions_a, VoteType::Precommit, hash_x);
        let precommit_b = vote_from(&lock_actions_b, VoteType::Precommit, hash_x);
        let attacker_precommit_x = sign_vote(attacker, 0, VoteType::Precommit, hash_x);

        // An observer in the X partition can genuinely finalize X from A/B plus
        // the attacker. A/B do not receive each other's precommits yet, so they
        // stay live and locked for the next-round conflict attempt.
        let observer_actions = deliver_votes(
            &mut observer,
            &[
                precommit_a.clone(),
                precommit_b.clone(),
                attacker_precommit_x,
            ],
        );
        let (finalized_x, certificate_x) =
            commit_of(&observer_actions).expect("the X partition has a valid finality quorum");
        assert_eq!(finalized_x.hash().unwrap(), hash_x);
        certificate_x
            .verify(&set, CURRENT_PROTOCOL_VERSION, &ChainId::devnet())
            .unwrap();

        // Advance the three honest validators to round 1. C, which never locked
        // Y0, is the scheduled leader and makes a fresh conflicting proposal Y1.
        machine_a
            .on_event(ConsensusEvent::Timeout {
                kind: TimeoutKind::Precommit,
                round: 0,
            })
            .unwrap();
        machine_b
            .on_event(ConsensusEvent::Timeout {
                kind: TimeoutKind::Precommit,
                round: 0,
            })
            .unwrap();
        machine_c
            .on_event(ConsensusEvent::Timeout {
                kind: TimeoutKind::Prevote,
                round: 0,
            })
            .unwrap();
        machine_c
            .on_event(ConsensusEvent::Timeout {
                kind: TimeoutKind::Precommit,
                round: 0,
            })
            .unwrap();
        assert_eq!(machine_a.round(), 1);
        assert_eq!(machine_b.round(), 1);
        assert_eq!(machine_c.round(), 1);

        let block_y1 = candidate_block(c.address(), height, 3);
        let hash_y1 = block_y1.hash().unwrap();
        assert_ne!(hash_x, hash_y1);
        let leader_actions = machine_c.provide_block(1, block_y1).unwrap();
        let proposal_y1 = broadcasts(&leader_actions)
            .into_iter()
            .find_map(|message| match message {
                ConsensusMessage::Proposal(proposal) => Some(proposal),
                _ => None,
            })
            .expect("round-1 leader broadcasts Y1");
        let prevote_c_y1 = vote_from(&leader_actions, VoteType::Prevote, hash_y1);
        let actions_a_y1 = machine_a
            .on_event(ConsensusEvent::Message(ConsensusMessage::Proposal(
                proposal_y1.clone(),
            )))
            .unwrap();
        let actions_b_y1 = machine_b
            .on_event(ConsensusEvent::Message(ConsensusMessage::Proposal(
                proposal_y1,
            )))
            .unwrap();
        let prevote_a_nil = vote_from(&actions_a_y1, VoteType::Prevote, NIL);
        let prevote_b_nil = vote_from(&actions_b_y1, VoteType::Prevote, NIL);
        let attacker_prevote_y1 = sign_vote(attacker, 1, VoteType::Prevote, hash_y1);

        // Locked A/B refuse Y1 and split the round-1 prevotes 2-for-Y1 versus
        // 2-for-nil. Even after all four votes are visible, every honest node
        // precommits nil on timeout; none signs the conflicting block.
        deliver_votes(
            &mut machine_a,
            &[
                prevote_b_nil.clone(),
                prevote_c_y1.clone(),
                attacker_prevote_y1.clone(),
            ],
        );
        deliver_votes(
            &mut machine_b,
            &[
                prevote_a_nil.clone(),
                prevote_c_y1.clone(),
                attacker_prevote_y1.clone(),
            ],
        );
        deliver_votes(
            &mut machine_c,
            &[prevote_a_nil, prevote_b_nil, attacker_prevote_y1],
        );
        let precommit_actions_a = machine_a
            .on_event(ConsensusEvent::Timeout {
                kind: TimeoutKind::Prevote,
                round: 1,
            })
            .unwrap();
        let precommit_actions_b = machine_b
            .on_event(ConsensusEvent::Timeout {
                kind: TimeoutKind::Prevote,
                round: 1,
            })
            .unwrap();
        let precommit_actions_c = machine_c
            .on_event(ConsensusEvent::Timeout {
                kind: TimeoutKind::Prevote,
                round: 1,
            })
            .unwrap();
        let precommit_a_nil = vote_from(&precommit_actions_a, VoteType::Precommit, NIL);
        let precommit_b_nil = vote_from(&precommit_actions_b, VoteType::Precommit, NIL);
        let precommit_c_nil = vote_from(&precommit_actions_c, VoteType::Precommit, NIL);
        let attacker_precommit_y1 = sign_vote(attacker, 1, VoteType::Precommit, hash_y1);
        let attempted_conflict = vec![
            precommit_a_nil,
            precommit_b_nil,
            precommit_c_nil,
            attacker_precommit_y1,
        ];

        assert!(FinalityCertificate::build(
            &set,
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            height,
            1,
            hash_y1,
            &attempted_conflict,
        )
        .is_none());
        assert!(
            [&machine_a, &machine_b, &machine_c]
                .into_iter()
                .all(|machine| machine.decided_block().is_none()),
            "no honest machine may finalize the conflicting Y1 block"
        );
    }

    /// Signs a fresh round-0 proposal for `block` by `leader`.
    fn sign_proposal(
        leader_key: &Keypair,
        height: u64,
        round: u32,
        block: Block,
    ) -> SignedProposal {
        SignedProposal::sign(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            height,
            round,
            None,
            block,
            leader_key.address(),
            leader_key,
        )
        .unwrap()
    }

    fn sign_vote(
        key: &Keypair,
        height: u64,
        round: u32,
        vote_type: VoteType,
        hash: Hash256,
    ) -> SignedVote {
        SignedVote::sign(
            Vote {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                chain_id: ChainId::devnet(),
                height,
                round,
                vote_type,
                block_hash: hash,
                validator: key.address(),
            },
            key,
        )
        .unwrap()
    }

    /// Collects every vote broadcast in `actions`.
    fn vote_broadcasts(actions: &[ConsensusAction]) -> Vec<SignedVote> {
        broadcasts(actions)
            .into_iter()
            .filter_map(|m| match m {
                ConsensusMessage::Vote(v) => Some(v),
                _ => None,
            })
            .collect()
    }

    /// Documents the exact danger the write-ahead journal exists to prevent:
    /// a machine rebuilt WITHOUT journal replay happily signs a conflicting
    /// vote for a step its previous life already signed, and the pair verifies
    /// as objective, slashable double-vote evidence.
    #[test]
    fn restart_without_journal_replay_self_equivocates() {
        let a = Keypair::from_seed([1u8; 32]);
        let b = Keypair::from_seed([2u8; 32]);
        let c = Keypair::from_seed([3u8; 32]);
        let set = set_with_keys(&[(&a, 1), (&b, 1), (&c, 1)]);
        let height = (1..=4_096)
            .find(|h| set.proposer_for(*h, 0) != Some(a.address()))
            .unwrap();
        let leader = set.proposer_for(height, 0).unwrap();
        let leader_key = [&a, &b, &c]
            .into_iter()
            .find(|k| k.address() == leader)
            .unwrap();

        let mut first_life = ConsensusMachine::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set.clone(),
            height,
            Some(identity(&a)),
        );
        first_life.start().unwrap();
        let block_x = candidate_block(leader, height, 1);
        let hash_x = block_x.hash().unwrap();
        let actions = first_life
            .on_event(ConsensusEvent::Message(ConsensusMessage::Proposal(
                Box::new(sign_proposal(leader_key, height, 0, block_x)),
            )))
            .unwrap();
        let first_vote = vote_broadcasts(&actions)
            .into_iter()
            .find(|v| v.payload.block_hash == hash_x)
            .expect("first life prevotes X");

        // "Restart" with no journal: a fresh machine, as the driver did pre-C4.
        let mut second_life = ConsensusMachine::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set.clone(),
            height,
            Some(identity(&a)),
        );
        second_life.start().unwrap();
        let block_y = candidate_block(leader, height, 9);
        let hash_y = block_y.hash().unwrap();
        assert_ne!(hash_x, hash_y);
        let actions = second_life
            .on_event(ConsensusEvent::Message(ConsensusMessage::Proposal(
                Box::new(sign_proposal(leader_key, height, 0, block_y)),
            )))
            .unwrap();
        let second_vote = vote_broadcasts(&actions)
            .into_iter()
            .find(|v| v.payload.block_hash == hash_y)
            .expect("an unjournaled restart re-prevotes the new proposal");

        // The two honest lives produced objective slashable evidence.
        let evidence = crate::SlashingEvidence::DoubleVote(DoubleVoteEvidence {
            first: first_vote,
            second: second_vote,
        });
        assert!(evidence
            .verify(
                CURRENT_PROTOCOL_VERSION,
                &ChainId::devnet(),
                &a.public_key()
            )
            .is_ok());
    }

    #[test]
    fn restored_machine_never_resigns_a_recorded_step() {
        let a = Keypair::from_seed([1u8; 32]);
        let b = Keypair::from_seed([2u8; 32]);
        let c = Keypair::from_seed([3u8; 32]);
        let set = set_with_keys(&[(&a, 1), (&b, 1), (&c, 1)]);
        let height = (1..=4_096)
            .find(|h| set.proposer_for(*h, 0) != Some(a.address()))
            .unwrap();
        let leader = set.proposer_for(height, 0).unwrap();
        let leader_key = [&a, &b, &c]
            .into_iter()
            .find(|k| k.address() == leader)
            .unwrap();

        let mut first_life = ConsensusMachine::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set.clone(),
            height,
            Some(identity(&a)),
        );
        first_life.start().unwrap();
        let block_x = candidate_block(leader, height, 1);
        let hash_x = block_x.hash().unwrap();
        first_life
            .on_event(ConsensusEvent::Message(ConsensusMessage::Proposal(
                Box::new(sign_proposal(leader_key, height, 0, block_x)),
            )))
            .unwrap();
        let journal = first_life.wal_record();
        assert_eq!(journal.votes.len(), 1, "first life journaled its prevote");

        // Restart with journal replay.
        let mut second_life = ConsensusMachine::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set.clone(),
            height,
            Some(identity(&a)),
        );
        second_life.restore(journal.clone()).unwrap();
        let start_actions = second_life.start().unwrap();

        // An equivocating leader now offers a conflicting round-0 proposal.
        let block_y = candidate_block(leader, height, 9);
        let hash_y = block_y.hash().unwrap();
        assert_ne!(hash_x, hash_y);
        let more = second_life
            .on_event(ConsensusEvent::Message(ConsensusMessage::Proposal(
                Box::new(sign_proposal(leader_key, height, 0, block_y)),
            )))
            .unwrap();

        // The restored machine must not sign anything new for round 0.
        for vote in vote_broadcasts(&start_actions)
            .into_iter()
            .chain(vote_broadcasts(&more))
        {
            assert_ne!(
                vote.payload.round, 0,
                "restored machine re-signed a journaled round"
            );
        }
        // The journal itself is unchanged by the replay.
        assert_eq!(second_life.wal_record(), journal);
    }

    #[test]
    fn restore_preserves_the_lock_across_a_restart() {
        let a = Keypair::from_seed([1u8; 32]);
        let b = Keypair::from_seed([2u8; 32]);
        let c = Keypair::from_seed([3u8; 32]);
        let set = set_with_keys(&[(&a, 1), (&b, 1), (&c, 1)]);
        // A must lead neither round 0 nor round 1, so both proposals come from
        // peers and the lock decision is A's alone.
        let height = (1..=4_096)
            .find(|h| {
                set.proposer_for(*h, 0) != Some(a.address())
                    && set.proposer_for(*h, 1) != Some(a.address())
            })
            .unwrap();
        let leader0 = set.proposer_for(height, 0).unwrap();
        let leader0_key = [&a, &b, &c]
            .into_iter()
            .find(|k| k.address() == leader0)
            .unwrap();
        let leader1 = set.proposer_for(height, 1).unwrap();
        let leader1_key = [&a, &b, &c]
            .into_iter()
            .find(|k| k.address() == leader1)
            .unwrap();

        // First life: A locks X (proposal + full prevote quorum) and precommits.
        let mut first_life = ConsensusMachine::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set.clone(),
            height,
            Some(identity(&a)),
        );
        first_life.start().unwrap();
        let block_x = candidate_block(leader0, height, 1);
        let hash_x = block_x.hash().unwrap();
        first_life
            .on_event(ConsensusEvent::Message(ConsensusMessage::Proposal(
                Box::new(sign_proposal(leader0_key, height, 0, block_x)),
            )))
            .unwrap();
        for key in [&b, &c] {
            first_life
                .on_event(ConsensusEvent::Message(ConsensusMessage::Vote(sign_vote(
                    key,
                    height,
                    0,
                    VoteType::Prevote,
                    hash_x,
                ))))
                .unwrap();
        }
        let journal = first_life.wal_record();
        assert_eq!(journal.locked_round, Some(0), "first life locked X");

        // Restart: the restored machine re-enters round 0 (Precommit step) and
        // moves on when the journaled round cannot complete.
        let mut second_life = ConsensusMachine::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set.clone(),
            height,
            Some(identity(&a)),
        );
        second_life.restore(journal).unwrap();
        second_life.start().unwrap();
        second_life
            .on_event(ConsensusEvent::Timeout {
                kind: TimeoutKind::Precommit,
                round: 0,
            })
            .unwrap();
        assert_eq!(second_life.round(), 1);

        // A fresh round-1 proposal for a conflicting Y (no proof-of-lock) must
        // draw a nil prevote: the lock survived the crash.
        let block_y = candidate_block(leader1, height, 9);
        let hash_y = block_y.hash().unwrap();
        assert_ne!(hash_x, hash_y);
        let actions = second_life
            .on_event(ConsensusEvent::Message(ConsensusMessage::Proposal(
                Box::new(sign_proposal(leader1_key, height, 1, block_y)),
            )))
            .unwrap();
        let round1_prevotes: Vec<Hash256> = vote_broadcasts(&actions)
            .into_iter()
            .filter(|v| v.payload.round == 1 && v.payload.vote_type == VoteType::Prevote)
            .map(|v| v.payload.block_hash)
            .collect();
        assert!(
            !round1_prevotes.is_empty(),
            "the restored machine keeps participating in fresh rounds"
        );
        assert!(
            round1_prevotes.iter().all(|h| *h == NIL),
            "a restart must not erase the lock: prevote for conflicting Y observed"
        );
    }

    #[test]
    fn restored_proposer_does_not_repropose_its_recorded_round() {
        let keys = [
            Keypair::from_seed([1u8; 32]),
            Keypair::from_seed([2u8; 32]),
            Keypair::from_seed([3u8; 32]),
        ];
        let set = set_with_keys(&[(&keys[0], 1), (&keys[1], 1), (&keys[2], 1)]);
        let height = 1;
        let leader = set.proposer_for(height, 0).unwrap();
        let leader_key = keys.iter().find(|k| k.address() == leader).unwrap();

        // First life: the leader proposes and prevotes its own block.
        let mut first_life = ConsensusMachine::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set.clone(),
            height,
            Some(identity(leader_key)),
        );
        let actions = first_life.start().unwrap();
        assert!(matches!(
            actions.first(),
            Some(ConsensusAction::NeedProposalBlock { round: 0 })
        ));
        first_life
            .provide_block(0, candidate_block(leader, height, 1))
            .unwrap();
        let journal = first_life.wal_record();
        assert_eq!(journal.proposals.len(), 1);

        // Restart: the restored leader must not build or sign a second round-0
        // proposal (a re-built block would differ and equivocate).
        let mut second_life = ConsensusMachine::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set,
            height,
            Some(identity(leader_key)),
        );
        second_life.restore(journal).unwrap();
        let actions = second_life.start().unwrap();
        for action in &actions {
            assert!(
                !matches!(
                    action,
                    ConsensusAction::NeedProposalBlock { .. }
                        | ConsensusAction::Broadcast(ConsensusMessage::Proposal(_))
                ),
                "restored proposer re-proposed its journaled round: {action:?}"
            );
        }
    }

    #[test]
    fn restore_rejects_corrupt_or_foreign_journals() {
        let a = Keypair::from_seed([1u8; 32]);
        let b = Keypair::from_seed([2u8; 32]);
        let c = Keypair::from_seed([3u8; 32]);
        let set = set_with_keys(&[(&a, 1), (&b, 1), (&c, 1)]);
        let fresh = || {
            ConsensusMachine::new(
                CURRENT_PROTOCOL_VERSION,
                ChainId::devnet(),
                set.clone(),
                1,
                Some(identity(&a)),
            )
        };
        let empty = ConsensusWalRecord {
            height: 1,
            proposals: Vec::new(),
            votes: Vec::new(),
            locked_round: None,
            locked_value: None,
            valid_round: None,
            valid_value: None,
        };

        // Wrong height.
        let mut journal = empty.clone();
        journal.height = 2;
        assert!(fresh().restore(journal).is_err());

        // A vote signed by another validator can never be "our own" journal.
        let mut journal = empty.clone();
        journal.votes = vec![sign_vote(
            &b,
            1,
            0,
            VoteType::Prevote,
            Hash256::digest(b"x"),
        )];
        assert!(fresh().restore(journal).is_err());

        // A journal that already records our own conflicting votes for one
        // step is evidence of past equivocation; nothing safe can be replayed.
        let mut journal = empty.clone();
        journal.votes = vec![
            sign_vote(&a, 1, 0, VoteType::Prevote, Hash256::digest(b"x")),
            sign_vote(&a, 1, 0, VoteType::Prevote, Hash256::digest(b"y")),
        ];
        assert!(fresh().restore(journal).is_err());

        // Lock fields must come in consistent pairs.
        let mut journal = empty.clone();
        journal.locked_round = Some(0);
        assert!(fresh().restore(journal).is_err());

        // An observer has no signing identity to restore.
        let mut observer = ConsensusMachine::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set.clone(),
            1,
            None,
        );
        assert!(observer.restore(empty.clone()).is_err());

        // A machine that already acted cannot be restored over.
        let mut started = fresh();
        started.start().unwrap();
        started
            .on_event(ConsensusEvent::Timeout {
                kind: TimeoutKind::Propose,
                round: 0,
            })
            .unwrap();
        assert!(started.restore(empty).is_err());
    }

    /// C3: per-height memory must not be sizeable by an attacker-chosen round
    /// number. A snapshot member can sign votes (and, for its leader slots,
    /// full-block proposals) for any of the 2^32 rounds; only a bounded window
    /// around the current round may be stored.
    #[test]
    fn far_future_rounds_are_ignored_and_stale_rounds_are_evicted() {
        let a = Keypair::from_seed([1u8; 32]);
        let b = Keypair::from_seed([2u8; 32]);
        let c = Keypair::from_seed([3u8; 32]);
        let set = set_with_keys(&[(&a, 1), (&b, 1), (&c, 1)]);
        let mut machine = ConsensusMachine::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set.clone(),
            1,
            Some(identity(&a)),
        );
        machine.start().unwrap();

        // A hostile-but-staked validator sprays validly signed votes across
        // absurd future rounds. None beyond the horizon may be stored.
        let hash = Hash256::digest(b"attack");
        for round in [
            MAX_FUTURE_ROUNDS + 1,
            MAX_FUTURE_ROUNDS + 2,
            1 << 16,
            1 << 24,
            u32::MAX,
        ] {
            machine
                .on_event(ConsensusEvent::Message(ConsensusMessage::Vote(sign_vote(
                    &b,
                    1,
                    round,
                    VoteType::Prevote,
                    hash,
                ))))
                .unwrap();
            machine
                .on_event(ConsensusEvent::Message(ConsensusMessage::Vote(sign_vote(
                    &b,
                    1,
                    round,
                    VoteType::Precommit,
                    hash,
                ))))
                .unwrap();
        }
        assert!(
            machine.prevotes.is_empty() && machine.precommits.is_empty(),
            "votes beyond the future-round horizon must not be stored \
             (prevotes: {}, precommits: {})",
            machine.prevotes.len(),
            machine.precommits.len()
        );

        // A vote at exactly the horizon IS stored: catch-up must keep working.
        machine
            .on_event(ConsensusEvent::Message(ConsensusMessage::Vote(sign_vote(
                &b,
                1,
                MAX_FUTURE_ROUNDS,
                VoteType::Prevote,
                hash,
            ))))
            .unwrap();
        assert_eq!(machine.prevotes.len(), 1, "in-horizon votes are kept");

        // Full-block proposals for far-future leader slots must be dropped
        // before they are stored (the largest per-round object).
        let far_leader_round = (MAX_FUTURE_ROUNDS + 1..)
            .find(|round| set.proposer_for(1, *round) == Some(b.address()))
            .unwrap();
        let far_block = candidate_block(b.address(), 1, 7);
        machine
            .on_event(ConsensusEvent::Message(ConsensusMessage::Proposal(
                Box::new(
                    SignedProposal::sign(
                        CURRENT_PROTOCOL_VERSION,
                        ChainId::devnet(),
                        1,
                        far_leader_round,
                        None,
                        far_block,
                        b.address(),
                        &b,
                    )
                    .unwrap(),
                ),
            )))
            .unwrap();
        assert!(
            !machine.proposals.contains_key(&far_leader_round),
            "a proposal beyond the future-round horizon must not be stored"
        );

        // Eviction: after the round advances beyond the past window, stale
        // round entries are dropped so long-lived heights stay bounded.
        let mut round = machine.round();
        while round < MAX_PAST_ROUNDS + 5 {
            machine
                .on_event(ConsensusEvent::Timeout {
                    kind: TimeoutKind::Precommit,
                    round,
                })
                .unwrap();
            round = machine.round();
        }
        assert!(
            machine
                .prevotes
                .keys()
                .all(|(r, _)| *r + MAX_PAST_ROUNDS >= machine.round),
            "rounds below the past window must be evicted"
        );

        // Total stored rounds stay within the fixed window no matter what
        // arrives, which is the memory bound this test exists to pin.
        let mut stored: BTreeSet<u32> = BTreeSet::new();
        stored.extend(machine.proposals.keys().copied());
        stored.extend(machine.prevotes.keys().map(|(r, _)| *r));
        stored.extend(machine.precommits.keys().map(|(r, _)| *r));
        assert!(
            stored.len() as u32 <= MAX_PAST_ROUNDS + MAX_FUTURE_ROUNDS + 1,
            "stored round count exceeds the documented bound"
        );
    }

    /// C5: a node that never saw round-`vr` prevotes must still be able to
    /// prevote a re-proposal, because the re-proposal carries the proof-of-lock
    /// (the 2f+1 prevotes) that authenticates its `valid_round`. Without the
    /// attached proof, the node can never satisfy the rule-28 guard and prevotes
    /// nil forever while the lock holder re-proposes (the liveness bug).
    #[test]
    fn a_reproposal_with_proof_of_lock_is_followed_by_a_node_that_missed_the_round() {
        let a = Keypair::from_seed([1u8; 32]);
        let b = Keypair::from_seed([2u8; 32]);
        let c = Keypair::from_seed([3u8; 32]);
        let d = Keypair::from_seed([4u8; 32]);
        let set = set_with_keys(&[(&a, 1), (&b, 1), (&c, 1), (&d, 1)]);

        // Node D is our subject: it will be TOTALLY unaware of round 0 (it saw
        // no round-0 proposal or prevotes) and must still follow a round-1
        // re-proposal that cites round 0 as its proof-of-lock.
        let mut node_d = ConsensusMachine::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set.clone(),
            1,
            Some(identity(&d)),
        );
        node_d.start().unwrap();

        // Build a real block X and a genuine round-0 prevote quorum for it from
        // A, B, C (3 of 4 > 2/3) — the material for a proof-of-lock.
        let leader0 = set.proposer_for(1, 0).unwrap();
        let block_x = candidate_block(leader0, 1, 1);
        let hash_x = block_x.hash().unwrap();
        let pol: Vec<SignedVote> = [&a, &b, &c]
            .iter()
            .map(|k| sign_vote(k, 1, 0, VoteType::Prevote, hash_x))
            .collect();

        // The round-1 leader re-proposes X citing valid_round 0 with the PoL.
        let leader1 = set.proposer_for(1, 1).unwrap();
        let leader1_key = [&a, &b, &c, &d]
            .into_iter()
            .find(|k| k.address() == leader1)
            .unwrap();
        let reproposal = SignedProposal::sign_with_proof_of_lock(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            1,
            1,
            Some(0),
            block_x,
            leader1,
            leader1_key,
            pol,
        )
        .unwrap();

        // Advance D to round 1 (it timed out round 0 having seen nothing).
        node_d
            .on_event(ConsensusEvent::Timeout {
                kind: TimeoutKind::Propose,
                round: 0,
            })
            .unwrap();
        node_d
            .on_event(ConsensusEvent::Timeout {
                kind: TimeoutKind::Prevote,
                round: 0,
            })
            .unwrap();
        node_d
            .on_event(ConsensusEvent::Timeout {
                kind: TimeoutKind::Precommit,
                round: 0,
            })
            .unwrap();
        assert_eq!(node_d.round(), 1);

        // Deliver the round-1 re-proposal. D never saw round 0, so without the
        // attached PoL it would prevote nil; with it, it must prevote X.
        let actions = node_d
            .on_event(ConsensusEvent::Message(ConsensusMessage::Proposal(
                Box::new(reproposal),
            )))
            .unwrap();
        let round1_prevotes: Vec<Hash256> = vote_broadcasts(&actions)
            .into_iter()
            .filter(|v| v.payload.round == 1 && v.payload.vote_type == VoteType::Prevote)
            .map(|v| v.payload.block_hash)
            .collect();
        assert_eq!(
            round1_prevotes,
            vec![hash_x],
            "a node that missed round 0 must follow the re-proposal via its proof-of-lock"
        );
    }

    #[test]
    fn a_reproposal_without_a_valid_proof_of_lock_is_rejected() {
        let a = Keypair::from_seed([1u8; 32]);
        let b = Keypair::from_seed([2u8; 32]);
        let c = Keypair::from_seed([3u8; 32]);
        let d = Keypair::from_seed([4u8; 32]);
        let set = set_with_keys(&[(&a, 1), (&b, 1), (&c, 1), (&d, 1)]);
        let mut node = ConsensusMachine::new(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            set.clone(),
            1,
            Some(identity(&d)),
        );
        node.start().unwrap();
        let leader1 = set.proposer_for(1, 1).unwrap();
        let leader1_key = [&a, &b, &c, &d]
            .into_iter()
            .find(|k| k.address() == leader1)
            .unwrap();
        let block_y = candidate_block(leader1, 1, 9);
        let hash_y = block_y.hash().unwrap();

        // A re-proposal citing valid_round 0 but attaching only ONE prevote
        // (far below quorum) must be rejected outright.
        let weak_pol = vec![sign_vote(&a, 1, 0, VoteType::Prevote, hash_y)];
        let bad = SignedProposal::sign_with_proof_of_lock(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            1,
            1,
            Some(0),
            block_y.clone(),
            leader1,
            leader1_key,
            weak_pol,
        )
        .unwrap();
        assert!(matches!(
            bad.verify_in_set(&set, CURRENT_PROTOCOL_VERSION, &ChainId::devnet()),
            Err(ChainError::ConsensusProofOfLockInvalid)
        ));

        // A fresh proposal (valid_round None) that nonetheless carries prevotes
        // is malformed and rejected.
        let stray_pol = vec![sign_vote(&a, 1, 0, VoteType::Prevote, hash_y)];
        let malformed = SignedProposal::sign_with_proof_of_lock(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            1,
            1,
            None,
            block_y,
            leader1,
            leader1_key,
            stray_pol,
        )
        .unwrap();
        assert!(matches!(
            malformed.verify_in_set(&set, CURRENT_PROTOCOL_VERSION, &ChainId::devnet()),
            Err(ChainError::ConsensusProofOfLockInvalid)
        ));
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
