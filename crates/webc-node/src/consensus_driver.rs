//! Async network driver for the BFT consensus machine.
//!
//! Purpose: turn the pure, deterministic [`ConsensusMachine`] (in `webc-chain`)
//! into a running network node. The machine decides *what* to do; this driver
//! does the I/O the machine cannot: it broadcasts messages over `webc-net`, arms
//! real timers for the machine's timeouts, builds a candidate block when the
//! machine (as proposer) asks for one, and durably commits a finalized block via
//! [`Node::import_block`]. It runs one machine per height and advances to the
//! next height on each commit.
//!
//! Boundaries: all consensus *logic* — proposing, locking, round changes,
//! quorum, finality — lives in the machine and is deterministically tested there.
//! This driver is deliberately thin glue: every consensus-safety property is a
//! property of the machine, not of this file.
//!
//! Scope (Phase 4 A-3): the driver admits gossiped transactions into a mempool
//! and includes fee-priority, nonce-ordered transactions in the blocks it
//! proposes. It broadcasts and consumes proposals and votes, and it runs **state
//! sync**: when it observes the network at a higher height, it requests finalized
//! blocks and imports each after verifying the block's finality certificate, so a
//! lagging or newly-joined node catches up without replaying consensus. It also
//! serves such requests from its own store.
//!
//! Block validity (C1, Tendermint's `valid(v)`): the machine never executes
//! blocks, so the driver re-executes every received proposal's block against a
//! scratch clone of current state (after the cheap authenticity checks) and
//! feeds the machine only proposals it could actually import. A Byzantine
//! leader therefore cannot collect prevotes — let alone a finality certificate
//! — for an unimportable block.
//!
//! Objective equivocation surfaced by the machine is retained by replay-stable
//! evidence hash and included in a later candidate block. The block header commits
//! the evidence root and deterministic execution applies the slash before user
//! transactions, so every importing node reaches the same penalized state.
//!
//! Crash safety (C4): because the slash path above is live, a validator that
//! forgets what it already signed and re-signs differently after a restart
//! destroys its own stake. The driver therefore journals the machine's signing
//! state durably ([`Node::persist_consensus_wal`]) **before** broadcasting any
//! message the local machine signed, and replays the journal
//! ([`ConsensusMachine::restore`]) when it rebuilds a machine for an
//! in-progress height. A journal that cannot be read or validated means the
//! node no longer knows what it signed, so it fails closed and follows that
//! height as a non-voting observer.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

use tokio::sync::mpsc;
use webc_chain::{
    apply_block, Block, ConsensusAction, ConsensusEvent, ConsensusMachine, ConsensusMessage,
    FinalityCertificate, SignedProposal, SlashingEvidence, TimeoutKind, ValidatorIdentity,
    ValidatorSet, MAX_BLOCK_SLASHING_EVIDENCE,
};
use webc_crypto::{Address, Hash256, Keypair};
use webc_net::{InboundMessage, NetMessage, NetworkHandle};
use webc_storage::KvStore;

use crate::http::now_ms;
use crate::mempool::{Mempool, MempoolConfig};
use crate::node::{Node, NodeError};

/// How long the driver waits in each step before firing the matching timeout.
#[derive(Clone, Copy, Debug)]
pub struct DriverTimeouts {
    /// Wait for a proposal before prevoting nil.
    pub propose: Duration,
    /// Wait after a prevote quorum before precommitting nil.
    pub prevote: Duration,
    /// Wait after a precommit quorum before changing round.
    pub precommit: Duration,
}

impl Default for DriverTimeouts {
    fn default() -> Self {
        // Devnet defaults; a public network tunes these from measurements.
        Self {
            propose: Duration::from_millis(1_000),
            prevote: Duration::from_millis(1_000),
            precommit: Duration::from_millis(1_000),
        }
    }
}

impl DriverTimeouts {
    fn for_kind(&self, kind: TimeoutKind) -> Duration {
        match kind {
            TimeoutKind::Propose => self.propose,
            TimeoutKind::Prevote => self.prevote,
            TimeoutKind::Precommit => self.precommit,
        }
    }
}

/// Reported to an observer each time this node commits a height.
#[derive(Clone, Copy, Debug)]
pub struct CommitInfo {
    /// The height that was committed.
    pub height: u64,
    /// The new tip block hash.
    pub tip: Option<Hash256>,
    /// Number of transactions in the committed block.
    pub tx_count: usize,
}

/// A single consensus node: a [`Node`] driven by a [`ConsensusMachine`] over a
/// [`NetworkHandle`].
pub struct ConsensusDriver<K: KvStore> {
    node: Node<K>,
    network: NetworkHandle,
    /// This node's consensus keypair seed and address, if it is a validator. The
    /// seed lets the driver rebuild a fresh `ValidatorIdentity` for each height
    /// (the keypair is not `Clone`). `None` runs the node as a non-voting
    /// observer that still follows and commits finalized blocks.
    consensus_seed: Option<[u8; 32]>,
    consensus_address: Option<Address>,
    timeouts: DriverTimeouts,
    /// Pending transactions to include when this node proposes; fed by gossip.
    mempool: Mempool,
    /// Verified double-vote evidence awaiting inclusion, keyed by its
    /// order-independent replay hash for deterministic ordering and de-duplication.
    pending_evidence: BTreeMap<Hash256, SlashingEvidence>,
    /// Rounds of the in-progress height whose first authentic leader proposal
    /// has already been validity-checked (C1 `valid(v)`); cleared when the
    /// height advances. Each round's proposal is re-executed at most once, so
    /// a Byzantine leader cannot burn CPU by spamming distinct signed
    /// proposals for its round.
    checked_proposal_rounds: BTreeSet<u32>,
}

/// Maximum blocks requested per state-sync round.
const SYNC_BATCH: u32 = 16;

/// A block finalized live by the local machine, with its proving certificate.
type Decided = (Block, FinalityCertificate);

impl<K: KvStore + Send + Sync + 'static> ConsensusDriver<K> {
    /// Creates a driver over `node`, broadcasting through `network`. Pass the
    /// validator consensus keypair's 32-byte seed to run as a validator, or `None`
    /// to run as an observer.
    pub fn new(
        node: Node<K>,
        network: NetworkHandle,
        consensus_seed: Option<[u8; 32]>,
        timeouts: DriverTimeouts,
        mempool_config: MempoolConfig,
    ) -> Self {
        let consensus_address = consensus_seed.map(|seed| Keypair::from_seed(seed).address());
        Self {
            node,
            network,
            consensus_seed,
            consensus_address,
            timeouts,
            mempool: Mempool::new(mempool_config),
            pending_evidence: BTreeMap::new(),
            checked_proposal_rounds: BTreeSet::new(),
        }
    }

    /// Runs the consensus loop until the inbound network channel closes.
    ///
    /// `inbound` delivers gossiped messages (the driver admits transactions into
    /// its mempool and feeds consensus messages to the machine). `commit_tx`, if
    /// present, receives a [`CommitInfo`] on every committed height, letting a
    /// supervisor or test observe progress.
    pub async fn run(
        mut self,
        mut inbound: mpsc::Receiver<InboundMessage>,
        commit_tx: Option<mpsc::Sender<CommitInfo>>,
    ) {
        let (timeout_tx, mut timeout_rx) = mpsc::channel::<(TimeoutKind, u32, u64)>(256);

        loop {
            let height = self.node.height() + 1;
            self.checked_proposal_rounds.clear();
            let snapshot = match ValidatorSet::from_state(self.node.state()) {
                Ok(snapshot) => snapshot,
                Err(_) => return,
            };
            let identity = self.identity_for(&snapshot);
            let is_validator = identity.is_some();
            let mut machine = ConsensusMachine::new(
                self.node.config().protocol_version,
                self.node.config().chain_id.clone(),
                snapshot.clone(),
                height,
                identity,
            );
            // C4 crash safety: if this node already signed something at this
            // height before a restart, replay the journal so the machine never
            // re-signs a recorded step and keeps its lock. An unreadable or
            // invalid journal means the node no longer knows what it signed —
            // fail closed and follow this height as a non-voting observer (an
            // observer cannot equivocate).
            if is_validator {
                let journal_safe = match self.node.consensus_wal(height) {
                    Ok(None) => true,
                    Ok(Some(record)) => machine.restore(record).is_ok(),
                    Err(_) => false,
                };
                if !journal_safe {
                    machine = ConsensusMachine::new(
                        self.node.config().protocol_version,
                        self.node.config().chain_id.clone(),
                        snapshot,
                        height,
                        None,
                    );
                }
            }

            // The height advances by either path: this node finalizes it live
            // (the machine emits a Commit), or it imports the finalized block from
            // a peer during state sync. The loop runs until the node's committed
            // height reaches `height` by one of those routes.
            let mut decided: Option<Decided> = None;
            let mut requested = false;
            let initial = machine.start().unwrap_or_default();
            let mut work: VecDeque<ConsensusAction> = initial.into();
            self.pump(&mut machine, &mut work, height, &timeout_tx, &mut decided)
                .await;
            if self
                .commit_if_decided(height, &mut decided, &commit_tx)
                .await
            {
                return;
            }

            while self.node.height() < height {
                tokio::select! {
                    inbound_message = inbound.recv() => {
                        match inbound_message {
                            None => return, // network shut down
                            Some(message) => {
                                self.on_inbound(message, &mut machine, height, &timeout_tx, &mut decided, &mut requested, &commit_tx).await;
                            }
                        }
                    }
                    fired = timeout_rx.recv() => {
                        if let Some((kind, round, event_height)) = fired {
                            // Ignore stale timers left over from an earlier height.
                            if event_height == height {
                                let actions = machine
                                    .on_event(ConsensusEvent::Timeout { kind, round })
                                    .unwrap_or_default();
                                let mut work: VecDeque<ConsensusAction> = actions.into();
                                self.pump(&mut machine, &mut work, height, &timeout_tx, &mut decided).await;
                            }
                        }
                    }
                }
                if self
                    .commit_if_decided(height, &mut decided, &commit_tx)
                    .await
                {
                    return;
                }
            }
        }
    }

    /// Commits a live-finalized block for `height` if the machine decided one and
    /// the node has not already reached that height (e.g. via a synced import).
    /// Returns `true` on a fatal storage error, signaling the caller to stop.
    async fn commit_if_decided(
        &mut self,
        height: u64,
        decided: &mut Option<Decided>,
        commit_tx: &Option<mpsc::Sender<CommitInfo>>,
    ) -> bool {
        let Some((block, certificate)) = decided.take() else {
            return false;
        };
        // A concurrent sync may have already imported this height.
        if self.node.height() + 1 != block.header.height {
            return false;
        }
        let tx_count = block.transactions.len();
        if self
            .node
            .import_finalized_block(block, &certificate)
            .is_err()
        {
            return true;
        }
        self.mempool.remove_obsolete(self.node.state());
        self.mempool.prune_expired(now_ms());
        self.prune_pending_evidence();
        self.report_commit(height, tx_count, commit_tx).await;
        false
    }

    /// Sends a [`CommitInfo`] to the observer, if one is attached.
    async fn report_commit(
        &self,
        height: u64,
        tx_count: usize,
        commit_tx: &Option<mpsc::Sender<CommitInfo>>,
    ) {
        if let Some(sender) = commit_tx {
            let _ = sender
                .send(CommitInfo {
                    height,
                    tip: self.node.tip_hash(),
                    tx_count,
                })
                .await;
        }
    }

    /// Verifies and imports one certified block received during sync. Returns
    /// whether the node's height advanced.
    async fn apply_synced_block(
        &mut self,
        response: webc_net::CertifiedBlock,
        commit_tx: &Option<mpsc::Sender<CommitInfo>>,
    ) -> bool {
        let webc_net::CertifiedBlock { block, certificate } = response;
        // Only the exact next block advances the chain.
        if block.header.height != self.node.height() + 1 {
            return false;
        }
        // The certificate must be for this exact block.
        let Ok(block_hash) = block.hash() else {
            return false;
        };
        if certificate.height != block.header.height || certificate.block_hash != block_hash {
            return false;
        }
        // Verify the certificate proves finality against the current validator
        // snapshot (stable within an epoch), then import (which re-executes and
        // enforces linkage). Both must pass.
        let Ok(snapshot) = ValidatorSet::from_state(self.node.state()) else {
            return false;
        };
        if certificate
            .verify(
                &snapshot,
                self.node.config().protocol_version,
                &self.node.config().chain_id,
            )
            .is_err()
        {
            return false;
        }
        let tx_count = block.transactions.len();
        let height = block.header.height;
        if self
            .node
            .import_finalized_block(block, &certificate)
            .is_err()
        {
            return false;
        }
        self.mempool.remove_obsolete(self.node.state());
        self.prune_pending_evidence();
        self.report_commit(height, tx_count, commit_tx).await;
        true
    }

    /// Serves finalized certified blocks for a peer's state-sync request.
    fn serve_block_request(&self, from_height: u64, max: u32) {
        let local = self.node.height();
        let count = u64::from(max.min(SYNC_BATCH));
        let mut height = from_height;
        while height <= local && height < from_height + count {
            match self.node.certified_block(height) {
                Ok(Some((block, certificate))) => {
                    let response = webc_net::CertifiedBlock { block, certificate };
                    let _ = self
                        .network
                        .broadcast(NetMessage::BlockResponse(Box::new(response)));
                }
                _ => break, // a missing block ends the servable run
            }
            height += 1;
        }
    }

    /// Builds this node's validator identity for a height, if it is a member of
    /// that height's snapshot.
    fn identity_for(&self, snapshot: &ValidatorSet) -> Option<ValidatorIdentity> {
        let seed = self.consensus_seed?;
        let address = self.consensus_address?;
        // Only build an identity if this node is a member of the height snapshot.
        snapshot.consensus_key_of(address)?;
        Some(ValidatorIdentity {
            address,
            consensus_key: Keypair::from_seed(seed),
        })
    }

    /// Routes one inbound gossip message.
    ///
    /// Live consensus and state sync share this path: consensus messages feed the
    /// machine (which may emit a live `Commit` into `decided`), a `BlockResponse`
    /// imports a finalized block during catch-up, and a `BlockRequest` is served
    /// from this node's store. When a message shows the network is at a higher
    /// height, this node requests the finalized block for the height it is on
    /// (once per height, tracked by `requested`), so a node missing votes can
    /// still advance by importing the certified block instead of stalling.
    #[allow(clippy::too_many_arguments)]
    async fn on_inbound(
        &mut self,
        message: InboundMessage,
        machine: &mut ConsensusMachine,
        height: u64,
        timeout_tx: &mpsc::Sender<(TimeoutKind, u32, u64)>,
        decided: &mut Option<Decided>,
        requested: &mut bool,
        commit_tx: &Option<mpsc::Sender<CommitInfo>>,
    ) {
        let event = match message.message {
            // Admit gossiped transactions so this node can include them when it
            // proposes. Admission failures (unknown sender, bad nonce, duplicate)
            // are expected and dropped.
            NetMessage::Transaction(tx) => {
                let _ = self
                    .mempool
                    .insert(*tx, self.node.state(), self.node.config(), now_ms());
                return;
            }
            NetMessage::Proposal(proposal) => {
                self.request_if_behind(proposal.payload.height, height, requested);
                // C1 (`valid(v)`): only a proposal whose block re-executes
                // cleanly at this exact chain position may reach the machine.
                // A dropped proposal draws a nil prevote via the propose
                // timeout, so a Byzantine leader can no longer collect a
                // finality certificate for an unimportable block.
                if !self.validate_proposal(&proposal, height) {
                    return;
                }
                ConsensusEvent::Message(ConsensusMessage::Proposal(proposal))
            }
            NetMessage::Vote(vote) => {
                self.request_if_behind(vote.payload.height, height, requested);
                ConsensusEvent::Message(ConsensusMessage::Vote(*vote))
            }
            NetMessage::Certificate(certificate) => {
                self.request_if_behind(certificate.height, height, requested);
                return;
            }
            // Serve peers that are catching up, even while running consensus.
            NetMessage::BlockRequest { from_height, max } => {
                self.serve_block_request(from_height, max);
                return;
            }
            // Import a finalized block from a peer to advance during catch-up.
            NetMessage::BlockResponse(response) => {
                self.apply_synced_block(*response, commit_tx).await;
                return;
            }
        };
        // A hostile or malformed message returns an error; drop it and continue.
        let actions = machine.on_event(event).unwrap_or_default();
        let mut work: VecDeque<ConsensusAction> = actions.into();
        self.pump(machine, &mut work, height, timeout_tx, decided)
            .await;
    }

    /// If a peer references a height beyond the one this node is working on,
    /// request the finalized block for the current height once, so a node that
    /// missed its votes can catch up by import instead of stalling.
    fn request_if_behind(
        &mut self,
        message_height: u64,
        working_height: u64,
        requested: &mut bool,
    ) {
        if message_height > working_height && !*requested {
            *requested = true;
            let _ = self.network.broadcast(NetMessage::BlockRequest {
                from_height: self.node.height() + 1,
                max: SYNC_BATCH,
            });
        }
    }

    /// Tendermint's `valid(v)` predicate (C1): decides whether a gossiped
    /// proposal may reach the consensus machine.
    ///
    /// The machine deliberately never executes blocks, so without this gate a
    /// Byzantine leader could propose a correctly signed but semantically
    /// invalid block (forged state root, over-budget or invalid transactions,
    /// bogus evidence); honest nodes would prevote it on signature alone, lock
    /// it, and hand the attacker a verifying finality certificate for a block
    /// no node can import.
    ///
    /// Order matters for DoS resistance: the cheap authenticity gate
    /// (signature, scheduled leader, block-hash binding) runs before the
    /// expensive re-execution, and each round's first authentic proposal is
    /// checked exactly once — matching the machine's own first-proposal-wins
    /// rule — so a Byzantine leader cannot make this node re-execute more than
    /// one block per round it leads.
    fn validate_proposal(&mut self, proposal: &SignedProposal, height: u64) -> bool {
        if proposal.payload.height != height {
            // The machine ignores other heights; skip the execution cost too.
            return false;
        }
        let round = proposal.payload.round;
        if self.checked_proposal_rounds.contains(&round) {
            return false;
        }
        // Cheap authenticity before any execution: only the scheduled leader's
        // correctly signed, hash-bound proposal is worth re-executing.
        let Ok(snapshot) = ValidatorSet::from_state(self.node.state()) else {
            return false;
        };
        if proposal
            .verify_in_set(
                &snapshot,
                self.node.config().protocol_version,
                &self.node.config().chain_id,
            )
            .is_err()
        {
            return false;
        }
        self.checked_proposal_rounds.insert(round);
        // Pin the block to this node's exact chain position. `apply_block`
        // re-executes against the block's own claimed height/parent/epoch
        // fields, so they must be compared against local state explicitly or a
        // block for the wrong position could still "re-execute" cleanly.
        let header = &proposal.block.header;
        let expected_parent = self.node.tip_hash().unwrap_or(Hash256([0u8; 32]));
        if header.height != height
            || header.previous_hash != expected_parent
            || header.epoch != self.node.state().current_epoch
            || header.chain_id != self.node.config().chain_id
        {
            return false;
        }
        // valid(v): dry-run the full deterministic state transition on a
        // scratch clone. Only a block this node could import earns a prevote.
        let mut scratch = self.node.state().clone();
        apply_block(&mut scratch, self.node.config(), &proposal.block).is_ok()
    }

    /// Durably journals the machine's signing state before one of its own
    /// messages is broadcast (the C4 write-ahead journal). Messages this node
    /// did not sign pass through without a journal write.
    fn journal_own_message(
        &mut self,
        machine: &ConsensusMachine,
        message: &ConsensusMessage,
    ) -> Result<(), NodeError> {
        let own = match (self.consensus_address, message) {
            (Some(address), ConsensusMessage::Proposal(proposal)) => {
                proposal.payload.proposer == address
            }
            (Some(address), ConsensusMessage::Vote(vote)) => vote.payload.validator == address,
            (None, _) => false,
        };
        if !own {
            return Ok(());
        }
        self.node.persist_consensus_wal(&machine.wal_record())
    }

    /// Drops evidence already committed or no longer verifiable against current
    /// validator state, preventing one stale item from stalling proposal creation.
    fn prune_pending_evidence(&mut self) {
        let state = self.node.state();
        let protocol_version = self.node.config().protocol_version;
        let chain_id = self.node.config().chain_id.clone();
        self.pending_evidence.retain(|hash, evidence| {
            if state.processed_slashing_evidence.contains(hash) {
                return false;
            }
            state
                .validators
                .get(&evidence.validator())
                .is_some_and(|validator| {
                    evidence
                        .verify(protocol_version, &chain_id, &validator.consensus_key)
                        .is_ok()
                })
        });
    }

    /// Executes the machine's actions, feeding follow-on actions back into the
    /// queue until it drains.
    async fn pump(
        &mut self,
        machine: &mut ConsensusMachine,
        work: &mut VecDeque<ConsensusAction>,
        height: u64,
        timeout_tx: &mpsc::Sender<(TimeoutKind, u32, u64)>,
        decided: &mut Option<Decided>,
    ) {
        while let Some(action) = work.pop_front() {
            match action {
                ConsensusAction::Broadcast(message) => {
                    // C4: a message this node signed must be journaled durably
                    // before it can reach the wire — a vote peers saw but the
                    // journal forgot is exactly the crash-restart
                    // self-equivocation window. Fail closed: if the journal
                    // write fails, the message is dropped (never broadcast),
                    // costing liveness but never safety.
                    if self.journal_own_message(machine, &message).is_err() {
                        continue;
                    }
                    let _ = self.network.broadcast(to_net_message(message));
                }
                ConsensusAction::ScheduleTimeout { kind, round } => {
                    let sender = timeout_tx.clone();
                    let delay = self.timeouts.for_kind(kind);
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        let _ = sender.send((kind, round, height)).await;
                    });
                }
                ConsensusAction::NeedProposalBlock { round } => {
                    let Some(proposer) = self.consensus_address else {
                        continue;
                    };
                    // Select fee-priority, nonce-contiguous transactions under the
                    // block unit budget from the mempool.
                    let max_units = self.node.config().fee_policy.max_block_units;
                    let transactions = self.mempool.select_block(
                        self.node.state(),
                        self.node.config(),
                        max_units,
                        now_ms(),
                    );
                    self.prune_pending_evidence();
                    let evidence = self
                        .pending_evidence
                        .values()
                        .take(MAX_BLOCK_SLASHING_EVIDENCE)
                        .cloned()
                        .collect();
                    if let Ok(block) =
                        self.node
                            .build_candidate(transactions, evidence, proposer, now_ms())
                    {
                        let more = machine.provide_block(round, block).unwrap_or_default();
                        work.extend(more);
                    }
                }
                ConsensusAction::Commit { block, certificate } => {
                    *decided = Some((*block, *certificate));
                }
                ConsensusAction::Equivocation(evidence) => {
                    let evidence = SlashingEvidence::DoubleVote(*evidence);
                    if let Ok(hash) = evidence.hash() {
                        self.pending_evidence.entry(hash).or_insert(evidence);
                    }
                }
            }
        }
    }
}

/// Wraps a consensus message in its network envelope.
fn to_net_message(message: ConsensusMessage) -> NetMessage {
    match message {
        ConsensusMessage::Proposal(proposal) => NetMessage::Proposal(proposal),
        ConsensusMessage::Vote(vote) => NetMessage::Vote(Box::new(vote)),
    }
}
