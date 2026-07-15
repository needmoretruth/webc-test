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
//! proposes, along with any gossiped equivocation evidence. It broadcasts and
//! consumes proposals and votes. Certificates are not yet used to fast-commit a
//! lagging node — that is the job of the separate state-sync path, since a
//! certificate carries a block hash but not the block.

use std::collections::VecDeque;
use std::time::Duration;

use tokio::sync::mpsc;
use webc_chain::{
    ConsensusAction, ConsensusEvent, ConsensusMachine, ConsensusMessage, SlashingEvidence,
    TimeoutKind, ValidatorIdentity, ValidatorSet,
};
use webc_crypto::{Address, Hash256, Keypair};
use webc_net::{InboundMessage, NetMessage, NetworkHandle};
use webc_storage::KvStore;

use crate::http::now_ms;
use crate::mempool::{Mempool, MempoolConfig};
use crate::node::Node;

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
    /// Objective equivocation evidence gathered from gossip, to embed in the next
    /// block this node proposes.
    pending_evidence: Vec<SlashingEvidence>,
}

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
            pending_evidence: Vec::new(),
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
            let snapshot = match ValidatorSet::from_state(self.node.state()) {
                Ok(snapshot) => snapshot,
                Err(_) => return,
            };
            let identity = self.identity_for(&snapshot);
            let mut machine = ConsensusMachine::new(
                self.node.config().protocol_version,
                self.node.config().chain_id.clone(),
                snapshot,
                height,
                identity,
            );

            let mut decided = None;
            let initial = machine.start().unwrap_or_default();
            let mut work: VecDeque<ConsensusAction> = initial.into();
            self.pump(&mut machine, &mut work, height, &timeout_tx, &mut decided)
                .await;

            while decided.is_none() {
                tokio::select! {
                    inbound_message = inbound.recv() => {
                        match inbound_message {
                            None => return, // network shut down
                            Some(message) => {
                                self.on_inbound(message, &mut machine, height, &timeout_tx, &mut decided).await;
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
            }

            if let Some(block) = decided {
                let tx_count = block.transactions.len();
                // Commit the finalized block. Every node, including the proposer,
                // re-validates via import_block before committing.
                if self.node.import_block(block).is_err() {
                    return;
                }
                // Drop now-included or stale transactions from the mempool.
                self.mempool.remove_obsolete(self.node.state());
                self.mempool.prune_expired(now_ms());
                if let Some(sender) = &commit_tx {
                    let info = CommitInfo {
                        height,
                        tip: self.node.tip_hash(),
                        tx_count,
                    };
                    let _ = sender.send(info).await;
                }
            }
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
    async fn on_inbound(
        &mut self,
        message: InboundMessage,
        machine: &mut ConsensusMachine,
        height: u64,
        timeout_tx: &mpsc::Sender<(TimeoutKind, u32, u64)>,
        decided: &mut Option<webc_chain::Block>,
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
                ConsensusEvent::Message(ConsensusMessage::Proposal(proposal))
            }
            NetMessage::Vote(vote) => ConsensusEvent::Message(ConsensusMessage::Vote(*vote)),
            // A certificate proves finality but not the block; state sync (a later
            // step) fetches the block. Ignore it here.
            NetMessage::Certificate(_) => return,
        };
        // A hostile or malformed message returns an error; drop it and continue.
        let actions = machine.on_event(event).unwrap_or_default();
        let mut work: VecDeque<ConsensusAction> = actions.into();
        self.pump(machine, &mut work, height, timeout_tx, decided)
            .await;
    }

    /// Executes the machine's actions, feeding follow-on actions back into the
    /// queue until it drains.
    async fn pump(
        &mut self,
        machine: &mut ConsensusMachine,
        work: &mut VecDeque<ConsensusAction>,
        height: u64,
        timeout_tx: &mpsc::Sender<(TimeoutKind, u32, u64)>,
        decided: &mut Option<webc_chain::Block>,
    ) {
        while let Some(action) = work.pop_front() {
            match action {
                ConsensusAction::Broadcast(message) => {
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
                    let evidence = std::mem::take(&mut self.pending_evidence);
                    // Select fee-priority, nonce-contiguous transactions under the
                    // block unit budget from the mempool.
                    let max_units = self.node.config().fee_policy.max_block_units;
                    let transactions = self.mempool.select_block(
                        self.node.state(),
                        self.node.config(),
                        max_units,
                        now_ms(),
                    );
                    match self.node.build_candidate(
                        transactions,
                        evidence.clone(),
                        proposer,
                        now_ms(),
                    ) {
                        Ok(block) => {
                            let more = machine.provide_block(round, block).unwrap_or_default();
                            work.extend(more);
                        }
                        Err(_) => {
                            // Restore the evidence for the next attempt.
                            self.pending_evidence = evidence;
                        }
                    }
                }
                ConsensusAction::Commit { block, .. } => {
                    *decided = Some(*block);
                }
                ConsensusAction::Equivocation(evidence) => {
                    self.pending_evidence
                        .push(SlashingEvidence::DoubleVote(*evidence));
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
