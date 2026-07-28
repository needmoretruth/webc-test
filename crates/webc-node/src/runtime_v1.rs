//! Protocol-2 node actor: one ordered owner for V5 pending transactions.
//!
//! Purpose: bind the pure [`crate::V5Mempool`] policy to durable lifecycle
//! storage without locks or split ownership. Responsibilities: bounded command
//! admission, persist-before-memory ordering, idempotent submission, local
//! expiry, deterministic restart reconstruction, candidate construction, and
//! certified finalization. Non-responsibilities: HTTP/WebSocket encoding, peer
//! transport, consensus voting/round logic, or certificate creation; those
//! layers call this actor through [`NodeHandle`].
//!
//! Data flow: a caller queues a command on a bounded Tokio channel; the sole
//! [`NodeRuntime`] task plans against its committed state, commits the complete
//! storage transition, and only then mutates its in-memory indexes. Replies are
//! returned through one-shot channels. Startup performs the same validation and
//! durably removes stale or no-longer-admissible records before serving traffic.
//!
//! Security boundary: signed transactions, persisted records, local timestamps,
//! and all future API/network callers are hostile. The bounded mailbox applies
//! backpressure, the actor prevents admission/finality races inside one node,
//! and a failed durable write leaves memory unchanged. Local time affects only
//! retention and never enters consensus state.

use std::collections::BTreeSet;
use std::sync::Arc;

use tokio::sync::{broadcast, mpsc, oneshot, Semaphore};
use webc_chain::{
    BlockHeight, BlockV4, BlockV4ExecutionError, BuiltBlockV4, ConsensusWalRecordV1,
    FinalityAuthoritySetV1, FinalityCertificate, ReceiptV1, SlashingEvidence, TransactionId,
    TransactionV5, TRANSACTION_V5_PROTOCOL_VERSION,
};
use webc_storage::{
    KvStore, LocalDropReasonV1, LocalTimestampMs, LocalTransactionObservationV1,
    PendingAdmissionOutcomeV1, StorageError, TransactionLifecycleV1,
    MAX_PENDING_TRANSACTION_SCAN_V1,
};

use crate::node::MAX_FINALIZED_PROOF_MATERIAL_BYTES_V1;
use crate::pending_evidence_v1::MAX_PENDING_SLASHING_EVIDENCE_V1;
use crate::{
    FinalizedTransactionProofBundleV1, Node, NodeError, V4FinalizationResult, V5InsertOutcome,
    V5Mempool, V5MempoolConfig, V5MempoolError,
};

/// Default maximum number of commands waiting for the single runtime owner.
pub const DEFAULT_V5_RUNTIME_QUEUE_CAPACITY: usize = 1_024;
/// Retained live lifecycle snapshots before a slow subscriber is disconnected.
pub const DEFAULT_V5_LIFECYCLE_EVENT_CAPACITY: usize = 1_024;
/// Maximum CPU-heavy finalized proofs built concurrently outside the actor.
pub const DEFAULT_FINALIZED_PROOF_WORKERS: usize = 2;
/// Maximum transaction IDs read by one actor lifecycle snapshot command.
pub const MAX_V5_LIFECYCLE_QUERY_IDS: usize = 64;

/// Successful protocol-2 submission result returned after durable admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V5SubmitReceipt {
    /// Domain-separated ID of the submitted signed transaction.
    pub transaction_id: TransactionId,
    /// Idempotent admission, insertion, replacement, or capacity-eviction result.
    pub outcome: V5InsertOutcome,
    /// Latest durable lifecycle projection for `transaction_id`.
    pub lifecycle: TransactionLifecycleV1,
    /// Number of pending transactions retained after this command.
    pub mempool_size: usize,
}

/// Bounded runtime counters read from the single owner without shared locks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V5RuntimeStats {
    /// Latest durably committed block height; zero means genesis only.
    pub committed_height: BlockHeight,
    /// Number of protocol-2 pending transactions retained in memory.
    pub mempool_size: usize,
    /// Sum of canonical JSON bytes charged to the configured memory budget.
    pub mempool_bytes: usize,
    /// CPU-heavy finalized proofs currently running outside the actor.
    pub active_finalized_proofs: usize,
}

/// Actor-consistent protocol-2 consensus inputs for the next height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusContextV1 {
    /// Exact next height after the durable tip.
    pub height: BlockHeight,
    /// Immutable outgoing set that proposes and certifies this height.
    pub current_authority_set: FinalityAuthoritySetV1,
}

/// Stored protocol-2 state-sync unit returned by the single runtime owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedBlockSnapshotV1 {
    /// Exact finalized V4 block.
    pub block: BlockV4,
    /// Concrete set committed to authorize the following height.
    pub next_authority_set: FinalityAuthoritySetV1,
    /// Finality certificate over the exact V4 header hash.
    pub certificate: FinalityCertificate,
}

/// Errors returned by the protocol-2 runtime and its bounded handle.
#[derive(Debug, thiserror::Error)]
pub enum NodeRuntimeError {
    /// The command mailbox must retain at least one item.
    #[error("protocol-2 runtime queue capacity must be non-zero")]
    InvalidQueueCapacity,
    /// Spawning requires an active Tokio executor instead of panicking implicitly.
    #[error("protocol-2 runtime must be spawned from an active Tokio runtime")]
    NoAsyncRuntime,
    /// The bounded command mailbox is full; callers must retry with backoff.
    #[error("protocol-2 runtime command queue is full")]
    QueueFull,
    /// Every bounded finalized-proof worker is already occupied.
    #[error("protocol-2 finalized proof workers are busy")]
    ProofWorkersBusy,
    /// The actor stopped or the response receiver was canceled.
    #[error("protocol-2 runtime is stopped")]
    Stopped,
    /// No block height exists after the committed tip.
    #[error("protocol-2 runtime cannot advance beyond the maximum block height")]
    HeightExhausted,
    /// A lifecycle snapshot request exceeded its fixed transaction-ID cap.
    #[error("protocol-2 lifecycle query exceeds the {MAX_V5_LIFECYCLE_QUERY_IDS}-ID limit")]
    TooManyLifecycleIds,
    /// A consensus evidence-status request exceeded the driver's fixed pool cap.
    #[error("protocol-2 evidence query exceeds the {MAX_PENDING_SLASHING_EVIDENCE_V1}-hash limit")]
    TooManySlashingEvidenceHashes,
    /// Durable storage failed; the current in-memory mutation was not applied.
    #[error("protocol-2 runtime storage error: {0}")]
    Storage(#[from] StorageError),
    /// Transaction admission or restart revalidation failed.
    #[error("protocol-2 runtime mempool error: {0}")]
    Mempool(#[from] V5MempoolError),
    /// Candidate construction or certified block import failed atomically.
    #[error("protocol-2 runtime node error: {0}")]
    Node(#[from] NodeError),
    /// Disk and memory violated a single-owner invariant; the actor stops closed.
    #[error("protocol-2 runtime invariant failed: {0}")]
    Inconsistent(&'static str),
}

impl NodeRuntimeError {
    fn fatal_invariant(&self) -> Option<&'static str> {
        match self {
            Self::Inconsistent(message) => Some(message),
            _ => None,
        }
    }
}

/// Cloneable, bounded entry point used by API, gossip, and consensus adapters.
#[derive(Clone)]
pub struct NodeHandle {
    sender: mpsc::Sender<Command>,
    lifecycle_events: broadcast::Sender<TransactionLifecycleV1>,
}

impl NodeHandle {
    /// Submits one complete signed V5 transaction without waiting for queue room.
    ///
    /// A full queue returns [`NodeRuntimeError::QueueFull`] immediately so
    /// hostile request volume cannot allocate an unbounded number of waiters.
    /// Success means the lifecycle transition is already durable.
    pub async fn submit(
        &self,
        transaction: TransactionV5,
        now_ms: LocalTimestampMs,
    ) -> Result<V5SubmitReceipt, NodeRuntimeError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(Command::Submit {
                transaction: Box::new(transaction),
                now_ms,
                response,
            })
            .map_err(map_send_error)?;
        receiver.await.map_err(|_| NodeRuntimeError::Stopped)?
    }

    /// Returns current committed-height and bounded mempool counters.
    pub async fn stats(&self) -> Result<V5RuntimeStats, NodeRuntimeError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(Command::Stats { response })
            .map_err(map_send_error)?;
        receiver.await.map_err(|_| NodeRuntimeError::Stopped)?
    }

    /// Returns one bounded ID-ordered pending page for availability gossip.
    ///
    /// This crate-private command is used only after restart or reconnection.
    /// The mempool enforces the page ceiling before cloning transaction bodies,
    /// and a full actor mailbox returns immediate backpressure.
    pub(crate) async fn pending_gossip_page(
        &self,
        after: Option<TransactionId>,
        limit: usize,
    ) -> Result<Vec<TransactionV5>, NodeRuntimeError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(Command::PendingGossipPage {
                after,
                limit,
                response,
            })
            .map_err(map_send_error)?;
        receiver.await.map_err(|_| NodeRuntimeError::Stopped)?
    }

    /// Returns the latest durable lifecycle for one transaction ID, if known.
    pub async fn lifecycle(
        &self,
        transaction_id: TransactionId,
    ) -> Result<Option<TransactionLifecycleV1>, NodeRuntimeError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(Command::Lifecycle {
                transaction_id,
                response,
            })
            .map_err(map_send_error)?;
        receiver.await.map_err(|_| NodeRuntimeError::Stopped)?
    }

    /// Returns one actor-consistent snapshot for up to 64 transaction IDs.
    ///
    /// The result preserves input order. Callers creating a live subscription
    /// should first call [`Self::subscribe_lifecycle`], then request this snapshot
    /// and discard queued events whose sequence is not newer than the snapshot.
    pub async fn lifecycles(
        &self,
        transaction_ids: Vec<TransactionId>,
    ) -> Result<Vec<Option<TransactionLifecycleV1>>, NodeRuntimeError> {
        if transaction_ids.len() > MAX_V5_LIFECYCLE_QUERY_IDS {
            return Err(NodeRuntimeError::TooManyLifecycleIds);
        }
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(Command::Lifecycles {
                transaction_ids,
                response,
            })
            .map_err(map_send_error)?;
        receiver.await.map_err(|_| NodeRuntimeError::Stopped)?
    }

    /// Returns a finalized receipt record, or `None` until finality is durable.
    pub async fn receipt(
        &self,
        transaction_id: TransactionId,
    ) -> Result<Option<ReceiptV1>, NodeRuntimeError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(Command::Receipt {
                transaction_id,
                response,
            })
            .map_err(map_send_error)?;
        receiver.await.map_err(|_| NodeRuntimeError::Stopped)?
    }

    /// Builds a self-verified finalized proof relative to a stored checkpoint.
    ///
    /// A full API queue returns backpressure instead of retaining unbounded proof
    /// work. `None` means the transaction is not finalized; an unavailable or
    /// inconsistent checkpoint is a typed failure.
    pub async fn finalized_proof(
        &self,
        transaction_id: TransactionId,
        checkpoint_height: BlockHeight,
    ) -> Result<Option<FinalizedTransactionProofBundleV1>, NodeRuntimeError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(Command::FinalizedProof {
                transaction_id,
                checkpoint_height,
                response,
            })
            .map_err(map_send_error)?;
        receiver.await.map_err(|_| NodeRuntimeError::Stopped)?
    }

    /// Subscribes to bounded live durable lifecycle snapshots.
    ///
    /// Broadcast lag is explicit: receivers get `Lagged` and must disconnect or
    /// resnapshot rather than buffering without limit.
    pub fn subscribe_lifecycle(&self) -> broadcast::Receiver<TransactionLifecycleV1> {
        self.lifecycle_events.subscribe()
    }

    /// Durably expires every retained entry whose local TTL elapsed by `now_ms`.
    ///
    /// Each deletion commits before the corresponding in-memory removal. The
    /// returned count includes only removals completed during this command.
    pub async fn expire(&self, now_ms: LocalTimestampMs) -> Result<usize, NodeRuntimeError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(Command::Expire { now_ms, response })
            .map_err(map_send_error)?;
        receiver.await.map_err(|_| NodeRuntimeError::Stopped)?
    }

    /// Selects pending transactions and builds one uncommitted V4 candidate.
    ///
    /// `now_ms` only filters locally expired pending copies. `timestamp_ms` is
    /// the consensus header time and is monotonically clamped by the node. The
    /// current and derived next authority sets come from the single actor-owned
    /// committed state.
    pub async fn build_candidate_v4(
        &self,
        proposer: webc_crypto::Address,
        timestamp_ms: u64,
        now_ms: LocalTimestampMs,
        evidence: Vec<SlashingEvidence>,
    ) -> Result<BuiltBlockV4, NodeRuntimeError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Command::BuildCandidateV4 {
                proposer,
                timestamp_ms,
                now_ms,
                evidence,
                response,
            })
            .await
            .map_err(|_| NodeRuntimeError::Stopped)?;
        receiver.await.map_err(|_| NodeRuntimeError::Stopped)?
    }

    /// Returns one consistent height/authority snapshot for a V4 machine.
    ///
    /// Consensus commands wait on the bounded mailbox instead of failing on a
    /// transiently full API queue; only the single driver can issue them, so
    /// this preserves bounded memory while preventing request traffic from
    /// turning queue pressure into consensus failure.
    pub async fn consensus_context_v1(&self) -> Result<ConsensusContextV1, NodeRuntimeError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Command::ConsensusContextV1 { response })
            .await
            .map_err(|_| NodeRuntimeError::Stopped)?;
        receiver.await.map_err(|_| NodeRuntimeError::Stopped)?
    }

    /// Returns the requested evidence hashes already present in durable chain state.
    ///
    /// The input is capped to the driver's complete fixed-capacity pool. This
    /// avoids cloning the chain's monotonically growing processed-evidence set
    /// into the consensus task on every height.
    pub async fn processed_slashing_evidence_v1(
        &self,
        hashes: Vec<webc_crypto::Hash256>,
    ) -> Result<BTreeSet<webc_crypto::Hash256>, NodeRuntimeError> {
        if hashes.len() > MAX_PENDING_SLASHING_EVIDENCE_V1 {
            return Err(NodeRuntimeError::TooManySlashingEvidenceHashes);
        }
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Command::ProcessedSlashingEvidenceV1 { hashes, response })
            .await
            .map_err(|_| NodeRuntimeError::Stopped)?;
        receiver.await.map_err(|_| NodeRuntimeError::Stopped)?
    }

    /// Replays a received authenticated V4 proposal without committing it.
    pub async fn validate_candidate_v4(
        &self,
        block: BlockV4,
        next_authority_set: FinalityAuthoritySetV1,
    ) -> Result<(), NodeRuntimeError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Command::ValidateCandidateV4 {
                block: Box::new(block),
                next_authority_set: Box::new(next_authority_set),
                response,
            })
            .await
            .map_err(|_| NodeRuntimeError::Stopped)?;
        receiver.await.map_err(|_| NodeRuntimeError::Stopped)?
    }

    /// Loads the protocol-2 crash journal for one unfinished height.
    pub async fn consensus_wal_v1(
        &self,
        height: BlockHeight,
    ) -> Result<Option<ConsensusWalRecordV1>, NodeRuntimeError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Command::ConsensusWalV1 { height, response })
            .await
            .map_err(|_| NodeRuntimeError::Stopped)?;
        receiver.await.map_err(|_| NodeRuntimeError::Stopped)?
    }

    /// Persists the full protocol-2 WAL before any own message reaches peers.
    pub async fn persist_consensus_wal_v1(
        &self,
        record: ConsensusWalRecordV1,
    ) -> Result<(), NodeRuntimeError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Command::PersistConsensusWalV1 {
                record: Box::new(record),
                response,
            })
            .await
            .map_err(|_| NodeRuntimeError::Stopped)?;
        receiver.await.map_err(|_| NodeRuntimeError::Stopped)?
    }

    /// Loads one stored certified V4 state-sync unit through the actor.
    pub async fn certified_block_v4(
        &self,
        height: BlockHeight,
    ) -> Result<Option<CertifiedBlockSnapshotV1>, NodeRuntimeError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Command::CertifiedBlockV4 { height, response })
            .await
            .map_err(|_| NodeRuntimeError::Stopped)?;
        receiver.await.map_err(|_| NodeRuntimeError::Stopped)?
    }

    /// Atomically commits one certified V4 block and updates pending memory.
    ///
    /// Success means block, post-state, authority sets, certificate, indexes,
    /// receipts, lifecycle facts, pending removals, WAL cleanup, and tip are all
    /// durable before the actor removes any corresponding in-memory entries.
    pub async fn finalize_v4(
        &self,
        block: BlockV4,
        next_authority_set: FinalityAuthoritySetV1,
        certificate: FinalityCertificate,
    ) -> Result<V4FinalizationResult, NodeRuntimeError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Command::FinalizeV4 {
                block: Box::new(block),
                next_authority_set: Box::new(next_authority_set),
                certificate: Box::new(certificate),
                response,
            })
            .await
            .map_err(|_| NodeRuntimeError::Stopped)?;
        receiver.await.map_err(|_| NodeRuntimeError::Stopped)?
    }

    /// Requests an orderly actor exit after all earlier queued commands.
    pub async fn shutdown(&self) -> Result<(), NodeRuntimeError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(Command::Shutdown { response })
            .map_err(map_send_error)?;
        receiver.await.map_err(|_| NodeRuntimeError::Stopped)
    }
}

fn map_send_error<T>(error: mpsc::error::TrySendError<T>) -> NodeRuntimeError {
    match error {
        mpsc::error::TrySendError::Full(_) => NodeRuntimeError::QueueFull,
        mpsc::error::TrySendError::Closed(_) => NodeRuntimeError::Stopped,
    }
}

enum Command {
    Submit {
        transaction: Box<TransactionV5>,
        now_ms: LocalTimestampMs,
        response: oneshot::Sender<Result<V5SubmitReceipt, NodeRuntimeError>>,
    },
    Stats {
        response: oneshot::Sender<Result<V5RuntimeStats, NodeRuntimeError>>,
    },
    PendingGossipPage {
        after: Option<TransactionId>,
        limit: usize,
        response: oneshot::Sender<Result<Vec<TransactionV5>, NodeRuntimeError>>,
    },
    Lifecycle {
        transaction_id: TransactionId,
        response: oneshot::Sender<Result<Option<TransactionLifecycleV1>, NodeRuntimeError>>,
    },
    Lifecycles {
        transaction_ids: Vec<TransactionId>,
        response: oneshot::Sender<Result<Vec<Option<TransactionLifecycleV1>>, NodeRuntimeError>>,
    },
    Receipt {
        transaction_id: TransactionId,
        response: oneshot::Sender<Result<Option<ReceiptV1>, NodeRuntimeError>>,
    },
    FinalizedProof {
        transaction_id: TransactionId,
        checkpoint_height: BlockHeight,
        response:
            oneshot::Sender<Result<Option<FinalizedTransactionProofBundleV1>, NodeRuntimeError>>,
    },
    Expire {
        now_ms: LocalTimestampMs,
        response: oneshot::Sender<Result<usize, NodeRuntimeError>>,
    },
    BuildCandidateV4 {
        proposer: webc_crypto::Address,
        timestamp_ms: u64,
        now_ms: LocalTimestampMs,
        evidence: Vec<SlashingEvidence>,
        response: oneshot::Sender<Result<BuiltBlockV4, NodeRuntimeError>>,
    },
    ConsensusContextV1 {
        response: oneshot::Sender<Result<ConsensusContextV1, NodeRuntimeError>>,
    },
    ProcessedSlashingEvidenceV1 {
        hashes: Vec<webc_crypto::Hash256>,
        response: oneshot::Sender<Result<BTreeSet<webc_crypto::Hash256>, NodeRuntimeError>>,
    },
    ValidateCandidateV4 {
        block: Box<BlockV4>,
        next_authority_set: Box<FinalityAuthoritySetV1>,
        response: oneshot::Sender<Result<(), NodeRuntimeError>>,
    },
    ConsensusWalV1 {
        height: BlockHeight,
        response: oneshot::Sender<Result<Option<ConsensusWalRecordV1>, NodeRuntimeError>>,
    },
    PersistConsensusWalV1 {
        record: Box<ConsensusWalRecordV1>,
        response: oneshot::Sender<Result<(), NodeRuntimeError>>,
    },
    CertifiedBlockV4 {
        height: BlockHeight,
        response: oneshot::Sender<Result<Option<CertifiedBlockSnapshotV1>, NodeRuntimeError>>,
    },
    FinalizeV4 {
        block: Box<BlockV4>,
        next_authority_set: Box<FinalityAuthoritySetV1>,
        certificate: Box<FinalityCertificate>,
        response: oneshot::Sender<Result<V4FinalizationResult, NodeRuntimeError>>,
    },
    Shutdown {
        response: oneshot::Sender<()>,
    },
}

/// Single-task owner of one node and its protocol-2 in-memory pending indexes.
pub struct NodeRuntime<K: KvStore> {
    node: Node<K>,
    mempool: V5Mempool,
    lifecycle_events: broadcast::Sender<TransactionLifecycleV1>,
    proof_workers: Arc<Semaphore>,
    /// Maximum projected JSON bytes loaded for one proof worker snapshot.
    proof_material_budget_bytes: usize,
}

impl<K> NodeRuntime<K>
where
    K: KvStore + Send + 'static,
{
    /// Revalidates durable pending records, then starts one bounded actor task.
    ///
    /// `recovery_now_ms` is node-local time used only to expire stale records.
    /// Startup fails closed on storage corruption or a write failure. Records
    /// rejected by current state/policy are durably marked dropped before the
    /// handle becomes reachable. A tightened capacity policy selects survivors
    /// deterministically in stored transaction-ID order.
    pub fn spawn(
        node: Node<K>,
        mempool_config: V5MempoolConfig,
        queue_capacity: usize,
        recovery_now_ms: LocalTimestampMs,
    ) -> Result<
        (
            NodeHandle,
            tokio::task::JoinHandle<Result<(), NodeRuntimeError>>,
        ),
        NodeRuntimeError,
    > {
        Self::spawn_with_proof_material_budget(
            node,
            mempool_config,
            queue_capacity,
            recovery_now_ms,
            MAX_FINALIZED_PROOF_MATERIAL_BYTES_V1,
        )
    }

    /// Starts the actor with an injectable proof budget for boundary tests.
    fn spawn_with_proof_material_budget(
        mut node: Node<K>,
        mempool_config: V5MempoolConfig,
        queue_capacity: usize,
        recovery_now_ms: LocalTimestampMs,
        proof_material_budget_bytes: usize,
    ) -> Result<
        (
            NodeHandle,
            tokio::task::JoinHandle<Result<(), NodeRuntimeError>>,
        ),
        NodeRuntimeError,
    > {
        if queue_capacity == 0 {
            return Err(NodeRuntimeError::InvalidQueueCapacity);
        }
        tokio::runtime::Handle::try_current().map_err(|_| NodeRuntimeError::NoAsyncRuntime)?;
        let mempool = recover_pending(&mut node, mempool_config, recovery_now_ms)?;
        let (sender, receiver) = mpsc::channel(queue_capacity);
        let (lifecycle_events, _) = broadcast::channel(DEFAULT_V5_LIFECYCLE_EVENT_CAPACITY);
        let runtime = Self {
            node,
            mempool,
            lifecycle_events: lifecycle_events.clone(),
            proof_workers: Arc::new(Semaphore::new(DEFAULT_FINALIZED_PROOF_WORKERS)),
            proof_material_budget_bytes,
        };
        let task = tokio::spawn(runtime.run(receiver));
        Ok((
            NodeHandle {
                sender,
                lifecycle_events,
            },
            task,
        ))
    }

    async fn run(mut self, mut receiver: mpsc::Receiver<Command>) -> Result<(), NodeRuntimeError> {
        while let Some(command) = receiver.recv().await {
            match command {
                Command::Submit {
                    transaction,
                    now_ms,
                    response,
                } => {
                    let result = self.submit(*transaction, now_ms);
                    let fatal = result
                        .as_ref()
                        .err()
                        .and_then(NodeRuntimeError::fatal_invariant);
                    let _response_canceled = response.send(result);
                    if let Some(message) = fatal {
                        return Err(NodeRuntimeError::Inconsistent(message));
                    }
                }
                Command::Stats { response } => {
                    let _response_canceled = response.send(self.stats());
                }
                Command::PendingGossipPage {
                    after,
                    limit,
                    response,
                } => {
                    let result = self
                        .mempool
                        .pending_gossip_page(after, limit)
                        .map_err(NodeRuntimeError::from);
                    let _response_canceled = response.send(result);
                }
                Command::Lifecycle {
                    transaction_id,
                    response,
                } => {
                    let result = self
                        .node
                        .store()
                        .transaction_lifecycle_v1(transaction_id)
                        .map_err(NodeRuntimeError::from);
                    let _response_canceled = response.send(result);
                }
                Command::Lifecycles {
                    transaction_ids,
                    response,
                } => {
                    let result = transaction_ids
                        .into_iter()
                        .map(|transaction_id| {
                            self.node
                                .store()
                                .transaction_lifecycle_v1(transaction_id)
                                .map_err(NodeRuntimeError::from)
                        })
                        .collect();
                    let _response_canceled = response.send(result);
                }
                Command::Receipt {
                    transaction_id,
                    response,
                } => {
                    let result = self
                        .node
                        .store()
                        .finalized_receipt_v1(transaction_id)
                        .map_err(NodeRuntimeError::from);
                    let _response_canceled = response.send(result);
                }
                Command::FinalizedProof {
                    transaction_id,
                    checkpoint_height,
                    response,
                } => {
                    let permit = self.proof_workers.clone().try_acquire_owned();
                    match permit {
                        Err(_) => {
                            let _response_canceled =
                                response.send(Err(NodeRuntimeError::ProofWorkersBusy));
                        }
                        Ok(permit) => {
                            match self.node.load_finalized_transaction_proof_with_budget_v1(
                                transaction_id,
                                checkpoint_height,
                                self.proof_material_budget_bytes,
                            ) {
                                Err(error) => {
                                    drop(permit);
                                    let _response_canceled =
                                        response.send(Err(NodeRuntimeError::from(error)));
                                }
                                Ok(None) => {
                                    drop(permit);
                                    let _response_canceled = response.send(Ok(None));
                                }
                                Ok(Some(material)) => {
                                    // The snapshot owns no store or mutable node
                                    // state. Hashing and signatures may therefore
                                    // run outside the ordered consensus owner.
                                    let _worker = tokio::task::spawn_blocking(move || {
                                        let _permit = permit;
                                        let result = material
                                            .assemble()
                                            .map(Some)
                                            .map_err(NodeRuntimeError::from);
                                        let _response_canceled = response.send(result);
                                    });
                                }
                            }
                        }
                    }
                }
                Command::Expire { now_ms, response } => {
                    let result = self.expire(now_ms);
                    let fatal = result
                        .as_ref()
                        .err()
                        .and_then(NodeRuntimeError::fatal_invariant);
                    let _response_canceled = response.send(result);
                    if let Some(message) = fatal {
                        return Err(NodeRuntimeError::Inconsistent(message));
                    }
                }
                Command::BuildCandidateV4 {
                    proposer,
                    timestamp_ms,
                    now_ms,
                    evidence,
                    response,
                } => {
                    let result = self.build_candidate_v4(proposer, timestamp_ms, now_ms, evidence);
                    let fatal = result
                        .as_ref()
                        .err()
                        .and_then(NodeRuntimeError::fatal_invariant);
                    let _response_canceled = response.send(result);
                    if let Some(message) = fatal {
                        return Err(NodeRuntimeError::Inconsistent(message));
                    }
                }
                Command::ConsensusContextV1 { response } => {
                    let result = self.consensus_context_v1();
                    let _response_canceled = response.send(result);
                }
                Command::ProcessedSlashingEvidenceV1 { hashes, response } => {
                    let processed = &self.node.state().processed_slashing_evidence;
                    let result = hashes
                        .into_iter()
                        .filter(|hash| processed.contains(hash))
                        .collect();
                    let _response_canceled = response.send(Ok(result));
                }
                Command::ValidateCandidateV4 {
                    block,
                    next_authority_set,
                    response,
                } => {
                    let result = self
                        .node
                        .validate_candidate_v4(&block, &next_authority_set)
                        .map_err(NodeRuntimeError::from);
                    let _response_canceled = response.send(result);
                }
                Command::ConsensusWalV1 { height, response } => {
                    let result = self
                        .node
                        .consensus_wal_v1(height.get())
                        .map_err(NodeRuntimeError::from);
                    let _response_canceled = response.send(result);
                }
                Command::PersistConsensusWalV1 { record, response } => {
                    let result = self
                        .node
                        .persist_consensus_wal_v1(&record)
                        .map_err(NodeRuntimeError::from);
                    let _response_canceled = response.send(result);
                }
                Command::CertifiedBlockV4 { height, response } => {
                    let result = self
                        .node
                        .certified_block_v4(height)
                        .map(|snapshot| {
                            snapshot.map(|(block, next_authority_set, certificate)| {
                                CertifiedBlockSnapshotV1 {
                                    block,
                                    next_authority_set,
                                    certificate,
                                }
                            })
                        })
                        .map_err(NodeRuntimeError::from);
                    let _response_canceled = response.send(result);
                }
                Command::FinalizeV4 {
                    block,
                    next_authority_set,
                    certificate,
                    response,
                } => {
                    let result = self.finalize_v4(*block, *next_authority_set, *certificate);
                    let fatal = result
                        .as_ref()
                        .err()
                        .and_then(NodeRuntimeError::fatal_invariant);
                    let _response_canceled = response.send(result);
                    if let Some(message) = fatal {
                        return Err(NodeRuntimeError::Inconsistent(message));
                    }
                }
                Command::Shutdown { response } => {
                    // No earlier proof task may outlive an acknowledged clean
                    // shutdown. Acquiring every permit waits for the bounded
                    // workers without retaining their large owned snapshots.
                    let worker_count =
                        u32::try_from(DEFAULT_FINALIZED_PROOF_WORKERS).map_err(|_| {
                            NodeRuntimeError::Inconsistent("proof worker count exceeds u32")
                        })?;
                    if let Ok(permits) = self
                        .proof_workers
                        .clone()
                        .acquire_many_owned(worker_count)
                        .await
                    {
                        drop(permits);
                    }
                    let _response_canceled = response.send(());
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn submit(
        &mut self,
        transaction: TransactionV5,
        now_ms: LocalTimestampMs,
    ) -> Result<V5SubmitReceipt, NodeRuntimeError> {
        let transaction_id = transaction.transaction_id().map_err(V5MempoolError::from)?;
        let next_height = next_height(&self.node)?;
        let plan = self.mempool.plan_admission(
            transaction,
            self.node.state(),
            self.node.config(),
            next_height,
            now_ms,
        )?;
        let outcome = plan.outcome();

        if outcome == V5InsertOutcome::DuplicateKnown {
            if self.mempool.get(transaction_id).is_none()
                || self
                    .node
                    .store()
                    .pending_transaction_v1(transaction_id)?
                    .is_none()
            {
                return Err(NodeRuntimeError::Inconsistent(
                    "duplicate pending transaction is missing from memory or storage",
                ));
            }
            let lifecycle = self
                .node
                .store()
                .transaction_lifecycle_v1(transaction_id)?
                .ok_or(NodeRuntimeError::Inconsistent(
                    "pending duplicate has no durable lifecycle",
                ))?;
            return Ok(V5SubmitReceipt {
                transaction_id,
                outcome,
                lifecycle,
                mempool_size: self.mempool.len(),
            });
        }

        let record = plan
            .record()
            .ok_or(NodeRuntimeError::Inconsistent(
                "mutating admission has no pending record",
            ))?
            .clone();
        let durable_outcome = match outcome {
            V5InsertOutcome::Added => self.node.store_mut().store_pending_v1(&record, None)?,
            V5InsertOutcome::Replaced { old_id } => self
                .node
                .store_mut()
                .store_pending_v1(&record, Some(old_id))?,
            V5InsertOutcome::Evicted { old_id } => self
                .node
                .store_mut()
                .store_pending_with_eviction_v1(&record, old_id)?,
            V5InsertOutcome::DuplicateKnown => {
                return Err(NodeRuntimeError::Inconsistent(
                    "duplicate admission reached the mutating storage path",
                ));
            }
        };

        let PendingAdmissionOutcomeV1::Stored {
            queued,
            replaced,
            evicted,
        } = durable_outcome
        else {
            return Err(NodeRuntimeError::Inconsistent(
                "single-owner storage unexpectedly knew a planned newcomer",
            ));
        };

        // The durable transition is complete. Applying this prevalidated plan is
        // now infallible and must happen before inspecting defensive metadata so
        // memory never lags a successful disk commit.
        self.mempool.apply_committed(plan);
        validate_durable_outcome(outcome, transaction_id, &queued, &replaced, &evicted)?;
        let mut events = replaced
            .iter()
            .chain(evicted.iter())
            .map(|lifecycle| lifecycle.as_ref().clone())
            .chain(std::iter::once(queued.clone()))
            .collect::<Vec<_>>();
        events.sort_by_key(|lifecycle| lifecycle.sequence);
        for lifecycle in events {
            let _no_live_subscribers = self.lifecycle_events.send(lifecycle);
        }
        Ok(V5SubmitReceipt {
            transaction_id,
            outcome,
            lifecycle: queued,
            mempool_size: self.mempool.len(),
        })
    }

    fn stats(&self) -> Result<V5RuntimeStats, NodeRuntimeError> {
        let committed_height = self
            .node
            .store()
            .tip()?
            .map_or(BlockHeight::new(0), |tip| BlockHeight::new(tip.height));
        Ok(V5RuntimeStats {
            committed_height,
            mempool_size: self.mempool.len(),
            mempool_bytes: self.mempool.total_bytes(),
            active_finalized_proofs: DEFAULT_FINALIZED_PROOF_WORKERS
                .saturating_sub(self.proof_workers.available_permits()),
        })
    }

    fn consensus_context_v1(&self) -> Result<ConsensusContextV1, NodeRuntimeError> {
        Ok(ConsensusContextV1 {
            height: next_height(&self.node)?,
            current_authority_set: self.node.current_finality_authority_set_v1()?,
        })
    }

    fn expire(&mut self, now_ms: LocalTimestampMs) -> Result<usize, NodeRuntimeError> {
        let expired = self.mempool.expired_ids(now_ms);
        let mut removed = 0usize;
        for transaction_id in expired {
            let lifecycle = self.node.store_mut().remove_pending_v1(
                transaction_id,
                LocalTransactionObservationV1::Expired {
                    observed_at_ms: now_ms,
                },
            )?;
            let lifecycle = lifecycle.ok_or(NodeRuntimeError::Inconsistent(
                "expired in-memory transaction has no durable lifecycle",
            ))?;
            self.mempool.remove_committed(transaction_id);
            let _no_live_subscribers = self.lifecycle_events.send(lifecycle);
            removed = removed
                .checked_add(1)
                .ok_or(NodeRuntimeError::Inconsistent(
                    "expired transaction count overflowed",
                ))?;
        }
        Ok(removed)
    }

    fn build_candidate_v4(
        &self,
        proposer: webc_crypto::Address,
        timestamp_ms: u64,
        now_ms: LocalTimestampMs,
        evidence: Vec<SlashingEvidence>,
    ) -> Result<BuiltBlockV4, NodeRuntimeError> {
        let height = next_height(&self.node)?;
        let mut transactions =
            self.mempool
                .select_block(self.node.state(), self.node.config(), height, now_ms)?;
        loop {
            match self.node.build_candidate_v4(
                transactions.clone(),
                evidence.clone(),
                proposer,
                timestamp_ms,
            ) {
                Ok(candidate) => return Ok(candidate),
                Err(NodeError::BlockV4(error))
                    if matches!(error.as_ref(), BlockV4ExecutionError::BlockTooLarge)
                        && !transactions.is_empty() =>
                {
                    // Receipt/event bytes are known only after execution. Drop
                    // the lowest-priority tail and retry against the same state;
                    // each iteration strictly reduces bounded input.
                    let reduced_len = transactions.len() / 2;
                    transactions.truncate(reduced_len);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn finalize_v4(
        &mut self,
        block: BlockV4,
        next_authority_set: FinalityAuthoritySetV1,
        certificate: FinalityCertificate,
    ) -> Result<V4FinalizationResult, NodeRuntimeError> {
        let result =
            self.node
                .import_finalized_block_v4(block, &next_authority_set, &certificate)?;

        // The complete backend batch is durable. Memory removals are now
        // infallible and must happen before any fallible lifecycle read.
        for transaction_id in &result.removed_pending_ids {
            self.mempool.remove_committed(*transaction_id);
        }
        let mut affected = result
            .finalized_transaction_ids
            .iter()
            .chain(result.removed_pending_ids.iter())
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .filter_map(|transaction_id| {
                self.node
                    .store()
                    .transaction_lifecycle_v1(transaction_id)
                    .ok()
                    .flatten()
            })
            .collect::<Vec<_>>();
        affected.sort_by_key(|lifecycle| lifecycle.sequence);
        for lifecycle in affected {
            let _no_live_subscribers = self.lifecycle_events.send(lifecycle);
        }
        Ok(result)
    }
}

fn next_height<K: KvStore>(node: &Node<K>) -> Result<BlockHeight, NodeRuntimeError> {
    let committed = node.store().tip()?.map_or(0, |tip| tip.height);
    committed
        .checked_add(1)
        .map(BlockHeight::new)
        .ok_or(NodeRuntimeError::HeightExhausted)
}

fn recover_pending<K: KvStore>(
    node: &mut Node<K>,
    config: V5MempoolConfig,
    now_ms: LocalTimestampMs,
) -> Result<V5Mempool, NodeRuntimeError> {
    if node.state().protocol_version != TRANSACTION_V5_PROTOCOL_VERSION
        || node.config().protocol_version != TRANSACTION_V5_PROTOCOL_VERSION
        || node.state().chain_id != node.config().chain_id
    {
        return Err(V5MempoolError::ProtocolInactive.into());
    }
    let next_height = next_height(node)?;
    let records = node
        .store()
        .pending_transactions_v1(MAX_PENDING_TRANSACTION_SCAN_V1)?;
    let mut mempool = V5Mempool::new(config.clone())?;

    for record in records {
        if now_ms.get().saturating_sub(record.admitted_at_ms.get()) >= config.ttl_ms {
            remove_recovered(
                node,
                record.transaction_id,
                LocalTransactionObservationV1::Expired {
                    observed_at_ms: now_ms,
                },
            )?;
            continue;
        }

        let plan = match mempool.plan_admission(
            record.transaction.clone(),
            node.state(),
            node.config(),
            next_height,
            record.admitted_at_ms,
        ) {
            Ok(plan) => plan,
            Err(V5MempoolError::Capacity) => {
                remove_recovered(
                    node,
                    record.transaction_id,
                    LocalTransactionObservationV1::Dropped {
                        reason: LocalDropReasonV1::CapacityEviction,
                        observed_at_ms: now_ms,
                    },
                )?;
                continue;
            }
            Err(_revalidation_failed) => {
                remove_recovered(
                    node,
                    record.transaction_id,
                    LocalTransactionObservationV1::Dropped {
                        reason: LocalDropReasonV1::RevalidationFailed,
                        observed_at_ms: now_ms,
                    },
                )?;
                continue;
            }
        };

        if plan.record() != Some(&record) {
            return Err(NodeRuntimeError::Inconsistent(
                "restart admission changed a durable pending record",
            ));
        }
        match plan.outcome() {
            V5InsertOutcome::Added => {}
            V5InsertOutcome::Evicted { old_id } => {
                remove_recovered(
                    node,
                    old_id,
                    LocalTransactionObservationV1::Dropped {
                        reason: LocalDropReasonV1::CapacityEviction,
                        observed_at_ms: now_ms,
                    },
                )?;
            }
            V5InsertOutcome::Replaced { .. } | V5InsertOutcome::DuplicateKnown => {
                return Err(NodeRuntimeError::Inconsistent(
                    "durable restart scan contains duplicate transaction slots",
                ));
            }
        }
        // Any victim removal is durable before this index mutation.
        mempool.apply_committed(plan);
    }
    Ok(mempool)
}

fn remove_recovered<K: KvStore>(
    node: &mut Node<K>,
    transaction_id: TransactionId,
    observation: LocalTransactionObservationV1,
) -> Result<(), NodeRuntimeError> {
    let lifecycle = node
        .store_mut()
        .remove_pending_v1(transaction_id, observation)?;
    if lifecycle.is_none() {
        return Err(NodeRuntimeError::Inconsistent(
            "restart scan record disappeared before durable removal",
        ));
    }
    Ok(())
}

fn validate_durable_outcome(
    outcome: V5InsertOutcome,
    transaction_id: TransactionId,
    queued: &TransactionLifecycleV1,
    replaced: &Option<Box<TransactionLifecycleV1>>,
    evicted: &Option<Box<TransactionLifecycleV1>>,
) -> Result<(), NodeRuntimeError> {
    let replaced_id = replaced.as_deref().map(|entry| entry.transaction_id);
    let evicted_id = evicted.as_deref().map(|entry| entry.transaction_id);
    let metadata_matches = match outcome {
        V5InsertOutcome::DuplicateKnown => false,
        V5InsertOutcome::Added => replaced_id.is_none() && evicted_id.is_none(),
        V5InsertOutcome::Replaced { old_id } => replaced_id == Some(old_id) && evicted_id.is_none(),
        V5InsertOutcome::Evicted { old_id } => replaced_id.is_none() && evicted_id == Some(old_id),
    };
    if queued.transaction_id != transaction_id || !metadata_matches {
        return Err(NodeRuntimeError::Inconsistent(
            "durable admission metadata disagrees with its pure plan",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::time::Duration;

    use super::*;
    use webc_chain::{
        ActionV1, Amount, AuthorizationLaneId, AuthorizationPolicyRevision, ChainConfig, ChainId,
        FeeBid, FeePaymentV1, GenesisAccount, GenesisConfig, GenesisValidator, Nonce, Operation,
        SignedVote, TransactionAuthorizationV1, ValidatorSet, ValidityWindowV1, Vote, VoteType,
    };
    use webc_crypto::Keypair;
    use webc_storage::{KvEntry, MemoryKvStore, RedbKvStore, Table, WriteBatch};

    const NOW: u64 = 1_700_000_000_000;

    fn genesis(sender: &Keypair) -> GenesisConfig {
        genesis_for(&[sender])
    }

    fn genesis_for(senders: &[&Keypair]) -> GenesisConfig {
        GenesisConfig {
            chain: ChainConfig {
                protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
                ..ChainConfig::default()
            },
            accounts: senders
                .iter()
                .map(|sender| GenesisAccount {
                    address: sender.address(),
                    balance: Amount::from_units(10_000_000),
                })
                .collect(),
            validators: Vec::new(),
        }
    }

    fn genesis_with_validator(validator: &Keypair) -> GenesisConfig {
        GenesisConfig {
            chain: ChainConfig {
                protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
                ..ChainConfig::default()
            },
            accounts: vec![GenesisAccount {
                address: validator.address(),
                balance: Amount::from_webc(1_000),
            }],
            validators: vec![GenesisValidator {
                operator: validator.address(),
                consensus_key: validator.public_key(),
                self_stake: Amount::from_webc(100),
                commission_bps: 500,
                bootstrap: false,
            }],
        }
    }

    fn certificate_for(
        genesis: &GenesisConfig,
        validator: &Keypair,
        block: &BlockV4,
    ) -> FinalityCertificate {
        let state = webc_chain::ChainState::from_genesis_v1(genesis)
            .expect("certificate fixture genesis builds");
        let validator_set =
            ValidatorSet::from_state(&state).expect("certificate fixture snapshot builds");
        let block_hash = block.hash().expect("candidate block hashes");
        let vote = SignedVote::sign(
            Vote {
                protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
                chain_id: genesis.chain.chain_id.clone(),
                height: block.header.height.get(),
                round: 0,
                vote_type: VoteType::Precommit,
                block_hash,
                validator: validator.address(),
            },
            validator,
        )
        .expect("certificate fixture vote signs");
        FinalityCertificate::build(
            &validator_set,
            TRANSACTION_V5_PROTOCOL_VERSION,
            genesis.chain.chain_id.clone(),
            block.header.height.get(),
            0,
            block_hash,
            &[vote],
        )
        .expect("single-validator certificate reaches quorum")
    }

    fn transfer(
        sender: &Keypair,
        recipient: &Keypair,
        nonce: u64,
        max_fee_per_unit: u64,
    ) -> TransactionV5 {
        let mut transaction = TransactionV5::for_actions_unsigned(
            ChainId::devnet(),
            sender.address(),
            sender.public_key(),
            TransactionAuthorizationV1 {
                lane: AuthorizationLaneId::DEFAULT,
                policy_revision: AuthorizationPolicyRevision::new(0),
                nonce: Nonce::new(nonce),
            },
            ValidityWindowV1::new(BlockHeight::new(1), BlockHeight::new(20)),
            vec![ActionV1::native(Operation::Transfer {
                to: recipient.address(),
                amount: Amount::from_units(1),
            })],
            FeeBid {
                gas_limit: 1_000,
                max_fee_per_unit,
                priority_fee_per_unit: 1,
            },
            FeePaymentV1::SenderLane,
        )
        .expect("test transaction shape is valid");
        transaction
            .sign(sender)
            .expect("test transaction signature is valid");
        transaction
    }

    #[tokio::test]
    async fn consensus_commands_share_the_actor_and_prune_wal_on_finality() {
        let validator = Keypair::from_seed([1; 32]);
        let genesis = genesis_with_validator(&validator);
        let node = Node::open(MemoryKvStore::new(), &genesis).expect("test node opens");
        let (handle, task) = NodeRuntime::spawn(
            node,
            V5MempoolConfig::default(),
            8,
            LocalTimestampMs::new(NOW),
        )
        .expect("runtime starts");

        let context = handle
            .consensus_context_v1()
            .await
            .expect("context is actor-consistent");
        assert_eq!(context.height, BlockHeight::new(1));
        assert_eq!(context.current_authority_set.authorities.len(), 1);
        let journal = ConsensusWalRecordV1 {
            height: 1,
            proposals: Vec::new(),
            votes: Vec::new(),
            locked_round: None,
            locked_value: None,
            valid_round: None,
            valid_value: None,
        };
        handle
            .persist_consensus_wal_v1(journal.clone())
            .await
            .expect("journal commits");
        assert_eq!(
            handle
                .consensus_wal_v1(BlockHeight::new(1))
                .await
                .expect("journal loads"),
            Some(journal)
        );

        let candidate = handle
            .build_candidate_v4(
                validator.address(),
                NOW,
                LocalTimestampMs::new(NOW),
                Vec::new(),
            )
            .await
            .expect("candidate builds through actor");
        handle
            .validate_candidate_v4(
                candidate.block.clone(),
                candidate.next_authority_set.clone(),
            )
            .await
            .expect("candidate replays through actor");
        let certificate = certificate_for(&genesis, &validator, &candidate.block);
        handle
            .finalize_v4(
                candidate.block.clone(),
                candidate.next_authority_set.clone(),
                certificate,
            )
            .await
            .expect("candidate finalizes through actor");
        assert!(handle
            .consensus_wal_v1(BlockHeight::new(1))
            .await
            .expect("pruned journal query succeeds")
            .is_none());
        let stored = handle
            .certified_block_v4(BlockHeight::new(1))
            .await
            .expect("certified snapshot loads")
            .expect("height one exists");
        assert_eq!(
            stored.block.header.hash().unwrap(),
            candidate.block.header.hash().unwrap()
        );
        assert_eq!(stored.next_authority_set, candidate.next_authority_set);

        handle.shutdown().await.expect("shutdown is acknowledged");
        task.await
            .expect("runtime task does not panic")
            .expect("runtime exits cleanly");
    }

    #[tokio::test]
    async fn finalized_proof_is_assembled_from_the_durable_certified_block() {
        let validator = Keypair::from_seed([0x21; 32]);
        let recipient = Keypair::from_seed([0x22; 32]);
        let genesis = genesis_with_validator(&validator);
        let node = Node::open(MemoryKvStore::new(), &genesis).expect("test node opens");
        let (handle, task) = NodeRuntime::spawn(
            node,
            V5MempoolConfig::default(),
            8,
            LocalTimestampMs::new(NOW),
        )
        .expect("runtime starts");
        let transaction = transfer(&validator, &recipient, 0, 5);
        let transaction_id = transaction
            .transaction_id()
            .expect("test transaction has an ID");

        handle
            .submit(transaction, LocalTimestampMs::new(NOW))
            .await
            .expect("transaction enters the durable mempool");
        assert!(handle
            .finalized_proof(transaction_id, BlockHeight::new(1))
            .await
            .expect("a pending transaction has no finalized proof")
            .is_none());

        let candidate = handle
            .build_candidate_v4(
                validator.address(),
                NOW + 1,
                LocalTimestampMs::new(NOW + 1),
                Vec::new(),
            )
            .await
            .expect("candidate builds");
        let target_height = candidate.block.header.height;
        let target_epoch = candidate.block.header.epoch;
        let certificate = certificate_for(&genesis, &validator, &candidate.block);
        handle
            .finalize_v4(candidate.block, candidate.next_authority_set, certificate)
            .await
            .expect("candidate finalizes");

        let bundle = handle
            .finalized_proof(transaction_id, target_height)
            .await
            .expect("proof assembly succeeds")
            .expect("finalized transaction has a proof");
        assert!(bundle.proof.authority_transitions.is_empty());
        assert_eq!(bundle.proof.target_header.height, target_height);

        // Re-run the pure verifier as a light client would. The served
        // checkpoint remains only a candidate until the caller applies its own
        // trust policy; this test supplies exact local requirements explicitly.
        let checkpoint = webc_proof::validate_checkpoint_v1(
            bundle.checkpoint_candidate,
            &webc_proof::CheckpointRequirementsV1::new(
                genesis.chain.chain_id.clone(),
                target_height,
                target_epoch,
            ),
        )
        .expect("checkpoint candidate validates structurally");
        let verified = webc_proof::verify_finalized_transaction_proof_v1(
            &bundle.proof,
            &checkpoint,
            &webc_proof::FinalizedTransactionProofRequirementsV1::new(
                genesis.chain.chain_id.clone(),
                transaction_id,
                genesis.chain.staking.blocks_per_epoch,
            ),
        )
        .expect("assembled proof verifies independently");
        assert_eq!(verified.transaction_id, transaction_id);
        assert_eq!(verified.position.height, target_height);

        assert!(matches!(
            handle
                .finalized_proof(transaction_id, BlockHeight::new(0))
                .await,
            Err(NodeRuntimeError::Node(NodeError::InvalidProofRequest(_)))
        ));

        handle.shutdown().await.expect("shutdown is acknowledged");
        task.await
            .expect("runtime task does not panic")
            .expect("runtime exits cleanly");
    }

    #[tokio::test]
    async fn finalized_proof_loads_only_the_required_epoch_boundary() {
        let validator = Keypair::from_seed([0x23; 32]);
        let recipient = Keypair::from_seed([0x24; 32]);
        let mut genesis = genesis_with_validator(&validator);
        genesis.chain.staking.blocks_per_epoch = 2;
        let node = Node::open(MemoryKvStore::new(), &genesis).expect("test node opens");
        let (handle, task) = NodeRuntime::spawn(
            node,
            V5MempoolConfig::default(),
            8,
            LocalTimestampMs::new(NOW),
        )
        .expect("runtime starts");

        // Height 1 is the trusted checkpoint. Height 2 is the only authority
        // transition needed to reach the target in epoch 1.
        for offset in 1..=2 {
            let timestamp = NOW + offset;
            let candidate = handle
                .build_candidate_v4(
                    validator.address(),
                    timestamp,
                    LocalTimestampMs::new(timestamp),
                    Vec::new(),
                )
                .await
                .expect("empty boundary history builds");
            assert_eq!(candidate.block.header.height, BlockHeight::new(offset));
            assert_eq!(candidate.block.header.epoch, webc_chain::Epoch::new(0));
            let certificate = certificate_for(&genesis, &validator, &candidate.block);
            handle
                .finalize_v4(candidate.block, candidate.next_authority_set, certificate)
                .await
                .expect("boundary history finalizes");
        }

        let transaction = transfer(&validator, &recipient, 0, 5);
        let transaction_id = transaction
            .transaction_id()
            .expect("test transaction has an ID");
        handle
            .submit(transaction, LocalTimestampMs::new(NOW + 3))
            .await
            .expect("target transaction enters the durable mempool");
        let candidate = handle
            .build_candidate_v4(
                validator.address(),
                NOW + 3,
                LocalTimestampMs::new(NOW + 3),
                Vec::new(),
            )
            .await
            .expect("epoch-one target builds");
        assert_eq!(candidate.block.header.height, BlockHeight::new(3));
        assert_eq!(candidate.block.header.epoch, webc_chain::Epoch::new(1));
        let certificate = certificate_for(&genesis, &validator, &candidate.block);
        handle
            .finalize_v4(candidate.block, candidate.next_authority_set, certificate)
            .await
            .expect("epoch-one target finalizes");

        let bundle = handle
            .finalized_proof(transaction_id, BlockHeight::new(1))
            .await
            .expect("cross-epoch proof assembly succeeds")
            .expect("finalized transaction has a proof");
        assert_eq!(bundle.proof.authority_transitions.len(), 1);
        let transition = &bundle.proof.authority_transitions[0];
        assert_eq!(transition.header.height, BlockHeight::new(2));
        assert_eq!(
            transition.outgoing_authority_set.epoch,
            webc_chain::Epoch::new(0)
        );
        assert_eq!(
            transition.incoming_authority_set.epoch,
            webc_chain::Epoch::new(1)
        );

        let checkpoint = webc_proof::validate_checkpoint_v1(
            bundle.checkpoint_candidate,
            &webc_proof::CheckpointRequirementsV1::new(
                genesis.chain.chain_id.clone(),
                BlockHeight::new(1),
                webc_chain::Epoch::new(0),
            ),
        )
        .expect("checkpoint candidate validates structurally");
        let verified = webc_proof::verify_finalized_transaction_proof_v1(
            &bundle.proof,
            &checkpoint,
            &webc_proof::FinalizedTransactionProofRequirementsV1::new(
                genesis.chain.chain_id.clone(),
                transaction_id,
                genesis.chain.staking.blocks_per_epoch,
            ),
        )
        .expect("cross-epoch proof verifies independently");
        assert_eq!(verified.position.height, BlockHeight::new(3));

        handle.shutdown().await.expect("shutdown is acknowledged");
        task.await
            .expect("runtime task does not panic")
            .expect("runtime exits cleanly");
    }

    #[tokio::test]
    async fn bounded_proof_workers_keep_the_actor_responsive() {
        let validator = Keypair::from_seed([0x25; 32]);
        let recipient = Keypair::from_seed([0x26; 32]);
        let genesis = genesis_with_validator(&validator);
        let mut node = Node::open(MemoryKvStore::new(), &genesis).expect("test node opens");
        let transactions = (0..128)
            .map(|nonce| transfer(&validator, &recipient, nonce, 5))
            .collect::<Vec<_>>();
        let transaction_id = transactions[64]
            .transaction_id()
            .expect("target transaction has an ID");
        let candidate = node
            .build_candidate_v4(transactions, Vec::new(), validator.address(), NOW + 1)
            .expect("large proof fixture builds");
        let certificate = certificate_for(&genesis, &validator, &candidate.block);
        node.import_finalized_block_v4(
            candidate.block,
            &candidate.next_authority_set,
            &certificate,
        )
        .expect("large proof fixture finalizes");
        let (handle, task) = NodeRuntime::spawn(
            node,
            V5MempoolConfig::default(),
            8,
            LocalTimestampMs::new(NOW + 1),
        )
        .expect("runtime starts");

        let first_handle = handle.clone();
        let first = tokio::spawn(async move {
            first_handle
                .finalized_proof(transaction_id, BlockHeight::new(1))
                .await
        });
        let second_handle = handle.clone();
        let second = tokio::spawn(async move {
            second_handle
                .finalized_proof(transaction_id, BlockHeight::new(1))
                .await
        });

        // Stats are served by the same ordered actor. Observing both workers
        // active proves that CPU-heavy hashing did not pin that actor.
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let stats = handle.stats().await.expect("actor serves stats");
                if stats.active_finalized_proofs == DEFAULT_FINALIZED_PROOF_WORKERS {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("actor remains responsive while proof workers run");
        assert!(matches!(
            handle
                .finalized_proof(transaction_id, BlockHeight::new(1))
                .await,
            Err(NodeRuntimeError::ProofWorkersBusy)
        ));

        for worker in [first, second] {
            let proof = worker
                .await
                .expect("proof task does not panic")
                .expect("proof worker succeeds")
                .expect("finalized transaction has a proof");
            assert_eq!(proof.proof.transaction_proof.leaf_count.get(), 128);
        }
        handle.shutdown().await.expect("shutdown is acknowledged");
        task.await
            .expect("runtime task does not panic")
            .expect("runtime exits cleanly");
    }

    #[tokio::test]
    async fn oversized_proof_material_releases_permit_and_actor_stays_responsive() {
        let validator = Keypair::from_seed([0x27; 32]);
        let recipient = Keypair::from_seed([0x28; 32]);
        let genesis = genesis_with_validator(&validator);
        let mut node = Node::open(MemoryKvStore::new(), &genesis).expect("test node opens");
        let transaction = transfer(&validator, &recipient, 0, 5);
        let transaction_id = transaction
            .transaction_id()
            .expect("target transaction has an ID");
        let candidate = node
            .build_candidate_v4(vec![transaction], Vec::new(), validator.address(), NOW + 1)
            .expect("proof fixture builds");
        let certificate = certificate_for(&genesis, &validator, &candidate.block);
        node.import_finalized_block_v4(
            candidate.block,
            &candidate.next_authority_set,
            &certificate,
        )
        .expect("proof fixture finalizes");
        let (handle, task) = NodeRuntime::spawn_with_proof_material_budget(
            node,
            V5MempoolConfig::default(),
            8,
            LocalTimestampMs::new(NOW + 1),
            1,
        )
        .expect("runtime starts with a tiny injected proof budget");

        for _ in 0..2 {
            assert!(matches!(
                tokio::time::timeout(
                    Duration::from_secs(1),
                    handle.finalized_proof(transaction_id, BlockHeight::new(1))
                )
                .await
                .expect("actor answers the bounded request"),
                Err(NodeRuntimeError::Node(
                    NodeError::FinalizedProofMaterialTooLarge { maximum_bytes: 1 }
                ))
            ));
            assert_eq!(
                handle
                    .stats()
                    .await
                    .expect("actor remains responsive after rejection")
                    .active_finalized_proofs,
                0,
                "the fail-closed loader must release its proof permit"
            );
        }

        handle.shutdown().await.expect("shutdown is acknowledged");
        task.await
            .expect("runtime task does not panic")
            .expect("runtime exits cleanly");
    }

    #[tokio::test]
    async fn submission_is_durable_idempotent_and_queryable() {
        let alice = Keypair::from_seed([31; 32]);
        let bob = Keypair::from_seed([32; 32]);
        let node = Node::open(MemoryKvStore::new(), &genesis(&alice)).expect("test node opens");
        let (handle, task) = NodeRuntime::spawn(
            node,
            V5MempoolConfig::default(),
            8,
            LocalTimestampMs::new(NOW),
        )
        .expect("runtime starts");
        let transaction = transfer(&alice, &bob, 0, 5);
        let transaction_id = transaction
            .transaction_id()
            .expect("test transaction has an ID");
        let mut events = handle.subscribe_lifecycle();

        let first = handle
            .submit(transaction.clone(), LocalTimestampMs::new(NOW))
            .await
            .expect("first submission commits");
        assert_eq!(first.outcome, V5InsertOutcome::Added);
        assert_eq!(first.transaction_id, transaction_id);
        assert_eq!(first.mempool_size, 1);
        assert!(matches!(
            first.lifecycle.local_observation,
            Some(LocalTransactionObservationV1::Queued { .. })
        ));
        assert_eq!(
            events.try_recv().expect("queued lifecycle is published"),
            first.lifecycle
        );

        let duplicate = handle
            .submit(transaction, LocalTimestampMs::new(NOW + 1))
            .await
            .expect("duplicate is idempotent");
        assert_eq!(duplicate.outcome, V5InsertOutcome::DuplicateKnown);
        assert_eq!(duplicate.lifecycle, first.lifecycle);
        assert_eq!(duplicate.mempool_size, 1);
        assert!(matches!(
            events.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
        assert_eq!(
            handle
                .lifecycle(transaction_id)
                .await
                .expect("lifecycle query succeeds"),
            Some(first.lifecycle)
        );
        assert_eq!(
            handle
                .lifecycles(vec![
                    transaction_id,
                    TransactionId::new(webc_crypto::Hash256([9; 32]))
                ])
                .await
                .expect("bounded lifecycle snapshot succeeds"),
            vec![Some(duplicate.lifecycle), None]
        );
        assert!(handle
            .receipt(transaction_id)
            .await
            .expect("receipt query succeeds")
            .is_none());
        let stats = handle.stats().await.expect("stats query succeeds");
        assert_eq!(stats.committed_height, BlockHeight::new(0));
        assert_eq!(stats.mempool_size, 1);
        assert!(stats.mempool_bytes > 0);

        handle.shutdown().await.expect("shutdown is acknowledged");
        task.await
            .expect("runtime task does not panic")
            .expect("runtime exits cleanly");
    }

    #[tokio::test]
    async fn replacement_commits_old_and_new_lifecycles_before_memory_changes() {
        let alice = Keypair::from_seed([39; 32]);
        let bob = Keypair::from_seed([40; 32]);
        let node = Node::open(MemoryKvStore::new(), &genesis(&alice)).expect("test node opens");
        let (handle, task) = NodeRuntime::spawn(
            node,
            V5MempoolConfig::default(),
            8,
            LocalTimestampMs::new(NOW),
        )
        .expect("runtime starts");
        let old = transfer(&alice, &bob, 0, 5);
        let old_id = old.transaction_id().expect("old transaction has an ID");
        handle
            .submit(old, LocalTimestampMs::new(NOW))
            .await
            .expect("old transaction commits");

        let replacement = transfer(&alice, &bob, 0, 6);
        let replacement_id = replacement.transaction_id().expect("replacement has an ID");
        let receipt = handle
            .submit(replacement, LocalTimestampMs::new(NOW + 1))
            .await
            .expect("replacement commits atomically");
        assert_eq!(receipt.outcome, V5InsertOutcome::Replaced { old_id });
        assert_eq!(receipt.transaction_id, replacement_id);
        assert_eq!(receipt.mempool_size, 1);
        assert!(matches!(
            handle
                .lifecycle(old_id)
                .await
                .expect("old lifecycle query succeeds")
                .and_then(|entry| entry.local_observation),
            Some(LocalTransactionObservationV1::Replaced {
                replacement_id: actual,
                ..
            }) if actual == replacement_id
        ));

        handle.shutdown().await.expect("shutdown is acknowledged");
        task.await
            .expect("runtime task does not panic")
            .expect("runtime exits cleanly");
    }

    #[tokio::test]
    async fn runnable_admission_durably_evicts_parked_gap_at_capacity() {
        let alice = Keypair::from_seed([41; 32]);
        let carol = Keypair::from_seed([42; 32]);
        let recipient = Keypair::from_seed([43; 32]);
        let node = Node::open(MemoryKvStore::new(), &genesis_for(&[&alice, &carol]))
            .expect("test node opens");
        let (handle, task) = NodeRuntime::spawn(
            node,
            V5MempoolConfig {
                max_transactions: 1,
                ..V5MempoolConfig::default()
            },
            8,
            LocalTimestampMs::new(NOW),
        )
        .expect("runtime starts");
        let parked = transfer(&alice, &recipient, 1, 100);
        let parked_id = parked
            .transaction_id()
            .expect("parked transaction has an ID");
        handle
            .submit(parked, LocalTimestampMs::new(NOW))
            .await
            .expect("bounded future nonce is parked");

        let runnable = transfer(&carol, &recipient, 0, 5);
        let receipt = handle
            .submit(runnable, LocalTimestampMs::new(NOW + 1))
            .await
            .expect("runnable newcomer evicts parked gap");
        assert_eq!(
            receipt.outcome,
            V5InsertOutcome::Evicted { old_id: parked_id }
        );
        assert_eq!(receipt.mempool_size, 1);
        assert!(matches!(
            handle
                .lifecycle(parked_id)
                .await
                .expect("evicted lifecycle query succeeds")
                .and_then(|entry| entry.local_observation),
            Some(LocalTransactionObservationV1::Dropped {
                reason: LocalDropReasonV1::CapacityEviction,
                ..
            })
        ));

        handle.shutdown().await.expect("shutdown is acknowledged");
        task.await
            .expect("runtime task does not panic")
            .expect("runtime exits cleanly");
    }

    struct FailSwitchStore {
        inner: MemoryKvStore,
        fail_next_commit: Arc<AtomicBool>,
    }

    impl KvStore for FailSwitchStore {
        fn get(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get(table, key)
        }

        fn commit(&mut self, batch: WriteBatch) -> Result<(), StorageError> {
            if self.fail_next_commit.swap(false, Ordering::SeqCst) {
                return Err(StorageError::Io("injected runtime commit failure".into()));
            }
            self.inner.commit(batch)
        }

        fn last_key(&self, table: Table) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.last_key(table)
        }

        fn scan(
            &self,
            table: Table,
            start_inclusive: Option<&[u8]>,
            limit: usize,
        ) -> Result<Vec<KvEntry>, StorageError> {
            self.inner.scan(table, start_inclusive, limit)
        }
    }

    #[tokio::test]
    async fn failed_persistence_leaves_memory_unchanged_and_runtime_retriable() {
        let alice = Keypair::from_seed([33; 32]);
        let bob = Keypair::from_seed([34; 32]);
        let fail_next_commit = Arc::new(AtomicBool::new(false));
        let backend = FailSwitchStore {
            inner: MemoryKvStore::new(),
            fail_next_commit: Arc::clone(&fail_next_commit),
        };
        let node = Node::open(backend, &genesis(&alice)).expect("test node opens");
        let (handle, task) = NodeRuntime::spawn(
            node,
            V5MempoolConfig::default(),
            8,
            LocalTimestampMs::new(NOW),
        )
        .expect("runtime starts");
        let transaction = transfer(&alice, &bob, 0, 5);
        let transaction_id = transaction
            .transaction_id()
            .expect("test transaction has an ID");

        fail_next_commit.store(true, Ordering::SeqCst);
        assert!(matches!(
            handle
                .submit(transaction.clone(), LocalTimestampMs::new(NOW))
                .await,
            Err(NodeRuntimeError::Storage(StorageError::Io(_)))
        ));
        assert_eq!(
            handle
                .stats()
                .await
                .expect("runtime remains responsive")
                .mempool_size,
            0
        );
        assert!(handle
            .lifecycle(transaction_id)
            .await
            .expect("lifecycle query succeeds")
            .is_none());

        let retry = handle
            .submit(transaction, LocalTimestampMs::new(NOW + 1))
            .await
            .expect("same transaction can be retried after failed disk write");
        assert_eq!(retry.outcome, V5InsertOutcome::Added);
        assert_eq!(retry.mempool_size, 1);

        handle.shutdown().await.expect("shutdown is acknowledged");
        task.await
            .expect("runtime task does not panic")
            .expect("runtime exits cleanly");
    }

    #[tokio::test]
    async fn certified_v4_finalization_is_disk_first_and_retriable() {
        let validator = Keypair::from_seed([0x51; 32]);
        let recipient = Keypair::from_seed([0x52; 32]);
        let genesis = genesis_with_validator(&validator);
        let fail_next_commit = Arc::new(AtomicBool::new(false));
        let backend = FailSwitchStore {
            inner: MemoryKvStore::new(),
            fail_next_commit: Arc::clone(&fail_next_commit),
        };
        let node = Node::open(backend, &genesis).expect("validator node opens");
        let (handle, task) = NodeRuntime::spawn(
            node,
            V5MempoolConfig::default(),
            8,
            LocalTimestampMs::new(NOW),
        )
        .expect("runtime starts");
        let transaction = transfer(&validator, &recipient, 0, 5);
        let transaction_id = transaction
            .transaction_id()
            .expect("test transaction has an ID");
        handle
            .submit(transaction, LocalTimestampMs::new(NOW))
            .await
            .expect("pending transaction commits");

        let candidate = handle
            .build_candidate_v4(
                validator.address(),
                NOW + 1,
                LocalTimestampMs::new(NOW + 1),
                Vec::new(),
            )
            .await
            .expect("runtime selects and builds V4 candidate");
        assert_eq!(candidate.block.transactions.len(), 1);
        let certificate = certificate_for(&genesis, &validator, &candidate.block);

        fail_next_commit.store(true, Ordering::SeqCst);
        assert!(matches!(
            handle
                .finalize_v4(
                    candidate.block.clone(),
                    candidate.next_authority_set.clone(),
                    certificate.clone(),
                )
                .await,
            Err(NodeRuntimeError::Node(NodeError::Storage(
                StorageError::Io(_)
            )))
        ));
        let after_failure = handle.stats().await.expect("runtime remains responsive");
        assert_eq!(after_failure.committed_height, BlockHeight::new(0));
        assert_eq!(after_failure.mempool_size, 1);
        assert!(handle
            .receipt(transaction_id)
            .await
            .expect("receipt query succeeds")
            .is_none());

        let finalized = handle
            .finalize_v4(candidate.block, candidate.next_authority_set, certificate)
            .await
            .expect("identical certified block retries successfully");
        assert_eq!(finalized.height, BlockHeight::new(1));
        assert_eq!(finalized.finalized_transaction_ids, vec![transaction_id]);
        assert_eq!(finalized.removed_pending_ids, vec![transaction_id]);
        let after_commit = handle
            .stats()
            .await
            .expect("committed stats query succeeds");
        assert_eq!(after_commit.committed_height, BlockHeight::new(1));
        assert_eq!(after_commit.mempool_size, 0);
        assert!(handle
            .receipt(transaction_id)
            .await
            .expect("finalized receipt query succeeds")
            .is_some());
        assert!(matches!(
            handle
                .lifecycle(transaction_id)
                .await
                .expect("lifecycle query succeeds")
                .and_then(|lifecycle| lifecycle.consensus_fact),
            Some(webc_storage::TransactionConsensusFactV1::Finalized { .. })
        ));

        handle.shutdown().await.expect("shutdown is acknowledged");
        task.await
            .expect("runtime task does not panic")
            .expect("runtime exits cleanly");
    }

    #[tokio::test]
    async fn external_finality_drops_the_local_slot_competitor_after_disk_commit() {
        let validator = Keypair::from_seed([0x53; 32]);
        let recipient = Keypair::from_seed([0x54; 32]);
        let genesis = genesis_with_validator(&validator);
        let node = Node::open(MemoryKvStore::new(), &genesis).expect("validator node opens");
        let (handle, task) = NodeRuntime::spawn(
            node,
            V5MempoolConfig::default(),
            8,
            LocalTimestampMs::new(NOW),
        )
        .expect("runtime starts");
        let local = transfer(&validator, &recipient, 0, 5);
        let local_id = local.transaction_id().expect("local transaction ID");
        handle
            .submit(local, LocalTimestampMs::new(NOW))
            .await
            .expect("local occupant commits");

        let external = transfer(&validator, &recipient, 0, 6);
        let external_id = external.transaction_id().expect("external transaction ID");
        let proposer = Node::open(MemoryKvStore::new(), &genesis).expect("peer node opens");
        let candidate = proposer
            .build_candidate_v4(vec![external], Vec::new(), validator.address(), NOW + 1)
            .expect("peer builds competing candidate");
        let certificate = certificate_for(&genesis, &validator, &candidate.block);

        let finalized = handle
            .finalize_v4(candidate.block, candidate.next_authority_set, certificate)
            .await
            .expect("external certified transaction finalizes");
        assert_eq!(finalized.finalized_transaction_ids, vec![external_id]);
        assert_eq!(finalized.removed_pending_ids, vec![local_id]);
        assert_eq!(handle.stats().await.expect("stats query").mempool_size, 0);
        assert!(matches!(
            handle
                .lifecycle(local_id)
                .await
                .expect("local lifecycle query")
                .and_then(|lifecycle| lifecycle.local_observation),
            Some(LocalTransactionObservationV1::Dropped {
                reason: LocalDropReasonV1::FinalizedSlotConflict,
                ..
            })
        ));
        assert!(matches!(
            handle
                .lifecycle(external_id)
                .await
                .expect("finalized lifecycle query")
                .and_then(|lifecycle| lifecycle.consensus_fact),
            Some(webc_storage::TransactionConsensusFactV1::Finalized { .. })
        ));

        handle.shutdown().await.expect("shutdown is acknowledged");
        task.await
            .expect("runtime task does not panic")
            .expect("runtime exits cleanly");
    }

    #[tokio::test]
    async fn redb_restart_recovers_then_durably_expires_pending_transaction() {
        let directory = tempfile::tempdir().expect("temporary directory is created");
        let path = directory.path().join("runtime-v1.redb");
        let alice = Keypair::from_seed([35; 32]);
        let bob = Keypair::from_seed([36; 32]);
        let genesis = genesis(&alice);
        let policy = V5MempoolConfig {
            ttl_ms: 10,
            ..V5MempoolConfig::default()
        };
        let transaction = transfer(&alice, &bob, 0, 5);
        let transaction_id = transaction
            .transaction_id()
            .expect("test transaction has an ID");

        {
            let node = Node::open(RedbKvStore::open(&path).expect("redb opens"), &genesis)
                .expect("test node opens");
            let (handle, task) =
                NodeRuntime::spawn(node, policy.clone(), 8, LocalTimestampMs::new(NOW))
                    .expect("runtime starts");
            handle
                .submit(transaction, LocalTimestampMs::new(NOW))
                .await
                .expect("submission commits to redb");
            handle.shutdown().await.expect("shutdown is acknowledged");
            task.await
                .expect("runtime task does not panic")
                .expect("runtime exits cleanly");
        }

        {
            let node = Node::open(RedbKvStore::open(&path).expect("redb reopens"), &genesis)
                .expect("test node recovers");
            let (handle, task) =
                NodeRuntime::spawn(node, policy.clone(), 8, LocalTimestampMs::new(NOW + 9))
                    .expect("runtime recovers pending record");
            assert_eq!(
                handle
                    .stats()
                    .await
                    .expect("stats query succeeds")
                    .mempool_size,
                1
            );
            assert!(matches!(
                handle
                    .lifecycle(transaction_id)
                    .await
                    .expect("lifecycle query succeeds")
                    .and_then(|entry| entry.local_observation),
                Some(LocalTransactionObservationV1::Queued { .. })
            ));
            handle.shutdown().await.expect("shutdown is acknowledged");
            task.await
                .expect("runtime task does not panic")
                .expect("runtime exits cleanly");
        }

        {
            let node = Node::open(
                RedbKvStore::open(&path).expect("redb reopens after TTL"),
                &genesis,
            )
            .expect("test node recovers");
            let (handle, task) =
                NodeRuntime::spawn(node, policy, 8, LocalTimestampMs::new(NOW + 10))
                    .expect("runtime starts after durable expiry cleanup");
            assert_eq!(
                handle
                    .stats()
                    .await
                    .expect("stats query succeeds")
                    .mempool_size,
                0
            );
            assert!(matches!(
                handle
                    .lifecycle(transaction_id)
                    .await
                    .expect("lifecycle query succeeds")
                    .and_then(|entry| entry.local_observation),
                Some(LocalTransactionObservationV1::Expired { .. })
            ));
            handle.shutdown().await.expect("shutdown is acknowledged");
            task.await
                .expect("runtime task does not panic")
                .expect("runtime exits cleanly");
        }
    }

    #[tokio::test]
    async fn full_command_queue_rejects_without_waiting_or_allocating_another_waiter() {
        let alice = Keypair::from_seed([37; 32]);
        let bob = Keypair::from_seed([38; 32]);
        let (sender, _receiver) = mpsc::channel(1);
        let (lifecycle_events, _) = broadcast::channel(1);
        let handle = NodeHandle {
            sender,
            lifecycle_events,
        };
        let (response, _held_response) = oneshot::channel();
        handle
            .sender
            .try_send(Command::Submit {
                transaction: Box::new(transfer(&alice, &bob, 0, 5)),
                now_ms: LocalTimestampMs::new(NOW),
                response,
            })
            .expect("first command fills the queue");

        assert!(matches!(
            handle
                .submit(transfer(&alice, &bob, 1, 5), LocalTimestampMs::new(NOW + 1),)
                .await,
            Err(NodeRuntimeError::QueueFull)
        ));
    }

    #[tokio::test]
    async fn processed_evidence_query_rejects_more_than_the_fixed_pool_bound() {
        let (sender, _receiver) = mpsc::channel(1);
        let (lifecycle_events, _) = broadcast::channel(1);
        let handle = NodeHandle {
            sender,
            lifecycle_events,
        };
        let hashes = vec![webc_crypto::Hash256([0xA5; 32]); MAX_PENDING_SLASHING_EVIDENCE_V1 + 1];

        assert!(matches!(
            handle.processed_slashing_evidence_v1(hashes).await,
            Err(NodeRuntimeError::TooManySlashingEvidenceHashes)
        ));
    }
}
