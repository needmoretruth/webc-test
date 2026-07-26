//! Protocol-2 node actor: one ordered owner for V5 pending transactions.
//!
//! Purpose: bind the pure [`crate::V5Mempool`] policy to durable lifecycle
//! storage without locks or split ownership. Responsibilities: bounded command
//! admission, persist-before-memory ordering, idempotent submission, local
//! expiry, and deterministic restart reconstruction. Non-responsibilities:
//! HTTP/WebSocket encoding, peer gossip, block selection, execution, consensus,
//! and finality; those layers must call this actor through [`NodeHandle`].
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

use tokio::sync::{mpsc, oneshot};
use webc_chain::{BlockHeight, TransactionId, TransactionV5, TRANSACTION_V5_PROTOCOL_VERSION};
use webc_storage::{
    KvStore, LocalDropReasonV1, LocalTimestampMs, LocalTransactionObservationV1,
    PendingAdmissionOutcomeV1, StorageError, TransactionLifecycleV1,
    MAX_PENDING_TRANSACTION_SCAN_V1,
};

use crate::{Node, V5InsertOutcome, V5Mempool, V5MempoolConfig, V5MempoolError};

/// Default maximum number of commands waiting for the single runtime owner.
pub const DEFAULT_V5_RUNTIME_QUEUE_CAPACITY: usize = 1_024;

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
    /// The actor stopped or the response receiver was canceled.
    #[error("protocol-2 runtime is stopped")]
    Stopped,
    /// No block height exists after the committed tip.
    #[error("protocol-2 runtime cannot advance beyond the maximum block height")]
    HeightExhausted,
    /// Durable storage failed; the current in-memory mutation was not applied.
    #[error("protocol-2 runtime storage error: {0}")]
    Storage(#[from] StorageError),
    /// Transaction admission or restart revalidation failed.
    #[error("protocol-2 runtime mempool error: {0}")]
    Mempool(#[from] V5MempoolError),
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
    Lifecycle {
        transaction_id: TransactionId,
        response: oneshot::Sender<Result<Option<TransactionLifecycleV1>, NodeRuntimeError>>,
    },
    Expire {
        now_ms: LocalTimestampMs,
        response: oneshot::Sender<Result<usize, NodeRuntimeError>>,
    },
    Shutdown {
        response: oneshot::Sender<()>,
    },
}

/// Single-task owner of one node and its protocol-2 in-memory pending indexes.
pub struct NodeRuntime<K: KvStore> {
    node: Node<K>,
    mempool: V5Mempool,
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
        mut node: Node<K>,
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
        if queue_capacity == 0 {
            return Err(NodeRuntimeError::InvalidQueueCapacity);
        }
        tokio::runtime::Handle::try_current().map_err(|_| NodeRuntimeError::NoAsyncRuntime)?;
        let mempool = recover_pending(&mut node, mempool_config, recovery_now_ms)?;
        let (sender, receiver) = mpsc::channel(queue_capacity);
        let runtime = Self { node, mempool };
        let task = tokio::spawn(runtime.run(receiver));
        Ok((NodeHandle { sender }, task))
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
                Command::Shutdown { response } => {
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
            if lifecycle.is_none() {
                return Err(NodeRuntimeError::Inconsistent(
                    "expired in-memory transaction has no durable lifecycle",
                ));
            }
            self.mempool.remove_committed(transaction_id);
            removed = removed
                .checked_add(1)
                .ok_or(NodeRuntimeError::Inconsistent(
                    "expired transaction count overflowed",
                ))?;
        }
        Ok(removed)
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

    use super::*;
    use webc_chain::{
        ActionV1, Amount, AuthorizationLaneId, AuthorizationPolicyRevision, ChainConfig, ChainId,
        FeeBid, FeePaymentV1, GenesisAccount, GenesisConfig, Nonce, Operation,
        TransactionAuthorizationV1, ValidityWindowV1,
    };
    use webc_crypto::Keypair;
    use webc_storage::{KvEntry, MemoryKvStore, RedbKvStore, Table, WriteBatch};

    const NOW: u64 = 1_700_000_000_000;

    fn genesis(sender: &Keypair) -> GenesisConfig {
        GenesisConfig {
            chain: ChainConfig {
                protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
                ..ChainConfig::default()
            },
            accounts: vec![GenesisAccount {
                address: sender.address(),
                balance: Amount::from_units(10_000_000),
            }],
            validators: Vec::new(),
        }
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

        let duplicate = handle
            .submit(transaction, LocalTimestampMs::new(NOW + 1))
            .await
            .expect("duplicate is idempotent");
        assert_eq!(duplicate.outcome, V5InsertOutcome::DuplicateKnown);
        assert_eq!(duplicate.lifecycle, first.lifecycle);
        assert_eq!(duplicate.mempool_size, 1);
        assert_eq!(
            handle
                .lifecycle(transaction_id)
                .await
                .expect("lifecycle query succeeds"),
            Some(first.lifecycle)
        );
        let stats = handle.stats().await.expect("stats query succeeds");
        assert_eq!(stats.committed_height, BlockHeight::new(0));
        assert_eq!(stats.mempool_size, 1);
        assert!(stats.mempool_bytes > 0);

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
        let handle = NodeHandle { sender };
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
}
