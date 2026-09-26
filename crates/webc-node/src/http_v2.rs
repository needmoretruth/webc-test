//! Protocol-2 HTTP and WebSocket transaction lifecycle transport.
//!
//! Purpose: expose the single [`crate::NodeRuntime`] owner through stable `/v2`
//! transaction routes. Responsibilities: reserve bounded request/connection
//! capacity, enforce hostile JSON/message limits before decoding, project durable
//! lifecycle facts into public status types, redact internal failures, and stream
//! explicitly subscribed IDs with resnapshot-on-lag behavior. Non-responsibilities:
//! mempool policy, storage mutation, execution, finality, proof construction, and
//! peer gossip; all mutable work crosses [`crate::NodeHandle`].
//!
//! Data flow: HTTP submissions enter a pre-body concurrency gate, decode through
//! `TransactionV5::decode_json`, and await the actor's durable receipt. Queries
//! ask the same actor for lifecycle/receipt records. WebSockets subscribe to the
//! bounded actor broadcast before taking one actor-consistent snapshot, filter
//! older queued events by sequence, and disconnect with a resumable marker on
//! lag instead of allocating an unbounded buffer.
//!
//! Security boundary: paths, bodies, WebSocket frames, subscription sets, local
//! time, and runtime errors are hostile. Fixed byte/count/concurrency limits are
//! checked before expensive validation. Public errors contain stable codes and
//! correlation IDs but never storage paths, signed request contents, or internal
//! invariant details.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Path, RawQuery, Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use tokio::sync::{broadcast, Semaphore};
use webc_chain::{
    ActionIndex, BlockPositionV1, ExecutionFailureCodeV1, ReceiptStatusV1, ReceiptV1,
    TransactionId, TransactionV5, TRANSACTION_V5_PROTOCOL_VERSION,
};
use webc_net::{NetMessage, NetworkHandle};
use webc_proof::{CheckpointV1, FinalizedTransactionProofV1};
use webc_storage::{
    LifecycleSequence, LocalDropReasonV1, LocalTimestampMs, LocalTransactionObservationV1,
    TransactionConsensusFactV1, TransactionLifecycleV1,
};

use crate::{
    FinalizedTransactionProofBundleV1, NodeError, NodeHandle, NodeRuntimeError, V5InsertOutcome,
    V5MempoolError, V5SubmitReceipt,
};

/// Stable route/API version returned by protocol-2 transaction endpoints.
pub const TRANSACTION_API_VERSION_V2: &str = "v2";
/// Existing outer HTTP body cap retained for all V2 routes (1 MiB).
pub const MAX_V2_HTTP_BODY_BYTES: usize = 1024 * 1024;
/// Maximum concurrently decoding/validating V2 submissions.
pub const MAX_V2_CONCURRENT_SUBMISSIONS: usize = 128;
/// Maximum proof assemblies admitted concurrently before fail-fast backpressure.
pub const MAX_V2_CONCURRENT_PROOFS: usize = 4;
/// Maximum concurrent V2 lifecycle WebSocket connections.
pub const MAX_V2_WS_SUBSCRIPTIONS: usize = 256;
/// Maximum first subscription frame size before JSON decoding.
pub const MAX_V2_WS_MESSAGE_BYTES: usize = 16 * 1024;
/// Time allowed for a connected socket to provide its bounded subscription.
pub const V2_WS_SUBSCRIBE_TIMEOUT: Duration = Duration::from_secs(10);
/// Default request burst allowed for one observed peer IP.
pub const DEFAULT_V2_PER_IP_BURST: u64 = 120;
/// Default local refill interval per request token (10 requests/second).
pub const DEFAULT_V2_PER_IP_REFILL_MS: u64 = 100;
/// Maximum peer-IP buckets retained to keep rate-limit memory bounded.
pub const DEFAULT_V2_MAX_TRACKED_IPS: usize = 4_096;
/// Idle peer bucket retention before bounded table cleanup.
pub const DEFAULT_V2_IP_BUCKET_IDLE_TTL: Duration = Duration::from_secs(10 * 60);

/// Public typed reason for a local lifecycle drop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum V2DropReason {
    /// Bounded policy displaced this transaction for a more valuable one.
    CapacityEviction,
    /// Restart checks found the stored transaction no longer admissible.
    RevalidationFailed,
    /// The stored record belongs to an unsupported transaction protocol.
    UnsupportedProtocolVersion,
    /// An operator explicitly removed the local pending copy.
    OperatorRequest,
    /// Another transaction for this authorization slot finalized.
    FinalizedSlotConflict,
}

impl From<LocalDropReasonV1> for V2DropReason {
    fn from(reason: LocalDropReasonV1) -> Self {
        match reason {
            LocalDropReasonV1::CapacityEviction => Self::CapacityEviction,
            LocalDropReasonV1::RevalidationFailed => Self::RevalidationFailed,
            LocalDropReasonV1::UnsupportedProtocolVersion => Self::UnsupportedProtocolVersion,
            LocalDropReasonV1::OperatorRequest => Self::OperatorRequest,
            LocalDropReasonV1::FinalizedSlotConflict => Self::FinalizedSlotConflict,
        }
    }
}

/// Stable public transaction status; authoritative finality always wins.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum V2TransactionStatus {
    /// This node has no durable fact for the transaction ID.
    Unknown,
    /// The complete signed transaction is durably queued locally.
    Queued {
        /// Node-local observation time in Unix milliseconds.
        observed_at_ms: LocalTimestampMs,
    },
    /// A higher-fee transaction took the same sender/lane/nonce slot.
    Replaced {
        /// Transaction now occupying the slot.
        replacement_id: TransactionId,
        /// Node-local replacement time in Unix milliseconds.
        observed_at_ms: LocalTimestampMs,
    },
    /// The node stopped retaining this transaction for a typed local reason.
    Dropped {
        /// Stable safe reason code.
        reason: V2DropReason,
        /// Node-local removal time in Unix milliseconds.
        observed_at_ms: LocalTimestampMs,
    },
    /// The node-local retention TTL elapsed.
    Expired {
        /// Node-local expiry time in Unix milliseconds.
        observed_at_ms: LocalTimestampMs,
    },
    /// A legacy stored observation knows the candidate position but not outcome.
    ///
    /// New candidates always use `IncludedSuccess` or `IncludedFailure`; this
    /// variant remains only so pre-outcome persisted records are not guessed.
    Included {
        /// Candidate block position, not yet an authoritative result.
        position: BlockPositionV1,
    },
    /// A legacy stored finality fact knows the position but not outcome.
    ///
    /// Storage normally enriches this from its canonical receipt before the API
    /// sees it. Keeping the variant makes the pure projection fail safe if an
    /// older in-memory caller supplies an un-enriched record.
    Finalized {
        /// Authoritative finalized position.
        position: BlockPositionV1,
    },
    /// A candidate included a transaction whose V1 receipt succeeded.
    IncludedSuccess {
        /// Candidate block position, not yet an authoritative finality fact.
        position: BlockPositionV1,
    },
    /// A candidate included a transaction whose V1 receipt recorded failure.
    IncludedFailure {
        /// Candidate block position, not yet an authoritative finality fact.
        position: BlockPositionV1,
        /// Stable consensus receipt failure code.
        code: ExecutionFailureCodeV1,
        /// Zero-based failed action, absent for transaction-wide execution work.
        failed_action_index: Option<ActionIndex>,
    },
    /// Consensus finalized a successful V1 receipt.
    FinalizedSuccess {
        /// Authoritative finalized position.
        position: BlockPositionV1,
    },
    /// Consensus finalized a failed V1 receipt after charging bounded work.
    FinalizedFailure {
        /// Authoritative finalized position.
        position: BlockPositionV1,
        /// Stable consensus receipt failure code.
        code: ExecutionFailureCodeV1,
        /// Zero-based failed action, absent for transaction-wide execution work.
        failed_action_index: Option<ActionIndex>,
    },
}

/// Public lifecycle query/stream snapshot for one transaction ID.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2LifecycleResponse {
    /// Stable API route family.
    pub api_version: &'static str,
    /// Queried domain-separated transaction ID.
    pub transaction_id: TransactionId,
    /// Latest durable global observation order, absent only for `Unknown`.
    pub sequence: Option<LifecycleSequence>,
    /// Finality-preferred lifecycle projection.
    pub status: V2TransactionStatus,
}

impl V2LifecycleResponse {
    fn project(transaction_id: TransactionId, lifecycle: Option<TransactionLifecycleV1>) -> Self {
        let Some(lifecycle) = lifecycle else {
            return Self {
                api_version: TRANSACTION_API_VERSION_V2,
                transaction_id,
                sequence: None,
                status: V2TransactionStatus::Unknown,
            };
        };
        let status = match lifecycle.consensus_fact {
            Some(TransactionConsensusFactV1::Finalized { position }) => {
                V2TransactionStatus::Finalized { position }
            }
            Some(TransactionConsensusFactV1::FinalizedWithOutcome { position, status }) => {
                project_finalized_outcome(position, status)
            }
            None => match lifecycle.local_observation {
                Some(LocalTransactionObservationV1::Queued { observed_at_ms }) => {
                    V2TransactionStatus::Queued { observed_at_ms }
                }
                Some(LocalTransactionObservationV1::Replaced {
                    replacement_id,
                    observed_at_ms,
                }) => V2TransactionStatus::Replaced {
                    replacement_id,
                    observed_at_ms,
                },
                Some(LocalTransactionObservationV1::Dropped {
                    reason,
                    observed_at_ms,
                }) => V2TransactionStatus::Dropped {
                    reason: reason.into(),
                    observed_at_ms,
                },
                Some(LocalTransactionObservationV1::Expired { observed_at_ms }) => {
                    V2TransactionStatus::Expired { observed_at_ms }
                }
                Some(LocalTransactionObservationV1::Included { position }) => {
                    V2TransactionStatus::Included { position }
                }
                Some(LocalTransactionObservationV1::IncludedWithOutcome { position, status }) => {
                    project_included_outcome(position, status)
                }
                None => V2TransactionStatus::Unknown,
            },
        };
        Self {
            api_version: TRANSACTION_API_VERSION_V2,
            transaction_id,
            sequence: Some(lifecycle.sequence),
            status,
        }
    }
}

fn project_included_outcome(
    position: BlockPositionV1,
    status: ReceiptStatusV1,
) -> V2TransactionStatus {
    match status {
        ReceiptStatusV1::Succeeded => V2TransactionStatus::IncludedSuccess { position },
        ReceiptStatusV1::Failed {
            code,
            failed_action_index,
        } => V2TransactionStatus::IncludedFailure {
            position,
            code,
            failed_action_index,
        },
    }
}

fn project_finalized_outcome(
    position: BlockPositionV1,
    status: ReceiptStatusV1,
) -> V2TransactionStatus {
    match status {
        ReceiptStatusV1::Succeeded => V2TransactionStatus::FinalizedSuccess { position },
        ReceiptStatusV1::Failed {
            code,
            failed_action_index,
        } => V2TransactionStatus::FinalizedFailure {
            position,
            code,
            failed_action_index,
        },
    }
}

/// Stable public classification of successful V5 admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum V2InsertOutcome {
    /// Exact ID already known and unchanged.
    DuplicateKnown,
    /// New transaction filled an empty pending slot.
    Added,
    /// New transaction replaced the named slot occupant.
    Replaced {
        /// Replaced transaction ID.
        old_id: TransactionId,
    },
    /// New transaction displaced the named capacity victim.
    Evicted {
        /// Capacity-evicted transaction ID.
        old_id: TransactionId,
    },
}

impl From<V5InsertOutcome> for V2InsertOutcome {
    fn from(outcome: V5InsertOutcome) -> Self {
        match outcome {
            V5InsertOutcome::DuplicateKnown => Self::DuplicateKnown,
            V5InsertOutcome::Added => Self::Added,
            V5InsertOutcome::Replaced { old_id } => Self::Replaced { old_id },
            V5InsertOutcome::Evicted { old_id } => Self::Evicted { old_id },
        }
    }
}

/// Successful `POST /v2/transactions` response after durable admission.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2SubmitResponse {
    /// Stable API route family.
    pub api_version: &'static str,
    /// Submitted transaction ID.
    pub transaction_id: TransactionId,
    /// Typed idempotent insertion outcome.
    pub outcome: V2InsertOutcome,
    /// Latest durable status for the submitted ID.
    pub lifecycle: V2LifecycleResponse,
    /// Retained pending transaction count after admission.
    pub mempool_size: usize,
}

/// Successful checkpoint-relative finalized transaction proof response.
///
/// `checkpoint_candidate` is structurally valid but not trusted merely because
/// this node served it. Clients must corroborate it under an explicit source
/// policy before verifying and relying on `proof`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2FinalizedTransactionProofResponse {
    /// Stable API route family.
    pub api_version: &'static str,
    /// Certified checkpoint candidate requiring independent corroboration.
    pub checkpoint_candidate: CheckpointV1,
    /// Transaction and receipt inclusion proof relative to the candidate.
    pub proof: FinalizedTransactionProofV1,
}

impl From<FinalizedTransactionProofBundleV1> for V2FinalizedTransactionProofResponse {
    fn from(bundle: FinalizedTransactionProofBundleV1) -> Self {
        Self {
            api_version: TRANSACTION_API_VERSION_V2,
            checkpoint_candidate: bundle.checkpoint_candidate,
            proof: bundle.proof,
        }
    }
}

impl From<V5SubmitReceipt> for V2SubmitResponse {
    fn from(receipt: V5SubmitReceipt) -> Self {
        Self {
            api_version: TRANSACTION_API_VERSION_V2,
            transaction_id: receipt.transaction_id,
            outcome: receipt.outcome.into(),
            lifecycle: V2LifecycleResponse::project(
                receipt.transaction_id,
                Some(receipt.lifecycle),
            ),
            mempool_size: receipt.mempool_size,
        }
    }
}

/// Stable redacted error body returned by V2 HTTP handlers.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2ErrorBody {
    /// Stable API route family.
    pub api_version: &'static str,
    /// Stable machine-readable error code.
    pub code: &'static str,
    /// Safe non-sensitive description.
    pub message: &'static str,
    /// Node-local correlation ID for operator logs.
    pub request_id: String,
}

#[derive(Debug)]
enum V2ApiError {
    InvalidTransaction,
    InvalidTransactionId,
    InvalidCheckpointHeight,
    ReceiptNotFinalized,
    ProofNotFinalized,
    ProofLimit,
    BodyTooLarge,
    SubmissionLimit,
    WebSocketLimit,
    RateLimited,
    RateLimiterUnavailable,
    Runtime(NodeRuntimeError),
}

struct V2ApiRejection {
    error: V2ApiError,
    request_id: String,
}

impl IntoResponse for V2ApiRejection {
    fn into_response(self) -> Response {
        let (status, code, message, internal) = match &self.error {
            V2ApiError::InvalidTransaction => (
                StatusCode::BAD_REQUEST,
                "invalid_transaction",
                "transaction JSON or signature is invalid",
                false,
            ),
            V2ApiError::InvalidTransactionId => (
                StatusCode::BAD_REQUEST,
                "invalid_transaction_id",
                "transaction ID must be 32-byte lowercase or uppercase hex",
                false,
            ),
            V2ApiError::InvalidCheckpointHeight => (
                StatusCode::BAD_REQUEST,
                "invalid_checkpoint_height",
                "checkpoint_height must be one non-zero canonical decimal u64",
                false,
            ),
            V2ApiError::ReceiptNotFinalized => (
                StatusCode::NOT_FOUND,
                "receipt_not_finalized",
                "no finalized receipt is available",
                false,
            ),
            V2ApiError::ProofNotFinalized => (
                StatusCode::NOT_FOUND,
                "proof_not_finalized",
                "no finalized transaction proof is available",
                false,
            ),
            V2ApiError::ProofLimit => (
                StatusCode::SERVICE_UNAVAILABLE,
                "proof_limit",
                "too many finalized proof requests are in progress",
                false,
            ),
            V2ApiError::BodyTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                "request body exceeds the configured limit",
                false,
            ),
            V2ApiError::SubmissionLimit => (
                StatusCode::SERVICE_UNAVAILABLE,
                "submission_limit",
                "too many transaction submissions are in progress",
                false,
            ),
            V2ApiError::WebSocketLimit => (
                StatusCode::SERVICE_UNAVAILABLE,
                "websocket_limit",
                "too many lifecycle subscriptions are active",
                false,
            ),
            V2ApiError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "request rate exceeds the per-peer limit",
                false,
            ),
            V2ApiError::RateLimiterUnavailable => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "internal server error",
                true,
            ),
            V2ApiError::Runtime(error) => classify_runtime_error(error),
        };
        if internal {
            eprintln!(
                "internal V2 API error (request_id={}): {:?}",
                self.request_id, self.error
            );
        }
        (
            status,
            Json(V2ErrorBody {
                api_version: TRANSACTION_API_VERSION_V2,
                code,
                message,
                request_id: self.request_id,
            }),
        )
            .into_response()
    }
}

fn classify_runtime_error(
    error: &NodeRuntimeError,
) -> (StatusCode, &'static str, &'static str, bool) {
    match error {
        NodeRuntimeError::QueueFull => (
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_busy",
            "transaction runtime is busy; retry with backoff",
            false,
        ),
        NodeRuntimeError::ProofWorkersBusy => (
            StatusCode::SERVICE_UNAVAILABLE,
            "proof_workers_busy",
            "finalized proof workers are busy; retry with backoff",
            false,
        ),
        NodeRuntimeError::Stopped => (
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_stopped",
            "transaction runtime is unavailable",
            false,
        ),
        NodeRuntimeError::TooManyLifecycleIds => (
            StatusCode::BAD_REQUEST,
            "too_many_transaction_ids",
            "lifecycle query contains too many transaction IDs",
            false,
        ),
        NodeRuntimeError::Mempool(V5MempoolError::ReplacementUnderpriced) => (
            StatusCode::CONFLICT,
            "replacement_underpriced",
            "replacement does not meet the required fee bump",
            false,
        ),
        NodeRuntimeError::Mempool(V5MempoolError::Capacity) => (
            StatusCode::TOO_MANY_REQUESTS,
            "mempool_full",
            "bounded transaction capacity cannot admit this transaction",
            false,
        ),
        NodeRuntimeError::Mempool(V5MempoolError::ProtocolInactive) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "protocol_inactive",
            "protocol-2 transaction service is not active",
            false,
        ),
        NodeRuntimeError::Node(NodeError::InvalidProofRequest(_)) => (
            StatusCode::BAD_REQUEST,
            "invalid_checkpoint_height",
            "checkpoint height cannot anchor the requested finalized transaction",
            false,
        ),
        NodeRuntimeError::Node(NodeError::ProofDataUnavailable(_)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "proof_data_unavailable",
            "required finalized proof history is unavailable on this node",
            false,
        ),
        NodeRuntimeError::Node(NodeError::FinalizedProofMaterialTooLarge { .. }) => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "proof_material_too_large",
            "requested finalized proof exceeds the fixed proof size limit",
            false,
        ),
        NodeRuntimeError::Mempool(V5MempoolError::PendingRecord(_))
        | NodeRuntimeError::Mempool(V5MempoolError::InconsistentRecovery)
        | NodeRuntimeError::InvalidQueueCapacity
        | NodeRuntimeError::NoAsyncRuntime
        | NodeRuntimeError::HeightExhausted
        | NodeRuntimeError::TooManySlashingEvidenceHashes
        | NodeRuntimeError::Storage(_)
        | NodeRuntimeError::Node(_)
        | NodeRuntimeError::Inconsistent(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal server error",
            true,
        ),
        NodeRuntimeError::Mempool(_) => (
            StatusCode::BAD_REQUEST,
            "transaction_rejected",
            "transaction was rejected by bounded admission policy",
            false,
        ),
    }
}

/// Shared V2 transport state. It owns no mutable chain or mempool copy.
#[derive(Clone)]
pub struct V2AppState {
    inner: Arc<V2AppInner>,
}

/// Replaceable node-local transport limits; protocol semantics do not depend on them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V2TransportLimits {
    /// Maximum submissions concurrently reading/decoding/awaiting the actor.
    pub concurrent_submissions: usize,
    /// Maximum proof assemblies concurrently admitted to the runtime queue.
    pub concurrent_proofs: usize,
    /// Maximum live lifecycle WebSocket connections.
    pub websocket_subscriptions: usize,
    /// Request tokens available in a burst for one observed socket IP.
    pub per_ip_burst: u64,
    /// Local milliseconds that replenish one request token.
    pub per_ip_refill_ms: u64,
    /// Maximum peer-IP buckets retained in memory.
    pub max_tracked_ips: usize,
}

impl Default for V2TransportLimits {
    fn default() -> Self {
        Self {
            concurrent_submissions: MAX_V2_CONCURRENT_SUBMISSIONS,
            concurrent_proofs: MAX_V2_CONCURRENT_PROOFS,
            websocket_subscriptions: MAX_V2_WS_SUBSCRIPTIONS,
            per_ip_burst: DEFAULT_V2_PER_IP_BURST,
            per_ip_refill_ms: DEFAULT_V2_PER_IP_REFILL_MS,
            max_tracked_ips: DEFAULT_V2_MAX_TRACKED_IPS,
        }
    }
}

/// Invalid zero-valued V2 transport configuration.
#[derive(Debug, thiserror::Error)]
#[error("V2 transport concurrency limits must be non-zero")]
pub struct V2TransportConfigError;

struct V2AppInner {
    runtime: NodeHandle,
    network: Option<NetworkHandle>,
    submission_slots: Arc<Semaphore>,
    proof_slots: Arc<Semaphore>,
    websocket_slots: Arc<Semaphore>,
    peer_rate_limiter: Mutex<PeerRateLimiter>,
    correlation_sequence: AtomicU64,
}

impl V2AppState {
    /// Creates bounded transport state over the one protocol-2 runtime handle.
    pub fn new(runtime: NodeHandle) -> Self {
        Self::from_validated_limits(runtime, None, V2TransportLimits::default())
    }

    /// Creates default-limited transport state that gossips new local admissions.
    pub fn with_network(runtime: NodeHandle, network: NetworkHandle) -> Self {
        Self::from_validated_limits(runtime, Some(network), V2TransportLimits::default())
    }

    /// Creates transport state with explicit replaceable node-local limits.
    pub fn with_limits(
        runtime: NodeHandle,
        limits: V2TransportLimits,
    ) -> Result<Self, V2TransportConfigError> {
        if limits.concurrent_submissions == 0
            || limits.concurrent_proofs == 0
            || limits.websocket_subscriptions == 0
            || limits.per_ip_burst == 0
            || limits.per_ip_refill_ms == 0
            || limits.max_tracked_ips == 0
        {
            return Err(V2TransportConfigError);
        }
        Ok(Self::from_validated_limits(runtime, None, limits))
    }

    /// Creates explicitly limited transport state with optional V5 gossip.
    pub fn with_network_and_limits(
        runtime: NodeHandle,
        network: Option<NetworkHandle>,
        limits: V2TransportLimits,
    ) -> Result<Self, V2TransportConfigError> {
        if limits.concurrent_submissions == 0
            || limits.concurrent_proofs == 0
            || limits.websocket_subscriptions == 0
            || limits.per_ip_burst == 0
            || limits.per_ip_refill_ms == 0
            || limits.max_tracked_ips == 0
        {
            return Err(V2TransportConfigError);
        }
        Ok(Self::from_validated_limits(runtime, network, limits))
    }

    fn from_validated_limits(
        runtime: NodeHandle,
        network: Option<NetworkHandle>,
        limits: V2TransportLimits,
    ) -> Self {
        Self {
            inner: Arc::new(V2AppInner {
                runtime,
                network,
                submission_slots: Arc::new(Semaphore::new(limits.concurrent_submissions)),
                proof_slots: Arc::new(Semaphore::new(limits.concurrent_proofs)),
                websocket_slots: Arc::new(Semaphore::new(limits.websocket_subscriptions)),
                peer_rate_limiter: Mutex::new(PeerRateLimiter::new(limits)),
                correlation_sequence: AtomicU64::new(1),
            }),
        }
    }

    fn request_id(&self) -> String {
        let sequence = self
            .inner
            .correlation_sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .unwrap_or(u64::MAX);
        format!("v2-{sequence:016x}")
    }

    fn reject(&self, error: V2ApiError) -> V2ApiRejection {
        V2ApiRejection {
            error,
            request_id: self.request_id(),
        }
    }
}

struct PeerBucket {
    tokens: u64,
    last_refill: Instant,
    last_seen: Instant,
}

struct PeerRateLimiter {
    buckets: BTreeMap<IpAddr, PeerBucket>,
    burst: u64,
    refill_ms: u64,
    max_tracked_ips: usize,
}

impl PeerRateLimiter {
    fn new(limits: V2TransportLimits) -> Self {
        Self {
            buckets: BTreeMap::new(),
            burst: limits.per_ip_burst,
            refill_ms: limits.per_ip_refill_ms,
            max_tracked_ips: limits.max_tracked_ips,
        }
    }

    fn allow(&mut self, peer: IpAddr, now: Instant) -> bool {
        if !self.buckets.contains_key(&peer) && self.buckets.len() >= self.max_tracked_ips {
            self.buckets.retain(|_, bucket| {
                now.saturating_duration_since(bucket.last_seen) < DEFAULT_V2_IP_BUCKET_IDLE_TTL
            });
            if self.buckets.len() >= self.max_tracked_ips {
                return false;
            }
        }
        let bucket = self.buckets.entry(peer).or_insert(PeerBucket {
            tokens: self.burst,
            last_refill: now,
            last_seen: now,
        });
        let refill_intervals = now
            .saturating_duration_since(bucket.last_refill)
            .as_millis()
            / u128::from(self.refill_ms);
        if refill_intervals > 0 {
            let refilled = u64::try_from(refill_intervals).unwrap_or(u64::MAX);
            bucket.tokens = bucket.tokens.saturating_add(refilled).min(self.burst);
            // Resetting to `now` discards a fractional interval. This is safely
            // stricter than carrying attacker-controlled fractional timing.
            bucket.last_refill = now;
        }
        bucket.last_seen = now;
        if bucket.tokens == 0 {
            return false;
        }
        bucket.tokens -= 1;
        true
    }
}

/// Builds only the protocol-2 transaction routes over an existing runtime.
pub fn router_v2(state: V2AppState) -> Router {
    Router::new()
        .route("/v2/health", get(protocol2_health))
        .route("/v2/transactions", post(submit_transaction))
        .route("/v2/transactions/{id}", get(transaction_lifecycle))
        .route("/v2/transactions/{id}/receipt", get(transaction_receipt))
        .route("/v2/transactions/{id}/proof", get(transaction_proof))
        .route("/v2/transactions/ws", get(subscribe_transactions))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_V2_HTTP_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            reserve_submission_before_body,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_by_peer_ip,
        ))
        .with_state(state)
}

/// Public protocol-2 liveness and finalized-tip projection.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2HealthResponse {
    /// Active transaction/consensus protocol version (exactly 2).
    pub protocol_version: webc_chain::ProtocolVersion,
    /// Chain replay-protection domain served by this runtime.
    pub chain_id: webc_chain::ChainId,
    /// Highest atomically finalized V4 height; zero means genesis only.
    pub finalized_height: u64,
    /// Authority-set commitment that may certify the next height.
    pub current_finality_authority_set_root: webc_crypto::Hash256,
}

async fn protocol2_health(
    State(state): State<V2AppState>,
) -> Result<Json<V2HealthResponse>, V2ApiRejection> {
    let context = state
        .inner
        .runtime
        .consensus_context_v1()
        .await
        .map_err(|error| state.reject(V2ApiError::Runtime(error)))?;
    let authority_root = context
        .current_authority_set
        .commitment()
        .map_err(|error| state.reject(V2ApiError::Runtime(NodeRuntimeError::Node(error.into()))))?;
    Ok(Json(V2HealthResponse {
        protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
        chain_id: context.current_authority_set.chain_id,
        finalized_height: context.height.get().saturating_sub(1),
        current_finality_authority_set_root: authority_root,
    }))
}

async fn rate_limit_by_peer_ip(
    State(state): State<V2AppState>,
    request: Request,
    next: Next,
) -> Response {
    // Trust only the socket address injected by axum's connect-info service;
    // spoofable forwarding headers are deliberately ignored. Router-only tests
    // share one unspecified bucket when no socket extension exists.
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect| connect.0.ip())
        .unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    let allowed = match state.inner.peer_rate_limiter.lock() {
        Ok(mut limiter) => limiter.allow(peer, Instant::now()),
        Err(_) => {
            return state
                .reject(V2ApiError::RateLimiterUnavailable)
                .into_response();
        }
    };
    if !allowed {
        return state.reject(V2ApiError::RateLimited).into_response();
    }
    next.run(request).await
}

async fn reserve_submission_before_body(
    State(state): State<V2AppState>,
    request: Request,
    next: Next,
) -> Response {
    if request.method() != Method::POST || request.uri().path() != "/v2/transactions" {
        return next.run(request).await;
    }
    let Ok(permit) = Arc::clone(&state.inner.submission_slots).try_acquire_owned() else {
        return state.reject(V2ApiError::SubmissionLimit).into_response();
    };
    let response = next.run(request).await;
    drop(permit);
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return state.reject(V2ApiError::BodyTooLarge).into_response();
    }
    response
}

async fn submit_transaction(
    State(state): State<V2AppState>,
    body: Bytes,
) -> Result<Json<V2SubmitResponse>, V2ApiRejection> {
    let transaction = TransactionV5::decode_json(&body)
        .map_err(|_| state.reject(V2ApiError::InvalidTransaction))?;
    let gossip_copy = transaction.clone();
    let receipt = state
        .inner
        .runtime
        .submit(transaction, LocalTimestampMs::new(crate::http::now_ms()))
        .await
        .map_err(|error| state.reject(V2ApiError::Runtime(error)))?;
    if receipt.outcome != V5InsertOutcome::DuplicateKnown {
        if let Some(network) = &state.inner.network {
            // The durable actor transition already succeeded. Gossip is
            // best-effort availability and cannot roll it back or change the
            // client result if the network worker is stopping. Do not consume
            // the network seen marker while disconnected: the public assembly's
            // bounded reconnection sweep will replay this durable transaction
            // when a peer becomes available.
            if network.connected_peers() > 0 {
                let _ = network.broadcast(NetMessage::TransactionV5(Box::new(gossip_copy)));
            }
        }
    }
    Ok(Json(receipt.into()))
}

async fn transaction_lifecycle(
    State(state): State<V2AppState>,
    Path(raw_id): Path<String>,
) -> Result<Json<V2LifecycleResponse>, V2ApiRejection> {
    let transaction_id = parse_transaction_id(&raw_id)
        .ok_or_else(|| state.reject(V2ApiError::InvalidTransactionId))?;
    let lifecycle = state
        .inner
        .runtime
        .lifecycle(transaction_id)
        .await
        .map_err(|error| state.reject(V2ApiError::Runtime(error)))?;
    Ok(Json(V2LifecycleResponse::project(
        transaction_id,
        lifecycle,
    )))
}

async fn transaction_receipt(
    State(state): State<V2AppState>,
    Path(raw_id): Path<String>,
) -> Result<Json<ReceiptV1>, V2ApiRejection> {
    let transaction_id = parse_transaction_id(&raw_id)
        .ok_or_else(|| state.reject(V2ApiError::InvalidTransactionId))?;
    let receipt = state
        .inner
        .runtime
        .receipt(transaction_id)
        .await
        .map_err(|error| state.reject(V2ApiError::Runtime(error)))?
        .ok_or_else(|| state.reject(V2ApiError::ReceiptNotFinalized))?;
    Ok(Json(receipt))
}

async fn transaction_proof(
    State(state): State<V2AppState>,
    Path(raw_id): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> Result<Json<V2FinalizedTransactionProofResponse>, V2ApiRejection> {
    let transaction_id = parse_transaction_id(&raw_id)
        .ok_or_else(|| state.reject(V2ApiError::InvalidTransactionId))?;
    let checkpoint_height = parse_checkpoint_height_query(raw_query.as_deref())
        .ok_or_else(|| state.reject(V2ApiError::InvalidCheckpointHeight))?;
    let permit = Arc::clone(&state.inner.proof_slots)
        .try_acquire_owned()
        .map_err(|_| state.reject(V2ApiError::ProofLimit))?;
    let bundle = state
        .inner
        .runtime
        .finalized_proof(transaction_id, checkpoint_height)
        .await
        .map_err(|error| state.reject(V2ApiError::Runtime(error)))?
        .ok_or_else(|| state.reject(V2ApiError::ProofNotFinalized))?;
    drop(permit);
    Ok(Json(bundle.into()))
}

fn parse_transaction_id(raw: &str) -> Option<TransactionId> {
    if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = hex::decode(raw).ok()?;
    let digest: [u8; 32] = bytes.try_into().ok()?;
    Some(TransactionId::new(webc_crypto::Hash256(digest)))
}

fn parse_checkpoint_height_query(raw: Option<&str>) -> Option<webc_chain::BlockHeight> {
    let value = raw?.strip_prefix("checkpoint_height=")?;
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.starts_with('0')
    {
        return None;
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|height| *height > 0)
        .map(webc_chain::BlockHeight::new)
}

/// First and only client-to-server lifecycle subscription message.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct V2WsSubscribe {
    /// Subscription schema version; currently exactly 1.
    version: u16,
    /// Explicit bounded transaction-ID allow-list.
    transaction_ids: Vec<TransactionId>,
    /// Last sequence already applied by the client, for resumable filtering.
    #[serde(default)]
    after_sequence: Option<LifecycleSequence>,
}

/// Server-to-client lifecycle WebSocket messages.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum V2WsServerMessage {
    /// Current or newly committed lifecycle snapshot for a subscribed ID.
    Snapshot {
        /// Finality-preferred lifecycle snapshot.
        lifecycle: V2LifecycleResponse,
    },
    /// The bounded receiver lagged; reconnect and resnapshot after this sequence.
    ResyncRequired {
        /// Highest sequence safely sent before disconnect.
        last_sequence: LifecycleSequence,
        /// Node-local correlation ID for operator logs.
        request_id: String,
    },
    /// The subscription request or runtime failed safely.
    Error {
        /// Stable machine-readable code.
        code: &'static str,
        /// Safe non-sensitive message.
        message: &'static str,
        /// Node-local correlation ID for operator logs.
        request_id: String,
    },
}

async fn subscribe_transactions(ws: WebSocketUpgrade, State(state): State<V2AppState>) -> Response {
    let Ok(permit) = Arc::clone(&state.inner.websocket_slots).try_acquire_owned() else {
        return state.reject(V2ApiError::WebSocketLimit).into_response();
    };
    ws.max_message_size(MAX_V2_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_V2_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            stream_transaction_lifecycle(socket, state).await;
        })
}

async fn stream_transaction_lifecycle(mut socket: WebSocket, state: V2AppState) {
    let subscription = match tokio::time::timeout(V2_WS_SUBSCRIBE_TIMEOUT, socket.recv()).await {
        Ok(Some(Ok(Message::Text(text)))) if text.len() <= MAX_V2_WS_MESSAGE_BYTES => {
            serde_json::from_str::<V2WsSubscribe>(&text).ok()
        }
        _ => None,
    };
    let Some(subscription) = subscription else {
        send_ws_error(
            &mut socket,
            &state,
            "invalid_subscription",
            "send one bounded JSON subscription message",
        )
        .await;
        return;
    };
    if subscription.version != 1
        || subscription.transaction_ids.is_empty()
        || subscription.transaction_ids.len() > crate::MAX_V5_LIFECYCLE_QUERY_IDS
    {
        send_ws_error(
            &mut socket,
            &state,
            "invalid_subscription",
            "subscription version or transaction-ID count is invalid",
        )
        .await;
        return;
    }
    let subscribed = subscription
        .transaction_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if subscribed.len() != subscription.transaction_ids.len() {
        send_ws_error(
            &mut socket,
            &state,
            "duplicate_transaction_id",
            "subscription transaction IDs must be unique",
        )
        .await;
        return;
    }

    // Subscribe before the actor-consistent snapshot. Events queued before the
    // snapshot response are already reflected by it and filtered by sequence.
    let mut receiver = state.inner.runtime.subscribe_lifecycle();
    let snapshots = match state
        .inner
        .runtime
        .lifecycles(subscription.transaction_ids.clone())
        .await
    {
        Ok(snapshots) => snapshots,
        Err(error) => {
            let (_status, code, message, _internal) = classify_runtime_error(&error);
            send_ws_error(&mut socket, &state, code, message).await;
            return;
        }
    };
    let mut last_sequence = subscription
        .after_sequence
        .map_or(0, LifecycleSequence::get);
    let mut initial_responses = subscription
        .transaction_ids
        .iter()
        .copied()
        .zip(snapshots)
        .map(|(transaction_id, lifecycle)| V2LifecycleResponse::project(transaction_id, lifecycle))
        .filter(|response| {
            response
                .sequence
                .is_none_or(|sequence| sequence.get() > last_sequence)
        })
        .collect::<Vec<_>>();
    // One global cursor is safe only when committed snapshots advance it in
    // sequence order. Request order is attacker-controlled and could otherwise
    // make a newer ID suppress an older-but-still-unseen subscribed lifecycle.
    // Unknown IDs have no sequence and are emitted first in stable request order.
    initial_responses.sort_by_key(|response| response.sequence.map_or(0, LifecycleSequence::get));
    for response in initial_responses {
        let sequence = response.sequence.map_or(0, LifecycleSequence::get);
        if send_ws_message(
            &mut socket,
            &V2WsServerMessage::Snapshot {
                lifecycle: response,
            },
        )
        .await
        .is_err()
        {
            return;
        }
        last_sequence = last_sequence.max(sequence);
    }

    loop {
        tokio::select! {
            event = receiver.recv() => match event {
                Ok(lifecycle) => {
                    if !subscribed.contains(&lifecycle.transaction_id)
                        || lifecycle.sequence.get() <= last_sequence
                    {
                        continue;
                    }
                    last_sequence = lifecycle.sequence.get();
                    let message = V2WsServerMessage::Snapshot {
                        lifecycle: V2LifecycleResponse::project(
                            lifecycle.transaction_id,
                            Some(lifecycle),
                        ),
                    };
                    if send_ws_message(&mut socket, &message).await.is_err() {
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    let _ = send_ws_message(
                        &mut socket,
                        &V2WsServerMessage::ResyncRequired {
                            last_sequence: LifecycleSequence::new(last_sequence),
                            request_id: state.request_id(),
                        },
                    ).await;
                    return;
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                Some(Ok(_)) => {}
            },
        }
    }
}

async fn send_ws_error(
    socket: &mut WebSocket,
    state: &V2AppState,
    code: &'static str,
    message: &'static str,
) {
    let _ = send_ws_message(
        socket,
        &V2WsServerMessage::Error {
            code,
            message,
            request_id: state.request_id(),
        },
    )
    .await;
}

async fn send_ws_message(socket: &mut WebSocket, message: &V2WsServerMessage) -> Result<(), ()> {
    let text = serde_json::to_string(message).map_err(|_| ())?;
    socket
        .send(Message::Text(text.into()))
        .await
        .map_err(|_| ())
}

/// Serves only protocol-2 transaction routes with devnet CORS policy.
pub async fn serve_v2(listener: tokio::net::TcpListener, state: V2AppState) -> std::io::Result<()> {
    let app = router_v2(state).layer(tower_http::cors::CorsLayer::permissive());
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use webc_storage::StorageError;

    #[test]
    fn receipt_outcomes_project_to_distinct_included_and_finalized_statuses() {
        let transaction_id = TransactionId::new(webc_crypto::Hash256([0x61; 32]));
        let position = BlockPositionV1::new(
            webc_chain::BlockHeight::new(7),
            webc_chain::TransactionIndex::new(1),
        );
        let failure = webc_chain::ReceiptStatusV1::Failed {
            code: webc_chain::ExecutionFailureCodeV1::ObjectNotFound,
            failed_action_index: Some(webc_chain::ActionIndex::new(2)),
        };
        let lifecycle = |local_observation, consensus_fact| TransactionLifecycleV1 {
            version: webc_storage::TRANSACTION_LIFECYCLE_RECORD_V1,
            transaction_id,
            sequence: LifecycleSequence::new(9),
            local_observation,
            consensus_fact,
        };

        assert_eq!(
            V2LifecycleResponse::project(
                transaction_id,
                Some(lifecycle(
                    Some(LocalTransactionObservationV1::IncludedWithOutcome {
                        position,
                        status: webc_chain::ReceiptStatusV1::Succeeded,
                    }),
                    None,
                )),
            )
            .status,
            V2TransactionStatus::IncludedSuccess { position }
        );
        assert_eq!(
            V2LifecycleResponse::project(
                transaction_id,
                Some(lifecycle(
                    Some(LocalTransactionObservationV1::IncludedWithOutcome {
                        position,
                        status: failure,
                    }),
                    None,
                )),
            )
            .status,
            V2TransactionStatus::IncludedFailure {
                position,
                code: webc_chain::ExecutionFailureCodeV1::ObjectNotFound,
                failed_action_index: Some(webc_chain::ActionIndex::new(2)),
            }
        );
        assert_eq!(
            V2LifecycleResponse::project(
                transaction_id,
                Some(lifecycle(
                    None,
                    Some(TransactionConsensusFactV1::FinalizedWithOutcome {
                        position,
                        status: webc_chain::ReceiptStatusV1::Succeeded,
                    }),
                )),
            )
            .status,
            V2TransactionStatus::FinalizedSuccess { position }
        );
        assert_eq!(
            V2LifecycleResponse::project(
                transaction_id,
                Some(lifecycle(
                    None,
                    Some(TransactionConsensusFactV1::FinalizedWithOutcome {
                        position,
                        status: failure,
                    }),
                )),
            )
            .status,
            V2TransactionStatus::FinalizedFailure {
                position,
                code: webc_chain::ExecutionFailureCodeV1::ObjectNotFound,
                failed_action_index: Some(webc_chain::ActionIndex::new(2)),
            }
        );
    }

    #[tokio::test]
    async fn internal_error_body_is_correlated_and_redacted() {
        let response = V2ApiRejection {
            error: V2ApiError::Runtime(NodeRuntimeError::Storage(StorageError::Io(
                "secret database path".into(),
            ))),
            request_id: "v2-test".into(),
        }
        .into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("error body reads");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("error body is JSON");
        assert_eq!(body["code"], "internal");
        assert_eq!(body["message"], "internal server error");
        assert_eq!(body["request_id"], "v2-test");
        assert!(!body.to_string().contains("secret database path"));
    }

    #[test]
    fn proof_worker_saturation_is_public_retryable_backpressure() {
        let (status, code, message, internal) =
            classify_runtime_error(&NodeRuntimeError::ProofWorkersBusy);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(code, "proof_workers_busy");
        assert!(message.contains("retry"));
        assert!(!internal);
    }

    #[test]
    fn peer_rate_limiter_bounds_identity_memory_and_refills_without_float_math() {
        let limits = V2TransportLimits {
            per_ip_burst: 1,
            per_ip_refill_ms: 10,
            max_tracked_ips: 1,
            ..V2TransportLimits::default()
        };
        let mut limiter = PeerRateLimiter::new(limits);
        let start = Instant::now();
        let first = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
        let second = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2));
        assert!(limiter.allow(first, start));
        assert!(!limiter.allow(first, start));
        assert!(!limiter.allow(second, start));
        assert!(limiter.allow(first, start + Duration::from_millis(10)));
        assert_eq!(limiter.buckets.len(), 1);
    }

    #[test]
    fn checkpoint_query_accepts_only_one_non_zero_canonical_decimal_height() {
        assert_eq!(
            parse_checkpoint_height_query(Some("checkpoint_height=1")),
            Some(webc_chain::BlockHeight::new(1))
        );
        assert_eq!(
            parse_checkpoint_height_query(Some("checkpoint_height=18446744073709551615")),
            Some(webc_chain::BlockHeight::new(u64::MAX))
        );
        for rejected in [
            None,
            Some(""),
            Some("checkpoint_height="),
            Some("checkpoint_height=0"),
            Some("checkpoint_height=01"),
            Some("checkpoint_height=+1"),
            Some("checkpoint_height=1&extra=1"),
            Some("height=1"),
            Some("checkpoint_height=18446744073709551616"),
        ] {
            assert_eq!(parse_checkpoint_height_query(rejected), None);
        }
    }

    #[tokio::test]
    async fn zero_proof_concurrency_is_rejected() {
        let sender = webc_crypto::Keypair::from_seed([0x71; 32]);
        let genesis = webc_chain::GenesisConfig {
            chain: webc_chain::ChainConfig {
                protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
                ..webc_chain::ChainConfig::default()
            },
            accounts: vec![webc_chain::GenesisAccount {
                address: sender.address(),
                balance: webc_chain::Amount::from_units(1_000_000),
            }],
            validators: Vec::new(),
        };
        let node = crate::Node::open(webc_storage::MemoryKvStore::new(), &genesis)
            .expect("test node opens");
        let (runtime, task) = crate::NodeRuntime::spawn(
            node,
            crate::V5MempoolConfig::default(),
            1,
            LocalTimestampMs::new(0),
        )
        .expect("runtime starts");
        let result = V2AppState::with_limits(
            runtime.clone(),
            V2TransportLimits {
                concurrent_proofs: 0,
                ..V2TransportLimits::default()
            },
        );
        assert!(result.is_err());
        runtime.shutdown().await.expect("runtime shuts down");
        task.await
            .expect("runtime task does not panic")
            .expect("runtime exits cleanly");
    }

    #[tokio::test]
    async fn proof_slot_returns_fail_fast_backpressure() {
        use tower::ServiceExt;

        let sender = webc_crypto::Keypair::from_seed([0x72; 32]);
        let genesis = webc_chain::GenesisConfig {
            chain: webc_chain::ChainConfig {
                protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
                ..webc_chain::ChainConfig::default()
            },
            accounts: vec![webc_chain::GenesisAccount {
                address: sender.address(),
                balance: webc_chain::Amount::from_units(1_000_000),
            }],
            validators: Vec::new(),
        };
        let node = crate::Node::open(webc_storage::MemoryKvStore::new(), &genesis)
            .expect("test node opens");
        let (runtime, task) = crate::NodeRuntime::spawn(
            node,
            crate::V5MempoolConfig::default(),
            1,
            LocalTimestampMs::new(0),
        )
        .expect("runtime starts");
        let state = V2AppState::with_limits(
            runtime.clone(),
            V2TransportLimits {
                concurrent_proofs: 1,
                ..V2TransportLimits::default()
            },
        )
        .expect("non-zero limits are valid");
        let held = Arc::clone(&state.inner.proof_slots)
            .try_acquire_owned()
            .expect("test reserves the only proof slot");
        let unknown = webc_chain::TransactionId::new(webc_crypto::Hash256([0x73; 32]));
        let response = router_v2(state)
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v2/transactions/{unknown}/proof?checkpoint_height=1"
                    ))
                    .body(axum::body::Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("error body reads");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("error body is JSON");
        assert_eq!(body["code"], "proof_limit");
        drop(held);

        runtime.shutdown().await.expect("runtime shuts down");
        task.await
            .expect("runtime task does not panic")
            .expect("runtime exits cleanly");
    }
}
