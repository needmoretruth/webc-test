//! WEBC node library: the restartable runtime that binds the protocol core to
//! durable storage.
//!
//! This crate turns `webc-chain` (deterministic state transitions) and
//! `webc-storage` (durable, crash-safe persistence) into a running node. It is
//! consumed both by the `webc-node` binary (CLI/demo) and, in later steps, by the
//! HTTP/WebSocket API layer.
//!
//! Modules:
//! - [`node`]: the [`Node`] runtime — block production, atomic commit, and
//!   startup recovery.
//! - [`mempool`]: pending-transaction admission, expiry, replacement-by-fee, and
//!   fee-prioritized nonce-ordered block selection.
//!
//! Networking and API surfaces are added as separate modules so consensus and
//! storage logic stay independent of them.

pub mod consensus_driver;
pub mod gossip;
pub mod http;
pub mod http_v2;
pub mod mempool;
pub mod mempool_v1;
pub mod node;
pub mod runtime_v1;
pub mod service;

pub use consensus_driver::{CommitInfo, ConsensusDriver, DriverExit, DriverTimeouts};
pub use gossip::{run_gossip_pump, run_v5_gossip_pump};
pub use http::{router, serve, AppState, BlockEvent};
pub use http_v2::{
    router_v2, serve_v2, V2AppState, V2DropReason, V2ErrorBody, V2InsertOutcome,
    V2LifecycleResponse, V2SubmitResponse, V2TransactionStatus, V2TransportConfigError,
    V2TransportLimits, V2WsServerMessage, DEFAULT_V2_IP_BUCKET_IDLE_TTL,
    DEFAULT_V2_MAX_TRACKED_IPS, DEFAULT_V2_PER_IP_BURST, DEFAULT_V2_PER_IP_REFILL_MS,
    MAX_V2_CONCURRENT_SUBMISSIONS, MAX_V2_HTTP_BODY_BYTES, MAX_V2_WS_MESSAGE_BYTES,
    MAX_V2_WS_SUBSCRIPTIONS, TRANSACTION_API_VERSION_V2, V2_WS_SUBSCRIBE_TIMEOUT,
};
pub use mempool::{InsertOutcome, Mempool, MempoolConfig, MempoolError};
pub use mempool_v1::{
    V5AdmissionPlan, V5InsertOutcome, V5Mempool, V5MempoolConfig, V5MempoolError,
};
pub use node::{Node, NodeError};
pub use runtime_v1::{
    NodeHandle, NodeRuntime, NodeRuntimeError, V5RuntimeStats, V5SubmitReceipt,
    DEFAULT_V5_LIFECYCLE_EVENT_CAPACITY, DEFAULT_V5_RUNTIME_QUEUE_CAPACITY,
    MAX_V5_LIFECYCLE_QUERY_IDS,
};
pub use service::{
    ApiError, FaucetConfig, NetworkAdmission, NodeService, NodeServiceOptions, API_VERSION,
};
