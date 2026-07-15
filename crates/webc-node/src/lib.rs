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

pub mod mempool;
pub mod node;
pub mod service;

pub use mempool::{InsertOutcome, Mempool, MempoolConfig, MempoolError};
pub use node::{Node, NodeError};
pub use service::{ApiError, FaucetConfig, NodeService, NodeServiceOptions, API_VERSION};
