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
//!
//! Networking, mempool, and API surfaces are added as separate modules so
//! consensus/storage logic stays independent of them.

pub mod node;

pub use node::{Node, NodeError};
