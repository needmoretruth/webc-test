//! WEBC durable storage: the backend seam and reference implementations.
//!
//! This crate sits between the deterministic protocol core (`webc-chain`) and a
//! running node. It defines *what* WEBC needs from a durable store — an atomic,
//! crash-safe, ordered key/value contract ([`KvStore`]) — deliberately before
//! committing to a concrete database, so the backend can be swapped without
//! touching chain logic.
//!
//! Layers:
//! - [`kv`]: the [`KvStore`] trait plus [`WriteBatch`]/[`Table`], the swappable
//!   backend seam.
//! - [`memory`]: a volatile in-memory backend for tests and ephemeral devnets.
//! - Higher layers (a crash-safe file backend and a typed `ChainStore`) build on
//!   `KvStore` and are added in later steps.
//!
//! Everything here is deterministic given its inputs and never panics on damaged
//! stored bytes: corruption is returned as [`StorageError::Corruption`].

mod error;
mod kv;
mod memory;

pub use error::StorageError;
pub use kv::{KvEntry, KvStore, Table, WriteBatch, WriteOp};
pub use memory::MemoryKvStore;
