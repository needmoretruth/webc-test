//! WEBC durable storage: the backend seam and reference implementations.
//!
//! This crate sits between the deterministic protocol core (`webc-chain`) and a
//! running node. It defines *what* WEBC needs from a durable store — an atomic,
//! crash-safe, ordered key/value contract ([`KvStore`]) — deliberately before
//! committing to a concrete database, so the backend can be swapped without
//! touching chain logic.
//!
//! Layers:
//! - `kv`: the [`KvStore`] trait plus [`WriteBatch`]/[`Table`], the swappable
//!   backend seam.
//! - `memory`: a volatile in-memory backend ([`MemoryKvStore`]) for tests and
//!   ephemeral devnets.
//! - `redb_store`: the durable, crash-safe backend ([`RedbKvStore`]) built on the
//!   `redb` embedded ACID database (MIT OR Apache-2.0). Per WEBC's reuse rule we
//!   adapt a proven database behind the seam rather than hand-rolling a
//!   write-ahead log and recovery.
//! - `chainstore`: the typed [`ChainStore`] — block/state/tip persistence with
//!   atomic per-block commits and startup consistency checks — built on any
//!   `KvStore`, so it runs identically on both backends.
//!
//! Everything here is deterministic given its inputs and never panics on damaged
//! stored bytes: corruption is returned as [`StorageError::Corruption`].

mod chainstore;
mod error;
mod kv;
mod memory;
mod record_codec;
mod redb_store;

pub use chainstore::{BlockCommit, ChainStore, ChainTip, CHAIN_STORE_SCHEMA_VERSION};
pub use error::StorageError;
pub use kv::{KvEntry, KvStore, Table, WriteBatch, WriteOp};
pub use memory::MemoryKvStore;
pub use redb_store::RedbKvStore;
