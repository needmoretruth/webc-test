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
//!   write-ahead log and recovery. Stored *values* pass through `codec` for
//!   transparent zstd compression; keys and logical behavior are unchanged.
//! - `codec`: the at-rest value compression seam (WEBC §15.19/§15.24). It
//!   zstd-compresses values on write with an adaptive skip for tiny or
//!   incompressible payloads and a 1-byte format tag, and decompresses on read.
//!   Compression is a pure physical encoding: a value read back is byte-identical
//!   to the value written, so hashes and signatures (computed over the canonical
//!   bytes above this layer) are unaffected.
//! - `chainstore`: the typed [`ChainStore`] — block/state/tip persistence with
//!   atomic per-block commits and startup consistency checks — built on any
//!   `KvStore`, so it runs identically on both backends.
//!
//! Everything here is deterministic given its inputs and never panics on damaged
//! stored bytes: corruption is returned as [`StorageError::Corruption`].

mod chainstore;
mod codec;
mod error;
mod kv;
mod lifecycle;
mod memory;
mod record_codec;
mod redb_store;
mod state_record;

pub use chainstore::{
    BlockCommit, BlockV4Commit, ChainStore, ChainTip, CHAIN_STORE_SCHEMA_VERSION,
};
pub use error::StorageError;
pub use kv::{KvEntry, KvStore, Table, WriteBatch, WriteOp};
pub use lifecycle::{
    FinalizedReceiptRecordV1, FinalizedTransactionIndexV1, LifecycleSequence, LocalDropReasonV1,
    LocalTimestampMs, LocalTransactionObservationV1, PendingAdmissionOutcomeV1, PendingSlotV1,
    PendingTransactionRecordV1, TransactionConsensusFactV1, TransactionLifecycleV1,
    MAX_PENDING_TRANSACTION_SCAN_V1, TRANSACTION_LIFECYCLE_RECORD_V1,
};
pub use memory::MemoryKvStore;
pub use redb_store::RedbKvStore;
