//! The backend seam: a minimal atomic key/value contract.
//!
//! Purpose: define what WEBC needs from a durable store *before* committing to a
//! concrete database. Everything above this line (`ChainStore`) is written
//! against `KvStore` only, so an in-memory map, a crash-safe append log, or a
//! future embedded database are interchangeable.
//!
//! Boundaries: this module defines the contract and the write-batch value type.
//! It performs no I/O itself.
//!
//! Data flow: callers stage all mutations for one logical commit into a
//! [`WriteBatch`], then hand it to [`KvStore::commit`]. The backend applies the
//! whole batch atomically and durably, or nothing.
//!
//! Security / correctness rules a backend MUST uphold:
//! - Atomicity: after a crash, a committed batch is either fully present or fully
//!   absent — never half applied. WEBC relies on this to advance the chain tip
//!   and the block/state it points at in one indivisible step.
//! - Durability: once `commit` returns `Ok`, the batch survives process and OS
//!   crashes (an fsync-class barrier, for on-disk backends).
//! - Namespace isolation: [`Table`] values address disjoint keyspaces. A key
//!   written under one table can never be read or overwritten through another.
//! - Ordering: `scan` and `last_key` observe keys in ascending *raw byte* order.
//!   WEBC always encodes numeric keys big-endian so byte order equals numeric
//!   order.

use crate::error::StorageError;

/// Disjoint logical namespaces within one backend.
///
/// A fixed enum (rather than free-form string prefixes) makes it impossible to
/// address a keyspace that the store does not know about, and lets a real
/// database map each variant to its own column family. Add variants here as new
/// record kinds appear; never reuse a discriminant for a different meaning, as
/// on-disk backends key their physical layout on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Table {
    /// Singleton chain metadata: the schema version and the committed tip.
    Meta,
    /// Finalized blocks keyed by 8-byte big-endian height.
    Blocks,
    /// Committed post-block state snapshots keyed by 8-byte big-endian height.
    StateSnapshots,
    /// Block-hash to big-endian height index, for hash-addressed block lookups.
    BlockHashIndex,
    /// Validator-set snapshots keyed by 8-byte big-endian epoch.
    ValidatorSets,
}

impl Table {
    /// Stable ordered list of every table. Backends iterate this to allocate
    /// one physical namespace per table; tests iterate it to assert coverage.
    pub const ALL: [Table; 5] = [
        Table::Meta,
        Table::Blocks,
        Table::StateSnapshots,
        Table::BlockHashIndex,
        Table::ValidatorSets,
    ];

    /// A stable, compact byte tag identifying the table in a serialized batch.
    ///
    /// The in-memory backend uses it as a physical namespace key, and on-disk
    /// backends embed it in their commit log, so the mapping is part of the
    /// storage format: change a value only with a schema-version bump.
    pub(crate) fn tag(self) -> u8 {
        match self {
            Table::Meta => 0,
            Table::Blocks => 1,
            Table::StateSnapshots => 2,
            Table::BlockHashIndex => 3,
            Table::ValidatorSets => 4,
        }
    }
}

/// A single key/value pair, both raw byte strings, as yielded by a scan.
pub type KvEntry = (Vec<u8>, Vec<u8>);

/// One staged mutation inside a [`WriteBatch`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteOp {
    /// Insert or overwrite the key with these bytes.
    Put(Vec<u8>),
    /// Remove the key if present.
    Delete,
}

/// An ordered set of mutations applied to a [`KvStore`] as one atomic unit.
///
/// Order is preserved so a later write to the same (table, key) within one batch
/// wins, matching how a caller would reason about sequential edits. Callers build
/// the entire commit — block bytes, state snapshot, indexes, and the tip pointer
/// — into a single batch so the store advances indivisibly.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WriteBatch {
    ops: Vec<(Table, Vec<u8>, WriteOp)>,
}

impl WriteBatch {
    /// Creates an empty batch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stages a put of `value` at `(table, key)`.
    pub fn put(&mut self, table: Table, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) {
        self.ops
            .push((table, key.into(), WriteOp::Put(value.into())));
    }

    /// Stages a delete of `(table, key)`.
    pub fn delete(&mut self, table: Table, key: impl Into<Vec<u8>>) {
        self.ops.push((table, key.into(), WriteOp::Delete));
    }

    /// Number of staged mutations.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Whether the batch has no staged mutations.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Iterates staged mutations in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (Table, &[u8], &WriteOp)> {
        self.ops
            .iter()
            .map(|(table, key, op)| (*table, key.as_slice(), op))
    }

    /// Consumes the batch, yielding owned mutations in insertion order.
    pub(crate) fn into_ops(self) -> Vec<(Table, Vec<u8>, WriteOp)> {
        self.ops
    }
}

/// The durable key/value contract every WEBC storage backend implements.
///
/// Implementations must uphold the atomicity, durability, isolation, and
/// ordering rules documented at the top of this module. Methods take `&self` for
/// reads and `&mut self` for the single mutating entry point, `commit`, so the
/// borrow checker enforces that no read races an in-progress commit within one
/// owner. Cross-thread sharing is the node runtime's responsibility (e.g. behind
/// a lock); the trait deliberately does not mandate interior mutability.
pub trait KvStore {
    /// Returns the value stored at `(table, key)`, or `None` if absent.
    fn get(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    /// Returns whether `(table, key)` is present. Defaults to a `get` probe;
    /// backends may override with a cheaper existence check.
    fn contains(&self, table: Table, key: &[u8]) -> Result<bool, StorageError> {
        Ok(self.get(table, key)?.is_some())
    }

    /// Applies every mutation in `batch` atomically and durably, or none.
    ///
    /// On `Ok`, the writes survive a crash. On `Err`, the store is unchanged and
    /// remains usable. An empty batch is a durable no-op.
    fn commit(&mut self, batch: WriteBatch) -> Result<(), StorageError>;

    /// Returns the largest key present in `table` (raw byte order), or `None`.
    ///
    /// WEBC uses this to find the highest stored height/epoch during recovery
    /// and consistency checks.
    fn last_key(&self, table: Table) -> Result<Option<Vec<u8>>, StorageError>;

    /// Returns up to `limit` entries of `table` in ascending key order, starting
    /// at the first key `>= start_inclusive` (or the first key when `None`).
    ///
    /// A `limit` of zero yields an empty vector. This is a bounded scan by
    /// design: callers page through ranges instead of materializing a whole
    /// table, keeping memory predictable under hostile query volume.
    fn scan(
        &self,
        table: Table,
        start_inclusive: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<KvEntry>, StorageError>;
}
