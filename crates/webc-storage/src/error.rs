//! Typed storage errors.
//!
//! Purpose: give every storage backend and the `ChainStore` layer a single,
//! non-panicking error channel. Boundaries: this module owns no I/O and no state;
//! it only classifies failures so callers can distinguish a transient I/O fault
//! from durable data corruption (which must be surfaced, never silently ignored).
//!
//! Security rules:
//! - Corruption is a first-class, reported outcome (`Corruption`). A backend that
//!   reads a torn or checksum-mismatched record MUST return this rather than
//!   panicking or returning partial data, so a node fails closed on a damaged
//!   store instead of committing to an inconsistent chain.
//! - Errors carry human-readable context strings only. They never embed secrets;
//!   callers pass in bytes, keys, and heights, none of which are secret material.

/// Every fallible storage operation returns this error.
///
/// It is `Send + Sync` so it can cross the node runtime and API task boundaries.
/// `std::io::Error` is flattened to a message string here on purpose: the exact
/// OS error object is not needed downstream, and keeping the enum free of
/// non-`PartialEq` payloads keeps it cheap to compare in tests.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// A lower-level I/O operation failed (open, read, write, fsync, rename).
    #[error("storage I/O error: {0}")]
    Io(String),
    /// Stored bytes are structurally damaged: a torn record, a bad checksum, or
    /// a truncated file. The store must be treated as untrustworthy from here.
    #[error("stored data is corrupt: {0}")]
    Corruption(String),
    /// A value could not be encoded to or decoded from its stored representation.
    #[error("storage serialization failed: {0}")]
    Serialization(String),
    /// A caller attempted to persist a structurally invalid or contradictory
    /// typed record. No write is performed.
    #[error("invalid storage record: {0}")]
    InvalidRecord(String),
    /// The on-disk schema version is not one this build understands. Refusing to
    /// proceed prevents interpreting a future layout with today's rules.
    #[error("unsupported storage schema version {found} (this build expects {expected})")]
    UnsupportedSchemaVersion { found: u32, expected: u32 },
    /// A cross-record invariant does not hold (for example, a tip pointer that
    /// references a height with no stored block). Indicates a logic or
    /// durability bug and must stop the node.
    #[error("chain store is inconsistent: {0}")]
    Inconsistent(String),
    /// The store was created for a different chain than the one opening it.
    /// Refusing to proceed stops a node from resuming another network's data
    /// under this configuration (finding ST1).
    #[error("stored chain id {found} does not match the expected chain id {expected}")]
    ChainIdMismatch { expected: String, found: String },
}

impl From<bincode::Error> for StorageError {
    fn from(error: bincode::Error) -> Self {
        Self::Serialization(error.to_string())
    }
}
