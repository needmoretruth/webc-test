//! Bounded encoding for typed records stored behind [`crate::KvStore`].
//!
//! Purpose: keep the stable bincode representation and every hostile-record
//! limit in one auditable seam. Responsibilities: choose an absolute byte cap
//! for each record class, use the protocol's variable-length integer encoding,
//! reject trailing bytes, and classify malformed persisted input as corruption.
//! Non-responsibilities: table/key layout, schema migration, database I/O, and
//! validation of consensus meaning remain with [`crate::ChainStore`] and the
//! protocol types themselves.
//!
//! Data flow: trusted in-memory values pass through [`encode`] before entering a
//! write batch; bytes returned by an untrusted or damaged backend pass through
//! [`decode`], which checks their outer length before serde may inspect any
//! attacker-controlled collection prefix. The same bincode limit remains active
//! during decoding as defense in depth. The limits are node-storage safety bounds,
//! not consensus block limits; changing one requires storage compatibility review.
//!
//! Security boundary: stored bytes can be corrupt or attacker-influenced. No
//! decoder in `ChainStore` may bypass this module. Oversized, truncated,
//! length-prefix-forged, or trailing-byte records fail closed without panicking.

use bincode::Options;
use serde::{de::DeserializeOwned, Serialize};

use crate::StorageError;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;

/// Absolute byte limits for one encoded record of each semantic kind.
///
/// Small metadata limits exceed their exact current encodings while remaining
/// tight. Blocks and certificates align with the current 4 MiB network/block
/// envelope. Validator sets allow the ADR-0016 authority-set ceiling with ample
/// per-entry overhead. State and WAL records need larger caps because the store
/// stores a complete latest-state snapshot and full signed proposal history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StoredRecordKind {
    /// Validated [`webc_chain::ChainId`] metadata (maximum encoded bytes: 128).
    ChainId,
    /// The singleton chain-tip pointer (maximum encoded bytes: 256).
    ChainTip,
    /// One finalized block (maximum encoded bytes: 4 MiB).
    Block,
    /// The latest complete state snapshot (maximum encoded bytes: 256 MiB).
    StateSnapshot,
    /// One epoch validator-set snapshot (maximum encoded bytes: 16 MiB).
    ValidatorSet,
    /// One finality certificate (maximum encoded bytes: 4 MiB).
    FinalityCertificate,
    /// One validator's own per-height consensus journal (maximum encoded bytes: 64 MiB).
    ConsensusWal,
}

impl StoredRecordKind {
    /// Stable diagnostic name that never includes a key or stored payload.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::ChainId => "chain id",
            Self::ChainTip => "chain tip",
            Self::Block => "block",
            Self::StateSnapshot => "state snapshot",
            Self::ValidatorSet => "validator set",
            Self::FinalityCertificate => "finality certificate",
            Self::ConsensusWal => "consensus WAL",
        }
    }

    /// Absolute maximum encoded record size in bytes.
    pub(crate) const fn max_bytes(self) -> u64 {
        match self {
            Self::ChainId => 128,
            Self::ChainTip => 256,
            Self::Block => 4 * MIB,
            Self::StateSnapshot => 256 * MIB,
            Self::ValidatorSet => 16 * MIB,
            Self::FinalityCertificate => 4 * MIB,
            Self::ConsensusWal => 64 * MIB,
        }
    }
}

/// Returns the stable bounded bincode configuration for `kind`.
///
/// Variable-length integers implement the current schema-1 at-rest format from
/// §15.14. Little endian is explicit for the multi-byte varint payloads, while
/// trailing bytes and kind-specific size overruns fail closed. The prototype's
/// earlier fixed-width schema-1 snapshots require an ephemeral-store reset; no
/// ambiguous dual decoder is accepted.
fn options(kind: StoredRecordKind) -> impl Options {
    bincode::DefaultOptions::new()
        .with_varint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
        .with_limit(kind.max_bytes())
}

/// Encodes one typed record in the bounded at-rest representation.
///
/// The record is rejected with [`StorageError::Serialization`] if its encoded
/// form exceeds the kind-specific absolute byte cap or serialization otherwise
/// fails. No partial bytes are returned to a write batch.
pub(crate) fn encode<T: Serialize + ?Sized>(
    kind: StoredRecordKind,
    value: &T,
) -> Result<Vec<u8>, StorageError> {
    options(kind).serialize(value).map_err(|error| {
        StorageError::Serialization(format!(
            "{} record encoding failed (maximum {} bytes): {error}",
            kind.name(),
            kind.max_bytes()
        ))
    })
}

/// Decodes one complete typed record after checking its outer byte length.
///
/// Bytes returned by a [`crate::KvStore`] are hostile. The explicit pre-check
/// runs before bincode/serde can act on a collection length prefix. The bincode
/// configuration then independently caps bytes consumed and rejects trailing,
/// truncated, invalid-tag, and impossible-length inputs. Every such failure is
/// [`StorageError::Corruption`], so callers fail closed rather than retrying a
/// damaged record as transient I/O.
pub(crate) fn decode<T: DeserializeOwned>(
    kind: StoredRecordKind,
    bytes: &[u8],
) -> Result<T, StorageError> {
    let actual = u64::try_from(bytes.len()).map_err(|_| {
        StorageError::Corruption(format!(
            "stored {} record length cannot be represented safely",
            kind.name()
        ))
    })?;
    if actual > kind.max_bytes() {
        return Err(StorageError::Corruption(format!(
            "stored {} record is oversized: {actual} bytes exceeds the {}-byte maximum",
            kind.name(),
            kind.max_bytes()
        )));
    }

    options(kind).deserialize(bytes).map_err(|error| {
        StorageError::Corruption(format!(
            "stored {} record is malformed: {error}",
            kind.name()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_matches_schema_v1_varint_bytes() {
        let value = vec![1u64, 2, u64::MAX];
        let expected = bincode::DefaultOptions::new()
            .with_varint_encoding()
            .with_little_endian()
            .serialize(&value)
            .unwrap();
        let bounded = encode(StoredRecordKind::StateSnapshot, &value).unwrap();
        assert_eq!(bounded, expected);
    }

    #[test]
    fn rejects_a_record_over_its_outer_byte_limit_before_decode() {
        let oversized =
            vec![0u8; usize::try_from(StoredRecordKind::ChainId.max_bytes()).unwrap() + 1];
        let error = decode::<Vec<u8>>(StoredRecordKind::ChainId, &oversized).unwrap_err();
        assert!(matches!(error, StorageError::Corruption(_)));
        assert!(error.to_string().contains("oversized"));
    }

    #[test]
    fn rejects_a_hostile_collection_length_prefix() {
        // Varint marker 0xfd declares that the following eight bytes contain a
        // u64 length. A maximal claimed length in an otherwise tiny record must
        // report corruption rather than drive a correspondingly sized allocation.
        let mut forged = vec![0xfd];
        forged.extend_from_slice(&u64::MAX.to_le_bytes());
        let error = decode::<Vec<u8>>(StoredRecordKind::ChainId, &forged).unwrap_err();
        assert!(matches!(error, StorageError::Corruption(_)));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut encoded = encode(StoredRecordKind::ChainTip, &42u64).unwrap();
        encoded.push(0xaa);
        let error = decode::<u64>(StoredRecordKind::ChainTip, &encoded).unwrap_err();
        assert!(matches!(error, StorageError::Corruption(_)));
    }

    #[test]
    fn rejects_encoding_beyond_the_record_limit() {
        let oversized = vec![0u8; usize::try_from(StoredRecordKind::ChainId.max_bytes()).unwrap()];
        let error = encode(StoredRecordKind::ChainId, &oversized).unwrap_err();
        assert!(matches!(error, StorageError::Serialization(_)));
    }
}
