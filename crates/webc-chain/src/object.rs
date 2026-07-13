//! Persistent versioned object identities, ownership, and bounded application data.
//!
//! Objects complement account-style fungible balances; they do not replace
//! them. This module defines data and checked version helpers but does not
//! execute authorization. State execution requires exact object/application
//! keys, current-version matching, and owned-object authorization. Shared-object
//! identity is reserved but mutation remains disabled until a public runtime can
//! supply an auditable authorization rule.

use crate::ChainError;
use serde::{Deserialize, Serialize};
use webc_crypto::{Address, Hash256};

/// Maximum on-chain payload bytes stored in one prototype object.
pub const MAX_OBJECT_DATA_BYTES: usize = 64 * 1024;

/// Fixed 32-byte identity of one application object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectId(Hash256);

impl ObjectId {
    /// Constructs an object identity from a collision-resistant commitment.
    pub const fn new(hash: Hash256) -> Self {
        Self(hash)
    }

    /// Returns the fixed hash used by versioned state keys.
    pub const fn hash(self) -> Hash256 {
        self.0
    }
}

/// Monotonic object revision used for optimistic replay/conflict protection.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct ObjectVersion(u64);

impl ObjectVersion {
    /// First committed revision of a newly created object.
    pub const INITIAL: Self = Self(1);

    /// Constructs a version from its consensus revision number.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the consensus revision number.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advances one revision without wrapping.
    pub fn checked_next(self) -> Result<Self, ChainError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(ChainError::ArithmeticOverflow)
    }
}

/// Authorization owner of one object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectOwner {
    /// One account may mutate or transfer the object.
    Address(Address),
    /// Reserved shared identity; mutation is fail-closed in Phase 1.
    Shared,
}

/// Persistent application object committed by the global state root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateObject {
    /// Stable object identity.
    pub id: ObjectId,
    /// Application namespace isolating scheduling and future local fees.
    pub namespace: Hash256,
    /// Current mutation authority.
    pub owner: ObjectOwner,
    /// Monotonic revision; every mutation or transfer increments it once.
    pub version: ObjectVersion,
    /// Bounded opaque application bytes; large files remain off-chain.
    #[serde(with = "bounded_hex")]
    pub data: Vec<u8>,
}

impl StateObject {
    /// Creates the first owned revision after enforcing the byte limit.
    pub fn new_owned(
        id: ObjectId,
        namespace: Hash256,
        owner: Address,
        data: Vec<u8>,
    ) -> Result<Self, ChainError> {
        validate_object_data(&data)?;
        Ok(Self {
            id,
            namespace,
            owner: ObjectOwner::Address(owner),
            version: ObjectVersion::INITIAL,
            data,
        })
    }
}

/// Rejects hostile object payloads before storage or canonical hashing work grows.
pub fn validate_object_data(data: &[u8]) -> Result<(), ChainError> {
    if data.len() > MAX_OBJECT_DATA_BYTES {
        return Err(ChainError::ObjectDataTooLarge {
            actual: data.len(),
            maximum: MAX_OBJECT_DATA_BYTES,
        });
    }
    Ok(())
}

/// Human-readable hex codec that checks the object limit before byte allocation.
pub(crate) mod bounded_hex {
    use super::MAX_OBJECT_DATA_BYTES;
    use serde::{de::Error as DeError, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let maximum_hex_bytes = MAX_OBJECT_DATA_BYTES
            .checked_mul(2)
            .ok_or_else(|| D::Error::custom("object data limit overflow"))?;
        if encoded.len() > maximum_hex_bytes {
            return Err(D::Error::custom("object data exceeds maximum byte length"));
        }
        if encoded.len() % 2 != 0 {
            return Err(D::Error::custom("object data hex length must be even"));
        }
        hex::decode(encoded).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_hex_is_rejected_before_byte_decoding() {
        let encoded = "00".repeat(MAX_OBJECT_DATA_BYTES + 1);
        let value = serde_json::json!({
            "id": "11".repeat(32),
            "namespace": "22".repeat(32),
            "owner": "Shared",
            "version": 1,
            "data": encoded,
        });
        assert!(serde_json::from_value::<StateObject>(value).is_err());
    }
}
