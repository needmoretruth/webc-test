//! Fixed-width SHA-256 values used at WEBC protocol boundaries.
//!
//! This module owns strict 32-byte hash storage, deterministic SHA-256 helpers,
//! and hexadecimal/binary serialization. It does not define signing or hashing
//! domains, canonicalize protocol messages, or build Merkle trees; callers must
//! supply canonical, explicitly domain-separated bytes where the protocol
//! requires them. Serialized values are hostile input and must decode to
//! exactly 32 bytes, preventing truncated or oversized identities from crossing
//! the crypto boundary.

use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;

/// A 32-byte SHA-256 hash used for blocks, transactions, and Merkle roots.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    /// All-zero hash, used as the empty Merkle root and genesis previous hash.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Hashes one byte sequence with SHA-256.
    ///
    /// This helper adds no domain separator. Consensus callers must include the
    /// appropriate versioned domain in `bytes` before invoking it.
    pub fn digest(bytes: impl AsRef<[u8]>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes.as_ref());
        Self(hasher.finalize().into())
    }

    /// Hashes `N` byte slices in order without intermediate allocation.
    ///
    /// Concatenation boundaries are not encoded by this helper. Protocol
    /// callers must use fixed-width fields or an unambiguous canonical encoding.
    pub fn digest_many<const N: usize>(parts: [&[u8]; N]) -> Self {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part);
        }
        Self(hasher.finalize().into())
    }

    /// Borrows the exact 32-byte SHA-256 value.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encodes the hash as 64 lowercase hexadecimal characters.
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Hash256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            serializer.serialize_bytes(self.0.as_slice())
        }
    }
}

impl<'de> Deserialize<'de> for Hash256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let value = String::deserialize(deserializer)?;
            let bytes = hex::decode(value).map_err(D::Error::custom)?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| D::Error::custom("expected a 32-byte hex hash"))?;
            Ok(Self(bytes))
        } else {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| D::Error::custom("expected a 32-byte hash"))?;
            Ok(Self(bytes))
        }
    }
}
