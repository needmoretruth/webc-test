use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;

/// A 32-byte SHA-256 hash used for blocks, transactions, and Merkle roots.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    /// All-zero hash, used as the empty Merkle root and genesis previous hash.
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn digest(bytes: impl AsRef<[u8]>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes.as_ref());
        Self(hasher.finalize().into())
    }

    pub fn digest_many<const N: usize>(parts: [&[u8]; N]) -> Self {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part);
        }
        Self(hasher.finalize().into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

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
