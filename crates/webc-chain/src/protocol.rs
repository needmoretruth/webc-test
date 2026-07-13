//! Versioned protocol identifiers and consensus-number wrappers.
//!
//! This module owns values that must not be mixed merely because their machine
//! representation is the same. It does not perform state transitions or read
//! node configuration. Values enter through validated constructors or serde;
//! malformed chain identifiers fail before reaching consensus logic. Arithmetic
//! helpers are checked so overflow is an explicit error at the caller boundary.

use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize};
use std::{fmt, str::FromStr};
use webc_crypto::{Address, Hash256};

/// Maximum UTF-8 byte length of a chain identifier.
pub const MAX_CHAIN_ID_BYTES: usize = 64;

/// Current protocol configuration version.
pub const CURRENT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1);

/// Errors returned when an untrusted chain identifier is invalid.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChainIdError {
    /// The identifier length is outside the allowed 3..=64 byte range.
    #[error("chain ID must contain between 3 and {MAX_CHAIN_ID_BYTES} ASCII bytes")]
    InvalidLength,
    /// The identifier does not use the canonical lowercase ASCII alphabet.
    #[error("chain ID must start with a lowercase letter and contain only lowercase letters, digits, or hyphens")]
    InvalidCharacter,
}

/// Canonical network identifier embedded in every signed protocol artifact.
///
/// A chain ID contains 3..=64 lowercase ASCII bytes, begins with a letter, and
/// otherwise contains letters, digits, or `-`. It is consensus-critical because
/// signing the same payload for two chain IDs must produce different authority.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ChainId(String);

impl ChainId {
    /// Validates and constructs a chain identifier from hostile input.
    pub fn new(value: impl Into<String>) -> Result<Self, ChainIdError> {
        let value = value.into();
        if !(3..=MAX_CHAIN_ID_BYTES).contains(&value.len()) {
            return Err(ChainIdError::InvalidLength);
        }
        let bytes = value.as_bytes();
        if !bytes[0].is_ascii_lowercase()
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        {
            return Err(ChainIdError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the canonical development-network identifier.
    pub fn devnet() -> Self {
        Self("webc-devnet-1".to_owned())
    }

    /// Borrows the validated identifier text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ChainId {
    type Err = ChainIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for ChainId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

macro_rules! consensus_integer {
    ($(#[$meta:meta])* $name:ident, $inner:ty) => {
        $(#[$meta])*
        #[derive(
            Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name($inner);

        impl $name {
            /// Constructs the typed value from its canonical integer unit.
            pub const fn new(value: $inner) -> Self {
                Self(value)
            }

            /// Returns the canonical integer unit.
            pub const fn get(self) -> $inner {
                self.0
            }

            /// Adds one and returns `None` rather than wrapping at the maximum.
            pub fn checked_next(self) -> Option<Self> {
                self.0.checked_add(1).map(Self)
            }
        }
    };
}

consensus_integer!(
    /// Version number selecting one immutable protocol configuration schema.
    ProtocolVersion,
    u32
);

/// Fixed identity of one independent wallet authorization and fee lane.
///
/// The all-zero value is the default account lane. Other values are explicit
/// 32-byte identifiers normally derived by a wallet from an origin-specific
/// policy; the protocol treats them as opaque and never reads a website URL.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct AuthorizationLaneId(Hash256);

impl AuthorizationLaneId {
    /// Default lane backed directly by the account's liquid balance and nonce.
    pub const DEFAULT: Self = Self(Hash256::ZERO);

    /// Constructs an opaque lane identity from a 32-byte hash.
    pub const fn new(value: Hash256) -> Self {
        Self(value)
    }

    /// Returns the underlying fixed-size lane identifier.
    pub const fn hash(self) -> Hash256 {
        self.0
    }

    /// Returns whether this is the account's default compatibility lane.
    pub fn is_default(self) -> bool {
        self.0 .0 == Hash256::ZERO.0
    }
}
consensus_integer!(
    /// Block height counted from the genesis block at height zero.
    BlockHeight,
    u64
);
consensus_integer!(
    /// Consensus epoch index counted from zero.
    Epoch,
    u64
);
consensus_integer!(
    /// Replay-protection sequence number within one authorization lane.
    Nonce,
    u64
);

/// Raw count of indivisible native or asset units.
///
/// This type does not identify an asset. Callers must pair it with the relevant
/// asset identity before changing balances.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct BaseUnits(u128);

impl BaseUnits {
    /// Constructs an exact base-unit count.
    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    /// Returns the exact base-unit count.
    pub const fn get(self) -> u128 {
        self.0
    }

    /// Adds two counts without wrapping.
    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }

    /// Subtracts two counts without underflowing.
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }
}

/// Stable identity of a validator pool independent of its mutable stake.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ValidatorId(Address);

impl ValidatorId {
    /// Constructs a validator identity from its operator address.
    pub const fn from_operator(operator: Address) -> Self {
        Self(operator)
    }

    /// Returns the validator operator address used by protocol version 1.
    pub const fn operator(self) -> Address {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_id_accepts_only_canonical_ascii() {
        assert!(ChainId::new("webc-devnet-1").is_ok());
        assert_eq!(
            ChainId::new("WEBC-mainnet"),
            Err(ChainIdError::InvalidCharacter)
        );
        assert_eq!(ChainId::new("a"), Err(ChainIdError::InvalidLength));
    }

    #[test]
    fn typed_integer_overflow_is_explicit() {
        assert_eq!(BlockHeight::new(u64::MAX).checked_next(), None);
    }
}
