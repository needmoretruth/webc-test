//! Native WEBC account-address derivation and text/binary encoding.
//!
//! This module owns the fixed 32-byte [`Address`] value, its version-1
//! public-key commitment, and strict human-readable and binary decoding. It
//! does not validate signatures, authorize accounts, or select a key scheme;
//! those responsibilities remain behind the crypto and transaction layers.
//! Trusted public-key bytes flow into a domain-separated SHA-256 commitment,
//! while serialized address bytes are treated as hostile and accepted only at
//! the exact native width. Callers must not treat an address as proof that the
//! corresponding private key exists or is controlled by a requester.

use crate::{CryptoError, PublicKeyBytes};
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};

const ADDRESS_PREFIX: &str = "webc1";

/// Native WEBC account address.
///
/// Addresses are SHA-256 commitments to Ed25519 public keys with a domain
/// separator. This keeps addresses fixed-size and prevents accidental reuse of
/// raw public-key bytes in unrelated contexts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(pub [u8; 32]);

impl Address {
    /// Derives the version-1 address commitment for an Ed25519 public key.
    ///
    /// This operation is deterministic and domain-separated with
    /// `WEBC_ADDRESS_V1`. It performs no signature or ownership check.
    pub fn from_public_key(public_key: &PublicKeyBytes) -> Self {
        let parts: [&[u8]; 2] = [
            b"WEBC_ADDRESS_V1".as_slice(),
            public_key.as_bytes().as_slice(),
        ];
        Self(crate::Hash256::digest_many(parts).0)
    }

    /// Constructs an address from an already validated 32-byte commitment.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the exact 32-byte address commitment.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encodes the address as the `webc1` prefix followed by Base58 bytes.
    pub fn to_base58(self) -> String {
        format!("{}{}", ADDRESS_PREFIX, bs58::encode(self.0).into_string())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl FromStr for Address {
    type Err = CryptoError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let encoded = value
            .strip_prefix(ADDRESS_PREFIX)
            .ok_or(CryptoError::InvalidAddress)?;
        let decoded = bs58::decode(encoded)
            .into_vec()
            .map_err(|_| CryptoError::InvalidAddress)?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| CryptoError::InvalidAddress)?;
        Ok(Self(bytes))
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_base58())
        } else {
            serializer.serialize_bytes(self.0.as_slice())
        }
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let value = String::deserialize(deserializer)?;
            value
                .parse()
                .map_err(|_| D::Error::custom("invalid WEBC address"))
        } else {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| D::Error::custom("expected a 32-byte WEBC address"))?;
            Ok(Self(bytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keypair;

    #[test]
    fn address_round_trips_through_display() {
        let keypair = Keypair::generate();
        let address = keypair.address();
        let parsed: Address = address.to_string().parse().unwrap();
        assert_eq!(address, parsed);
    }
}
