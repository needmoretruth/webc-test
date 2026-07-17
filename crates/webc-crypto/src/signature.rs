//! Ed25519 key generation, signing, verification, and exact wire byte wrappers.
//!
//! This module owns only current classical signing primitives. It does not
//! derive wallet recovery phrases, persist secrets, or define account policy.
//! Secret keys are never serializable; malformed public input returns typed
//! errors through the reviewed `ed25519-dalek` implementation.

use crate::{Address, CryptoError};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};

/// Raw Ed25519 public key bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKeyBytes(pub [u8; 32]);

impl PublicKeyBytes {
    /// Borrows the exact 32-byte RFC 8032 public key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encodes the public key as lowercase 64-character hex.
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl Serialize for PublicKeyBytes {
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

impl<'de> Deserialize<'de> for PublicKeyBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let value = String::deserialize(deserializer)?;
            let bytes = hex::decode(value).map_err(D::Error::custom)?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| D::Error::custom("expected a 32-byte Ed25519 public key"))?;
            Ok(Self(bytes))
        } else {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| D::Error::custom("expected a 32-byte Ed25519 public key"))?;
            Ok(Self(bytes))
        }
    }
}

/// Raw Ed25519 signature bytes.
///
/// Some supported Rust/serde combinations do not implement serde for arrays
/// larger than 32 elements. Manual serialization keeps the wire format explicit
/// and avoids pulling in an extra dependency only for `[u8; 64]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SignatureBytes(pub [u8; 64]);

impl SignatureBytes {
    /// Borrows the exact 64-byte RFC 8032 signature.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Encodes the signature as lowercase 128-character hex.
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl Serialize for SignatureBytes {
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

impl<'de> Deserialize<'de> for SignatureBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let value = String::deserialize(deserializer)?;
            let bytes = hex::decode(value).map_err(D::Error::custom)?;
            let bytes: [u8; 64] = bytes
                .try_into()
                .map_err(|_| D::Error::custom("expected a 64-byte Ed25519 signature"))?;
            Ok(Self(bytes))
        } else {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            let bytes: [u8; 64] = bytes
                .try_into()
                .map_err(|_| D::Error::custom("expected a 64-byte Ed25519 signature"))?;
            Ok(Self(bytes))
        }
    }
}

/// In-memory Ed25519 keypair.
///
/// This type intentionally does not implement `Serialize`; wallet export should
/// use an encrypted keystore format in the browser SDK rather than accidentally
/// dumping raw signing keys into JSON.
pub struct Keypair {
    signing_key: SigningKey,
}

impl Keypair {
    /// Generates an in-memory Ed25519 key from operating-system randomness.
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Creates a keypair from a 32-byte seed. Useful for deterministic tests and
    /// future encrypted wallet imports.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    /// Returns the verifying half of this in-memory keypair.
    pub fn public_key(&self) -> PublicKeyBytes {
        PublicKeyBytes(self.signing_key.verifying_key().to_bytes())
    }

    /// Derives the current V1 WEBC address from the public key.
    pub fn address(&self) -> Address {
        Address::from_public_key(&self.public_key())
    }

    /// Signs exact message bytes and returns a deterministic 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> SignatureBytes {
        SignatureBytes(self.signing_key.sign(message).to_bytes())
    }
}

/// Verifies an exact Ed25519 signature and rejects malformed keys/signatures.
///
/// Uses `verify_strict` (finding E6), which rejects non-canonical signature `S`
/// components and small-order / torsion public keys. Malleable verification
/// (`verify`) would accept a *different* valid signature encoding of the same
/// message: benign for content binding, but a foot-gun anywhere a caller keyed
/// on the signature bytes — e.g. equivocation detection. Honest signers always
/// produce canonical signatures, so this rejects only maliciously reshaped ones.
pub fn verify_signature(
    public_key: &PublicKeyBytes,
    message: &[u8],
    signature: &SignatureBytes,
) -> Result<(), CryptoError> {
    let verifying_key = VerifyingKey::from_bytes(public_key.as_bytes())
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(signature.as_bytes());
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_verifies_for_original_message() {
        let keypair = Keypair::generate();
        let message: &[u8] = b"webc test message".as_slice();
        let signature = keypair.sign(message);
        verify_signature(&keypair.public_key(), message, &signature).unwrap();
    }

    #[test]
    fn signature_rejects_modified_message() {
        let keypair = Keypair::generate();
        let original: &[u8] = b"one message".as_slice();
        let modified: &[u8] = b"other message".as_slice();
        let signature = keypair.sign(original);
        let err = verify_signature(&keypair.public_key(), modified, &signature).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSignature));
    }

    #[test]
    fn browser_mnemonic_derivation_signature_fixture_verifies() {
        // The browser fixture derives BIP-39's standard "abandon ... about"
        // vector at devnet path m/44'/1'/0'/0'/0'. Rust does not derive wallet
        // secrets, but must verify the exact public output and signature.
        let public_key: [u8; 32] =
            hex::decode("437541f4d29af2d2f1c2aa568ab16842b06b1820fc654494468d45cbdf5e1b56")
                .expect("fixed public key hex")
                .try_into()
                .expect("fixed public key length");
        let signature: [u8; 64] = hex::decode(
            "02ba5df7a18727d096516c0cea9c7637763a8119077d6a4d1c841115731144ed447bf2d683158d5cb8777d10bc7095c4c0cdc525a291c3ffbb4101ea01455c07",
        )
        .expect("fixed signature hex")
        .try_into()
        .expect("fixed signature length");
        let public_key = PublicKeyBytes(public_key);
        let signature = SignatureBytes(signature);

        assert_eq!(
            Address::from_public_key(&public_key).to_string(),
            "webc153HwTorSAA3P8GNpTs1Z19dKPKVt5pmMQa2XbJ8Ff71V"
        );
        verify_signature(&public_key, b"WEBC_WALLET_DERIVATION_V1", &signature)
            .expect("browser-derived signature verifies in Rust");
    }
}
