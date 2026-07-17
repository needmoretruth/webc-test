//! ML-DSA-65 (FIPS 204) signing boundary for the post-quantum recovery root.
//!
//! Purpose: verify — and, for wallets and tests, produce — ML-DSA-65 signatures
//! over exact message bytes. Consensus uses only [`ml_dsa65_verify`], which is
//! deterministic and consumes no randomness, so the state transition stays
//! reproducible on every node.
//!
//! Boundary: this module wraps the pinned `fips204` crate and nothing else. It
//! is intentionally the single replaceable seam for the post-quantum scheme; no
//! other code names `fips204` types. Naming ML-DSA-65 here is a devnet
//! experiment for interoperability and performance work, not a post-quantum
//! security claim.
//!
//! Security rules:
//! - Secret keys never derive `Debug`, `Serialize`, or `Clone`, so they cannot
//!   be logged or dumped to JSON by accident.
//! - Verification is total over hostile input: wrong-length or unparseable keys
//!   and signatures return a typed error or `Ok(false)`, never a panic.
//! - `ml_dsa65_verify` is deterministic; only key generation and signing draw
//!   randomness, and those never run inside consensus.

use crate::CryptoError;
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};

/// Exact ML-DSA-65 public key length in bytes (FIPS 204).
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = ml_dsa_65::PK_LEN;

/// Exact ML-DSA-65 signature length in bytes (FIPS 204).
pub const ML_DSA_65_SIGNATURE_LEN: usize = ml_dsa_65::SIG_LEN;

/// Verifies an ML-DSA-65 signature over exact message bytes under a context.
///
/// Returns `Ok(true)` only when `public_key` and `signature` are the exact
/// FIPS 204 lengths, the key parses, and the signature verifies. A structurally
/// invalid key or a non-verifying signature returns `Ok(false)`; a wrong-length
/// key or signature returns a typed error. This function is deterministic and
/// draws no randomness, so it is safe to call inside a consensus state
/// transition. `context` must be at most 255 bytes (FIPS 204); a longer context
/// simply fails to verify.
pub fn ml_dsa65_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    context: &[u8],
) -> Result<bool, CryptoError> {
    let public_key: [u8; ML_DSA_65_PUBLIC_KEY_LEN] = public_key
        .try_into()
        .map_err(|_| CryptoError::InvalidMlDsaPublicKey)?;
    let signature: [u8; ML_DSA_65_SIGNATURE_LEN] = signature
        .try_into()
        .map_err(|_| CryptoError::InvalidMlDsaSignature)?;
    // A key that fails to decode is not a verification success; fail closed
    // rather than surfacing an internal error the caller would treat the same.
    let verifying_key = match ml_dsa_65::PublicKey::try_from_bytes(public_key) {
        Ok(key) => key,
        Err(_) => return Ok(false),
    };
    Ok(verifying_key.verify(message, &signature, context))
}

/// An ML-DSA-65 public key held as its exact FIPS 204 byte encoding.
///
/// This is a thin owned wrapper so callers never juggle raw fixed-size arrays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsa65PublicKey {
    bytes: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
}

impl MlDsa65PublicKey {
    /// Borrows the exact public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns an owned copy of the exact public key bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

/// An ML-DSA-65 secret key usable only to sign.
///
/// It intentionally implements neither `Debug`, `Serialize`, nor `Clone`: a
/// signing secret must not be logged, serialized, or silently duplicated. It is
/// used by wallets and tests, never inside consensus.
pub struct MlDsa65SecretKey {
    inner: ml_dsa_65::PrivateKey,
}

impl MlDsa65SecretKey {
    /// Signs exact message bytes under a context (at most 255 bytes).
    ///
    /// Signing is hedged: it draws operating-system randomness, so it must not
    /// run inside a deterministic state transition. The output is a fixed-length
    /// ML-DSA-65 signature.
    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner
            .try_sign(message, context)
            .map(|signature| signature.to_vec())
            .map_err(|_| CryptoError::MlDsaSigningFailed)
    }
}

/// Generates a fresh ML-DSA-65 keypair from operating-system randomness.
///
/// For wallet key setup and tests only. The verifier never generates keys.
pub fn ml_dsa65_keygen() -> Result<(MlDsa65PublicKey, MlDsa65SecretKey), CryptoError> {
    let (public_key, private_key) =
        ml_dsa_65::try_keygen().map_err(|_| CryptoError::MlDsaSigningFailed)?;
    Ok((
        MlDsa65PublicKey {
            bytes: public_key.into_bytes(),
        },
        MlDsa65SecretKey { inner: private_key },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_sizes_match_fips204_constants() {
        let (public_key, _secret) = ml_dsa65_keygen().unwrap();
        assert_eq!(public_key.as_bytes().len(), ML_DSA_65_PUBLIC_KEY_LEN);
    }

    #[test]
    fn signature_round_trips_for_original_message() {
        let (public_key, secret) = ml_dsa65_keygen().unwrap();
        let message = b"WEBC ml-dsa round trip".as_slice();
        let signature = secret.sign(message, b"").unwrap();
        assert_eq!(signature.len(), ML_DSA_65_SIGNATURE_LEN);
        assert!(ml_dsa65_verify(public_key.as_bytes(), message, &signature, b"").unwrap());
    }

    #[test]
    fn verification_rejects_tampered_message() {
        let (public_key, secret) = ml_dsa65_keygen().unwrap();
        let signature = secret.sign(b"one message", b"").unwrap();
        assert!(
            !ml_dsa65_verify(public_key.as_bytes(), b"other message", &signature, b"").unwrap()
        );
    }

    #[test]
    fn verification_rejects_wrong_context() {
        let (public_key, secret) = ml_dsa65_keygen().unwrap();
        let message = b"context-bound message".as_slice();
        let signature = secret.sign(message, b"context-a").unwrap();
        assert!(
            !ml_dsa65_verify(public_key.as_bytes(), message, &signature, b"context-b").unwrap()
        );
    }

    #[test]
    fn verification_rejects_wrong_key() {
        let (_public_key, secret) = ml_dsa65_keygen().unwrap();
        let (other_public, _other_secret) = ml_dsa65_keygen().unwrap();
        let message = b"bound to signer".as_slice();
        let signature = secret.sign(message, b"").unwrap();
        assert!(!ml_dsa65_verify(other_public.as_bytes(), message, &signature, b"").unwrap());
    }

    #[test]
    fn verification_reports_length_errors() {
        let (public_key, secret) = ml_dsa65_keygen().unwrap();
        let signature = secret.sign(b"m", b"").unwrap();
        assert!(matches!(
            ml_dsa65_verify(&[0u8; 10], b"m", &signature, b""),
            Err(CryptoError::InvalidMlDsaPublicKey)
        ));
        assert!(matches!(
            ml_dsa65_verify(public_key.as_bytes(), b"m", &[0u8; 10], b""),
            Err(CryptoError::InvalidMlDsaSignature)
        ));
    }

    #[test]
    fn verification_fails_closed_on_unparseable_key() {
        let (_public_key, secret) = ml_dsa65_keygen().unwrap();
        let signature = secret.sign(b"m", b"").unwrap();
        // A correctly sized but structurally invalid key must not panic and must
        // not verify.
        let bogus = vec![0xFFu8; ML_DSA_65_PUBLIC_KEY_LEN];
        assert!(!ml_dsa65_verify(&bogus, b"m", &signature, b"").unwrap());
    }
}
