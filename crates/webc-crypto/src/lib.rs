//! Cryptographic primitives for WEBC.
//!
//! The protocol starts with Ed25519 because it is fast, compact, and practical in
//! browsers/WASM. Ethereum bridge support can add secp256k1 verification later
//! without changing native WEBC account addresses.

mod address;
mod hash;
mod merkle;
mod mldsa;
mod signature;

pub use address::Address;
pub use hash::Hash256;
pub use merkle::{
    merkle_parent, merkle_proof, merkle_root, verify_merkle_proof, MerkleDirection, MerkleProof,
    MerkleProofStep,
};
pub use mldsa::{
    ml_dsa65_keygen, ml_dsa65_verify, MlDsa65PublicKey, MlDsa65SecretKey, ML_DSA_65_PUBLIC_KEY_LEN,
    ML_DSA_65_SIGNATURE_LEN,
};
pub use signature::{verify_signature, Keypair, PublicKeyBytes, SignatureBytes};

/// Errors returned by the crypto crate.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid WEBC address")]
    InvalidAddress,
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    #[error("invalid Ed25519 signature")]
    InvalidSignature,
    #[error("invalid ML-DSA-65 public key length or encoding")]
    InvalidMlDsaPublicKey,
    #[error("invalid ML-DSA-65 signature length")]
    InvalidMlDsaSignature,
    #[error("ML-DSA-65 signing failed")]
    MlDsaSigningFailed,
}
