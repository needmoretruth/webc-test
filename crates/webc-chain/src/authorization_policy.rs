//! Versioned account authorization policy and post-quantum root commitments.
//!
//! This module owns policy data and local invariant validation. It does not
//! verify transaction signatures, mutate chain state, or implement ML-DSA.
//! Consensus stores only a domain-separated hash of the post-quantum public
//! key until the selected implementation is benchmarked and reviewed. The
//! separate policy revision invalidates signatures prepared under older keys.

use crate::ChainError;
use serde::{Deserialize, Serialize};
use webc_crypto::{Hash256, PublicKeyBytes};

/// Revision used by address-derived Ed25519 accounts before policy installation.
pub const LEGACY_AUTHORIZATION_POLICY_REVISION: AuthorizationPolicyRevision =
    AuthorizationPolicyRevision::new(0);

/// First revision assigned to an installed version-1 policy.
pub const INITIAL_AUTHORIZATION_POLICY_REVISION: AuthorizationPolicyRevision =
    AuthorizationPolicyRevision::new(1);

/// Largest revision represented exactly by canonical browser JSON numbers.
pub const MAX_AUTHORIZATION_POLICY_REVISION: u64 = 9_007_199_254_740_991;

/// Monotonic account-policy revision signed by every transaction.
///
/// Revision zero is reserved for the explicit legacy migration path. Installed
/// policies start at one and advance on rotation or recovery, preventing a
/// previously signed transaction from becoming valid under a new key set.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct AuthorizationPolicyRevision(u64);

impl AuthorizationPolicyRevision {
    /// Creates a revision from its consensus integer representation.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the unsigned consensus integer carried on the wire.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advances the revision or returns `None` at `u64::MAX`.
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) if value <= MAX_AUTHORIZATION_POLICY_REVISION => Some(Self(value)),
            _ => None,
        }
    }

    /// Rejects revisions a TypeScript wallet cannot encode exactly.
    pub fn validate(self) -> Result<(), ChainError> {
        if self.0 > MAX_AUTHORIZATION_POLICY_REVISION {
            return Err(ChainError::InvalidAuthorizationPolicyRevision);
        }
        Ok(())
    }
}

/// Domain tag separating post-quantum root commitments from other hashes.
const POST_QUANTUM_ROOT_DOMAIN: &[u8] = b"WEBC_POST_QUANTUM_ROOT_V1";

/// Upper bound on a revealed post-quantum public key, in bytes.
///
/// ML-DSA-65 public keys are 1,952 bytes; the ceiling bounds hostile reveals
/// before hashing so a malformed operation cannot force large allocations.
pub const MAX_POST_QUANTUM_PUBLIC_KEY_BYTES: usize = 4_096;

/// Standards identifier for a post-quantum account root.
///
/// ML-DSA-65 is a candidate selected for Phase 2 interoperability and
/// performance experiments. Naming it here does not enable verification or
/// constitute a security claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PostQuantumScheme {
    /// NIST FIPS 204 ML-DSA parameter set 65.
    MlDsa65,
}

impl PostQuantumScheme {
    /// Stable domain-separation bytes identifying this scheme in a commitment.
    pub const fn wire_tag(self) -> &'static [u8] {
        match self {
            Self::MlDsa65 => b"ML-DSA-65",
        }
    }
}

/// Commitment to the public half of a post-quantum recovery root.
///
/// The hash is SHA-256 over a domain tag, the scheme name, and the exact public
/// key bytes. Recovery must later reveal bytes that reproduce this commitment
/// and pass the scheme verifier. Raw keys are not accepted by this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostQuantumRoot {
    /// Algorithm and parameter set used to interpret a future key reveal.
    pub scheme: PostQuantumScheme,
    /// Non-zero commitment to the exact encoded public key.
    pub public_key_hash: Hash256,
}

impl PostQuantumRoot {
    /// Creates a candidate root and rejects the reserved empty commitment.
    pub fn new(scheme: PostQuantumScheme, public_key_hash: Hash256) -> Result<Self, ChainError> {
        let root = Self {
            scheme,
            public_key_hash,
        };
        root.validate()?;
        Ok(root)
    }

    /// Domain-separated commitment to an exact post-quantum public key.
    ///
    /// The hash is `SHA-256(domain || scheme_tag || public_key)`. Both the
    /// creator of a root and a later reveal must use this exact function so a
    /// reveal can be checked against the stored commitment.
    pub fn commit(scheme: PostQuantumScheme, public_key: &[u8]) -> Hash256 {
        let parts: [&[u8]; 3] = [POST_QUANTUM_ROOT_DOMAIN, scheme.wire_tag(), public_key];
        Hash256::digest_many(parts)
    }

    /// Builds a root by committing to an exact public key.
    pub fn from_public_key(
        scheme: PostQuantumScheme,
        public_key: &[u8],
    ) -> Result<Self, ChainError> {
        Self::new(scheme, Self::commit(scheme, public_key))
    }

    /// Validates consensus invariants without allocating or performing crypto.
    pub fn validate(self) -> Result<(), ChainError> {
        if self.public_key_hash == Hash256::ZERO {
            return Err(ChainError::InvalidPostQuantumRoot);
        }
        Ok(())
    }
}

/// A reveal of the post-quantum root public key committed by an account policy.
///
/// Critical account actions (installing or revoking a session key, and later
/// recovery/rotation) require proving knowledge of the committed root.
///
/// Limitation recorded per `AGENTS.md`: this reveal proves the caller knows the
/// exact committed public key, not that the root *signed* the request. Real
/// ML-DSA signature verification is a later gate; until then this path is
/// devnet-only and disabled for real funds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostQuantumRootReveal {
    /// Scheme the revealed key is interpreted under; must match the root.
    pub scheme: PostQuantumScheme,
    /// Exact encoded post-quantum public key bytes, hex on the wire.
    #[serde(with = "crate::hex_bytes")]
    pub public_key: Vec<u8>,
}

impl PostQuantumRootReveal {
    /// Validates the reveal size before any hashing work.
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.public_key.is_empty() || self.public_key.len() > MAX_POST_QUANTUM_PUBLIC_KEY_BYTES {
            return Err(ChainError::InvalidPostQuantumRootReveal);
        }
        Ok(())
    }

    /// Returns whether this reveal reproduces the committed root exactly.
    ///
    /// Fails closed on an oversized/empty reveal, a scheme mismatch, or a
    /// commitment mismatch.
    pub fn matches(&self, root: &PostQuantumRoot) -> Result<bool, ChainError> {
        self.validate()?;
        if self.scheme != root.scheme {
            return Ok(false);
        }
        Ok(PostQuantumRoot::commit(self.scheme, &self.public_key) == root.public_key_hash)
    }
}

/// Installed account authorization policy schema.
///
/// The enum is intentionally externally tagged in canonical JSON so future
/// incompatible policies can coexist without ambiguous optional fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountAuthorizationPolicy {
    /// First policy schema: one active Ed25519 transaction key plus a committed
    /// ML-DSA recovery root. Session keys are added as explicit constrained
    /// records rather than silently overloading this active key.
    V1(AccountAuthorizationPolicyV1),
}

impl AccountAuthorizationPolicy {
    /// Installs the first policy revision for an address-derived legacy account.
    pub fn new_v1(
        active_transaction_key: PublicKeyBytes,
        post_quantum_root: PostQuantumRoot,
    ) -> Result<Self, ChainError> {
        post_quantum_root.validate()?;
        Ok(Self::V1(AccountAuthorizationPolicyV1 {
            revision: INITIAL_AUTHORIZATION_POLICY_REVISION,
            active_transaction_key,
            post_quantum_root,
        }))
    }

    /// Returns the revision every transaction authorized by this policy signs.
    pub const fn revision(&self) -> AuthorizationPolicyRevision {
        match self {
            Self::V1(policy) => policy.revision,
        }
    }

    /// Returns the only ordinary transaction key active in this policy version.
    pub const fn active_transaction_key(&self) -> &PublicKeyBytes {
        match self {
            Self::V1(policy) => &policy.active_transaction_key,
        }
    }

    /// Returns the committed post-quantum recovery root for critical actions.
    pub const fn post_quantum_root(&self) -> &PostQuantumRoot {
        match self {
            Self::V1(policy) => &policy.post_quantum_root,
        }
    }

    /// Validates stored invariants after hostile decoding or state loading.
    pub fn validate(&self) -> Result<(), ChainError> {
        match self {
            Self::V1(policy) => policy.validate(),
        }
    }
}

/// Fields interpreted by version-1 account authorization.
///
/// Invariants:
/// - `revision` is never zero;
/// - the post-quantum root commitment is non-zero;
/// - exactly one ordinary Ed25519 transaction key is active.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountAuthorizationPolicyV1 {
    /// Monotonic policy revision, starting at one.
    pub revision: AuthorizationPolicyRevision,
    /// Current Ed25519 key allowed to authorize ordinary transactions.
    pub active_transaction_key: PublicKeyBytes,
    /// Post-quantum recovery-root commitment required for critical changes.
    pub post_quantum_root: PostQuantumRoot,
}

impl AccountAuthorizationPolicyV1 {
    /// Validates state loaded from an untrusted database or wire snapshot.
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.revision == LEGACY_AUTHORIZATION_POLICY_REVISION {
            return Err(ChainError::InvalidAuthorizationPolicy);
        }
        self.revision.validate()?;
        self.post_quantum_root.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_rejects_empty_post_quantum_commitment() {
        let error = PostQuantumRoot::new(PostQuantumScheme::MlDsa65, Hash256::ZERO)
            .expect_err("empty commitment must fail closed");
        assert!(matches!(error, ChainError::InvalidPostQuantumRoot));
    }

    #[test]
    fn installed_policy_starts_at_revision_one() {
        let key = PublicKeyBytes([7; 32]);
        let root = PostQuantumRoot::new(
            PostQuantumScheme::MlDsa65,
            Hash256::digest(b"candidate ML-DSA public key"),
        )
        .unwrap();
        let policy = AccountAuthorizationPolicy::new_v1(key, root).unwrap();
        assert_eq!(policy.revision(), INITIAL_AUTHORIZATION_POLICY_REVISION);
        assert_eq!(policy.active_transaction_key(), &key);
        policy.validate().unwrap();
    }

    #[test]
    fn revision_stops_at_browser_exact_integer_limit() {
        let maximum = AuthorizationPolicyRevision::new(MAX_AUTHORIZATION_POLICY_REVISION);
        maximum.validate().unwrap();
        assert_eq!(maximum.checked_next(), None);
        assert!(
            AuthorizationPolicyRevision::new(MAX_AUTHORIZATION_POLICY_REVISION + 1)
                .validate()
                .is_err()
        );
    }
}
