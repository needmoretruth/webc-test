//! Constrained, short-lived session keys delegated under an account policy.
//!
//! Purpose: represent a limited signing key a wallet grants to one website so it
//! can authorize a narrow set of transactions without exposing the account's
//! active key or its post-quantum recovery root.
//! Responsibilities: the session-key identity, its immutable constraint set,
//! constraint validation, and deterministic expiry math.
//! Non-responsibilities: this module never verifies signatures, mutates
//! balances, reads chain state, decides transaction authorization, or reads a
//! wall clock. `state` owns those and consumes these records atomically.
//! Data flow: a wallet signs an `InstallSessionKey` operation carrying a
//! `SessionKeyConstraints` grant; execution validates it, resolves the relative
//! lifetime to an absolute expiry epoch, and stores a `SessionKey` record.
//! Security boundary: a session key is an authorization credential only. It
//! holds no funds, cannot perform critical/account-structural actions, is bound
//! to one lane, is capped per use and cumulatively, and expires by epoch. Every
//! bound is validated before use and enforced with checked arithmetic.
//!
//! This path is a devnet prototype and is disabled for real funds. The
//! post-quantum-root gate on install/revoke is a real ML-DSA-65 signature over
//! the canonical [`session_key_authorization_message`] (verified through the
//! replaceable `webc-crypto::mldsa` boundary), not a commitment-knowledge check.
//! ML-DSA-65 remains a named devnet candidate pending benchmarks and audit (see
//! `docs/session-keys-implementation-plan.md` sections 5.5 and 14).

use crate::{Amount, AuthorizationLaneId, AuthorizationPolicyRevision, ChainError, ChainId, Epoch};
use serde::{Deserialize, Serialize};
use webc_crypto::{Address, Hash256, PublicKeyBytes};

/// Domain tag hashed with a session public key to derive its opaque identity.
///
/// Domain separation keeps a session-key id from colliding with an address or
/// any other 32-byte WEBC artifact derived from the same public key.
const SESSION_KEY_ID_DOMAIN: &[u8] = b"WEBC_SESSION_KEY_ID_V1";

/// Domain tag for the message a post-quantum root signs to authorize a critical
/// session-key action.
///
/// The tag lives inside the signed message (not in the ML-DSA context) so both
/// Rust and a future browser signer reproduce identical bytes through the shared
/// canonical-JSON encoder. Changing it invalidates every previously prepared
/// root signature, so treat it as a signing-format breaking change.
pub const SESSION_KEY_AUTHORIZATION_DOMAIN: &str = "WEBC_SESSION_KEY_AUTHORIZATION_V1";

/// Versioned-chain session-key limits, in consensus epochs and record counts.
///
/// The exact numbers are conservative devnet placeholders. Final values are a
/// benchmark and security gate (`docs/decision-record.md` line 119), not a
/// product-owner preference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKeyConfig {
    /// Hard upper bound on a session key's lifetime, in consensus epochs.
    pub max_lifetime_epochs: u64,
    /// Maximum simultaneously installed session keys per account.
    pub max_session_keys_per_account: u32,
}

impl Default for SessionKeyConfig {
    fn default() -> Self {
        // The prototype treats one epoch as roughly one devnet minute, so
        // 1,440 epochs is about one day. A session key is meant to be
        // short-lived; this ceiling is intentionally modest and non-final.
        Self {
            max_lifetime_epochs: 1_440,
            max_session_keys_per_account: 8,
        }
    }
}

/// Opaque, non-secret identity of one session key under an account.
///
/// Derived as `SHA-256("WEBC_SESSION_KEY_ID_V1" || session_public_key)`. Keying
/// state by this fixed-size id keeps state keys bounded and lets verification
/// find a key in one map probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionKeyId(Hash256);

impl SessionKeyId {
    /// Constructs an id from a raw 32-byte hash (wire/decoding path).
    pub const fn new(value: Hash256) -> Self {
        Self(value)
    }

    /// Returns the underlying fixed-size identifier.
    pub const fn hash(self) -> Hash256 {
        self.0
    }

    /// Derives the deterministic id committing to a session public key.
    pub fn derive(session_public_key: &PublicKeyBytes) -> Self {
        let parts: [&[u8]; 2] = [
            SESSION_KEY_ID_DOMAIN,
            session_public_key.as_bytes().as_slice(),
        ];
        Self(Hash256::digest_many(parts))
    }
}

/// Operation kinds a session key may authorize.
///
/// v1 exposes only native transfers, matching the off-chain wallet service. The
/// set can never contain a critical or account-structural operation; those are
/// excluded by the execution allow-list check, not by configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAllowedOperations {
    /// Whether native `Transfer` is permitted. The only v1 capability.
    pub transfer: bool,
}

impl SessionAllowedOperations {
    /// Returns the v1 default granting native transfers only.
    pub const fn transfers_only() -> Self {
        Self { transfer: true }
    }

    /// Returns whether no operation kind is permitted (a useless, rejected key).
    pub const fn is_empty(self) -> bool {
        !self.transfer
    }
}

/// Immutable constraint grant signed when a session key is installed.
///
/// Invariants (checked by [`SessionKeyConstraints::validate`]):
/// - at least one operation kind is allowed;
/// - `max_amount_per_use` and `max_fee_per_use` are non-zero;
/// - `total_amount_budget >= max_amount_per_use`;
/// - `total_fee_budget >= max_fee_per_use`;
/// - `lifetime_epochs` is non-zero.
///
/// `lifetime_epochs` is relative to the install epoch; execution resolves it to
/// an absolute `expires_after_epoch` so the deadline never depends on a wall
/// clock. Amounts are exact native base units. Both the principal and the fee
/// have a per-use ceiling and a cumulative budget, so a compromised key's total
/// blast radius is bounded by `total_amount_budget + total_fee_budget` however
/// many times it is used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionKeyConstraints {
    /// Lane this key must use; binds the key to one origin (or the default lane).
    pub authorization_lane: AuthorizationLaneId,
    /// Operation kinds this key may authorize.
    pub allowed_operations: SessionAllowedOperations,
    /// Maximum native principal moved by one session-signed transaction.
    pub max_amount_per_use: Amount,
    /// Maximum cumulative native principal over the key's whole life.
    pub total_amount_budget: Amount,
    /// Maximum fee this key authorizes on one transaction, in base units.
    pub max_fee_per_use: Amount,
    /// Maximum cumulative fee this key may spend over its whole life.
    ///
    /// Without this, a compromised key could drain an account through fees on
    /// unlimited tiny transfers, since the principal budget alone does not bound
    /// fees. This ceiling closes that path.
    pub total_fee_budget: Amount,
    /// Requested lifetime in consensus epochs from the install epoch.
    pub lifetime_epochs: u64,
}

impl SessionKeyConstraints {
    /// Validates the grant independent of chain state.
    ///
    /// This does not compare against the current epoch or the configured
    /// lifetime cap; execution performs those chain-dependent checks.
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.allowed_operations.is_empty() {
            return Err(ChainError::InvalidSessionKeyConstraints);
        }
        if self.max_amount_per_use.is_zero() || self.max_fee_per_use.is_zero() {
            return Err(ChainError::InvalidSessionKeyConstraints);
        }
        if self.total_amount_budget < self.max_amount_per_use {
            return Err(ChainError::InvalidSessionKeyConstraints);
        }
        if self.total_fee_budget < self.max_fee_per_use {
            return Err(ChainError::InvalidSessionKeyConstraints);
        }
        if self.lifetime_epochs == 0 {
            return Err(ChainError::InvalidSessionKeyConstraints);
        }
        Ok(())
    }
}

/// One installed, constrained session key. Holds no funds.
///
/// Invariants:
/// - `constraints` validate;
/// - `id == SessionKeyId::derive(&session_public_key)`;
/// - `spent_amount <= constraints.total_amount_budget`;
/// - `spent_fees <= constraints.total_fee_budget`;
/// - `policy_revision` equals the owner policy revision at install; a rotation
///   changes the policy revision and thereby invalidates this key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionKey {
    /// Stable account that installed and owns this key.
    pub owner: Address,
    /// Opaque identity used as the state-map and state-key selector.
    pub id: SessionKeyId,
    /// Ed25519 key that signs transactions under this session.
    pub session_public_key: PublicKeyBytes,
    /// Owner policy revision this key was installed under.
    pub policy_revision: AuthorizationPolicyRevision,
    /// Fixed constraints checked on every use.
    pub constraints: SessionKeyConstraints,
    /// Absolute last epoch (inclusive) in which the key may be used.
    pub expires_after_epoch: Epoch,
    /// Cumulative native principal already spent. Mutable; only grows.
    pub spent_amount: Amount,
    /// Cumulative native fees already spent. Mutable; only grows.
    pub spent_fees: Amount,
}

impl SessionKey {
    /// Creates a validated session-key record at zero cumulative spend.
    pub fn new(
        owner: Address,
        session_public_key: PublicKeyBytes,
        policy_revision: AuthorizationPolicyRevision,
        constraints: SessionKeyConstraints,
        expires_after_epoch: Epoch,
    ) -> Result<Self, ChainError> {
        constraints.validate()?;
        Ok(Self {
            owner,
            id: SessionKeyId::derive(&session_public_key),
            session_public_key,
            policy_revision,
            constraints,
            expires_after_epoch,
            spent_amount: Amount::ZERO,
            spent_fees: Amount::ZERO,
        })
    }

    /// Re-validates invariants after hostile decoding or state loading.
    pub fn validate(&self) -> Result<(), ChainError> {
        self.constraints.validate()?;
        if SessionKeyId::derive(&self.session_public_key) != self.id {
            return Err(ChainError::InvalidSessionKeyConstraints);
        }
        if self.spent_amount > self.constraints.total_amount_budget
            || self.spent_fees > self.constraints.total_fee_budget
        {
            return Err(ChainError::InvalidSessionKeyConstraints);
        }
        Ok(())
    }
}

/// The exact critical action a post-quantum root signature authorizes.
///
/// The action is part of the signed message, so a root signature captured for
/// one action cannot be replayed against another: installing a specific key
/// under specific constraints and revoking a specific key produce different
/// messages, and neither can be forged without the root secret key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum SessionKeyAuthorizationAction {
    /// Install a session key with an exact public key and constraint grant.
    Install {
        /// The Ed25519 key the session will sign transactions with.
        session_public_key: PublicKeyBytes,
        /// The exact immutable constraints the owner is granting. This MUST be
        /// serialized into the signed message so the root signature binds the
        /// exact grant; never `#[serde(skip)]` it.
        constraints: SessionKeyConstraints,
    },
    /// Revoke a previously installed session key by its opaque id.
    Revoke {
        /// The id of the session key being revoked.
        session_key: SessionKeyId,
    },
}

/// Builds the canonical bytes a post-quantum root signs to authorize a critical
/// session-key action.
///
/// The message binds `chain_id + owner + policy_revision + nonce + action` under
/// a domain tag, using the shared canonical-JSON encoder so a future browser
/// signer reproduces identical bytes. Replay is prevented on two axes:
/// - the `action` binds the signature to one exact install/revoke, so a captured
///   signature cannot be moved to a different action; and
/// - critical actions must use the default lane, where `nonce` is the account
///   nonce and is single-use, so the same signature cannot be replayed at a
///   later nonce (the second transaction fails the nonce check).
///
/// `policy_revision` binds the signature to the current policy, so a signature
/// prepared before a key rotation cannot be reused afterward.
pub fn session_key_authorization_message(
    chain_id: &ChainId,
    owner: Address,
    policy_revision: AuthorizationPolicyRevision,
    nonce: u64,
    action: &SessionKeyAuthorizationAction,
) -> Result<Vec<u8>, ChainError> {
    #[derive(Serialize)]
    struct AuthorizationMessage<'a> {
        domain: &'a str,
        chain_id: &'a ChainId,
        owner: Address,
        policy_revision: AuthorizationPolicyRevision,
        nonce: u64,
        action: &'a SessionKeyAuthorizationAction,
    }
    crate::canonical::canonical_json_bytes(&AuthorizationMessage {
        domain: SESSION_KEY_AUTHORIZATION_DOMAIN,
        chain_id,
        owner,
        policy_revision,
        nonce,
        action,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn constraints() -> SessionKeyConstraints {
        SessionKeyConstraints {
            authorization_lane: AuthorizationLaneId::DEFAULT,
            allowed_operations: SessionAllowedOperations::transfers_only(),
            max_amount_per_use: Amount::from_units(10),
            total_amount_budget: Amount::from_units(100),
            max_fee_per_use: Amount::from_units(5),
            total_fee_budget: Amount::from_units(50),
            lifetime_epochs: 60,
        }
    }

    #[test]
    fn valid_constraints_pass() {
        constraints().validate().unwrap();
    }

    #[test]
    fn empty_allow_list_is_rejected() {
        let mut invalid = constraints();
        invalid.allowed_operations = SessionAllowedOperations { transfer: false };
        assert!(matches!(
            invalid.validate(),
            Err(ChainError::InvalidSessionKeyConstraints)
        ));
    }

    #[test]
    fn zero_caps_and_zero_lifetime_are_rejected() {
        let mut zero_amount = constraints();
        zero_amount.max_amount_per_use = Amount::ZERO;
        assert!(zero_amount.validate().is_err());

        let mut zero_fee = constraints();
        zero_fee.max_fee_per_use = Amount::ZERO;
        assert!(zero_fee.validate().is_err());

        let mut zero_life = constraints();
        zero_life.lifetime_epochs = 0;
        assert!(zero_life.validate().is_err());
    }

    #[test]
    fn budget_below_per_use_is_rejected() {
        let mut invalid = constraints();
        invalid.total_amount_budget = Amount::from_units(1);
        assert!(matches!(
            invalid.validate(),
            Err(ChainError::InvalidSessionKeyConstraints)
        ));

        let mut invalid_fee = constraints();
        invalid_fee.total_fee_budget = Amount::from_units(1);
        assert!(matches!(
            invalid_fee.validate(),
            Err(ChainError::InvalidSessionKeyConstraints)
        ));
    }

    #[test]
    fn id_derivation_is_deterministic_and_domain_separated() {
        let key = PublicKeyBytes([7u8; 32]);
        let id = SessionKeyId::derive(&key);
        assert_eq!(id, SessionKeyId::derive(&key));
        // The id must not equal the raw address commitment of the same key.
        assert_ne!(id.hash().0, Address::from_public_key(&key).0);
    }

    #[test]
    fn id_derivation_has_a_stable_cross_language_vector() {
        // Fixed vector: the browser SDK's `deriveSessionKeyIdHex` must reproduce
        // this exact id for the all-0x11 public key. If it changes, the SDK vector
        // in `sdk/webc-js/src/transaction.test.ts` MUST be updated to match.
        let id = SessionKeyId::derive(&PublicKeyBytes([0x11; 32]));
        assert_eq!(
            id.hash().to_hex(),
            "0ccf7ce5d50b1e08cb4b7d2f7c5b7af9eb094dce0c9d1668a2e270de7fb40c74"
        );
    }

    #[test]
    fn record_validate_detects_tampered_identity_and_overspend() {
        let record = SessionKey::new(
            Address::from_public_key(&PublicKeyBytes([1u8; 32])),
            PublicKeyBytes([2u8; 32]),
            AuthorizationPolicyRevision::new(1),
            constraints(),
            Epoch::new(60),
        )
        .unwrap();
        record.validate().unwrap();

        let mut tampered_id = record.clone();
        tampered_id.id = SessionKeyId::new(Hash256([0u8; 32]));
        assert!(tampered_id.validate().is_err());

        let mut overspent = record;
        overspent.spent_amount = Amount::from_units(101);
        assert!(overspent.validate().is_err());
    }
}
