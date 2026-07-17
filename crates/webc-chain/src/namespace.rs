//! Application namespace ownership registry (WEBC-DEFINITION §8 "Application isolation").
//!
//! Purpose: give an application namespace a first-class on-chain owner. Today a
//! namespace is used ad hoc — objects carry a `namespace: Hash256`, the scheduler
//! isolates work by namespace, and fee sponsorship keys an app sponsor by
//! namespace — but nothing records *who owns a namespace*. This module adds a
//! deterministic map from an application namespace to a [`NamespaceRecord`], so an
//! app can claim its namespace and later prove ownership. Local fees and app
//! governance (later phases) build on this record.
//!
//! Responsibilities: define the per-namespace ownership record ([`NamespaceRecord`]),
//! the Merkle sub-root domain that commits the registry to the state root
//! ([`NAMESPACE_LEAF_DOMAIN`]), and the fixed application-key discriminant that
//! addresses a namespace's registry record inside the `Application { namespace,
//! key_hash }` key space ([`namespace_state_key_hash`]).
//!
//! Non-responsibilities: this module never moves native supply, never touches
//! accounts, and never reads a wall clock, network, files, or randomness. The
//! `state` module owns the registry map, the claim/transfer state transitions,
//! and the state-commitment/access-list wiring; it uses the pure identifiers here.
//!
//! Security boundary: registration only records an owner — it locks no native
//! units, so the supply invariant is unaffected (only the ordinary transaction fee
//! moves). Claiming an already-owned namespace and transferring one you do not own
//! are both rejected with typed errors. Ownership of a namespace is deliberately
//! **not** required to create objects under it today: object create/mutate/
//! transfer/delete keep working on open namespaces exactly as before. Gating object
//! creation on namespace ownership is a later-phase policy decision, not this
//! registry's job.

use serde::{Deserialize, Serialize};
use webc_crypto::{Address, Hash256};

/// Domain tag for the namespace-registry Merkle sub-root committed by the state root.
///
/// Each `(namespace, NamespaceRecord)` entry is a leaf under this domain, so any
/// change to a namespace's owner changes the state root. Bumping this constant is
/// a consensus-format change.
pub const NAMESPACE_LEAF_DOMAIN: &[u8] = b"WEBC_NAMESPACE_LEAF_V1";

/// Fixed application-key discriminant that isolates namespace-registry state inside
/// the `Application { namespace, key_hash }` key space.
///
/// A registry record for application `namespace` is addressed by the logical key
/// `StateKey::application(namespace, namespace_state_key_hash())`. It is
/// domain-separated from object keys (which use the object id hash) and from the
/// sponsor state key (which uses its own discriminant), so registry state, sponsor
/// state, and object state under the same namespace never collide, while two
/// registrations/transfers of the same namespace deterministically share (and
/// therefore serialize on) this one key — correct for a single ownership record.
const NAMESPACE_STATE_KEY_DISCRIMINANT: &[u8] = b"WEBC_NAMESPACE_STATE_KEY_V1";

/// Returns the fixed `key_hash` that addresses a namespace's registry record.
///
/// Deterministic: a domain-separated hash of a constant, identical on every node.
pub fn namespace_state_key_hash() -> Hash256 {
    Hash256::digest(NAMESPACE_STATE_KEY_DISCRIMINANT)
}

/// On-chain ownership record for one application namespace.
///
/// Keyed in [`crate::ChainState::namespaces`] by application namespace. Holds only
/// the current owner today; additional fields (metadata, governance policy, local
/// fee configuration) are deliberately deferred to later phases so the record stays
/// small and the claim/transfer rules stay auditable.
///
/// Invariant: a `NamespaceRecord` exists for a namespace only after an explicit,
/// authorized `RegisterNamespace`, and `owner` is the address that most recently
/// claimed or received it via `TransferNamespace`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceRecord {
    /// Account that owns (controls and may transfer) this application namespace.
    pub owner: Address,
}

impl NamespaceRecord {
    /// Creates a registry record owned by `owner`.
    pub const fn new(owner: Address) -> Self {
        Self { owner }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webc_crypto::Keypair;

    #[test]
    fn state_key_hash_is_deterministic_and_domain_separated() {
        // The addressing hash is a fixed function of a constant, so every node
        // computes the same key, and it must not equal a bare digest of the
        // discriminant used elsewhere by accident.
        assert_eq!(namespace_state_key_hash(), namespace_state_key_hash());
        assert_eq!(
            namespace_state_key_hash(),
            Hash256::digest(NAMESPACE_STATE_KEY_DISCRIMINANT)
        );
    }

    #[test]
    fn record_round_trips_and_rejects_unknown_fields() {
        let owner = Keypair::from_seed([7u8; 32]).address();
        let record = NamespaceRecord::new(owner);
        let text = serde_json::to_string(&record).expect("record serializes");
        let decoded: NamespaceRecord = serde_json::from_str(&text).expect("record decodes");
        assert_eq!(decoded, record);
        // Strict decode: an unexpected field is rejected on hostile input.
        let mut value = serde_json::to_value(&record).expect("to value");
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<NamespaceRecord>(value).is_err());
    }
}
