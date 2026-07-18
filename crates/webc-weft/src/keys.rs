//! Deterministic state-key derivation — the single source of truth shared by
//! codegen (which bakes the key bytes into the guest's data segment) and the
//! interface manifest (which lists them as the on-chain footprint).
//!
//! Because both consumers call [`state_key`], the 32 bytes the guest passes to
//! `webc_get`/`webc_set` are, by construction, identical to the
//! `WasmContractManifest.footprint` entry the chain maps to
//! `StateKey::application(namespace, key_hash)`. If these ever diverged, the
//! declared-footprint recorder would deny the access — so keeping one derivation
//! is a correctness invariant, not a convenience.

use webc_crypto::Hash256;

/// Domain separator for Weft state keys. Edition-tagged so a future edition can
/// evolve the derivation without colliding with edition-1 keys.
const WEFT_STATE_KEY_DOMAIN: &[u8] = b"weft.state.v1";

/// Derives the 32-byte state key for `component`'s `field`.
///
/// Deterministic and collision-resistant (domain-separated SHA-256 with an
/// explicit `\0` separator between the component and field names, so
/// `("ab","c")` and `("a","bc")` cannot alias).
pub fn state_key(component: &str, field: &str) -> Hash256 {
    Hash256::digest_many([
        WEFT_STATE_KEY_DOMAIN,
        component.as_bytes(),
        b"\0",
        field.as_bytes(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_deterministic_and_separated() {
        assert_eq!(state_key("counter", "count"), state_key("counter", "count"));
        assert_ne!(state_key("counter", "count"), state_key("counter", "total"));
        assert_ne!(state_key("a", "bc"), state_key("ab", "c"));
    }
}
