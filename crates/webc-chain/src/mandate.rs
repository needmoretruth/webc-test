//! Native AI-agent MANDATE primitive: a pre-funded, instantly-revocable spending
//! authorization a principal grants to a distinct agent signing key
//! (WEBC-DEFINITION §15.5/§15.32; `docs/agent-commerce.md` §2).
//!
//! Purpose: represent a "prepaid card with rules engraved on it". A principal
//! moves native units into escrow and delegates bounded spending authority to an
//! AI agent's own Ed25519 key. The agent spends by signing transactions that
//! reference the mandate; the runtime enforces the budget, per-transaction cap,
//! expiry, counterparty allowlist, and daily rate limit atomically with the
//! payment, and the principal can revoke and reclaim the unspent remainder at any
//! time.
//!
//! Responsibilities: define the mandate identity ([`MandateId`]) and its
//! deterministic derivation, the immutable-plus-mutable mandate record
//! ([`Mandate`]), the counterparty policy ([`MandateCounterpartyPolicy`] and its
//! entries [`MandateCounterparty`]), the deterministic "per day" rate-limit window
//! parameters ([`MandateConfig`]), and the Merkle sub-root domain that commits the
//! mandate map to the state root ([`MANDATE_LEAF_DOMAIN`]).
//!
//! Non-responsibilities: this module never verifies signatures, moves native
//! supply, reads chain state, decides transaction authorization, or reads a wall
//! clock, network, files, or randomness. The `state` module owns the committed
//! `mandates` map, the aggregate `mandate_escrow` locked bucket, the
//! grant/top-up/spend/revoke state transitions, and the state-commitment /
//! access-list wiring; it consumes the pure identifiers, records, and validation
//! here.
//!
//! Relationship to session keys (`session_key.rs`): a session key authorizes the
//! **owner's own** device flows under the owner's account; a mandate authorizes a
//! **distinct agent identity** with its own key, its own escrowed budget, and its
//! own audit trail. They are separate primitives.
//!
//! Security boundary: a mandate is a spending authorization backed by escrowed
//! value. Its whole blast radius is bounded by `budget_total`, which the agent can
//! never exceed however many times it spends; each spend is additionally capped by
//! `per_tx_max`, gated by `expiry_epoch`, restricted to permitted counterparties,
//! and throttled by `rate_limit_per_day`. There is **no re-delegation**: the record
//! carries no mechanism for an agent to mint sub-mandates, and only a
//! principal-signed operation can grant, top up, or revoke one. Every bound is
//! validated before use and enforced with checked arithmetic; nothing panics on
//! hostile input.
//!
//! This path is a devnet prototype and is disabled for real funds.

use crate::{Amount, ChainError, Epoch};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use webc_crypto::{Address, Hash256, PublicKeyBytes};

/// Domain tag hashed into a mandate's opaque identity.
///
/// Domain separation keeps a mandate id from colliding with an address, a session
/// key id, or any other 32-byte WEBC artifact derived from the same inputs.
/// Changing it is a consensus-format break.
const MANDATE_ID_DOMAIN: &[u8] = b"WEBC_MANDATE_ID_V1";

/// Domain tag for the mandate-registry Merkle sub-root committed by the state root.
///
/// Each `(MandateId, Mandate)` entry is a leaf under this domain, so any grant,
/// top-up, spend, or revocation changes the state root. Bumping this constant is a
/// consensus-format change.
pub const MANDATE_LEAF_DOMAIN: &[u8] = b"WEBC_MANDATE_LEAF_V1";

/// Opaque, non-secret identity of one mandate under a principal.
///
/// Derived as `SHA-256("WEBC_MANDATE_ID_V1" || principal || agent_key ||
/// grant_nonce_be)`. Binding the `grant_nonce` (a principal-chosen uniquifier)
/// lets one principal hold many mandates for the **same** agent key without
/// collision: distinct grant nonces derive distinct ids, while a repeated
/// `(principal, agent_key, grant_nonce)` derives the same id and the second grant
/// is rejected as a duplicate. Keying state by this fixed-size id keeps state keys
/// bounded and lets a spend find its mandate in one map probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MandateId(Hash256);

impl MandateId {
    /// Constructs an id from a raw 32-byte hash (wire/decoding path).
    pub const fn new(value: Hash256) -> Self {
        Self(value)
    }

    /// Returns the underlying fixed-size identifier.
    pub const fn hash(self) -> Hash256 {
        self.0
    }

    /// Derives the deterministic id committing to a `(principal, agent_key,
    /// grant_nonce)` grant.
    ///
    /// Identical inputs derive an identical id on every node; changing any input
    /// (including the `grant_nonce`) derives a different id. This is the only way
    /// an id is minted, so a spend/top-up/revoke that names an id can never
    /// address a mandate a different principal or agent controls.
    pub fn derive(principal: Address, agent_key: &PublicKeyBytes, grant_nonce: u64) -> Self {
        let nonce = grant_nonce.to_be_bytes();
        let parts: [&[u8]; 4] = [
            MANDATE_ID_DOMAIN,
            principal.as_bytes().as_slice(),
            agent_key.as_bytes().as_slice(),
            nonce.as_slice(),
        ];
        Self(Hash256::digest_many(parts))
    }
}

/// One permitted counterparty in a mandate allowlist.
///
/// An entry is either an opaque category tag or a specific recipient address.
/// Category tags are placeholders a later service registry (Phase 9b) will name
/// and map recipients to; in Phase 9a a spend is matched against the allowlist by
/// recipient address only (see [`MandateCounterpartyPolicy::permits`]), so an
/// allowlist that contains only categories admits no spend yet. The variant is
/// `Ord` so it can live in a deterministic [`BTreeSet`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MandateCounterparty {
    /// An opaque registry category tag (named by a future service registry).
    Category(Hash256),
    /// A specific recipient account permitted to receive spends.
    Recipient(Address),
}

/// Which counterparties a mandate's spends may pay.
///
/// `Open` permits any recipient; `Allowlist` permits only the listed entries. A
/// non-empty allowlist is required when this variant is used (an empty one would
/// admit no spend and is rejected by [`Mandate::validate`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MandateCounterpartyPolicy {
    /// Any recipient is permitted.
    Open,
    /// Only the listed categories/recipients are permitted.
    Allowlist(BTreeSet<MandateCounterparty>),
}

impl MandateCounterpartyPolicy {
    /// Whether a spend to `recipient` is permitted by this policy.
    ///
    /// `Open` permits everyone. `Allowlist` permits a recipient only if it is
    /// listed as an explicit [`MandateCounterparty::Recipient`]. Category tags are
    /// intentionally **not** matched here in Phase 9a — resolving whether a
    /// recipient belongs to a category needs the Phase 9b service registry — so a
    /// category-only allowlist admits nothing until that registry exists.
    pub fn permits(&self, recipient: &Address) -> bool {
        match self {
            Self::Open => true,
            Self::Allowlist(entries) => {
                entries.contains(&MandateCounterparty::Recipient(*recipient))
            }
        }
    }

    /// Whether this policy can never permit any spend (an empty allowlist).
    ///
    /// A category-only allowlist is *not* considered empty here: it is a valid,
    /// forward-looking grant that the Phase 9b registry will make matchable. Only a
    /// literally empty allowlist is rejected at grant time.
    fn is_empty_allowlist(&self) -> bool {
        matches!(self, Self::Allowlist(entries) if entries.is_empty())
    }
}

/// Deterministic "per day" rate-limit window parameters for mandates.
///
/// The window index is `current_epoch / day_window_epochs`, so "per day" is
/// expressed purely from consensus epochs — never a wall clock — mirroring the
/// sponsor per-user/day window (`sponsorship::SponsorshipConfig`). The launch
/// value is a measurement-tuned placeholder; the method (a fixed epoch window) is
/// fixed. `#[serde(default)]` via the derived `Default` keeps a genesis written
/// before mandates decodable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MandateConfig {
    /// Number of consensus epochs in one "per day" rate-limit window. Must be
    /// non-zero (validated at genesis). Placeholder 1440 (≈ one day at ~1-minute
    /// devnet epochs).
    pub day_window_epochs: u64,
}

impl Default for MandateConfig {
    fn default() -> Self {
        Self {
            // ≈ one day at the ~1-minute devnet epoch assumption; a placeholder.
            day_window_epochs: 1_440,
        }
    }
}

impl MandateConfig {
    /// Rejects a configuration whose rate-limit window is zero (division base).
    ///
    /// Called at genesis so a chain never runs with a malformed mandate window.
    /// The spend path additionally treats a zero window defensively (it yields
    /// window `0`), so a bad config fails closed either way.
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.day_window_epochs == 0 {
            return Err(ChainError::InvalidMandateConfig);
        }
        Ok(())
    }

    /// Deterministic rate-limit window index for a consensus epoch.
    ///
    /// `current_epoch / day_window_epochs`. A zero window yields `0` (never
    /// divides by zero); genesis validation independently rejects a zero window.
    pub fn window_index(&self, current_epoch: u64) -> u64 {
        if self.day_window_epochs == 0 {
            return 0;
        }
        current_epoch / self.day_window_epochs
    }
}

/// One live, pre-funded mandate granting an agent bounded spending authority.
///
/// Keyed in [`crate::ChainState::mandates`] by [`MandateId`]. The mandate's
/// `budget_total` is locked native value the aggregate `mandate_escrow` supply
/// bucket accounts for: a grant moves `budget_total` here from the principal's
/// liquid balance, a spend moves `amount + fee` out (to the recipient and the fee
/// path), a top-up raises both, and a revoke returns the unspent remainder.
///
/// Invariants (checked by [`Mandate::validate`], enforced with checked arithmetic
/// in `state`):
/// - `budget_total` and `per_tx_max` are non-zero, and `per_tx_max <=
///   budget_total`;
/// - `spent` only grows and never exceeds `budget_total`;
/// - a non-empty allowlist when `counterparty_policy` is
///   [`MandateCounterpartyPolicy::Allowlist`];
/// - the sum of every live mandate's `budget_total - spent` equals the
///   `mandate_escrow` scalar the supply invariant reconciles.
///
/// There is deliberately **no** field by which an agent could grant, widen, or
/// re-delegate authority: only principal-signed operations mutate a mandate's
/// budget or revocation state, and a spend may only advance `spent`, the
/// rate-limit counters, and (never up) the budget.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mandate {
    /// Account that owns this mandate: funds it, tops it up, and may revoke it.
    pub principal: Address,
    /// The agent's Ed25519 signing key. Authorizes spends by signing; it is not
    /// necessarily an account and holds no balance of its own.
    pub agent_key: PublicKeyBytes,
    /// Total native base units authorized over the mandate's whole life. Raised
    /// only by a principal-signed top-up.
    pub budget_total: Amount,
    /// Native base units already spent (principal moved plus fees paid). Only
    /// grows; never exceeds `budget_total`.
    pub spent: Amount,
    /// Last consensus epoch (inclusive) in which the mandate may be spent.
    pub expiry_epoch: Epoch,
    /// Maximum native principal one mandate-signed spend may move (excludes fee).
    pub per_tx_max: Amount,
    /// Maximum spends per rate-limit window. `0` means unlimited (no per-day cap).
    pub rate_limit_per_day: u32,
    /// Which counterparties spends may pay.
    pub counterparty_policy: MandateCounterpartyPolicy,
    /// Whether the principal has revoked the mandate. A revoked mandate rejects
    /// every further spend; its unspent remainder was returned at revocation.
    pub revoked: bool,
    /// Rate-limit window that `spends_in_window` belongs to (lazily rolled
    /// forward on the next spend, resetting the counter at each window boundary).
    pub window_index: u64,
    /// Spends counted in `window_index`, reset each new window.
    pub spends_in_window: u32,
}

impl Mandate {
    /// Creates a validated, unspent mandate.
    ///
    /// Validates the grant parameters independent of chain state (existence,
    /// escrow, and expiry-vs-epoch are the caller's concern). Returns
    /// [`ChainError::InvalidMandate`] on a malformed grant.
    #[allow(
        clippy::too_many_arguments,
        reason = "a mandate grant fixes each independent bound explicitly at the security boundary"
    )]
    pub fn new(
        principal: Address,
        agent_key: PublicKeyBytes,
        budget_total: Amount,
        expiry_epoch: Epoch,
        per_tx_max: Amount,
        rate_limit_per_day: u32,
        counterparty_policy: MandateCounterpartyPolicy,
    ) -> Result<Self, ChainError> {
        let mandate = Self {
            principal,
            agent_key,
            budget_total,
            spent: Amount::ZERO,
            expiry_epoch,
            per_tx_max,
            rate_limit_per_day,
            counterparty_policy,
            revoked: false,
            window_index: 0,
            spends_in_window: 0,
        };
        mandate.validate()?;
        Ok(mandate)
    }

    /// Re-validates the mandate's parameter invariants.
    ///
    /// Rejects a zero budget or per-transaction cap, a per-transaction cap above
    /// the budget, an empty allowlist, and a `spent` above the budget (which a
    /// hostile decode or state load could otherwise smuggle in). Does not compare
    /// against the current epoch or the escrow bucket; `state` owns those.
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.budget_total.is_zero() || self.per_tx_max.is_zero() {
            return Err(ChainError::InvalidMandate);
        }
        if self.per_tx_max > self.budget_total {
            return Err(ChainError::InvalidMandate);
        }
        if self.spent > self.budget_total {
            return Err(ChainError::InvalidMandate);
        }
        if self.counterparty_policy.is_empty_allowlist() {
            return Err(ChainError::InvalidMandate);
        }
        Ok(())
    }

    /// Unspent native base units still escrowed for this mandate.
    ///
    /// This is exactly what a revocation returns to the principal, and this
    /// mandate's contribution to the `mandate_escrow` supply bucket.
    pub fn remaining(&self) -> Result<Amount, ChainError> {
        self.budget_total
            .checked_sub(self.spent)
            .ok_or(ChainError::ArithmeticOverflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webc_crypto::Keypair;

    fn agent_key() -> PublicKeyBytes {
        Keypair::from_seed([9u8; 32]).public_key()
    }

    fn principal() -> Address {
        Keypair::from_seed([1u8; 32]).address()
    }

    fn open_mandate() -> Mandate {
        Mandate::new(
            principal(),
            agent_key(),
            Amount::from_units(1_000),
            Epoch::new(100),
            Amount::from_units(100),
            5,
            MandateCounterpartyPolicy::Open,
        )
        .expect("valid mandate")
    }

    #[test]
    fn id_derivation_is_deterministic_and_grant_nonce_separated() {
        let p = principal();
        let key = agent_key();
        assert_eq!(MandateId::derive(p, &key, 0), MandateId::derive(p, &key, 0));
        // A different grant nonce for the same principal + agent key yields a
        // distinct id, so a principal can hold many mandates for one agent.
        assert_ne!(MandateId::derive(p, &key, 0), MandateId::derive(p, &key, 1));
        // The id is domain-separated from the raw address commitment of the agent.
        assert_ne!(
            MandateId::derive(p, &key, 0).hash().0,
            Address::from_public_key(&key).0
        );
    }

    #[test]
    fn valid_mandate_passes_and_records_zero_spend() {
        let mandate = open_mandate();
        mandate.validate().unwrap();
        assert_eq!(mandate.spent, Amount::ZERO);
        assert_eq!(mandate.remaining().unwrap(), Amount::from_units(1_000));
        assert!(!mandate.revoked);
    }

    #[test]
    fn zero_budget_or_per_tx_and_cap_above_budget_are_rejected() {
        let p = principal();
        let key = agent_key();
        let cases = [
            (Amount::ZERO, Amount::from_units(10)),
            (Amount::from_units(100), Amount::ZERO),
            // per_tx_max above budget_total.
            (Amount::from_units(10), Amount::from_units(11)),
        ];
        for (budget, per_tx) in cases {
            assert!(matches!(
                Mandate::new(
                    p,
                    key,
                    budget,
                    Epoch::new(10),
                    per_tx,
                    1,
                    MandateCounterpartyPolicy::Open,
                ),
                Err(ChainError::InvalidMandate)
            ));
        }
    }

    #[test]
    fn empty_allowlist_is_rejected_but_category_only_is_allowed() {
        let p = principal();
        let key = agent_key();
        assert!(matches!(
            Mandate::new(
                p,
                key,
                Amount::from_units(100),
                Epoch::new(10),
                Amount::from_units(10),
                1,
                MandateCounterpartyPolicy::Allowlist(BTreeSet::new()),
            ),
            Err(ChainError::InvalidMandate)
        ));
        // A category-only allowlist is a valid forward-looking grant.
        let mut entries = BTreeSet::new();
        entries.insert(MandateCounterparty::Category(Hash256([0x42; 32])));
        assert!(Mandate::new(
            p,
            key,
            Amount::from_units(100),
            Epoch::new(10),
            Amount::from_units(10),
            1,
            MandateCounterpartyPolicy::Allowlist(entries),
        )
        .is_ok());
    }

    #[test]
    fn allowlist_permits_only_listed_recipients() {
        let allowed = Keypair::from_seed([2u8; 32]).address();
        let denied = Keypair::from_seed([3u8; 32]).address();
        let mut entries = BTreeSet::new();
        entries.insert(MandateCounterparty::Recipient(allowed));
        // A category tag in the same set must not accidentally admit anyone.
        entries.insert(MandateCounterparty::Category(Hash256([0x7; 32])));
        let policy = MandateCounterpartyPolicy::Allowlist(entries);
        assert!(policy.permits(&allowed));
        assert!(!policy.permits(&denied));
        assert!(MandateCounterpartyPolicy::Open.permits(&denied));
    }

    #[test]
    fn window_index_is_epoch_division_and_never_divides_by_zero() {
        let config = MandateConfig {
            day_window_epochs: 10,
        };
        assert_eq!(config.window_index(0), 0);
        assert_eq!(config.window_index(9), 0);
        assert_eq!(config.window_index(10), 1);
        assert_eq!(config.window_index(25), 2);
        let zero = MandateConfig {
            day_window_epochs: 0,
        };
        assert_eq!(zero.window_index(1_000), 0);
        assert!(matches!(
            zero.validate(),
            Err(ChainError::InvalidMandateConfig)
        ));
    }

    #[test]
    fn record_round_trips_and_rejects_unknown_fields() {
        let mandate = open_mandate();
        let text = serde_json::to_string(&mandate).expect("mandate serializes");
        let decoded: Mandate = serde_json::from_str(&text).expect("mandate decodes");
        assert_eq!(decoded, mandate);
        // Strict decode: an unexpected field is rejected on hostile input.
        let mut value = serde_json::to_value(&mandate).expect("to value");
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Mandate>(value).is_err());
    }

    #[test]
    fn tampered_overspend_is_detected_by_validate() {
        let mut mandate = open_mandate();
        mandate.spent = Amount::from_units(1_001);
        assert!(matches!(
            mandate.validate(),
            Err(ChainError::InvalidMandate)
        ));
    }
}
