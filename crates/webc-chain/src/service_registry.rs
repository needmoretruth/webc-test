//! Native SERVICE REGISTRY: on-chain, machine-readable service discovery for AI
//! agents (WEBC-DEFINITION §15.5; `docs/agent-commerce.md` §3).
//!
//! Purpose: let a service publish its prices, interface, and payment flows
//! on-chain so an agent can discover it and pay for it under a mandate without a
//! bespoke integration. An entry is the commerce counterpart of the component
//! catalog: a namespace-scoped, versioned record an application claims for a fee
//! and later updates or retires. The registry also NAMES the taxonomy categories
//! a mandate's counterparty allowlist references (§2), closing the loop the Phase
//! 9a mandate left open: a `Category(Hash256)` tag in an allowlist becomes
//! matchable once a service declares that category.
//!
//! Responsibilities: define the service identity ([`ServiceId`]) and its
//! deterministic namespace-scoped derivation, the canonical entry record
//! ([`ServiceEntry`]) with every variable-length field BOUNDED, the entry's
//! sub-records ([`ServicePrice`], [`ServicePaymentFlags`], [`ServiceStatus`]),
//! the length/count bounds ([`MAX_SERVICE_TITLE_BYTES`] and siblings), and the
//! Merkle sub-root domain that commits the registry map to the state root
//! ([`SERVICE_REGISTRY_LEAF_DOMAIN`]).
//!
//! Non-responsibilities: this module never moves native supply, never touches
//! accounts, and never reads a wall clock, network, files, or randomness. The
//! `state` module owns the committed `services` map, the
//! register/update/set-status/service-scoped-spend state transitions, and the
//! state-commitment / access-list wiring; it consumes the pure identifiers,
//! records, and validation here.
//!
//! Bounded active state: only the CURRENT revision of an entry lives in committed
//! active state, exactly as the namespace and oracle registries keep only the
//! current record. Each update bumps [`ServiceEntry::revision`] in place; prior
//! revisions are an archival / event-log concern (a light client reconstructs
//! history from `ServiceUpdated` / `ServiceStatusChanged` events), never a growth
//! term in consensus state. This keeps the registry's committed size a function
//! of the number of live services, not of their edit history.
//!
//! Security boundary: every field of a [`ServiceEntry`] is untrusted. Registration
//! records data only — it locks NO native units, so the supply invariant is
//! unaffected (only the ordinary, spam-priced transaction fee moves through the
//! existing burn / fee-pool split). Every byte-string is length-bounded on decode
//! *and* re-checked by [`ServiceEntry::validate`], every list/set count is
//! bounded, and a required field may not be empty, so a hostile entry cannot size
//! an allocation or smuggle an over-length record past a state load. Ownership is
//! enforced by `state`: only the entry's `owner` may update it or change its
//! status. This path is a devnet prototype and is disabled for real funds.

use crate::mandate::{MandateCounterparty, MandateCounterpartyPolicy};
use crate::{Amount, ChainError};
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeSet;
use webc_crypto::{Address, Hash256};

/// Domain tag hashed into a service's opaque, namespace-scoped identity.
///
/// Domain separation keeps a service id from colliding with an address, a feed
/// id, a mandate id, or any other 32-byte WEBC artifact derived from the same
/// inputs. Changing it is a consensus-format break.
const SERVICE_ID_DOMAIN: &[u8] = b"WEBC_SERVICE_ID_V1";

/// Domain tag for the service-registry Merkle sub-root committed by the state root.
///
/// Each `(ServiceId, ServiceEntry)` entry is a leaf under this domain, so any
/// registration, update, or status change moves the state root. Bumping this
/// constant is a consensus-format change.
pub const SERVICE_REGISTRY_LEAF_DOMAIN: &[u8] = b"WEBC_SERVICE_REGISTRY_LEAF_V1";

/// Maximum taxonomy categories one service entry may declare.
///
/// Bounds the per-entry category set (mandate allowlists reference these tags),
/// so a hostile entry cannot inflate committed state or the category-intersection
/// work a service-scoped spend performs.
pub const MAX_SERVICE_CATEGORIES: usize = 8;

/// Maximum bytes in a service entry's human/machine title label.
pub const MAX_SERVICE_TITLE_BYTES: usize = 64;

/// Maximum bytes in a service entry's endpoint reference (an HTTPS URL or an
/// on-chain entrypoint reference).
pub const MAX_SERVICE_ENDPOINT_BYTES: usize = 256;

/// Maximum priced operations one service entry may list.
pub const MAX_SERVICE_PRICING_ENTRIES: usize = 16;

/// Maximum bytes in one [`ServicePrice`] unit label (e.g. `"call"`, `"1k-token"`).
pub const MAX_SERVICE_PRICE_UNIT_BYTES: usize = 32;

/// The revision a freshly registered entry carries. Each update bumps it by one.
///
/// Starting at `1` makes "revision 0" mean "never registered" for any off-chain
/// index and keeps the first committed revision human-meaningful.
pub const INITIAL_SERVICE_REVISION: u64 = 1;

/// Serializes a byte string as a lowercase hex string (shared by the bounded
/// service-field codecs below).
fn serialize_hex<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

/// Deserializes a lowercase hex string into a `Vec<u8>`, rejecting an over-length
/// or odd-length string *before* any allocation is sized (hostile-input safety).
fn deserialize_bounded_hex<'de, D>(deserializer: D, max_bytes: usize) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    // Two hex characters per byte; bound the string length before decoding so a
    // hostile length prefix cannot size an allocation.
    if encoded.len() > max_bytes.saturating_mul(2) {
        return Err(D::Error::custom("service field exceeds maximum byte length"));
    }
    if encoded.len() % 2 != 0 {
        return Err(D::Error::custom("service field hex length must be even"));
    }
    hex::decode(encoded).map_err(D::Error::custom)
}

/// Bounded lowercase-hex codec for the entry title (≤ [`MAX_SERVICE_TITLE_BYTES`]).
pub(crate) mod bounded_title_hex {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        super::serialize_hex(bytes, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        super::deserialize_bounded_hex(deserializer, super::MAX_SERVICE_TITLE_BYTES)
    }
}

/// Bounded lowercase-hex codec for the entry endpoint
/// (≤ [`MAX_SERVICE_ENDPOINT_BYTES`]).
pub(crate) mod bounded_endpoint_hex {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        super::serialize_hex(bytes, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        super::deserialize_bounded_hex(deserializer, super::MAX_SERVICE_ENDPOINT_BYTES)
    }
}

/// Bounded lowercase-hex codec for a price unit label
/// (≤ [`MAX_SERVICE_PRICE_UNIT_BYTES`]).
pub(crate) mod bounded_unit_hex {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        super::serialize_hex(bytes, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        super::deserialize_bounded_hex(deserializer, super::MAX_SERVICE_PRICE_UNIT_BYTES)
    }
}

/// Opaque, non-secret, namespace-scoped identity of one registered service.
///
/// Derived as `SHA-256("WEBC_SERVICE_ID_V1" || namespace || owner ||
/// create_nonce_be)`. Binding the `namespace` keeps registry activity isolated by
/// application (§8) and lets two applications register under distinct namespaces
/// without contention; binding the `owner` and an owner-chosen `create_nonce`
/// makes registration permissionless and collision-safe — one owner may register
/// many services under one namespace by varying the nonce, while a repeated
/// `(namespace, owner, create_nonce)` derives the same id and the second
/// registration is rejected as a duplicate. Keying state by this fixed-size id
/// keeps state keys bounded and lets a service-scoped spend find its entry in one
/// map probe. A distinct wrapper type keeps a service id from being mixed with an
/// object id, a feed id, a mandate id, or a raw hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServiceId(Hash256);

impl ServiceId {
    /// Constructs a service id from a raw 32-byte hash (wire/decoding path).
    pub const fn new(value: Hash256) -> Self {
        Self(value)
    }

    /// Returns the underlying fixed-size identifier used by versioned state keys
    /// and leaf hashing.
    pub const fn hash(self) -> Hash256 {
        self.0
    }

    /// Derives the deterministic id committing to a `(namespace, owner,
    /// create_nonce)` registration.
    ///
    /// Identical inputs derive an identical id on every node; changing any input
    /// (including the `create_nonce`) derives a different id. This is the only way
    /// an id is minted, so an update / status change / spend that names an id can
    /// never address a service a different owner registered.
    pub fn derive(namespace: Hash256, owner: Address, create_nonce: u64) -> Self {
        let nonce = create_nonce.to_be_bytes();
        let parts: [&[u8]; 4] = [
            SERVICE_ID_DOMAIN,
            namespace.as_bytes().as_slice(),
            owner.as_bytes().as_slice(),
            nonce.as_slice(),
        ];
        Self(Hash256::digest_many(parts))
    }
}

/// Lifecycle status of a registered service.
///
/// `Active` is the only status a service-scoped spend may pay; `Paused` and
/// `Retired` both reject a spend (the runtime returns
/// [`ChainError::ServiceNotActive`]). The distinction between paused and retired
/// is advisory metadata for off-chain discovery — a paused service intends to
/// return, a retired one does not — and both may be reactivated by the owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceStatus {
    /// The service is live and accepts service-scoped payments.
    Active,
    /// The service is temporarily unavailable and rejects payments.
    Paused,
    /// The service is permanently withdrawn and rejects payments.
    Retired,
}

impl ServiceStatus {
    /// Whether the service currently accepts service-scoped payments.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// The payment flows a service advertises it accepts.
///
/// A small explicit bitset-as-bools rather than a packed integer, so the wire
/// form is self-describing and a browser SDK reads each flag by name. At least
/// one flow must be set — an entry that accepts no payment flow is meaningless
/// and is rejected by [`ServiceEntry::validate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePaymentFlags {
    /// Accepts a direct on-chain payment (e.g. a mandate spend to this service).
    pub on_chain_direct: bool,
    /// Accepts payment inside an HTTP-402 request cycle (`docs/agent-commerce.md`
    /// §4).
    pub http_402: bool,
    /// Accepts a prepaid subscription allowance.
    pub subscription: bool,
}

impl ServicePaymentFlags {
    /// Whether at least one payment flow is accepted.
    pub fn any(self) -> bool {
        self.on_chain_direct || self.http_402 || self.subscription
    }
}

/// One priced operation a service exposes.
///
/// `operation` is a domain-separated tag (a hash of the operation's canonical
/// name) rather than a free string, so pricing keys are fixed-size and
/// collision-resistant. `price` is in native base units (an [`Amount`], whose
/// human-readable serde form is a decimal string so a browser never loses
/// precision). `unit` is a short bounded label naming what the price is *per*
/// (e.g. a call, a token, a megabyte).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePrice {
    /// Domain-separated operation tag this price applies to.
    pub operation: Hash256,
    /// Price in native base units.
    pub price: Amount,
    /// Bounded label naming the unit the price is charged per, lowercase hex on
    /// the wire (≤ [`MAX_SERVICE_PRICE_UNIT_BYTES`] bytes).
    #[serde(with = "bounded_unit_hex")]
    pub unit: Vec<u8>,
}

/// Canonical registry record for one service (the CURRENT revision only).
///
/// Keyed in [`crate::ChainState::services`] by [`ServiceId`]. Holds the entry's
/// owner (which is both the controller and the pay-to account for on-chain
/// payments), its application namespace, its taxonomy categories, its bounded
/// descriptive fields, its price list, its accepted payment flows, its lifecycle
/// status, and a monotonically increasing revision.
///
/// Invariants (checked by [`ServiceEntry::validate`], re-checked on any state
/// load or update in `state`):
/// - `title` is non-empty and at most [`MAX_SERVICE_TITLE_BYTES`] bytes;
/// - `endpoint` is non-empty and at most [`MAX_SERVICE_ENDPOINT_BYTES`] bytes;
/// - `categories` has at most [`MAX_SERVICE_CATEGORIES`] entries;
/// - `pricing` has at most [`MAX_SERVICE_PRICING_ENTRIES`] entries, each with a
///   `unit` at most [`MAX_SERVICE_PRICE_UNIT_BYTES`] bytes;
/// - `payment_flags` accepts at least one flow;
/// - `revision` starts at [`INITIAL_SERVICE_REVISION`] and only grows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceEntry {
    /// Account that controls this entry AND is credited by on-chain payments to
    /// the service (the registry pay-to account).
    pub owner: Address,
    /// Application namespace this entry lives under (registry activity stays
    /// namespace-isolated, §8); also bound into the derived [`ServiceId`].
    pub namespace: Hash256,
    /// Taxonomy tags a mandate counterparty allowlist may reference. Bounded to
    /// [`MAX_SERVICE_CATEGORIES`]; a `BTreeSet` keeps them deduplicated and in a
    /// deterministic order for the hashed/consensus path.
    pub categories: BTreeSet<Hash256>,
    /// Short human/machine label, lowercase hex on the wire
    /// (non-empty, ≤ [`MAX_SERVICE_TITLE_BYTES`] bytes).
    #[serde(with = "bounded_title_hex")]
    pub title: Vec<u8>,
    /// HTTPS URL or on-chain entrypoint reference, lowercase hex on the wire
    /// (non-empty, ≤ [`MAX_SERVICE_ENDPOINT_BYTES`] bytes).
    #[serde(with = "bounded_endpoint_hex")]
    pub endpoint: Vec<u8>,
    /// Manifest reference: a hash of the machine-readable interface description
    /// (same schema family as the component catalog / Weft manifest).
    pub interface: Hash256,
    /// Priced operations, bounded to [`MAX_SERVICE_PRICING_ENTRIES`].
    pub pricing: Vec<ServicePrice>,
    /// Accepted payment flows.
    pub payment_flags: ServicePaymentFlags,
    /// Lifecycle status; only [`ServiceStatus::Active`] accepts payments.
    pub status: ServiceStatus,
    /// Monotonically increasing revision, bumped on every update or status
    /// change. Only the current revision lives in committed active state.
    pub revision: u64,
}

impl ServiceEntry {
    /// Creates a freshly registered, validated entry at
    /// [`INITIAL_SERVICE_REVISION`] with status [`ServiceStatus::Active`].
    ///
    /// Validates the bounded fields independent of chain state (id derivation,
    /// duplicate rejection, and fee accounting are the caller's concern). Returns
    /// [`ChainError::InvalidServiceEntry`] on a malformed entry.
    #[allow(
        clippy::too_many_arguments,
        reason = "a service registration fixes each independent bounded field explicitly at the security boundary"
    )]
    pub fn new(
        owner: Address,
        namespace: Hash256,
        categories: BTreeSet<Hash256>,
        title: Vec<u8>,
        endpoint: Vec<u8>,
        interface: Hash256,
        pricing: Vec<ServicePrice>,
        payment_flags: ServicePaymentFlags,
    ) -> Result<Self, ChainError> {
        let entry = Self {
            owner,
            namespace,
            categories,
            title,
            endpoint,
            interface,
            pricing,
            payment_flags,
            status: ServiceStatus::Active,
            revision: INITIAL_SERVICE_REVISION,
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Re-validates the entry's bounded-field invariants.
    ///
    /// Rejects an empty or over-length title/endpoint, too many categories or
    /// pricing entries, an over-length price unit, and payment flags that accept
    /// no flow. A hostile decode or a state load could otherwise smuggle an
    /// over-count record in, so this is called on every register and update.
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.title.is_empty() || self.title.len() > MAX_SERVICE_TITLE_BYTES {
            return Err(ChainError::InvalidServiceEntry);
        }
        if self.endpoint.is_empty() || self.endpoint.len() > MAX_SERVICE_ENDPOINT_BYTES {
            return Err(ChainError::InvalidServiceEntry);
        }
        if self.categories.len() > MAX_SERVICE_CATEGORIES {
            return Err(ChainError::InvalidServiceEntry);
        }
        if self.pricing.len() > MAX_SERVICE_PRICING_ENTRIES {
            return Err(ChainError::InvalidServiceEntry);
        }
        if self
            .pricing
            .iter()
            .any(|price| price.unit.len() > MAX_SERVICE_PRICE_UNIT_BYTES)
        {
            return Err(ChainError::InvalidServiceEntry);
        }
        if !self.payment_flags.any() {
            return Err(ChainError::InvalidServiceEntry);
        }
        Ok(())
    }
}

impl MandateCounterpartyPolicy {
    /// Whether a spend to `service` is permitted by this policy, resolving
    /// category tags against the registry (Phase 9b closes the §2 allowlist loop).
    ///
    /// `Open` permits any service. `Allowlist` permits a service when either the
    /// service's `owner` is listed as an explicit
    /// [`MandateCounterparty::Recipient`], OR the service is
    /// [`ServiceStatus::Active`] and at least one of the service's `categories` is
    /// listed as a [`MandateCounterparty::Category`]. Category resolution is what
    /// the Phase 9a `permits` (recipient-only) deliberately left to this phase; a
    /// category-only allowlist that admitted nothing before now admits any active
    /// service tagged with a listed category.
    ///
    /// The recipient-address path of [`Self::permits`] is unchanged: a service's
    /// `owner` is the address that path would match, so a recipient allowlist keeps
    /// working through the service's owner without any registry lookup.
    pub fn permits_service(&self, service: &ServiceEntry) -> bool {
        match self {
            Self::Open => true,
            Self::Allowlist(entries) => {
                if entries.contains(&MandateCounterparty::Recipient(service.owner)) {
                    return true;
                }
                service.status.is_active()
                    && service
                        .categories
                        .iter()
                        .any(|category| entries.contains(&MandateCounterparty::Category(*category)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webc_crypto::Keypair;

    fn owner() -> Address {
        Keypair::from_seed([21u8; 32]).address()
    }

    fn sample_entry() -> ServiceEntry {
        let mut categories = BTreeSet::new();
        categories.insert(Hash256([0xc1; 32]));
        ServiceEntry::new(
            owner(),
            Hash256([0x55; 32]),
            categories,
            b"inference".to_vec(),
            b"https://api.example/infer".to_vec(),
            Hash256([0x1f; 32]),
            vec![ServicePrice {
                operation: Hash256([0x0b; 32]),
                price: Amount::from_units(1_000),
                unit: b"call".to_vec(),
            }],
            ServicePaymentFlags {
                on_chain_direct: true,
                http_402: true,
                subscription: false,
            },
        )
        .expect("valid entry")
    }

    #[test]
    fn id_derivation_is_deterministic_and_input_separated() {
        let ns = Hash256([0x55; 32]);
        let o = owner();
        assert_eq!(ServiceId::derive(ns, o, 0), ServiceId::derive(ns, o, 0));
        // A different create nonce, owner, or namespace yields a distinct id.
        assert_ne!(ServiceId::derive(ns, o, 0), ServiceId::derive(ns, o, 1));
        assert_ne!(
            ServiceId::derive(ns, o, 0),
            ServiceId::derive(Hash256([0x56; 32]), o, 0)
        );
        let other = Keypair::from_seed([22u8; 32]).address();
        assert_ne!(ServiceId::derive(ns, o, 0), ServiceId::derive(ns, other, 0));
        // Domain-separated from a bare digest of the concatenated inputs.
        assert_ne!(ServiceId::derive(ns, o, 0).hash().0, o.0);
    }

    #[test]
    fn valid_entry_starts_active_at_initial_revision() {
        let entry = sample_entry();
        entry.validate().unwrap();
        assert_eq!(entry.status, ServiceStatus::Active);
        assert_eq!(entry.revision, INITIAL_SERVICE_REVISION);
        assert!(entry.status.is_active());
    }

    #[test]
    fn over_length_and_over_count_fields_are_rejected() {
        // Empty required fields.
        let mut entry = sample_entry();
        entry.title.clear();
        assert!(matches!(
            entry.validate(),
            Err(ChainError::InvalidServiceEntry)
        ));
        let mut entry = sample_entry();
        entry.endpoint.clear();
        assert!(matches!(
            entry.validate(),
            Err(ChainError::InvalidServiceEntry)
        ));
        // Over-length title / endpoint.
        let mut entry = sample_entry();
        entry.title = vec![0x61; MAX_SERVICE_TITLE_BYTES + 1];
        assert!(matches!(
            entry.validate(),
            Err(ChainError::InvalidServiceEntry)
        ));
        let mut entry = sample_entry();
        entry.endpoint = vec![0x61; MAX_SERVICE_ENDPOINT_BYTES + 1];
        assert!(matches!(
            entry.validate(),
            Err(ChainError::InvalidServiceEntry)
        ));
        // Too many categories.
        let mut entry = sample_entry();
        entry.categories = (0..=MAX_SERVICE_CATEGORIES as u8)
            .map(|i| Hash256([i; 32]))
            .collect();
        assert!(entry.categories.len() > MAX_SERVICE_CATEGORIES);
        assert!(matches!(
            entry.validate(),
            Err(ChainError::InvalidServiceEntry)
        ));
        // Too many pricing entries.
        let mut entry = sample_entry();
        entry.pricing = (0..=MAX_SERVICE_PRICING_ENTRIES as u8)
            .map(|i| ServicePrice {
                operation: Hash256([i; 32]),
                price: Amount::from_units(1),
                unit: b"call".to_vec(),
            })
            .collect();
        assert!(matches!(
            entry.validate(),
            Err(ChainError::InvalidServiceEntry)
        ));
        // Over-length price unit.
        let mut entry = sample_entry();
        entry.pricing = vec![ServicePrice {
            operation: Hash256([0x0b; 32]),
            price: Amount::from_units(1),
            unit: vec![0x61; MAX_SERVICE_PRICE_UNIT_BYTES + 1],
        }];
        assert!(matches!(
            entry.validate(),
            Err(ChainError::InvalidServiceEntry)
        ));
        // No payment flow accepted.
        let mut entry = sample_entry();
        entry.payment_flags = ServicePaymentFlags {
            on_chain_direct: false,
            http_402: false,
            subscription: false,
        };
        assert!(matches!(
            entry.validate(),
            Err(ChainError::InvalidServiceEntry)
        ));
    }

    #[test]
    fn entry_round_trips_and_rejects_unknown_fields() {
        let entry = sample_entry();
        let text = serde_json::to_string(&entry).expect("entry serializes");
        let decoded: ServiceEntry = serde_json::from_str(&text).expect("entry decodes");
        assert_eq!(decoded, entry);
        // Strict decode: an unexpected field is rejected on hostile input.
        let mut value = serde_json::to_value(&entry).expect("to value");
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ServiceEntry>(value).is_err());
    }

    #[test]
    fn over_length_title_hex_is_rejected_before_decode() {
        // The bounded codec rejects an over-length hex string before allocation,
        // so a hostile entry cannot size a title allocation past the bound.
        let entry = sample_entry();
        let mut value = serde_json::to_value(&entry).expect("to value");
        value["title"] =
            serde_json::Value::String("61".repeat(MAX_SERVICE_TITLE_BYTES + 1));
        assert!(serde_json::from_value::<ServiceEntry>(value).is_err());
    }

    #[test]
    fn permits_service_resolves_recipient_and_category_allowlists() {
        let entry = sample_entry();
        let category = *entry.categories.iter().next().unwrap();

        // Open permits any service.
        assert!(MandateCounterpartyPolicy::Open.permits_service(&entry));

        // Recipient allowlist: matches through the service owner (unchanged path).
        let mut recipient_only = BTreeSet::new();
        recipient_only.insert(MandateCounterparty::Recipient(entry.owner));
        assert!(MandateCounterpartyPolicy::Allowlist(recipient_only).permits_service(&entry));

        // Category allowlist: matches an active service tagged with the category.
        let mut category_only = BTreeSet::new();
        category_only.insert(MandateCounterparty::Category(category));
        let policy = MandateCounterpartyPolicy::Allowlist(category_only.clone());
        assert!(policy.permits_service(&entry));

        // A non-intersecting category allowlist admits nothing.
        let mut other = BTreeSet::new();
        other.insert(MandateCounterparty::Category(Hash256([0xee; 32])));
        assert!(!MandateCounterpartyPolicy::Allowlist(other).permits_service(&entry));

        // A paused service is not matchable by category even if the tag is listed.
        let mut paused = entry.clone();
        paused.status = ServiceStatus::Paused;
        assert!(!MandateCounterpartyPolicy::Allowlist(category_only).permits_service(&paused));
    }
}
