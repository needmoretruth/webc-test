//! Native NON-FUNGIBLE TOKEN (NFT) system: low-cost, permissionless creation of
//! application-defined NFT collections with unique per-item ownership and
//! configurable authorities (WEBC-DEFINITION §15; `docs/development-plan.md`
//! "Phase 13: tokens, NFTs, and application governance").
//!
//! Purpose: let anyone create a self-contained NFT collection — its own name,
//! symbol, off-chain metadata commitment, and optional royalty commitment — for a
//! spam-priced native deposit, then mint / transfer / burn its unique items and
//! freeze / pause / transfer or permanently renounce its authorities. This is a
//! DISTINCT pass from the native FUNGIBLE token system ([`crate::token`]): a
//! collection is an [`NftCollectionId`] (never a [`crate::TokenId`]) and its items
//! live in their own map keyed by [`NftId`] (never `token_balances`), so per-item
//! ownership accounting stays isolated from fungible-balance accounting.
//!
//! Responsibilities: define the collection identity ([`NftCollectionId`]) and its
//! deterministic namespace-scoped derivation, the per-item identity ([`NftId`], the
//! `(collection, serial)` pair that IS the id — never hashed), the canonical
//! bounded metadata record ([`NftMetadata`]) with every variable-length field
//! BOUNDED, the per-collection authority/supply record ([`NftCollection`]), the
//! per-item ownership record ([`NftItem`]), the authority discriminant
//! ([`NftAuthorityKind`]), the length/range bounds ([`MAX_NFT_NAME_BYTES`] and
//! siblings), and the two Merkle sub-root domains that commit the collection map and
//! the item map to the state root ([`NFT_COLLECTION_LEAF_DOMAIN`],
//! [`NFT_ITEM_LEAF_DOMAIN`]).
//!
//! Non-responsibilities: this module never moves native WEBC supply, never touches
//! native accounts, and never reads a wall clock, network, files, or randomness.
//! The `state` module owns the committed `nft_collections` / `nft_items`
//! collections, the `nft_deposits` locked bucket, every create / mint / transfer /
//! burn / freeze / pause / authority state transition, and the state-commitment /
//! access-list wiring; it consumes the pure identifiers, records, and validation
//! here. Application governance is a SEPARATE later pass (Phase 13c) and is
//! deliberately not built here.
//!
//! Security boundary: every field of an [`NftMetadata`] is untrusted — the name and
//! symbol are length-bounded on decode *and* re-checked by [`NftMetadata::validate`],
//! and `royalty_bps` is range-bounded by [`NftCollection::new`], so a hostile record
//! cannot size an allocation or smuggle an over-length/out-of-range record past a
//! state load. Authorities are `Option<Address>`: `None` means the power is
//! permanently RENOUNCED, and revocation (`Some -> None`) can never be undone — a
//! Phase 13 acceptance criterion ("revoked authority cannot return"), enforced by
//! `state`. Collection creation locks a native WEBC deposit (an anti-spam price) but
//! NEVER mints or burns native WEBC; NFT mint/burn move only the collection's own
//! `minted_count` / `burned_count` counters and the per-item ownership map, never
//! native supply. Royalty ENFORCEMENT is a marketplace / later concern: the chain
//! records only the `royalty_bps` commitment and never enforces it on transfer. This
//! path is a devnet prototype and is disabled for real funds.

use crate::{Amount, ChainError};
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use webc_crypto::{Address, Hash256};

/// Domain tag hashed into a collection's opaque, namespace-scoped identity.
///
/// Domain separation keeps a collection id from colliding with an address, a token
/// id, a service id, a feed id, or any other 32-byte WEBC artifact derived from the
/// same inputs. Changing it is a consensus-format break.
const NFT_COLLECTION_ID_DOMAIN: &[u8] = b"WEBC_NFT_COLLECTION_ID_V1";

/// Domain tag for the NFT-collection-registry Merkle sub-root committed by the
/// state root.
///
/// Each `(NftCollectionId, NftCollection)` entry is a leaf under this domain, so a
/// create, mint, burn, pause, or authority change (each of which rewrites the
/// collection record) moves the state root. Bumping this constant is a
/// consensus-format change.
pub const NFT_COLLECTION_LEAF_DOMAIN: &[u8] = b"WEBC_NFT_COLLECTION_LEAF_V1";

/// Domain tag for the NFT-item Merkle sub-root committed by the state root.
///
/// Each `(NftId, NftItem)` entry is a leaf under this domain, so a mint, transfer,
/// burn, freeze, or thaw of any item changes the state root. The per-[`NftId`] leaf
/// is what keeps ordinary transfers parallel-schedulable — a transfer writes only
/// the one item leaf, never one global per-collection object. Bumping this constant
/// is a consensus-format change.
pub const NFT_ITEM_LEAF_DOMAIN: &[u8] = b"WEBC_NFT_ITEM_LEAF_V1";

/// Maximum bytes in a collection's human-readable name.
///
/// Bounds the per-record name so a hostile record cannot inflate committed state or
/// size a name allocation. Enforced on decode by the bounded name codec and
/// re-checked by [`NftMetadata::validate`].
pub const MAX_NFT_NAME_BYTES: usize = 32;

/// Maximum bytes in a collection's ticker symbol.
pub const MAX_NFT_SYMBOL_BYTES: usize = 12;

/// Maximum basis points a collection may commit as a creator royalty.
///
/// `10_000` bps == 100%. Bounds `royalty_bps` so a hostile record cannot smuggle an
/// out-of-range royalty commitment past a state load. Royalty ENFORCEMENT is a
/// marketplace/later concern (§15); the chain records only the commitment.
pub const MAX_NFT_ROYALTY_BPS: u16 = 10_000;

/// Native NFT-collection parameters (Phase 13b, §15).
///
/// The launch value is a measurement-tuned placeholder; the METHOD (a flat native
/// deposit locked for the collection's life) is fixed. `#[serde(default)]` via the
/// derived [`Default`] keeps a genesis written before NFTs decodable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NftConfig {
    /// Native base units LOCKED from the creator's liquid balance into the
    /// `nft_deposits` bucket at collection creation. NON-REFUNDABLE for the
    /// collection's life — an anti-spam price (a close/refund path is a later
    /// pass). Placeholder: 1 WEBC.
    pub creation_deposit: Amount,
}

impl Default for NftConfig {
    fn default() -> Self {
        Self {
            // 1 WEBC: a spam-resistant placeholder deposit (§15.22 method), matching
            // the fungible-token creation deposit.
            creation_deposit: Amount::from_webc(1),
        }
    }
}

/// Serializes a byte string as a lowercase hex string (shared by the bounded
/// metadata-field codecs below).
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
        return Err(D::Error::custom("nft field exceeds maximum byte length"));
    }
    if encoded.len() % 2 != 0 {
        return Err(D::Error::custom("nft field hex length must be even"));
    }
    hex::decode(encoded).map_err(D::Error::custom)
}

/// Bounded lowercase-hex codec for the collection name (≤ [`MAX_NFT_NAME_BYTES`]).
pub(crate) mod bounded_name_hex {
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
        super::deserialize_bounded_hex(deserializer, super::MAX_NFT_NAME_BYTES)
    }
}

/// Bounded lowercase-hex codec for the collection symbol (≤ [`MAX_NFT_SYMBOL_BYTES`]).
pub(crate) mod bounded_symbol_hex {
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
        super::deserialize_bounded_hex(deserializer, super::MAX_NFT_SYMBOL_BYTES)
    }
}

/// Opaque, non-secret, namespace-scoped identity of one NFT collection.
///
/// Derived as `SHA-256("WEBC_NFT_COLLECTION_ID_V1" || namespace || creator ||
/// create_nonce_be)`. Binding the `namespace` keeps collection activity isolated by
/// application (§8) and lets two applications create collections under distinct
/// namespaces without contention; binding the `creator` and a creator-chosen
/// `create_nonce` makes creation permissionless and collision-safe — one creator
/// may create many collections under one namespace by varying the nonce, while a
/// repeated `(namespace, creator, create_nonce)` derives the same id and the second
/// creation is rejected as a duplicate. Keying state by this fixed-size id keeps
/// state keys bounded and lets a mint / transfer / burn find its collection in one
/// map probe. A distinct wrapper type keeps a collection id from being mixed with a
/// token id, a bridge asset id, an object id, or a raw hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NftCollectionId(Hash256);

impl NftCollectionId {
    /// Constructs a collection id from a raw 32-byte hash (wire/decoding path).
    pub const fn new(value: Hash256) -> Self {
        Self(value)
    }

    /// Returns the underlying fixed-size identifier used by versioned state keys
    /// and leaf hashing.
    pub const fn hash(self) -> Hash256 {
        self.0
    }

    /// Derives the deterministic id committing to a `(namespace, creator,
    /// create_nonce)` creation.
    ///
    /// Identical inputs derive an identical id on every node; changing any input
    /// (including the `create_nonce`) derives a different id. This is the only way
    /// an id is minted, so a mint / transfer / burn / authority change that names an
    /// id can never address a collection a different creator created.
    pub fn derive(namespace: Hash256, creator: Address, create_nonce: u64) -> Self {
        let nonce = create_nonce.to_be_bytes();
        let parts: [&[u8]; 4] = [
            NFT_COLLECTION_ID_DOMAIN,
            namespace.as_bytes().as_slice(),
            creator.as_bytes().as_slice(),
            nonce.as_slice(),
        ];
        Self(Hash256::digest_many(parts))
    }
}

/// Identity of one NFT item: the `(collection, serial)` PAIR is the id.
///
/// Unlike a collection id (a hash of its creation inputs), an item id is NOT hashed:
/// the pair itself IS the identity, so an item is addressable in a
/// `BTreeMap<NftId, NftItem>` and its per-item state key `(collection_id, serial)`
/// keeps ordinary [`crate::Operation::TransferNft`] parallel-schedulable — a
/// transfer writes only the one item leaf, never one global per-collection object.
/// The derived `Ord` orders first by collection then by serial (a serial is
/// monotonic within its collection), giving a deterministic, contiguous item
/// ordering under one collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NftId {
    /// Collection the item belongs to.
    pub collection: NftCollectionId,
    /// Monotonic per-collection serial assigned at mint; never reused (a burned
    /// serial is never reminted, so this pair is a permanent identity).
    pub serial: u64,
}

impl NftId {
    /// Constructs an item id from its collection and serial.
    pub const fn new(collection: NftCollectionId, serial: u64) -> Self {
        Self { collection, serial }
    }
}

/// Which of a collection's two configurable authorities a transfer/renounce targets.
///
/// The mint authority controls [`crate::Operation::MintNft`] and (by the Phase 13b
/// simplification) [`crate::Operation::SetNftCollectionPaused`]; the freeze
/// authority controls [`crate::Operation::FreezeNftItem`] /
/// [`crate::Operation::ThawNftItem`]. Either may be transferred to a new holder or
/// permanently renounced through [`crate::Operation::SetNftAuthority`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NftAuthorityKind {
    /// The mint (and pause) authority.
    Mint,
    /// The freeze/thaw authority.
    Freeze,
}

/// Canonical, bounded metadata describing one NFT collection.
///
/// Keyed inside an [`NftCollection`]. Holds the human-readable name and symbol and a
/// fixed-size commitment to off-chain collection metadata (a content hash, e.g. of a
/// collection banner / description document). Every variable-length field is
/// bounded; `metadata_hash` is fixed 32 bytes and needs no bound.
///
/// Invariants (checked by [`NftMetadata::validate`], re-checked on any state load or
/// record write in `state`):
/// - `name` is non-empty and at most [`MAX_NFT_NAME_BYTES`] bytes;
/// - `symbol` is non-empty and at most [`MAX_NFT_SYMBOL_BYTES`] bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NftMetadata {
    /// Human-readable collection name, lowercase hex on the wire
    /// (non-empty, ≤ [`MAX_NFT_NAME_BYTES`] bytes).
    #[serde(with = "bounded_name_hex")]
    pub name: Vec<u8>,
    /// Ticker symbol, lowercase hex on the wire
    /// (non-empty, ≤ [`MAX_NFT_SYMBOL_BYTES`] bytes).
    #[serde(with = "bounded_symbol_hex")]
    pub symbol: Vec<u8>,
    /// Fixed-size commitment to off-chain collection metadata (a content hash). The
    /// chain stores only the commitment; the referenced document lives off-chain.
    pub metadata_hash: Hash256,
}

impl NftMetadata {
    /// Creates and validates a metadata record.
    ///
    /// Returns [`ChainError::InvalidNftMetadata`] on an empty or over-length
    /// name/symbol.
    pub fn new(name: Vec<u8>, symbol: Vec<u8>, metadata_hash: Hash256) -> Result<Self, ChainError> {
        let metadata = Self {
            name,
            symbol,
            metadata_hash,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    /// Re-validates the bounded-field invariants.
    ///
    /// Rejects an empty or over-length name/symbol. A hostile decode or a state load
    /// could otherwise smuggle an over-length record in, so this is called on every
    /// create and record construction.
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.name.is_empty() || self.name.len() > MAX_NFT_NAME_BYTES {
            return Err(ChainError::InvalidNftMetadata);
        }
        if self.symbol.is_empty() || self.symbol.len() > MAX_NFT_SYMBOL_BYTES {
            return Err(ChainError::InvalidNftMetadata);
        }
        Ok(())
    }
}

/// Per-collection authority and supply record.
///
/// Keyed in [`crate::ChainState::nft_collections`] by [`NftCollectionId`]. Holds the
/// collection's creator, its validated [`NftMetadata`], its two configurable
/// authorities, the paused flag, the monotonic mint counter, the minted/burned
/// running counts, the optional supply cap, and the royalty-basis-points commitment.
///
/// Authorities are `Option<Address>` so that RENOUNCING a power is representable and
/// PERMANENT: a `Some -> None` transition (through
/// [`crate::Operation::SetNftAuthority`]) can never be reversed — a `None` authority
/// has nothing to transfer, so no operation can put an address back (a Phase 13
/// acceptance criterion, "revoked authority cannot return", enforced by `state`).
/// `None` therefore means the power is permanently disabled: a collection with
/// `mint_authority == None` can never mint again, and one with
/// `freeze_authority == None` can never freeze again.
///
/// Invariant: `minted_count - burned_count` equals the number of LIVE
/// [`crate::ChainState::nft_items`] entries for this collection (the per-collection
/// item invariant, checked by `ChainState::nft_collection_supply_report`). NFT items
/// are not fungible balances and are NOT part of the native WEBC supply
/// reconciliation.
///
/// Monotonic-serial invariant: `next_serial` only ever grows (each mint assigns
/// `next_serial` then increments it), so a burned serial is never reminted and every
/// [`NftId`] is a permanent identity. `next_serial == minted_count` always holds
/// (serials start at zero and both advance in lockstep), but both are recorded — one
/// for the next assignment, one for provenance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NftCollection {
    /// Account that created the collection (immutable; recorded for provenance).
    pub creator: Address,
    /// Validated bounded metadata (name, symbol, off-chain commitment).
    pub metadata: NftMetadata,
    /// Current mint (and pause) authority; `None` means minting is permanently
    /// renounced.
    pub mint_authority: Option<Address>,
    /// Current freeze/thaw authority; `None` means freezing is permanently
    /// renounced.
    pub freeze_authority: Option<Address>,
    /// Whether the collection is currently paused (mint authority-controlled). A
    /// paused collection rejects BOTH [`crate::Operation::MintNft`] and
    /// [`crate::Operation::TransferNft`] (see `state` for the exact gates); burning
    /// an item is still permitted so a paused collection never strands an owner.
    pub paused: bool,
    /// Next serial to assign on mint; monotonically increasing, NEVER decremented
    /// (so a burned serial is never reminted).
    pub next_serial: u64,
    /// Total items ever minted in this collection.
    pub minted_count: u64,
    /// Total items ever burned in this collection.
    pub burned_count: u64,
    /// Optional hard cap on the total number of items ever minted (`None` = no cap).
    /// A mint is rejected once `minted_count` reaches this cap; because burned
    /// serials are never reminted, burning does not free capacity.
    pub max_supply: Option<u64>,
    /// Creator royalty commitment, in basis points (≤ [`MAX_NFT_ROYALTY_BPS`]).
    /// A metadata/commitment field only: the chain records it but does NOT enforce
    /// it on transfer — royalty enforcement is a marketplace/later concern (§15).
    pub royalty_bps: u16,
}

impl NftCollection {
    /// Creates a freshly created, validated collection record with the given
    /// authorities, supply cap, and royalty commitment.
    ///
    /// Validates the embedded metadata and the royalty range; id derivation,
    /// duplicate rejection, and the deposit lock are the caller's (`state`'s)
    /// concern. Starts with `paused == false`, `next_serial == 0`,
    /// `minted_count == 0`, and `burned_count == 0`. Returns
    /// [`ChainError::InvalidNftMetadata`] on malformed metadata or an out-of-range
    /// `royalty_bps`.
    pub fn new(
        creator: Address,
        metadata: NftMetadata,
        mint_authority: Option<Address>,
        freeze_authority: Option<Address>,
        max_supply: Option<u64>,
        royalty_bps: u16,
    ) -> Result<Self, ChainError> {
        metadata.validate()?;
        if royalty_bps > MAX_NFT_ROYALTY_BPS {
            return Err(ChainError::InvalidNftMetadata);
        }
        Ok(Self {
            creator,
            metadata,
            mint_authority,
            freeze_authority,
            paused: false,
            next_serial: 0,
            minted_count: 0,
            burned_count: 0,
            max_supply,
            royalty_bps,
        })
    }

    /// Returns the number of live items implied by the running counters
    /// (`minted_count - burned_count`), or [`ChainError::ArithmeticOverflow`] if the
    /// counters are inconsistent (which the state transitions never allow, since
    /// every burn is preceded by a mint).
    pub fn live_count(&self) -> Result<u64, ChainError> {
        self.minted_count
            .checked_sub(self.burned_count)
            .ok_or(ChainError::ArithmeticOverflow)
    }
}

/// Persistent per-item ownership record.
///
/// Keyed in [`crate::ChainState::nft_items`] by [`NftId`]. An NFT item is owned by
/// EXACTLY ONE address — single-owner ownership is the whole point (mirroring
/// [`crate::object::ObjectOwner::Address`]). The `frozen` flag is stored ON the item
/// (there is no separate freeze set), so the transfer/burn value path reads the same
/// key it writes and the declared access list stays exact.
///
/// Invariants:
/// - a `frozen` item can be neither transferred nor burned until thawed;
/// - the item exists iff it was minted and not yet burned (a burn REMOVES the entry).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NftItem {
    /// The single account that owns (and may transfer/burn) this item.
    pub owner: Address,
    /// Fixed-size commitment to this item's off-chain metadata (a content hash).
    pub item_metadata_hash: Hash256,
    /// Whether the item is frozen (freeze authority-controlled). A frozen item
    /// cannot be transferred or burned.
    pub frozen: bool,
}

impl NftItem {
    /// Creates a freshly minted item owned by `owner`, not frozen.
    pub const fn new_owned(owner: Address, item_metadata_hash: Hash256) -> Self {
        Self {
            owner,
            item_metadata_hash,
            frozen: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webc_crypto::Keypair;

    fn creator() -> Address {
        Keypair::from_seed([61u8; 32]).address()
    }

    fn sample_metadata() -> NftMetadata {
        NftMetadata::new(b"Acme Apes".to_vec(), b"APE".to_vec(), Hash256([0x2f; 32]))
            .expect("valid metadata")
    }

    #[test]
    fn collection_id_derivation_is_deterministic_and_input_separated() {
        let ns = Hash256([0x55; 32]);
        let c = creator();
        assert_eq!(
            NftCollectionId::derive(ns, c, 0),
            NftCollectionId::derive(ns, c, 0)
        );
        // A different create nonce, creator, or namespace yields a distinct id.
        assert_ne!(
            NftCollectionId::derive(ns, c, 0),
            NftCollectionId::derive(ns, c, 1)
        );
        assert_ne!(
            NftCollectionId::derive(ns, c, 0),
            NftCollectionId::derive(Hash256([0x56; 32]), c, 0)
        );
        let other = Keypair::from_seed([62u8; 32]).address();
        assert_ne!(
            NftCollectionId::derive(ns, c, 0),
            NftCollectionId::derive(ns, other, 0)
        );
        // Domain-separated from the bare creator bytes.
        assert_ne!(NftCollectionId::derive(ns, c, 0).hash().0, c.0);
    }

    #[test]
    fn nft_id_orders_by_collection_then_serial() {
        let a = NftCollectionId::new(Hash256([0x01; 32]));
        let b = NftCollectionId::new(Hash256([0x02; 32]));
        // Within one collection, serials order numerically.
        assert!(NftId::new(a, 1) < NftId::new(a, 2));
        // A lower collection id orders before a higher one regardless of serial.
        assert!(NftId::new(a, u64::MAX) < NftId::new(b, 0));
    }

    #[test]
    fn metadata_bounds_are_enforced() {
        // Empty name / symbol rejected.
        let mut m = sample_metadata();
        m.name.clear();
        assert!(matches!(m.validate(), Err(ChainError::InvalidNftMetadata)));
        let mut m = sample_metadata();
        m.symbol.clear();
        assert!(matches!(m.validate(), Err(ChainError::InvalidNftMetadata)));
        // Over-length name / symbol rejected.
        let mut m = sample_metadata();
        m.name = vec![0x61; MAX_NFT_NAME_BYTES + 1];
        assert!(matches!(m.validate(), Err(ChainError::InvalidNftMetadata)));
        let mut m = sample_metadata();
        m.symbol = vec![0x61; MAX_NFT_SYMBOL_BYTES + 1];
        assert!(matches!(m.validate(), Err(ChainError::InvalidNftMetadata)));
    }

    #[test]
    fn out_of_range_royalty_is_rejected() {
        let err = NftCollection::new(
            creator(),
            sample_metadata(),
            Some(creator()),
            None,
            None,
            MAX_NFT_ROYALTY_BPS + 1,
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::InvalidNftMetadata));
        // The maximum is accepted.
        assert!(NftCollection::new(
            creator(),
            sample_metadata(),
            Some(creator()),
            None,
            None,
            MAX_NFT_ROYALTY_BPS,
        )
        .is_ok());
    }

    #[test]
    fn metadata_round_trips_and_rejects_unknown_fields() {
        let metadata = sample_metadata();
        let text = serde_json::to_string(&metadata).expect("metadata serializes");
        let decoded: NftMetadata = serde_json::from_str(&text).expect("metadata decodes");
        assert_eq!(decoded, metadata);
        // The name is lowercase hex on the wire.
        assert!(text.contains(&format!("\"name\":\"{}\"", hex::encode("Acme Apes"))));
        // Strict decode: an unexpected field is rejected on hostile input.
        let mut value = serde_json::to_value(&metadata).expect("to value");
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<NftMetadata>(value).is_err());
    }

    #[test]
    fn over_length_name_hex_is_rejected_before_decode() {
        // The bounded codec rejects an over-length hex string before allocation.
        let metadata = sample_metadata();
        let mut value = serde_json::to_value(&metadata).expect("to value");
        value["name"] = serde_json::Value::String("61".repeat(MAX_NFT_NAME_BYTES + 1));
        assert!(serde_json::from_value::<NftMetadata>(value).is_err());
    }

    #[test]
    fn collection_record_round_trips_and_rejects_unknown_fields() {
        let record = NftCollection::new(
            creator(),
            sample_metadata(),
            Some(creator()),
            None,
            Some(10_000),
            500,
        )
        .expect("valid record");
        assert!(!record.paused);
        assert_eq!(record.next_serial, 0);
        assert_eq!(record.minted_count, 0);
        assert_eq!(record.burned_count, 0);
        assert_eq!(record.live_count().unwrap(), 0);
        assert_eq!(record.freeze_authority, None);
        let text = serde_json::to_string(&record).expect("record serializes");
        let decoded: NftCollection = serde_json::from_str(&text).expect("record decodes");
        assert_eq!(decoded, record);
        let mut value = serde_json::to_value(&record).expect("to value");
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<NftCollection>(value).is_err());
    }

    #[test]
    fn item_record_round_trips_and_rejects_unknown_fields() {
        let item = NftItem::new_owned(creator(), Hash256([0x3a; 32]));
        assert!(!item.frozen);
        let text = serde_json::to_string(&item).expect("item serializes");
        let decoded: NftItem = serde_json::from_str(&text).expect("item decodes");
        assert_eq!(decoded, item);
        let mut value = serde_json::to_value(&item).expect("to value");
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<NftItem>(value).is_err());
    }
}
