//! Native FUNGIBLE TOKEN system: low-cost, permissionless creation of
//! application-defined fungible assets with configurable authorities
//! (WEBC-DEFINITION §15; `docs/development-plan.md` "Phase 13: tokens, NFTs, and
//! application governance").
//!
//! Purpose: let anyone mint a self-contained fungible token — its own name,
//! symbol, decimals, and off-chain metadata commitment — for a spam-priced native
//! deposit, then mint / burn / transfer / freeze / pause it and transfer or
//! permanently renounce its authorities. This is a DISTINCT identity space from
//! the production bridge: a token is a [`TokenId`] (never a bridge `AssetId`) and
//! its balances live in their own map (never `asset_balances`), so native-token
//! supply accounting stays isolated from the bridge trust model and the SDK's
//! bridge codec.
//!
//! Responsibilities: define the token identity ([`TokenId`]) and its deterministic
//! namespace-scoped derivation, the canonical metadata record ([`TokenMetadata`])
//! with every variable-length field BOUNDED, the per-token authority/supply record
//! ([`TokenRecord`]), the authority discriminant ([`TokenAuthorityKind`]), the
//! length/range bounds ([`MAX_TOKEN_NAME_BYTES`] and siblings), and the three
//! Merkle sub-root domains that commit the token map, the balance map, and the
//! frozen-account set to the state root ([`TOKEN_LEAF_DOMAIN`],
//! [`TOKEN_BALANCE_LEAF_DOMAIN`], [`FROZEN_TOKEN_LEAF_DOMAIN`]).
//!
//! Non-responsibilities: this module never moves native WEBC supply, never touches
//! native accounts, and never reads a wall clock, network, files, or randomness.
//! The `state` module owns the committed `tokens` / `token_balances` /
//! `frozen_token_accounts` collections, the `token_deposits` locked bucket, every
//! create / mint / burn / transfer / freeze / pause / authority state transition,
//! and the state-commitment / access-list wiring; it consumes the pure
//! identifiers, records, and validation here. NFTs and application governance are
//! SEPARATE later passes (Phase 13b/13c) and are deliberately not built here.
//!
//! Security boundary: every field of a [`TokenMetadata`] is untrusted — the name
//! and symbol are length-bounded on decode *and* re-checked by
//! [`TokenMetadata::validate`], and the decimals are range-bounded, so a hostile
//! record cannot size an allocation or smuggle an over-length/out-of-range record
//! past a state load. Authorities are `Option<Address>`: `None` means the power is
//! permanently RENOUNCED, and revocation (`Some -> None`) can never be undone — a
//! Phase 13 acceptance criterion ("revoked authority cannot return"), enforced by
//! `state`. Token creation locks a native WEBC deposit (an anti-spam price) but
//! NEVER mints or burns native WEBC; token mint/burn move only the token's own
//! [`TokenRecord::issued_supply`] and never touch native supply. This path is a
//! devnet prototype and is disabled for real funds.

use crate::{Amount, ChainError};
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use webc_crypto::{Address, Hash256};

/// Domain tag hashed into a token's opaque, namespace-scoped identity.
///
/// Domain separation keeps a token id from colliding with an address, a service
/// id, a feed id, a mandate id, or any other 32-byte WEBC artifact derived from
/// the same inputs. Changing it is a consensus-format break.
const TOKEN_ID_DOMAIN: &[u8] = b"WEBC_TOKEN_ID_V1";

/// Domain tag for the token-registry Merkle sub-root committed by the state root.
///
/// Each `(TokenId, TokenRecord)` entry is a leaf under this domain, so a create,
/// mint, burn, pause, or authority change (each of which rewrites the record)
/// moves the state root. Bumping this constant is a consensus-format change.
pub const TOKEN_LEAF_DOMAIN: &[u8] = b"WEBC_TOKEN_LEAF_V1";

/// Domain tag for the token-balance Merkle sub-root committed by the state root.
///
/// Each `((TokenId, Address), Amount)` entry is a leaf under this domain, so any
/// balance credit/debit changes the state root. The per-`(token, addr)` leaf is
/// what keeps ordinary transfers parallel-schedulable — a transfer writes only the
/// two account balance leaves, never one global per-token object. Bumping this
/// constant is a consensus-format change.
pub const TOKEN_BALANCE_LEAF_DOMAIN: &[u8] = b"WEBC_TOKEN_BALANCE_LEAF_V1";

/// Domain tag for the frozen-account Merkle sub-root committed by the state root.
///
/// Each frozen `(TokenId, Address)` pair is a leaf under this domain, so a freeze
/// or thaw changes the state root. Only currently-frozen pairs are present, so the
/// committed set stays bounded. Bumping this constant is a consensus-format change.
pub const FROZEN_TOKEN_LEAF_DOMAIN: &[u8] = b"WEBC_FROZEN_TOKEN_LEAF_V1";

/// Maximum bytes in a token's human-readable name.
///
/// Bounds the per-record name so a hostile record cannot inflate committed state
/// or size a name allocation. Enforced on decode by [`bounded_name_hex`] and
/// re-checked by [`TokenMetadata::validate`].
pub const MAX_TOKEN_NAME_BYTES: usize = 32;

/// Maximum bytes in a token's ticker symbol.
pub const MAX_TOKEN_SYMBOL_BYTES: usize = 12;

/// Maximum number of fractional decimal places a token may declare.
///
/// Bounds `decimals` so wallet/decimal math on a token amount cannot be handed an
/// absurd exponent. `18` matches the widely-used ERC-20 ceiling.
pub const MAX_TOKEN_DECIMALS: u8 = 18;

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
        return Err(D::Error::custom("token field exceeds maximum byte length"));
    }
    if encoded.len() % 2 != 0 {
        return Err(D::Error::custom("token field hex length must be even"));
    }
    hex::decode(encoded).map_err(D::Error::custom)
}

/// Bounded lowercase-hex codec for the token name (≤ [`MAX_TOKEN_NAME_BYTES`]).
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
        super::deserialize_bounded_hex(deserializer, super::MAX_TOKEN_NAME_BYTES)
    }
}

/// Bounded lowercase-hex codec for the token symbol (≤ [`MAX_TOKEN_SYMBOL_BYTES`]).
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
        super::deserialize_bounded_hex(deserializer, super::MAX_TOKEN_SYMBOL_BYTES)
    }
}

/// Opaque, non-secret, namespace-scoped identity of one native token.
///
/// Derived as `SHA-256("WEBC_TOKEN_ID_V1" || namespace || creator ||
/// create_nonce_be)`. Binding the `namespace` keeps token activity isolated by
/// application (§8) and lets two applications create tokens under distinct
/// namespaces without contention; binding the `creator` and a creator-chosen
/// `create_nonce` makes creation permissionless and collision-safe — one creator
/// may create many tokens under one namespace by varying the nonce, while a
/// repeated `(namespace, creator, create_nonce)` derives the same id and the
/// second creation is rejected as a duplicate. Keying state by this fixed-size id
/// keeps state keys bounded and lets a mint/burn/transfer find its record in one
/// map probe. A distinct wrapper type keeps a token id from being mixed with a
/// bridge asset id, a service id, an object id, or a raw hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TokenId(Hash256);

impl TokenId {
    /// Constructs a token id from a raw 32-byte hash (wire/decoding path).
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
    /// an id is minted, so a mint / burn / transfer / authority change that names
    /// an id can never address a token a different creator created.
    pub fn derive(namespace: Hash256, creator: Address, create_nonce: u64) -> Self {
        let nonce = create_nonce.to_be_bytes();
        let parts: [&[u8]; 4] = [
            TOKEN_ID_DOMAIN,
            namespace.as_bytes().as_slice(),
            creator.as_bytes().as_slice(),
            nonce.as_slice(),
        ];
        Self(Hash256::digest_many(parts))
    }
}

/// Which of a token's two configurable authorities a transfer/renounce targets.
///
/// The mint authority controls [`crate::Operation::MintToken`] and (by the Phase
/// 13a simplification) [`crate::Operation::SetTokenPaused`]; the freeze authority
/// controls [`crate::Operation::FreezeTokenAccount`] /
/// [`crate::Operation::ThawTokenAccount`]. Either may be transferred to a new
/// holder or permanently renounced through [`crate::Operation::SetTokenAuthority`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenAuthorityKind {
    /// The mint (and pause) authority.
    Mint,
    /// The freeze/thaw authority.
    Freeze,
}

/// Canonical, bounded metadata describing one token.
///
/// Keyed inside a [`TokenRecord`]. Holds the human-readable name and symbol, the
/// fractional `decimals`, and a fixed-size commitment to off-chain metadata (a
/// content hash, e.g. of a token icon / extended description document). Every
/// variable-length field is bounded; `metadata_hash` is fixed 32 bytes and needs
/// no bound.
///
/// Invariants (checked by [`TokenMetadata::validate`], re-checked on any state
/// load or record write in `state`):
/// - `name` is non-empty and at most [`MAX_TOKEN_NAME_BYTES`] bytes;
/// - `symbol` is non-empty and at most [`MAX_TOKEN_SYMBOL_BYTES`] bytes;
/// - `decimals` is at most [`MAX_TOKEN_DECIMALS`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenMetadata {
    /// Human-readable token name, lowercase hex on the wire
    /// (non-empty, ≤ [`MAX_TOKEN_NAME_BYTES`] bytes).
    #[serde(with = "bounded_name_hex")]
    pub name: Vec<u8>,
    /// Ticker symbol, lowercase hex on the wire
    /// (non-empty, ≤ [`MAX_TOKEN_SYMBOL_BYTES`] bytes).
    #[serde(with = "bounded_symbol_hex")]
    pub symbol: Vec<u8>,
    /// Number of fractional decimal places (≤ [`MAX_TOKEN_DECIMALS`]).
    pub decimals: u8,
    /// Fixed-size commitment to off-chain metadata (a content hash). The chain
    /// stores only the commitment; the referenced document lives off-chain.
    pub metadata_hash: Hash256,
}

impl TokenMetadata {
    /// Creates and validates a metadata record.
    ///
    /// Returns [`ChainError::InvalidTokenMetadata`] on an empty or over-length
    /// name/symbol or an out-of-range `decimals`.
    pub fn new(
        name: Vec<u8>,
        symbol: Vec<u8>,
        decimals: u8,
        metadata_hash: Hash256,
    ) -> Result<Self, ChainError> {
        let metadata = Self {
            name,
            symbol,
            decimals,
            metadata_hash,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    /// Re-validates the bounded-field invariants.
    ///
    /// Rejects an empty or over-length name/symbol and out-of-range `decimals`. A
    /// hostile decode or a state load could otherwise smuggle an over-length or
    /// out-of-range record in, so this is called on every create and state load.
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.name.is_empty() || self.name.len() > MAX_TOKEN_NAME_BYTES {
            return Err(ChainError::InvalidTokenMetadata);
        }
        if self.symbol.is_empty() || self.symbol.len() > MAX_TOKEN_SYMBOL_BYTES {
            return Err(ChainError::InvalidTokenMetadata);
        }
        if self.decimals > MAX_TOKEN_DECIMALS {
            return Err(ChainError::InvalidTokenMetadata);
        }
        Ok(())
    }
}

/// Per-token authority and supply record.
///
/// Keyed in [`crate::ChainState::tokens`] by [`TokenId`]. Holds the token's
/// creator, its validated [`TokenMetadata`], its two configurable authorities, the
/// paused flag, and the running issued supply.
///
/// Authorities are `Option<Address>` so that RENOUNCING a power is representable
/// and PERMANENT: a `Some -> None` transition (through
/// [`crate::Operation::SetTokenAuthority`]) can never be reversed — a `None`
/// authority has nothing to transfer, so no operation can put an address back
/// (a Phase 13 acceptance criterion, "revoked authority cannot return", enforced
/// by `state`). `None` therefore means the power is permanently disabled: a token
/// with `mint_authority == None` can never mint again, and one with
/// `freeze_authority == None` can never freeze again.
///
/// Invariant: `issued_supply` equals the total minted minus the total burned for
/// this token, which `state` keeps equal to the sum of every
/// [`crate::ChainState::token_balances`] entry for this token (the per-token supply
/// invariant, checked by `ChainState::token_supply_report`). Token supply is a
/// SEPARATE asset from native WEBC and never enters the native supply
/// reconciliation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRecord {
    /// Account that created the token (immutable; recorded for provenance).
    pub creator: Address,
    /// Validated bounded metadata (name, symbol, decimals, off-chain commitment).
    pub metadata: TokenMetadata,
    /// Current mint (and pause) authority; `None` means minting is permanently
    /// renounced.
    pub mint_authority: Option<Address>,
    /// Current freeze/thaw authority; `None` means freezing is permanently
    /// renounced.
    pub freeze_authority: Option<Address>,
    /// Whether transfers are currently paused (mint authority-controlled).
    pub paused: bool,
    /// Total minted minus total burned (the token's outstanding supply).
    pub issued_supply: Amount,
}

impl TokenRecord {
    /// Creates a freshly created, validated record with the given authorities and
    /// initial issued supply.
    ///
    /// Validates the embedded metadata; id derivation, duplicate rejection, the
    /// deposit lock, and any initial mint are the caller's (`state`'s) concern.
    /// Returns [`ChainError::InvalidTokenMetadata`] on malformed metadata.
    pub fn new(
        creator: Address,
        metadata: TokenMetadata,
        mint_authority: Option<Address>,
        freeze_authority: Option<Address>,
        issued_supply: Amount,
    ) -> Result<Self, ChainError> {
        metadata.validate()?;
        Ok(Self {
            creator,
            metadata,
            mint_authority,
            freeze_authority,
            paused: false,
            issued_supply,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webc_crypto::Keypair;

    fn creator() -> Address {
        Keypair::from_seed([41u8; 32]).address()
    }

    fn sample_metadata() -> TokenMetadata {
        TokenMetadata::new(b"Acme Dollar".to_vec(), b"ACME".to_vec(), 6, Hash256([0x1f; 32]))
            .expect("valid metadata")
    }

    #[test]
    fn id_derivation_is_deterministic_and_input_separated() {
        let ns = Hash256([0x55; 32]);
        let c = creator();
        assert_eq!(TokenId::derive(ns, c, 0), TokenId::derive(ns, c, 0));
        // A different create nonce, creator, or namespace yields a distinct id.
        assert_ne!(TokenId::derive(ns, c, 0), TokenId::derive(ns, c, 1));
        assert_ne!(
            TokenId::derive(ns, c, 0),
            TokenId::derive(Hash256([0x56; 32]), c, 0)
        );
        let other = Keypair::from_seed([42u8; 32]).address();
        assert_ne!(TokenId::derive(ns, c, 0), TokenId::derive(ns, other, 0));
        // Domain-separated from the bare creator bytes.
        assert_ne!(TokenId::derive(ns, c, 0).hash().0, c.0);
    }

    #[test]
    fn metadata_bounds_are_enforced() {
        // Empty name / symbol rejected.
        let mut m = sample_metadata();
        m.name.clear();
        assert!(matches!(m.validate(), Err(ChainError::InvalidTokenMetadata)));
        let mut m = sample_metadata();
        m.symbol.clear();
        assert!(matches!(m.validate(), Err(ChainError::InvalidTokenMetadata)));
        // Over-length name / symbol rejected.
        let mut m = sample_metadata();
        m.name = vec![0x61; MAX_TOKEN_NAME_BYTES + 1];
        assert!(matches!(m.validate(), Err(ChainError::InvalidTokenMetadata)));
        let mut m = sample_metadata();
        m.symbol = vec![0x61; MAX_TOKEN_SYMBOL_BYTES + 1];
        assert!(matches!(m.validate(), Err(ChainError::InvalidTokenMetadata)));
        // Out-of-range decimals rejected.
        let mut m = sample_metadata();
        m.decimals = MAX_TOKEN_DECIMALS + 1;
        assert!(matches!(m.validate(), Err(ChainError::InvalidTokenMetadata)));
    }

    #[test]
    fn metadata_round_trips_and_rejects_unknown_fields() {
        let metadata = sample_metadata();
        let text = serde_json::to_string(&metadata).expect("metadata serializes");
        let decoded: TokenMetadata = serde_json::from_str(&text).expect("metadata decodes");
        assert_eq!(decoded, metadata);
        // The name is lowercase hex on the wire.
        assert!(text.contains(&format!("\"name\":\"{}\"", hex::encode("Acme Dollar"))));
        // Strict decode: an unexpected field is rejected on hostile input.
        let mut value = serde_json::to_value(&metadata).expect("to value");
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<TokenMetadata>(value).is_err());
    }

    #[test]
    fn over_length_name_hex_is_rejected_before_decode() {
        // The bounded codec rejects an over-length hex string before allocation.
        let metadata = sample_metadata();
        let mut value = serde_json::to_value(&metadata).expect("to value");
        value["name"] = serde_json::Value::String("61".repeat(MAX_TOKEN_NAME_BYTES + 1));
        assert!(serde_json::from_value::<TokenMetadata>(value).is_err());
    }

    #[test]
    fn record_round_trips_and_rejects_unknown_fields() {
        let record = TokenRecord::new(
            creator(),
            sample_metadata(),
            Some(creator()),
            None,
            Amount::from_units(1_000),
        )
        .expect("valid record");
        assert!(!record.paused);
        assert_eq!(record.freeze_authority, None);
        let text = serde_json::to_string(&record).expect("record serializes");
        let decoded: TokenRecord = serde_json::from_str(&text).expect("record decodes");
        assert_eq!(decoded, record);
        let mut value = serde_json::to_value(&record).expect("to value");
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<TokenRecord>(value).is_err());
    }
}
