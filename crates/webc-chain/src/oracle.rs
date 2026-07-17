//! Native oracle: feed registry, bonded reporters, median aggregation, and
//! accuracy/liveness-weighted read-fee revenue (WEBC-DEFINITION §9, §15.6,
//! §15.17, §15.21; `docs/oracle-economics.md`).
//!
//! Purpose: bring outside data on-chain through many independent reporters whose
//! values the network aggregates by median, so no single reporter dictates the
//! answer, and pay those reporters out of the read fees consuming applications
//! deposit — weighted by how close each was to the accepted median (accuracy)
//! and how recently it reported (liveness).
//!
//! Responsibilities: define the canonical feed record ([`Feed`]), the per-feed
//! bonded-reporter record ([`OracleReporter`]), the integer feed value
//! ([`FeedValue`]) and its overflow-safe median and accuracy/liveness scoring,
//! the protocol parameters ([`OracleConfig`]), the feed identity ([`FeedId`]),
//! and the Merkle sub-root domains that commit the registry and reporter maps to
//! the state root.
//!
//! Non-responsibilities: this module never moves native supply, never touches
//! accounts, and never reads a wall clock, network, files, or randomness. The
//! `state` module owns the committed maps (`oracle_feeds`, `oracle_reporters`),
//! the aggregate locked buckets (`oracle_bonds`, `oracle_revenue`), the
//! create/register/report/pay/settle/deregister state transitions, the
//! epoch-boundary settlement hook, and the state-commitment/access-list wiring;
//! it uses the pure identifiers, records, and scoring here.
//!
//! Determinism: every value is an integer (no float); the median is an
//! overflow-safe lower-mid rule on a sorted `Vec`; accuracy is a checked integer
//! inverse-distance weight; liveness is a checked-arithmetic epoch-window test.
//! Committed collections are `BTreeMap`s in `state`, so iteration order in the
//! hashed/consensus path is deterministic.
//!
//! Security boundary: every input (a submitted value, a paid amount, a feed id,
//! a reporter address) is untrusted. A reporter's BOND is locked native value
//! that the supply invariant accounts for, and a feed's accrued read-fee REVENUE
//! is likewise locked until settlement redistributes it to reporters; both flow
//! supply-neutrally (create/register lock, deregister returns, settle moves pool
//! → reporter liquid with the integer-division remainder carried, never minted
//! or lost). Reporter slashing (persistent-outlier penalties) is deliberately
//! **not** implemented here: §15.6/§15.17 defer slashing mechanics to the
//! security documents, and the slashing severity schedule is an owner-deferred
//! economic decision (ADR-0012 / `docs/decision-record.md`). Outliers instead
//! earn zero revenue (their accuracy weight decays to zero), which is the
//! standing-loss lever the definition specifies without an evidence-graded
//! penalty.

use crate::ChainError;
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use webc_crypto::{Address, Hash256};

/// Domain tag for the feed-registry Merkle sub-root committed by the state root.
///
/// Each `(FeedId, Feed)` entry is a leaf under this domain, so any change to a
/// feed's creator, bond class, or accrued revenue changes the state root.
/// Bumping this constant is a consensus-format change.
pub const ORACLE_FEED_LEAF_DOMAIN: &[u8] = b"WEBC_ORACLE_FEED_LEAF_V1";

/// Domain tag for the reporter-registry Merkle sub-root committed by the state
/// root.
///
/// Each `((FeedId, Address), OracleReporter)` entry is a leaf under this domain,
/// so registering, deregistering, or reporting changes the state root. Bumping
/// this constant is a consensus-format change.
pub const ORACLE_REPORTER_LEAF_DOMAIN: &[u8] = b"WEBC_ORACLE_REPORTER_LEAF_V1";

/// Fixed-point scale for the integer accuracy weight (`weight = SCALE /
/// (distance + 1)`).
///
/// A reporter exactly on the accepted median earns the full `SCALE`; a reporter
/// one unit away earns `SCALE / 2`; a reporter farther than `SCALE` units away
/// earns `0` (integer division floors), so a persistent outlier's revenue decays
/// to zero without any slashing. The scale cancels out of the proportional
/// revenue split, so its only effect is the granularity of accuracy
/// discrimination; `1_000_000` gives fine discrimination while keeping the
/// `revenue * score` intermediate comfortably inside `u128`.
pub const ORACLE_ACCURACY_SCALE: u128 = 1_000_000;

/// Fixed 32-byte identity of one oracle feed.
///
/// Caller-chosen and collision-resistant, exactly like [`crate::ObjectId`]: the
/// creator commits to a feed by an opaque 32-byte id, and the registry rejects a
/// duplicate id. A distinct wrapper type keeps a feed id from being mixed with an
/// object id, a namespace, or a raw hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FeedId(Hash256);

impl FeedId {
    /// Constructs a feed identity from a collision-resistant commitment.
    pub const fn new(hash: Hash256) -> Self {
        Self(hash)
    }

    /// Returns the fixed hash used by versioned state keys and leaf hashing.
    pub const fn hash(self) -> Hash256 {
        self.0
    }
}

/// An integer oracle value in a feed's own units.
///
/// Consensus stores oracle values only as signed integers (`i128`) — never a
/// float, which the canonical encoder rejects and which is nondeterministic
/// across languages. Signed so a feed may carry deltas or values that cross zero
/// (temperatures, spreads); price feeds simply use non-negative values. Like
/// [`crate::Amount`], the human-readable serde form is a decimal string so a
/// browser never loses precision on a value outside the JS safe-integer range,
/// while the binary at-rest/wire form is a native `i128`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FeedValue(pub i128);

impl FeedValue {
    /// Constructs a feed value from an exact signed integer.
    pub const fn new(value: i128) -> Self {
        Self(value)
    }

    /// Returns the exact signed integer value.
    pub const fn get(self) -> i128 {
        self.0
    }

    /// Overflow-safe absolute distance to another value, as an unsigned integer.
    ///
    /// `i128::abs_diff` returns a `u128` and never overflows even for
    /// `i128::MIN`/`i128::MAX`, so hostile extreme values cannot panic the
    /// accuracy scorer.
    pub fn distance(self, other: Self) -> u128 {
        self.0.abs_diff(other.0)
    }
}

impl Serialize for FeedValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            // JSON numbers cannot safely represent values outside ±(2^53-1) in a
            // browser, and the canonical encoder rejects them outright. Use a
            // decimal string of the exact value, matching how `Amount` is encoded.
            serializer.serialize_str(&self.0.to_string())
        } else {
            serializer.serialize_i128(self.0)
        }
    }
}

impl<'de> Deserialize<'de> for FeedValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let value = String::deserialize(deserializer)?;
            let parsed = value.parse::<i128>().map_err(D::Error::custom)?;
            Ok(Self(parsed))
        } else {
            Ok(Self(i128::deserialize(deserializer)?))
        }
    }
}

/// Protocol parameters for the native oracle (§15.35 measurement method).
///
/// The launch values are **testnet-measured placeholders**, not promises — the
/// method (a flat creation fee, a minimum reporter bond, and a fixed settlement
/// cadence with a liveness window) is fixed; the numbers move with data. All
/// fields carry `#[serde(default)]` via the derived `Default` so a genesis
/// written before the oracle stays decodable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleConfig {
    /// Flat fee, in native base units, charged to create a feed. Feed creation is
    /// permissionless *for a fee* (§15.6): anyone may create a feed, but the fee
    /// is burned (liquid → burned) so a creation is never free spam. Placeholder.
    pub feed_creation_fee: crate::Amount,
    /// Minimum bond, in native base units, a reporter locks to register on a feed
    /// (higher-value feeds would demand larger bonds — §2.2). A feed freezes this
    /// value at creation, so a later config change never disturbs live bonds.
    pub min_reporter_bond: crate::Amount,
    /// Number of consensus epochs between read-fee settlements. Every feed's
    /// accrued revenue is distributed when a completed epoch is a multiple of
    /// this cadence. Must be non-zero (validated at genesis). Placeholder.
    pub settlement_epochs: u64,
    /// A reporter counts as *live* at a settlement if its latest report is no
    /// older than this many epochs. A reporter that has not reported within the
    /// window earns no liveness reward for that settlement (§2.2). Must be
    /// non-zero (validated at genesis). Placeholder.
    pub liveness_window_epochs: u64,
}

impl Default for OracleConfig {
    fn default() -> Self {
        Self {
            // 1e-3 WEBC: a small anti-spam creation fee, comfortably above an
            // ordinary transaction fee. Measurement-tuned (§15.35).
            feed_creation_fee: crate::Amount::from_units(1_000_000_000),
            // 1 WEBC minimum reporter bond as a placeholder bond-size class.
            min_reporter_bond: crate::Amount::from_webc(1),
            // Settle once per epoch by default; a chain with very short epochs can
            // raise this to batch settlements. Non-zero.
            settlement_epochs: 1,
            // ≈ a handful of epochs of tolerance for a reporter to stay "live".
            liveness_window_epochs: 4,
        }
    }
}

impl OracleConfig {
    /// Rejects a configuration whose settlement cadence or liveness window is zero.
    ///
    /// Called at genesis so a chain never runs with an undefined settlement
    /// boundary (a zero cadence would make `is_multiple_of` divide by zero) or an
    /// undefined liveness window. The settlement path additionally treats a zero
    /// cadence defensively (it never settles), so a bad config fails closed.
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.settlement_epochs == 0 || self.liveness_window_epochs == 0 {
            return Err(ChainError::InvalidOracleConfig);
        }
        Ok(())
    }

    /// Whether a just-completed `epoch` is a settlement boundary for this cadence.
    ///
    /// A zero cadence never settles (defensive: `validate` already rejects it at
    /// genesis, and this avoids a divide-by-zero on a hostile in-memory config).
    pub fn is_settlement_epoch(&self, epoch: u64) -> bool {
        self.settlement_epochs != 0 && epoch.is_multiple_of(self.settlement_epochs)
    }

    /// Whether a report submitted for `reported_epoch` is live at `settlement_epoch`.
    ///
    /// Live iff `reported_epoch + liveness_window_epochs >= settlement_epoch`.
    /// Uses checked addition and treats an overflow (an astronomically large
    /// window) as live, so the test never panics on hostile inputs.
    pub fn report_is_live(&self, reported_epoch: u64, settlement_epoch: u64) -> bool {
        reported_epoch
            .checked_add(self.liveness_window_epochs)
            .is_none_or(|bound| bound >= settlement_epoch)
    }
}

/// Canonical registry record for one oracle feed.
///
/// Keyed in [`crate::ChainState::oracle_feeds`] by [`FeedId`]. Holds the creator,
/// the frozen reporter bond-size class, and the accrued read-fee revenue awaiting
/// settlement. `revenue` is part of the `oracle_revenue` locked supply bucket:
/// [`crate::Operation::PayFeedRead`] moves units here from a consumer's liquid
/// balance, and settlement moves them out to reporters' liquid balances, carrying
/// any integer-division remainder here to the next settlement.
///
/// Invariants:
/// - a `Feed` exists only after an explicit [`crate::Operation::CreateFeed`];
/// - `bond` is immutable after creation, so every reporter on this feed locks and
///   is refunded exactly this amount;
/// - `revenue` is the exact accrued, not-yet-distributed read-fee balance for
///   this feed, and the sum of every feed's `revenue` equals the
///   `oracle_revenue` scalar the supply invariant reconciles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Feed {
    /// Account that created (and paid the creation fee for) this feed.
    pub creator: Address,
    /// Native base units a reporter must bond to register on this feed, frozen at
    /// creation from [`OracleConfig::min_reporter_bond`].
    pub bond: crate::Amount,
    /// Accrued read-fee revenue, in native base units, awaiting settlement.
    pub revenue: crate::Amount,
}

impl Feed {
    /// Creates an empty feed owned by `creator` with the given frozen bond class.
    pub const fn new(creator: Address, bond: crate::Amount) -> Self {
        Self {
            creator,
            bond,
            revenue: crate::Amount::ZERO,
        }
    }
}

/// A bonded reporter's record on one feed.
///
/// Keyed in [`crate::ChainState::oracle_reporters`] by `(FeedId, Address)`. The
/// mere existence of the record means the reporter's bond (its feed's `bond`) is
/// locked in the `oracle_bonds` supply bucket. `value` is the reporter's latest
/// submission, which enters the feed's median once present; `reported_epoch` is
/// the epoch that submission was recorded for, used for the liveness weight.
///
/// Invariant: a reporter record exists only between
/// [`crate::Operation::RegisterReporter`] and
/// [`crate::Operation::DeregisterReporter`]; while it exists, exactly its feed's
/// `bond` is accounted in `oracle_bonds`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleReporter {
    /// Latest submitted value, or `None` until the reporter's first report. A
    /// reporter without a value does not enter the median and earns no revenue.
    pub value: Option<FeedValue>,
    /// Consensus epoch the latest report was submitted for (liveness reference).
    /// Meaningful only when `value` is `Some`.
    pub reported_epoch: u64,
}

impl OracleReporter {
    /// Creates a freshly bonded reporter that has not yet reported a value.
    pub const fn new() -> Self {
        Self {
            value: None,
            reported_epoch: 0,
        }
    }
}

impl Default for OracleReporter {
    fn default() -> Self {
        Self::new()
    }
}

/// Deterministic integer median of a set of feed values, or `None` if empty.
///
/// Tie-break rule (documented and consensus-critical): the values are sorted
/// ascending and the element at index `(n - 1) / 2` is returned. For an odd `n`
/// that is the exact middle; for an even `n` it is the **lower-mid** — the lower
/// of the two central values. Lower-mid is chosen over an averaged-with-floor
/// rule specifically because it needs no arithmetic on the values themselves and
/// therefore cannot overflow on hostile `i128::MIN`/`i128::MAX` inputs, while
/// still guaranteeing the returned median equals some reporter's submitted value
/// (so at least one reporter always has distance zero, keeping total accuracy
/// weight positive).
pub fn median(values: &[FeedValue]) -> Option<FeedValue> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    Some(sorted[(sorted.len() - 1) / 2])
}

/// Integer accuracy weight for a value given the accepted median.
///
/// `weight = ORACLE_ACCURACY_SCALE / (distance + 1)`, where `distance` is the
/// overflow-safe absolute distance from the median. A value on the median earns
/// the full scale; a value farther than the scale earns zero. Never panics
/// (`saturating_add` guards the `+1`, division by a non-zero denominator).
pub fn accuracy_weight(value: FeedValue, median_value: FeedValue) -> u128 {
    let denominator = value.distance(median_value).saturating_add(1);
    ORACLE_ACCURACY_SCALE / denominator
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Amount;

    #[test]
    fn feed_value_json_is_a_decimal_string_and_round_trips() {
        // Large values outside the JS safe-integer range must survive as decimal
        // strings, exactly like `Amount`, so a browser and the canonical encoder
        // never see a bare JSON number they cannot represent.
        for value in [
            FeedValue(0),
            FeedValue(1),
            FeedValue(-1),
            FeedValue(i128::MAX),
            FeedValue(i128::MIN),
        ] {
            let json = serde_json::to_string(&value).expect("serializes");
            assert!(json.starts_with('"'), "human-readable form is a string");
            let decoded: FeedValue = serde_json::from_str(&json).expect("decodes");
            assert_eq!(decoded, value);
        }
        assert_eq!(
            serde_json::to_string(&FeedValue(i128::MAX)).unwrap(),
            format!("\"{}\"", i128::MAX)
        );
    }

    #[test]
    fn feed_value_binary_round_trips() {
        use bincode::Options;
        let options = bincode::DefaultOptions::new().with_varint_encoding();
        for value in [FeedValue(0), FeedValue(-42), FeedValue(i128::MAX)] {
            let bytes = options.serialize(&value).expect("serializes");
            let restored: FeedValue = options.deserialize(&bytes).expect("deserializes");
            assert_eq!(restored, value);
        }
    }

    #[test]
    fn median_odd_even_and_single() {
        assert_eq!(median(&[]), None);
        assert_eq!(median(&[FeedValue(7)]), Some(FeedValue(7)));
        // Odd count: exact middle regardless of input order.
        assert_eq!(
            median(&[FeedValue(9), FeedValue(1), FeedValue(5)]),
            Some(FeedValue(5))
        );
        // Even count: lower-mid (index (n-1)/2 = index 1 of the sorted [2,4,6,8]).
        assert_eq!(
            median(&[FeedValue(8), FeedValue(2), FeedValue(6), FeedValue(4)]),
            Some(FeedValue(4))
        );
    }

    #[test]
    fn median_does_not_overflow_on_extreme_values() {
        // Lower-mid needs no arithmetic on the values, so extremes cannot panic.
        let m = median(&[FeedValue(i128::MIN), FeedValue(i128::MAX)]);
        assert_eq!(m, Some(FeedValue(i128::MIN)));
    }

    #[test]
    fn accuracy_weight_is_full_on_median_and_decays_to_zero() {
        let m = FeedValue(100);
        assert_eq!(accuracy_weight(FeedValue(100), m), ORACLE_ACCURACY_SCALE);
        assert_eq!(
            accuracy_weight(FeedValue(101), m),
            ORACLE_ACCURACY_SCALE / 2
        );
        assert_eq!(accuracy_weight(FeedValue(99), m), ORACLE_ACCURACY_SCALE / 2);
        // Farther than the scale earns nothing — the standing-loss lever.
        assert_eq!(
            accuracy_weight(FeedValue(100 + ORACLE_ACCURACY_SCALE as i128 + 1), m),
            0
        );
        // Extreme distance never panics.
        assert_eq!(
            accuracy_weight(FeedValue(i128::MIN), FeedValue(i128::MAX)),
            0
        );
    }

    #[test]
    fn liveness_window_and_settlement_cadence() {
        let config = OracleConfig {
            settlement_epochs: 3,
            liveness_window_epochs: 2,
            ..OracleConfig::default()
        };
        assert!(config.is_settlement_epoch(0));
        assert!(!config.is_settlement_epoch(1));
        assert!(config.is_settlement_epoch(6));
        // Reported at epoch 8, window 2: live through settlement epoch 10.
        assert!(config.report_is_live(8, 10));
        assert!(!config.report_is_live(8, 11));
        // A zero cadence never settles and validate rejects it.
        let bad = OracleConfig {
            settlement_epochs: 0,
            ..OracleConfig::default()
        };
        assert!(!bad.is_settlement_epoch(10));
        assert!(matches!(
            bad.validate(),
            Err(ChainError::InvalidOracleConfig)
        ));
    }

    #[test]
    fn feed_and_reporter_records_round_trip_and_reject_unknown_fields() {
        let creator = webc_crypto::Keypair::from_seed([3u8; 32]).address();
        let feed = Feed::new(creator, Amount::from_webc(2));
        let text = serde_json::to_string(&feed).expect("feed serializes");
        assert_eq!(serde_json::from_str::<Feed>(&text).unwrap(), feed);
        let mut value = serde_json::to_value(&feed).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Feed>(value).is_err());

        let mut reporter = OracleReporter::new();
        reporter.value = Some(FeedValue(123_456_789_012_345));
        reporter.reported_epoch = 9;
        let text = serde_json::to_string(&reporter).expect("reporter serializes");
        assert_eq!(
            serde_json::from_str::<OracleReporter>(&text).unwrap(),
            reporter
        );
    }
}
