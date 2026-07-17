//! Native DEX order records and the pure uniform-price batch-settlement math
//! (WEBC-DEFINITION §15.13, §15.18, §15.37; `docs/dex-batch-settlement.md`).
//!
//! Purpose: settle every swap on a trading pair together, once per block, at a
//! single uniform clearing price, so no participant can improve their execution
//! by being ordered earlier or later inside the block (sandwich / front-running
//! MEV becomes meaningless). This module owns the *order intent record* and the
//! *pure, deterministic clearing arithmetic*; the state machine owns escrow,
//! account moves, and the per-block settlement hook.
//!
//! Responsibilities: define the order identity ([`OrderId`]), the traded-pair
//! identity ([`TradingPair`]), the order side ([`OrderSide`]), the integer limit
//! price ([`Price`]), the committed order record ([`Order`]), the protocol
//! parameters ([`DexConfig`]), the Merkle sub-root domain that commits the order
//! map to the state root, and the overflow-safe pure functions that compute the
//! uniform clearing price ([`uniform_clearing_price`]) and the dust-free
//! integer pro-rata rationing of the surplus side ([`prorata_fills`]).
//!
//! Non-responsibilities: this module never moves native supply, never touches
//! accounts or asset balances, and never reads a wall clock, network, files, or
//! randomness. The `state` module owns the committed order map (`dex_orders`),
//! the aggregate locked native bucket (`dex_escrow`), the submit/cancel state
//! transitions, the per-block batch-settlement hook (run identically on build and
//! import), and the state-commitment/access-list wiring; it uses the pure
//! identifiers, records, and math here.
//!
//! Determinism: every value is an unsigned integer (no float); the clearing price
//! is a pure function of the aggregated price ladders (a two-pointer crossing scan
//! plus a documented midpoint rule); pro-rata rationing uses a cumulative-rounding
//! rule whose per-order fills provably sum to the target with no dust and never
//! exceed an order's remaining amount. Committed collections are `BTreeMap`s in
//! `state`, so iteration order in the hashed/consensus path is deterministic.
//!
//! Security boundary: every input (a pair, a side, an amount, a limit price, a
//! deadline) is untrusted. An order's LOCKED input is value the supply invariant
//! accounts for (the native leg lives in the `dex_escrow` bucket; a non-native leg
//! is held out of the owner's `asset_balances`), and settlement moves that value
//! between owners plus an optional fee split supply-neutrally — nothing is minted
//! or lost across submit / settle / partial-fill / cancel / expire. Curve/AMM
//! shared-pool pricing, multi-hop routing, and complex slippage are deliberately
//! **not** implemented here: §15.13/§15.18 defer them to later mechanics. This is
//! the coincidence-of-wants (CoW-style) order-crossing core only.

use crate::bridge::AssetId;
use crate::{Amount, ChainError};
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use webc_crypto::{Address, Hash256};

/// Domain tag for the DEX order-registry Merkle sub-root committed by the state
/// root.
///
/// Each `(OrderId, Order)` entry is a leaf under this domain, so submitting,
/// filling (partially or fully), cancelling, or expiring an order changes the
/// state root. Bumping this constant is a consensus-format change.
pub const DEX_ORDER_LEAF_DOMAIN: &[u8] = b"WEBC_DEX_ORDER_LEAF_V1";

/// Fixed 32-byte identity of one DEX order intent.
///
/// Caller-chosen and collision-resistant, exactly like [`crate::ObjectId`] and
/// [`crate::FeedId`]: the submitter commits to an order by an opaque 32-byte id,
/// the registry rejects a duplicate live id, and the signed access list can name
/// the order's state key up front (the id is known at signing time, unlike a
/// server-assigned monotonic counter). A distinct wrapper type keeps an order id
/// from being mixed with an object id, a feed id, or a raw hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OrderId(Hash256);

impl OrderId {
    /// Constructs an order identity from a collision-resistant commitment.
    pub const fn new(hash: Hash256) -> Self {
        Self(hash)
    }

    /// Returns the fixed hash used by versioned state keys and leaf hashing.
    pub const fn hash(self) -> Hash256 {
        self.0
    }
}

/// Direction of an order relative to a pair's base asset.
///
/// Both sides denominate `amount` in the pair's **base** asset. A `Buy` acquires
/// base and pays quote (locks quote); a `Sell` disposes of base and receives
/// quote (locks base). This mirrors an ordinary limit order book: a buy names the
/// most it will pay per base unit, a sell the least it will accept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OrderSide {
    /// Acquire `amount` base, paying at most `limit_price` quote per base unit.
    Buy,
    /// Dispose of `amount` base, receiving at least `limit_price` quote per base unit.
    Sell,
}

/// An oriented trading pair: `amount` is denominated in `base`, price in `quote`.
///
/// A market is oriented by `(base, quote)`: buy/sell are expressed with `base` as
/// the traded quantity and `quote` as the means of payment. `base` and `quote`
/// must differ. Orders only match other orders on the exact same `(base, quote)`
/// pair — the module does not auto-merge `(A, B)` with `(B, A)` (that would need
/// fractional price inversion; the canonical shared-pool registry that would pick
/// one orientation is deferred, §15.13). Two distinct pairs settle independently.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradingPair {
    /// Asset whose quantity `amount` measures and that a buy acquires / a sell disposes.
    pub base: AssetId,
    /// Asset used to pay for the base; a limit price is in quote base-units per base base-unit.
    pub quote: AssetId,
}

impl TradingPair {
    /// Constructs a pair; use [`TradingPair::validate`] before trusting it.
    pub const fn new(base: AssetId, quote: AssetId) -> Self {
        Self { base, quote }
    }

    /// Rejects a degenerate pair whose base and quote are the same asset.
    ///
    /// A pair of an asset with itself has no meaningful price and could let escrow
    /// accounting double up on one asset, so it is refused before any state change.
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.base == self.quote {
            return Err(ChainError::InvalidTradingPair);
        }
        Ok(())
    }
}

/// An integer limit/clearing price: quote base-units per one base base-unit.
///
/// Consensus prices are exact unsigned integers — never a float, which the
/// canonical encoder rejects and which is nondeterministic across languages. A
/// price of `p` means one base base-unit costs exactly `p` quote base-units, so
/// the quote locked/settled for `q` base units is exactly `q * p` with no rounding
/// on the value leg (only the pro-rata *quantity* leg rounds, and that is
/// dust-free — see [`prorata_fills`]). Finer sub-unit tick sizes (a price scale)
/// are a deferred refinement; the batch semantics are unaffected by the tick size.
/// Like [`Amount`], the human-readable serde form is a decimal string so a browser
/// never loses precision on a value outside the JS safe-integer range, while the
/// binary at-rest/wire form is a native `u128`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Price(pub u128);

impl Price {
    /// Constructs a price from exact quote-base-units per base-base-unit.
    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    /// Returns the exact integer price.
    pub const fn get(self) -> u128 {
        self.0
    }

    /// Whether the price is zero (an invalid limit — rejected at submit time).
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Quote base-units needed to trade `amount` base units at this price.
    ///
    /// Exact integer `amount * price` with a 256-bit-safe checked multiply
    /// (`checked_mul_ratio(price, 1)` reuses [`Amount`]'s overflow-safe path).
    /// Returns `None` on overflow so hostile amounts/prices fail closed.
    pub fn quote_for(self, amount: Amount) -> Option<Amount> {
        amount.checked_mul_ratio(self.0, 1)
    }
}

impl Serialize for Price {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            // JSON numbers cannot safely represent large u128 values in a browser,
            // and the canonical encoder rejects them. Use a decimal string of the
            // exact value, matching how `Amount` is encoded.
            serializer.serialize_str(&self.0.to_string())
        } else {
            serializer.serialize_u128(self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Price {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let value = String::deserialize(deserializer)?;
            let parsed = value.parse::<u128>().map_err(D::Error::custom)?;
            Ok(Self(parsed))
        } else {
            Ok(Self(u128::deserialize(deserializer)?))
        }
    }
}

/// Protocol parameters for the native DEX (§15.35 measurement method).
///
/// The launch values are **testnet-measured placeholders**, not promises — the
/// method (a minimum order size, a default retry deadline, and an optional
/// per-fill fee) is fixed; the numbers move with data. All fields carry
/// `#[serde(default)]` via the derived `Default` so a genesis written before the
/// DEX stays decodable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DexConfig {
    /// Minimum order size, in base-asset base units. An order below this (or of
    /// zero amount) is rejected at submit. `0` disables the extra floor (a zero
    /// amount is still always rejected). Placeholder.
    pub min_order_amount: Amount,
    /// Default number of blocks an order stays pending when the submitter passes a
    /// deadline height of `0` (the "use the default" sentinel): the effective
    /// deadline becomes `submit_height + default_deadline_blocks`. `≈ a few blocks`
    /// realizes the §15.37 "~10s default" retry window. A submitter may instead
    /// name an explicit future deadline height. Placeholder.
    pub default_deadline_blocks: u64,
    /// Per-fill protocol fee in basis points (`0..=10_000`) charged on the quote
    /// proceeds of each fill. `0` (default) charges no fee. The fee is only levied
    /// when the pair's quote asset is native WEBC, in which case it is split by
    /// [`crate::split_fee`] (50% burned, 50% to validators); a non-native quote
    /// leg carries no protocol fee (external-asset fee routing is deferred).
    /// Placeholder.
    pub fee_bps: u16,
}

impl Default for DexConfig {
    fn default() -> Self {
        Self {
            // No extra size floor by default; a zero-amount order is always rejected
            // regardless of this value.
            min_order_amount: Amount::ZERO,
            // ≈ a handful of ~2s blocks of retry tolerance (the §15.37 ~10s default).
            default_deadline_blocks: 5,
            // No protocol fee by default; a chain can enable a small per-fill fee.
            fee_bps: 0,
        }
    }
}

impl DexConfig {
    /// Rejects a configuration whose fee share is outside the basis-point range.
    ///
    /// Called at genesis so a chain never runs with a fee above 100%, which would
    /// try to carve more than the proceeds and underflow settlement.
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.fee_bps > 10_000 {
            return Err(ChainError::InvalidDexConfig);
        }
        Ok(())
    }
}

/// Canonical registry record for one live DEX order intent.
///
/// Keyed in [`crate::ChainState::dex_orders`] by [`OrderId`]. An order exists only
/// between an explicit [`crate::Operation::SubmitOrder`] and the batch/cancel/
/// expiry that closes it. Its currently-locked input is derived from `remaining`:
/// a live `Buy` has `remaining * limit_price` quote locked; a live `Sell` has
/// `remaining` base locked. The native leg of that lock is accounted in the
/// `dex_escrow` supply bucket.
///
/// Invariants (consensus-critical, enforced by the `state` settlement hook):
/// - `remaining <= amount` and `remaining > 0` while the record exists (a fully
///   filled order is removed, not left at zero);
/// - a `Buy` never trades above `limit_price`, a `Sell` never below it (the
///   uniform clearing price lies within every filled order's limit);
/// - the currently-locked input equals the derivation above, so cancel/expiry
///   refunds exactly what is still locked and settlement conserves both assets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Order {
    /// Account that submitted the order, locked its input, and may cancel it.
    pub owner: Address,
    /// Oriented pair this order trades on.
    pub pair: TradingPair,
    /// Buy (acquire base, pay quote) or sell (dispose base, receive quote).
    pub side: OrderSide,
    /// Original order size, in base-asset base units (immutable).
    pub amount: Amount,
    /// Not-yet-filled size, in base-asset base units (decreases on each fill).
    pub remaining: Amount,
    /// Limit price: a buy pays at most this, a sell receives at least this, in
    /// quote base-units per base base-unit.
    pub limit_price: Price,
    /// Last block height at which this order may still settle; after it, the order
    /// is auto-cancelled and its remaining lock refunded (§15.37 deadline).
    pub deadline_height: u64,
    /// Immediate-or-cancel flag: when `true`, any amount unfilled in the batch it
    /// participates in is cancelled and refunded that same block instead of
    /// retrying (§15.37 fill-or-cancel).
    pub fill_or_cancel: bool,
    /// Owner-requested cancellation, honored at the block's batch pass.
    ///
    /// [`crate::Operation::CancelOrder`] carries only an order id and so cannot name
    /// a non-native refund asset in its signed access list; it therefore only marks
    /// the order here (a write to the order's own state key) and the block-level
    /// batch pass — which is not access-list-bound, exactly like epoch settlement —
    /// performs the refund and removal. Because the batch pass runs at the end of
    /// every block and processes cancellations *before* matching, a cancel included
    /// in block N takes effect before block N's batch (§15.37 / doc §3.1).
    #[serde(default)]
    pub cancel_requested: bool,
}

impl Order {
    /// Creates a fresh, wholly-unfilled order (`remaining == amount`).
    pub fn new(
        owner: Address,
        pair: TradingPair,
        side: OrderSide,
        amount: Amount,
        limit_price: Price,
        deadline_height: u64,
        fill_or_cancel: bool,
    ) -> Self {
        Self {
            owner,
            pair,
            side,
            amount,
            remaining: amount,
            limit_price,
            deadline_height,
            fill_or_cancel,
            cancel_requested: false,
        }
    }

    /// The asset and amount this order currently locks, refunded when it is
    /// cancelled or expires.
    ///
    /// A `Buy` locks `remaining * limit_price` of the quote asset; a `Sell` locks
    /// `remaining` of the base asset. Returns `None` on the overflow of the buy's
    /// quote product, so a hostile amount/price fails closed.
    pub fn locked_input(&self) -> Option<(AssetId, Amount)> {
        match self.side {
            OrderSide::Buy => self
                .limit_price
                .quote_for(self.remaining)
                .map(|quote| (self.pair.quote.clone(), quote)),
            OrderSide::Sell => Some((self.pair.base.clone(), self.remaining)),
        }
    }

    /// The native-WEBC units this order currently locks, for the `dex_escrow`
    /// bucket, or `Amount::ZERO` when its locked leg is a non-native asset.
    ///
    /// A `Buy` locks `remaining * limit_price` quote; a `Sell` locks `remaining`
    /// base. Only the leg that is [`AssetId::NativeWebc`] contributes to
    /// `dex_escrow` (a non-native leg is held out of the owner's `asset_balances`
    /// and is not part of the native supply invariant). Returns `None` on overflow.
    pub fn locked_native(&self) -> Option<Amount> {
        match self.side {
            OrderSide::Buy => {
                if self.pair.quote == AssetId::NativeWebc {
                    self.limit_price.quote_for(self.remaining)
                } else {
                    Some(Amount::ZERO)
                }
            }
            OrderSide::Sell => {
                if self.pair.base == AssetId::NativeWebc {
                    Some(self.remaining)
                } else {
                    Some(Amount::ZERO)
                }
            }
        }
    }
}

/// Deterministic uniform clearing price and matched base volume for one pair.
///
/// Inputs are `(limit, remaining)` contributions for the buy and sell orders on a
/// single pair; only aggregate price and quantity matter (the function is a pure
/// function of the multiset of contributions, so any permutation of the same
/// orders clears identically — the key no-ordering-games invariant). Returns
/// `None` when the books do not cross (no non-negative matched volume).
///
/// Algorithm:
/// 1. Aggregate each side into a price ladder (buys high→low, sells low→high).
/// 2. Two-pointer crossing scan: repeatedly match the best bid against the best
///    ask while `bid >= ask`, accumulating matched volume and tracking the
///    marginal (last-matched) ask `a*` and bid `b*`. `a* <= b*` always holds.
/// 3. **Tie-rule (documented, consensus-critical):** the uniform clearing price is
///    the integer midpoint of the marginal spread, `pc = a* + (b* - a*) / 2`
///    (floor). It lies in `[a*, b*]`, so every matched buy (bid `>= b* >= pc`) pays
///    no more than its limit and every matched sell (ask `<= a* <= pc`) receives no
///    less than its limit, while splitting the marginal surplus symmetrically
///    rather than handing it entirely to one side.
/// 4. Recompute eligible demand `D` (buys with limit `>= pc`) and supply `S`
///    (sells with limit `<= pc`); the executable volume is `min(D, S)`, which by
///    construction equals the scan's matched volume.
///
/// Returned `Amount` is that executable base volume (`> 0`). Never panics: all
/// arithmetic is checked/saturating and the midpoint cannot overflow.
pub fn uniform_clearing_price(
    buys: &[(Price, Amount)],
    sells: &[(Price, Amount)],
) -> Option<(Price, Amount)> {
    if buys.is_empty() || sells.is_empty() {
        return None;
    }
    // Aggregate into price ladders. `BTreeMap` gives sorted, deterministic order.
    let buy_levels = aggregate_levels(buys);
    let sell_levels = aggregate_levels(sells);
    // Buys are scanned high→low (most aggressive first), sells low→high.
    let buy_ladder: Vec<(Price, u128)> = buy_levels.into_iter().rev().collect();
    let sell_ladder: Vec<(Price, u128)> = sell_levels.into_iter().collect();

    let mut i = 0usize;
    let mut j = 0usize;
    let mut bid_qty = buy_ladder[0].1;
    let mut ask_qty = sell_ladder[0].1;
    let mut marginal_ask: Option<Price> = None;
    let mut marginal_bid: Option<Price> = None;
    while i < buy_ladder.len() && j < sell_ladder.len() {
        let bid = buy_ladder[i].0;
        let ask = sell_ladder[j].0;
        if bid.0 < ask.0 {
            break;
        }
        let matched = bid_qty.min(ask_qty);
        marginal_ask = Some(ask);
        marginal_bid = Some(bid);
        bid_qty -= matched;
        ask_qty -= matched;
        if bid_qty == 0 {
            i += 1;
            if i < buy_ladder.len() {
                bid_qty = buy_ladder[i].1;
            }
        }
        if ask_qty == 0 {
            j += 1;
            if j < sell_ladder.len() {
                ask_qty = sell_ladder[j].1;
            }
        }
    }
    let (a_star, b_star) = match (marginal_ask, marginal_bid) {
        (Some(a), Some(b)) => (a, b),
        // The books did not cross at all.
        _ => return None,
    };
    // Midpoint of the marginal spread, floored. `b_star >= a_star`, so the
    // subtraction never underflows and the sum never overflows a `u128`.
    let clearing = Price::new(a_star.0 + (b_star.0 - a_star.0) / 2);

    // Executable volume at the clearing price: min(eligible demand, eligible supply).
    let demand = sum_eligible(buys, |limit| limit.0 >= clearing.0)?;
    let supply = sum_eligible(sells, |limit| limit.0 <= clearing.0)?;
    let volume = demand.min(supply);
    if volume.is_zero() {
        return None;
    }
    Some((clearing, volume))
}

/// Aggregates `(price, amount)` contributions into a sorted per-price ladder.
fn aggregate_levels(entries: &[(Price, Amount)]) -> BTreeMap<Price, u128> {
    let mut levels: BTreeMap<Price, u128> = BTreeMap::new();
    for (price, amount) in entries {
        let slot = levels.entry(*price).or_insert(0);
        *slot = slot.saturating_add(amount.0);
    }
    levels
}

/// Sums the amounts of contributions whose limit price satisfies `eligible`.
fn sum_eligible(entries: &[(Price, Amount)], eligible: impl Fn(Price) -> bool) -> Option<Amount> {
    let mut total = Amount::ZERO;
    for (price, amount) in entries {
        if eligible(*price) {
            total = total.checked_add(*amount)?;
        }
    }
    Some(total)
}

/// Dust-free integer pro-rata rationing of `total` across `remainings`.
///
/// Distributes exactly `total` base units among the given per-order remaining
/// amounts using **cumulative rounding**: with prefix sums `P_0=0 .. P_n=L`
/// (where `L` is the sum of `remainings`), order `i` receives
/// `floor(total * P_i / L) - floor(total * P_{i-1} / L)`. This guarantees three
/// properties with no separate remainder-distribution step and no lost dust:
/// - the fills sum to exactly `total` (telescoping: `floor(total*L/L) = total`);
/// - each fill is `<= remainings[i]` (since `total <= L`), so no order overfills;
/// - the result is a pure function of the input order — callers pass `remainings`
///   in a deterministic (sorted `OrderId`) order, so settlement is reproducible.
///
/// `total` must be `<= L`; when `total == L` every order fills its full remaining.
/// Returns `Err(ArithmeticOverflow)` only on a checked-arithmetic overflow (the
/// 256-bit-safe [`Amount::checked_mul_ratio`] keeps this panic-free), and
/// `Err(InvalidDexConfig)` if `total` exceeds `L` (a caller bug, never hostile
/// input, but rejected rather than silently clamped).
pub fn prorata_fills(remainings: &[Amount], total: Amount) -> Result<Vec<Amount>, ChainError> {
    let liquidity = remainings
        .iter()
        .try_fold(Amount::ZERO, |sum, amount| sum.checked_add(*amount))
        .ok_or(ChainError::ArithmeticOverflow)?;
    if total.0 > liquidity.0 {
        return Err(ChainError::InvalidDexConfig);
    }
    let mut fills = Vec::with_capacity(remainings.len());
    if liquidity.is_zero() {
        // No liquidity: every fill is zero (and `total` is also zero here).
        fills.resize(remainings.len(), Amount::ZERO);
        return Ok(fills);
    }
    let mut prefix = Amount::ZERO;
    let mut previous_alloc = Amount::ZERO;
    for amount in remainings {
        prefix = prefix
            .checked_add(*amount)
            .ok_or(ChainError::ArithmeticOverflow)?;
        // floor(total * prefix / liquidity), overflow-safe.
        let alloc = total
            .checked_mul_ratio(prefix.0, liquidity.0)
            .ok_or(ChainError::ArithmeticOverflow)?;
        let fill = alloc
            .checked_sub(previous_alloc)
            .ok_or(ChainError::ArithmeticOverflow)?;
        fills.push(fill);
        previous_alloc = alloc;
    }
    Ok(fills)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn price(value: u128) -> Price {
        Price::new(value)
    }

    fn amount(value: u128) -> Amount {
        Amount::from_units(value)
    }

    #[test]
    fn price_json_is_a_decimal_string_and_round_trips() {
        for value in [Price(0), Price(1), Price(u128::MAX)] {
            let json = serde_json::to_string(&value).expect("serializes");
            assert!(json.starts_with('"'), "human-readable form is a string");
            let decoded: Price = serde_json::from_str(&json).expect("decodes");
            assert_eq!(decoded, value);
        }
        assert_eq!(
            serde_json::to_string(&Price(u128::MAX)).unwrap(),
            format!("\"{}\"", u128::MAX)
        );
    }

    #[test]
    fn price_binary_round_trips() {
        use bincode::Options;
        let options = bincode::DefaultOptions::new().with_varint_encoding();
        for value in [Price(0), Price(42), Price(u128::MAX)] {
            let bytes = options.serialize(&value).expect("serializes");
            let restored: Price = options.deserialize(&bytes).expect("deserializes");
            assert_eq!(restored, value);
        }
    }

    #[test]
    fn quote_for_is_exact_and_overflow_safe() {
        assert_eq!(price(3).quote_for(amount(10)), Some(amount(30)));
        assert_eq!(price(0).quote_for(amount(10)), Some(amount(0)));
        // A near-maximal product still computes without overflow.
        assert_eq!(
            price(1).quote_for(Amount(u128::MAX)),
            Some(Amount(u128::MAX))
        );
        // A genuine overflow fails closed.
        assert_eq!(price(2).quote_for(Amount(u128::MAX)), None);
    }

    #[test]
    fn dex_config_validate_rejects_over_full_fee() {
        assert!(DexConfig::default().validate().is_ok());
        let bad = DexConfig {
            fee_bps: 10_001,
            ..DexConfig::default()
        };
        assert!(matches!(bad.validate(), Err(ChainError::InvalidDexConfig)));
    }

    #[test]
    fn trading_pair_rejects_identical_assets() {
        let pair = TradingPair::new(AssetId::NativeWebc, AssetId::NativeWebc);
        assert!(matches!(
            pair.validate(),
            Err(ChainError::InvalidTradingPair)
        ));
        let ok = TradingPair::new(
            AssetId::NativeWebc,
            AssetId::WrappedWebc {
                origin_chain: crate::ExternalChain::Ethereum,
            },
        );
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn simple_cross_clears_at_the_midpoint() {
        // Buy 100 @ 10, sell 100 @ 8. Marginal spread [8, 10] → midpoint 9.
        let (pc, volume) =
            uniform_clearing_price(&[(price(10), amount(100))], &[(price(8), amount(100))])
                .expect("crossing books clear");
        assert_eq!(pc, price(9));
        assert_eq!(volume, amount(100));
    }

    #[test]
    fn non_crossing_books_do_not_clear() {
        // Highest bid 8 < lowest ask 9: no crossing.
        assert!(
            uniform_clearing_price(&[(price(8), amount(100))], &[(price(9), amount(100))])
                .is_none()
        );
        assert!(uniform_clearing_price(&[], &[(price(9), amount(100))]).is_none());
        assert!(uniform_clearing_price(&[(price(9), amount(100))], &[]).is_none());
    }

    #[test]
    fn clearing_is_permutation_invariant() {
        // The same multiset of orders in any order clears identically (the key
        // no-ordering-games property).
        let buys_a = [
            (price(10), amount(50)),
            (price(9), amount(40)),
            (price(12), amount(30)),
        ];
        let buys_b = [
            (price(12), amount(30)),
            (price(10), amount(50)),
            (price(9), amount(40)),
        ];
        let sells = [(price(8), amount(60)), (price(9), amount(60))];
        let sells_rev = [(price(9), amount(60)), (price(8), amount(60))];
        assert_eq!(
            uniform_clearing_price(&buys_a, &sells),
            uniform_clearing_price(&buys_b, &sells_rev)
        );
    }

    #[test]
    fn clearing_price_respects_every_limit() {
        // A spread of asks and bids; the clearing price must be within [max matched
        // ask, min matched bid] so no order trades beyond its limit.
        let buys = [(price(20), amount(100)), (price(15), amount(100))];
        let sells = [(price(10), amount(100)), (price(14), amount(100))];
        let (pc, _volume) = uniform_clearing_price(&buys, &sells).expect("crosses");
        // Every matched buy bid >= pc and every matched sell ask <= pc.
        assert!(pc.0 >= 14 || pc.0 >= 10);
        // Concretely: two-pointer matches 100@20 vs 100@10 then 100@15 vs 100@14,
        // marginal ask 14, marginal bid 15 → midpoint 14.
        assert_eq!(pc, price(14));
    }

    #[test]
    fn prorata_is_dust_free_and_never_overfills() {
        // Distribute 100 among remainings [30, 30, 40] (sum 100) => full fills.
        let full = prorata_fills(&[amount(30), amount(30), amount(40)], amount(100)).unwrap();
        assert_eq!(full, vec![amount(30), amount(30), amount(40)]);

        // Distribute 10 among [3, 3, 4] (sum 10) — exact, sums to 10.
        let exact = prorata_fills(&[amount(3), amount(3), amount(4)], amount(10)).unwrap();
        assert_eq!(exact.iter().map(|a| a.0).sum::<u128>(), 10);

        // A rationed case with an indivisible remainder: 7 among [10, 10, 10]
        // (sum 30). Cumulative rounding assigns floor(7*10/30)=2, floor(7*20/30)-2=2,
        // floor(7*30/30)-4=3 => [2, 2, 3], summing to exactly 7 with no dust and
        // each <= its remaining.
        let rationed = prorata_fills(&[amount(10), amount(10), amount(10)], amount(7)).unwrap();
        assert_eq!(rationed, vec![amount(2), amount(2), amount(3)]);
        assert_eq!(rationed.iter().map(|a| a.0).sum::<u128>(), 7);
        for (fill, remaining) in rationed.iter().zip([amount(10), amount(10), amount(10)]) {
            assert!(fill.0 <= remaining.0, "no order overfills");
        }
    }

    #[test]
    fn prorata_rejects_total_above_liquidity() {
        assert!(matches!(
            prorata_fills(&[amount(5)], amount(6)),
            Err(ChainError::InvalidDexConfig)
        ));
        // Zero liquidity with zero total yields all-zero fills.
        let zeros = prorata_fills(&[amount(0), amount(0)], amount(0)).unwrap();
        assert_eq!(zeros, vec![amount(0), amount(0)]);
    }

    #[test]
    fn locked_native_tracks_the_native_leg_only() {
        let owner = webc_crypto::Keypair::from_seed([9u8; 32]).address();
        let ext = AssetId::WrappedWebc {
            origin_chain: crate::ExternalChain::Ethereum,
        };
        // base = native, sell locks `remaining` native.
        let sell_native = Order::new(
            owner,
            TradingPair::new(AssetId::NativeWebc, ext.clone()),
            OrderSide::Sell,
            amount(100),
            price(3),
            10,
            false,
        );
        assert_eq!(sell_native.locked_native(), Some(amount(100)));
        // quote = native, buy locks `remaining * price` native.
        let buy_native = Order::new(
            owner,
            TradingPair::new(ext.clone(), AssetId::NativeWebc),
            OrderSide::Buy,
            amount(100),
            price(3),
            10,
            false,
        );
        assert_eq!(buy_native.locked_native(), Some(amount(300)));
        // Non-native locked leg contributes nothing to the native bucket.
        let buy_ext = Order::new(
            owner,
            TradingPair::new(AssetId::NativeWebc, ext),
            OrderSide::Buy,
            amount(100),
            price(3),
            10,
            false,
        );
        assert_eq!(buy_ext.locked_native(), Some(Amount::ZERO));
    }

    #[test]
    fn order_and_records_round_trip_and_reject_unknown_fields() {
        let owner = webc_crypto::Keypair::from_seed([5u8; 32]).address();
        let order = Order::new(
            owner,
            TradingPair::new(
                AssetId::NativeWebc,
                AssetId::WrappedWebc {
                    origin_chain: crate::ExternalChain::Solana,
                },
            ),
            OrderSide::Buy,
            amount(1_000),
            price(7),
            42,
            true,
        );
        let text = serde_json::to_string(&order).expect("order serializes");
        assert_eq!(serde_json::from_str::<Order>(&text).unwrap(), order);
        let mut value = serde_json::to_value(&order).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Order>(value).is_err());
    }
}
