//! Native WEBC amount representation and checked base-unit arithmetic.
//!
//! Consensus stores amounts only as unsigned integer base units. This module
//! does not apply fees, rewards, or asset identity. Human-readable serde uses a
//! decimal string so browsers never lose precision, and arithmetic helpers
//! report overflow instead of wrapping.

use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Number of decimal places in native WEBC amounts.
pub const WEBC_DECIMALS: u32 = 12;
/// Number of indivisible base units in one WEBC.
pub const WEBC_UNIT: u128 = 1_000_000_000_000;

/// Confirmed genesis total supply: exactly 10,000,000 WEBC (WEBC-DEFINITION §15.14).
///
/// Both mainnet and devnet initialize this same total (owner-confirmed
/// 2026-07-17). A production genesis pins it through
/// `ChainConfig::expected_total_supply` so `ChainState::from_genesis` rejects
/// any allocation whose accounts do not sum to it (finding G1 — the supply
/// invariant alone is tautological and never pins the total). In-crate test
/// fixtures that intentionally use a small allocation leave the expectation
/// unset.
pub const GENESIS_TOTAL_SUPPLY: Amount = Amount::from_webc(10_000_000);

/// Native WEBC amount in the smallest indivisible unit.
///
/// 1 WEBC = 1,000,000,000,000 base units. `u128` gives enough room for long-lived
/// inflation experiments without overflowing during normal fee/reward math.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(pub u128);

impl Amount {
    /// Zero native base units.
    pub const ZERO: Self = Self(0);

    /// Constructs an amount from exact native base units.
    pub fn from_units(units: u128) -> Self {
        Self(units)
    }

    /// Converts whole WEBC to native base units.
    ///
    /// `u64::MAX * WEBC_UNIT` fits in the `u128` representation. `const` so
    /// compile-time supply constants such as [`GENESIS_TOTAL_SUPPLY`] can be
    /// defined from a whole-WEBC figure.
    #[allow(clippy::cast_lossless)]
    pub const fn from_webc(whole: u64) -> Self {
        // Widening `u64` -> `u128` is lossless; `u128::from` is not yet
        // const-stable, so the widening cast is required inside a `const fn`.
        Self((whole as u128) * WEBC_UNIT)
    }

    /// Returns whether the amount contains zero base units.
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Adds exact native base units, returning `None` on overflow.
    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }

    /// Subtracts exact native base units, returning `None` on underflow.
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }

    /// Multiplies native base units by a `u64`, returning `None` on overflow.
    pub fn checked_mul_u64(self, rhs: u64) -> Option<Self> {
        self.0.checked_mul(u128::from(rhs)).map(Self)
    }

    /// Multiplies by basis points without overflowing the intermediate product.
    pub fn checked_mul_bps(self, bps: u16) -> Option<Self> {
        let bps = u128::from(bps);
        let whole = self.0 / 10_000;
        let remainder = self.0 % 10_000;
        whole
            .checked_mul(bps)
            .and_then(|value| value.checked_add(remainder * bps / 10_000))
            .map(Self)
    }

    /// Computes `floor(self * numerator / denominator)` exactly, in base units.
    ///
    /// The product `self * numerator` is formed as a full 256-bit intermediate
    /// (WEBC-DEFINITION §15.14), so the floored quotient is returned whenever
    /// it fits in `u128`, even when the product alone does not. Returns `None`
    /// if and only if `denominator` is zero or the exact quotient exceeds
    /// `u128::MAX`; the result never wraps, rounds up, or panics.
    ///
    /// Consensus-critical: reward splits and DEX pro-rata fills rely on this
    /// being the same exact floor on every node.
    pub fn checked_mul_ratio(self, numerator: u128, denominator: u128) -> Option<Self> {
        mul_div_floor(self.0, numerator, denominator).map(Self)
    }

    /// Splits an amount into two conserving halves, assigning odd dust second.
    pub fn half_split(self) -> (Self, Self) {
        let first = Self(self.0 / 2);
        let second = Self(self.0 - first.0);
        (first, second)
    }
}

/// Computes `floor(a * b / denominator)` over a full 256-bit intermediate.
///
/// Returns `None` exactly when `denominator` is zero or the floored quotient
/// exceeds `u128::MAX`. Consensus-critical: it must be an exact floor with no
/// silent wrapping, so reward, fee, and stake ratios agree on every node.
fn mul_div_floor(a: u128, b: u128, denominator: u128) -> Option<u128> {
    if denominator == 0 {
        return None;
    }
    // The 256-bit product as `(low, high)` 128-bit halves. With a zero carry
    // `carrying_mul` cannot overflow (std, stable since Rust 1.91).
    let (low, high) = a.carrying_mul(b, 0);
    if high == 0 {
        // The product fits in `u128`, so native division is the exact floor.
        return low.checked_div(denominator);
    }
    div_u256_by_u128(high, low, denominator)
}

/// Floors the 256-bit value `high * 2^128 + low` divided by `denominator`.
///
/// Returns `None` when the quotient needs more than 128 bits, which is exactly
/// when `high >= denominator` (this also rejects a zero denominator). Restoring
/// binary long division, most significant dividend bit first: the running
/// remainder stays below `denominator`, so each shifted value `2 * remainder +
/// bit` is below `2 * denominator < 2^129`. Its bit 128 is tracked in `carry`,
/// so the `u128` shift never silently loses information.
fn div_u256_by_u128(high: u128, low: u128, denominator: u128) -> Option<u128> {
    if high >= denominator {
        return None;
    }
    let mut remainder = high;
    let mut quotient = 0u128;
    for bit in (0..u128::BITS).rev() {
        let carry = (remainder >> (u128::BITS - 1)) == 1;
        remainder = (remainder << 1) | ((low >> bit) & 1);
        if carry || remainder >= denominator {
            // The true shifted value lies in `[denominator, 2 * denominator)`,
            // so the difference fits in `u128`. When `carry` is set the lost
            // 2^128 cancels in the wrapping subtraction, which is then exact.
            remainder = remainder.wrapping_sub(denominator);
            quotient |= 1 << bit;
        }
    }
    Some(quotient)
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.0 / WEBC_UNIT;
        let fractional = self.0 % WEBC_UNIT;
        write!(f, "{}.{:012} WEBC", whole, fractional)
    }
}

impl Serialize for Amount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            // JSON numbers cannot safely represent large u128 values in browsers.
            // Use a decimal string of base units for RPC and SDK compatibility.
            serializer.serialize_str(&self.0.to_string())
        } else {
            serializer.serialize_u128(self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let value = String::deserialize(deserializer)?;
            let units = value.parse::<u128>().map_err(D::Error::custom)?;
            Ok(Self(units))
        } else {
            Ok(Self(u128::deserialize(deserializer)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;
    use std::collections::BTreeMap;

    #[test]
    fn confirmed_precision_and_display_are_stable() {
        assert_eq!(WEBC_DECIMALS, 12);
        assert_eq!(Amount::from_webc(1).0, 1_000_000_000_000);
        assert_eq!(Amount::from_units(42).to_string(), "0.000000000042 WEBC");
    }

    #[test]
    fn json_uses_exact_decimal_base_unit_strings() {
        let genesis_supply = Amount::from_webc(10_000_000);
        let json = serde_json::to_string(&genesis_supply).expect("test amount must serialize");
        assert_eq!(json, "\"10000000000000000000\"");
    }

    #[test]
    fn binary_encoding_is_variable_length_and_round_trips() {
        use bincode::Options;
        // The storage-at-rest and wire codecs both use bincode's variable-length
        // integer encoding (WEBC §15.14). `Amount`'s non-human-readable
        // `Serialize` emits `serialize_u128`, so under that config a small amount
        // costs a few bytes instead of the fixed 16 a `u128` takes under fixint.
        let options = bincode::DefaultOptions::new().with_varint_encoding();
        for amount in [
            Amount::ZERO,
            Amount::from_units(1),
            Amount::from_units(250),
            Amount::from_units(255),
            Amount::from_units(300),
        ] {
            let bytes = options.serialize(&amount).expect("amount serializes");
            assert!(
                bytes.len() < 16,
                "a small amount must be shorter than a fixed 16-byte u128 ({} bytes for {})",
                bytes.len(),
                amount.0
            );
            let restored: Amount = options.deserialize(&bytes).expect("amount deserializes");
            assert_eq!(restored, amount);
        }
        // A near-maximal amount must still round-trip exactly. Under bincode's
        // varint it pays full width plus a one-byte length marker (17 bytes) — the
        // accepted §15.14 trade-off: only the very largest balances exceed 16.
        for amount in [
            Amount(u128::MAX),
            Amount(u128::MAX - 1),
            Amount::from_webc(10_000_000),
            Amount(u64::MAX as u128),
        ] {
            let bytes = options.serialize(&amount).expect("amount serializes");
            let restored: Amount = options.deserialize(&bytes).expect("amount deserializes");
            assert_eq!(restored, amount, "round trip for {}", amount.0);
        }
    }

    #[test]
    fn json_encoding_is_unchanged_by_the_binary_varint_switch() {
        // The load-bearing invariant: switching the BINARY path to varint must
        // leave the human-readable path byte-identical. JSON still emits the exact
        // decimal string of base units, which drives the canonical `state_root`,
        // transaction signing, and the TypeScript SDK — none of which may move.
        assert_eq!(
            serde_json::to_string(&Amount::from_units(1)).unwrap(),
            "\"1\""
        );
        assert_eq!(
            serde_json::to_string(&Amount::from_units(300)).unwrap(),
            "\"300\""
        );
        assert_eq!(
            serde_json::to_string(&Amount(u128::MAX)).unwrap(),
            "\"340282366920938463463374607431768211455\""
        );
        // The exact base-unit string also round-trips back to the same amount.
        let value = Amount::from_webc(10_000_000);
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(json, "\"10000000000000000000\"");
        assert_eq!(serde_json::from_str::<Amount>(&json).unwrap(), value);
    }

    #[test]
    fn basis_point_math_does_not_overflow_intermediate_values() {
        assert_eq!(
            Amount(u128::MAX).checked_mul_bps(10_000),
            Some(Amount(u128::MAX))
        );
        assert_eq!(
            Amount::from_units(12_345).checked_mul_bps(8_000),
            Some(Amount::from_units(9_876))
        );
        assert_eq!(
            Amount(u128::MAX).checked_mul_ratio(u128::MAX, u128::MAX),
            Some(Amount(u128::MAX))
        );
    }

    // ---- checked_mul_ratio: exact floor(self * numerator / denominator) ----
    //
    // Regression tests for the remainder-split overflow: the pre-fix code
    // computed `(self / d) * n + ((self % d) * n) / d` and returned `None`
    // whenever `(self % d) * n` alone overflowed `u128`, even though the exact
    // floored quotient fits. Every expected value below is that exact floor.

    #[test]
    fn mul_ratio_2_pow_64_squared_over_2_pow_64_plus_1_is_exact() {
        // 2^64 * 2^64 = 2^128 = (2^64 - 1)(2^64 + 1) + 1, so the floor is 2^64 - 1.
        let two_pow_64 = 1u128 << 64;
        assert_eq!(
            Amount(two_pow_64).checked_mul_ratio(two_pow_64, two_pow_64 + 1),
            Some(Amount(two_pow_64 - 1))
        );
    }

    #[test]
    fn mul_ratio_near_max_operands_over_max_is_exact() {
        // (MAX - 1)^2 = MAX * (MAX - 2) + 1, so the floor is MAX - 2.
        assert_eq!(
            Amount(u128::MAX - 1).checked_mul_ratio(u128::MAX - 1, u128::MAX),
            Some(Amount(u128::MAX - 2))
        );
    }

    #[test]
    fn mul_ratio_is_exact_whenever_the_floored_quotient_fits() {
        let pow2 = |bits: u32| 1u128 << bits;
        let webc = |whole: u64| Amount::from_webc(whole).0;
        // (self, numerator, denominator, exact floor); every product overflows u128.
        let cases = [
            // 2 * MAX / MAX = 2 (ported from 36bc921).
            (2, u128::MAX, u128::MAX, 2),
            // 2^100 * 2^100 / 2^127 = 2^73 (ported from 36bc921).
            (pow2(100), pow2(100), pow2(127), pow2(73)),
            // Reward-split shape (state.rs): reward * validator_stake / total_stake
            // with reward < total_stake, so the old "remainder" was the whole reward.
            (
                webc(20_000_000),
                webc(20_000_000),
                webc(40_000_000),
                webc(10_000_000),
            ),
            // DEX pro-rata shape (dex.rs): total * prefix / liquidity, total <= liquidity.
            (
                6 * 10u128.pow(29),
                4 * 10u128.pow(29),
                10u128.pow(30),
                24 * 10u128.pow(28),
            ),
            // The largest quotient, MAX, reached through a 256-bit product.
            (u128::MAX, pow2(127) + 1, pow2(127) + 1, u128::MAX),
            // A non-exact floor: (MAX - 2)(MAX - 1) = MAX * (MAX - 3) + 2.
            (u128::MAX - 2, u128::MAX - 1, u128::MAX, u128::MAX - 3),
        ];
        for (value, numerator, denominator, expected) in cases {
            assert_eq!(
                Amount(value).checked_mul_ratio(numerator, denominator),
                Some(Amount(expected)),
                "{value} * {numerator} / {denominator}"
            );
        }
    }

    #[test]
    fn mul_ratio_is_none_when_the_exact_quotient_exceeds_u128() {
        let pow2 = |bits: u32| 1u128 << bits;
        for (value, numerator, denominator) in [
            // MAX * 2 / 1.
            (u128::MAX, 2, 1),
            // MAX * MAX / 1 (ported from 36bc921).
            (u128::MAX, u128::MAX, 1),
            // Exactly 2^128, the smallest quotient that does not fit.
            (pow2(127), 2, 1),
            (pow2(127), pow2(127), pow2(126)),
            // MAX^2 = (MAX - 1)(MAX + 1) + 1, so the floor is MAX + 1 = 2^128.
            (u128::MAX, u128::MAX, u128::MAX - 1),
        ] {
            assert_eq!(
                Amount(value).checked_mul_ratio(numerator, denominator),
                None,
                "{value} * {numerator} / {denominator}"
            );
        }
    }

    #[test]
    fn mul_ratio_with_a_zero_denominator_is_none() {
        for (value, numerator) in [
            (0, 0),
            (5, 3),
            (0, u128::MAX),
            (u128::MAX, 0),
            (u128::MAX, u128::MAX),
        ] {
            assert_eq!(
                Amount(value).checked_mul_ratio(numerator, 0),
                None,
                "{value} * {numerator} / 0"
            );
        }
    }

    #[test]
    fn mul_ratio_identities_hold_for_small_and_large_values() {
        let samples = [
            0,
            1,
            2,
            3,
            10_000,
            WEBC_UNIT,
            GENESIS_TOTAL_SUPPLY.0,
            u128::from(u64::MAX),
            1 << 64,
            (1 << 64) + 1,
            (1 << 127) - 1,
            1 << 127,
            u128::MAX - 1,
            u128::MAX,
        ];
        for x in samples {
            assert_eq!(
                Amount(x).checked_mul_ratio(1, 1),
                Some(Amount(x)),
                "{x} * 1 / 1"
            );
            for d in samples.into_iter().filter(|&d| d != 0) {
                assert_eq!(
                    Amount(x).checked_mul_ratio(d, d),
                    Some(Amount(x)),
                    "{x} * {d} / {d}"
                );
                assert_eq!(
                    Amount::ZERO.checked_mul_ratio(x, d),
                    Some(Amount::ZERO),
                    "0 * {x} / {d}"
                );
                assert_eq!(
                    Amount(x).checked_mul_ratio(0, d),
                    Some(Amount::ZERO),
                    "{x} * 0 / {d}"
                );
            }
        }
    }

    /// Seed and length of the deterministic sweep shared by the oracle and the
    /// compatibility tests (fixed, so every run and machine sees the same inputs).
    const SWEEP_SEED: u64 = 0x9E37_79B9_7F4A_7C15;
    const SWEEP_CASES: usize = 50_000;

    /// Marsaglia's xorshift64*: a tiny deterministic generator, so the sweep
    /// needs no RNG dependency. The state must never be zero.
    struct XorShift64Star(u64);

    impl XorShift64Star {
        fn next_u64(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn next_u128(&mut self) -> u128 {
            (u128::from(self.next_u64()) << 64) | u128::from(self.next_u64())
        }

        /// A draw from `0..bound`; modulo bias is irrelevant for coverage.
        fn below(&mut self, bound: u32) -> u32 {
            u32::try_from(self.next_u64() % u64::from(bound)).expect("draw is below a u32 bound")
        }

        /// A `u128` from a deliberately mixed-magnitude distribution: tiny
        /// values (including zero), values just below `u128::MAX`, values
        /// hugging a power of two, and — most often — a uniformly random bit
        /// width, so narrow, wide, and boundary products all occur.
        fn mixed_u128(&mut self) -> u128 {
            let raw = self.next_u128();
            match self.below(8) {
                0 => raw % 4,
                1 => u128::MAX - raw % 4,
                2 => (1 << self.below(128)) + raw % 3 - 1,
                _ => raw >> self.below(128),
            }
        }
    }

    /// The deterministic `(self, numerator, denominator)` sweep inputs.
    fn sweep_inputs() -> impl Iterator<Item = (u128, u128, u128)> {
        let mut rng = XorShift64Star(SWEEP_SEED);
        (0..SWEEP_CASES).map(move |_| (rng.mixed_u128(), rng.mixed_u128(), rng.mixed_u128()))
    }

    /// Test-only 256-bit oracle: eight little-endian 32-bit digits, each held
    /// in a `u128` so digit products and column sums cannot overflow. It uses
    /// schoolbook arithmetic and shares no code with `checked_mul_ratio`.
    type Wide = [u128; 8];

    const DIGIT_BITS: u32 = 32;
    const DIGIT_MASK: u128 = (1 << DIGIT_BITS) - 1;

    fn wide(value: u128) -> Wide {
        let mut digits = [0; 8];
        let mut rest = value;
        for digit in &mut digits[..4] {
            *digit = rest & DIGIT_MASK;
            rest >>= DIGIT_BITS;
        }
        digits
    }

    /// Propagates carries so every digit is below 2^32 (the value must fit in
    /// 256 bits).
    fn normalized(mut columns: Wide) -> Wide {
        let mut carry = 0;
        for column in &mut columns {
            let total = *column + carry;
            *column = total & DIGIT_MASK;
            carry = total >> DIGIT_BITS;
        }
        assert_eq!(carry, 0, "oracle value exceeds 256 bits");
        columns
    }

    fn wide_mul(a: u128, b: u128) -> Wide {
        let (a, b) = (wide(a), wide(b));
        let mut columns = [0; 8];
        for (i, a_digit) in a[..4].iter().enumerate() {
            for (j, b_digit) in b[..4].iter().enumerate() {
                // Digit products are below 2^64 and a column sums at most four.
                columns[i + j] += a_digit * b_digit;
            }
        }
        normalized(columns)
    }

    fn wide_add(a: Wide, b: Wide) -> Wide {
        let mut sum = a;
        for (digit, addend) in sum.iter_mut().zip(b) {
            *digit += addend;
        }
        normalized(sum)
    }

    /// `value * 2^128`: the value moved into the upper four digits.
    fn wide_shl_128(value: u128) -> Wide {
        let mut digits = [0; 8];
        digits[4..].copy_from_slice(&wide(value)[..4]);
        digits
    }

    /// Numeric order of two normalized values (most significant digit first).
    fn wide_cmp(a: &Wide, b: &Wide) -> Ordering {
        a.iter().rev().cmp(b.iter().rev())
    }

    /// Where an input sits relative to `u128`, decided by the oracle alone.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    enum RatioRegion {
        ZeroDenominator,
        /// `self * numerator` fits in `u128`.
        NarrowProduct,
        /// The product needs more than 128 bits but the floored quotient fits.
        WideProductFittingQuotient,
        /// The floored quotient exceeds `u128::MAX`.
        QuotientOverflow,
    }

    /// Asserts `checked_mul_ratio` against the oracle for one input and returns
    /// the input's region.
    fn check_against_oracle(value: u128, numerator: u128, denominator: u128) -> RatioRegion {
        let result = Amount(value).checked_mul_ratio(numerator, denominator);
        if denominator == 0 {
            assert_eq!(result, None, "{value} * {numerator} / 0");
            return RatioRegion::ZeroDenominator;
        }
        let product = wide_mul(value, numerator);
        let region = if wide_cmp(&product, &wide_shl_128(denominator)) != Ordering::Less {
            RatioRegion::QuotientOverflow
        } else if product[4..].iter().all(|&digit| digit == 0) {
            RatioRegion::NarrowProduct
        } else {
            RatioRegion::WideProductFittingQuotient
        };
        match result {
            // `None` only when the exact quotient really exceeds u128::MAX.
            None => assert_eq!(
                region,
                RatioRegion::QuotientOverflow,
                "spurious None for {value} * {numerator} / {denominator}"
            ),
            // The defining property of the floor: q * d <= a * n < (q + 1) * d.
            Some(Amount(quotient)) => {
                let lower = wide_mul(quotient, denominator);
                let upper = wide_add(lower, wide(denominator));
                assert!(
                    wide_cmp(&lower, &product) != Ordering::Greater
                        && wide_cmp(&product, &upper) == Ordering::Less,
                    "{value} * {numerator} / {denominator} returned {quotient}, not the floor"
                );
            }
        }
        // Where the product fits, plain u128 arithmetic is the reference.
        if let Some(product) = value.checked_mul(numerator) {
            assert_eq!(
                result,
                Some(Amount(product / denominator)),
                "{value} * {numerator} / {denominator}"
            );
        }
        region
    }

    #[test]
    fn mul_ratio_matches_an_independent_256_bit_oracle_on_a_deterministic_sweep() {
        let mut regions = BTreeMap::<RatioRegion, usize>::new();
        for (value, numerator, denominator) in sweep_inputs() {
            *regions
                .entry(check_against_oracle(value, numerator, denominator))
                .or_default() += 1;
        }
        // Guard against a degenerate generator: every region must be well covered.
        for region in [
            RatioRegion::ZeroDenominator,
            RatioRegion::NarrowProduct,
            RatioRegion::WideProductFittingQuotient,
            RatioRegion::QuotientOverflow,
        ] {
            let count = regions.get(&region).copied().unwrap_or_default();
            assert!(
                count >= SWEEP_CASES / 100,
                "{region:?} covered by only {count} of {SWEEP_CASES} inputs"
            );
        }
    }

    /// The pre-fix remainder-split algorithm, kept as a compatibility reference.
    fn legacy_remainder_split(value: u128, numerator: u128, denominator: u128) -> Option<u128> {
        if denominator == 0 {
            return None;
        }
        let whole = value / denominator;
        let remainder = value % denominator;
        whole
            .checked_mul(numerator)
            .zip(remainder.checked_mul(numerator))
            .and_then(|(value, fraction)| value.checked_add(fraction / denominator))
    }

    #[test]
    fn mul_ratio_is_unchanged_wherever_the_old_remainder_split_succeeded() {
        // Every input the old code accepted must keep its exact result; only
        // the old spurious `None`s may change.
        let mut compared = 0;
        for (value, numerator, denominator) in sweep_inputs() {
            if let Some(legacy) = legacy_remainder_split(value, numerator, denominator) {
                compared += 1;
                assert_eq!(
                    Amount(value).checked_mul_ratio(numerator, denominator),
                    Some(Amount(legacy)),
                    "{value} * {numerator} / {denominator}"
                );
            }
        }
        assert!(
            compared >= SWEEP_CASES / 4,
            "only {compared} of {SWEEP_CASES} inputs were comparable"
        );
    }
}
