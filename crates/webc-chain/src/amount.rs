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

    /// Computes `self * numerator / denominator` without an overflowing product.
    pub fn checked_mul_ratio(self, numerator: u128, denominator: u128) -> Option<Self> {
        if denominator == 0 {
            return None;
        }
        let whole = self.0 / denominator;
        let remainder = self.0 % denominator;
        whole
            .checked_mul(numerator)
            .zip(remainder.checked_mul(numerator))
            .and_then(|(value, fraction)| value.checked_add(fraction / denominator))
            .map(Self)
    }

    /// Splits an amount into two conserving halves, assigning odd dust second.
    pub fn half_split(self) -> (Self, Self) {
        let first = Self(self.0 / 2);
        let second = Self(self.0 - first.0);
        (first, second)
    }
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
}
