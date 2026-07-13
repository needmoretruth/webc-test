//! Deterministic base-fee adjustment and protocol fee splitting.
//!
//! This module owns only integer fee arithmetic. It does not debit accounts or
//! choose block contents. All calculations fail closed on invalid policy values
//! or overflow so hostile configuration cannot silently clamp consensus state.

use crate::{Amount, ChainError};
use serde::{Deserialize, Serialize};

/// Congestion-aware fee configuration.
///
/// The model is intentionally close to EIP-1559 but smaller: a base fee reacts
/// to block fullness, while the user can add a priority fee/tip. The state
/// transition splits paid fees 50/50 between burn and validator accounting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeePolicy {
    /// Network-wide minimum base fee in base units per execution unit.
    pub min_base_fee_per_unit: u64,
    /// Desired execution units per block; must be non-zero.
    pub target_block_units: u64,
    /// Hard execution-unit limit per block; must be at least the target.
    pub max_block_units: u64,
    /// Maximum proportional change divisor; must be non-zero.
    pub base_fee_adjustment_denominator: u64,
}

impl Default for FeePolicy {
    fn default() -> Self {
        Self {
            min_base_fee_per_unit: 1,
            target_block_units: 1_000_000,
            max_block_units: 2_000_000,
            base_fee_adjustment_denominator: 8,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeBreakdown {
    /// Complete fee paid in native base units.
    pub total: Amount,
    /// Protocol-burned half in native base units.
    pub burned: Amount,
    /// Validator/delegator half in native base units.
    pub validator_reward: Amount,
}

/// Splits a native fee exactly between burn and validator accounting.
///
/// An odd remainder goes to validator rewards, and the two outputs always sum
/// to `total` without minting or loss.
pub fn split_fee(total: Amount) -> FeeBreakdown {
    let (burned, validator_reward) = total.half_split();
    FeeBreakdown {
        total,
        burned,
        validator_reward,
    }
}

/// Computes the next block's base fee in base units per execution unit.
///
/// `units_used` is the deterministic execution-unit total for the completed
/// block. Invalid zero divisors, a target above the hard limit, or arithmetic
/// overflow returns an error instead of saturating consensus state.
pub fn next_base_fee(current: u64, units_used: u64, policy: &FeePolicy) -> Result<u64, ChainError> {
    if policy.target_block_units == 0
        || policy.base_fee_adjustment_denominator == 0
        || policy.max_block_units < policy.target_block_units
        || units_used > policy.max_block_units
    {
        return Err(ChainError::InvalidFeePolicy);
    }
    let current = current.max(policy.min_base_fee_per_unit);
    let target = policy.target_block_units;
    let denominator = policy.base_fee_adjustment_denominator;

    if units_used == target {
        return Ok(current);
    }

    if units_used > target {
        let delta = units_used
            .checked_sub(target)
            .ok_or(ChainError::ArithmeticOverflow)?;
        let increase = u128::from(current)
            .checked_mul(u128::from(delta))
            .ok_or(ChainError::ArithmeticOverflow)?
            / u128::from(target)
            / u128::from(denominator);
        let increase =
            u64::try_from(increase.max(1)).map_err(|_| ChainError::ArithmeticOverflow)?;
        current
            .checked_add(increase)
            .ok_or(ChainError::ArithmeticOverflow)
    } else {
        let delta = target
            .checked_sub(units_used)
            .ok_or(ChainError::ArithmeticOverflow)?;
        let decrease = u128::from(current)
            .checked_mul(u128::from(delta))
            .ok_or(ChainError::ArithmeticOverflow)?
            / u128::from(target)
            / u128::from(denominator);
        let decrease = u64::try_from(decrease).map_err(|_| ChainError::ArithmeticOverflow)?;
        Ok(current
            .checked_sub(decrease)
            .ok_or(ChainError::ArithmeticOverflow)?
            .max(policy.min_base_fee_per_unit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_split_preserves_total() {
        let fee = Amount::from_units(101);
        let split = split_fee(fee);
        assert_eq!(split.burned.0 + split.validator_reward.0, fee.0);
    }

    #[test]
    fn base_fee_rises_when_block_is_full() {
        let policy = FeePolicy::default();
        assert!(next_base_fee(10, policy.max_block_units, &policy).expect("valid policy") > 10);
    }

    #[test]
    fn invalid_policy_and_overflow_fail_closed() {
        let invalid = FeePolicy {
            target_block_units: 0,
            ..FeePolicy::default()
        };
        assert!(matches!(
            next_base_fee(10, 0, &invalid),
            Err(ChainError::InvalidFeePolicy)
        ));

        let overflow = FeePolicy {
            min_base_fee_per_unit: 1,
            target_block_units: 1,
            max_block_units: 2,
            base_fee_adjustment_denominator: 1,
        };
        assert!(matches!(
            next_base_fee(u64::MAX, 2, &overflow),
            Err(ChainError::ArithmeticOverflow)
        ));
    }
}
