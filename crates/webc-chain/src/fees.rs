//! Deterministic base-fee adjustment, protocol fee splitting, and storage-deposit pricing.
//!
//! This module owns only integer fee/pricing arithmetic. It does not debit
//! accounts or choose block contents. All calculations fail closed on invalid
//! policy values or overflow so hostile configuration cannot silently clamp
//! consensus state. Storage deposits priced here are refundable capital, not a
//! fee: the state machine locks them separately and only the deletion occupancy
//! remainder is ever burned.

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

/// Occupancy-priced storage deposit + deletion rebate policy (WEBC-DEFINITION §15.22).
///
/// Writing object state locks a refundable native deposit proportional to the
/// object's stored bytes (Sui-style occupancy pricing). Deleting the object
/// refunds `refund_bps` of the recorded deposit to the owner and burns the
/// remainder as the occupancy fee, which discourages parking dead state on
/// every validator forever. The deposit is refundable capital held in the
/// `storage_deposits` supply bucket while locked; only the burned remainder ever
/// leaves circulation. Launch constants are measurement-tuned placeholders
/// (§15.35); the mechanism, not the exact numbers, is what is fixed here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePricing {
    /// Native base units locked per stored object byte. A small placeholder;
    /// `0` disables storage deposits entirely (no lock, no refund, no burn).
    pub deposit_per_byte: u64,
    /// Basis points (`0..=10_000`) of a deposit refunded to the owner on
    /// deletion; the remaining `10_000 - refund_bps` is burned as the occupancy
    /// fee. `9_000` = 90% refunded, 10% burned.
    pub refund_bps: u16,
}

impl Default for StoragePricing {
    fn default() -> Self {
        // Cheap placeholder: 1000 base units/byte is 1e-9 WEBC/byte, so a full
        // 64 KiB object locks well under 0.0001 WEBC. 90% is refunded on delete.
        Self {
            deposit_per_byte: 1_000,
            refund_bps: 9_000,
        }
    }
}

/// Conserving split of a released storage deposit on object deletion.
///
/// `refund + burned == deposit` always holds, so settlement neither mints nor
/// loses native units — it only moves them out of the `storage_deposits` bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageRefund {
    /// Native base units returned to the owner's liquid balance.
    pub refund: Amount,
    /// Native base units permanently burned as the occupancy fee.
    pub burned: Amount,
}

impl StoragePricing {
    /// Rejects a policy whose refund share is outside the basis-point range.
    ///
    /// `refund_bps > 10_000` would compute a refund larger than the deposit and
    /// a negative (underflowing) burn, so it is rejected before any settlement.
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.refund_bps > 10_000 {
            return Err(ChainError::InvalidStoragePricing);
        }
        Ok(())
    }

    /// Refundable deposit that must be locked for `byte_len` stored object bytes.
    ///
    /// Deterministic checked arithmetic: `byte_len * deposit_per_byte`, in native
    /// base units. Object byte length is bounded by `MAX_OBJECT_DATA_BYTES`, so
    /// the product cannot realistically overflow `u128`, but the multiply is
    /// still checked to fail closed on hostile input rather than wrap.
    pub fn deposit_for_bytes(&self, byte_len: usize) -> Result<Amount, ChainError> {
        let bytes = u128::try_from(byte_len).map_err(|_| ChainError::ArithmeticOverflow)?;
        bytes
            .checked_mul(u128::from(self.deposit_per_byte))
            .map(Amount::from_units)
            .ok_or(ChainError::ArithmeticOverflow)
    }

    /// Splits a recorded deposit into `(refund, burned)` on object deletion.
    ///
    /// `refund = deposit * refund_bps / 10_000` (no overflow in the intermediate)
    /// and `burned = deposit - refund`, so the two always sum back to `deposit`.
    /// Fails closed if the policy's refund share is invalid.
    pub fn refund_split(&self, deposit: Amount) -> Result<StorageRefund, ChainError> {
        self.validate()?;
        let refund = deposit
            .checked_mul_bps(self.refund_bps)
            .ok_or(ChainError::ArithmeticOverflow)?;
        let burned = deposit
            .checked_sub(refund)
            .ok_or(ChainError::ArithmeticOverflow)?;
        Ok(StorageRefund { refund, burned })
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
    fn storage_deposit_scales_with_bytes_and_splits_conservingly() {
        let pricing = StoragePricing {
            deposit_per_byte: 1_000,
            refund_bps: 9_000,
        };
        // Deposit is exactly byte_len * deposit_per_byte.
        assert_eq!(
            pricing.deposit_for_bytes(0).unwrap(),
            Amount::from_units(0)
        );
        let deposit = pricing.deposit_for_bytes(64).unwrap();
        assert_eq!(deposit, Amount::from_units(64_000));

        // The refund/burn split always sums back to the deposit (no mint/loss).
        let split = pricing.refund_split(deposit).unwrap();
        assert_eq!(split.refund, Amount::from_units(57_600)); // 90%
        assert_eq!(split.burned, Amount::from_units(6_400)); // 10%
        assert_eq!(
            split.refund.checked_add(split.burned).unwrap(),
            deposit,
            "refund + burn must reconstruct the deposit"
        );
    }

    #[test]
    fn storage_pricing_edges_are_exact_and_fail_closed() {
        // Full refund keeps the whole deposit; zero burn.
        let full = StoragePricing {
            deposit_per_byte: 5,
            refund_bps: 10_000,
        };
        let split = full.refund_split(Amount::from_units(101)).unwrap();
        assert_eq!(split.refund, Amount::from_units(101));
        assert_eq!(split.burned, Amount::ZERO);

        // Zero refund burns the entire deposit.
        let none = StoragePricing {
            deposit_per_byte: 5,
            refund_bps: 0,
        };
        let split = none.refund_split(Amount::from_units(101)).unwrap();
        assert_eq!(split.refund, Amount::ZERO);
        assert_eq!(split.burned, Amount::from_units(101));

        // An out-of-range refund share is rejected before any settlement.
        let invalid = StoragePricing {
            deposit_per_byte: 1,
            refund_bps: 10_001,
        };
        assert!(matches!(
            invalid.refund_split(Amount::from_units(1)),
            Err(ChainError::InvalidStoragePricing)
        ));
        assert!(matches!(invalid.validate(), Err(ChainError::InvalidStoragePricing)));

        // A zero per-byte price disables deposits.
        let disabled = StoragePricing {
            deposit_per_byte: 0,
            refund_bps: 9_000,
        };
        assert_eq!(disabled.deposit_for_bytes(4_096).unwrap(), Amount::ZERO);
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
