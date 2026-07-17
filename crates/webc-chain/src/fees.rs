//! Deterministic base-fee adjustment and versioned transaction fee accounting.
//!
//! Purpose: keep every consensus fee calculation in one auditable module.
//! Responsibilities: adjust the dynamic base fee, preserve the legacy V4 fee
//! split, and construct/validate the protocol-V2 fee summary committed by a V1
//! receipt. Non-responsibilities: selecting a payer, reserving funds, mutating
//! accounts, or choosing block contents. Execution supplies validated typed
//! inputs, this module performs checked integer arithmetic, and returns a fully
//! reconciled summary. Hostile decoded summaries are revalidated field by field;
//! any unsupported version, inconsistency, or overflow fails closed without a
//! state change.

use crate::{Amount, AuthorizationLaneId, ChainError};
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use webc_crypto::Address;

/// Schema version carried by every [`FeeSummaryV1`].
pub const FEE_SUMMARY_V1: u16 = 1;

macro_rules! decimal_u64_wrapper {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            /// Constructs the typed value from its exact integer unit.
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            /// Returns the exact integer unit.
            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.serialize_str(&self.0.to_string())
                } else {
                    serializer.serialize_u64(self.0)
                }
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                if deserializer.is_human_readable() {
                    let value = String::deserialize(deserializer)?;
                    if value.is_empty()
                        || (value.len() > 1 && value.starts_with('0'))
                        || !value.bytes().all(|byte| byte.is_ascii_digit())
                    {
                        return Err(D::Error::custom("expected a canonical unsigned decimal string"));
                    }
                    value
                        .parse::<u64>()
                        .map(Self)
                        .map_err(D::Error::custom)
                } else {
                    u64::deserialize(deserializer).map(Self)
                }
            }
        }
    };
}

decimal_u64_wrapper!(
    /// Deterministic execution work measured in protocol gas units.
    GasUnits
);

decimal_u64_wrapper!(
    /// Native base units charged for one gas unit.
    FeeRate
);

/// Exact fee source selected by a prepared transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeePayerV1 {
    /// Account whose liquid balance or prepaid lane funds the reservation.
    pub address: Address,
    /// Authorization lane containing the fee balance and replay state.
    pub lane: AuthorizationLaneId,
}

/// Complete protocol-V2 fee result committed by a transaction receipt.
///
/// Amount fields use exact native base units. Gas/rate fields serialize as
/// decimal strings in JSON so a browser never rounds a `u64` above `2^53`.
/// [`FeeSummaryV1::validate`] recomputes every derived field before a decoded
/// receipt is trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeeSummaryV1 {
    /// Must equal [`FEE_SUMMARY_V1`].
    pub version: u16,
    /// Account and lane that paid; sponsorship changes this, never action authority.
    pub payer: FeePayerV1,
    /// Maximum gas units authorized and reserved by the payer.
    pub gas_limit: GasUnits,
    /// Deterministically measured work, no greater than `gas_limit`.
    pub units_consumed: GasUnits,
    /// Block base fee in native base units per gas unit.
    pub base_fee_per_unit: FeeRate,
    /// Effective, capped priority fee in native base units per gas unit.
    pub priority_fee_per_unit: FeeRate,
    /// Sender-authorized maximum total rate in native base units per gas unit.
    pub max_fee_per_unit: FeeRate,
    /// `gas_limit * max_fee_per_unit`, debited before action execution.
    pub reserved: Amount,
    /// `units_consumed * base_fee_per_unit`.
    pub base_fee: Amount,
    /// `units_consumed * priority_fee_per_unit`.
    pub priority_fee: Amount,
    /// `base_fee + priority_fee`.
    pub charged: Amount,
    /// `reserved - charged`, returned to the payer.
    pub refund: Amount,
    /// Floor of half the base fee; priority fees are never burned.
    pub burned: Amount,
    /// Base-fee remainder plus the complete priority fee.
    pub validator_reward: Amount,
}

/// Typed failures for protocol-V2 fee calculation and hostile summary checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FeeComputationError {
    /// A decoded summary names a schema this implementation does not understand.
    #[error("unsupported fee-summary version {actual}")]
    UnsupportedVersion { actual: u16 },
    /// Measured work exceeds the payer-authorized limit.
    #[error("consumed gas units exceed the gas limit")]
    GasLimitExceeded,
    /// The maximum total rate cannot cover the block's base rate.
    #[error("maximum fee per unit is below the base fee")]
    MaxFeeBelowBase,
    /// A multiplication, addition, or subtraction exceeded the exact amount range.
    #[error("fee arithmetic overflow")]
    ArithmeticOverflow,
    /// A decoded summary disagrees with deterministic recomputation.
    #[error("fee summary does not reconcile")]
    InconsistentSummary,
}

impl FeeSummaryV1 {
    /// Recomputes and verifies every consensus-critical fee field.
    ///
    /// This method is pure and changes no state. It rejects unknown versions,
    /// impossible unit/rate combinations, arithmetic overflow, and any tampered
    /// derived amount.
    pub fn validate(&self) -> Result<(), FeeComputationError> {
        if self.version != FEE_SUMMARY_V1 {
            return Err(FeeComputationError::UnsupportedVersion {
                actual: self.version,
            });
        }
        let expected = calculate_fee_summary_v1(
            self.payer,
            self.gas_limit,
            self.units_consumed,
            self.base_fee_per_unit,
            self.max_fee_per_unit,
            self.priority_fee_per_unit,
        )?;
        if &expected != self {
            return Err(FeeComputationError::InconsistentSummary);
        }
        Ok(())
    }
}

/// Computes the exact fee reservation, charge, refund, burn, and reward.
///
/// `requested_priority_fee_per_unit` is capped by the room between the base
/// rate and maximum rate. The odd base-fee unit goes to the validator, and the
/// entire priority fee goes to the validator. Inputs and outputs are consensus
/// critical; this pure function never reads state, time, or network data.
pub fn calculate_fee_summary_v1(
    payer: FeePayerV1,
    gas_limit: GasUnits,
    units_consumed: GasUnits,
    base_fee_per_unit: FeeRate,
    max_fee_per_unit: FeeRate,
    requested_priority_fee_per_unit: FeeRate,
) -> Result<FeeSummaryV1, FeeComputationError> {
    if units_consumed > gas_limit {
        return Err(FeeComputationError::GasLimitExceeded);
    }
    let priority_room = max_fee_per_unit
        .get()
        .checked_sub(base_fee_per_unit.get())
        .ok_or(FeeComputationError::MaxFeeBelowBase)?;
    let priority_fee_per_unit =
        FeeRate::new(requested_priority_fee_per_unit.get().min(priority_room));

    let amount_product = |left: u64, right: u64| {
        u128::from(left)
            .checked_mul(u128::from(right))
            .map(Amount::from_units)
            .ok_or(FeeComputationError::ArithmeticOverflow)
    };
    let reserved = amount_product(gas_limit.get(), max_fee_per_unit.get())?;
    let base_fee = amount_product(units_consumed.get(), base_fee_per_unit.get())?;
    let priority_fee = amount_product(units_consumed.get(), priority_fee_per_unit.get())?;
    let charged = base_fee
        .checked_add(priority_fee)
        .ok_or(FeeComputationError::ArithmeticOverflow)?;
    let refund = reserved
        .checked_sub(charged)
        .ok_or(FeeComputationError::ArithmeticOverflow)?;
    let (burned, base_reward) = base_fee.half_split();
    let validator_reward = base_reward
        .checked_add(priority_fee)
        .ok_or(FeeComputationError::ArithmeticOverflow)?;

    Ok(FeeSummaryV1 {
        version: FEE_SUMMARY_V1,
        payer,
        gas_limit,
        units_consumed,
        base_fee_per_unit,
        priority_fee_per_unit,
        max_fee_per_unit,
        reserved,
        base_fee,
        priority_fee,
        charged,
        refund,
        burned,
        validator_reward,
    })
}

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
    use crate::AuthorizationLaneId;
    use proptest::prelude::*;
    use webc_crypto::Keypair;

    fn payer() -> FeePayerV1 {
        FeePayerV1 {
            address: Keypair::from_seed([7; 32]).address(),
            lane: AuthorizationLaneId::DEFAULT,
        }
    }

    #[test]
    fn fee_split_preserves_total() {
        let fee = Amount::from_units(101);
        let split = split_fee(fee);
        assert_eq!(split.burned.0 + split.validator_reward.0, fee.0);
    }

    #[test]
    fn v1_separates_base_burn_from_validator_priority_fee() {
        let summary = calculate_fee_summary_v1(
            payer(),
            GasUnits::new(10),
            GasUnits::new(3),
            FeeRate::new(5),
            FeeRate::new(9),
            FeeRate::new(2),
        )
        .expect("bounded fixture fee must calculate");

        assert_eq!(summary.reserved, Amount::from_units(90));
        assert_eq!(summary.base_fee, Amount::from_units(15));
        assert_eq!(summary.priority_fee, Amount::from_units(6));
        assert_eq!(summary.charged, Amount::from_units(21));
        assert_eq!(summary.refund, Amount::from_units(69));
        assert_eq!(summary.burned, Amount::from_units(7));
        assert_eq!(summary.validator_reward, Amount::from_units(14));
        summary.validate().expect("fresh summary must reconcile");
    }

    #[test]
    fn v1_caps_priority_and_rejects_impossible_inputs() {
        let capped = calculate_fee_summary_v1(
            payer(),
            GasUnits::new(4),
            GasUnits::new(4),
            FeeRate::new(8),
            FeeRate::new(9),
            FeeRate::new(100),
        )
        .expect("priority fee has one unit of room");
        assert_eq!(capped.priority_fee_per_unit, FeeRate::new(1));
        assert_eq!(capped.priority_fee, Amount::from_units(4));

        assert_eq!(
            calculate_fee_summary_v1(
                payer(),
                GasUnits::new(3),
                GasUnits::new(4),
                FeeRate::new(1),
                FeeRate::new(1),
                FeeRate::new(0),
            ),
            Err(FeeComputationError::GasLimitExceeded)
        );
        assert_eq!(
            calculate_fee_summary_v1(
                payer(),
                GasUnits::new(1),
                GasUnits::new(1),
                FeeRate::new(2),
                FeeRate::new(1),
                FeeRate::new(0),
            ),
            Err(FeeComputationError::MaxFeeBelowBase)
        );
    }

    #[test]
    fn v1_validation_rejects_tampering_and_unknown_versions() {
        let mut summary = calculate_fee_summary_v1(
            payer(),
            GasUnits::new(5),
            GasUnits::new(2),
            FeeRate::new(3),
            FeeRate::new(5),
            FeeRate::new(1),
        )
        .expect("fixture fee must calculate");
        summary.refund = Amount::from_units(summary.refund.0 + 1);
        assert_eq!(
            summary.validate(),
            Err(FeeComputationError::InconsistentSummary)
        );
        summary.version = 99;
        assert_eq!(
            summary.validate(),
            Err(FeeComputationError::UnsupportedVersion { actual: 99 })
        );
    }

    #[test]
    fn v1_json_uses_exact_decimal_strings_for_u64_values() {
        let summary = calculate_fee_summary_v1(
            payer(),
            GasUnits::new(u64::MAX),
            GasUnits::new(1),
            FeeRate::new(1),
            FeeRate::new(1),
            FeeRate::new(0),
        )
        .expect("u64 bounds fit in u128 reservation");
        let mut value = serde_json::to_value(summary).expect("summary must serialize");
        assert_eq!(value["gas_limit"], u64::MAX.to_string());
        assert_eq!(value["max_fee_per_unit"], "1");

        value["gas_limit"] = serde_json::Value::String("01".to_owned());
        assert!(serde_json::from_value::<FeeSummaryV1>(value).is_err());
    }

    proptest! {
        #[test]
        fn v1_fee_paths_conserve_reserved_and_charged(
            gas_limit in 0u64..1_000_000,
            units in 0u64..1_000_000,
            base in 0u64..1_000_000,
            extra in 0u64..1_000_000,
            requested_priority in 0u64..1_000_000,
        ) {
            let units = units.min(gas_limit);
            let max = base.checked_add(extra).expect("bounded generator cannot overflow");
            let summary = calculate_fee_summary_v1(
                payer(),
                GasUnits::new(gas_limit),
                GasUnits::new(units),
                FeeRate::new(base),
                FeeRate::new(max),
                FeeRate::new(requested_priority),
            ).expect("bounded generated fee must calculate");

            prop_assert_eq!(
                summary.charged.checked_add(summary.refund),
                Some(summary.reserved)
            );
            prop_assert_eq!(
                summary.burned.checked_add(summary.validator_reward),
                Some(summary.charged)
            );
            prop_assert_eq!(summary.validate(), Ok(()));
        }
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
