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
    ///
    /// Every base fee — the global one and every localized per-namespace one — is
    /// floored here, so this is the "small network-wide floor" that still applies
    /// during global overload (§7 "Localized pricing").
    pub min_base_fee_per_unit: u64,
    /// Desired execution units per block; must be non-zero.
    pub target_block_units: u64,
    /// Hard execution-unit limit per block; must be at least the target.
    pub max_block_units: u64,
    /// Maximum proportional change divisor; must be non-zero.
    pub base_fee_adjustment_denominator: u64,
    /// Per-application-namespace congestion target in execution units (localized
    /// fees, §8 "Application isolation").
    ///
    /// A namespace's own localized base fee adjusts by the same EIP-1559 rule as
    /// the global base fee, but measured against THIS target using only that
    /// namespace's own per-block usage — so a busy namespace raises only its own
    /// price and one application's congestion never moves another's. Must be
    /// non-zero. A testnet-measured placeholder (§15.35), defaulting to a quarter
    /// of `target_block_units`.
    #[serde(default = "default_per_namespace_target_units")]
    pub per_namespace_target_units: u64,
    /// Fair-packing cap: the maximum share of `max_block_units` a single
    /// application namespace may consume in one block, in basis points
    /// (`0..=10_000`).
    ///
    /// Reserves block capacity for other namespaces so one hot application cannot
    /// monopolize a block (Phase 6 acceptance). `0` disables the cap (a namespace
    /// is then bounded only by `max_block_units`). A testnet-measured placeholder
    /// (§15.35), defaulting to 50%.
    #[serde(default = "default_namespace_block_share_bps")]
    pub namespace_block_share_bps: u16,
}

/// Default per-namespace congestion target: a quarter of the global block target.
fn default_per_namespace_target_units() -> u64 {
    250_000
}

/// Default fair-packing share cap: 50% of the block per namespace.
fn default_namespace_block_share_bps() -> u16 {
    5_000
}

impl Default for FeePolicy {
    fn default() -> Self {
        Self {
            min_base_fee_per_unit: 1,
            target_block_units: 1_000_000,
            max_block_units: 2_000_000,
            base_fee_adjustment_denominator: 8,
            per_namespace_target_units: default_per_namespace_target_units(),
            namespace_block_share_bps: default_namespace_block_share_bps(),
        }
    }
}

impl FeePolicy {
    /// Per-block execution-unit cap for a single application namespace (fair packing).
    ///
    /// Returns `max_block_units * namespace_block_share_bps / 10_000`, at least `1`.
    /// A `namespace_block_share_bps` of `0` disables the cap and returns
    /// `max_block_units` (a namespace bounded only by the whole-block limit). A
    /// share above `10_000` is rejected as an invalid policy. Deterministic checked
    /// integer arithmetic that fails closed rather than wrapping.
    pub fn namespace_block_unit_cap(&self) -> Result<u64, ChainError> {
        if self.namespace_block_share_bps == 0 {
            return Ok(self.max_block_units);
        }
        if self.namespace_block_share_bps > 10_000 {
            return Err(ChainError::InvalidFeePolicy);
        }
        let cap = u128::from(self.max_block_units)
            .checked_mul(u128::from(self.namespace_block_share_bps))
            .ok_or(ChainError::ArithmeticOverflow)?
            / 10_000;
        let cap = u64::try_from(cap).map_err(|_| ChainError::ArithmeticOverflow)?;
        Ok(cap.max(1))
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

/// Domain tag for the localized per-namespace fee-state Merkle sub-root.
///
/// Each `(namespace, NamespaceFeeState)` entry is a leaf under this domain, so any
/// change to a namespace's localized base fee changes the state root. Bumping this
/// constant is a consensus-format change.
pub const NAMESPACE_FEE_LEAF_DOMAIN: &[u8] = b"WEBC_NAMESPACE_FEE_LEAF_V1";

/// Localized (per-application-namespace) base-fee state (§8 "Application isolation").
///
/// One record per currently-congested namespace. `base_fee_per_unit` is that
/// namespace's own EIP-1559 base fee, adjusted each block from ONLY that
/// namespace's own execution-unit usage and floored at the network-wide
/// `min_base_fee_per_unit`. A namespace resting at the floor carries no record —
/// pricing at the floor is identical to having none — so the map holds only
/// congested namespaces and stays bounded. Committed by the state root through the
/// [`NAMESPACE_FEE_LEAF_DOMAIN`] sub-root; it locks no native units, so it does not
/// enter supply reconciliation (localized pricing changes the *rate*, never the
/// accounting).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceFeeState {
    /// This namespace's localized base fee, in base units per execution unit.
    ///
    /// Always strictly above `min_base_fee_per_unit` while a record exists (a value
    /// at or below the floor is dropped by the block-finish adjustment).
    pub base_fee_per_unit: u64,
}

/// Shared EIP-1559 integer base-fee adjustment.
///
/// Raises the fee toward `current + current*(used-target)/(target*denominator)`
/// when `used > target` (minimum +1 so a persistently full target always moves),
/// symmetrically lowers it when `used < target`, and floors the result at `min`.
/// `min_decrease_step` sets the smallest downward move when `used < target`: `0`
/// preserves the plain EIP-1559 rule (a small fee can stall just above the floor),
/// while `1` guarantees the fee decays all the way to `min` when persistently idle
/// — the localized path uses `1` so an uncongested namespace always returns to the
/// floor and its committed record is dropped, keeping the per-namespace fee map
/// bounded. Callers must validate `target != 0` and `denominator != 0` first.
/// Deterministic checked arithmetic that fails closed on overflow.
fn adjust_base_fee(
    current: u64,
    units_used: u64,
    target: u64,
    denominator: u64,
    min: u64,
    min_decrease_step: u64,
) -> Result<u64, ChainError> {
    let current = current.max(min);
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
        let decrease = u64::try_from(decrease)
            .map_err(|_| ChainError::ArithmeticOverflow)?
            .max(min_decrease_step);
        // `saturating_sub` cannot underflow; the `.max(min)` floor is what actually
        // bounds the result (the plain-EIP-1559 decrease is always `<= current`, and
        // a forced `min_decrease_step` only ever drives `current` down toward `min`).
        Ok(current.saturating_sub(decrease).max(min))
    }
}

/// Computes the next block's global base fee in base units per execution unit.
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
    adjust_base_fee(
        current,
        units_used,
        policy.target_block_units,
        policy.base_fee_adjustment_denominator,
        policy.min_base_fee_per_unit,
        // The single global base fee keeps the plain EIP-1559 rule (no forced
        // downward step); it is one scalar and never accumulates records.
        0,
    )
}

/// Computes a namespace's next localized base fee from its OWN block usage.
///
/// Identical EIP-1559 integer math to [`next_base_fee`], but measured against the
/// per-namespace target ([`FeePolicy::per_namespace_target_units`]) using only this
/// namespace's own execution units — so one application's congestion never moves
/// another application's localized price (Phase 6 acceptance). Floored at the
/// network-wide `min_base_fee_per_unit`, so a namespace with no congestion decays
/// toward — and rests at — the floor. Fails closed on an invalid policy or on a
/// usage above the whole-block hard limit.
pub fn next_localized_base_fee(
    current: u64,
    namespace_units_used: u64,
    policy: &FeePolicy,
) -> Result<u64, ChainError> {
    if policy.per_namespace_target_units == 0
        || policy.base_fee_adjustment_denominator == 0
        || namespace_units_used > policy.max_block_units
    {
        return Err(ChainError::InvalidFeePolicy);
    }
    adjust_base_fee(
        current,
        namespace_units_used,
        policy.per_namespace_target_units,
        policy.base_fee_adjustment_denominator,
        policy.min_base_fee_per_unit,
        // Force at least a 1-unit downward step when idle so an uncongested
        // namespace always decays to the floor and sheds its committed record.
        1,
    )
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
        assert_eq!(pricing.deposit_for_bytes(0).unwrap(), Amount::from_units(0));
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
        assert!(matches!(
            invalid.validate(),
            Err(ChainError::InvalidStoragePricing)
        ));

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
    fn localized_base_fee_rises_only_from_its_own_usage() {
        let policy = FeePolicy::default();
        // Namespace usage above its per-namespace target raises the localized fee.
        let hot = next_localized_base_fee(10, policy.per_namespace_target_units * 2, &policy)
            .expect("valid policy");
        assert!(hot > 10, "over-target namespace usage must raise the fee");
        // Usage below the target lowers it, but never below the network floor.
        let cool = next_localized_base_fee(10, 0, &policy).expect("valid policy");
        assert!(cool < 10);
        assert!(cool >= policy.min_base_fee_per_unit);
        // A low current fee with no usage cannot fall under the network minimum.
        assert_eq!(
            next_localized_base_fee(policy.min_base_fee_per_unit, 0, &policy).unwrap(),
            policy.min_base_fee_per_unit
        );
    }

    #[test]
    fn localized_base_fee_decays_all_the_way_to_the_floor_when_idle() {
        // The forced 1-unit downward step guarantees an idle namespace returns to
        // the network floor (a plain EIP-1559 decrease stalls just above it), so a
        // once-congested namespace's committed record can always be dropped.
        let policy = FeePolicy::default();
        let mut fee = 1_000u64;
        for _ in 0..10_000 {
            fee = next_localized_base_fee(fee, 0, &policy).expect("valid policy");
        }
        assert_eq!(
            fee, policy.min_base_fee_per_unit,
            "idle localized fee reaches the floor"
        );
    }

    #[test]
    fn localized_base_fee_fails_closed_on_invalid_policy_and_overflow() {
        let invalid = FeePolicy {
            per_namespace_target_units: 0,
            ..FeePolicy::default()
        };
        assert!(matches!(
            next_localized_base_fee(10, 0, &invalid),
            Err(ChainError::InvalidFeePolicy)
        ));
        // Usage above the whole-block hard limit is rejected before any math.
        assert!(matches!(
            next_localized_base_fee(
                10,
                FeePolicy::default().max_block_units + 1,
                &FeePolicy::default()
            ),
            Err(ChainError::InvalidFeePolicy)
        ));
        let overflow = FeePolicy {
            min_base_fee_per_unit: 1,
            per_namespace_target_units: 1,
            max_block_units: 2,
            base_fee_adjustment_denominator: 1,
            ..FeePolicy::default()
        };
        assert!(matches!(
            next_localized_base_fee(u64::MAX, 2, &overflow),
            Err(ChainError::ArithmeticOverflow)
        ));
    }

    #[test]
    fn namespace_block_unit_cap_is_a_share_of_the_block() {
        let policy = FeePolicy::default();
        // 50% of the 2_000_000 default block.
        assert_eq!(policy.namespace_block_unit_cap().unwrap(), 1_000_000);
        // Zero share bps disables the cap (bounded only by the whole block).
        let disabled = FeePolicy {
            namespace_block_share_bps: 0,
            ..FeePolicy::default()
        };
        assert_eq!(
            disabled.namespace_block_unit_cap().unwrap(),
            policy.max_block_units
        );
        // A share above 100% is rejected as an invalid policy.
        let bad = FeePolicy {
            namespace_block_share_bps: 10_001,
            ..FeePolicy::default()
        };
        assert!(matches!(
            bad.namespace_block_unit_cap(),
            Err(ChainError::InvalidFeePolicy)
        ));
    }

    #[test]
    fn fee_policy_deserializes_without_the_new_localized_knobs() {
        // A genesis written before localized fees omits the new fields; serde
        // defaults must fill them so an older config still decodes deterministically.
        let json = r#"{
            "min_base_fee_per_unit": 1,
            "target_block_units": 1000000,
            "max_block_units": 2000000,
            "base_fee_adjustment_denominator": 8
        }"#;
        let policy: FeePolicy = serde_json::from_str(json).expect("legacy policy decodes");
        assert_eq!(policy, FeePolicy::default());
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
            ..FeePolicy::default()
        };
        assert!(matches!(
            next_base_fee(u64::MAX, 2, &overflow),
            Err(ChainError::ArithmeticOverflow)
        ));
    }
}
