//! Validator pools, explicit eligibility states, delegation records, and staking config.
//!
//! The module owns pool-local data and threshold evaluation but does not process
//! epoch queues, rewards, slashing evidence, or consensus votes. Its bootstrap
//! flag is retained only for hostile legacy-wire rejection and never grants
//! voting power. State execution owns atomic mirror updates.

use crate::Amount;
use serde::{Deserialize, Serialize};
use webc_crypto::{Address, PublicKeyBytes};

/// Seven-day target expressed in one-minute epochs for configuration tests.
///
/// Mainnet must recompute this if its measured epoch duration changes before
/// configuration freeze; the protocol stores epochs, never wall-clock reads.
pub const SEVEN_DAY_TARGET_AT_ONE_MINUTE_EPOCHS: u64 = 7 * 24 * 60;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    /// Registered pool that cannot vote or produce until stake rules are met.
    PendingActivation,
    /// Eligible pool included by a newly built validator-set snapshot.
    Active,
    /// Previously active pool below a threshold after a snapshot transition.
    Draining,
    /// Temporarily excluded after an objective protocol penalty.
    Jailed {
        /// Stable human-readable reason; consensus must not infer evidence from it.
        reason: String,
    },
    /// Permanently excluded after severe objective signed evidence.
    Tombstoned {
        /// Stable human-readable reason; consensus must not infer evidence from it.
        reason: String,
    },
}

/// Validator pool record mirrored into deterministic chain state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validator {
    /// Pool operator account and validator identity.
    pub operator: Address,
    /// Ed25519 public key that authenticates current consensus messages.
    pub consensus_key: PublicKeyBytes,
    /// Operator principal in native base units.
    pub self_stake: Amount,
    /// Sum of active delegation principal in native base units.
    pub delegated_stake: Amount,
    /// Operator commission in basis points, where 10,000 is 100%.
    pub commission_bps: u16,
    /// Eligibility or penalty state used by validator-set snapshots.
    pub status: ValidatorStatus,
    /// Legacy wire flag retained only so new paths can reject it explicitly.
    pub bootstrap: bool,
    /// Claimable operator rewards in native base units.
    pub accumulated_rewards: Amount,
}

impl Validator {
    /// Returns operator plus delegated active stake, failing on corrupt overflow.
    pub fn total_stake(&self) -> Result<Amount, crate::ChainError> {
        self.self_stake
            .checked_add(self.delegated_stake)
            .ok_or(crate::ChainError::ArithmeticOverflow)
    }

    /// Returns whether a new validator-set snapshot may include this pool.
    pub fn is_active(&self) -> bool {
        self.status == ValidatorStatus::Active
    }

    /// Recomputes eligibility after a stake change without releasing jailed or tombstoned pools.
    pub fn refresh_stake_status(
        &mut self,
        config: &StakingConfig,
    ) -> Result<(), crate::ChainError> {
        if matches!(
            self.status,
            ValidatorStatus::Jailed { .. } | ValidatorStatus::Tombstoned { .. }
        ) {
            return Ok(());
        }
        let maximum_delegated = self
            .self_stake
            .checked_mul_u64(4)
            .ok_or(crate::ChainError::ArithmeticOverflow)?;
        let was_active = matches!(
            self.status,
            ValidatorStatus::Active | ValidatorStatus::Draining
        );
        self.status = if self.self_stake >= config.min_validator_self_stake
            && self.delegated_stake <= maximum_delegated
            && self.total_stake()? >= config.min_validator_total_stake
        {
            ValidatorStatus::Active
        } else if was_active {
            ValidatorStatus::Draining
        } else {
            ValidatorStatus::PendingActivation
        };
        Ok(())
    }
}

/// One delegator's active principal and earned-reward position.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    /// Account that owns the principal and rewards.
    pub delegator: Address,
    /// Validator operator receiving the delegated voting stake.
    pub validator: Address,
    /// Active principal in native base units.
    pub amount: Amount,
    /// Claimable rewards in native base units.
    pub accumulated_rewards: Amount,
}

/// Versioned-chain staking thresholds expressed in base units and epochs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakingConfig {
    /// Minimum operator stake, in base units, required for any registered pool.
    pub min_validator_self_stake: Amount,
    /// Minimum total active pool stake, in base units, required to vote or produce.
    pub min_validator_total_stake: Amount,
    /// Minimum amount, in base units, for one active delegation position.
    pub min_delegation: Amount,
    /// Maximum operator commission in basis points, where 10,000 is 100%.
    pub max_commission_bps: u16,
    /// Normal cooldown after churn admission, measured in consensus epochs.
    pub unbonding_cooldown_epochs: u64,
    /// Evidence window after admission, measured in consensus epochs.
    pub slashable_unbonding_epochs: u64,
    /// Maximum native base units admitted into cooldown per epoch.
    pub max_unbonding_units_per_epoch: Amount,
}

impl Default for StakingConfig {
    fn default() -> Self {
        Self {
            min_validator_self_stake: Amount::from_webc(20),
            min_validator_total_stake: Amount::from_webc(100),
            min_delegation: Amount::from_webc(1),
            max_commission_bps: 2_000,
            // The prototype treats one epoch as one devnet minute. Mainnet
            // configuration is separately versioned before launch.
            unbonding_cooldown_epochs: 7,
            slashable_unbonding_epochs: 7,
            max_unbonding_units_per_epoch: Amount::from_webc(1_000),
        }
    }
}

impl StakingConfig {
    /// Sets normal cooldown and evidence windows in consensus epoch units.
    ///
    /// This is configuration construction only. Mainnet launch review must map
    /// its measured epoch duration to the confirmed about-seven-day target.
    pub fn with_unbonding_delay_epochs(mut self, epochs: u64) -> Self {
        self.unbonding_cooldown_epochs = epochs;
        self.slashable_unbonding_epochs = epochs;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_and_configurable_mainnet_delay_targets_are_explicit() {
        let devnet = StakingConfig::default();
        assert_eq!(devnet.unbonding_cooldown_epochs, 7);
        let mainnet_target = devnet
            .clone()
            .with_unbonding_delay_epochs(SEVEN_DAY_TARGET_AT_ONE_MINUTE_EPOCHS);
        assert_eq!(mainnet_target.unbonding_cooldown_epochs, 10_080);
        assert_eq!(mainnet_target.slashable_unbonding_epochs, 10_080);
    }
}
