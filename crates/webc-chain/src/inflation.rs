//! Confirmed annual inflation-rate curve and deterministic period distribution.
//!
//! The schedule calculates an annual integer budget from the supply at the
//! start of each protocol year. It distributes that budget using cumulative
//! integer division, so rounding cannot lose or create units across a complete
//! year. No wall clock is read; callers supply the consensus period index.

use crate::{Amount, ChainError};
use serde::{Deserialize, Serialize};

/// Version-1 WEBC inflation parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InflationSchedule {
    /// Initial annual rate in basis points; 1,000 means 10%.
    pub initial_rate_bps: u16,
    /// Numerator of the annual relative decay ratio.
    pub annual_decay_numerator: u16,
    /// Denominator of the annual relative decay ratio.
    pub annual_decay_denominator: u16,
    /// Minimum annual rate in basis points; 100 means 1%.
    pub floor_rate_bps: u16,
    /// Number of deterministic reward periods in one protocol year.
    pub reward_periods_per_year: u64,
}

impl Default for InflationSchedule {
    fn default() -> Self {
        Self {
            initial_rate_bps: 1_000,
            annual_decay_numerator: 4,
            annual_decay_denominator: 5,
            floor_rate_bps: 100,
            reward_periods_per_year: 365,
        }
    }
}

impl InflationSchedule {
    /// Validates the schedule and returns its non-zero period count.
    pub fn validated_periods_per_year(&self) -> Result<u64, ChainError> {
        self.validate()?;
        Ok(self.reward_periods_per_year)
    }

    /// Returns the annual rate for a zero-based protocol year.
    pub fn rate_bps_for_year(&self, year: u64) -> Result<u16, ChainError> {
        self.validate()?;
        let mut numerator = u128::from(self.initial_rate_bps);
        let mut denominator = 1u128;
        for _ in 0..year {
            numerator = numerator
                .checked_mul(u128::from(self.annual_decay_numerator))
                .ok_or(ChainError::ArithmeticOverflow)?;
            denominator = denominator
                .checked_mul(u128::from(self.annual_decay_denominator))
                .ok_or(ChainError::ArithmeticOverflow)?;
            let floor_scaled = u128::from(self.floor_rate_bps)
                .checked_mul(denominator)
                .ok_or(ChainError::ArithmeticOverflow)?;
            if numerator <= floor_scaled {
                return Ok(self.floor_rate_bps);
            }
        }
        let rate = numerator / denominator;
        u16::try_from(rate).map_err(|_| ChainError::ArithmeticOverflow)
    }

    /// Returns issuance for one absolute reward period.
    ///
    /// `year_start_supply` is the gross issued supply captured at the first
    /// period of the relevant protocol year. Summing all periods in that year
    /// equals `floor(year_start_supply * rate / 10_000)` exactly.
    pub fn reward_for_period(
        &self,
        year_start_supply: Amount,
        absolute_period: u64,
    ) -> Result<Amount, ChainError> {
        self.validate()?;
        let year = absolute_period / self.reward_periods_per_year;
        let period = absolute_period % self.reward_periods_per_year;
        let rate = self.rate_bps_for_year(year)?;
        let annual_units = year_start_supply
            .0
            .checked_mul(u128::from(rate))
            .ok_or(ChainError::ArithmeticOverflow)?
            / 10_000;
        let periods = u128::from(self.reward_periods_per_year);
        let before = annual_units
            .checked_mul(u128::from(period))
            .ok_or(ChainError::ArithmeticOverflow)?
            / periods;
        let after_period = period
            .checked_add(1)
            .ok_or(ChainError::ArithmeticOverflow)?;
        let after = annual_units
            .checked_mul(u128::from(after_period))
            .ok_or(ChainError::ArithmeticOverflow)?
            / periods;
        Ok(Amount::from_units(
            after
                .checked_sub(before)
                .ok_or(ChainError::ArithmeticOverflow)?,
        ))
    }

    fn validate(&self) -> Result<(), ChainError> {
        if self.reward_periods_per_year == 0
            || self.annual_decay_denominator == 0
            || self.annual_decay_numerator > self.annual_decay_denominator
            || self.floor_rate_bps > self.initial_rate_bps
            || self.initial_rate_bps > 10_000
        {
            return Err(ChainError::InvalidInflationSchedule);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_vectors_reach_confirmed_floor() {
        let schedule = InflationSchedule::default();
        let expected = [
            1_000, 800, 640, 512, 409, 327, 262, 209, 167, 134, 107, 100, 100,
        ];
        for (year, expected_rate) in expected.into_iter().enumerate() {
            assert_eq!(
                schedule
                    .rate_bps_for_year(u64::try_from(year).expect("small test year"))
                    .expect("default schedule must be valid"),
                expected_rate
            );
        }
    }

    #[test]
    fn period_rounding_preserves_exact_annual_budget() {
        let schedule = InflationSchedule {
            reward_periods_per_year: 7,
            ..InflationSchedule::default()
        };
        let supply = Amount::from_units(1_000_003);
        let mut total = Amount::ZERO;
        for period in 0..7 {
            total = total
                .checked_add(
                    schedule
                        .reward_for_period(supply, period)
                        .expect("valid test schedule"),
                )
                .expect("small test total");
        }
        assert_eq!(total, Amount::from_units(100_000));
    }
}
