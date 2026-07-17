//! Stake-locked, vest-by-operation grant primitive (distribution-program §3.2).
//!
//! Phase 5 prepares the primitive so the Phase 16 incentivized-testnet /
//! distribution program does not have to retrofit it. A [`StakeGrant`] is an
//! allocation of native units that are **stake-locked** — usable only as a
//! validator's self-stake, counting toward the ≥20 WEBC / ≥20%-of-pool
//! requirement — and that **vest by operation**: a fixed fraction unlocks per
//! epoch of provably correct validation over a target horizon (1–2 years), while
//! quitting early or misbehaving forfeits the still-locked remainder (which the
//! program reverts to the contributor pool).
//!
//! This module is the deterministic vesting/forfeiture *math*, testable in
//! isolation. Wiring grants into the self-stake accounting and the supply
//! invariant (grant-locked units count as stake but cannot be withdrawn until
//! vested) is the Phase 16 program integration and is intentionally deferred —
//! the constants (horizon, per-operator cap, co-stake ramp, diversity criteria)
//! are published with that program.

use crate::{Amount, ChainError};
use serde::{Deserialize, Serialize};
use webc_crypto::Address;

/// A stake-locked grant that vests linearly per epoch of correct validation.
///
/// The grant is defined over `[start_epoch, start_epoch + vest_epochs)`: at
/// `start_epoch` nothing is vested, and after `vest_epochs` full epochs the whole
/// grant is vested. Vesting is realized only by epochs the beneficiary actually
/// validated correctly — the program advances [`credited_epochs`] only for such
/// epochs, so downtime simply does not progress vesting (it does not, by itself,
/// forfeit). A forfeiture (early exit / slashable fault) freezes vesting and
/// returns the locked remainder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeGrant {
    /// The operator the grant is stake-locked to.
    pub beneficiary: Address,
    /// Total granted units.
    pub total: Amount,
    /// Number of correctly-validated epochs over which the grant fully vests.
    /// Must be non-zero.
    pub vest_epochs: u64,
    /// Correctly-validated epochs credited so far (advanced by the program, one
    /// per proven epoch). Capped at `vest_epochs` for vesting purposes.
    pub credited_epochs: u64,
    /// Set once the grant is forfeited; vesting freezes and the locked remainder
    /// is returned to the program's reversion pool.
    pub forfeited: bool,
}

impl StakeGrant {
    /// Creates a fresh grant. Returns an error if `vest_epochs` is zero.
    pub fn new(beneficiary: Address, total: Amount, vest_epochs: u64) -> Result<Self, ChainError> {
        if vest_epochs == 0 {
            return Err(ChainError::InvalidStakeGrant);
        }
        Ok(Self {
            beneficiary,
            total,
            vest_epochs,
            credited_epochs: 0,
            forfeited: false,
        })
    }

    /// The units vested so far: `total × min(credited, vest_epochs) / vest_epochs`
    /// (floored). A forfeited grant vests nothing further beyond what it had at
    /// forfeiture — callers should read [`vested`] before calling [`forfeit`] if
    /// they need the pre-forfeit figure. `vest_epochs` is guaranteed non-zero by
    /// the constructor.
    pub fn vested(&self) -> Result<Amount, ChainError> {
        if self.vest_epochs == 0 {
            return Err(ChainError::InvalidStakeGrant);
        }
        let credited = self.credited_epochs.min(self.vest_epochs);
        let vested_units = self
            .total
            .0
            .checked_mul(u128::from(credited))
            .ok_or(ChainError::ArithmeticOverflow)?
            / u128::from(self.vest_epochs);
        Ok(Amount::from_units(vested_units))
    }

    /// The still-locked remainder: `total − vested`.
    pub fn locked(&self) -> Result<Amount, ChainError> {
        self.total
            .checked_sub(self.vested()?)
            .ok_or(ChainError::ArithmeticOverflow)
    }

    /// Whether the grant has fully vested (all epochs credited).
    pub fn is_fully_vested(&self) -> bool {
        self.credited_epochs >= self.vest_epochs
    }

    /// Credits one correctly-validated epoch, advancing vesting. A forfeited or
    /// fully-vested grant does not advance further.
    pub fn credit_epoch(&mut self) {
        if !self.forfeited && self.credited_epochs < self.vest_epochs {
            self.credited_epochs = self.credited_epochs.saturating_add(1);
        }
    }

    /// Forfeits the grant, freezing vesting. Returns the locked remainder that the
    /// program reverts to the contributor pool.
    pub fn forfeit(&mut self) -> Result<Amount, ChainError> {
        let locked = self.locked()?;
        self.forfeited = true;
        Ok(locked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webc_crypto::Keypair;

    fn beneficiary() -> Address {
        Keypair::from_seed([77u8; 32]).address()
    }

    #[test]
    fn grant_vests_linearly_per_credited_epoch() {
        let mut grant = StakeGrant::new(beneficiary(), Amount::from_webc(100), 10).unwrap();
        assert_eq!(grant.vested().unwrap(), Amount::ZERO);
        assert_eq!(grant.locked().unwrap(), Amount::from_webc(100));

        for _ in 0..4 {
            grant.credit_epoch();
        }
        // 4/10 of 100 WEBC vested.
        assert_eq!(grant.vested().unwrap(), Amount::from_webc(40));
        assert_eq!(grant.locked().unwrap(), Amount::from_webc(60));
        assert!(!grant.is_fully_vested());

        for _ in 0..6 {
            grant.credit_epoch();
        }
        assert!(grant.is_fully_vested());
        assert_eq!(grant.vested().unwrap(), Amount::from_webc(100));
        assert_eq!(grant.locked().unwrap(), Amount::ZERO);
        // Crediting beyond the horizon does not over-vest.
        grant.credit_epoch();
        assert_eq!(grant.vested().unwrap(), Amount::from_webc(100));
    }

    #[test]
    fn forfeit_freezes_vesting_and_returns_the_locked_remainder() {
        let mut grant = StakeGrant::new(beneficiary(), Amount::from_webc(100), 10).unwrap();
        for _ in 0..3 {
            grant.credit_epoch();
        }
        let reverted = grant.forfeit().unwrap();
        // 3/10 vested (30), so 70 reverts to the program pool.
        assert_eq!(reverted, Amount::from_webc(70));
        assert!(grant.forfeited);
        // A forfeited grant vests no further even if epochs are (wrongly) credited.
        grant.credit_epoch();
        assert_eq!(grant.vested().unwrap(), Amount::from_webc(30));
    }

    #[test]
    fn zero_vest_epochs_is_rejected() {
        assert!(matches!(
            StakeGrant::new(beneficiary(), Amount::from_webc(1), 0),
            Err(ChainError::InvalidStakeGrant)
        ));
    }
}
