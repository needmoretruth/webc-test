//! Fee sponsorship (paymaster) registry, caps, and deterministic day-windows.
//!
//! Purpose: let a registered application pre-fund a budget that pays its users'
//! transaction fees, so an end user can transact without holding native units —
//! bounded by hard, deterministic caps (WEBC-DEFINITION §7, §15.35; the "delivery
//! rides the existing sponsorship mechanism" subsidy path of §3.3 /
//! `docs/distribution-program.md`).
//!
//! Responsibilities: define the per-application sponsor record ([`AppSponsor`]),
//! the protocol caps ([`SponsorshipConfig`]), the deterministic "per day" window
//! math, and the pure cap-enforcement/decrement logic ([`AppSponsor::try_charge`]).
//!
//! Non-responsibilities: this module never moves native supply, never touches
//! accounts, and never reads a wall clock, network, files, or randomness. The
//! `state` module owns the supply-conserving budget → burn + validator-reward
//! move and the state-commitment/access-list wiring; it calls the pure logic here.
//!
//! Data flow: `state::execute_transaction` computes a transaction's fee, resolves
//! the current day-window from the consensus epoch, and asks the named app's
//! `AppSponsor` to `try_charge` it. On success the sponsor's budget and counters
//! are decremented here; the caller performs the matching supply move. On any
//! cap miss the caller falls back to normal self-payment (fail-open).
//!
//! Security boundary: every input (fee, window, config, user) is untrusted.
//! All arithmetic is checked; nothing panics. Caps are hard bounds an app cannot
//! exceed, so a sponsor budget is never drainable beyond the app's declared
//! per-user / per-operation / per-app-per-day exposure, and a sponsor never gains
//! authority over a user's funds (a sponsor only ever pays, never signs for, the
//! user — ADR-0003).

use crate::{Amount, ChainError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use webc_crypto::{Address, Hash256};

/// Domain tag for the sponsor-registry Merkle sub-root committed by the state root.
///
/// Each `(namespace, AppSponsor)` entry is a leaf under this domain, so any change
/// to a sponsor's budget, caps, window, or per-user counters changes the state
/// root. Bumping this constant is a consensus-format change.
pub const SPONSOR_LEAF_DOMAIN: &[u8] = b"WEBC_SPONSOR_LEAF_V1";

/// Fixed application-key discriminant that isolates sponsor state inside the
/// `Application { namespace, key_hash }` key space.
///
/// A sponsor record for application `namespace` is addressed by the logical key
/// `StateKey::application(namespace, sponsor_state_key_hash())`. It is
/// domain-separated from object keys (which use the object id hash), so sponsor
/// state and object state under the same namespace never collide, while two
/// sponsored transactions for the same app deterministically share (and therefore
/// serialize on) this one hot key — correct for a shared budget.
const SPONSOR_STATE_KEY_DISCRIMINANT: &[u8] = b"WEBC_SPONSOR_STATE_KEY_V1";

/// Returns the fixed `key_hash` that addresses an application's sponsor record.
///
/// Deterministic: a domain-separated hash of a constant, identical on every node.
pub fn sponsor_state_key_hash() -> Hash256 {
    Hash256::digest(SPONSOR_STATE_KEY_DISCRIMINANT)
}

/// Hard, deterministic protocol caps on fee sponsorship (WEBC-DEFINITION §15.35).
///
/// The launch values are **testnet-measured placeholders**, not promises — the
/// method is fixed (per-user / per-operation / per-app-per-day hard bounds and a
/// simple-operation restriction), the numbers move with data. All fields carry
/// `#[serde(default)]` so a genesis written before sponsorship stays decodable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SponsorshipConfig {
    /// Master switch. When `false`, no transaction can draw from a sponsor budget
    /// (every sponsored transaction fails open to self-payment). Registration and
    /// funding still work, so a chain can pre-provision sponsors before enabling.
    pub enabled: bool,
    /// Maximum sponsored operations one user may have paid by one application per
    /// day-window. Placeholder ~20 (§15.35). Bounds a single user's daily drain.
    pub max_ops_per_user_per_app_per_day: u32,
    /// Maximum fee, in native base units, the protocol will let a sponsor cover
    /// for a single operation. Bounds the per-operation drain so a hostile user
    /// cannot empty a day's budget in one transaction via a large priority tip.
    pub max_sponsored_fee_per_op: Amount,
    /// Hard protocol ceiling, in native base units, on an application's
    /// self-chosen per-day budget cap. A `RegisterAppSponsor` whose
    /// `daily_budget_cap` exceeds this is rejected (§15.35 "within hard protocol
    /// caps").
    pub max_app_daily_budget: Amount,
    /// Number of consensus epochs in one "per day" window. The window index is
    /// `current_epoch / day_window_epochs`, so "per day" is expressed purely from
    /// consensus epochs — never a wall clock (a consensus path reads no clock).
    /// Must be non-zero. Placeholder 1440 (≈ one day at ~1-minute devnet epochs).
    pub day_window_epochs: u64,
}

impl Default for SponsorshipConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_ops_per_user_per_app_per_day: 20,
            // 1e-5 WEBC: comfortably covers an ordinary transfer's fee while
            // capping a single sponsored operation. Measurement-tuned (§15.35).
            max_sponsored_fee_per_op: Amount::from_units(10_000_000),
            // 10 WEBC per app per day-window as a hard ceiling on the app-chosen cap.
            max_app_daily_budget: Amount::from_webc(10),
            // ≈ one day at the ~1-minute devnet epoch assumption; a placeholder.
            day_window_epochs: 1_440,
        }
    }
}

impl SponsorshipConfig {
    /// Rejects a configuration whose day-window is zero (division/rollover base).
    ///
    /// Called at genesis so a chain never runs with a malformed sponsorship
    /// window. The eligibility path additionally treats a zero window defensively
    /// (no sponsor is ever charged), so a bad config fails closed either way.
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.day_window_epochs == 0 {
            return Err(ChainError::InvalidSponsorshipConfig);
        }
        Ok(())
    }

    /// Deterministic day-window index for a consensus epoch.
    ///
    /// `current_epoch / day_window_epochs`. A zero window yields `0` (the
    /// eligibility path independently declines to charge under a zero window), so
    /// this never divides by zero.
    pub fn window_index(&self, current_epoch: u64) -> u64 {
        if self.day_window_epochs == 0 {
            return 0;
        }
        current_epoch / self.day_window_epochs
    }
}

/// One application's per-user sponsored-operation counter for a single day-window.
///
/// Stored inside [`AppSponsor::user_ops`]. A stale entry (whose `window_index`
/// is older than the current window) reads as zero and is overwritten in place on
/// the next charge, so counters reset deterministically at each window boundary
/// without a scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SponsorUserWindow {
    /// Day-window the `ops` count belongs to.
    pub window_index: u64,
    /// Sponsored operations this user has had paid by this app in `window_index`.
    pub ops: u32,
}

/// A registered application's fee-sponsorship account.
///
/// Keyed in [`crate::ChainState::sponsors`] by application namespace. Holds the
/// refundable-in-aggregate `budget` (its sum across all sponsors is the
/// `sponsor_budgets` supply bucket), the app-chosen per-day spend cap, and the
/// per-day counters. Only the `owner` may fund or withdraw; any user may be a
/// sponsored beneficiary (that is the point — an app pays for its users).
///
/// Invariants:
/// - `budget` is the exact remaining locked native base units for this app;
/// - `spent_in_window` never exceeds `daily_budget_cap` (enforced in `try_charge`);
/// - `daily_budget_cap <= SponsorshipConfig::max_app_daily_budget` at registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppSponsor {
    /// Account that registered and controls (funds/withdraws) this sponsor.
    pub owner: Address,
    /// Remaining locked native base units available to pay users' fees.
    pub budget: Amount,
    /// App-chosen maximum sponsored fee spend per day-window, in base units,
    /// bounded at registration by `SponsorshipConfig::max_app_daily_budget`.
    pub daily_budget_cap: Amount,
    /// Day-window that `spent_in_window` belongs to (lazily rolled forward).
    pub window_index: u64,
    /// Sponsored fees already paid in `window_index`, reset each new window.
    pub spent_in_window: Amount,
    /// Per-user sponsored-operation counters for the current day-window.
    pub user_ops: BTreeMap<Address, SponsorUserWindow>,
}

impl AppSponsor {
    /// Creates an unfunded sponsor owned by `owner` with the given daily cap.
    pub fn new(owner: Address, daily_budget_cap: Amount) -> Self {
        Self {
            owner,
            budget: Amount::ZERO,
            daily_budget_cap,
            window_index: 0,
            spent_in_window: Amount::ZERO,
            user_ops: BTreeMap::new(),
        }
    }

    /// This user's op count if their counter belongs to `window`, else zero.
    ///
    /// A counter from an earlier window is treated as zero (deterministic lazy
    /// reset) without mutation, so read-only eligibility checks are side-effect
    /// free.
    pub fn user_ops_in_window(&self, user: &Address, window: u64) -> u32 {
        match self.user_ops.get(user) {
            Some(entry) if entry.window_index == window => entry.ops,
            _ => 0,
        }
    }

    /// Attempts to charge `fee` to this sponsor for `user` in `window`.
    ///
    /// Pure and deterministic. First rolls the app-level daily spend counter into
    /// `window` (resetting it when the window advanced — correct regardless of
    /// this call's outcome). Then checks every cap in order; on the first miss it
    /// returns `Ok(false)` and leaves `budget` and the per-user counter unchanged
    /// (the app-window roll may have reset `spent_in_window`, which is intended).
    /// When every cap permits, it decrements `budget`, adds to `spent_in_window`,
    /// increments the user's counter, and returns `Ok(true)`; the caller then
    /// performs the matching supply-conserving move (budget → burn + reward).
    ///
    /// Caps enforced (all hard, all from `config`): sponsorship enabled; a
    /// non-zero fee within `max_sponsored_fee_per_op`; the user below
    /// `max_ops_per_user_per_app_per_day`; `spent_in_window + fee` within this
    /// app's `daily_budget_cap`; and `budget >= fee`. Returns
    /// `Err(ArithmeticOverflow)` only on a checked-arithmetic overflow, never a
    /// panic.
    pub fn try_charge(
        &mut self,
        user: Address,
        fee: Amount,
        window: u64,
        config: &SponsorshipConfig,
    ) -> Result<bool, ChainError> {
        // A disabled feature, a zero window, or a free/zero fee is never
        // sponsored: self-paying a zero fee is a harmless no-op debit, and this
        // avoids consuming a user's daily op slot for a free transaction.
        if !config.enabled || config.day_window_epochs == 0 || fee.is_zero() {
            return Ok(false);
        }
        // Roll the app-level daily spend counter into the current window.
        if window != self.window_index {
            self.window_index = window;
            self.spent_in_window = Amount::ZERO;
        }
        // Per-operation fee cap: bounds a single operation's drain.
        if fee > config.max_sponsored_fee_per_op {
            return Ok(false);
        }
        // Per-user-per-app-per-day operation cap.
        let user_ops = self.user_ops_in_window(&user, window);
        if user_ops >= config.max_ops_per_user_per_app_per_day {
            return Ok(false);
        }
        // Per-app-per-day spend cap.
        let next_spent = self
            .spent_in_window
            .checked_add(fee)
            .ok_or(ChainError::ArithmeticOverflow)?;
        if next_spent > self.daily_budget_cap {
            return Ok(false);
        }
        // Funded-budget floor.
        if self.budget < fee {
            return Ok(false);
        }
        // Every cap passed: commit the decrement and counter bump.
        self.budget = self
            .budget
            .checked_sub(fee)
            .ok_or(ChainError::ArithmeticOverflow)?;
        self.spent_in_window = next_spent;
        let next_ops = user_ops
            .checked_add(1)
            .ok_or(ChainError::ArithmeticOverflow)?;
        self.user_ops.insert(
            user,
            SponsorUserWindow {
                window_index: window,
                ops: next_ops,
            },
        );
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webc_crypto::Keypair;

    fn user(seed: u8) -> Address {
        Keypair::from_seed([seed; 32]).address()
    }

    fn test_config() -> SponsorshipConfig {
        SponsorshipConfig {
            enabled: true,
            max_ops_per_user_per_app_per_day: 3,
            max_sponsored_fee_per_op: Amount::from_units(1_000),
            max_app_daily_budget: Amount::from_units(10_000),
            day_window_epochs: 10,
        }
    }

    #[test]
    fn window_index_is_epoch_division_and_never_divides_by_zero() {
        let config = test_config();
        assert_eq!(config.window_index(0), 0);
        assert_eq!(config.window_index(9), 0);
        assert_eq!(config.window_index(10), 1);
        assert_eq!(config.window_index(25), 2);
        let zero = SponsorshipConfig {
            day_window_epochs: 0,
            ..config
        };
        assert_eq!(zero.window_index(1_000), 0);
        assert!(matches!(
            zero.validate(),
            Err(ChainError::InvalidSponsorshipConfig)
        ));
    }

    #[test]
    fn charge_succeeds_and_decrements_until_a_cap_binds() {
        let config = test_config();
        let owner = user(1);
        let alice = user(2);
        let mut sponsor = AppSponsor::new(owner, Amount::from_units(10_000));
        sponsor.budget = Amount::from_units(10_000);

        // Three charges of 100 succeed for one user (per-user op cap is 3).
        for expected_ops in 1..=3 {
            assert!(sponsor
                .try_charge(alice, Amount::from_units(100), 0, &config)
                .unwrap());
            assert_eq!(sponsor.user_ops_in_window(&alice, 0), expected_ops);
        }
        assert_eq!(sponsor.budget, Amount::from_units(9_700));
        assert_eq!(sponsor.spent_in_window, Amount::from_units(300));

        // The 4th charge hits the per-user daily op cap and does not mutate.
        let before = sponsor.clone();
        assert!(!sponsor
            .try_charge(alice, Amount::from_units(100), 0, &config)
            .unwrap());
        assert_eq!(sponsor, before, "a capped charge must not mutate");
    }

    #[test]
    fn per_operation_fee_cap_blocks_a_single_large_drain() {
        let config = test_config();
        let mut sponsor = AppSponsor::new(user(1), Amount::from_units(10_000));
        sponsor.budget = Amount::from_units(10_000);
        // Over the per-op cap (1_000): declined, no mutation.
        assert!(!sponsor
            .try_charge(user(2), Amount::from_units(1_001), 0, &config)
            .unwrap());
        assert_eq!(sponsor.budget, Amount::from_units(10_000));
    }

    #[test]
    fn per_app_daily_cap_and_budget_floor_bind() {
        let mut config = test_config();
        config.max_ops_per_user_per_app_per_day = 1_000;
        // daily_budget_cap 250, per-op cap 1000: two 100s fit, the third exceeds 250.
        let mut sponsor = AppSponsor::new(user(1), Amount::from_units(250));
        sponsor.budget = Amount::from_units(10_000);
        assert!(sponsor
            .try_charge(user(2), Amount::from_units(100), 0, &config)
            .unwrap());
        assert!(sponsor
            .try_charge(user(3), Amount::from_units(100), 0, &config)
            .unwrap());
        assert!(
            !sponsor
                .try_charge(user(4), Amount::from_units(100), 0, &config)
                .unwrap(),
            "third charge exceeds the 250 per-day cap"
        );
        assert_eq!(sponsor.spent_in_window, Amount::from_units(200));

        // Budget floor: a fresh sponsor with only 50 funded cannot pay a 100 fee.
        let mut poor = AppSponsor::new(user(1), Amount::from_units(10_000));
        poor.budget = Amount::from_units(50);
        assert!(!poor
            .try_charge(user(2), Amount::from_units(100), 0, &config)
            .unwrap());
        assert_eq!(poor.budget, Amount::from_units(50));
    }

    #[test]
    fn day_window_rolls_over_and_resets_counters_deterministically() {
        let config = test_config();
        let alice = user(2);
        let mut sponsor = AppSponsor::new(user(1), Amount::from_units(10_000));
        sponsor.budget = Amount::from_units(10_000);
        // Exhaust the per-user op cap in window 0.
        for _ in 0..3 {
            assert!(sponsor
                .try_charge(alice, Amount::from_units(100), 0, &config)
                .unwrap());
        }
        assert!(!sponsor
            .try_charge(alice, Amount::from_units(100), 0, &config)
            .unwrap());
        // In the next window the app spend counter and the user op counter reset.
        assert!(sponsor
            .try_charge(alice, Amount::from_units(100), 1, &config)
            .unwrap());
        assert_eq!(sponsor.window_index, 1);
        assert_eq!(sponsor.spent_in_window, Amount::from_units(100));
        assert_eq!(sponsor.user_ops_in_window(&alice, 1), 1);
        assert_eq!(
            sponsor.user_ops_in_window(&alice, 0),
            0,
            "the prior window reads as zero"
        );
    }

    #[test]
    fn disabled_or_zero_fee_never_charges() {
        let mut config = test_config();
        config.enabled = false;
        let mut sponsor = AppSponsor::new(user(1), Amount::from_units(10_000));
        sponsor.budget = Amount::from_units(10_000);
        assert!(!sponsor
            .try_charge(user(2), Amount::from_units(100), 0, &config)
            .unwrap());
        config.enabled = true;
        assert!(!sponsor
            .try_charge(user(2), Amount::ZERO, 0, &config)
            .unwrap());
        assert_eq!(sponsor.budget, Amount::from_units(10_000));
    }
}
