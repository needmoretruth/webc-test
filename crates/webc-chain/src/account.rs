//! Account-style native balance and staking bucket state.
//!
//! The module stores owner totals but does not execute transfers, delegation,
//! unbonding, or rewards. Active delegation and cooling principal are separate
//! buckets so voting stake cannot be paid out before queue maturity.

use crate::Amount;
use serde::{Deserialize, Serialize};

/// Simple native account state.
///
/// WEBC intentionally starts with Ethereum-like balances/nonces for wallet
/// simplicity. Staked/delegated amounts are tracked separately so wallet UIs can
/// clearly show liquid versus bonded funds.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Immediately spendable native base units.
    pub balance: Amount,
    /// Current version-1 authorization sequence number.
    pub nonce: u64,
    /// Active validator operator stake in native base units.
    pub staked: Amount,
    /// Active delegated stake in native base units.
    pub delegated: Amount,
    /// Inactive principal cooling or matured but not yet claimed.
    pub unbonding: Amount,
}

impl Account {
    pub fn with_balance(balance: Amount) -> Self {
        Self {
            balance,
            nonce: 0,
            staked: Amount::ZERO,
            delegated: Amount::ZERO,
            unbonding: Amount::ZERO,
        }
    }
}
