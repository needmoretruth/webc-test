//! Independent wallet authorization lanes with prepaid fee balances.
//!
//! This module stores lane-local replay and fee state but does not verify
//! signatures or execute operations. The default all-zero lane remains in the
//! account record for compatibility. Non-default lanes are explicitly opened
//! from that account and let unrelated site/object operations avoid a shared
//! nonce and fee-balance write. Lane IDs are public identifiers, never secrets.

use crate::{Amount, AuthorizationLaneId, Nonce};
use serde::{Deserialize, Serialize};
use webc_crypto::Address;

/// Persistent replay and prepaid-fee state for one non-default lane.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationLane {
    /// Account whose authorization policy controls this lane.
    pub owner: Address,
    /// Opaque non-default lane identity.
    pub id: AuthorizationLaneId,
    /// Next accepted sequence number inside this lane.
    pub next_nonce: Nonce,
    /// Native base units reserved only for this lane's transaction fees.
    pub fee_balance: Amount,
}

impl AuthorizationLane {
    /// Creates a non-default lane at nonce zero with an explicit fee deposit.
    pub const fn new(owner: Address, id: AuthorizationLaneId, fee_balance: Amount) -> Self {
        Self {
            owner,
            id,
            next_nonce: Nonce::new(0),
            fee_balance,
        }
    }
}
