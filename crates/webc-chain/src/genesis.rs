//! Declarative WEBC genesis configuration records.
//!
//! This module owns only the serializable account, validator, and chain-config
//! input schema. It does not validate total supply, validator uniqueness,
//! staking thresholds, authorization, or construct live state; those
//! consensus-critical checks are performed by `ChainState::from_genesis_v1`.
//! Configuration bytes flow through a decoder into these records and then into
//! that fail-closed constructor. Callers must therefore never treat successful
//! deserialization alone as proof that a genesis configuration is valid.

use crate::{Amount, ChainConfig};
use serde::{Deserialize, Serialize};
use webc_crypto::{Address, PublicKeyBytes};

/// One account balance declared at genesis.
///
/// The balance is measured in native base units. Duplicate addresses and the
/// aggregate-supply invariant are rejected when live state is constructed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisAccount {
    /// Account receiving the initial balance.
    pub address: Address,
    /// Initial native balance in WEBC base units.
    pub balance: Amount,
}

/// One validator registration declared at genesis.
///
/// Stake and commission policy is validated by the consensus state
/// constructor; this transport record deliberately performs no authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisValidator {
    /// Account that controls validator operations and owns the self stake.
    pub operator: Address,
    /// Ed25519 public key used for version-1 consensus messages.
    pub consensus_key: PublicKeyBytes,
    /// Operator stake in native WEBC base units.
    pub self_stake: Amount,
    /// Validator commission in basis points, where 10,000 represents 100%.
    pub commission_bps: u16,
    /// Whether this validator participates in the bounded bootstrap allowance.
    pub bootstrap: bool,
}

/// Complete declarative input used to construct protocol genesis state.
///
/// `accounts` and `validators` retain their encoded order, but state
/// construction validates them and stores consensus state deterministically.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Consensus and economic chain parameters.
    pub chain: ChainConfig,
    /// Initial native account balances.
    pub accounts: Vec<GenesisAccount>,
    /// Initial validator declarations.
    pub validators: Vec<GenesisValidator>,
}
