//! Deterministic in-memory protocol state and native-operation execution.
//!
//! The module owns account, staking, fee, replay, and prototype bridge state. It
//! does not own networking, durable storage, or consensus voting. Signed
//! transactions enter through validation, execute against a cloned overlay, and
//! commit only on success. Block construction supplies the parent overlay, and
//! each transaction fails if its recorded logical access differs from its signed
//! versioned access list.

use crate::account::Account;
use crate::authorization::AuthorizationLane;
use crate::authorization_policy::AccountAuthorizationPolicy;
use crate::bridge::{AssetId, BridgeConfig, BridgeEvent, BridgeMessage, ExternalChain};
use crate::fees::{next_base_fee, split_fee, FeeBreakdown, FeePolicy};
use crate::genesis::GenesisConfig;
use crate::object::{validate_object_data, ObjectOwner, StateObject};
use crate::slashing::{
    slash_validator_with_delegation_loss, slashing_bps, SlashingOutcome, SlashingPolicy,
};
use crate::staking::{Delegation, StakingConfig, Validator, ValidatorStatus};
use crate::state_key::StateAccessRecorder;
use crate::transaction::{Operation, Transaction};
use crate::unbonding::{UnbondingKind, UnbondingQueue, UnbondingRequestId, UnbondingTransition};
use crate::{
    Amount, AuthorizationLaneId, ChainError, ChainId, Epoch, InflationSchedule, ObjectId,
    ObjectVersion, ProtocolStateKey, ProtocolVersion, StateKey, CURRENT_PROTOCOL_VERSION,
    LEGACY_AUTHORIZATION_POLICY_REVISION,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use webc_crypto::{merkle_proof, merkle_root, verify_merkle_proof, Address, Hash256, MerkleProof};

/// Static chain configuration used by deterministic state transitions.
///
/// Production nodes should load this from genesis and never silently change it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Immutable schema version interpreted by deterministic state transitions.
    pub protocol_version: ProtocolVersion,
    /// Replay-protection domain shared by genesis, transactions, blocks, and votes.
    pub chain_id: ChainId,
    /// Maximum canonical serialized block size in bytes, including its header.
    pub max_block_bytes: u64,
    pub fee_policy: FeePolicy,
    pub staking: StakingConfig,
    pub slashing: SlashingPolicy,
    pub inflation: InflationSchedule,
    pub bridge: BridgeConfig,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            max_block_bytes: 4 * 1024 * 1024,
            fee_policy: FeePolicy::default(),
            staking: StakingConfig::default(),
            slashing: SlashingPolicy::default(),
            inflation: InflationSchedule::default(),
            bridge: BridgeConfig::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    Transfer {
        from: Address,
        to: Address,
        amount: Amount,
    },
    FeePaid {
        payer: Address,
        breakdown: FeeBreakdown,
    },
    ValidatorRegistered {
        operator: Address,
        bootstrap: bool,
    },
    Delegated {
        delegator: Address,
        validator: Address,
        amount: Amount,
    },
    UnbondingRequested {
        request_id: UnbondingRequestId,
        delegator: Address,
        validator: Address,
        kind: UnbondingKind,
        amount: Amount,
    },
    UnbondingAdmitted {
        request_id: UnbondingRequestId,
        delegator: Address,
        validator: Address,
        kind: UnbondingKind,
        amount: Amount,
    },
    UnbondingMatured {
        request_id: UnbondingRequestId,
        delegator: Address,
        validator: Address,
        kind: UnbondingKind,
        amount: Amount,
    },
    UnbondingClaimed {
        request_id: UnbondingRequestId,
        delegator: Address,
        kind: UnbondingKind,
        amount: Amount,
    },
    ValidatorRewardsClaimed {
        validator: Address,
        amount: Amount,
    },
    DelegatorRewardsClaimed {
        delegator: Address,
        validator: Address,
        amount: Amount,
    },
    Slashed {
        outcome: SlashingOutcome,
    },
    Bridge {
        event: BridgeEvent,
    },
    EpochRewardsDistributed {
        epoch: u64,
        total: Amount,
    },
    AuthorizationLaneOpened {
        owner: Address,
        lane: AuthorizationLaneId,
        fee_deposit: Amount,
    },
    AuthorizationLaneFunded {
        owner: Address,
        lane: AuthorizationLaneId,
        fee_deposit: Amount,
    },
    AuthorizationPolicyInstalled {
        /// Stable account address whose legacy key approved migration.
        owner: Address,
        /// First installed revision; currently always one.
        revision: crate::AuthorizationPolicyRevision,
        /// Committed post-quantum recovery root, not a verification claim.
        post_quantum_root: crate::PostQuantumRoot,
    },
    ObjectCreated {
        object_id: ObjectId,
        namespace: Hash256,
        owner: Address,
        version: ObjectVersion,
    },
    ObjectMutated {
        object_id: ObjectId,
        version: ObjectVersion,
    },
    ObjectTransferred {
        object_id: ObjectId,
        from: Address,
        to: Address,
        version: ObjectVersion,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub tx_hash: Hash256,
    pub success: bool,
    pub fee: FeeBreakdown,
    pub units_consumed: u64,
    pub events: Vec<Event>,
    pub error: Option<String>,
}

/// Inclusion proof for one account under the current account Merkle root.
///
/// This is the first practical light-wallet primitive: a browser can request an
/// account plus proof from an RPC node and verify that the account is committed
/// by a block header's `account_root` without downloading full state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountStateProof {
    pub address: Address,
    pub account: Account,
    pub account_root: Hash256,
    pub proof: MerkleProof,
}

impl AccountStateProof {
    pub fn verify(&self) -> Result<bool, ChainError> {
        let expected_leaf = ChainState::account_leaf_hash(self.address, &self.account)?;
        if self.proof.leaf != expected_leaf {
            return Ok(false);
        }
        Ok(verify_merkle_proof(self.account_root, &self.proof))
    }
}

/// In-memory deterministic chain state.
///
/// This is not a production database. It is the auditable state-transition model
/// that storage/networking layers should wrap later.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainState {
    /// Protocol schema that must be used to interpret every stored field.
    pub protocol_version: ProtocolVersion,
    /// Network domain preventing state and signatures from crossing chains.
    pub chain_id: ChainId,
    pub accounts: BTreeMap<Address, Account>,
    /// Versioned account signing and recovery policy, absent only for migration.
    #[serde(default)]
    pub authorization_policies: BTreeMap<Address, AccountAuthorizationPolicy>,
    /// Non-default wallet lanes with independent nonce and prepaid fee state.
    pub authorization_lanes: BTreeMap<(Address, AuthorizationLaneId), AuthorizationLane>,
    /// Persistent versioned application/NFT objects keyed by stable identity.
    pub objects: BTreeMap<ObjectId, StateObject>,
    pub validators: BTreeMap<Address, Validator>,
    pub delegations: BTreeMap<(Address, Address), Delegation>,
    /// FIFO stake-exit requests and cooling tranches.
    pub unbonding: UnbondingQueue,
    pub asset_balances: BTreeMap<(AssetId, Address), Amount>,
    /// Native WEBC locked for release on return from each external domain.
    pub native_bridge_escrow: BTreeMap<ExternalChain, Amount>,
    pub processed_bridge_messages: BTreeSet<Hash256>,
    pub processed_slashing_evidence: BTreeSet<Hash256>,
    pub burned_fees: Amount,
    /// Native units destroyed by verified objective penalties.
    pub slashed_units: Amount,
    pub validator_fee_pool: Amount,
    pub minted_supply: Amount,
    /// Gross issued supply captured at the start of the current inflation year.
    pub inflation_year_start_supply: Amount,
    pub current_base_fee_per_unit: u64,
    pub current_epoch: u64,
    pub bridge_nonce: u64,
}

/// Deterministic reconciliation of gross native issuance and all value buckets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyInvariantReport {
    /// Total native units ever issued by genesis and inflation.
    pub issued: Amount,
    /// Native units available for immediate transfer.
    pub liquid: Amount,
    /// Native units locked as validator operator stake.
    pub staked: Amount,
    /// Native units locked in delegation positions.
    pub delegated: Amount,
    /// Native principal admitted out of active stake but not yet claimed.
    pub unbonding: Amount,
    /// Native units locked for wrapped WEBC on external bridge domains.
    pub escrowed: Amount,
    /// Native units prepaid into non-default authorization lanes.
    pub lane_fees: Amount,
    /// Issued rewards that have not yet been claimed.
    pub pending_rewards: Amount,
    /// Collected fee rewards awaiting distribution.
    pub fee_reward_pool: Amount,
    /// Native units permanently removed by base-fee burning.
    pub burned: Amount,
    /// Native units permanently removed by objective slashing.
    pub slashed: Amount,
    /// Checked sum of all non-duplicated buckets.
    pub accounted: Amount,
    /// Whether gross issuance exactly equals all buckets.
    pub balanced: bool,
}

/// Validated fields for an outgoing bridge message before nonce assignment.
///
/// This private value prevents positional argument mix-ups between two chains,
/// sender/recipient byte strings, and amount/source transaction fields.
struct OutgoingBridgeMessage {
    source_chain: ExternalChain,
    destination_chain: ExternalChain,
    asset: AssetId,
    sender: Vec<u8>,
    recipient: Vec<u8>,
    amount: Amount,
    source_tx: Hash256,
}

/// Incoming bridge action fixes which asset class may change on WEBC.
enum IncomingBridgeAction {
    /// Mint a representation of an externally locked asset.
    MintRepresentation,
    /// Release native WEBC previously escrowed for one external domain.
    ReleaseNative,
}

impl Default for ChainState {
    fn default() -> Self {
        Self {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            accounts: BTreeMap::new(),
            authorization_policies: BTreeMap::new(),
            authorization_lanes: BTreeMap::new(),
            objects: BTreeMap::new(),
            validators: BTreeMap::new(),
            delegations: BTreeMap::new(),
            unbonding: UnbondingQueue::default(),
            asset_balances: BTreeMap::new(),
            native_bridge_escrow: BTreeMap::new(),
            processed_bridge_messages: BTreeSet::new(),
            processed_slashing_evidence: BTreeSet::new(),
            burned_fees: Amount::ZERO,
            slashed_units: Amount::ZERO,
            validator_fee_pool: Amount::ZERO,
            minted_supply: Amount::ZERO,
            inflation_year_start_supply: Amount::ZERO,
            current_base_fee_per_unit: 0,
            current_epoch: 0,
            bridge_nonce: 0,
        }
    }
}

impl ChainState {
    /// Creates empty deterministic state for one supported protocol config.
    ///
    /// This operation allocates no supply and performs no external I/O. Unknown
    /// versions fail before state exists so a node cannot silently interpret a
    /// future genesis using version-1 rules.
    pub fn new(config: &ChainConfig) -> Result<Self, ChainError> {
        if config.protocol_version != CURRENT_PROTOCOL_VERSION {
            return Err(ChainError::UnsupportedProtocolVersion {
                actual: config.protocol_version,
            });
        }
        Ok(Self {
            protocol_version: config.protocol_version,
            chain_id: config.chain_id.clone(),
            current_base_fee_per_unit: config.fee_policy.min_base_fee_per_unit,
            ..Self::default()
        })
    }

    /// Builds initial state from a versioned genesis allocation.
    ///
    /// Genesis data is consensus-critical hostile input. Failure leaves no
    /// partially constructed state and returns a typed error. Phase 1 adds full
    /// supply reconciliation and prevents stake from being counted twice.
    pub fn from_genesis(genesis: &GenesisConfig) -> Result<Self, ChainError> {
        let mut state = Self::new(&genesis.chain)?;

        for account in &genesis.accounts {
            if state.accounts.contains_key(&account.address) {
                return Err(ChainError::DuplicateGenesisAccount(account.address));
            }
            state
                .accounts
                .insert(account.address, Account::with_balance(account.balance));
            state.minted_supply = state
                .minted_supply
                .checked_add(account.balance)
                .ok_or(ChainError::ArithmeticOverflow)?;
        }

        for genesis_validator in &genesis.validators {
            if state.validators.contains_key(&genesis_validator.operator) {
                return Err(ChainError::ValidatorAlreadyExists(
                    genesis_validator.operator,
                ));
            }
            if genesis_validator.commission_bps > genesis.chain.staking.max_commission_bps {
                return Err(ChainError::CommissionTooHigh);
            }
            if genesis_validator.bootstrap {
                return Err(ChainError::BootstrapDisabled);
            }
            if genesis_validator.self_stake < genesis.chain.staking.min_validator_self_stake {
                return Err(ChainError::StakeTooSmall);
            }

            state.debit_native(genesis_validator.operator, genesis_validator.self_stake)?;
            let account = state.account_mut(genesis_validator.operator)?;
            account.staked = account
                .staked
                .checked_add(genesis_validator.self_stake)
                .ok_or(ChainError::ArithmeticOverflow)?;

            state.validators.insert(
                genesis_validator.operator,
                Validator {
                    operator: genesis_validator.operator,
                    consensus_key: genesis_validator.consensus_key,
                    self_stake: genesis_validator.self_stake,
                    delegated_stake: Amount::ZERO,
                    commission_bps: genesis_validator.commission_bps,
                    status: ValidatorStatus::PendingActivation,
                    bootstrap: false,
                    accumulated_rewards: Amount::ZERO,
                },
            );
            let validator = state
                .validators
                .get_mut(&genesis_validator.operator)
                .ok_or(ChainError::ValidatorNotFound(genesis_validator.operator))?;
            validator.refresh_stake_status(&genesis.chain.staking)?;
        }

        state.inflation_year_start_supply = state.minted_supply;

        if !state.supply_invariant_report()?.balanced {
            return Err(ChainError::SupplyInvariantViolation);
        }

        Ok(state)
    }

    /// Reconciles native supply without counting mirrored validator/delegation indexes twice.
    pub fn supply_invariant_report(&self) -> Result<SupplyInvariantReport, ChainError> {
        let mut liquid = Amount::ZERO;
        let mut staked = Amount::ZERO;
        let mut delegated = Amount::ZERO;
        let mut unbonding = Amount::ZERO;
        for account in self.accounts.values() {
            liquid = liquid
                .checked_add(account.balance)
                .ok_or(ChainError::ArithmeticOverflow)?;
            staked = staked
                .checked_add(account.staked)
                .ok_or(ChainError::ArithmeticOverflow)?;
            delegated = delegated
                .checked_add(account.delegated)
                .ok_or(ChainError::ArithmeticOverflow)?;
            unbonding = unbonding
                .checked_add(account.unbonding)
                .ok_or(ChainError::ArithmeticOverflow)?;
        }
        let mut pending_rewards = Amount::ZERO;
        for validator in self.validators.values() {
            pending_rewards = pending_rewards
                .checked_add(validator.accumulated_rewards)
                .ok_or(ChainError::ArithmeticOverflow)?;
        }
        for delegation in self.delegations.values() {
            pending_rewards = pending_rewards
                .checked_add(delegation.accumulated_rewards)
                .ok_or(ChainError::ArithmeticOverflow)?;
        }
        let escrowed =
            self.native_bridge_escrow
                .values()
                .try_fold(Amount::ZERO, |total, amount| {
                    total
                        .checked_add(*amount)
                        .ok_or(ChainError::ArithmeticOverflow)
                })?;
        let lane_fees =
            self.authorization_lanes
                .values()
                .try_fold(Amount::ZERO, |total, lane| {
                    total
                        .checked_add(lane.fee_balance)
                        .ok_or(ChainError::ArithmeticOverflow)
                })?;
        let accounted = liquid
            .checked_add(staked)
            .and_then(|amount| amount.checked_add(delegated))
            .and_then(|amount| amount.checked_add(unbonding))
            .and_then(|amount| amount.checked_add(escrowed))
            .and_then(|amount| amount.checked_add(lane_fees))
            .and_then(|amount| amount.checked_add(pending_rewards))
            .and_then(|amount| amount.checked_add(self.validator_fee_pool))
            .and_then(|amount| amount.checked_add(self.burned_fees))
            .and_then(|amount| amount.checked_add(self.slashed_units))
            .ok_or(ChainError::ArithmeticOverflow)?;
        Ok(SupplyInvariantReport {
            issued: self.minted_supply,
            liquid,
            staked,
            delegated,
            unbonding,
            escrowed,
            lane_fees,
            pending_rewards,
            fee_reward_pool: self.validator_fee_pool,
            burned: self.burned_fees,
            slashed: self.slashed_units,
            accounted,
            balanced: accounted == self.minted_supply,
        })
    }

    /// Executes a signed transaction atomically.
    ///
    /// The method clones state, applies all checks/mutations, and commits only on
    /// success. This is slower than production storage but safer for a prototype
    /// because invalid transactions cannot leave partial changes behind.
    pub fn execute_transaction(
        &mut self,
        tx: &Transaction,
        config: &ChainConfig,
    ) -> Result<Receipt, ChainError> {
        if tx.protocol_version != config.protocol_version {
            return Err(ChainError::UnsupportedProtocolVersion {
                actual: tx.protocol_version,
            });
        }
        if tx.chain_id != config.chain_id {
            return Err(ChainError::TransactionChainIdMismatch);
        }
        tx.verify()?;
        self.verify_transaction_authorization(tx)?;
        let tx_hash = tx.hash()?;
        let mut next = self.clone();
        let receipt = next.apply_verified_transaction(tx, config, tx_hash)?;
        *self = next;
        Ok(receipt)
    }

    /// Verifies the stateful sender/key binding before any fee or nonce change.
    ///
    /// Accounts without a policy are restricted to revision zero and the
    /// address-derived Ed25519 key so only the existing owner can install the
    /// first policy. Installed accounts require an exact revision and active
    /// key match; address derivation is no longer consulted, allowing later key
    /// rotation without changing the stable account address.
    fn verify_transaction_authorization(&self, tx: &Transaction) -> Result<(), ChainError> {
        tx.authorization_policy_revision.validate()?;
        let Some(policy) = self.authorization_policies.get(&tx.sender) else {
            if tx.authorization_policy_revision != LEGACY_AUTHORIZATION_POLICY_REVISION {
                return Err(ChainError::AuthorizationPolicyRevisionMismatch {
                    expected: LEGACY_AUTHORIZATION_POLICY_REVISION.get(),
                    actual: tx.authorization_policy_revision.get(),
                });
            }
            if Address::from_public_key(&tx.public_key) != tx.sender {
                return Err(ChainError::SenderPublicKeyMismatch);
            }
            return Ok(());
        };

        policy.validate()?;
        if tx.authorization_policy_revision != policy.revision() {
            return Err(ChainError::AuthorizationPolicyRevisionMismatch {
                expected: policy.revision().get(),
                actual: tx.authorization_policy_revision.get(),
            });
        }
        if &tx.public_key != policy.active_transaction_key() {
            return Err(ChainError::AuthorizationKeyMismatch);
        }
        Ok(())
    }

    /// Commits the next deterministic base fee after a completed block.
    ///
    /// `units_used` is measured in execution units and must not exceed the
    /// configured block maximum. Invalid policy or overflow leaves state
    /// unchanged and returns an error to the whole-block overlay.
    pub fn finish_block(
        &mut self,
        units_used: u64,
        config: &ChainConfig,
    ) -> Result<(), ChainError> {
        self.current_base_fee_per_unit = next_base_fee(
            self.current_base_fee_per_unit,
            units_used,
            &config.fee_policy,
        )?;
        Ok(())
    }

    pub fn distribute_epoch_rewards(
        &mut self,
        config: &ChainConfig,
    ) -> Result<Vec<Event>, ChainError> {
        let mut next = self.clone();
        let events = next.apply_epoch_rewards(config)?;
        *self = next;
        Ok(events)
    }

    fn apply_epoch_rewards(&mut self, config: &ChainConfig) -> Result<Vec<Event>, ChainError> {
        let periods_per_year = config.inflation.validated_periods_per_year()?;
        if self.current_epoch.is_multiple_of(periods_per_year) {
            self.inflation_year_start_supply = self.minted_supply;
        }
        let inflation = config
            .inflation
            .reward_for_period(self.inflation_year_start_supply, self.current_epoch)?;
        let total_reward = inflation
            .checked_add(self.validator_fee_pool)
            .ok_or(ChainError::ArithmeticOverflow)?;

        if total_reward.is_zero() {
            return self.finish_epoch(config, Amount::ZERO);
        }

        let total_active_stake = self
            .validators
            .values()
            .filter(|validator| validator.is_active())
            .try_fold(Amount::ZERO, |sum, validator| {
                sum.checked_add(validator.total_stake()?)
                    .ok_or(ChainError::ArithmeticOverflow)
            })?;

        if total_active_stake.is_zero() {
            // If no one is eligible, avoid minting rewards into nowhere. Fees stay
            // in the pool and can be distributed once validators exist.
            return self.finish_epoch(config, Amount::ZERO);
        }

        let active_validators = self
            .validators
            .values()
            .filter(|validator| validator.is_active())
            .map(|validator| {
                Ok((
                    validator.operator,
                    validator.total_stake()?,
                    validator.self_stake,
                    validator.commission_bps,
                ))
            })
            .collect::<Result<Vec<_>, ChainError>>()?;

        for (validator_address, validator_total_stake, self_stake, commission_bps) in
            active_validators
        {
            let validator_share = total_reward
                .checked_mul_ratio(validator_total_stake.0, total_active_stake.0)
                .ok_or(ChainError::ArithmeticOverflow)?;
            let commission = validator_share
                .checked_mul_bps(commission_bps)
                .ok_or(ChainError::ArithmeticOverflow)?;
            let staker_reward_pool = validator_share
                .checked_sub(commission)
                .ok_or(ChainError::ArithmeticOverflow)?;
            let self_reward = if validator_total_stake.is_zero() {
                Amount::ZERO
            } else {
                staker_reward_pool
                    .checked_mul_ratio(self_stake.0, validator_total_stake.0)
                    .ok_or(ChainError::ArithmeticOverflow)?
            };

            let mut distributed = commission
                .checked_add(self_reward)
                .ok_or(ChainError::ArithmeticOverflow)?;
            let mut delegation_rewards = Vec::new();
            for delegation in self
                .delegations
                .values()
                .filter(|delegation| delegation.validator == validator_address)
            {
                let reward = if validator_total_stake.is_zero() {
                    Amount::ZERO
                } else {
                    staker_reward_pool
                        .checked_mul_ratio(delegation.amount.0, validator_total_stake.0)
                        .ok_or(ChainError::ArithmeticOverflow)?
                };
                distributed = distributed
                    .checked_add(reward)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                delegation_rewards.push((delegation.delegator, reward));
            }

            // Integer division can leave tiny dust. Assign it to the validator so
            // total rewards are conserved and accounting remains deterministic.
            let dust = validator_share
                .checked_sub(distributed)
                .ok_or(ChainError::ArithmeticOverflow)?;
            let validator_reward = commission
                .checked_add(self_reward)
                .and_then(|reward| reward.checked_add(dust))
                .ok_or(ChainError::ArithmeticOverflow)?;

            let validator = self
                .validators
                .get_mut(&validator_address)
                .ok_or(ChainError::ValidatorNotFound(validator_address))?;
            validator.accumulated_rewards = validator
                .accumulated_rewards
                .checked_add(validator_reward)
                .ok_or(ChainError::ArithmeticOverflow)?;

            for (delegator, reward) in delegation_rewards {
                let delegation = self
                    .delegations
                    .get_mut(&(delegator, validator_address))
                    .ok_or(ChainError::DelegationNotFound)?;
                delegation.accumulated_rewards = delegation
                    .accumulated_rewards
                    .checked_add(reward)
                    .ok_or(ChainError::ArithmeticOverflow)?;
            }
        }

        self.minted_supply = self
            .minted_supply
            .checked_add(inflation)
            .ok_or(ChainError::ArithmeticOverflow)?;
        self.validator_fee_pool = Amount::ZERO;
        self.finish_epoch(config, total_reward)
    }

    fn finish_epoch(
        &mut self,
        config: &ChainConfig,
        distributed_reward: Amount,
    ) -> Result<Vec<Event>, ChainError> {
        let event_epoch = self.current_epoch;
        let next_epoch = self
            .current_epoch
            .checked_add(1)
            .ok_or(ChainError::ArithmeticOverflow)?;
        let transitions = self.unbonding.advance_epoch(
            Epoch::new(next_epoch),
            config.staking.max_unbonding_units_per_epoch,
            config.staking.unbonding_cooldown_epochs,
            config.staking.slashable_unbonding_epochs,
        )?;
        let mut events = vec![Event::EpochRewardsDistributed {
            epoch: event_epoch,
            total: distributed_reward,
        }];
        for transition in transitions {
            match transition {
                UnbondingTransition::Admitted {
                    request_id,
                    owner,
                    validator,
                    kind,
                    amount,
                } => {
                    let validator_state = self
                        .validators
                        .get_mut(&validator)
                        .ok_or(ChainError::ValidatorNotFound(validator))?;
                    match kind {
                        UnbondingKind::Delegation => {
                            let delegation = self
                                .delegations
                                .get_mut(&(owner, validator))
                                .ok_or(ChainError::DelegationNotFound)?;
                            delegation.amount = delegation
                                .amount
                                .checked_sub(amount)
                                .ok_or(ChainError::ArithmeticOverflow)?;
                            validator_state.delegated_stake = validator_state
                                .delegated_stake
                                .checked_sub(amount)
                                .ok_or(ChainError::ArithmeticOverflow)?;
                        }
                        UnbondingKind::OperatorStake => {
                            validator_state.self_stake = validator_state
                                .self_stake
                                .checked_sub(amount)
                                .ok_or(ChainError::ArithmeticOverflow)?;
                        }
                    }
                    validator_state.refresh_stake_status(&config.staking)?;
                    let account = self.account_mut(owner)?;
                    match kind {
                        UnbondingKind::Delegation => {
                            account.delegated = account
                                .delegated
                                .checked_sub(amount)
                                .ok_or(ChainError::ArithmeticOverflow)?;
                        }
                        UnbondingKind::OperatorStake => {
                            account.staked = account
                                .staked
                                .checked_sub(amount)
                                .ok_or(ChainError::ArithmeticOverflow)?;
                        }
                    }
                    account.unbonding = account
                        .unbonding
                        .checked_add(amount)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    events.push(Event::UnbondingAdmitted {
                        request_id,
                        delegator: owner,
                        validator,
                        kind,
                        amount,
                    });
                }
                UnbondingTransition::Matured {
                    request_id,
                    owner,
                    validator,
                    kind,
                    amount,
                } => events.push(Event::UnbondingMatured {
                    request_id,
                    delegator: owner,
                    validator,
                    kind,
                    amount,
                }),
            }
        }
        self.current_epoch = next_epoch;
        Ok(events)
    }

    /// Commits to all major state subtrees and global accounting counters.
    ///
    /// The account subtree is exposed separately through `account_root()` so
    /// browser light wallets can verify balances. Other roots are included to
    /// prevent validators from committing only account balances while hiding
    /// validator, delegation, asset, bridge, or fee state changes.
    pub fn state_root(&self) -> Result<Hash256, ChainError> {
        #[derive(Serialize)]
        struct StateCommitment {
            domain: &'static str,
            protocol_version: ProtocolVersion,
            chain_id: ChainId,
            account_root: Hash256,
            authorization_policy_root: Hash256,
            authorization_lane_root: Hash256,
            object_root: Hash256,
            validator_root: Hash256,
            delegation_root: Hash256,
            asset_root: Hash256,
            native_bridge_escrow_root: Hash256,
            processed_bridge_root: Hash256,
            processed_slashing_root: Hash256,
            unbonding_root: Hash256,
            burned_fees: Amount,
            slashed_units: Amount,
            validator_fee_pool: Amount,
            minted_supply: Amount,
            inflation_year_start_supply: Amount,
            current_base_fee_per_unit: u64,
            current_epoch: u64,
            bridge_nonce: u64,
        }

        let commitment = StateCommitment {
            domain: "WEBC_STATE_COMMITMENT_V5",
            protocol_version: self.protocol_version,
            chain_id: self.chain_id.clone(),
            account_root: self.account_root()?,
            authorization_policy_root: ordered_value_root(
                b"WEBC_AUTHORIZATION_POLICY_LEAF_V1",
                self.authorization_policies.iter(),
            )?,
            authorization_lane_root: ordered_value_root(
                b"WEBC_AUTHORIZATION_LANE_LEAF_V1",
                self.authorization_lanes.iter(),
            )?,
            object_root: ordered_value_root(b"WEBC_OBJECT_LEAF_V1", self.objects.iter())?,
            validator_root: ordered_value_root(b"WEBC_VALIDATOR_LEAF_V1", self.validators.iter())?,
            delegation_root: ordered_value_root(
                b"WEBC_DELEGATION_LEAF_V1",
                self.delegations.iter(),
            )?,
            asset_root: ordered_value_root(
                b"WEBC_ASSET_BALANCE_LEAF_V1",
                self.asset_balances.iter(),
            )?,
            native_bridge_escrow_root: ordered_value_root(
                b"WEBC_NATIVE_BRIDGE_ESCROW_LEAF_V1",
                self.native_bridge_escrow.iter(),
            )?,
            processed_bridge_root: ordered_set_root(
                b"WEBC_PROCESSED_BRIDGE_LEAF_V1",
                self.processed_bridge_messages.iter(),
            )?,
            processed_slashing_root: ordered_set_root(
                b"WEBC_PROCESSED_SLASHING_LEAF_V1",
                self.processed_slashing_evidence.iter(),
            )?,
            unbonding_root: leaf_hash(b"WEBC_UNBONDING_QUEUE_V1", &self.unbonding)?,
            burned_fees: self.burned_fees,
            slashed_units: self.slashed_units,
            validator_fee_pool: self.validator_fee_pool,
            minted_supply: self.minted_supply,
            inflation_year_start_supply: self.inflation_year_start_supply,
            current_base_fee_per_unit: self.current_base_fee_per_unit,
            current_epoch: self.current_epoch,
            bridge_nonce: self.bridge_nonce,
        };

        // Canonical JSON so the state root can, in principle, be recomputed
        // from browser-visible state once browser helpers for validator and
        // delegation leaves exist. The account_root (already browser-verifiable)
        // is the primary cross-language commitment today.
        let bytes = crate::canonical::canonical_json_bytes(&commitment)?;
        Ok(Hash256::digest(bytes))
    }

    pub fn account_root(&self) -> Result<Hash256, ChainError> {
        let leaves = self.account_leaf_entries()?;
        Ok(merkle_root(
            &leaves.into_iter().map(|(_, leaf)| leaf).collect::<Vec<_>>(),
        ))
    }

    pub fn account_leaf(&self, address: Address) -> Result<Option<Hash256>, ChainError> {
        let Some(account) = self.accounts.get(&address) else {
            return Ok(None);
        };
        Ok(Some(Self::account_leaf_hash(address, account)?))
    }

    pub fn account_state_proof(
        &self,
        address: Address,
    ) -> Result<Option<AccountStateProof>, ChainError> {
        let Some(account) = self.accounts.get(&address).cloned() else {
            return Ok(None);
        };
        let leaves = self.account_leaf_entries()?;
        let Some(index) = leaves
            .iter()
            .position(|(candidate, _)| *candidate == address)
        else {
            return Ok(None);
        };
        let hashes = leaves.into_iter().map(|(_, leaf)| leaf).collect::<Vec<_>>();
        let Some(proof) = merkle_proof(&hashes, index) else {
            return Ok(None);
        };
        Ok(Some(AccountStateProof {
            address,
            account,
            account_root: merkle_root(&hashes),
            proof,
        }))
    }

    pub fn account_leaf_hash(address: Address, account: &Account) -> Result<Hash256, ChainError> {
        // Account proofs must be verifiable from browser JavaScript without a
        // Rust bincode implementation. Use an explicit byte layout:
        // domain || address[32] || balance[u128be] || nonce[u64be]
        //        || staked[u128be] || delegated[u128be] || unbonding[u128be]
        let balance = account.balance.0.to_be_bytes();
        let nonce = account.nonce.to_be_bytes();
        let staked = account.staked.0.to_be_bytes();
        let delegated = account.delegated.0.to_be_bytes();
        let unbonding = account.unbonding.0.to_be_bytes();
        let parts: [&[u8]; 7] = [
            b"WEBC_ACCOUNT_LEAF_V2".as_slice(),
            address.as_bytes().as_slice(),
            balance.as_slice(),
            nonce.as_slice(),
            staked.as_slice(),
            delegated.as_slice(),
            unbonding.as_slice(),
        ];
        Ok(Hash256::digest_many(parts))
    }

    fn account_leaf_entries(&self) -> Result<Vec<(Address, Hash256)>, ChainError> {
        self.accounts
            .iter()
            .map(|(address, account)| Ok((*address, Self::account_leaf_hash(*address, account)?)))
            .collect()
    }

    fn apply_verified_transaction(
        &mut self,
        tx: &Transaction,
        config: &ChainConfig,
        tx_hash: Hash256,
    ) -> Result<Receipt, ChainError> {
        let mut access =
            StateAccessRecorder::new(&tx.access_list.read_only, &tx.access_list.read_write)?;
        // Authorization policy is consensus state even though it is consulted
        // before mutation. Ordinary transactions read it; first installation
        // writes the same key and therefore conflicts with concurrent spends.
        if matches!(&tx.operation, Operation::InstallAuthorizationPolicy { .. }) {
            access.write(StateKey::authorization_policy(tx.sender))?;
        } else {
            access.read(StateKey::authorization_policy(tx.sender))?;
        }
        // The selected lane owns both replay state and the fee source. This is
        // recorded before reading either value so a forged list fails closed.
        let expected_nonce = if tx.authorization_lane.is_default() {
            access.write(StateKey::account(tx.sender))?;
            self.accounts
                .get(&tx.sender)
                .ok_or(ChainError::AccountNotFound(tx.sender))?
                .nonce
        } else {
            access.write(StateKey::authorization_lane(
                tx.sender,
                tx.authorization_lane,
            ))?;
            self.authorization_lanes
                .get(&(tx.sender, tx.authorization_lane))
                .ok_or(ChainError::AuthorizationLaneNotFound)?
                .next_nonce
                .get()
        };
        if expected_nonce != tx.nonce {
            return Err(ChainError::NonceMismatch {
                address: tx.sender,
                expected: expected_nonce,
                actual: tx.nonce,
            });
        }

        let units = tx.required_units();
        if tx.fee.gas_limit < units {
            return Err(ChainError::GasLimitTooLow);
        }
        access.read(StateKey::protocol(ProtocolStateKey::BaseFee))?;
        let fee_per_unit = tx
            .fee
            .effective_fee_per_unit(self.current_base_fee_per_unit)?;
        let total_fee = Amount(
            u128::from(units)
                .checked_mul(u128::from(fee_per_unit))
                .ok_or(ChainError::ArithmeticOverflow)?,
        );
        let fee = split_fee(total_fee);

        if tx.authorization_lane.is_default() {
            self.debit_native(tx.sender, total_fee)?;
        } else {
            let lane = self
                .authorization_lanes
                .get_mut(&(tx.sender, tx.authorization_lane))
                .ok_or(ChainError::AuthorizationLaneNotFound)?;
            if lane.fee_balance < total_fee {
                return Err(ChainError::InsufficientLaneFeeBalance {
                    needed: total_fee,
                    available: lane.fee_balance,
                });
            }
            lane.fee_balance = lane
                .fee_balance
                .checked_sub(total_fee)
                .ok_or(ChainError::ArithmeticOverflow)?;
        }
        // Fee deltas are declared per payer. The sequential Phase 1 state folds
        // them into aggregate counters with checked addition; a future parallel
        // overlay can merge independent payer deltas without a global scheduler
        // lock while preserving the same deterministic totals.
        access.write(StateKey::fee_accumulator_for_lane(
            tx.sender,
            tx.authorization_lane,
        ))?;
        self.burned_fees = self
            .burned_fees
            .checked_add(fee.burned)
            .ok_or(ChainError::ArithmeticOverflow)?;
        self.validator_fee_pool = self
            .validator_fee_pool
            .checked_add(fee.validator_reward)
            .ok_or(ChainError::ArithmeticOverflow)?;
        if tx.authorization_lane.is_default() {
            let sender_account = self.account_mut(tx.sender)?;
            sender_account.nonce = sender_account
                .nonce
                .checked_add(1)
                .ok_or(ChainError::ArithmeticOverflow)?;
        } else {
            let lane = self
                .authorization_lanes
                .get_mut(&(tx.sender, tx.authorization_lane))
                .ok_or(ChainError::AuthorizationLaneNotFound)?;
            lane.next_nonce = lane
                .next_nonce
                .checked_next()
                .ok_or(ChainError::ArithmeticOverflow)?;
        }

        let mut events = vec![Event::FeePaid {
            payer: tx.sender,
            breakdown: fee,
        }];

        match &tx.operation {
            Operation::InstallAuthorizationPolicy { post_quantum_root } => {
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::AuthorizationPolicyRequiresDefaultLane);
                }
                if self.authorization_policies.contains_key(&tx.sender) {
                    return Err(ChainError::AuthorizationPolicyAlreadyExists);
                }
                let policy = AccountAuthorizationPolicy::new_v1(
                    tx.public_key,
                    *post_quantum_root,
                )?;
                let revision = policy.revision();
                self.authorization_policies.insert(tx.sender, policy);
                events.push(Event::AuthorizationPolicyInstalled {
                    owner: tx.sender,
                    revision,
                    post_quantum_root: *post_quantum_root,
                });
            }
            Operation::OpenAuthorizationLane { lane, fee_deposit } => {
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::LaneManagementRequiresDefault);
                }
                if lane.is_default() {
                    return Err(ChainError::DefaultAuthorizationLaneReserved);
                }
                if fee_deposit.is_zero() {
                    return Err(ChainError::AuthorizationLaneDepositZero);
                }
                access.write(StateKey::authorization_lane(tx.sender, *lane))?;
                if self.authorization_lanes.contains_key(&(tx.sender, *lane)) {
                    return Err(ChainError::AuthorizationLaneExists);
                }
                self.debit_native(tx.sender, *fee_deposit)?;
                self.authorization_lanes.insert(
                    (tx.sender, *lane),
                    AuthorizationLane::new(tx.sender, *lane, *fee_deposit),
                );
                events.push(Event::AuthorizationLaneOpened {
                    owner: tx.sender,
                    lane: *lane,
                    fee_deposit: *fee_deposit,
                });
            }
            Operation::FundAuthorizationLane { lane, fee_deposit } => {
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::LaneManagementRequiresDefault);
                }
                if fee_deposit.is_zero() {
                    return Err(ChainError::AuthorizationLaneDepositZero);
                }
                access.write(StateKey::authorization_lane(tx.sender, *lane))?;
                self.debit_native(tx.sender, *fee_deposit)?;
                let target = self
                    .authorization_lanes
                    .get_mut(&(tx.sender, *lane))
                    .ok_or(ChainError::AuthorizationLaneNotFound)?;
                target.fee_balance = target
                    .fee_balance
                    .checked_add(*fee_deposit)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                events.push(Event::AuthorizationLaneFunded {
                    owner: tx.sender,
                    lane: *lane,
                    fee_deposit: *fee_deposit,
                });
            }
            Operation::CreateObject {
                object_id,
                namespace,
                data,
            } => {
                access.write(StateKey::object(*object_id))?;
                access.write(StateKey::application(*namespace, object_id.hash()))?;
                if self.objects.contains_key(object_id) {
                    return Err(ChainError::ObjectAlreadyExists);
                }
                let object =
                    StateObject::new_owned(*object_id, *namespace, tx.sender, data.clone())?;
                let version = object.version;
                self.objects.insert(*object_id, object);
                events.push(Event::ObjectCreated {
                    object_id: *object_id,
                    namespace: *namespace,
                    owner: tx.sender,
                    version,
                });
            }
            Operation::MutateObject {
                object_id,
                namespace,
                expected_version,
                data,
            } => {
                access.write(StateKey::object(*object_id))?;
                access.write(StateKey::application(*namespace, object_id.hash()))?;
                validate_object_data(data)?;
                let object = self
                    .objects
                    .get_mut(object_id)
                    .ok_or(ChainError::ObjectNotFound)?;
                validate_owned_object(object, tx.sender, *namespace, *expected_version)?;
                object.version = object.version.checked_next()?;
                object.data = data.clone();
                events.push(Event::ObjectMutated {
                    object_id: *object_id,
                    version: object.version,
                });
            }
            Operation::TransferObject {
                object_id,
                namespace,
                expected_version,
                new_owner,
            } => {
                access.write(StateKey::object(*object_id))?;
                access.write(StateKey::application(*namespace, object_id.hash()))?;
                let object = self
                    .objects
                    .get_mut(object_id)
                    .ok_or(ChainError::ObjectNotFound)?;
                validate_owned_object(object, tx.sender, *namespace, *expected_version)?;
                object.version = object.version.checked_next()?;
                object.owner = ObjectOwner::Address(*new_owner);
                events.push(Event::ObjectTransferred {
                    object_id: *object_id,
                    from: tx.sender,
                    to: *new_owner,
                    version: object.version,
                });
            }
            Operation::Transfer { to, amount } => {
                access.write(StateKey::account(*to))?;
                self.debit_native(tx.sender, *amount)?;
                self.credit_native(*to, *amount)?;
                events.push(Event::Transfer {
                    from: tx.sender,
                    to: *to,
                    amount: *amount,
                });
            }
            Operation::RegisterValidator {
                consensus_key,
                self_stake,
                commission_bps,
                bootstrap,
            } => {
                access.write(StateKey::validator(tx.sender))?;
                if self.validators.contains_key(&tx.sender) {
                    return Err(ChainError::ValidatorAlreadyExists(tx.sender));
                }
                if *commission_bps > config.staking.max_commission_bps {
                    return Err(ChainError::CommissionTooHigh);
                }
                if *bootstrap {
                    return Err(ChainError::BootstrapDisabled);
                }
                if *self_stake < config.staking.min_validator_self_stake {
                    return Err(ChainError::StakeTooSmall);
                }
                if !self_stake.is_zero() {
                    self.debit_native(tx.sender, *self_stake)?;
                    let account = self.account_mut(tx.sender)?;
                    account.staked = account
                        .staked
                        .checked_add(*self_stake)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                }
                self.validators.insert(
                    tx.sender,
                    Validator {
                        operator: tx.sender,
                        consensus_key: *consensus_key,
                        self_stake: *self_stake,
                        delegated_stake: Amount::ZERO,
                        commission_bps: *commission_bps,
                        status: ValidatorStatus::PendingActivation,
                        bootstrap: false,
                        accumulated_rewards: Amount::ZERO,
                    },
                );
                let validator = self
                    .validators
                    .get_mut(&tx.sender)
                    .ok_or(ChainError::ValidatorNotFound(tx.sender))?;
                validator.refresh_stake_status(&config.staking)?;
                events.push(Event::ValidatorRegistered {
                    operator: tx.sender,
                    bootstrap: false,
                });
            }
            Operation::Delegate { validator, amount } => {
                access.write(StateKey::validator(*validator))?;
                access.write(StateKey::delegation(tx.sender, *validator))?;
                access.write(StateKey::unbonding_queue(*validator))?;
                if *amount < config.staking.min_delegation {
                    return Err(ChainError::DelegationTooSmall);
                }
                let target = self
                    .validators
                    .get(validator)
                    .ok_or(ChainError::ValidatorNotFound(*validator))?;
                if matches!(
                    target.status,
                    ValidatorStatus::Jailed { .. } | ValidatorStatus::Tombstoned { .. }
                ) {
                    return Err(ChainError::ValidatorNotActive(*validator));
                }
                // A queued operator exit remains slashable and voting-active
                // until admission, but it cannot safely back new delegation:
                // otherwise a delegator could enter after a full exit request
                // and be stranded when the epoch snapshot admits that exit.
                let queued_operator_stake = self.unbonding.queued_for(
                    *validator,
                    *validator,
                    UnbondingKind::OperatorStake,
                )?;
                let available_operator_stake = target
                    .self_stake
                    .checked_sub(queued_operator_stake)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                let maximum_delegated = available_operator_stake
                    .checked_mul_u64(4)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                let proposed_delegated = target
                    .delegated_stake
                    .checked_add(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                if proposed_delegated > maximum_delegated {
                    return Err(ChainError::DelegationRatioExceeded);
                }

                self.debit_native(tx.sender, *amount)?;
                let account = self.account_mut(tx.sender)?;
                account.delegated = account
                    .delegated
                    .checked_add(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;

                let validator_state = self
                    .validators
                    .get_mut(validator)
                    .ok_or(ChainError::ValidatorNotFound(*validator))?;
                validator_state.delegated_stake = validator_state
                    .delegated_stake
                    .checked_add(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                validator_state.refresh_stake_status(&config.staking)?;

                let key = (tx.sender, *validator);
                let delegation = self.delegations.entry(key).or_insert(Delegation {
                    delegator: tx.sender,
                    validator: *validator,
                    amount: Amount::ZERO,
                    accumulated_rewards: Amount::ZERO,
                });
                delegation.amount = delegation
                    .amount
                    .checked_add(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                events.push(Event::Delegated {
                    delegator: tx.sender,
                    validator: *validator,
                    amount: *amount,
                });
            }
            Operation::Undelegate { validator, amount } => {
                access.write(StateKey::delegation(tx.sender, *validator))?;
                access.write(StateKey::unbonding_queue(*validator))?;
                let key = (tx.sender, *validator);
                let existing = self
                    .delegations
                    .get(&key)
                    .ok_or(ChainError::DelegationNotFound)?;
                let already_queued =
                    self.unbonding
                        .queued_for(tx.sender, *validator, UnbondingKind::Delegation)?;
                let available = existing
                    .amount
                    .checked_sub(already_queued)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                if available < *amount {
                    return Err(ChainError::InsufficientBalance {
                        address: tx.sender,
                        needed: *amount,
                        available,
                    });
                }
                let remaining_active = available
                    .checked_sub(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                if !remaining_active.is_zero() && remaining_active < config.staking.min_delegation {
                    return Err(ChainError::DelegationTooSmall);
                }
                let request_id = self.unbonding.request(
                    tx.sender,
                    *validator,
                    UnbondingKind::Delegation,
                    *amount,
                    Epoch::new(self.current_epoch),
                    existing.accumulated_rewards,
                )?;
                events.push(Event::UnbondingRequested {
                    request_id,
                    delegator: tx.sender,
                    validator: *validator,
                    kind: UnbondingKind::Delegation,
                    amount: *amount,
                });
            }
            Operation::UnstakeValidator { amount } => {
                access.write(StateKey::validator(tx.sender))?;
                access.write(StateKey::unbonding_queue(tx.sender))?;
                let validator = self
                    .validators
                    .get(&tx.sender)
                    .ok_or(ChainError::ValidatorNotFound(tx.sender))?;
                let already_queued = self.unbonding.queued_for(
                    tx.sender,
                    tx.sender,
                    UnbondingKind::OperatorStake,
                )?;
                let available = validator
                    .self_stake
                    .checked_sub(already_queued)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                if available < *amount {
                    return Err(ChainError::InsufficientBalance {
                        address: tx.sender,
                        needed: *amount,
                        available,
                    });
                }
                let remaining = available
                    .checked_sub(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                if remaining.is_zero() {
                    if !validator.delegated_stake.is_zero() {
                        return Err(ChainError::OperatorExitHasDelegations);
                    }
                } else {
                    let maximum_delegated = remaining
                        .checked_mul_u64(4)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    let projected_total = remaining
                        .checked_add(validator.delegated_stake)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    if remaining < config.staking.min_validator_self_stake
                        || validator.delegated_stake > maximum_delegated
                        || projected_total < config.staking.min_validator_total_stake
                    {
                        return Err(ChainError::OperatorExitWouldDeactivatePool);
                    }
                }
                let request_id = self.unbonding.request(
                    tx.sender,
                    tx.sender,
                    UnbondingKind::OperatorStake,
                    *amount,
                    Epoch::new(self.current_epoch),
                    validator.accumulated_rewards,
                )?;
                events.push(Event::UnbondingRequested {
                    request_id,
                    delegator: tx.sender,
                    validator: tx.sender,
                    kind: UnbondingKind::OperatorStake,
                    amount: *amount,
                });
            }
            Operation::ClaimUnbonded {
                validator,
                request_id,
            } => {
                access.write(StateKey::unbonding_queue(*validator))?;
                let request = self
                    .unbonding
                    .get(*request_id)
                    .ok_or(ChainError::UnbondingRequestNotFound)?;
                if request.validator != *validator {
                    return Err(ChainError::UnbondingRequestNotFound);
                }
                let kind = request.kind;
                let amount = self.unbonding.claim(*request_id, tx.sender)?;
                let account = self.account_mut(tx.sender)?;
                account.unbonding = account
                    .unbonding
                    .checked_sub(amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                self.credit_native(tx.sender, amount)?;
                events.push(Event::UnbondingClaimed {
                    request_id: *request_id,
                    delegator: tx.sender,
                    kind,
                    amount,
                });
            }
            Operation::ClaimValidatorRewards => {
                access.write(StateKey::validator(tx.sender))?;
                let reward = {
                    let validator = self
                        .validators
                        .get_mut(&tx.sender)
                        .ok_or(ChainError::ValidatorNotFound(tx.sender))?;
                    let reward = validator.accumulated_rewards;
                    validator.accumulated_rewards = Amount::ZERO;
                    reward
                };
                self.credit_native(tx.sender, reward)?;
                events.push(Event::ValidatorRewardsClaimed {
                    validator: tx.sender,
                    amount: reward,
                });
            }
            Operation::ClaimDelegatorRewards { validator } => {
                access.write(StateKey::delegation(tx.sender, *validator))?;
                let reward = {
                    let delegation = self
                        .delegations
                        .get_mut(&(tx.sender, *validator))
                        .ok_or(ChainError::DelegationNotFound)?;
                    let reward = delegation.accumulated_rewards;
                    delegation.accumulated_rewards = Amount::ZERO;
                    reward
                };
                self.credit_native(tx.sender, reward)?;
                events.push(Event::DelegatorRewardsClaimed {
                    delegator: tx.sender,
                    validator: *validator,
                    amount: reward,
                });
            }
            Operation::SubmitSlashingEvidence { evidence } => {
                let validator_address = evidence.validator();
                access.write(StateKey::validator(validator_address))?;
                let consensus_key = self
                    .validators
                    .get(&validator_address)
                    .ok_or(ChainError::ValidatorNotFound(validator_address))?
                    .consensus_key;
                evidence.verify(config.protocol_version, &config.chain_id, &consensus_key)?;
                let evidence_hash = evidence.hash()?;
                access.write(StateKey::slashing_evidence(evidence_hash))?;
                if self.processed_slashing_evidence.contains(&evidence_hash) {
                    return Err(ChainError::SlashingReplay);
                }

                let penalty_bps = slashing_bps(evidence, &config.slashing);
                access.write(StateKey::unbonding_queue(validator_address))?;
                let delegation_losses = self
                    .delegations
                    .iter()
                    .filter(|((_, validator), _)| *validator == validator_address)
                    .map(|(key, delegation)| {
                        Ok((
                            *key,
                            delegation
                                .amount
                                .checked_mul_bps(penalty_bps)
                                .ok_or(ChainError::ArithmeticOverflow)?,
                        ))
                    })
                    .filter(|result| result.as_ref().map_or(true, |(_, loss)| !loss.is_zero()))
                    .collect::<Result<Vec<_>, ChainError>>()?;
                let delegated_slashed =
                    delegation_losses
                        .iter()
                        .try_fold(Amount::ZERO, |total, (_, loss)| {
                            total
                                .checked_add(*loss)
                                .ok_or(ChainError::ArithmeticOverflow)
                        })?;

                for ((delegator, validator), loss) in &delegation_losses {
                    self.unbonding.apply_active_slash(
                        *delegator,
                        *validator,
                        UnbondingKind::Delegation,
                        *loss,
                    )?;
                }
                let locked_slash = self
                    .unbonding
                    .slash_locked(validator_address, penalty_bps)?;
                for owner in locked_slash.locked_losses.keys() {
                    access.write(StateKey::account(*owner))?;
                }

                access.write(StateKey::account(validator_address))?;
                for ((delegator, validator), _) in &delegation_losses {
                    access.write(StateKey::delegation(*delegator, *validator))?;
                    access.write(StateKey::account(*delegator))?;
                }
                let validator = self
                    .validators
                    .get_mut(&validator_address)
                    .ok_or(ChainError::ValidatorNotFound(validator_address))?;
                let outcome = slash_validator_with_delegation_loss(
                    validator,
                    evidence,
                    &config.slashing,
                    delegated_slashed,
                )?;
                self.unbonding.apply_active_slash(
                    validator_address,
                    validator_address,
                    UnbondingKind::OperatorStake,
                    outcome.self_slashed,
                )?;
                let operator = self.account_mut(validator_address)?;
                operator.staked = operator
                    .staked
                    .checked_sub(outcome.self_slashed)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                for ((delegator, validator), loss) in delegation_losses {
                    let delegation = self
                        .delegations
                        .get_mut(&(delegator, validator))
                        .ok_or(ChainError::DelegationNotFound)?;
                    delegation.amount = delegation
                        .amount
                        .checked_sub(loss)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    let account = self.account_mut(delegator)?;
                    account.delegated = account
                        .delegated
                        .checked_sub(loss)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                }
                let locked_total_slashed = locked_slash.total_locked_slashed;
                for (owner, loss) in locked_slash.locked_losses {
                    let account = self.account_mut(owner)?;
                    account.unbonding = account
                        .unbonding
                        .checked_sub(loss)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                }
                let total_slashed = outcome
                    .self_slashed
                    .checked_add(outcome.delegated_slashed)
                    .and_then(|amount| amount.checked_add(locked_total_slashed))
                    .ok_or(ChainError::ArithmeticOverflow)?;
                self.slashed_units = self
                    .slashed_units
                    .checked_add(total_slashed)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                self.processed_slashing_evidence.insert(evidence_hash);
                events.push(Event::Slashed { outcome });
            }
            Operation::BridgeLock {
                asset,
                destination_chain,
                recipient,
                amount,
            } => {
                if amount.is_zero() {
                    return Err(ChainError::BridgeAmountZero);
                }
                if *asset != AssetId::NativeWebc || *destination_chain == ExternalChain::Webc {
                    return Err(ChainError::InvalidBridgeAssetFlow);
                }
                access.write(StateKey::bridge_escrow(destination_chain.clone()))?;
                self.debit_asset_or_native(tx.sender, asset, *amount)?;
                self.credit_native_bridge_escrow(destination_chain.clone(), *amount)?;
                let message = self.next_bridge_message(
                    OutgoingBridgeMessage {
                        source_chain: ExternalChain::Webc,
                        destination_chain: destination_chain.clone(),
                        asset: asset.clone(),
                        sender: tx.sender.as_bytes().to_vec(),
                        recipient: recipient.clone(),
                        amount: *amount,
                        source_tx: tx_hash,
                    },
                    &mut access,
                )?;
                let message_hash = message.hash()?;
                events.push(Event::Bridge {
                    event: BridgeEvent::Locked {
                        message,
                        message_hash,
                    },
                });
            }
            Operation::BridgeBurn {
                asset,
                destination_chain,
                recipient,
                amount,
            } => {
                if amount.is_zero() {
                    return Err(ChainError::BridgeAmountZero);
                }
                let AssetId::External { origin_chain, .. } = asset else {
                    return Err(ChainError::InvalidBridgeAssetFlow);
                };
                if *origin_chain != *destination_chain || *destination_chain == ExternalChain::Webc
                {
                    return Err(ChainError::BridgeSourceMismatch);
                }
                access.write(StateKey::asset_balance(asset.clone(), tx.sender))?;
                self.debit_asset_or_native(tx.sender, asset, *amount)?;
                let message = self.next_bridge_message(
                    OutgoingBridgeMessage {
                        source_chain: ExternalChain::Webc,
                        destination_chain: destination_chain.clone(),
                        asset: asset.clone(),
                        sender: tx.sender.as_bytes().to_vec(),
                        recipient: recipient.clone(),
                        amount: *amount,
                        source_tx: tx_hash,
                    },
                    &mut access,
                )?;
                let message_hash = message.hash()?;
                events.push(Event::Bridge {
                    event: BridgeEvent::Burned {
                        message,
                        message_hash,
                    },
                });
            }
            Operation::BridgeMint { message } => {
                if !config.bridge.can_submit_incoming(tx.sender) {
                    return Err(ChainError::UnauthorizedBridgeRelayer);
                }
                let message_hash = self.process_incoming_bridge_message(
                    message,
                    IncomingBridgeAction::MintRepresentation,
                    &mut access,
                )?;
                events.push(Event::Bridge {
                    event: BridgeEvent::Minted {
                        message: message.clone(),
                        message_hash,
                    },
                });
            }
            Operation::BridgeRelease { message } => {
                if !config.bridge.can_submit_incoming(tx.sender) {
                    return Err(ChainError::UnauthorizedBridgeRelayer);
                }
                let message_hash = self.process_incoming_bridge_message(
                    message,
                    IncomingBridgeAction::ReleaseNative,
                    &mut access,
                )?;
                events.push(Event::Bridge {
                    event: BridgeEvent::Released {
                        message: message.clone(),
                        message_hash,
                    },
                });
            }
        }

        access.finish()?;

        Ok(Receipt {
            tx_hash,
            success: true,
            fee,
            units_consumed: units,
            events,
            error: None,
        })
    }

    fn process_incoming_bridge_message(
        &mut self,
        message: &BridgeMessage,
        action: IncomingBridgeAction,
        access: &mut StateAccessRecorder,
    ) -> Result<Hash256, ChainError> {
        if message.destination_chain != ExternalChain::Webc {
            return Err(ChainError::BridgeDestinationMismatch);
        }
        if message.amount.is_zero() {
            return Err(ChainError::BridgeAmountZero);
        }
        let message_hash = message.hash()?;
        access.write(StateKey::bridge_message(message_hash))?;
        if self.processed_bridge_messages.contains(&message_hash) {
            return Err(ChainError::BridgeReplay);
        }
        let recipient_bytes: [u8; 32] = message
            .recipient
            .as_slice()
            .try_into()
            .map_err(|_| ChainError::InvalidBridgeRecipient)?;
        let recipient = Address::from_bytes(recipient_bytes);
        match action {
            IncomingBridgeAction::MintRepresentation => {
                let AssetId::External { origin_chain, .. } = &message.asset else {
                    return Err(ChainError::InvalidBridgeAssetFlow);
                };
                if *origin_chain != message.source_chain
                    || message.source_chain == ExternalChain::Webc
                {
                    return Err(ChainError::BridgeSourceMismatch);
                }
                access.write(StateKey::asset_balance(message.asset.clone(), recipient))?;
                self.credit_asset_or_native(recipient, &message.asset, message.amount)?;
            }
            IncomingBridgeAction::ReleaseNative => {
                if message.asset != AssetId::NativeWebc
                    || message.source_chain == ExternalChain::Webc
                {
                    return Err(ChainError::InvalidBridgeAssetFlow);
                }
                access.write(StateKey::account(recipient))?;
                access.write(StateKey::bridge_escrow(message.source_chain.clone()))?;
                self.debit_native_bridge_escrow(message.source_chain.clone(), message.amount)?;
                self.credit_native(recipient, message.amount)?;
            }
        }
        self.processed_bridge_messages.insert(message_hash);
        Ok(message_hash)
    }

    fn next_bridge_message(
        &mut self,
        draft: OutgoingBridgeMessage,
        access: &mut StateAccessRecorder,
    ) -> Result<BridgeMessage, ChainError> {
        access.write(StateKey::protocol(ProtocolStateKey::BridgeNonce))?;
        let nonce = self.bridge_nonce;
        self.bridge_nonce = self
            .bridge_nonce
            .checked_add(1)
            .ok_or(ChainError::ArithmeticOverflow)?;
        Ok(BridgeMessage {
            source_chain: draft.source_chain,
            destination_chain: draft.destination_chain,
            nonce,
            asset: draft.asset,
            sender: draft.sender,
            recipient: draft.recipient,
            amount: draft.amount,
            source_tx: draft.source_tx,
        })
    }

    fn credit_native_bridge_escrow(
        &mut self,
        domain: ExternalChain,
        amount: Amount,
    ) -> Result<(), ChainError> {
        let current = self
            .native_bridge_escrow
            .get(&domain)
            .copied()
            .unwrap_or(Amount::ZERO);
        self.native_bridge_escrow.insert(
            domain,
            current
                .checked_add(amount)
                .ok_or(ChainError::ArithmeticOverflow)?,
        );
        Ok(())
    }

    fn debit_native_bridge_escrow(
        &mut self,
        domain: ExternalChain,
        amount: Amount,
    ) -> Result<(), ChainError> {
        let available = self
            .native_bridge_escrow
            .get(&domain)
            .copied()
            .unwrap_or(Amount::ZERO);
        if available < amount {
            return Err(ChainError::InsufficientBridgeEscrow {
                needed: amount,
                available,
            });
        }
        let remaining = available
            .checked_sub(amount)
            .ok_or(ChainError::ArithmeticOverflow)?;
        if remaining.is_zero() {
            self.native_bridge_escrow.remove(&domain);
        } else {
            self.native_bridge_escrow.insert(domain, remaining);
        }
        Ok(())
    }

    fn account_mut(&mut self, address: Address) -> Result<&mut Account, ChainError> {
        self.accounts
            .get_mut(&address)
            .ok_or(ChainError::AccountNotFound(address))
    }

    fn debit_native(&mut self, address: Address, amount: Amount) -> Result<(), ChainError> {
        if amount.is_zero() {
            return Ok(());
        }
        let account = self.account_mut(address)?;
        if account.balance < amount {
            return Err(ChainError::InsufficientBalance {
                address,
                needed: amount,
                available: account.balance,
            });
        }
        account.balance = account
            .balance
            .checked_sub(amount)
            .ok_or(ChainError::ArithmeticOverflow)?;
        Ok(())
    }

    fn credit_native(&mut self, address: Address, amount: Amount) -> Result<(), ChainError> {
        if amount.is_zero() {
            return Ok(());
        }
        let account = self.accounts.entry(address).or_default();
        account.balance = account
            .balance
            .checked_add(amount)
            .ok_or(ChainError::ArithmeticOverflow)?;
        Ok(())
    }

    fn debit_asset_or_native(
        &mut self,
        owner: Address,
        asset: &AssetId,
        amount: Amount,
    ) -> Result<(), ChainError> {
        if *asset == AssetId::NativeWebc {
            return self.debit_native(owner, amount);
        }
        if amount.is_zero() {
            return Ok(());
        }
        let key = (asset.clone(), owner);
        let balance = self
            .asset_balances
            .get(&key)
            .copied()
            .unwrap_or(Amount::ZERO);
        if balance < amount {
            return Err(ChainError::InsufficientBalance {
                address: owner,
                needed: amount,
                available: balance,
            });
        }
        let remaining = balance
            .checked_sub(amount)
            .ok_or(ChainError::ArithmeticOverflow)?;
        if remaining.is_zero() {
            self.asset_balances.remove(&key);
        } else {
            self.asset_balances.insert(key, remaining);
        }
        Ok(())
    }

    fn credit_asset_or_native(
        &mut self,
        owner: Address,
        asset: &AssetId,
        amount: Amount,
    ) -> Result<(), ChainError> {
        if *asset == AssetId::NativeWebc {
            return self.credit_native(owner, amount);
        }
        if amount.is_zero() {
            return Ok(());
        }
        let key = (asset.clone(), owner);
        let balance = self
            .asset_balances
            .get(&key)
            .copied()
            .unwrap_or(Amount::ZERO);
        self.asset_balances.insert(
            key,
            balance
                .checked_add(amount)
                .ok_or(ChainError::ArithmeticOverflow)?,
        );
        Ok(())
    }
}

fn validate_owned_object(
    object: &StateObject,
    sender: Address,
    namespace: Hash256,
    expected_version: ObjectVersion,
) -> Result<(), ChainError> {
    if object.namespace != namespace {
        return Err(ChainError::ObjectNamespaceMismatch);
    }
    match object.owner {
        ObjectOwner::Address(owner) if owner == sender => {}
        ObjectOwner::Address(_) => return Err(ChainError::ObjectOwnerMismatch),
        ObjectOwner::Shared => return Err(ChainError::SharedObjectMutationUnsupported),
    }
    if object.version != expected_version {
        return Err(ChainError::ObjectVersionMismatch {
            expected: expected_version.get(),
            actual: object.version.get(),
        });
    }
    Ok(())
}

fn ordered_value_root<'a, K, V, I>(domain: &'static [u8], entries: I) -> Result<Hash256, ChainError>
where
    K: Serialize + 'a,
    V: Serialize + 'a,
    I: Iterator<Item = (&'a K, &'a V)>,
{
    let leaves = entries
        .map(|entry| leaf_hash(domain, &entry))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(merkle_root(&leaves))
}

fn ordered_set_root<'a, T, I>(domain: &'static [u8], entries: I) -> Result<Hash256, ChainError>
where
    T: Serialize + 'a,
    I: Iterator<Item = &'a T>,
{
    let leaves = entries
        .map(|entry| leaf_hash(domain, entry))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(merkle_root(&leaves))
}

fn leaf_hash<T: Serialize + ?Sized>(
    domain: &'static [u8],
    value: &T,
) -> Result<Hash256, ChainError> {
    // Previously this used bincode. Canonical JSON keeps leaves reproducible
    // from any language once equivalent browser SDK helpers exist. The domain
    // bytes are prepended verbatim so the leaf space stays namespace-separated
    // and cannot collide with other WEBC artifacts.
    let bytes = crate::canonical::canonical_json_bytes(value)?;
    let parts: [&[u8]; 2] = [domain, bytes.as_slice()];
    Ok(Hash256::digest_many(parts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthorizationPolicyRevision, DoubleVoteEvidence, FeeBid, GenesisAccount,
        GenesisValidator, Nonce, Operation, PostQuantumRoot, PostQuantumScheme, SignedVote,
        SlashingEvidence, ValidatorSet, Vote, VoteType, MAX_AUTHORIZATION_POLICY_REVISION,
    };
    use proptest::prelude::*;
    use webc_crypto::{Keypair, PublicKeyBytes};

    fn funded_state() -> (ChainConfig, ChainState, Keypair, Keypair) {
        let config = ChainConfig::default();
        let alice = Keypair::from_seed([1u8; 32]);
        let bob = Keypair::from_seed([2u8; 32]);
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![GenesisAccount {
                address: alice.address(),
                balance: Amount::from_webc(1_000),
            }],
            validators: Vec::new(),
        };
        let state = ChainState::from_genesis(&genesis).unwrap();
        (config, state, alice, bob)
    }

    #[test]
    fn policy_installation_commits_root_and_invalidates_legacy_revision() {
        let (config, mut state, alice, bob) = funded_state();
        let root = PostQuantumRoot::new(
            PostQuantumScheme::MlDsa65,
            Hash256::digest(b"alice ML-DSA-65 candidate public key"),
        )
        .unwrap();
        let before_root = state.state_root().unwrap();
        let install = Transaction::for_operation(
            &alice,
            0,
            Operation::InstallAuthorizationPolicy {
                post_quantum_root: root,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        state.execute_transaction(&install, &config).unwrap();

        let policy = state
            .authorization_policies
            .get(&alice.address())
            .expect("policy committed");
        assert_eq!(policy.revision(), AuthorizationPolicyRevision::new(1));
        assert_eq!(policy.active_transaction_key(), &alice.public_key());
        assert_ne!(state.state_root().unwrap(), before_root);

        let legacy_revision = Transaction::for_operation(
            &alice,
            1,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_units(1),
            },
            FeeBid::default(),
        )
        .unwrap();
        let before_rejected = state.clone();
        assert!(matches!(
            state.execute_transaction(&legacy_revision, &config),
            Err(ChainError::AuthorizationPolicyRevisionMismatch {
                expected: 1,
                actual: 0
            })
        ));
        assert_eq!(state, before_rejected);

        let authorized = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(1),
            1,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_units(1),
            },
            FeeBid::default(),
        )
        .unwrap();
        state.execute_transaction(&authorized, &config).unwrap();
    }

    #[test]
    fn installed_policy_rejects_another_valid_signature_key_atomically() {
        let (config, mut state, alice, attacker) = funded_state();
        let root = PostQuantumRoot::new(
            PostQuantumScheme::MlDsa65,
            Hash256::digest(b"alice recovery root"),
        )
        .unwrap();
        let install = Transaction::for_operation(
            &alice,
            0,
            Operation::InstallAuthorizationPolicy {
                post_quantum_root: root,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        state.execute_transaction(&install, &config).unwrap();

        let operation = Operation::Transfer {
            to: attacker.address(),
            amount: Amount::from_units(1),
        };
        let access_list = operation.default_access_list(alice.address()).unwrap();
        let mut forged = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            config.chain_id.clone(),
            alice.address(),
            attacker.public_key(),
            AuthorizationLaneId::DEFAULT,
            AuthorizationPolicyRevision::new(1),
            1,
            operation,
            access_list,
            FeeBid::default(),
        );
        forged.sign_with_policy_key(&attacker).unwrap();
        forged.verify().expect("signature itself is valid");
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&forged, &config),
            Err(ChainError::AuthorizationKeyMismatch)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn malformed_root_and_inexact_revision_fail_before_state_commit() {
        let (config, mut state, alice, _) = funded_state();
        let invalid_root = PostQuantumRoot {
            scheme: PostQuantumScheme::MlDsa65,
            public_key_hash: Hash256::ZERO,
        };
        let install = Transaction::for_operation(
            &alice,
            0,
            Operation::InstallAuthorizationPolicy {
                post_quantum_root: invalid_root,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        let before_root = state.clone();
        assert!(matches!(
            state.execute_transaction(&install, &config),
            Err(ChainError::InvalidPostQuantumRoot)
        ));
        assert_eq!(state, before_root);

        let mut inexact = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: alice.address(),
                amount: Amount::from_units(1),
            },
            FeeBid::default(),
        )
        .unwrap();
        inexact.authorization_policy_revision =
            AuthorizationPolicyRevision::new(MAX_AUTHORIZATION_POLICY_REVISION + 1);
        inexact.sign(&alice).unwrap();
        let before_revision = state.clone();
        assert!(matches!(
            state.execute_transaction(&inexact, &config),
            Err(ChainError::InvalidAuthorizationPolicyRevision)
        ));
        assert_eq!(state, before_revision);
    }

    fn double_vote_evidence(
        validator: &Keypair,
        chain_id: ChainId,
        first_block: Hash256,
        second_block: Hash256,
    ) -> SlashingEvidence {
        double_vote_evidence_at_height(validator, chain_id, 1, first_block, second_block)
    }

    fn double_vote_evidence_at_height(
        validator: &Keypair,
        chain_id: ChainId,
        height: u64,
        first_block: Hash256,
        second_block: Hash256,
    ) -> SlashingEvidence {
        let vote = |block_hash| Vote {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            chain_id: chain_id.clone(),
            height,
            round: 0,
            vote_type: VoteType::Precommit,
            block_hash,
            validator: validator.address(),
        };
        SlashingEvidence::DoubleVote(DoubleVoteEvidence {
            first: SignedVote::sign(vote(first_block), validator).expect("first vote signs"),
            second: SignedVote::sign(vote(second_block), validator).expect("second vote signs"),
        })
    }

    fn active_delegated_state() -> (ChainConfig, ChainState, Keypair, Keypair) {
        let (config, mut state, alice, bob) = funded_state();
        let fund = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(200),
            },
            FeeBid::default(),
        )
        .expect("funding signs");
        state.execute_transaction(&fund, &config).expect("funding");
        let register = Transaction::for_operation(
            &alice,
            1,
            Operation::RegisterValidator {
                consensus_key: alice.public_key(),
                self_stake: Amount::from_webc(20),
                commission_bps: 500,
                bootstrap: false,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("registration signs");
        state
            .execute_transaction(&register, &config)
            .expect("registration");
        let delegate = Transaction::for_operation(
            &bob,
            0,
            Operation::Delegate {
                validator: alice.address(),
                amount: Amount::from_webc(80),
            },
            FeeBid {
                gas_limit: 15_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("delegation signs");
        state
            .execute_transaction(&delegate, &config)
            .expect("delegation");
        (config, state, alice, bob)
    }

    fn randomized_staking_state() -> (ChainConfig, ChainState, Keypair, [Keypair; 2]) {
        let mut config = ChainConfig::default();
        // Short test-only epochs expose queue admission, partial churn, maturity,
        // and claims inside each generated operation sequence.
        config.staking.unbonding_cooldown_epochs = 2;
        config.staking.slashable_unbonding_epochs = 2;
        config.staking.max_unbonding_units_per_epoch = Amount::from_webc(30);

        let operator = Keypair::from_seed([31u8; 32]);
        let delegators = [
            Keypair::from_seed([32u8; 32]),
            Keypair::from_seed([33u8; 32]),
        ];
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![
                GenesisAccount {
                    address: operator.address(),
                    balance: Amount::from_webc(1_000),
                },
                GenesisAccount {
                    address: delegators[0].address(),
                    balance: Amount::from_webc(500),
                },
                GenesisAccount {
                    address: delegators[1].address(),
                    balance: Amount::from_webc(500),
                },
            ],
            validators: Vec::new(),
        };
        let mut state = ChainState::from_genesis(&genesis).expect("property genesis");
        let register = Transaction::for_operation(
            &operator,
            0,
            Operation::RegisterValidator {
                consensus_key: operator.public_key(),
                self_stake: Amount::from_webc(100),
                commission_bps: 500,
                bootstrap: false,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("property registration signs");
        state
            .execute_transaction(&register, &config)
            .expect("property validator registration");
        (config, state, operator, delegators)
    }

    fn checked_test_sum(values: impl Iterator<Item = Amount>) -> Amount {
        values.fold(Amount::ZERO, |total, value| {
            total.checked_add(value).expect("test amount sum")
        })
    }

    fn assert_staking_invariants(state: &ChainState, config: &ChainConfig) {
        for (address, account) in &state.accounts {
            let expected_staked = state
                .validators
                .get(address)
                .map_or(Amount::ZERO, |validator| validator.self_stake);
            assert_eq!(account.staked, expected_staked, "operator mirror mismatch");

            let expected_delegated = checked_test_sum(
                state
                    .delegations
                    .values()
                    .filter(|delegation| delegation.delegator == *address)
                    .map(|delegation| delegation.amount),
            );
            assert_eq!(
                account.delegated, expected_delegated,
                "delegator mirror mismatch"
            );

            let expected_unbonding = checked_test_sum(
                state
                    .unbonding
                    .requests()
                    .filter(|request| request.owner == *address)
                    .map(|request| {
                        checked_test_sum(request.cooling.iter().map(|tranche| tranche.amount))
                            .checked_add(request.withdrawable)
                            .expect("test locked principal sum")
                    }),
            );
            assert_eq!(
                account.unbonding, expected_unbonding,
                "cooling/withdrawable mirror mismatch"
            );
        }

        for (operator, validator) in &state.validators {
            let expected_delegated = checked_test_sum(
                state
                    .delegations
                    .values()
                    .filter(|delegation| delegation.validator == *operator)
                    .map(|delegation| delegation.amount),
            );
            assert_eq!(
                validator.delegated_stake, expected_delegated,
                "validator delegation aggregate mismatch"
            );

            if validator.status == ValidatorStatus::Active {
                let total = validator.total_stake().expect("active total stake");
                let maximum_delegated = validator
                    .self_stake
                    .checked_mul_u64(4)
                    .expect("active ratio capacity");
                assert!(validator.self_stake >= config.staking.min_validator_self_stake);
                assert!(total >= config.staking.min_validator_total_stake);
                assert!(validator.delegated_stake <= maximum_delegated);
            }

            let queued_operator = state
                .unbonding
                .queued_for(*operator, *operator, UnbondingKind::OperatorStake)
                .expect("queued operator total");
            assert!(queued_operator <= validator.self_stake);
        }

        for ((delegator, validator), delegation) in &state.delegations {
            let queued = state
                .unbonding
                .queued_for(*delegator, *validator, UnbondingKind::Delegation)
                .expect("queued delegation total");
            assert!(queued <= delegation.amount);
        }

        assert!(
            state
                .supply_invariant_report()
                .expect("property supply report")
                .balanced,
            "native supply buckets must reconcile after every step"
        );
    }

    fn execute_with_rollback_check(
        state: &mut ChainState,
        config: &ChainConfig,
        transaction: &Transaction,
    ) {
        let before = state.clone();
        if state.execute_transaction(transaction, config).is_err() {
            assert_eq!(*state, before, "failed transaction mutated chain state");
        }
    }

    fn property_transaction(
        state: &ChainState,
        signer: &Keypair,
        operation: Operation,
    ) -> Transaction {
        let nonce = state
            .accounts
            .get(&signer.address())
            .expect("property signer account")
            .nonce;
        Transaction::for_operation(
            signer,
            nonce,
            operation,
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("property transaction signs")
    }

    fn property_slash_transaction(
        state: &ChainState,
        config: &ChainConfig,
        operator: &Keypair,
        height: u64,
        entropy: u8,
    ) -> Transaction {
        let evidence = double_vote_evidence_at_height(
            operator,
            config.chain_id.clone(),
            height,
            Hash256::digest([entropy, 0]),
            Hash256::digest([entropy, 1]),
        );
        let mut transaction = property_transaction(
            state,
            operator,
            Operation::SubmitSlashingEvidence { evidence },
        );

        let mut declare_write = |key: StateKey| {
            if !transaction.access_list.read_write.contains(&key) {
                transaction.access_list.read_write.push(key);
            }
        };
        for delegation in state.delegations.values().filter(|delegation| {
            delegation.validator == operator.address()
                && delegation
                    .amount
                    .checked_mul_bps(config.slashing.double_sign_bps)
                    .is_some_and(|loss| !loss.is_zero())
        }) {
            declare_write(StateKey::delegation(
                delegation.delegator,
                delegation.validator,
            ));
            declare_write(StateKey::account(delegation.delegator));
        }
        for request in state.unbonding.requests().filter(|request| {
            request.validator == operator.address()
                && (request.cooling.iter().any(|tranche| {
                    tranche
                        .amount
                        .checked_mul_bps(config.slashing.double_sign_bps)
                        .is_some_and(|loss| !loss.is_zero())
                }) || request
                    .withdrawable
                    .checked_mul_bps(config.slashing.double_sign_bps)
                    .is_some_and(|loss| !loss.is_zero()))
        }) {
            declare_write(StateKey::account(request.owner));
        }
        transaction
            .sign(operator)
            .expect("expanded property slash signs");
        transaction
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Generated operation streams exercise success, rejection, rollback,
        /// epoch admission, reward, slash, maturity, and claim interleavings.
        #[test]
        fn arbitrary_stake_sequences_preserve_all_accounting_mirrors(
            actions in prop::collection::vec((any::<u8>(), any::<u8>()), 1..128)
        ) {
            let (config, mut state, operator, delegators) = randomized_staking_state();
            assert_staking_invariants(&state, &config);

            for (step, (selector, entropy)) in actions.into_iter().enumerate() {
                let delegator = &delegators[usize::from(selector & 1)];
                let amount = Amount::from_webc(u64::from(entropy % 40) + 1);
                match selector % 8 {
                    0 => {
                        let transaction = property_transaction(
                            &state,
                            delegator,
                            Operation::Delegate {
                                validator: operator.address(),
                                amount,
                            },
                        );
                        execute_with_rollback_check(&mut state, &config, &transaction);
                    }
                    1 => {
                        let transaction = property_transaction(
                            &state,
                            delegator,
                            Operation::Undelegate {
                                validator: operator.address(),
                                amount,
                            },
                        );
                        execute_with_rollback_check(&mut state, &config, &transaction);
                    }
                    2 => {
                        state
                            .distribute_epoch_rewards(&config)
                            .expect("property epoch transition");
                    }
                    3 => {
                        let transaction = property_transaction(
                            &state,
                            delegator,
                            Operation::ClaimUnbonded {
                                validator: operator.address(),
                                request_id: UnbondingRequestId::new(u64::from(entropy % 32)),
                            },
                        );
                        execute_with_rollback_check(&mut state, &config, &transaction);
                    }
                    4 => {
                        let transaction = property_transaction(
                            &state,
                            &operator,
                            Operation::UnstakeValidator { amount },
                        );
                        execute_with_rollback_check(&mut state, &config, &transaction);
                    }
                    5 => {
                        let transaction = property_transaction(
                            &state,
                            delegator,
                            Operation::ClaimDelegatorRewards {
                                validator: operator.address(),
                            },
                        );
                        execute_with_rollback_check(&mut state, &config, &transaction);
                    }
                    6 => {
                        let transaction = property_transaction(
                            &state,
                            &operator,
                            Operation::ClaimValidatorRewards,
                        );
                        execute_with_rollback_check(&mut state, &config, &transaction);
                    }
                    _ => {
                        let height = u64::try_from(step)
                            .expect("property sequence length fits u64")
                            .checked_add(1)
                            .expect("property height");
                        let transaction = property_slash_transaction(
                            &state,
                            &config,
                            &operator,
                            height,
                            entropy,
                        );
                        execute_with_rollback_check(&mut state, &config, &transaction);
                    }
                }
                assert_staking_invariants(&state, &config);
            }
        }
    }

    #[test]
    fn transfer_updates_balances_and_splits_fee() {
        let (config, mut state, alice, bob) = funded_state();
        let tx = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(10),
            },
            FeeBid {
                gas_limit: 1_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();

        let receipt = state.execute_transaction(&tx, &config).unwrap();
        assert!(receipt.success);
        assert_eq!(
            state.accounts.get(&bob.address()).unwrap().balance,
            Amount::from_webc(10)
        );
        assert_eq!(state.burned_fees.0 + state.validator_fee_pool.0, 500);
    }

    #[test]
    fn undeclared_write_rejects_and_rolls_back_transaction() {
        let (config, mut state, alice, bob) = funded_state();
        let mut tx = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(10),
            },
            FeeBid::default(),
        )
        .expect("default transfer is valid");
        tx.access_list
            .read_write
            .retain(|key| key != &StateKey::account(bob.address()));
        tx.sign(&alice).expect("modified declaration is signed");
        let before = state.clone();

        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::UndeclaredStateWrite { key })
                if key == StateKey::account(bob.address())
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn undeclared_read_rejects_before_fee_state_changes() {
        let (config, mut state, alice, bob) = funded_state();
        let mut tx = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(10),
            },
            FeeBid::default(),
        )
        .expect("default transfer is valid");
        tx.access_list.read_only.clear();
        tx.sign(&alice).expect("modified declaration is signed");
        let before = state.clone();

        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::UndeclaredStateRead { key })
                if key == StateKey::authorization_policy(alice.address())
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn read_only_key_cannot_be_written_and_rolls_back_transaction() {
        let (config, mut state, alice, bob) = funded_state();
        let recipient_key = StateKey::account(bob.address());
        let mut tx = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(10),
            },
            FeeBid::default(),
        )
        .expect("default transfer is valid");
        tx.access_list
            .read_write
            .retain(|key| key != &recipient_key);
        tx.access_list.read_only.push(recipient_key.clone());
        tx.access_list.read_only.sort();
        tx.sign(&alice).expect("modified declaration is signed");
        let before = state.clone();

        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::UndeclaredStateWrite { key }) if key == recipient_key
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn unused_declared_key_rejects_and_rolls_back_transaction() {
        let (config, mut state, alice, bob) = funded_state();
        let unrelated = StateKey::application(
            Hash256::digest(b"unrelated-site"),
            Hash256::digest(b"unused-key"),
        );
        let mut tx = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(10),
            },
            FeeBid::default(),
        )
        .expect("default transfer is valid");
        tx.access_list.read_write.push(unrelated);
        tx.access_list.read_write.sort();
        tx.sign(&alice).expect("modified declaration is signed");
        let before = state.clone();

        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::UnusedDeclaredStateAccess)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn genesis_stake_is_debited_and_supply_reconciles() {
        let config = ChainConfig::default();
        let operator = Keypair::from_seed([41u8; 32]);
        let genesis = GenesisConfig {
            chain: config,
            accounts: vec![GenesisAccount {
                address: operator.address(),
                balance: Amount::from_webc(100),
            }],
            validators: vec![GenesisValidator {
                operator: operator.address(),
                consensus_key: PublicKeyBytes([7u8; 32]),
                self_stake: Amount::from_webc(20),
                commission_bps: 500,
                bootstrap: false,
            }],
        };
        let state = ChainState::from_genesis(&genesis).expect("valid staked genesis");
        let account = state
            .accounts
            .get(&operator.address())
            .expect("operator account");
        assert_eq!(account.balance, Amount::from_webc(80));
        assert_eq!(account.staked, Amount::from_webc(20));
        let report = state.supply_invariant_report().expect("checked report");
        assert!(report.balanced);
        assert_eq!(report.issued, Amount::from_webc(100));
    }

    #[test]
    fn duplicate_genesis_accounts_are_rejected() {
        let config = ChainConfig::default();
        let account = Keypair::from_seed([42u8; 32]).address();
        let genesis = GenesisConfig {
            chain: config,
            accounts: vec![
                GenesisAccount {
                    address: account,
                    balance: Amount::from_webc(1),
                },
                GenesisAccount {
                    address: account,
                    balance: Amount::from_webc(1),
                },
            ],
            validators: Vec::new(),
        };
        assert!(matches!(
            ChainState::from_genesis(&genesis),
            Err(ChainError::DuplicateGenesisAccount(duplicate)) if duplicate == account
        ));
    }

    #[test]
    fn invalid_nonce_does_not_mutate_state() {
        let (config, mut state, alice, bob) = funded_state();
        let before = state.clone();
        let tx = Transaction::for_operation(
            &alice,
            7,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(10),
            },
            FeeBid::default(),
        )
        .unwrap();
        assert!(state.execute_transaction(&tx, &config).is_err());
        assert_eq!(state, before);
    }

    #[test]
    fn transaction_protocol_and_chain_context_prevent_replay() {
        let (config, mut state, alice, bob) = funded_state();
        let operation = Operation::Transfer {
            to: bob.address(),
            amount: Amount::from_webc(1),
        };
        let other_chain = Transaction::for_operation_on_chain(
            &alice,
            config.protocol_version,
            ChainId::new("webc-other-1").expect("valid alternate chain"),
            0,
            operation.clone(),
            FeeBid::default(),
        )
        .expect("alternate-chain transaction signs");
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&other_chain, &config),
            Err(ChainError::TransactionChainIdMismatch)
        ));
        assert_eq!(state, before);

        let other_protocol = Transaction::for_operation_on_chain(
            &alice,
            ProtocolVersion::new(2),
            config.chain_id.clone(),
            0,
            operation,
            FeeBid::default(),
        )
        .expect("future-version transaction can be encoded");
        assert!(matches!(
            state.execute_transaction(&other_protocol, &config),
            Err(ChainError::UnsupportedProtocolVersion { actual })
                if actual == ProtocolVersion::new(2)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn unsupported_protocol_version_cannot_create_state() {
        let config = ChainConfig {
            protocol_version: ProtocolVersion::new(2),
            ..ChainConfig::default()
        };
        assert!(matches!(
            ChainState::new(&config),
            Err(ChainError::UnsupportedProtocolVersion { actual })
                if actual == ProtocolVersion::new(2)
        ));
    }

    #[test]
    fn bootstrap_validator_registration_is_rejected() {
        let (config, mut state, alice, _) = funded_state();
        let tx = Transaction::for_operation(
            &alice,
            0,
            Operation::RegisterValidator {
                consensus_key: alice.public_key(),
                self_stake: Amount::from_webc(20),
                commission_bps: 500,
                bootstrap: true,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::BootstrapDisabled)
        ));
        assert!(!state.validators.contains_key(&alice.address()));
    }

    #[test]
    fn slashing_evidence_replay_is_rejected() {
        let (config, mut state, alice, _) = funded_state();
        let register_validator = Transaction::for_operation(
            &alice,
            0,
            Operation::RegisterValidator {
                consensus_key: alice.public_key(),
                self_stake: Amount::from_webc(20),
                commission_bps: 500,
                bootstrap: false,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        state
            .execute_transaction(&register_validator, &config)
            .unwrap();

        let evidence = double_vote_evidence(
            &alice,
            config.chain_id.clone(),
            Hash256::digest(b"block-a"),
            Hash256::digest(b"block-b"),
        );
        let reversed = match evidence.clone() {
            SlashingEvidence::DoubleVote(pair) => {
                SlashingEvidence::DoubleVote(DoubleVoteEvidence {
                    first: pair.second,
                    second: pair.first,
                })
            }
        };
        let slash = Transaction::for_operation(
            &alice,
            1,
            Operation::SubmitSlashingEvidence {
                evidence: evidence.clone(),
            },
            FeeBid {
                gas_limit: 25_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        state.execute_transaction(&slash, &config).unwrap();

        let replay = Transaction::for_operation(
            &alice,
            2,
            Operation::SubmitSlashingEvidence { evidence: reversed },
            FeeBid {
                gas_limit: 25_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        assert!(matches!(
            state.execute_transaction(&replay, &config),
            Err(ChainError::SlashingReplay)
        ));
    }

    #[test]
    fn forged_and_cross_chain_slashing_evidence_rolls_back() {
        let (config, mut state, alice, bob) = funded_state();
        let register_validator = Transaction::for_operation(
            &alice,
            0,
            Operation::RegisterValidator {
                consensus_key: alice.public_key(),
                self_stake: Amount::from_webc(20),
                commission_bps: 500,
                bootstrap: false,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("registration signs");
        state
            .execute_transaction(&register_validator, &config)
            .expect("registration succeeds");

        let forged = double_vote_evidence(
            &bob,
            config.chain_id.clone(),
            Hash256::digest(b"forged-a"),
            Hash256::digest(b"forged-b"),
        );
        let forged = match forged {
            SlashingEvidence::DoubleVote(mut pair) => {
                pair.first.payload.validator = alice.address();
                pair.second.payload.validator = alice.address();
                SlashingEvidence::DoubleVote(pair)
            }
        };
        let forged_tx = Transaction::for_operation(
            &alice,
            1,
            Operation::SubmitSlashingEvidence { evidence: forged },
            FeeBid {
                gas_limit: 25_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("submission signs");
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&forged_tx, &config),
            Err(ChainError::InvalidSlashingEvidence)
        ));
        assert_eq!(state, before);

        let wrong_chain = double_vote_evidence(
            &alice,
            ChainId::new("webc-other-1").expect("valid alternate chain ID"),
            Hash256::digest(b"other-a"),
            Hash256::digest(b"other-b"),
        );
        let wrong_chain_tx = Transaction::for_operation(
            &alice,
            1,
            Operation::SubmitSlashingEvidence {
                evidence: wrong_chain,
            },
            FeeBid {
                gas_limit: 25_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("submission signs");
        assert!(matches!(
            state.execute_transaction(&wrong_chain_tx, &config),
            Err(ChainError::InvalidSlashingEvidence)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn invalid_slashing_evidence_is_rejected() {
        let (config, mut state, alice, _) = funded_state();
        let register_validator = Transaction::for_operation(
            &alice,
            0,
            Operation::RegisterValidator {
                consensus_key: alice.public_key(),
                self_stake: Amount::from_webc(20),
                commission_bps: 500,
                bootstrap: false,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        state
            .execute_transaction(&register_validator, &config)
            .unwrap();

        let invalid = double_vote_evidence(
            &alice,
            config.chain_id.clone(),
            Hash256::digest(b"same-block"),
            Hash256::digest(b"same-block"),
        );
        let tx = Transaction::for_operation(
            &alice,
            1,
            Operation::SubmitSlashingEvidence { evidence: invalid },
            FeeBid {
                gas_limit: 25_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::InvalidSlashingEvidence)
        ));
    }

    #[test]
    fn slashing_reconciles_operator_delegator_and_supply_buckets() {
        let (config, mut state, alice, bob) = funded_state();
        let fund_bob = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(200),
            },
            FeeBid::default(),
        )
        .expect("funding transfer signs");
        state
            .execute_transaction(&fund_bob, &config)
            .expect("funding succeeds");
        let register = Transaction::for_operation(
            &alice,
            1,
            Operation::RegisterValidator {
                consensus_key: alice.public_key(),
                self_stake: Amount::from_webc(20),
                commission_bps: 500,
                bootstrap: false,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("registration signs");
        state
            .execute_transaction(&register, &config)
            .expect("registration succeeds");
        let delegate = Transaction::for_operation(
            &bob,
            0,
            Operation::Delegate {
                validator: alice.address(),
                amount: Amount::from_webc(80),
            },
            FeeBid {
                gas_limit: 15_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("delegation signs");
        state
            .execute_transaction(&delegate, &config)
            .expect("delegation succeeds");

        let evidence = double_vote_evidence(
            &alice,
            config.chain_id.clone(),
            Hash256::digest(b"slash-a"),
            Hash256::digest(b"slash-b"),
        );
        let mut slash = Transaction::for_operation(
            &alice,
            2,
            Operation::SubmitSlashingEvidence { evidence },
            FeeBid {
                gas_limit: 25_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("slash submission signs");
        slash
            .access_list
            .read_write
            .push(StateKey::delegation(bob.address(), alice.address()));
        slash
            .access_list
            .read_write
            .push(StateKey::account(bob.address()));
        slash.sign(&alice).expect("expanded access list signs");
        state
            .execute_transaction(&slash, &config)
            .expect("verified slash succeeds");

        let validator = state
            .validators
            .get(&alice.address())
            .expect("validator remains tombstoned");
        assert_eq!(validator.self_stake, Amount::from_webc(4));
        assert_eq!(validator.delegated_stake, Amount::from_webc(16));
        assert_eq!(
            state
                .accounts
                .get(&alice.address())
                .expect("operator")
                .staked,
            Amount::from_webc(4)
        );
        assert_eq!(
            state
                .accounts
                .get(&bob.address())
                .expect("delegator")
                .delegated,
            Amount::from_webc(16)
        );
        assert_eq!(
            state
                .delegations
                .get(&(bob.address(), alice.address()))
                .expect("position")
                .amount,
            Amount::from_webc(16)
        );
        assert_eq!(state.slashed_units, Amount::from_webc(80));
        assert!(
            state
                .supply_invariant_report()
                .expect("checked supply report")
                .balanced
        );
    }

    #[test]
    fn unbonding_request_preserves_snapshot_then_matures_and_claims() {
        let (config, mut state, alice, bob) = active_delegated_state();
        let request = Transaction::for_operation(
            &bob,
            1,
            Operation::Undelegate {
                validator: alice.address(),
                amount: Amount::from_webc(80),
            },
            FeeBid {
                gas_limit: 15_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("request signs");
        let receipt = state
            .execute_transaction(&request, &config)
            .expect("request succeeds");
        let request_id = receipt
            .events
            .iter()
            .find_map(|event| match event {
                Event::UnbondingRequested { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .expect("request event");

        assert_eq!(
            state
                .validators
                .get(&alice.address())
                .expect("validator")
                .delegated_stake,
            Amount::from_webc(80)
        );
        assert_eq!(
            state
                .accounts
                .get(&bob.address())
                .expect("delegator")
                .unbonding,
            Amount::ZERO
        );

        state
            .distribute_epoch_rewards(&config)
            .expect("epoch admission");
        assert_eq!(state.current_epoch, 1);
        assert_eq!(
            state
                .validators
                .get(&alice.address())
                .expect("validator")
                .delegated_stake,
            Amount::ZERO
        );
        assert_eq!(
            state
                .accounts
                .get(&bob.address())
                .expect("delegator")
                .unbonding,
            Amount::from_webc(80)
        );
        assert_eq!(
            state
                .validators
                .get(&alice.address())
                .expect("validator")
                .status,
            ValidatorStatus::Draining
        );

        assert!(
            state
                .delegations
                .get(&(bob.address(), alice.address()))
                .expect("position retained for rewards")
                .accumulated_rewards
                > Amount::ZERO
        );
        let reward_claim = Transaction::for_operation(
            &bob,
            2,
            Operation::ClaimDelegatorRewards {
                validator: alice.address(),
            },
            FeeBid {
                gas_limit: 10_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("reward claim signs");
        state
            .execute_transaction(&reward_claim, &config)
            .expect("earned rewards survive full exit admission");

        let early_claim = Transaction::for_operation(
            &bob,
            3,
            Operation::ClaimUnbonded {
                validator: alice.address(),
                request_id,
            },
            FeeBid {
                gas_limit: 15_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("claim signs");
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&early_claim, &config),
            Err(ChainError::UnbondingNotWithdrawable)
        ));
        assert_eq!(state, before);

        while state.current_epoch < 9 {
            state
                .distribute_epoch_rewards(&config)
                .expect("deterministic epoch advance");
        }
        state
            .execute_transaction(&early_claim, &config)
            .expect("mature claim succeeds");
        assert_eq!(
            state
                .accounts
                .get(&bob.address())
                .expect("delegator")
                .unbonding,
            Amount::ZERO
        );
        assert!(
            state
                .supply_invariant_report()
                .expect("supply report")
                .balanced
        );
    }

    #[test]
    fn cooling_principal_is_slashed_before_release() {
        let (config, mut state, alice, bob) = active_delegated_state();
        let request = Transaction::for_operation(
            &bob,
            1,
            Operation::Undelegate {
                validator: alice.address(),
                amount: Amount::from_webc(80),
            },
            FeeBid {
                gas_limit: 15_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("request signs");
        state
            .execute_transaction(&request, &config)
            .expect("request");
        state
            .distribute_epoch_rewards(&config)
            .expect("admit to cooldown");

        let evidence = double_vote_evidence(
            &alice,
            config.chain_id.clone(),
            Hash256::digest(b"cooling-slash-a"),
            Hash256::digest(b"cooling-slash-b"),
        );
        let mut slash = Transaction::for_operation(
            &alice,
            2,
            Operation::SubmitSlashingEvidence { evidence },
            FeeBid {
                gas_limit: 25_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("slash signs");
        slash
            .access_list
            .read_write
            .push(StateKey::account(bob.address()));
        slash.sign(&alice).expect("expanded slash signs");
        state
            .execute_transaction(&slash, &config)
            .expect("cooling slash");

        assert_eq!(
            state
                .accounts
                .get(&bob.address())
                .expect("delegator")
                .unbonding,
            Amount::from_webc(16)
        );
        assert_eq!(state.slashed_units, Amount::from_webc(80));
        assert!(
            state
                .supply_invariant_report()
                .expect("supply report")
                .balanced
        );
    }

    #[test]
    fn operator_exit_is_delayed_and_cannot_abandon_delegators() {
        let (config, mut delegated_state, delegated_operator, _) = active_delegated_state();
        let blocked = Transaction::for_operation(
            &delegated_operator,
            2,
            Operation::UnstakeValidator {
                amount: Amount::from_webc(20),
            },
            FeeBid {
                gas_limit: 15_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("operator request signs");
        let before = delegated_state.clone();
        assert!(matches!(
            delegated_state.execute_transaction(&blocked, &config),
            Err(ChainError::OperatorExitHasDelegations)
        ));
        assert_eq!(delegated_state, before);

        let (config, mut state, operator, prospective_delegator) = funded_state();
        let register = Transaction::for_operation(
            &operator,
            0,
            Operation::RegisterValidator {
                consensus_key: operator.public_key(),
                self_stake: Amount::from_webc(100),
                commission_bps: 500,
                bootstrap: false,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("registration signs");
        state
            .execute_transaction(&register, &config)
            .expect("operator-only pool activates");
        let current_epoch_snapshot = ValidatorSet::from_state(&state).expect("snapshot");
        let exit = Transaction::for_operation(
            &operator,
            1,
            Operation::UnstakeValidator {
                amount: Amount::from_webc(100),
            },
            FeeBid {
                gas_limit: 15_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("full exit signs");
        state
            .execute_transaction(&exit, &config)
            .expect("full exit queues");
        assert_eq!(
            ValidatorSet::from_state(&state).expect("same-epoch snapshot"),
            current_epoch_snapshot,
            "exit request must not change current-epoch voting power"
        );
        let fund_delegator = Transaction::for_operation(
            &operator,
            2,
            Operation::Transfer {
                to: prospective_delegator.address(),
                amount: Amount::from_webc(2),
            },
            FeeBid::default(),
        )
        .expect("funding signs");
        state
            .execute_transaction(&fund_delegator, &config)
            .expect("prospective delegator funded");
        let late_delegation = Transaction::for_operation(
            &prospective_delegator,
            0,
            Operation::Delegate {
                validator: operator.address(),
                amount: Amount::from_webc(1),
            },
            FeeBid {
                gas_limit: 15_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("late delegation signs");
        let before_late_delegation = state.clone();
        assert!(matches!(
            state.execute_transaction(&late_delegation, &config),
            Err(ChainError::DelegationRatioExceeded)
        ));
        assert_eq!(state, before_late_delegation);
        assert_eq!(
            state
                .validators
                .get(&operator.address())
                .expect("validator")
                .self_stake,
            Amount::from_webc(100)
        );
        state
            .distribute_epoch_rewards(&config)
            .expect("snapshot transition");
        assert_eq!(
            ValidatorSet::from_state(&state)
                .expect("next snapshot")
                .power_of(operator.address()),
            Amount::ZERO
        );
        assert_eq!(
            state
                .validators
                .get(&operator.address())
                .expect("validator")
                .status,
            ValidatorStatus::Draining
        );
        assert_eq!(
            state
                .accounts
                .get(&operator.address())
                .expect("operator")
                .unbonding,
            Amount::from_webc(100)
        );
        assert!(
            state
                .supply_invariant_report()
                .expect("supply report")
                .balanced
        );
    }

    #[test]
    fn non_default_lane_uses_independent_nonce_and_prepaid_fees() {
        let (config, mut state, validator, delegator) = active_delegated_state();
        let lane_id = AuthorizationLaneId::new(Hash256::digest(b"site-a-lane"));
        let open = Transaction::for_operation(
            &delegator,
            1,
            Operation::OpenAuthorizationLane {
                lane: lane_id,
                fee_deposit: Amount::from_webc(1),
            },
            FeeBid {
                gas_limit: 20_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("lane opening signs");
        state
            .execute_transaction(&open, &config)
            .expect("lane opens from default account");
        let default_nonce_after_open = state
            .accounts
            .get(&delegator.address())
            .expect("delegator")
            .nonce;
        assert_eq!(default_nonce_after_open, 2);

        let exit = Transaction::for_operation_in_lane(
            &delegator,
            lane_id,
            0,
            Operation::Undelegate {
                validator: validator.address(),
                amount: Amount::from_webc(1),
            },
            FeeBid {
                gas_limit: 20_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("lane transaction signs");
        state
            .execute_transaction(&exit, &config)
            .expect("lane pays its own fee and nonce");
        let lane = state
            .authorization_lanes
            .get(&(delegator.address(), lane_id))
            .expect("lane persists");
        assert_eq!(lane.next_nonce, Nonce::new(1));
        assert_eq!(
            lane.fee_balance,
            Amount::from_webc(1)
                .checked_sub(Amount::from_units(10_000))
                .expect("test fee fits")
        );
        assert_eq!(
            state
                .accounts
                .get(&delegator.address())
                .expect("delegator")
                .nonce,
            default_nonce_after_open
        );
        assert!(
            state
                .supply_invariant_report()
                .expect("lane report")
                .balanced
        );

        let replay_before = state.clone();
        assert!(matches!(
            state.execute_transaction(&exit, &config),
            Err(ChainError::NonceMismatch { .. })
        ));
        assert_eq!(state, replay_before);
    }

    #[test]
    fn owned_object_lifecycle_enforces_namespace_owner_version_and_size() {
        let (config, mut state, alice, bob) = funded_state();
        let lane_id = AuthorizationLaneId::new(Hash256::digest(b"object-site-lane"));
        let namespace = Hash256::digest(b"object-site");
        let object_id = ObjectId::new(Hash256::digest(b"object-1"));
        let open = Transaction::for_operation(
            &alice,
            0,
            Operation::OpenAuthorizationLane {
                lane: lane_id,
                fee_deposit: Amount::from_webc(1),
            },
            FeeBid {
                gas_limit: 20_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("object lane opens");
        state
            .execute_transaction(&open, &config)
            .expect("object lane funded");

        let create = Transaction::for_operation_in_lane(
            &alice,
            lane_id,
            0,
            Operation::CreateObject {
                object_id,
                namespace,
                data: b"v1".to_vec(),
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("create signs");
        state
            .execute_transaction(&create, &config)
            .expect("object created");
        assert_eq!(
            state.objects.get(&object_id).expect("object").version,
            ObjectVersion::INITIAL
        );

        let mutate = Transaction::for_operation_in_lane(
            &alice,
            lane_id,
            1,
            Operation::MutateObject {
                object_id,
                namespace,
                expected_version: ObjectVersion::INITIAL,
                data: b"v2".to_vec(),
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("mutation signs");
        state
            .execute_transaction(&mutate, &config)
            .expect("owned mutation succeeds");
        assert_eq!(
            state.objects.get(&object_id).expect("object").version,
            ObjectVersion::new(2)
        );

        let stale = Transaction::for_operation_in_lane(
            &alice,
            lane_id,
            2,
            Operation::MutateObject {
                object_id,
                namespace,
                expected_version: ObjectVersion::INITIAL,
                data: b"stale".to_vec(),
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("stale mutation signs");
        let before_stale = state.clone();
        assert!(matches!(
            state.execute_transaction(&stale, &config),
            Err(ChainError::ObjectVersionMismatch { .. })
        ));
        assert_eq!(state, before_stale);

        let transfer = Transaction::for_operation_in_lane(
            &alice,
            lane_id,
            2,
            Operation::TransferObject {
                object_id,
                namespace,
                expected_version: ObjectVersion::new(2),
                new_owner: bob.address(),
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("transfer signs");
        state
            .execute_transaction(&transfer, &config)
            .expect("owned transfer succeeds");
        let object = state.objects.get(&object_id).expect("object");
        assert_eq!(object.version, ObjectVersion::new(3));
        assert_eq!(object.owner, ObjectOwner::Address(bob.address()));

        let oversized_id = ObjectId::new(Hash256::digest(b"oversized"));
        let oversized = Transaction::for_operation_in_lane(
            &alice,
            lane_id,
            3,
            Operation::CreateObject {
                object_id: oversized_id,
                namespace,
                data: vec![0u8; crate::MAX_OBJECT_DATA_BYTES + 1],
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("oversized object signs");
        let before_oversized = state.clone();
        assert!(matches!(
            state.execute_transaction(&oversized, &config),
            Err(ChainError::ObjectDataTooLarge { .. })
        ));
        assert_eq!(state, before_oversized);
        assert!(
            state
                .supply_invariant_report()
                .expect("object report")
                .balanced
        );
    }

    #[test]
    fn delegated_rewards_can_be_claimed_by_delegator() {
        let (config, mut state, alice, bob) = funded_state();

        let fund_bob = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(200),
            },
            FeeBid::default(),
        )
        .unwrap();
        state.execute_transaction(&fund_bob, &config).unwrap();

        let register_validator = Transaction::for_operation(
            &alice,
            1,
            Operation::RegisterValidator {
                consensus_key: PublicKeyBytes([9u8; 32]),
                self_stake: Amount::from_webc(20),
                commission_bps: 500,
                bootstrap: false,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        state
            .execute_transaction(&register_validator, &config)
            .unwrap();

        let delegate = Transaction::for_operation(
            &bob,
            0,
            Operation::Delegate {
                validator: alice.address(),
                amount: Amount::from_webc(80),
            },
            FeeBid {
                gas_limit: 15_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        state.execute_transaction(&delegate, &config).unwrap();
        assert!(state
            .validators
            .get(&alice.address())
            .expect("registered validator")
            .is_active());

        state.distribute_epoch_rewards(&config).unwrap();
        let delegation = state
            .delegations
            .get(&(bob.address(), alice.address()))
            .unwrap();
        assert!(delegation.accumulated_rewards > Amount::ZERO);
        assert!(
            state
                .validators
                .get(&alice.address())
                .unwrap()
                .accumulated_rewards
                > Amount::ZERO
        );

        let balance_before_claim = state.accounts.get(&bob.address()).unwrap().balance;
        let claim = Transaction::for_operation(
            &bob,
            1,
            Operation::ClaimDelegatorRewards {
                validator: alice.address(),
            },
            FeeBid {
                gas_limit: 10_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        state.execute_transaction(&claim, &config).unwrap();
        assert!(state.accounts.get(&bob.address()).unwrap().balance > balance_before_claim);
        assert_eq!(
            state
                .delegations
                .get(&(bob.address(), alice.address()))
                .unwrap()
                .accumulated_rewards,
            Amount::ZERO
        );
    }

    #[test]
    fn delegation_above_eighty_percent_is_rejected_atomically() {
        let (config, mut state, alice, bob) = funded_state();
        let fund_bob = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(100),
            },
            FeeBid::default(),
        )
        .expect("valid funding transaction");
        state
            .execute_transaction(&fund_bob, &config)
            .expect("funding succeeds");
        let register = Transaction::for_operation(
            &alice,
            1,
            Operation::RegisterValidator {
                consensus_key: PublicKeyBytes([9u8; 32]),
                self_stake: Amount::from_webc(20),
                commission_bps: 500,
                bootstrap: false,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("valid registration transaction");
        state
            .execute_transaction(&register, &config)
            .expect("registration succeeds");
        let before = state.clone();
        let excessive = Transaction::for_operation(
            &bob,
            0,
            Operation::Delegate {
                validator: alice.address(),
                amount: Amount::from_webc(81),
            },
            FeeBid {
                gas_limit: 15_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("signed delegation transaction");

        assert!(matches!(
            state.execute_transaction(&excessive, &config),
            Err(ChainError::DelegationRatioExceeded)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn account_state_proof_verifies_and_rejects_tampering() {
        let (config, mut state, alice, bob) = funded_state();
        let tx = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(10),
            },
            FeeBid::default(),
        )
        .unwrap();
        state.execute_transaction(&tx, &config).unwrap();

        let proof = state.account_state_proof(bob.address()).unwrap().unwrap();
        assert!(proof.verify().unwrap());

        let mut tampered = proof.clone();
        tampered.account.balance = Amount::from_units(1);
        assert!(!tampered.verify().unwrap());
    }

    #[test]
    fn unauthorized_bridge_relayer_is_rejected() {
        let (config, mut state, alice, bob) = funded_state();
        let message = BridgeMessage {
            source_chain: ExternalChain::Ethereum,
            destination_chain: ExternalChain::Webc,
            nonce: 99,
            asset: AssetId::WrappedWebc {
                origin_chain: ExternalChain::Webc,
            },
            sender: vec![1u8; 20],
            recipient: bob.address().as_bytes().to_vec(),
            amount: Amount::from_webc(5),
            source_tx: Hash256::digest(b"eth-lock-unauthorized"),
        };
        let tx = Transaction::for_operation(
            &alice,
            0,
            Operation::BridgeMint { message },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::UnauthorizedBridgeRelayer)
        ));
    }

    #[test]
    fn bridge_message_replay_is_rejected() {
        let (mut config, mut state, alice, bob) = funded_state();
        config.bridge.incoming_messages_enabled = true;
        config.bridge.trusted_relayers.push(alice.address());
        let message = BridgeMessage {
            source_chain: ExternalChain::Ethereum,
            destination_chain: ExternalChain::Webc,
            nonce: 1,
            asset: AssetId::External {
                origin_chain: ExternalChain::Ethereum,
                symbol: "MOCK".to_owned(),
                contract_or_mint: "0xmock".to_owned(),
            },
            sender: vec![1u8; 20],
            recipient: bob.address().as_bytes().to_vec(),
            amount: Amount::from_webc(5),
            source_tx: Hash256::digest(b"eth-lock"),
        };
        let tx = Transaction::for_operation(
            &alice,
            0,
            Operation::BridgeMint {
                message: message.clone(),
            },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        state.execute_transaction(&tx, &config).unwrap();

        let replay = Transaction::for_operation(
            &alice,
            1,
            Operation::BridgeMint { message },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        assert!(matches!(
            state.execute_transaction(&replay, &config),
            Err(ChainError::BridgeReplay)
        ));
    }

    #[test]
    fn native_bridge_escrow_reconciles_lock_release_and_domain_limits() {
        let (mut config, mut state, alice, bob) = funded_state();
        config.bridge.incoming_messages_enabled = true;
        config.bridge.trusted_relayers.push(alice.address());

        let zero_lock = Transaction::for_operation(
            &alice,
            0,
            Operation::BridgeLock {
                asset: AssetId::NativeWebc,
                destination_chain: ExternalChain::Ethereum,
                recipient: vec![0x10; 20],
                amount: Amount::ZERO,
            },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("zero lock signs");
        let before_zero = state.clone();
        assert!(matches!(
            state.execute_transaction(&zero_lock, &config),
            Err(ChainError::BridgeAmountZero)
        ));
        assert_eq!(state, before_zero);

        let lock = Transaction::for_operation(
            &alice,
            0,
            Operation::BridgeLock {
                asset: AssetId::NativeWebc,
                destination_chain: ExternalChain::Ethereum,
                recipient: vec![0x11; 20],
                amount: Amount::from_webc(10),
            },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("lock signs");
        state
            .execute_transaction(&lock, &config)
            .expect("native lock enters escrow");
        assert_eq!(
            state.native_bridge_escrow.get(&ExternalChain::Ethereum),
            Some(&Amount::from_webc(10))
        );
        let locked_report = state.supply_invariant_report().expect("lock report");
        assert_eq!(locked_report.escrowed, Amount::from_webc(10));
        assert!(locked_report.balanced);

        let over_release_message = BridgeMessage {
            source_chain: ExternalChain::Ethereum,
            destination_chain: ExternalChain::Webc,
            nonce: 1,
            asset: AssetId::NativeWebc,
            sender: vec![0x21; 20],
            recipient: bob.address().as_bytes().to_vec(),
            amount: Amount::from_webc(11),
            source_tx: Hash256::digest(b"ethereum-over-release"),
        };
        let over_release = Transaction::for_operation(
            &alice,
            1,
            Operation::BridgeRelease {
                message: over_release_message,
            },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("over-release signs");
        let before_over_release = state.clone();
        assert!(matches!(
            state.execute_transaction(&over_release, &config),
            Err(ChainError::InsufficientBridgeEscrow { .. })
        ));
        assert_eq!(state, before_over_release);

        let wrong_domain = BridgeMessage {
            source_chain: ExternalChain::Solana,
            destination_chain: ExternalChain::Webc,
            nonce: 1,
            asset: AssetId::NativeWebc,
            sender: vec![0x22; 32],
            recipient: bob.address().as_bytes().to_vec(),
            amount: Amount::from_webc(1),
            source_tx: Hash256::digest(b"solana-burn-without-solana-escrow"),
        };
        let wrong_release = Transaction::for_operation(
            &alice,
            1,
            Operation::BridgeRelease {
                message: wrong_domain,
            },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("wrong-domain release signs");
        let before_wrong_domain = state.clone();
        assert!(matches!(
            state.execute_transaction(&wrong_release, &config),
            Err(ChainError::InsufficientBridgeEscrow { .. })
        ));
        assert_eq!(state, before_wrong_domain);

        let release_message = BridgeMessage {
            source_chain: ExternalChain::Ethereum,
            destination_chain: ExternalChain::Webc,
            nonce: 2,
            asset: AssetId::NativeWebc,
            sender: vec![0x33; 20],
            recipient: bob.address().as_bytes().to_vec(),
            amount: Amount::from_webc(7),
            source_tx: Hash256::digest(b"ethereum-wrapped-webc-burn"),
        };
        let release = Transaction::for_operation(
            &alice,
            1,
            Operation::BridgeRelease {
                message: release_message,
            },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("release signs");
        state
            .execute_transaction(&release, &config)
            .expect("same-domain escrow release");
        assert_eq!(
            state.native_bridge_escrow.get(&ExternalChain::Ethereum),
            Some(&Amount::from_webc(3))
        );
        assert_eq!(
            state
                .accounts
                .get(&bob.address())
                .expect("recipient")
                .balance,
            Amount::from_webc(7)
        );
        let released_report = state.supply_invariant_report().expect("release report");
        assert_eq!(released_report.escrowed, Amount::from_webc(3));
        assert!(released_report.balanced);
    }

    #[test]
    fn external_asset_mint_preserves_native_supply_and_rejects_native_mint() {
        let (mut config, mut state, alice, bob) = funded_state();
        config.bridge.incoming_messages_enabled = true;
        config.bridge.trusted_relayers.push(alice.address());
        let external_asset = AssetId::External {
            origin_chain: ExternalChain::Ethereum,
            symbol: "MOCK".to_owned(),
            contract_or_mint: "0xmock".to_owned(),
        };
        let external_message = BridgeMessage {
            source_chain: ExternalChain::Ethereum,
            destination_chain: ExternalChain::Webc,
            nonce: 1,
            asset: external_asset.clone(),
            sender: vec![0x44; 20],
            recipient: bob.address().as_bytes().to_vec(),
            amount: Amount::from_webc(5),
            source_tx: Hash256::digest(b"external-mock-lock"),
        };
        let mint = Transaction::for_operation(
            &alice,
            0,
            Operation::BridgeMint {
                message: external_message,
            },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("mint signs");
        state
            .execute_transaction(&mint, &config)
            .expect("external representation mints");
        assert_eq!(
            state.asset_balances.get(&(external_asset, bob.address())),
            Some(&Amount::from_webc(5))
        );
        assert!(
            state
                .supply_invariant_report()
                .expect("mint report")
                .balanced
        );

        let invalid_native_mint = BridgeMessage {
            source_chain: ExternalChain::Ethereum,
            destination_chain: ExternalChain::Webc,
            nonce: 2,
            asset: AssetId::NativeWebc,
            sender: vec![0x55; 20],
            recipient: bob.address().as_bytes().to_vec(),
            amount: Amount::from_webc(1),
            source_tx: Hash256::digest(b"invalid-native-mint"),
        };
        let invalid = Transaction::for_operation(
            &alice,
            1,
            Operation::BridgeMint {
                message: invalid_native_mint,
            },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("invalid native mint signs");
        let before_invalid = state.clone();
        assert!(matches!(
            state.execute_transaction(&invalid, &config),
            Err(ChainError::InvalidBridgeAssetFlow)
        ));
        assert_eq!(state, before_invalid);
    }
}
