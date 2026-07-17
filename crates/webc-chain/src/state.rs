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
use crate::authorization_policy::{
    active_key_rotation_message, post_quantum_root_rotation_message, AccountAuthorizationPolicy,
};
use crate::bridge::{AssetId, BridgeConfig, BridgeEvent, BridgeMessage, ExternalChain};
use crate::fees::{next_base_fee, split_fee, FeeBreakdown, FeePolicy, StoragePricing};
use crate::genesis::GenesisConfig;
use crate::object::{validate_object_data, ObjectOwner, StateObject};
use crate::session_key::{
    session_key_authorization_message, SessionAllowedOperations, SessionKey,
    SessionKeyAuthorizationAction, SessionKeyConfig, SessionKeyId,
};
use crate::slashing::{
    slash_validator_with_delegation_loss, slashing_bps, SlashingOutcome, SlashingPolicy,
};
use crate::sponsorship::{
    sponsor_state_key_hash, AppSponsor, SponsorshipConfig, SPONSOR_LEAF_DOMAIN,
};
use crate::staking::{Delegation, StakingConfig, Validator, ValidatorStatus};
use crate::state_key::StateAccessRecorder;
use crate::transaction::{Operation, Transaction};
use crate::unbonding::{UnbondingKind, UnbondingQueue, UnbondingRequestId, UnbondingTransition};
use crate::{
    Amount, AuthorizationLaneId, BootstrapIssuance, ChainError, ChainId, Epoch,
    InactivityLeakConfig, InflationSchedule, ObjectId, ObjectVersion, ProtocolStateKey,
    ProtocolVersion, SlashingEvidence, StateKey, CURRENT_PROTOCOL_VERSION,
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
    /// Occupancy-priced storage deposit + deletion rebate policy (§15.22).
    ///
    /// `#[serde(default)]` keeps a genesis written before storage pricing
    /// decodable; the default locks a cheap refundable deposit per object byte
    /// and refunds 90% on delete (burning 10% as the occupancy fee).
    #[serde(default)]
    pub storage_pricing: StoragePricing,
    /// Hard, deterministic caps for application fee sponsorship (§15.35).
    ///
    /// `#[serde(default)]` keeps a genesis written before sponsorship decodable;
    /// the launch values are measurement-tuned placeholders (per-user /
    /// per-operation / per-app-per-day bounds, simple operations only).
    #[serde(default)]
    pub sponsorship: SponsorshipConfig,
    /// Constrained session-key lifetime and per-account count limits.
    #[serde(default)]
    pub session_keys: SessionKeyConfig,
    /// Total native supply, in base units, that the genesis allocation must sum
    /// to. `Some` on production genesis — mainnet and devnet both pin
    /// [`GENESIS_TOTAL_SUPPLY`] — so `ChainState::from_genesis` rejects any
    /// allocation whose minted supply differs (finding G1; the supply invariant
    /// on its own is tautological and never pins the total). `None` skips the
    /// check for trusted in-crate test fixtures that use small allocations.
    ///
    /// [`GENESIS_TOTAL_SUPPLY`]: crate::GENESIS_TOTAL_SUPPLY
    #[serde(default)]
    pub expected_total_supply: Option<Amount>,
    /// Opt-in bootstrap-phase issuance (§15.2). `None` (default) uses only the
    /// base [`InflationSchedule`]; `Some` keys issuance to staked amount, capped
    /// by the base per-period budget, until [`BootstrapIssuance::sunset_epoch`].
    #[serde(default)]
    pub bootstrap_issuance: Option<BootstrapIssuance>,
    /// Opt-in inactivity leak (ADR-0012). `None` (default) keeps vanilla
    /// Tendermint liveness (halt on >1/3 offline) plus the ADR-0011 restart
    /// fallback; `Some` will drain offline validator weight to recover finality
    /// once the recovery-mode consensus design is confirmed and wired.
    #[serde(default)]
    pub inactivity_leak: Option<InactivityLeakConfig>,
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
            storage_pricing: StoragePricing::default(),
            sponsorship: SponsorshipConfig::default(),
            session_keys: SessionKeyConfig::default(),
            expected_total_supply: None,
            bootstrap_issuance: None,
            inactivity_leak: None,
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
    /// An application sponsor's budget covered a transaction's fee (§15.35).
    FeeSponsored {
        /// Application namespace whose sponsor budget paid the fee.
        application: Hash256,
        /// User whose transaction fee was sponsored.
        beneficiary: Address,
        /// The burn + validator-reward split drawn from the sponsor budget.
        breakdown: FeeBreakdown,
    },
    /// A new application fee sponsor was registered and initially funded (§15.35).
    AppSponsorRegistered {
        /// Application namespace this sponsor underwrites.
        application: Hash256,
        /// Account that controls (funds/withdraws) the sponsor.
        owner: Address,
        /// App-chosen per-day-window sponsored-fee spend cap.
        daily_budget_cap: Amount,
        /// Native base units moved into the budget at registration.
        funded: Amount,
    },
    /// An application fee sponsor's budget was topped up (§15.35).
    AppSponsorFunded {
        /// Application namespace whose budget grew.
        application: Hash256,
        /// Native base units added to the budget.
        amount: Amount,
    },
    /// Unspent budget was withdrawn from an application fee sponsor (§15.35).
    AppSponsorWithdrawn {
        /// Application namespace whose budget shrank.
        application: Hash256,
        /// Native base units returned to the owner's liquid balance.
        amount: Amount,
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
    ValidatorRewardsCompounded {
        validator: Address,
        amount: Amount,
    },
    DelegatorRewardsCompounded {
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
    SessionKeyInstalled {
        /// Account that owns the new session key.
        owner: Address,
        /// Opaque session-key identity.
        session_key: SessionKeyId,
        /// Absolute last epoch the key may be used.
        expires_after_epoch: Epoch,
    },
    SessionKeyRevoked {
        /// Account whose session key was removed.
        owner: Address,
        /// Opaque identity of the revoked session key.
        session_key: SessionKeyId,
    },
    SessionKeyExpired {
        /// Account whose session key was pruned at an epoch boundary.
        owner: Address,
        /// Opaque identity of the expired session key.
        session_key: SessionKeyId,
    },
    ActiveTransactionKeyRotated {
        /// Account whose active transaction key was replaced.
        owner: Address,
        /// Revision after rotation; every prior-revision session key is now dead.
        new_revision: crate::AuthorizationPolicyRevision,
        /// New Ed25519 key now authorizing ordinary transactions.
        new_active_transaction_key: webc_crypto::PublicKeyBytes,
    },
    PostQuantumRootRotated {
        /// Account whose post-quantum recovery root was replaced.
        owner: Address,
        /// Revision after rotation; every prior-revision session key is now dead.
        new_revision: crate::AuthorizationPolicyRevision,
        /// New committed recovery root now required for critical actions.
        new_post_quantum_root: crate::PostQuantumRoot,
    },
    SessionKeyUsed {
        /// Account that owns the session key.
        owner: Address,
        /// Opaque identity of the session key that authorized the transaction.
        session_key: SessionKeyId,
        /// Native principal moved under this use.
        amount: Amount,
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
    ObjectDeleted {
        object_id: ObjectId,
        /// Object owner who authorized the deletion and received the refund.
        owner: Address,
        /// Native base units returned to the owner's liquid balance.
        refund: Amount,
        /// Native base units burned as the storage occupancy fee.
        burned: Amount,
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
    /// Constrained session keys delegated under each account's policy.
    ///
    /// Keyed by owner and opaque session-key id. Records hold constraints and
    /// cumulative spend, never funds, so they do not enter supply reconciliation.
    #[serde(default)]
    pub session_keys: BTreeMap<(Address, SessionKeyId), SessionKey>,
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
    /// Refundable native units locked as object storage deposits (§15.22).
    ///
    /// Total of every live object's recorded `deposit`. `CreateObject` moves
    /// units here from the creator's liquid balance; `MutateObject` resizes the
    /// lock; `DeleteObject` moves them out as an owner refund plus a burned
    /// occupancy remainder. Reconciled by [`SupplyInvariantReport`] like the
    /// other locked buckets, and committed by the state root as a scalar.
    #[serde(default)]
    pub storage_deposits: Amount,
    /// Registered application fee sponsors, keyed by application namespace (§15.35).
    ///
    /// Each [`AppSponsor`] holds a pre-funded budget and the hard per-user /
    /// per-app-per-day counters. Committed by the state root through a dedicated
    /// Merkle sub-root (`SPONSOR_LEAF_DOMAIN`), so any change to a sponsor's
    /// budget or counters changes the state root. A `BTreeMap` keeps iteration
    /// deterministic in the hashed/consensus path.
    #[serde(default)]
    pub sponsors: BTreeMap<Hash256, AppSponsor>,
    /// Refundable native units locked across every application sponsor budget (§15.35).
    ///
    /// Sum of every live [`AppSponsor::budget`]. Registering/funding a sponsor
    /// moves units here from the owner's liquid balance; a sponsored fee moves
    /// them out as the same burn + validator-reward split a normal fee uses;
    /// withdrawing moves them back to the owner. Reconciled by
    /// [`SupplyInvariantReport`] as a locked bucket and committed by the state
    /// root as a scalar (mirroring `storage_deposits`).
    #[serde(default)]
    pub sponsor_budgets: Amount,
    pub validator_fee_pool: Amount,
    pub minted_supply: Amount,
    /// Gross issued supply captured at the start of the current inflation year.
    pub inflation_year_start_supply: Amount,
    pub current_base_fee_per_unit: u64,
    pub current_epoch: u64,
    pub bridge_nonce: u64,
    /// Consensus timestamp (Unix ms) of the most recently applied block.
    ///
    /// E2: block timestamps must strictly increase. `build_block` rejects a
    /// candidate whose `timestamp_ms` is not greater than this, so a proposer
    /// cannot rewind or freeze consensus time (which future epoch/expiry/fee
    /// logic may read). Genesis leaves it `0`, so the first block's timestamp
    /// only has to be positive.
    #[serde(default)]
    pub last_block_timestamp_ms: u64,
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
    /// Refundable native units locked as object storage deposits (§15.22).
    pub storage_deposits: Amount,
    /// Native units locked across every application fee-sponsor budget (§15.35).
    pub sponsor_budgets: Amount,
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

/// Which account authority approved a verified transaction.
///
/// Returned by `verify_transaction_authorization` and consumed by execution so
/// session-key constraint enforcement runs only for session-signed transactions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransactionAuthorization {
    /// The account's active transaction key, or its legacy address-derived key.
    AccountKey,
    /// A registered constrained session key, identified for constraint checks.
    SessionKey(SessionKeyId),
    /// A recovery/rotation transaction whose envelope is signed by the *new*
    /// active key. Its real authority is the post-quantum root signature, which
    /// the `RotateActiveTransactionKey` arm verifies before mutating the policy.
    /// Produced only for that operation and only when the signing key equals the
    /// proposed new key, so a stranger's key can never take this path.
    PostQuantumRootRecovery,
}

impl Default for ChainState {
    fn default() -> Self {
        Self {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            accounts: BTreeMap::new(),
            authorization_policies: BTreeMap::new(),
            authorization_lanes: BTreeMap::new(),
            session_keys: BTreeMap::new(),
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
            storage_deposits: Amount::ZERO,
            sponsors: BTreeMap::new(),
            sponsor_budgets: Amount::ZERO,
            validator_fee_pool: Amount::ZERO,
            minted_supply: Amount::ZERO,
            inflation_year_start_supply: Amount::ZERO,
            current_base_fee_per_unit: 0,
            current_epoch: 0,
            bridge_nonce: 0,
            last_block_timestamp_ms: 0,
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
        // Reject a malformed sponsorship window (zero epochs) before any state
        // exists, so a chain never runs with an undefined "per day" boundary.
        genesis.chain.sponsorship.validate()?;

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

        // G1: pin the declared total supply. `minted_supply` is the checked sum
        // of all genesis account balances; staking only relocates units between
        // an account's liquid and staked buckets and never changes gross
        // issuance, so this is the single place a wrong-total genesis is caught.
        // The `balanced` invariant below cannot catch it because it is
        // tautological (it re-sums the very buckets `minted_supply` was defined
        // from). Production genesis sets `Some(GENESIS_TOTAL_SUPPLY)`; trusted
        // in-crate fixtures leave it `None`.
        if let Some(expected) = genesis.chain.expected_total_supply {
            if state.minted_supply != expected {
                return Err(ChainError::GenesisSupplyMismatch {
                    expected,
                    actual: state.minted_supply,
                });
            }
        }

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
            .and_then(|amount| amount.checked_add(self.storage_deposits))
            .and_then(|amount| amount.checked_add(self.sponsor_budgets))
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
            storage_deposits: self.storage_deposits,
            sponsor_budgets: self.sponsor_budgets,
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
        let authorization = self.verify_transaction_authorization(tx)?;
        let tx_hash = tx.hash()?;
        let mut next = self.clone();
        let receipt = next.apply_verified_transaction(tx, config, tx_hash, authorization)?;
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
    fn verify_transaction_authorization(
        &self,
        tx: &Transaction,
    ) -> Result<TransactionAuthorization, ChainError> {
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
            return Ok(TransactionAuthorization::AccountKey);
        };

        policy.validate()?;
        if tx.authorization_policy_revision != policy.revision() {
            return Err(ChainError::AuthorizationPolicyRevisionMismatch {
                expected: policy.revision().get(),
                actual: tx.authorization_policy_revision.get(),
            });
        }
        if &tx.public_key == policy.active_transaction_key() {
            return Ok(TransactionAuthorization::AccountKey);
        }

        // Recovery/rotation may be signed by the *new* key so a lost or
        // compromised active key can still be replaced. The envelope signature
        // only proves control of the proposed new key here; the real authority
        // is the post-quantum root signature verified in the rotation arm. Any
        // other signer for this operation is rejected, and this path is reachable
        // for no other operation.
        if let Operation::RotateActiveTransactionKey {
            new_active_transaction_key,
            ..
        } = &tx.operation
        {
            if &tx.public_key == new_active_transaction_key {
                return Ok(TransactionAuthorization::PostQuantumRootRecovery);
            }
            return Err(ChainError::AuthorizationKeyMismatch);
        }

        // The active key did not sign. The only other acceptable signer is a
        // registered, policy-current, lane-bound session key. Expiry and spend
        // limits are enforced in execution, where the operation and epoch are in
        // hand and rollback is atomic; here we only bind the key to the account.
        let id = SessionKeyId::derive(&tx.public_key);
        let Some(session) = self.session_keys.get(&(tx.sender, id)) else {
            return Err(ChainError::AuthorizationKeyMismatch);
        };
        if session.session_public_key != tx.public_key
            || session.policy_revision != policy.revision()
        {
            return Err(ChainError::AuthorizationKeyMismatch);
        }
        if tx.authorization_lane != session.constraints.authorization_lane {
            return Err(ChainError::SessionKeyLaneMismatch);
        }
        Ok(TransactionAuthorization::SessionKey(id))
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

        // Total active stake is needed both for reward weighting and to size the
        // stake-keyed bootstrap budget, so it is computed before the issuance.
        let total_active_stake = self
            .validators
            .values()
            .filter(|validator| validator.is_active())
            .try_fold(Amount::ZERO, |sum, validator| {
                sum.checked_add(validator.total_stake()?)
                    .ok_or(ChainError::ArithmeticOverflow)
            })?;

        // Base schedule budget for this period. During a configured, not-yet-sunset
        // bootstrap phase (§15.2), issuance is instead keyed to staked amount and
        // capped by this base budget, so a thin early staking base cannot capture
        // the full base issuance. Supply conservation is unaffected: whatever the
        // issued `inflation` is, `minted_supply` grows by exactly it and the F1
        // distribution accounts for exactly it (see below).
        let base_budget = config
            .inflation
            .reward_for_period(self.inflation_year_start_supply, self.current_epoch)?;
        let inflation = match &config.bootstrap_issuance {
            Some(bootstrap) if bootstrap.is_active(self.current_epoch) => {
                bootstrap.budget_for_period(total_active_stake, periods_per_year, base_budget)?
            }
            _ => base_budget,
        };
        let total_reward = inflation
            .checked_add(self.validator_fee_pool)
            .ok_or(ChainError::ArithmeticOverflow)?;

        if total_reward.is_zero() {
            return self.finish_epoch(config, Amount::ZERO);
        }

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

        // F1: sum every validator's floored share so the outer cross-validator
        // remainder can be carried forward instead of dropped (see below).
        let mut distributed_total = Amount::ZERO;
        for (validator_address, validator_total_stake, self_stake, commission_bps) in
            active_validators
        {
            let validator_share = total_reward
                .checked_mul_ratio(validator_total_stake.0, total_active_stake.0)
                .ok_or(ChainError::ArithmeticOverflow)?;
            distributed_total = distributed_total
                .checked_add(validator_share)
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
        // F1: retain the outer division remainder (total_reward minus the sum of
        // the floored per-validator shares) in the fee pool, carrying it to the
        // next epoch. Each validator's share is fully distributed internally (its
        // inner dust is recaptured to the validator), but the SUM of floored
        // shares is <= total_reward; the difference is 0..num_validators-1 base
        // units. Zeroing the pool while minting the full inflation would destroy
        // those units and break supply conservation (accounted < minted_supply)
        // by that amount every epoch. Carrying it keeps
        // accounted_new == minted_old + inflation == minted_new.
        let outer_leftover = total_reward
            .checked_sub(distributed_total)
            .ok_or(ChainError::ArithmeticOverflow)?;
        self.validator_fee_pool = outer_leftover;
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

        // Epoch-boundary pruning of expired session keys. A key is usable while
        // `current_epoch <= expires_after_epoch`; once the epoch passes it, the
        // key can never authorize again (epochs only ever increase), so removing
        // it is safe. The use-time check already rejects expired keys, so this
        // changes no authorization outcome — it only reclaims space and bounds
        // session-key map growth. It is deterministic: `next_epoch` is committed
        // state, iteration is sorted, and it is a pure function of the snapshot,
        // so replaying from a serialized state prunes identically.
        let expired: Vec<(Address, SessionKeyId)> = self
            .session_keys
            .iter()
            .filter(|(_, session)| session.expires_after_epoch.get() < next_epoch)
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            self.session_keys.remove(&key);
            events.push(Event::SessionKeyExpired {
                owner: key.0,
                session_key: key.1,
            });
        }

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
            session_key_root: Hash256,
            object_root: Hash256,
            validator_root: Hash256,
            delegation_root: Hash256,
            asset_root: Hash256,
            native_bridge_escrow_root: Hash256,
            processed_bridge_root: Hash256,
            processed_slashing_root: Hash256,
            unbonding_root: Hash256,
            sponsor_root: Hash256,
            burned_fees: Amount,
            slashed_units: Amount,
            storage_deposits: Amount,
            sponsor_budgets: Amount,
            validator_fee_pool: Amount,
            minted_supply: Amount,
            inflation_year_start_supply: Amount,
            current_base_fee_per_unit: u64,
            current_epoch: u64,
            bridge_nonce: u64,
            last_block_timestamp_ms: u64,
        }

        let commitment = StateCommitment {
            // V9 adds the fee-sponsorship state (§15.35): the `sponsor_root`
            // sub-root commits every per-app sponsor record (budget, caps, and
            // per-user/day counters), and the `sponsor_budgets` scalar commits the
            // aggregate locked bucket (mirroring how `storage_deposits` pairs with
            // the object sub-root). The domain bump is a deliberate consensus-format
            // change; no external fixture pins the prior V8 root. V8 added the
            // `storage_deposits` scalar (§15.22); V7 added `last_block_timestamp_ms`
            // (finding E2).
            domain: "WEBC_STATE_COMMITMENT_V9",
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
            session_key_root: ordered_value_root(
                b"WEBC_SESSION_KEY_LEAF_V1",
                self.session_keys.iter(),
            )?,
            // V2: the object leaf now includes the recorded storage deposit
            // (§15.22), so a resize/refund changes the object sub-root.
            object_root: ordered_value_root(b"WEBC_OBJECT_LEAF_V2", self.objects.iter())?,
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
            // Per-map bucket committed by its own ordered sub-root (§15.35): a
            // change to any sponsor's budget, caps, or per-user/day counters
            // changes this root and therefore the state root.
            sponsor_root: ordered_value_root(SPONSOR_LEAF_DOMAIN, self.sponsors.iter())?,
            burned_fees: self.burned_fees,
            slashed_units: self.slashed_units,
            storage_deposits: self.storage_deposits,
            sponsor_budgets: self.sponsor_budgets,
            validator_fee_pool: self.validator_fee_pool,
            minted_supply: self.minted_supply,
            inflation_year_start_supply: self.inflation_year_start_supply,
            current_base_fee_per_unit: self.current_base_fee_per_unit,
            current_epoch: self.current_epoch,
            bridge_nonce: self.bridge_nonce,
            last_block_timestamp_ms: self.last_block_timestamp_ms,
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
        authorization: TransactionAuthorization,
    ) -> Result<Receipt, ChainError> {
        // Fee sponsorship is a default-lane-only feature (a prepaid lane already
        // funds its own fees). Reject a sponsor named on a non-default lane up
        // front — before any lane/nonce lookup — so the combination fails fast
        // with a precise error regardless of whether the named lane exists.
        if tx.sponsor.is_some() && !tx.authorization_lane.is_default() {
            return Err(ChainError::SponsorshipRequiresDefaultLane);
        }
        let mut access =
            StateAccessRecorder::new(&tx.access_list.read_only, &tx.access_list.read_write)?;
        // Authorization policy is consensus state even though it is consulted
        // before mutation. Ordinary transactions read it; first installation
        // writes the same key and therefore conflicts with concurrent spends.
        if matches!(
            &tx.operation,
            Operation::InstallAuthorizationPolicy { .. }
                | Operation::RotateActiveTransactionKey { .. }
                | Operation::RotatePostQuantumRoot { .. }
        ) {
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

        // Choose the fee source. On the default lane a transaction may opt into
        // application fee sponsorship (§15.35): when it names a sponsor, the
        // operation is sponsorable, and the app's hard per-user / per-operation /
        // per-app-per-day caps and funded budget permit it, the fee is drawn from
        // the app's sponsor budget instead of the sender's liquid balance.
        // Best-effort (fail-open): an unavailable, non-sponsorable, or exhausted
        // sponsor never fails the transaction — the sender pays exactly as a
        // non-sponsored transaction would, never more than `fee` already
        // authorized. The burn + validator-reward split below is identical
        // whichever source pays, so supply is conserved either way.
        let mut sponsored_by: Option<Hash256> = None;
        if tx.authorization_lane.is_default() {
            let mut paid_by_sponsor = false;
            if let Some(namespace) = tx.sponsor {
                // The sponsor record is consensus state this transaction touches
                // whether or not it ultimately pays, so record the declared write
                // up front (the recorder requires every declared key be used).
                access.write(StateKey::application(namespace, sponsor_state_key_hash()))?;
                if tx.operation.is_sponsorable()
                    && self.try_charge_sponsor(namespace, tx.sender, total_fee, config)?
                {
                    paid_by_sponsor = true;
                    sponsored_by = Some(namespace);
                }
            }
            if !paid_by_sponsor {
                self.debit_native(tx.sender, total_fee)?;
            }
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
        // When an application sponsor covered the fee, additionally record which
        // application paid and for whom, so wallets/indexers can attribute the
        // subsidy. `FeePaid` above still records the burn + reward split.
        if let Some(application) = sponsored_by {
            events.push(Event::FeeSponsored {
                application,
                beneficiary: tx.sender,
                breakdown: fee,
            });
        }

        // A session key authorizes only within its fixed constraints. This runs
        // before the operation mutates balances; any failure rolls back the
        // whole transaction because execution is applied to a cloned overlay.
        if let TransactionAuthorization::SessionKey(id) = authorization {
            self.enforce_session_key_use(tx, id, total_fee, &mut access, &mut events)?;
        }

        match &tx.operation {
            Operation::InstallAuthorizationPolicy { post_quantum_root } => {
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::AuthorizationPolicyRequiresDefaultLane);
                }
                if self.authorization_policies.contains_key(&tx.sender) {
                    return Err(ChainError::AuthorizationPolicyAlreadyExists);
                }
                let policy = AccountAuthorizationPolicy::new_v1(tx.public_key, *post_quantum_root)?;
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
            Operation::InstallSessionKey {
                session_public_key,
                constraints,
                post_quantum_root_reveal,
            } => {
                // Installing a session key is a critical action: it must use the
                // default lane and prove knowledge of the account's committed
                // post-quantum root. A legacy account without a policy has no
                // root to gate the action and therefore cannot own session keys.
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::SessionKeyManagementRequiresDefaultLane);
                }
                let (policy_revision, root) = {
                    let policy = self
                        .authorization_policies
                        .get(&tx.sender)
                        .ok_or(ChainError::SessionKeyRequiresInstalledPolicy)?;
                    policy.validate()?;
                    (policy.revision(), *policy.post_quantum_root())
                };
                // The root must sign this exact install (its lane-bound
                // constraints and session key) under the current policy revision
                // and account nonce, not merely prove knowledge of the public
                // root key. A signature captured for any other action, nonce, or
                // policy revision rebuilds a different message and fails here.
                let authorization = SessionKeyAuthorizationAction::Install {
                    session_public_key: *session_public_key,
                    constraints: constraints.clone(),
                };
                let message = session_key_authorization_message(
                    &config.chain_id,
                    tx.sender,
                    policy_revision,
                    tx.nonce,
                    &authorization,
                )?;
                if !post_quantum_root_reveal.verify(&root, &message)? {
                    return Err(ChainError::InvalidPostQuantumRootReveal);
                }
                constraints.validate()?;
                if constraints.lifetime_epochs > config.session_keys.max_lifetime_epochs {
                    return Err(ChainError::SessionKeyLifetimeTooLong);
                }
                // Expiry is an absolute epoch derived from the install epoch, so
                // the deadline never depends on a wall clock.
                let expires_after_epoch = Epoch::new(
                    self.current_epoch
                        .checked_add(constraints.lifetime_epochs)
                        .ok_or(ChainError::ArithmeticOverflow)?,
                );
                let id = SessionKeyId::derive(session_public_key);
                access.write(StateKey::session_key(tx.sender, id))?;
                if self.session_keys.contains_key(&(tx.sender, id)) {
                    return Err(ChainError::SessionKeyAlreadyExists);
                }
                let installed = self
                    .session_keys
                    .keys()
                    .filter(|(owner, _)| *owner == tx.sender)
                    .count();
                if installed >= config.session_keys.max_session_keys_per_account as usize {
                    return Err(ChainError::SessionKeyLimitExceeded);
                }
                let record = SessionKey::new(
                    tx.sender,
                    *session_public_key,
                    policy_revision,
                    constraints.clone(),
                    expires_after_epoch,
                )?;
                self.session_keys.insert((tx.sender, id), record);
                events.push(Event::SessionKeyInstalled {
                    owner: tx.sender,
                    session_key: id,
                    expires_after_epoch,
                });
            }
            Operation::RevokeSessionKey {
                session_key,
                post_quantum_root_reveal,
            } => {
                // Revocation is immediate and unconditional so a compromised key
                // can be killed at once. It is a critical action under the same
                // default-lane and post-quantum-root gate as installation.
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::SessionKeyManagementRequiresDefaultLane);
                }
                let (policy_revision, root) = {
                    let policy = self
                        .authorization_policies
                        .get(&tx.sender)
                        .ok_or(ChainError::SessionKeyRequiresInstalledPolicy)?;
                    policy.validate()?;
                    (policy.revision(), *policy.post_quantum_root())
                };
                // Revocation is gated by the same root signature as installation,
                // bound to this exact session-key id, policy revision, and nonce.
                let authorization = SessionKeyAuthorizationAction::Revoke {
                    session_key: *session_key,
                };
                let message = session_key_authorization_message(
                    &config.chain_id,
                    tx.sender,
                    policy_revision,
                    tx.nonce,
                    &authorization,
                )?;
                if !post_quantum_root_reveal.verify(&root, &message)? {
                    return Err(ChainError::InvalidPostQuantumRootReveal);
                }
                access.write(StateKey::session_key(tx.sender, *session_key))?;
                if self
                    .session_keys
                    .remove(&(tx.sender, *session_key))
                    .is_none()
                {
                    return Err(ChainError::SessionKeyNotFound);
                }
                events.push(Event::SessionKeyRevoked {
                    owner: tx.sender,
                    session_key: *session_key,
                });
            }
            Operation::RotateActiveTransactionKey {
                new_active_transaction_key,
                post_quantum_root_reveal,
            } => {
                // Rotating the sole active key is the account recovery path and a
                // critical action: default lane, an installed policy with a
                // post-quantum root, and a real root signature over this exact
                // rotation. A legacy account without a policy has no root to gate
                // the change and therefore cannot rotate this way.
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::ActiveKeyRotationRequiresDefaultLane);
                }
                let (policy_revision, root, current_active) = {
                    let policy = self
                        .authorization_policies
                        .get(&tx.sender)
                        .ok_or(ChainError::ActiveKeyRotationRequiresInstalledPolicy)?;
                    policy.validate()?;
                    (
                        policy.revision(),
                        *policy.post_quantum_root(),
                        *policy.active_transaction_key(),
                    )
                };
                // A no-op rotation would waste a revision and could be used to
                // grief outstanding session keys without any real key change.
                if *new_active_transaction_key == current_active {
                    return Err(ChainError::ActiveKeyRotationToSameKey);
                }
                // The root must sign this exact new key under the current policy
                // revision and account nonce. A signature captured for any other
                // key, nonce, or revision rebuilds a different message and fails,
                // so it cannot be replayed after this rotation bumps the revision.
                let message = active_key_rotation_message(
                    &config.chain_id,
                    tx.sender,
                    policy_revision,
                    tx.nonce,
                    new_active_transaction_key,
                )?;
                if !post_quantum_root_reveal.verify(&root, &message)? {
                    return Err(ChainError::InvalidPostQuantumRootReveal);
                }
                // The policy state key was already recorded as a write at the top
                // of apply, so the rotation conflicts with concurrent spends.
                let rotated = self
                    .authorization_policies
                    .get(&tx.sender)
                    .ok_or(ChainError::ActiveKeyRotationRequiresInstalledPolicy)?
                    .rotate_active_key(*new_active_transaction_key)?;
                let new_revision = rotated.revision();
                self.authorization_policies.insert(tx.sender, rotated);
                events.push(Event::ActiveTransactionKeyRotated {
                    owner: tx.sender,
                    new_revision,
                    new_active_transaction_key: *new_active_transaction_key,
                });
            }
            Operation::RotatePostQuantumRoot {
                new_post_quantum_root,
                post_quantum_root_reveal,
            } => {
                // Replacing the recovery root is a critical action gated on a
                // signature by the CURRENT root, so only the present recovery-root
                // holder can change it. The envelope is signed by the active key
                // (the AccountKey path), so a stolen root alone cannot rotate the
                // root without also holding the active key.
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::PostQuantumRootRotationRequiresDefaultLane);
                }
                let (policy_revision, current_root) = {
                    let policy = self
                        .authorization_policies
                        .get(&tx.sender)
                        .ok_or(ChainError::PostQuantumRootRotationRequiresInstalledPolicy)?;
                    policy.validate()?;
                    (policy.revision(), *policy.post_quantum_root())
                };
                new_post_quantum_root.validate()?;
                // A no-op rotation would waste a revision and needlessly grief
                // outstanding session keys without changing the root.
                if *new_post_quantum_root == current_root {
                    return Err(ChainError::PostQuantumRootRotationToSameRoot);
                }
                // The CURRENT root must sign this exact new commitment under the
                // current revision and nonce. A signature captured for any other
                // root, nonce, or revision rebuilds a different message and fails.
                let message = post_quantum_root_rotation_message(
                    &config.chain_id,
                    tx.sender,
                    policy_revision,
                    tx.nonce,
                    new_post_quantum_root,
                )?;
                if !post_quantum_root_reveal.verify(&current_root, &message)? {
                    return Err(ChainError::InvalidPostQuantumRootReveal);
                }
                // The policy state key was already recorded as a write at the top
                // of apply, so the rotation conflicts with concurrent spends.
                let rotated = self
                    .authorization_policies
                    .get(&tx.sender)
                    .ok_or(ChainError::PostQuantumRootRotationRequiresInstalledPolicy)?
                    .rotate_post_quantum_root(*new_post_quantum_root)?;
                let new_revision = rotated.revision();
                self.authorization_policies.insert(tx.sender, rotated);
                events.push(Event::PostQuantumRootRotated {
                    owner: tx.sender,
                    new_revision,
                    new_post_quantum_root: *new_post_quantum_root,
                });
            }
            Operation::CreateObject {
                object_id,
                namespace,
                data,
            } => {
                access.write(StateKey::object(*object_id))?;
                access.write(StateKey::application(*namespace, object_id.hash()))?;
                // The storage deposit is locked from the creator's liquid
                // balance, so this operation also writes the sender account
                // (already recorded on the default lane; declared explicitly so
                // it is covered on a non-default fee lane too).
                access.write(StateKey::account(tx.sender))?;
                if self.objects.contains_key(object_id) {
                    return Err(ChainError::ObjectAlreadyExists);
                }
                let mut object =
                    StateObject::new_owned(*object_id, *namespace, tx.sender, data.clone())?;
                // §15.22: lock a refundable storage deposit proportional to the
                // deterministic stored byte count. `debit_native` fails closed
                // (rolling the whole transaction back) if the creator cannot
                // afford it, so an object can never exist without its deposit.
                let deposit = config
                    .storage_pricing
                    .deposit_for_bytes(object.data.len())?;
                self.debit_native(tx.sender, deposit)?;
                object.deposit = deposit;
                self.storage_deposits = self
                    .storage_deposits
                    .checked_add(deposit)
                    .ok_or(ChainError::ArithmeticOverflow)?;
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
                // A resize locks or refunds the difference against the sender's
                // liquid balance, so the sender account is written here too.
                access.write(StateKey::account(tx.sender))?;
                validate_object_data(data)?;
                let new_deposit = config.storage_pricing.deposit_for_bytes(data.len())?;
                // Validate ownership/version and read the current deposit, then
                // release the object borrow before touching balances (which
                // borrow `self` mutably through the native credit/debit helpers).
                let old_deposit = {
                    let object = self
                        .objects
                        .get_mut(object_id)
                        .ok_or(ChainError::ObjectNotFound)?;
                    validate_owned_object(object, tx.sender, *namespace, *expected_version)?;
                    object.deposit
                };
                // Keep the locked deposit exactly matching the new byte size:
                // lock the extra when growing (fail closed if unaffordable),
                // refund the difference when shrinking. Both conserve supply
                // (liquid <-> storage_deposits).
                if new_deposit > old_deposit {
                    let extra = new_deposit
                        .checked_sub(old_deposit)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    self.debit_native(tx.sender, extra)?;
                    self.storage_deposits = self
                        .storage_deposits
                        .checked_add(extra)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                } else if old_deposit > new_deposit {
                    let refund = old_deposit
                        .checked_sub(new_deposit)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    self.storage_deposits = self
                        .storage_deposits
                        .checked_sub(refund)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    self.credit_native(tx.sender, refund)?;
                }
                // Commit the new revision, bytes, and matching deposit only after
                // the balance move succeeded.
                let object = self
                    .objects
                    .get_mut(object_id)
                    .ok_or(ChainError::ObjectNotFound)?;
                object.version = object.version.checked_next()?;
                object.data = data.clone();
                object.deposit = new_deposit;
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
            Operation::DeleteObject {
                object_id,
                namespace,
                expected_version,
            } => {
                access.write(StateKey::object(*object_id))?;
                access.write(StateKey::application(*namespace, object_id.hash()))?;
                // The deletion refund credits the owner's liquid balance.
                access.write(StateKey::account(tx.sender))?;
                // Validate ownership/version and read the recorded deposit, then
                // release the borrow before settling balances.
                let deposit = {
                    let object = self
                        .objects
                        .get(object_id)
                        .ok_or(ChainError::ObjectNotFound)?;
                    validate_owned_object(object, tx.sender, *namespace, *expected_version)?;
                    object.deposit
                };
                // §15.22: refund the majority to the owner, burn the occupancy
                // remainder. `refund + burned == deposit`, so the deposit leaves
                // `storage_deposits` with no mint or loss.
                let split = config.storage_pricing.refund_split(deposit)?;
                self.storage_deposits = self
                    .storage_deposits
                    .checked_sub(deposit)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                self.credit_native(tx.sender, split.refund)?;
                self.burned_fees = self
                    .burned_fees
                    .checked_add(split.burned)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                self.objects.remove(object_id);
                events.push(Event::ObjectDeleted {
                    object_id: *object_id,
                    owner: tx.sender,
                    refund: split.refund,
                    burned: split.burned,
                });
            }
            Operation::Transfer { to, amount } => {
                // The sender account is debited for the principal. On the default
                // lane the fee step already recorded this write, but on a
                // non-default lane fees come from the lane, so record it here or
                // the signed access list's sender-account entry stays unused.
                access.write(StateKey::account(tx.sender))?;
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
            Operation::CompoundValidatorRewards => {
                access.write(StateKey::validator(tx.sender))?;
                access.write(StateKey::account(tx.sender))?;
                // Move accumulated operator rewards straight into self-stake. This
                // shifts units from the pending-rewards bucket to the staked
                // bucket (supply-neutral) without a claim-then-restake round trip.
                let reward = {
                    let validator = self
                        .validators
                        .get_mut(&tx.sender)
                        .ok_or(ChainError::ValidatorNotFound(tx.sender))?;
                    let reward = validator.accumulated_rewards;
                    validator.accumulated_rewards = Amount::ZERO;
                    validator.self_stake = validator
                        .self_stake
                        .checked_add(reward)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    validator.refresh_stake_status(&config.staking)?;
                    reward
                };
                let account = self.account_mut(tx.sender)?;
                account.staked = account
                    .staked
                    .checked_add(reward)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                events.push(Event::ValidatorRewardsCompounded {
                    validator: tx.sender,
                    amount: reward,
                });
            }
            Operation::CompoundDelegatorRewards { validator } => {
                access.write(StateKey::validator(*validator))?;
                access.write(StateKey::delegation(tx.sender, *validator))?;
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::unbonding_queue(*validator))?;
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
                let reward = self
                    .delegations
                    .get(&(tx.sender, *validator))
                    .ok_or(ChainError::DelegationNotFound)?
                    .accumulated_rewards;
                // Adding the reward to the position must respect the operator/
                // delegator ratio, exactly as a fresh delegation would (a queued
                // operator exit still cannot back new delegated stake).
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
                    .checked_add(reward)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                if proposed_delegated > maximum_delegated {
                    return Err(ChainError::DelegationRatioExceeded);
                }

                {
                    let delegation = self
                        .delegations
                        .get_mut(&(tx.sender, *validator))
                        .ok_or(ChainError::DelegationNotFound)?;
                    delegation.accumulated_rewards = Amount::ZERO;
                    delegation.amount = delegation
                        .amount
                        .checked_add(reward)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                }
                let validator_state = self
                    .validators
                    .get_mut(validator)
                    .ok_or(ChainError::ValidatorNotFound(*validator))?;
                validator_state.delegated_stake = validator_state
                    .delegated_stake
                    .checked_add(reward)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                validator_state.refresh_stake_status(&config.staking)?;
                let account = self.account_mut(tx.sender)?;
                account.delegated = account
                    .delegated
                    .checked_add(reward)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                events.push(Event::DelegatorRewardsCompounded {
                    delegator: tx.sender,
                    validator: *validator,
                    amount: reward,
                });
            }
            Operation::SubmitSlashingEvidence { evidence } => {
                let outcome = self.apply_slashing_evidence(evidence, config, Some(&mut access))?;
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
            Operation::RegisterAppSponsor {
                namespace,
                daily_budget_cap,
                initial_funding,
            } => {
                // Owner financial action: default lane only (the account balance
                // is the funding source). The sender account key is already
                // recorded by the default-lane path; declare the sponsor state key.
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::SponsorshipRequiresDefaultLane);
                }
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::application(*namespace, sponsor_state_key_hash()))?;
                // The app-chosen per-day cap must stay within the protocol ceiling
                // (§15.35 "within hard protocol caps").
                if *daily_budget_cap > config.sponsorship.max_app_daily_budget {
                    return Err(ChainError::AppSponsorDailyCapTooHigh);
                }
                if self.sponsors.contains_key(namespace) {
                    return Err(ChainError::AppSponsorAlreadyExists);
                }
                // Lock the initial funding: liquid -> sponsor_budgets. `debit_native`
                // fails closed if the owner cannot afford it, rolling back the tx.
                self.debit_native(tx.sender, *initial_funding)?;
                self.sponsor_budgets = self
                    .sponsor_budgets
                    .checked_add(*initial_funding)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                let mut sponsor = AppSponsor::new(tx.sender, *daily_budget_cap);
                sponsor.budget = *initial_funding;
                self.sponsors.insert(*namespace, sponsor);
                events.push(Event::AppSponsorRegistered {
                    application: *namespace,
                    owner: tx.sender,
                    daily_budget_cap: *daily_budget_cap,
                    funded: *initial_funding,
                });
            }
            Operation::FundAppSponsor { namespace, amount } => {
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::SponsorshipRequiresDefaultLane);
                }
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::application(*namespace, sponsor_state_key_hash()))?;
                // Validate existence and ownership before touching balances; only
                // the owner may fund. Read-only borrow is dropped before `debit`.
                {
                    let sponsor = self
                        .sponsors
                        .get(namespace)
                        .ok_or(ChainError::AppSponsorNotFound)?;
                    if sponsor.owner != tx.sender {
                        return Err(ChainError::AppSponsorNotOwner);
                    }
                }
                self.debit_native(tx.sender, *amount)?;
                self.sponsor_budgets = self
                    .sponsor_budgets
                    .checked_add(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                let sponsor = self
                    .sponsors
                    .get_mut(namespace)
                    .ok_or(ChainError::AppSponsorNotFound)?;
                sponsor.budget = sponsor
                    .budget
                    .checked_add(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                events.push(Event::AppSponsorFunded {
                    application: *namespace,
                    amount: *amount,
                });
            }
            Operation::WithdrawAppSponsor { namespace, amount } => {
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::SponsorshipRequiresDefaultLane);
                }
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::application(*namespace, sponsor_state_key_hash()))?;
                // Validate ownership and sufficient budget before moving units.
                {
                    let sponsor = self
                        .sponsors
                        .get(namespace)
                        .ok_or(ChainError::AppSponsorNotFound)?;
                    if sponsor.owner != tx.sender {
                        return Err(ChainError::AppSponsorNotOwner);
                    }
                    if sponsor.budget < *amount {
                        return Err(ChainError::AppSponsorBudgetInsufficient {
                            needed: *amount,
                            available: sponsor.budget,
                        });
                    }
                }
                // Move sponsor_budgets -> owner liquid, keeping the per-app budget
                // and the aggregate bucket in lockstep (no mint, no loss).
                {
                    let sponsor = self
                        .sponsors
                        .get_mut(namespace)
                        .ok_or(ChainError::AppSponsorNotFound)?;
                    sponsor.budget = sponsor
                        .budget
                        .checked_sub(*amount)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                }
                self.sponsor_budgets = self
                    .sponsor_budgets
                    .checked_sub(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                self.credit_native(tx.sender, *amount)?;
                events.push(Event::AppSponsorWithdrawn {
                    application: *namespace,
                    amount: *amount,
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

    /// Applies block-carried objective evidence without a transaction access list.
    ///
    /// Block construction already runs on a whole-block overlay, so any failure
    /// rolls back this slash together with every other block transition. The
    /// evidence is still independently signature-verified and replay-protected;
    /// only the transaction-specific declared-access bookkeeping is skipped.
    pub(crate) fn apply_block_slashing_evidence(
        &mut self,
        evidence: &SlashingEvidence,
        config: &ChainConfig,
    ) -> Result<SlashingOutcome, ChainError> {
        self.apply_slashing_evidence(evidence, config, None)
    }

    /// Shared deterministic slashing transition used by signed transactions and
    /// header-committed block evidence.
    fn apply_slashing_evidence(
        &mut self,
        evidence: &SlashingEvidence,
        config: &ChainConfig,
        mut access: Option<&mut StateAccessRecorder>,
    ) -> Result<SlashingOutcome, ChainError> {
        let validator_address = evidence.validator();
        Self::record_slashing_write(&mut access, StateKey::validator(validator_address))?;
        let consensus_key = self
            .validators
            .get(&validator_address)
            .ok_or(ChainError::ValidatorNotFound(validator_address))?
            .consensus_key;
        evidence.verify(config.protocol_version, &config.chain_id, &consensus_key)?;
        let evidence_hash = evidence.hash()?;
        Self::record_slashing_write(&mut access, StateKey::slashing_evidence(evidence_hash))?;
        if self.processed_slashing_evidence.contains(&evidence_hash) {
            return Err(ChainError::SlashingReplay);
        }

        let penalty_bps = slashing_bps(evidence, &config.slashing);
        Self::record_slashing_write(&mut access, StateKey::unbonding_queue(validator_address))?;
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
        let locked_slash = self.unbonding.slash_locked(
            validator_address,
            penalty_bps,
            Epoch::new(self.current_epoch),
        )?;
        for owner in locked_slash.locked_losses.keys() {
            Self::record_slashing_write(&mut access, StateKey::account(*owner))?;
        }

        Self::record_slashing_write(&mut access, StateKey::account(validator_address))?;
        for ((delegator, validator), _) in &delegation_losses {
            Self::record_slashing_write(&mut access, StateKey::delegation(*delegator, *validator))?;
            Self::record_slashing_write(&mut access, StateKey::account(*delegator))?;
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
        Ok(outcome)
    }

    /// Records a slashing write for a user transaction, or deliberately skips
    /// access-list bookkeeping for authenticated block-system evidence.
    fn record_slashing_write(
        access: &mut Option<&mut StateAccessRecorder>,
        key: StateKey,
    ) -> Result<(), ChainError> {
        if let Some(recorder) = access.as_deref_mut() {
            recorder.write(key)?;
        }
        Ok(())
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

    /// Enforces a session key's constraints and advances its cumulative spend.
    ///
    /// Runs during execution before the operation mutates balances. Every
    /// failure returns a typed error and, because execution runs on a cloned
    /// overlay, rolls back the entire transaction. A session key never gains
    /// authority beyond its declared lane, operations, per-use amount,
    /// cumulative budget, per-use fee, and expiry epoch. The lane binding was
    /// already checked in `verify_transaction_authorization`.
    fn enforce_session_key_use(
        &mut self,
        tx: &Transaction,
        id: SessionKeyId,
        total_fee: Amount,
        access: &mut StateAccessRecorder,
        events: &mut Vec<Event>,
    ) -> Result<(), ChainError> {
        access.write(StateKey::session_key(tx.sender, id))?;
        let session = self
            .session_keys
            .get(&(tx.sender, id))
            .ok_or(ChainError::SessionKeyNotFound)?;
        if self.current_epoch > session.expires_after_epoch.get() {
            return Err(ChainError::SessionKeyExpired);
        }
        let principal =
            session_permitted_principal(&tx.operation, session.constraints.allowed_operations)?;
        if principal > session.constraints.max_amount_per_use {
            return Err(ChainError::SessionKeyAmountExceeded);
        }
        let next_spent = session
            .spent_amount
            .checked_add(principal)
            .ok_or(ChainError::ArithmeticOverflow)?;
        if next_spent > session.constraints.total_amount_budget {
            return Err(ChainError::SessionKeyBudgetExceeded);
        }
        // Bound the maximum fee the transaction authorizes, independent of the
        // current base fee, matching the off-chain grant's per-transaction cap.
        let max_fee = Amount(
            u128::from(tx.fee.gas_limit)
                .checked_mul(u128::from(tx.fee.max_fee_per_unit))
                .ok_or(ChainError::ArithmeticOverflow)?,
        );
        if max_fee > session.constraints.max_fee_per_use {
            return Err(ChainError::SessionKeyFeeExceeded);
        }
        // Bound cumulative fees on the fee actually charged, so a compromised key
        // cannot drain the account through fees on unlimited tiny transfers.
        let next_fees = session
            .spent_fees
            .checked_add(total_fee)
            .ok_or(ChainError::ArithmeticOverflow)?;
        if next_fees > session.constraints.total_fee_budget {
            return Err(ChainError::SessionKeyFeeBudgetExceeded);
        }
        let record = self
            .session_keys
            .get_mut(&(tx.sender, id))
            .ok_or(ChainError::SessionKeyNotFound)?;
        record.spent_amount = next_spent;
        record.spent_fees = next_fees;
        events.push(Event::SessionKeyUsed {
            owner: tx.sender,
            session_key: id,
            amount: principal,
        });
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

    /// Attempts to draw `total_fee` from application `namespace`'s sponsor budget.
    ///
    /// Returns `true` and relocates the fee out of the aggregate `sponsor_budgets`
    /// bucket (the caller then applies the identical burn + validator-reward split
    /// a normal fee uses) iff the app is a registered sponsor and its hard
    /// per-user / per-operation / per-app-per-day caps and funded budget all
    /// permit charging `user` in the current day-window. Returns `false` with no
    /// mutation of the aggregate bucket otherwise, so the caller self-pays.
    /// Deterministic (the day-window comes from `current_epoch`, never a clock);
    /// checked arithmetic; never panics.
    fn try_charge_sponsor(
        &mut self,
        namespace: Hash256,
        user: Address,
        total_fee: Amount,
        config: &ChainConfig,
    ) -> Result<bool, ChainError> {
        let window = config.sponsorship.window_index(self.current_epoch);
        let Some(sponsor) = self.sponsors.get_mut(&namespace) else {
            return Ok(false);
        };
        if !sponsor.try_charge(user, total_fee, window, &config.sponsorship)? {
            return Ok(false);
        }
        // The per-app budget already decremented inside `try_charge`; keep the
        // aggregate locked bucket in lockstep so the supply invariant reconciles
        // (issued == liquid + … + sponsor_budgets + burned + slashed).
        self.sponsor_budgets = self
            .sponsor_budgets
            .checked_sub(total_fee)
            .ok_or(ChainError::ArithmeticOverflow)?;
        Ok(true)
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

/// Returns the native principal a session key would move for an operation, or
/// rejects an operation kind the session key is not permitted to authorize.
///
/// v1 permits only native transfers. Critical, staking, bridge, object, and
/// lane/policy operations are never delegable to a session key, so they fall
/// through to a rejection regardless of the grant's allow-list.
fn session_permitted_principal(
    operation: &Operation,
    allowed: SessionAllowedOperations,
) -> Result<Amount, ChainError> {
    match operation {
        Operation::Transfer { amount, .. } if allowed.transfer => Ok(*amount),
        _ => Err(ChainError::SessionKeyOperationNotPermitted),
    }
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
        AuthorizationPolicyRevision, DoubleVoteEvidence, FeeBid, GenesisAccount, GenesisValidator,
        Nonce, Operation, PostQuantumRoot, PostQuantumRootReveal, PostQuantumScheme,
        SessionKeyConstraints, SignedVote, SlashingEvidence, ValidatorSet, Vote, VoteType,
        GENESIS_TOTAL_SUPPLY, MAX_AUTHORIZATION_POLICY_REVISION,
    };
    use proptest::prelude::*;
    use std::sync::OnceLock;
    use webc_crypto::{
        ml_dsa65_keygen, Keypair, MlDsa65PublicKey, MlDsa65SecretKey, PublicKeyBytes,
        ML_DSA_65_SIGNATURE_LEN,
    };

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

    // ----- G1: genesis total-supply pinning -----

    #[test]
    fn genesis_pins_the_declared_total_supply() {
        // A production genesis pins the total; an allocation that does not sum
        // to it is rejected (finding G1). Before this fix `from_genesis`
        // accepted any total, because the supply invariant is tautological.
        let faucet = Keypair::from_seed([9u8; 32]);
        let chain = ChainConfig {
            expected_total_supply: Some(GENESIS_TOTAL_SUPPLY),
            ..ChainConfig::default()
        };
        let short = GenesisConfig {
            chain,
            accounts: vec![GenesisAccount {
                address: faucet.address(),
                balance: Amount::from_webc(1_000_000), // only 1M, not the pinned 10M
            }],
            validators: Vec::new(),
        };
        match ChainState::from_genesis(&short) {
            Err(ChainError::GenesisSupplyMismatch { expected, actual }) => {
                assert_eq!(expected, GENESIS_TOTAL_SUPPLY);
                assert_eq!(actual, Amount::from_webc(1_000_000));
            }
            other => panic!("expected GenesisSupplyMismatch, got {other:?}"),
        }
    }

    #[test]
    fn genesis_accepts_an_allocation_matching_the_declared_total() {
        let faucet = Keypair::from_seed([9u8; 32]);
        let genesis = GenesisConfig {
            chain: ChainConfig {
                expected_total_supply: Some(GENESIS_TOTAL_SUPPLY),
                ..ChainConfig::default()
            },
            accounts: vec![GenesisAccount {
                address: faucet.address(),
                balance: GENESIS_TOTAL_SUPPLY,
            }],
            validators: Vec::new(),
        };
        let state = ChainState::from_genesis(&genesis).expect("exact declared total is accepted");
        assert_eq!(state.minted_supply, GENESIS_TOTAL_SUPPLY);
    }

    #[test]
    fn genesis_without_a_declared_total_skips_the_pin() {
        // Trusted in-crate fixtures leave the expectation unset (the default)
        // and may use any small allocation.
        let alice = Keypair::from_seed([1u8; 32]);
        let genesis = GenesisConfig {
            chain: ChainConfig::default(),
            accounts: vec![GenesisAccount {
                address: alice.address(),
                balance: Amount::from_webc(1_000),
            }],
            validators: Vec::new(),
        };
        assert!(ChainState::from_genesis(&genesis).is_ok());
    }

    // ----- F1: epoch-reward supply conservation with multiple validators -----

    fn two_active_validators_with_odd_fee_pool() -> (ChainConfig, ChainState) {
        let config = ChainConfig::default();
        let mut state = ChainState::new(&config).expect("empty state");
        let stake = Amount::from_webc(100);
        for seed in [21u8, 22u8] {
            let address = Keypair::from_seed([seed; 32]).address();
            let mut account = Account::with_balance(Amount::ZERO);
            account.staked = stake;
            state.accounts.insert(address, account);
            state.validators.insert(
                address,
                Validator {
                    operator: address,
                    consensus_key: PublicKeyBytes([seed; 32]),
                    self_stake: stake,
                    delegated_stake: Amount::ZERO,
                    commission_bps: 0,
                    status: ValidatorStatus::Active,
                    bootstrap: false,
                    accumulated_rewards: Amount::ZERO,
                },
            );
        }
        // An odd fee pool guarantees the outer remainder: two equal-stake
        // validators each floor to (pool - 1) / 2, leaving one base unit over.
        let fee_pool = 101u128;
        state.validator_fee_pool = Amount::from_units(fee_pool);
        // Balanced by construction: staked principal plus the fee pool == minted.
        state.minted_supply = Amount::from_units(2 * stake.0 + fee_pool);
        // Zero year-start supply => zero inflation; epoch 1 is not a year
        // boundary, so `apply_epoch_rewards` does not reset the year-start.
        state.inflation_year_start_supply = Amount::ZERO;
        state.current_epoch = 1;
        (config, state)
    }

    #[test]
    fn epoch_rewards_conserve_supply_across_multiple_validators() {
        // F1: the outer cross-validator division remainder must be retained in
        // the fee pool, not dropped. Dropping it breaks supply conservation by
        // up to num_validators-1 base units per epoch (invisible with a single
        // validator, where the whole reward is one exact share).
        let (config, mut state) = two_active_validators_with_odd_fee_pool();
        assert!(
            state.supply_invariant_report().unwrap().balanced,
            "state is balanced before distribution"
        );

        state
            .distribute_epoch_rewards(&config)
            .expect("epoch reward distribution");

        assert!(
            state.supply_invariant_report().unwrap().balanced,
            "supply must still reconcile after distributing rewards to two validators"
        );
        // The remainder that was previously dropped now carries forward.
        assert_eq!(state.validator_fee_pool, Amount::from_units(1));
    }

    #[test]
    fn bootstrap_issuance_keys_to_stake_caps_at_base_and_conserves_supply() {
        // Task 12 (§15.2): during the bootstrap phase issuance is keyed to the
        // staked amount and capped by the base per-period budget, and supply must
        // still reconcile exactly. Here the staking base is thin relative to the
        // circulating supply, so the (small) stake-keyed budget binds, not the
        // (large) base budget — the whole point of §15.2.
        let config = ChainConfig {
            bootstrap_issuance: Some(BootstrapIssuance {
                annual_rate_bps: 1_000,
                sunset_epoch: 1_000_000,
            }),
            ..ChainConfig::default()
        };
        let mut state = ChainState::new(&config).expect("empty state");
        let stake = Amount::from_webc(100);
        for seed in [31u8, 32u8] {
            let address = Keypair::from_seed([seed; 32]).address();
            let mut account = Account::with_balance(Amount::ZERO);
            account.staked = stake;
            state.accounts.insert(address, account);
            state.validators.insert(
                address,
                Validator {
                    operator: address,
                    consensus_key: PublicKeyBytes([seed; 32]),
                    self_stake: stake,
                    delegated_stake: Amount::ZERO,
                    commission_bps: 0,
                    status: ValidatorStatus::Active,
                    bootstrap: false,
                    accumulated_rewards: Amount::ZERO,
                },
            );
        }
        // A large liquid holder makes the base schedule budget far exceed the
        // stake-keyed budget, so the stake-keying (not the cap) binds.
        let holder = Keypair::from_seed([33u8; 32]).address();
        let extra = Amount::from_webc(1_000_000);
        state.accounts.insert(holder, Account::with_balance(extra));
        state.minted_supply = Amount::from_units(2 * stake.0 + extra.0);
        state.inflation_year_start_supply = state.minted_supply;
        state.current_epoch = 1;
        assert!(state.supply_invariant_report().unwrap().balanced);

        let minted_before = state.minted_supply;
        state
            .distribute_epoch_rewards(&config)
            .expect("bootstrap epoch reward distribution");

        assert!(
            state.supply_invariant_report().unwrap().balanced,
            "supply must reconcile after bootstrap issuance"
        );
        // Minted grew by exactly the stake-keyed budget (below the base cap):
        // 200 WEBC * 1000 bps / (10_000 * 365) base units.
        let minted_growth = state.minted_supply.0 - minted_before.0;
        let expected_stake_keyed = (2 * stake.0) * 1_000 / (10_000 * 365);
        assert_eq!(minted_growth, expected_stake_keyed);
        assert!(minted_growth > 0);
    }

    #[test]
    fn compound_validator_rewards_restakes_and_conserves_supply() {
        // Task 6b: compounding moves accumulated operator rewards straight into
        // self-stake (pending-rewards bucket -> staked bucket), supply-neutral.
        let config = ChainConfig::default();
        let mut state = ChainState::new(&config).expect("empty state");
        let alice = Keypair::from_seed([41u8; 32]);
        let self_stake = Amount::from_webc(100);
        let reward = Amount::from_webc(10);
        let mut account = Account::with_balance(Amount::from_webc(1));
        account.staked = self_stake;
        state.accounts.insert(alice.address(), account);
        state.validators.insert(
            alice.address(),
            Validator {
                operator: alice.address(),
                consensus_key: alice.public_key(),
                self_stake,
                delegated_stake: Amount::ZERO,
                commission_bps: 0,
                status: ValidatorStatus::Active,
                bootstrap: false,
                accumulated_rewards: reward,
            },
        );
        state.minted_supply = Amount::from_units(self_stake.0 + reward.0 + Amount::from_webc(1).0);
        state.inflation_year_start_supply = state.minted_supply;
        assert!(state.supply_invariant_report().unwrap().balanced);

        let tx = Transaction::for_operation(
            &alice,
            0,
            Operation::CompoundValidatorRewards,
            FeeBid {
                gas_limit: 10_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("compound signs");
        state
            .execute_transaction(&tx, &config)
            .expect("compound executes");

        let compounded = self_stake.checked_add(reward).unwrap();
        let v = state.validators.get(&alice.address()).unwrap();
        assert_eq!(v.self_stake, compounded);
        assert_eq!(v.accumulated_rewards, Amount::ZERO);
        assert_eq!(
            state.accounts.get(&alice.address()).unwrap().staked,
            compounded
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn compound_delegator_rewards_restakes_within_ratio_and_conserves_supply() {
        // Task 6b: compounding a delegation restakes its rewards into the position
        // (pending -> delegated), supply-neutral, respecting the 4x ratio.
        let config = ChainConfig::default();
        let mut state = ChainState::new(&config).expect("empty state");
        let alice = Keypair::from_seed([42u8; 32]); // operator
        let bob = Keypair::from_seed([43u8; 32]); // delegator
        let self_stake = Amount::from_webc(100);
        let delegated = Amount::from_webc(40);
        let reward = Amount::from_webc(5);

        let mut op_account = Account::with_balance(Amount::ZERO);
        op_account.staked = self_stake;
        state.accounts.insert(alice.address(), op_account);
        let mut del_account = Account::with_balance(Amount::from_webc(1));
        del_account.delegated = delegated;
        state.accounts.insert(bob.address(), del_account);
        state.validators.insert(
            alice.address(),
            Validator {
                operator: alice.address(),
                consensus_key: alice.public_key(),
                self_stake,
                delegated_stake: delegated,
                commission_bps: 0,
                status: ValidatorStatus::Active,
                bootstrap: false,
                accumulated_rewards: Amount::ZERO,
            },
        );
        state.delegations.insert(
            (bob.address(), alice.address()),
            Delegation {
                delegator: bob.address(),
                validator: alice.address(),
                amount: delegated,
                accumulated_rewards: reward,
            },
        );
        state.minted_supply =
            Amount::from_units(self_stake.0 + delegated.0 + reward.0 + Amount::from_webc(1).0);
        state.inflation_year_start_supply = state.minted_supply;
        assert!(state.supply_invariant_report().unwrap().balanced);

        let tx = Transaction::for_operation(
            &bob,
            0,
            Operation::CompoundDelegatorRewards {
                validator: alice.address(),
            },
            FeeBid {
                gas_limit: 10_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("compound signs");
        state
            .execute_transaction(&tx, &config)
            .expect("compound executes");

        let compounded = delegated.checked_add(reward).unwrap();
        assert_eq!(
            state
                .delegations
                .get(&(bob.address(), alice.address()))
                .unwrap()
                .amount,
            compounded
        );
        assert_eq!(
            state
                .delegations
                .get(&(bob.address(), alice.address()))
                .unwrap()
                .accumulated_rewards,
            Amount::ZERO
        );
        assert_eq!(
            state
                .validators
                .get(&alice.address())
                .unwrap()
                .delegated_stake,
            compounded
        );
        assert_eq!(
            state.accounts.get(&bob.address()).unwrap().delegated,
            compounded
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn compound_delegator_rewards_rejects_ratio_violation() {
        // Compounding cannot push delegated stake past 4x the operator self-stake,
        // exactly as a fresh delegation cannot.
        let config = ChainConfig::default();
        let mut state = ChainState::new(&config).expect("empty state");
        let alice = Keypair::from_seed([44u8; 32]);
        let bob = Keypair::from_seed([45u8; 32]);
        let self_stake = Amount::from_webc(20);
        let delegated = Amount::from_webc(80); // exactly at the 4x cap
        let reward = Amount::from_webc(5); // would exceed the cap

        let mut op_account = Account::with_balance(Amount::ZERO);
        op_account.staked = self_stake;
        state.accounts.insert(alice.address(), op_account);
        let mut del_account = Account::with_balance(Amount::from_webc(1));
        del_account.delegated = delegated;
        state.accounts.insert(bob.address(), del_account);
        state.validators.insert(
            alice.address(),
            Validator {
                operator: alice.address(),
                consensus_key: alice.public_key(),
                self_stake,
                delegated_stake: delegated,
                commission_bps: 0,
                status: ValidatorStatus::Active,
                bootstrap: false,
                accumulated_rewards: Amount::ZERO,
            },
        );
        state.delegations.insert(
            (bob.address(), alice.address()),
            Delegation {
                delegator: bob.address(),
                validator: alice.address(),
                amount: delegated,
                accumulated_rewards: reward,
            },
        );
        state.minted_supply =
            Amount::from_units(self_stake.0 + delegated.0 + reward.0 + Amount::from_webc(1).0);
        state.inflation_year_start_supply = state.minted_supply;

        let tx = Transaction::for_operation(
            &bob,
            0,
            Operation::CompoundDelegatorRewards {
                validator: alice.address(),
            },
            FeeBid {
                gas_limit: 10_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("compound signs");
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::DelegationRatioExceeded)
        ));
        assert_eq!(state, before, "rejected compound leaves state unchanged");
    }

    #[test]
    fn every_scalar_state_counter_is_committed_by_the_state_root() {
        // E8: the state root (canonical JSON) must commit every consensus field,
        // so no field can be mutated on disk (the bincode restart path) without
        // changing the committed root — otherwise two nodes could diverge on a
        // JSON-invisible field yet share a state root. Map fields are covered by
        // their dedicated sub-roots; this guards the scalar counters, which are
        // the easiest to add and forget.
        let (_config, base, _a, _b) = funded_state();
        let root = base.state_root().unwrap();
        type StateMutator = fn(&mut ChainState);
        let mutators: Vec<(&str, StateMutator)> = vec![
            ("burned_fees", |s| {
                s.burned_fees = Amount::from_units(s.burned_fees.0 + 1)
            }),
            ("slashed_units", |s| {
                s.slashed_units = Amount::from_units(s.slashed_units.0 + 1)
            }),
            ("storage_deposits", |s| {
                s.storage_deposits = Amount::from_units(s.storage_deposits.0 + 1)
            }),
            ("sponsor_budgets", |s| {
                s.sponsor_budgets = Amount::from_units(s.sponsor_budgets.0 + 1)
            }),
            ("validator_fee_pool", |s| {
                s.validator_fee_pool = Amount::from_units(s.validator_fee_pool.0 + 1)
            }),
            ("minted_supply", |s| {
                s.minted_supply = Amount::from_units(s.minted_supply.0 + 1)
            }),
            ("inflation_year_start_supply", |s| {
                s.inflation_year_start_supply =
                    Amount::from_units(s.inflation_year_start_supply.0 + 1)
            }),
            ("current_base_fee_per_unit", |s| {
                s.current_base_fee_per_unit += 1
            }),
            ("current_epoch", |s| s.current_epoch += 1),
            ("bridge_nonce", |s| s.bridge_nonce += 1),
            ("last_block_timestamp_ms", |s| {
                s.last_block_timestamp_ms += 1
            }),
        ];
        for (name, mutate) in mutators {
            let mut mutated = base.clone();
            mutate(&mut mutated);
            assert_ne!(
                mutated.state_root().unwrap(),
                root,
                "mutating {name} must change the state root (E8)"
            );
        }
    }

    // ----- session-key test helpers -----

    /// Process-wide ML-DSA-65 recovery keypair for session-key tests.
    ///
    /// One keypair is generated once and reused so the committed root and every
    /// signed reveal agree. Generation draws OS randomness (fine in tests);
    /// verification inside the state machine stays deterministic.
    fn pq_keypair() -> &'static (MlDsa65PublicKey, MlDsa65SecretKey) {
        static KEYPAIR: OnceLock<(MlDsa65PublicKey, MlDsa65SecretKey)> = OnceLock::new();
        KEYPAIR.get_or_init(|| ml_dsa65_keygen().expect("ml-dsa-65 keygen"))
    }

    /// The committed root public key bytes for `installed_policy_state`.
    fn pq_public_key() -> Vec<u8> {
        pq_keypair().0.to_bytes()
    }

    /// Signs an authorization message for `action` at `nonce` under Alice's
    /// installed policy (revision 1) on the devnet chain, matching exactly what
    /// the state machine rebuilds and verifies.
    fn signed_reveal(
        owner: Address,
        nonce: u64,
        action: &SessionKeyAuthorizationAction,
    ) -> PostQuantumRootReveal {
        let (public_key, secret) = pq_keypair();
        let message = session_key_authorization_message(
            &ChainId::devnet(),
            owner,
            AuthorizationPolicyRevision::new(1),
            nonce,
            action,
        )
        .unwrap();
        // Empty context: the domain lives in the signed message, matching the
        // verifier's `POST_QUANTUM_AUTHORIZATION_CONTEXT`.
        let signature = secret.sign(&message, b"").unwrap();
        PostQuantumRootReveal {
            scheme: PostQuantumScheme::MlDsa65,
            public_key: public_key.to_bytes(),
            signature,
        }
    }

    /// A reveal whose signature is over exactly `message` (a test may sign a
    /// message that disagrees with what the chain will rebuild, to prove a
    /// specific binding axis is enforced).
    fn reveal_over_message(message: &[u8]) -> PostQuantumRootReveal {
        let (public_key, secret) = pq_keypair();
        PostQuantumRootReveal {
            scheme: PostQuantumScheme::MlDsa65,
            public_key: public_key.to_bytes(),
            signature: secret.sign(message, b"").unwrap(),
        }
    }

    /// A valid install reveal for the given session key and constraints.
    fn install_reveal(
        owner: Address,
        nonce: u64,
        session_public_key: PublicKeyBytes,
        constraints: &SessionKeyConstraints,
    ) -> PostQuantumRootReveal {
        signed_reveal(
            owner,
            nonce,
            &SessionKeyAuthorizationAction::Install {
                session_public_key,
                constraints: constraints.clone(),
            },
        )
    }

    /// A valid revoke reveal for the given session-key id.
    fn revoke_reveal(
        owner: Address,
        nonce: u64,
        session_key: SessionKeyId,
    ) -> PostQuantumRootReveal {
        signed_reveal(
            owner,
            nonce,
            &SessionKeyAuthorizationAction::Revoke { session_key },
        )
    }

    /// A well-formed reveal used only where the action is rejected *before* the
    /// root signature is checked (wrong lane, no installed policy). Its signature
    /// is never verified, so a correctly sized placeholder is enough.
    fn unverified_reveal() -> PostQuantumRootReveal {
        PostQuantumRootReveal {
            scheme: PostQuantumScheme::MlDsa65,
            public_key: pq_public_key(),
            signature: vec![0u8; ML_DSA_65_SIGNATURE_LEN],
        }
    }

    /// Funded Alice with an installed policy whose post-quantum root commits to
    /// `pq_public_key()`. Alice's account nonce is 1 after installation.
    fn installed_policy_state() -> (ChainConfig, ChainState, Keypair, Keypair) {
        let (config, mut state, alice, bob) = funded_state();
        let root =
            PostQuantumRoot::from_public_key(PostQuantumScheme::MlDsa65, &pq_public_key()).unwrap();
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
        (config, state, alice, bob)
    }

    /// Default-lane transfer constraints: 5 WEBC per use, 20 WEBC budget.
    fn session_constraints() -> SessionKeyConstraints {
        SessionKeyConstraints {
            authorization_lane: AuthorizationLaneId::DEFAULT,
            allowed_operations: SessionAllowedOperations::transfers_only(),
            max_amount_per_use: Amount::from_webc(5),
            total_amount_budget: Amount::from_webc(20),
            max_fee_per_use: Amount::from_webc(1),
            total_fee_budget: Amount::from_webc(5),
            lifetime_epochs: 60,
        }
    }

    fn install_session_key_tx(
        owner: &Keypair,
        session: &Keypair,
        nonce: u64,
        constraints: SessionKeyConstraints,
    ) -> Transaction {
        let reveal = install_reveal(owner.address(), nonce, session.public_key(), &constraints);
        install_session_key_tx_with_reveal(owner, session, nonce, constraints, reveal)
    }

    fn install_session_key_tx_with_reveal(
        owner: &Keypair,
        session: &Keypair,
        nonce: u64,
        constraints: SessionKeyConstraints,
        reveal: PostQuantumRootReveal,
    ) -> Transaction {
        Transaction::for_operation_with_policy(
            owner,
            AuthorizationPolicyRevision::new(1),
            nonce,
            Operation::InstallSessionKey {
                session_public_key: session.public_key(),
                constraints,
                post_quantum_root_reveal: reveal,
            },
            FeeBid {
                gas_limit: 20_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap()
    }

    /// Builds and signs a transfer authorized by a session key.
    fn session_transfer_tx(
        owner: &Keypair,
        session: &Keypair,
        lane: AuthorizationLaneId,
        nonce: u64,
        to: Address,
        amount: Amount,
        fee: FeeBid,
    ) -> Transaction {
        let id = SessionKeyId::derive(&session.public_key());
        let operation = Operation::Transfer { to, amount };
        let access_list = operation
            .default_access_list_for_session(owner.address(), lane, id)
            .unwrap();
        let mut tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            owner.address(),
            session.public_key(),
            lane,
            AuthorizationPolicyRevision::new(1),
            nonce,
            operation,
            access_list,
            fee,
        );
        tx.sign_with_policy_key(session).unwrap();
        tx
    }

    fn small_fee() -> FeeBid {
        FeeBid {
            gas_limit: 1_000,
            max_fee_per_unit: 1,
            priority_fee_per_unit: 0,
        }
    }

    // ----- session-key tests -----

    #[test]
    fn session_key_install_use_and_revoke_lifecycle() {
        let (config, mut state, alice, bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let id = SessionKeyId::derive(&session.public_key());

        let before_install = state.state_root().unwrap();
        let install = install_session_key_tx(&alice, &session, 1, session_constraints());
        state.execute_transaction(&install, &config).unwrap();
        assert!(state.session_keys.contains_key(&(alice.address(), id)));
        assert_ne!(state.state_root().unwrap(), before_install);
        assert!(state.supply_invariant_report().unwrap().balanced);

        // A within-limits transfer signed by the session key succeeds and moves
        // the owner's funds, advancing only the session's cumulative spend.
        let bob_before = state.accounts.get(&bob.address()).map(|a| a.balance);
        let transfer = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            2,
            bob.address(),
            Amount::from_webc(4),
            small_fee(),
        );
        state.execute_transaction(&transfer, &config).unwrap();
        assert_eq!(
            state.session_keys[&(alice.address(), id)].spent_amount,
            Amount::from_webc(4)
        );
        let bob_after = state.accounts.get(&bob.address()).unwrap().balance;
        assert_eq!(
            bob_after,
            bob_before
                .unwrap_or(Amount::ZERO)
                .checked_add(Amount::from_webc(4))
                .unwrap()
        );
        assert!(state.supply_invariant_report().unwrap().balanced);

        // Revocation removes the key; the same key can no longer authorize.
        let revoke = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(1),
            3,
            Operation::RevokeSessionKey {
                session_key: id,
                post_quantum_root_reveal: revoke_reveal(alice.address(), 3, id),
            },
            small_fee_with_units(20_000),
        )
        .unwrap();
        state.execute_transaction(&revoke, &config).unwrap();
        assert!(!state.session_keys.contains_key(&(alice.address(), id)));

        let after_revoke = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            3,
            bob.address(),
            Amount::from_webc(1),
            small_fee(),
        );
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&after_revoke, &config),
            Err(ChainError::AuthorizationKeyMismatch)
        ));
        assert_eq!(state, before);
    }

    fn small_fee_with_units(gas_limit: u64) -> FeeBid {
        FeeBid {
            gas_limit,
            max_fee_per_unit: 1,
            priority_fee_per_unit: 0,
        }
    }

    #[test]
    fn session_transfer_respects_per_use_budget_and_fee_caps() {
        let (config, mut state, alice, bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let id = SessionKeyId::derive(&session.public_key());
        // Per-use 5 WEBC, cumulative budget 12 WEBC, per-use fee cap 1 WEBC.
        let mut constraints = session_constraints();
        constraints.total_amount_budget = Amount::from_webc(12);
        let install = install_session_key_tx(&alice, &session, 1, constraints);
        state.execute_transaction(&install, &config).unwrap();

        // Over the per-use cap (5 WEBC): rejected atomically, nonce unchanged.
        let over_use = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            2,
            bob.address(),
            Amount::from_webc(6),
            small_fee(),
        );
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&over_use, &config),
            Err(ChainError::SessionKeyAmountExceeded)
        ));
        assert_eq!(state, before);

        // Two 5 WEBC transfers succeed and reach 10 WEBC cumulative spend.
        for nonce in [2u64, 3] {
            let tx = session_transfer_tx(
                &alice,
                &session,
                AuthorizationLaneId::DEFAULT,
                nonce,
                bob.address(),
                Amount::from_webc(5),
                small_fee(),
            );
            state.execute_transaction(&tx, &config).unwrap();
        }
        assert_eq!(
            state.session_keys[&(alice.address(), id)].spent_amount,
            Amount::from_webc(10)
        );

        // A third 5 WEBC transfer would reach 15 WEBC, above the 12 WEBC budget,
        // and is rejected atomically.
        let over_budget = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            4,
            bob.address(),
            Amount::from_webc(5),
            small_fee(),
        );
        let before_budget = state.clone();
        assert!(matches!(
            state.execute_transaction(&over_budget, &config),
            Err(ChainError::SessionKeyBudgetExceeded)
        ));
        assert_eq!(state, before_budget);

        // A fee bid whose ceiling exceeds the per-use fee cap (1 WEBC) fails,
        // even though the 1 WEBC principal is within budget.
        let over_fee = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            4,
            bob.address(),
            Amount::from_webc(1),
            FeeBid {
                gas_limit: 2_000_000_000,
                max_fee_per_unit: 1_000,
                priority_fee_per_unit: 0,
            },
        );
        let before_fee = state.clone();
        assert!(matches!(
            state.execute_transaction(&over_fee, &config),
            Err(ChainError::SessionKeyFeeExceeded)
        ));
        assert_eq!(state, before_fee);
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn expired_session_key_is_rejected_at_the_boundary() {
        let (config, mut state, alice, bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let mut constraints = session_constraints();
        constraints.lifetime_epochs = 2;
        let install = install_session_key_tx(&alice, &session, 1, constraints);
        state.execute_transaction(&install, &config).unwrap();

        // Valid through the expiry epoch (inclusive). Advancing the epoch is a
        // deterministic integer step; expiry never reads a wall clock.
        state.current_epoch = 2;
        let at_expiry = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            2,
            bob.address(),
            Amount::from_webc(1),
            small_fee(),
        );
        state.execute_transaction(&at_expiry, &config).unwrap();

        // One epoch later the key is expired and cannot authorize.
        state.current_epoch = 3;
        let after_expiry = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            3,
            bob.address(),
            Amount::from_webc(1),
            small_fee(),
        );
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&after_expiry, &config),
            Err(ChainError::SessionKeyExpired)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn session_key_cannot_authorize_a_non_transfer_operation() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let install = install_session_key_tx(&alice, &session, 1, session_constraints());
        state.execute_transaction(&install, &config).unwrap();

        // A claim operation is not in the session allow-list and is refused
        // before any state change, even though the key is otherwise valid.
        let operation = Operation::ClaimValidatorRewards;
        let id = SessionKeyId::derive(&session.public_key());
        let access_list = operation
            .default_access_list_for_session(alice.address(), AuthorizationLaneId::DEFAULT, id)
            .unwrap();
        let mut tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            alice.address(),
            session.public_key(),
            AuthorizationLaneId::DEFAULT,
            AuthorizationPolicyRevision::new(1),
            2,
            operation,
            access_list,
            small_fee_with_units(10_000),
        );
        tx.sign_with_policy_key(&session).unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::SessionKeyOperationNotPermitted)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn session_key_bound_lane_mismatch_is_rejected() {
        let (config, mut state, alice, bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let bound_lane = AuthorizationLaneId::new(Hash256([0x77; 32]));
        let mut constraints = session_constraints();
        constraints.authorization_lane = bound_lane;
        let install = install_session_key_tx(&alice, &session, 1, constraints);
        state.execute_transaction(&install, &config).unwrap();

        // The key is bound to `bound_lane`; a transfer on the default lane is
        // refused during authorization, before any fee or state change.
        let wrong_lane = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            2,
            bob.address(),
            Amount::from_webc(1),
            small_fee(),
        );
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&wrong_lane, &config),
            Err(ChainError::SessionKeyLaneMismatch)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn session_key_is_invalidated_when_bound_policy_revision_changes() {
        let (config, mut state, alice, bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let id = SessionKeyId::derive(&session.public_key());
        let install = install_session_key_tx(&alice, &session, 1, session_constraints());
        state.execute_transaction(&install, &config).unwrap();

        // A key rotation bumps the account policy revision. Simulate the stored
        // effect: the session was installed under revision 1, so a policy now at
        // revision 2 must invalidate it.
        state
            .session_keys
            .get_mut(&(alice.address(), id))
            .unwrap()
            .policy_revision = AuthorizationPolicyRevision::new(2);
        let transfer = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            2,
            bob.address(),
            Amount::from_webc(1),
            small_fee(),
        );
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&transfer, &config),
            Err(ChainError::AuthorizationKeyMismatch)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn install_session_key_fail_closed_paths() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);

        // Wrong post-quantum root reveal: a well-formed reveal whose public key
        // does not match the committed root, so the commitment check rejects it
        // before any signature verification.
        let bad_reveal = PostQuantumRootReveal {
            scheme: PostQuantumScheme::MlDsa65,
            public_key: vec![0xC4u8; 1_952],
            signature: vec![0u8; ML_DSA_65_SIGNATURE_LEN],
        };
        let install_bad = install_session_key_tx_with_reveal(
            &alice,
            &session,
            1,
            session_constraints(),
            bad_reveal,
        );
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&install_bad, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // Lifetime beyond the configured maximum.
        let mut too_long = session_constraints();
        too_long.lifetime_epochs = config.session_keys.max_lifetime_epochs + 1;
        let install_long = install_session_key_tx(&alice, &session, 1, too_long);
        assert!(matches!(
            state.execute_transaction(&install_long, &config),
            Err(ChainError::SessionKeyLifetimeTooLong)
        ));

        // Invalid constraints (budget below per-use).
        let mut invalid = session_constraints();
        invalid.total_amount_budget = Amount::from_webc(1);
        let install_invalid = install_session_key_tx(&alice, &session, 1, invalid);
        assert!(matches!(
            state.execute_transaction(&install_invalid, &config),
            Err(ChainError::InvalidSessionKeyConstraints)
        ));

        // Duplicate installation is rejected.
        let install = install_session_key_tx(&alice, &session, 1, session_constraints());
        state.execute_transaction(&install, &config).unwrap();
        let dup = install_session_key_tx(&alice, &session, 2, session_constraints());
        assert!(matches!(
            state.execute_transaction(&dup, &config),
            Err(ChainError::SessionKeyAlreadyExists)
        ));
    }

    /// The root-signature gate must reject a reveal that does not carry a real
    /// ML-DSA signature by the committed root over this exact install. These are
    /// the attacks the commitment-only reveal could not stop.
    #[test]
    fn install_session_key_rejects_misbound_or_forged_root_signature() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let constraints = session_constraints();
        let before = state.clone();

        // (a) Correct root key and action, but signed for a different nonce than
        // the transaction runs at: a captured signature cannot be replayed at a
        // new nonce because the message binds the nonce.
        let wrong_nonce = install_reveal(alice.address(), 2, session.public_key(), &constraints);
        let install_wrong_nonce = install_session_key_tx_with_reveal(
            &alice,
            &session,
            1,
            constraints.clone(),
            wrong_nonce,
        );
        assert!(matches!(
            state.execute_transaction(&install_wrong_nonce, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (b) A real signature over a *different action* (a revoke) cannot be
        // repurposed to authorize this install.
        let wrong_action = revoke_reveal(
            alice.address(),
            1,
            SessionKeyId::derive(&session.public_key()),
        );
        let install_wrong_action = install_session_key_tx_with_reveal(
            &alice,
            &session,
            1,
            constraints.clone(),
            wrong_action,
        );
        assert!(matches!(
            state.execute_transaction(&install_wrong_action, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (c) The committed public key but a garbage signature of the right
        // length: the commitment check passes, the signature check fails closed.
        let garbage = PostQuantumRootReveal {
            scheme: PostQuantumScheme::MlDsa65,
            public_key: pq_public_key(),
            signature: vec![0x7u8; ML_DSA_65_SIGNATURE_LEN],
        };
        let install_garbage =
            install_session_key_tx_with_reveal(&alice, &session, 1, constraints.clone(), garbage);
        assert!(matches!(
            state.execute_transaction(&install_garbage, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (d) A *different* ML-DSA key with a genuine signature over the correct
        // message: this models a compromised active key trying to substitute its
        // own post-quantum key. The commitment check binds the reveal to the
        // account's committed root, so it is rejected.
        let (other_public, other_secret) = ml_dsa65_keygen().unwrap();
        let action = SessionKeyAuthorizationAction::Install {
            session_public_key: session.public_key(),
            constraints: constraints.clone(),
        };
        let message = session_key_authorization_message(
            &ChainId::devnet(),
            alice.address(),
            AuthorizationPolicyRevision::new(1),
            1,
            &action,
        )
        .unwrap();
        let wrong_key = PostQuantumRootReveal {
            scheme: PostQuantumScheme::MlDsa65,
            public_key: other_public.to_bytes(),
            signature: other_secret.sign(&message, b"").unwrap(),
        };
        let install_wrong_key =
            install_session_key_tx_with_reveal(&alice, &session, 1, constraints, wrong_key);
        assert!(matches!(
            state.execute_transaction(&install_wrong_key, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // The correctly bound install still succeeds, so the gate is not simply
        // rejecting everything.
        let good = install_session_key_tx(&alice, &session, 1, session_constraints());
        state.execute_transaction(&good, &config).unwrap();
        assert!(state
            .session_keys
            .contains_key(&(alice.address(), SessionKeyId::derive(&session.public_key()))));
    }

    /// The install root signature must bind the exact constraints, the owner, and
    /// the chain id — not just the nonce and action. Each sub-case signs a message
    /// that disagrees with the submitted transaction on exactly one axis and must
    /// be rejected, so a future regression that drops any binding is caught.
    #[test]
    fn install_session_key_binds_signature_to_constraints_owner_and_chain() {
        let (config, mut state, alice, bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let revision = AuthorizationPolicyRevision::new(1);
        let before = state.clone();

        // (a) Constraint escalation: sign a modest grant but submit a larger one.
        // The chain rebuilds the message from the *submitted* constraints, so the
        // signature over the smaller grant does not verify.
        let signed_constraints = session_constraints();
        let mut submitted_constraints = session_constraints();
        submitted_constraints.max_amount_per_use = Amount::from_webc(4);
        submitted_constraints.total_amount_budget = Amount::from_webc(80);
        assert_ne!(signed_constraints, submitted_constraints);
        let signed_action = SessionKeyAuthorizationAction::Install {
            session_public_key: session.public_key(),
            constraints: signed_constraints,
        };
        let message = session_key_authorization_message(
            &ChainId::devnet(),
            alice.address(),
            revision,
            1,
            &signed_action,
        )
        .unwrap();
        let install_escalated = install_session_key_tx_with_reveal(
            &alice,
            &session,
            1,
            submitted_constraints,
            reveal_over_message(&message),
        );
        assert!(matches!(
            state.execute_transaction(&install_escalated, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // The correctly bound install action, reused for the owner and chain axes.
        let action = SessionKeyAuthorizationAction::Install {
            session_public_key: session.public_key(),
            constraints: session_constraints(),
        };

        // (b) Cross-account replay: sign with a different owner than the submitting
        // account. Even if two accounts shared a post-quantum root, the owner
        // binding stops a signature made for one account authorizing the other.
        let wrong_owner_message = session_key_authorization_message(
            &ChainId::devnet(),
            bob.address(),
            revision,
            1,
            &action,
        )
        .unwrap();
        let install_wrong_owner = install_session_key_tx_with_reveal(
            &alice,
            &session,
            1,
            session_constraints(),
            reveal_over_message(&wrong_owner_message),
        );
        assert!(matches!(
            state.execute_transaction(&install_wrong_owner, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (c) Cross-chain replay: sign for a different chain id than the one the
        // transaction executes on.
        let other_chain = ChainId::new("webc-testnet-9").unwrap();
        let wrong_chain_message =
            session_key_authorization_message(&other_chain, alice.address(), revision, 1, &action)
                .unwrap();
        let install_wrong_chain = install_session_key_tx_with_reveal(
            &alice,
            &session,
            1,
            session_constraints(),
            reveal_over_message(&wrong_chain_message),
        );
        assert!(matches!(
            state.execute_transaction(&install_wrong_chain, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);
    }

    /// The revoke gate binds the root signature to the exact session-key id, so a
    /// signature prepared for another id cannot revoke this one.
    #[test]
    fn revoke_session_key_rejects_misbound_root_signature() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let id = SessionKeyId::derive(&session.public_key());
        let install = install_session_key_tx(&alice, &session, 1, session_constraints());
        state.execute_transaction(&install, &config).unwrap();

        // Revoke at nonce 2 with a reveal signed for a different session-key id.
        let other_id = SessionKeyId::new(Hash256([0x33; 32]));
        let revoke = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(1),
            2,
            Operation::RevokeSessionKey {
                session_key: id,
                post_quantum_root_reveal: revoke_reveal(alice.address(), 2, other_id),
            },
            small_fee_with_units(20_000),
        )
        .unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&revoke, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);
        // The key is still installed because the misbound revoke was rejected.
        assert!(state.session_keys.contains_key(&(alice.address(), id)));
    }

    #[test]
    fn session_key_management_requires_default_lane() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let lane = AuthorizationLaneId::new(Hash256([0x55; 32]));
        // Open a funded non-default lane so its nonce/fee lookup succeeds and the
        // critical-action default-lane guard is the check that actually fires.
        let open = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(1),
            1,
            Operation::OpenAuthorizationLane {
                lane,
                fee_deposit: Amount::from_webc(1),
            },
            small_fee_with_units(10_000),
        )
        .unwrap();
        state.execute_transaction(&open, &config).unwrap();

        let session = Keypair::from_seed([9u8; 32]);
        let operation = Operation::InstallSessionKey {
            session_public_key: session.public_key(),
            constraints: session_constraints(),
            // Rejected by the default-lane guard before the reveal is verified.
            post_quantum_root_reveal: unverified_reveal(),
        };
        let access_list = operation
            .default_access_list_for_lane(alice.address(), lane)
            .unwrap();
        let mut tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            alice.address(),
            alice.public_key(),
            lane,
            AuthorizationPolicyRevision::new(1),
            0,
            operation,
            access_list,
            small_fee_with_units(20_000),
        );
        tx.sign_with_policy_key(&alice).unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::SessionKeyManagementRequiresDefaultLane)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn legacy_account_cannot_own_session_keys() {
        let (config, mut state, alice, _bob) = funded_state();
        let session = Keypair::from_seed([9u8; 32]);
        // Alice has no installed policy, so `for_operation` uses revision zero.
        let install = Transaction::for_operation(
            &alice,
            0,
            Operation::InstallSessionKey {
                session_public_key: session.public_key(),
                constraints: session_constraints(),
                // Rejected for having no installed policy before reveal checks.
                post_quantum_root_reveal: unverified_reveal(),
            },
            small_fee_with_units(20_000),
        )
        .unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&install, &config),
            Err(ChainError::SessionKeyRequiresInstalledPolicy)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn session_key_count_cap_is_enforced() {
        let (mut config, mut state, alice, _bob) = installed_policy_state();
        config.session_keys.max_session_keys_per_account = 2;
        for (i, seed) in [[10u8; 32], [11u8; 32]].into_iter().enumerate() {
            let session = Keypair::from_seed(seed);
            let install =
                install_session_key_tx(&alice, &session, 1 + i as u64, session_constraints());
            state.execute_transaction(&install, &config).unwrap();
        }
        let third = Keypair::from_seed([12u8; 32]);
        let install = install_session_key_tx(&alice, &third, 3, session_constraints());
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&install, &config),
            Err(ChainError::SessionKeyLimitExceeded)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn revoke_unknown_session_key_is_rejected() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let missing = SessionKeyId::new(Hash256([0xEE; 32]));
        let revoke = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(1),
            1,
            Operation::RevokeSessionKey {
                session_key: missing,
                post_quantum_root_reveal: revoke_reveal(alice.address(), 1, missing),
            },
            small_fee_with_units(20_000),
        )
        .unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&revoke, &config),
            Err(ChainError::SessionKeyNotFound)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn session_keys_survive_serialization_restart() {
        let (config, mut state, alice, bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let install = install_session_key_tx(&alice, &session, 1, session_constraints());
        state.execute_transaction(&install, &config).unwrap();
        let transfer = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            2,
            bob.address(),
            Amount::from_webc(3),
            small_fee(),
        );
        state.execute_transaction(&transfer, &config).unwrap();

        // The whole chain state uses tuple-keyed maps, so it round-trips through
        // bincode (a non-string-key format) rather than JSON.
        let bytes = bincode::serialize(&state).unwrap();
        let restored: ChainState = bincode::deserialize(&bytes).unwrap();
        assert_eq!(restored, state);
        assert_eq!(restored.state_root().unwrap(), state.state_root().unwrap());
    }

    #[test]
    fn cumulative_fee_budget_bounds_a_compromised_key() {
        let (config, mut state, alice, bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let id = SessionKeyId::derive(&session.public_key());
        // Tiny principal, but a cumulative fee budget of 3,000 base units. Each
        // transfer below charges exactly 1,000 base units in real fees.
        let mut constraints = session_constraints();
        constraints.max_fee_per_use = Amount::from_units(2_000);
        constraints.total_fee_budget = Amount::from_units(3_000);
        let install = install_session_key_tx(&alice, &session, 1, constraints);
        state.execute_transaction(&install, &config).unwrap();

        // A fee bid that charges 1,000 base units per transfer (500 units * 2).
        let drain_fee = FeeBid {
            gas_limit: 500,
            max_fee_per_unit: 2,
            priority_fee_per_unit: 2,
        };
        for nonce in [2u64, 3, 4] {
            let tx = session_transfer_tx(
                &alice,
                &session,
                AuthorizationLaneId::DEFAULT,
                nonce,
                bob.address(),
                Amount::from_units(1),
                drain_fee,
            );
            state.execute_transaction(&tx, &config).unwrap();
        }
        assert_eq!(
            state.session_keys[&(alice.address(), id)].spent_fees,
            Amount::from_units(3_000)
        );

        // The fourth transfer would push cumulative fees to 4,000 > 3,000 and is
        // rejected, so the total fee drain is bounded regardless of use count.
        let over = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            5,
            bob.address(),
            Amount::from_units(1),
            drain_fee,
        );
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&over, &config),
            Err(ChainError::SessionKeyFeeBudgetExceeded)
        ));
        assert_eq!(state, before);
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn session_transfer_works_on_a_bound_non_default_lane() {
        let (config, mut state, alice, bob) = installed_policy_state();
        let lane = AuthorizationLaneId::new(Hash256::digest(b"origin-lane"));
        // Open and fund the origin lane from the default lane.
        let open = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(1),
            1,
            Operation::OpenAuthorizationLane {
                lane,
                fee_deposit: Amount::from_webc(1),
            },
            small_fee_with_units(10_000),
        )
        .unwrap();
        state.execute_transaction(&open, &config).unwrap();

        // Install a session key bound to that lane.
        let session = Keypair::from_seed([9u8; 32]);
        let id = SessionKeyId::derive(&session.public_key());
        let mut constraints = session_constraints();
        constraints.authorization_lane = lane;
        let install = install_session_key_tx(&alice, &session, 2, constraints);
        state.execute_transaction(&install, &config).unwrap();

        // A session transfer on the bound lane succeeds: principal leaves the
        // owner account, the lane nonce advances, and cumulative spend updates.
        let transfer = session_transfer_tx(
            &alice,
            &session,
            lane,
            0,
            bob.address(),
            Amount::from_webc(3),
            small_fee(),
        );
        state.execute_transaction(&transfer, &config).unwrap();
        assert_eq!(
            state.accounts.get(&bob.address()).unwrap().balance,
            Amount::from_webc(3)
        );
        assert_eq!(
            state.session_keys[&(alice.address(), id)].spent_amount,
            Amount::from_webc(3)
        );
        assert_eq!(
            state.authorization_lanes[&(alice.address(), lane)].next_nonce,
            Nonce::new(1)
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]
        #[test]
        fn session_spend_never_exceeds_budget(
            amounts in proptest::collection::vec(1u64..8, 1..24)
        ) {
            let (config, mut state, alice, bob) = installed_policy_state();
            let session = Keypair::from_seed([9u8; 32]);
            let id = SessionKeyId::derive(&session.public_key());
            let install = install_session_key_tx(
                &alice, &session, 1, session_constraints());
            state.execute_transaction(&install, &config).unwrap();

            let per_use = Amount::from_webc(5);
            let budget = Amount::from_webc(20);
            let mut expected_spent = Amount::ZERO;
            let mut nonce = 2u64;
            for raw in amounts {
                let amount = Amount::from_webc(raw);
                let next = expected_spent.checked_add(amount).unwrap();
                let accepted = amount <= per_use && next <= budget;
                let tx = session_transfer_tx(
                    &alice, &session, AuthorizationLaneId::DEFAULT,
                    nonce, bob.address(), amount, small_fee());
                let before = state.clone();
                let result = state.execute_transaction(&tx, &config);
                if accepted {
                    prop_assert!(result.is_ok());
                    expected_spent = next;
                    nonce += 1;
                } else {
                    prop_assert!(result.is_err());
                    prop_assert_eq!(&state, &before);
                }
                prop_assert_eq!(
                    state.session_keys[&(alice.address(), id)].spent_amount,
                    expected_spent
                );
                prop_assert!(state.session_keys[&(alice.address(), id)].spent_amount <= budget);
                prop_assert!(state.supply_invariant_report().unwrap().balanced);
            }
        }
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

        // An authorization revision beyond the JS-safe wire bound (which equals
        // MAX_AUTHORIZATION_POLICY_REVISION = 2^53-1) can no longer even be
        // signed: the canonical encoder rejects the out-of-range integer (X3), a
        // stricter and earlier guard than the execution-time range check. The
        // transaction therefore never becomes a valid signed payload and cannot
        // reach a state commit.
        let mut over_range = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: alice.address(),
                amount: Amount::from_units(1),
            },
            FeeBid::default(),
        )
        .unwrap();
        over_range.authorization_policy_revision =
            AuthorizationPolicyRevision::new(MAX_AUTHORIZATION_POLICY_REVISION + 1);
        assert!(matches!(
            over_range.sign(&alice),
            Err(ChainError::CanonicalIntegerOutOfSafeRange)
        ));
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
    fn storage_deposit_locks_on_create_resizes_on_mutate_and_refunds_on_delete() {
        // §15.22: writing object state locks a refundable native deposit
        // proportional to stored bytes; deleting refunds the majority and burns
        // the occupancy remainder. Supply must reconcile at every step.
        let (config, mut state, alice, _bob) = funded_state();
        let namespace = Hash256::digest(b"deposit-ns");
        let object_id = ObjectId::new(Hash256::digest(b"deposit-obj"));
        let per_byte = config.storage_pricing.deposit_per_byte;
        assert!(per_byte > 0, "default pricing must lock a real deposit");
        let deposit_for = |len: usize| Amount::from_units(u128::from(per_byte) * len as u128);
        let issued = state.minted_supply;
        let assert_balanced = |s: &ChainState| {
            assert!(
                s.supply_invariant_report().expect("report").balanced,
                "supply must reconcile"
            );
        };

        let fee = FeeBid {
            gas_limit: 30_000,
            max_fee_per_unit: 1,
            priority_fee_per_unit: 0,
        };

        // --- Create: liquid -> storage_deposits ---
        let liquid_before = state.accounts[&alice.address()].balance;
        let create = Transaction::for_operation(
            &alice,
            0,
            Operation::CreateObject {
                object_id,
                namespace,
                data: vec![0u8; 10],
            },
            fee,
        )
        .expect("create signs");
        let create_fee = Amount::from_units(u128::from(create.required_units())); // base fee 1/unit
        state
            .execute_transaction(&create, &config)
            .expect("object created");
        assert_eq!(state.storage_deposits, deposit_for(10));
        assert_eq!(state.objects[&object_id].deposit, deposit_for(10));
        assert_eq!(
            state.accounts[&alice.address()].balance,
            liquid_before
                .checked_sub(create_fee)
                .and_then(|b| b.checked_sub(deposit_for(10)))
                .unwrap(),
            "create must debit both the fee and the storage deposit"
        );
        assert_eq!(state.minted_supply, issued, "create mints no supply");
        assert_balanced(&state);

        // --- Mutate grow: 10 -> 30 bytes locks the extra ---
        let liquid_before = state.accounts[&alice.address()].balance;
        let grow = Transaction::for_operation(
            &alice,
            1,
            Operation::MutateObject {
                object_id,
                namespace,
                expected_version: ObjectVersion::INITIAL,
                data: vec![0u8; 30],
            },
            fee,
        )
        .expect("grow signs");
        let grow_fee = Amount::from_units(u128::from(grow.required_units()));
        state.execute_transaction(&grow, &config).expect("grew");
        assert_eq!(state.storage_deposits, deposit_for(30));
        assert_eq!(state.objects[&object_id].deposit, deposit_for(30));
        let extra = deposit_for(30).checked_sub(deposit_for(10)).unwrap();
        assert_eq!(
            state.accounts[&alice.address()].balance,
            liquid_before
                .checked_sub(grow_fee)
                .and_then(|b| b.checked_sub(extra))
                .unwrap(),
        );
        assert_balanced(&state);

        // --- Mutate shrink: 30 -> 5 bytes refunds the difference ---
        let liquid_before = state.accounts[&alice.address()].balance;
        let shrink = Transaction::for_operation(
            &alice,
            2,
            Operation::MutateObject {
                object_id,
                namespace,
                expected_version: ObjectVersion::new(2),
                data: vec![0u8; 5],
            },
            fee,
        )
        .expect("shrink signs");
        let shrink_fee = Amount::from_units(u128::from(shrink.required_units()));
        state.execute_transaction(&shrink, &config).expect("shrank");
        assert_eq!(state.storage_deposits, deposit_for(5));
        assert_eq!(state.objects[&object_id].deposit, deposit_for(5));
        let refunded = deposit_for(30).checked_sub(deposit_for(5)).unwrap();
        assert_eq!(
            state.accounts[&alice.address()].balance,
            liquid_before
                .checked_sub(shrink_fee)
                .and_then(|b| b.checked_add(refunded))
                .unwrap(),
        );
        assert_balanced(&state);

        // --- Delete: storage_deposits -> refund + burned ---
        let liquid_before = state.accounts[&alice.address()].balance;
        let burned_before = state.burned_fees;
        let split = config
            .storage_pricing
            .refund_split(deposit_for(5))
            .expect("split");
        assert_eq!(
            split.refund.checked_add(split.burned).unwrap(),
            deposit_for(5)
        );
        assert!(
            !split.burned.is_zero(),
            "occupancy fee must burn a remainder"
        );
        let delete = Transaction::for_operation(
            &alice,
            3,
            Operation::DeleteObject {
                object_id,
                namespace,
                expected_version: ObjectVersion::new(3),
            },
            fee,
        )
        .expect("delete signs");
        let delete_fee = Amount::from_units(u128::from(delete.required_units()));
        let receipt = state
            .execute_transaction(&delete, &config)
            .expect("deleted");
        assert!(!state.objects.contains_key(&object_id), "object removed");
        assert_eq!(state.storage_deposits, Amount::ZERO);
        assert!(receipt.events.iter().any(|event| matches!(
            event,
            Event::ObjectDeleted { refund, burned, .. }
                if *refund == split.refund && *burned == split.burned
        )));
        // The delete fee burns half its fee too, so account for both burn sources.
        let delete_fee_burn = split_fee(delete_fee).burned;
        assert_eq!(
            state.burned_fees,
            burned_before
                .checked_add(split.burned)
                .and_then(|b| b.checked_add(delete_fee_burn))
                .unwrap(),
            "deletion burns the occupancy remainder plus the fee burn"
        );
        assert_eq!(
            state.accounts[&alice.address()].balance,
            liquid_before
                .checked_sub(delete_fee)
                .and_then(|b| b.checked_add(split.refund))
                .unwrap(),
            "owner is refunded the majority of the deposit"
        );
        assert_eq!(state.minted_supply, issued, "delete mints no supply");
        assert_balanced(&state);
    }

    #[test]
    fn insufficient_balance_storage_deposit_create_fails_closed() {
        // A creator who cannot afford the storage deposit fails closed and leaves
        // no partial object or deposit behind (the whole transaction rolls back).
        let (config, mut state, alice, bob) = funded_state();
        // Fund bob with just enough for one fee but far less than a big deposit.
        let seed = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_units(30_000),
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("seed signs");
        state
            .execute_transaction(&seed, &config)
            .expect("bob funded");

        let namespace = Hash256::digest(b"poor-ns");
        let object_id = ObjectId::new(Hash256::digest(b"poor-obj"));
        // Deposit for 100 bytes = 100_000 base units, above bob's post-fee balance.
        let create = Transaction::for_operation(
            &bob,
            0,
            Operation::CreateObject {
                object_id,
                namespace,
                data: vec![0u8; 100],
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("create signs");
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&create, &config),
            Err(ChainError::InsufficientBalance { .. })
        ));
        assert_eq!(state, before, "failed create leaves no partial state");
        assert!(!state.objects.contains_key(&object_id));
        assert_eq!(state.storage_deposits, Amount::ZERO);
        assert!(state.supply_invariant_report().expect("report").balanced);
    }

    #[test]
    fn storage_deposits_survive_bincode_restart_with_stable_state_root() {
        // A crash-restart (bincode round-trip of the whole state) must preserve
        // the locked storage deposits and the committed state root, so a node
        // cannot silently diverge on the new bucket after reloading from disk.
        let (config, mut state, alice, _bob) = funded_state();
        let namespace = Hash256::digest(b"restart-ns");
        let object_id = ObjectId::new(Hash256::digest(b"restart-obj"));
        let create = Transaction::for_operation(
            &alice,
            0,
            Operation::CreateObject {
                object_id,
                namespace,
                data: vec![7u8; 42],
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
            .expect("created");
        assert!(!state.storage_deposits.is_zero());

        let bytes = bincode::serialize(&state).expect("state serializes");
        let restored: ChainState = bincode::deserialize(&bytes).expect("state deserializes");
        assert_eq!(restored.storage_deposits, state.storage_deposits);
        assert_eq!(
            restored.objects[&object_id].deposit,
            state.objects[&object_id].deposit
        );
        assert_eq!(restored, state, "restart preserves full state");
        assert_eq!(
            restored.state_root().expect("restored root"),
            state.state_root().expect("root"),
            "storage_deposits is committed by the state root across a restart"
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

    // ----- active-key rotation (recovery) tests -----

    /// A rotation reveal: the post-quantum root signs the exact rotation to
    /// `new_key` at `nonce` under Alice's installed policy (revision 1), matching
    /// what the state machine rebuilds and verifies.
    fn rotation_reveal(
        owner: Address,
        nonce: u64,
        new_key: &PublicKeyBytes,
    ) -> PostQuantumRootReveal {
        let message = crate::active_key_rotation_message(
            &ChainId::devnet(),
            owner,
            AuthorizationPolicyRevision::new(1),
            nonce,
            new_key,
        )
        .unwrap();
        reveal_over_message(&message)
    }

    /// Builds a default-lane rotation transaction whose envelope is signed by
    /// `signer` (the new key for recovery, or the current active key for an
    /// ordinary rotation) and carries `reveal` as the root authority.
    fn rotate_key_tx(
        owner: &Keypair,
        signer: &Keypair,
        nonce: u64,
        new_key: PublicKeyBytes,
        reveal: PostQuantumRootReveal,
    ) -> Transaction {
        let operation = Operation::RotateActiveTransactionKey {
            new_active_transaction_key: new_key,
            post_quantum_root_reveal: reveal,
        };
        let access_list = operation
            .default_access_list_for_lane(owner.address(), AuthorizationLaneId::DEFAULT)
            .unwrap();
        let mut tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            owner.address(),
            signer.public_key(),
            AuthorizationLaneId::DEFAULT,
            AuthorizationPolicyRevision::new(1),
            nonce,
            operation,
            access_list,
            small_fee_with_units(25_000),
        );
        tx.sign_with_policy_key(signer).unwrap();
        tx
    }

    #[test]
    fn active_key_rotation_recovers_with_the_new_key_and_invalidates_sessions() {
        let (config, mut state, alice, bob) = installed_policy_state();
        // Install a session key under revision 1; rotation must invalidate it.
        let session = Keypair::from_seed([9u8; 32]);
        let session_id = SessionKeyId::derive(&session.public_key());
        let install = install_session_key_tx(&alice, &session, 1, session_constraints());
        state.execute_transaction(&install, &config).unwrap();
        assert!(state
            .session_keys
            .contains_key(&(alice.address(), session_id)));

        let new_key = Keypair::from_seed([42u8; 32]);
        let before_root = state.state_root().unwrap();
        // Recovery: the NEW key signs the envelope (the old key is never used) and
        // the real authority is the post-quantum root signature.
        let rotate = rotate_key_tx(
            &alice,
            &new_key,
            2,
            new_key.public_key(),
            rotation_reveal(alice.address(), 2, &new_key.public_key()),
        );
        state.execute_transaction(&rotate, &config).unwrap();

        let policy = state.authorization_policies.get(&alice.address()).unwrap();
        assert_eq!(policy.active_transaction_key(), &new_key.public_key());
        assert_eq!(policy.revision(), AuthorizationPolicyRevision::new(2));
        // The recovery root is preserved, never silently dropped.
        assert_eq!(
            *policy.post_quantum_root(),
            PostQuantumRoot::from_public_key(PostQuantumScheme::MlDsa65, &pq_public_key()).unwrap()
        );
        assert_ne!(state.state_root().unwrap(), before_root);
        assert!(state.supply_invariant_report().unwrap().balanced);

        // The session key installed under revision 1 can no longer be used: the
        // policy is now at revision 2, so a transfer it signs fails.
        let session_tx = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            3,
            bob.address(),
            Amount::from_webc(1),
            small_fee(),
        );
        assert!(matches!(
            state.execute_transaction(&session_tx, &config),
            Err(ChainError::AuthorizationPolicyRevisionMismatch { .. })
        ));

        // The new active key authorizes an ordinary transfer at revision 2.
        let operation = Operation::Transfer {
            to: bob.address(),
            amount: Amount::from_webc(1),
        };
        let access_list = operation
            .default_access_list_for_lane(alice.address(), AuthorizationLaneId::DEFAULT)
            .unwrap();
        let mut new_tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            alice.address(),
            new_key.public_key(),
            AuthorizationLaneId::DEFAULT,
            AuthorizationPolicyRevision::new(2),
            3,
            operation,
            access_list,
            small_fee(),
        );
        new_tx.sign_with_policy_key(&new_key).unwrap();
        state.execute_transaction(&new_tx, &config).unwrap();
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn active_key_rotation_also_works_when_signed_by_the_current_key() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let new_key = Keypair::from_seed([42u8; 32]);
        // Ordinary rotation: the CURRENT active key signs the envelope (the
        // AccountKey authorization path), still gated by the root signature.
        let rotate = rotate_key_tx(
            &alice,
            &alice,
            1,
            new_key.public_key(),
            rotation_reveal(alice.address(), 1, &new_key.public_key()),
        );
        state.execute_transaction(&rotate, &config).unwrap();
        let policy = state.authorization_policies.get(&alice.address()).unwrap();
        assert_eq!(policy.active_transaction_key(), &new_key.public_key());
        assert_eq!(policy.revision(), AuthorizationPolicyRevision::new(2));

        // The old active key can no longer authorize a transfer.
        let old_key_tx = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(2),
            2,
            Operation::Transfer {
                to: _bob.address(),
                amount: Amount::from_webc(1),
            },
            small_fee(),
        )
        .unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&old_key_tx, &config),
            Err(ChainError::AuthorizationKeyMismatch)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn active_key_rotation_rejects_rotating_to_the_same_key() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let same = alice.public_key();
        // The current active key signs a rotation whose new key equals the old
        // one; the no-op guard fires before the (valid) root signature is checked.
        let rotate = rotate_key_tx(
            &alice,
            &alice,
            1,
            same,
            rotation_reveal(alice.address(), 1, &same),
        );
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&rotate, &config),
            Err(ChainError::ActiveKeyRotationToSameKey)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn active_key_rotation_requires_default_lane() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let lane = AuthorizationLaneId::new(Hash256([0x55; 32]));
        let open = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(1),
            1,
            Operation::OpenAuthorizationLane {
                lane,
                fee_deposit: Amount::from_webc(1),
            },
            small_fee_with_units(10_000),
        )
        .unwrap();
        state.execute_transaction(&open, &config).unwrap();

        let new_key = Keypair::from_seed([42u8; 32]);
        let operation = Operation::RotateActiveTransactionKey {
            new_active_transaction_key: new_key.public_key(),
            // Rejected by the default-lane guard before the reveal is verified.
            post_quantum_root_reveal: unverified_reveal(),
        };
        let access_list = operation
            .default_access_list_for_lane(alice.address(), lane)
            .unwrap();
        let mut tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            alice.address(),
            alice.public_key(),
            lane,
            AuthorizationPolicyRevision::new(1),
            0,
            operation,
            access_list,
            small_fee_with_units(25_000),
        );
        tx.sign_with_policy_key(&alice).unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::ActiveKeyRotationRequiresDefaultLane)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn active_key_rotation_requires_an_installed_policy() {
        let (config, mut state, alice, _bob) = funded_state();
        let new_key = Keypair::from_seed([42u8; 32]);
        // No policy is installed, so the account is still on the legacy revision.
        // Signing with the address-deriving key at the legacy revision lets the
        // authorization check pass so the arm's installed-policy guard is what
        // actually fires.
        let operation = Operation::RotateActiveTransactionKey {
            new_active_transaction_key: new_key.public_key(),
            post_quantum_root_reveal: unverified_reveal(),
        };
        let access_list = operation
            .default_access_list_for_lane(alice.address(), AuthorizationLaneId::DEFAULT)
            .unwrap();
        let mut tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            alice.address(),
            alice.public_key(),
            AuthorizationLaneId::DEFAULT,
            LEGACY_AUTHORIZATION_POLICY_REVISION,
            0,
            operation,
            access_list,
            small_fee_with_units(25_000),
        );
        tx.sign_with_policy_key(&alice).unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::ActiveKeyRotationRequiresInstalledPolicy)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn active_key_rotation_rejects_a_third_party_envelope_signer() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let new_key = Keypair::from_seed([42u8; 32]);
        let stranger = Keypair::from_seed([44u8; 32]);
        // The envelope is signed by a key that is neither the current active key
        // nor the proposed new key; authorization fails before execution.
        let rotate = rotate_key_tx(
            &alice,
            &stranger,
            1,
            new_key.public_key(),
            rotation_reveal(alice.address(), 1, &new_key.public_key()),
        );
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&rotate, &config),
            Err(ChainError::AuthorizationKeyMismatch)
        ));
        assert_eq!(state, before);
    }

    /// The root-signature gate must reject any reveal that is not a real ML-DSA
    /// signature by the committed root over this exact rotation. Every binding
    /// axis (new key, nonce, owner, chain) and forgery is checked, and each
    /// rejection leaves state unchanged.
    #[test]
    fn active_key_rotation_rejects_misbound_or_forged_root_signature() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let new_key = Keypair::from_seed([42u8; 32]);
        let before = state.clone();

        // (a) Signed for a different new key.
        let other_key = Keypair::from_seed([43u8; 32]);
        let tx_a = rotate_key_tx(
            &alice,
            &new_key,
            1,
            new_key.public_key(),
            rotation_reveal(alice.address(), 1, &other_key.public_key()),
        );
        assert!(matches!(
            state.execute_transaction(&tx_a, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (b) Signed for a different nonce: no replay at another nonce.
        let tx_b = rotate_key_tx(
            &alice,
            &new_key,
            1,
            new_key.public_key(),
            rotation_reveal(alice.address(), 2, &new_key.public_key()),
        );
        assert!(matches!(
            state.execute_transaction(&tx_b, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (c) Signed for a different owner: no cross-account reuse.
        let stranger = Keypair::from_seed([44u8; 32]);
        let wrong_owner_msg = crate::active_key_rotation_message(
            &ChainId::devnet(),
            stranger.address(),
            AuthorizationPolicyRevision::new(1),
            1,
            &new_key.public_key(),
        )
        .unwrap();
        let tx_c = rotate_key_tx(
            &alice,
            &new_key,
            1,
            new_key.public_key(),
            reveal_over_message(&wrong_owner_msg),
        );
        assert!(matches!(
            state.execute_transaction(&tx_c, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (d) Signed for a different chain: no cross-chain reuse.
        let wrong_chain_msg = crate::active_key_rotation_message(
            &ChainId::new("webc-testnet-9").unwrap(),
            alice.address(),
            AuthorizationPolicyRevision::new(1),
            1,
            &new_key.public_key(),
        )
        .unwrap();
        let tx_d = rotate_key_tx(
            &alice,
            &new_key,
            1,
            new_key.public_key(),
            reveal_over_message(&wrong_chain_msg),
        );
        assert!(matches!(
            state.execute_transaction(&tx_d, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (e) The committed public key but a garbage signature of the right
        // length: the commitment check passes, the signature check fails closed.
        let garbage = PostQuantumRootReveal {
            scheme: PostQuantumScheme::MlDsa65,
            public_key: pq_public_key(),
            signature: vec![0x7u8; ML_DSA_65_SIGNATURE_LEN],
        };
        let tx_e = rotate_key_tx(&alice, &new_key, 1, new_key.public_key(), garbage);
        assert!(matches!(
            state.execute_transaction(&tx_e, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (f) A different ML-DSA key with a genuine signature over the correct
        // message: a compromised active key cannot substitute its own root key,
        // because the commitment binds the reveal to the account's stored root.
        let (other_public, other_secret) = ml_dsa65_keygen().unwrap();
        let correct_msg = crate::active_key_rotation_message(
            &ChainId::devnet(),
            alice.address(),
            AuthorizationPolicyRevision::new(1),
            1,
            &new_key.public_key(),
        )
        .unwrap();
        let mismatched = PostQuantumRootReveal {
            scheme: PostQuantumScheme::MlDsa65,
            public_key: other_public.to_bytes(),
            signature: other_secret.sign(&correct_msg, b"").unwrap(),
        };
        let tx_f = rotate_key_tx(&alice, &new_key, 1, new_key.public_key(), mismatched);
        assert!(matches!(
            state.execute_transaction(&tx_f, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn session_key_cannot_authorize_a_rotation() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let install = install_session_key_tx(&alice, &session, 1, session_constraints());
        state.execute_transaction(&install, &config).unwrap();

        // A session key tries to sign a rotation. Authorization only accepts the
        // current active key or the exact proposed new key as a rotation envelope
        // signer, so a session key (which is neither) is rejected outright with
        // `AuthorizationKeyMismatch` and never reaches the rotation arm. The
        // session-constraint gate would also refuse it, but this earlier check is
        // what fires, so a session key can never rotate the account key.
        let new_key = Keypair::from_seed([42u8; 32]);
        let operation = Operation::RotateActiveTransactionKey {
            new_active_transaction_key: new_key.public_key(),
            post_quantum_root_reveal: rotation_reveal(alice.address(), 2, &new_key.public_key()),
        };
        let id = SessionKeyId::derive(&session.public_key());
        let access_list = operation
            .default_access_list_for_session(alice.address(), AuthorizationLaneId::DEFAULT, id)
            .unwrap();
        let mut tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            alice.address(),
            session.public_key(),
            AuthorizationLaneId::DEFAULT,
            AuthorizationPolicyRevision::new(1),
            2,
            operation,
            access_list,
            small_fee_with_units(25_000),
        );
        tx.sign_with_policy_key(&session).unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::AuthorizationKeyMismatch)
        ));
        assert_eq!(state, before);
    }

    // ----- post-quantum root rotation tests -----

    /// A second process-wide ML-DSA-65 keypair used as the *new* recovery root in
    /// root-rotation tests (the first keypair is the current committed root).
    fn pq_keypair_b() -> &'static (MlDsa65PublicKey, MlDsa65SecretKey) {
        static KEYPAIR_B: OnceLock<(MlDsa65PublicKey, MlDsa65SecretKey)> = OnceLock::new();
        KEYPAIR_B.get_or_init(|| ml_dsa65_keygen().expect("ml-dsa-65 keygen b"))
    }

    /// The new post-quantum root committing to keypair B.
    fn new_root_b() -> PostQuantumRoot {
        PostQuantumRoot::from_public_key(PostQuantumScheme::MlDsa65, &pq_keypair_b().0.to_bytes())
            .unwrap()
    }

    /// A reveal whose public key and signature come from `keypair`, over exactly
    /// `message`. Used to sign with either the current root (A) or a candidate
    /// new root (B / a stranger).
    fn reveal_with_keypair(
        keypair: &(MlDsa65PublicKey, MlDsa65SecretKey),
        message: &[u8],
    ) -> PostQuantumRootReveal {
        PostQuantumRootReveal {
            scheme: PostQuantumScheme::MlDsa65,
            public_key: keypair.0.to_bytes(),
            signature: keypair.1.sign(message, b"").unwrap(),
        }
    }

    /// A root-rotation reveal: the CURRENT root (keypair A) signs the rotation to
    /// `new_root` at `nonce` under revision 1, matching what the state machine
    /// rebuilds and verifies.
    fn root_rotation_reveal(
        owner: Address,
        nonce: u64,
        new_root: &PostQuantumRoot,
    ) -> PostQuantumRootReveal {
        let message = crate::post_quantum_root_rotation_message(
            &ChainId::devnet(),
            owner,
            AuthorizationPolicyRevision::new(1),
            nonce,
            new_root,
        )
        .unwrap();
        reveal_over_message(&message)
    }

    /// Builds a default-lane root-rotation transaction signed by the current
    /// active key (the AccountKey authorization path).
    fn rotate_root_tx(
        owner: &Keypair,
        nonce: u64,
        new_root: PostQuantumRoot,
        reveal: PostQuantumRootReveal,
    ) -> Transaction {
        Transaction::for_operation_with_policy(
            owner,
            AuthorizationPolicyRevision::new(1),
            nonce,
            Operation::RotatePostQuantumRoot {
                new_post_quantum_root: new_root,
                post_quantum_root_reveal: reveal,
            },
            small_fee_with_units(25_000),
        )
        .unwrap()
    }

    #[test]
    fn post_quantum_root_rotation_replaces_the_root_and_preserves_the_active_key() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        // A session key installed under revision 1 must die on any policy bump.
        let session = Keypair::from_seed([9u8; 32]);
        let session_id = SessionKeyId::derive(&session.public_key());
        let install = install_session_key_tx(&alice, &session, 1, session_constraints());
        state.execute_transaction(&install, &config).unwrap();
        assert!(state
            .session_keys
            .contains_key(&(alice.address(), session_id)));

        let new_root = new_root_b();
        let before_root = state.state_root().unwrap();
        let rotate = rotate_root_tx(
            &alice,
            2,
            new_root,
            root_rotation_reveal(alice.address(), 2, &new_root),
        );
        state.execute_transaction(&rotate, &config).unwrap();

        let policy = state.authorization_policies.get(&alice.address()).unwrap();
        assert_eq!(*policy.post_quantum_root(), new_root);
        // The everyday signing key is untouched by a root rotation.
        assert_eq!(policy.active_transaction_key(), &alice.public_key());
        assert_eq!(policy.revision(), AuthorizationPolicyRevision::new(2));
        assert_ne!(state.state_root().unwrap(), before_root);
        assert!(state.supply_invariant_report().unwrap().balanced);

        // The session key installed under revision 1 can no longer be used.
        let session_tx = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            3,
            _bob.address(),
            Amount::from_webc(1),
            small_fee(),
        );
        assert!(matches!(
            state.execute_transaction(&session_tx, &config),
            Err(ChainError::AuthorizationPolicyRevisionMismatch { .. })
        ));
    }

    #[test]
    fn post_quantum_root_rotation_rejects_rotating_to_the_same_root() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let same_root =
            PostQuantumRoot::from_public_key(PostQuantumScheme::MlDsa65, &pq_public_key()).unwrap();
        let rotate = rotate_root_tx(
            &alice,
            1,
            same_root,
            root_rotation_reveal(alice.address(), 1, &same_root),
        );
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&rotate, &config),
            Err(ChainError::PostQuantumRootRotationToSameRoot)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn post_quantum_root_rotation_requires_default_lane() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let lane = AuthorizationLaneId::new(Hash256([0x55; 32]));
        let open = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(1),
            1,
            Operation::OpenAuthorizationLane {
                lane,
                fee_deposit: Amount::from_webc(1),
            },
            small_fee_with_units(10_000),
        )
        .unwrap();
        state.execute_transaction(&open, &config).unwrap();

        let new_root = new_root_b();
        let operation = Operation::RotatePostQuantumRoot {
            new_post_quantum_root: new_root,
            // Rejected by the default-lane guard before the reveal is verified.
            post_quantum_root_reveal: unverified_reveal(),
        };
        let access_list = operation
            .default_access_list_for_lane(alice.address(), lane)
            .unwrap();
        let mut tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            alice.address(),
            alice.public_key(),
            lane,
            AuthorizationPolicyRevision::new(1),
            0,
            operation,
            access_list,
            small_fee_with_units(25_000),
        );
        tx.sign_with_policy_key(&alice).unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::PostQuantumRootRotationRequiresDefaultLane)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn post_quantum_root_rotation_requires_an_installed_policy() {
        let (config, mut state, alice, _bob) = funded_state();
        let new_root = new_root_b();
        // No policy installed: sign with the address-deriving key at the legacy
        // revision so authorization passes and the arm's policy guard fires.
        let operation = Operation::RotatePostQuantumRoot {
            new_post_quantum_root: new_root,
            post_quantum_root_reveal: unverified_reveal(),
        };
        let access_list = operation
            .default_access_list_for_lane(alice.address(), AuthorizationLaneId::DEFAULT)
            .unwrap();
        let mut tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            alice.address(),
            alice.public_key(),
            AuthorizationLaneId::DEFAULT,
            LEGACY_AUTHORIZATION_POLICY_REVISION,
            0,
            operation,
            access_list,
            small_fee_with_units(25_000),
        );
        tx.sign_with_policy_key(&alice).unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::PostQuantumRootRotationRequiresInstalledPolicy)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn post_quantum_root_rotation_rejects_a_non_active_envelope_signer() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let new_root = new_root_b();
        let stranger = Keypair::from_seed([44u8; 32]);
        // A non-active Ed25519 key signs the envelope. Unlike active-key rotation,
        // root rotation has no recovery signer path, so this is just an ordinary
        // authorization failure.
        let operation = Operation::RotatePostQuantumRoot {
            new_post_quantum_root: new_root,
            post_quantum_root_reveal: root_rotation_reveal(alice.address(), 1, &new_root),
        };
        let access_list = operation
            .default_access_list_for_lane(alice.address(), AuthorizationLaneId::DEFAULT)
            .unwrap();
        let mut tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            alice.address(),
            stranger.public_key(),
            AuthorizationLaneId::DEFAULT,
            AuthorizationPolicyRevision::new(1),
            1,
            operation,
            access_list,
            small_fee_with_units(25_000),
        );
        tx.sign_with_policy_key(&stranger).unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::AuthorizationKeyMismatch)
        ));
        assert_eq!(state, before);
    }

    /// The gate must reject any reveal that is not a real ML-DSA signature by the
    /// *current* committed root over this exact root rotation. Every binding axis
    /// and forgery is checked, each leaving state unchanged.
    #[test]
    fn post_quantum_root_rotation_rejects_misbound_or_forged_current_root_signature() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let new_root = new_root_b();
        let before = state.clone();

        // (a) Signed over a different new root.
        let other_root =
            PostQuantumRoot::from_public_key(PostQuantumScheme::MlDsa65, b"a third root").unwrap();
        let tx_a = rotate_root_tx(
            &alice,
            1,
            new_root,
            root_rotation_reveal(alice.address(), 1, &other_root),
        );
        assert!(matches!(
            state.execute_transaction(&tx_a, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (b) Signed for a different nonce.
        let tx_b = rotate_root_tx(
            &alice,
            1,
            new_root,
            root_rotation_reveal(alice.address(), 2, &new_root),
        );
        assert!(matches!(
            state.execute_transaction(&tx_b, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (c) Signed for a different owner.
        let stranger = Keypair::from_seed([44u8; 32]);
        let wrong_owner_msg = crate::post_quantum_root_rotation_message(
            &ChainId::devnet(),
            stranger.address(),
            AuthorizationPolicyRevision::new(1),
            1,
            &new_root,
        )
        .unwrap();
        let tx_c = rotate_root_tx(&alice, 1, new_root, reveal_over_message(&wrong_owner_msg));
        assert!(matches!(
            state.execute_transaction(&tx_c, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (d) Signed for a different chain.
        let wrong_chain_msg = crate::post_quantum_root_rotation_message(
            &ChainId::new("webc-testnet-9").unwrap(),
            alice.address(),
            AuthorizationPolicyRevision::new(1),
            1,
            &new_root,
        )
        .unwrap();
        let tx_d = rotate_root_tx(&alice, 1, new_root, reveal_over_message(&wrong_chain_msg));
        assert!(matches!(
            state.execute_transaction(&tx_d, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (e) The current root's public key but a garbage signature.
        let garbage = PostQuantumRootReveal {
            scheme: PostQuantumScheme::MlDsa65,
            public_key: pq_public_key(),
            signature: vec![0x7u8; ML_DSA_65_SIGNATURE_LEN],
        };
        let tx_e = rotate_root_tx(&alice, 1, new_root, garbage);
        assert!(matches!(
            state.execute_transaction(&tx_e, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (f) Signed by the NEW root instead of the current one: the current root
        // must authorize its own replacement, so the future root cannot.
        let correct_msg = crate::post_quantum_root_rotation_message(
            &ChainId::devnet(),
            alice.address(),
            AuthorizationPolicyRevision::new(1),
            1,
            &new_root,
        )
        .unwrap();
        let signed_by_new = reveal_with_keypair(pq_keypair_b(), &correct_msg);
        let tx_f = rotate_root_tx(&alice, 1, new_root, signed_by_new);
        assert!(matches!(
            state.execute_transaction(&tx_f, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn after_root_rotation_the_new_root_holds_authority_and_the_old_root_does_not() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        // Rotate the root from A to B (envelope signed by the active key).
        let new_root = new_root_b();
        let rotate = rotate_root_tx(
            &alice,
            1,
            new_root,
            root_rotation_reveal(alice.address(), 1, &new_root),
        );
        state.execute_transaction(&rotate, &config).unwrap();
        assert_eq!(
            *state
                .authorization_policies
                .get(&alice.address())
                .unwrap()
                .post_quantum_root(),
            new_root
        );

        // Now attempt an active-key rotation at the new revision 2. The rotation
        // message binds revision 2; the active key (alice) signs the envelope.
        let new_ed = Keypair::from_seed([50u8; 32]);
        let msg = crate::active_key_rotation_message(
            &ChainId::devnet(),
            alice.address(),
            AuthorizationPolicyRevision::new(2),
            2,
            &new_ed.public_key(),
        )
        .unwrap();

        // The OLD root (A) can no longer authorize: the commitment now binds B.
        let signed_by_old = reveal_over_message(&msg);
        let operation_old = Operation::RotateActiveTransactionKey {
            new_active_transaction_key: new_ed.public_key(),
            post_quantum_root_reveal: signed_by_old,
        };
        let old_tx = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(2),
            2,
            operation_old,
            small_fee_with_units(25_000),
        )
        .unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&old_tx, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // The NEW root (B) now authorizes the same active-key rotation.
        let signed_by_new = reveal_with_keypair(pq_keypair_b(), &msg);
        let operation_new = Operation::RotateActiveTransactionKey {
            new_active_transaction_key: new_ed.public_key(),
            post_quantum_root_reveal: signed_by_new,
        };
        let new_tx = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(2),
            2,
            operation_new,
            small_fee_with_units(25_000),
        )
        .unwrap();
        state.execute_transaction(&new_tx, &config).unwrap();
        let policy = state.authorization_policies.get(&alice.address()).unwrap();
        assert_eq!(policy.active_transaction_key(), &new_ed.public_key());
        assert_eq!(policy.revision(), AuthorizationPolicyRevision::new(3));
        // The recovery root is still B after the active-key rotation.
        assert_eq!(*policy.post_quantum_root(), new_root);
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    // ----- epoch-boundary session-key pruning -----

    #[test]
    fn expired_session_keys_are_pruned_at_the_epoch_boundary_deterministically() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let short = Keypair::from_seed([9u8; 32]);
        let long = Keypair::from_seed([10u8; 32]);
        let short_id = SessionKeyId::derive(&short.public_key());
        let long_id = SessionKeyId::derive(&long.public_key());

        // Installed at epoch 0: `short` expires after epoch 1, `long` after 50.
        let mut short_c = session_constraints();
        short_c.lifetime_epochs = 1;
        let mut long_c = session_constraints();
        long_c.lifetime_epochs = 50;
        state
            .execute_transaction(&install_session_key_tx(&alice, &short, 1, short_c), &config)
            .unwrap();
        state
            .execute_transaction(&install_session_key_tx(&alice, &long, 2, long_c), &config)
            .unwrap();

        // Advance to epoch 1: `short` is still usable at its expiry epoch, so
        // nothing is pruned yet.
        state.distribute_epoch_rewards(&config).unwrap();
        assert_eq!(state.current_epoch, 1);
        assert!(state
            .session_keys
            .contains_key(&(alice.address(), short_id)));
        assert!(state.session_keys.contains_key(&(alice.address(), long_id)));

        // Snapshot at epoch 1, then advance to epoch 2 on both the live state and
        // a serialized-then-restored copy. Pruning is a pure function of committed
        // state, so both must produce identical state, root, and events.
        // bincode (not JSON) because state maps use non-string tuple keys.
        let snapshot = bincode::serialize(&state).unwrap();
        let mut restored: ChainState = bincode::deserialize(&snapshot).unwrap();
        let live_events = state.distribute_epoch_rewards(&config).unwrap();
        let restored_events = restored.distribute_epoch_rewards(&config).unwrap();
        assert_eq!(state, restored);
        assert_eq!(state.state_root().unwrap(), restored.state_root().unwrap());
        assert_eq!(live_events, restored_events);

        // At epoch 2 the short key is gone (its expiry epoch has passed) and the
        // long key survives; a prune event was emitted for the short key.
        assert_eq!(state.current_epoch, 2);
        assert!(!state
            .session_keys
            .contains_key(&(alice.address(), short_id)));
        assert!(state.session_keys.contains_key(&(alice.address(), long_id)));
        assert!(live_events.iter().any(|event| matches!(
            event,
            Event::SessionKeyExpired { owner, session_key }
                if *owner == alice.address() && *session_key == short_id
        )));
        assert!(state.supply_invariant_report().unwrap().balanced);

        // Pruning removes only unusable keys, so it never changes an authorization
        // outcome: the surviving long key still authorizes a transfer.
        let transfer = session_transfer_tx(
            &alice,
            &long,
            AuthorizationLaneId::DEFAULT,
            3,
            _bob.address(),
            Amount::from_webc(1),
            small_fee(),
        );
        state.execute_transaction(&transfer, &config).unwrap();
    }

    // ----- §15.35 fee sponsorship (paymaster) -----

    /// Devnet-style state whose sponsorship caps are small enough to exhaust in
    /// a test. Alice (seed 1) is funded with 1,000 WEBC; Bob (seed 2) has nothing.
    fn sponsored_setup() -> (ChainConfig, ChainState, Keypair, Keypair, Hash256) {
        let config = ChainConfig {
            sponsorship: SponsorshipConfig {
                enabled: true,
                max_ops_per_user_per_app_per_day: 2,
                max_sponsored_fee_per_op: Amount::from_units(1_000),
                max_app_daily_budget: Amount::from_units(1_000_000),
                day_window_epochs: 10,
            },
            ..ChainConfig::default()
        };
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
        let state = ChainState::from_genesis(&genesis).expect("genesis builds");
        (
            config,
            state,
            alice,
            bob,
            Hash256::digest(b"demo-app-namespace"),
        )
    }

    /// Fee bid whose effective per-unit price is exactly 1, so a `Transfer`'s fee
    /// is exactly 500 base units (its 500 execution units × 1).
    fn unit_fee(gas_limit: u64) -> FeeBid {
        FeeBid {
            gas_limit,
            max_fee_per_unit: 1,
            priority_fee_per_unit: 0,
        }
    }

    /// Registers `owner` as the sponsor of `namespace`, funding `funding` and
    /// setting a `daily_cap`, at `nonce`; asserts the transaction succeeds.
    fn register_sponsor(
        state: &mut ChainState,
        config: &ChainConfig,
        owner: &Keypair,
        namespace: Hash256,
        daily_cap: u128,
        funding: u128,
        nonce: u64,
    ) {
        let tx = Transaction::for_operation(
            owner,
            nonce,
            Operation::RegisterAppSponsor {
                namespace,
                daily_budget_cap: Amount::from_units(daily_cap),
                initial_funding: Amount::from_units(funding),
            },
            unit_fee(20_000),
        )
        .expect("register signs");
        state
            .execute_transaction(&tx, config)
            .expect("sponsor registered");
    }

    /// Transfers `amount` base units from `from` to `to` at `nonce` (self-paid).
    fn seed_balance(
        state: &mut ChainState,
        config: &ChainConfig,
        from: &Keypair,
        to: Address,
        amount: u128,
        nonce: u64,
    ) {
        let tx = Transaction::for_operation(
            from,
            nonce,
            Operation::Transfer {
                to,
                amount: Amount::from_units(amount),
            },
            unit_fee(1_000),
        )
        .expect("seed signs");
        state.execute_transaction(&tx, config).expect("seeded");
    }

    /// Builds a sponsored `Transfer` of `amount` from `from` to `to` at `nonce`,
    /// opting into fee sponsorship by `namespace`. The transfer fee is 500.
    fn sponsored_transfer(
        from: &Keypair,
        to: Address,
        amount: u128,
        nonce: u64,
        namespace: Hash256,
    ) -> Transaction {
        Transaction::for_sponsored_operation(
            from,
            nonce,
            Operation::Transfer {
                to,
                amount: Amount::from_units(amount),
            },
            unit_fee(1_000),
            namespace,
        )
        .expect("sponsored transfer signs")
    }

    #[test]
    fn register_and_fund_app_sponsor_locks_budget_and_conserves_supply() {
        let (config, mut state, alice, _bob, namespace) = sponsored_setup();
        let issued = state.minted_supply;

        register_sponsor(&mut state, &config, &alice, namespace, 50_000, 100_000, 0);
        let sponsor = &state.sponsors[&namespace];
        assert_eq!(sponsor.owner, alice.address());
        assert_eq!(sponsor.budget, Amount::from_units(100_000));
        assert_eq!(sponsor.daily_budget_cap, Amount::from_units(50_000));
        assert_eq!(state.sponsor_budgets, Amount::from_units(100_000));
        assert_eq!(
            state.minted_supply, issued,
            "registering a sponsor mints no supply"
        );
        assert!(state.supply_invariant_report().unwrap().balanced);

        // Top up the same sponsor; the aggregate bucket tracks the per-app budget.
        let fund = Transaction::for_operation(
            &alice,
            1,
            Operation::FundAppSponsor {
                namespace,
                amount: Amount::from_units(50_000),
            },
            unit_fee(20_000),
        )
        .expect("fund signs");
        let receipt = state.execute_transaction(&fund, &config).expect("funded");
        assert_eq!(
            state.sponsors[&namespace].budget,
            Amount::from_units(150_000)
        );
        assert_eq!(state.sponsor_budgets, Amount::from_units(150_000));
        assert!(receipt.events.iter().any(|e| matches!(
            e,
            Event::AppSponsorFunded { application, amount }
                if *application == namespace && *amount == Amount::from_units(50_000)
        )));
        assert!(state.supply_invariant_report().unwrap().balanced);

        // Only the owner may fund; a stranger's fund is rejected and rolls back.
        let stranger = Keypair::from_seed([9u8; 32]);
        seed_balance(&mut state, &config, &alice, stranger.address(), 100_000, 2);
        let bad = Transaction::for_operation(
            &stranger,
            0,
            Operation::FundAppSponsor {
                namespace,
                amount: Amount::from_units(10),
            },
            unit_fee(20_000),
        )
        .expect("stranger fund signs");
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&bad, &config),
            Err(ChainError::AppSponsorNotOwner)
        ));
        assert_eq!(state, before, "rejected fund leaves state unchanged");
    }

    #[test]
    fn sponsored_transfer_draws_fee_from_sponsor_leaving_sender_fee_untouched() {
        let (config, mut state, alice, bob, namespace) = sponsored_setup();
        register_sponsor(
            &mut state, &config, &alice, namespace, 1_000_000, 200_000, 0,
        );

        // Fund Bob with EXACTLY one transfer principal and no fee headroom: a
        // self-paid transfer would fail, so success proves the sponsor paid.
        let principal = 100u128;
        seed_balance(&mut state, &config, &alice, bob.address(), principal, 1);
        assert_eq!(
            state.accounts[&bob.address()].balance,
            Amount::from_units(principal)
        );

        let carol = Keypair::from_seed([3u8; 32]).address();
        let issued = state.minted_supply;
        let burned_before = state.burned_fees;
        let pool_before = state.validator_fee_pool;

        let tx = sponsored_transfer(&bob, carol, principal, 0, namespace);
        let receipt = state
            .execute_transaction(&tx, &config)
            .expect("sponsored transfer succeeds despite zero fee headroom");

        // Bob's balance fell by the principal only — the 500 fee never touched it.
        assert_eq!(state.accounts[&bob.address()].balance, Amount::ZERO);
        assert_eq!(
            state.accounts[&carol].balance,
            Amount::from_units(principal)
        );
        // The fee came out of the sponsor budget and split into burn + reward.
        assert_eq!(
            state.sponsors[&namespace].budget,
            Amount::from_units(199_500)
        );
        assert_eq!(state.sponsor_budgets, Amount::from_units(199_500));
        assert_eq!(
            state.sponsors[&namespace].spent_in_window,
            Amount::from_units(500)
        );
        assert_eq!(
            state.sponsors[&namespace].user_ops_in_window(&bob.address(), 0),
            1
        );
        assert_eq!(
            state.burned_fees,
            burned_before.checked_add(Amount::from_units(250)).unwrap()
        );
        assert_eq!(
            state.validator_fee_pool,
            pool_before.checked_add(Amount::from_units(250)).unwrap()
        );
        assert!(receipt.events.iter().any(|e| matches!(
            e,
            Event::FeeSponsored { application, beneficiary, .. }
                if *application == namespace && *beneficiary == bob.address()
        )));
        assert_eq!(
            state.minted_supply, issued,
            "a sponsored fee mints no supply"
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn per_user_daily_cap_exhausts_then_falls_back_to_self_pay() {
        let (config, mut state, alice, bob, namespace) = sponsored_setup();
        // per-user cap is 2. Fund Bob for 3 principals + exactly one self-paid fee.
        register_sponsor(
            &mut state, &config, &alice, namespace, 1_000_000, 100_000, 0,
        );
        seed_balance(&mut state, &config, &alice, bob.address(), 3 * 10 + 500, 1);
        let carol = Keypair::from_seed([3u8; 32]).address();

        // First two sponsored operations are covered by the sponsor.
        for nonce in 0..2 {
            let tx = sponsored_transfer(&bob, carol, 10, nonce, namespace);
            let receipt = state.execute_transaction(&tx, &config).expect("sponsored");
            assert!(receipt
                .events
                .iter()
                .any(|e| matches!(e, Event::FeeSponsored { .. })));
        }
        assert_eq!(
            state.sponsors[&namespace].budget,
            Amount::from_units(99_000)
        );
        assert_eq!(
            state.sponsors[&namespace].user_ops_in_window(&bob.address(), 0),
            2
        );

        // The third exceeds the per-user daily cap and falls back to self-pay.
        let bob_before = state.accounts[&bob.address()].balance;
        let tx = sponsored_transfer(&bob, carol, 10, 2, namespace);
        let receipt = state
            .execute_transaction(&tx, &config)
            .expect("third op still succeeds via self-pay");
        assert!(
            !receipt
                .events
                .iter()
                .any(|e| matches!(e, Event::FeeSponsored { .. })),
            "over-cap op is not sponsored"
        );
        // Bob paid the 500 fee himself plus the 10 principal; sponsor unchanged.
        assert_eq!(
            state.accounts[&bob.address()].balance,
            bob_before.checked_sub(Amount::from_units(510)).unwrap()
        );
        assert_eq!(
            state.sponsors[&namespace].budget,
            Amount::from_units(99_000),
            "the sponsor budget did not move for the self-paid op"
        );
        assert_eq!(
            state.sponsors[&namespace].user_ops_in_window(&bob.address(), 0),
            2
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn per_app_budget_exhaustion_falls_back_to_self_pay() {
        let (config, mut state, alice, bob, namespace) = sponsored_setup();
        // Fund the sponsor with only enough for a single 500-unit fee.
        register_sponsor(&mut state, &config, &alice, namespace, 1_000_000, 600, 0);
        seed_balance(&mut state, &config, &alice, bob.address(), 2 * 10 + 500, 1);
        let carol = Keypair::from_seed([3u8; 32]).address();

        let first = sponsored_transfer(&bob, carol, 10, 0, namespace);
        let receipt = state.execute_transaction(&first, &config).expect("first");
        assert!(receipt
            .events
            .iter()
            .any(|e| matches!(e, Event::FeeSponsored { .. })));
        assert_eq!(state.sponsors[&namespace].budget, Amount::from_units(100));

        // Budget (100) can no longer cover the 500 fee -> self-pay.
        let bob_before = state.accounts[&bob.address()].balance;
        let second = sponsored_transfer(&bob, carol, 10, 1, namespace);
        let receipt = state.execute_transaction(&second, &config).expect("second");
        assert!(!receipt
            .events
            .iter()
            .any(|e| matches!(e, Event::FeeSponsored { .. })));
        assert_eq!(
            state.accounts[&bob.address()].balance,
            bob_before.checked_sub(Amount::from_units(510)).unwrap()
        );
        assert_eq!(
            state.sponsors[&namespace].budget,
            Amount::from_units(100),
            "an underfunded sponsor is never overdrawn"
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn per_app_daily_spend_cap_binds_then_self_pays() {
        let (config, mut state, alice, bob, namespace) = sponsored_setup();
        // Well-funded, but the app's per-day spend cap only covers one 500 fee.
        register_sponsor(&mut state, &config, &alice, namespace, 700, 100_000, 0);
        seed_balance(&mut state, &config, &alice, bob.address(), 2 * 10 + 500, 1);
        let carol = Keypair::from_seed([3u8; 32]).address();

        let first = sponsored_transfer(&bob, carol, 10, 0, namespace);
        assert!(state
            .execute_transaction(&first, &config)
            .unwrap()
            .events
            .iter()
            .any(|e| matches!(e, Event::FeeSponsored { .. })));
        assert_eq!(
            state.sponsors[&namespace].spent_in_window,
            Amount::from_units(500)
        );

        // 500 + 500 > 700 day cap -> self-pay; the daily spend counter stays put.
        let second = sponsored_transfer(&bob, carol, 10, 1, namespace);
        assert!(!state
            .execute_transaction(&second, &config)
            .unwrap()
            .events
            .iter()
            .any(|e| matches!(e, Event::FeeSponsored { .. })));
        assert_eq!(
            state.sponsors[&namespace].spent_in_window,
            Amount::from_units(500)
        );
        assert_eq!(
            state.sponsors[&namespace].budget,
            Amount::from_units(99_500)
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn a_non_simple_operation_is_never_sponsored() {
        let (config, mut state, alice, bob, namespace) = sponsored_setup();
        register_sponsor(
            &mut state, &config, &alice, namespace, 1_000_000, 100_000, 0,
        );
        // CreateObject costs a 20,000 fee + a 1,000 storage deposit (1 byte).
        seed_balance(&mut state, &config, &alice, bob.address(), 21_000, 1);
        let sponsor_before = state.sponsors[&namespace].clone();

        let object_id = ObjectId::new(Hash256::digest(b"sponsor-nonsimple-obj"));
        let tx = Transaction::for_sponsored_operation(
            &bob,
            0,
            Operation::CreateObject {
                object_id,
                namespace,
                data: vec![0u8; 1],
            },
            unit_fee(20_000),
            namespace,
        )
        .expect("sponsored non-simple op signs");
        let receipt = state
            .execute_transaction(&tx, &config)
            .expect("CreateObject self-pays and succeeds");

        assert!(
            !receipt
                .events
                .iter()
                .any(|e| matches!(e, Event::FeeSponsored { .. })),
            "a non-sponsorable operation must never draw from a sponsor"
        );
        assert_eq!(
            state.sponsors[&namespace], sponsor_before,
            "the sponsor budget and counters are untouched by a non-simple op"
        );
        assert!(state.objects.contains_key(&object_id));
        // Bob self-paid the 20,000 fee and the 1,000 deposit out of 21,000.
        assert_eq!(state.accounts[&bob.address()].balance, Amount::ZERO);
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn day_window_counter_resets_deterministically_across_windows() {
        let (config, mut state, alice, bob, namespace) = sponsored_setup();
        register_sponsor(
            &mut state, &config, &alice, namespace, 1_000_000, 100_000, 0,
        );
        // window 0: two sponsored + one self-paid (per-user cap 2); window 1: one more.
        seed_balance(&mut state, &config, &alice, bob.address(), 4 * 10 + 500, 1);
        let carol = Keypair::from_seed([3u8; 32]).address();

        for nonce in 0..2 {
            let tx = sponsored_transfer(&bob, carol, 10, nonce, namespace);
            state
                .execute_transaction(&tx, &config)
                .expect("window-0 sponsored");
        }
        // Third in window 0 hits the per-user cap and self-pays.
        let capped = sponsored_transfer(&bob, carol, 10, 2, namespace);
        assert!(!state
            .execute_transaction(&capped, &config)
            .unwrap()
            .events
            .iter()
            .any(|e| matches!(e, Event::FeeSponsored { .. })));
        assert_eq!(
            state.sponsors[&namespace].user_ops_in_window(&bob.address(), 0),
            2
        );
        let budget_after_window0 = state.sponsors[&namespace].budget;
        assert_eq!(budget_after_window0, Amount::from_units(99_000));

        // Advance the consensus epoch into the next day-window (10 epochs/window).
        state.current_epoch = 10;

        // The per-user and per-app daily counters reset, so Bob can be sponsored again.
        let next_window = sponsored_transfer(&bob, carol, 10, 3, namespace);
        assert!(state
            .execute_transaction(&next_window, &config)
            .unwrap()
            .events
            .iter()
            .any(|e| matches!(e, Event::FeeSponsored { .. })));
        assert_eq!(state.sponsors[&namespace].window_index, 1);
        assert_eq!(
            state.sponsors[&namespace].spent_in_window,
            Amount::from_units(500)
        );
        assert_eq!(
            state.sponsors[&namespace].user_ops_in_window(&bob.address(), 1),
            1
        );
        assert_eq!(
            state.sponsors[&namespace].user_ops_in_window(&bob.address(), 0),
            0,
            "the previous window reads as zero after rollover"
        );
        assert_eq!(
            state.sponsors[&namespace].budget,
            budget_after_window0
                .checked_sub(Amount::from_units(500))
                .unwrap()
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn withdraw_returns_unspent_budget_and_conserves_supply() {
        let (config, mut state, alice, _bob, namespace) = sponsored_setup();
        register_sponsor(
            &mut state, &config, &alice, namespace, 1_000_000, 100_000, 0,
        );
        let liquid_before = state.accounts[&alice.address()].balance;

        let withdraw = Transaction::for_operation(
            &alice,
            1,
            Operation::WithdrawAppSponsor {
                namespace,
                amount: Amount::from_units(40_000),
            },
            unit_fee(20_000),
        )
        .expect("withdraw signs");
        let withdraw_fee = Amount::from_units(u128::from(withdraw.required_units()));
        state
            .execute_transaction(&withdraw, &config)
            .expect("withdrew");

        assert_eq!(
            state.sponsors[&namespace].budget,
            Amount::from_units(60_000)
        );
        assert_eq!(state.sponsor_budgets, Amount::from_units(60_000));
        // Alice regained the withdrawal minus the withdrawal transaction's own fee.
        assert_eq!(
            state.accounts[&alice.address()].balance,
            liquid_before
                .checked_add(Amount::from_units(40_000))
                .and_then(|b| b.checked_sub(withdraw_fee))
                .unwrap()
        );
        assert!(state.supply_invariant_report().unwrap().balanced);

        // Over-withdrawing the remaining budget is rejected and rolls back.
        let over = Transaction::for_operation(
            &alice,
            2,
            Operation::WithdrawAppSponsor {
                namespace,
                amount: Amount::from_units(60_001),
            },
            unit_fee(20_000),
        )
        .expect("over-withdraw signs");
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&over, &config),
            Err(ChainError::AppSponsorBudgetInsufficient { .. })
        ));
        assert_eq!(state, before, "rejected withdraw leaves state unchanged");
    }

    #[test]
    fn sponsorship_on_a_non_default_lane_is_rejected() {
        let (config, mut state, alice, _bob, namespace) = sponsored_setup();
        register_sponsor(
            &mut state, &config, &alice, namespace, 1_000_000, 100_000, 0,
        );
        // Hand-craft a transfer that names a sponsor but selects a non-default lane.
        let carol = Keypair::from_seed([3u8; 32]).address();
        let lane = AuthorizationLaneId::new(Hash256([0x42; 32]));
        let mut tx = Transaction::new_unsigned_in_lane(
            alice.address(),
            alice.public_key(),
            lane,
            0,
            Operation::Transfer {
                to: carol,
                amount: Amount::from_units(1),
            },
            Operation::Transfer {
                to: carol,
                amount: Amount::from_units(1),
            }
            .default_access_list_for_lane(alice.address(), lane)
            .unwrap(),
            unit_fee(1_000),
        );
        tx.sponsor = Some(namespace);
        tx.sign(&alice).expect("signs");
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::SponsorshipRequiresDefaultLane)
        ));
    }

    #[test]
    fn sponsor_registry_and_counters_survive_bincode_restart_with_stable_state_root() {
        // A crash-restart (bincode round-trip of the whole state) must preserve
        // the sponsor registry, per-user/day counters, the sponsor_budgets bucket,
        // and the committed state root, so a node cannot silently diverge on the
        // new sponsorship state after reloading from disk.
        let (config, mut state, alice, bob, namespace) = sponsored_setup();
        register_sponsor(
            &mut state, &config, &alice, namespace, 1_000_000, 100_000, 0,
        );
        seed_balance(&mut state, &config, &alice, bob.address(), 100, 1);
        let carol = Keypair::from_seed([3u8; 32]).address();
        let tx = sponsored_transfer(&bob, carol, 100, 0, namespace);
        state
            .execute_transaction(&tx, &config)
            .expect("sponsored transfer");
        assert_eq!(
            state.sponsors[&namespace].user_ops_in_window(&bob.address(), 0),
            1
        );
        assert!(!state.sponsor_budgets.is_zero());

        let bytes = bincode::serialize(&state).expect("state serializes");
        let restored: ChainState = bincode::deserialize(&bytes).expect("state deserializes");
        assert_eq!(
            restored.sponsors, state.sponsors,
            "restart preserves the sponsor registry and its per-user/day counters"
        );
        assert_eq!(restored.sponsor_budgets, state.sponsor_budgets);
        assert_eq!(restored, state, "restart preserves full state");
        assert_eq!(
            restored.state_root().expect("restored root"),
            state.state_root().expect("root"),
            "sponsor state is committed by the state root across a restart"
        );
    }
}
