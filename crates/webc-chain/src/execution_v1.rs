//! Protocol-version-2 transaction admission and execution boundaries.
//!
//! Purpose: turn a hostile signed V5 wire value into progressively stronger
//! typed states before any consensus mutation. This module owns stateless
//! validation, snapshot preparation, and the two-level inclusion/action
//! overlay. It does not decode HTTP, choose mempool policy, build blocks, or
//! persist lifecycle records.
//!
//! Data flows from `TransactionV5` through signature/chain/structure checks and
//! an exact access-list recomputation. Preparation proves inclusion against a
//! state snapshot. Execution rechecks that snapshot, reserves fees and advances
//! replay state in a parent overlay, then commits or discards a child action
//! overlay. Security boundary: chargeable action failures commit only the
//! parent; undeclared access, arithmetic faults, and unsupported actions discard
//! everything as block errors.

use crate::sponsor_grant_book::SponsorGrantBookError;
use crate::state::NativeActionEffects;
use crate::state_key::StateAccessRecorder;
use crate::{
    calculate_fee_summary_v1, ActionIndex, ActionV1, Amount, AssetId, AuthorizationLaneId,
    BlockHeight, BlockPositionV1, ChainError, ChainId, ChainState, Event, EventIndex, EventV1,
    ExecutionFailureCodeV1, ExternalChain, FeeComputationError, FeePayerV1, FeePaymentV1, FeeRate,
    GasUnits, Nonce, ObjectId, Operation, ProtocolStateKey, ReceiptError, ReceiptStatusV1,
    ReceiptV1, SessionKey, SessionKeyId, SponsorGrantId, SponsorGrantStateV1, StateKey,
    StateKeyKind, TransactionKindV1, TransactionV5, TransactionValidationErrorV1, EVENT_V1,
    LEGACY_AUTHORIZATION_POLICY_REVISION, MAX_TRANSACTION_VALIDITY_BLOCKS, RECEIPT_V1,
    SPONSOR_GRANT_USE_V1_REQUIRED_UNITS,
};
use std::collections::{BTreeMap, BTreeSet};
use webc_crypto::{Address, Hash256, PublicKeyBytes};

/// Maximum blocks before activation at which a signed grant may be revoked.
///
/// Combined with the grant's 4,096-block maximum span, this bounds a pre-use
/// tombstone's lifetime to at most 8,191 blocks. The value is an experimental
/// protocol-2 activation parameter and must be benchmarked before activation.
pub const MAX_SPONSOR_REVOCATION_LOOKAHEAD_BLOCKS_V1: u64 = MAX_TRANSACTION_VALIDITY_BLOCKS;

/// Stable state-dependent rejection before a transaction becomes includable.
///
/// These failures consume no nonce or fee. Arithmetic/invariant errors remain
/// distinct because an internal state inconsistency is never a chargeable user
/// failure.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TransactionPreparationErrorV1 {
    /// The signed validity window excludes the candidate block height.
    #[error("V5 transaction is outside its signed height window")]
    HeightOutsideValidity,
    /// Static action units exceed the sender-authorized gas limit.
    #[error("V5 gas limit is below statically required units")]
    GasLimitTooLow,
    /// The maximum rate cannot pay the current block base fee.
    #[error("V5 maximum fee rate is below the current base fee")]
    FeeBidBelowBase,
    /// The sender account or selected sender lane does not exist.
    #[error("V5 sender or authorization lane was not found")]
    SenderStateNotFound,
    /// The sender key, policy revision, session constraints, or expiry is invalid.
    #[error("V5 sender authority is not valid in current state")]
    SenderAuthorizationInvalid,
    /// The signed sender nonce is not the next nonce in its lane.
    #[error("V5 sender nonce does not match current state")]
    SenderNonceMismatch,
    /// Access names account-key or session-key state inconsistent with authority.
    #[error("V5 authorization access does not match the selected sender authority")]
    AuthorizationAccessMismatch,
    /// The selected payer account or prepaid lane does not exist.
    #[error("V5 fee payer or payer lane was not found")]
    FeePayerStateNotFound,
    /// The payer cannot reserve `gas_limit * max_fee_per_unit`.
    #[error("V5 fee payer cannot cover the maximum reserve")]
    InsufficientFeeReserve,
    /// The sponsor signing key is not the sponsor's current authority.
    #[error("V5 sponsor authority is not valid in current state")]
    SponsorAuthorizationInvalid,
    /// Durable state under this grant id belongs to another immutable grant.
    #[error("V5 sponsor grant digest conflicts with durable state")]
    SponsorGrantMismatch,
    /// The grant was permanently revoked by its sponsor.
    #[error("V5 sponsor grant is revoked")]
    SponsorGrantRevoked,
    /// ID-only revocation cannot create state for a grant never observed on-chain.
    #[error("V5 sponsor grant must be materialized before ID-only revocation")]
    SponsorGrantNotMaterialized,
    /// The authenticated grant lifetime ended before the candidate height.
    #[error("V5 sponsor grant is already expired")]
    SponsorGrantExpired,
    /// A pre-use revocation would retain state beyond the bounded lookahead.
    #[error("V5 sponsor grant starts beyond the revocation lookahead")]
    SponsorGrantTooFarInFuture,
    /// The use nonce is not the durable next nonce.
    #[error("V5 sponsor use nonce does not match current state")]
    SponsorNonceMismatch,
    /// The signed maximum use count has already been reached.
    #[error("V5 sponsor grant use count is exhausted")]
    SponsorUsesExhausted,
    /// Worst-case reservation would exceed the signed cumulative budget.
    #[error("V5 sponsor grant cumulative budget is exhausted")]
    SponsorBudgetExceeded,
    /// A checked consensus calculation overflowed or decoded state was invalid.
    #[error("V5 preparation encountered an invalid internal state")]
    InvalidState,
}

/// Stateful sender authority selected during preparation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparedAuthorizationV1 {
    /// The account's active or legacy address-derived transaction key.
    AccountKey,
    /// An installed constrained session key whose budgets advance on inclusion.
    SessionKey(SessionKeyId),
}

/// A validated V5 transaction proven includable against one state snapshot.
///
/// Preparation is pure: it captures checked identities, units, fee rates,
/// reserve, and authority without mutating balances, nonces, or grant records.
/// It must be consumed against the same ordered parent state snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedTransactionV1 {
    validated: ValidatedTransactionV1,
    transaction_id: crate::TransactionId,
    snapshot: PreparationSnapshotV1,
}

/// Small state-dependent preparation result used for stale-value detection.
///
/// The signed transaction and its identifier are immutable once admitted, so
/// re-execution only needs to recompute these state-derived scalar fields. This
/// avoids cloning and canonically hashing the complete signed envelope again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PreparationSnapshotV1 {
    fee_payer: FeePayerV1,
    fee_reserve: Amount,
    required_units: GasUnits,
    base_fee_per_unit: FeeRate,
    effective_priority_fee_per_unit: FeeRate,
    authorization: PreparedAuthorizationV1,
}

/// Typed writable identities captured by one bounded execution overlay.
///
/// Converting hostile `StateKey` values into this closed enum happens before
/// execution. Commit can therefore be infallible and cannot partially mutate
/// the base state before discovering an unsupported key.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ExecutionWriteKeyV1 {
    Account(Address),
    AuthorizationPolicy(Address),
    AssetBalance(AssetId, Address),
    Validator(Address),
    Delegation(Address, Address),
    AuthorizationLane(Address, AuthorizationLaneId),
    FeeAccumulator,
    SessionKey(Address, SessionKeyId),
    BridgeMessage(Hash256),
    BridgeEscrow(ExternalChain),
    SlashingEvidence(Hash256),
    UnbondingQueue,
    Object(ObjectId),
    Application,
    ProtocolBridgeNonce,
    SponsorGrant(Address, SponsorGrantId),
}

/// Sui-style bounded input snapshot plus deterministic write effects.
///
/// Only records named by the signed access list are copied from the global
/// state. Native transitions still operate on the existing `ChainState` API,
/// while commit moves only declared writable records back. This preserves the
/// replaceable storage boundary without cloning unrelated accounts or objects.
struct SparseExecutionStateV1 {
    state: ChainState,
    writes: Vec<ExecutionWriteKeyV1>,
    captured_burned_fees: Amount,
    captured_validator_fee_pool: Amount,
}

impl SparseExecutionStateV1 {
    /// Captures all declared inputs and validates the complete write set before execution.
    fn capture(
        base: &ChainState,
        read_only: &[StateKey],
        read_write: &[StateKey],
    ) -> Result<Self, BlockExecutionErrorV1> {
        let mut state = ChainState {
            protocol_version: base.protocol_version,
            chain_id: base.chain_id.clone(),
            burned_fees: base.burned_fees,
            slashed_units: base.slashed_units,
            validator_fee_pool: base.validator_fee_pool,
            minted_supply: base.minted_supply,
            inflation_year_start_supply: base.inflation_year_start_supply,
            current_base_fee_per_unit: base.current_base_fee_per_unit,
            current_epoch: base.current_epoch,
            bridge_nonce: base.bridge_nonce,
            last_block_timestamp_ms: base.last_block_timestamp_ms,
            ..ChainState::default()
        };
        let mut unbonding_captured = false;
        for key in read_only.iter().chain(read_write) {
            capture_state_key(base, &mut state, key, &mut unbonding_captured)?;
        }
        let writes = read_write
            .iter()
            .map(execution_write_key)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            state,
            writes,
            captured_burned_fees: base.burned_fees,
            captured_validator_fee_pool: base.validator_fee_pool,
        })
    }

    /// Applies typed records and additive global fee deltas after receipt validation.
    fn commit(mut self, base: &mut ChainState) -> Result<(), BlockExecutionErrorV1> {
        let burned_delta = self
            .state
            .burned_fees
            .checked_sub(self.captured_burned_fees)
            .ok_or(BlockExecutionErrorV1::InvalidState)?;
        let validator_fee_delta = self
            .state
            .validator_fee_pool
            .checked_sub(self.captured_validator_fee_pool)
            .ok_or(BlockExecutionErrorV1::InvalidState)?;
        let merged_burned_fees = base
            .burned_fees
            .checked_add(burned_delta)
            .ok_or(BlockExecutionErrorV1::InvalidState)?;
        let merged_validator_fee_pool = base
            .validator_fee_pool
            .checked_add(validator_fee_delta)
            .ok_or(BlockExecutionErrorV1::InvalidState)?;
        let commit_unbonding = self
            .writes
            .iter()
            .any(|key| matches!(key, ExecutionWriteKeyV1::UnbondingQueue));
        let sponsor_keys = self
            .writes
            .iter()
            .filter_map(|key| match key {
                ExecutionWriteKeyV1::SponsorGrant(sponsor, grant_id) => Some((*sponsor, *grant_id)),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        // The sponsor book is the only typed commit that can fail after
        // execution. Preflight and apply the complete batch before touching any
        // account/nonce/fee record, so an invalid sparse index cannot leave a
        // partially committed transaction.
        base.sponsor_grants
            .commit_entries_from(&self.state.sponsor_grants, sponsor_keys)
            .map_err(map_sponsor_book_execution_error)?;
        for key in self.writes {
            match key {
                ExecutionWriteKeyV1::Account(address) => {
                    commit_map_entry(&mut base.accounts, &mut self.state.accounts, address);
                }
                ExecutionWriteKeyV1::AuthorizationPolicy(owner) => commit_map_entry(
                    &mut base.authorization_policies,
                    &mut self.state.authorization_policies,
                    owner,
                ),
                ExecutionWriteKeyV1::AssetBalance(asset, owner) => commit_map_entry(
                    &mut base.asset_balances,
                    &mut self.state.asset_balances,
                    (asset, owner),
                ),
                ExecutionWriteKeyV1::Validator(operator) => {
                    commit_map_entry(&mut base.validators, &mut self.state.validators, operator)
                }
                ExecutionWriteKeyV1::Delegation(delegator, validator) => commit_map_entry(
                    &mut base.delegations,
                    &mut self.state.delegations,
                    (delegator, validator),
                ),
                ExecutionWriteKeyV1::AuthorizationLane(owner, lane) => commit_map_entry(
                    &mut base.authorization_lanes,
                    &mut self.state.authorization_lanes,
                    (owner, lane),
                ),
                ExecutionWriteKeyV1::FeeAccumulator => {}
                ExecutionWriteKeyV1::SessionKey(owner, session_key) => commit_map_entry(
                    &mut base.session_keys,
                    &mut self.state.session_keys,
                    (owner, session_key),
                ),
                ExecutionWriteKeyV1::BridgeMessage(message_hash) => commit_set_membership(
                    &mut base.processed_bridge_messages,
                    &mut self.state.processed_bridge_messages,
                    message_hash,
                ),
                ExecutionWriteKeyV1::BridgeEscrow(domain) => commit_map_entry(
                    &mut base.native_bridge_escrow,
                    &mut self.state.native_bridge_escrow,
                    domain,
                ),
                ExecutionWriteKeyV1::SlashingEvidence(evidence_hash) => commit_set_membership(
                    &mut base.processed_slashing_evidence,
                    &mut self.state.processed_slashing_evidence,
                    evidence_hash,
                ),
                ExecutionWriteKeyV1::UnbondingQueue => {}
                ExecutionWriteKeyV1::Object(object_id) => {
                    commit_map_entry(&mut base.objects, &mut self.state.objects, object_id);
                }
                ExecutionWriteKeyV1::Application => {}
                ExecutionWriteKeyV1::ProtocolBridgeNonce => {
                    base.bridge_nonce = self.state.bridge_nonce;
                }
                ExecutionWriteKeyV1::SponsorGrant(_, _) => {}
            }
        }
        if commit_unbonding {
            base.unbonding = self.state.unbonding;
        }
        base.burned_fees = merged_burned_fees;
        base.validator_fee_pool = merged_validator_fee_pool;
        Ok(())
    }
}

/// Copies one declared logical record into the bounded temporary state.
fn capture_state_key(
    base: &ChainState,
    target: &mut ChainState,
    key: &StateKey,
    unbonding_captured: &mut bool,
) -> Result<(), BlockExecutionErrorV1> {
    key.validate_version().map_err(map_block_chain_error)?;
    match &key.kind {
        StateKeyKind::Account { address } => {
            capture_map_entry(&base.accounts, &mut target.accounts, address);
        }
        StateKeyKind::AuthorizationPolicy { owner } => capture_map_entry(
            &base.authorization_policies,
            &mut target.authorization_policies,
            owner,
        ),
        StateKeyKind::AssetBalance { asset, owner } => capture_map_entry(
            &base.asset_balances,
            &mut target.asset_balances,
            &(asset.clone(), *owner),
        ),
        StateKeyKind::Validator { operator } => {
            capture_map_entry(&base.validators, &mut target.validators, operator);
        }
        StateKeyKind::Delegation {
            delegator,
            validator,
        } => capture_map_entry(
            &base.delegations,
            &mut target.delegations,
            &(*delegator, *validator),
        ),
        StateKeyKind::AuthorizationLane { owner, lane } => capture_map_entry(
            &base.authorization_lanes,
            &mut target.authorization_lanes,
            &(*owner, *lane),
        ),
        StateKeyKind::FeeAccumulator { .. } => {}
        StateKeyKind::SessionKey { owner, session_key } => capture_map_entry(
            &base.session_keys,
            &mut target.session_keys,
            &(*owner, *session_key),
        ),
        StateKeyKind::BridgeMessage { message_hash } => capture_set_membership(
            &base.processed_bridge_messages,
            &mut target.processed_bridge_messages,
            message_hash,
        ),
        StateKeyKind::BridgeEscrow { domain } => capture_map_entry(
            &base.native_bridge_escrow,
            &mut target.native_bridge_escrow,
            domain,
        ),
        StateKeyKind::SlashingEvidence { evidence_hash } => capture_set_membership(
            &base.processed_slashing_evidence,
            &mut target.processed_slashing_evidence,
            evidence_hash,
        ),
        StateKeyKind::UnbondingQueue { .. } => {
            if !*unbonding_captured {
                target.unbonding = base.unbonding.clone();
                *unbonding_captured = true;
            }
        }
        StateKeyKind::Object { object_id } => {
            capture_map_entry(&base.objects, &mut target.objects, object_id);
        }
        StateKeyKind::Protocol { .. } => {}
        StateKeyKind::SponsorGrant { sponsor, grant_id } => target
            .sponsor_grants
            .capture_from(
                &base.sponsor_grants,
                (*sponsor, SponsorGrantId::new(*grant_id)),
            )
            .map_err(map_sponsor_book_execution_error)?,
        StateKeyKind::Application { .. } => {}
        StateKeyKind::Module { .. } => {
            return Err(BlockExecutionErrorV1::StateAccessInvariant);
        }
    }
    Ok(())
}

/// Converts one prevalidated writable key into an infallible commit effect.
fn execution_write_key(key: &StateKey) -> Result<ExecutionWriteKeyV1, BlockExecutionErrorV1> {
    key.validate_version().map_err(map_block_chain_error)?;
    match &key.kind {
        StateKeyKind::Account { address } => Ok(ExecutionWriteKeyV1::Account(*address)),
        StateKeyKind::AuthorizationPolicy { owner } => {
            Ok(ExecutionWriteKeyV1::AuthorizationPolicy(*owner))
        }
        StateKeyKind::AssetBalance { asset, owner } => {
            Ok(ExecutionWriteKeyV1::AssetBalance(asset.clone(), *owner))
        }
        StateKeyKind::Validator { operator } => Ok(ExecutionWriteKeyV1::Validator(*operator)),
        StateKeyKind::Delegation {
            delegator,
            validator,
        } => Ok(ExecutionWriteKeyV1::Delegation(*delegator, *validator)),
        StateKeyKind::AuthorizationLane { owner, lane } => {
            Ok(ExecutionWriteKeyV1::AuthorizationLane(*owner, *lane))
        }
        StateKeyKind::FeeAccumulator { .. } => Ok(ExecutionWriteKeyV1::FeeAccumulator),
        StateKeyKind::SessionKey { owner, session_key } => {
            Ok(ExecutionWriteKeyV1::SessionKey(*owner, *session_key))
        }
        StateKeyKind::BridgeMessage { message_hash } => {
            Ok(ExecutionWriteKeyV1::BridgeMessage(*message_hash))
        }
        StateKeyKind::BridgeEscrow { domain } => {
            Ok(ExecutionWriteKeyV1::BridgeEscrow(domain.clone()))
        }
        StateKeyKind::SlashingEvidence { evidence_hash } => {
            Ok(ExecutionWriteKeyV1::SlashingEvidence(*evidence_hash))
        }
        StateKeyKind::UnbondingQueue { .. } => Ok(ExecutionWriteKeyV1::UnbondingQueue),
        StateKeyKind::Object { object_id } => Ok(ExecutionWriteKeyV1::Object(*object_id)),
        StateKeyKind::Application { .. } => Ok(ExecutionWriteKeyV1::Application),
        StateKeyKind::Protocol {
            field: ProtocolStateKey::BridgeNonce,
        } => Ok(ExecutionWriteKeyV1::ProtocolBridgeNonce),
        StateKeyKind::SponsorGrant { sponsor, grant_id } => Ok(ExecutionWriteKeyV1::SponsorGrant(
            *sponsor,
            SponsorGrantId::new(*grant_id),
        )),
        StateKeyKind::Protocol {
            field: ProtocolStateKey::BaseFee,
        }
        | StateKeyKind::Module { .. } => Err(BlockExecutionErrorV1::StateAccessInvariant),
    }
}

fn capture_map_entry<K: Clone + Ord, V: Clone>(
    source: &BTreeMap<K, V>,
    target: &mut BTreeMap<K, V>,
    key: &K,
) {
    if let Some(value) = source.get(key) {
        target.insert(key.clone(), value.clone());
    }
}

fn capture_set_membership<T: Clone + Ord>(
    source: &BTreeSet<T>,
    target: &mut BTreeSet<T>,
    value: &T,
) {
    if source.contains(value) {
        target.insert(value.clone());
    }
}

fn commit_map_entry<K: Ord, V>(base: &mut BTreeMap<K, V>, overlay: &mut BTreeMap<K, V>, key: K) {
    if let Some(value) = overlay.remove(&key) {
        base.insert(key, value);
    } else {
        base.remove(&key);
    }
}

fn commit_set_membership<T: Ord>(base: &mut BTreeSet<T>, overlay: &mut BTreeSet<T>, value: T) {
    if overlay.remove(&value) {
        base.insert(value);
    } else {
        base.remove(&value);
    }
}

impl PreparedTransactionV1 {
    /// Borrows the stateless-validated signed transaction.
    pub const fn validated(&self) -> &ValidatedTransactionV1 {
        &self.validated
    }

    /// Returns the complete signed transaction identity used by receipts.
    pub const fn transaction_id(&self) -> crate::TransactionId {
        self.transaction_id
    }

    /// Returns the exact account/lane that must reserve the fee.
    pub const fn fee_payer(&self) -> FeePayerV1 {
        self.snapshot.fee_payer
    }

    /// Returns `gas_limit * max_fee_per_unit` in native base units.
    pub const fn fee_reserve(&self) -> Amount {
        self.snapshot.fee_reserve
    }

    /// Returns checked static units for every action or cancellation.
    pub const fn required_units(&self) -> GasUnits {
        self.snapshot.required_units
    }

    /// Returns the current block base rate captured during preparation.
    pub const fn base_fee_per_unit(&self) -> FeeRate {
        self.snapshot.base_fee_per_unit
    }

    /// Returns the signed priority rate capped by maximum-minus-base room.
    pub const fn effective_priority_fee_per_unit(&self) -> FeeRate {
        self.snapshot.effective_priority_fee_per_unit
    }

    /// Returns the state authority selected for later budget accounting.
    pub const fn authorization(&self) -> PreparedAuthorizationV1 {
        self.snapshot.authorization
    }
}

/// A V5 transaction result whose parent/child overlays have been resolved.
///
/// Chargeable action failure is represented inside the receipt, never as a
/// Rust error. The wrapper can therefore be passed to block/root/storage layers
/// without losing the distinction between an invalid block and a failed user
/// action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutedTransactionV1 {
    receipt: ReceiptV1,
}

impl ExecutedTransactionV1 {
    /// Borrows the complete deterministic receipt.
    pub const fn receipt(&self) -> &ReceiptV1 {
        &self.receipt
    }

    /// Returns ownership for block/root/storage integration.
    pub fn into_receipt(self) -> ReceiptV1 {
        self.receipt
    }
}

/// Block-invalidating V5 execution failure for which no state may commit.
///
/// These errors are implementation/invariant failures, not chargeable user
/// outcomes. They deliberately contain no free-form consensus text.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BlockExecutionErrorV1 {
    /// The prepared value is no longer includable at its claimed position.
    #[error("V5 prepared transaction is stale: {0}")]
    Preparation(#[from] TransactionPreparationErrorV1),
    /// Re-preparation succeeded but produced different snapshot-dependent data.
    #[error("V5 prepared transaction no longer matches current state")]
    StalePreparation,
    /// A signed access declaration or observed access violated its invariant.
    #[error("V5 execution violated its signed state-access invariant")]
    StateAccessInvariant,
    /// Checked state arithmetic or another internal invariant failed.
    #[error("V5 execution encountered an invalid internal state")]
    InvalidState,
    /// The fee summary could not be reconciled from checked inputs.
    #[error("V5 execution fee accounting failed: {0}")]
    FeeAccounting(#[from] FeeComputationError),
    /// A locally constructed receipt did not satisfy its own schema invariants.
    #[error("V5 execution constructed an invalid receipt")]
    ReceiptInvariant,
    /// This incremental executor has not yet extracted this V4 transition.
    #[error("V5 action uses a native operation not integrated with the action executor")]
    UnsupportedNativeAction,
    /// A bounded action/event position did not fit its wire index.
    #[error("V5 action or event index overflowed")]
    IndexOverflow,
}

/// A signed V5 transaction whose stateless admission checks have passed.
///
/// Invariants: the schema and chain are supported, sender/sponsor signatures
/// verify, all structural bounds hold, and the signed access list exactly equals
/// the deterministic authorization/fee/action union. Stateful nonce, balance,
/// height, policy, and sponsor-budget checks belong to preparation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedTransactionV1 {
    transaction: TransactionV5,
}

impl ValidatedTransactionV1 {
    /// Verifies one hostile signed transaction without changing chain state.
    ///
    /// `expected_chain` is the genesis-fixed replay domain. Any signature,
    /// sponsor binding, bound, chain, or exact-access failure is returned as a
    /// stable validation error and the candidate remains unincludable/free.
    pub fn validate(
        transaction: TransactionV5,
        expected_chain: &ChainId,
    ) -> Result<Self, TransactionValidationErrorV1> {
        transaction.verify_for_chain(expected_chain)?;
        let expected = transaction.expected_access_list()?;
        let expected_session = transaction.expected_session_access_list()?;
        if transaction.access_list != expected && transaction.access_list != expected_session {
            return Err(TransactionValidationErrorV1::InvalidAccessList);
        }
        Ok(Self { transaction })
    }

    /// Borrows the fully checked signed transaction.
    pub const fn transaction(&self) -> &TransactionV5 {
        &self.transaction
    }

    /// Returns ownership for the later preparation or durable admission layer.
    pub fn into_transaction(self) -> TransactionV5 {
        self.transaction
    }
}

impl ChainState {
    /// Prepares one validated transaction against the current ordered state.
    ///
    /// This pure check performs no reservation or nonce mutation. It verifies
    /// height, static units, base-fee coverage, sender authority/nonce/session
    /// constraints, payer reserve, and sponsor replay/budget/revocation state.
    /// The returned value is snapshot-specific and must be consumed before any
    /// other transaction changes the same logical keys.
    pub fn prepare_transaction_v1(
        &self,
        validated: ValidatedTransactionV1,
        height: BlockHeight,
    ) -> Result<PreparedTransactionV1, TransactionPreparationErrorV1> {
        let snapshot = self.prepare_snapshot_v1(&validated, height)?;
        let transaction_id = validated
            .transaction()
            .transaction_id()
            .map_err(|_| TransactionPreparationErrorV1::InvalidState)?;
        Ok(PreparedTransactionV1 {
            validated,
            transaction_id,
            snapshot,
        })
    }

    /// Recomputes only state-derived preparation fields for stale-value checks.
    fn prepare_snapshot_v1(
        &self,
        validated: &ValidatedTransactionV1,
        height: BlockHeight,
    ) -> Result<PreparationSnapshotV1, TransactionPreparationErrorV1> {
        let transaction = validated.transaction();
        if !transaction.validity.contains(height) {
            return Err(TransactionPreparationErrorV1::HeightOutsideValidity);
        }

        let required_units = transaction
            .required_units()
            .map_err(|_| TransactionPreparationErrorV1::InvalidState)?;
        if transaction.fee_bid.gas_limit < required_units {
            return Err(TransactionPreparationErrorV1::GasLimitTooLow);
        }
        let priority_room = transaction
            .fee_bid
            .max_fee_per_unit
            .checked_sub(self.current_base_fee_per_unit)
            .ok_or(TransactionPreparationErrorV1::FeeBidBelowBase)?;
        let fee_reserve = Amount::from_units(
            u128::from(transaction.fee_bid.gas_limit)
                .checked_mul(u128::from(transaction.fee_bid.max_fee_per_unit))
                .ok_or(TransactionPreparationErrorV1::InvalidState)?,
        );

        let authorization = prepare_sender_authorization(self, transaction, fee_reserve)?;
        let expected_access = match authorization {
            PreparedAuthorizationV1::AccountKey => transaction.expected_access_list(),
            PreparedAuthorizationV1::SessionKey(_) => transaction.expected_session_access_list(),
        }
        .map_err(|_| TransactionPreparationErrorV1::InvalidState)?;
        if transaction.access_list != expected_access {
            return Err(TransactionPreparationErrorV1::AuthorizationAccessMismatch);
        }
        let expected_nonce =
            sender_nonce(self, transaction.sender, transaction.authorization.lane)?;
        if expected_nonce != transaction.authorization.nonce {
            return Err(TransactionPreparationErrorV1::SenderNonceMismatch);
        }
        let fee_payer = match &transaction.fee_payment {
            FeePaymentV1::SenderLane => FeePayerV1 {
                address: transaction.sender,
                lane: transaction.authorization.lane,
            },
            FeePaymentV1::Sponsored(sponsor_use) => {
                prepare_sponsor_use(self, transaction, sponsor_use, height, fee_reserve)?;
                FeePayerV1 {
                    address: sponsor_use.grant.sponsor,
                    lane: sponsor_use.grant.payer_lane,
                }
            }
        };
        prepare_sponsor_storage(self, transaction, height)?;
        if payer_balance(self, fee_payer)? < fee_reserve {
            return Err(TransactionPreparationErrorV1::InsufficientFeeReserve);
        }

        Ok(PreparationSnapshotV1 {
            fee_payer,
            fee_reserve,
            required_units: GasUnits::new(required_units),
            base_fee_per_unit: FeeRate::new(self.current_base_fee_per_unit),
            effective_priority_fee_per_unit: FeeRate::new(
                transaction.fee_bid.priority_fee_per_unit.min(priority_room),
            ),
            authorization,
        })
    }

    /// Executes one prepared V5 transaction with parent/child rollback semantics.
    ///
    /// The method first re-prepares against the current logical state, so a stale
    /// value cannot reserve fees. The parent overlay reserves the payer's signed
    /// maximum, advances the sender nonce, and later records exact fee/sponsor
    /// accounting. Ordered actions run in a child clone. Success merges that
    /// clone and all typed events; a chargeable action failure discards the child
    /// while committing the parent nonce and measured fee. Any returned error
    /// leaves `self` byte-for-byte unchanged.
    pub fn execute_prepared_transaction_v1(
        &mut self,
        prepared: PreparedTransactionV1,
        position: BlockPositionV1,
    ) -> Result<ExecutedTransactionV1, BlockExecutionErrorV1> {
        let refreshed = self.prepare_snapshot_v1(&prepared.validated, position.height)?;
        if refreshed != prepared.snapshot {
            return Err(BlockExecutionErrorV1::StalePreparation);
        }
        let PreparedTransactionV1 {
            validated,
            transaction_id,
            snapshot,
        } = prepared;
        let transaction = validated.into_transaction();
        preflight_supported_actions(&transaction.kind)?;
        let mut access = StateAccessRecorder::new(
            &transaction.access_list.read_only,
            &transaction.access_list.read_write,
        )
        .map_err(map_block_chain_error)?;
        record_parent_access(
            &transaction,
            snapshot.fee_payer,
            snapshot.authorization,
            &mut access,
        )?;

        let SparseExecutionStateV1 {
            state: mut parent,
            writes,
            captured_burned_fees,
            captured_validator_fee_pool,
        } = SparseExecutionStateV1::capture(
            self,
            &transaction.access_list.read_only,
            &transaction.access_list.read_write,
        )?;
        debit_fee_reserve(&mut parent, snapshot.fee_payer, snapshot.fee_reserve)?;
        advance_sender_nonce(
            &mut parent,
            transaction.sender,
            transaction.authorization.lane,
        )?;

        let (mut selected, status, attempted_units, typed_events) = match &transaction.kind {
            TransactionKindV1::Cancel(_) => {
                access.finish().map_err(map_block_chain_error)?;
                (
                    parent,
                    ReceiptStatusV1::Succeeded,
                    snapshot.required_units,
                    Vec::new(),
                )
            }
            TransactionKindV1::Actions(program) => execute_action_program_v1(
                parent,
                &transaction,
                transaction_id,
                program,
                position.height,
                &mut access,
            )?,
        };

        let fee_summary = calculate_fee_summary_v1(
            snapshot.fee_payer,
            GasUnits::new(transaction.fee_bid.gas_limit),
            attempted_units,
            snapshot.base_fee_per_unit,
            FeeRate::new(transaction.fee_bid.max_fee_per_unit),
            FeeRate::new(transaction.fee_bid.priority_fee_per_unit),
        )?;
        finalize_fee_accounting(&mut selected, &fee_summary)?;
        finalize_sponsor_use(
            &mut selected,
            &transaction,
            position.height,
            fee_summary.charged,
        )?;
        finalize_session_use(
            &mut selected,
            &transaction,
            snapshot.authorization,
            status,
            fee_summary.charged,
        )?;

        let receipt = ReceiptV1 {
            version: RECEIPT_V1,
            position,
            transaction_id,
            sender: transaction.sender,
            status,
            fee_summary,
            events: typed_events,
        };
        receipt
            .validate()
            .map_err(|_error: ReceiptError| BlockExecutionErrorV1::ReceiptInvariant)?;
        SparseExecutionStateV1 {
            state: selected,
            writes,
            captured_burned_fees,
            captured_validator_fee_pool,
        }
        .commit(self)?;
        Ok(ExecutedTransactionV1 { receipt })
    }
}

fn preflight_supported_actions(kind: &TransactionKindV1) -> Result<(), BlockExecutionErrorV1> {
    let TransactionKindV1::Actions(program) = kind else {
        return Ok(());
    };
    if program
        .actions
        .iter()
        .any(|action| !action.execution_supported())
    {
        return Err(BlockExecutionErrorV1::UnsupportedNativeAction);
    }
    Ok(())
}

enum NativeActionExecutionErrorV1 {
    Unsupported,
    Transition(ChainError),
}

/// Transaction-envelope authority shared by every action in one V5 program.
///
/// This starts with sender and lane coordinates; later native groups add only
/// the reviewed chain-config or authorization fields their V4 transition uses.
#[derive(Clone, Copy)]
struct NativeActionContextV1 {
    sender: Address,
    sender_public_key: PublicKeyBytes,
    authorization_lane: AuthorizationLaneId,
}

/// Executes one supported native action without owning fee or rollback policy.
///
/// Every arm delegates to the same transition helper used by V4. The caller's
/// child overlay decides whether a returned user-state error is chargeable and
/// disposable; unsupported operations remain block errors until their complete
/// configuration and authorization context is integrated here.
fn execute_native_action_v1(
    state: &mut ChainState,
    context: NativeActionContextV1,
    operation: &Operation,
    access: &mut StateAccessRecorder,
    events: &mut Vec<Event>,
) -> Result<(), NativeActionExecutionErrorV1> {
    let effects = NativeActionEffects::new(access, events);
    let result = match operation {
        Operation::InstallAuthorizationPolicy { post_quantum_root } => state
            .apply_native_install_authorization_policy(
                context.sender,
                context.sender_public_key,
                context.authorization_lane,
                *post_quantum_root,
                effects,
            ),
        Operation::Transfer { to, amount } => {
            state.apply_native_transfer(context.sender, *to, *amount, effects)
        }
        Operation::OpenAuthorizationLane { lane, fee_deposit } => state.apply_native_lane_open(
            context.sender,
            context.authorization_lane,
            *lane,
            *fee_deposit,
            effects,
        ),
        Operation::FundAuthorizationLane { lane, fee_deposit } => state.apply_native_lane_fund(
            context.sender,
            context.authorization_lane,
            *lane,
            *fee_deposit,
            effects,
        ),
        Operation::ClaimValidatorRewards => {
            state.apply_native_claim_validator_rewards(context.sender, effects)
        }
        Operation::ClaimDelegatorRewards { validator } => {
            state.apply_native_claim_delegator_rewards(context.sender, *validator, effects)
        }
        Operation::ClaimUnbonded {
            validator,
            request_id,
        } => state.apply_native_claim_unbonded(context.sender, *validator, *request_id, effects),
        Operation::CreateObject {
            object_id,
            namespace,
            data,
        } => {
            state.apply_native_object_create(context.sender, *object_id, *namespace, data, effects)
        }
        Operation::MutateObject {
            object_id,
            namespace,
            expected_version,
            data,
        } => state.apply_native_object_mutation(
            context.sender,
            *object_id,
            *namespace,
            *expected_version,
            data,
            effects,
        ),
        Operation::TransferObject {
            object_id,
            namespace,
            expected_version,
            new_owner,
        } => state.apply_native_object_transfer(
            context.sender,
            *object_id,
            *namespace,
            *expected_version,
            *new_owner,
            effects,
        ),
        _ => return Err(NativeActionExecutionErrorV1::Unsupported),
    };
    result.map_err(NativeActionExecutionErrorV1::Transition)
}

fn record_parent_access(
    transaction: &TransactionV5,
    payer: FeePayerV1,
    authorization: PreparedAuthorizationV1,
    access: &mut StateAccessRecorder,
) -> Result<(), BlockExecutionErrorV1> {
    access
        .read(StateKey::authorization_policy(transaction.sender))
        .map_err(map_block_chain_error)?;
    access
        .read(StateKey::protocol(ProtocolStateKey::BaseFee))
        .map_err(map_block_chain_error)?;
    access
        .write(lane_state_key(
            transaction.sender,
            transaction.authorization.lane,
        ))
        .map_err(map_block_chain_error)?;
    if let PreparedAuthorizationV1::SessionKey(session_key) = authorization {
        access
            .write(StateKey::session_key(transaction.sender, session_key))
            .map_err(map_block_chain_error)?;
    }

    if let FeePaymentV1::Sponsored(sponsor_use) = &transaction.fee_payment {
        access
            .read(StateKey::authorization_policy(sponsor_use.grant.sponsor))
            .map_err(map_block_chain_error)?;
        access
            .write(StateKey::sponsor_grant(
                sponsor_use.grant.sponsor,
                sponsor_use.grant.grant_id.digest(),
            ))
            .map_err(map_block_chain_error)?;
    }
    access
        .write(lane_state_key(payer.address, payer.lane))
        .map_err(map_block_chain_error)?;
    access
        .write(StateKey::fee_accumulator_for_lane(
            payer.address,
            payer.lane,
        ))
        .map_err(map_block_chain_error)
}

fn lane_state_key(owner: Address, lane: AuthorizationLaneId) -> StateKey {
    if lane.is_default() {
        StateKey::account(owner)
    } else {
        StateKey::authorization_lane(owner, lane)
    }
}

fn debit_fee_reserve(
    state: &mut ChainState,
    payer: FeePayerV1,
    reserve: Amount,
) -> Result<(), BlockExecutionErrorV1> {
    let balance = if payer.lane.is_default() {
        &mut state
            .accounts
            .get_mut(&payer.address)
            .ok_or(BlockExecutionErrorV1::InvalidState)?
            .balance
    } else {
        &mut state
            .authorization_lanes
            .get_mut(&(payer.address, payer.lane))
            .ok_or(BlockExecutionErrorV1::InvalidState)?
            .fee_balance
    };
    *balance = balance
        .checked_sub(reserve)
        .ok_or(BlockExecutionErrorV1::InvalidState)?;
    Ok(())
}

fn credit_fee_refund(
    state: &mut ChainState,
    payer: FeePayerV1,
    refund: Amount,
) -> Result<(), BlockExecutionErrorV1> {
    let balance = if payer.lane.is_default() {
        &mut state
            .accounts
            .get_mut(&payer.address)
            .ok_or(BlockExecutionErrorV1::InvalidState)?
            .balance
    } else {
        &mut state
            .authorization_lanes
            .get_mut(&(payer.address, payer.lane))
            .ok_or(BlockExecutionErrorV1::InvalidState)?
            .fee_balance
    };
    *balance = balance
        .checked_add(refund)
        .ok_or(BlockExecutionErrorV1::InvalidState)?;
    Ok(())
}

fn advance_sender_nonce(
    state: &mut ChainState,
    sender: Address,
    lane: AuthorizationLaneId,
) -> Result<(), BlockExecutionErrorV1> {
    if lane.is_default() {
        let account = state
            .accounts
            .get_mut(&sender)
            .ok_or(BlockExecutionErrorV1::InvalidState)?;
        account.nonce = account
            .nonce
            .checked_add(1)
            .ok_or(BlockExecutionErrorV1::InvalidState)?;
    } else {
        let lane_state = state
            .authorization_lanes
            .get_mut(&(sender, lane))
            .ok_or(BlockExecutionErrorV1::InvalidState)?;
        lane_state.next_nonce = lane_state
            .next_nonce
            .checked_next()
            .ok_or(BlockExecutionErrorV1::InvalidState)?;
    }
    Ok(())
}

fn execute_action_program_v1(
    parent: ChainState,
    transaction: &TransactionV5,
    transaction_id: crate::TransactionId,
    program: &crate::ActionProgramV1,
    height: BlockHeight,
    access: &mut StateAccessRecorder,
) -> Result<(ChainState, ReceiptStatusV1, GasUnits, Vec<EventV1>), BlockExecutionErrorV1> {
    let mut child = parent.clone();
    let mut attempted_units = if matches!(&transaction.fee_payment, FeePaymentV1::Sponsored(_)) {
        SPONSOR_GRANT_USE_V1_REQUIRED_UNITS
    } else {
        0
    };
    let mut events = Vec::new();

    for (ordinal, action) in program.actions.iter().enumerate() {
        attempted_units = attempted_units
            .checked_add(action.required_units())
            .ok_or(BlockExecutionErrorV1::InvalidState)?;
        let action_index = u32::try_from(ordinal)
            .map(ActionIndex::new)
            .map_err(|_| BlockExecutionErrorV1::IndexOverflow)?;
        let mut action_events = Vec::new();
        let result = match action {
            ActionV1::Native { operation } => match execute_native_action_v1(
                &mut child,
                NativeActionContextV1 {
                    sender: transaction.sender,
                    sender_public_key: transaction.sender_public_key,
                    authorization_lane: transaction.authorization.lane,
                },
                operation,
                access,
                &mut action_events,
            ) {
                Ok(()) => Ok(()),
                Err(NativeActionExecutionErrorV1::Unsupported) => {
                    return Err(BlockExecutionErrorV1::UnsupportedNativeAction);
                }
                Err(NativeActionExecutionErrorV1::Transition(error)) => Err(error),
            },
            ActionV1::RevokeSponsorGrant { grant_id } => {
                access
                    .write(StateKey::sponsor_grant(
                        transaction.sender,
                        grant_id.digest(),
                    ))
                    .map_err(map_block_chain_error)?;
                revoke_sponsor_grant_record(
                    &mut child,
                    transaction.sender,
                    *grant_id,
                    height,
                    None,
                )?;
                action_events.push(Event::SponsorGrantRevoked {
                    sponsor: transaction.sender,
                    grant_id: *grant_id,
                });
                Ok(())
            }
            ActionV1::RevokeSignedSponsorGrant { grant } => {
                access
                    .write(StateKey::sponsor_grant(
                        transaction.sender,
                        grant.grant_id.digest(),
                    ))
                    .map_err(map_block_chain_error)?;
                let digest = grant
                    .digest()
                    .map_err(|_| BlockExecutionErrorV1::InvalidState)?;
                revoke_sponsor_grant_record(
                    &mut child,
                    transaction.sender,
                    grant.grant_id,
                    height,
                    Some((digest, grant.validity.valid_until_height)),
                )?;
                action_events.push(Event::SponsorGrantRevoked {
                    sponsor: transaction.sender,
                    grant_id: grant.grant_id,
                });
                Ok(())
            }
        };

        if let Err(error) = result {
            let code = classify_action_failure(error)?;
            return Ok((
                parent,
                ReceiptStatusV1::Failed {
                    code,
                    failed_action_index: Some(action_index),
                },
                GasUnits::new(attempted_units),
                Vec::new(),
            ));
        }
        append_typed_events(&mut events, transaction_id, action_index, action_events)?;
    }

    access.finish().map_err(map_block_chain_error)?;
    Ok((
        child,
        ReceiptStatusV1::Succeeded,
        GasUnits::new(attempted_units),
        events,
    ))
}

/// Applies either a cheap materialized revoke or an authenticated pre-use revoke.
fn revoke_sponsor_grant_record(
    state: &mut ChainState,
    sponsor: Address,
    grant_id: SponsorGrantId,
    height: BlockHeight,
    authenticated: Option<(Hash256, BlockHeight)>,
) -> Result<(), BlockExecutionErrorV1> {
    let key = (sponsor, grant_id);
    let mut record = match state.sponsor_grants.get(&key).copied() {
        Some(record) if record.valid_until_height >= height => record,
        Some(_) | None => {
            let (digest, valid_until_height) =
                authenticated.ok_or(BlockExecutionErrorV1::InvalidState)?;
            SponsorGrantStateV1::unused(digest, valid_until_height)
        }
    };
    if let Some((digest, valid_until_height)) = authenticated {
        if record.grant_digest != digest || record.valid_until_height != valid_until_height {
            return Err(BlockExecutionErrorV1::InvalidState);
        }
    }
    record.revoked = true;
    state
        .sponsor_grants
        .set(key, record)
        .map_err(map_sponsor_book_execution_error)
}

fn append_typed_events(
    target: &mut Vec<EventV1>,
    transaction_id: crate::TransactionId,
    action_index: ActionIndex,
    action_events: Vec<Event>,
) -> Result<(), BlockExecutionErrorV1> {
    for body in action_events {
        let ordinal =
            u32::try_from(target.len()).map_err(|_| BlockExecutionErrorV1::IndexOverflow)?;
        target.push(EventV1 {
            version: EVENT_V1,
            transaction_id,
            action_index,
            event_index: EventIndex::new(ordinal),
            body,
        });
    }
    Ok(())
}

fn classify_action_failure(
    error: ChainError,
) -> Result<ExecutionFailureCodeV1, BlockExecutionErrorV1> {
    match error {
        ChainError::InsufficientBalance { .. } => Ok(ExecutionFailureCodeV1::InsufficientBalance),
        ChainError::ObjectNotFound => Ok(ExecutionFailureCodeV1::ObjectNotFound),
        ChainError::ObjectOwnerMismatch | ChainError::SharedObjectMutationUnsupported => {
            Ok(ExecutionFailureCodeV1::ObjectOwnerMismatch)
        }
        ChainError::ObjectVersionMismatch { .. } => {
            Ok(ExecutionFailureCodeV1::ObjectVersionMismatch)
        }
        ChainError::ObjectAlreadyExists
        | ChainError::ObjectNamespaceMismatch
        | ChainError::AuthorizationPolicyAlreadyExists
        | ChainError::AuthorizationLaneExists
        | ChainError::AuthorizationLaneNotFound
        | ChainError::ValidatorNotFound(_)
        | ChainError::DelegationNotFound
        | ChainError::UnbondingRequestNotFound
        | ChainError::UnbondingOwnerMismatch
        | ChainError::UnbondingNotWithdrawable => Ok(ExecutionFailureCodeV1::Precondition),
        ChainError::AccountNotFound(_) => Ok(ExecutionFailureCodeV1::Precondition),
        other => Err(map_block_chain_error(other)),
    }
}

fn map_block_chain_error(error: ChainError) -> BlockExecutionErrorV1 {
    match error {
        ChainError::UndeclaredStateRead { .. }
        | ChainError::UndeclaredStateWrite { .. }
        | ChainError::UnusedDeclaredStateAccess
        | ChainError::InvalidAccessList
        | ChainError::TooManyStateKeys { .. }
        | ChainError::UnsupportedStateKeyVersion { .. } => {
            BlockExecutionErrorV1::StateAccessInvariant
        }
        _ => BlockExecutionErrorV1::InvalidState,
    }
}

fn map_sponsor_book_execution_error(_error: SponsorGrantBookError) -> BlockExecutionErrorV1 {
    BlockExecutionErrorV1::InvalidState
}

fn finalize_fee_accounting(
    state: &mut ChainState,
    summary: &crate::FeeSummaryV1,
) -> Result<(), BlockExecutionErrorV1> {
    credit_fee_refund(state, summary.payer, summary.refund)?;
    state.burned_fees = state
        .burned_fees
        .checked_add(summary.burned)
        .ok_or(BlockExecutionErrorV1::InvalidState)?;
    state.validator_fee_pool = state
        .validator_fee_pool
        .checked_add(summary.validator_reward)
        .ok_or(BlockExecutionErrorV1::InvalidState)?;
    Ok(())
}

fn finalize_sponsor_use(
    state: &mut ChainState,
    transaction: &TransactionV5,
    height: BlockHeight,
    actual_charge: Amount,
) -> Result<(), BlockExecutionErrorV1> {
    let FeePaymentV1::Sponsored(sponsor_use) = &transaction.fee_payment else {
        return Ok(());
    };
    let grant = &sponsor_use.grant;
    let key = (grant.sponsor, grant.grant_id);
    let mut record = state
        .sponsor_grants
        .get(&key)
        .copied()
        .filter(|record| record.valid_until_height >= height)
        .unwrap_or_else(|| {
            SponsorGrantStateV1::unused(sponsor_use.grant_digest, grant.validity.valid_until_height)
        });
    if record.grant_digest != sponsor_use.grant_digest
        || record.valid_until_height != grant.validity.valid_until_height
    {
        return Err(BlockExecutionErrorV1::InvalidState);
    }
    record.next_use_nonce = record
        .next_use_nonce
        .checked_next()
        .ok_or(BlockExecutionErrorV1::InvalidState)?;
    record.uses = record
        .uses
        .checked_next()
        .ok_or(BlockExecutionErrorV1::InvalidState)?;
    record.total_charged = record
        .total_charged
        .checked_add(actual_charge)
        .ok_or(BlockExecutionErrorV1::InvalidState)?;
    state
        .sponsor_grants
        .set(key, record)
        .map_err(map_sponsor_book_execution_error)
}

fn finalize_session_use(
    state: &mut ChainState,
    transaction: &TransactionV5,
    authorization: PreparedAuthorizationV1,
    status: ReceiptStatusV1,
    actual_charge: Amount,
) -> Result<(), BlockExecutionErrorV1> {
    let PreparedAuthorizationV1::SessionKey(session_key) = authorization else {
        return Ok(());
    };
    let principal = if status == ReceiptStatusV1::Succeeded {
        session_principal(&transaction.kind)?
    } else {
        Amount::ZERO
    };
    let record = state
        .session_keys
        .get_mut(&(transaction.sender, session_key))
        .ok_or(BlockExecutionErrorV1::InvalidState)?;
    record.spent_amount = record
        .spent_amount
        .checked_add(principal)
        .ok_or(BlockExecutionErrorV1::InvalidState)?;
    record.spent_fees = record
        .spent_fees
        .checked_add(actual_charge)
        .ok_or(BlockExecutionErrorV1::InvalidState)?;
    record
        .validate()
        .map_err(|_| BlockExecutionErrorV1::InvalidState)
}

fn session_principal(kind: &TransactionKindV1) -> Result<Amount, BlockExecutionErrorV1> {
    let TransactionKindV1::Actions(program) = kind else {
        return Err(BlockExecutionErrorV1::InvalidState);
    };
    program
        .actions
        .iter()
        .try_fold(Amount::ZERO, |total, action| {
            let ActionV1::Native { operation } = action else {
                return Err(BlockExecutionErrorV1::InvalidState);
            };
            let Operation::Transfer { amount, .. } = operation.as_ref() else {
                return Err(BlockExecutionErrorV1::InvalidState);
            };
            total
                .checked_add(*amount)
                .ok_or(BlockExecutionErrorV1::InvalidState)
        })
}

fn prepare_sender_authorization(
    state: &ChainState,
    transaction: &TransactionV5,
    fee_reserve: Amount,
) -> Result<PreparedAuthorizationV1, TransactionPreparationErrorV1> {
    if !state.accounts.contains_key(&transaction.sender) {
        return Err(TransactionPreparationErrorV1::SenderStateNotFound);
    }
    let Some(policy) = state.authorization_policies.get(&transaction.sender) else {
        if transaction.authorization.policy_revision != LEGACY_AUTHORIZATION_POLICY_REVISION
            || Address::from_public_key(&transaction.sender_public_key) != transaction.sender
        {
            return Err(TransactionPreparationErrorV1::SenderAuthorizationInvalid);
        }
        return Ok(PreparedAuthorizationV1::AccountKey);
    };
    policy
        .validate()
        .map_err(|_| TransactionPreparationErrorV1::InvalidState)?;
    if transaction.authorization.policy_revision != policy.revision() {
        return Err(TransactionPreparationErrorV1::SenderAuthorizationInvalid);
    }
    if &transaction.sender_public_key == policy.active_transaction_key() {
        return Ok(PreparedAuthorizationV1::AccountKey);
    }

    let session_id = SessionKeyId::derive(&transaction.sender_public_key);
    let session = state
        .session_keys
        .get(&(transaction.sender, session_id))
        .ok_or(TransactionPreparationErrorV1::SenderAuthorizationInvalid)?;
    validate_session_authority(state, transaction, session, fee_reserve)?;
    Ok(PreparedAuthorizationV1::SessionKey(session_id))
}

fn validate_session_authority(
    state: &ChainState,
    transaction: &TransactionV5,
    session: &SessionKey,
    fee_reserve: Amount,
) -> Result<(), TransactionPreparationErrorV1> {
    session
        .validate()
        .map_err(|_| TransactionPreparationErrorV1::InvalidState)?;
    if session.owner != transaction.sender
        || session.session_public_key != transaction.sender_public_key
        || session.policy_revision != transaction.authorization.policy_revision
        || session.constraints.authorization_lane != transaction.authorization.lane
        || session.expires_after_epoch.get() < state.current_epoch
    {
        return Err(TransactionPreparationErrorV1::SenderAuthorizationInvalid);
    }

    let TransactionKindV1::Actions(program) = &transaction.kind else {
        return Err(TransactionPreparationErrorV1::SenderAuthorizationInvalid);
    };
    let mut principal = Amount::ZERO;
    for action in &program.actions {
        let ActionV1::Native { operation } = action else {
            return Err(TransactionPreparationErrorV1::SenderAuthorizationInvalid);
        };
        let Operation::Transfer { amount, .. } = operation.as_ref() else {
            return Err(TransactionPreparationErrorV1::SenderAuthorizationInvalid);
        };
        principal = principal
            .checked_add(*amount)
            .ok_or(TransactionPreparationErrorV1::InvalidState)?;
    }
    let constraints = &session.constraints;
    if !constraints.allowed_operations.transfer
        || principal > constraints.max_amount_per_use
        || session
            .spent_amount
            .checked_add(principal)
            .ok_or(TransactionPreparationErrorV1::InvalidState)?
            > constraints.total_amount_budget
        || fee_reserve > constraints.max_fee_per_use
        || session
            .spent_fees
            .checked_add(fee_reserve)
            .ok_or(TransactionPreparationErrorV1::InvalidState)?
            > constraints.total_fee_budget
    {
        return Err(TransactionPreparationErrorV1::SenderAuthorizationInvalid);
    }
    Ok(())
}

fn sender_nonce(
    state: &ChainState,
    sender: Address,
    lane: AuthorizationLaneId,
) -> Result<Nonce, TransactionPreparationErrorV1> {
    if lane.is_default() {
        return state
            .accounts
            .get(&sender)
            .map(|account| Nonce::new(account.nonce))
            .ok_or(TransactionPreparationErrorV1::SenderStateNotFound);
    }
    let lane_state = state
        .authorization_lanes
        .get(&(sender, lane))
        .ok_or(TransactionPreparationErrorV1::SenderStateNotFound)?;
    if lane_state.owner != sender || lane_state.id != lane {
        return Err(TransactionPreparationErrorV1::InvalidState);
    }
    Ok(lane_state.next_nonce)
}

fn payer_balance(
    state: &ChainState,
    payer: FeePayerV1,
) -> Result<Amount, TransactionPreparationErrorV1> {
    if payer.lane.is_default() {
        return state
            .accounts
            .get(&payer.address)
            .map(|account| account.balance)
            .ok_or(TransactionPreparationErrorV1::FeePayerStateNotFound);
    }
    let lane = state
        .authorization_lanes
        .get(&(payer.address, payer.lane))
        .ok_or(TransactionPreparationErrorV1::FeePayerStateNotFound)?;
    if lane.owner != payer.address || lane.id != payer.lane {
        return Err(TransactionPreparationErrorV1::InvalidState);
    }
    Ok(lane.fee_balance)
}

fn prepare_sponsor_use(
    state: &ChainState,
    transaction: &TransactionV5,
    sponsor_use: &crate::SponsorUseV1,
    height: BlockHeight,
    fee_reserve: Amount,
) -> Result<(), TransactionPreparationErrorV1> {
    let grant = &sponsor_use.grant;
    if !grant.validity.contains(height)
        || !account_key_is_current(state, grant.sponsor, &grant.sponsor_public_key)?
    {
        return Err(TransactionPreparationErrorV1::SponsorAuthorizationInvalid);
    }
    let key = (grant.sponsor, grant.grant_id);
    let unused =
        SponsorGrantStateV1::unused(sponsor_use.grant_digest, grant.validity.valid_until_height);
    let record = state
        .sponsor_grants
        .get(&key)
        .copied()
        .filter(|record| record.valid_until_height >= height)
        .unwrap_or(unused);
    if record.revoked {
        return Err(TransactionPreparationErrorV1::SponsorGrantRevoked);
    }
    if record.grant_digest != sponsor_use.grant_digest
        || record.valid_until_height != grant.validity.valid_until_height
    {
        return Err(TransactionPreparationErrorV1::SponsorGrantMismatch);
    }
    if record.next_use_nonce != sponsor_use.use_nonce {
        return Err(TransactionPreparationErrorV1::SponsorNonceMismatch);
    }
    if record.uses.get() >= grant.max_uses {
        return Err(TransactionPreparationErrorV1::SponsorUsesExhausted);
    }
    if record
        .total_charged
        .checked_add(fee_reserve)
        .ok_or(TransactionPreparationErrorV1::InvalidState)?
        > grant.max_cumulative_fee
    {
        return Err(TransactionPreparationErrorV1::SponsorBudgetExceeded);
    }
    if transaction.sender != grant.sender {
        return Err(TransactionPreparationErrorV1::SponsorGrantMismatch);
    }
    Ok(())
}

/// Validates and batches every durable sponsor identity in one transaction.
fn prepare_sponsor_storage(
    state: &ChainState,
    transaction: &TransactionV5,
    height: BlockHeight,
) -> Result<(), TransactionPreparationErrorV1> {
    let mut candidates = Vec::new();
    if let FeePaymentV1::Sponsored(sponsor_use) = &transaction.fee_payment {
        candidates.push((
            (sponsor_use.grant.sponsor, sponsor_use.grant.grant_id),
            SponsorGrantStateV1::unused(
                sponsor_use.grant_digest,
                sponsor_use.grant.validity.valid_until_height,
            ),
        ));
    }
    let TransactionKindV1::Actions(program) = &transaction.kind else {
        return state
            .sponsor_grants
            .ensure_can_set_batch(candidates)
            .map_err(map_sponsor_book_preparation_error);
    };
    for action in &program.actions {
        match action {
            ActionV1::RevokeSponsorGrant { grant_id } => {
                let materialized = state
                    .sponsor_grants
                    .get(&(transaction.sender, *grant_id))
                    .is_some_and(|record| record.valid_until_height >= height);
                if !materialized {
                    return Err(TransactionPreparationErrorV1::SponsorGrantNotMaterialized);
                }
            }
            ActionV1::RevokeSignedSponsorGrant { grant } => {
                if grant.validity.valid_until_height < height {
                    return Err(TransactionPreparationErrorV1::SponsorGrantExpired);
                }
                let latest_start = height
                    .get()
                    .checked_add(MAX_SPONSOR_REVOCATION_LOOKAHEAD_BLOCKS_V1)
                    .map(BlockHeight::new)
                    .unwrap_or(BlockHeight::new(u64::MAX));
                if grant.validity.valid_from_height > latest_start {
                    return Err(TransactionPreparationErrorV1::SponsorGrantTooFarInFuture);
                }
                let digest = grant
                    .digest()
                    .map_err(|_| TransactionPreparationErrorV1::InvalidState)?;
                let key = (transaction.sender, grant.grant_id);
                let unused = SponsorGrantStateV1::unused(digest, grant.validity.valid_until_height);
                if let Some(record) = state
                    .sponsor_grants
                    .get(&key)
                    .filter(|record| record.valid_until_height >= height)
                {
                    if record.grant_digest != digest
                        || record.valid_until_height != grant.validity.valid_until_height
                    {
                        return Err(TransactionPreparationErrorV1::SponsorGrantMismatch);
                    }
                }
                candidates.push((key, unused));
            }
            ActionV1::Native { .. } => {}
        }
    }
    state
        .sponsor_grants
        .ensure_can_set_batch(candidates)
        .map_err(map_sponsor_book_preparation_error)
}

fn map_sponsor_book_preparation_error(
    error: SponsorGrantBookError,
) -> TransactionPreparationErrorV1 {
    match error {
        SponsorGrantBookError::ConflictingBatchIdentity => {
            TransactionPreparationErrorV1::SponsorGrantMismatch
        }
        SponsorGrantBookError::InvalidRecord | SponsorGrantBookError::InvalidIndex => {
            TransactionPreparationErrorV1::InvalidState
        }
    }
}

fn account_key_is_current(
    state: &ChainState,
    account: Address,
    key: &PublicKeyBytes,
) -> Result<bool, TransactionPreparationErrorV1> {
    if !state.accounts.contains_key(&account) {
        return Ok(false);
    }
    let Some(policy) = state.authorization_policies.get(&account) else {
        return Ok(Address::from_public_key(key) == account);
    };
    policy
        .validate()
        .map_err(|_| TransactionPreparationErrorV1::InvalidState)?;
    Ok(policy.active_transaction_key() == key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Account, AccountAuthorizationPolicy, ActionScopeV1, ActionV1, Amount, AuthorizationLane,
        AuthorizationLaneId, AuthorizationPolicyRevision, BlockHeight, ChainState, Delegation,
        Epoch, FeeBid, FeePaymentV1, Nonce, ObjectId, ObjectOwner, ObjectVersion, Operation,
        PostQuantumRoot, PostQuantumScheme, SessionAllowedOperations, SessionKeyConstraints,
        SponsorGrantId, SponsorGrantV1, SponsorUseCount, SponsorUseNonce, SponsorUseV1,
        TransactionAuthorizationV1, TransactionIndex, UnbondingKind, UnbondingRequestId, Validator,
        ValidatorStatus, ValidityWindowV1, INITIAL_AUTHORIZATION_POLICY_REVISION,
        MAX_SPONSOR_GRANT_PRUNES_PER_BLOCK_V1, REVOKE_SIGNED_SPONSOR_GRANT_V1_REQUIRED_UNITS,
        TRANSACTION_V5_PROTOCOL_VERSION,
    };
    use webc_crypto::{Hash256, Keypair};

    fn sender_paid_fixture(sender: &Keypair, recipient: &Keypair) -> TransactionV5 {
        sender_actions_fixture(
            sender,
            vec![ActionV1::native(Operation::Transfer {
                to: recipient.address(),
                amount: Amount::from_units(100),
            })],
            1_000,
        )
    }

    fn sender_actions_fixture(
        sender: &Keypair,
        actions: Vec<ActionV1>,
        gas_limit: u64,
    ) -> TransactionV5 {
        let mut transaction = TransactionV5::for_actions_unsigned(
            ChainId::devnet(),
            sender.address(),
            sender.public_key(),
            TransactionAuthorizationV1 {
                lane: AuthorizationLaneId::DEFAULT,
                policy_revision: AuthorizationPolicyRevision::new(0),
                nonce: Nonce::new(0),
            },
            ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(20)),
            actions,
            FeeBid {
                gas_limit,
                max_fee_per_unit: 5,
                priority_fee_per_unit: 1,
            },
            FeePaymentV1::SenderLane,
        )
        .expect("bounded sender fixture");
        transaction.sign(sender).expect("sender fixture signs");
        transaction
    }

    fn sponsor_transaction(
        mut transaction: TransactionV5,
        sender: &Keypair,
        sponsor: &Keypair,
    ) -> TransactionV5 {
        transaction.sender_signature = None;
        transaction.fee_bid.gas_limit = transaction
            .kind
            .required_units()
            .expect("fixture action units")
            .checked_add(SPONSOR_GRANT_USE_V1_REQUIRED_UNITS)
            .expect("fixture sponsored units");
        let maximum_charge = u128::from(transaction.fee_bid.gas_limit)
            .checked_mul(u128::from(transaction.fee_bid.max_fee_per_unit))
            .expect("fixture maximum charge");
        let validity = transaction.validity;
        let mut grant = SponsorGrantV1 {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            grant_id: SponsorGrantId::new(Hash256([0x44; 32])),
            sponsor: sponsor.address(),
            sponsor_public_key: sponsor.public_key(),
            payer_lane: AuthorizationLaneId::DEFAULT,
            sender: transaction.sender,
            site_namespace: None,
            application_namespace: None,
            action_scope: ActionScopeV1::exact(transaction.kind.digest().expect("action digest")),
            validity,
            max_fee_per_transaction: Amount::from_units(maximum_charge),
            max_cumulative_fee: Amount::from_units(
                maximum_charge
                    .checked_mul(10)
                    .expect("fixture cumulative charge"),
            ),
            max_uses: 10,
            sponsor_signature: None,
        };
        grant.sign(sponsor).expect("grant signs");
        transaction.fee_payment = FeePaymentV1::Sponsored(Box::new(
            SponsorUseV1::for_transaction(
                grant,
                SponsorUseNonce::new(0),
                &transaction.kind,
                transaction.fee_bid,
            )
            .expect("sponsor use"),
        ));
        transaction.access_list = transaction.expected_access_list().expect("exact access");
        transaction.sign(sender).expect("sponsored fixture signs");
        transaction
    }

    fn sponsored_fixture(
        sender: &Keypair,
        recipient: &Keypair,
        sponsor: &Keypair,
        exact_access: bool,
    ) -> TransactionV5 {
        let sender_paid = sender_paid_fixture(sender, recipient);
        let sender_access = sender_paid.access_list.clone();
        let mut transaction = sponsor_transaction(sender_paid, sender, sponsor);
        if !exact_access {
            transaction.sender_signature = None;
            transaction.access_list = sender_access;
            transaction
                .sign(sender)
                .expect("sender-shaped sponsor fixture signs");
        }
        transaction
    }

    fn funded_state(sender: &Keypair, sponsor: Option<&Keypair>) -> ChainState {
        let mut state = ChainState {
            current_base_fee_per_unit: 2,
            ..ChainState::default()
        };
        state.accounts.insert(
            sender.address(),
            Account::with_balance(Amount::from_units(20_000)),
        );
        if let Some(sponsor) = sponsor {
            state.accounts.insert(
                sponsor.address(),
                Account::with_balance(Amount::from_units(20_000)),
            );
        }
        state
    }

    fn prepared(state: &ChainState, transaction: TransactionV5) -> PreparedTransactionV1 {
        state
            .prepare_transaction_v1(
                ValidatedTransactionV1::validate(transaction, &ChainId::devnet())
                    .expect("fixture validates"),
                BlockHeight::new(10),
            )
            .expect("fixture prepares")
    }

    fn session_state(owner: &Keypair, session: &Keypair) -> ChainState {
        let mut state = funded_state(owner, None);
        let root = PostQuantumRoot::new(PostQuantumScheme::MlDsa65, Hash256([0x88; 32]))
            .expect("nonzero test root");
        state.authorization_policies.insert(
            owner.address(),
            AccountAuthorizationPolicy::new_v1(owner.public_key(), root).expect("test policy"),
        );
        let constraints = SessionKeyConstraints {
            authorization_lane: AuthorizationLaneId::DEFAULT,
            allowed_operations: SessionAllowedOperations::transfers_only(),
            max_amount_per_use: Amount::from_units(30_000),
            total_amount_budget: Amount::from_units(30_000),
            max_fee_per_use: Amount::from_units(5_000),
            total_fee_budget: Amount::from_units(10_000),
            lifetime_epochs: 10,
        };
        let record = SessionKey::new(
            owner.address(),
            session.public_key(),
            INITIAL_AUTHORIZATION_POLICY_REVISION,
            constraints,
            Epoch::new(10),
        )
        .expect("test session record");
        state
            .session_keys
            .insert((owner.address(), record.id), record);
        state
    }

    fn session_transaction(
        owner: &Keypair,
        session: &Keypair,
        actions: Vec<ActionV1>,
        gas_limit: u64,
    ) -> TransactionV5 {
        let mut transaction = TransactionV5::for_session_actions_unsigned(
            ChainId::devnet(),
            owner.address(),
            session.public_key(),
            TransactionAuthorizationV1 {
                lane: AuthorizationLaneId::DEFAULT,
                policy_revision: INITIAL_AUTHORIZATION_POLICY_REVISION,
                nonce: Nonce::new(0),
            },
            ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(20)),
            actions,
            FeeBid {
                gas_limit,
                max_fee_per_unit: 5,
                priority_fee_per_unit: 1,
            },
            FeePaymentV1::SenderLane,
        )
        .expect("session transaction builds");
        transaction
            .sign_with_policy_key(session)
            .expect("session transaction signs");
        transaction
    }

    fn matured_unbonding_state(
        owner: &Keypair,
        validator: &Keypair,
    ) -> (ChainState, UnbondingRequestId) {
        let mut state = funded_state(owner, None);
        let amount = Amount::from_units(100);
        let account = state
            .accounts
            .get_mut(&owner.address())
            .expect("owner account");
        account.balance = Amount::from_units(500_000);
        account.unbonding = amount;
        let request_id = state
            .unbonding
            .request(
                owner.address(),
                validator.address(),
                UnbondingKind::Delegation,
                amount,
                Epoch::new(0),
                Amount::ZERO,
            )
            .expect("unbonding request");
        state
            .unbonding
            .advance_epoch(Epoch::new(1), amount, 1, 1)
            .expect("unbonding admission");
        state
            .unbonding
            .advance_epoch(Epoch::new(3), Amount::ZERO, 1, 1)
            .expect("unbonding maturity");
        state.current_epoch = 3;
        state.minted_supply = Amount::from_units(500_100);
        state.inflation_year_start_supply = state.minted_supply;
        (state, request_id)
    }

    #[test]
    fn validation_accepts_exact_sender_and_sponsor_access() {
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let sponsor = Keypair::from_seed([3; 32]);

        assert!(ValidatedTransactionV1::validate(
            sender_paid_fixture(&sender, &recipient),
            &ChainId::devnet()
        )
        .is_ok());
        assert!(ValidatedTransactionV1::validate(
            sponsored_fixture(&sender, &recipient, &sponsor, true),
            &ChainId::devnet()
        )
        .is_ok());
    }

    #[test]
    fn validation_rejects_sender_shaped_sponsor_access_and_wrong_chain() {
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let sponsor = Keypair::from_seed([3; 32]);

        assert_eq!(
            ValidatedTransactionV1::validate(
                sponsored_fixture(&sender, &recipient, &sponsor, false),
                &ChainId::devnet(),
            ),
            Err(TransactionValidationErrorV1::InvalidAccessList)
        );
        assert_eq!(
            ValidatedTransactionV1::validate(
                sender_paid_fixture(&sender, &recipient),
                &ChainId::new("webc-other-1").expect("test chain"),
            ),
            Err(TransactionValidationErrorV1::WrongChain)
        );
    }

    #[test]
    fn sponsor_grant_state_is_exact_and_committed_by_the_state_root() {
        let sponsor = Keypair::from_seed([3; 32]);
        let grant_id = SponsorGrantId::new(Hash256([0x44; 32]));
        let record = SponsorGrantStateV1 {
            grant_digest: Hash256([0x55; 32]),
            valid_until_height: BlockHeight::new(20),
            next_use_nonce: SponsorUseNonce::new(3),
            total_charged: Amount::from_units(123),
            uses: SponsorUseCount::new(3),
            revoked: false,
        };
        let value = serde_json::to_value(record).expect("grant state serializes");
        assert_eq!(value["next_use_nonce"], "3");
        assert_eq!(value["uses"], "3");
        assert_eq!(value["total_charged"], "123");

        let state = ChainState::default();
        let before = state.state_root().expect("empty state root");
        let mut with_grant = state;
        with_grant
            .sponsor_grants
            .set((sponsor.address(), grant_id), record)
            .expect("valid grant record");
        assert_ne!(with_grant.state_root().expect("grant state root"), before);
        let restored: ChainState =
            bincode::deserialize(&bincode::serialize(&with_grant).expect("state serializes"))
                .expect("state restores");
        assert_eq!(restored, with_grant);
    }

    #[test]
    fn preparation_is_pure_and_checks_height_nonce_fee_and_reserve() {
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let state = funded_state(&sender, None);
        let before = state.clone();
        let prepared = state
            .prepare_transaction_v1(
                ValidatedTransactionV1::validate(
                    sender_paid_fixture(&sender, &recipient),
                    &ChainId::devnet(),
                )
                .expect("valid sender transaction"),
                BlockHeight::new(10),
            )
            .expect("transaction prepares");
        assert_eq!(prepared.fee_reserve(), Amount::from_units(5_000));
        assert_eq!(prepared.required_units(), GasUnits::new(500));
        assert_eq!(prepared.base_fee_per_unit(), FeeRate::new(2));
        assert_eq!(prepared.effective_priority_fee_per_unit(), FeeRate::new(1));
        assert_eq!(state, before);

        let outside = state.prepare_transaction_v1(
            ValidatedTransactionV1::validate(
                sender_paid_fixture(&sender, &recipient),
                &ChainId::devnet(),
            )
            .expect("valid sender transaction"),
            BlockHeight::new(21),
        );
        assert_eq!(
            outside,
            Err(TransactionPreparationErrorV1::HeightOutsideValidity)
        );

        let mut wrong_nonce = sender_paid_fixture(&sender, &recipient);
        wrong_nonce.authorization.nonce = Nonce::new(1);
        wrong_nonce.sender_signature = None;
        wrong_nonce.sign(&sender).expect("wrong nonce signs");
        assert_eq!(
            state.prepare_transaction_v1(
                ValidatedTransactionV1::validate(wrong_nonce, &ChainId::devnet())
                    .expect("nonce is stateful"),
                BlockHeight::new(10),
            ),
            Err(TransactionPreparationErrorV1::SenderNonceMismatch)
        );

        let mut poor_state = state;
        poor_state
            .accounts
            .get_mut(&sender.address())
            .expect("sender account")
            .balance = Amount::from_units(4_999);
        assert_eq!(
            poor_state.prepare_transaction_v1(
                ValidatedTransactionV1::validate(
                    sender_paid_fixture(&sender, &recipient),
                    &ChainId::devnet(),
                )
                .expect("valid sender transaction"),
                BlockHeight::new(10),
            ),
            Err(TransactionPreparationErrorV1::InsufficientFeeReserve)
        );
    }

    #[test]
    fn preparation_checks_sponsor_replay_revocation_and_cumulative_budget() {
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let sponsor = Keypair::from_seed([3; 32]);
        let transaction = sponsored_fixture(&sender, &recipient, &sponsor, true);
        let FeePaymentV1::Sponsored(use_record) = &transaction.fee_payment else {
            panic!("sponsored fixture")
        };
        let key = (use_record.grant.sponsor, use_record.grant.grant_id);
        let digest = use_record.grant_digest;
        let mut state = funded_state(&sender, Some(&sponsor));
        state
            .accounts
            .get_mut(&sponsor.address())
            .expect("sponsor account")
            .balance = Amount::from_units(2_000_000);

        assert_eq!(
            transaction.required_units(),
            Ok(500 + SPONSOR_GRANT_USE_V1_REQUIRED_UNITS)
        );

        assert!(state
            .prepare_transaction_v1(
                ValidatedTransactionV1::validate(transaction.clone(), &ChainId::devnet())
                    .expect("valid sponsored transaction"),
                BlockHeight::new(10),
            )
            .is_ok());

        let mut replayed = state.clone();
        replayed
            .sponsor_grants
            .set(
                key,
                SponsorGrantStateV1 {
                    grant_digest: digest,
                    valid_until_height: use_record.grant.validity.valid_until_height,
                    next_use_nonce: SponsorUseNonce::new(1),
                    total_charged: Amount::ZERO,
                    uses: SponsorUseCount::new(1),
                    revoked: false,
                },
            )
            .expect("valid replay record");
        assert_eq!(
            replayed.prepare_transaction_v1(
                ValidatedTransactionV1::validate(transaction.clone(), &ChainId::devnet())
                    .expect("valid sponsored transaction"),
                BlockHeight::new(10),
            ),
            Err(TransactionPreparationErrorV1::SponsorNonceMismatch)
        );

        let mut revoked = state.clone();
        let mut revoked_record =
            SponsorGrantStateV1::unused(digest, use_record.grant.validity.valid_until_height);
        revoked_record.revoked = true;
        revoked
            .sponsor_grants
            .set(key, revoked_record)
            .expect("valid revoked record");
        assert_eq!(
            revoked.prepare_transaction_v1(
                ValidatedTransactionV1::validate(transaction.clone(), &ChainId::devnet())
                    .expect("valid sponsored transaction"),
                BlockHeight::new(10),
            ),
            Err(TransactionPreparationErrorV1::SponsorGrantRevoked)
        );

        let mut exhausted = state;
        let mut exhausted_record =
            SponsorGrantStateV1::unused(digest, use_record.grant.validity.valid_until_height);
        exhausted_record.total_charged = use_record.grant.max_cumulative_fee;
        exhausted
            .sponsor_grants
            .set(key, exhausted_record)
            .expect("valid exhausted record");
        assert_eq!(
            exhausted.prepare_transaction_v1(
                ValidatedTransactionV1::validate(transaction, &ChainId::devnet())
                    .expect("valid sponsored transaction"),
                BlockHeight::new(10),
            ),
            Err(TransactionPreparationErrorV1::SponsorBudgetExceeded)
        );
    }

    #[test]
    fn action_program_commits_ordered_transfers_events_and_exact_fee() {
        let sender = Keypair::from_seed([1; 32]);
        let first = Keypair::from_seed([2; 32]);
        let second = Keypair::from_seed([4; 32]);
        let transaction = sender_actions_fixture(
            &sender,
            vec![
                ActionV1::native(Operation::Transfer {
                    to: first.address(),
                    amount: Amount::from_units(100),
                }),
                ActionV1::native(Operation::Transfer {
                    to: second.address(),
                    amount: Amount::from_units(200),
                }),
            ],
            1_000,
        );
        let mut state = funded_state(&sender, None);
        state.minted_supply = Amount::from_units(20_000);
        state.inflation_year_start_supply = state.minted_supply;
        let success_prepared = prepared(&state, transaction);

        let executed = state
            .execute_prepared_transaction_v1(
                success_prepared,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("two transfers execute");
        let receipt = executed.receipt();

        assert_eq!(receipt.status, ReceiptStatusV1::Succeeded);
        assert_eq!(receipt.fee_summary.units_consumed, GasUnits::new(1_000));
        assert_eq!(receipt.fee_summary.charged, Amount::from_units(3_000));
        assert_eq!(receipt.fee_summary.refund, Amount::from_units(2_000));
        assert_eq!(receipt.fee_summary.burned, Amount::from_units(1_000));
        assert_eq!(
            receipt.fee_summary.validator_reward,
            Amount::from_units(2_000)
        );
        assert_eq!(receipt.events.len(), 2);
        assert_eq!(receipt.events[0].action_index, ActionIndex::new(0));
        assert_eq!(receipt.events[1].action_index, ActionIndex::new(1));
        assert_eq!(receipt.events[0].event_index, EventIndex::new(0));
        assert_eq!(receipt.events[1].event_index, EventIndex::new(1));
        assert_eq!(state.accounts[&sender.address()].nonce, 1);
        assert_eq!(
            state.accounts[&sender.address()].balance,
            Amount::from_units(16_700)
        );
        assert_eq!(
            state.accounts[&first.address()].balance,
            Amount::from_units(100)
        );
        assert_eq!(
            state.accounts[&second.address()].balance,
            Amount::from_units(200)
        );
        assert!(
            state
                .supply_invariant_report()
                .expect("supply report")
                .balanced
        );
    }

    #[test]
    fn action_program_reuses_ordered_object_transitions() {
        let sender = Keypair::from_seed([1; 32]);
        let new_owner = Keypair::from_seed([2; 32]);
        let object_id = ObjectId::new(Hash256([0x91; 32]));
        let namespace = Hash256([0x92; 32]);
        let transaction = sender_actions_fixture(
            &sender,
            vec![
                ActionV1::native(Operation::CreateObject {
                    object_id,
                    namespace,
                    data: vec![1, 2],
                }),
                ActionV1::native(Operation::MutateObject {
                    object_id,
                    namespace,
                    expected_version: ObjectVersion::INITIAL,
                    data: vec![3, 4],
                }),
                ActionV1::native(Operation::TransferObject {
                    object_id,
                    namespace,
                    expected_version: ObjectVersion::new(2),
                    new_owner: new_owner.address(),
                }),
            ],
            60_000,
        );
        let mut state = funded_state(&sender, None);
        state
            .accounts
            .get_mut(&sender.address())
            .expect("sender account")
            .balance = Amount::from_units(500_000);
        state.minted_supply = Amount::from_units(500_000);
        state.inflation_year_start_supply = state.minted_supply;
        let prepared = prepared(&state, transaction);

        let receipt = state
            .execute_prepared_transaction_v1(
                prepared,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("ordered object actions execute")
            .into_receipt();

        assert_eq!(receipt.status, ReceiptStatusV1::Succeeded);
        assert_eq!(receipt.events.len(), 3);
        assert_eq!(receipt.events[0].action_index, ActionIndex::new(0));
        assert_eq!(receipt.events[1].action_index, ActionIndex::new(1));
        assert_eq!(receipt.events[2].action_index, ActionIndex::new(2));
        assert_eq!(receipt.fee_summary.charged, Amount::from_units(180_000));
        let object = &state.objects[&object_id];
        assert_eq!(object.owner, ObjectOwner::Address(new_owner.address()));
        assert_eq!(object.version, ObjectVersion::new(3));
        assert_eq!(object.data, vec![3, 4]);
        assert_eq!(state.accounts[&sender.address()].nonce, 1);
        assert!(
            state
                .supply_invariant_report()
                .expect("object action supply report")
                .balanced
        );
    }

    #[test]
    fn action_program_reuses_authorization_lane_transitions() {
        let sender = Keypair::from_seed([1; 32]);
        let lane = AuthorizationLaneId::new(Hash256([0x95; 32]));
        let transaction = sender_actions_fixture(
            &sender,
            vec![
                ActionV1::native(Operation::OpenAuthorizationLane {
                    lane,
                    fee_deposit: Amount::from_units(100_000),
                }),
                ActionV1::native(Operation::FundAuthorizationLane {
                    lane,
                    fee_deposit: Amount::from_units(20_000),
                }),
            ],
            20_000,
        );
        let mut state = funded_state(&sender, None);
        state
            .accounts
            .get_mut(&sender.address())
            .expect("sender account")
            .balance = Amount::from_units(500_000);
        state.minted_supply = Amount::from_units(500_000);
        state.inflation_year_start_supply = state.minted_supply;
        let prepared = prepared(&state, transaction);

        let receipt = state
            .execute_prepared_transaction_v1(
                prepared,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("ordered lane actions execute")
            .into_receipt();

        assert_eq!(receipt.status, ReceiptStatusV1::Succeeded);
        assert_eq!(receipt.events.len(), 2);
        assert_eq!(receipt.fee_summary.charged, Amount::from_units(60_000));
        assert_eq!(
            state.authorization_lanes[&(sender.address(), lane)].fee_balance,
            Amount::from_units(120_000)
        );
        assert_eq!(
            state.accounts[&sender.address()].balance,
            Amount::from_units(320_000)
        );
        assert_eq!(state.accounts[&sender.address()].nonce, 1);
        assert!(
            state
                .supply_invariant_report()
                .expect("lane action supply report")
                .balanced
        );
    }

    #[test]
    fn lane_funding_failure_discards_opened_child_lane() {
        let sender = Keypair::from_seed([1; 32]);
        let lane = AuthorizationLaneId::new(Hash256([0x96; 32]));
        let transaction = sender_actions_fixture(
            &sender,
            vec![
                ActionV1::native(Operation::OpenAuthorizationLane {
                    lane,
                    fee_deposit: Amount::from_units(100_000),
                }),
                ActionV1::native(Operation::FundAuthorizationLane {
                    lane,
                    fee_deposit: Amount::from_units(400_000),
                }),
            ],
            20_000,
        );
        let mut state = funded_state(&sender, None);
        state
            .accounts
            .get_mut(&sender.address())
            .expect("sender account")
            .balance = Amount::from_units(500_000);
        state.minted_supply = Amount::from_units(500_000);
        state.inflation_year_start_supply = state.minted_supply;
        let prepared = prepared(&state, transaction);

        let receipt = state
            .execute_prepared_transaction_v1(
                prepared,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("lane funding balance failure is chargeable")
            .into_receipt();

        assert_eq!(
            receipt.status,
            ReceiptStatusV1::Failed {
                code: ExecutionFailureCodeV1::InsufficientBalance,
                failed_action_index: Some(ActionIndex::new(1)),
            }
        );
        assert!(receipt.events.is_empty());
        assert!(!state
            .authorization_lanes
            .contains_key(&(sender.address(), lane)));
        assert_eq!(
            state.accounts[&sender.address()].balance,
            Amount::from_units(440_000)
        );
        assert_eq!(state.accounts[&sender.address()].nonce, 1);
        assert!(
            state
                .supply_invariant_report()
                .expect("failed lane action supply report")
                .balanced
        );
    }

    #[test]
    fn authorization_policy_install_reuses_native_transition() {
        let sender = Keypair::from_seed([1; 32]);
        let root = PostQuantumRoot::new(PostQuantumScheme::MlDsa65, Hash256([0x97; 32]))
            .expect("valid recovery root");
        let transaction = sender_actions_fixture(
            &sender,
            vec![ActionV1::native(Operation::InstallAuthorizationPolicy {
                post_quantum_root: root,
            })],
            25_000,
        );
        let mut state = funded_state(&sender, None);
        state
            .accounts
            .get_mut(&sender.address())
            .expect("sender account")
            .balance = Amount::from_units(500_000);
        state.minted_supply = Amount::from_units(500_000);
        state.inflation_year_start_supply = state.minted_supply;
        let prepared = prepared(&state, transaction);

        let receipt = state
            .execute_prepared_transaction_v1(
                prepared,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("authorization policy installs")
            .into_receipt();

        assert_eq!(receipt.status, ReceiptStatusV1::Succeeded);
        assert_eq!(receipt.events.len(), 1);
        assert_eq!(receipt.fee_summary.charged, Amount::from_units(75_000));
        let policy = &state.authorization_policies[&sender.address()];
        assert_eq!(policy.active_transaction_key(), &sender.public_key());
        assert_eq!(policy.post_quantum_root(), &root);
        assert_eq!(state.accounts[&sender.address()].nonce, 1);
        assert!(
            state
                .supply_invariant_report()
                .expect("policy install supply report")
                .balanced
        );
    }

    #[test]
    fn duplicate_policy_install_discards_first_child_policy() {
        let sender = Keypair::from_seed([1; 32]);
        let root = PostQuantumRoot::new(PostQuantumScheme::MlDsa65, Hash256([0x98; 32]))
            .expect("valid recovery root");
        let install = ActionV1::native(Operation::InstallAuthorizationPolicy {
            post_quantum_root: root,
        });
        let transaction = sender_actions_fixture(&sender, vec![install.clone(), install], 50_000);
        let mut state = funded_state(&sender, None);
        state
            .accounts
            .get_mut(&sender.address())
            .expect("sender account")
            .balance = Amount::from_units(500_000);
        state.minted_supply = Amount::from_units(500_000);
        state.inflation_year_start_supply = state.minted_supply;
        let prepared = prepared(&state, transaction);

        let receipt = state
            .execute_prepared_transaction_v1(
                prepared,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("duplicate policy install is chargeable")
            .into_receipt();

        assert_eq!(
            receipt.status,
            ReceiptStatusV1::Failed {
                code: ExecutionFailureCodeV1::Precondition,
                failed_action_index: Some(ActionIndex::new(1)),
            }
        );
        assert!(receipt.events.is_empty());
        assert!(!state.authorization_policies.contains_key(&sender.address()));
        assert_eq!(
            state.accounts[&sender.address()].balance,
            Amount::from_units(350_000)
        );
        assert_eq!(state.accounts[&sender.address()].nonce, 1);
        assert!(
            state
                .supply_invariant_report()
                .expect("failed policy install supply report")
                .balanced
        );
    }

    #[test]
    fn action_program_claims_validator_and_delegator_rewards_atomically() {
        let sender = Keypair::from_seed([1; 32]);
        let other_validator = Keypair::from_seed([2; 32]);
        let transaction = sender_actions_fixture(
            &sender,
            vec![
                ActionV1::native(Operation::ClaimValidatorRewards),
                ActionV1::native(Operation::ClaimDelegatorRewards {
                    validator: other_validator.address(),
                }),
            ],
            10_000,
        );
        let mut state = funded_state(&sender, None);
        state
            .accounts
            .get_mut(&sender.address())
            .expect("sender account")
            .balance = Amount::from_units(500_000);
        state.validators.insert(
            sender.address(),
            Validator {
                operator: sender.address(),
                consensus_key: sender.public_key(),
                self_stake: Amount::ZERO,
                delegated_stake: Amount::ZERO,
                commission_bps: 0,
                status: ValidatorStatus::PendingActivation,
                bootstrap: false,
                accumulated_rewards: Amount::from_units(50),
            },
        );
        state.delegations.insert(
            (sender.address(), other_validator.address()),
            Delegation {
                delegator: sender.address(),
                validator: other_validator.address(),
                amount: Amount::ZERO,
                accumulated_rewards: Amount::from_units(70),
            },
        );
        state.minted_supply = Amount::from_units(500_120);
        state.inflation_year_start_supply = state.minted_supply;
        let prepared = prepared(&state, transaction);

        let receipt = state
            .execute_prepared_transaction_v1(
                prepared,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("ordered reward claims execute")
            .into_receipt();

        assert_eq!(receipt.status, ReceiptStatusV1::Succeeded);
        assert_eq!(receipt.events.len(), 2);
        assert_eq!(receipt.fee_summary.charged, Amount::from_units(30_000));
        assert_eq!(
            state.accounts[&sender.address()].balance,
            Amount::from_units(470_120)
        );
        assert_eq!(
            state.validators[&sender.address()].accumulated_rewards,
            Amount::ZERO
        );
        assert_eq!(
            state.delegations[&(sender.address(), other_validator.address())].accumulated_rewards,
            Amount::ZERO
        );
        assert!(
            state
                .supply_invariant_report()
                .expect("reward claim supply report")
                .balanced
        );
    }

    #[test]
    fn missing_delegation_discards_prior_reward_claim() {
        let sender = Keypair::from_seed([1; 32]);
        let missing_validator = Keypair::from_seed([2; 32]);
        let transaction = sender_actions_fixture(
            &sender,
            vec![
                ActionV1::native(Operation::ClaimValidatorRewards),
                ActionV1::native(Operation::ClaimDelegatorRewards {
                    validator: missing_validator.address(),
                }),
            ],
            10_000,
        );
        let mut state = funded_state(&sender, None);
        state
            .accounts
            .get_mut(&sender.address())
            .expect("sender account")
            .balance = Amount::from_units(500_000);
        state.validators.insert(
            sender.address(),
            Validator {
                operator: sender.address(),
                consensus_key: sender.public_key(),
                self_stake: Amount::ZERO,
                delegated_stake: Amount::ZERO,
                commission_bps: 0,
                status: ValidatorStatus::PendingActivation,
                bootstrap: false,
                accumulated_rewards: Amount::from_units(50),
            },
        );
        state.minted_supply = Amount::from_units(500_050);
        state.inflation_year_start_supply = state.minted_supply;
        let prepared = prepared(&state, transaction);

        let receipt = state
            .execute_prepared_transaction_v1(
                prepared,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("missing delegation is chargeable")
            .into_receipt();

        assert_eq!(
            receipt.status,
            ReceiptStatusV1::Failed {
                code: ExecutionFailureCodeV1::Precondition,
                failed_action_index: Some(ActionIndex::new(1)),
            }
        );
        assert!(receipt.events.is_empty());
        assert_eq!(
            state.accounts[&sender.address()].balance,
            Amount::from_units(470_000)
        );
        assert_eq!(
            state.validators[&sender.address()].accumulated_rewards,
            Amount::from_units(50)
        );
        assert!(
            state
                .supply_invariant_report()
                .expect("failed reward claim supply report")
                .balanced
        );
    }

    #[test]
    fn matured_unbonding_claim_commits_principal_and_event() {
        let sender = Keypair::from_seed([1; 32]);
        let validator = Keypair::from_seed([2; 32]);
        let (mut state, request_id) = matured_unbonding_state(&sender, &validator);
        let transaction = sender_actions_fixture(
            &sender,
            vec![ActionV1::native(Operation::ClaimUnbonded {
                validator: validator.address(),
                request_id,
            })],
            10_000,
        );
        let prepared = prepared(&state, transaction);

        let receipt = state
            .execute_prepared_transaction_v1(
                prepared,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("matured unbonding claim executes")
            .into_receipt();

        assert_eq!(receipt.status, ReceiptStatusV1::Succeeded);
        assert_eq!(receipt.events.len(), 1);
        assert_eq!(receipt.fee_summary.charged, Amount::from_units(30_000));
        assert_eq!(
            state.accounts[&sender.address()].balance,
            Amount::from_units(470_100)
        );
        assert_eq!(state.accounts[&sender.address()].unbonding, Amount::ZERO);
        assert!(
            state
                .supply_invariant_report()
                .expect("unbonding claim supply report")
                .balanced
        );
    }

    #[test]
    fn duplicate_unbonding_claim_discards_first_child_claim() {
        let sender = Keypair::from_seed([1; 32]);
        let validator = Keypair::from_seed([2; 32]);
        let (mut state, request_id) = matured_unbonding_state(&sender, &validator);
        let claim = ActionV1::native(Operation::ClaimUnbonded {
            validator: validator.address(),
            request_id,
        });
        let transaction = sender_actions_fixture(&sender, vec![claim.clone(), claim], 20_000);
        let prepared = prepared(&state, transaction);

        let receipt = state
            .execute_prepared_transaction_v1(
                prepared,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("duplicate claim is chargeable")
            .into_receipt();

        assert_eq!(
            receipt.status,
            ReceiptStatusV1::Failed {
                code: ExecutionFailureCodeV1::Precondition,
                failed_action_index: Some(ActionIndex::new(1)),
            }
        );
        assert!(receipt.events.is_empty());
        assert_eq!(
            state.accounts[&sender.address()].balance,
            Amount::from_units(440_000)
        );
        assert_eq!(
            state.accounts[&sender.address()].unbonding,
            Amount::from_units(100)
        );
        assert_eq!(
            state
                .unbonding
                .get(request_id)
                .expect("request remains")
                .withdrawable,
            Amount::from_units(100)
        );
        assert!(
            state
                .supply_invariant_report()
                .expect("failed unbonding claim supply report")
                .balanced
        );
    }

    #[test]
    fn object_precondition_failure_discards_child_and_events() {
        let sender = Keypair::from_seed([1; 32]);
        let object_id = ObjectId::new(Hash256([0x93; 32]));
        let namespace = Hash256([0x94; 32]);
        let transaction = sender_actions_fixture(
            &sender,
            vec![
                ActionV1::native(Operation::CreateObject {
                    object_id,
                    namespace,
                    data: vec![1],
                }),
                ActionV1::native(Operation::MutateObject {
                    object_id,
                    namespace,
                    expected_version: ObjectVersion::new(9),
                    data: vec![2],
                }),
            ],
            40_000,
        );
        let mut state = funded_state(&sender, None);
        state
            .accounts
            .get_mut(&sender.address())
            .expect("sender account")
            .balance = Amount::from_units(500_000);
        state.minted_supply = Amount::from_units(500_000);
        state.inflation_year_start_supply = state.minted_supply;
        let prepared = prepared(&state, transaction);

        let receipt = state
            .execute_prepared_transaction_v1(
                prepared,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("object version failure is chargeable")
            .into_receipt();

        assert_eq!(
            receipt.status,
            ReceiptStatusV1::Failed {
                code: ExecutionFailureCodeV1::ObjectVersionMismatch,
                failed_action_index: Some(ActionIndex::new(1)),
            }
        );
        assert!(receipt.events.is_empty());
        assert_eq!(receipt.fee_summary.charged, Amount::from_units(120_000));
        assert!(!state.objects.contains_key(&object_id));
        assert_eq!(state.accounts[&sender.address()].nonce, 1);
        assert!(
            state
                .supply_invariant_report()
                .expect("failed object action supply report")
                .balanced
        );
    }

    #[test]
    fn failed_action_rolls_back_principal_but_commits_nonce_and_fee() {
        let sender = Keypair::from_seed([1; 32]);
        let first = Keypair::from_seed([2; 32]);
        let second = Keypair::from_seed([4; 32]);
        let never_attempted = Keypair::from_seed([6; 32]);
        let unrelated = Keypair::from_seed([7; 32]);
        let unrelated_recipient = Keypair::from_seed([8; 32]);
        let transaction = sender_actions_fixture(
            &sender,
            vec![
                ActionV1::native(Operation::Transfer {
                    to: first.address(),
                    amount: Amount::from_units(10_000),
                }),
                ActionV1::native(Operation::Transfer {
                    to: second.address(),
                    amount: Amount::from_units(10_000),
                }),
                ActionV1::native(Operation::Transfer {
                    to: never_attempted.address(),
                    amount: Amount::from_units(1),
                }),
            ],
            1_500,
        );
        let mut state = funded_state(&sender, None);
        state.accounts.insert(
            unrelated.address(),
            Account::with_balance(Amount::from_units(10_000)),
        );
        state.minted_supply = Amount::from_units(30_000);
        state.inflation_year_start_supply = state.minted_supply;
        let failed_prepared = prepared(&state, transaction);

        let executed = state
            .execute_prepared_transaction_v1(
                failed_prepared,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("chargeable failure is an executed result");

        assert_eq!(
            executed.receipt().status,
            ReceiptStatusV1::Failed {
                code: ExecutionFailureCodeV1::InsufficientBalance,
                failed_action_index: Some(ActionIndex::new(1)),
            }
        );
        assert!(executed.receipt().events.is_empty());
        assert_eq!(
            executed.receipt().fee_summary.units_consumed,
            GasUnits::new(1_000)
        );
        assert_eq!(state.accounts[&sender.address()].nonce, 1);
        assert_eq!(
            state.accounts[&sender.address()].balance,
            Amount::from_units(17_000)
        );
        assert!(!state.accounts.contains_key(&first.address()));
        assert!(!state.accounts.contains_key(&second.address()));
        assert!(!state.accounts.contains_key(&never_attempted.address()));
        assert!(
            state
                .supply_invariant_report()
                .expect("supply report")
                .balanced
        );

        let unrelated_transaction = sender_actions_fixture(
            &unrelated,
            vec![ActionV1::native(Operation::Transfer {
                to: unrelated_recipient.address(),
                amount: Amount::from_units(100),
            })],
            1_000,
        );
        let unrelated_prepared = prepared(&state, unrelated_transaction);
        let unrelated_receipt = state
            .execute_prepared_transaction_v1(
                unrelated_prepared,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(1)),
            )
            .expect("unrelated transaction still executes")
            .into_receipt();
        assert_eq!(unrelated_receipt.status, ReceiptStatusV1::Succeeded);
        assert_eq!(state.accounts[&unrelated.address()].nonce, 1);
        assert_eq!(
            state.accounts[&unrelated_recipient.address()].balance,
            Amount::from_units(100)
        );
        assert!(
            state
                .supply_invariant_report()
                .expect("post-unrelated supply report")
                .balanced
        );
    }

    #[test]
    fn cancellation_consumes_nonce_and_fee_without_action_events() {
        let sender = Keypair::from_seed([1; 32]);
        let mut transaction = TransactionV5::for_cancel_unsigned(
            ChainId::devnet(),
            sender.address(),
            sender.public_key(),
            TransactionAuthorizationV1 {
                lane: AuthorizationLaneId::DEFAULT,
                policy_revision: AuthorizationPolicyRevision::new(0),
                nonce: Nonce::new(0),
            },
            ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(20)),
            FeeBid {
                gas_limit: 100,
                max_fee_per_unit: 5,
                priority_fee_per_unit: 1,
            },
            FeePaymentV1::SenderLane,
        );
        transaction.sign(&sender).expect("cancel signs");
        let mut state = funded_state(&sender, None);
        let prepared = prepared(&state, transaction);

        let receipt = state
            .execute_prepared_transaction_v1(
                prepared,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("cancel executes")
            .into_receipt();

        assert_eq!(receipt.status, ReceiptStatusV1::Succeeded);
        assert_eq!(receipt.fee_summary.units_consumed, GasUnits::new(50));
        assert_eq!(receipt.fee_summary.charged, Amount::from_units(150));
        assert!(receipt.events.is_empty());
        assert_eq!(state.accounts[&sender.address()].nonce, 1);
        assert_eq!(
            state.accounts[&sender.address()].balance,
            Amount::from_units(19_850)
        );
    }

    #[test]
    fn non_default_sender_lane_keeps_principal_and_fee_replay_separate() {
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let lane = AuthorizationLaneId::new(Hash256([0x55; 32]));
        let mut transaction = TransactionV5::for_actions_unsigned(
            ChainId::devnet(),
            sender.address(),
            sender.public_key(),
            TransactionAuthorizationV1 {
                lane,
                policy_revision: AuthorizationPolicyRevision::new(0),
                nonce: Nonce::new(0),
            },
            ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(20)),
            vec![ActionV1::native(Operation::Transfer {
                to: recipient.address(),
                amount: Amount::from_units(100),
            })],
            FeeBid {
                gas_limit: 1_000,
                max_fee_per_unit: 5,
                priority_fee_per_unit: 1,
            },
            FeePaymentV1::SenderLane,
        )
        .expect("lane transaction builds");
        transaction.sign(&sender).expect("lane transaction signs");
        let mut state = funded_state(&sender, None);
        state.authorization_lanes.insert(
            (sender.address(), lane),
            AuthorizationLane::new(sender.address(), lane, Amount::from_units(10_000)),
        );
        state.minted_supply = Amount::from_units(30_000);
        state.inflation_year_start_supply = state.minted_supply;
        let prepared = prepared(&state, transaction);

        state
            .execute_prepared_transaction_v1(
                prepared,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("lane transaction executes");

        assert_eq!(state.accounts[&sender.address()].nonce, 0);
        assert_eq!(
            state.accounts[&sender.address()].balance,
            Amount::from_units(19_900)
        );
        let lane_state = &state.authorization_lanes[&(sender.address(), lane)];
        assert_eq!(lane_state.next_nonce, Nonce::new(1));
        assert_eq!(lane_state.fee_balance, Amount::from_units(8_500));
        assert!(
            state
                .supply_invariant_report()
                .expect("lane supply report")
                .balanced
        );
    }

    #[test]
    fn non_default_lane_reward_claim_records_the_credited_account() {
        let sender = Keypair::from_seed([1; 32]);
        let lane = AuthorizationLaneId::new(Hash256([0x56; 32]));
        let mut transaction = TransactionV5::for_actions_unsigned(
            ChainId::devnet(),
            sender.address(),
            sender.public_key(),
            TransactionAuthorizationV1 {
                lane,
                policy_revision: AuthorizationPolicyRevision::new(0),
                nonce: Nonce::new(0),
            },
            ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(20)),
            vec![ActionV1::native(Operation::ClaimValidatorRewards)],
            FeeBid {
                gas_limit: 5_000,
                max_fee_per_unit: 5,
                priority_fee_per_unit: 1,
            },
            FeePaymentV1::SenderLane,
        )
        .expect("lane reward transaction builds");
        transaction
            .sign(&sender)
            .expect("lane reward transaction signs");
        let mut state = funded_state(&sender, None);
        state.authorization_lanes.insert(
            (sender.address(), lane),
            AuthorizationLane::new(sender.address(), lane, Amount::from_units(30_000)),
        );
        state.validators.insert(
            sender.address(),
            Validator {
                operator: sender.address(),
                consensus_key: sender.public_key(),
                self_stake: Amount::ZERO,
                delegated_stake: Amount::ZERO,
                commission_bps: 0,
                status: ValidatorStatus::PendingActivation,
                bootstrap: false,
                accumulated_rewards: Amount::from_units(50),
            },
        );
        state.minted_supply = Amount::from_units(50_050);
        state.inflation_year_start_supply = state.minted_supply;
        let prepared = prepared(&state, transaction);

        let receipt = state
            .execute_prepared_transaction_v1(
                prepared,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("non-default lane reward claim executes")
            .into_receipt();

        assert_eq!(receipt.status, ReceiptStatusV1::Succeeded);
        assert_eq!(
            state.accounts[&sender.address()].balance,
            Amount::from_units(20_050)
        );
        assert_eq!(state.accounts[&sender.address()].nonce, 0);
        assert_eq!(
            state.authorization_lanes[&(sender.address(), lane)].fee_balance,
            Amount::from_units(15_000)
        );
        assert_eq!(
            state.authorization_lanes[&(sender.address(), lane)].next_nonce,
            Nonce::new(1)
        );
        assert!(
            state
                .supply_invariant_report()
                .expect("lane reward claim supply report")
                .balanced
        );
    }

    #[test]
    fn sponsored_failure_charges_sponsor_and_advances_grant() {
        let sender = Keypair::from_seed([1; 32]);
        let first = Keypair::from_seed([2; 32]);
        let second = Keypair::from_seed([4; 32]);
        let sponsor = Keypair::from_seed([3; 32]);
        let sender_paid = sender_actions_fixture(
            &sender,
            vec![
                ActionV1::native(Operation::Transfer {
                    to: first.address(),
                    amount: Amount::from_units(15_000),
                }),
                ActionV1::native(Operation::Transfer {
                    to: second.address(),
                    amount: Amount::from_units(10_000),
                }),
            ],
            1_000,
        );
        let transaction = sponsor_transaction(sender_paid, &sender, &sponsor);
        let FeePaymentV1::Sponsored(sponsor_use) = &transaction.fee_payment else {
            panic!("sponsored fixture")
        };
        let grant_key = (sponsor.address(), sponsor_use.grant.grant_id);
        let mut state = funded_state(&sender, Some(&sponsor));
        state
            .accounts
            .get_mut(&sponsor.address())
            .expect("sponsor account")
            .balance = Amount::from_units(2_000_000);
        state.minted_supply = Amount::from_units(2_020_000);
        state.inflation_year_start_supply = state.minted_supply;
        let prepared = prepared(&state, transaction);

        let receipt = state
            .execute_prepared_transaction_v1(
                prepared,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("sponsored failure executes")
            .into_receipt();

        assert!(matches!(receipt.status, ReceiptStatusV1::Failed { .. }));
        assert_eq!(state.accounts[&sender.address()].nonce, 1);
        assert_eq!(
            state.accounts[&sender.address()].balance,
            Amount::from_units(20_000)
        );
        assert_eq!(state.accounts[&sponsor.address()].nonce, 0);
        assert_eq!(
            state.accounts[&sponsor.address()].balance,
            Amount::from_units(1_697_000)
        );
        assert!(!state.accounts.contains_key(&first.address()));
        let grant = state
            .sponsor_grants
            .get(&grant_key)
            .copied()
            .expect("sponsor grant materializes");
        assert_eq!(grant.next_use_nonce, SponsorUseNonce::new(1));
        assert_eq!(grant.uses, SponsorUseCount::new(1));
        assert_eq!(grant.total_charged, Amount::from_units(303_000));
        assert!(
            state
                .supply_invariant_report()
                .expect("supply report")
                .balanced
        );
    }

    #[test]
    fn sponsored_cancellation_charges_exact_bookkeeping_units() {
        let sender = Keypair::from_seed([1; 32]);
        let sponsor = Keypair::from_seed([3; 32]);
        let mut sender_paid = TransactionV5::for_cancel_unsigned(
            ChainId::devnet(),
            sender.address(),
            sender.public_key(),
            TransactionAuthorizationV1 {
                lane: AuthorizationLaneId::DEFAULT,
                policy_revision: AuthorizationPolicyRevision::new(0),
                nonce: Nonce::new(0),
            },
            ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(20)),
            FeeBid {
                gas_limit: crate::CANCEL_V1_REQUIRED_UNITS,
                max_fee_per_unit: 5,
                priority_fee_per_unit: 1,
            },
            FeePaymentV1::SenderLane,
        );
        sender_paid
            .sign(&sender)
            .expect("sender cancellation signs");
        let sponsored = sponsor_transaction(sender_paid, &sender, &sponsor);
        let FeePaymentV1::Sponsored(use_record) = &sponsored.fee_payment else {
            panic!("sponsored cancellation")
        };
        let grant_key = (sponsor.address(), use_record.grant.grant_id);
        let mut state = funded_state(&sender, Some(&sponsor));
        state
            .accounts
            .get_mut(&sponsor.address())
            .expect("sponsor account")
            .balance = Amount::from_units(2_000_000);

        let prepared = prepared(&state, sponsored);
        assert_eq!(
            prepared.required_units(),
            GasUnits::new(crate::CANCEL_V1_REQUIRED_UNITS + SPONSOR_GRANT_USE_V1_REQUIRED_UNITS)
        );
        let receipt = state
            .execute_prepared_transaction_v1(
                prepared,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("sponsored cancellation executes")
            .into_receipt();

        assert_eq!(receipt.status, ReceiptStatusV1::Succeeded);
        assert_eq!(
            receipt.fee_summary.units_consumed,
            GasUnits::new(crate::CANCEL_V1_REQUIRED_UNITS + SPONSOR_GRANT_USE_V1_REQUIRED_UNITS)
        );
        assert_eq!(receipt.fee_summary.charged, Amount::from_units(300_150));
        assert_eq!(
            state
                .sponsor_grants
                .get(&grant_key)
                .expect("cancellation materializes grant")
                .total_charged,
            Amount::from_units(300_150)
        );
    }

    #[test]
    fn later_action_failure_discards_child_revocation_but_records_fee_grant() {
        let grant_sponsor = Keypair::from_seed([3; 32]);
        let outer_sponsor = Keypair::from_seed([4; 32]);
        let scoped_sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let scoped = sponsored_fixture(&scoped_sender, &recipient, &grant_sponsor, true);
        let FeePaymentV1::Sponsored(scoped_use) = scoped.fee_payment else {
            panic!("scoped sponsor fixture")
        };
        let inner_key = (grant_sponsor.address(), scoped_use.grant.grant_id);
        let sender_paid = sender_actions_fixture(
            &grant_sponsor,
            vec![
                ActionV1::revoke_signed_sponsor_grant(scoped_use.grant),
                ActionV1::native(Operation::Transfer {
                    to: recipient.address(),
                    amount: Amount::from_units(30_000),
                }),
            ],
            REVOKE_SIGNED_SPONSOR_GRANT_V1_REQUIRED_UNITS + 500,
        );
        let sponsored = sponsor_transaction(sender_paid, &grant_sponsor, &outer_sponsor);
        let FeePaymentV1::Sponsored(outer_use) = &sponsored.fee_payment else {
            panic!("outer sponsor fixture")
        };
        let outer_key = (outer_sponsor.address(), outer_use.grant.grant_id);
        let mut state = funded_state(&grant_sponsor, Some(&outer_sponsor));
        state
            .accounts
            .get_mut(&outer_sponsor.address())
            .expect("outer sponsor account")
            .balance = Amount::from_units(2_000_000);

        let prepared = prepared(&state, sponsored);
        let receipt = state
            .execute_prepared_transaction_v1(
                prepared,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("chargeable later action failure executes")
            .into_receipt();

        assert!(matches!(receipt.status, ReceiptStatusV1::Failed { .. }));
        assert!(receipt.events.is_empty());
        assert!(!state.sponsor_grants.contains_key(&inner_key));
        assert_eq!(
            state
                .sponsor_grants
                .get(&outer_key)
                .expect("fee grant advances in parent")
                .uses,
            SponsorUseCount::new(1)
        );
        assert_eq!(receipt.fee_summary.charged, Amount::from_units(601_500));
    }

    #[test]
    fn revocation_blocks_later_sponsored_preparation() {
        let sponsor = Keypair::from_seed([3; 32]);
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let grant_id = SponsorGrantId::new(Hash256([0x44; 32]));
        let sponsored = sponsored_fixture(&sender, &recipient, &sponsor, true);
        let FeePaymentV1::Sponsored(sponsor_use) = &sponsored.fee_payment else {
            panic!("sponsored fixture")
        };
        let revoke = sender_actions_fixture(
            &sponsor,
            vec![ActionV1::revoke_sponsor_grant(grant_id)],
            5_000,
        );
        let mut state = funded_state(&sender, Some(&sponsor));
        state
            .accounts
            .get_mut(&sponsor.address())
            .expect("sponsor account")
            .balance = Amount::from_units(30_000);
        state
            .sponsor_grants
            .set(
                (sponsor.address(), grant_id),
                SponsorGrantStateV1::unused(
                    sponsor_use.grant_digest,
                    sponsor_use.grant.validity.valid_until_height,
                ),
            )
            .expect("valid materialized grant");
        let prepared_revoke = prepared(&state, revoke);
        let receipt = state
            .execute_prepared_transaction_v1(
                prepared_revoke,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("revocation executes")
            .into_receipt();
        assert_eq!(receipt.events.len(), 1);
        assert!(
            state
                .sponsor_grants
                .get(&(sponsor.address(), grant_id))
                .expect("revoked grant remains through expiry")
                .revoked
        );

        assert_eq!(
            state.prepare_transaction_v1(
                ValidatedTransactionV1::validate(sponsored, &ChainId::devnet())
                    .expect("sponsored wire validates"),
                BlockHeight::new(10),
            ),
            Err(TransactionPreparationErrorV1::SponsorGrantRevoked)
        );
    }

    #[test]
    fn signed_grant_revocation_blocks_first_use_and_records_authenticated_expiry() {
        let sponsor = Keypair::from_seed([3; 32]);
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let sponsored = sponsored_fixture(&sender, &recipient, &sponsor, true);
        let FeePaymentV1::Sponsored(sponsor_use) = &sponsored.fee_payment else {
            panic!("sponsored fixture")
        };
        let grant = sponsor_use.grant.clone();
        let grant_digest = sponsor_use.grant_digest;
        let grant_key = (sponsor.address(), grant.grant_id);
        let revoke = sender_actions_fixture(
            &sponsor,
            vec![ActionV1::revoke_signed_sponsor_grant(grant.clone())],
            REVOKE_SIGNED_SPONSOR_GRANT_V1_REQUIRED_UNITS,
        );
        let mut state = funded_state(&sender, Some(&sponsor));
        state
            .accounts
            .get_mut(&sponsor.address())
            .expect("sponsor account")
            .balance = Amount::from_units(1_000_000);

        let prepared_revoke = prepared(&state, revoke);
        let receipt = state
            .execute_prepared_transaction_v1(
                prepared_revoke,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("pre-use revocation executes")
            .into_receipt();

        assert_eq!(receipt.status, ReceiptStatusV1::Succeeded);
        let record = state
            .sponsor_grants
            .get(&grant_key)
            .copied()
            .expect("bounded revocation record");
        assert_eq!(record.grant_digest, grant_digest);
        assert_eq!(record.valid_until_height, grant.validity.valid_until_height);
        assert_eq!(record.uses, SponsorUseCount::new(0));
        assert_eq!(record.next_use_nonce, SponsorUseNonce::new(0));
        assert!(record.revoked);
        assert_eq!(
            state.prepare_transaction_v1(
                ValidatedTransactionV1::validate(sponsored, &ChainId::devnet())
                    .expect("sponsored wire validates"),
                BlockHeight::new(10),
            ),
            Err(TransactionPreparationErrorV1::SponsorGrantRevoked)
        );
    }

    #[test]
    fn sponsored_signed_revocation_prices_both_possible_records() {
        let grant_sponsor = Keypair::from_seed([3; 32]);
        let outer_sponsor = Keypair::from_seed([4; 32]);
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let sponsored = sponsored_fixture(&sender, &recipient, &grant_sponsor, true);
        let FeePaymentV1::Sponsored(use_record) = sponsored.fee_payment else {
            panic!("sponsored fixture")
        };
        let sender_paid_revoke = sender_actions_fixture(
            &grant_sponsor,
            vec![ActionV1::revoke_signed_sponsor_grant(use_record.grant)],
            REVOKE_SIGNED_SPONSOR_GRANT_V1_REQUIRED_UNITS + SPONSOR_GRANT_USE_V1_REQUIRED_UNITS,
        );
        let doubly_materializing =
            sponsor_transaction(sender_paid_revoke, &grant_sponsor, &outer_sponsor);

        assert_eq!(
            doubly_materializing.required_units(),
            Ok(REVOKE_SIGNED_SPONSOR_GRANT_V1_REQUIRED_UNITS + SPONSOR_GRANT_USE_V1_REQUIRED_UNITS)
        );
        doubly_materializing
            .verify_for_chain(&ChainId::devnet())
            .expect("both nested grants verify");
    }

    #[test]
    fn signed_grant_revocation_rejects_expired_and_far_future_lifetimes() {
        let sponsor = Keypair::from_seed([3; 32]);
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let sponsored = sponsored_fixture(&sender, &recipient, &sponsor, true);
        let FeePaymentV1::Sponsored(sponsor_use) = &sponsored.fee_payment else {
            panic!("sponsored fixture")
        };
        let signed_revoke = |validity: ValidityWindowV1| {
            let mut grant = sponsor_use.grant.clone();
            grant.validity = validity;
            grant.sponsor_signature = None;
            grant.sign(&sponsor).expect("adjusted grant signs");
            sender_actions_fixture(
                &sponsor,
                vec![ActionV1::revoke_signed_sponsor_grant(grant)],
                REVOKE_SIGNED_SPONSOR_GRANT_V1_REQUIRED_UNITS,
            )
        };
        let mut state = funded_state(&sender, Some(&sponsor));
        state
            .accounts
            .get_mut(&sponsor.address())
            .expect("sponsor account")
            .balance = Amount::from_units(1_000_000);

        let expired = signed_revoke(ValidityWindowV1::new(
            BlockHeight::new(1),
            BlockHeight::new(9),
        ));
        assert_eq!(
            state.prepare_transaction_v1(
                ValidatedTransactionV1::validate(expired, &ChainId::devnet())
                    .expect("expired revoke wire validates"),
                BlockHeight::new(10),
            ),
            Err(TransactionPreparationErrorV1::SponsorGrantExpired)
        );

        let first_too_far = 10_u64 + MAX_SPONSOR_REVOCATION_LOOKAHEAD_BLOCKS_V1 + 1;
        let far_future = signed_revoke(ValidityWindowV1::new(
            BlockHeight::new(first_too_far),
            BlockHeight::new(first_too_far),
        ));
        assert_eq!(
            state.prepare_transaction_v1(
                ValidatedTransactionV1::validate(far_future, &ChainId::devnet())
                    .expect("future revoke wire validates"),
                BlockHeight::new(10),
            ),
            Err(TransactionPreparationErrorV1::SponsorGrantTooFarInFuture)
        );
        assert!(state.sponsor_grants.is_empty());
    }

    #[test]
    fn expired_backlog_record_is_replaced_without_prepare_execute_divergence() {
        let sponsor = Keypair::from_seed([3; 32]);
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let sponsored = sponsored_fixture(&sender, &recipient, &sponsor, true);
        let FeePaymentV1::Sponsored(sponsor_use) = &sponsored.fee_payment else {
            panic!("sponsored fixture")
        };
        let target = (sponsor.address(), sponsor_use.grant.grant_id);
        let expected_digest = sponsor_use.grant_digest;
        let expected_expiry = sponsor_use.grant.validity.valid_until_height;
        let mut state = funded_state(&sender, Some(&sponsor));
        state
            .accounts
            .get_mut(&sponsor.address())
            .expect("sponsor account")
            .balance = Amount::from_units(2_000_000);

        for ordinal in 1..=MAX_SPONSOR_GRANT_PRUNES_PER_BLOCK_V1 {
            let mut grant_id = [0_u8; 32];
            grant_id[24..].copy_from_slice(
                &u64::try_from(ordinal)
                    .expect("test ordinal fits u64")
                    .to_be_bytes(),
            );
            state
                .sponsor_grants
                .set(
                    (sponsor.address(), SponsorGrantId::new(Hash256(grant_id))),
                    SponsorGrantStateV1::unused(Hash256([0xF0; 32]), BlockHeight::new(9)),
                )
                .expect("expired filler record");
        }
        state
            .sponsor_grants
            .set(
                target,
                SponsorGrantStateV1::unused(Hash256([0xAA; 32]), BlockHeight::new(9)),
            )
            .expect("expired target record");
        assert_eq!(
            state
                .prune_expired_sponsor_grants_v1(BlockHeight::new(10))
                .expect("bounded prune"),
            MAX_SPONSOR_GRANT_PRUNES_PER_BLOCK_V1
        );
        assert!(state.sponsor_grants.contains_key(&target));

        let prepared = prepared(&state, sponsored);
        let receipt = state
            .execute_prepared_transaction_v1(
                prepared,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("expired identity is atomically replaced")
            .into_receipt();

        assert_eq!(receipt.status, ReceiptStatusV1::Succeeded);
        let replacement = state
            .sponsor_grants
            .get(&target)
            .copied()
            .expect("replacement grant record");
        assert_eq!(replacement.grant_digest, expected_digest);
        assert_eq!(replacement.valid_until_height, expected_expiry);
        assert_eq!(replacement.uses, SponsorUseCount::new(1));
    }

    #[test]
    fn unknown_id_revocations_cannot_create_sponsor_tombstones() {
        let sponsor = Keypair::from_seed([3; 32]);
        let actions = (1_u8..=32)
            .map(|byte| ActionV1::revoke_sponsor_grant(SponsorGrantId::new(Hash256([byte; 32]))))
            .collect();
        let transaction = sender_actions_fixture(&sponsor, actions, 1_000_000);
        let state = funded_state(&sponsor, None);
        let before = state.clone();

        assert_eq!(
            state.prepare_transaction_v1(
                ValidatedTransactionV1::validate(transaction, &ChainId::devnet())
                    .expect("bounded revocation batch validates"),
                BlockHeight::new(10),
            ),
            Err(TransactionPreparationErrorV1::SponsorGrantNotMaterialized)
        );
        assert_eq!(state, before);
        assert!(state.sponsor_grants.is_empty());
    }

    #[test]
    fn stale_execution_leaves_state_unchanged() {
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let mut state = funded_state(&sender, None);
        let prepared_transfer = prepared(&state, sender_paid_fixture(&sender, &recipient));
        state.current_base_fee_per_unit = 3;
        let before_stale = state.clone();
        assert_eq!(
            state.execute_prepared_transaction_v1(
                prepared_transfer,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            ),
            Err(BlockExecutionErrorV1::StalePreparation)
        );
        assert_eq!(state, before_stale);
    }

    #[test]
    fn invalidated_preparation_returns_typed_error_without_execution_mutation() {
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let mut state = funded_state(&sender, None);
        let prepared_transfer = prepared(&state, sender_paid_fixture(&sender, &recipient));
        state
            .accounts
            .get_mut(&sender.address())
            .expect("funded sender")
            .nonce = 1;
        let before_execution = state.clone();

        assert_eq!(
            state.execute_prepared_transaction_v1(
                prepared_transfer,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            ),
            Err(BlockExecutionErrorV1::Preparation(
                TransactionPreparationErrorV1::SenderNonceMismatch,
            ))
        );
        assert_eq!(state, before_execution);
    }

    #[test]
    fn unrelated_state_change_does_not_stale_prepared_transaction() {
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let unrelated = Keypair::from_seed([9; 32]);
        let mut state = funded_state(&sender, None);
        let prepared_transfer = prepared(&state, sender_paid_fixture(&sender, &recipient));
        state.accounts.insert(
            unrelated.address(),
            Account::with_balance(Amount::from_units(7)),
        );

        state
            .execute_prepared_transaction_v1(
                prepared_transfer,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("unrelated state does not invalidate preparation");
        assert_eq!(
            state.accounts[&unrelated.address()].balance,
            Amount::from_units(7)
        );
    }

    #[test]
    fn execution_overlay_captures_only_declared_existing_records() {
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let mut state = funded_state(&sender, None);
        for seed in 10_u8..110 {
            let unrelated = Keypair::from_seed([seed; 32]);
            state.accounts.insert(
                unrelated.address(),
                Account::with_balance(Amount::from_units(u128::from(seed))),
            );
        }
        let transaction = sender_paid_fixture(&sender, &recipient);
        let overlay = SparseExecutionStateV1::capture(
            &state,
            &transaction.access_list.read_only,
            &transaction.access_list.read_write,
        )
        .expect("declared transfer inputs capture");

        assert_eq!(state.accounts.len(), 101);
        assert_eq!(overlay.state.accounts.len(), 1);
        assert!(overlay.state.accounts.contains_key(&sender.address()));
        assert!(overlay.state.objects.is_empty());
        assert_eq!(
            overlay.writes.len(),
            transaction.access_list.read_write.len()
        );
    }

    #[test]
    fn independent_fee_overlays_merge_additive_global_deltas() {
        let first_payer = Keypair::from_seed([31; 32]).address();
        let second_payer = Keypair::from_seed([32; 32]).address();
        let mut base = ChainState {
            burned_fees: Amount::from_units(100),
            validator_fee_pool: Amount::from_units(200),
            ..ChainState::default()
        };
        let mut first =
            SparseExecutionStateV1::capture(&base, &[], &[StateKey::fee_accumulator(first_payer)])
                .expect("first fee overlay captures");
        let mut second =
            SparseExecutionStateV1::capture(&base, &[], &[StateKey::fee_accumulator(second_payer)])
                .expect("second fee overlay captures from same snapshot");
        first.state.burned_fees = Amount::from_units(103);
        first.state.validator_fee_pool = Amount::from_units(204);
        second.state.burned_fees = Amount::from_units(105);
        second.state.validator_fee_pool = Amount::from_units(206);

        first.commit(&mut base).expect("first delta commits");
        second.commit(&mut base).expect("second delta merges");

        assert_eq!(base.burned_fees, Amount::from_units(108));
        assert_eq!(base.validator_fee_pool, Amount::from_units(210));
    }

    #[test]
    fn session_access_shape_is_statefully_bound_to_session_authority() {
        let owner = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let session = Keypair::from_seed([5; 32]);
        let transaction = session_transaction(
            &owner,
            &session,
            vec![ActionV1::native(Operation::Transfer {
                to: recipient.address(),
                amount: Amount::from_units(100),
            })],
            1_000,
        );
        let session_id = SessionKeyId::derive(&session.public_key());
        assert!(transaction
            .access_list
            .read_write
            .contains(&StateKey::session_key(owner.address(), session_id)));
        let state = session_state(&owner, &session);
        assert_eq!(
            prepared(&state, transaction).authorization(),
            PreparedAuthorizationV1::SessionKey(session_id)
        );

        let mut account_shaped_as_session = sender_paid_fixture(&owner, &recipient);
        account_shaped_as_session.access_list = account_shaped_as_session
            .expected_session_access_list()
            .expect("session access derives");
        account_shaped_as_session.sender_signature = None;
        account_shaped_as_session
            .sign(&owner)
            .expect("active key signs session-shaped access");
        let legacy_state = funded_state(&owner, None);
        assert_eq!(
            legacy_state.prepare_transaction_v1(
                ValidatedTransactionV1::validate(account_shaped_as_session, &ChainId::devnet(),)
                    .expect("both static authorization shapes validate"),
                BlockHeight::new(10),
            ),
            Err(TransactionPreparationErrorV1::AuthorizationAccessMismatch)
        );
    }

    #[test]
    fn session_execution_charges_actual_fee_and_only_committed_principal() {
        let owner = Keypair::from_seed([1; 32]);
        let first = Keypair::from_seed([2; 32]);
        let second = Keypair::from_seed([4; 32]);
        let session = Keypair::from_seed([5; 32]);
        let session_id = SessionKeyId::derive(&session.public_key());

        let successful = session_transaction(
            &owner,
            &session,
            vec![ActionV1::native(Operation::Transfer {
                to: first.address(),
                amount: Amount::from_units(100),
            })],
            1_000,
        );
        let mut success_state = session_state(&owner, &session);
        let prepared_success = prepared(&success_state, successful);
        success_state
            .execute_prepared_transaction_v1(
                prepared_success,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("session transfer executes");
        let success_record = &success_state.session_keys[&(owner.address(), session_id)];
        assert_eq!(success_record.spent_amount, Amount::from_units(100));
        assert_eq!(success_record.spent_fees, Amount::from_units(1_500));

        let failing = session_transaction(
            &owner,
            &session,
            vec![
                ActionV1::native(Operation::Transfer {
                    to: first.address(),
                    amount: Amount::from_units(15_000),
                }),
                ActionV1::native(Operation::Transfer {
                    to: second.address(),
                    amount: Amount::from_units(10_000),
                }),
            ],
            1_000,
        );
        let mut failure_state = session_state(&owner, &session);
        let prepared_failure = prepared(&failure_state, failing);
        let failed_receipt = failure_state
            .execute_prepared_transaction_v1(
                prepared_failure,
                BlockPositionV1::new(BlockHeight::new(10), TransactionIndex::new(0)),
            )
            .expect("session action failure is chargeable")
            .into_receipt();
        assert!(matches!(
            failed_receipt.status,
            ReceiptStatusV1::Failed { .. }
        ));
        let failure_record = &failure_state.session_keys[&(owner.address(), session_id)];
        assert_eq!(failure_record.spent_amount, Amount::ZERO);
        assert_eq!(failure_record.spent_fees, Amount::from_units(3_000));
        assert!(!failure_state.accounts.contains_key(&first.address()));
        assert!(!failure_state.accounts.contains_key(&second.address()));
    }
}
