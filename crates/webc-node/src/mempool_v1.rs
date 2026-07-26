//! Protocol-2 V5 pending-transaction policy and in-memory indexes.
//!
//! Purpose: decide bounded V5 admission, replacement, capacity eviction,
//! expiry, and restart reconstruction without performing durable writes.
//! Responsibilities: validate hostile signed transactions, fully prepare an
//! immediately runnable transaction against one state view, bound parked future
//! nonces, and produce a mutation plan that can be persisted before memory is
//! changed. Non-responsibilities: database commits, HTTP, gossip, block
//! execution, consensus, or finality.
//!
//! Data flow: the runtime asks [`V5Mempool::plan_admission`] for a pure plan,
//! commits that plan through `webc-storage`, then calls
//! [`V5Mempool::apply_committed`] as an infallible index update. Restart loads
//! the durable pending records and rebuilds these indexes under the same caps.
//!
//! Security boundary: transactions and recovered records are hostile. Global,
//! byte, and sender/lane limits are checked before constructing a durable
//! record. A future-nonce entry is only parked within the configured gap and is
//! never considered runnable until full state preparation succeeds later.

use std::collections::BTreeMap;

use webc_chain::{
    Amount, AuthorizationLaneId, BlockHeight, ChainConfig, ChainState, FeePaymentV1, Nonce,
    TransactionId, TransactionPreparationErrorV1, TransactionV5, TransactionValidationErrorV1,
    ValidatedTransactionV1, TRANSACTION_V5_PROTOCOL_VERSION,
};
use webc_crypto::Address;
use webc_storage::{
    LocalTimestampMs, PendingSlotV1, PendingTransactionRecordV1, StorageError,
    TRANSACTION_LIFECYCLE_RECORD_V1,
};

/// Default protocol-2 mempool byte budget: 64 MiB of canonical transactions.
pub const DEFAULT_V5_MEMPOOL_MAX_BYTES: usize = 64 * 1024 * 1024;
/// Default maximum number of pending protocol-2 transactions.
pub const DEFAULT_V5_MEMPOOL_MAX_TRANSACTIONS: usize = 8_192;
/// Default maximum pending transactions for one `(sender, lane)` queue.
pub const DEFAULT_V5_MEMPOOL_MAX_PER_SENDER_LANE: usize = 64;
/// Default maximum nonce distance from the committed expected nonce.
pub const DEFAULT_V5_MEMPOOL_FUTURE_NONCE_GAP: u64 = 64;
/// Default maximum blocks before the next height at which validity may start.
pub const DEFAULT_V5_MEMPOOL_FUTURE_START_BLOCKS: u64 = 128;
/// Default local retention time in milliseconds.
pub const DEFAULT_V5_MEMPOOL_TTL_MS: u64 = 120_000;
/// Default replacement bump in basis points (10%).
pub const DEFAULT_V5_REPLACEMENT_BUMP_BPS: u64 = 1_000;

/// Bounded, node-local policy for protocol-2 pending transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V5MempoolConfig {
    /// Maximum retained canonical transaction bytes.
    pub max_bytes: usize,
    /// Maximum retained transaction count.
    pub max_transactions: usize,
    /// Maximum retained count for one sender/lane queue.
    pub max_per_sender_lane: usize,
    /// Maximum accepted nonce distance from committed replay state.
    pub max_future_nonce_gap: u64,
    /// Maximum accepted validity start distance from the next block height.
    pub max_future_start_blocks: u64,
    /// Local wall-clock retention in milliseconds.
    pub ttl_ms: u64,
    /// Minimum maximum-fee increase required to replace an occupied slot.
    pub min_replacement_bump_bps: u64,
}

impl Default for V5MempoolConfig {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_V5_MEMPOOL_MAX_BYTES,
            max_transactions: DEFAULT_V5_MEMPOOL_MAX_TRANSACTIONS,
            max_per_sender_lane: DEFAULT_V5_MEMPOOL_MAX_PER_SENDER_LANE,
            max_future_nonce_gap: DEFAULT_V5_MEMPOOL_FUTURE_NONCE_GAP,
            max_future_start_blocks: DEFAULT_V5_MEMPOOL_FUTURE_START_BLOCKS,
            ttl_ms: DEFAULT_V5_MEMPOOL_TTL_MS,
            min_replacement_bump_bps: DEFAULT_V5_REPLACEMENT_BUMP_BPS,
        }
    }
}

/// Stable successful admission classification used by runtime and V2 APIs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V5InsertOutcome {
    /// The exact transaction ID was already pending; no write is required.
    DuplicateKnown,
    /// A previously empty slot was filled.
    Added,
    /// A higher maximum-fee transaction replaced the named slot occupant.
    Replaced { old_id: TransactionId },
    /// A more valuable transaction displaced the named capacity victim.
    Evicted { old_id: TransactionId },
}

/// Pure admission result to persist before mutating in-memory indexes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V5AdmissionPlan {
    outcome: V5InsertOutcome,
    record: Option<PendingTransactionRecordV1>,
    remove_id: Option<TransactionId>,
    canonical_bytes: usize,
}

impl V5AdmissionPlan {
    /// Returns the public classification for this admission.
    pub const fn outcome(&self) -> V5InsertOutcome {
        self.outcome
    }

    /// Returns the new durable pending record, absent for an exact duplicate.
    pub const fn record(&self) -> Option<&PendingTransactionRecordV1> {
        self.record.as_ref()
    }

    /// Returns the record that must be removed in the same durable batch.
    pub const fn remove_id(&self) -> Option<TransactionId> {
        self.remove_id
    }
}

/// Typed node-local admission failure; none of these consume a fee or nonce.
#[derive(Debug, thiserror::Error)]
pub enum V5MempoolError {
    /// A configured count/byte/TTL limit is zero or the bump exceeds 100%.
    #[error("invalid protocol-2 mempool configuration")]
    InvalidConfiguration,
    /// Stateless signature, structure, chain, or access validation failed.
    #[error("invalid V5 transaction: {0}")]
    Validation(#[from] TransactionValidationErrorV1),
    /// Stateful preparation of an immediately runnable transaction failed.
    #[error("V5 transaction is not currently preparable: {0}")]
    Preparation(#[from] TransactionPreparationErrorV1),
    /// State/configuration has not activated protocol 2 consistently.
    #[error("protocol-2 mempool requires matching protocol-2 state and configuration")]
    ProtocolInactive,
    /// The committed sender/lane replay state does not exist.
    #[error("V5 sender or authorization lane was not found")]
    SenderOrLaneNotFound,
    /// The signed nonce is already consumed.
    #[error("V5 nonce is below committed replay state")]
    NonceTooLow,
    /// The signed nonce exceeds the bounded parking window.
    #[error("V5 nonce is beyond the future-nonce parking limit")]
    NonceTooFarAhead,
    /// The signed validity ended before the next proposed height.
    #[error("V5 validity window is already expired")]
    ValidityExpired,
    /// The signed validity begins beyond the bounded future-start window.
    #[error("V5 validity starts too far in the future")]
    ValidityStartsTooFarAhead,
    /// A parked future-nonce transaction cannot cover static units/base fee.
    #[error("parked V5 transaction fails static fee checks")]
    ParkedFeeInvalid,
    /// The current fee payer cannot cover the maximum signed reservation.
    #[error("V5 fee payer cannot cover the maximum reserve")]
    InsufficientFeeReserve,
    /// The replacement bid is below the configured strict bump.
    #[error("V5 replacement does not meet the maximum-fee bump")]
    ReplacementUnderpriced,
    /// Count, byte, or sender/lane capacity cannot admit this transaction.
    #[error("protocol-2 mempool capacity cannot admit this transaction")]
    Capacity,
    /// JSON encoding failed after protocol validation.
    #[error("validated V5 transaction could not be measured")]
    Encoding,
    /// A durable pending-record invariant unexpectedly rejected validated data.
    #[error("validated V5 transaction could not become a pending record: {0}")]
    PendingRecord(#[from] StorageError),
    /// Restart data contains duplicate IDs/slots or exceeds configured bounds.
    #[error("durable protocol-2 pending records are inconsistent")]
    InconsistentRecovery,
}

#[derive(Clone, Debug)]
struct V5Entry {
    record: PendingTransactionRecordV1,
    canonical_bytes: usize,
}

/// Exact sender/lane queue key used for the per-principal resource cap.
type SenderLane = (Address, AuthorizationLaneId);

/// Restartable protocol-2 mempool with transaction-ID and slot indexes.
#[derive(Debug)]
pub struct V5Mempool {
    config: V5MempoolConfig,
    by_id: BTreeMap<TransactionId, V5Entry>,
    by_slot: BTreeMap<PendingSlotV1, TransactionId>,
    sender_lane_counts: BTreeMap<SenderLane, usize>,
    total_bytes: usize,
}

impl V5Mempool {
    /// Creates an empty pool after validating every resource-policy bound.
    pub fn new(config: V5MempoolConfig) -> Result<Self, V5MempoolError> {
        if config.max_bytes == 0
            || config.max_transactions == 0
            || config.max_per_sender_lane == 0
            || config.ttl_ms == 0
            || config.min_replacement_bump_bps > 10_000
        {
            return Err(V5MempoolError::InvalidConfiguration);
        }
        Ok(Self {
            config,
            by_id: BTreeMap::new(),
            by_slot: BTreeMap::new(),
            sender_lane_counts: BTreeMap::new(),
            total_bytes: 0,
        })
    }

    /// Rebuilds the exact in-memory indexes from already-decoded durable records.
    ///
    /// The runtime must revalidate stateful admissibility separately and durably
    /// remove any rejected record before gossip. This function checks signatures,
    /// IDs, slots, canonical byte sizes, duplicates, and all memory caps.
    pub fn recover(
        config: V5MempoolConfig,
        records: Vec<PendingTransactionRecordV1>,
        expected_chain: &webc_chain::ChainId,
    ) -> Result<Self, V5MempoolError> {
        let mut pool = Self::new(config)?;
        for record in records {
            record.transaction.verify_for_chain(expected_chain)?;
            if record.version != TRANSACTION_LIFECYCLE_RECORD_V1
                || record.transaction.transaction_id()? != record.transaction_id
                || PendingSlotV1::for_transaction(&record.transaction) != record.slot
                || pool.by_id.contains_key(&record.transaction_id)
                || pool.by_slot.contains_key(&record.slot)
            {
                return Err(V5MempoolError::InconsistentRecovery);
            }
            let canonical_bytes = transaction_size(&record.transaction)?;
            if !pool.fits_without_removal(record.slot, canonical_bytes) {
                return Err(V5MempoolError::InconsistentRecovery);
            }
            pool.insert_entry(V5Entry {
                record,
                canonical_bytes,
            });
        }
        Ok(pool)
    }

    /// Returns the retained transaction count.
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Returns whether no pending transaction is retained.
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Returns the retained canonical-byte total.
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Returns one retained durable record by transaction ID.
    pub fn get(&self, transaction_id: TransactionId) -> Option<&PendingTransactionRecordV1> {
        self.by_id.get(&transaction_id).map(|entry| &entry.record)
    }

    /// Purely validates and plans one admission without changing memory.
    ///
    /// Immediately runnable transactions pass complete V5 preparation against
    /// `state`. A bounded future nonce is parked after stateless and static fee
    /// checks, then must pass full preparation when it reaches the queue head.
    /// No durable record is constructed until count/byte policy has selected a
    /// legal replacement or eviction.
    pub fn plan_admission(
        &self,
        transaction: TransactionV5,
        state: &ChainState,
        chain_config: &ChainConfig,
        next_height: BlockHeight,
        now_ms: LocalTimestampMs,
    ) -> Result<V5AdmissionPlan, V5MempoolError> {
        if state.protocol_version != TRANSACTION_V5_PROTOCOL_VERSION
            || chain_config.protocol_version != TRANSACTION_V5_PROTOCOL_VERSION
            || state.chain_id != chain_config.chain_id
        {
            return Err(V5MempoolError::ProtocolInactive);
        }
        let validated = ValidatedTransactionV1::validate(transaction, &chain_config.chain_id)?;
        let transaction = validated.transaction();
        let transaction_id = transaction.transaction_id()?;
        if self.by_id.contains_key(&transaction_id) {
            return Ok(V5AdmissionPlan {
                outcome: V5InsertOutcome::DuplicateKnown,
                record: None,
                remove_id: None,
                canonical_bytes: 0,
            });
        }

        let canonical_bytes = transaction_size(transaction)?;
        if canonical_bytes > self.config.max_bytes {
            return Err(V5MempoolError::Capacity);
        }
        let expected = expected_nonce(state, transaction.sender, transaction.authorization.lane)
            .ok_or(V5MempoolError::SenderOrLaneNotFound)?;
        let actual = transaction.authorization.nonce;
        if actual < expected {
            return Err(V5MempoolError::NonceTooLow);
        }
        if actual.get().saturating_sub(expected.get()) > self.config.max_future_nonce_gap {
            return Err(V5MempoolError::NonceTooFarAhead);
        }
        if transaction.validity.valid_until_height < next_height {
            return Err(V5MempoolError::ValidityExpired);
        }
        let latest_start = next_height
            .get()
            .checked_add(self.config.max_future_start_blocks)
            .map(BlockHeight::new)
            .ok_or(V5MempoolError::ValidityStartsTooFarAhead)?;
        if transaction.validity.valid_from_height > latest_start {
            return Err(V5MempoolError::ValidityStartsTooFarAhead);
        }

        if actual != expected {
            validate_parked_fee(transaction, state)?;
        }

        let slot = PendingSlotV1::for_transaction(transaction);
        let existing_id = self.by_slot.get(&slot).copied();
        let (outcome, remove_id) = if let Some(old_id) = existing_id {
            let existing = self
                .by_id
                .get(&old_id)
                .ok_or(V5MempoolError::InconsistentRecovery)?;
            let floor = replacement_floor(
                existing.record.transaction.fee_bid.max_fee_per_unit,
                self.config.min_replacement_bump_bps,
            );
            if transaction.fee_bid.max_fee_per_unit < floor {
                return Err(V5MempoolError::ReplacementUnderpriced);
            }
            let new_total = self
                .total_bytes
                .saturating_sub(existing.canonical_bytes)
                .saturating_add(canonical_bytes);
            if new_total > self.config.max_bytes {
                return Err(V5MempoolError::Capacity);
            }
            (V5InsertOutcome::Replaced { old_id }, Some(old_id))
        } else if self.fits_without_removal(slot, canonical_bytes) {
            (V5InsertOutcome::Added, None)
        } else {
            let victim = self
                .capacity_victim(transaction, state, next_height, canonical_bytes)
                .ok_or(V5MempoolError::Capacity)?;
            (V5InsertOutcome::Evicted { old_id: victim }, Some(victim))
        };

        // Count/byte policy is settled before this one required clone. The
        // original validated value remains available to become the durable
        // record after preparation consumes its snapshot-specific clone.
        if actual == expected {
            let preparation_height = next_height.max(transaction.validity.valid_from_height);
            state.prepare_transaction_v1(validated.clone(), preparation_height, chain_config)?;
        }
        let transaction = validated.into_transaction();
        let record = PendingTransactionRecordV1::new(transaction, now_ms)?;
        Ok(V5AdmissionPlan {
            outcome,
            record: Some(record),
            remove_id,
            canonical_bytes,
        })
    }

    /// Applies one successfully persisted admission plan without further checks.
    ///
    /// The runtime calls this only after the corresponding storage batch commits.
    /// It returns no error so disk can never succeed while memory reports failure.
    pub fn apply_committed(&mut self, plan: V5AdmissionPlan) {
        if matches!(plan.outcome, V5InsertOutcome::DuplicateKnown) {
            return;
        }
        if let Some(remove_id) = plan.remove_id {
            self.remove_entry(remove_id);
        }
        if let Some(record) = plan.record {
            self.insert_entry(V5Entry {
                record,
                canonical_bytes: plan.canonical_bytes,
            });
        }
    }

    /// Removes a transaction after its durable pending deletion succeeds.
    pub fn remove_committed(&mut self, transaction_id: TransactionId) {
        self.remove_entry(transaction_id);
    }

    /// Returns locally TTL-expired IDs in deterministic transaction-ID order.
    pub fn expired_ids(&self, now_ms: LocalTimestampMs) -> Vec<TransactionId> {
        self.by_id
            .iter()
            .filter_map(|(transaction_id, entry)| {
                (now_ms
                    .get()
                    .saturating_sub(entry.record.admitted_at_ms.get())
                    >= self.config.ttl_ms)
                    .then_some(*transaction_id)
            })
            .collect()
    }

    fn fits_without_removal(&self, slot: PendingSlotV1, canonical_bytes: usize) -> bool {
        let sender_lane = (slot.sender, slot.lane);
        self.by_id.len() < self.config.max_transactions
            && self.total_bytes.saturating_add(canonical_bytes) <= self.config.max_bytes
            && self
                .sender_lane_counts
                .get(&sender_lane)
                .copied()
                .unwrap_or(0)
                < self.config.max_per_sender_lane
    }

    fn capacity_victim(
        &self,
        incoming: &TransactionV5,
        state: &ChainState,
        next_height: BlockHeight,
        incoming_bytes: usize,
    ) -> Option<TransactionId> {
        let incoming_slot = PendingSlotV1::for_transaction(incoming);
        let incoming_sender_lane = (incoming_slot.sender, incoming_slot.lane);
        let group_is_full = self
            .sender_lane_counts
            .get(&incoming_sender_lane)
            .copied()
            .unwrap_or(0)
            >= self.config.max_per_sender_lane;
        let incoming_value = transaction_value(incoming, state, next_height);
        self.by_id
            .iter()
            .filter(|(_, entry)| {
                let victim_group = (entry.record.slot.sender, entry.record.slot.lane);
                (!group_is_full || victim_group == incoming_sender_lane)
                    && transaction_value(&entry.record.transaction, state, next_height)
                        < incoming_value
                    && self
                        .total_bytes
                        .saturating_sub(entry.canonical_bytes)
                        .saturating_add(incoming_bytes)
                        <= self.config.max_bytes
            })
            .min_by(|(left_id, left), (right_id, right)| {
                transaction_value(&left.record.transaction, state, next_height)
                    .cmp(&transaction_value(
                        &right.record.transaction,
                        state,
                        next_height,
                    ))
                    .then_with(|| left_id.cmp(right_id))
            })
            .map(|(transaction_id, _)| *transaction_id)
    }

    fn insert_entry(&mut self, entry: V5Entry) {
        let transaction_id = entry.record.transaction_id;
        let slot = entry.record.slot;
        let sender_lane = (slot.sender, slot.lane);
        self.total_bytes = self.total_bytes.saturating_add(entry.canonical_bytes);
        *self.sender_lane_counts.entry(sender_lane).or_default() += 1;
        self.by_slot.insert(slot, transaction_id);
        self.by_id.insert(transaction_id, entry);
    }

    fn remove_entry(&mut self, transaction_id: TransactionId) {
        let Some(entry) = self.by_id.remove(&transaction_id) else {
            return;
        };
        self.total_bytes = self.total_bytes.saturating_sub(entry.canonical_bytes);
        self.by_slot.remove(&entry.record.slot);
        let sender_lane = (entry.record.slot.sender, entry.record.slot.lane);
        if let Some(count) = self.sender_lane_counts.get_mut(&sender_lane) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.sender_lane_counts.remove(&sender_lane);
            }
        }
    }
}

fn transaction_size(transaction: &TransactionV5) -> Result<usize, V5MempoolError> {
    serde_json::to_vec(transaction)
        .map(|bytes| bytes.len())
        .map_err(|_| V5MempoolError::Encoding)
}

fn expected_nonce(state: &ChainState, sender: Address, lane: AuthorizationLaneId) -> Option<Nonce> {
    if lane.is_default() {
        state
            .accounts
            .get(&sender)
            .map(|account| Nonce::new(account.nonce))
    } else {
        state
            .authorization_lanes
            .get(&(sender, lane))
            .map(|lane_state| lane_state.next_nonce)
    }
}

fn validate_parked_fee(
    transaction: &TransactionV5,
    state: &ChainState,
) -> Result<(), V5MempoolError> {
    let required_units = transaction.required_units()?;
    if transaction.fee_bid.gas_limit < required_units
        || transaction.fee_bid.max_fee_per_unit < state.current_base_fee_per_unit
    {
        return Err(V5MempoolError::ParkedFeeInvalid);
    }
    let reserve = Amount::from_units(
        u128::from(transaction.fee_bid.gas_limit)
            .checked_mul(u128::from(transaction.fee_bid.max_fee_per_unit))
            .ok_or(V5MempoolError::InsufficientFeeReserve)?,
    );
    let (payer, lane) = match &transaction.fee_payment {
        FeePaymentV1::SenderLane => (transaction.sender, transaction.authorization.lane),
        FeePaymentV1::Sponsored(use_v1) => (use_v1.grant.sponsor, use_v1.grant.payer_lane),
    };
    let available = if lane.is_default() {
        state.accounts.get(&payer).map(|account| account.balance)
    } else {
        state
            .authorization_lanes
            .get(&(payer, lane))
            .map(|lane_state| lane_state.fee_balance)
    }
    .ok_or(V5MempoolError::InsufficientFeeReserve)?;
    if available < reserve {
        return Err(V5MempoolError::InsufficientFeeReserve);
    }
    Ok(())
}

fn replacement_floor(existing_max_fee: u64, bump_bps: u64) -> u64 {
    let bump = u128::from(existing_max_fee).saturating_mul(u128::from(bump_bps)) / 10_000;
    let bump = u64::try_from(bump).unwrap_or(u64::MAX);
    existing_max_fee.saturating_add(bump.max(1))
}

fn transaction_value(
    transaction: &TransactionV5,
    state: &ChainState,
    next_height: BlockHeight,
) -> (bool, u64) {
    let runnable = expected_nonce(state, transaction.sender, transaction.authorization.lane)
        == Some(transaction.authorization.nonce)
        && transaction.validity.contains(next_height);
    let effective_fee = transaction
        .fee_bid
        .max_fee_per_unit
        .checked_sub(state.current_base_fee_per_unit)
        .map(|room| {
            state
                .current_base_fee_per_unit
                .saturating_add(transaction.fee_bid.priority_fee_per_unit.min(room))
        })
        .unwrap_or(0);
    (runnable, effective_fee)
}

#[cfg(test)]
mod tests {
    use super::*;
    use webc_chain::{
        Account, ActionV1, AuthorizationPolicyRevision, ChainId, FeeBid, FeePaymentV1, Operation,
        TransactionAuthorizationV1, ValidityWindowV1,
    };
    use webc_crypto::Keypair;

    const NOW: u64 = 1_700_000_000_000;

    fn state_and_config(keys: &[&Keypair]) -> (ChainState, ChainConfig) {
        let mut state = ChainState {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            current_base_fee_per_unit: 2,
            ..ChainState::default()
        };
        for key in keys {
            state.accounts.insert(
                key.address(),
                Account::with_balance(Amount::from_units(10_000_000)),
            );
        }
        let config = ChainConfig {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            ..ChainConfig::default()
        };
        (state, config)
    }

    fn transfer(
        sender: &Keypair,
        recipient: &Keypair,
        nonce: u64,
        max_fee: u64,
        priority_fee: u64,
    ) -> TransactionV5 {
        let mut transaction = TransactionV5::for_actions_unsigned(
            ChainId::devnet(),
            sender.address(),
            sender.public_key(),
            TransactionAuthorizationV1 {
                lane: AuthorizationLaneId::DEFAULT,
                policy_revision: AuthorizationPolicyRevision::new(0),
                nonce: Nonce::new(nonce),
            },
            ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(20)),
            vec![ActionV1::native(Operation::Transfer {
                to: recipient.address(),
                amount: Amount::from_units(1),
            })],
            FeeBid {
                gas_limit: 1_000,
                max_fee_per_unit: max_fee,
                priority_fee_per_unit: priority_fee,
            },
            FeePaymentV1::SenderLane,
        )
        .unwrap();
        transaction.sign(sender).unwrap();
        transaction
    }

    #[test]
    fn durable_plan_precedes_infallible_memory_update_and_duplicate_is_idempotent() {
        let alice = Keypair::from_seed([1; 32]);
        let bob = Keypair::from_seed([2; 32]);
        let (state, config) = state_and_config(&[&alice]);
        let mut pool = V5Mempool::new(V5MempoolConfig::default()).unwrap();
        let transaction = transfer(&alice, &bob, 0, 5, 1);
        let transaction_id = transaction.transaction_id().unwrap();

        let plan = pool
            .plan_admission(
                transaction.clone(),
                &state,
                &config,
                BlockHeight::new(10),
                LocalTimestampMs::new(NOW),
            )
            .unwrap();
        assert_eq!(plan.outcome(), V5InsertOutcome::Added);
        assert!(
            pool.is_empty(),
            "planning must not mutate memory before disk"
        );
        pool.apply_committed(plan);
        assert_eq!(pool.len(), 1);
        assert!(pool.get(transaction_id).is_some());

        let duplicate = pool
            .plan_admission(
                transaction,
                &state,
                &config,
                BlockHeight::new(10),
                LocalTimestampMs::new(NOW + 1),
            )
            .unwrap();
        assert_eq!(duplicate.outcome(), V5InsertOutcome::DuplicateKnown);
        assert!(duplicate.record().is_none());
        pool.apply_committed(duplicate);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn replacement_requires_ten_percent_and_names_the_durable_removal() {
        let alice = Keypair::from_seed([3; 32]);
        let bob = Keypair::from_seed([4; 32]);
        let (state, config) = state_and_config(&[&alice]);
        let mut pool = V5Mempool::new(V5MempoolConfig::default()).unwrap();
        let old = transfer(&alice, &bob, 0, 10, 1);
        let old_id = old.transaction_id().unwrap();
        let first = pool
            .plan_admission(
                old,
                &state,
                &config,
                BlockHeight::new(10),
                LocalTimestampMs::new(NOW),
            )
            .unwrap();
        pool.apply_committed(first);

        assert!(matches!(
            pool.plan_admission(
                transfer(&alice, &bob, 0, 10, 2),
                &state,
                &config,
                BlockHeight::new(10),
                LocalTimestampMs::new(NOW + 1),
            ),
            Err(V5MempoolError::ReplacementUnderpriced)
        ));
        let replacement = pool
            .plan_admission(
                transfer(&alice, &bob, 0, 11, 2),
                &state,
                &config,
                BlockHeight::new(10),
                LocalTimestampMs::new(NOW + 2),
            )
            .unwrap();
        assert_eq!(replacement.remove_id(), Some(old_id));
        assert_eq!(replacement.outcome(), V5InsertOutcome::Replaced { old_id });
        pool.apply_committed(replacement);
        assert!(pool.get(old_id).is_none());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn parked_gap_cannot_evict_a_runnable_transaction() {
        let alice = Keypair::from_seed([5; 32]);
        let carol = Keypair::from_seed([6; 32]);
        let recipient = Keypair::from_seed([7; 32]);
        let (state, config) = state_and_config(&[&alice, &carol]);
        let mut pool = V5Mempool::new(V5MempoolConfig {
            max_transactions: 1,
            ..V5MempoolConfig::default()
        })
        .unwrap();
        let runnable = pool
            .plan_admission(
                transfer(&alice, &recipient, 0, 5, 1),
                &state,
                &config,
                BlockHeight::new(10),
                LocalTimestampMs::new(NOW),
            )
            .unwrap();
        pool.apply_committed(runnable);

        assert!(matches!(
            pool.plan_admission(
                transfer(&carol, &recipient, 1, 1_000, 999),
                &state,
                &config,
                BlockHeight::new(10),
                LocalTimestampMs::new(NOW + 1),
            ),
            Err(V5MempoolError::Capacity)
        ));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn runnable_newcomer_evicts_parked_gap_and_recovery_restores_exact_indexes() {
        let alice = Keypair::from_seed([8; 32]);
        let carol = Keypair::from_seed([9; 32]);
        let recipient = Keypair::from_seed([10; 32]);
        let (state, config) = state_and_config(&[&alice, &carol]);
        let policy = V5MempoolConfig {
            max_transactions: 1,
            ..V5MempoolConfig::default()
        };
        let mut pool = V5Mempool::new(policy.clone()).unwrap();
        let parked = pool
            .plan_admission(
                transfer(&alice, &recipient, 1, 100, 98),
                &state,
                &config,
                BlockHeight::new(10),
                LocalTimestampMs::new(NOW),
            )
            .unwrap();
        let parked_id = parked.record().unwrap().transaction_id;
        pool.apply_committed(parked);

        let newcomer = pool
            .plan_admission(
                transfer(&carol, &recipient, 0, 3, 0),
                &state,
                &config,
                BlockHeight::new(10),
                LocalTimestampMs::new(NOW + 1),
            )
            .unwrap();
        assert_eq!(
            newcomer.outcome(),
            V5InsertOutcome::Evicted { old_id: parked_id }
        );
        pool.apply_committed(newcomer);
        let records = pool
            .by_id
            .values()
            .map(|entry| entry.record.clone())
            .collect();
        let recovered = V5Mempool::recover(policy, records, &ChainId::devnet()).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered.total_bytes(), pool.total_bytes());
        assert!(recovered.get(parked_id).is_none());
    }

    #[test]
    fn expiry_is_planned_without_mutating_or_overriding_consensus() {
        let alice = Keypair::from_seed([11; 32]);
        let recipient = Keypair::from_seed([12; 32]);
        let (state, config) = state_and_config(&[&alice]);
        let mut pool = V5Mempool::new(V5MempoolConfig {
            ttl_ms: 10,
            ..V5MempoolConfig::default()
        })
        .unwrap();
        let plan = pool
            .plan_admission(
                transfer(&alice, &recipient, 0, 5, 1),
                &state,
                &config,
                BlockHeight::new(10),
                LocalTimestampMs::new(NOW),
            )
            .unwrap();
        let transaction_id = plan.record().unwrap().transaction_id;
        pool.apply_committed(plan);
        assert!(pool.expired_ids(LocalTimestampMs::new(NOW + 9)).is_empty());
        assert_eq!(
            pool.expired_ids(LocalTimestampMs::new(NOW + 10)),
            vec![transaction_id]
        );
        assert_eq!(pool.len(), 1, "durable deletion must happen first");
        pool.remove_committed(transaction_id);
        assert!(pool.is_empty());
    }
}
