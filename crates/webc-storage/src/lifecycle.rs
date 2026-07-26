//! Protocol-2 pending transaction and lifecycle persistence.
//!
//! Purpose: own the versioned records and atomic storage operations that make a
//! V5 transaction restart-safe between admission and finality. Responsibilities:
//! bind each pending record to its exact transaction ID and `(sender, lane,
//! nonce)` slot, keep the two pending indexes consistent, record typed local
//! observations separately from consensus facts, and allocate durable monotonic
//! observation sequences. Non-responsibilities: signature/state admission,
//! replacement or eviction policy, gossip, block execution, and finality remain
//! node/chain responsibilities.
//!
//! Data flow: the node validates and prepares a transaction, constructs a
//! [`PendingTransactionRecordV1`], and asks [`ChainStore::store_pending_v1`] to
//! commit the transaction, slot index, lifecycle snapshots, and sequence marker
//! in one [`WriteBatch`]. Only after that commit succeeds may memory and gossip
//! observe the admission. Removal uses the same ordering and atomicity.
//!
//! Security boundary: stored bytes and caller-supplied records are hostile. Every
//! record is bounded before decoding, carries an exact schema version, and is
//! revalidated against its key, transaction ID, and slot. A missing counterpart,
//! malformed sequence, conflicting slot, or partial index is corruption or an
//! inconsistency; it is never repaired by guessing.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use webc_chain::{
    AuthorizationLaneId, BlockPositionV1, BlockV4, Nonce, ReceiptV1, TransactionId, TransactionV5,
};
use webc_crypto::Address;

use crate::chainstore::ChainStore;
use crate::kv::{KvStore, Table, WriteBatch};
use crate::record_codec::{decode, encode, StoredRecordKind};
use crate::StorageError;

/// Schema version carried by every protocol-2 lifecycle storage record.
pub const TRANSACTION_LIFECYCLE_RECORD_V1: u16 = 1;

/// Maximum pending records returned by one bounded restart scan.
pub const MAX_PENDING_TRANSACTION_SCAN_V1: usize = 8_192;

/// Meta key holding the latest allocated lifecycle observation sequence.
pub(crate) const META_LIFECYCLE_SEQUENCE: &[u8] = b"transaction_lifecycle_sequence_v1";

/// Version byte prefixed to every pending-slot key.
const PENDING_SLOT_KEY_V1: u8 = 1;

macro_rules! decimal_u64_wrapper {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            /// Constructs the typed value from its unsigned unit.
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            /// Returns the unsigned unit.
            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                if value.is_empty()
                    || (value.len() > 1 && value.starts_with('0'))
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(serde::de::Error::custom("expected canonical unsigned decimal string"));
                }
                value
                    .parse::<u64>()
                    .map(Self)
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

decimal_u64_wrapper!(
    /// Durable monotonically increasing order assigned to each lifecycle change.
    LifecycleSequence
);

decimal_u64_wrapper!(
    /// Node-supplied local Unix timestamp in milliseconds, never consensus input.
    LocalTimestampMs
);

/// Stable pending-slot identity used for replacement and cancellation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingSlotV1 {
    /// Account authorizing the transaction.
    pub sender: Address,
    /// Independent authorization lane whose nonce is consumed.
    pub lane: AuthorizationLaneId,
    /// Exact replay-protection nonce within `lane`.
    pub nonce: Nonce,
}

impl PendingSlotV1 {
    /// Derives the only valid pending slot for `transaction`.
    pub const fn for_transaction(transaction: &TransactionV5) -> Self {
        Self {
            sender: transaction.sender,
            lane: transaction.authorization.lane,
            nonce: transaction.authorization.nonce,
        }
    }

    /// Encodes the stable fixed-width table key without allocation-dependent data.
    fn key(self) -> Vec<u8> {
        let mut key = Vec::with_capacity(73);
        key.push(PENDING_SLOT_KEY_V1);
        key.extend_from_slice(&self.sender.0);
        key.extend_from_slice(&self.lane.hash().0);
        key.extend_from_slice(&self.nonce.get().to_be_bytes());
        key
    }
}

/// Typed reason a node stopped retaining a pending transaction locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum LocalDropReasonV1 {
    /// A more valuable newcomer displaced the transaction under bounded policy.
    CapacityEviction,
    /// Restart revalidation found the transaction no longer admissible.
    RevalidationFailed,
    /// A schema-1 pending transaction could not be interpreted as protocol 2.
    UnsupportedProtocolVersion,
    /// An operator explicitly removed the local pending copy.
    OperatorRequest,
    /// Another transaction for this slot finalized before the local occupant.
    FinalizedSlotConflict,
}

/// Node-local observation, which never overrides an authoritative finality fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum LocalTransactionObservationV1 {
    /// The complete transaction is durably queued.
    Queued {
        /// Local admission time; resource policy only, never consensus validity.
        observed_at_ms: LocalTimestampMs,
    },
    /// Another transaction took the same sender/lane/nonce slot.
    Replaced {
        /// Exact replacement transaction ID.
        replacement_id: TransactionId,
        /// Local replacement time.
        observed_at_ms: LocalTimestampMs,
    },
    /// The local node dropped the pending copy for a typed non-expiry reason.
    Dropped {
        /// Stable reason code safe for API projection.
        reason: LocalDropReasonV1,
        /// Local removal time.
        observed_at_ms: LocalTimestampMs,
    },
    /// Local wall-clock retention expired; consensus validity is unchanged.
    Expired {
        /// Local expiry observation time.
        observed_at_ms: LocalTimestampMs,
    },
    /// The node observed inclusion before authoritative finality was committed.
    Included {
        /// Candidate block position observed by this node.
        position: BlockPositionV1,
    },
}

/// Durable consensus fact, always preferred over local observations in APIs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TransactionConsensusFactV1 {
    /// A certified block finalized the transaction at this exact position.
    Finalized {
        /// Authoritative finalized block position.
        position: BlockPositionV1,
    },
}

/// Latest durable lifecycle projection for one transaction ID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionLifecycleV1 {
    /// Must equal [`TRANSACTION_LIFECYCLE_RECORD_V1`].
    pub version: u16,
    /// Transaction this projection describes.
    pub transaction_id: TransactionId,
    /// Global durable order of this latest projection.
    pub sequence: LifecycleSequence,
    /// Latest node-local observation, if this node has one.
    pub local_observation: Option<LocalTransactionObservationV1>,
    /// Authoritative finality fact, if consensus has finalized one.
    pub consensus_fact: Option<TransactionConsensusFactV1>,
}

impl TransactionLifecycleV1 {
    /// Validates the record version and requires at least one known fact.
    fn validate(&self) -> Result<(), StorageError> {
        if self.version != TRANSACTION_LIFECYCLE_RECORD_V1 {
            return Err(StorageError::Corruption(format!(
                "unsupported transaction lifecycle record version {}",
                self.version
            )));
        }
        if self.local_observation.is_none() && self.consensus_fact.is_none() {
            return Err(StorageError::Corruption(
                "transaction lifecycle record contains no observation or consensus fact".into(),
            ));
        }
        Ok(())
    }
}

/// Complete restart-safe pending V5 transaction record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingTransactionRecordV1 {
    /// Must equal [`TRANSACTION_LIFECYCLE_RECORD_V1`].
    pub version: u16,
    /// Domain-separated identity of `transaction`.
    pub transaction_id: TransactionId,
    /// Exact replacement/cancellation slot derived from `transaction`.
    pub slot: PendingSlotV1,
    /// Complete signed protocol-2 transaction.
    pub transaction: TransactionV5,
    /// Local admission time used only for bounded retention.
    pub admitted_at_ms: LocalTimestampMs,
}

impl PendingTransactionRecordV1 {
    /// Builds and validates a record for one already-admitted signed transaction.
    pub fn new(
        transaction: TransactionV5,
        admitted_at_ms: LocalTimestampMs,
    ) -> Result<Self, StorageError> {
        let transaction_id = transaction.transaction_id().map_err(|error| {
            StorageError::InvalidRecord(format!("cannot identify pending V5 transaction: {error}"))
        })?;
        let record = Self {
            version: TRANSACTION_LIFECYCLE_RECORD_V1,
            transaction_id,
            slot: PendingSlotV1::for_transaction(&transaction),
            transaction,
            admitted_at_ms,
        };
        record.validate_for_write()?;
        Ok(record)
    }

    /// Revalidates all self-authenticating bindings before a durable write.
    fn validate_for_write(&self) -> Result<(), StorageError> {
        if self.version != TRANSACTION_LIFECYCLE_RECORD_V1 {
            return Err(StorageError::InvalidRecord(format!(
                "unsupported pending transaction record version {}",
                self.version
            )));
        }
        self.transaction
            .verify_for_chain(&self.transaction.chain_id)
            .map_err(|error| {
                StorageError::InvalidRecord(format!("invalid pending V5 transaction: {error}"))
            })?;
        let actual_id = self.transaction.transaction_id().map_err(|error| {
            StorageError::InvalidRecord(format!("cannot identify pending V5 transaction: {error}"))
        })?;
        if actual_id != self.transaction_id {
            return Err(StorageError::InvalidRecord(
                "pending transaction ID does not match its signed transaction".into(),
            ));
        }
        if self.slot != PendingSlotV1::for_transaction(&self.transaction) {
            return Err(StorageError::InvalidRecord(
                "pending slot does not match the signed sender, lane, and nonce".into(),
            ));
        }
        Ok(())
    }

    /// Validates a decoded record and classifies failure as stored-data corruption.
    fn validate_after_read(&self) -> Result<(), StorageError> {
        self.validate_for_write().map_err(|error| {
            StorageError::Corruption(format!(
                "stored pending transaction failed validation: {error}"
            ))
        })
    }
}

/// Durable transaction-ID to finalized block-position index record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedTransactionIndexV1 {
    /// Must equal [`TRANSACTION_LIFECYCLE_RECORD_V1`].
    pub version: u16,
    /// Finalized transaction ID used as the table key.
    pub transaction_id: TransactionId,
    /// Exact position inside the stored protocol-2 block.
    pub position: BlockPositionV1,
}

impl FinalizedTransactionIndexV1 {
    fn validate(&self) -> Result<(), StorageError> {
        if self.version != TRANSACTION_LIFECYCLE_RECORD_V1 {
            return Err(StorageError::Corruption(format!(
                "unsupported finalized transaction index version {}",
                self.version
            )));
        }
        if self.position.height.get() == 0 {
            return Err(StorageError::Corruption(
                "finalized transaction index names genesis height zero".into(),
            ));
        }
        Ok(())
    }
}

/// Durable finalized V1 receipt record keyed by transaction ID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedReceiptRecordV1 {
    /// Must equal [`TRANSACTION_LIFECYCLE_RECORD_V1`].
    pub version: u16,
    /// Finalized transaction ID used as the table key.
    pub transaction_id: TransactionId,
    /// Complete independently reconcilable finalized receipt.
    pub receipt: ReceiptV1,
}

impl FinalizedReceiptRecordV1 {
    fn validate(&self) -> Result<(), StorageError> {
        if self.version != TRANSACTION_LIFECYCLE_RECORD_V1 {
            return Err(StorageError::Corruption(format!(
                "unsupported finalized receipt record version {}",
                self.version
            )));
        }
        self.receipt.validate().map_err(|error| {
            StorageError::Corruption(format!("stored finalized receipt is invalid: {error}"))
        })?;
        if self.receipt.transaction_id != self.transaction_id {
            return Err(StorageError::Corruption(
                "finalized receipt record transaction ID mismatch".into(),
            ));
        }
        Ok(())
    }
}

/// Result of an atomic pending-record admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingAdmissionOutcomeV1 {
    /// This transaction ID already has a durable lifecycle; no write occurred.
    DuplicateKnown(TransactionLifecycleV1),
    /// New pending state committed, optionally replacing the returned old state.
    Stored {
        /// Latest lifecycle for the newly queued transaction.
        queued: TransactionLifecycleV1,
        /// Latest lifecycle for the replaced transaction, when replacement occurred.
        replaced: Option<Box<TransactionLifecycleV1>>,
        /// Latest lifecycle for a capacity-evicted transaction, when one was removed.
        evicted: Option<Box<TransactionLifecycleV1>>,
    },
}

impl<K: KvStore> ChainStore<K> {
    /// Atomically stores one pending V5 transaction and its lifecycle/index state.
    ///
    /// `replaced_id` is a node-policy decision already proven by admission. When
    /// present, the current slot must point at exactly that pending ID. This method
    /// performs no fee comparison; it only enforces cross-record consistency. A
    /// known transaction ID is idempotent and returns `DuplicateKnown` unchanged.
    pub fn store_pending_v1(
        &mut self,
        record: &PendingTransactionRecordV1,
        replaced_id: Option<TransactionId>,
    ) -> Result<PendingAdmissionOutcomeV1, StorageError> {
        self.store_pending_transition_v1(record, replaced_id, None)
    }

    /// Atomically stores one pending transaction while capacity-evicting another.
    ///
    /// The evicted ID must name a complete pending record and matching slot index
    /// in a different slot. Its typed `Dropped(CapacityEviction)` lifecycle,
    /// pending deletions, the new queued record/index/lifecycle, and the shared
    /// sequence marker commit in one backend transaction.
    pub fn store_pending_with_eviction_v1(
        &mut self,
        record: &PendingTransactionRecordV1,
        evicted_id: TransactionId,
    ) -> Result<PendingAdmissionOutcomeV1, StorageError> {
        self.store_pending_transition_v1(record, None, Some(evicted_id))
    }

    fn store_pending_transition_v1(
        &mut self,
        record: &PendingTransactionRecordV1,
        replaced_id: Option<TransactionId>,
        evicted_id: Option<TransactionId>,
    ) -> Result<PendingAdmissionOutcomeV1, StorageError> {
        record.validate_for_write()?;
        if record.transaction.chain_id != self.chain_id()? {
            return Err(StorageError::InvalidRecord(
                "pending transaction targets a different chain than this store".into(),
            ));
        }

        if let Some(existing) = self.transaction_lifecycle_v1(record.transaction_id)? {
            return Ok(PendingAdmissionOutcomeV1::DuplicateKnown(existing));
        }
        if replaced_id.is_some() && evicted_id.is_some() {
            return Err(StorageError::InvalidRecord(
                "pending admission cannot replace and capacity-evict simultaneously".into(),
            ));
        }

        let slot_key = record.slot.key();
        let occupant = self.pending_id_for_slot_v1(record.slot)?;
        if occupant != replaced_id {
            return Err(StorageError::Inconsistent(format!(
                "pending slot occupant does not match requested replacement: expected {replaced_id:?}, found {occupant:?}"
            )));
        }

        let mut batch = WriteBatch::new();
        let mut next = self.latest_lifecycle_sequence_v1()?;
        let replaced = match replaced_id {
            None => None,
            Some(old_id) => {
                if old_id == record.transaction_id {
                    return Err(StorageError::InvalidRecord(
                        "a pending transaction cannot replace itself".into(),
                    ));
                }
                let old = self.pending_transaction_v1(old_id)?.ok_or_else(|| {
                    StorageError::Inconsistent(
                        "pending slot points at a transaction record that is missing".into(),
                    )
                })?;
                if old.slot != record.slot {
                    return Err(StorageError::Inconsistent(
                        "pending slot and replaced transaction disagree".into(),
                    ));
                }
                next = next_sequence(next)?;
                let lifecycle = self.lifecycle_with_local_v1(
                    old_id,
                    next,
                    LocalTransactionObservationV1::Replaced {
                        replacement_id: record.transaction_id,
                        observed_at_ms: record.admitted_at_ms,
                    },
                )?;
                batch.delete(Table::PendingTransactions, transaction_key(old_id));
                batch.put(
                    Table::TransactionLifecycle,
                    transaction_key(old_id),
                    encode(StoredRecordKind::TransactionLifecycle, &lifecycle)?,
                );
                Some(Box::new(lifecycle))
            }
        };
        let evicted = match evicted_id {
            None => None,
            Some(old_id) => {
                if old_id == record.transaction_id {
                    return Err(StorageError::InvalidRecord(
                        "a pending transaction cannot capacity-evict itself".into(),
                    ));
                }
                let old = self.pending_transaction_v1(old_id)?.ok_or_else(|| {
                    StorageError::Inconsistent(
                        "capacity eviction names a missing pending transaction".into(),
                    )
                })?;
                if old.slot == record.slot {
                    return Err(StorageError::InvalidRecord(
                        "capacity eviction cannot substitute for slot replacement".into(),
                    ));
                }
                if self.pending_id_for_slot_v1(old.slot)? != Some(old_id) {
                    return Err(StorageError::Inconsistent(
                        "capacity-evicted transaction has no matching slot index".into(),
                    ));
                }
                next = next_sequence(next)?;
                let lifecycle = self.lifecycle_with_local_v1(
                    old_id,
                    next,
                    LocalTransactionObservationV1::Dropped {
                        reason: LocalDropReasonV1::CapacityEviction,
                        observed_at_ms: record.admitted_at_ms,
                    },
                )?;
                batch.delete(Table::PendingTransactions, transaction_key(old_id));
                batch.delete(Table::PendingBySlot, old.slot.key());
                batch.put(
                    Table::TransactionLifecycle,
                    transaction_key(old_id),
                    encode(StoredRecordKind::TransactionLifecycle, &lifecycle)?,
                );
                Some(Box::new(lifecycle))
            }
        };

        next = next_sequence(next)?;
        let queued = TransactionLifecycleV1 {
            version: TRANSACTION_LIFECYCLE_RECORD_V1,
            transaction_id: record.transaction_id,
            sequence: next,
            local_observation: Some(LocalTransactionObservationV1::Queued {
                observed_at_ms: record.admitted_at_ms,
            }),
            consensus_fact: None,
        };
        batch.put(
            Table::PendingTransactions,
            transaction_key(record.transaction_id),
            encode(StoredRecordKind::PendingTransaction, record)?,
        );
        batch.put(
            Table::PendingBySlot,
            slot_key,
            transaction_key(record.transaction_id),
        );
        batch.put(
            Table::TransactionLifecycle,
            transaction_key(record.transaction_id),
            encode(StoredRecordKind::TransactionLifecycle, &queued)?,
        );
        batch.put(
            Table::Meta,
            META_LIFECYCLE_SEQUENCE,
            next.get().to_be_bytes().to_vec(),
        );
        self.backend_mut().commit(batch)?;

        Ok(PendingAdmissionOutcomeV1::Stored {
            queued,
            replaced,
            evicted,
        })
    }

    /// Atomically removes a pending transaction and records a typed local status.
    ///
    /// A missing pending record is idempotent when a lifecycle is already known.
    /// Consensus facts are retained unchanged and therefore still win API
    /// presentation over this local observation.
    pub fn remove_pending_v1(
        &mut self,
        transaction_id: TransactionId,
        observation: LocalTransactionObservationV1,
    ) -> Result<Option<TransactionLifecycleV1>, StorageError> {
        if !matches!(
            observation,
            LocalTransactionObservationV1::Dropped { .. }
                | LocalTransactionObservationV1::Expired { .. }
        ) {
            return Err(StorageError::InvalidRecord(
                "pending removal requires a Dropped or Expired observation".into(),
            ));
        }
        let Some(record) = self.pending_transaction_v1(transaction_id)? else {
            return self.transaction_lifecycle_v1(transaction_id);
        };
        if self.pending_id_for_slot_v1(record.slot)? != Some(transaction_id) {
            return Err(StorageError::Inconsistent(
                "pending transaction exists without its matching slot index".into(),
            ));
        }

        let sequence = next_sequence(self.latest_lifecycle_sequence_v1()?)?;
        let lifecycle = self.lifecycle_with_local_v1(transaction_id, sequence, observation)?;
        let mut batch = WriteBatch::new();
        batch.delete(Table::PendingTransactions, transaction_key(transaction_id));
        batch.delete(Table::PendingBySlot, record.slot.key());
        batch.put(
            Table::TransactionLifecycle,
            transaction_key(transaction_id),
            encode(StoredRecordKind::TransactionLifecycle, &lifecycle)?,
        );
        batch.put(
            Table::Meta,
            META_LIFECYCLE_SEQUENCE,
            sequence.get().to_be_bytes().to_vec(),
        );
        self.backend_mut().commit(batch)?;
        Ok(Some(lifecycle))
    }

    /// Records a non-final candidate inclusion while retaining the pending copy.
    ///
    /// A proposal may fail to finalize, so candidate inclusion must not delete
    /// restart-safe pending bytes. Authoritative finalization later removes the
    /// pending indexes in the same batch as the block and receipt indexes.
    pub fn observe_pending_included_v1(
        &mut self,
        transaction_id: TransactionId,
        position: BlockPositionV1,
    ) -> Result<TransactionLifecycleV1, StorageError> {
        if self.pending_transaction_v1(transaction_id)?.is_none() {
            return Err(StorageError::InvalidRecord(
                "cannot observe inclusion for a transaction that is not pending".into(),
            ));
        }
        let sequence = next_sequence(self.latest_lifecycle_sequence_v1()?)?;
        let lifecycle = self.lifecycle_with_local_v1(
            transaction_id,
            sequence,
            LocalTransactionObservationV1::Included { position },
        )?;
        let mut batch = WriteBatch::new();
        batch.put(
            Table::TransactionLifecycle,
            transaction_key(transaction_id),
            encode(StoredRecordKind::TransactionLifecycle, &lifecycle)?,
        );
        batch.put(
            Table::Meta,
            META_LIFECYCLE_SEQUENCE,
            sequence.get().to_be_bytes().to_vec(),
        );
        self.backend_mut().commit(batch)?;
        Ok(lifecycle)
    }

    /// Returns one pending record by transaction ID, validating key bindings.
    pub fn pending_transaction_v1(
        &self,
        transaction_id: TransactionId,
    ) -> Result<Option<PendingTransactionRecordV1>, StorageError> {
        let Some(bytes) = self
            .backend()
            .get(Table::PendingTransactions, &transaction_key(transaction_id))?
        else {
            return Ok(None);
        };
        let record: PendingTransactionRecordV1 =
            decode(StoredRecordKind::PendingTransaction, &bytes)?;
        record.validate_after_read()?;
        if record.transaction_id != transaction_id {
            return Err(StorageError::Corruption(
                "pending transaction record does not match its table key".into(),
            ));
        }
        Ok(Some(record))
    }

    /// Returns the transaction ID currently occupying `slot`, if any.
    pub fn pending_id_for_slot_v1(
        &self,
        slot: PendingSlotV1,
    ) -> Result<Option<TransactionId>, StorageError> {
        let Some(bytes) = self.backend().get(Table::PendingBySlot, &slot.key())? else {
            return Ok(None);
        };
        Ok(Some(transaction_id_from_key(&bytes)?))
    }

    /// Returns one durable lifecycle projection by transaction ID.
    pub fn transaction_lifecycle_v1(
        &self,
        transaction_id: TransactionId,
    ) -> Result<Option<TransactionLifecycleV1>, StorageError> {
        let Some(bytes) = self.backend().get(
            Table::TransactionLifecycle,
            &transaction_key(transaction_id),
        )?
        else {
            return Ok(None);
        };
        let lifecycle: TransactionLifecycleV1 =
            decode(StoredRecordKind::TransactionLifecycle, &bytes)?;
        lifecycle.validate()?;
        if lifecycle.transaction_id != transaction_id {
            return Err(StorageError::Corruption(
                "transaction lifecycle record does not match its table key".into(),
            ));
        }
        Ok(Some(lifecycle))
    }

    /// Returns up to 8,192 pending records for bounded restart revalidation.
    pub fn pending_transactions_v1(
        &self,
        limit: usize,
    ) -> Result<Vec<PendingTransactionRecordV1>, StorageError> {
        if limit > MAX_PENDING_TRANSACTION_SCAN_V1 {
            return Err(StorageError::InvalidRecord(format!(
                "pending scan limit {limit} exceeds {MAX_PENDING_TRANSACTION_SCAN_V1}"
            )));
        }
        self.backend()
            .scan(Table::PendingTransactions, None, limit)?
            .into_iter()
            .map(|(key, bytes)| {
                let expected = transaction_id_from_key(&key)?;
                let record: PendingTransactionRecordV1 =
                    decode(StoredRecordKind::PendingTransaction, &bytes)?;
                record.validate_after_read()?;
                if record.transaction_id != expected {
                    return Err(StorageError::Corruption(
                        "pending scan found a record under the wrong transaction ID".into(),
                    ));
                }
                if self.pending_id_for_slot_v1(record.slot)? != Some(expected) {
                    return Err(StorageError::Inconsistent(
                        "pending scan found a record without its matching slot index".into(),
                    ));
                }
                Ok(record)
            })
            .collect()
    }

    /// Returns the latest durable lifecycle sequence, or zero before any event.
    pub fn latest_lifecycle_sequence_v1(&self) -> Result<LifecycleSequence, StorageError> {
        let Some(bytes) = self.backend().get(Table::Meta, META_LIFECYCLE_SEQUENCE)? else {
            return Ok(LifecycleSequence::new(0));
        };
        let raw: [u8; 8] = bytes.try_into().map_err(|_| {
            StorageError::Corruption("lifecycle sequence marker is malformed".into())
        })?;
        Ok(LifecycleSequence::new(u64::from_be_bytes(raw)))
    }

    /// Returns a finalized transaction position by ID, validating the table key.
    pub fn finalized_transaction_index_v1(
        &self,
        transaction_id: TransactionId,
    ) -> Result<Option<FinalizedTransactionIndexV1>, StorageError> {
        let Some(bytes) = self.backend().get(
            Table::FinalizedTransactionIndex,
            &transaction_key(transaction_id),
        )?
        else {
            return Ok(None);
        };
        let index: FinalizedTransactionIndexV1 =
            decode(StoredRecordKind::FinalizedTransactionIndex, &bytes)?;
        index.validate()?;
        if index.transaction_id != transaction_id {
            return Err(StorageError::Corruption(
                "finalized transaction index does not match its table key".into(),
            ));
        }
        Ok(Some(index))
    }

    /// Returns one finalized V1 receipt by transaction ID.
    pub fn finalized_receipt_v1(
        &self,
        transaction_id: TransactionId,
    ) -> Result<Option<ReceiptV1>, StorageError> {
        let Some(bytes) = self.backend().get(
            Table::FinalizedReceiptIndex,
            &transaction_key(transaction_id),
        )?
        else {
            return Ok(None);
        };
        let record: FinalizedReceiptRecordV1 =
            decode(StoredRecordKind::FinalizedReceiptIndex, &bytes)?;
        record.validate()?;
        if record.transaction_id != transaction_id {
            return Err(StorageError::Corruption(
                "finalized receipt record does not match its table key".into(),
            ));
        }
        Ok(Some(record.receipt))
    }

    /// Resolves a finalized V5 transaction through its position and stored block.
    pub fn finalized_transaction_v1(
        &self,
        transaction_id: TransactionId,
    ) -> Result<Option<TransactionV5>, StorageError> {
        let Some(index) = self.finalized_transaction_index_v1(transaction_id)? else {
            return Ok(None);
        };
        let block = self
            .block_v4_by_height(index.position.height)?
            .ok_or_else(|| {
                StorageError::Inconsistent(
                    "finalized transaction index names a missing protocol-2 block".into(),
                )
            })?;
        let position = usize::try_from(index.position.transaction_index.get()).map_err(|_| {
            StorageError::Corruption(
                "finalized transaction index cannot fit memory position".into(),
            )
        })?;
        let transaction = block.transactions.get(position).ok_or_else(|| {
            StorageError::Corruption(
                "finalized transaction index lies outside its protocol-2 block".into(),
            )
        })?;
        if transaction.transaction_id().map_err(|error| {
            StorageError::Corruption(format!("stored finalized transaction is invalid: {error}"))
        })? != transaction_id
        {
            return Err(StorageError::Corruption(
                "finalized transaction index points at another transaction".into(),
            ));
        }
        Ok(Some(transaction.clone()))
    }

    /// Stages every transaction/receipt lifecycle mutation for one finalized block.
    ///
    /// The caller must commit `batch` together with the block, post-state,
    /// authority sets, certificate, and tip. This helper never commits by itself.
    pub(crate) fn stage_finalized_block_v1(
        &self,
        batch: &mut WriteBatch,
        block: &BlockV4,
    ) -> Result<(), StorageError> {
        let initial_sequence = self.latest_lifecycle_sequence_v1()?;
        let mut sequence = initial_sequence;
        let mut finalized_slots = BTreeSet::new();
        for (transaction, receipt) in block.transactions.iter().zip(&block.receipts) {
            let transaction_id = transaction.transaction_id().map_err(|error| {
                StorageError::InvalidRecord(format!(
                    "cannot identify finalized V5 transaction: {error}"
                ))
            })?;
            if self
                .finalized_transaction_index_v1(transaction_id)?
                .is_some()
                || self.finalized_receipt_v1(transaction_id)?.is_some()
            {
                return Err(StorageError::Inconsistent(
                    "transaction ID already has a finalized index".into(),
                ));
            }

            let slot = PendingSlotV1::for_transaction(transaction);
            if !finalized_slots.insert(slot) {
                return Err(StorageError::InvalidRecord(
                    "protocol-2 block finalizes the same authorization slot twice".into(),
                ));
            }
            let occupant = self.pending_id_for_slot_v1(slot)?;
            let exact_pending = self.pending_transaction_v1(transaction_id)?;
            if exact_pending.is_some() && occupant != Some(transaction_id) {
                return Err(StorageError::Inconsistent(
                    "finalizing pending transaction is not its slot occupant".into(),
                ));
            }
            if let Some(occupant_id) = occupant {
                let occupant_record =
                    self.pending_transaction_v1(occupant_id)?.ok_or_else(|| {
                        StorageError::Inconsistent(
                            "pending slot occupant has no transaction record".into(),
                        )
                    })?;
                if occupant_record.slot != slot {
                    return Err(StorageError::Inconsistent(
                        "pending slot occupant record names another slot".into(),
                    ));
                }
                if occupant_id == transaction_id && occupant_record.transaction != *transaction {
                    return Err(StorageError::Corruption(
                        "pending transaction bytes differ from the finalized transaction".into(),
                    ));
                }
                batch.delete(Table::PendingTransactions, transaction_key(occupant_id));
                batch.delete(Table::PendingBySlot, slot.key());

                if occupant_id != transaction_id {
                    sequence = next_sequence(sequence)?;
                    let displaced = self.lifecycle_with_local_v1(
                        occupant_id,
                        sequence,
                        LocalTransactionObservationV1::Dropped {
                            reason: LocalDropReasonV1::FinalizedSlotConflict,
                            observed_at_ms: LocalTimestampMs::new(block.header.timestamp_ms),
                        },
                    )?;
                    batch.put(
                        Table::TransactionLifecycle,
                        transaction_key(occupant_id),
                        encode(StoredRecordKind::TransactionLifecycle, &displaced)?,
                    );
                }
            }

            sequence = next_sequence(sequence)?;
            let previous = self.transaction_lifecycle_v1(transaction_id)?;
            if previous
                .as_ref()
                .and_then(|lifecycle| lifecycle.consensus_fact)
                .is_some()
            {
                return Err(StorageError::Inconsistent(
                    "transaction already has a finalized consensus fact".into(),
                ));
            }
            let lifecycle = TransactionLifecycleV1 {
                version: TRANSACTION_LIFECYCLE_RECORD_V1,
                transaction_id,
                sequence,
                local_observation: previous.and_then(|value| value.local_observation),
                consensus_fact: Some(TransactionConsensusFactV1::Finalized {
                    position: receipt.position,
                }),
            };
            let position_index = FinalizedTransactionIndexV1 {
                version: TRANSACTION_LIFECYCLE_RECORD_V1,
                transaction_id,
                position: receipt.position,
            };
            let receipt_record = FinalizedReceiptRecordV1 {
                version: TRANSACTION_LIFECYCLE_RECORD_V1,
                transaction_id,
                receipt: receipt.clone(),
            };
            batch.put(
                Table::FinalizedTransactionIndex,
                transaction_key(transaction_id),
                encode(StoredRecordKind::FinalizedTransactionIndex, &position_index)?,
            );
            batch.put(
                Table::FinalizedReceiptIndex,
                transaction_key(transaction_id),
                encode(StoredRecordKind::FinalizedReceiptIndex, &receipt_record)?,
            );
            batch.put(
                Table::TransactionLifecycle,
                transaction_key(transaction_id),
                encode(StoredRecordKind::TransactionLifecycle, &lifecycle)?,
            );
        }
        if sequence != initial_sequence {
            batch.put(
                Table::Meta,
                META_LIFECYCLE_SEQUENCE,
                sequence.get().to_be_bytes().to_vec(),
            );
        }
        Ok(())
    }

    fn lifecycle_with_local_v1(
        &self,
        transaction_id: TransactionId,
        sequence: LifecycleSequence,
        local_observation: LocalTransactionObservationV1,
    ) -> Result<TransactionLifecycleV1, StorageError> {
        let consensus_fact = self
            .transaction_lifecycle_v1(transaction_id)?
            .and_then(|lifecycle| lifecycle.consensus_fact);
        Ok(TransactionLifecycleV1 {
            version: TRANSACTION_LIFECYCLE_RECORD_V1,
            transaction_id,
            sequence,
            local_observation: Some(local_observation),
            consensus_fact,
        })
    }
}

pub(crate) fn next_sequence(current: LifecycleSequence) -> Result<LifecycleSequence, StorageError> {
    current
        .get()
        .checked_add(1)
        .map(LifecycleSequence::new)
        .ok_or_else(|| StorageError::Inconsistent("lifecycle sequence exhausted".into()))
}

pub(crate) fn transaction_key(transaction_id: TransactionId) -> Vec<u8> {
    transaction_id.digest().0.to_vec()
}

fn transaction_id_from_key(bytes: &[u8]) -> Result<TransactionId, StorageError> {
    let raw: [u8; 32] = bytes.try_into().map_err(|_| {
        StorageError::Corruption("transaction ID index contains a non-32-byte key".into())
    })?;
    Ok(TransactionId::new(webc_crypto::Hash256(raw)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use webc_chain::{
        calculate_fee_summary_v1, evidence_root, receipt_root_v1, transaction_root_v1, ActionV1,
        Amount, AuthorizationPolicyRevision, BlockHeaderV4, BlockHeight, ChainId, ChainState,
        Epoch, FeeBid, FeePayerV1, FeePaymentV1, FeeRate, FinalityAuthoritySetV1,
        FinalityCertificate, GasUnits, Operation, ReceiptStatusV1, SignedVote,
        TransactionAuthorizationV1, TransactionIndex, ValidatorPower, ValidatorSet,
        ValidityWindowV1, Vote, VoteType, RECEIPT_V1, TRANSACTION_V5_PROTOCOL_VERSION,
    };
    use webc_crypto::{Hash256, Keypair};

    use crate::{BlockV4Commit, KvEntry, MemoryKvStore, RedbKvStore};

    const NOW: u64 = 1_700_000_000_000;

    fn signed_transfer(seed: u8, nonce: u64, max_fee_per_unit: u64) -> TransactionV5 {
        let sender = Keypair::from_seed([seed; 32]);
        let recipient = Keypair::from_seed([seed.wrapping_add(1); 32]);
        let mut transaction = TransactionV5::for_actions_unsigned(
            ChainId::devnet(),
            sender.address(),
            sender.public_key(),
            TransactionAuthorizationV1 {
                lane: AuthorizationLaneId::DEFAULT,
                policy_revision: AuthorizationPolicyRevision::new(0),
                nonce: Nonce::new(nonce),
            },
            ValidityWindowV1::new(BlockHeight::new(1), BlockHeight::new(10)),
            vec![ActionV1::native(Operation::Transfer {
                to: recipient.address(),
                amount: Amount::from_units(1),
            })],
            FeeBid {
                gas_limit: 1_000,
                max_fee_per_unit,
                priority_fee_per_unit: 0,
            },
            FeePaymentV1::SenderLane,
        )
        .unwrap();
        transaction.sign(&sender).unwrap();
        transaction
    }

    fn open_memory() -> ChainStore<MemoryKvStore> {
        ChainStore::open(MemoryKvStore::new(), &ChainId::devnet()).unwrap()
    }

    struct ProtocolTwoFixture {
        state: ChainState,
        block: BlockV4,
        authority_set: FinalityAuthoritySetV1,
        certificate: FinalityCertificate,
    }

    fn initialize_protocol_two<K: KvStore>(store: &mut ChainStore<K>) {
        let genesis = ChainState {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            ..ChainState::default()
        };
        store.initialize_genesis(&genesis).unwrap();
    }

    fn authority_fixture(seed: u8) -> (Keypair, ValidatorSet, FinalityAuthoritySetV1) {
        let consensus_key = Keypair::from_seed([seed; 32]);
        let validator = consensus_key.address();
        let validator_set = ValidatorSet {
            validators: BTreeMap::from([(
                validator,
                ValidatorPower {
                    validator,
                    power: Amount::from_units(100),
                    consensus_key: consensus_key.public_key(),
                },
            )]),
            total_power: Amount::from_units(100),
        };
        let authority_set = FinalityAuthoritySetV1::from_validator_set(
            TRANSACTION_V5_PROTOCOL_VERSION,
            ChainId::devnet(),
            Epoch::new(0),
            &validator_set,
        )
        .unwrap();
        (consensus_key, validator_set, authority_set)
    }

    fn successful_receipt(transaction: &TransactionV5, index: u32) -> ReceiptV1 {
        ReceiptV1 {
            version: RECEIPT_V1,
            position: BlockPositionV1::new(BlockHeight::new(1), TransactionIndex::new(index)),
            transaction_id: transaction.transaction_id().unwrap(),
            sender: transaction.sender,
            status: ReceiptStatusV1::Succeeded,
            fee_summary: calculate_fee_summary_v1(
                FeePayerV1 {
                    address: transaction.sender,
                    lane: transaction.authorization.lane,
                },
                GasUnits::new(transaction.fee_bid.gas_limit),
                GasUnits::new(transaction.required_units().unwrap()),
                FeeRate::new(1),
                FeeRate::new(transaction.fee_bid.max_fee_per_unit),
                FeeRate::new(transaction.fee_bid.priority_fee_per_unit),
            )
            .unwrap(),
            events: Vec::new(),
        }
    }

    fn finalized_fixture(transaction: TransactionV5) -> ProtocolTwoFixture {
        let (consensus_key, validator_set, authority_set) = authority_fixture(100);
        let receipt = successful_receipt(&transaction, 0);
        let state = ChainState {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            current_height: 1,
            ..ChainState::default()
        };
        let authority_root = authority_set.commitment().unwrap();
        let block = BlockV4 {
            header: BlockHeaderV4 {
                protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
                chain_id: ChainId::devnet(),
                height: BlockHeight::new(1),
                epoch: Epoch::new(0),
                previous_hash: Hash256::ZERO,
                state_root: state.state_root().unwrap(),
                account_root: state.account_root().unwrap(),
                tx_root: transaction_root_v1(
                    BlockHeight::new(1),
                    std::slice::from_ref(&transaction),
                )
                .unwrap(),
                receipt_root: receipt_root_v1(std::slice::from_ref(&receipt)).unwrap(),
                evidence_root: evidence_root(&[]).unwrap(),
                finality_authority_set_root: authority_root,
                next_finality_authority_set_root: authority_root,
                proposer: consensus_key.address(),
                timestamp_ms: NOW,
                base_fee_per_unit: 1,
            },
            transactions: vec![transaction],
            receipts: vec![receipt],
            evidence: Vec::new(),
        };
        let block_hash = block.hash().unwrap();
        let vote = SignedVote::sign(
            Vote {
                protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
                chain_id: ChainId::devnet(),
                height: 1,
                round: 0,
                vote_type: VoteType::Precommit,
                block_hash,
                validator: consensus_key.address(),
            },
            &consensus_key,
        )
        .unwrap();
        let certificate = FinalityCertificate::build(
            &validator_set,
            TRANSACTION_V5_PROTOCOL_VERSION,
            ChainId::devnet(),
            1,
            0,
            block_hash,
            &[vote],
        )
        .unwrap();
        ProtocolTwoFixture {
            state,
            block,
            authority_set,
            certificate,
        }
    }

    #[derive(Debug, Default)]
    struct FailNextCommitStore {
        inner: MemoryKvStore,
        fail_next: bool,
    }

    impl KvStore for FailNextCommitStore {
        fn get(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get(table, key)
        }

        fn contains(&self, table: Table, key: &[u8]) -> Result<bool, StorageError> {
            self.inner.contains(table, key)
        }

        fn commit(&mut self, batch: WriteBatch) -> Result<(), StorageError> {
            if self.fail_next {
                self.fail_next = false;
                return Err(StorageError::Io("injected commit failure".into()));
            }
            self.inner.commit(batch)
        }

        fn last_key(&self, table: Table) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.last_key(table)
        }

        fn scan(
            &self,
            table: Table,
            start_inclusive: Option<&[u8]>,
            limit: usize,
        ) -> Result<Vec<KvEntry>, StorageError> {
            self.inner.scan(table, start_inclusive, limit)
        }
    }

    #[test]
    fn pending_admission_is_idempotent_and_indexes_the_exact_slot() {
        let mut store = open_memory();
        let record =
            PendingTransactionRecordV1::new(signed_transfer(1, 0, 5), LocalTimestampMs::new(NOW))
                .unwrap();

        let first = store.store_pending_v1(&record, None).unwrap();
        let PendingAdmissionOutcomeV1::Stored {
            queued,
            replaced,
            evicted,
        } = first
        else {
            panic!("first admission must store");
        };
        assert!(replaced.is_none());
        assert!(evicted.is_none());
        assert_eq!(queued.sequence, LifecycleSequence::new(1));
        assert_eq!(
            store.pending_id_for_slot_v1(record.slot).unwrap(),
            Some(record.transaction_id)
        );
        assert_eq!(
            store.pending_transaction_v1(record.transaction_id).unwrap(),
            Some(record.clone())
        );

        let duplicate = store.store_pending_v1(&record, None).unwrap();
        assert_eq!(duplicate, PendingAdmissionOutcomeV1::DuplicateKnown(queued));
        assert_eq!(store.latest_lifecycle_sequence_v1().unwrap().get(), 1);
    }

    #[test]
    fn replacement_updates_both_lifecycles_and_indexes_atomically() {
        let mut store = open_memory();
        let old =
            PendingTransactionRecordV1::new(signed_transfer(1, 0, 5), LocalTimestampMs::new(NOW))
                .unwrap();
        store.store_pending_v1(&old, None).unwrap();
        let new = PendingTransactionRecordV1::new(
            signed_transfer(1, 0, 6),
            LocalTimestampMs::new(NOW + 1),
        )
        .unwrap();

        let outcome = store
            .store_pending_v1(&new, Some(old.transaction_id))
            .unwrap();
        let PendingAdmissionOutcomeV1::Stored {
            queued,
            replaced,
            evicted,
        } = outcome
        else {
            panic!("replacement must store");
        };
        assert!(evicted.is_none());
        let replaced = replaced.unwrap();
        assert_eq!(replaced.sequence.get(), 2);
        assert_eq!(queued.sequence.get(), 3);
        assert!(matches!(
            replaced.local_observation,
            Some(LocalTransactionObservationV1::Replaced { replacement_id, .. })
                if replacement_id == new.transaction_id
        ));
        assert_eq!(
            store.pending_transaction_v1(old.transaction_id).unwrap(),
            None
        );
        assert_eq!(
            store.pending_id_for_slot_v1(new.slot).unwrap(),
            Some(new.transaction_id)
        );
    }

    #[test]
    fn capacity_eviction_and_new_admission_share_one_durable_batch() {
        let mut store = open_memory();
        let victim =
            PendingTransactionRecordV1::new(signed_transfer(21, 0, 5), LocalTimestampMs::new(NOW))
                .unwrap();
        store.store_pending_v1(&victim, None).unwrap();
        let newcomer = PendingTransactionRecordV1::new(
            signed_transfer(22, 0, 9),
            LocalTimestampMs::new(NOW + 1),
        )
        .unwrap();

        let outcome = store
            .store_pending_with_eviction_v1(&newcomer, victim.transaction_id)
            .unwrap();
        let PendingAdmissionOutcomeV1::Stored {
            queued,
            replaced,
            evicted,
        } = outcome
        else {
            panic!("capacity eviction must store");
        };
        assert!(replaced.is_none());
        assert_eq!(queued.sequence.get(), 3);
        let evicted = evicted.unwrap();
        assert_eq!(evicted.sequence.get(), 2);
        assert!(matches!(
            evicted.local_observation,
            Some(LocalTransactionObservationV1::Dropped {
                reason: LocalDropReasonV1::CapacityEviction,
                ..
            })
        ));
        assert!(store
            .pending_transaction_v1(victim.transaction_id)
            .unwrap()
            .is_none());
        assert!(store.pending_id_for_slot_v1(victim.slot).unwrap().is_none());
        assert_eq!(
            store
                .pending_transaction_v1(newcomer.transaction_id)
                .unwrap(),
            Some(newcomer.clone())
        );
        assert_eq!(
            store.pending_id_for_slot_v1(newcomer.slot).unwrap(),
            Some(newcomer.transaction_id)
        );
    }

    #[test]
    fn failed_capacity_eviction_keeps_the_old_pending_record() {
        let backend = FailNextCommitStore::default();
        let mut store = ChainStore::open(backend, &ChainId::devnet()).unwrap();
        let victim =
            PendingTransactionRecordV1::new(signed_transfer(23, 0, 5), LocalTimestampMs::new(NOW))
                .unwrap();
        store.store_pending_v1(&victim, None).unwrap();
        let newcomer = PendingTransactionRecordV1::new(
            signed_transfer(24, 0, 9),
            LocalTimestampMs::new(NOW + 1),
        )
        .unwrap();
        store.backend_mut().fail_next = true;

        assert!(matches!(
            store.store_pending_with_eviction_v1(&newcomer, victim.transaction_id),
            Err(StorageError::Io(_))
        ));
        assert_eq!(
            store.pending_transaction_v1(victim.transaction_id).unwrap(),
            Some(victim.clone())
        );
        assert_eq!(
            store.pending_id_for_slot_v1(victim.slot).unwrap(),
            Some(victim.transaction_id)
        );
        assert!(store
            .pending_transaction_v1(newcomer.transaction_id)
            .unwrap()
            .is_none());
        assert!(store
            .pending_id_for_slot_v1(newcomer.slot)
            .unwrap()
            .is_none());
        assert_eq!(store.latest_lifecycle_sequence_v1().unwrap().get(), 1);
    }

    #[test]
    fn removal_deletes_both_pending_indexes_but_keeps_lifecycle() {
        let mut store = open_memory();
        let record =
            PendingTransactionRecordV1::new(signed_transfer(9, 4, 5), LocalTimestampMs::new(NOW))
                .unwrap();
        store.store_pending_v1(&record, None).unwrap();

        let lifecycle = store
            .remove_pending_v1(
                record.transaction_id,
                LocalTransactionObservationV1::Expired {
                    observed_at_ms: LocalTimestampMs::new(NOW + 10),
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(lifecycle.sequence.get(), 2);
        assert!(matches!(
            lifecycle.local_observation,
            Some(LocalTransactionObservationV1::Expired { .. })
        ));
        assert!(store
            .pending_transaction_v1(record.transaction_id)
            .unwrap()
            .is_none());
        assert!(store.pending_id_for_slot_v1(record.slot).unwrap().is_none());
        assert_eq!(
            store
                .transaction_lifecycle_v1(record.transaction_id)
                .unwrap(),
            Some(lifecycle.clone())
        );
        assert_eq!(
            store
                .remove_pending_v1(
                    record.transaction_id,
                    LocalTransactionObservationV1::Expired {
                        observed_at_ms: LocalTimestampMs::new(NOW + 11),
                    },
                )
                .unwrap(),
            Some(lifecycle)
        );
    }

    #[test]
    fn candidate_inclusion_retains_restart_safe_pending_bytes() {
        let mut store = open_memory();
        let record =
            PendingTransactionRecordV1::new(signed_transfer(4, 0, 5), LocalTimestampMs::new(NOW))
                .unwrap();
        store.store_pending_v1(&record, None).unwrap();

        let lifecycle = store
            .observe_pending_included_v1(
                record.transaction_id,
                BlockPositionV1::new(BlockHeight::new(3), webc_chain::TransactionIndex::new(2)),
            )
            .unwrap();
        assert!(matches!(
            lifecycle.local_observation,
            Some(LocalTransactionObservationV1::Included { .. })
        ));
        assert_eq!(
            store.pending_transaction_v1(record.transaction_id).unwrap(),
            Some(record)
        );
    }

    #[test]
    fn injected_commit_failure_leaves_every_pending_index_unchanged() {
        let backend = FailNextCommitStore::default();
        let mut store = ChainStore::open(backend, &ChainId::devnet()).unwrap();
        let record =
            PendingTransactionRecordV1::new(signed_transfer(5, 0, 5), LocalTimestampMs::new(NOW))
                .unwrap();
        store.backend_mut().fail_next = true;

        assert!(matches!(
            store.store_pending_v1(&record, None),
            Err(StorageError::Io(_))
        ));
        assert!(store
            .pending_transaction_v1(record.transaction_id)
            .unwrap()
            .is_none());
        assert!(store.pending_id_for_slot_v1(record.slot).unwrap().is_none());
        assert!(store
            .transaction_lifecycle_v1(record.transaction_id)
            .unwrap()
            .is_none());
        assert_eq!(store.latest_lifecycle_sequence_v1().unwrap().get(), 0);
    }

    #[test]
    fn store_rejects_a_valid_transaction_for_another_chain() {
        let backend = MemoryKvStore::new();
        let mut store = ChainStore::open(backend, &ChainId::new("webc-other-1").unwrap()).unwrap();
        let record =
            PendingTransactionRecordV1::new(signed_transfer(6, 0, 5), LocalTimestampMs::new(NOW))
                .unwrap();
        assert!(matches!(
            store.store_pending_v1(&record, None),
            Err(StorageError::InvalidRecord(_))
        ));
    }

    #[test]
    fn redb_reopen_restores_pending_bytes_slot_and_sequence() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lifecycle.redb");
        let record =
            PendingTransactionRecordV1::new(signed_transfer(7, 3, 9), LocalTimestampMs::new(NOW))
                .unwrap();
        {
            let backend = RedbKvStore::open(&path).unwrap();
            let mut store = ChainStore::open(backend, &ChainId::devnet()).unwrap();
            store.store_pending_v1(&record, None).unwrap();
        }
        let backend = RedbKvStore::open(&path).unwrap();
        let reopened = ChainStore::open(backend, &ChainId::devnet()).unwrap();
        assert_eq!(
            reopened.pending_transactions_v1(8_192).unwrap(),
            vec![record.clone()]
        );
        assert_eq!(
            reopened.pending_id_for_slot_v1(record.slot).unwrap(),
            Some(record.transaction_id)
        );
        assert_eq!(reopened.latest_lifecycle_sequence_v1().unwrap().get(), 1);
    }

    #[test]
    fn rejects_conflicting_slot_and_noncanonical_decimal_json() {
        let mut store = open_memory();
        let first =
            PendingTransactionRecordV1::new(signed_transfer(3, 0, 5), LocalTimestampMs::new(NOW))
                .unwrap();
        store.store_pending_v1(&first, None).unwrap();
        let conflict = PendingTransactionRecordV1::new(
            signed_transfer(3, 0, 6),
            LocalTimestampMs::new(NOW + 1),
        )
        .unwrap();
        assert!(matches!(
            store.store_pending_v1(&conflict, None),
            Err(StorageError::Inconsistent(_))
        ));
        assert!(serde_json::from_str::<LifecycleSequence>("\"01\"").is_err());
        assert!(serde_json::from_str::<LifecycleSequence>("1").is_err());
    }

    #[test]
    fn pending_scan_is_bounded_before_backend_work() {
        let store = open_memory();
        assert!(matches!(
            store.pending_transactions_v1(MAX_PENDING_TRANSACTION_SCAN_V1 + 1),
            Err(StorageError::InvalidRecord(_))
        ));
    }

    #[test]
    fn certified_finalization_survives_restart_with_every_v1_index() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("finalized-v4.redb");
        let pending = PendingTransactionRecordV1::new(
            signed_transfer(11, 0, 5),
            LocalTimestampMs::new(NOW - 1),
        )
        .unwrap();
        let fixture = finalized_fixture(pending.transaction.clone());
        let block_hash = fixture.block.hash().unwrap();
        let position = fixture.block.receipts[0].position;
        {
            let backend = RedbKvStore::open(&path).unwrap();
            let mut store = ChainStore::open(backend, &ChainId::devnet()).unwrap();
            initialize_protocol_two(&mut store);
            store.store_pending_v1(&pending, None).unwrap();
            store
                .commit_block_v4(BlockV4Commit {
                    block: &fixture.block,
                    state: &fixture.state,
                    current_authority_set: &fixture.authority_set,
                    next_authority_set: &fixture.authority_set,
                    certificate: &fixture.certificate,
                })
                .unwrap();
        }

        let backend = RedbKvStore::open(&path).unwrap();
        let reopened = ChainStore::open(backend, &ChainId::devnet()).unwrap();
        assert_eq!(reopened.tip().unwrap().unwrap().height, 1);
        assert_eq!(
            reopened.block_v4_by_height(BlockHeight::new(1)).unwrap(),
            Some(fixture.block.clone())
        );
        assert_eq!(
            reopened.block_v4_by_hash(&block_hash).unwrap(),
            Some(fixture.block.clone())
        );
        assert_eq!(
            reopened
                .finalized_transaction_v1(pending.transaction_id)
                .unwrap(),
            Some(pending.transaction.clone())
        );
        assert_eq!(
            reopened
                .finalized_receipt_v1(pending.transaction_id)
                .unwrap(),
            Some(fixture.block.receipts[0].clone())
        );
        assert_eq!(
            reopened
                .finalized_transaction_index_v1(pending.transaction_id)
                .unwrap()
                .unwrap()
                .position,
            position
        );
        let lifecycle = reopened
            .transaction_lifecycle_v1(pending.transaction_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            lifecycle.consensus_fact,
            Some(TransactionConsensusFactV1::Finalized { position })
        );
        assert!(matches!(
            lifecycle.local_observation,
            Some(LocalTransactionObservationV1::Queued { .. })
        ));
        assert!(reopened
            .pending_transaction_v1(pending.transaction_id)
            .unwrap()
            .is_none());
        assert!(reopened
            .pending_id_for_slot_v1(pending.slot)
            .unwrap()
            .is_none());
        assert_eq!(reopened.latest_lifecycle_sequence_v1().unwrap().get(), 2);
        assert_eq!(reopened.certificate(1).unwrap(), Some(fixture.certificate));
        assert_eq!(
            reopened.finality_authority_set_v1(Epoch::new(0)).unwrap(),
            Some(fixture.authority_set)
        );
        assert_eq!(reopened.latest_state().unwrap(), Some(fixture.state));
    }

    #[test]
    fn finalized_consensus_fact_displaces_a_local_replacement() {
        let mut store = open_memory();
        initialize_protocol_two(&mut store);
        let old = PendingTransactionRecordV1::new(
            signed_transfer(12, 0, 5),
            LocalTimestampMs::new(NOW - 2),
        )
        .unwrap();
        let replacement = PendingTransactionRecordV1::new(
            signed_transfer(12, 0, 6),
            LocalTimestampMs::new(NOW - 1),
        )
        .unwrap();
        store.store_pending_v1(&old, None).unwrap();
        store
            .store_pending_v1(&replacement, Some(old.transaction_id))
            .unwrap();
        let fixture = finalized_fixture(old.transaction.clone());

        store
            .commit_block_v4(BlockV4Commit {
                block: &fixture.block,
                state: &fixture.state,
                current_authority_set: &fixture.authority_set,
                next_authority_set: &fixture.authority_set,
                certificate: &fixture.certificate,
            })
            .unwrap();

        assert!(store
            .pending_transaction_v1(replacement.transaction_id)
            .unwrap()
            .is_none());
        assert!(store.pending_id_for_slot_v1(old.slot).unwrap().is_none());
        let displaced = store
            .transaction_lifecycle_v1(replacement.transaction_id)
            .unwrap()
            .unwrap();
        assert!(matches!(
            displaced.local_observation,
            Some(LocalTransactionObservationV1::Dropped {
                reason: LocalDropReasonV1::FinalizedSlotConflict,
                ..
            })
        ));
        let finalized = store
            .transaction_lifecycle_v1(old.transaction_id)
            .unwrap()
            .unwrap();
        assert!(matches!(
            finalized.local_observation,
            Some(LocalTransactionObservationV1::Replaced {
                replacement_id,
                ..
            }) if replacement_id == replacement.transaction_id
        ));
        assert!(matches!(
            finalized.consensus_fact,
            Some(TransactionConsensusFactV1::Finalized { .. })
        ));
        assert!(finalized.sequence > displaced.sequence);
    }

    #[test]
    fn invalid_certificate_and_authority_root_leave_pending_state_unchanged() {
        let mut store = open_memory();
        initialize_protocol_two(&mut store);
        let pending = PendingTransactionRecordV1::new(
            signed_transfer(13, 0, 5),
            LocalTimestampMs::new(NOW - 1),
        )
        .unwrap();
        store.store_pending_v1(&pending, None).unwrap();
        let fixture = finalized_fixture(pending.transaction.clone());
        let mut wrong_certificate = fixture.certificate.clone();
        wrong_certificate.block_hash = Hash256([9; 32]);

        assert!(matches!(
            store.commit_block_v4(BlockV4Commit {
                block: &fixture.block,
                state: &fixture.state,
                current_authority_set: &fixture.authority_set,
                next_authority_set: &fixture.authority_set,
                certificate: &wrong_certificate,
            }),
            Err(StorageError::InvalidRecord(_))
        ));
        let (_, _, wrong_authority) = authority_fixture(101);
        assert!(matches!(
            store.commit_block_v4(BlockV4Commit {
                block: &fixture.block,
                state: &fixture.state,
                current_authority_set: &wrong_authority,
                next_authority_set: &wrong_authority,
                certificate: &fixture.certificate,
            }),
            Err(StorageError::InvalidRecord(_))
        ));
        assert_eq!(store.tip().unwrap().unwrap().height, 0);
        assert_eq!(
            store
                .pending_transaction_v1(pending.transaction_id)
                .unwrap(),
            Some(pending.clone())
        );
        assert!(store
            .finalized_transaction_index_v1(pending.transaction_id)
            .unwrap()
            .is_none());
        assert!(store
            .block_v4_by_height(BlockHeight::new(1))
            .unwrap()
            .is_none());
        assert_eq!(store.latest_lifecycle_sequence_v1().unwrap().get(), 1);
    }

    #[test]
    fn backend_failure_rolls_back_block_tip_and_lifecycle_as_one_unit() {
        let backend = FailNextCommitStore::default();
        let mut store = ChainStore::open(backend, &ChainId::devnet()).unwrap();
        initialize_protocol_two(&mut store);
        let pending = PendingTransactionRecordV1::new(
            signed_transfer(14, 0, 5),
            LocalTimestampMs::new(NOW - 1),
        )
        .unwrap();
        store.store_pending_v1(&pending, None).unwrap();
        let fixture = finalized_fixture(pending.transaction.clone());
        store.backend_mut().fail_next = true;

        assert!(matches!(
            store.commit_block_v4(BlockV4Commit {
                block: &fixture.block,
                state: &fixture.state,
                current_authority_set: &fixture.authority_set,
                next_authority_set: &fixture.authority_set,
                certificate: &fixture.certificate,
            }),
            Err(StorageError::Io(_))
        ));
        assert_eq!(store.tip().unwrap().unwrap().height, 0);
        assert_eq!(
            store
                .pending_transaction_v1(pending.transaction_id)
                .unwrap(),
            Some(pending.clone())
        );
        assert_eq!(store.latest_lifecycle_sequence_v1().unwrap().get(), 1);
        assert!(store
            .finalized_transaction_v1(pending.transaction_id)
            .unwrap()
            .is_none());
        assert!(store
            .finalized_receipt_v1(pending.transaction_id)
            .unwrap()
            .is_none());
        assert!(store
            .block_v4_by_height(BlockHeight::new(1))
            .unwrap()
            .is_none());
        assert!(store.certificate(1).unwrap().is_none());
        assert!(store
            .finality_authority_set_v1(Epoch::new(0))
            .unwrap()
            .is_none());
    }

    #[test]
    fn finalization_rejects_two_transactions_for_one_authorization_slot() {
        let store = open_memory();
        let first = signed_transfer(15, 0, 5);
        let second = signed_transfer(15, 0, 6);
        let mut fixture = finalized_fixture(first);
        fixture.block.receipts.push(successful_receipt(&second, 1));
        fixture.block.transactions.push(second);
        let mut batch = WriteBatch::new();

        assert!(matches!(
            store.stage_finalized_block_v1(&mut batch, &fixture.block),
            Err(StorageError::InvalidRecord(_))
        ));
    }
}
