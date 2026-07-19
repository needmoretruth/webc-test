//! Protocol-version-2 receipt, event, and ordered Merkle-leaf commitments.
//!
//! Purpose: give every included V5 transaction one typed, independently
//! verifiable execution result. Responsibilities: own the V1 receipt/event
//! schemas, bounded position wrappers, domain-separated content and leaf hashes,
//! ordered transaction/receipt roots, and exact transaction-to-receipt binding.
//! Non-responsibilities: executing actions, selecting fees, storing receipts,
//! constructing inclusion proofs, or deciding finality. Execution supplies a
//! complete receipt; this module validates its fee arithmetic and bindings before
//! hashing it. Security boundary: decoded receipts are hostile, so unknown
//! versions, inconsistent fees, failed receipts with events, position/identity
//! mismatches, duplicate transaction IDs, and index overflow all fail closed
//! without mutating state.

use crate::fees::{FeeComputationError, FeePayerV1, FeeRate, FeeSummaryV1, GasUnits};
use crate::state::Event;
use crate::transaction_v5::{
    FeePaymentV1, TransactionId, TransactionKindV1, TransactionV5, TransactionValidationErrorV1,
};
use crate::BlockHeight;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeSet;
use webc_crypto::{merkle_root, Address, Hash256};

/// Schema version carried by every [`ReceiptV1`].
pub const RECEIPT_V1: u16 = 1;
/// Schema version carried by every [`EventV1`].
pub const EVENT_V1: u16 = 1;

/// Domain separating a receipt content identity from every other protocol hash.
pub const RECEIPT_V1_DOMAIN: &str = "WEBC_RECEIPT_V1";
/// Domain separating an ordered receipt-tree leaf from its content identity.
pub const RECEIPT_LEAF_V1_DOMAIN: &str = "WEBC_RECEIPT_LEAF_V1";
/// Domain separating one typed transaction event from every receipt and leaf.
pub const EVENT_V1_DOMAIN: &str = "WEBC_EVENT_V1";
/// Domain separating an ordered transaction-tree leaf from the transaction ID.
pub const TRANSACTION_LEAF_V1_DOMAIN: &str = "WEBC_TRANSACTION_LEAF_V1";

/// Maximum events one decoded or locally constructed V1 receipt may contain.
///
/// The current native executor emits at most one event for each of 32 actions.
/// Headroom keeps this boundary usable by later bounded runtimes while stopping
/// a hostile receipt from turning validation and hashing into an unbounded loop.
pub const MAX_RECEIPT_EVENTS_V1: usize = 256;

/// Maximum JSON bytes accepted by [`ReceiptV1::decode_json`].
pub const MAX_RECEIPT_V1_JSON_BYTES: usize = 256 * 1024;

macro_rules! bounded_index {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash,
            Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(u32);

        impl $name {
            /// Constructs a zero-based index from its bounded JSON-number value.
            pub const fn new(value: u32) -> Self {
                Self(value)
            }

            /// Returns the zero-based index.
            pub const fn get(self) -> u32 {
                self.0
            }
        }
    };
}

bounded_index!(
    /// Zero-based action position inside a V5 action program.
    ActionIndex
);

bounded_index!(
    /// Zero-based event position assigned by the action executor.
    EventIndex
);

bounded_index!(
    /// Zero-based transaction position inside one block.
    TransactionIndex
);

/// Exact block position committed by a transaction and its receipt leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockPositionV1 {
    /// Finalized block height, encoded as a canonical decimal string in JSON.
    #[serde(with = "block_height_decimal")]
    pub height: BlockHeight,
    /// Zero-based transaction position, encoded as a bounded JSON number.
    pub transaction_index: TransactionIndex,
}

impl BlockPositionV1 {
    /// Constructs a block position from typed height and transaction index.
    pub const fn new(height: BlockHeight, transaction_index: TransactionIndex) -> Self {
        Self {
            height,
            transaction_index,
        }
    }
}

/// Stable chargeable failure recorded after a V5 transaction passed admission.
///
/// Adding a variant changes consensus receipt meaning and therefore requires a
/// new receipt schema version once protocol version 2 is active.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ExecutionFailureCodeV1 {
    /// Action-state balance was insufficient after earlier ordered execution.
    InsufficientBalance,
    /// A referenced object did not exist at execution time.
    ObjectNotFound,
    /// A referenced object was not owned by the required account.
    ObjectOwnerMismatch,
    /// A referenced object no longer had the signed expected version.
    ObjectVersionMismatch,
    /// Another deterministic native-operation precondition was no longer true.
    Precondition,
}

/// Final execution outcome committed by a V1 receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ReceiptStatusV1 {
    /// Every action succeeded and the child action overlay committed.
    Succeeded,
    /// The child action overlay rolled back after a chargeable failure.
    Failed {
        /// Stable failure category; human text is derived outside consensus.
        code: ExecutionFailureCodeV1,
        /// Action that failed, when the transaction kind contains actions.
        failed_action_index: Option<ActionIndex>,
    },
}

/// One ordered typed event emitted by a successful V5 action program.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventV1 {
    /// Must equal [`EVENT_V1`].
    pub version: u16,
    /// Complete signed transaction that produced the event.
    pub transaction_id: TransactionId,
    /// Zero-based action that produced the event.
    pub action_index: ActionIndex,
    /// Zero-based event position assigned by execution.
    pub event_index: EventIndex,
    /// Existing typed native event body.
    pub body: Event,
}

impl EventV1 {
    /// Validates the event schema version without trusting its enclosing receipt.
    pub fn validate(&self) -> Result<(), ReceiptError> {
        if self.version != EVENT_V1 {
            return Err(ReceiptError::UnsupportedEventVersion {
                actual: self.version,
            });
        }
        Ok(())
    }

    /// Returns the domain-separated content identity of this complete event.
    pub fn digest(&self) -> Result<Hash256, ReceiptError> {
        self.validate()?;
        #[derive(Serialize)]
        struct Payload<'a> {
            domain: &'static str,
            event: &'a EventV1,
        }
        canonical_hash(&Payload {
            domain: EVENT_V1_DOMAIN,
            event: self,
        })
    }
}

/// Complete deterministic result of one included V5 transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptV1 {
    /// Must equal [`RECEIPT_V1`].
    pub version: u16,
    /// Exact block height and transaction index committed by the receipt leaf.
    pub position: BlockPositionV1,
    /// Stable identity of the complete signed V5 transaction.
    pub transaction_id: TransactionId,
    /// Account that authorized the transaction actions.
    pub sender: Address,
    /// Success or stable chargeable failure.
    pub status: ReceiptStatusV1,
    /// Independently reconciled reservation, charge, refund, burn, and reward.
    pub fee_summary: FeeSummaryV1,
    /// Ordered successful child-overlay events; always empty on failure.
    #[serde(deserialize_with = "bounded_events::deserialize")]
    pub events: Vec<EventV1>,
}

impl ReceiptV1 {
    /// Decodes and validates one hostile JSON receipt under hard resource bounds.
    ///
    /// The byte ceiling is checked before JSON allocation. The event sequence
    /// uses a bounded streaming visitor, so a forged length prefix or oversized
    /// array cannot preallocate or retain an attacker-selected number of events.
    pub fn decode_json(bytes: &[u8]) -> Result<Self, ReceiptError> {
        if bytes.len() > MAX_RECEIPT_V1_JSON_BYTES {
            return Err(ReceiptError::ReceiptTooLarge {
                actual: bytes.len(),
                maximum: MAX_RECEIPT_V1_JSON_BYTES,
            });
        }
        let receipt =
            serde_json::from_slice::<Self>(bytes).map_err(|_| ReceiptError::MalformedReceipt)?;
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validates every receipt-local invariant before storage, hashing, or proof use.
    ///
    /// This check is pure. It rejects unknown versions, inconsistent fee
    /// arithmetic, events on a failed transaction, and events that name another
    /// transaction. Position and transaction-list binding are checked by
    /// [`verify_transaction_receipt_binding`].
    pub fn validate(&self) -> Result<(), ReceiptError> {
        if self.version != RECEIPT_V1 {
            return Err(ReceiptError::UnsupportedReceiptVersion {
                actual: self.version,
            });
        }
        if self.events.len() > MAX_RECEIPT_EVENTS_V1 {
            return Err(ReceiptError::TooManyEvents {
                actual: self.events.len(),
                maximum: MAX_RECEIPT_EVENTS_V1,
            });
        }
        self.fee_summary.validate()?;
        if matches!(self.status, ReceiptStatusV1::Failed { .. }) && !self.events.is_empty() {
            return Err(ReceiptError::FailedReceiptHasEvents);
        }
        let mut previous_action = None;
        for (ordinal, event) in self.events.iter().enumerate() {
            event.validate()?;
            let expected_event_index = u32::try_from(ordinal)
                .map(EventIndex::new)
                .map_err(|_| ReceiptError::EventIndexOverflow { index: ordinal })?;
            if event.event_index != expected_event_index {
                return Err(ReceiptError::EventIndexMismatch {
                    expected: expected_event_index,
                    actual: event.event_index,
                });
            }
            if let Some(previous) = previous_action {
                if previous > event.action_index {
                    return Err(ReceiptError::EventActionOrderInvalid {
                        previous,
                        actual: event.action_index,
                    });
                }
            }
            previous_action = Some(event.action_index);
            if event.transaction_id != self.transaction_id {
                return Err(ReceiptError::EventTransactionIdMismatch {
                    event_index: event.event_index,
                });
            }
        }
        Ok(())
    }

    /// Returns the domain-separated content identity used by receipt indexes.
    pub fn digest(&self) -> Result<Hash256, ReceiptError> {
        self.validate()?;
        #[derive(Serialize)]
        struct Payload<'a> {
            domain: &'static str,
            receipt: &'a ReceiptV1,
        }
        canonical_hash(&Payload {
            domain: RECEIPT_V1_DOMAIN,
            receipt: self,
        })
    }

    /// Returns the domain-separated ordered leaf committed by a receipt root.
    pub fn leaf(&self) -> Result<Hash256, ReceiptError> {
        self.validate()?;
        #[derive(Serialize)]
        struct Payload<'a> {
            domain: &'static str,
            receipt: &'a ReceiptV1,
        }
        canonical_hash(&Payload {
            domain: RECEIPT_LEAF_V1_DOMAIN,
            receipt: self,
        })
    }
}

/// Typed rejection while validating or committing V1 receipt data.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptError {
    /// Hostile JSON exceeded the pre-allocation receipt byte ceiling.
    #[error("receipt JSON has {actual} bytes, maximum is {maximum}")]
    ReceiptTooLarge {
        /// Rejected input byte length.
        actual: usize,
        /// Protocol decoder ceiling in bytes.
        maximum: usize,
    },
    /// Hostile JSON did not decode as one strict V1 receipt.
    #[error("receipt JSON is malformed")]
    MalformedReceipt,
    /// A receipt attempted to retain more events than the schema permits.
    #[error("receipt has {actual} events, maximum is {maximum}")]
    TooManyEvents {
        /// Rejected event count.
        actual: usize,
        /// V1 event-count ceiling.
        maximum: usize,
    },
    /// A decoded receipt names an unsupported schema.
    #[error("unsupported receipt version {actual}")]
    UnsupportedReceiptVersion {
        /// Rejected version.
        actual: u16,
    },
    /// A decoded event names an unsupported schema.
    #[error("unsupported event version {actual}")]
    UnsupportedEventVersion {
        /// Rejected version.
        actual: u16,
    },
    /// The committed fee fields do not reconcile independently.
    #[error("receipt fee summary is invalid: {0}")]
    InvalidFeeSummary(#[from] FeeComputationError),
    /// Rolled-back child execution cannot publish partial events.
    #[error("failed receipt must not contain events")]
    FailedReceiptHasEvents,
    /// An event names a transaction other than its enclosing receipt.
    #[error("event {event_index:?} names another transaction")]
    EventTransactionIdMismatch {
        /// Event position supplied by the decoded event.
        event_index: EventIndex,
    },
    /// A platform event position does not fit the V1 `u32` index schema.
    #[error("event index {index} exceeds the V1 u32 range")]
    EventIndexOverflow {
        /// Rejected platform index.
        index: usize,
    },
    /// The committed event index does not equal its ordered receipt position.
    #[error("event index does not match its ordered receipt position")]
    EventIndexMismatch {
        /// Position derived from the receipt event array.
        expected: EventIndex,
        /// Position carried by the decoded event.
        actual: EventIndex,
    },
    /// Events are not grouped in nondecreasing action order.
    #[error("receipt events are not ordered by action index")]
    EventActionOrderInvalid {
        /// Previous event's action index.
        previous: ActionIndex,
        /// Current event's decreasing action index.
        actual: ActionIndex,
    },
    /// Transaction and receipt arrays cannot be paired positionally.
    #[error("transaction count {transactions} does not equal receipt count {receipts}")]
    TransactionReceiptCountMismatch {
        /// Number of block transactions.
        transactions: usize,
        /// Number of block receipts.
        receipts: usize,
    },
    /// A platform collection position does not fit the V1 `u32` index schema.
    #[error("transaction index {index} exceeds the V1 u32 range")]
    TransactionIndexOverflow {
        /// Rejected platform index.
        index: usize,
    },
    /// A receipt is not at the height/index of its paired transaction.
    #[error("receipt position does not match transaction position")]
    ReceiptPositionMismatch {
        /// Position derived from the block and transaction array.
        expected: BlockPositionV1,
        /// Position carried by the decoded receipt.
        actual: BlockPositionV1,
    },
    /// A receipt names a different transaction than the one at its position.
    #[error("receipt transaction ID does not match its paired transaction")]
    ReceiptTransactionIdMismatch {
        /// Position of the mismatched pair.
        index: TransactionIndex,
    },
    /// The receipt attributes execution to an account other than the signed sender.
    #[error("receipt sender does not match its paired transaction")]
    ReceiptSenderMismatch {
        /// Position of the mismatched pair.
        index: TransactionIndex,
    },
    /// The receipt charges another account/lane than the signed fee-payment choice.
    #[error("receipt fee payer does not match its paired transaction")]
    ReceiptFeePayerMismatch {
        /// Position of the mismatched pair.
        index: TransactionIndex,
    },
    /// The receipt's gas limit, maximum rate, or effective priority rate disagrees
    /// with the signed fee bid.
    #[error("receipt fee bid does not match its paired transaction")]
    ReceiptFeeBidMismatch {
        /// Position of the mismatched pair.
        index: TransactionIndex,
    },
    /// An event names an action position absent from its paired transaction.
    #[error("receipt event action index is outside its paired transaction")]
    EventActionIndexOutOfRange {
        /// Ordered event position.
        event_index: EventIndex,
        /// Rejected action position.
        action_index: ActionIndex,
        /// Number of actions in the paired transaction.
        action_count: usize,
    },
    /// A failed receipt names an action position absent from its paired transaction.
    #[error("failed receipt action index is outside its paired transaction")]
    FailedActionIndexOutOfRange {
        /// Rejected failing action position.
        action_index: ActionIndex,
        /// Number of actions in the paired transaction.
        action_count: usize,
    },
    /// A block repeats one complete signed transaction identity.
    #[error("duplicate transaction ID {transaction_id}")]
    DuplicateTransactionId {
        /// Repeated complete signed transaction identity.
        transaction_id: TransactionId,
    },
    /// The complete V5 transaction could not produce its stable identity.
    #[error("transaction identity is invalid: {0}")]
    InvalidTransactionIdentity(#[from] TransactionValidationErrorV1),
    /// Canonical cross-language JSON could not be produced.
    #[error("receipt or leaf cannot be canonically encoded")]
    CanonicalEncoding,
}

/// Hashes one position-bound V5 transaction leaf.
///
/// The transaction ID already commits the complete signed transaction. The
/// separate position binds an otherwise identical ID to exactly one ordered
/// block slot and deliberately differs from the legacy V4 undomained leaf.
pub fn transaction_leaf_v1(
    position: BlockPositionV1,
    transaction_id: TransactionId,
) -> Result<Hash256, ReceiptError> {
    #[derive(Serialize)]
    struct Payload {
        domain: &'static str,
        position: BlockPositionV1,
        transaction_id: TransactionId,
    }
    canonical_hash(&Payload {
        domain: TRANSACTION_LEAF_V1_DOMAIN,
        position,
        transaction_id,
    })
}

/// Builds the ordered V1 receipt root after validating every receipt.
///
/// Empty blocks use [`Hash256::ZERO`] through the shared `webc-crypto` Merkle
/// implementation. Odd layers duplicate their last node exactly as every other
/// current WEBC tree does.
pub fn receipt_root_v1(receipts: &[ReceiptV1]) -> Result<Hash256, ReceiptError> {
    let leaves = receipts
        .iter()
        .map(ReceiptV1::leaf)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(merkle_root(&leaves))
}

/// Builds the ordered, position-bound V5 transaction root for one block height.
///
/// A repeated complete signed transaction ID is rejected even at another
/// position. This function computes identities but does not replace stateless or
/// stateful transaction validation performed by the execution pipeline.
pub fn transaction_root_v1(
    height: BlockHeight,
    transactions: &[TransactionV5],
) -> Result<Hash256, ReceiptError> {
    let mut seen = BTreeSet::new();
    let mut leaves = Vec::with_capacity(transactions.len());
    for (index, transaction) in transactions.iter().enumerate() {
        let transaction_index = transaction_index(index)?;
        let transaction_id = transaction.transaction_id()?;
        if !seen.insert(transaction_id) {
            return Err(ReceiptError::DuplicateTransactionId { transaction_id });
        }
        leaves.push(transaction_leaf_v1(
            BlockPositionV1::new(height, transaction_index),
            transaction_id,
        )?);
    }
    Ok(merkle_root(&leaves))
}

/// Verifies one-to-one positional binding between V5 transactions and receipts.
///
/// Counts must match. For every zero-based block position, the receipt must name
/// the same height, index, and complete signed transaction ID; no transaction ID
/// may repeat; and every receipt-local invariant must validate. The function is
/// pure and performs no storage or consensus mutation.
pub fn verify_transaction_receipt_binding(
    height: BlockHeight,
    transactions: &[TransactionV5],
    receipts: &[ReceiptV1],
) -> Result<(), ReceiptError> {
    if transactions.len() != receipts.len() {
        return Err(ReceiptError::TransactionReceiptCountMismatch {
            transactions: transactions.len(),
            receipts: receipts.len(),
        });
    }

    let mut seen = BTreeSet::new();
    for (index, (transaction, receipt)) in transactions.iter().zip(receipts).enumerate() {
        let transaction_index = transaction_index(index)?;
        let expected_position = BlockPositionV1::new(height, transaction_index);
        if receipt.position != expected_position {
            return Err(ReceiptError::ReceiptPositionMismatch {
                expected: expected_position,
                actual: receipt.position,
            });
        }

        let transaction_id = transaction.transaction_id()?;
        if !seen.insert(transaction_id) {
            return Err(ReceiptError::DuplicateTransactionId { transaction_id });
        }
        if receipt.transaction_id != transaction_id {
            return Err(ReceiptError::ReceiptTransactionIdMismatch {
                index: transaction_index,
            });
        }
        if receipt.sender != transaction.sender {
            return Err(ReceiptError::ReceiptSenderMismatch {
                index: transaction_index,
            });
        }
        receipt.validate()?;
        verify_receipt_fee_binding(transaction_index, transaction, &receipt.fee_summary)?;
        verify_receipt_action_binding(transaction, receipt)?;
    }
    Ok(())
}

fn verify_receipt_action_binding(
    transaction: &TransactionV5,
    receipt: &ReceiptV1,
) -> Result<(), ReceiptError> {
    let action_count = match &transaction.kind {
        TransactionKindV1::Actions(program) => program.actions.len(),
        TransactionKindV1::Cancel(_) => 0,
    };
    for event in &receipt.events {
        let action_index = usize::try_from(event.action_index.get()).map_err(|_| {
            ReceiptError::EventActionIndexOutOfRange {
                event_index: event.event_index,
                action_index: event.action_index,
                action_count,
            }
        })?;
        if action_index >= action_count {
            return Err(ReceiptError::EventActionIndexOutOfRange {
                event_index: event.event_index,
                action_index: event.action_index,
                action_count,
            });
        }
    }
    if let ReceiptStatusV1::Failed {
        failed_action_index: Some(action_index),
        ..
    } = receipt.status
    {
        let failed_index = usize::try_from(action_index.get()).map_err(|_| {
            ReceiptError::FailedActionIndexOutOfRange {
                action_index,
                action_count,
            }
        })?;
        if failed_index >= action_count {
            return Err(ReceiptError::FailedActionIndexOutOfRange {
                action_index,
                action_count,
            });
        }
    }
    Ok(())
}

fn verify_receipt_fee_binding(
    index: TransactionIndex,
    transaction: &TransactionV5,
    summary: &FeeSummaryV1,
) -> Result<(), ReceiptError> {
    let expected_payer = match &transaction.fee_payment {
        FeePaymentV1::SenderLane => FeePayerV1 {
            address: transaction.sender,
            lane: transaction.authorization.lane,
        },
        FeePaymentV1::Sponsored(use_authorization) => FeePayerV1 {
            address: use_authorization.grant.sponsor,
            lane: use_authorization.grant.payer_lane,
        },
    };
    if summary.payer != expected_payer {
        return Err(ReceiptError::ReceiptFeePayerMismatch { index });
    }

    let expected_gas_limit = GasUnits::new(transaction.fee_bid.gas_limit);
    let expected_max_rate = FeeRate::new(transaction.fee_bid.max_fee_per_unit);
    let priority_room = transaction
        .fee_bid
        .max_fee_per_unit
        .checked_sub(summary.base_fee_per_unit.get())
        .ok_or(ReceiptError::ReceiptFeeBidMismatch { index })?;
    let expected_priority =
        FeeRate::new(transaction.fee_bid.priority_fee_per_unit.min(priority_room));
    if summary.gas_limit != expected_gas_limit
        || summary.max_fee_per_unit != expected_max_rate
        || summary.priority_fee_per_unit != expected_priority
    {
        return Err(ReceiptError::ReceiptFeeBidMismatch { index });
    }
    Ok(())
}

fn transaction_index(index: usize) -> Result<TransactionIndex, ReceiptError> {
    u32::try_from(index)
        .map(TransactionIndex::new)
        .map_err(|_| ReceiptError::TransactionIndexOverflow { index })
}

fn canonical_hash<T: Serialize>(value: &T) -> Result<Hash256, ReceiptError> {
    crate::canonical::canonical_json_bytes(value)
        .map(Hash256::digest)
        .map_err(|_| ReceiptError::CanonicalEncoding)
}

mod bounded_events {
    use super::{EventV1, MAX_RECEIPT_EVENTS_V1};
    use serde::de::{Error as DeError, SeqAccess, Visitor};
    use serde::Deserializer;
    use std::fmt;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<EventV1>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedEventsVisitor;

        impl<'de> Visitor<'de> for BoundedEventsVisitor {
            type Value = Vec<EventV1>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "an event array with at most {MAX_RECEIPT_EVENTS_V1} entries"
                )
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if sequence
                    .size_hint()
                    .is_some_and(|length| length > MAX_RECEIPT_EVENTS_V1)
                {
                    return Err(A::Error::custom("receipt event array exceeds V1 limit"));
                }
                let mut events = Vec::with_capacity(
                    sequence.size_hint().unwrap_or(0).min(MAX_RECEIPT_EVENTS_V1),
                );
                while let Some(event) = sequence.next_element()? {
                    if events.len() == MAX_RECEIPT_EVENTS_V1 {
                        return Err(A::Error::custom("receipt event array exceeds V1 limit"));
                    }
                    events.push(event);
                }
                Ok(events)
            }
        }

        deserializer.deserialize_seq(BoundedEventsVisitor)
    }
}

mod block_height_decimal {
    use super::*;
    use serde::de::Error as DeError;

    pub fn serialize<S>(value: &BlockHeight, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.get().to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BlockHeight, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || value.len() > 20
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(D::Error::custom(
                "expected a canonical unsigned decimal u64 string",
            ));
        }
        value
            .parse::<u64>()
            .map(BlockHeight::new)
            .map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::canonical_json_string;
    use crate::{
        calculate_fee_summary_v1, ActionV1, Amount, AuthorizationLaneId,
        AuthorizationPolicyRevision, ChainId, FeeBid, FeePaymentV1, Nonce, Operation,
        TransactionAuthorizationV1, ValidityWindowV1,
    };
    use webc_crypto::Keypair;

    fn sample_transaction(nonce: u64, amount: u128) -> TransactionV5 {
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let authorization = TransactionAuthorizationV1 {
            lane: AuthorizationLaneId::DEFAULT,
            policy_revision: AuthorizationPolicyRevision::new(0),
            nonce: Nonce::new(nonce),
        };
        let mut transaction = TransactionV5::for_actions_unsigned(
            ChainId::devnet(),
            sender.address(),
            sender.public_key(),
            authorization,
            ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(20)),
            vec![ActionV1::native(Operation::Transfer {
                to: recipient.address(),
                amount: Amount::from_units(amount),
            })],
            FeeBid {
                gas_limit: 1_000,
                max_fee_per_unit: 5,
                priority_fee_per_unit: 1,
            },
            FeePaymentV1::SenderLane,
        )
        .expect("bounded transaction fixture must build");
        transaction
            .sign(&sender)
            .expect("deterministic fixture must sign");
        transaction
    }

    fn fee_summary(transaction: &TransactionV5, units_consumed: u64) -> FeeSummaryV1 {
        calculate_fee_summary_v1(
            FeePayerV1 {
                address: transaction.sender,
                lane: transaction.authorization.lane,
            },
            GasUnits::new(transaction.fee_bid.gas_limit),
            GasUnits::new(units_consumed),
            FeeRate::new(2),
            FeeRate::new(transaction.fee_bid.max_fee_per_unit),
            FeeRate::new(transaction.fee_bid.priority_fee_per_unit),
        )
        .expect("bounded fixture fee must calculate")
    }

    fn successful_receipt(transaction: &TransactionV5, index: u32) -> ReceiptV1 {
        let recipient = Keypair::from_seed([2; 32]).address();
        let transaction_id = transaction
            .transaction_id()
            .expect("signed fixture must have an ID");
        ReceiptV1 {
            version: RECEIPT_V1,
            position: BlockPositionV1::new(BlockHeight::new(42), TransactionIndex::new(index)),
            transaction_id,
            sender: transaction.sender,
            status: ReceiptStatusV1::Succeeded,
            fee_summary: fee_summary(transaction, 100),
            events: vec![EventV1 {
                version: EVENT_V1,
                transaction_id,
                action_index: ActionIndex::new(0),
                event_index: EventIndex::new(0),
                body: Event::Transfer {
                    from: transaction.sender,
                    to: recipient,
                    amount: Amount::from_units(123_456),
                },
            }],
        }
    }

    fn failed_receipt(transaction: &TransactionV5, index: u32) -> ReceiptV1 {
        ReceiptV1 {
            version: RECEIPT_V1,
            position: BlockPositionV1::new(BlockHeight::new(42), TransactionIndex::new(index)),
            transaction_id: transaction
                .transaction_id()
                .expect("signed fixture must have an ID"),
            sender: transaction.sender,
            status: ReceiptStatusV1::Failed {
                code: ExecutionFailureCodeV1::InsufficientBalance,
                failed_action_index: Some(ActionIndex::new(0)),
            },
            fee_summary: fee_summary(transaction, 40),
            events: Vec::new(),
        }
    }

    #[test]
    fn valid_success_and_failure_receipts_reconcile() {
        let success_tx = sample_transaction(7, 123_456);
        let failed_tx = sample_transaction(8, 999_999);
        let success = successful_receipt(&success_tx, 0);
        let failure = failed_receipt(&failed_tx, 1);

        assert_eq!(success.validate(), Ok(()));
        assert_eq!(failure.validate(), Ok(()));
        assert_ne!(success.digest().unwrap(), success.leaf().unwrap());
        assert_ne!(
            success.events[0].digest().unwrap(),
            success.digest().unwrap()
        );
    }

    #[test]
    fn receipt_validation_fails_closed_on_local_invariant_tampering() {
        let transaction = sample_transaction(7, 123_456);
        let receipt = successful_receipt(&transaction, 0);

        let mut wrong_version = receipt.clone();
        wrong_version.version = 2;
        assert_eq!(
            wrong_version.validate(),
            Err(ReceiptError::UnsupportedReceiptVersion { actual: 2 })
        );

        let mut wrong_fee = receipt.clone();
        wrong_fee.fee_summary.refund = Amount::from_units(wrong_fee.fee_summary.refund.0 + 1);
        assert_eq!(
            wrong_fee.validate(),
            Err(ReceiptError::InvalidFeeSummary(
                FeeComputationError::InconsistentSummary
            ))
        );

        let mut failed_with_events = receipt.clone();
        failed_with_events.status = ReceiptStatusV1::Failed {
            code: ExecutionFailureCodeV1::Precondition,
            failed_action_index: Some(ActionIndex::new(0)),
        };
        assert_eq!(
            failed_with_events.validate(),
            Err(ReceiptError::FailedReceiptHasEvents)
        );

        let mut wrong_event_version = receipt.clone();
        wrong_event_version.events[0].version = 2;
        assert_eq!(
            wrong_event_version.validate(),
            Err(ReceiptError::UnsupportedEventVersion { actual: 2 })
        );

        let mut wrong_event_id = receipt.clone();
        wrong_event_id.events[0].transaction_id = TransactionId::new(Hash256([9; 32]));
        assert_eq!(
            wrong_event_id.validate(),
            Err(ReceiptError::EventTransactionIdMismatch {
                event_index: EventIndex::new(0)
            })
        );

        let mut wrong_event_index = receipt.clone();
        wrong_event_index.events[0].event_index = EventIndex::new(1);
        assert_eq!(
            wrong_event_index.validate(),
            Err(ReceiptError::EventIndexMismatch {
                expected: EventIndex::new(0),
                actual: EventIndex::new(1)
            })
        );

        let mut wrong_action_order = receipt;
        let mut second = wrong_action_order.events[0].clone();
        wrong_action_order.events[0].action_index = ActionIndex::new(1);
        second.action_index = ActionIndex::new(0);
        second.event_index = EventIndex::new(1);
        wrong_action_order.events.push(second);
        assert_eq!(
            wrong_action_order.validate(),
            Err(ReceiptError::EventActionOrderInvalid {
                previous: ActionIndex::new(1),
                actual: ActionIndex::new(0)
            })
        );
    }

    #[test]
    fn hostile_receipt_decode_bounds_bytes_and_events_before_hashing() {
        let transaction = sample_transaction(7, 123_456);
        let mut receipt = successful_receipt(&transaction, 0);
        let template = receipt.events[0].clone();
        receipt.events = (0..=MAX_RECEIPT_EVENTS_V1)
            .map(|index| {
                let mut event = template.clone();
                event.event_index = EventIndex::new(
                    u32::try_from(index).expect("test event limit must fit the V1 index"),
                );
                event
            })
            .collect();

        assert_eq!(
            receipt.validate(),
            Err(ReceiptError::TooManyEvents {
                actual: MAX_RECEIPT_EVENTS_V1 + 1,
                maximum: MAX_RECEIPT_EVENTS_V1,
            })
        );
        let json = serde_json::to_vec(&receipt).expect("oversized event fixture must serialize");
        assert_eq!(
            ReceiptV1::decode_json(&json),
            Err(ReceiptError::MalformedReceipt)
        );
        assert_eq!(
            ReceiptV1::decode_json(&vec![b' '; MAX_RECEIPT_V1_JSON_BYTES + 1]),
            Err(ReceiptError::ReceiptTooLarge {
                actual: MAX_RECEIPT_V1_JSON_BYTES + 1,
                maximum: MAX_RECEIPT_V1_JSON_BYTES,
            })
        );
    }

    #[test]
    fn receipt_json_uses_exact_decimal_strings_and_bounded_numbers() {
        let transaction = sample_transaction(7, 123_456);
        let receipt = successful_receipt(&transaction, 0);
        let mut value = serde_json::to_value(&receipt).expect("receipt must serialize");

        assert_eq!(value["version"], 1);
        assert_eq!(value["position"]["height"], "42");
        assert_eq!(value["position"]["transaction_index"], 0);
        assert_eq!(value["events"][0]["action_index"], 0);
        assert_eq!(value["events"][0]["event_index"], 0);
        assert_eq!(value["fee_summary"]["gas_limit"], "1000");
        assert_eq!(value["fee_summary"]["charged"], "300");

        value["position"]["height"] = serde_json::Value::String("042".to_owned());
        assert!(serde_json::from_value::<ReceiptV1>(value.clone()).is_err());

        let mut numeric_index = serde_json::to_value(&receipt).expect("receipt must serialize");
        numeric_index["position"]["transaction_index"] = serde_json::Value::String("0".to_owned());
        assert!(serde_json::from_value::<ReceiptV1>(numeric_index).is_err());

        let mut unknown = serde_json::to_value(&receipt).expect("receipt must serialize");
        unknown["unknown"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<ReceiptV1>(unknown).is_err());

        let status_with_extra = serde_json::json!({
            "Failed": {
                "code": "Precondition",
                "failed_action_index": 0,
                "extra": true
            }
        });
        assert!(serde_json::from_value::<ReceiptStatusV1>(status_with_extra).is_err());
    }

    #[test]
    fn transaction_receipt_binding_rejects_every_cross_object_mismatch() {
        let first = sample_transaction(7, 123_456);
        let second = sample_transaction(8, 999_999);
        let first_receipt = successful_receipt(&first, 0);
        let second_receipt = failed_receipt(&second, 1);
        let transactions = vec![first.clone(), second.clone()];
        let receipts = vec![first_receipt.clone(), second_receipt.clone()];

        assert_eq!(
            verify_transaction_receipt_binding(BlockHeight::new(42), &transactions, &receipts),
            Ok(())
        );

        assert_eq!(
            verify_transaction_receipt_binding(BlockHeight::new(42), &transactions, &receipts[..1]),
            Err(ReceiptError::TransactionReceiptCountMismatch {
                transactions: 2,
                receipts: 1
            })
        );

        let mut wrong_position = receipts.clone();
        wrong_position[0].position.transaction_index = TransactionIndex::new(1);
        assert!(matches!(
            verify_transaction_receipt_binding(
                BlockHeight::new(42),
                &transactions,
                &wrong_position
            ),
            Err(ReceiptError::ReceiptPositionMismatch { .. })
        ));

        let mut wrong_id = receipts.clone();
        wrong_id[0].transaction_id = second_receipt.transaction_id;
        assert_eq!(
            verify_transaction_receipt_binding(BlockHeight::new(42), &transactions, &wrong_id),
            Err(ReceiptError::ReceiptTransactionIdMismatch {
                index: TransactionIndex::new(0)
            })
        );

        let mut wrong_sender = receipts.clone();
        wrong_sender[0].sender = Keypair::from_seed([9; 32]).address();
        assert_eq!(
            verify_transaction_receipt_binding(BlockHeight::new(42), &transactions, &wrong_sender),
            Err(ReceiptError::ReceiptSenderMismatch {
                index: TransactionIndex::new(0)
            })
        );

        let mut wrong_payer = receipts.clone();
        wrong_payer[0].fee_summary = calculate_fee_summary_v1(
            FeePayerV1 {
                address: Keypair::from_seed([9; 32]).address(),
                lane: AuthorizationLaneId::DEFAULT,
            },
            GasUnits::new(1_000),
            GasUnits::new(100),
            FeeRate::new(2),
            FeeRate::new(5),
            FeeRate::new(1),
        )
        .expect("alternate payer summary must calculate");
        assert_eq!(
            verify_transaction_receipt_binding(BlockHeight::new(42), &transactions, &wrong_payer),
            Err(ReceiptError::ReceiptFeePayerMismatch {
                index: TransactionIndex::new(0)
            })
        );

        let mut wrong_bid = receipts.clone();
        wrong_bid[0].fee_summary = calculate_fee_summary_v1(
            wrong_bid[0].fee_summary.payer,
            GasUnits::new(999),
            GasUnits::new(100),
            FeeRate::new(2),
            FeeRate::new(5),
            FeeRate::new(1),
        )
        .expect("alternate bid summary must calculate");
        assert_eq!(
            verify_transaction_receipt_binding(BlockHeight::new(42), &transactions, &wrong_bid),
            Err(ReceiptError::ReceiptFeeBidMismatch {
                index: TransactionIndex::new(0)
            })
        );

        let duplicate_transactions = vec![first.clone(), first.clone()];
        let duplicate_receipts = vec![successful_receipt(&first, 0), successful_receipt(&first, 1)];
        assert!(matches!(
            verify_transaction_receipt_binding(
                BlockHeight::new(42),
                &duplicate_transactions,
                &duplicate_receipts
            ),
            Err(ReceiptError::DuplicateTransactionId { .. })
        ));

        let mut out_of_range_event = receipts.clone();
        out_of_range_event[0].events[0].action_index = ActionIndex::new(1);
        assert_eq!(
            verify_transaction_receipt_binding(
                BlockHeight::new(42),
                &transactions,
                &out_of_range_event
            ),
            Err(ReceiptError::EventActionIndexOutOfRange {
                event_index: EventIndex::new(0),
                action_index: ActionIndex::new(1),
                action_count: 1
            })
        );

        let mut out_of_range_failure = receipts;
        out_of_range_failure[1].status = ReceiptStatusV1::Failed {
            code: ExecutionFailureCodeV1::Precondition,
            failed_action_index: Some(ActionIndex::new(1)),
        };
        assert_eq!(
            verify_transaction_receipt_binding(
                BlockHeight::new(42),
                &transactions,
                &out_of_range_failure
            ),
            Err(ReceiptError::FailedActionIndexOutOfRange {
                action_index: ActionIndex::new(1),
                action_count: 1
            })
        );
    }

    #[test]
    fn shared_merkle_roots_are_position_bound_and_reject_duplicate_ids() {
        assert_eq!(receipt_root_v1(&[]), Ok(Hash256::ZERO));
        assert_eq!(
            transaction_root_v1(BlockHeight::new(42), &[]),
            Ok(Hash256::ZERO)
        );

        let first = sample_transaction(7, 123_456);
        let second = sample_transaction(8, 999_999);
        let first_receipt = successful_receipt(&first, 0);
        let second_receipt = failed_receipt(&second, 1);
        assert_ne!(
            receipt_root_v1(std::slice::from_ref(&first_receipt)).unwrap(),
            Hash256::ZERO
        );
        assert_ne!(
            receipt_root_v1(&[first_receipt, second_receipt]).unwrap(),
            transaction_root_v1(BlockHeight::new(42), &[first.clone(), second]).unwrap()
        );

        assert!(matches!(
            transaction_root_v1(BlockHeight::new(42), &[first.clone(), first]),
            Err(ReceiptError::DuplicateTransactionId { .. })
        ));
    }

    #[test]
    fn sender_paid_receipt_has_frozen_cross_language_vector() {
        let first = sample_transaction(7, 123_456);
        let success = successful_receipt(&first, 0);
        let fixed_position = BlockPositionV1::new(BlockHeight::new(42), TransactionIndex::new(0));
        let transaction_id = first.transaction_id().expect("first transaction ID");
        let expected_json = concat!(
            "{\"events\":[{\"action_index\":0,\"body\":{\"Transfer\":{\"amount\":\"123456\",",
            "\"from\":\"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3\",",
            "\"to\":\"webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem\"}},",
            "\"event_index\":0,\"transaction_id\":\"c268d7d32a67ddbe985e18f881bcbd93",
            "bcfafcae5fbb6e7145276941b143f50f\",\"version\":1}],\"fee_summary\":{",
            "\"base_fee\":\"200\",\"base_fee_per_unit\":\"2\",\"burned\":\"100\",",
            "\"charged\":\"300\",\"gas_limit\":\"1000\",\"max_fee_per_unit\":\"5\",",
            "\"payer\":{\"address\":\"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3\",",
            "\"lane\":\"0000000000000000000000000000000000000000000000000000000000000000\"},",
            "\"priority_fee\":\"100\",\"priority_fee_per_unit\":\"1\",\"refund\":\"4700\",",
            "\"reserved\":\"5000\",\"units_consumed\":\"100\",\"validator_reward\":\"200\",",
            "\"version\":1},\"position\":{\"height\":\"42\",\"transaction_index\":0},",
            "\"sender\":\"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3\",",
            "\"status\":\"Succeeded\",\"transaction_id\":\"c268d7d32a67ddbe985e18f881bcbd93",
            "bcfafcae5fbb6e7145276941b143f50f\",\"version\":1}"
        );

        assert_eq!(
            transaction_id.to_string(),
            "c268d7d32a67ddbe985e18f881bcbd93bcfafcae5fbb6e7145276941b143f50f"
        );
        assert_eq!(canonical_json_string(&success).unwrap(), expected_json);
        assert_eq!(
            success.events[0].digest().unwrap().to_string(),
            "8326e93d7ad7056037c59ca7275b1431905208cf8fab0c95576c7c17c23fe1aa"
        );
        assert_eq!(
            success.digest().unwrap().to_string(),
            "007ce5d68886fc6a1e28688c808f4c5c7fa3213815deb0f924d5c564693e90af"
        );
        assert_eq!(
            success.leaf().unwrap().to_string(),
            "b5a3a00301bb0137b3324657300f8d635d4310b25d239ca9d401f92c04d114de"
        );
        assert_eq!(
            transaction_leaf_v1(fixed_position, transaction_id)
                .unwrap()
                .to_string(),
            "46a6c2901131463dc65fd1b823a68c84d74f1e1ee2a9e708190690d5b0b7d3ef"
        );
        assert_eq!(
            receipt_root_v1(&[success]).unwrap().to_string(),
            "b5a3a00301bb0137b3324657300f8d635d4310b25d239ca9d401f92c04d114de"
        );
    }
}
