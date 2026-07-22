//! Deterministic optimistic batching from signed logical state keys.
//!
//! This module groups transaction indices but does not execute transactions or
//! trust declarations as proof of safety. Runtime access enforcement remains
//! mandatory. Batches preserve input order and use ordered sets, so local hash
//! iteration or thread timing cannot change the proposed schedule.

use crate::{StateConflictKey, Transaction};
use std::collections::BTreeSet;

/// Builds optimistic parallel execution batches from transaction access lists.
///
/// Transactions in the same batch do not write accounts read/written by each
/// other, so they can be executed in parallel after signature/fee prechecks. The
/// current prototype returns indices; a future executor can map each batch onto a
/// worker pool.
///
/// **Serializability (finding SC1):** batches execute in order, so the schedule
/// is serializable-equivalent to the original transaction order only if every
/// conflicting pair `(i, j)` with `i < j` lands with `batch(i) <= batch(j)`. Each
/// transaction is therefore placed in the first batch at or after every earlier
/// batch it conflicts with — never merely the first non-conflicting batch, which
/// could drop a later transaction into an earlier batch than an earlier
/// transaction it conflicts with and reverse their commit order.
pub fn parallel_batches(transactions: &[Transaction]) -> Vec<Vec<usize>> {
    let mut batches: Vec<BatchLocks> = Vec::new();

    for (index, tx) in transactions.iter().enumerate() {
        let tx_locks = BatchLocks::from_transaction(tx);
        // The first batch this transaction may join: one past the highest batch
        // it conflicts with (0 if it conflicts with none). Every batch at or
        // after that index is conflict-free with this transaction by
        // construction, so joining the earliest such batch packs tightly while
        // preserving order.
        let mut earliest = 0usize;
        for (batch_index, batch) in batches.iter().enumerate() {
            if batch.conflicts_with(&tx_locks) {
                earliest = batch_index + 1;
            }
        }
        if earliest < batches.len() {
            batches[earliest].merge(index, &tx_locks);
        } else {
            batches.push(BatchLocks::new(index, tx_locks));
        }
    }

    batches.into_iter().map(|batch| batch.indices).collect()
}

#[derive(Clone, Debug)]
struct BatchLocks {
    indices: Vec<usize>,
    reads: BTreeSet<StateConflictKey>,
    writes: BTreeSet<StateConflictKey>,
}

impl BatchLocks {
    fn new(index: usize, locks: Self) -> Self {
        Self {
            indices: vec![index],
            reads: locks.reads,
            writes: locks.writes,
        }
    }

    fn from_transaction(tx: &Transaction) -> Self {
        // Conflict detection uses the version-independent physical identity,
        // not the full versioned `StateKey` (finding SC2). This also collapses
        // validator-labelled unbonding keys onto the current global queue lock;
        // the labels may become independent only after physical state sharding.
        Self {
            indices: Vec::new(),
            reads: tx
                .access_list
                .read_only
                .iter()
                .map(|key| key.kind.conflict_key())
                .collect(),
            writes: tx
                .access_list
                .read_write
                .iter()
                .map(|key| key.kind.conflict_key())
                .collect(),
        }
    }

    fn conflicts_with(&self, other: &Self) -> bool {
        intersects(&self.writes, &other.writes)
            || intersects(&self.writes, &other.reads)
            || intersects(&self.reads, &other.writes)
    }

    fn merge(&mut self, index: usize, other: &Self) {
        self.indices.push(index);
        self.reads.extend(other.reads.iter().cloned());
        self.writes.extend(other.writes.iter().cloned());
    }
}

fn intersects(left: &BTreeSet<StateConflictKey>, right: &BTreeSet<StateConflictKey>) -> bool {
    left.iter().any(|item| right.contains(item))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccessList, Amount, AuthorizationLaneId, FeeBid, ObjectId, Operation, ProtocolVersion,
        StateKey, StateKeyKind, Transaction, CURRENT_PROTOCOL_VERSION,
    };
    use webc_crypto::{Address, Hash256, Keypair, PublicKeyBytes};

    fn tx_writing(sender: Address, writes: Vec<StateKey>) -> Transaction {
        Transaction::new_unsigned(
            sender,
            PublicKeyBytes([1u8; 32]),
            0,
            Operation::Transfer {
                to: sender,
                amount: Amount::from_units(1),
            },
            AccessList::new(vec![], writes),
            FeeBid::default(),
        )
    }

    fn tx(sender: Address, target: Address) -> Transaction {
        Transaction::new_unsigned(
            sender,
            PublicKeyBytes([1u8; 32]),
            0,
            Operation::Transfer {
                to: target,
                amount: Amount::from_units(1),
            },
            AccessList::new(
                vec![],
                vec![StateKey::account(sender), StateKey::account(target)],
            ),
            FeeBid::default(),
        )
    }

    #[test]
    fn non_conflicting_transactions_share_a_batch() {
        let a = Keypair::from_seed([1u8; 32]).address();
        let b = Keypair::from_seed([2u8; 32]).address();
        let c = Keypair::from_seed([3u8; 32]).address();
        let d = Keypair::from_seed([4u8; 32]).address();
        let transactions = [tx(a, b), tx(c, d)];
        let batches = parallel_batches(transactions.as_slice());
        assert_eq!(batches, vec![vec![0, 1]]);
    }

    #[test]
    fn token_transfer_serializes_against_a_freeze_of_either_party() {
        // Regression (token review Finding 1): a TransferToken must declare both
        // parties' freeze markers as reads so the scheduler serializes it against a
        // concurrent FreezeTokenAccount of either party. Before the fix the transfer
        // touched no freeze key and shared a batch with the freeze, so under the
        // parallel executor the two would race (freeze bypass + nondeterministic
        // state root). This exercises the real access-list builder via `for_operation`.
        let holder = Keypair::from_seed([1u8; 32]);
        let recipient = Keypair::from_seed([2u8; 32]).address();
        let freeze_authority = Keypair::from_seed([3u8; 32]);
        let token_id = crate::TokenId::new(Hash256([7u8; 32]));

        let transfer = Transaction::for_operation(
            &holder,
            0,
            Operation::TransferToken {
                token_id,
                recipient,
                amount: Amount::from_units(1),
            },
            FeeBid::default(),
        )
        .expect("transfer signs");
        // Freezing the SENDER conflicts with the transfer's read of that marker.
        let freeze_sender = Transaction::for_operation(
            &freeze_authority,
            0,
            Operation::FreezeTokenAccount {
                token_id,
                account: holder.address(),
            },
            FeeBid::default(),
        )
        .expect("freeze signs");
        assert_eq!(
            parallel_batches(&[transfer.clone(), freeze_sender]),
            vec![vec![0], vec![1]]
        );

        // Freezing the RECIPIENT is likewise serialized.
        let freeze_recipient = Transaction::for_operation(
            &freeze_authority,
            0,
            Operation::FreezeTokenAccount {
                token_id,
                account: recipient,
            },
            FeeBid::default(),
        )
        .expect("freeze signs");
        assert_eq!(
            parallel_batches(&[transfer, freeze_recipient]),
            vec![vec![0], vec![1]]
        );
    }

    #[test]
    fn nft_transfer_serializes_against_a_freeze_of_the_same_item() {
        // A TransferNft and a FreezeNftItem of the SAME item both touch the per-item
        // key (the transfer writes it to move ownership / read the frozen flag; the
        // freeze writes it to set the flag), so the scheduler must serialize them.
        // Otherwise a transfer could race a concurrent freeze (freeze bypass +
        // nondeterministic state root). This exercises the real access-list builder.
        let owner = Keypair::from_seed([1u8; 32]);
        let recipient = Keypair::from_seed([2u8; 32]).address();
        let freeze_authority = Keypair::from_seed([3u8; 32]);
        let collection_id = crate::NftCollectionId::new(Hash256([7u8; 32]));

        let transfer = Transaction::for_operation(
            &owner,
            0,
            Operation::TransferNft {
                collection_id,
                serial: 5,
                recipient,
            },
            FeeBid::default(),
        )
        .expect("transfer signs");
        let freeze_same = Transaction::for_operation(
            &freeze_authority,
            0,
            Operation::FreezeNftItem {
                collection_id,
                serial: 5,
            },
            FeeBid::default(),
        )
        .expect("freeze signs");
        assert_eq!(
            parallel_batches(&[transfer.clone(), freeze_same]),
            vec![vec![0], vec![1]],
            "transfer and freeze of the same item must serialize"
        );

        // A freeze of a DIFFERENT item shares no item key, so it may batch in
        // parallel (the collection record is read-only on both, which does not
        // conflict). This confirms the serialization above is item-specific, not a
        // blanket per-collection lock.
        let freeze_other = Transaction::for_operation(
            &freeze_authority,
            0,
            Operation::FreezeNftItem {
                collection_id,
                serial: 6,
            },
            FeeBid::default(),
        )
        .expect("freeze signs");
        assert_eq!(
            parallel_batches(&[transfer, freeze_other]),
            vec![vec![0, 1]],
            "transfer and freeze of different items may run in parallel"
        );
    }

    #[test]
    fn conflicting_pairs_keep_their_commit_order_across_batches() {
        // SC1: tx0 touches A; tx1 touches A and C (conflicts tx0); tx2 touches C
        // (conflicts tx1 but not tx0). Greedy first-fit would place tx2 in tx0's
        // batch (it does not conflict there), landing the later tx2 in an earlier
        // batch than the earlier tx1 it conflicts with — a reversed commit order.
        // The serializable rule keeps tx1 before tx2.
        let a = Keypair::from_seed([1u8; 32]).address();
        let c = Keypair::from_seed([3u8; 32]).address();
        let key_a = StateKey::account(a);
        let key_c = StateKey::account(c);
        let tx0 = tx_writing(a, vec![key_a.clone()]);
        let tx1 = tx_writing(a, vec![key_a, key_c.clone()]);
        let tx2 = tx_writing(c, vec![key_c]);

        let batches = parallel_batches(&[tx0, tx1, tx2]);
        assert_eq!(batches, vec![vec![0], vec![1], vec![2]]);

        // The essential property: the conflicting pair (1, 2) does not reverse.
        let batch_of = |index: usize| {
            batches
                .iter()
                .position(|batch| batch.contains(&index))
                .expect("scheduled")
        };
        assert!(batch_of(1) < batch_of(2));
    }

    #[test]
    fn keys_conflict_on_logical_identity_regardless_of_version() {
        // SC2: the same logical account at two schema versions refers to the same
        // state and must conflict. Keying on the full versioned StateKey would let
        // these share a parallel batch.
        let account = Keypair::from_seed([1u8; 32]).address();
        let current = StateKey::account(account);
        let other_version = StateKey {
            version: ProtocolVersion::new(CURRENT_PROTOCOL_VERSION.get() + 1),
            kind: StateKeyKind::Account { address: account },
        };
        let tx0 = tx_writing(account, vec![current]);
        let tx1 = tx_writing(account, vec![other_version]);

        assert_eq!(parallel_batches(&[tx0, tx1]), vec![vec![0], vec![1]]);
    }

    #[test]
    fn validator_scoped_unbonding_keys_lock_the_current_global_queue() {
        let first = Keypair::from_seed([21u8; 32]).address();
        let second = Keypair::from_seed([22u8; 32]).address();
        let tx0 = tx_writing(first, vec![StateKey::unbonding_queue(first)]);
        let tx1 = tx_writing(second, vec![StateKey::unbonding_queue(second)]);

        assert_eq!(parallel_batches(&[tx0, tx1]), vec![vec![0], vec![1]]);
    }

    #[test]
    fn conflicting_transactions_are_split() {
        let a = Keypair::from_seed([1u8; 32]).address();
        let b = Keypair::from_seed([2u8; 32]).address();
        let c = Keypair::from_seed([3u8; 32]).address();
        let transactions = [tx(a, b), tx(c, b)];
        let batches = parallel_batches(transactions.as_slice());
        assert_eq!(batches, vec![vec![0], vec![1]]);
    }

    #[test]
    fn unrelated_application_namespaces_share_a_batch() {
        let a = Keypair::from_seed([1u8; 32]).address();
        let b = Keypair::from_seed([2u8; 32]).address();
        let namespace_a = Hash256::digest(b"site-a");
        let namespace_b = Hash256::digest(b"site-b");
        let local_key = Hash256::digest(b"session");
        let mut first = tx(a, b);
        first.access_list =
            AccessList::new(vec![], vec![StateKey::application(namespace_a, local_key)]);
        let mut second = tx(b, a);
        second.access_list =
            AccessList::new(vec![], vec![StateKey::application(namespace_b, local_key)]);

        assert_eq!(parallel_batches(&[first, second]), vec![vec![0, 1]]);
    }

    #[test]
    fn global_unbonding_queue_serializes_otherwise_independent_wallet_lanes() {
        let wallet = Keypair::from_seed([9u8; 32]);
        let first_validator = Keypair::from_seed([10u8; 32]).address();
        let second_validator = Keypair::from_seed([11u8; 32]).address();
        let first = Transaction::for_operation_in_lane(
            &wallet,
            AuthorizationLaneId::new(Hash256::digest(b"site-a")),
            0,
            Operation::Undelegate {
                validator: first_validator,
                amount: Amount::from_units(1),
            },
            FeeBid {
                gas_limit: 20_000,
                ..FeeBid::default()
            },
        )
        .expect("first lane signs");
        let second = Transaction::for_operation_in_lane(
            &wallet,
            AuthorizationLaneId::new(Hash256::digest(b"site-b")),
            0,
            Operation::Undelegate {
                validator: second_validator,
                amount: Amount::from_units(1),
            },
            FeeBid {
                gas_limit: 20_000,
                ..FeeBid::default()
            },
        )
        .expect("second lane signs");

        // The fee lanes and validator labels differ, but both operations write
        // the same physical queue today. Treating them as independent would
        // permit a last-writer-wins merge that loses one exit request.
        assert_eq!(parallel_batches(&[first, second]), vec![vec![0], vec![1]]);
    }

    #[test]
    fn distinct_wallet_objects_in_distinct_namespaces_share_a_batch() {
        // Object creation locks a storage deposit from the creator's liquid
        // balance (§15.22), so two creates by DIFFERENT wallets in different
        // namespaces still touch disjoint state and can run in parallel — the
        // namespace/account isolation the scheduler exists to exploit.
        let operation = |label: &'static [u8]| Operation::CreateObject {
            object_id: ObjectId::new(Hash256::digest_many([b"object", label])),
            namespace: Hash256::digest_many([b"namespace", label]),
            data: label.to_vec(),
        };
        let first = Transaction::for_operation_in_lane(
            &Keypair::from_seed([12u8; 32]),
            AuthorizationLaneId::new(Hash256::digest(b"lane-a")),
            0,
            operation(b"a"),
            FeeBid {
                gas_limit: 30_000,
                ..FeeBid::default()
            },
        )
        .expect("first object signs");
        let second = Transaction::for_operation_in_lane(
            &Keypair::from_seed([13u8; 32]),
            AuthorizationLaneId::new(Hash256::digest(b"lane-b")),
            0,
            operation(b"b"),
            FeeBid {
                gas_limit: 30_000,
                ..FeeBid::default()
            },
        )
        .expect("second object signs");

        assert_eq!(parallel_batches(&[first, second]), vec![vec![0, 1]]);
    }

    #[test]
    fn same_wallet_object_creates_serialize_on_the_deposit_funding_account() {
        // Two creates by the SAME wallet — even in different namespaces and fee
        // lanes — both lock a storage deposit from that wallet's single liquid
        // balance, so they conflict on the sender account and must be scheduled
        // sequentially. This mirrors Sui's shared gas coin serializing an owner's
        // transactions, and prevents parallel double-spend of the same balance.
        let wallet = Keypair::from_seed([12u8; 32]);
        let operation = |label: &'static [u8]| Operation::CreateObject {
            object_id: ObjectId::new(Hash256::digest_many([b"object", label])),
            namespace: Hash256::digest_many([b"namespace", label]),
            data: label.to_vec(),
        };
        let first = Transaction::for_operation_in_lane(
            &wallet,
            AuthorizationLaneId::new(Hash256::digest(b"lane-a")),
            0,
            operation(b"a"),
            FeeBid {
                gas_limit: 30_000,
                ..FeeBid::default()
            },
        )
        .expect("first object signs");
        let second = Transaction::for_operation_in_lane(
            &wallet,
            AuthorizationLaneId::new(Hash256::digest(b"lane-b")),
            0,
            operation(b"b"),
            FeeBid {
                gas_limit: 30_000,
                ..FeeBid::default()
            },
        )
        .expect("second object signs");

        assert_eq!(parallel_batches(&[first, second]), vec![vec![0], vec![1]]);
    }
}
