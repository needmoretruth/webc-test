//! Deterministic optimistic batching from signed logical state keys.
//!
//! This module groups transaction indices but does not execute transactions or
//! trust declarations as proof of safety. Runtime access enforcement remains
//! mandatory. Batches preserve input order and use ordered sets, so local hash
//! iteration or thread timing cannot change the proposed schedule.

use crate::{StateKey, Transaction};
use std::collections::BTreeSet;

/// Builds optimistic parallel execution batches from transaction access lists.
///
/// Transactions in the same batch do not write accounts read/written by each
/// other, so they can be executed in parallel after signature/fee prechecks. The
/// current prototype returns indices; a future executor can map each batch onto a
/// worker pool.
pub fn parallel_batches(transactions: &[Transaction]) -> Vec<Vec<usize>> {
    let mut batches: Vec<BatchLocks> = Vec::new();

    'tx_loop: for (index, tx) in transactions.iter().enumerate() {
        let tx_locks = BatchLocks::from_transaction(tx);
        for batch in &mut batches {
            if !batch.conflicts_with(&tx_locks) {
                batch.merge(index, &tx_locks);
                continue 'tx_loop;
            }
        }
        batches.push(BatchLocks::new(index, tx_locks));
    }

    batches.into_iter().map(|batch| batch.indices).collect()
}

#[derive(Clone, Debug)]
struct BatchLocks {
    indices: Vec<usize>,
    reads: BTreeSet<StateKey>,
    writes: BTreeSet<StateKey>,
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
        Self {
            indices: Vec::new(),
            reads: tx.access_list.read_only.iter().cloned().collect(),
            writes: tx.access_list.read_write.iter().cloned().collect(),
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

fn intersects(left: &BTreeSet<StateKey>, right: &BTreeSet<StateKey>) -> bool {
    left.iter().any(|item| right.contains(item))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccessList, Amount, AuthorizationLaneId, FeeBid, ObjectId, Operation, Transaction,
    };
    use webc_crypto::{Address, Hash256, Keypair, PublicKeyBytes};

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
    fn same_wallet_independent_lanes_can_share_a_batch() {
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

        assert_eq!(parallel_batches(&[first, second]), vec![vec![0, 1]]);
    }

    #[test]
    fn same_wallet_objects_in_distinct_namespaces_share_a_batch() {
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

        assert_eq!(parallel_batches(&[first, second]), vec![vec![0, 1]]);
    }
}
