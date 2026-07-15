//! In-memory reference backend.
//!
//! Purpose: the simplest correct [`KvStore`] — a sorted map per table. It backs
//! unit tests and ephemeral devnets where durability is not required.
//!
//! Boundaries: holds all data in process memory; nothing survives a restart. It
//! still honors atomicity (a `commit` either fully applies or, on the single
//! validation failure path, changes nothing) so code tested against it behaves
//! identically against the durable file backend.
//!
//! Ordering: each table is a `BTreeMap<Vec<u8>, _>`, whose iteration is ascending
//! lexicographic byte order — exactly the order [`KvStore`] requires.

use std::collections::BTreeMap;

use crate::error::StorageError;
use crate::kv::{KvEntry, KvStore, Table, WriteBatch, WriteOp};

/// A volatile, ordered, atomic key/value store.
#[derive(Debug, Default)]
pub struct MemoryKvStore {
    tables: BTreeMap<u8, BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl MemoryKvStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn table(&self, table: Table) -> Option<&BTreeMap<Vec<u8>, Vec<u8>>> {
        self.tables.get(&table.tag())
    }
}

impl KvStore for MemoryKvStore {
    fn get(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.table(table).and_then(|map| map.get(key).cloned()))
    }

    fn commit(&mut self, batch: WriteBatch) -> Result<(), StorageError> {
        // In-memory application cannot partially fail: `BTreeMap` mutations do
        // not error, so the whole batch lands or (on an empty batch) nothing
        // does. Order is preserved, so a later write to the same key wins.
        for (table, key, op) in batch.into_ops() {
            let map = self.tables.entry(table.tag()).or_default();
            match op {
                WriteOp::Put(value) => {
                    map.insert(key, value);
                }
                WriteOp::Delete => {
                    map.remove(&key);
                }
            }
        }
        Ok(())
    }

    fn last_key(&self, table: Table) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self
            .table(table)
            .and_then(|map| map.keys().next_back().cloned()))
    }

    fn scan(
        &self,
        table: Table,
        start_inclusive: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<KvEntry>, StorageError> {
        let Some(map) = self.table(table) else {
            return Ok(Vec::new());
        };
        let iter: Box<dyn Iterator<Item = (&Vec<u8>, &Vec<u8>)>> = match start_inclusive {
            Some(start) => Box::new(map.range(start.to_vec()..)),
            None => Box::new(map.iter()),
        };
        Ok(iter
            .take(limit)
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_delete_round_trip() {
        let mut store = MemoryKvStore::new();
        let mut batch = WriteBatch::new();
        batch.put(Table::Blocks, vec![0, 0, 0, 1], vec![10, 11]);
        store.commit(batch).unwrap();

        assert_eq!(
            store.get(Table::Blocks, &[0, 0, 0, 1]).unwrap(),
            Some(vec![10, 11])
        );
        assert!(store.contains(Table::Blocks, &[0, 0, 0, 1]).unwrap());

        let mut batch = WriteBatch::new();
        batch.delete(Table::Blocks, vec![0, 0, 0, 1]);
        store.commit(batch).unwrap();
        assert_eq!(store.get(Table::Blocks, &[0, 0, 0, 1]).unwrap(), None);
    }

    #[test]
    fn tables_are_isolated() {
        let mut store = MemoryKvStore::new();
        let mut batch = WriteBatch::new();
        batch.put(Table::Blocks, vec![1], vec![0xaa]);
        batch.put(Table::StateSnapshots, vec![1], vec![0xbb]);
        store.commit(batch).unwrap();

        assert_eq!(store.get(Table::Blocks, &[1]).unwrap(), Some(vec![0xaa]));
        assert_eq!(
            store.get(Table::StateSnapshots, &[1]).unwrap(),
            Some(vec![0xbb])
        );
    }

    #[test]
    fn last_write_in_batch_wins() {
        let mut store = MemoryKvStore::new();
        let mut batch = WriteBatch::new();
        batch.put(Table::Meta, b"tip".to_vec(), vec![1]);
        batch.put(Table::Meta, b"tip".to_vec(), vec![2]);
        store.commit(batch).unwrap();
        assert_eq!(store.get(Table::Meta, b"tip").unwrap(), Some(vec![2]));
    }

    #[test]
    fn last_key_and_scan_are_ascending() {
        let mut store = MemoryKvStore::new();
        let mut batch = WriteBatch::new();
        for height in [3u64, 1, 2] {
            batch.put(
                Table::Blocks,
                height.to_be_bytes().to_vec(),
                vec![height as u8],
            );
        }
        store.commit(batch).unwrap();

        assert_eq!(
            store.last_key(Table::Blocks).unwrap(),
            Some(3u64.to_be_bytes().to_vec())
        );

        let scanned = store.scan(Table::Blocks, None, 10).unwrap();
        let heights: Vec<u8> = scanned.iter().map(|(_, v)| v[0]).collect();
        assert_eq!(heights, vec![1, 2, 3]);

        let from_two = store
            .scan(Table::Blocks, Some(&2u64.to_be_bytes()), 10)
            .unwrap();
        let heights: Vec<u8> = from_two.iter().map(|(_, v)| v[0]).collect();
        assert_eq!(heights, vec![2, 3]);

        assert!(store.scan(Table::Blocks, None, 0).unwrap().is_empty());
    }

    #[test]
    fn missing_table_reads_are_empty() {
        let store = MemoryKvStore::new();
        assert_eq!(store.get(Table::ValidatorSets, &[9]).unwrap(), None);
        assert_eq!(store.last_key(Table::ValidatorSets).unwrap(), None);
        assert!(store
            .scan(Table::ValidatorSets, None, 5)
            .unwrap()
            .is_empty());
    }
}
