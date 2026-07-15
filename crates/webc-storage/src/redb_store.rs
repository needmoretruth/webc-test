//! Durable, crash-safe backend built on the `redb` embedded database.
//!
//! Purpose: satisfy the [`KvStore`] contract with real on-disk durability without
//! hand-writing a write-ahead log, fsync discipline, or crash recovery. `redb`
//! (MIT OR Apache-2.0, license-compatible with WEBC) is a mature pure-Rust
//! embedded key/value store with ACID transactions, so it provides exactly the
//! atomicity, durability, and startup recovery this layer needs. This module is
//! the thin *adapter* that binds it behind our swappable seam — building it
//! ourselves is the intended decoupling, not reinvention of the database.
//!
//! Boundaries: it maps our [`Table`] namespaces onto redb tables, our
//! [`WriteBatch`] onto a single redb write transaction (one indivisible commit),
//! and our reads onto redb read transactions. It holds no chain logic.
//!
//! Crash-safety: every [`KvStore::commit`] runs as one redb write transaction
//! committed with immediate durability (an fsync barrier), so after the call
//! returns the whole batch is on stable storage or, on a crash mid-commit, none
//! of it is. On reopen, redb recovers to the last committed transaction and
//! surfaces structural damage as an error, which this adapter reports as
//! [`StorageError::Corruption`] — the node then fails closed instead of trusting
//! a damaged store.

use std::path::Path;

use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition, TableError};

use crate::error::StorageError;
use crate::kv::{KvEntry, KvStore, Table, WriteBatch, WriteOp};

/// redb table definition for one WEBC [`Table`] namespace.
///
/// Keys and values are opaque byte strings; all typing lives in the `ChainStore`
/// layer above. The physical table name is part of the on-disk format, so treat
/// these strings as frozen: change one only with a schema-version migration.
fn table_def(table: Table) -> TableDefinition<'static, &'static [u8], &'static [u8]> {
    let name = match table {
        Table::Meta => "webc_meta",
        Table::Blocks => "webc_blocks",
        Table::StateSnapshots => "webc_state_snapshots",
        Table::BlockHashIndex => "webc_block_hash_index",
        Table::ValidatorSets => "webc_validator_sets",
    };
    TableDefinition::new(name)
}

/// Classifies a redb error, mapping structural damage to [`StorageError::Corruption`]
/// and everything else to [`StorageError::Io`].
///
/// redb reports a torn or inconsistent file as `redb::StorageError::Corrupted`;
/// distinguishing it lets the node treat a damaged store as untrustworthy rather
/// than a transient fault.
fn map_redb(context: &str, error: impl Into<redb::Error>) -> StorageError {
    match error.into() {
        redb::Error::Corrupted(message) => {
            StorageError::Corruption(format!("{context}: {message}"))
        }
        other => StorageError::Io(format!("{context}: {other}")),
    }
}

/// A durable [`KvStore`] backed by a single redb database file.
#[derive(Debug)]
pub struct RedbKvStore {
    db: Database,
}

impl RedbKvStore {
    /// Opens the database at `path`, creating an empty one if it does not exist.
    ///
    /// On an existing file, redb performs crash recovery to the last committed
    /// transaction before returning. A structurally damaged file yields
    /// [`StorageError::Corruption`].
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let db =
            Database::create(path).map_err(|error| map_redb("open storage database", error))?;
        Ok(Self { db })
    }

    /// Reads a value inside an already-open read transaction, treating a table
    /// that has never been written as simply empty (not an error).
    fn read_value(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|error| map_redb("begin read transaction", error))?;
        let opened = txn.open_table(table_def(table));
        let table_handle = match opened {
            Ok(handle) => handle,
            // A table only exists after its first write. An absent table means
            // "no keys", which is a normal empty read, not corruption.
            Err(TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(error) => return Err(map_redb("open table for read", error)),
        };
        let found = table_handle
            .get(key)
            .map_err(|error| map_redb("read key", error))?;
        Ok(found.map(|guard| guard.value().to_vec()))
    }
}

impl KvStore for RedbKvStore {
    fn get(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.read_value(table, key)
    }

    fn commit(&mut self, batch: WriteBatch) -> Result<(), StorageError> {
        // An empty batch is a durable no-op: skip the transaction entirely so we
        // never write an empty commit record.
        if batch.is_empty() {
            return Ok(());
        }
        let mut txn = self
            .db
            .begin_write()
            .map_err(|error| map_redb("begin write transaction", error))?;
        // Immediate durability fsyncs the commit, which is what makes an
        // acknowledged block truly survive a crash. WEBC commits once per block,
        // so the fsync cost is amortised over the whole block.
        txn.set_durability(Durability::Immediate)
            .map_err(|error| map_redb("set durability", error))?;
        {
            // Open each referenced table lazily and apply ops in insertion order
            // so a later write to the same key within the batch wins, matching
            // the in-memory backend.
            for (table, key, op) in batch.into_ops() {
                let mut handle = txn
                    .open_table(table_def(table))
                    .map_err(|error| map_redb("open table for write", error))?;
                match op {
                    WriteOp::Put(value) => {
                        handle
                            .insert(key.as_slice(), value.as_slice())
                            .map_err(|error| map_redb("insert key", error))?;
                    }
                    WriteOp::Delete => {
                        handle
                            .remove(key.as_slice())
                            .map_err(|error| map_redb("remove key", error))?;
                    }
                }
            }
        }
        // The commit is the single atomic, durable point: everything above lands
        // together or (on failure/crash) not at all.
        txn.commit()
            .map_err(|error| map_redb("commit write transaction", error))?;
        Ok(())
    }

    fn last_key(&self, table: Table) -> Result<Option<Vec<u8>>, StorageError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|error| map_redb("begin read transaction", error))?;
        let table_handle = match txn.open_table(table_def(table)) {
            Ok(handle) => handle,
            Err(TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(error) => return Err(map_redb("open table for read", error)),
        };
        let last = table_handle
            .last()
            .map_err(|error| map_redb("read last key", error))?;
        Ok(last.map(|(key, _)| key.value().to_vec()))
    }

    fn scan(
        &self,
        table: Table,
        start_inclusive: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<KvEntry>, StorageError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let txn = self
            .db
            .begin_read()
            .map_err(|error| map_redb("begin read transaction", error))?;
        let table_handle = match txn.open_table(table_def(table)) {
            Ok(handle) => handle,
            Err(TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(error) => return Err(map_redb("open table for read", error)),
        };
        // redb yields entries in ascending key order, which for our big-endian
        // numeric keys is ascending numeric order.
        let range = match start_inclusive {
            Some(start) => table_handle
                .range(start..)
                .map_err(|error| map_redb("open scan range", error))?,
            None => table_handle
                .range::<&[u8]>(..)
                .map_err(|error| map_redb("open scan range", error))?,
        };
        let mut out = Vec::new();
        for entry in range.take(limit) {
            let (key, value) = entry.map_err(|error| map_redb("read scan entry", error))?;
            out.push((key.value().to_vec(), value.value().to_vec()));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn open_temp() -> (tempfile::TempDir, RedbKvStore) {
        let dir = tempdir().unwrap();
        let store = RedbKvStore::open(dir.path().join("chain.redb")).unwrap();
        (dir, store)
    }

    #[test]
    fn put_get_delete_round_trip() {
        let (_dir, mut store) = open_temp();
        let mut batch = WriteBatch::new();
        batch.put(Table::Blocks, 1u64.to_be_bytes().to_vec(), vec![10, 11]);
        store.commit(batch).unwrap();

        assert_eq!(
            store.get(Table::Blocks, &1u64.to_be_bytes()).unwrap(),
            Some(vec![10, 11])
        );

        let mut batch = WriteBatch::new();
        batch.delete(Table::Blocks, 1u64.to_be_bytes().to_vec());
        store.commit(batch).unwrap();
        assert_eq!(store.get(Table::Blocks, &1u64.to_be_bytes()).unwrap(), None);
    }

    #[test]
    fn survives_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.redb");
        {
            let mut store = RedbKvStore::open(&path).unwrap();
            let mut batch = WriteBatch::new();
            batch.put(Table::Meta, b"tip".to_vec(), 42u64.to_be_bytes().to_vec());
            batch.put(Table::Blocks, 7u64.to_be_bytes().to_vec(), vec![0xab]);
            store.commit(batch).unwrap();
        }
        // Reopen from disk: a fresh handle must see the committed data, proving
        // durability across a simulated restart.
        let reopened = RedbKvStore::open(&path).unwrap();
        assert_eq!(
            reopened.get(Table::Meta, b"tip").unwrap(),
            Some(42u64.to_be_bytes().to_vec())
        );
        assert_eq!(
            reopened.get(Table::Blocks, &7u64.to_be_bytes()).unwrap(),
            Some(vec![0xab])
        );
    }

    #[test]
    fn tables_are_isolated() {
        let (_dir, mut store) = open_temp();
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
    fn last_key_and_scan_are_ascending() {
        let (_dir, mut store) = open_temp();
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
        let (_dir, store) = open_temp();
        assert_eq!(store.get(Table::ValidatorSets, &[9]).unwrap(), None);
        assert_eq!(store.last_key(Table::ValidatorSets).unwrap(), None);
        assert!(store
            .scan(Table::ValidatorSets, None, 5)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn last_write_in_batch_wins() {
        let (_dir, mut store) = open_temp();
        let mut batch = WriteBatch::new();
        batch.put(Table::Meta, b"k".to_vec(), vec![1]);
        batch.put(Table::Meta, b"k".to_vec(), vec![2]);
        store.commit(batch).unwrap();
        assert_eq!(store.get(Table::Meta, b"k").unwrap(), Some(vec![2]));
    }
}
