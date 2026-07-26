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
//! At-rest compression: every *value* is run through [`crate::codec`] on the way
//! to redb (transparent zstd, with an adaptive raw-store skip and a 1-byte format
//! tag) and reversed on the way out — point reads and scans alike. Keys are never
//! compressed, so key order, ranges, and `last_key` are untouched. This is a pure
//! physical encoding: what `get`/`scan` yield is byte-identical to what was
//! `put`, so nothing above this seam can observe that compression happened.
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

use crate::codec::{decode_value, encode_value};
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
        Table::Certificates => "webc_certificates",
        Table::ConsensusWal => "webc_consensus_wal",
        Table::PendingBySlot => "webc_pending_by_slot",
        Table::PendingTransactions => "webc_pending_transactions",
        Table::TransactionLifecycle => "webc_transaction_lifecycle",
        Table::FinalizedTransactionIndex => "webc_finalized_transaction_index",
        Table::FinalizedReceiptIndex => "webc_finalized_receipt_index",
        Table::BlocksV2 => "webc_blocks_v2",
        Table::BlockV4HashIndex => "webc_block_v4_hash_index",
        Table::FinalityAuthoritySets => "webc_finality_authority_sets",
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
        // Decode the stored physical value (tag byte + raw/zstd body) back into
        // its canonical form. `transpose` turns the `Option<Result<..>>` into a
        // `Result<Option<..>>` so a corrupt value surfaces as an error, not data.
        found.map(|guard| decode_value(guard.value())).transpose()
    }

    /// Reports whether `(table, key)` exists without decoding its value.
    ///
    /// Overrides the trait default (which would `get` and decompress the whole
    /// value just to test presence) — existence is a property of the key, and
    /// keys are never compressed, so this reads only the key index.
    fn key_exists(&self, table: Table, key: &[u8]) -> Result<bool, StorageError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|error| map_redb("begin read transaction", error))?;
        let table_handle = match txn.open_table(table_def(table)) {
            Ok(handle) => handle,
            Err(TableError::TableDoesNotExist(_)) => return Ok(false),
            Err(error) => return Err(map_redb("open table for read", error)),
        };
        Ok(table_handle
            .get(key)
            .map_err(|error| map_redb("read key", error))?
            .is_some())
    }
}

impl KvStore for RedbKvStore {
    fn get(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.read_value(table, key)
    }

    fn contains(&self, table: Table, key: &[u8]) -> Result<bool, StorageError> {
        // Cheaper than the default `get` probe: presence needs only the key, so
        // we skip fetching and decompressing the value.
        self.key_exists(table, key)
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
                        // Compress the value (transparently; keys are stored as
                        // given) before it lands in redb.
                        let encoded = encode_value(&value);
                        handle
                            .insert(key.as_slice(), encoded.as_slice())
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
            // Keys are stored verbatim; values are decompressed back to canonical
            // form, so a scan yields the same logical bytes a caller `put`.
            out.push((key.value().to_vec(), decode_value(value.value())?));
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

    /// Reads the raw *physical* bytes stored for a key (tag byte + body),
    /// bypassing the codec, so a test can assert how a value was encoded on disk.
    fn physical_value(store: &RedbKvStore, table: Table, key: &[u8]) -> Option<Vec<u8>> {
        let txn = store.db.begin_read().unwrap();
        let handle = match txn.open_table(table_def(table)) {
            Ok(handle) => handle,
            Err(TableError::TableDoesNotExist(_)) => return None,
            Err(error) => panic!("open table: {error:?}"),
        };
        handle.get(key).unwrap().map(|guard| guard.value().to_vec())
    }

    /// Writes raw physical bytes for a key, bypassing the codec, so a test can
    /// inject a corrupted stored value (bad tag / truncated frame).
    fn put_physical(store: &mut RedbKvStore, table: Table, key: &[u8], physical: &[u8]) {
        let txn = store.db.begin_write().unwrap();
        {
            let mut handle = txn.open_table(table_def(table)).unwrap();
            handle.insert(key, physical).unwrap();
        }
        txn.commit().unwrap();
    }

    /// Deterministic high-entropy bytes (xorshift64) that zstd cannot shrink —
    /// no RNG dependency, reproducible across runs.
    fn incompressible(len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for byte in out.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = (state & 0xff) as u8;
        }
        out
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

    // --- Transparent at-rest compression (WEBC §15.19/§15.24) ---------------

    /// The whole point: `get` returns byte-identical values across empty, tiny,
    /// highly-compressible, and incompressible payloads, regardless of how each
    /// was physically encoded.
    #[test]
    fn compression_is_transparent_across_payload_shapes() {
        let (_dir, mut store) = open_temp();
        let cases: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"x".to_vec(),
            vec![7u8; 63],          // just under the raw threshold
            vec![7u8; 64],          // exactly the threshold
            vec![0u8; 100_000],     // highly compressible
            incompressible(50_000), // high entropy
        ];
        let mut batch = WriteBatch::new();
        for (i, value) in cases.iter().enumerate() {
            batch.put(
                Table::Blocks,
                (i as u64).to_be_bytes().to_vec(),
                value.clone(),
            );
        }
        store.commit(batch).unwrap();
        for (i, value) in cases.iter().enumerate() {
            assert_eq!(
                store.get(Table::Blocks, &(i as u64).to_be_bytes()).unwrap(),
                Some(value.clone()),
                "case {i} did not round-trip byte-identically"
            );
        }
    }

    /// A highly compressible value is physically stored with the zstd tag and is
    /// dramatically smaller than the logical value on disk.
    #[test]
    fn compressible_value_is_physically_compressed_and_smaller() {
        let (_dir, mut store) = open_temp();
        let key = 1u64.to_be_bytes();
        let value = vec![0u8; 100_000];
        let mut batch = WriteBatch::new();
        batch.put(Table::Blocks, key.to_vec(), value.clone());
        store.commit(batch).unwrap();

        let physical = physical_value(&store, Table::Blocks, &key).unwrap();
        assert_eq!(physical[0], crate::codec::ZSTD_TAG);
        assert!(
            physical.len() < value.len() / 10,
            "expected strong on-disk compression, got {} bytes from {}",
            physical.len(),
            value.len()
        );
        // And it still reads back identically.
        assert_eq!(store.get(Table::Blocks, &key).unwrap(), Some(value));
    }

    /// Incompressible and tiny values are stored RAW: exactly the value plus the
    /// one-byte format tag.
    #[test]
    fn incompressible_and_tiny_values_are_stored_raw() {
        let (_dir, mut store) = open_temp();
        let big_random = incompressible(8_192);
        let tiny = b"hi".to_vec();
        let empty: Vec<u8> = Vec::new();
        let mut batch = WriteBatch::new();
        batch.put(
            Table::Blocks,
            1u64.to_be_bytes().to_vec(),
            big_random.clone(),
        );
        batch.put(Table::Blocks, 2u64.to_be_bytes().to_vec(), tiny.clone());
        batch.put(Table::Blocks, 3u64.to_be_bytes().to_vec(), empty.clone());
        store.commit(batch).unwrap();

        for (key, value) in [(1u64, &big_random), (2, &tiny), (3, &empty)] {
            let physical = physical_value(&store, Table::Blocks, &key.to_be_bytes()).unwrap();
            assert_eq!(
                physical[0],
                crate::codec::RAW_TAG,
                "key {key} should be raw"
            );
            assert_eq!(
                physical.len(),
                value.len() + 1,
                "raw storage is value + one tag byte (key {key})"
            );
            assert_eq!(
                store.get(Table::Blocks, &key.to_be_bytes()).unwrap(),
                Some(value.clone())
            );
        }
    }

    /// A batch of compressible values written together and then read back by
    /// `scan` all come out decompressed and in order.
    #[test]
    fn batch_write_then_scan_returns_decompressed_values() {
        let (_dir, mut store) = open_temp();
        let mut batch = WriteBatch::new();
        let mut expected = Vec::new();
        for height in 0u64..5 {
            // Distinct, compressible values so we can tell them apart.
            let value = vec![height as u8; 2_000];
            batch.put(Table::Blocks, height.to_be_bytes().to_vec(), value.clone());
            expected.push((height.to_be_bytes().to_vec(), value));
        }
        store.commit(batch).unwrap();

        // Every value was actually compressed on disk...
        for (height, _) in &expected {
            let physical = physical_value(&store, Table::Blocks, height).unwrap();
            assert_eq!(physical[0], crate::codec::ZSTD_TAG);
        }
        // ...yet the scan yields the logical, decompressed values in key order.
        let scanned = store.scan(Table::Blocks, None, 100).unwrap();
        assert_eq!(scanned, expected);
    }

    /// A stored value with a corrupted format tag surfaces as a StorageError,
    /// never a panic.
    #[test]
    fn corrupted_tag_yields_storage_error() {
        let (_dir, mut store) = open_temp();
        let key = 1u64.to_be_bytes();
        // Inject a physical value with an unknown tag byte.
        put_physical(&mut store, Table::Blocks, &key, &[0xff, 1, 2, 3]);
        let err = store.get(Table::Blocks, &key).unwrap_err();
        assert!(matches!(err, StorageError::Corruption(_)));
    }

    /// A truncated zstd frame on disk surfaces as a StorageError from both the
    /// point-read and the scan path, never a panic.
    #[test]
    fn truncated_compressed_value_yields_storage_error() {
        let (_dir, mut store) = open_temp();
        let key = 1u64.to_be_bytes();
        let value = vec![3u8; 20_000];
        let mut batch = WriteBatch::new();
        batch.put(Table::Blocks, key.to_vec(), value);
        store.commit(batch).unwrap();

        // Chop the stored zstd frame in half to simulate on-disk damage.
        let physical = physical_value(&store, Table::Blocks, &key).unwrap();
        assert_eq!(physical[0], crate::codec::ZSTD_TAG);
        put_physical(
            &mut store,
            Table::Blocks,
            &key,
            &physical[..physical.len() / 2],
        );

        let err = store.get(Table::Blocks, &key).unwrap_err();
        assert!(matches!(err, StorageError::Corruption(_)));
        // The scan path must fail closed the same way.
        let scan_err = store.scan(Table::Blocks, None, 10).unwrap_err();
        assert!(matches!(scan_err, StorageError::Corruption(_)));
    }

    /// `contains` still works over compressed values without decoding them.
    #[test]
    fn contains_works_over_compressed_values() {
        let (_dir, mut store) = open_temp();
        let key = 1u64.to_be_bytes();
        let mut batch = WriteBatch::new();
        batch.put(Table::Blocks, key.to_vec(), vec![0u8; 5_000]);
        store.commit(batch).unwrap();
        assert!(store.contains(Table::Blocks, &key).unwrap());
        assert!(!store.contains(Table::Blocks, &2u64.to_be_bytes()).unwrap());
    }

    /// A compressed value written, then read after reopening the database from
    /// disk, is byte-identical — durability holds through the codec.
    #[test]
    fn compressed_value_survives_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.redb");
        let value = vec![0u8; 100_000];
        {
            let mut store = RedbKvStore::open(&path).unwrap();
            let mut batch = WriteBatch::new();
            batch.put(Table::Blocks, 9u64.to_be_bytes().to_vec(), value.clone());
            store.commit(batch).unwrap();
            // It was genuinely compressed on disk before the close.
            let physical = physical_value(&store, Table::Blocks, &9u64.to_be_bytes()).unwrap();
            assert_eq!(physical[0], crate::codec::ZSTD_TAG);
            assert!(physical.len() < value.len());
        }
        // Fresh handle from disk decompresses back to the exact bytes.
        let reopened = RedbKvStore::open(&path).unwrap();
        assert_eq!(
            reopened.get(Table::Blocks, &9u64.to_be_bytes()).unwrap(),
            Some(value)
        );
    }
}
