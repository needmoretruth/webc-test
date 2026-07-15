//! Typed chain persistence: blocks, latest state, and the committed tip.
//!
//! Purpose: translate WEBC domain objects — [`Block`], [`ChainState`], and the
//! chain tip — into the untyped [`KvStore`] seam, and expose one indivisible
//! per-block commit. This is WEBC's own storage glue (not a reusable database),
//! so it lives here rather than in a dependency.
//!
//! Boundaries: it does not execute transactions, validate signatures, or decide
//! finality. Callers hand it an already-executed block and the resulting state;
//! it durably records them and advances the tip. It is generic over any
//! [`KvStore`], so the same logic runs on the in-memory and redb backends.
//!
//! Data flow / atomicity: [`ChainStore::commit_block`] builds a single
//! [`WriteBatch`] containing the block, the new latest-state snapshot (replacing
//! the previous one), the block-hash index entry, an optional validator-set
//! snapshot, and the updated tip pointer — then commits it as one atomic,
//! durable unit. Because the tip advances in the same batch as the data it
//! points at, a crash can never leave the tip ahead of, or behind, its block and
//! state. This is what lets a node restart without losing or duplicating
//! committed state.
//!
//! Corruption / consistency: [`ChainStore::open`] verifies the schema version and
//! that the tip's block and state are actually present and hash-consistent,
//! reporting any mismatch as [`StorageError::Inconsistent`] or
//! [`StorageError::Corruption`] so the node fails closed on a damaged store.

use serde::{Deserialize, Serialize};

use webc_chain::{Block, BlockHeader, ChainState, ValidatorSet};
use webc_crypto::Hash256;

use crate::error::StorageError;
use crate::kv::{KvStore, Table, WriteBatch};

/// On-disk schema version for the typed chain layout.
///
/// Bump this only with a migration: [`ChainStore::open`] refuses any other
/// version so a future layout is never interpreted with today's rules.
pub const CHAIN_STORE_SCHEMA_VERSION: u32 = 1;

/// Meta-table key holding the 4-byte big-endian schema version.
const META_SCHEMA_VERSION: &[u8] = b"schema_version";
/// Meta-table key holding the bincode-encoded [`ChainTip`].
const META_TIP: &[u8] = b"tip";

/// The latest committed point of the chain.
///
/// `height` is 0 at genesis (the genesis state, before any block). `block_hash`
/// is `None` only at genesis, since there is no block 0; every committed block
/// sets it to that block's V2 header hash. `state_root` always matches the state
/// snapshot stored at `height`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainTip {
    /// Height of the most recently committed block, or 0 for genesis-only state.
    pub height: u64,
    /// V2 header hash of the tip block, or `None` at genesis.
    pub block_hash: Option<Hash256>,
    /// State root committed after applying the tip (matches the stored snapshot).
    pub state_root: Hash256,
}

/// Everything one finalized block contributes to durable storage.
///
/// The caller supplies an already-executed `block` and the `state` that results
/// from applying it. `validator_set`, when present, is the snapshot that governs
/// this block's epoch and is stored under `block.header.epoch`.
pub struct BlockCommit<'a> {
    /// The finalized block (header, transactions, receipts, evidence).
    pub block: &'a Block,
    /// Chain state after this block; becomes the new latest snapshot.
    pub state: &'a ChainState,
    /// Optional validator-set snapshot for this block's epoch.
    pub validator_set: Option<&'a ValidatorSet>,
}

/// Big-endian 8-byte key for a height or epoch, so byte order equals numeric order.
fn be(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

/// Typed, backend-agnostic chain storage over any [`KvStore`].
#[derive(Debug)]
pub struct ChainStore<K: KvStore> {
    store: K,
}

impl<K: KvStore> ChainStore<K> {
    /// Opens typed storage over `store`, initializing or verifying the schema and
    /// checking tip consistency.
    ///
    /// A fresh (empty) store is stamped with the current schema version. An
    /// existing store must carry exactly [`CHAIN_STORE_SCHEMA_VERSION`]; any other
    /// value is [`StorageError::UnsupportedSchemaVersion`]. If a tip is present,
    /// its block (for height > 0) and state snapshot must exist and hash
    /// consistently, else the store is reported as inconsistent/corrupt.
    pub fn open(mut store: K) -> Result<Self, StorageError> {
        match store.get(Table::Meta, META_SCHEMA_VERSION)? {
            None => {
                // Fresh store: stamp the schema version durably so a later open
                // recognizes the layout.
                let mut batch = WriteBatch::new();
                batch.put(
                    Table::Meta,
                    META_SCHEMA_VERSION,
                    CHAIN_STORE_SCHEMA_VERSION.to_be_bytes().to_vec(),
                );
                store.commit(batch)?;
            }
            Some(bytes) => {
                let found = decode_u32(&bytes).ok_or_else(|| {
                    StorageError::Corruption("schema version is malformed".into())
                })?;
                if found != CHAIN_STORE_SCHEMA_VERSION {
                    return Err(StorageError::UnsupportedSchemaVersion {
                        found,
                        expected: CHAIN_STORE_SCHEMA_VERSION,
                    });
                }
            }
        }

        let chain_store = Self { store };
        chain_store.verify_tip_consistency()?;
        Ok(chain_store)
    }

    /// Confirms that a stored tip is backed by the block and state it names.
    fn verify_tip_consistency(&self) -> Result<(), StorageError> {
        let Some(tip) = self.tip()? else {
            return Ok(());
        };
        // The tip's state snapshot must exist and commit to the recorded root.
        let state = self.state_at_height(tip.height)?.ok_or_else(|| {
            StorageError::Inconsistent(format!(
                "tip names height {} but no state snapshot is stored",
                tip.height
            ))
        })?;
        let actual_root = state
            .state_root()
            .map_err(|error| StorageError::Serialization(error.to_string()))?;
        if actual_root != tip.state_root {
            return Err(StorageError::Corruption(format!(
                "tip state root does not match the stored snapshot at height {}",
                tip.height
            )));
        }
        // For any real block (height > 0) the block must exist and its header
        // hash must equal the tip's recorded block hash.
        if tip.height > 0 {
            let block = self.block_by_height(tip.height)?.ok_or_else(|| {
                StorageError::Inconsistent(format!(
                    "tip names block height {} but no block is stored",
                    tip.height
                ))
            })?;
            let header_hash = block
                .hash()
                .map_err(|error| StorageError::Serialization(error.to_string()))?;
            if Some(header_hash) != tip.block_hash {
                return Err(StorageError::Corruption(format!(
                    "stored block at height {} does not match the tip block hash",
                    tip.height
                )));
            }
        }
        Ok(())
    }

    /// Records the genesis state as height 0, establishing the initial tip.
    ///
    /// Idempotent-safe: if a tip already exists it must be the genesis tip for
    /// this exact state (verified by state root), and the call is a no-op;
    /// otherwise it errors rather than overwriting a chain that has advanced.
    pub fn initialize_genesis(&mut self, genesis: &ChainState) -> Result<(), StorageError> {
        let root = genesis
            .state_root()
            .map_err(|error| StorageError::Serialization(error.to_string()))?;
        if let Some(existing) = self.tip()? {
            if existing.height != 0 || existing.state_root != root {
                return Err(StorageError::Inconsistent(
                    "cannot initialize genesis over an already-initialized chain".into(),
                ));
            }
            return Ok(());
        }
        let state_bytes = bincode::serialize(genesis)?;
        let tip = ChainTip {
            height: 0,
            block_hash: None,
            state_root: root,
        };
        let mut batch = WriteBatch::new();
        batch.put(Table::StateSnapshots, be(0).to_vec(), state_bytes);
        batch.put(Table::Meta, META_TIP, bincode::serialize(&tip)?);
        self.store.commit(batch)
    }

    /// Atomically appends one finalized block and advances the tip.
    ///
    /// Requires an initialized chain (a genesis tip). The block must be exactly
    /// one height above the current tip, and — for a non-genesis parent — its
    /// `previous_hash` must equal the current tip block hash. These checks make
    /// duplicate or gapped commits impossible. The new state snapshot replaces
    /// the previous one (only the latest is retained), and the state root must
    /// match the block header's `state_root`.
    pub fn commit_block(&mut self, commit: BlockCommit<'_>) -> Result<(), StorageError> {
        let tip = self.tip()?.ok_or_else(|| {
            StorageError::Inconsistent("chain is not initialized; call initialize_genesis".into())
        })?;
        let header = &commit.block.header;

        // Contiguity: the only acceptable next height is tip + 1. This single
        // check rejects both replays (<= tip) and gaps (> tip + 1).
        if header.height != tip.height + 1 {
            return Err(StorageError::Inconsistent(format!(
                "next block height must be {}, got {}",
                tip.height + 1,
                header.height
            )));
        }
        // Parent linkage: for any real parent block, the child must point at it.
        if let Some(parent_hash) = tip.block_hash {
            if header.previous_hash != parent_hash {
                return Err(StorageError::Inconsistent(
                    "block previous_hash does not match the current tip".into(),
                ));
            }
        }

        // The recorded state must be the one the header commits to.
        let state_root = commit
            .state
            .state_root()
            .map_err(|error| StorageError::Serialization(error.to_string()))?;
        if state_root != header.state_root {
            return Err(StorageError::Inconsistent(
                "provided state root does not match the block header state_root".into(),
            ));
        }

        let block_hash = commit
            .block
            .hash()
            .map_err(|error| StorageError::Serialization(error.to_string()))?;
        let block_bytes = bincode::serialize(commit.block)?;
        let state_bytes = bincode::serialize(commit.state)?;
        let new_tip = ChainTip {
            height: header.height,
            block_hash: Some(block_hash),
            state_root,
        };

        let mut batch = WriteBatch::new();
        batch.put(Table::Blocks, be(header.height).to_vec(), block_bytes);
        batch.put(
            Table::BlockHashIndex,
            block_hash.0.to_vec(),
            be(header.height).to_vec(),
        );
        // Keep only the latest state snapshot: write the new height and delete
        // the previous one, both inside this atomic batch.
        batch.put(
            Table::StateSnapshots,
            be(header.height).to_vec(),
            state_bytes,
        );
        batch.delete(Table::StateSnapshots, be(tip.height).to_vec());
        if let Some(validator_set) = commit.validator_set {
            batch.put(
                Table::ValidatorSets,
                be(header.epoch).to_vec(),
                bincode::serialize(validator_set)?,
            );
        }
        // The tip advances in the same batch, so it is never observable ahead of
        // its block or state.
        batch.put(Table::Meta, META_TIP, bincode::serialize(&new_tip)?);
        self.store.commit(batch)
    }

    /// Returns the current committed tip, or `None` before genesis initialization.
    pub fn tip(&self) -> Result<Option<ChainTip>, StorageError> {
        match self.store.get(Table::Meta, META_TIP)? {
            None => Ok(None),
            Some(bytes) => Ok(Some(decode(&bytes)?)),
        }
    }

    /// Returns the finalized block at `height`, or `None` if absent.
    pub fn block_by_height(&self, height: u64) -> Result<Option<Block>, StorageError> {
        match self.store.get(Table::Blocks, &be(height))? {
            None => Ok(None),
            Some(bytes) => Ok(Some(decode(&bytes)?)),
        }
    }

    /// Returns the finalized block with the given V2 header hash, via the index.
    pub fn block_by_hash(&self, hash: &Hash256) -> Result<Option<Block>, StorageError> {
        let Some(height_bytes) = self.store.get(Table::BlockHashIndex, &hash.0)? else {
            return Ok(None);
        };
        let height = decode_u64(&height_bytes).ok_or_else(|| {
            StorageError::Corruption("block-hash index holds a malformed height".into())
        })?;
        self.block_by_height(height)
    }

    /// Returns just the header at `height` (projected from the stored block).
    pub fn header_by_height(&self, height: u64) -> Result<Option<BlockHeader>, StorageError> {
        Ok(self.block_by_height(height)?.map(|block| block.header))
    }

    /// Returns the state snapshot stored at `height`, or `None`.
    ///
    /// Only the latest snapshot is retained, so this yields state exactly for the
    /// current tip height (and genesis height 0 before any block).
    pub fn state_at_height(&self, height: u64) -> Result<Option<ChainState>, StorageError> {
        match self.store.get(Table::StateSnapshots, &be(height))? {
            None => Ok(None),
            Some(bytes) => Ok(Some(decode(&bytes)?)),
        }
    }

    /// Returns the latest committed chain state, or `None` before initialization.
    pub fn latest_state(&self) -> Result<Option<ChainState>, StorageError> {
        match self.tip()? {
            None => Ok(None),
            Some(tip) => self.state_at_height(tip.height),
        }
    }

    /// Returns the validator-set snapshot recorded for `epoch`, or `None`.
    pub fn validator_set(&self, epoch: u64) -> Result<Option<ValidatorSet>, StorageError> {
        match self.store.get(Table::ValidatorSets, &be(epoch))? {
            None => Ok(None),
            Some(bytes) => Ok(Some(decode(&bytes)?)),
        }
    }

    /// Borrows the underlying backend (for read-only queries the typed layer does
    /// not wrap, and for tests).
    pub fn backend(&self) -> &K {
        &self.store
    }
}

/// Decodes a bincode value, mapping any failure to a corruption error.
fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, StorageError> {
    bincode::deserialize(bytes)
        .map_err(|error| StorageError::Corruption(format!("stored value is malformed: {error}")))
}

/// Decodes a 4-byte big-endian `u32`, or `None` if the length is wrong.
fn decode_u32(bytes: &[u8]) -> Option<u32> {
    bytes.try_into().ok().map(u32::from_be_bytes)
}

/// Decodes an 8-byte big-endian `u64`, or `None` if the length is wrong.
fn decode_u64(bytes: &[u8]) -> Option<u64> {
    bytes.try_into().ok().map(u64::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use webc_chain::{ChainConfig, ChainId, CURRENT_PROTOCOL_VERSION};
    use webc_crypto::Keypair;

    use crate::{MemoryKvStore, RedbKvStore};

    /// A distinct genesis-shaped state per epoch, so successive blocks commit to
    /// different state roots (letting tests observe the latest snapshot change).
    fn state_at_epoch(epoch: u64) -> ChainState {
        let mut state = ChainState::new(&ChainConfig::default()).unwrap();
        state.current_epoch = epoch;
        state
    }

    /// A storage-valid block committing to `state` at `height`, chained to
    /// `previous_hash`. Consensus fields not checked by the store are placeholders.
    fn block_for(state: &ChainState, height: u64, previous_hash: Hash256) -> Block {
        let header = BlockHeader {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            height,
            epoch: state.current_epoch,
            previous_hash,
            state_root: state.state_root().unwrap(),
            account_root: state.account_root().unwrap(),
            tx_root: Hash256([0u8; 32]),
            receipt_root: Hash256([0u8; 32]),
            proposer: Keypair::from_seed([1u8; 32]).address(),
            timestamp_ms: 1_700_000_000_000 + height,
            base_fee_per_unit: 0,
        };
        Block {
            header,
            transactions: Vec::new(),
            receipts: Vec::new(),
            evidence: Vec::new(),
        }
    }

    fn commit(store: &mut ChainStore<impl KvStore>, block: &Block, state: &ChainState) {
        store
            .commit_block(BlockCommit {
                block,
                state,
                validator_set: None,
            })
            .unwrap();
    }

    /// The core lifecycle, run against any backend: genesis, two chained blocks,
    /// tip/state/index reads, and latest-only snapshot retention.
    fn exercise_lifecycle<K: KvStore>(backend: K) {
        let mut store = ChainStore::open(backend).unwrap();
        assert!(store.tip().unwrap().is_none());

        let genesis = state_at_epoch(0);
        store.initialize_genesis(&genesis).unwrap();
        let tip = store.tip().unwrap().unwrap();
        assert_eq!(tip.height, 0);
        assert_eq!(tip.block_hash, None);

        // Block 1 chains off the genesis (no parent hash to match).
        let state1 = state_at_epoch(1);
        let block1 = block_for(&state1, 1, Hash256([0u8; 32]));
        commit(&mut store, &block1, &state1);

        // Block 2 must point at block 1.
        let state2 = state_at_epoch(2);
        let block2 = block_for(&state2, 2, block1.hash().unwrap());
        commit(&mut store, &block2, &state2);

        let tip = store.tip().unwrap().unwrap();
        assert_eq!(tip.height, 2);
        assert_eq!(tip.block_hash, Some(block2.hash().unwrap()));
        assert_eq!(tip.state_root, state2.state_root().unwrap());

        // Blocks are retrievable by height and by hash; headers project cleanly.
        assert_eq!(store.block_by_height(1).unwrap().unwrap(), block1);
        assert_eq!(
            store
                .block_by_hash(&block2.hash().unwrap())
                .unwrap()
                .unwrap(),
            block2
        );
        assert_eq!(
            store.header_by_height(2).unwrap().unwrap(),
            block2.header.clone()
        );

        // Latest state matches block 2; earlier snapshots are pruned.
        assert_eq!(store.latest_state().unwrap().unwrap(), state2);
        assert!(store.state_at_height(0).unwrap().is_none());
        assert!(store.state_at_height(1).unwrap().is_none());
        assert_eq!(store.state_at_height(2).unwrap().unwrap(), state2);
    }

    #[test]
    fn lifecycle_on_memory_backend() {
        exercise_lifecycle(MemoryKvStore::new());
    }

    #[test]
    fn lifecycle_on_redb_backend() {
        let dir = tempfile::tempdir().unwrap();
        let backend = RedbKvStore::open(dir.path().join("chain.redb")).unwrap();
        exercise_lifecycle(backend);
    }

    #[test]
    fn rejects_replayed_and_gapped_heights() {
        let mut store = ChainStore::open(MemoryKvStore::new()).unwrap();
        store.initialize_genesis(&state_at_epoch(0)).unwrap();
        let state1 = state_at_epoch(1);
        let block1 = block_for(&state1, 1, Hash256([0u8; 32]));
        commit(&mut store, &block1, &state1);

        // Re-committing height 1 (a replay) is rejected.
        let err = store
            .commit_block(BlockCommit {
                block: &block1,
                state: &state1,
                validator_set: None,
            })
            .unwrap_err();
        assert!(matches!(err, StorageError::Inconsistent(_)));

        // Skipping to height 3 (a gap) is rejected.
        let state3 = state_at_epoch(3);
        let block3 = block_for(&state3, 3, block1.hash().unwrap());
        let err = store
            .commit_block(BlockCommit {
                block: &block3,
                state: &state3,
                validator_set: None,
            })
            .unwrap_err();
        assert!(matches!(err, StorageError::Inconsistent(_)));

        // The tip never moved off block 1.
        assert_eq!(store.tip().unwrap().unwrap().height, 1);
    }

    #[test]
    fn rejects_broken_parent_linkage() {
        let mut store = ChainStore::open(MemoryKvStore::new()).unwrap();
        store.initialize_genesis(&state_at_epoch(0)).unwrap();
        let state1 = state_at_epoch(1);
        let block1 = block_for(&state1, 1, Hash256([0u8; 32]));
        commit(&mut store, &block1, &state1);

        // Block 2 points at the wrong parent hash.
        let state2 = state_at_epoch(2);
        let bad = block_for(&state2, 2, Hash256([0xff; 32]));
        let err = store
            .commit_block(BlockCommit {
                block: &bad,
                state: &state2,
                validator_set: None,
            })
            .unwrap_err();
        assert!(matches!(err, StorageError::Inconsistent(_)));
    }

    #[test]
    fn rejects_state_root_mismatch() {
        let mut store = ChainStore::open(MemoryKvStore::new()).unwrap();
        store.initialize_genesis(&state_at_epoch(0)).unwrap();
        // Header commits to state epoch 1, but the provided state is epoch 2.
        let header_state = state_at_epoch(1);
        let block1 = block_for(&header_state, 1, Hash256([0u8; 32]));
        let wrong_state = state_at_epoch(2);
        let err = store
            .commit_block(BlockCommit {
                block: &block1,
                state: &wrong_state,
                validator_set: None,
            })
            .unwrap_err();
        assert!(matches!(err, StorageError::Inconsistent(_)));
    }

    #[test]
    fn redb_state_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.redb");
        let block1_hash;
        {
            let mut store = ChainStore::open(RedbKvStore::open(&path).unwrap()).unwrap();
            store.initialize_genesis(&state_at_epoch(0)).unwrap();
            let state1 = state_at_epoch(1);
            let block1 = block_for(&state1, 1, Hash256([0u8; 32]));
            commit(&mut store, &block1, &state1);
            block1_hash = block1.hash().unwrap();
        }
        // Reopen from disk: open() re-verifies tip consistency, and the committed
        // block and latest state are intact — no loss, no duplication.
        let reopened = ChainStore::open(RedbKvStore::open(&path).unwrap()).unwrap();
        let tip = reopened.tip().unwrap().unwrap();
        assert_eq!(tip.height, 1);
        assert_eq!(tip.block_hash, Some(block1_hash));
        assert_eq!(reopened.latest_state().unwrap().unwrap(), state_at_epoch(1));
        assert_eq!(
            reopened
                .block_by_height(1)
                .unwrap()
                .unwrap()
                .hash()
                .unwrap(),
            block1_hash
        );
    }

    #[test]
    fn refuses_unsupported_schema_version() {
        let mut backend = MemoryKvStore::new();
        let mut batch = WriteBatch::new();
        batch.put(
            Table::Meta,
            META_SCHEMA_VERSION.to_vec(),
            999u32.to_be_bytes().to_vec(),
        );
        backend.commit(batch).unwrap();
        let err = ChainStore::open(backend).unwrap_err();
        assert!(matches!(
            err,
            StorageError::UnsupportedSchemaVersion {
                found: 999,
                expected: CHAIN_STORE_SCHEMA_VERSION
            }
        ));
    }

    #[test]
    fn open_detects_tip_without_state() {
        // Stamp a valid schema and a tip that references a height with no stored
        // state snapshot: open() must report the store as inconsistent.
        let mut backend = MemoryKvStore::new();
        let mut batch = WriteBatch::new();
        batch.put(
            Table::Meta,
            META_SCHEMA_VERSION.to_vec(),
            CHAIN_STORE_SCHEMA_VERSION.to_be_bytes().to_vec(),
        );
        let tip = ChainTip {
            height: 5,
            block_hash: Some(Hash256([7u8; 32])),
            state_root: Hash256([9u8; 32]),
        };
        batch.put(
            Table::Meta,
            META_TIP.to_vec(),
            bincode::serialize(&tip).unwrap(),
        );
        backend.commit(batch).unwrap();
        let err = ChainStore::open(backend).unwrap_err();
        assert!(matches!(err, StorageError::Inconsistent(_)));
    }

    #[test]
    fn genesis_initialization_is_idempotent() {
        let mut store = ChainStore::open(MemoryKvStore::new()).unwrap();
        store.initialize_genesis(&state_at_epoch(0)).unwrap();
        // Same genesis again is a safe no-op.
        store.initialize_genesis(&state_at_epoch(0)).unwrap();
        // A different genesis over an initialized chain is refused.
        let err = store.initialize_genesis(&state_at_epoch(1)).unwrap_err();
        assert!(matches!(err, StorageError::Inconsistent(_)));
    }
}
