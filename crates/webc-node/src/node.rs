//! The node runtime: block production bound to durable storage.
//!
//! Purpose: turn the deterministic protocol core (`webc-chain`) and the durable
//! store (`webc-storage`) into a single restartable node. It owns the working
//! chain state, produces blocks from selected transactions using the existing
//! `build_block` logic, and commits each block atomically to storage. This is
//! WEBC's own orchestration glue — it reuses the chain and storage crates rather
//! than reimplementing either.
//!
//! Boundaries: it holds no networking, no mempool, and no API surface (those are
//! separate modules). It performs no consensus voting; a single local proposer
//! drives block production for Phase 3. Wall-clock time is supplied by the caller
//! (`timestamp_ms`), so the state transition itself never reads a clock.
//!
//! Recovery: [`Node::open`] loads the latest committed state from storage, or
//! initializes genesis on a fresh store. Because the store advances its tip in
//! the same atomic batch as each block, reopening always resumes exactly at the
//! last fully-committed block — no lost or duplicated state.
//!
//! Transactionality: a block is produced against a *clone* of the working state;
//! the node adopts the new state only after the storage commit succeeds. A
//! durable-write failure therefore leaves the in-memory state exactly where it
//! was, so memory and disk never disagree.

use webc_chain::{
    apply_block, build_block, Block, BlockBuildInput, ChainConfig, ChainError, ChainState,
    GenesisConfig, SlashingEvidence, Transaction, ValidatorSet,
};
use webc_crypto::{Address, Hash256};
use webc_storage::{BlockCommit, ChainStore, KvStore, StorageError};

/// Errors returned by the node runtime.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// A durable storage operation failed.
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    /// Block construction or a state transition failed (invalid transaction,
    /// overflow, block limit, etc.).
    #[error("chain error: {0}")]
    Chain(#[from] ChainError),
    /// The persisted chain belongs to a different network than the genesis config.
    #[error("stored chain id does not match the genesis configuration")]
    ChainIdMismatch,
}

/// A single-proposer, restartable WEBC node over any storage backend.
#[derive(Debug)]
pub struct Node<K: KvStore> {
    config: ChainConfig,
    store: ChainStore<K>,
    /// Latest committed chain state, kept in memory for fast block production.
    state: ChainState,
}

impl<K: KvStore> Node<K> {
    /// Opens a node over `backend`, recovering the latest committed state or
    /// initializing genesis on a fresh store.
    ///
    /// The chain configuration is taken from `genesis.chain`, the single source of
    /// truth. On an existing store, the persisted state's chain id must match, or
    /// [`NodeError::ChainIdMismatch`] is returned so a node never resumes another
    /// network's data.
    pub fn open(backend: K, genesis: &GenesisConfig) -> Result<Self, NodeError> {
        let config = genesis.chain.clone();
        let mut store = ChainStore::open(backend)?;
        let state = match store.latest_state()? {
            Some(existing) => {
                if existing.chain_id != config.chain_id {
                    return Err(NodeError::ChainIdMismatch);
                }
                existing
            }
            None => {
                let genesis_state = ChainState::from_genesis(genesis)?;
                store.initialize_genesis(&genesis_state)?;
                genesis_state
            }
        };
        Ok(Self {
            config,
            store,
            state,
        })
    }

    /// Height of the most recently committed block (0 = genesis only).
    pub fn height(&self) -> u64 {
        self.store
            .tip()
            .ok()
            .flatten()
            .map(|tip| tip.height)
            .unwrap_or(0)
    }

    /// Hash of the tip block, or `None` at genesis.
    pub fn tip_hash(&self) -> Option<Hash256> {
        self.store
            .tip()
            .ok()
            .flatten()
            .and_then(|tip| tip.block_hash)
    }

    /// Read-only access to the latest committed chain state.
    pub fn state(&self) -> &ChainState {
        &self.state
    }

    /// The active chain configuration (from genesis).
    pub fn config(&self) -> &ChainConfig {
        &self.config
    }

    /// Read-only access to the durable chain store (for queries and proofs).
    pub fn store(&self) -> &ChainStore<K> {
        &self.store
    }

    /// Produces, executes, and durably commits the next block.
    ///
    /// `transactions` are executed in order against a clone of the current state;
    /// if any transaction is invalid the whole call fails and nothing is
    /// committed. `timestamp_ms` is supplied by the caller (consensus/clock),
    /// keeping the state transition itself clock-free. `proposer` records who
    /// built the block. On success the block is committed atomically and becomes
    /// the new tip; the node's in-memory state advances only then.
    pub fn produce_block(
        &mut self,
        transactions: Vec<Transaction>,
        evidence: Vec<SlashingEvidence>,
        proposer: Address,
        timestamp_ms: u64,
    ) -> Result<Block, NodeError> {
        let height = self.height() + 1;
        // A zero parent hash marks the genesis parent for block 1; the store's
        // parent-linkage check only enforces equality once a real parent exists.
        let previous_hash = self.tip_hash().unwrap_or(Hash256([0u8; 32]));
        let epoch = self.state.current_epoch;

        let input = BlockBuildInput {
            chain_id: self.config.chain_id.clone(),
            height,
            epoch,
            previous_hash,
            proposer,
            timestamp_ms,
        };

        // Build against a clone so a failure (or a later storage failure) never
        // corrupts the live state. `build_block` advances `next_state` to the
        // post-block state committed by the header.
        let mut next_state = self.state.clone();
        let block = build_block(&mut next_state, &self.config, input, transactions, evidence)?;

        // Persist the per-epoch validator-set snapshot the first time this epoch
        // is committed. Consensus requires a fixed snapshot per epoch so voting
        // power cannot shift mid-epoch; taking it from the pre-block state at the
        // epoch's first block fixes the active set as the epoch opens. Later
        // blocks in the same epoch reuse it. Until validators activate through
        // staking, the snapshot is an empty (zero-power) set, which is correct.
        let epoch_snapshot = if self.store.validator_set(epoch)?.is_none() {
            Some(ValidatorSet::from_state(&self.state)?)
        } else {
            None
        };

        self.store.commit_block(BlockCommit {
            block: &block,
            state: &next_state,
            validator_set: epoch_snapshot.as_ref(),
        })?;

        // Storage committed durably; only now adopt the new state.
        self.state = next_state;
        Ok(block)
    }

    /// Builds a candidate block for the next height **without committing it**.
    ///
    /// A consensus proposer uses this to produce the block it proposes; the block
    /// is committed later — by every node, including the proposer — through
    /// [`Self::import_block`] once consensus finalizes it. Because it never mutates
    /// the node, a proposal that loses a round leaves no trace. It shares
    /// `produce_block`'s deterministic construction, differing only in that it
    /// stops before the durable commit.
    pub fn build_candidate(
        &self,
        transactions: Vec<Transaction>,
        evidence: Vec<SlashingEvidence>,
        proposer: Address,
        timestamp_ms: u64,
    ) -> Result<Block, NodeError> {
        let height = self.height() + 1;
        let previous_hash = self.tip_hash().unwrap_or(Hash256([0u8; 32]));
        let epoch = self.state.current_epoch;
        let input = BlockBuildInput {
            chain_id: self.config.chain_id.clone(),
            height,
            epoch,
            previous_hash,
            proposer,
            timestamp_ms,
        };
        let mut next_state = self.state.clone();
        let block = build_block(&mut next_state, &self.config, input, transactions, evidence)?;
        Ok(block)
    }

    /// Validates and durably commits a block produced by another node.
    ///
    /// This is the receiving side of networked consensus and the building block
    /// of state sync: the node re-executes the received block's body and requires
    /// it to reproduce the block's header exactly (via [`apply_block`]) before the
    /// durable store — which independently enforces height contiguity, parent
    /// linkage, and `state_root` equality — commits it. A forged or mis-linked
    /// block is rejected with the in-memory and on-disk state left unchanged, so a
    /// hostile peer cannot corrupt a node by gossiping a bad block.
    ///
    /// It performs no consensus checks (proposer schedule, finality); a consensus
    /// driver commits a block here only after it is finalized by a certificate.
    pub fn import_block(&mut self, block: Block) -> Result<(), NodeError> {
        if block.header.chain_id != self.config.chain_id {
            return Err(NodeError::ChainIdMismatch);
        }

        // Re-execute against a clone: a mismatch fails before anything is adopted.
        let mut next_state = self.state.clone();
        apply_block(&mut next_state, &self.config, &block)?;

        // Snapshot the epoch validator set on the epoch's first committed block,
        // matching local production so imported and produced chains agree.
        let epoch = block.header.epoch;
        let epoch_snapshot = if self.store.validator_set(epoch)?.is_none() {
            Some(ValidatorSet::from_state(&self.state)?)
        } else {
            None
        };

        // The store rejects a non-contiguous or mis-linked block, so this both
        // validates placement and commits atomically.
        self.store.commit_block(BlockCommit {
            block: &block,
            state: &next_state,
            validator_set: epoch_snapshot.as_ref(),
        })?;
        self.state = next_state;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webc_chain::{Amount, ChainConfig, FeeBid, GenesisAccount, GenesisConfig, Operation};
    use webc_crypto::Keypair;
    use webc_storage::{MemoryKvStore, RedbKvStore};

    /// Genesis with two funded accounts and no validators (enough to move value
    /// and produce blocks in a Phase 3 single-proposer node).
    fn test_genesis() -> (GenesisConfig, Keypair, Keypair) {
        let alice = Keypair::from_seed([1u8; 32]);
        let bob = Keypair::from_seed([2u8; 32]);
        let genesis = GenesisConfig {
            chain: ChainConfig::default(),
            accounts: vec![
                GenesisAccount {
                    address: alice.address(),
                    balance: Amount::from_webc(1_000),
                },
                GenesisAccount {
                    address: bob.address(),
                    balance: Amount::from_webc(1_000),
                },
            ],
            validators: Vec::new(),
        };
        (genesis, alice, bob)
    }

    /// Builds and signs a whole-WEBC transfer with the standard access list.
    fn transfer(from: &Keypair, to: &Keypair, whole: u64, nonce: u64) -> Transaction {
        Transaction::for_operation(
            from,
            nonce,
            Operation::Transfer {
                to: to.address(),
                amount: Amount::from_webc(whole),
            },
            FeeBid {
                gas_limit: 1_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap()
    }

    #[test]
    fn produces_and_commits_blocks() {
        let (genesis, alice, bob) = test_genesis();
        let mut node = Node::open(MemoryKvStore::new(), &genesis).unwrap();
        assert_eq!(node.height(), 0);

        let tx = transfer(&alice, &bob, 10, 0);
        let block = node
            .produce_block(vec![tx], Vec::new(), alice.address(), 1_700_000_000_000)
            .unwrap();
        assert_eq!(block.header.height, 1);
        assert_eq!(node.height(), 1);
        assert_eq!(node.tip_hash(), Some(block.hash().unwrap()));

        // Bob received the transfer.
        let bob_balance = node.state().accounts.get(&bob.address()).unwrap().balance;
        assert_eq!(bob_balance, Amount::from_webc(1_010));
    }

    #[test]
    fn writes_the_epoch_validator_set_snapshot_once() {
        let (genesis, alice, bob) = test_genesis();
        let mut node = Node::open(MemoryKvStore::new(), &genesis).unwrap();

        // No snapshot exists before the first block of epoch 0.
        assert!(node.store().validator_set(0).unwrap().is_none());

        node.produce_block(
            vec![transfer(&alice, &bob, 10, 0)],
            Vec::new(),
            alice.address(),
            1_700_000_000_000,
        )
        .unwrap();

        // The writer fired: epoch 0 now has a persisted snapshot. This devnet
        // genesis has no active validators, so the set is empty but present,
        // proving the previously-unpopulated path is now live.
        let snapshot = node
            .store()
            .validator_set(0)
            .unwrap()
            .expect("epoch 0 snapshot persisted");
        assert!(snapshot.validators.is_empty());
        assert_eq!(snapshot.total_power, Amount::ZERO);

        // A second block in the same epoch does not fail or duplicate the write.
        node.produce_block(
            vec![transfer(&alice, &bob, 5, 1)],
            Vec::new(),
            alice.address(),
            1_700_000_000_001,
        )
        .unwrap();
        assert!(node.store().validator_set(0).unwrap().is_some());
    }

    #[test]
    fn recovers_latest_state_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.redb");
        let (genesis, alice, bob) = test_genesis();

        let tip_after_two;
        {
            let mut node = Node::open(RedbKvStore::open(&path).unwrap(), &genesis).unwrap();
            node.produce_block(
                vec![transfer(&alice, &bob, 10, 0)],
                Vec::new(),
                alice.address(),
                1_700_000_000_001,
            )
            .unwrap();
            node.produce_block(
                vec![transfer(&alice, &bob, 5, 1)],
                Vec::new(),
                alice.address(),
                1_700_000_000_002,
            )
            .unwrap();
            tip_after_two = node.tip_hash();
            assert_eq!(node.height(), 2);
        }

        // Reopen from disk: the node resumes at height 2 with the same tip and
        // the accumulated balance, proving no loss or duplication.
        let mut node = Node::open(RedbKvStore::open(&path).unwrap(), &genesis).unwrap();
        assert_eq!(node.height(), 2);
        assert_eq!(node.tip_hash(), tip_after_two);
        let bob_balance = node.state().accounts.get(&bob.address()).unwrap().balance;
        assert_eq!(bob_balance, Amount::from_webc(1_015));

        // And it can keep producing from the recovered tip.
        let block3 = node
            .produce_block(
                vec![transfer(&alice, &bob, 1, 2)],
                Vec::new(),
                alice.address(),
                1_700_000_000_003,
            )
            .unwrap();
        assert_eq!(block3.header.height, 3);
        assert_eq!(block3.header.previous_hash, tip_after_two.unwrap());
    }

    #[test]
    fn imports_a_block_produced_by_another_node() {
        let (genesis, alice, bob) = test_genesis();
        let mut producer = Node::open(MemoryKvStore::new(), &genesis).unwrap();
        let mut follower = Node::open(MemoryKvStore::new(), &genesis).unwrap();

        // Producer builds two blocks; the follower imports each in order and ends
        // at the identical tip and balances without rebuilding from a mempool.
        let b1 = producer
            .produce_block(
                vec![transfer(&alice, &bob, 10, 0)],
                Vec::new(),
                alice.address(),
                1_700_000_000_001,
            )
            .unwrap();
        follower.import_block(b1.clone()).unwrap();
        assert_eq!(follower.height(), 1);
        assert_eq!(follower.tip_hash(), producer.tip_hash());

        let b2 = producer
            .produce_block(
                vec![transfer(&alice, &bob, 5, 1)],
                Vec::new(),
                alice.address(),
                1_700_000_000_002,
            )
            .unwrap();
        follower.import_block(b2).unwrap();
        assert_eq!(follower.height(), 2);
        assert_eq!(follower.tip_hash(), producer.tip_hash());
        assert_eq!(
            follower
                .state()
                .accounts
                .get(&bob.address())
                .unwrap()
                .balance,
            producer
                .state()
                .accounts
                .get(&bob.address())
                .unwrap()
                .balance
        );
        // The follower also persisted the epoch-0 snapshot on its first import.
        assert!(follower.store().validator_set(0).unwrap().is_some());
    }

    #[test]
    fn build_candidate_does_not_commit_but_imports_cleanly() {
        let (genesis, alice, bob) = test_genesis();
        let mut proposer = Node::open(MemoryKvStore::new(), &genesis).unwrap();
        let mut follower = Node::open(MemoryKvStore::new(), &genesis).unwrap();

        let block = proposer
            .build_candidate(
                vec![transfer(&alice, &bob, 7, 0)],
                Vec::new(),
                alice.address(),
                1_700_000_000_000,
            )
            .unwrap();
        // Building a candidate leaves the proposer's committed height unchanged.
        assert_eq!(proposer.height(), 0);

        // The candidate is a valid block: both nodes import it to the same tip.
        proposer.import_block(block.clone()).unwrap();
        follower.import_block(block).unwrap();
        assert_eq!(proposer.height(), 1);
        assert_eq!(proposer.tip_hash(), follower.tip_hash());
    }

    #[test]
    fn rejects_a_tampered_imported_block() {
        let (genesis, alice, bob) = test_genesis();
        let mut producer = Node::open(MemoryKvStore::new(), &genesis).unwrap();
        let mut follower = Node::open(MemoryKvStore::new(), &genesis).unwrap();

        let mut block = producer
            .produce_block(
                vec![transfer(&alice, &bob, 10, 0)],
                Vec::new(),
                alice.address(),
                1_700_000_000_001,
            )
            .unwrap();
        // Forge the committed state root: re-execution will not reproduce it.
        block.header.state_root = Hash256([0xAB; 32]);

        assert!(matches!(
            follower.import_block(block),
            Err(NodeError::Chain(ChainError::ImportedBlockMismatch))
        ));
        // The follower did not advance.
        assert_eq!(follower.height(), 0);
    }

    #[test]
    fn rejects_a_non_contiguous_imported_block() {
        let (genesis, alice, bob) = test_genesis();
        let mut producer = Node::open(MemoryKvStore::new(), &genesis).unwrap();
        let mut follower = Node::open(MemoryKvStore::new(), &genesis).unwrap();

        producer
            .produce_block(
                vec![transfer(&alice, &bob, 10, 0)],
                Vec::new(),
                alice.address(),
                1_700_000_000_001,
            )
            .unwrap();
        // Height-2 block imported before height 1: the store rejects the gap.
        let b2 = producer
            .produce_block(
                vec![transfer(&alice, &bob, 5, 1)],
                Vec::new(),
                alice.address(),
                1_700_000_000_002,
            )
            .unwrap();
        assert!(follower.import_block(b2).is_err());
        assert_eq!(follower.height(), 0);
    }

    #[test]
    fn invalid_transaction_does_not_mutate_state_or_advance_tip() {
        let (genesis, alice, bob) = test_genesis();
        let mut node = Node::open(MemoryKvStore::new(), &genesis).unwrap();

        // Wrong nonce (1 instead of 0) makes block production fail wholesale.
        let bad = transfer(&alice, &bob, 10, 1);
        let err = node
            .produce_block(vec![bad], Vec::new(), alice.address(), 1_700_000_000_000)
            .unwrap_err();
        assert!(matches!(err, NodeError::Chain(_)));

        // Neither the tip nor balances moved.
        assert_eq!(node.height(), 0);
        let alice_balance = node.state().accounts.get(&alice.address()).unwrap().balance;
        assert_eq!(alice_balance, Amount::from_webc(1_000));
    }

    #[test]
    fn rejects_reopen_with_mismatched_chain_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.redb");
        let (genesis, _alice, _bob) = test_genesis();
        {
            let _node = Node::open(RedbKvStore::open(&path).unwrap(), &genesis).unwrap();
        }
        // Reopen with a different chain id over the same store: refused.
        let mut other = test_genesis().0;
        other.chain.chain_id = webc_chain::ChainId::new("webc-other").unwrap();
        let err = Node::open(RedbKvStore::open(&path).unwrap(), &other).unwrap_err();
        assert!(matches!(err, NodeError::ChainIdMismatch));
    }
}
