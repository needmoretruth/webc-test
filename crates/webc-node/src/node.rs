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
//! separate modules). It performs no consensus voting. Legacy local production
//! remains isolated from protocol-2 V4 candidate/replay/finality methods.
//! Wall-clock time is supplied by the caller (`timestamp_ms`), so deterministic
//! state transitions never read a clock.
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

use std::collections::BTreeSet;
use std::io::{self, Write};

use webc_chain::{
    apply_block, build_block, build_block_v4_with_derived_authority_transition,
    replay_block_v4_transition, Block, BlockBuildInput, BlockBuildInputV1, BlockHeight, BlockV4,
    BlockV4ExecutionError, BuiltBlockV4, ChainConfig, ChainError, ChainState, ConsensusWalRecord,
    ConsensusWalRecordV1, Epoch, FinalityAuthoritySetErrorV1, FinalityAuthoritySetV1,
    FinalityCertificate, GenesisConfig, SlashingEvidence, Transaction, TransactionId,
    TransactionV5, TransactionValidationErrorV1, ValidatorSet, CURRENT_PROTOCOL_VERSION,
    TRANSACTION_V5_PROTOCOL_VERSION,
};
use webc_crypto::{Address, Hash256};
use webc_proof::{
    build_indexed_merkle_proof, validate_checkpoint_v1, verify_finalized_transaction_proof_v1,
    AuthoritySetTransitionV1, CheckpointErrorV1, CheckpointRequirementsV1, CheckpointV1,
    FinalizedTransactionProofErrorV1, FinalizedTransactionProofRequirementsV1,
    FinalizedTransactionProofV1, AUTHORITY_SET_TRANSITION_V1, CHECKPOINT_V1,
    FINALIZED_TRANSACTION_PROOF_V1, MAX_AUTHORITY_TRANSITIONS_V1,
    MAX_FINALIZED_TRANSACTION_PROOF_V1_JSON_BYTES,
};
use webc_storage::{BlockCommit, BlockV4Commit, ChainStore, KvStore, PendingSlotV1, StorageError};

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
    /// A legacy block-format method was called on a protocol-2 node.
    #[error("legacy block API is inactive under protocol 2")]
    LegacyBlockApiInactive,
    /// A protocol-2-only method was called on a legacy node.
    #[error("protocol-2 block API is inactive under the legacy protocol")]
    ProtocolTwoBlockApiInactive,
    /// Protocol-2 whole-block execution or replay failed atomically.
    #[error("protocol-2 block execution error: {0}")]
    BlockV4(#[source] Box<BlockV4ExecutionError>),
    /// A supposedly validated V5 transaction could not reproduce its identity.
    #[error("protocol-2 transaction identity is invalid: {0}")]
    TransactionV5(#[from] TransactionValidationErrorV1),
    /// A persisted or genesis-derived protocol-2 authority snapshot is invalid.
    #[error("protocol-2 authority set is invalid: {0}")]
    Authority(#[from] FinalityAuthoritySetErrorV1),
    /// A stored or assembled transparent proof failed pure verification.
    #[error("protocol-2 finalized proof is invalid: {0}")]
    FinalizedProof(#[from] FinalizedTransactionProofErrorV1),
    /// A checkpoint candidate or authority transition failed pure verification.
    #[error("protocol-2 checkpoint proof is invalid: {0}")]
    CheckpointProof(#[from] CheckpointErrorV1),
    /// A requested checkpoint or its certified history is unavailable locally.
    #[error("protocol-2 finalized proof data is unavailable: {0}")]
    ProofDataUnavailable(&'static str),
    /// Retaining or assembling the requested proof would exceed its fixed budget.
    #[error("protocol-2 finalized proof material exceeds the {maximum_bytes}-byte limit")]
    FinalizedProofMaterialTooLarge {
        /// Maximum projected JSON bytes accepted for one proof snapshot.
        maximum_bytes: usize,
    },
    /// A requested checkpoint/target relationship cannot form a proof.
    #[error("protocol-2 finalized proof request is invalid: {0}")]
    InvalidProofRequest(&'static str),
}

impl From<BlockV4ExecutionError> for NodeError {
    fn from(error: BlockV4ExecutionError) -> Self {
        Self::BlockV4(Box::new(error))
    }
}

/// Durable effects the single-owner runtime must mirror after V4 finalization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V4FinalizationResult {
    /// Finalized block height.
    pub height: BlockHeight,
    /// Finalized V5 identities in exact block order.
    pub finalized_transaction_ids: Vec<TransactionId>,
    /// Pending identities deleted atomically, including finalized IDs and local
    /// competitors that occupied a finalized `(sender, lane, nonce)` slot.
    pub removed_pending_ids: Vec<TransactionId>,
}

/// Node-served proof plus an explicitly untrusted checkpoint candidate.
///
/// The proof is valid relative to `checkpoint_candidate`, but serving both does
/// not make the checkpoint trusted. A browser must validate the candidate under
/// its configured multi-source or explicit-operator policy before relying on
/// the proof.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedTransactionProofBundleV1 {
    /// Candidate anchor to corroborate independently before proof verification.
    pub checkpoint_candidate: CheckpointV1,
    /// Finalized transaction proof relative to that candidate.
    pub proof: FinalizedTransactionProofV1,
}

/// Maximum projected JSON bytes retained or assembled for one finalized proof.
///
/// This matches the public proof envelope. The actor checks the same budget
/// while loading, before cloning or pushing the next durable record, so a proof
/// that cannot fit the envelope never accumulates a many-record snapshot.
pub(crate) const MAX_FINALIZED_PROOF_MATERIAL_BYTES_V1: usize =
    MAX_FINALIZED_TRANSACTION_PROOF_V1_JSON_BYTES;

/// Minimal transition material retained by the actor before worker assembly.
///
/// Adjacent transitions share an authority set. Retaining only each incoming set
/// once avoids keeping the previous transition's incoming set again as the next
/// transition's outgoing set; the bounded worker creates the wire-owned copies.
struct AuthoritySetTransitionMaterialV1 {
    header: webc_chain::BlockHeaderV4,
    certificate: FinalityCertificate,
    incoming_authority_set: FinalityAuthoritySetV1,
}

/// Fail-closed cumulative projection for one proof snapshot and final envelope.
struct FinalizedProofMaterialBudgetV1 {
    used_bytes: usize,
    maximum_bytes: usize,
}

impl FinalizedProofMaterialBudgetV1 {
    fn new(maximum_bytes: usize) -> Self {
        Self {
            used_bytes: 0,
            maximum_bytes,
        }
    }

    fn measure<T: serde::Serialize + ?Sized>(&self, value: &T) -> Result<usize, NodeError> {
        let mut writer = BoundedCountingWriterV1::new(self.maximum_bytes);
        match serde_json::to_writer(&mut writer, value) {
            Ok(()) => Ok(writer.written_bytes),
            Err(_) if writer.limit_exceeded => Err(self.too_large()),
            Err(_) => Err(NodeError::ProofDataUnavailable(
                "finalized proof material cannot be sized",
            )),
        }
    }

    fn charge<T: serde::Serialize + ?Sized>(&mut self, value: &T) -> Result<usize, NodeError> {
        let bytes = self.measure(value)?;
        self.charge_bytes(bytes)?;
        Ok(bytes)
    }

    fn charge_bytes(&mut self, bytes: usize) -> Result<(), NodeError> {
        let Some(next) = self.used_bytes.checked_add(bytes) else {
            return Err(self.too_large());
        };
        if next > self.maximum_bytes {
            return Err(self.too_large());
        }
        self.used_bytes = next;
        Ok(())
    }

    fn too_large(&self) -> NodeError {
        NodeError::FinalizedProofMaterialTooLarge {
            maximum_bytes: self.maximum_bytes,
        }
    }
}

/// Non-allocating JSON byte counter that aborts as soon as its limit is crossed.
struct BoundedCountingWriterV1 {
    written_bytes: usize,
    maximum_bytes: usize,
    limit_exceeded: bool,
}

impl BoundedCountingWriterV1 {
    fn new(maximum_bytes: usize) -> Self {
        Self {
            written_bytes: 0,
            maximum_bytes,
            limit_exceeded: false,
        }
    }
}

impl Write for BoundedCountingWriterV1 {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self.written_bytes.checked_add(bytes.len()) else {
            self.limit_exceeded = true;
            return Err(io::Error::other("proof material byte count overflowed"));
        };
        if next > self.maximum_bytes {
            self.limit_exceeded = true;
            return Err(io::Error::other("proof material byte limit exceeded"));
        }
        self.written_bytes = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Owned, bounded storage snapshot awaiting CPU-heavy proof construction.
///
/// The single-owner runtime loads this snapshot in command order, then may move
/// it to a bounded blocking worker. No storage handle or mutable node state
/// crosses that boundary. [`Self::assemble`] validates the checkpoint and every
/// commitment before it can return a public proof bundle.
pub(crate) struct FinalizedTransactionProofMaterialV1 {
    /// Replay-protection domain copied from immutable node configuration.
    chain_id: webc_chain::ChainId,
    /// Consensus blocks per epoch used to verify transition boundaries.
    blocks_per_epoch: u64,
    /// Exact finalized transaction identity requested by the caller.
    transaction_id: TransactionId,
    /// Certified non-zero anchor height requested by the caller.
    checkpoint_height: BlockHeight,
    /// Candidate anchor that still requires caller-selected source trust.
    checkpoint_candidate: CheckpointV1,
    /// Bounded decoded block containing the requested transaction and receipt.
    target_block: BlockV4,
    /// Durable zero-based position of the requested transaction in the block.
    transaction_index: usize,
    /// Certificate authenticating a distinct target; `None` reuses checkpoint finality.
    target_certificate: Option<FinalityCertificate>,
    /// Ordered unique incoming-set material between checkpoint and target.
    authority_transitions: Vec<AuthoritySetTransitionMaterialV1>,
}

impl FinalizedTransactionProofMaterialV1 {
    /// Constructs and self-verifies the complete proof without touching storage.
    pub(crate) fn assemble(self) -> Result<FinalizedTransactionProofBundleV1, NodeError> {
        let checkpoint = validate_checkpoint_v1(
            self.checkpoint_candidate.clone(),
            &CheckpointRequirementsV1::new(
                self.chain_id.clone(),
                self.checkpoint_height,
                self.checkpoint_candidate.header.epoch,
            ),
        )?;
        if self.target_block.transactions.len() != self.target_block.receipts.len() {
            return Err(NodeError::ProofDataUnavailable(
                "target transaction and receipt counts disagree",
            ));
        }
        let index = self.transaction_index;
        let transaction = self
            .target_block
            .transactions
            .get(index)
            .ok_or(NodeError::ProofDataUnavailable(
                "finalized transaction index is outside its block",
            ))?
            .clone();
        if transaction.transaction_id()? != self.transaction_id {
            return Err(NodeError::ProofDataUnavailable(
                "finalized transaction index identifies another transaction",
            ));
        }
        let receipt = self
            .target_block
            .receipts
            .get(index)
            .ok_or(NodeError::ProofDataUnavailable(
                "finalized receipt index is outside its block",
            ))?
            .clone();

        let transaction_leaves = self
            .target_block
            .transactions
            .iter()
            .enumerate()
            .map(|(position, transaction)| {
                let position = u32::try_from(position)
                    .map(webc_chain::TransactionIndex::new)
                    .map_err(|_| {
                        NodeError::ProofDataUnavailable(
                            "target transaction position exceeds the V1 index",
                        )
                    })?;
                let transaction_id = transaction.transaction_id()?;
                webc_chain::transaction_leaf_v1(
                    webc_chain::BlockPositionV1::new(self.target_block.header.height, position),
                    transaction_id,
                )
                .map_err(|_| NodeError::ProofDataUnavailable("transaction leaf is invalid"))
            })
            .collect::<Result<Vec<_>, NodeError>>()?;
        let receipt_leaves = self
            .target_block
            .receipts
            .iter()
            .map(|receipt| {
                receipt
                    .leaf()
                    .map_err(|_| NodeError::ProofDataUnavailable("receipt leaf is invalid"))
            })
            .collect::<Result<Vec<_>, NodeError>>()?;
        let transaction_proof = build_indexed_merkle_proof(&transaction_leaves, index)
            .map_err(|_| NodeError::ProofDataUnavailable("transaction path cannot be built"))?;
        let receipt_proof = build_indexed_merkle_proof(&receipt_leaves, index)
            .map_err(|_| NodeError::ProofDataUnavailable("receipt path cannot be built"))?;

        let target_certificate = self
            .target_certificate
            .unwrap_or_else(|| self.checkpoint_candidate.certificate.clone());
        let mut outgoing_authority_set = self.checkpoint_candidate.authority_set.clone();
        let mut authority_transitions = Vec::with_capacity(self.authority_transitions.len());
        for transition in self.authority_transitions {
            // The public proof owns both sides of every boundary. Keep the next
            // outgoing copy only inside this bounded worker; the actor snapshot
            // retained each incoming authority set exactly once.
            let next_outgoing_authority_set = transition.incoming_authority_set.clone();
            authority_transitions.push(AuthoritySetTransitionV1 {
                version: AUTHORITY_SET_TRANSITION_V1,
                header: transition.header,
                certificate: transition.certificate,
                outgoing_authority_set,
                incoming_authority_set: transition.incoming_authority_set,
            });
            outgoing_authority_set = next_outgoing_authority_set;
        }

        let proof = FinalizedTransactionProofV1 {
            version: FINALIZED_TRANSACTION_PROOF_V1,
            authority_transitions,
            target_header: self.target_block.header,
            target_certificate,
            target_authority_set: outgoing_authority_set,
            transaction,
            receipt,
            transaction_proof,
            receipt_proof,
        };
        verify_finalized_transaction_proof_v1(
            &proof,
            &checkpoint,
            &FinalizedTransactionProofRequirementsV1::new(
                self.chain_id,
                self.transaction_id,
                self.blocks_per_epoch,
            ),
        )?;
        Ok(FinalizedTransactionProofBundleV1 {
            checkpoint_candidate: self.checkpoint_candidate,
            proof,
        })
    }
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
        // ST1: bind the store to this chain id at the storage layer, so a store
        // from another network is rejected before any state is read.
        let mut store = ChainStore::open(backend, &config.chain_id)?;
        let state = match store.latest_state()? {
            Some(existing) => {
                if existing.chain_id != config.chain_id {
                    return Err(NodeError::ChainIdMismatch);
                }
                existing
            }
            None => {
                let genesis_state = if config.protocol_version == TRANSACTION_V5_PROTOCOL_VERSION {
                    ChainState::from_genesis_v1(genesis)?
                } else {
                    ChainState::from_genesis(genesis)?
                };
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

    /// Mutable storage access for crate-internal single-owner orchestration.
    ///
    /// This is deliberately not public outside `webc-node`: the protocol-2
    /// runtime must persist a pending transition before updating its in-memory
    /// index, while API and networking callers may only reach that path through
    /// the bounded actor handle.
    pub(crate) fn store_mut(&mut self) -> &mut ChainStore<K> {
        &mut self.store
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
        self.ensure_legacy_block_api()?;
        let height = self.height() + 1;
        // A zero parent hash marks the genesis parent for block 1; the store's
        // parent-linkage check only enforces equality once a real parent exists.
        let previous_hash = self.tip_hash().unwrap_or(Hash256([0u8; 32]));
        let epoch = self.state.current_epoch;
        let timestamp_ms = self.monotonic_timestamp(timestamp_ms);

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
            certificate: None,
        })?;

        // Storage committed durably; only now adopt the new state.
        self.state = next_state;
        Ok(block)
    }

    /// Durably journals this node's own consensus votes, proposals, and lock
    /// state for the in-progress height (the C4 write-ahead journal).
    ///
    /// The consensus driver calls this **before** broadcasting each message the
    /// local machine signed; only after `Ok` may the message reach the wire.
    /// The journal is pruned atomically when its height commits.
    pub fn persist_consensus_wal(&mut self, record: &ConsensusWalRecord) -> Result<(), NodeError> {
        Ok(self.store.put_consensus_wal(record)?)
    }

    /// Returns the journaled consensus record for `height`, or `None` when this
    /// node signed nothing at that height (or the height already committed).
    pub fn consensus_wal(&self, height: u64) -> Result<Option<ConsensusWalRecord>, NodeError> {
        Ok(self.store.consensus_wal(height)?)
    }

    /// Durably journals protocol-2 V4 proposals, votes, and lock state.
    ///
    /// This uses a disjoint storage record from the frozen legacy WAL and must
    /// complete before any newly signed V4 consensus message is broadcast.
    pub fn persist_consensus_wal_v1(
        &mut self,
        record: &ConsensusWalRecordV1,
    ) -> Result<(), NodeError> {
        self.ensure_protocol_two_block_api()?;
        Ok(self.store.put_consensus_wal_v1(record)?)
    }

    /// Returns the protocol-2 crash journal for an unfinished height.
    pub fn consensus_wal_v1(&self, height: u64) -> Result<Option<ConsensusWalRecordV1>, NodeError> {
        self.ensure_protocol_two_block_api()?;
        Ok(self.store.consensus_wal_v1(height)?)
    }

    /// Returns a finalized block together with its stored finality certificate,
    /// or `None` if either is absent. State-sync serving uses this to hand a
    /// certified block to a catching-up peer.
    pub fn certified_block(
        &self,
        height: u64,
    ) -> Result<Option<(Block, FinalityCertificate)>, NodeError> {
        self.ensure_legacy_block_api()?;
        let Some(block) = self.store.block_by_height(height)? else {
            return Ok(None);
        };
        let Some(certificate) = self.store.certificate(height)? else {
            return Ok(None);
        };
        Ok(Some((block, certificate)))
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
        self.ensure_legacy_block_api()?;
        let height = self.height() + 1;
        let previous_hash = self.tip_hash().unwrap_or(Hash256([0u8; 32]));
        let epoch = self.state.current_epoch;
        let timestamp_ms = self.monotonic_timestamp(timestamp_ms);
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

    /// Clamps a supplied wall-clock timestamp so the produced block is strictly
    /// newer than its parent (E2).
    ///
    /// A proposer's clock may lag the chain, or two blocks may fall in the same
    /// millisecond; `build_block` requires a strictly increasing `timestamp_ms`,
    /// so honest production must never emit a stale one. Consensus time therefore
    /// advances by at least one millisecond per block even under a frozen clock.
    fn monotonic_timestamp(&self, supplied_ms: u64) -> u64 {
        supplied_ms.max(self.state.last_block_timestamp_ms.saturating_add(1))
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
        self.import_validated(block, None)
    }

    /// Like [`Self::import_block`], but also persists the block's finality
    /// certificate under its height, so this node can later serve the certified
    /// block to a peer during state sync. The consensus driver uses this on commit.
    pub fn import_finalized_block(
        &mut self,
        block: Block,
        certificate: &FinalityCertificate,
    ) -> Result<(), NodeError> {
        self.import_validated(block, Some(certificate))
    }

    /// Shared import path: re-execute, snapshot the epoch validator set on the
    /// epoch's first block, and atomically commit (optionally with a certificate).
    fn import_validated(
        &mut self,
        block: Block,
        certificate: Option<&FinalityCertificate>,
    ) -> Result<(), NodeError> {
        self.ensure_legacy_block_api()?;
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
            certificate,
        })?;
        self.state = next_state;
        Ok(())
    }

    /// Returns the immutable authority snapshot certifying the next V4 block.
    ///
    /// Once any protocol-2 block has committed, the set must exist in storage
    /// under the current epoch. Genesis is the sole exception: its initial set is
    /// derived from genesis stake and is persisted by the first certified block.
    pub fn current_finality_authority_set_v1(&self) -> Result<FinalityAuthoritySetV1, NodeError> {
        self.ensure_protocol_two_block_api()?;
        let epoch = Epoch::new(self.state.current_epoch);
        if let Some(stored) = self.store.finality_authority_set_v1(epoch)? {
            return Ok(stored);
        }
        let tip = self.store.tip()?.ok_or_else(|| {
            StorageError::Inconsistent("chain store has no initialized genesis tip".into())
        })?;
        if tip.height != 0 {
            return Err(StorageError::Inconsistent(format!(
                "protocol-2 authority set for committed epoch {} is missing",
                epoch.get()
            ))
            .into());
        }
        Ok(FinalityAuthoritySetV1::from_validator_set(
            TRANSACTION_V5_PROTOCOL_VERSION,
            self.config.chain_id.clone(),
            epoch,
            &ValidatorSet::from_state(&self.state)?,
        )?)
    }

    /// Builds the next protocol-2 candidate without changing live state or disk.
    ///
    /// Height, parent hash, epoch, and the current authority set come from the
    /// single committed node view. The supplied timestamp is monotonically
    /// clamped for honest local production; a received block is never clamped.
    pub fn build_candidate_v4(
        &self,
        transactions: Vec<TransactionV5>,
        evidence: Vec<SlashingEvidence>,
        proposer: Address,
        timestamp_ms: u64,
    ) -> Result<BuiltBlockV4, NodeError> {
        self.ensure_protocol_two_block_api()?;
        let tip = self.store.tip()?.ok_or_else(|| {
            StorageError::Inconsistent("chain store has no initialized genesis tip".into())
        })?;
        let height = tip
            .height
            .checked_add(1)
            .map(BlockHeight::new)
            .ok_or_else(|| StorageError::Inconsistent("chain height is exhausted".into()))?;
        let current_authority_set = self.current_finality_authority_set_v1()?;
        let input = BlockBuildInputV1 {
            chain_id: self.config.chain_id.clone(),
            height,
            epoch: Epoch::new(self.state.current_epoch),
            previous_hash: tip.block_hash.unwrap_or(Hash256::ZERO),
            proposer,
            timestamp_ms: self.monotonic_timestamp(timestamp_ms),
        };
        Ok(build_block_v4_with_derived_authority_transition(
            &self.state,
            &self.config,
            input,
            transactions,
            evidence,
            &current_authority_set,
        )?
        .built)
    }

    /// Replays one received V4 proposal against committed state without mutation.
    ///
    /// Consensus authentication runs before this call. This is the expensive
    /// `valid(v)` gate: success proves the exact block and transported successor
    /// set reproduce locally, while every failure leaves memory and disk intact.
    pub fn validate_candidate_v4(
        &self,
        block: &BlockV4,
        next_authority_set: &FinalityAuthoritySetV1,
    ) -> Result<(), NodeError> {
        self.ensure_protocol_two_block_api()?;
        if block.header.chain_id != self.config.chain_id {
            return Err(NodeError::ChainIdMismatch);
        }
        let current_authority_set = self.current_finality_authority_set_v1()?;
        let _validated_post_state = replay_block_v4_transition(
            &self.state,
            &self.config,
            block,
            &current_authority_set,
            next_authority_set,
        )?;
        Ok(())
    }

    /// Returns one stored certified V4 block with its committed successor set.
    ///
    /// The set is resolved by commitment rather than guessed from epoch alone;
    /// an ordinary block reuses the current epoch, while a boundary block names
    /// the single next epoch. Missing or inconsistent records fail closed.
    pub fn certified_block_v4(
        &self,
        height: BlockHeight,
    ) -> Result<Option<(BlockV4, FinalityAuthoritySetV1, FinalityCertificate)>, NodeError> {
        self.ensure_protocol_two_block_api()?;
        let Some(block) = self.store.block_v4_by_height(height)? else {
            return Ok(None);
        };
        let Some(certificate) = self.store.certificate(height.get())? else {
            return Ok(None);
        };
        let current = self
            .store
            .finality_authority_set_v1(block.header.epoch)?
            .ok_or_else(|| {
                StorageError::Inconsistent(
                    "stored V4 block has no current authority snapshot".into(),
                )
            })?;
        let next = if current.commitment()? == block.header.next_finality_authority_set_root {
            current
        } else {
            let next_epoch = block.header.epoch.checked_next().ok_or_else(|| {
                StorageError::Inconsistent("stored V4 authority epoch is exhausted".into())
            })?;
            self.store
                .finality_authority_set_v1(next_epoch)?
                .ok_or_else(|| {
                    StorageError::Inconsistent(
                        "stored V4 block has no successor authority snapshot".into(),
                    )
                })?
        };
        if next.commitment()? != block.header.next_finality_authority_set_root {
            return Err(StorageError::Inconsistent(
                "stored V4 successor authority commitment does not match its header".into(),
            )
            .into());
        }
        Ok(Some((block, next, certificate)))
    }

    /// Builds and self-verifies a checkpoint-relative finalized transaction proof.
    ///
    /// The requested transaction must already have an authoritative finalized
    /// position. `checkpoint_height` names a stored certified V4 block at or
    /// before that position. Only epoch-boundary blocks between the checkpoint
    /// and target are loaded as transitions; no per-height history scan or
    /// precomputed path table is needed. Returning `None` means the transaction
    /// is not finalized. Missing/corrupt checkpoint history fails closed.
    pub fn finalized_transaction_proof_v1(
        &self,
        transaction_id: TransactionId,
        checkpoint_height: BlockHeight,
    ) -> Result<Option<FinalizedTransactionProofBundleV1>, NodeError> {
        self.load_finalized_transaction_proof_v1(transaction_id, checkpoint_height)?
            .map(FinalizedTransactionProofMaterialV1::assemble)
            .transpose()
    }

    /// Loads one actor-consistent, bounded proof snapshot without heavy hashing.
    ///
    /// Storage decoding, height/index lookup, and bounded epoch-history reads
    /// happen while the node owner is ordered with finality. Signature checks,
    /// transaction/receipt hashing, Merkle construction, and self-verification
    /// are deferred to [`FinalizedTransactionProofMaterialV1::assemble`], which
    /// owns everything it needs and cannot observe later node mutations.
    pub(crate) fn load_finalized_transaction_proof_v1(
        &self,
        transaction_id: TransactionId,
        checkpoint_height: BlockHeight,
    ) -> Result<Option<FinalizedTransactionProofMaterialV1>, NodeError> {
        self.load_finalized_transaction_proof_with_budget_v1(
            transaction_id,
            checkpoint_height,
            MAX_FINALIZED_PROOF_MATERIAL_BYTES_V1,
        )
    }

    /// Loads proof material under an explicit cumulative byte budget.
    ///
    /// This seam is used by the runtime's fixed production limit and focused
    /// tests with a tiny limit. Each durable value is measured without allocating
    /// serialized bytes, and the budget is charged before that value is cloned or
    /// pushed into the owned worker snapshot.
    pub(crate) fn load_finalized_transaction_proof_with_budget_v1(
        &self,
        transaction_id: TransactionId,
        checkpoint_height: BlockHeight,
        maximum_material_bytes: usize,
    ) -> Result<Option<FinalizedTransactionProofMaterialV1>, NodeError> {
        self.ensure_protocol_two_block_api()?;
        let mut material_budget = FinalizedProofMaterialBudgetV1::new(maximum_material_bytes);
        let Some(index) = self.store.finalized_transaction_index_v1(transaction_id)? else {
            return Ok(None);
        };
        if checkpoint_height.get() == 0 || checkpoint_height > index.position.height {
            return Err(NodeError::InvalidProofRequest(
                "checkpoint height must be finalized, non-zero, and no later than the target",
            ));
        }

        let checkpoint_block = self
            .store
            .block_v4_for_finalized_proof(checkpoint_height)?
            .ok_or(NodeError::ProofDataUnavailable(
                "checkpoint block is not retained",
            ))?;
        let checkpoint_certificate = self.store.certificate(checkpoint_height.get())?.ok_or(
            NodeError::ProofDataUnavailable("checkpoint certificate is not retained"),
        )?;
        let checkpoint_authority_set = self
            .store
            .finality_authority_set_v1(checkpoint_block.header.epoch)?
            .ok_or(NodeError::ProofDataUnavailable(
                "checkpoint authority set is not retained",
            ))?;

        // The common request anchors the target itself. Account for the full
        // block before cloning its header, because the same decoded allocation
        // will become the retained target block below.
        let same_block = index.position.height == checkpoint_height;
        if same_block {
            material_budget.charge(&checkpoint_block)?;
        }
        material_budget.charge(&checkpoint_block.header)?;
        let checkpoint_certificate_bytes = material_budget.charge(&checkpoint_certificate)?;
        let checkpoint_authority_set_bytes = material_budget.charge(&checkpoint_authority_set)?;
        let checkpoint_candidate = CheckpointV1 {
            version: CHECKPOINT_V1,
            header: checkpoint_block.header.clone(),
            certificate: checkpoint_certificate,
            authority_set: checkpoint_authority_set,
        };

        let target_block = if same_block {
            checkpoint_block
        } else {
            // Only its charged header survives in `checkpoint_candidate`.
            // Release the potentially multi-megabyte block before the next read.
            drop(checkpoint_block);
            let block = self
                .store
                .block_v4_for_finalized_proof(index.position.height)?
                .ok_or(NodeError::ProofDataUnavailable(
                    "target block is not retained",
                ))?;
            material_budget.charge(&block)?;
            block
        };
        let target_certificate = if same_block {
            // The public proof owns a second certificate even though the actor
            // snapshot retains only the checkpoint copy.
            material_budget.charge_bytes(checkpoint_certificate_bytes)?;
            None
        } else {
            let certificate = self.store.certificate(index.position.height.get())?.ok_or(
                NodeError::ProofDataUnavailable("target certificate is not retained"),
            )?;
            material_budget.charge(&certificate)?;
            Some(certificate)
        };

        let transaction_index =
            usize::try_from(index.position.transaction_index.get()).map_err(|_| {
                NodeError::InvalidProofRequest("transaction index is not representable")
            })?;
        if transaction_index >= target_block.transactions.len()
            || transaction_index >= target_block.receipts.len()
        {
            return Err(NodeError::ProofDataUnavailable(
                "finalized transaction index is outside its block",
            ));
        }

        let mut authority_transitions = Vec::new();
        let mut current_authority_set_bytes = checkpoint_authority_set_bytes;
        let checkpoint_epoch = checkpoint_candidate.header.epoch.get();
        let target_epoch = target_block.header.epoch.get();
        let transition_span =
            target_epoch
                .checked_sub(checkpoint_epoch)
                .ok_or(NodeError::ProofDataUnavailable(
                    "target epoch predates checkpoint epoch",
                ))?;
        let maximum_transitions = u64::try_from(MAX_AUTHORITY_TRANSITIONS_V1).map_err(|_| {
            NodeError::InvalidProofRequest("authority transition limit is not representable")
        })?;
        if transition_span > maximum_transitions {
            return Err(NodeError::InvalidProofRequest(
                "target requires more authority transitions than one proof permits",
            ));
        }
        let mut next_epoch_value =
            checkpoint_epoch
                .checked_add(1)
                .ok_or(NodeError::InvalidProofRequest(
                    "authority epoch is exhausted",
                ))?;
        while next_epoch_value <= target_epoch {
            let next_epoch = Epoch::new(next_epoch_value);
            let boundary_height = next_epoch
                .get()
                .checked_mul(self.config.staking.blocks_per_epoch)
                .map(BlockHeight::new)
                .ok_or(NodeError::InvalidProofRequest(
                    "epoch boundary height is exhausted",
                ))?;
            // A checkpoint taken on the boundary already carries the incoming
            // root, so it needs no duplicate transition for its own height.
            if boundary_height > checkpoint_height {
                if boundary_height >= target_block.header.height {
                    return Err(NodeError::ProofDataUnavailable(
                        "required authority transition height is inconsistent",
                    ));
                }
                let transition_block = self
                    .store
                    .block_v4_for_finalized_proof(boundary_height)?
                    .ok_or(NodeError::ProofDataUnavailable(
                        "authority transition block is not retained",
                    ))?;
                material_budget.charge(&transition_block.header)?;
                let transition_header = transition_block.header.clone();
                // Transition proofs retain only the header. Drop transactions
                // and receipts before loading the certificate and authority set.
                drop(transition_block);
                let transition_certificate = self.store.certificate(boundary_height.get())?.ok_or(
                    NodeError::ProofDataUnavailable(
                        "authority transition certificate is not retained",
                    ),
                )?;
                let incoming_authority_set = self
                    .store
                    .finality_authority_set_v1(next_epoch)?
                    .ok_or(NodeError::ProofDataUnavailable(
                        "incoming transition authority set is not retained",
                    ))?;

                // Charge every public-wire occurrence, but retain adjacent
                // authority sets once. Reusing the measured outgoing size avoids
                // repeatedly serializing a large set on the actor thread.
                material_budget.charge_bytes(current_authority_set_bytes)?;
                material_budget.charge(&transition_certificate)?;
                let incoming_authority_set_bytes =
                    material_budget.charge(&incoming_authority_set)?;
                let transition = AuthoritySetTransitionMaterialV1 {
                    header: transition_header,
                    certificate: transition_certificate,
                    incoming_authority_set,
                };
                authority_transitions.push(transition);
                current_authority_set_bytes = incoming_authority_set_bytes;
            }
            if next_epoch_value == target_epoch {
                break;
            }
            next_epoch_value =
                next_epoch_value
                    .checked_add(1)
                    .ok_or(NodeError::InvalidProofRequest(
                        "authority epoch is exhausted",
                    ))?;
        }

        // Target-certificate verification carries its own authority-set field.
        // It may reuse the checkpoint or last incoming set in memory, but its
        // projected public bytes still count against the single proof envelope.
        material_budget.charge_bytes(current_authority_set_bytes)?;

        Ok(Some(FinalizedTransactionProofMaterialV1 {
            chain_id: self.config.chain_id.clone(),
            blocks_per_epoch: self.config.staking.blocks_per_epoch,
            transaction_id,
            checkpoint_height,
            checkpoint_candidate,
            target_block,
            target_certificate,
            authority_transitions,
            transaction_index,
        }))
    }

    /// Replays and atomically commits one certified protocol-2 V4 block.
    ///
    /// The store transaction includes block/state/authority/certificate/tip,
    /// pending deletions, finalized indexes, receipts, and lifecycle facts. Live
    /// state is adopted only after that batch succeeds. The returned pending IDs
    /// let the owning actor perform its infallible memory removals afterwards.
    pub fn import_finalized_block_v4(
        &mut self,
        block: BlockV4,
        next_authority_set: &FinalityAuthoritySetV1,
        certificate: &FinalityCertificate,
    ) -> Result<V4FinalizationResult, NodeError> {
        self.ensure_protocol_two_block_api()?;
        if block.header.chain_id != self.config.chain_id {
            return Err(NodeError::ChainIdMismatch);
        }
        let current_authority_set = self.current_finality_authority_set_v1()?;
        let next_state = replay_block_v4_transition(
            &self.state,
            &self.config,
            &block,
            &current_authority_set,
            next_authority_set,
        )?;

        let mut finalized_transaction_ids = Vec::with_capacity(block.transactions.len());
        let mut removed_pending_ids = BTreeSet::new();
        for transaction in &block.transactions {
            let transaction_id = transaction.transaction_id()?;
            finalized_transaction_ids.push(transaction_id);
            if self.store.pending_transaction_v1(transaction_id)?.is_some() {
                removed_pending_ids.insert(transaction_id);
            }
            let slot = PendingSlotV1::for_transaction(transaction);
            if let Some(occupant) = self.store.pending_id_for_slot_v1(slot)? {
                removed_pending_ids.insert(occupant);
            }
        }

        self.store.commit_block_v4(BlockV4Commit {
            block: &block,
            state: &next_state,
            current_authority_set: &current_authority_set,
            next_authority_set,
            certificate,
        })?;
        self.state = next_state;
        Ok(V4FinalizationResult {
            height: block.header.height,
            finalized_transaction_ids,
            removed_pending_ids: removed_pending_ids.into_iter().collect(),
        })
    }

    /// Stops V3-header/legacy-transaction methods from writing a protocol-2 store.
    fn ensure_legacy_block_api(&self) -> Result<(), NodeError> {
        if self.config.protocol_version != CURRENT_PROTOCOL_VERSION {
            return Err(NodeError::LegacyBlockApiInactive);
        }
        Ok(())
    }

    /// Stops protocol-2 block methods from interpreting legacy state or storage.
    fn ensure_protocol_two_block_api(&self) -> Result<(), NodeError> {
        if self.config.protocol_version != TRANSACTION_V5_PROTOCOL_VERSION
            || self.state.protocol_version != TRANSACTION_V5_PROTOCOL_VERSION
        {
            return Err(NodeError::ProtocolTwoBlockApiInactive);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webc_chain::{Amount, ChainConfig, FeeBid, GenesisAccount, GenesisConfig, Operation};
    use webc_crypto::Keypair;
    use webc_storage::{MemoryKvStore, RedbKvStore};

    #[test]
    fn proof_material_budget_rejects_the_next_record_atomically() {
        let mut budget = FinalizedProofMaterialBudgetV1::new(4);
        budget.charge_bytes(3).expect("first retained record fits");

        assert!(matches!(
            budget.charge_bytes(2),
            Err(NodeError::FinalizedProofMaterialTooLarge { maximum_bytes: 4 })
        ));
        assert_eq!(
            budget.used_bytes, 3,
            "a rejected record must not become retained budget"
        );
    }

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
    fn protocol_two_node_opens_but_legacy_block_methods_fail_closed() {
        let alice = Keypair::from_seed([0x81; 32]);
        let genesis = GenesisConfig {
            chain: ChainConfig {
                protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
                ..ChainConfig::default()
            },
            accounts: vec![GenesisAccount {
                address: alice.address(),
                balance: Amount::from_units(100_000),
            }],
            validators: Vec::new(),
        };
        let mut node =
            Node::open(MemoryKvStore::new(), &genesis).expect("protocol-2 state and schema open");
        assert_eq!(
            node.state().protocol_version,
            TRANSACTION_V5_PROTOCOL_VERSION
        );
        assert!(matches!(
            node.produce_block(Vec::new(), Vec::new(), alice.address(), 1),
            Err(NodeError::LegacyBlockApiInactive)
        ));
        assert_eq!(node.height(), 0);
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
    fn produce_block_clamps_timestamp_to_stay_monotonic() {
        // E2: reusing or lowering the supplied timestamp still yields strictly
        // increasing block timestamps, so honest production never trips the
        // monotonicity check.
        let (genesis, alice, bob) = test_genesis();
        let mut node = Node::open(MemoryKvStore::new(), &genesis).unwrap();

        let b1 = node
            .produce_block(
                vec![transfer(&alice, &bob, 1, 0)],
                Vec::new(),
                alice.address(),
                5_000,
            )
            .unwrap();
        assert_eq!(b1.header.timestamp_ms, 5_000);

        // The same wall-clock value is clamped to parent + 1.
        let b2 = node
            .produce_block(
                vec![transfer(&alice, &bob, 1, 1)],
                Vec::new(),
                alice.address(),
                5_000,
            )
            .unwrap();
        assert_eq!(b2.header.timestamp_ms, 5_001);

        // An earlier value is clamped forward too.
        let b3 = node
            .produce_block(
                vec![transfer(&alice, &bob, 1, 2)],
                Vec::new(),
                alice.address(),
                1,
            )
            .unwrap();
        assert_eq!(b3.header.timestamp_ms, 5_002);
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
        // Reopen with a different chain id over the same store: refused at the
        // storage layer now (ST1), before any state is read — stricter and
        // earlier than the node-level check.
        let mut other = test_genesis().0;
        other.chain.chain_id = webc_chain::ChainId::new("webc-other").unwrap();
        let err = Node::open(RedbKvStore::open(&path).unwrap(), &other).unwrap_err();
        assert!(matches!(
            err,
            NodeError::Storage(StorageError::ChainIdMismatch { .. })
        ));
    }
}
