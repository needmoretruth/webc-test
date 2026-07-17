//! Deterministic construction of a candidate block from an execution state.
//!
//! Consensus supplies metadata and selected transactions; this module executes
//! them and commits roots. It does not read clocks, networking, or storage.
//! Inputs are hostile until transaction and state checks pass. All work occurs
//! in a whole-block overlay; any transaction, arithmetic, root, or size failure
//! discards the overlay and leaves the caller's state unchanged.

use crate::{
    Block, BlockHeader, ChainConfig, ChainError, ChainId, ChainState, Receipt, SlashingEvidence,
    Transaction,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use webc_crypto::{merkle_root, Address, Hash256};

/// Maximum objective slashing artifacts carried by one block.
///
/// Evidence has no user-paid gas envelope, so a fixed consensus bound prevents
/// an equivocating proposer from forcing unbounded signature verification while
/// still allowing many independently proven offenders to be processed together.
pub const MAX_BLOCK_SLASHING_EVIDENCE: usize = 64;

/// Metadata supplied by the consensus/proposer layer when building a block.
///
/// The state transition code should not read wall-clock time or global node
/// state by itself. Passing this data in keeps block construction deterministic
/// and testable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockBuildInput {
    /// Replay-protection network identifier; must equal genesis configuration.
    pub chain_id: ChainId,
    /// Monotonic candidate height assigned by consensus.
    pub height: u64,
    /// Validator-snapshot epoch authorizing the proposer.
    pub epoch: u64,
    /// Hash of the immediately preceding authoritative block.
    pub previous_hash: Hash256,
    /// Validator operator address selected to propose the candidate.
    pub proposer: Address,
    /// Consensus-supplied Unix timestamp in milliseconds; execution reads no clock.
    pub timestamp_ms: u64,
}

/// Builds a block by executing already-selected transactions in order.
///
/// This function is deliberately strict: if any transaction fails, block building
/// fails. A real mempool should filter invalid transactions before proposing a
/// block, and consensus should slash/sign-reject validators that propose invalid
/// blocks.
pub fn build_block(
    state: &mut ChainState,
    config: &ChainConfig,
    input: BlockBuildInput,
    transactions: Vec<Transaction>,
    evidence: Vec<SlashingEvidence>,
) -> Result<Block, ChainError> {
    if input.chain_id != config.chain_id || state.chain_id != config.chain_id {
        return Err(ChainError::BlockChainIdMismatch);
    }

    // E2: block timestamps must strictly increase. A proposer cannot rewind or
    // freeze consensus time, so any logic that later reads `timestamp_ms`
    // (epoch/expiry/fee) has a monotonic clock. The check runs identically in
    // `build_block` and `apply_block` (which re-executes this function), so it is
    // consensus-enforced on every node. Genesis leaves `last_block_timestamp_ms`
    // at 0, so the first block only needs a positive timestamp.
    if input.timestamp_ms <= state.last_block_timestamp_ms {
        return Err(ChainError::NonMonotonicBlockTimestamp {
            timestamp: input.timestamp_ms,
            parent: state.last_block_timestamp_ms,
        });
    }

    let mut next_state = state.clone();
    let base_fee_for_block = next_state.current_base_fee_per_unit;
    let mut receipts = Vec::with_capacity(transactions.len());
    let mut units_used = 0u64;

    if evidence.len() > MAX_BLOCK_SLASHING_EVIDENCE {
        return Err(ChainError::TooManyBlockEvidence {
            actual: evidence.len(),
            maximum: MAX_BLOCK_SLASHING_EVIDENCE,
        });
    }
    let evidence_root = evidence_root(&evidence)?;
    // Objective evidence executes before user transactions. This prevents an
    // offender from moving or exiting slashable stake earlier in the same block.
    // The whole-block overlay preserves atomic rollback if evidence or any later
    // transaction fails.
    for item in &evidence {
        next_state.apply_block_slashing_evidence(item, config)?;
    }

    // Fair packing (Phase 6 acceptance): a single application namespace may not
    // consume more than its per-block share cap, so one hot application cannot
    // monopolize block capacity. Enforced here as a hard consensus validity rule —
    // `apply_block` re-runs this function, so a Byzantine proposer that over-packs
    // one namespace produces a block every honest node rejects. The proposer's
    // mempool selects a compliant, fair set up front (webc-node `select_block`).
    let namespace_unit_cap = config.fee_policy.namespace_block_unit_cap()?;
    let mut namespace_units: BTreeMap<Hash256, u64> = BTreeMap::new();
    for transaction in &transactions {
        let tx_units = transaction.required_units();
        let projected_units = units_used
            .checked_add(tx_units)
            .ok_or(ChainError::ArithmeticOverflow)?;
        if projected_units > config.fee_policy.max_block_units {
            return Err(ChainError::BlockUnitsExceeded {
                maximum: config.fee_policy.max_block_units,
            });
        }
        // Object operations are namespace-scoped; enforce the fair-packing cap on
        // this namespace's running total before executing.
        let namespace_projected = if let Some(namespace) = transaction.operation.fee_namespace() {
            let projected = namespace_units
                .get(&namespace)
                .copied()
                .unwrap_or(0)
                .checked_add(tx_units)
                .ok_or(ChainError::ArithmeticOverflow)?;
            if projected > namespace_unit_cap {
                return Err(ChainError::NamespaceBlockShareExceeded {
                    namespace,
                    maximum: namespace_unit_cap,
                });
            }
            Some((namespace, projected))
        } else {
            None
        };
        let receipt = next_state.execute_transaction(transaction, config)?;
        units_used = projected_units;
        if let Some((namespace, projected)) = namespace_projected {
            namespace_units.insert(namespace, projected);
        }
        receipts.push(receipt);
    }

    // Base-fee adjustment is a protocol state update caused by block fullness.
    // The header records the fee used by this block, while `state_root` commits
    // to the next global base fee and every congested namespace's next localized
    // base fee after the block is finished.
    next_state.finish_block(units_used, &namespace_units, config)?;
    // Record this block's timestamp so the next block must exceed it (E2). This
    // is committed by `state_root`, so all nodes agree on the monotonic clock.
    next_state.last_block_timestamp_ms = input.timestamp_ms;

    // E1: advance the epoch deterministically at height-derived boundaries,
    // inside the state transition. Reward distribution, unbonding maturation,
    // and session-key expiry therefore fire identically on every node — because
    // `apply_block` re-runs this exact function — instead of only when the demo
    // called `distribute_epoch_rewards` out of band. The trigger is a pure
    // function of the committed height, so honest nodes never diverge at the
    // boundary. `blocks_per_epoch == 0` disables it (unit tests that drive the
    // epoch directly). The returned events are informational; the committed
    // state change is what `state_root` binds.
    let blocks_per_epoch = config.staking.blocks_per_epoch;
    if blocks_per_epoch != 0 && input.height.is_multiple_of(blocks_per_epoch) {
        next_state.distribute_epoch_rewards(config)?;
    }

    let header = BlockHeader {
        protocol_version: config.protocol_version,
        chain_id: input.chain_id,
        height: input.height,
        epoch: input.epoch,
        previous_hash: input.previous_hash,
        state_root: next_state.state_root()?,
        account_root: next_state.account_root()?,
        tx_root: transaction_root(&transactions)?,
        receipt_root: receipt_root(&receipts)?,
        evidence_root,
        proposer: input.proposer,
        timestamp_ms: input.timestamp_ms,
        base_fee_per_unit: base_fee_for_block,
    };

    let block = Block {
        header,
        transactions,
        receipts,
        evidence,
    };
    let block_bytes = crate::canonical::canonical_json_bytes(&block)?;
    let actual_bytes =
        u64::try_from(block_bytes.len()).map_err(|_| ChainError::ArithmeticOverflow)?;
    if actual_bytes > config.max_block_bytes {
        return Err(ChainError::BlockBytesExceeded {
            actual: actual_bytes,
            maximum: config.max_block_bytes,
        });
    }

    *state = next_state;
    Ok(block)
}

/// Validates a *received* block by re-executing it and commits it to `state`.
///
/// Where [`build_block`] constructs a candidate from selected transactions, this
/// verifies a block another node produced: it re-executes the block's own
/// transactions and evidence with the block's own header metadata, then requires
/// the locally recomputed header and receipts to match the received ones exactly.
/// Because the recomputed header carries `state_root`, `account_root`, `tx_root`,
/// `receipt_root`, `evidence_root`, and `base_fee_per_unit`, a single mismatch
/// anywhere — a forged root, altered evidence/transactions, or a wrong fee —
/// rejects the block. All work
/// happens on a clone, so a rejected block leaves `state` untouched.
///
/// This does not check consensus placement (height linkage, proposer schedule,
/// finality); the node and consensus layers own those. It answers exactly one
/// question: does this block's body deterministically produce this block's
/// header from the current state?
pub fn apply_block(
    state: &mut ChainState,
    config: &ChainConfig,
    block: &Block,
) -> Result<(), ChainError> {
    let input = BlockBuildInput {
        chain_id: block.header.chain_id.clone(),
        height: block.header.height,
        epoch: block.header.epoch,
        previous_hash: block.header.previous_hash,
        proposer: block.header.proposer,
        timestamp_ms: block.header.timestamp_ms,
    };
    let mut candidate_state = state.clone();
    let rebuilt = build_block(
        &mut candidate_state,
        config,
        input,
        block.transactions.clone(),
        block.evidence.clone(),
    )?;
    // The header commits every root and the block fee, so header equality proves
    // the re-execution reproduced the proposer's exact state transition.
    if rebuilt.header != block.header || rebuilt.receipts != block.receipts {
        return Err(ChainError::ImportedBlockMismatch);
    }
    *state = candidate_state;
    Ok(())
}

/// Computes the ordered Merkle root of signed transaction identifiers.
pub fn transaction_root(transactions: &[Transaction]) -> Result<Hash256, ChainError> {
    let leaves = transactions
        .iter()
        .map(Transaction::hash)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(merkle_root(&leaves))
}

/// Computes the ordered Merkle root of canonical deterministic receipts.
pub fn receipt_root(receipts: &[Receipt]) -> Result<Hash256, ChainError> {
    // Use canonical JSON so a browser light client can recompute the receipt
    // root from the same receipt data. Previously this used Rust-only bincode,
    // which made browser verification impossible.
    let leaves = receipts
        .iter()
        .map(|receipt| {
            let bytes = crate::canonical::canonical_json_bytes(receipt)?;
            Ok::<Hash256, ChainError>(Hash256::digest(bytes))
        })
        .collect::<Result<Vec<_>, ChainError>>()?;
    Ok(merkle_root(&leaves))
}

/// Computes the ordered Merkle root of replay-stable slashing-evidence IDs.
pub fn evidence_root(evidence: &[SlashingEvidence]) -> Result<Hash256, ChainError> {
    let leaves = evidence
        .iter()
        .map(SlashingEvidence::hash)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(merkle_root(&leaves))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Amount, DoubleVoteEvidence, FeeBid, FeePolicy, GenesisAccount, GenesisConfig,
        GenesisValidator, ObjectId, Operation, SignedVote, SlashingEvidence, ValidatorStatus, Vote,
        VoteType,
    };
    use webc_crypto::Keypair;

    #[test]
    fn block_builder_executes_transactions_and_commits_roots() {
        let config = ChainConfig::default();
        let alice = Keypair::from_seed([1u8; 32]);
        let bob = Keypair::from_seed([2u8; 32]);
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![GenesisAccount {
                address: alice.address(),
                balance: Amount::from_webc(1_000),
            }],
            validators: Vec::new(),
        };
        let mut state = ChainState::from_genesis(&genesis).unwrap();
        let tx = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(1),
            },
            FeeBid::default(),
        )
        .unwrap();

        let block = build_block(
            &mut state,
            &config,
            BlockBuildInput {
                chain_id: config.chain_id.clone(),
                height: 1,
                epoch: 0,
                previous_hash: Hash256::ZERO,
                proposer: alice.address(),
                timestamp_ms: 1_700_000_000_000,
            },
            vec![tx],
            Vec::new(),
        )
        .unwrap();

        assert_eq!(block.header.height, 1);
        assert_eq!(block.receipts.len(), 1);
        assert_eq!(block.header.account_root, state.account_root().unwrap());
        assert_eq!(block.header.state_root, state.state_root().unwrap());
        assert_ne!(block.header.tx_root, Hash256::ZERO);
        assert_ne!(block.header.receipt_root, Hash256::ZERO);
    }

    #[test]
    fn block_timestamps_must_strictly_increase() {
        // E2: a proposer cannot rewind or freeze consensus time.
        let config = ChainConfig::default();
        let alice = Keypair::from_seed([1u8; 32]);
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![GenesisAccount {
                address: alice.address(),
                balance: Amount::from_webc(1_000),
            }],
            validators: Vec::new(),
        };
        let mut state = ChainState::from_genesis(&genesis).unwrap();

        let block_at = |state: &mut ChainState, height, ts| {
            build_block(
                state,
                &config,
                BlockBuildInput {
                    chain_id: config.chain_id.clone(),
                    height,
                    epoch: 0,
                    previous_hash: Hash256::ZERO,
                    proposer: alice.address(),
                    timestamp_ms: ts,
                },
                Vec::new(),
                Vec::new(),
            )
        };

        // First block above the genesis parent timestamp (0) succeeds.
        block_at(&mut state, 1, 5_000).expect("first block");
        assert_eq!(state.last_block_timestamp_ms, 5_000);

        // Equal or earlier timestamps are rejected and leave state unchanged.
        for stale in [5_000u64, 4_000] {
            assert!(matches!(
                block_at(&mut state, 2, stale),
                Err(ChainError::NonMonotonicBlockTimestamp { .. })
            ));
            assert_eq!(state.last_block_timestamp_ms, 5_000);
        }

        // A strictly newer timestamp advances the chain clock.
        block_at(&mut state, 2, 5_001).expect("newer block");
        assert_eq!(state.last_block_timestamp_ms, 5_001);
    }

    #[test]
    fn epoch_advances_deterministically_at_height_boundaries() {
        // E1: the epoch rollover runs inside build_block (re-run by apply_block),
        // keyed on committed height, so every node advances the epoch identically
        // instead of only when the demo called distribute_epoch_rewards.
        let mut config = ChainConfig::default();
        config.staking.blocks_per_epoch = 2;
        let alice = Keypair::from_seed([1u8; 32]);
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![GenesisAccount {
                address: alice.address(),
                balance: Amount::from_webc(1_000),
            }],
            validators: Vec::new(),
        };
        let mut state = ChainState::from_genesis(&genesis).unwrap();
        assert_eq!(state.current_epoch, 0);

        let build_at = |state: &mut ChainState, height: u64, ts: u64| {
            let epoch = state.current_epoch;
            build_block(
                state,
                &config,
                BlockBuildInput {
                    chain_id: config.chain_id.clone(),
                    height,
                    epoch,
                    previous_hash: Hash256::ZERO,
                    proposer: alice.address(),
                    timestamp_ms: ts,
                },
                Vec::new(),
                Vec::new(),
            )
            .expect("block builds");
        };

        build_at(&mut state, 1, 1_000); // not a boundary
        assert_eq!(state.current_epoch, 0);
        build_at(&mut state, 2, 2_000); // completes epoch 0
        assert_eq!(state.current_epoch, 1);
        build_at(&mut state, 3, 3_000); // not a boundary
        assert_eq!(state.current_epoch, 1);
        build_at(&mut state, 4, 4_000); // completes epoch 1
        assert_eq!(state.current_epoch, 2);
    }

    fn build_input(config: &ChainConfig, proposer: Address) -> BlockBuildInput {
        BlockBuildInput {
            chain_id: config.chain_id.clone(),
            height: 1,
            epoch: 0,
            previous_hash: Hash256::ZERO,
            proposer,
            timestamp_ms: 1_700_000_000_000,
        }
    }

    fn double_vote_evidence(
        validator: &Keypair,
        config: &ChainConfig,
        height: u64,
    ) -> SlashingEvidence {
        let vote = |block_hash| Vote {
            protocol_version: config.protocol_version,
            chain_id: config.chain_id.clone(),
            height,
            round: 0,
            vote_type: VoteType::Prevote,
            block_hash,
            validator: validator.address(),
        };
        SlashingEvidence::DoubleVote(DoubleVoteEvidence {
            first: SignedVote::sign(vote(Hash256([0xA1; 32])), validator).unwrap(),
            second: SignedVote::sign(vote(Hash256([0xB2; 32])), validator).unwrap(),
        })
    }

    #[test]
    fn header_committed_evidence_slashes_and_imports_deterministically() {
        let config = ChainConfig::default();
        let validator = Keypair::from_seed([61u8; 32]);
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![GenesisAccount {
                address: validator.address(),
                balance: Amount::from_webc(1_000),
            }],
            validators: vec![GenesisValidator {
                operator: validator.address(),
                consensus_key: validator.public_key(),
                self_stake: Amount::from_webc(200),
                commission_bps: 500,
                bootstrap: false,
            }],
        };
        let evidence = double_vote_evidence(&validator, &config, 1);
        let evidence_hash = evidence.hash().unwrap();

        let mut producer = ChainState::from_genesis(&genesis).unwrap();
        let block = build_block(
            &mut producer,
            &config,
            build_input(&config, validator.address()),
            Vec::new(),
            vec![evidence.clone()],
        )
        .unwrap();

        assert_eq!(
            block.header.evidence_root,
            evidence_root(&[evidence]).unwrap()
        );
        assert_eq!(block.header.evidence_root, evidence_hash);
        assert_eq!(producer.slashed_units, Amount::from_webc(160));
        assert_eq!(
            producer.validators[&validator.address()].self_stake,
            Amount::from_webc(40)
        );
        assert!(matches!(
            producer.validators[&validator.address()].status,
            ValidatorStatus::Tombstoned { .. }
        ));

        let mut importer = ChainState::from_genesis(&genesis).unwrap();
        apply_block(&mut importer, &config, &block).unwrap();
        assert_eq!(importer, producer);

        // Removing the evidence without changing the signed header cannot
        // preserve the evidence root or the post-slash state root.
        let mut tampered = block;
        tampered.evidence.clear();
        let before = ChainState::from_genesis(&genesis).unwrap();
        let mut rejected = before.clone();
        assert!(matches!(
            apply_block(&mut rejected, &config, &tampered),
            Err(ChainError::ImportedBlockMismatch)
        ));
        assert_eq!(rejected, before);
    }

    #[test]
    fn late_transaction_failure_rolls_back_the_whole_block() {
        let config = ChainConfig::default();
        let alice = Keypair::from_seed([11u8; 32]);
        let bob = Keypair::from_seed([12u8; 32]);
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![GenesisAccount {
                address: alice.address(),
                balance: Amount::from_webc(100),
            }],
            validators: Vec::new(),
        };
        let mut state = ChainState::from_genesis(&genesis).expect("valid test genesis");
        let before = state.clone();
        let first = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(1),
            },
            FeeBid::default(),
        )
        .expect("valid first transaction");
        let invalid_late = Transaction::for_operation(
            &alice,
            9,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(1),
            },
            FeeBid::default(),
        )
        .expect("signed but invalid nonce transaction");

        assert!(build_block(
            &mut state,
            &config,
            build_input(&config, alice.address()),
            vec![first, invalid_late],
            Vec::new(),
        )
        .is_err());
        assert_eq!(state, before);
    }

    #[test]
    fn byte_limit_failure_does_not_commit_execution() {
        let config = ChainConfig {
            max_block_bytes: 1,
            ..ChainConfig::default()
        };
        let alice = Keypair::from_seed([21u8; 32]);
        let bob = Keypair::from_seed([22u8; 32]);
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![GenesisAccount {
                address: alice.address(),
                balance: Amount::from_webc(100),
            }],
            validators: Vec::new(),
        };
        let mut state = ChainState::from_genesis(&genesis).expect("valid test genesis");
        let before = state.clone();
        let transaction = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(1),
            },
            FeeBid::default(),
        )
        .expect("valid transaction");

        assert!(matches!(
            build_block(
                &mut state,
                &config,
                build_input(&config, alice.address()),
                vec![transaction],
                Vec::new(),
            ),
            Err(ChainError::BlockBytesExceeded { .. })
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn apply_block_reproduces_the_producers_state() {
        let config = ChainConfig::default();
        let alice = Keypair::from_seed([41u8; 32]);
        let bob = Keypair::from_seed([42u8; 32]);
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![GenesisAccount {
                address: alice.address(),
                balance: Amount::from_webc(1_000),
            }],
            validators: Vec::new(),
        };
        // Producer builds a block; its state advances.
        let mut producer_state = ChainState::from_genesis(&genesis).unwrap();
        let tx = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(3),
            },
            FeeBid::default(),
        )
        .unwrap();
        let block = build_block(
            &mut producer_state,
            &config,
            build_input(&config, alice.address()),
            vec![tx],
            Vec::new(),
        )
        .unwrap();

        // A second node imports the received block onto its own genesis state and
        // ends at the identical state root — no rebuild-from-mempool required.
        let mut importer_state = ChainState::from_genesis(&genesis).unwrap();
        apply_block(&mut importer_state, &config, &block).unwrap();
        assert_eq!(
            importer_state.state_root().unwrap(),
            producer_state.state_root().unwrap()
        );
        assert_eq!(
            importer_state.accounts.get(&bob.address()).unwrap().balance,
            Amount::from_webc(3)
        );
    }

    #[test]
    fn apply_block_rejects_a_tampered_header() {
        let config = ChainConfig::default();
        let alice = Keypair::from_seed([51u8; 32]);
        let bob = Keypair::from_seed([52u8; 32]);
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![GenesisAccount {
                address: alice.address(),
                balance: Amount::from_webc(1_000),
            }],
            validators: Vec::new(),
        };
        let mut producer_state = ChainState::from_genesis(&genesis).unwrap();
        let tx = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(3),
            },
            FeeBid::default(),
        )
        .unwrap();
        let mut block = build_block(
            &mut producer_state,
            &config,
            build_input(&config, alice.address()),
            vec![tx],
            Vec::new(),
        )
        .unwrap();
        // Forge a false state root; re-execution will not reproduce it.
        block.header.state_root = Hash256([0xAB; 32]);

        let mut importer_state = ChainState::from_genesis(&genesis).unwrap();
        let before = importer_state.clone();
        assert!(matches!(
            apply_block(&mut importer_state, &config, &block),
            Err(ChainError::ImportedBlockMismatch)
        ));
        // A rejected block leaves the importer's state untouched.
        assert_eq!(importer_state, before);
    }

    #[test]
    fn fair_packing_rejects_a_single_namespace_monopolizing_a_block() {
        // Phase 6 acceptance: a block that packs one application namespace beyond its
        // fair per-block share is invalid, so a Byzantine proposer cannot let one hot
        // app monopolize capacity (apply_block re-runs this and rejects it too). Cap
        // = 100_000 * 5000 / 10_000 = 50_000 units = 2 object ops; a third exceeds it.
        let config = ChainConfig {
            fee_policy: FeePolicy {
                target_block_units: 50_000,
                max_block_units: 100_000,
                namespace_block_share_bps: 5_000,
                ..FeePolicy::default()
            },
            ..ChainConfig::default()
        };
        let alice = Keypair::from_seed([71u8; 32]);
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![GenesisAccount {
                address: alice.address(),
                balance: Amount::from_webc(1_000),
            }],
            validators: Vec::new(),
        };
        let namespace = Hash256::digest(b"greedy-app");
        let object_op = |nonce: u64| {
            Transaction::for_operation(
                &alice,
                nonce,
                Operation::CreateObject {
                    object_id: ObjectId::new(Hash256::digest(format!("obj-{nonce}").as_bytes())),
                    namespace,
                    data: Vec::new(),
                },
                FeeBid {
                    gas_limit: 30_000,
                    max_fee_per_unit: 1,
                    priority_fee_per_unit: 0,
                },
            )
            .expect("object op signs")
        };

        // Two object ops in one namespace fit the fair share and build a valid block.
        let mut ok_state = ChainState::from_genesis(&genesis).unwrap();
        build_block(
            &mut ok_state,
            &config,
            build_input(&config, alice.address()),
            vec![object_op(0), object_op(1)],
            Vec::new(),
        )
        .expect("two object ops fit the namespace share");

        // A third pushes the namespace past its share cap: the whole block is
        // rejected and the caller's state is left unchanged.
        let mut state = ChainState::from_genesis(&genesis).unwrap();
        let before = state.clone();
        assert!(matches!(
            build_block(
                &mut state,
                &config,
                build_input(&config, alice.address()),
                vec![object_op(0), object_op(1), object_op(2)],
                Vec::new(),
            ),
            Err(ChainError::NamespaceBlockShareExceeded {
                maximum: 50_000,
                ..
            })
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn unit_limit_failure_does_not_commit_execution() {
        let config = ChainConfig {
            fee_policy: FeePolicy {
                max_block_units: 499,
                ..FeePolicy::default()
            },
            ..ChainConfig::default()
        };
        let alice = Keypair::from_seed([31u8; 32]);
        let bob = Keypair::from_seed([32u8; 32]);
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![GenesisAccount {
                address: alice.address(),
                balance: Amount::from_webc(100),
            }],
            validators: Vec::new(),
        };
        let mut state = ChainState::from_genesis(&genesis).expect("valid test genesis");
        let before = state.clone();
        let transaction = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(1),
            },
            FeeBid::default(),
        )
        .expect("valid transaction");

        assert!(matches!(
            build_block(
                &mut state,
                &config,
                build_input(&config, alice.address()),
                vec![transaction],
                Vec::new(),
            ),
            Err(ChainError::BlockUnitsExceeded { maximum: 499 })
        ));
        assert_eq!(state, before);
    }
}
