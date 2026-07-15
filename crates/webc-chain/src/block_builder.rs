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
use webc_crypto::{merkle_root, Address, Hash256};

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

    let mut next_state = state.clone();
    let base_fee_for_block = next_state.current_base_fee_per_unit;
    let mut receipts = Vec::with_capacity(transactions.len());
    let mut units_used = 0u64;

    for transaction in &transactions {
        let projected_units = units_used
            .checked_add(transaction.required_units())
            .ok_or(ChainError::ArithmeticOverflow)?;
        if projected_units > config.fee_policy.max_block_units {
            return Err(ChainError::BlockUnitsExceeded {
                maximum: config.fee_policy.max_block_units,
            });
        }
        let receipt = next_state.execute_transaction(transaction, config)?;
        units_used = projected_units;
        receipts.push(receipt);
    }

    // Base-fee adjustment is a protocol state update caused by block fullness.
    // The header records the fee used by this block, while `state_root` commits
    // to the next base fee after the block is finished.
    next_state.finish_block(units_used, config)?;

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
/// `receipt_root`, and `base_fee_per_unit`, a single mismatch anywhere — a forged
/// root, an altered transaction set, a wrong fee — rejects the block. All work
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Amount, FeeBid, FeePolicy, GenesisAccount, GenesisConfig, Operation};
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
