//! Deterministic protocol-2 block construction and hostile-block replay.
//!
//! Purpose: connect signed V5 transactions and typed V1 receipts to the V4
//! block container through one whole-block state transition. Responsibilities:
//! enforce block metadata/resource bounds, apply objective evidence before user
//! work, execute transactions in order, finish fee/epoch state, bind authority
//! commitments, and reproduce received blocks exactly. Non-responsibilities:
//! choose transactions, read clocks, schedule proposers, collect votes, verify a
//! finality certificate, persist a block, or perform networking.
//!
//! Data flow: consensus supplies immutable metadata, the current/next authority
//! snapshots, selected transactions, and evidence. [`build_block_v4`] executes
//! them against a private overlay and publishes the resulting block plus state.
//! [`apply_block_v4`] feeds a received block through the same transition and
//! adopts the overlay only when every reconstructed byte-level field matches.
//!
//! Security boundary: every argument may originate from a hostile peer. Cheap
//! count/byte/configuration checks run before signature and state work; checked
//! arithmetic bounds all loops and units; transaction errors never partially
//! mutate the caller; and an imported mismatch discards the complete overlay.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use webc_crypto::{Address, Hash256};

use crate::{
    canonical::canonical_json_bytes, evidence_root, receipt_root_v1, transaction_root_v1,
    BlockExecutionErrorV1, BlockHeaderV4, BlockHeight, BlockPositionV1, BlockV4, BlockV4Error,
    ChainConfig, ChainError, ChainId, ChainState, Epoch, FinalityAuthoritySetErrorV1,
    FinalityAuthoritySetV1, ReceiptError, SlashingEvidence, TransactionId, TransactionIndex,
    TransactionPreparationErrorV1, TransactionV5, TransactionValidationErrorV1,
    ValidatedTransactionV1, ValidatorSet, MAX_BLOCK_SLASHING_EVIDENCE,
    MAX_BLOCK_V4_CANONICAL_BYTES, MAX_BLOCK_V4_TRANSACTIONS, TRANSACTION_V5_PROTOCOL_VERSION,
};

/// Consensus metadata supplied for one protocol-2 candidate transition.
///
/// Time is an explicit signed-header input. This type deliberately carries no
/// round, local timestamp, storage handle, or network state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockBuildInputV1 {
    /// Genesis-fixed replay-protection network identifier.
    pub chain_id: ChainId,
    /// Candidate height, which must be exactly current state height plus one.
    pub height: BlockHeight,
    /// Outgoing authority epoch that certifies this block.
    pub epoch: Epoch,
    /// Hash of the immediately preceding finalized V4 header.
    pub previous_hash: Hash256,
    /// Current-set validator selected by consensus to propose this candidate.
    pub proposer: Address,
    /// Consensus-supplied Unix timestamp in milliseconds; execution reads no clock.
    pub timestamp_ms: u64,
}

/// Locally built candidate plus the authority snapshot committed for its successor.
///
/// The next set is derived from post-state rather than accepted as an opaque
/// caller choice. Consensus transports it with an epoch-changing proposal, and
/// storage persists it atomically with the certified block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuiltBlockV4 {
    /// Deterministically executed V4 candidate.
    pub block: BlockV4,
    /// Authority set whose commitment authorizes the next height.
    pub next_authority_set: FinalityAuthoritySetV1,
}

/// Fail-closed errors from protocol-2 whole-block construction or replay.
#[derive(Debug, thiserror::Error)]
pub enum BlockV4ExecutionError {
    /// State/config/header version or chain domains disagree.
    #[error("protocol-2 block configuration does not match state")]
    ConfigurationMismatch,
    /// Candidate height is not the single successor of committed state.
    #[error("protocol-2 block height must be {expected:?}, got {actual:?}")]
    NonContiguousHeight {
        /// Only acceptable successor height.
        expected: BlockHeight,
        /// Supplied candidate height.
        actual: BlockHeight,
    },
    /// Committed height is already at the maximum representable value.
    #[error("protocol-2 block height is exhausted")]
    HeightExhausted,
    /// Header epoch is not the current committed execution epoch.
    #[error("protocol-2 block epoch must be {expected:?}, got {actual:?}")]
    EpochMismatch {
        /// Execution state's outgoing epoch.
        expected: Epoch,
        /// Supplied header epoch.
        actual: Epoch,
    },
    /// Consensus time did not strictly advance beyond the parent.
    #[error("protocol-2 block timestamp is not strictly greater than its parent")]
    NonMonotonicTimestamp,
    /// The current authority snapshot does not match header/state domains.
    #[error("current finality authority set does not match this block")]
    CurrentAuthoritySetMismatch,
    /// The supplied proposer is absent from the current finality authority set.
    #[error("protocol-2 block proposer is not a current finality authority")]
    ProposerNotAuthority,
    /// The next authority snapshot is not the deterministic post-block snapshot.
    #[error("next finality authority set does not match the post-block transition")]
    NextAuthoritySetMismatch,
    /// Objective evidence exceeds the fixed per-block verification bound.
    #[error("protocol-2 block carries too many objective evidence items")]
    TooManyEvidence,
    /// Transaction count exceeds the fixed V4 container bound.
    #[error("protocol-2 block carries too many transactions")]
    TooManyTransactions,
    /// Canonical body or complete block exceeds the configured byte limit.
    #[error("protocol-2 block exceeds its canonical byte limit")]
    BlockTooLarge,
    /// Static maximum work in the selected transaction set exceeds block capacity.
    #[error("protocol-2 block exceeds its execution-unit limit")]
    BlockUnitsExceeded,
    /// Two positions carry the same complete signed transaction identity.
    #[error("protocol-2 block contains duplicate transaction IDs")]
    DuplicateTransaction,
    /// A transaction position cannot be represented by the V1 receipt schema.
    #[error("protocol-2 transaction index exceeds the receipt index range")]
    TransactionIndexOverflow,
    /// Stateless transaction validation failed at the named position.
    #[error("protocol-2 transaction {index} failed stateless validation: {source}")]
    TransactionValidation {
        /// Zero-based transaction position.
        index: usize,
        /// Stable V5 validation failure.
        source: TransactionValidationErrorV1,
    },
    /// Stateful preparation failed at the named position.
    #[error("protocol-2 transaction {index} failed state preparation: {source}")]
    TransactionPreparation {
        /// Zero-based transaction position.
        index: usize,
        /// Stable V5 state/preparation failure.
        source: TransactionPreparationErrorV1,
    },
    /// An invariant-level execution error invalidated the complete block.
    #[error("protocol-2 transaction {index} failed block execution: {source}")]
    TransactionExecution {
        /// Zero-based transaction position.
        index: usize,
        /// Block-invalidating V5 execution failure.
        source: BlockExecutionErrorV1,
    },
    /// A shared deterministic state transition or root operation failed.
    #[error("protocol-2 block state transition failed: {0}")]
    State(#[from] ChainError),
    /// Authority set validation or commitment construction failed.
    #[error("protocol-2 authority snapshot is invalid: {0}")]
    Authority(#[from] FinalityAuthoritySetErrorV1),
    /// Position-bound receipt or transaction root construction failed.
    #[error("protocol-2 receipt commitment failed: {0}")]
    Receipt(#[from] ReceiptError),
    /// Locally built or received V4 structure failed its independent validator.
    #[error("protocol-2 block structure is invalid: {0}")]
    Block(#[source] Box<BlockV4Error>),
    /// Received header/body/receipts differ from deterministic local replay.
    #[error("received protocol-2 block does not match deterministic replay")]
    ImportedBlockMismatch,
}

impl From<BlockV4Error> for BlockV4ExecutionError {
    fn from(error: BlockV4Error) -> Self {
        Self::Block(Box::new(error))
    }
}

/// Builds one V4 block and atomically adopts its protocol-2 post-state.
///
/// Transactions execute in the supplied order. A chargeable action failure is
/// a successful inclusion with a failed [`crate::ReceiptV1`]; only a returned
/// error invalidates the block. The caller's state remains byte-for-byte
/// unchanged on every error, including the final serialized-size check.
pub fn build_block_v4(
    state: &mut ChainState,
    config: &ChainConfig,
    input: BlockBuildInputV1,
    transactions: Vec<TransactionV5>,
    evidence: Vec<SlashingEvidence>,
    current_authority_set: &FinalityAuthoritySetV1,
    next_authority_set: &FinalityAuthoritySetV1,
) -> Result<BlockV4, BlockV4ExecutionError> {
    let (block, next_state, _) = execute_block_v4(
        state,
        config,
        input,
        transactions,
        evidence,
        current_authority_set,
        Some(next_authority_set),
    )?;
    *state = next_state;
    Ok(block)
}

/// Builds a candidate while deriving its successor authority set from post-state.
///
/// At an ordinary height the outgoing set is carried forward unchanged. At an
/// epoch boundary the post-transition active validators become the next epoch's
/// set. Returning the concrete snapshot avoids duplicating epoch execution in a
/// proposer merely to predict the header commitment.
pub fn build_block_v4_with_derived_authority(
    state: &mut ChainState,
    config: &ChainConfig,
    input: BlockBuildInputV1,
    transactions: Vec<TransactionV5>,
    evidence: Vec<SlashingEvidence>,
    current_authority_set: &FinalityAuthoritySetV1,
) -> Result<BuiltBlockV4, BlockV4ExecutionError> {
    let (block, next_state, next_authority_set) = execute_block_v4(
        state,
        config,
        input,
        transactions,
        evidence,
        current_authority_set,
        None,
    )?;
    *state = next_state;
    Ok(BuiltBlockV4 {
        block,
        next_authority_set,
    })
}

/// Re-executes a received V4 block and atomically adopts it only on exact match.
///
/// Structural/signature/root validation runs before state execution. Consensus
/// placement, proposal leadership, and certificate verification remain node and
/// consensus responsibilities; the proposer must nevertheless be a member of
/// the supplied outgoing authority set.
pub fn apply_block_v4(
    state: &mut ChainState,
    config: &ChainConfig,
    block: &BlockV4,
    current_authority_set: &FinalityAuthoritySetV1,
    next_authority_set: &FinalityAuthoritySetV1,
) -> Result<(), BlockV4ExecutionError> {
    block.validate()?;
    let input = BlockBuildInputV1 {
        chain_id: block.header.chain_id.clone(),
        height: block.header.height,
        epoch: block.header.epoch,
        previous_hash: block.header.previous_hash,
        proposer: block.header.proposer,
        timestamp_ms: block.header.timestamp_ms,
    };
    let (rebuilt, next_state, _) = execute_block_v4(
        state,
        config,
        input,
        block.transactions.clone(),
        block.evidence.clone(),
        current_authority_set,
        Some(next_authority_set),
    )?;
    if rebuilt != *block {
        return Err(BlockV4ExecutionError::ImportedBlockMismatch);
    }
    *state = next_state;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn execute_block_v4(
    state: &ChainState,
    config: &ChainConfig,
    input: BlockBuildInputV1,
    transactions: Vec<TransactionV5>,
    evidence: Vec<SlashingEvidence>,
    current_authority_set: &FinalityAuthoritySetV1,
    declared_next_authority_set: Option<&FinalityAuthoritySetV1>,
) -> Result<(BlockV4, ChainState, FinalityAuthoritySetV1), BlockV4ExecutionError> {
    validate_block_context(state, config, &input, current_authority_set)?;
    if let Some(next_authority_set) = declared_next_authority_set {
        validate_declared_next_authority_set(
            config,
            &input,
            current_authority_set,
            next_authority_set,
        )?;
    }
    if transactions.len() > MAX_BLOCK_V4_TRANSACTIONS {
        return Err(BlockV4ExecutionError::TooManyTransactions);
    }
    if evidence.len() > MAX_BLOCK_SLASHING_EVIDENCE {
        return Err(BlockV4ExecutionError::TooManyEvidence);
    }
    let byte_limit = config
        .max_block_bytes
        .min(u64::try_from(MAX_BLOCK_V4_CANONICAL_BYTES).unwrap_or(u64::MAX));
    preflight_body_size(&transactions, &evidence, byte_limit)?;

    // Stateless work and the worst-case unit sum run before cloning state or
    // verifying evidence. Besides saving memory on rejection, this ensures a
    // directly constructed hostile value cannot bypass BlockV4's duplicate-ID
    // and count rules just because it did not arrive through decode_json.
    let mut seen = BTreeSet::<TransactionId>::new();
    let mut validated = Vec::with_capacity(transactions.len());
    let mut maximum_units = 0_u64;
    for (index, transaction) in transactions.iter().cloned().enumerate() {
        let transaction_id = transaction
            .transaction_id()
            .map_err(|source| BlockV4ExecutionError::TransactionValidation { index, source })?;
        if !seen.insert(transaction_id) {
            return Err(BlockV4ExecutionError::DuplicateTransaction);
        }
        let candidate = ValidatedTransactionV1::validate(transaction, &input.chain_id)
            .map_err(|source| BlockV4ExecutionError::TransactionValidation { index, source })?;
        maximum_units =
            maximum_units
                .checked_add(candidate.transaction().required_units().map_err(|source| {
                    BlockV4ExecutionError::TransactionValidation { index, source }
                })?)
                .ok_or(BlockV4ExecutionError::BlockUnitsExceeded)?;
        if maximum_units > config.fee_policy.max_block_units {
            return Err(BlockV4ExecutionError::BlockUnitsExceeded);
        }
        validated.push(candidate);
    }

    let base_fee_for_block = state.current_base_fee_per_unit;
    let evidence_commitment = evidence_root(&evidence)?;
    let mut next_state = state.clone();
    next_state.current_height = input.height.get();

    // Objective slashing precedes user actions so an offender cannot move
    // slashable value earlier in the same block. The outer overlay still rolls
    // all slashing back if a later transaction or commitment is invalid.
    for item in &evidence {
        next_state.apply_block_slashing_evidence(item, config)?;
    }
    next_state.prune_expired_sponsor_grants_v1(input.height)?;

    let mut receipts = Vec::with_capacity(validated.len());
    let mut units_used = 0_u64;
    for (index, transaction) in validated.into_iter().enumerate() {
        let transaction_index = u32::try_from(index)
            .map(TransactionIndex::new)
            .map_err(|_| BlockV4ExecutionError::TransactionIndexOverflow)?;
        let prepared = next_state
            .prepare_transaction_v1(transaction, input.height, config)
            .map_err(|source| BlockV4ExecutionError::TransactionPreparation { index, source })?;
        let executed = next_state
            .execute_prepared_transaction_v1(
                prepared,
                BlockPositionV1::new(input.height, transaction_index),
                config,
            )
            .map_err(|source| BlockV4ExecutionError::TransactionExecution { index, source })?;
        let receipt = executed.into_receipt();
        units_used = units_used
            .checked_add(receipt.fee_summary.units_consumed.get())
            .ok_or(BlockV4ExecutionError::BlockUnitsExceeded)?;
        if units_used > config.fee_policy.max_block_units {
            return Err(BlockV4ExecutionError::BlockUnitsExceeded);
        }
        receipts.push(receipt);
    }

    // Protocol-2 currently prices its complete action program at the shared
    // block base rate. The empty namespace map makes that explicit; localized
    // multi-action pricing needs a separately versioned receipt rule rather
    // than silently inventing one rate for several namespaces here.
    next_state.finish_block(units_used, &BTreeMap::new(), config)?;
    next_state.last_block_timestamp_ms = input.timestamp_ms;

    let blocks_per_epoch = config.staking.blocks_per_epoch;
    if blocks_per_epoch != 0 && input.height.get().is_multiple_of(blocks_per_epoch) {
        next_state.distribute_epoch_rewards(config)?;
    }
    let next_epoch = Epoch::new(next_state.current_epoch);
    let next_authority_set =
        derive_next_authority_set(&next_state, &input, current_authority_set, next_epoch)?;
    if declared_next_authority_set.is_some_and(|declared| declared != &next_authority_set) {
        return Err(BlockV4ExecutionError::NextAuthoritySetMismatch);
    }
    if !next_state.supply_invariant_report()?.balanced {
        return Err(BlockV4ExecutionError::State(
            ChainError::SupplyInvariantViolation,
        ));
    }

    let header = BlockHeaderV4 {
        protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
        chain_id: input.chain_id,
        height: input.height,
        epoch: input.epoch,
        previous_hash: input.previous_hash,
        state_root: next_state.state_root()?,
        account_root: next_state.account_root()?,
        tx_root: transaction_root_v1(input.height, &transactions)?,
        receipt_root: receipt_root_v1(&receipts)?,
        evidence_root: evidence_commitment,
        finality_authority_set_root: current_authority_set.commitment()?,
        next_finality_authority_set_root: next_authority_set.commitment()?,
        proposer: input.proposer,
        timestamp_ms: input.timestamp_ms,
        base_fee_per_unit: base_fee_for_block,
    };
    let block = BlockV4 {
        header,
        transactions,
        receipts,
        evidence,
    };
    block.validate()?;
    let actual_bytes = u64::try_from(canonical_json_bytes(&block)?.len())
        .map_err(|_| BlockV4ExecutionError::BlockTooLarge)?;
    if actual_bytes > byte_limit {
        return Err(BlockV4ExecutionError::BlockTooLarge);
    }
    Ok((block, next_state, next_authority_set))
}

fn validate_block_context(
    state: &ChainState,
    config: &ChainConfig,
    input: &BlockBuildInputV1,
    current_authority_set: &FinalityAuthoritySetV1,
) -> Result<(), BlockV4ExecutionError> {
    if config.protocol_version != TRANSACTION_V5_PROTOCOL_VERSION
        || state.protocol_version != TRANSACTION_V5_PROTOCOL_VERSION
        || config.chain_id != state.chain_id
        || input.chain_id != state.chain_id
    {
        return Err(BlockV4ExecutionError::ConfigurationMismatch);
    }
    let expected_height = BlockHeight::new(
        state
            .current_height
            .checked_add(1)
            .ok_or(BlockV4ExecutionError::HeightExhausted)?,
    );
    if input.height != expected_height {
        return Err(BlockV4ExecutionError::NonContiguousHeight {
            expected: expected_height,
            actual: input.height,
        });
    }
    let expected_epoch = Epoch::new(state.current_epoch);
    if input.epoch != expected_epoch {
        return Err(BlockV4ExecutionError::EpochMismatch {
            expected: expected_epoch,
            actual: input.epoch,
        });
    }
    if input.timestamp_ms <= state.last_block_timestamp_ms {
        return Err(BlockV4ExecutionError::NonMonotonicTimestamp);
    }
    current_authority_set.validate()?;
    if current_authority_set.protocol_version != TRANSACTION_V5_PROTOCOL_VERSION
        || current_authority_set.chain_id != input.chain_id
        || current_authority_set.epoch != input.epoch
    {
        return Err(BlockV4ExecutionError::CurrentAuthoritySetMismatch);
    }
    if !current_authority_set
        .authorities
        .iter()
        .any(|authority| authority.validator_id.operator() == input.proposer)
    {
        return Err(BlockV4ExecutionError::ProposerNotAuthority);
    }
    Ok(())
}

fn validate_declared_next_authority_set(
    config: &ChainConfig,
    input: &BlockBuildInputV1,
    current_authority_set: &FinalityAuthoritySetV1,
    next_authority_set: &FinalityAuthoritySetV1,
) -> Result<(), BlockV4ExecutionError> {
    next_authority_set.validate()?;
    let crosses_epoch = config.staking.blocks_per_epoch != 0
        && input
            .height
            .get()
            .is_multiple_of(config.staking.blocks_per_epoch);
    let expected_epoch = if crosses_epoch {
        input
            .epoch
            .checked_next()
            .ok_or(BlockV4ExecutionError::NextAuthoritySetMismatch)?
    } else {
        input.epoch
    };
    if next_authority_set.protocol_version != TRANSACTION_V5_PROTOCOL_VERSION
        || next_authority_set.chain_id != input.chain_id
        || next_authority_set.epoch != expected_epoch
        || (!crosses_epoch && next_authority_set != current_authority_set)
    {
        return Err(BlockV4ExecutionError::NextAuthoritySetMismatch);
    }
    Ok(())
}

fn derive_next_authority_set(
    next_state: &ChainState,
    input: &BlockBuildInputV1,
    current_authority_set: &FinalityAuthoritySetV1,
    next_epoch: Epoch,
) -> Result<FinalityAuthoritySetV1, BlockV4ExecutionError> {
    if next_epoch == input.epoch {
        return Ok(current_authority_set.clone());
    }
    if input.epoch.checked_next() != Some(next_epoch) {
        return Err(BlockV4ExecutionError::NextAuthoritySetMismatch);
    }
    FinalityAuthoritySetV1::from_validator_set(
        TRANSACTION_V5_PROTOCOL_VERSION,
        input.chain_id.clone(),
        next_epoch,
        &ValidatorSet::from_state(next_state)?,
    )
    .map_err(BlockV4ExecutionError::from)
}

fn preflight_body_size(
    transactions: &[TransactionV5],
    evidence: &[SlashingEvidence],
    maximum: u64,
) -> Result<(), BlockV4ExecutionError> {
    let mut bytes = 0_u64;
    for transaction in transactions {
        let encoded = canonical_json_bytes(transaction)?;
        let length =
            u64::try_from(encoded.len()).map_err(|_| BlockV4ExecutionError::BlockTooLarge)?;
        bytes = bytes
            .checked_add(length)
            .ok_or(BlockV4ExecutionError::BlockTooLarge)?;
        if bytes > maximum {
            return Err(BlockV4ExecutionError::BlockTooLarge);
        }
    }
    for item in evidence {
        let encoded = canonical_json_bytes(item)?;
        let length =
            u64::try_from(encoded.len()).map_err(|_| BlockV4ExecutionError::BlockTooLarge)?;
        bytes = bytes
            .checked_add(length)
            .ok_or(BlockV4ExecutionError::BlockTooLarge)?;
        if bytes > maximum {
            return Err(BlockV4ExecutionError::BlockTooLarge);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActionV1, Amount, AuthorizationLaneId, AuthorizationPolicyRevision, FeeBid, FeePaymentV1,
        GenesisAccount, GenesisConfig, GenesisValidator, Nonce, Operation, ReceiptStatusV1,
        TransactionAuthorizationV1, ValidityWindowV1,
    };
    use webc_crypto::Keypair;

    struct Fixture {
        config: ChainConfig,
        state: ChainState,
        validator: Keypair,
        alice: Keypair,
        bob: Keypair,
        recipient: Keypair,
    }

    fn fixture() -> Fixture {
        let validator = Keypair::from_seed([0x11; 32]);
        let alice = Keypair::from_seed([0x12; 32]);
        let bob = Keypair::from_seed([0x13; 32]);
        let recipient = Keypair::from_seed([0x14; 32]);
        let config = ChainConfig {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            ..ChainConfig::default()
        };
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![
                GenesisAccount {
                    address: validator.address(),
                    balance: Amount::from_webc(1_000),
                },
                GenesisAccount {
                    address: alice.address(),
                    balance: Amount::from_webc(1_000),
                },
                GenesisAccount {
                    address: bob.address(),
                    balance: Amount::from_webc(1_000),
                },
                GenesisAccount {
                    address: recipient.address(),
                    balance: Amount::from_webc(1),
                },
            ],
            validators: vec![GenesisValidator {
                operator: validator.address(),
                consensus_key: validator.public_key(),
                self_stake: Amount::from_webc(100),
                commission_bps: 500,
                bootstrap: false,
            }],
        };
        let state = ChainState::from_genesis_v1(&genesis).expect("protocol-2 genesis builds");
        Fixture {
            config,
            state,
            validator,
            alice,
            bob,
            recipient,
        }
    }

    fn authority_set(state: &ChainState, epoch: Epoch) -> FinalityAuthoritySetV1 {
        FinalityAuthoritySetV1::from_validator_set(
            TRANSACTION_V5_PROTOCOL_VERSION,
            state.chain_id.clone(),
            epoch,
            &ValidatorSet::from_state(state).expect("fixture validator snapshot builds"),
        )
        .expect("fixture authority set builds")
    }

    fn input(state: &ChainState, proposer: Address) -> BlockBuildInputV1 {
        BlockBuildInputV1 {
            chain_id: state.chain_id.clone(),
            height: BlockHeight::new(state.current_height + 1),
            epoch: Epoch::new(state.current_epoch),
            previous_hash: Hash256([0x41; 32]),
            proposer,
            timestamp_ms: state.last_block_timestamp_ms + 1,
        }
    }

    fn transfer(sender: &Keypair, recipient: Address, nonce: u64, amount: Amount) -> TransactionV5 {
        let action = ActionV1::native(Operation::Transfer {
            to: recipient,
            amount,
        });
        let mut transaction = TransactionV5::for_actions_unsigned(
            ChainId::devnet(),
            sender.address(),
            sender.public_key(),
            TransactionAuthorizationV1 {
                lane: AuthorizationLaneId::DEFAULT,
                policy_revision: AuthorizationPolicyRevision::new(0),
                nonce: Nonce::new(nonce),
            },
            ValidityWindowV1::new(BlockHeight::new(1), BlockHeight::new(20)),
            vec![action.clone()],
            FeeBid {
                gas_limit: action.required_units(),
                max_fee_per_unit: 5,
                priority_fee_per_unit: 1,
            },
            FeePaymentV1::SenderLane,
        )
        .expect("fixture V5 transaction builds");
        transaction
            .sign(sender)
            .expect("fixture V5 transaction signs");
        transaction
    }

    #[test]
    fn chargeable_failure_is_followed_by_success_and_replays_identically() {
        let Fixture {
            config,
            state,
            validator,
            alice,
            bob,
            recipient,
        } = fixture();
        let authority = authority_set(&state, Epoch::new(0));
        let failing = transfer(&alice, recipient.address(), 0, Amount::from_webc(2_000));
        let succeeding = transfer(&bob, recipient.address(), 0, Amount::from_units(1));
        let original = state.clone();
        let mut producer = state;
        let block = build_block_v4(
            &mut producer,
            &config,
            input(&original, validator.address()),
            vec![failing, succeeding],
            Vec::new(),
            &authority,
            &authority,
        )
        .expect("chargeable failure remains an includable receipt");

        assert!(matches!(
            block.receipts[0].status,
            ReceiptStatusV1::Failed { .. }
        ));
        assert!(block.receipts[0].events.is_empty());
        assert_eq!(block.receipts[0].position.transaction_index.get(), 0);
        assert_eq!(block.receipts[1].status, ReceiptStatusV1::Succeeded);
        assert_eq!(block.receipts[1].position.transaction_index.get(), 1);
        assert_eq!(producer.accounts[&alice.address()].nonce, 1);
        assert_eq!(producer.accounts[&bob.address()].nonce, 1);
        assert_eq!(
            producer.accounts[&recipient.address()].balance,
            original.accounts[&recipient.address()]
                .balance
                .checked_add(Amount::from_units(1))
                .expect("recipient balance does not overflow")
        );

        let mut importer = original;
        apply_block_v4(&mut importer, &config, &block, &authority, &authority)
            .expect("independent replay accepts exact block");
        assert_eq!(importer, producer);
    }

    #[test]
    fn later_invalid_transaction_rolls_back_the_complete_block() {
        let Fixture {
            config,
            mut state,
            validator,
            alice,
            recipient,
            ..
        } = fixture();
        let authority = authority_set(&state, Epoch::new(0));
        let before = state.clone();
        let valid = transfer(&alice, recipient.address(), 0, Amount::from_units(1));
        let nonce_gap = transfer(&alice, recipient.address(), 2, Amount::from_units(1));

        let error = build_block_v4(
            &mut state,
            &config,
            input(&before, validator.address()),
            vec![valid, nonce_gap],
            Vec::new(),
            &authority,
            &authority,
        )
        .expect_err("later nonce gap invalidates the full block");
        assert!(matches!(
            error,
            BlockV4ExecutionError::TransactionPreparation { index: 1, .. }
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn tampered_header_is_rejected_without_mutating_importer() {
        let Fixture {
            config,
            state,
            validator,
            alice,
            recipient,
            ..
        } = fixture();
        let authority = authority_set(&state, Epoch::new(0));
        let original = state.clone();
        let mut producer = state;
        let mut block = build_block_v4(
            &mut producer,
            &config,
            input(&original, validator.address()),
            vec![transfer(
                &alice,
                recipient.address(),
                0,
                Amount::from_units(1),
            )],
            Vec::new(),
            &authority,
            &authority,
        )
        .expect("valid block builds");
        block.header.state_root = Hash256([0x99; 32]);

        let mut importer = original.clone();
        assert!(matches!(
            apply_block_v4(&mut importer, &config, &block, &authority, &authority),
            Err(BlockV4ExecutionError::ImportedBlockMismatch)
        ));
        assert_eq!(importer, original);
    }

    #[test]
    fn metadata_authority_and_final_size_fail_closed() {
        let Fixture {
            config,
            state,
            validator,
            alice,
            recipient,
            ..
        } = fixture();
        let authority = authority_set(&state, Epoch::new(0));

        let mut wrong_height_state = state.clone();
        let mut wrong_height = input(&state, validator.address());
        wrong_height.height = BlockHeight::new(2);
        assert!(matches!(
            build_block_v4(
                &mut wrong_height_state,
                &config,
                wrong_height,
                Vec::new(),
                Vec::new(),
                &authority,
                &authority
            ),
            Err(BlockV4ExecutionError::NonContiguousHeight { .. })
        ));
        assert_eq!(wrong_height_state, state);

        let mut outsider_state = state.clone();
        assert!(matches!(
            build_block_v4(
                &mut outsider_state,
                &config,
                input(&state, recipient.address()),
                Vec::new(),
                Vec::new(),
                &authority,
                &authority
            ),
            Err(BlockV4ExecutionError::ProposerNotAuthority)
        ));
        assert_eq!(outsider_state, state);

        let mut stale_time_state = state.clone();
        let mut stale_time = input(&state, validator.address());
        stale_time.timestamp_ms = state.last_block_timestamp_ms;
        assert!(matches!(
            build_block_v4(
                &mut stale_time_state,
                &config,
                stale_time,
                Vec::new(),
                Vec::new(),
                &authority,
                &authority
            ),
            Err(BlockV4ExecutionError::NonMonotonicTimestamp)
        ));
        assert_eq!(stale_time_state, state);

        let duplicate = transfer(&alice, recipient.address(), 0, Amount::from_units(1));
        let mut duplicate_state = state.clone();
        assert!(matches!(
            build_block_v4(
                &mut duplicate_state,
                &config,
                input(&state, validator.address()),
                vec![duplicate.clone(), duplicate],
                Vec::new(),
                &authority,
                &authority
            ),
            Err(BlockV4ExecutionError::DuplicateTransaction)
        ));
        assert_eq!(duplicate_state, state);

        let wrong_next = authority_set(&state, Epoch::new(1));
        let mut wrong_next_state = state.clone();
        assert!(matches!(
            build_block_v4(
                &mut wrong_next_state,
                &config,
                input(&state, validator.address()),
                Vec::new(),
                Vec::new(),
                &authority,
                &wrong_next
            ),
            Err(BlockV4ExecutionError::NextAuthoritySetMismatch)
        ));
        assert_eq!(wrong_next_state, state);

        let tiny_config = ChainConfig {
            max_block_bytes: 1,
            ..config
        };
        let mut undersized_state = state.clone();
        assert!(matches!(
            build_block_v4(
                &mut undersized_state,
                &tiny_config,
                input(&state, validator.address()),
                Vec::new(),
                Vec::new(),
                &authority,
                &authority
            ),
            Err(BlockV4ExecutionError::BlockTooLarge)
        ));
        assert_eq!(undersized_state, state);
    }

    #[test]
    fn epoch_boundary_binds_the_deterministic_next_authority_set() {
        let Fixture {
            mut config,
            state,
            validator,
            ..
        } = fixture();
        config.staking.blocks_per_epoch = 1;
        let current = authority_set(&state, Epoch::new(0));
        let next = authority_set(&state, Epoch::new(1));
        let block_input = input(&state, validator.address());
        let mut producer = state;

        let built = build_block_v4_with_derived_authority(
            &mut producer,
            &config,
            block_input,
            Vec::new(),
            Vec::new(),
            &current,
        )
        .expect("epoch boundary builds with next snapshot");
        assert_eq!(producer.current_epoch, 1);
        assert_eq!(built.next_authority_set, next);
        assert_eq!(
            built.block.header.next_finality_authority_set_root,
            next.commitment().expect("next commitment")
        );
    }
}
