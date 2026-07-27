//! Repeatable developer benchmark for finalized transaction-proof assembly.
//!
//! Purpose: measure the node's complete durable-block lookup, Merkle-path
//! construction, and self-verification cost as block occupancy grows.
//! Responsibilities: build one deterministic certified V4 block, warm the
//! proof path, time repeated proofs, and report serialized sizes plus a
//! conservative hash-workspace bound. Non-responsibilities: publishable TPS,
//! consensus timing, network latency, allocator profiling, or state mutation
//! during measurement. Data flow: deterministic keys create sequential V5
//! transfers; a memory-backed node finalizes one block and repeatedly proves
//! its middle transaction. Security boundary: CLI counts are bounded before
//! allocation, and this developer-only module never handles production keys.

use std::hint::black_box;
use std::mem::size_of;
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};
use webc_chain::{
    ActionV1, Amount, AuthorizationLaneId, AuthorizationPolicyRevision, BlockHeight, ChainConfig,
    ChainId, ChainState, FeeBid, FeePaymentV1, FinalityCertificate, GenesisAccount, GenesisConfig,
    GenesisValidator, Nonce, Operation, SignedVote, TransactionAuthorizationV1, TransactionId,
    TransactionV5, ValidatorSet, ValidityWindowV1, Vote, VoteType, MAX_BLOCK_V4_TRANSACTIONS,
    TRANSACTION_V5_PROTOCOL_VERSION,
};
use webc_crypto::{Hash256, Keypair};
use webc_node::{FinalizedTransactionProofBundleV1, Node};
use webc_storage::MemoryKvStore;

/// Runs the indicative finalized-proof benchmark.
///
/// `transaction_count` is the number of sequential transfers in the single
/// finalized block (1..=8192). `iterations` is the number of timed, independent
/// proof assemblies after one warm-up call and must be non-zero. Results are for
/// local engineering decisions only, never a network performance claim.
pub(crate) fn run(transaction_count: u32, iterations: u32) -> Result<()> {
    let fixture = ProofBenchmarkFixture::build(transaction_count)?;
    ensure!(iterations > 0, "iterations must be non-zero");

    let warm = fixture.prove()?;
    let proof_json_bytes = serde_json::to_vec(&warm)
        .context("serialize the representative proof response")?
        .len();

    let start = Instant::now();
    for _ in 0..iterations {
        black_box(fixture.prove()?);
    }
    let elapsed = start.elapsed();
    let average = elapsed / iterations;

    println!("Indicative finalized-proof benchmark -- NOT a performance claim.");
    println!("Run release builds on a documented reference machine before publishing numbers.");
    println!(
        "transactions in finalized block: {}",
        fixture.transaction_count
    );
    println!(
        "serialized block bytes:          {}",
        fixture.block_json_bytes
    );
    println!("serialized proof bytes:          {proof_json_bytes}");
    println!(
        "hash workspace upper bound:      {} bytes",
        fixture.hash_workspace_upper_bound
    );
    println!("timed proof assemblies:          {iterations}");
    println!(
        "total:                           {}",
        display_duration(elapsed)
    );
    println!(
        "average:                         {}",
        display_duration(average)
    );
    Ok(())
}

/// Deterministic finalized block retained across timed proof calls.
struct ProofBenchmarkFixture {
    node: Node<MemoryKvStore>,
    transaction_id: TransactionId,
    checkpoint_height: BlockHeight,
    transaction_count: usize,
    block_json_bytes: usize,
    hash_workspace_upper_bound: usize,
}

impl ProofBenchmarkFixture {
    /// Builds and certifies one maximum-shape sequential-transfer block.
    fn build(transaction_count: u32) -> Result<Self> {
        let transaction_count = usize::try_from(transaction_count)
            .context("transaction count is not representable on this host")?;
        ensure!(
            (1..=MAX_BLOCK_V4_TRANSACTIONS).contains(&transaction_count),
            "transaction-count must be in 1..={MAX_BLOCK_V4_TRANSACTIONS}"
        );

        let validator = Keypair::from_seed([0xb1; 32]);
        let recipient = Keypair::from_seed([0xb2; 32]);
        let genesis = GenesisConfig {
            chain: ChainConfig {
                protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
                ..ChainConfig::default()
            },
            accounts: vec![GenesisAccount {
                address: validator.address(),
                balance: Amount::from_webc(1_000),
            }],
            validators: vec![GenesisValidator {
                operator: validator.address(),
                consensus_key: validator.public_key(),
                self_stake: Amount::from_webc(100),
                commission_bps: 500,
                bootstrap: false,
            }],
        };
        let mut node =
            Node::open(MemoryKvStore::new(), &genesis).context("open benchmark protocol-2 node")?;

        let mut transactions = Vec::with_capacity(transaction_count);
        for index in 0..transaction_count {
            let nonce = u64::try_from(index).context("transaction nonce does not fit u64")?;
            transactions.push(signed_transfer(&validator, &recipient, nonce)?);
        }
        let target_index = transaction_count / 2;
        let transaction_id = transactions[target_index]
            .transaction_id()
            .context("derive target transaction identity")?;
        let built = node
            .build_candidate_v4(transactions, Vec::new(), validator.address(), 1)
            .context("build benchmark V4 block")?;
        let block_json_bytes = serde_json::to_vec(&built.block)
            .context("serialize benchmark V4 block")?
            .len();
        let certificate = certificate_for(&genesis, &validator, &built.block)?;
        let checkpoint_height = built.block.header.height;
        node.import_finalized_block_v4(built.block, &built.next_authority_set, &certificate)
            .context("finalize benchmark V4 block")?;

        // During either path build, two persistent leaf arrays plus the current
        // and next Merkle layers stay below four hashes per transaction. This
        // intentionally excludes the retained block itself, reported above.
        let hash_workspace_upper_bound = transaction_count
            .checked_mul(4)
            .and_then(|count| count.checked_mul(size_of::<Hash256>()))
            .context("hash workspace bound overflow")?;
        Ok(Self {
            node,
            transaction_id,
            checkpoint_height,
            transaction_count,
            block_json_bytes,
            hash_workspace_upper_bound,
        })
    }

    /// Builds and self-verifies one proof from the retained durable block.
    fn prove(&self) -> Result<FinalizedTransactionProofBundleV1> {
        self.node
            .finalized_transaction_proof_v1(self.transaction_id, self.checkpoint_height)
            .context("assemble finalized transaction proof")?
            .context("benchmark transaction unexpectedly lacks a finalized proof")
    }
}

/// Produces one signed sequential transfer for the benchmark block.
fn signed_transfer(sender: &Keypair, recipient: &Keypair, nonce: u64) -> Result<TransactionV5> {
    let mut transaction = TransactionV5::for_actions_unsigned(
        ChainId::devnet(),
        sender.address(),
        sender.public_key(),
        TransactionAuthorizationV1 {
            lane: AuthorizationLaneId::DEFAULT,
            policy_revision: AuthorizationPolicyRevision::new(0),
            nonce: Nonce::new(nonce),
        },
        ValidityWindowV1::new(BlockHeight::new(1), BlockHeight::new(1)),
        vec![ActionV1::native(Operation::Transfer {
            to: recipient.address(),
            amount: Amount::from_units(1),
        })],
        FeeBid {
            gas_limit: 1_000,
            max_fee_per_unit: 5,
            priority_fee_per_unit: 1,
        },
        FeePaymentV1::SenderLane,
    )
    .context("construct benchmark transaction")?;
    transaction
        .sign(sender)
        .context("sign benchmark transaction")?;
    Ok(transaction)
}

/// Builds the single-validator certificate for the deterministic fixture.
fn certificate_for(
    genesis: &GenesisConfig,
    validator: &Keypair,
    block: &webc_chain::BlockV4,
) -> Result<FinalityCertificate> {
    let state = ChainState::from_genesis_v1(genesis).context("build benchmark genesis state")?;
    let validator_set =
        ValidatorSet::from_state(&state).context("derive benchmark validator set")?;
    let block_hash = block.hash().context("hash benchmark block")?;
    let vote = SignedVote::sign(
        Vote {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            chain_id: genesis.chain.chain_id.clone(),
            height: block.header.height.get(),
            round: 0,
            vote_type: VoteType::Precommit,
            block_hash,
            validator: validator.address(),
        },
        validator,
    )
    .context("sign benchmark finality vote")?;
    FinalityCertificate::build(
        &validator_set,
        TRANSACTION_V5_PROTOCOL_VERSION,
        genesis.chain.chain_id.clone(),
        block.header.height.get(),
        0,
        block_hash,
        &[vote],
    )
    .context("build benchmark finality certificate")
}

/// Formats durations without implying more precision than the local clock.
fn display_duration(duration: Duration) -> String {
    if duration.as_millis() > 0 {
        format!("{:.3} ms", duration.as_secs_f64() * 1_000.0)
    } else {
        format!("{:.3} us", duration.as_secs_f64() * 1_000_000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_fixture_exercises_the_complete_proof_path() {
        let fixture = ProofBenchmarkFixture::build(4).expect("small fixture builds");
        let proof = fixture.prove().expect("small fixture proves");
        assert_eq!(proof.proof.target_header.height, BlockHeight::new(1));
        assert_eq!(proof.proof.transaction_proof.leaf_count.get(), 4);
    }
}
