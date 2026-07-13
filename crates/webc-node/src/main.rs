use anyhow::Result;
use clap::{Parser, Subcommand};
use webc_chain::{
    build_block, Amount, BlockBuildInput, ChainConfig, ChainState, FeeBid, GenesisAccount,
    GenesisConfig, Operation, Transaction,
};
use webc_crypto::{Hash256, Keypair, PublicKeyBytes};

#[derive(Parser)]
#[command(name = "webc-node")]
#[command(about = "WEBC prototype node/demo CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a fresh in-memory keypair and print its public identity.
    Keygen,
    /// Print a commented genesis template as JSON.
    GenesisTemplate,
    /// Run a deterministic local chain demo: transfer, validator registration, delegation, rewards.
    Demo,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen => keygen(),
        Command::GenesisTemplate => genesis_template(),
        Command::Demo => demo(),
    }
}

fn keygen() -> Result<()> {
    let keypair = Keypair::generate();
    println!("WEBC address: {}", keypair.address());
    println!("Ed25519 public key: {}", keypair.public_key().to_hex());
    println!("\nPrivate keys are intentionally not printed by this prototype command.");
    Ok(())
}

fn genesis_template() -> Result<()> {
    let faucet = Keypair::from_seed([1u8; 32]);
    let validator = Keypair::from_seed([2u8; 32]);
    let config = sample_genesis(&faucet, &validator);
    println!("{}", serde_json::to_string_pretty(&config)?);
    Ok(())
}

fn demo() -> Result<()> {
    let alice = Keypair::from_seed([1u8; 32]);
    let bob = Keypair::from_seed([2u8; 32]);
    let validator = Keypair::from_seed([3u8; 32]);

    let genesis = sample_genesis(&alice, &validator);
    let config = genesis.chain.clone();
    let mut state = ChainState::from_genesis(&genesis)?;

    let transfer = Transaction::for_operation(
        &alice,
        0,
        Operation::Transfer {
            to: bob.address(),
            amount: Amount::from_webc(25),
        },
        FeeBid {
            gas_limit: 1_000,
            max_fee_per_unit: 1,
            priority_fee_per_unit: 0,
        },
    )?;

    let register_validator = Transaction::for_operation(
        &validator,
        0,
        Operation::RegisterValidator {
            consensus_key: PublicKeyBytes([42u8; 32]),
            self_stake: Amount::from_webc(20),
            commission_bps: 500,
            bootstrap: false,
        },
        FeeBid {
            gas_limit: 30_000,
            max_fee_per_unit: 1,
            priority_fee_per_unit: 0,
        },
    )?;

    let delegate = Transaction::for_operation(
        &alice,
        1,
        Operation::Delegate {
            validator: validator.address(),
            amount: Amount::from_webc(80),
        },
        FeeBid {
            gas_limit: 15_000,
            max_fee_per_unit: 1,
            priority_fee_per_unit: 0,
        },
    )?;

    let block1 = build_block(
        &mut state,
        &config,
        BlockBuildInput {
            chain_id: config.chain_id.clone(),
            height: 1,
            epoch: 0,
            previous_hash: Hash256::ZERO,
            proposer: validator.address(),
            timestamp_ms: 1_700_000_000_000,
        },
        vec![transfer, register_validator, delegate],
        Vec::new(),
    )?;

    let reward_events = state.distribute_epoch_rewards(&config)?;

    let claim_validator_rewards = Transaction::for_operation(
        &validator,
        1,
        Operation::ClaimValidatorRewards,
        FeeBid {
            gas_limit: 10_000,
            max_fee_per_unit: state.current_base_fee_per_unit,
            priority_fee_per_unit: 0,
        },
    )?;
    let claim_delegator_rewards = Transaction::for_operation(
        &alice,
        2,
        Operation::ClaimDelegatorRewards {
            validator: validator.address(),
        },
        FeeBid {
            gas_limit: 10_000,
            max_fee_per_unit: state.current_base_fee_per_unit,
            priority_fee_per_unit: 0,
        },
    )?;

    let block1_hash = block1.hash()?;
    let block2_epoch = state.current_epoch;

    let block2 = build_block(
        &mut state,
        &config,
        BlockBuildInput {
            chain_id: config.chain_id.clone(),
            height: 2,
            epoch: block2_epoch,
            previous_hash: block1_hash,
            proposer: validator.address(),
            timestamp_ms: 1_700_000_001_000,
        },
        vec![claim_validator_rewards, claim_delegator_rewards],
        Vec::new(),
    )?;

    let bob_proof = state
        .account_state_proof(bob.address())?
        .expect("Bob should exist after the demo transfer");
    let bob_proof_valid = bob_proof.verify()?;

    let summary = serde_json::json!({
        "chain_id": config.chain_id,
        "blocks": [
            {
                "hash": block1_hash.to_string(),
                "header": &block1.header,
                "receipt_count": block1.receipts.len(),
            },
            {
                "hash": block2.hash()?.to_string(),
                "header": &block2.header,
                "receipt_count": block2.receipts.len(),
            }
        ],
        "alice": {
            "address": alice.address().to_string(),
            "account": state.accounts.get(&alice.address()),
        },
        "bob": {
            "address": bob.address().to_string(),
            "account": state.accounts.get(&bob.address()),
            "account_proof_valid": bob_proof_valid,
            "account_proof": bob_proof,
        },
        "validator": {
            "address": validator.address().to_string(),
            "account": state.accounts.get(&validator.address()),
            "validator_state": state.validators.get(&validator.address()),
        },
        "burned_fees": state.burned_fees,
        "validator_fee_pool": state.validator_fee_pool,
        "minted_supply": state.minted_supply,
        "account_root": state.account_root()?.to_string(),
        "state_root": state.state_root()?.to_string(),
        "block1_receipts": &block1.receipts,
        "block2_receipts": &block2.receipts,
        "reward_events": reward_events,
        "note": "This is a local deterministic prototype, not a networked production node."
    });

    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

fn sample_genesis(faucet: &Keypair, validator: &Keypair) -> GenesisConfig {
    GenesisConfig {
        chain: ChainConfig::default(),
        accounts: vec![
            GenesisAccount {
                address: faucet.address(),
                balance: Amount::from_webc(1_000_000),
            },
            GenesisAccount {
                address: validator.address(),
                balance: Amount::from_webc(1_000),
            },
        ],
        validators: Vec::new(),
    }
}

#[allow(dead_code)]
fn genesis_previous_hash() -> Hash256 {
    Hash256::ZERO
}
