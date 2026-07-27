mod proof_bench;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use webc_chain::{
    build_block, Amount, BlockBuildInput, ChainConfig, ChainState, FeeBid, GenesisAccount,
    GenesisConfig, GenesisValidator, Operation, Transaction, GENESIS_TOTAL_SUPPLY,
};
use webc_crypto::{Address, Hash256, Keypair, PublicKeyBytes};
use webc_net::{spawn_network, NetworkConfig};
use webc_node::{
    run_gossip_pump, start_protocol2, AppState, FaucetConfig, MempoolConfig, Node, NodeService,
    NodeServiceOptions, Protocol2RunConfig,
};
use webc_storage::{MemoryKvStore, RedbKvStore};

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
    /// Micro-benchmark ML-DSA-65 vs Ed25519 sign/verify (indicative ratio only).
    Bench {
        /// Iterations per measured operation.
        #[arg(long, default_value_t = 300)]
        iterations: u32,
    },
    /// Benchmark finalized V5 transaction-proof assembly (indicative only).
    ProofBench {
        /// Sequential transfers in the single finalized V4 block (1..=8192).
        #[arg(long, default_value_t = 1_750)]
        transactions: u32,
        /// Timed proof assemblies after one warm-up call.
        #[arg(long, default_value_t = 20)]
        iterations: u32,
    },
    /// Run a restartable devnet node serving the HTTP/WebSocket developer API.
    Run {
        /// Directory holding the durable redb database (created if absent).
        #[arg(long, default_value = "./webc-data")]
        data_dir: PathBuf,
        /// Address to bind the HTTP/WebSocket API to.
        #[arg(long, default_value = "127.0.0.1:8645")]
        listen: String,
        /// Optional address to listen on for peer-to-peer connections. When set
        /// (or when --peer is given), the node joins the gossip network.
        #[arg(long)]
        p2p_listen: Option<String>,
        /// Peer address to dial and gossip with (repeatable).
        #[arg(long = "peer")]
        peers: Vec<String>,
        /// Protocol-2 genesis JSON. When present, `run` starts the V5/V4
        /// transaction, actor, consensus, sync, and `/v2` stack instead of the
        /// frozen legacy development auto-sealer.
        #[arg(long)]
        protocol2_genesis: Option<PathBuf>,
        /// Protected protocol-2 validator credential JSON. Omit to run as a
        /// non-voting observer. The seed is read only from this file.
        #[arg(long, requires = "protocol2_genesis")]
        validator_key_file: Option<PathBuf>,
    },
    /// Register the local devnet key as a validator (drives Operation::RegisterValidator).
    StakeRegister {
        /// Operator self-stake in whole WEBC (must meet the chain minimum).
        #[arg(long, default_value_t = 20)]
        self_stake: u64,
        /// Validator commission in basis points (0..=max_commission_bps).
        #[arg(long, default_value_t = 500)]
        commission_bps: u16,
        /// Optional 32-byte hex seed for the local key (defaults to a fixed devnet seed).
        #[arg(long)]
        seed: Option<String>,
    },
    /// Delegate whole WEBC from the local key to a validator (drives Operation::Delegate).
    StakeDelegate {
        /// Amount to delegate, in whole WEBC.
        #[arg(long, default_value_t = 10)]
        amount: u64,
        /// Target validator operator address (defaults to the demo's local validator).
        #[arg(long)]
        validator: Option<String>,
        /// Optional 32-byte hex seed for the local key.
        #[arg(long)]
        seed: Option<String>,
    },
    /// Begin undelegation of whole WEBC from a validator (drives Operation::Undelegate).
    StakeUndelegate {
        /// Amount to begin undelegating, in whole WEBC.
        #[arg(long, default_value_t = 10)]
        amount: u64,
        /// Target validator operator address (defaults to the demo's local validator).
        #[arg(long)]
        validator: Option<String>,
        /// Optional 32-byte hex seed for the local key.
        #[arg(long)]
        seed: Option<String>,
    },
    /// Claim validator and/or delegator rewards (drives the Claim* operations).
    StakeClaim {
        /// Claim accumulated operator rewards for the local validator.
        #[arg(long)]
        validator_rewards: bool,
        /// Claim accumulated delegator rewards for the local delegation.
        #[arg(long)]
        delegator_rewards: bool,
        /// Validator the delegator-reward claim targets (defaults to the demo validator).
        #[arg(long)]
        validator: Option<String>,
        /// Optional 32-byte hex seed for the local key.
        #[arg(long)]
        seed: Option<String>,
    },
    /// Faucet-drip the local key then delegate in one flow (drives faucet + Operation::Delegate).
    FaucetStake {
        /// Amount to delegate from the freshly dripped funds, in whole WEBC.
        #[arg(long, default_value_t = 10)]
        amount: u64,
        /// Optional 32-byte hex seed for the local key.
        #[arg(long)]
        seed: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen => keygen(),
        Command::GenesisTemplate => genesis_template(),
        Command::Demo => demo(),
        Command::Bench { iterations } => bench(iterations),
        Command::ProofBench {
            transactions,
            iterations,
        } => proof_bench::run(transactions, iterations),
        Command::Run {
            data_dir,
            listen,
            p2p_listen,
            peers,
            protocol2_genesis,
            validator_key_file,
        } => run(
            data_dir,
            listen,
            p2p_listen,
            peers,
            protocol2_genesis,
            validator_key_file,
        ),
        Command::StakeRegister {
            self_stake,
            commission_bps,
            seed,
        } => emit(run_stake_register(self_stake, commission_bps, seed)?),
        Command::StakeDelegate {
            amount,
            validator,
            seed,
        } => emit(run_stake_delegate(amount, validator, seed)?),
        Command::StakeUndelegate {
            amount,
            validator,
            seed,
        } => emit(run_stake_undelegate(amount, validator, seed)?),
        Command::StakeClaim {
            validator_rewards,
            delegator_rewards,
            validator,
            seed,
        } => emit(run_stake_claim(
            validator_rewards,
            delegator_rewards,
            validator,
            seed,
        )?),
        Command::FaucetStake { amount, seed } => emit(run_faucet_stake(amount, seed)?),
    }
}

/// Milliseconds since the Unix epoch, read only at the node orchestration
/// boundary (never inside a deterministic state transition).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Selects the explicit protocol-2 public stack or frozen legacy developer stack.
///
/// Supplying `protocol2_genesis` starts the single-owner V5 runtime, V4 BFT
/// consensus/state sync, and `/v2` API. Omitting it preserves the existing
/// protocol-1 auto-sealer for compatibility; it never labels itself protocol 2.
fn run(
    data_dir: PathBuf,
    listen: String,
    p2p_listen: Option<String>,
    peers: Vec<String>,
    protocol2_genesis: Option<PathBuf>,
    validator_key_file: Option<PathBuf>,
) -> Result<()> {
    if let Some(genesis_path) = protocol2_genesis {
        return run_protocol2_node(
            data_dir,
            listen,
            p2p_listen,
            peers,
            genesis_path,
            validator_key_file,
        );
    }
    run_legacy(data_dir, listen, p2p_listen, peers)
}

/// Runs the frozen protocol-1 developer API and transaction-only auto-sealer.
fn run_legacy(
    data_dir: PathBuf,
    listen: String,
    p2p_listen: Option<String>,
    peers: Vec<String>,
) -> Result<()> {
    std::fs::create_dir_all(&data_dir)?;

    // Fixed devnet faucet identity. Devnet only; these units carry no value.
    let faucet = Keypair::from_seed([7u8; 32]);
    // Devnet initializes the same 10,000,000 WEBC total as mainnet
    // (owner-confirmed 2026-07-17), held in the single valueless faucet account.
    // Pinning `expected_total_supply` makes `from_genesis` reject any allocation
    // that does not sum to the declared total (finding G1).
    let genesis = GenesisConfig {
        chain: ChainConfig {
            expected_total_supply: Some(GENESIS_TOTAL_SUPPLY),
            ..ChainConfig::default()
        },
        accounts: vec![GenesisAccount {
            address: faucet.address(),
            balance: GENESIS_TOTAL_SUPPLY,
        }],
        validators: Vec::new(),
    };
    let chain_id = genesis.chain.chain_id.clone();

    let store = RedbKvStore::open(data_dir.join("chain.redb"))?;
    let node = Node::open(store, &genesis)?;
    let service = NodeService::new(
        node,
        NodeServiceOptions {
            mempool: MempoolConfig::default(),
            faucet: Some(FaucetConfig {
                keypair: Keypair::from_seed([7u8; 32]),
                drip_amount: Amount::from_webc(100),
                cooldown_ms: 10_000,
                max_recipient_balance: Amount::from_webc(1_000),
            }),
            proposer: faucet.address(),
        },
    );

    // Parse the peer-to-peer configuration. The node joins the network if it
    // either listens for peers or is told to dial some.
    let p2p_listen_addr: Option<SocketAddr> = match &p2p_listen {
        Some(addr) => Some(addr.parse().context("invalid --p2p-listen address")?),
        None => None,
    };
    let bootstrap_peers: Vec<SocketAddr> = peers
        .iter()
        .map(|addr| addr.parse().context("invalid --peer address"))
        .collect::<Result<_>>()?;
    let networked = p2p_listen_addr.is_some() || !bootstrap_peers.is_empty();

    println!("WEBC devnet node");
    println!("  data dir:       {}", data_dir.display());
    println!("  faucet address: {}", faucet.address());
    println!("  API base:       http://{listen}/v1");
    println!("  health:         http://{listen}/v1/health");

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        // Bring up the peer-to-peer network first (if configured), so the API
        // state can gossip locally submitted transactions.
        let state = if networked {
            // A fresh random network identity per process for devnet. It names
            // this node on the wire and is distinct from any account key.
            let identity = Keypair::generate();
            let (handle, inbound) = spawn_network(NetworkConfig::new(
                identity,
                chain_id,
                p2p_listen_addr,
                bootstrap_peers,
            ))
            .await?;
            println!("  p2p identity:   {}", handle.local_peer_id());
            if let Some(addr) = handle.local_addr() {
                println!("  p2p listen:     {addr}");
            }
            let state = AppState::with_network(service, Some(handle));
            // Drain inbound gossip into the mempool.
            tokio::spawn(run_gossip_pump(state.clone(), inbound));
            state
        } else {
            AppState::new(service)
        };

        let listener = tokio::net::TcpListener::bind(&listen).await?;

        // Auto-seal pending transactions on the devnet block cadence so submitted
        // transactions reach finality without a manual seal call.
        let sealer = state.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(2));
            loop {
                ticker.tick().await;
                if let Ok(Some(_)) = sealer.service().seal_block(now_ms()) {
                    sealer.publish_tip();
                }
            }
        });

        webc_node::serve(listener, state).await?;
        Ok::<(), anyhow::Error>(())
    })
}

/// Runs the public protocol-2 actor/network/consensus/V2 API assembly.
fn run_protocol2_node(
    data_dir: PathBuf,
    listen: String,
    p2p_listen: Option<String>,
    peers: Vec<String>,
    genesis_path: PathBuf,
    validator_key_path: Option<PathBuf>,
) -> Result<()> {
    let api_listen = listen
        .parse()
        .context("invalid protocol-2 --listen address")?;
    let p2p_listen = p2p_listen
        .map(|address| {
            address
                .parse()
                .context("invalid protocol-2 --p2p-listen address")
        })
        .transpose()?;
    let bootstrap_peers = peers
        .iter()
        .map(|address| address.parse().context("invalid protocol-2 --peer address"))
        .collect::<Result<Vec<_>>>()?;
    let validator_mode = validator_key_path.is_some();
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let node = start_protocol2(Protocol2RunConfig {
            data_dir: data_dir.clone(),
            api_listen,
            p2p_listen,
            bootstrap_peers,
            genesis_path,
            validator_key_path,
        })
        .await?;
        println!("WEBC protocol-2 devnet node");
        println!(
            "  mode:           {}",
            if validator_mode {
                "validator"
            } else {
                "observer"
            }
        );
        println!("  data dir:       {}", data_dir.display());
        println!("  API base:       http://{}/v2", node.api_addr());
        println!("  health:         http://{}/v2/health", node.api_addr());
        println!("  p2p identity:   {}", node.peer_id());
        if let Some(address) = node.p2p_addr() {
            println!("  p2p listen:     {address}");
        }
        node.wait().await
    })
}

/// Prints an indicative signature micro-benchmark.
///
/// This is a developer tool, not a consensus path, so wall-clock timing is fine
/// here (deterministic state transitions never read a clock). The numbers are a
/// rough ratio for engineering intuition on the chosen host — NOT a reference
/// measurement and NOT a performance or post-quantum-security claim. Publish only
/// numbers taken on the reference machines in `docs/development-plan.md` before
/// making any claim.
fn bench(iterations: u32) -> Result<()> {
    use std::hint::black_box;
    use std::time::{Duration, Instant};
    use webc_crypto::{
        ml_dsa65_keygen, ml_dsa65_verify, verify_signature, ML_DSA_65_PUBLIC_KEY_LEN,
        ML_DSA_65_SIGNATURE_LEN,
    };

    let n = iterations.max(1);
    let message = [0x42u8; 96];

    // Ed25519 baseline.
    let ed = Keypair::generate();
    let ed_public = ed.public_key();
    let start = Instant::now();
    for _ in 0..n {
        black_box(ed.sign(black_box(&message)));
    }
    let ed_sign = start.elapsed() / n;
    let ed_signature = ed.sign(&message);
    let start = Instant::now();
    for _ in 0..n {
        black_box(verify_signature(&ed_public, black_box(&message), &ed_signature).is_ok());
    }
    let ed_verify = start.elapsed() / n;

    // ML-DSA-65 candidate.
    let start = Instant::now();
    for _ in 0..n {
        black_box(ml_dsa65_keygen()?);
    }
    let ml_keygen = start.elapsed() / n;
    let (ml_public, ml_secret) = ml_dsa65_keygen()?;
    let ml_public_bytes = ml_public.to_bytes();
    let start = Instant::now();
    for _ in 0..n {
        black_box(ml_secret.sign(black_box(&message), b"")?);
    }
    let ml_sign = start.elapsed() / n;
    let ml_signature = ml_secret.sign(&message, b"")?;
    let start = Instant::now();
    for _ in 0..n {
        black_box(
            ml_dsa65_verify(&ml_public_bytes, black_box(&message), &ml_signature, b"").is_ok(),
        );
    }
    let ml_verify = start.elapsed() / n;

    let micros = |duration: Duration| duration.as_secs_f64() * 1e6;
    println!("Indicative signature micro-benchmark — NOT a reference machine.");
    println!("Rough ratio for engineering intuition only; not a performance claim.");
    println!("iterations per measured op: {n}\n");
    println!("Ed25519    sign:   {:>10.2} us", micros(ed_sign));
    println!("Ed25519    verify: {:>10.2} us", micros(ed_verify));
    println!("ML-DSA-65  keygen: {:>10.2} us", micros(ml_keygen));
    println!("ML-DSA-65  sign:   {:>10.2} us", micros(ml_sign));
    println!("ML-DSA-65  verify: {:>10.2} us", micros(ml_verify));
    println!(
        "\nverify ratio (ML-DSA-65 / Ed25519): {:>5.1}x",
        micros(ml_verify) / micros(ed_verify).max(f64::MIN_POSITIVE)
    );
    println!(
        "sign ratio   (ML-DSA-65 / Ed25519): {:>5.1}x",
        micros(ml_sign) / micros(ed_sign).max(f64::MIN_POSITIVE)
    );
    println!(
        "\nsizes: Ed25519 pubkey 32 B, sig 64 B; \
         ML-DSA-65 pubkey {ML_DSA_65_PUBLIC_KEY_LEN} B, sig {ML_DSA_65_SIGNATURE_LEN} B"
    );
    Ok(())
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

// ---------------------------------------------------------------------------
// Devnet staking UX subcommands.
//
// These drive the existing native staking operations (RegisterValidator,
// Delegate, Undelegate, ClaimValidatorRewards, ClaimDelegatorRewards) through
// the same in-process service path the node uses: build and sign a
// `Transaction` with `Transaction::for_operation`, submit it to a
// `NodeService`, and seal a block (`NodeService::submit_and_seal`). Each command
// runs a self-contained, deterministic local devnet over in-memory storage — no
// network client, and no wall clock in the consensus path (fixed, increasing
// timestamps are supplied to sealing). Every balance here is a valueless devnet
// test unit.
// ---------------------------------------------------------------------------

/// Default deterministic seed for the CLI's local staking key (devnet only).
const DEFAULT_LOCAL_SEED: [u8; 32] = [11u8; 32];
/// Deterministic seed for the demo's target validator that local delegations,
/// undelegations, and delegator-reward claims act on (devnet only).
const TARGET_VALIDATOR_SEED: [u8; 32] = [12u8; 32];
/// Fixed devnet faucet seed, matching the `run` subcommand's valueless faucet.
const STAKE_FAUCET_SEED: [u8; 32] = [7u8; 32];
/// Fixed base block timestamp for the deterministic staking demos. Sealing is
/// fed explicit, increasing timestamps so the consensus path never reads a clock.
const STAKE_BASE_TS_MS: u64 = 1_700_000_000_000;
/// Disclaimer attached to every staking-demo summary.
const STAKE_NOTE: &str = "Local deterministic devnet demo; balances are valueless WEBC test units.";

/// Pretty-prints a command summary as JSON.
fn emit(value: serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

/// Parses a 32-byte key seed from lowercase hex (64 characters).
fn parse_seed(text: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(text.trim()).context("--seed must be hex-encoded")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("--seed must be exactly 32 bytes (64 hex characters)"))
}

/// Resolves the local staking keypair from an optional hex seed, defaulting to
/// the fixed devnet seed.
fn local_keypair(seed: Option<String>) -> Result<Keypair> {
    let seed = match seed {
        Some(text) => parse_seed(&text)?,
        None => DEFAULT_LOCAL_SEED,
    };
    Ok(Keypair::from_seed(seed))
}

/// Resolves a validator target address from an optional base58 argument,
/// defaulting to the demo's deterministic local validator.
fn resolve_validator(validator: Option<String>, default: Address) -> Result<Address> {
    match validator {
        Some(text) => text
            .trim()
            .parse::<Address>()
            .context("invalid --validator address"),
        None => Ok(default),
    }
}

/// Builds a fee bid that always clears the current base fee.
fn stake_fee(base_fee_per_unit: u64, gas_limit: u64) -> FeeBid {
    FeeBid {
        gas_limit,
        max_fee_per_unit: base_fee_per_unit.max(1),
        priority_fee_per_unit: 0,
    }
}

/// A `GenesisValidator` backed by the operator keypair's own consensus key.
fn genesis_validator(
    keypair: &Keypair,
    self_stake_webc: u64,
    commission_bps: u16,
) -> GenesisValidator {
    GenesisValidator {
        operator: keypair.address(),
        consensus_key: keypair.public_key(),
        self_stake: Amount::from_webc(self_stake_webc),
        commission_bps,
        bootstrap: false,
    }
}

/// Opens an in-memory devnet service for the staking demos.
fn open_staking_service(
    genesis: &GenesisConfig,
    faucet: Option<Keypair>,
    proposer: Address,
) -> Result<NodeService<MemoryKvStore>> {
    let node = Node::open(MemoryKvStore::new(), genesis)?;
    let faucet = faucet.map(|keypair| FaucetConfig {
        keypair,
        drip_amount: Amount::from_webc(100),
        cooldown_ms: 10_000,
        max_recipient_balance: Amount::from_webc(1_000),
    });
    Ok(NodeService::new(
        node,
        NodeServiceOptions {
            mempool: MempoolConfig::default(),
            faucet,
            proposer,
        },
    ))
}

/// `stake-register`: registers the local key as a validator.
fn run_stake_register(
    self_stake_webc: u64,
    commission_bps: u16,
    seed: Option<String>,
) -> Result<serde_json::Value> {
    let local = local_keypair(seed)?;
    let genesis = GenesisConfig {
        chain: ChainConfig::default(),
        accounts: vec![GenesisAccount {
            address: local.address(),
            balance: Amount::from_webc(1_000_000),
        }],
        validators: Vec::new(),
    };
    let service = open_staking_service(&genesis, None, local.address())?;
    let base_fee = service.fees().base_fee_per_unit;
    let tx = Transaction::for_operation(
        &local,
        0,
        Operation::RegisterValidator {
            consensus_key: local.public_key(),
            self_stake: Amount::from_webc(self_stake_webc),
            commission_bps,
            bootstrap: false,
        },
        stake_fee(base_fee, 30_000),
    )?;
    let sealed = service.submit_and_seal(tx, STAKE_BASE_TS_MS)?;
    Ok(serde_json::json!({
        "command": "stake-register",
        "local_address": local.address().to_string(),
        "operation": "RegisterValidator",
        "self_stake_webc": self_stake_webc,
        "commission_bps": commission_bps,
        "sealed_block": sealed,
        "validator": service.validator(local.address())?,
        "note": STAKE_NOTE,
    }))
}

/// `stake-delegate`: delegates local funds to a validator.
fn run_stake_delegate(
    amount_webc: u64,
    validator: Option<String>,
    seed: Option<String>,
) -> Result<serde_json::Value> {
    let local = local_keypair(seed)?;
    let target = Keypair::from_seed(TARGET_VALIDATOR_SEED);
    let validator_addr = resolve_validator(validator, target.address())?;
    let genesis = staking_genesis_with_target(&local, &target);
    let service = open_staking_service(&genesis, None, local.address())?;
    let base_fee = service.fees().base_fee_per_unit;
    let tx = Transaction::for_operation(
        &local,
        0,
        Operation::Delegate {
            validator: validator_addr,
            amount: Amount::from_webc(amount_webc),
        },
        stake_fee(base_fee, 15_000),
    )?;
    let sealed = service.submit_and_seal(tx, STAKE_BASE_TS_MS)?;
    Ok(serde_json::json!({
        "command": "stake-delegate",
        "local_address": local.address().to_string(),
        "operation": "Delegate",
        "validator_address": validator_addr.to_string(),
        "amount_webc": amount_webc,
        "sealed_block": sealed,
        "delegator_account": service.account(local.address())?,
        "validator": service.validator(validator_addr)?,
        "note": STAKE_NOTE,
    }))
}

/// `stake-undelegate`: delegates, then begins undelegation of the same amount.
fn run_stake_undelegate(
    amount_webc: u64,
    validator: Option<String>,
    seed: Option<String>,
) -> Result<serde_json::Value> {
    let local = local_keypair(seed)?;
    let target = Keypair::from_seed(TARGET_VALIDATOR_SEED);
    let validator_addr = resolve_validator(validator, target.address())?;
    let genesis = staking_genesis_with_target(&local, &target);
    let service = open_staking_service(&genesis, None, local.address())?;
    let base_fee = service.fees().base_fee_per_unit;
    // Establish a delegation to undelegate from.
    let delegate = Transaction::for_operation(
        &local,
        0,
        Operation::Delegate {
            validator: validator_addr,
            amount: Amount::from_webc(amount_webc),
        },
        stake_fee(base_fee, 15_000),
    )?;
    let delegation_block = service.submit_and_seal(delegate, STAKE_BASE_TS_MS)?;
    // Then begin undelegation of the full delegated amount.
    let undelegate = Transaction::for_operation(
        &local,
        1,
        Operation::Undelegate {
            validator: validator_addr,
            amount: Amount::from_webc(amount_webc),
        },
        stake_fee(base_fee, 15_000),
    )?;
    let undelegation_block = service.submit_and_seal(undelegate, STAKE_BASE_TS_MS + 1_000)?;
    Ok(serde_json::json!({
        "command": "stake-undelegate",
        "local_address": local.address().to_string(),
        "operation": "Undelegate",
        "validator_address": validator_addr.to_string(),
        "amount_webc": amount_webc,
        "delegation_block": delegation_block,
        "undelegation_block": undelegation_block,
        "delegator_account": service.account(local.address())?,
        "validator": service.validator(validator_addr)?,
        "note": "Undelegation is queued into the unbonding cooldown; matured principal \
                 is claimed later. Local deterministic devnet; valueless test units.",
    }))
}

/// `stake-claim`: claims validator and/or delegator rewards for the local key.
///
/// When neither flag is set, both claims run. The local key is a genesis
/// validator (so operator rewards can be claimed) and, when a delegator claim is
/// requested, first opens a small delegation to the target so a position exists.
fn run_stake_claim(
    claim_validator: bool,
    claim_delegator: bool,
    validator: Option<String>,
    seed: Option<String>,
) -> Result<serde_json::Value> {
    let (do_validator, do_delegator) = if !claim_validator && !claim_delegator {
        (true, true)
    } else {
        (claim_validator, claim_delegator)
    };
    let local = local_keypair(seed)?;
    let target = Keypair::from_seed(TARGET_VALIDATOR_SEED);
    let del_validator = resolve_validator(validator, target.address())?;
    let genesis = GenesisConfig {
        chain: ChainConfig::default(),
        accounts: vec![
            GenesisAccount {
                address: local.address(),
                balance: Amount::from_webc(1_000_000),
            },
            GenesisAccount {
                address: target.address(),
                balance: Amount::from_webc(1_000),
            },
        ],
        validators: vec![
            genesis_validator(&local, 100, 500),
            genesis_validator(&target, 100, 500),
        ],
    };
    let service = open_staking_service(&genesis, None, local.address())?;
    let base_fee = service.fees().base_fee_per_unit;

    // Ordered operations. A delegator claim first opens a delegation position.
    let mut ops: Vec<(&str, Operation)> = Vec::new();
    if do_delegator {
        ops.push((
            "delegation_setup",
            Operation::Delegate {
                validator: del_validator,
                amount: Amount::from_webc(1),
            },
        ));
    }
    if do_validator {
        ops.push(("validator_rewards", Operation::ClaimValidatorRewards));
    }
    if do_delegator {
        ops.push((
            "delegator_rewards",
            Operation::ClaimDelegatorRewards {
                validator: del_validator,
            },
        ));
    }

    let mut claimed = serde_json::Map::new();
    for (index, (label, operation)) in ops.into_iter().enumerate() {
        let tx = Transaction::for_operation(
            &local,
            index as u64,
            operation,
            stake_fee(base_fee, 30_000),
        )?;
        let sealed = service.submit_and_seal(tx, STAKE_BASE_TS_MS + index as u64 * 1_000)?;
        if label != "delegation_setup" {
            claimed.insert(label.to_owned(), serde_json::to_value(sealed)?);
        }
    }

    Ok(serde_json::json!({
        "command": "stake-claim",
        "local_address": local.address().to_string(),
        "delegator_target": del_validator.to_string(),
        "claimed": serde_json::Value::Object(claimed),
        "local_account": service.account(local.address())?,
        "note": "Rewards accrue at epoch boundaries; on this short-lived local devnet the \
                 claimable amount is typically zero. Valueless test units.",
    }))
}

/// `faucet-stake`: drips valueless devnet funds to the local key, then delegates.
fn run_faucet_stake(amount_webc: u64, seed: Option<String>) -> Result<serde_json::Value> {
    let local = local_keypair(seed)?;
    let target = Keypair::from_seed(TARGET_VALIDATOR_SEED);
    let faucet = Keypair::from_seed(STAKE_FAUCET_SEED);
    // The local key is intentionally absent from genesis so the faucet can fund it.
    let genesis = GenesisConfig {
        chain: ChainConfig::default(),
        accounts: vec![
            GenesisAccount {
                address: faucet.address(),
                balance: Amount::from_webc(1_000_000),
            },
            GenesisAccount {
                address: target.address(),
                balance: Amount::from_webc(1_000),
            },
        ],
        validators: vec![genesis_validator(&target, 100, 500)],
    };
    let service = open_staking_service(
        &genesis,
        Some(Keypair::from_seed(STAKE_FAUCET_SEED)),
        faucet.address(),
    )?;
    // 1) Faucet-drip valueless devnet funds to the local key (seals its own block).
    let faucet_drip = service.faucet_drip(local.address(), STAKE_BASE_TS_MS)?;
    // 2) Delegate part of the drip to the target validator.
    let base_fee = service.fees().base_fee_per_unit;
    let delegate = Transaction::for_operation(
        &local,
        0,
        Operation::Delegate {
            validator: target.address(),
            amount: Amount::from_webc(amount_webc),
        },
        stake_fee(base_fee, 15_000),
    )?;
    let delegation_block = service.submit_and_seal(delegate, STAKE_BASE_TS_MS + 1_000)?;
    Ok(serde_json::json!({
        "command": "faucet-stake",
        "local_address": local.address().to_string(),
        "validator_address": target.address().to_string(),
        "faucet_drip": faucet_drip,
        "delegated_webc": amount_webc,
        "delegation_block": delegation_block,
        "delegator_account": service.account(local.address())?,
        "validator": service.validator(target.address())?,
        "note": STAKE_NOTE,
    }))
}

/// Genesis that funds the local key and registers the deterministic target
/// validator (funded and self-staked), shared by the delegate/undelegate demos.
fn staking_genesis_with_target(local: &Keypair, target: &Keypair) -> GenesisConfig {
    GenesisConfig {
        chain: ChainConfig::default(),
        accounts: vec![
            GenesisAccount {
                address: local.address(),
                balance: Amount::from_webc(1_000_000),
            },
            GenesisAccount {
                address: target.address(),
                balance: Amount::from_webc(1_000),
            },
        ],
        validators: vec![genesis_validator(target, 100, 500)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn amount_string(whole: u64) -> String {
        Amount::from_webc(whole).0.to_string()
    }

    #[test]
    fn run_accepts_protocol2_files_without_putting_a_seed_in_argv() {
        let cli = Cli::try_parse_from([
            "webc-node",
            "run",
            "--protocol2-genesis",
            "genesis.json",
            "--validator-key-file",
            "validator-key.json",
        ])
        .expect("protocol-2 run arguments parse");
        let Command::Run {
            protocol2_genesis,
            validator_key_file,
            ..
        } = cli.command
        else {
            panic!("run subcommand expected");
        };
        assert_eq!(protocol2_genesis, Some(PathBuf::from("genesis.json")));
        assert_eq!(
            validator_key_file,
            Some(PathBuf::from("validator-key.json"))
        );
        assert!(
            Cli::try_parse_from([
                "webc-node",
                "run",
                "--validator-key-file",
                "validator-key.json",
            ])
            .is_err(),
            "a key file without an explicit protocol-2 genesis is rejected"
        );
    }

    #[test]
    fn parse_seed_accepts_32_byte_hex_and_rejects_others() {
        let hex_seed = "11".repeat(32);
        assert_eq!(parse_seed(&hex_seed).unwrap(), [0x11u8; 32]);
        // Wrong length and non-hex are rejected.
        assert!(parse_seed("1122").is_err());
        assert!(parse_seed(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn local_keypair_defaults_to_fixed_seed() {
        let default = local_keypair(None).unwrap();
        assert_eq!(
            default.address(),
            Keypair::from_seed(DEFAULT_LOCAL_SEED).address()
        );
        let explicit = local_keypair(Some("11".repeat(32))).unwrap();
        assert_eq!(
            explicit.address(),
            Keypair::from_seed([0x11u8; 32]).address()
        );
    }

    #[test]
    fn resolve_validator_parses_or_defaults() {
        let default = Keypair::from_seed(TARGET_VALIDATOR_SEED).address();
        assert_eq!(resolve_validator(None, default).unwrap(), default);
        let explicit = Keypair::from_seed([5u8; 32]).address();
        assert_eq!(
            resolve_validator(Some(explicit.to_string()), default).unwrap(),
            explicit
        );
        assert!(resolve_validator(Some("not-an-address".to_owned()), default).is_err());
    }

    #[test]
    fn stake_register_registers_the_local_validator() {
        let value = run_stake_register(25, 500, None).unwrap();
        let local = Keypair::from_seed(DEFAULT_LOCAL_SEED).address().to_string();
        assert_eq!(value["local_address"], local);
        assert_eq!(value["validator"]["operator"], local);
        assert_eq!(value["validator"]["self_stake"], amount_string(25));
        assert_eq!(value["validator"]["commission_bps"], 500);
        assert_eq!(value["sealed_block"]["height"], 1);
    }

    #[test]
    fn stake_delegate_increases_validator_delegated_stake() {
        let value = run_stake_delegate(10, None, None).unwrap();
        assert_eq!(value["operation"], "Delegate");
        assert_eq!(value["validator"]["delegated_stake"], amount_string(10));
        assert_eq!(value["sealed_block"]["transaction_count"], 1);
    }

    #[test]
    fn stake_undelegate_delegates_then_queues() {
        let value = run_stake_undelegate(5, None, None).unwrap();
        assert_eq!(value["operation"], "Undelegate");
        assert_eq!(value["delegation_block"]["height"], 1);
        assert_eq!(value["undelegation_block"]["height"], 2);
    }

    #[test]
    fn stake_claim_runs_both_claims_by_default() {
        let value = run_stake_claim(false, false, None, None).unwrap();
        assert!(value["claimed"].get("validator_rewards").is_some());
        assert!(value["claimed"].get("delegator_rewards").is_some());
    }

    #[test]
    fn stake_claim_can_claim_only_validator_rewards() {
        let value = run_stake_claim(true, false, None, None).unwrap();
        assert!(value["claimed"].get("validator_rewards").is_some());
        assert!(value["claimed"].get("delegator_rewards").is_none());
    }

    #[test]
    fn faucet_stake_funds_then_delegates() {
        let value = run_faucet_stake(10, None).unwrap();
        assert_eq!(value["validator"]["delegated_stake"], amount_string(10));
        // The drip funded the local key with the devnet faucet amount.
        assert_eq!(value["faucet_drip"]["amount"], amount_string(100));
    }
}
