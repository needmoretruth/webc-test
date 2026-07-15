use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use webc_chain::{
    build_block, Amount, BlockBuildInput, ChainConfig, ChainState, FeeBid, GenesisAccount,
    GenesisConfig, Operation, Transaction,
};
use webc_crypto::{Hash256, Keypair, PublicKeyBytes};
use webc_net::{spawn_network, NetworkConfig};
use webc_node::{
    run_gossip_pump, AppState, FaucetConfig, MempoolConfig, Node, NodeService, NodeServiceOptions,
};
use webc_storage::RedbKvStore;

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
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen => keygen(),
        Command::GenesisTemplate => genesis_template(),
        Command::Demo => demo(),
        Command::Bench { iterations } => bench(iterations),
        Command::Run {
            data_dir,
            listen,
            p2p_listen,
            peers,
        } => run(data_dir, listen, p2p_listen, peers),
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

/// Runs a single-proposer devnet node backed by durable redb storage.
///
/// The node recovers its latest committed state from `data_dir` on start (or
/// initializes a devnet genesis on first run), serves the versioned HTTP/WebSocket
/// API, and auto-seals a block every two seconds (the devnet block target) when
/// the mempool has pending transactions. The faucet identity is a fixed devnet
/// seed and its funds are valueless test units.
fn run(
    data_dir: PathBuf,
    listen: String,
    p2p_listen: Option<String>,
    peers: Vec<String>,
) -> Result<()> {
    std::fs::create_dir_all(&data_dir)?;

    // Fixed devnet faucet identity. Devnet only; these units carry no value.
    let faucet = Keypair::from_seed([7u8; 32]);
    let genesis = GenesisConfig {
        chain: ChainConfig::default(),
        accounts: vec![GenesisAccount {
            address: faucet.address(),
            balance: Amount::from_webc(1_000_000),
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
