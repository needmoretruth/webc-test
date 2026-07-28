//! Public protocol-2 node assembly and protected validator-key loading.
//!
//! Purpose: wire the one protocol-2 runtime, authenticated network, V4 consensus
//! driver, and bounded V2 HTTP service into a restartable public node process.
//! Responsibilities: bound and validate local genesis/key files, open durable
//! redb state, verify validator credentials against genesis, own task lifetimes,
//! and surface any driver/runtime/server exit. Non-responsibilities: implement
//! consensus rules, transaction admission, HTTP handlers, key generation, or a
//! production secrets manager.
//!
//! Data flow: a validated protocol-2 genesis opens one `Node`; `NodeRuntime`
//! becomes its single mutable owner; cloned handles feed the V2 API and V4
//! driver; one authenticated network receiver is consumed only by the driver,
//! which also admits V5 gossip through the actor.
//!
//! Security boundary: local files are hostile and bounded before JSON work.
//! Consensus seed bytes come only from a file (never argv/environment/logs), are
//! retained in a non-Debug/non-Serialize zeroizing type, and must match the
//! registered operator/consensus public key. Unix group/other-readable key files
//! are rejected; Windows operators must protect the file with an ACL.

use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use webc_chain::{
    GenesisConfig, TransactionV5, GENESIS_TOTAL_SUPPLY, MAX_FINALITY_AUTHORITIES_V1,
    TRANSACTION_V5_PROTOCOL_VERSION,
};
use webc_crypto::{Address, Keypair};
use webc_net::{spawn_network, NetMessage, NetworkConfig, NetworkHandle, PeerId};
use webc_storage::{LocalTimestampMs, RedbKvStore};
use zeroize::{Zeroize, Zeroizing};

use crate::mempool_v1::MAX_V5_GOSSIP_PAGE_TRANSACTIONS;
use crate::{
    serve_v2, ConsensusCredentialsV1, ConsensusDriverV1, DriverExitV1, DriverTimeouts, Node,
    NodeHandle, NodeRuntime, NodeRuntimeError, V2AppState, V5MempoolConfig,
};

/// Maximum bytes read from a protocol-2 genesis JSON file.
pub const MAX_PROTOCOL2_GENESIS_BYTES: usize = 8 * 1024 * 1024;
/// Maximum genesis accounts accepted by the public node assembly boundary.
pub const MAX_PROTOCOL2_GENESIS_ACCOUNTS: usize = 65_536;
/// Maximum bytes read from a small protected credential JSON file.
pub const MAX_PROTECTED_KEY_FILE_BYTES: usize = 512;
/// Poll interval for detecting a disconnected-to-connected peer transition.
const PENDING_GOSSIP_PEER_POLL: Duration = Duration::from_millis(100);
/// Minimum delay between recovered transaction replay commands.
const PENDING_GOSSIP_SEND_DELAY: Duration = Duration::from_millis(20);

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidatorKeyFileV1 {
    version: u8,
    operator: Address,
    seed_hex: String,
}

impl Drop for ValidatorKeyFileV1 {
    fn drop(&mut self) {
        self.seed_hex.zeroize();
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DevnetKeyFileV1 {
    version: u8,
    seed_hex: String,
}

impl Drop for DevnetKeyFileV1 {
    fn drop(&mut self) {
        self.seed_hex.zeroize();
    }
}

/// Filesystem and socket inputs required to start one protocol-2 node.
pub struct Protocol2RunConfig {
    /// Directory holding the restartable redb database.
    pub data_dir: PathBuf,
    /// Address for the bounded V2 HTTP/WebSocket API.
    pub api_listen: SocketAddr,
    /// Optional address accepting authenticated peer connections.
    pub p2p_listen: Option<SocketAddr>,
    /// Static authenticated peer addresses dialed on startup.
    pub bootstrap_peers: Vec<SocketAddr>,
    /// Canonical shared protocol-2 genesis JSON path.
    pub genesis_path: PathBuf,
    /// Protected validator credential file, or `None` for an observer.
    pub validator_key_path: Option<PathBuf>,
}

/// Running protocol-2 node tasks with explicit shutdown ownership.
pub struct Protocol2Node {
    api_addr: SocketAddr,
    p2p_addr: Option<SocketAddr>,
    peer_id: PeerId,
    runtime: NodeHandle,
    runtime_task: tokio::task::JoinHandle<Result<(), NodeRuntimeError>>,
    driver_task: tokio::task::JoinHandle<DriverExitV1>,
    server_task: tokio::task::JoinHandle<std::io::Result<()>>,
    pending_gossip_task: tokio::task::JoinHandle<Result<()>>,
}

impl Protocol2Node {
    /// Actual API socket address (useful when configured with port zero in tests).
    pub fn api_addr(&self) -> SocketAddr {
        self.api_addr
    }

    /// Actual peer-listen address, when inbound networking is enabled.
    pub fn p2p_addr(&self) -> Option<SocketAddr> {
        self.p2p_addr
    }

    /// Public ephemeral network identity for this process.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Waits until one critical task exits, stops the others, and reports why.
    pub async fn wait(mut self) -> Result<()> {
        tokio::select! {
            server = &mut self.server_task => {
                self.driver_task.abort();
                self.pending_gossip_task.abort();
                stop_actor(&self.runtime, &mut self.runtime_task).await;
                match server {
                    Ok(Ok(())) => bail!("protocol-2 API server stopped unexpectedly"),
                    Ok(Err(error)) => Err(error).context("protocol-2 API server failed"),
                    Err(error) => Err(error).context("protocol-2 API task failed"),
                }
            }
            driver = &mut self.driver_task => {
                self.server_task.abort();
                self.pending_gossip_task.abort();
                stop_actor(&self.runtime, &mut self.runtime_task).await;
                let exit = driver.context("protocol-2 consensus task failed")?;
                bail!("protocol-2 consensus stopped: {exit}")
            }
            runtime = &mut self.runtime_task => {
                self.driver_task.abort();
                self.server_task.abort();
                self.pending_gossip_task.abort();
                match runtime {
                    Ok(Ok(())) => bail!("protocol-2 node runtime stopped unexpectedly"),
                    Ok(Err(error)) => Err(error).context("protocol-2 node runtime failed"),
                    Err(error) => Err(error).context("protocol-2 node runtime task failed"),
                }
            }
            pending_gossip = &mut self.pending_gossip_task => {
                self.driver_task.abort();
                self.server_task.abort();
                stop_actor(&self.runtime, &mut self.runtime_task).await;
                match pending_gossip {
                    Ok(Ok(())) => bail!("protocol-2 pending gossip task stopped unexpectedly"),
                    Ok(Err(error)) => Err(error).context("protocol-2 pending gossip task failed"),
                    Err(error) => Err(error).context("protocol-2 pending gossip task crashed"),
                }
            }
        }
    }

    /// Stops API/consensus tasks, drains the actor, and closes durable storage.
    pub async fn shutdown(self) -> Result<()> {
        self.server_task.abort();
        self.driver_task.abort();
        self.pending_gossip_task.abort();
        self.runtime
            .shutdown()
            .await
            .context("protocol-2 runtime rejected shutdown")?;
        self.runtime_task
            .await
            .context("protocol-2 runtime task failed during shutdown")??;
        Ok(())
    }
}

async fn stop_actor(
    runtime: &NodeHandle,
    runtime_task: &mut tokio::task::JoinHandle<Result<(), NodeRuntimeError>>,
) {
    if !runtime_task.is_finished() {
        let _ = runtime.shutdown().await;
        let _ = runtime_task.await;
    }
}

/// Starts one public protocol-2 node without blocking on its task lifetime.
pub async fn start_protocol2(config: Protocol2RunConfig) -> Result<Protocol2Node> {
    let genesis = load_protocol2_genesis(&config.genesis_path)?;
    let credentials = config
        .validator_key_path
        .as_deref()
        .map(|path| load_consensus_credentials(path, &genesis))
        .transpose()?;

    std::fs::create_dir_all(&config.data_dir).context("create protocol-2 data directory")?;
    let store = RedbKvStore::open(config.data_dir.join("chain.redb"))
        .context("open protocol-2 redb store")?;
    let node = Node::open(store, &genesis).context("open protocol-2 chain state")?;
    let listener = tokio::net::TcpListener::bind(config.api_listen)
        .await
        .context("bind protocol-2 API listener")?;
    let api_addr = listener
        .local_addr()
        .context("read protocol-2 API listener address")?;

    let (network, inbound) = spawn_network(NetworkConfig::new(
        Keypair::generate(),
        genesis.chain.chain_id.clone(),
        config.p2p_listen,
        config.bootstrap_peers,
    ))
    .await
    .context("start authenticated protocol-2 network")?;
    let p2p_addr = network.local_addr();
    let peer_id = network.local_peer_id();
    let (runtime, runtime_task) = NodeRuntime::spawn(
        node,
        V5MempoolConfig::default(),
        256,
        LocalTimestampMs::new(crate::http::now_ms()),
    )
    .context("start single-owner protocol-2 runtime")?;
    let app_state = V2AppState::with_network(runtime.clone(), network.clone());
    let server_task = tokio::spawn(serve_v2(listener, app_state));
    let pending_gossip_task = tokio::spawn(run_pending_regossip(runtime.clone(), network.clone()));
    let driver_task = tokio::spawn(
        ConsensusDriverV1::new_with_credentials(
            runtime.clone(),
            network,
            credentials,
            DriverTimeouts::default(),
        )
        .run(inbound, None),
    );

    Ok(Protocol2Node {
        api_addr,
        p2p_addr,
        peer_id,
        runtime,
        runtime_task,
        driver_task,
        server_task,
        pending_gossip_task,
    })
}

/// Replays bounded pending pages whenever this node gains a peer generation.
///
/// The actor revalidated every recovered record before this task starts. A
/// connection-generation change triggers one deterministic ID-ordered
/// scan, bounded to 16 cloned transactions (at most 4 MiB) per actor response.
/// Individual sends are paced so the network worker's command/outbound queues
/// cannot be flooded by a full recovered mempool. The explicit network replay
/// bypasses only the sender's stale seen marker; peers still suppress duplicates.
async fn run_pending_regossip(runtime: NodeHandle, network: NetworkHandle) -> Result<()> {
    let mut observed_generation = None;
    let mut poll = tokio::time::interval(PENDING_GOSSIP_PEER_POLL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        poll.tick().await;
        let generation = network.peer_generation();
        let connected = network.connected_peers() > 0;
        if connected && observed_generation != Some(generation) {
            replay_pending_once(&runtime, &network).await?;
        }
        // Keep the generation captured before replay. A peer change during the
        // scan therefore remains visible and triggers a complete next sweep,
        // ensuring the newcomer cannot miss an earlier page.
        observed_generation = Some(generation);
    }
}

async fn replay_pending_once(runtime: &NodeHandle, network: &NetworkHandle) -> Result<()> {
    let mut cursor = None;
    loop {
        if network.connected_peers() == 0 {
            return Ok(());
        }
        let page = loop {
            match runtime
                .pending_gossip_page(cursor, MAX_V5_GOSSIP_PAGE_TRANSACTIONS)
                .await
            {
                Ok(page) => break page,
                Err(NodeRuntimeError::QueueFull) => {
                    if network.connected_peers() == 0 {
                        return Ok(());
                    }
                    tokio::time::sleep(PENDING_GOSSIP_SEND_DELAY).await;
                }
                Err(error) => {
                    return Err(error).context("load bounded pending gossip page");
                }
            }
        };
        if page.is_empty() {
            return Ok(());
        }
        let next_cursor = page
            .last()
            .map(TransactionV5::transaction_id)
            .transpose()
            .context("identify revalidated pending transaction")?;
        for transaction in page {
            if network.connected_peers() == 0 {
                return Ok(());
            }
            network
                .rebroadcast(NetMessage::TransactionV5(Box::new(transaction)))
                .context("replay pending transaction")?;
            tokio::time::sleep(PENDING_GOSSIP_SEND_DELAY).await;
        }
        cursor = next_cursor;
    }
}

/// Loads and validates a bounded protocol-2 genesis file.
pub fn load_protocol2_genesis(path: &Path) -> Result<GenesisConfig> {
    let bytes = read_bounded(path, MAX_PROTOCOL2_GENESIS_BYTES, "protocol-2 genesis")?;
    let genesis: GenesisConfig =
        serde_json::from_slice(&bytes).context("protocol-2 genesis JSON is malformed")?;
    if genesis.chain.protocol_version != TRANSACTION_V5_PROTOCOL_VERSION {
        bail!("protocol-2 genesis must set protocol_version to 2");
    }
    if genesis.chain.expected_total_supply != Some(GENESIS_TOTAL_SUPPLY) {
        bail!("protocol-2 devnet genesis must declare the fixed total supply");
    }
    if genesis.accounts.len() > MAX_PROTOCOL2_GENESIS_ACCOUNTS {
        bail!("protocol-2 genesis has too many accounts");
    }
    if genesis.validators.is_empty() || genesis.validators.len() > MAX_FINALITY_AUTHORITIES_V1 {
        bail!("protocol-2 genesis validator count is outside the allowed range");
    }
    // Run the complete shared allocation/config/supply validator before opening
    // storage, so malformed genesis never stamps a database.
    webc_chain::ChainState::from_genesis_v1(&genesis)
        .context("protocol-2 genesis validation failed")?;
    Ok(genesis)
}

/// Loads one bounded validator credential file and binds it to genesis.
pub fn load_consensus_credentials(
    path: &Path,
    genesis: &GenesisConfig,
) -> Result<ConsensusCredentialsV1> {
    let key_file: ValidatorKeyFileV1 = read_protected_key_json(path, "validator key")?;
    if key_file.version != 1 {
        bail!("validator key schema is invalid");
    }
    let mut seed = decode_seed(&key_file.seed_hex, "validator key")?;
    let consensus_public_key = Keypair::from_seed(seed).public_key();
    let matches_genesis = genesis.validators.iter().any(|validator| {
        validator.operator == key_file.operator && validator.consensus_key == consensus_public_key
    });
    if !matches_genesis {
        seed.zeroize();
        bail!("validator key does not match a genesis authority");
    }
    let credentials = ConsensusCredentialsV1::new(key_file.operator, seed);
    seed.zeroize();
    Ok(credentials)
}

/// Loads a devnet signing key from a bounded, protected JSON file.
///
/// The accepted schema is exactly `{"version":1,"seed_hex":"<64 lowercase
/// hex characters>"}`. The raw secret is never accepted through argv, included
/// in errors, logged, serialized, or returned. This helper is for local devnet
/// commands only; production browser wallets require an encrypted keystore.
pub fn load_devnet_keypair(path: &Path) -> Result<Keypair> {
    let key_file: DevnetKeyFileV1 = read_protected_key_json(path, "devnet key")?;
    if key_file.version != 1 {
        bail!("devnet key schema is invalid");
    }
    let mut seed = decode_seed(&key_file.seed_hex, "devnet key")?;
    let keypair = Keypair::from_seed(seed);
    seed.zeroize();
    Ok(keypair)
}

fn read_protected_key_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    label: &'static str,
) -> Result<T> {
    let file = File::open(path).with_context(|| format!("open {label} file"))?;
    validate_key_file_permissions(&file)?;
    let bytes = Zeroizing::new(read_open_file_bounded(
        file,
        MAX_PROTECTED_KEY_FILE_BYTES,
        label,
    )?);
    serde_json::from_slice(&bytes).with_context(|| format!("{label} JSON is malformed"))
}

fn decode_seed(seed_hex: &str, label: &'static str) -> Result<[u8; 32]> {
    if seed_hex.len() != 64
        || !seed_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} seed is invalid");
    }
    let mut seed = [0u8; 32];
    if hex::decode_to_slice(seed_hex.as_bytes(), &mut seed).is_err() {
        seed.zeroize();
        bail!("{label} seed is invalid");
    }
    Ok(seed)
}

fn read_bounded(path: &Path, maximum: usize, label: &'static str) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("open {label} file"))?;
    read_open_file_bounded(file, maximum, label)
}

fn read_open_file_bounded(file: File, maximum: usize, label: &'static str) -> Result<Vec<u8>> {
    if !file
        .metadata()
        .context("read local file metadata")?
        .is_file()
    {
        bail!("{label} path is not a regular file");
    }
    let limit = u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {label} file"))?;
    if bytes.len() > maximum {
        bytes.zeroize();
        bail!("{label} file exceeds its byte limit");
    }
    Ok(bytes)
}

#[cfg(unix)]
fn validate_key_file_permissions(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = file
        .metadata()
        .context("read validator key metadata")?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        bail!("validator key file must not be accessible by group or other users");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_key_file_permissions(_file: &File) -> Result<()> {
    // Windows DACL policy is deployment-specific and cannot be represented by
    // `std::fs::Permissions`. The operator/install service must grant the node
    // identity exclusive read access; the loader still bounds and validates all
    // bytes and never prints or exports the seed.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use webc_chain::{
        ActionV1, Amount, AuthorizationLaneId, AuthorizationPolicyRevision, BlockHeight,
        ChainConfig, ChainId, FeeBid, FeePaymentV1, GenesisAccount, GenesisValidator, Nonce,
        Operation, TransactionAuthorizationV1, ValidityWindowV1,
    };

    fn genesis(operator: &Keypair, consensus: &Keypair) -> GenesisConfig {
        GenesisConfig {
            chain: ChainConfig {
                protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
                expected_total_supply: Some(GENESIS_TOTAL_SUPPLY),
                ..ChainConfig::default()
            },
            accounts: vec![GenesisAccount {
                address: operator.address(),
                balance: GENESIS_TOTAL_SUPPLY,
            }],
            validators: vec![GenesisValidator {
                operator: operator.address(),
                consensus_key: consensus.public_key(),
                self_stake: Amount::from_webc(200),
                commission_bps: 500,
                bootstrap: false,
            }],
        }
    }

    fn protect_key_file(_path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(_path, std::fs::Permissions::from_mode(0o600))
                .expect("test key permissions set");
        }
    }

    fn pending_transfer(sender: &Keypair, recipient: &Keypair) -> TransactionV5 {
        let mut transaction = TransactionV5::for_actions_unsigned(
            ChainId::devnet(),
            sender.address(),
            sender.public_key(),
            TransactionAuthorizationV1 {
                lane: AuthorizationLaneId::DEFAULT,
                policy_revision: AuthorizationPolicyRevision::new(0),
                nonce: Nonce::new(0),
            },
            ValidityWindowV1::new(BlockHeight::new(1), BlockHeight::new(20)),
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
        .expect("test transfer shape is valid");
        transaction.sign(sender).expect("test transfer signs");
        transaction
    }

    #[test]
    fn dedicated_consensus_key_file_is_bounded_and_genesis_bound() {
        let directory = tempfile::tempdir().expect("temporary directory exists");
        let path = directory.path().join("validator-key.json");
        let operator = Keypair::from_seed([0x21; 32]);
        let consensus = Keypair::from_seed([0x22; 32]);
        let json = serde_json::json!({
            "version": 1,
            "operator": operator.address(),
            "seed_hex": hex::encode([0x22; 32]),
        });
        std::fs::write(&path, serde_json::to_vec(&json).expect("JSON encodes"))
            .expect("test key writes");
        protect_key_file(&path);

        let credentials = load_consensus_credentials(&path, &genesis(&operator, &consensus))
            .expect("dedicated key loads");
        assert_eq!(credentials.operator(), operator.address());

        let wrong_genesis = genesis(&operator, &Keypair::from_seed([0x23; 32]));
        let error = load_consensus_credentials(&path, &wrong_genesis)
            .err()
            .expect("wrong registered key is rejected");
        assert!(!error.to_string().contains(&hex::encode([0x22; 32])));
    }

    #[test]
    fn devnet_key_file_is_strict_bounded_and_secret_safe() {
        let directory = tempfile::tempdir().expect("temporary directory exists");
        let path = directory.path().join("devnet-key.json");
        let secret = "42".repeat(32);
        let json = serde_json::json!({
            "version": 1,
            "seed_hex": secret.clone(),
        });
        std::fs::write(&path, serde_json::to_vec(&json).expect("JSON encodes"))
            .expect("test key writes");
        protect_key_file(&path);
        let keypair = load_devnet_keypair(&path).expect("strict devnet key loads");
        assert_eq!(keypair.address(), Keypair::from_seed([0x42; 32]).address());

        let duplicate = format!(r#"{{"version":1,"seed_hex":"{secret}","seed_hex":"{secret}"}}"#);
        std::fs::write(&path, duplicate).expect("duplicate-field key writes");
        let duplicate_error = load_devnet_keypair(&path)
            .err()
            .expect("duplicate field is rejected");
        assert!(!duplicate_error.to_string().contains(&secret));

        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "seed_hex": secret.clone(),
                "unexpected": true,
            }))
            .expect("JSON encodes"),
        )
        .expect("unknown-field key writes");
        let unknown_error = load_devnet_keypair(&path)
            .err()
            .expect("unknown field is rejected");
        assert!(!unknown_error.to_string().contains(&secret));

        std::fs::write(&path, vec![b'x'; MAX_PROTECTED_KEY_FILE_BYTES + 1])
            .expect("oversized key writes");
        let oversized_error = load_devnet_keypair(&path)
            .err()
            .expect("oversized file is rejected");
        assert!(oversized_error.to_string().contains("byte limit"));
    }

    #[tokio::test]
    async fn public_protocol2_assembly_serves_health_and_shuts_down() {
        let directory = tempfile::tempdir().expect("temporary directory exists");
        let operator = Keypair::from_seed([0x31; 32]);
        let consensus = Keypair::from_seed([0x32; 32]);
        let genesis = genesis(&operator, &consensus);
        let genesis_path = directory.path().join("genesis.json");
        std::fs::write(
            &genesis_path,
            serde_json::to_vec(&genesis).expect("genesis encodes"),
        )
        .expect("genesis writes");
        let key_path = directory.path().join("validator-key.json");
        std::fs::write(
            &key_path,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "operator": operator.address(),
                "seed_hex": hex::encode([0x32; 32]),
            }))
            .expect("key JSON encodes"),
        )
        .expect("key file writes");
        protect_key_file(&key_path);

        let node = start_protocol2(Protocol2RunConfig {
            data_dir: directory.path().join("data"),
            api_listen: "127.0.0.1:0".parse().expect("API address parses"),
            p2p_listen: Some("127.0.0.1:0".parse().expect("P2P address parses")),
            bootstrap_peers: Vec::new(),
            genesis_path,
            validator_key_path: Some(key_path),
        })
        .await
        .expect("public protocol-2 node starts");
        let mut stream = tokio::net::TcpStream::connect(node.api_addr())
            .await
            .expect("API accepts TCP");
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream
            .write_all(b"GET /v2/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("health request writes");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("health response reads");
        let response = String::from_utf8(response).expect("HTTP response is UTF-8");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"protocol_version\":2"));
        node.shutdown().await.expect("public node shuts down");
    }

    #[tokio::test]
    async fn recovered_pending_replays_when_the_first_peer_connects_late() {
        const TEST_NOW: u64 = 1_700_000_000_000;

        let directory = tempfile::tempdir().expect("temporary directory exists");
        let database_path = directory.path().join("chain.redb");
        let operator = Keypair::from_seed([0x61; 32]);
        let consensus = Keypair::from_seed([0x62; 32]);
        let recipient = Keypair::from_seed([0x63; 32]);
        let genesis = genesis(&operator, &consensus);
        let transaction = pending_transfer(&operator, &recipient);
        let transaction_id = transaction
            .transaction_id()
            .expect("test transaction has an ID");

        {
            let store = RedbKvStore::open(&database_path).expect("first redb opens");
            let node = Node::open(store, &genesis).expect("first node opens");
            let (runtime, runtime_task) = NodeRuntime::spawn(
                node,
                V5MempoolConfig::default(),
                32,
                LocalTimestampMs::new(TEST_NOW),
            )
            .expect("first runtime starts");
            runtime
                .submit(transaction, LocalTimestampMs::new(TEST_NOW))
                .await
                .expect("pending transaction becomes durable");
            runtime.shutdown().await.expect("first runtime shuts down");
            runtime_task
                .await
                .expect("first runtime does not panic")
                .expect("first runtime exits cleanly");
        }

        let store = RedbKvStore::open(&database_path).expect("restart redb opens");
        let node = Node::open(store, &genesis).expect("restart node opens");
        let (runtime, runtime_task) = NodeRuntime::spawn(
            node,
            V5MempoolConfig::default(),
            32,
            LocalTimestampMs::new(TEST_NOW + 1),
        )
        .expect("restart runtime recovers");
        assert_eq!(
            runtime
                .stats()
                .await
                .expect("restart stats read")
                .mempool_size,
            1
        );

        let (source_network, _source_inbound) = spawn_network(NetworkConfig::new(
            Keypair::from_seed([0x64; 32]),
            ChainId::devnet(),
            Some("127.0.0.1:0".parse().expect("source listen parses")),
            Vec::new(),
        ))
        .await
        .expect("source network starts");
        let source_address = source_network.local_addr().expect("source listens");
        let replay_task = tokio::spawn(run_pending_regossip(
            runtime.clone(),
            source_network.clone(),
        ));
        tokio::time::sleep(PENDING_GOSSIP_PEER_POLL + PENDING_GOSSIP_PEER_POLL).await;

        let (late_network, mut late_inbound) = spawn_network(NetworkConfig::new(
            Keypair::from_seed([0x65; 32]),
            ChainId::devnet(),
            Some("127.0.0.1:0".parse().expect("late listen parses")),
            vec![source_address],
        ))
        .await
        .expect("late network starts");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while source_network.connected_peers() == 0 || late_network.connected_peers() == 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "late peer did not authenticate"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let received = tokio::time::timeout(Duration::from_secs(5), late_inbound.recv())
            .await
            .expect("recovered transaction arrives")
            .expect("late inbound remains open");
        let NetMessage::TransactionV5(received) = received.message else {
            panic!("expected a protocol-2 transaction");
        };
        assert_eq!(
            received.transaction_id().expect("replayed transaction ID"),
            transaction_id
        );

        replay_task.abort();
        drop(late_network);
        drop(source_network);
        runtime
            .shutdown()
            .await
            .expect("restart runtime shuts down");
        runtime_task
            .await
            .expect("restart runtime does not panic")
            .expect("restart runtime exits cleanly");
    }
}
