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

use anyhow::{bail, Context, Result};
use webc_chain::{
    GenesisConfig, GENESIS_TOTAL_SUPPLY, MAX_FINALITY_AUTHORITIES_V1,
    TRANSACTION_V5_PROTOCOL_VERSION,
};
use webc_crypto::{Address, Keypair};
use webc_net::{spawn_network, NetworkConfig, PeerId};
use webc_storage::{LocalTimestampMs, RedbKvStore};
use zeroize::{Zeroize, Zeroizing};

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
                stop_actor(&self.runtime, &mut self.runtime_task).await;
                match server {
                    Ok(Ok(())) => bail!("protocol-2 API server stopped unexpectedly"),
                    Ok(Err(error)) => Err(error).context("protocol-2 API server failed"),
                    Err(error) => Err(error).context("protocol-2 API task failed"),
                }
            }
            driver = &mut self.driver_task => {
                self.server_task.abort();
                stop_actor(&self.runtime, &mut self.runtime_task).await;
                let exit = driver.context("protocol-2 consensus task failed")?;
                bail!("protocol-2 consensus stopped: {exit}")
            }
            runtime = &mut self.runtime_task => {
                self.driver_task.abort();
                self.server_task.abort();
                match runtime {
                    Ok(Ok(())) => bail!("protocol-2 node runtime stopped unexpectedly"),
                    Ok(Err(error)) => Err(error).context("protocol-2 node runtime failed"),
                    Err(error) => Err(error).context("protocol-2 node runtime task failed"),
                }
            }
        }
    }

    /// Stops API/consensus tasks, drains the actor, and closes durable storage.
    pub async fn shutdown(self) -> Result<()> {
        self.server_task.abort();
        self.driver_task.abort();
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
    })
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
    use webc_chain::{Amount, ChainConfig, GenesisAccount, GenesisValidator};

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
}
