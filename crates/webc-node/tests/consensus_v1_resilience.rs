//! Protocol-2 consensus crash and storage-fault regressions.
//!
//! Purpose: prove the V4 driver preserves validator safety across a process
//! restart and distinguishes retryable finalization I/O from persistent storage
//! failure. Responsibilities: run the real actor, authenticated transport,
//! protocol-2 WAL, and certified V4 commit path. Non-responsibilities: exercise
//! public CLI configuration, benchmark throughput, or replace storage's own
//! atomicity tests.
//!
//! Data flow: a harness records every signed proposal/vote around a redb-backed
//! validator restart. Separate single-validator cases inject failure only into
//! batches containing `BlocksV2`, leaving WAL writes healthy so the test reaches
//! the driver's finalization retry boundary.
//!
//! Security boundary: a crash must never make an honest validator equivocate,
//! and an already certified block must never be silently dropped. Test-only
//! storage faults are selected by the public `WriteBatch`/`Table` seam and apply
//! atomically before the in-memory backend sees the batch.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use webc_chain::{
    Amount, ChainConfig, GenesisAccount, GenesisConfig, GenesisValidator, ValidatorSet, VoteType,
    TRANSACTION_V5_PROTOCOL_VERSION,
};
use webc_crypto::{Hash256, Keypair};
use webc_net::{spawn_network, InboundMessage, NetMessage, NetworkConfig};
use webc_node::{
    CommitInfo, ConsensusDriverV1, DriverExitV1, DriverTimeouts, Node, NodeHandle, NodeRuntime,
    NodeRuntimeError, V5MempoolConfig,
};
use webc_storage::{
    KvEntry, KvStore, LocalTimestampMs, MemoryKvStore, RedbKvStore, StorageError, Table, WriteBatch,
};

const RECOVERY_NOW_MS: u64 = 1_700_000_000_000;

fn validator_genesis(validators: &[Keypair]) -> GenesisConfig {
    GenesisConfig {
        chain: ChainConfig {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            ..ChainConfig::default()
        },
        accounts: validators
            .iter()
            .map(|validator| GenesisAccount {
                address: validator.address(),
                balance: Amount::from_webc(1_000),
            })
            .collect(),
        validators: validators
            .iter()
            .map(|validator| GenesisValidator {
                operator: validator.address(),
                consensus_key: validator.public_key(),
                self_stake: Amount::from_webc(200),
                commission_bps: 500,
                bootstrap: false,
            })
            .collect(),
    }
}

fn spawn_runtime<K: KvStore + Send + 'static>(
    node: Node<K>,
) -> Result<
    (
        NodeHandle,
        tokio::task::JoinHandle<Result<(), NodeRuntimeError>>,
    ),
    NodeRuntimeError,
> {
    NodeRuntime::spawn(
        node,
        V5MempoolConfig::default(),
        128,
        LocalTimestampMs::new(RECOVERY_NOW_MS),
    )
}

async fn stop_runtime(
    handle: &NodeHandle,
    task: tokio::task::JoinHandle<Result<(), NodeRuntimeError>>,
) {
    handle
        .shutdown()
        .await
        .expect("runtime shutdown is accepted");
    task.await
        .expect("runtime task does not panic")
        .expect("runtime exits cleanly");
}

/// In-memory backend that fails only atomic protocol-2 finalization batches.
struct FinalizationFailingStore {
    inner: MemoryKvStore,
    failures_remaining: Arc<AtomicU32>,
    failed_attempts: Arc<AtomicU32>,
}

impl KvStore for FinalizationFailingStore {
    fn get(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(table, key)
    }

    fn commit(&mut self, batch: WriteBatch) -> Result<(), StorageError> {
        let is_v4_finalization = batch.iter().any(|(table, _, _)| table == Table::BlocksV2);
        if is_v4_finalization
            && self
                .failures_remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
        {
            self.failed_attempts.fetch_add(1, Ordering::SeqCst);
            return Err(StorageError::Io(
                "injected protocol-2 finalization failure".into(),
            ));
        }
        self.inner.commit(batch)
    }

    fn last_key(&self, table: Table) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.last_key(table)
    }

    fn scan(
        &self,
        table: Table,
        start_inclusive: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<KvEntry>, StorageError> {
        self.inner.scan(table, start_inclusive, limit)
    }
}

fn failing_node(
    genesis: &GenesisConfig,
    failures: u32,
) -> (Node<FinalizationFailingStore>, Arc<AtomicU32>) {
    let failed_attempts = Arc::new(AtomicU32::new(0));
    let backend = FinalizationFailingStore {
        inner: MemoryKvStore::new(),
        failures_remaining: Arc::new(AtomicU32::new(failures)),
        failed_attempts: failed_attempts.clone(),
    };
    (
        Node::open(backend, genesis).expect("protocol-2 node opens"),
        failed_attempts,
    )
}

#[tokio::test]
async fn a_transient_v4_finalization_failure_is_retried_and_survived() {
    let seed = [1u8; 32];
    let validator = Keypair::from_seed(seed);
    let genesis = validator_genesis(std::slice::from_ref(&validator));
    let (network, inbound) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([91; 32]),
        genesis.chain.chain_id.clone(),
        Some("127.0.0.1:0".parse().expect("listen address parses")),
        Vec::new(),
    ))
    .await
    .expect("network starts");
    let (node, failed_attempts) = failing_node(&genesis, 1);
    let (runtime, runtime_task) = spawn_runtime(node).expect("runtime starts");
    let (commit_tx, mut commit_rx) = mpsc::channel::<CommitInfo>(64);
    let driver = tokio::spawn(
        ConsensusDriverV1::new(
            runtime.clone(),
            network,
            Some(seed),
            DriverTimeouts::default(),
        )
        .run(inbound, Some(commit_tx)),
    );

    let committed = tokio::time::timeout(Duration::from_secs(10), async {
        let mut last_height = 0;
        while last_height < 2 {
            last_height = commit_rx.recv().await.expect("driver remains alive").height;
        }
    })
    .await;
    assert!(committed.is_ok(), "driver did not progress after retry");
    assert_eq!(
        failed_attempts.load(Ordering::SeqCst),
        1,
        "exactly one selected finalization commit must fail"
    );

    driver.abort();
    let _ = driver.await;
    stop_runtime(&runtime, runtime_task).await;
}

#[tokio::test]
async fn persistent_v4_finalization_failure_exits_after_bounded_retries() {
    let seed = [2u8; 32];
    let validator = Keypair::from_seed(seed);
    let genesis = validator_genesis(std::slice::from_ref(&validator));
    let (network, inbound) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([92; 32]),
        genesis.chain.chain_id.clone(),
        Some("127.0.0.1:0".parse().expect("listen address parses")),
        Vec::new(),
    ))
    .await
    .expect("network starts");
    let (node, failed_attempts) = failing_node(&genesis, u32::MAX);
    let (runtime, runtime_task) = spawn_runtime(node).expect("runtime starts");
    let exit = tokio::time::timeout(
        Duration::from_secs(10),
        ConsensusDriverV1::new(
            runtime.clone(),
            network,
            Some(seed),
            DriverTimeouts::default(),
        )
        .run(inbound, None),
    )
    .await
    .expect("driver exits after bounded retries");
    assert!(
        matches!(exit, DriverExitV1::StorageFailed { .. }),
        "persistent storage failure must be typed, got {exit:?}"
    );
    assert_eq!(
        failed_attempts.load(Ordering::SeqCst),
        4,
        "one initial attempt plus three retries are permitted"
    );

    stop_runtime(&runtime, runtime_task).await;
}

#[derive(Default)]
struct SignedLog {
    proposals: BTreeMap<u32, Hash256>,
    votes: BTreeMap<(u32, VoteType), Hash256>,
    conflicts: Vec<String>,
}

impl SignedLog {
    fn absorb(&mut self, message: &NetMessage) {
        match message {
            NetMessage::ProposalV4(proposal) if proposal.payload.height == 1 => {
                let round = proposal.payload.round;
                let hash = proposal.payload.block_hash;
                match self.proposals.get(&round) {
                    Some(first) if *first != hash => self.conflicts.push(format!(
                        "conflicting V4 proposals at round {round}: {first:?} vs {hash:?}"
                    )),
                    Some(_) => {}
                    None => {
                        self.proposals.insert(round, hash);
                    }
                }
            }
            NetMessage::Vote(vote)
                if vote.payload.protocol_version == TRANSACTION_V5_PROTOCOL_VERSION
                    && vote.payload.height == 1 =>
            {
                let key = (vote.payload.round, vote.payload.vote_type);
                let hash = vote.payload.block_hash;
                match self.votes.get(&key) {
                    Some(first) if *first != hash => self.conflicts.push(format!(
                        "conflicting protocol-2 votes at {key:?}: {first:?} vs {hash:?}"
                    )),
                    Some(_) => {}
                    None => {
                        self.votes.insert(key, hash);
                    }
                }
            }
            _ => {}
        }
    }
}

fn drain(inbound: &mut mpsc::Receiver<InboundMessage>, log: &mut SignedLog) {
    while let Ok(message) = inbound.try_recv() {
        log.absorb(&message.message);
    }
}

#[tokio::test]
async fn restarted_protocol2_validator_never_signs_a_conflicting_message() {
    let seeds = [[11u8; 32], [12u8; 32], [13u8; 32]];
    let validators = seeds
        .iter()
        .map(|seed| Keypair::from_seed(*seed))
        .collect::<Vec<_>>();
    let genesis = validator_genesis(&validators);
    let probe = Node::open(MemoryKvStore::new(), &genesis).expect("probe node opens");
    let set = ValidatorSet::from_state(probe.state()).expect("validator set derives");
    let leader = set.proposer_for(1, 0).expect("height-one leader exists");
    let leader_index = validators
        .iter()
        .position(|validator| validator.address() == leader)
        .expect("leader is in genesis");
    let leader_seed = seeds[leader_index];

    let (harness, mut harness_inbound) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([90; 32]),
        genesis.chain.chain_id.clone(),
        Some("127.0.0.1:0".parse().expect("listen address parses")),
        Vec::new(),
    ))
    .await
    .expect("harness network starts");
    let harness_addr = harness.local_addr().expect("harness listens");
    let temp = tempfile::tempdir().expect("temporary database directory exists");
    let store_path = temp.path().join("protocol2-validator.redb");
    let timeouts = DriverTimeouts {
        propose: Duration::from_millis(200),
        prevote: Duration::from_millis(200),
        precommit: Duration::from_millis(200),
        increment: Duration::from_millis(150),
    };
    let mut log = SignedLog::default();

    {
        let (network, inbound) = spawn_network(NetworkConfig::new(
            Keypair::from_seed([91; 32]),
            genesis.chain.chain_id.clone(),
            Some("127.0.0.1:0".parse().expect("listen address parses")),
            vec![harness_addr],
        ))
        .await
        .expect("first validator network starts");
        wait_for_peer(&network).await;
        let node = Node::open(
            RedbKvStore::open(&store_path).expect("database opens"),
            &genesis,
        )
        .expect("first protocol-2 node opens");
        let (runtime, runtime_task) = spawn_runtime(node).expect("first runtime starts");
        let driver = tokio::spawn(
            ConsensusDriverV1::new(runtime.clone(), network, Some(leader_seed), timeouts)
                .run(inbound, None),
        );

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                drain(&mut harness_inbound, &mut log);
                if log.proposals.contains_key(&0) && log.votes.contains_key(&(0, VoteType::Prevote))
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("first life proposes and prevotes");
        driver.abort();
        let _ = driver.await;
        stop_runtime(&runtime, runtime_task).await;
    }

    tokio::time::sleep(Duration::from_millis(25)).await;
    let (network, inbound) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([92; 32]),
        genesis.chain.chain_id.clone(),
        Some("127.0.0.1:0".parse().expect("listen address parses")),
        vec![harness_addr],
    ))
    .await
    .expect("restarted validator network starts");
    wait_for_peer(&network).await;
    let node = Node::open(
        RedbKvStore::open(&store_path).expect("database reopens"),
        &genesis,
    )
    .expect("restarted protocol-2 node opens");
    let (runtime, runtime_task) = spawn_runtime(node).expect("restarted runtime starts");
    let driver = tokio::spawn(
        ConsensusDriverV1::new(runtime.clone(), network, Some(leader_seed), timeouts)
            .run(inbound, None),
    );

    let mut later_round_activity = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        while let Ok(message) = harness_inbound.try_recv() {
            match &message.message {
                NetMessage::ProposalV4(proposal)
                    if proposal.payload.height == 1 && proposal.payload.round > 0 =>
                {
                    later_round_activity = true;
                }
                NetMessage::Vote(vote)
                    if vote.payload.protocol_version == TRANSACTION_V5_PROTOCOL_VERSION
                        && vote.payload.height == 1
                        && vote.payload.round > 0 =>
                {
                    later_round_activity = true;
                }
                _ => {}
            }
            log.absorb(&message.message);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    driver.abort();
    let _ = driver.await;
    stop_runtime(&runtime, runtime_task).await;
    assert!(
        log.conflicts.is_empty(),
        "restarted protocol-2 validator self-equivocated: {:?}",
        log.conflicts
    );
    assert!(
        later_round_activity,
        "restarted validator must keep participating in later rounds"
    );
}

async fn wait_for_peer(network: &webc_net::NetworkHandle) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while network.connected_peers() == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "validator did not connect to harness"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
