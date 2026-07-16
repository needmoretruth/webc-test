//! C2 regression: the consensus driver must never terminate silently when a
//! finalized block fails to import.
//!
//! Two distinct failure classes must both be surfaced, not swallowed:
//! - a **transient storage I/O failure** must be retried, and only a
//!   persistent failure may stop the driver — with a typed reason;
//! - a **certified-but-unimportable block** (a block carrying a valid
//!   finality certificate that fails local re-execution) is a post-finality
//!   consensus emergency: it proves more than two-thirds of stake certified a
//!   state transition this node rejects. The node must stop loudly so an
//!   operator can investigate, not exit as if the network had simply closed.
//!
//! Pre-fix behavior (review finding C2, CONFIRMED): `commit_if_decided`
//! returned `true` on any import error and `run()` treated that as a clean
//! exit — no retry, no distinguishable signal; the sync path swallowed the
//! error entirely.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use webc_chain::{
    Amount, ChainConfig, FinalityCertificate, GenesisAccount, GenesisConfig, GenesisValidator,
    SignedVote, ValidatorSet, Vote, VoteType,
};
use webc_crypto::{Hash256, Keypair};
use webc_net::{spawn_network, CertifiedBlock, NetMessage, NetworkConfig};
use webc_node::{CommitInfo, ConsensusDriver, DriverExit, DriverTimeouts, MempoolConfig, Node};
use webc_storage::{KvEntry, KvStore, MemoryKvStore, StorageError, Table, WriteBatch};

/// A storage backend whose commits can be made to fail on demand with a
/// transient-class I/O error, for exercising the driver's failure paths.
struct FailingKvStore {
    inner: MemoryKvStore,
    /// While set, every commit fails with `StorageError::Io`.
    fail_commits: Arc<AtomicBool>,
    /// Counts commit attempts made while failure is armed (observes retries).
    failed_attempts: Arc<AtomicU32>,
}

impl KvStore for FailingKvStore {
    fn get(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(table, key)
    }

    fn commit(&mut self, batch: WriteBatch) -> Result<(), StorageError> {
        if self.fail_commits.load(Ordering::SeqCst) {
            self.failed_attempts.fetch_add(1, Ordering::SeqCst);
            return Err(StorageError::Io("injected transient failure".into()));
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

fn validator_genesis(validators: &[Keypair]) -> GenesisConfig {
    let accounts = validators
        .iter()
        .map(|keypair| GenesisAccount {
            address: keypair.address(),
            balance: Amount::from_webc(1_000),
        })
        .collect();
    let genesis_validators = validators
        .iter()
        .map(|keypair| GenesisValidator {
            operator: keypair.address(),
            consensus_key: keypair.public_key(),
            self_stake: Amount::from_webc(200),
            commission_bps: 500,
            bootstrap: false,
        })
        .collect();
    GenesisConfig {
        chain: ChainConfig::default(),
        accounts,
        validators: genesis_validators,
    }
}

/// A single-validator driver self-finalizes heights continuously; when its
/// store starts failing persistently, the driver must stop with a typed
/// storage-failure exit — after retrying — never a silent clean return.
#[tokio::test]
async fn a_persistent_storage_failure_exits_typed_after_retrying() {
    let chain = ChainConfig::default().chain_id;
    let seed = [1u8; 32];
    let validator = Keypair::from_seed(seed);
    let genesis = validator_genesis(std::slice::from_ref(&validator));

    // A network handle is required but no peers are: the single validator
    // reaches quorum alone.
    let (handle, inbound) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([91u8; 32]),
        chain.clone(),
        Some("127.0.0.1:0".parse().unwrap()),
        Vec::new(),
    ))
    .await
    .unwrap();

    let fail_commits = Arc::new(AtomicBool::new(false));
    let failed_attempts = Arc::new(AtomicU32::new(0));
    let backend = FailingKvStore {
        inner: MemoryKvStore::new(),
        fail_commits: fail_commits.clone(),
        failed_attempts: failed_attempts.clone(),
    };
    let node = Node::open(backend, &genesis).unwrap();
    let (commit_tx, mut commit_rx) = mpsc::channel::<CommitInfo>(1024);
    let driver = ConsensusDriver::new(
        node,
        handle,
        Some(seed),
        DriverTimeouts::default(),
        MempoolConfig::default(),
    );
    let task = tokio::spawn(driver.run(inbound, Some(commit_tx)));

    // Let it commit a few heights, then break the store permanently.
    let warmup = tokio::time::timeout(Duration::from_secs(10), async {
        let mut last = 0;
        while last < 2 {
            if let Some(info) = commit_rx.recv().await {
                last = info.height;
            } else {
                panic!("driver stopped during warmup");
            }
        }
    })
    .await;
    assert!(warmup.is_ok(), "single validator did not self-finalize");
    fail_commits.store(true, Ordering::SeqCst);

    let exit = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("driver must stop once storage fails persistently")
        .expect("driver task must not panic");
    assert!(
        matches!(exit, DriverExit::StorageFailed { .. }),
        "a persistent storage failure must surface as a typed exit, got: {exit:?}"
    );
    assert!(
        failed_attempts.load(Ordering::SeqCst) >= 2,
        "the driver must retry a transient-class storage failure before giving up"
    );
}

/// A transient (single) storage failure must be retried and survived: the
/// driver keeps finalizing heights afterwards.
#[tokio::test]
async fn a_transient_storage_failure_is_retried_and_survived() {
    let chain = ChainConfig::default().chain_id;
    let seed = [1u8; 32];
    let validator = Keypair::from_seed(seed);
    let genesis = validator_genesis(std::slice::from_ref(&validator));

    let (handle, inbound) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([92u8; 32]),
        chain.clone(),
        Some("127.0.0.1:0".parse().unwrap()),
        Vec::new(),
    ))
    .await
    .unwrap();

    let fail_commits = Arc::new(AtomicBool::new(false));
    let failed_attempts = Arc::new(AtomicU32::new(0));
    let backend = FailingKvStore {
        inner: MemoryKvStore::new(),
        fail_commits: fail_commits.clone(),
        failed_attempts: failed_attempts.clone(),
    };
    let node = Node::open(backend, &genesis).unwrap();
    let (commit_tx, mut commit_rx) = mpsc::channel::<CommitInfo>(1024);
    let driver = ConsensusDriver::new(
        node,
        handle,
        Some(seed),
        DriverTimeouts::default(),
        MempoolConfig::default(),
    );
    let task = tokio::spawn(driver.run(inbound, Some(commit_tx)));

    // Wait for the first commit, then break the store.
    let warmup = tokio::time::timeout(Duration::from_secs(10), commit_rx.recv()).await;
    assert!(
        matches!(warmup, Ok(Some(_))),
        "single validator did not self-finalize"
    );
    fail_commits.store(true, Ordering::SeqCst);

    // The driver keeps committing, so it must hit the armed failure soon.
    // Disarm as soon as the first attempt fails: the driver's first retry
    // backoff (50 ms) then lands on a healthy store — a transient fault.
    let armed = tokio::time::timeout(Duration::from_secs(10), async {
        while failed_attempts.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await;
    assert!(armed.is_ok(), "the injected failure was never hit");
    fail_commits.store(false, Ordering::SeqCst);

    // Survival: the driver must keep finalizing new heights after the fault.
    let progressed = tokio::time::timeout(Duration::from_secs(10), async {
        let mut after_fault = 0u32;
        while after_fault < 3 {
            match commit_rx.recv().await {
                Some(_) => after_fault += 1,
                None => panic!("driver stopped after a transient storage failure"),
            }
        }
    })
    .await;
    assert!(
        progressed.is_ok(),
        "the driver did not survive a single transient storage failure"
    );
    task.abort();
    let _ = task.await;
}

/// A block carrying a *valid* finality certificate that fails re-execution is
/// a consensus emergency and must stop the driver with a typed reason — it is
/// cryptographic proof that >2/3 of stake certified a transition this node
/// rejects. Pre-fix, the sync path swallowed the error and the node stalled
/// silently forever.
#[tokio::test]
async fn a_certified_invalid_block_is_a_surfaced_consensus_emergency() {
    let chain = ChainConfig::default().chain_id;
    // Four equal validators: the harness holds three keys (75% > 2/3), so it
    // can produce a genuinely verifying certificate for an invalid block.
    let seeds: [[u8; 32]; 4] = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    let validators: Vec<Keypair> = seeds.iter().map(|s| Keypair::from_seed(*s)).collect();
    let genesis = validator_genesis(&validators);

    let probe = Node::open(MemoryKvStore::new(), &genesis).unwrap();
    let snapshot = ValidatorSet::from_state(probe.state()).unwrap();

    // Forge an unimportable block and certify it with three of four keys.
    let mut bad_block = probe
        .build_candidate(
            Vec::new(),
            Vec::new(),
            validators[1].address(),
            1_700_000_000_000,
        )
        .unwrap();
    bad_block.header.state_root = Hash256([0xAB; 32]);
    let bad_hash = bad_block.hash().unwrap();
    let precommits: Vec<SignedVote> = validators[1..]
        .iter()
        .map(|key| {
            SignedVote::sign(
                Vote {
                    protocol_version: genesis.chain.protocol_version,
                    chain_id: chain.clone(),
                    height: 1,
                    round: 0,
                    vote_type: VoteType::Precommit,
                    block_hash: bad_hash,
                    validator: key.address(),
                },
                key,
            )
            .unwrap()
        })
        .collect();
    let certificate = FinalityCertificate::build(
        &snapshot,
        genesis.chain.protocol_version,
        chain.clone(),
        1,
        0,
        bad_hash,
        &precommits,
    )
    .expect("three of four equal validators exceed two thirds");
    certificate
        .verify(&snapshot, genesis.chain.protocol_version, &chain)
        .expect("the forged block's certificate genuinely verifies");

    // Harness peer + the honest driver (holding the fourth key).
    let (harness, _harness_inbound) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([93u8; 32]),
        chain.clone(),
        Some("127.0.0.1:0".parse().unwrap()),
        Vec::new(),
    ))
    .await
    .unwrap();
    let harness_addr = harness.local_addr().unwrap();
    let (handle, inbound) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([94u8; 32]),
        chain.clone(),
        Some("127.0.0.1:0".parse().unwrap()),
        vec![harness_addr],
    ))
    .await
    .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while handle.connected_peers() == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "driver did not peer with the harness"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let node = Node::open(MemoryKvStore::new(), &genesis).unwrap();
    let driver = ConsensusDriver::new(
        node,
        handle,
        Some(seeds[0]),
        DriverTimeouts::default(),
        MempoolConfig::default(),
    );
    let task = tokio::spawn(driver.run(inbound, None));

    // Deliver the certified-but-invalid block through the state-sync path.
    harness
        .broadcast(NetMessage::BlockResponse(Box::new(CertifiedBlock {
            block: bad_block,
            certificate,
        })))
        .unwrap();

    let exit = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("the driver must stop on a certified-but-unimportable block")
        .expect("driver task must not panic");
    assert!(
        matches!(exit, DriverExit::CertifiedBlockInvalid { height: 1, .. }),
        "a certified invalid block must surface as a consensus emergency, got: {exit:?}"
    );
}
