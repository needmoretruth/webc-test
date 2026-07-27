//! Protocol-2 HTTP-to-finality convergence over the real authenticated network.
//!
//! Purpose: prove three validator runtimes share V5 gossip, the V4 BFT driver,
//! atomic certified storage, and finalized receipt APIs end to end. Responsibilities:
//! submit one signed transaction through HTTP, run three real TCP gossip meshes,
//! observe identical certified tips, query the durable receipt, and prove a late
//! observer can replay certified V4 state sync across an epoch boundary.
//! Non-responsibilities: benchmark throughput, choose first-checkpoint trust, or
//! launch the public CLI command.
//!
//! Data flow: HTTP admits and gossips to node zero; each driver consumes its
//! network receiver and actor handle; one scheduled leader builds a V4 proposal;
//! the shared BFT core certifies it; every actor replays and atomically finalizes;
//! HTTP then returns the stored position-bound receipt. A late observer starts
//! from genesis, requests certified blocks, replays them through the same actor,
//! and reconstructs the exact receipt and successor authority epoch.
//!
//! Security boundary: the test crosses the actual HTTP body limits, V6 decoder,
//! proposal signatures/authority commitments, certificate verifier, WAL-before-
//! broadcast path, and disk-first actor finalization instead of injecting state.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use tokio::sync::mpsc;
use tower::ServiceExt;
use webc_chain::{
    ActionV1, Amount, AuthorizationLaneId, AuthorizationPolicyRevision, BlockHeight, ChainConfig,
    ChainId, Epoch, FeeBid, FeePaymentV1, GenesisAccount, GenesisConfig, GenesisValidator, Nonce,
    Operation, TransactionAuthorizationV1, TransactionV5, ValidityWindowV1,
    TRANSACTION_V5_PROTOCOL_VERSION,
};
use webc_crypto::{Hash256, Keypair};
use webc_net::{spawn_network, NetworkConfig};
use webc_node::{
    router_v2, CommitInfo, ConsensusDriverV1, DriverTimeouts, Node, NodeHandle, NodeRuntime,
    NodeRuntimeError, V2AppState, V5MempoolConfig,
};
use webc_storage::{LocalTimestampMs, MemoryKvStore};

const NOW: u64 = 1_700_000_000_000;

fn genesis(validators: &[Keypair], sender: &Keypair) -> GenesisConfig {
    let mut accounts = validators
        .iter()
        .map(|validator| GenesisAccount {
            address: validator.address(),
            balance: Amount::from_webc(1_000),
        })
        .collect::<Vec<_>>();
    accounts.push(GenesisAccount {
        address: sender.address(),
        balance: Amount::from_webc(1_000),
    });
    GenesisConfig {
        chain: ChainConfig {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            ..ChainConfig::default()
        },
        accounts,
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

fn transfer(sender: &Keypair, recipient: &Keypair) -> TransactionV5 {
    let mut transaction = TransactionV5::for_actions_unsigned(
        ChainId::devnet(),
        sender.address(),
        sender.public_key(),
        TransactionAuthorizationV1 {
            lane: AuthorizationLaneId::DEFAULT,
            policy_revision: AuthorizationPolicyRevision::new(0),
            nonce: Nonce::new(0),
        },
        ValidityWindowV1::new(BlockHeight::new(1), BlockHeight::new(1_000)),
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
    .expect("V5 transfer shape validates");
    transaction.sign(sender).expect("V5 transfer signs");
    transaction
}

fn spawn_runtime(
    genesis: &GenesisConfig,
) -> (
    NodeHandle,
    tokio::task::JoinHandle<Result<(), NodeRuntimeError>>,
) {
    let node = Node::open(MemoryKvStore::new(), genesis).expect("protocol-2 node opens");
    NodeRuntime::spawn(
        node,
        V5MempoolConfig::default(),
        128,
        LocalTimestampMs::new(NOW),
    )
    .expect("runtime starts")
}

fn driver_timeouts() -> DriverTimeouts {
    DriverTimeouts {
        propose: Duration::from_millis(400),
        prevote: Duration::from_millis(400),
        precommit: Duration::from_millis(400),
        increment: Duration::from_millis(200),
    }
}

fn local_now_ms() -> LocalTimestampMs {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock is after the Unix epoch")
        .as_millis();
    LocalTimestampMs::new(u64::try_from(milliseconds).expect("test time fits u64 milliseconds"))
}

#[tokio::test]
async fn three_validators_finalize_http_gossip_transaction_and_receipt() {
    let seeds = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let validators = seeds
        .iter()
        .map(|seed| Keypair::from_seed(*seed))
        .collect::<Vec<_>>();
    let sender = Keypair::from_seed([51; 32]);
    let recipient = Keypair::from_seed([52; 32]);
    let genesis = genesis(&validators, &sender);
    let chain_id = genesis.chain.chain_id.clone();

    let mut networks = Vec::new();
    let mut inbounds = Vec::new();
    let mut prior = Vec::new();
    for index in 0..3u8 {
        let (network, inbound) = spawn_network(NetworkConfig::new(
            Keypair::from_seed([100 + index; 32]),
            chain_id.clone(),
            Some("127.0.0.1:0".parse().expect("listen address parses")),
            prior.clone(),
        ))
        .await
        .expect("network starts");
        prior.push(network.local_addr().expect("network listens"));
        networks.push(network);
        inbounds.push(inbound);
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while networks.iter().any(|network| network.connected_peers() < 2) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "peers did not connect"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let mut runtimes = Vec::new();
    let mut runtime_tasks = Vec::new();
    for _ in 0..3 {
        let (runtime, task) = spawn_runtime(&genesis);
        runtimes.push(runtime);
        runtime_tasks.push(task);
    }

    let transaction = transfer(&sender, &recipient);
    let transaction_id = transaction
        .transaction_id()
        .expect("submitted transaction has an ID");
    let app = router_v2(V2AppState::with_network(
        runtimes[0].clone(),
        networks[0].clone(),
    ));
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2/transactions")
                .body(Body::from(
                    serde_json::to_vec(&transaction).expect("transaction serializes"),
                ))
                .expect("request builds"),
        )
        .await
        .expect("submission responds");
    assert_eq!(response.status(), StatusCode::OK);

    let timeouts = driver_timeouts();
    let mut commit_receivers = Vec::new();
    let mut driver_tasks = Vec::new();
    for (index, (network, inbound)) in networks
        .iter()
        .cloned()
        .zip(inbounds.into_iter())
        .enumerate()
    {
        let (commit_tx, commit_rx) = mpsc::channel::<CommitInfo>(64);
        commit_receivers.push(commit_rx);
        driver_tasks.push(tokio::spawn(
            ConsensusDriverV1::new(
                runtimes[index].clone(),
                network,
                Some(seeds[index]),
                timeouts,
            )
            .run(inbound, Some(commit_tx)),
        ));
    }

    let mut tips: Vec<BTreeMap<u64, Hash256>> = vec![BTreeMap::new(); 3];
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            for (index, receiver) in commit_receivers.iter_mut().enumerate() {
                while let Ok(info) = receiver.try_recv() {
                    if let Some(tip) = info.tip {
                        tips[index].insert(info.height, tip);
                    }
                }
            }
            let finalized_everywhere = futures_util::future::join_all(
                runtimes
                    .iter()
                    .map(|runtime| runtime.receipt(transaction_id)),
            )
            .await
            .into_iter()
            .all(|result| result.ok().flatten().is_some());
            if finalized_everywhere {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("transaction did not finalize on all validators");

    let finalized_height = runtimes[0]
        .receipt(transaction_id)
        .await
        .expect("receipt query succeeds")
        .expect("receipt is finalized")
        .position
        .height
        .get();
    for node_tips in &tips {
        assert_eq!(
            node_tips.get(&finalized_height),
            tips[0].get(&finalized_height),
            "validators disagree on the transaction's finalized block"
        );
    }
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/v2/transactions/{transaction_id}/receipt"))
                .body(Body::empty())
                .expect("receipt request builds"),
        )
        .await
        .expect("receipt route responds");
    assert_eq!(response.status(), StatusCode::OK);

    for task in driver_tasks {
        task.abort();
    }
    for runtime in &runtimes {
        runtime.shutdown().await.expect("runtime shuts down");
    }
    for task in runtime_tasks {
        task.await
            .expect("runtime does not panic")
            .expect("runtime exits cleanly");
    }
}

#[tokio::test]
async fn late_observer_replays_certified_v4_blocks_across_an_epoch_boundary() {
    let seeds = [[11u8; 32], [12u8; 32], [13u8; 32]];
    let validators = seeds
        .iter()
        .map(|seed| Keypair::from_seed(*seed))
        .collect::<Vec<_>>();
    let sender = Keypair::from_seed([61; 32]);
    let recipient = Keypair::from_seed([62; 32]);
    let mut genesis = genesis(&validators, &sender);
    // Height two commits the epoch-1 authority set, so syncing through height
    // three proves the observer did not merely import same-epoch blocks.
    genesis.chain.staking.blocks_per_epoch = 2;
    let chain_id = genesis.chain.chain_id.clone();

    let mut validator_networks = Vec::new();
    let mut validator_inbounds = Vec::new();
    let mut validator_addresses = Vec::new();
    for index in 0..3u8 {
        let (network, inbound) = spawn_network(NetworkConfig::new(
            Keypair::from_seed([210 + index; 32]),
            chain_id.clone(),
            Some("127.0.0.1:0".parse().expect("listen address parses")),
            validator_addresses.clone(),
        ))
        .await
        .expect("validator network starts");
        validator_addresses.push(network.local_addr().expect("validator listens"));
        validator_networks.push(network);
        validator_inbounds.push(inbound);
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while validator_networks
        .iter()
        .any(|network| network.connected_peers() < 2)
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "validator mesh did not connect"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let transaction = transfer(&sender, &recipient);
    let transaction_id = transaction
        .transaction_id()
        .expect("synced transaction has an ID");
    let mut validator_runtimes = Vec::new();
    let mut runtime_tasks = Vec::new();
    for _ in 0..3 {
        let (runtime, task) = spawn_runtime(&genesis);
        runtime
            .submit(transaction.clone(), local_now_ms())
            .await
            .expect("transaction enters each validator's durable queue");
        validator_runtimes.push(runtime);
        runtime_tasks.push(task);
    }

    let mut validator_drivers = Vec::new();
    for (index, (network, inbound)) in validator_networks
        .iter()
        .cloned()
        .zip(validator_inbounds.into_iter())
        .enumerate()
    {
        validator_drivers.push(tokio::spawn(
            ConsensusDriverV1::new(
                validator_runtimes[index].clone(),
                network,
                Some(seeds[index]),
                driver_timeouts(),
            )
            .run(inbound, None),
        ));
    }

    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let committed =
                futures_util::future::join_all(validator_runtimes.iter().map(NodeHandle::stats))
                    .await
                    .into_iter()
                    .all(|result| result.is_ok_and(|stats| stats.committed_height.get() >= 3));
            if committed {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("validators did not finalize through epoch-1 height three");

    // The observer has no signing seed and starts only after the validator
    // history exists. It must learn a higher certificate, request height one,
    // verify every response, and atomically replay each block in order.
    let (observer_network, observer_inbound) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([250; 32]),
        chain_id,
        Some("127.0.0.1:0".parse().expect("listen address parses")),
        validator_addresses,
    ))
    .await
    .expect("observer network starts");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while observer_network.connected_peers() == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "late observer did not connect"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (observer_runtime, observer_runtime_task) = spawn_runtime(&genesis);
    let observer_driver = tokio::spawn(
        ConsensusDriverV1::new(
            observer_runtime.clone(),
            observer_network,
            None,
            driver_timeouts(),
        )
        .run(observer_inbound, None),
    );

    let sync_result = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let stats = observer_runtime
                .stats()
                .await
                .expect("observer actor remains available");
            let receipt = observer_runtime
                .receipt(transaction_id)
                .await
                .expect("observer receipt query succeeds");
            if stats.committed_height.get() >= 3 && receipt.is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if sync_result.is_err() {
        let validator_heights =
            futures_util::future::join_all(validator_runtimes.iter().map(NodeHandle::stats))
                .await
                .into_iter()
                .map(|result| result.map(|stats| stats.committed_height.get()))
                .collect::<Vec<_>>();
        let observer_height = observer_runtime
            .stats()
            .await
            .map(|stats| stats.committed_height.get());
        eprintln!(
            "late-sync timeout: validators={validator_heights:?}, observer={observer_height:?}, validator_drivers_finished={:?}, observer_driver_finished={}",
            validator_drivers
                .iter()
                .map(tokio::task::JoinHandle::is_finished)
                .collect::<Vec<_>>(),
            observer_driver.is_finished(),
        );
    }
    assert!(
        sync_result.is_ok(),
        "late observer did not replay the finalized transaction through height three"
    );

    for height in 1..=3 {
        let expected = validator_runtimes[0]
            .certified_block_v4(BlockHeight::new(height))
            .await
            .expect("validator snapshot query succeeds")
            .expect("validator stores the certified block");
        let observed = observer_runtime
            .certified_block_v4(BlockHeight::new(height))
            .await
            .expect("observer snapshot query succeeds")
            .expect("observer stores the synced certified block");
        assert_eq!(observed, expected, "state sync diverged at height {height}");
    }
    let epoch_one_snapshot = observer_runtime
        .certified_block_v4(BlockHeight::new(3))
        .await
        .expect("observer epoch-one snapshot query succeeds")
        .expect("observer stores epoch-one height three");
    assert_eq!(epoch_one_snapshot.block.header.epoch, Epoch::new(1));
    assert_eq!(epoch_one_snapshot.next_authority_set.epoch, Epoch::new(1));

    observer_driver.abort();
    for driver in validator_drivers {
        driver.abort();
    }
    observer_runtime
        .shutdown()
        .await
        .expect("observer runtime shuts down");
    for runtime in &validator_runtimes {
        runtime
            .shutdown()
            .await
            .expect("validator runtime shuts down");
    }
    observer_runtime_task
        .await
        .expect("observer runtime does not panic")
        .expect("observer runtime exits cleanly");
    for task in runtime_tasks {
        task.await
            .expect("validator runtime does not panic")
            .expect("validator runtime exits cleanly");
    }
}
