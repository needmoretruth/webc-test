//! Protocol-2 RPC-to-gossip integration over authenticated TCP.
//!
//! Purpose: prove a V5 transaction accepted durably through node A's real V2
//! router is encoded under network wire v5, authenticated/flooded, and admitted
//! by node B's same single-owner runtime. Responsibilities: one end-to-end happy
//! path plus bounded waiting. Non-responsibilities: consensus proposal/finality
//! and finalized query, which require the protocol-2 driver checkpoint.
//!
//! Security boundary: both network decoders and both mempools receive the signed
//! wire as hostile input. The test observes only public runtime counters and does
//! not inject directly into node B.

use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use tower::ServiceExt;
use webc_chain::{
    ActionV1, Amount, AuthorizationLaneId, AuthorizationPolicyRevision, BlockHeight, ChainConfig,
    ChainId, FeeBid, FeePaymentV1, GenesisAccount, GenesisConfig, Nonce, Operation,
    TransactionAuthorizationV1, TransactionV5, ValidityWindowV1, TRANSACTION_V5_PROTOCOL_VERSION,
};
use webc_crypto::Keypair;
use webc_net::{spawn_network, NetworkConfig};
use webc_node::{
    router_v2, run_v5_gossip_pump, Node, NodeHandle, NodeRuntime, NodeRuntimeError, V2AppState,
    V5MempoolConfig,
};
use webc_storage::{LocalTimestampMs, MemoryKvStore};

fn spawn_runtime(
    alice: &Keypair,
) -> (
    NodeHandle,
    tokio::task::JoinHandle<Result<(), NodeRuntimeError>>,
) {
    let genesis = GenesisConfig {
        chain: ChainConfig {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            ..ChainConfig::default()
        },
        accounts: vec![GenesisAccount {
            address: alice.address(),
            balance: Amount::from_units(10_000_000),
        }],
        validators: Vec::new(),
    };
    let node = Node::open(MemoryKvStore::new(), &genesis).expect("protocol-2 node opens");
    NodeRuntime::spawn(
        node,
        V5MempoolConfig::default(),
        32,
        LocalTimestampMs::new(1_700_000_000_000),
    )
    .expect("protocol-2 runtime starts")
}

fn transfer(alice: &Keypair, bob: &Keypair) -> TransactionV5 {
    let mut transaction = TransactionV5::for_actions_unsigned(
        ChainId::devnet(),
        alice.address(),
        alice.public_key(),
        TransactionAuthorizationV1 {
            lane: AuthorizationLaneId::DEFAULT,
            policy_revision: AuthorizationPolicyRevision::new(0),
            nonce: Nonce::new(0),
        },
        ValidityWindowV1::new(BlockHeight::new(1), BlockHeight::new(20)),
        vec![ActionV1::native(Operation::Transfer {
            to: bob.address(),
            amount: Amount::from_units(1),
        })],
        FeeBid {
            gas_limit: 1_000,
            max_fee_per_unit: 5,
            priority_fee_per_unit: 1,
        },
        FeePaymentV1::SenderLane,
    )
    .expect("V5 transfer shape is valid");
    transaction.sign(alice).expect("V5 transfer signs");
    transaction
}

#[tokio::test]
async fn v2_http_submission_reaches_the_other_runtime_over_wire_v5() {
    let alice = Keypair::from_seed([61; 32]);
    let bob = Keypair::from_seed([62; 32]);
    let chain_id = ChainId::devnet();
    let (a_network, a_inbound) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([63; 32]),
        chain_id.clone(),
        Some("127.0.0.1:0".parse().expect("listen address parses")),
        Vec::new(),
    ))
    .await
    .expect("node A network starts");
    let a_address = a_network.local_addr().expect("node A listens");
    let (b_network, b_inbound) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([64; 32]),
        chain_id,
        Some("127.0.0.1:0".parse().expect("listen address parses")),
        vec![a_address],
    ))
    .await
    .expect("node B network starts");

    let (a_runtime, a_task) = spawn_runtime(&alice);
    let (b_runtime, b_task) = spawn_runtime(&alice);
    tokio::spawn(run_v5_gossip_pump(a_runtime.clone(), a_inbound));
    tokio::spawn(run_v5_gossip_pump(b_runtime.clone(), b_inbound));
    let app = router_v2(V2AppState::with_network(
        a_runtime.clone(),
        a_network.clone(),
    ));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while a_network.connected_peers() == 0 || b_network.connected_peers() == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "authenticated V5 peers did not connect"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let transaction = transfer(&alice, &bob);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2/transactions")
                .body(Body::from(
                    serde_json::to_vec(&transaction).expect("V5 transaction serializes"),
                ))
                .expect("request builds"),
        )
        .await
        .expect("V2 router responds");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        a_runtime
            .stats()
            .await
            .expect("node A stats succeed")
            .mempool_size,
        1
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if b_runtime
            .stats()
            .await
            .expect("node B stats succeed")
            .mempool_size
            == 1
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "wire-v5 transaction never reached node B's runtime"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    a_runtime.shutdown().await.expect("node A runtime stops");
    b_runtime.shutdown().await.expect("node B runtime stops");
    a_task
        .await
        .expect("node A runtime does not panic")
        .expect("node A exits cleanly");
    b_task
        .await
        .expect("node B runtime does not panic")
        .expect("node B exits cleanly");
}
