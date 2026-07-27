//! Protocol-2 transaction HTTP/WebSocket boundary integration tests.
//!
//! Purpose: prove that hostile transport input reaches the single runtime only
//! through bounded V2 adapters and that durable lifecycle snapshots cross a real
//! WebSocket. Responsibilities: submission/idempotency/status/receipt response
//! shapes, inner/outer body caps, malformed paths, correlation IDs, and live
//! socket delivery. Non-responsibilities: storage batch internals, consensus
//! finalization, or proof generation, which have focused crate tests.
//!
//! Data flow and security boundary: each test starts one protocol-2 runtime over
//! the in-memory backend, drives the actual axum router (and one real TCP socket),
//! then shuts the actor down. All request bytes are treated as hostile and no
//! test bypasses the public handle or transport API.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body, Bytes};
use axum::http::{Method, Request, StatusCode};
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use tower::ServiceExt;
use webc_chain::{
    ActionV1, Amount, AuthorizationLaneId, AuthorizationPolicyRevision, BlockHeight, ChainConfig,
    ChainId, FeeBid, FeePaymentV1, FinalityCertificate, GenesisAccount, GenesisConfig,
    GenesisValidator, Nonce, Operation, SignedVote, TransactionAuthorizationV1, TransactionV5,
    ValidatorSet, ValidityWindowV1, Vote, VoteType, TRANSACTION_V5_PROTOCOL_VERSION,
};
use webc_crypto::Keypair;
use webc_node::{
    router_v2, serve_v2, Node, NodeHandle, NodeRuntime, NodeRuntimeError, V2AppState,
    V2TransportLimits, V5MempoolConfig, MAX_V2_HTTP_BODY_BYTES,
};
use webc_storage::{LocalTimestampMs, MemoryKvStore};

const NOW: u64 = 1_700_000_000_000;

fn transaction(sender: &Keypair, recipient: &Keypair) -> TransactionV5 {
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
    .expect("test transaction shape is valid");
    transaction.sign(sender).expect("test transaction signs");
    transaction
}

fn runtime() -> (
    NodeHandle,
    tokio::task::JoinHandle<Result<(), NodeRuntimeError>>,
    Keypair,
    Keypair,
) {
    let alice = Keypair::from_seed([51; 32]);
    let bob = Keypair::from_seed([52; 32]);
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
    let node = Node::open(MemoryKvStore::new(), &genesis).expect("test node opens");
    let (handle, task) = NodeRuntime::spawn(
        node,
        V5MempoolConfig::default(),
        32,
        LocalTimestampMs::new(NOW),
    )
    .expect("test runtime starts");
    (handle, task, alice, bob)
}

async fn json_body(response: Response) -> serde_json::Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body reads");
    serde_json::from_slice(&bytes).expect("response body is JSON")
}

#[tokio::test]
async fn submission_duplicate_status_and_pending_receipt_are_stable() {
    let (handle, task, alice, bob) = runtime();
    let app = router_v2(V2AppState::new(handle.clone()));
    let transaction = transaction(&alice, &bob);
    let transaction_id = transaction
        .transaction_id()
        .expect("test transaction has an ID");
    let body = serde_json::to_vec(&transaction).expect("transaction serializes");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2/transactions")
                .body(Body::from(body.clone()))
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::OK);
    let submitted = json_body(response).await;
    assert_eq!(submitted["api_version"], "v2");
    assert_eq!(submitted["outcome"]["kind"], "added");
    assert_eq!(submitted["lifecycle"]["status"]["kind"], "queued");
    assert_eq!(submitted["mempool_size"], 1);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2/transactions")
                .body(Body::from(body))
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await["outcome"]["kind"],
        "duplicate_known"
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v2/transactions/{transaction_id}"))
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["status"]["kind"], "queued");

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/v2/transactions/{transaction_id}/receipt"))
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let error = json_body(response).await;
    assert_eq!(error["code"], "receipt_not_finalized");
    assert!(error["request_id"]
        .as_str()
        .is_some_and(|request_id| request_id.starts_with("v2-")));

    handle.shutdown().await.expect("runtime shuts down");
    task.await
        .expect("runtime does not panic")
        .expect("runtime exits cleanly");
}

#[tokio::test]
async fn finalized_proof_route_requires_an_explicit_anchor_and_serves_a_verifiable_proof() {
    let validator = Keypair::from_seed([0x61; 32]);
    let recipient = Keypair::from_seed([0x62; 32]);
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
    let node = Node::open(MemoryKvStore::new(), &genesis).expect("validator node opens");
    let (handle, task) = NodeRuntime::spawn(
        node,
        V5MempoolConfig::default(),
        32,
        LocalTimestampMs::new(NOW),
    )
    .expect("test runtime starts");
    let app = router_v2(V2AppState::new(handle.clone()));
    let transaction = transaction(&validator, &recipient);
    let transaction_id = transaction
        .transaction_id()
        .expect("test transaction has an ID");
    handle
        .submit(transaction, LocalTimestampMs::new(NOW))
        .await
        .expect("transaction is durably queued");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v2/transactions/{transaction_id}/proof"))
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await["code"],
        "invalid_checkpoint_height"
    );

    let candidate = handle
        .build_candidate_v4(
            validator.address(),
            NOW + 1,
            LocalTimestampMs::new(NOW + 1),
            Vec::new(),
        )
        .await
        .expect("candidate builds");
    let height = candidate.block.header.height;
    let epoch = candidate.block.header.epoch;
    let state = webc_chain::ChainState::from_genesis_v1(&genesis)
        .expect("certificate fixture genesis builds");
    let validator_set =
        ValidatorSet::from_state(&state).expect("certificate authority snapshot builds");
    let block_hash = candidate.block.hash().expect("candidate hashes");
    let signed_vote = SignedVote::sign(
        Vote {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            chain_id: genesis.chain.chain_id.clone(),
            height: height.get(),
            round: 0,
            vote_type: VoteType::Precommit,
            block_hash,
            validator: validator.address(),
        },
        &validator,
    )
    .expect("finality vote signs");
    let certificate = FinalityCertificate::build(
        &validator_set,
        TRANSACTION_V5_PROTOCOL_VERSION,
        genesis.chain.chain_id.clone(),
        height.get(),
        0,
        block_hash,
        &[signed_vote],
    )
    .expect("single validator reaches quorum");
    handle
        .finalize_v4(candidate.block, candidate.next_authority_set, certificate)
        .await
        .expect("candidate finalizes");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v2/transactions/{transaction_id}/proof?checkpoint_height={}",
                    height.get()
                ))
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["api_version"], "v2");
    let checkpoint_candidate: webc_proof::CheckpointV1 =
        serde_json::from_value(body["checkpoint_candidate"].clone())
            .expect("checkpoint response decodes");
    let proof: webc_proof::FinalizedTransactionProofV1 =
        serde_json::from_value(body["proof"].clone()).expect("proof response decodes");
    let checkpoint = webc_proof::validate_checkpoint_v1(
        checkpoint_candidate,
        &webc_proof::CheckpointRequirementsV1::new(genesis.chain.chain_id.clone(), height, epoch),
    )
    .expect("served checkpoint is structurally valid");
    let verified = webc_proof::verify_finalized_transaction_proof_v1(
        &proof,
        &checkpoint,
        &webc_proof::FinalizedTransactionProofRequirementsV1::new(
            genesis.chain.chain_id.clone(),
            transaction_id,
            genesis.chain.staking.blocks_per_epoch,
        ),
    )
    .expect("served proof independently verifies");
    assert_eq!(verified.transaction_id, transaction_id);

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v2/transactions/{transaction_id}/proof?checkpoint_height=2"
                ))
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await["code"],
        "invalid_checkpoint_height"
    );

    handle.shutdown().await.expect("runtime shuts down");
    task.await
        .expect("runtime does not panic")
        .expect("runtime exits cleanly");
}

#[tokio::test]
async fn malformed_ids_and_inner_and_outer_body_limits_fail_without_admission() {
    let (handle, task, _alice, _bob) = runtime();
    let app = router_v2(V2AppState::new(handle.clone()));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v2/transactions/not-a-transaction-id")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await["code"], "invalid_transaction_id");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2/transactions")
                .body(Body::from(vec![
                    b' ';
                    webc_chain::MAX_TRANSACTION_V5_CANONICAL_BYTES
                        + 1
                ]))
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await["code"], "invalid_transaction");

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2/transactions")
                .body(Body::from(vec![0u8; MAX_V2_HTTP_BODY_BYTES + 1]))
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(json_body(response).await["code"], "body_too_large");
    assert_eq!(
        handle
            .stats()
            .await
            .expect("runtime stats succeed")
            .mempool_size,
        0
    );

    handle.shutdown().await.expect("runtime shuts down");
    task.await
        .expect("runtime does not panic")
        .expect("runtime exits cleanly");
}

#[tokio::test]
async fn submission_slot_is_reserved_before_a_streaming_body_is_read() {
    let (handle, task, _alice, _bob) = runtime();
    let state = V2AppState::with_limits(
        handle.clone(),
        V2TransportLimits {
            concurrent_submissions: 1,
            websocket_subscriptions: 1,
            ..V2TransportLimits::default()
        },
    )
    .expect("test limits are non-zero");
    let app = router_v2(state);
    let body_polled = Arc::new(tokio::sync::Notify::new());
    let notify = Arc::clone(&body_polled);
    let first_chunk = futures_util::stream::once(async move {
        notify.notify_one();
        Ok::<Bytes, Infallible>(Bytes::from_static(b"{"))
    });
    let never_finishes = futures_util::stream::pending::<Result<Bytes, Infallible>>();
    let streaming_body = Body::from_stream(first_chunk.chain(never_finishes));
    let first = tokio::spawn(
        app.clone().oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2/transactions")
                .body(streaming_body)
                .expect("streaming request builds"),
        ),
    );
    body_polled.notified().await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2/transactions")
                .body(Body::from(vec![0u8; MAX_V2_HTTP_BODY_BYTES + 1]))
                .expect("second request builds"),
        )
        .await
        .expect("router responds before reading the second body");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json_body(response).await["code"], "submission_limit");

    first.abort();
    handle.shutdown().await.expect("runtime shuts down");
    task.await
        .expect("runtime does not panic")
        .expect("runtime exits cleanly");
}

#[tokio::test]
async fn per_peer_bucket_rate_limits_before_route_work() {
    let (handle, task, _alice, _bob) = runtime();
    let state = V2AppState::with_limits(
        handle.clone(),
        V2TransportLimits {
            per_ip_burst: 1,
            per_ip_refill_ms: 60_000,
            max_tracked_ips: 4,
            ..V2TransportLimits::default()
        },
    )
    .expect("test limits are non-zero");
    let app = router_v2(state);
    let unknown = webc_chain::TransactionId::new(webc_crypto::Hash256([0x77; 32]));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v2/transactions/{unknown}"))
                .body(Body::empty())
                .expect("first request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/v2/transactions/{unknown}"))
                .body(Body::empty())
                .expect("second request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json_body(response).await["code"], "rate_limited");

    handle.shutdown().await.expect("runtime shuts down");
    task.await
        .expect("runtime does not panic")
        .expect("runtime exits cleanly");
}

#[tokio::test]
async fn websocket_sends_unknown_snapshot_then_live_queued_snapshot() {
    let (handle, task, alice, bob) = runtime();
    let transaction = transaction(&alice, &bob);
    let transaction_id = transaction
        .transaction_id()
        .expect("test transaction has an ID");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener binds");
    let address = listener.local_addr().expect("listener has an address");
    let server = tokio::spawn(serve_v2(listener, V2AppState::new(handle.clone())));
    let (mut socket, _) =
        tokio_tungstenite::connect_async(format!("ws://{address}/v2/transactions/ws"))
            .await
            .expect("WebSocket connects");
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            serde_json::json!({
                "version": 1,
                "transaction_ids": [transaction_id],
            })
            .to_string()
            .into(),
        ))
        .await
        .expect("subscription sends");

    let first = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .expect("initial snapshot arrives")
        .expect("socket remains open")
        .expect("initial message is valid");
    let first: serde_json::Value =
        serde_json::from_str(first.to_text().expect("message is text")).expect("snapshot is JSON");
    assert_eq!(first["type"], "snapshot");
    assert_eq!(first["lifecycle"]["status"]["kind"], "unknown");

    handle
        .submit(transaction, LocalTimestampMs::new(NOW))
        .await
        .expect("transaction commits");
    let second = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .expect("live snapshot arrives")
        .expect("socket remains open")
        .expect("live message is valid");
    let second: serde_json::Value =
        serde_json::from_str(second.to_text().expect("message is text")).expect("snapshot is JSON");
    assert_eq!(second["type"], "snapshot");
    assert_eq!(second["lifecycle"]["status"]["kind"], "queued");
    assert!(second["lifecycle"]["sequence"].is_string());

    drop(socket);
    server.abort();
    handle.shutdown().await.expect("runtime shuts down");
    task.await
        .expect("runtime does not panic")
        .expect("runtime exits cleanly");
}
