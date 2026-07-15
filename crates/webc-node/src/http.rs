//! HTTP + WebSocket transport for the developer API.
//!
//! Purpose: expose [`NodeService`] over versioned HTTP routes and a WebSocket
//! block subscription. This layer is deliberately thin — parsing, status-code
//! mapping, and streaming only — so all logic stays in the transport-independent
//! service and stays unit-testable without a socket. It reuses axum/tokio (both
//! MIT, Apache-2.0-compatible) rather than hand-rolling an HTTP server.
//!
//! Boundaries: it reads the wall clock to timestamp submissions, seals, and
//! faucet drips (transport orchestration, never inside a state transition). It
//! holds no chain logic of its own.
//!
//! Versioning & limits: every route is under `/v1`, and a request-body size limit
//! caps memory from hostile payloads. Additional bounds (mempool caps, faucet
//! rate limits) live in the service.
//!
//! Endpoints (all under `/v1`):
//! - `GET  /health`                     node health and identity
//! - `GET  /fees`                       current base fee and block unit budget
//! - `GET  /accounts/{address}`         account snapshot
//! - `GET  /accounts/{address}/proof`   Merkle account proof
//! - `GET  /objects/{id}`               persistent object by hex id
//! - `GET  /blocks/height/{height}`     finalized block by height
//! - `GET  /blocks/hash/{hash}`         finalized block by hex header hash
//! - `POST /transactions`               submit a signed transaction (JSON)
//! - `POST /blocks/seal`                devnet: seal a block from the mempool
//! - `POST /faucet/{address}`           devnet: drip valueless test funds
//! - `GET  /subscribe/blocks`           WebSocket stream of new-block events

use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use tokio::sync::broadcast;

use webc_chain::{Block, ObjectId, Transaction};
use webc_crypto::{Address, Hash256};
use webc_storage::KvStore;

use crate::service::{
    AccountSummary, ApiError, FaucetReceipt, FeeSummary, HealthSummary, NodeService, SealSummary,
    SubmitReceipt, API_VERSION,
};

/// Default maximum request body size (1 MiB), bounding hostile payloads.
const MAX_BODY_BYTES: usize = 1024 * 1024;
/// Default broadcast buffer of recent block events for slow subscribers.
const BLOCK_EVENT_CAPACITY: usize = 256;

/// A new-block notification pushed to WebSocket subscribers.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockEvent {
    pub height: u64,
    pub block_hash: Option<Hash256>,
    pub state_root: Option<Hash256>,
}

/// Shared, cheaply-cloneable API state: the service plus the block-event channel.
pub struct AppState<K: KvStore> {
    inner: Arc<AppInner<K>>,
}

struct AppInner<K: KvStore> {
    service: NodeService<K>,
    block_events: broadcast::Sender<BlockEvent>,
}

impl<K: KvStore> Clone for AppState<K> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<K: KvStore> AppState<K> {
    /// Wraps a service and creates the block-event broadcast channel.
    pub fn new(service: NodeService<K>) -> Self {
        let (block_events, _) = broadcast::channel(BLOCK_EVENT_CAPACITY);
        Self {
            inner: Arc::new(AppInner {
                service,
                block_events,
            }),
        }
    }

    /// The underlying service (for direct queries and tests).
    pub fn service(&self) -> &NodeService<K> {
        &self.inner.service
    }

    /// Subscribes to block events (used by WebSocket handlers and tests).
    pub fn subscribe(&self) -> broadcast::Receiver<BlockEvent> {
        self.inner.block_events.subscribe()
    }

    /// Publishes the current tip as a block event after a state-advancing call.
    ///
    /// Called by the seal and faucet handlers; also exposed for embedders that
    /// advance the chain through the service directly and want subscribers
    /// notified.
    pub fn publish_tip(&self) {
        let health = self.inner.service.health();
        let _ = self.inner.block_events.send(BlockEvent {
            height: health.height,
            block_hash: health.tip_hash,
            state_root: health.state_root,
        });
    }
}

/// Milliseconds since the Unix epoch, read at the transport boundary only.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Maps a service error to an HTTP status and a JSON error body.
///
/// The inner error is boxed to keep the `Err` variant of handler results small.
struct ApiRejection(Box<ApiError>);

impl From<ApiError> for ApiRejection {
    fn from(error: ApiError) -> Self {
        Self(Box::new(error))
    }
}

#[derive(serde::Serialize)]
struct ErrorBody {
    error: String,
    kind: &'static str,
}

impl IntoResponse for ApiRejection {
    fn into_response(self) -> Response {
        let (status, kind) = match &*self.0 {
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            ApiError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            ApiError::Rejected(_) => (StatusCode::BAD_REQUEST, "rejected"),
            ApiError::FaucetDisabled => (StatusCode::FORBIDDEN, "faucet_disabled"),
            ApiError::FaucetCooldown => (StatusCode::TOO_MANY_REQUESTS, "faucet_cooldown"),
            ApiError::FaucetRecipientFunded => (StatusCode::CONFLICT, "faucet_recipient_funded"),
            ApiError::Node(_) | ApiError::Storage(_) | ApiError::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
        };
        let body = ErrorBody {
            error: self.0.to_string(),
            kind,
        };
        (status, Json(body)).into_response()
    }
}

/// Parses a base58 WEBC address or returns a 400-mapped error.
fn parse_address(raw: &str) -> Result<Address, ApiRejection> {
    Address::from_str(raw)
        .map_err(|_| ApiRejection(Box::new(ApiError::InvalidRequest("invalid address".into()))))
}

/// Parses a 32-byte hex hash or returns a 400-mapped error.
fn parse_hash(raw: &str) -> Result<Hash256, ApiRejection> {
    let bytes = hex::decode(raw).map_err(|_| {
        ApiRejection(Box::new(ApiError::InvalidRequest(
            "invalid hex hash".into(),
        )))
    })?;
    let fixed: [u8; 32] = bytes.try_into().map_err(|_| {
        ApiRejection(Box::new(ApiError::InvalidRequest(
            "hash must be 32 bytes".into(),
        )))
    })?;
    Ok(Hash256(fixed))
}

/// Builds the versioned API router with a request-body size limit.
pub fn router<K>(state: AppState<K>) -> Router
where
    K: KvStore + Send + Sync + 'static,
{
    Router::new()
        .route("/v1/health", get(health::<K>))
        .route("/v1/fees", get(fees::<K>))
        .route("/v1/accounts/{address}", get(account::<K>))
        .route("/v1/accounts/{address}/proof", get(account_proof::<K>))
        .route("/v1/objects/{id}", get(object::<K>))
        .route("/v1/blocks/height/{height}", get(block_by_height::<K>))
        .route("/v1/blocks/hash/{hash}", get(block_by_hash::<K>))
        .route("/v1/transactions", post(submit_transaction::<K>))
        .route("/v1/blocks/seal", post(seal_block::<K>))
        .route("/v1/faucet/{address}", post(faucet::<K>))
        .route("/v1/subscribe/blocks", get(subscribe_blocks::<K>))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

async fn health<K: KvStore>(State(state): State<AppState<K>>) -> Json<HealthSummary> {
    Json(state.service().health())
}

async fn fees<K: KvStore>(State(state): State<AppState<K>>) -> Json<FeeSummary> {
    Json(state.service().fees())
}

async fn account<K: KvStore>(
    State(state): State<AppState<K>>,
    Path(address): Path<String>,
) -> Result<Json<AccountSummary>, ApiRejection> {
    let address = parse_address(&address)?;
    Ok(Json(state.service().account(address)?))
}

async fn account_proof<K: KvStore>(
    State(state): State<AppState<K>>,
    Path(address): Path<String>,
) -> Result<Json<webc_chain::AccountStateProof>, ApiRejection> {
    let address = parse_address(&address)?;
    Ok(Json(state.service().account_proof(address)?))
}

async fn object<K: KvStore>(
    State(state): State<AppState<K>>,
    Path(id): Path<String>,
) -> Result<Json<webc_chain::StateObject>, ApiRejection> {
    let hash = parse_hash(&id)?;
    Ok(Json(state.service().object(ObjectId::new(hash))?))
}

async fn block_by_height<K: KvStore>(
    State(state): State<AppState<K>>,
    Path(height): Path<u64>,
) -> Result<Json<Block>, ApiRejection> {
    Ok(Json(state.service().block_by_height(height)?))
}

async fn block_by_hash<K: KvStore>(
    State(state): State<AppState<K>>,
    Path(hash): Path<String>,
) -> Result<Json<Block>, ApiRejection> {
    let hash = parse_hash(&hash)?;
    Ok(Json(state.service().block_by_hash(hash)?))
}

async fn submit_transaction<K: KvStore>(
    State(state): State<AppState<K>>,
    Json(tx): Json<Transaction>,
) -> Result<Json<SubmitReceipt>, ApiRejection> {
    Ok(Json(state.service().submit_transaction(tx, now_ms())?))
}

async fn seal_block<K: KvStore>(
    State(state): State<AppState<K>>,
) -> Result<Json<SealSummary>, ApiRejection> {
    match state.service().seal_block(now_ms())? {
        Some(summary) => {
            state.publish_tip();
            Ok(Json(summary))
        }
        // Nothing to include: 204-style empty is awkward with typed JSON, so a
        // "no pending transactions" is reported as NotFound to the caller.
        None => Err(ApiRejection(Box::new(ApiError::NotFound))),
    }
}

async fn faucet<K: KvStore>(
    State(state): State<AppState<K>>,
    Path(address): Path<String>,
) -> Result<Json<FaucetReceipt>, ApiRejection> {
    let address = parse_address(&address)?;
    let receipt = state.service().faucet_drip(address, now_ms())?;
    state.publish_tip();
    Ok(Json(receipt))
}

async fn subscribe_blocks<K: KvStore + Send + Sync + 'static>(
    ws: WebSocketUpgrade,
    State(state): State<AppState<K>>,
) -> Response {
    let receiver = state.subscribe();
    ws.on_upgrade(move |socket| stream_block_events(socket, receiver))
}

/// Forwards each block event to one WebSocket client as JSON text until the
/// socket closes or the sender is dropped. A lagging subscriber skips missed
/// events rather than disconnecting.
async fn stream_block_events(mut socket: WebSocket, mut receiver: broadcast::Receiver<BlockEvent>) {
    loop {
        tokio::select! {
            event = receiver.recv() => match event {
                Ok(event) => {
                    let text = match serde_json::to_string(&event) {
                        Ok(text) => text,
                        Err(_) => continue,
                    };
                    if socket.send(Message::Text(text.into())).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            },
            incoming = socket.recv() => match incoming {
                Some(Ok(_)) => {}
                // Client closed or errored: stop streaming.
                _ => break,
            },
        }
    }
}

/// Serves the API on `listener` until the process ends. `API_VERSION` is exposed
/// in responses; the route prefix is `/v1`.
pub async fn serve<K>(listener: tokio::net::TcpListener, state: AppState<K>) -> std::io::Result<()>
where
    K: KvStore + Send + Sync + 'static,
{
    let _ = API_VERSION;
    // Permissive CORS is applied only at the real serving boundary (never in the
    // test router). This is a devnet developer API with no value at risk; a
    // browser demo served from any origin must be able to call it.
    let app = router(state).layer(tower_http::cors::CorsLayer::permissive());
    axum::serve(listener, app).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use futures_util::StreamExt;
    use tower::ServiceExt;
    use webc_chain::{Amount, ChainConfig, GenesisAccount, GenesisConfig};
    use webc_crypto::Keypair;
    use webc_storage::MemoryKvStore;

    use crate::mempool::MempoolConfig;
    use crate::node::Node;
    use crate::service::{FaucetConfig, NodeServiceOptions};

    fn app_state() -> (AppState<MemoryKvStore>, Keypair) {
        let faucet = Keypair::from_seed([9u8; 32]);
        let genesis = GenesisConfig {
            chain: ChainConfig::default(),
            accounts: vec![GenesisAccount {
                address: faucet.address(),
                balance: Amount::from_webc(1_000_000),
            }],
            validators: Vec::new(),
        };
        let node = Node::open(MemoryKvStore::new(), &genesis).unwrap();
        let options = NodeServiceOptions {
            mempool: MempoolConfig::default(),
            faucet: Some(FaucetConfig {
                keypair: Keypair::from_seed([9u8; 32]),
                drip_amount: Amount::from_webc(10),
                cooldown_ms: 60_000,
                max_recipient_balance: Amount::from_webc(100),
            }),
            proposer: faucet.address(),
        };
        (AppState::new(NodeService::new(node, options)), faucet)
    }

    async fn body_value(response: Response) -> serde_json::Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Native base units for `whole` WEBC, matching `Amount::from_webc`.
    fn webc_units(whole: u64) -> u64 {
        whole * 1_000_000_000_000
    }

    #[tokio::test]
    async fn health_endpoint_reports_version_and_height() {
        let (state, _faucet) = app_state();
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let health = body_value(response).await;
        assert_eq!(health["api_version"], "v1");
        assert_eq!(health["height"], 0);
        assert_eq!(health["faucet_enabled"], true);
    }

    #[tokio::test]
    async fn faucet_then_account_over_http() {
        let (state, _faucet) = app_state();
        let app = router(state);
        let newcomer = Keypair::from_seed([123u8; 32]);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/faucet/{}", newcomer.address()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let receipt = body_value(response).await;
        // Amount serializes as a decimal string in JSON.
        assert_eq!(receipt["new_balance"], webc_units(10).to_string());
        assert!(!receipt["disclaimer"].as_str().unwrap().is_empty());

        // The dripped account is now queryable and the block exists.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/accounts/{}", newcomer.address()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let account = body_value(response).await;
        assert_eq!(account["account"]["balance"], webc_units(10).to_string());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/blocks/height/1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unknown_account_is_404_and_bad_address_is_400() {
        let (state, _faucet) = app_state();
        let app = router(state);
        let stranger = Keypair::from_seed([200u8; 32]);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/accounts/{}", stranger.address()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/accounts/not-a-valid-address")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn websocket_streams_new_block_events() {
        // Bind a real ephemeral port and run the server.
        let (state, _faucet) = app_state();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_state = state.clone();
        tokio::spawn(async move {
            let _ = serve(listener, server_state).await;
        });

        // Connect a WebSocket subscriber.
        let url = format!("ws://{addr}/v1/subscribe/blocks");
        let (mut socket, _response) = tokio_tungstenite::connect_async(url).await.unwrap();

        // Advance the chain through the service and notify subscribers.
        let newcomer = Keypair::from_seed([200u8; 32]);
        state
            .service()
            .faucet_drip(newcomer.address(), 1_000)
            .unwrap();
        state.publish_tip();

        // The subscriber receives a block event at height 1.
        let message = socket.next().await.unwrap().unwrap();
        let text = message.to_text().unwrap();
        let event: BlockEvent = serde_json::from_str(text).unwrap();
        assert_eq!(event.height, 1);
        assert!(event.block_hash.is_some());

        drop(socket);
    }
}
