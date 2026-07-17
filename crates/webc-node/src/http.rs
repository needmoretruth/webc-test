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
//! - `GET  /tokens/{id}`                native token record by hex id
//! - `GET  /tokens/{id}/balances/{address}` a holder's token balance
//! - `GET  /tokens/{id}/supply`         per-token supply reconciliation
//! - `GET  /nft/collections/{id}`       NFT collection record by hex id
//! - `GET  /nft/collections/{id}/items/{serial}` one NFT item
//! - `GET  /services`                   paginated services (optional `category`)
//! - `GET  /services/{id}`              service-registry entry by hex id
//! - `GET  /governance/instances/{id}`  governance instance by hex id
//! - `GET  /governance/proposals/{id}`  governance proposal by hex id
//! - `GET  /mandates/{id}`              agent-payment mandate by hex id
//! - `GET  /blocks/height/{height}`     finalized block by height
//! - `GET  /blocks/hash/{hash}`         finalized block by hex header hash
//! - `POST /transactions`               submit a signed transaction (JSON)
//! - `POST /blocks/seal`                devnet: seal a block from the mempool
//! - `POST /faucet/{address}`           devnet: drip valueless test funds
//! - `GET  /subscribe/blocks`           WebSocket stream of new-block events

use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use tokio::sync::broadcast;
use webc_net::{NetMessage, NetworkHandle};

use webc_chain::{
    Amount, Block, GovernanceInstanceId, MandateId, NftCollectionId, NftId, ObjectId, ProposalId,
    ServiceId, TokenId, Transaction,
};
use webc_crypto::{Address, Hash256};
use webc_storage::KvStore;

use crate::service::{
    AccountSummary, ApiError, FaucetReceipt, FeeSummary, HealthSummary, NodeService, SealSummary,
    ServicesPage, SubmitReceipt, ValidatorSummary, ValidatorsResponse, API_VERSION,
};

/// Default maximum request body size (1 MiB), bounding hostile payloads.
const MAX_BODY_BYTES: usize = 1024 * 1024;
/// Default broadcast buffer of recent block events for slow subscribers.
const BLOCK_EVENT_CAPACITY: usize = 256;
/// Maximum concurrent WebSocket block subscriptions (H3).
///
/// Each subscription holds a socket, a file descriptor, and a broadcast
/// receiver. Unbounded, unauthenticated subscribers are a file-descriptor and
/// memory DoS, so new subscriptions past this cap are refused with 503.
const MAX_WS_SUBSCRIPTIONS: usize = 256;

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
    /// Present when the node participates in a peer-to-peer network. Locally
    /// submitted transactions are gossiped through it; `None` runs standalone.
    network: Option<NetworkHandle>,
    /// Live WebSocket block subscriptions, bounded by `MAX_WS_SUBSCRIPTIONS`
    /// (H3). Held in an `Arc` so a per-connection guard can decrement it on
    /// drop independently of the generic `K`.
    active_subscriptions: Arc<AtomicUsize>,
}

/// Decrements the live-subscription count when a WebSocket connection ends
/// (H3), whether it closed cleanly or the upgrade was never completed.
struct SubscriptionGuard(Arc<AtomicUsize>);

impl Drop for SubscriptionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Reserves one of `cap` slots in `counter`, returning `true` on success (H3).
///
/// A bounded compare-and-swap loop increments the count only while it is
/// strictly under `cap`, so concurrent callers can never push it past the
/// limit. On success the caller owns one slot and must release it (via
/// [`SubscriptionGuard`]).
fn reserve_slot(counter: &AtomicUsize, cap: usize) -> bool {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current >= cap {
            return false;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
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
    ///
    /// The node runs standalone (no gossip). Use [`Self::with_network`] to
    /// attach a peer-to-peer network handle.
    pub fn new(service: NodeService<K>) -> Self {
        Self::with_network(service, None)
    }

    /// Wraps a service with an optional peer-to-peer network handle.
    ///
    /// When a handle is present, transactions submitted to this node are
    /// gossiped to peers so they reach every mempool.
    pub fn with_network(service: NodeService<K>, network: Option<NetworkHandle>) -> Self {
        let (block_events, _) = broadcast::channel(BLOCK_EVENT_CAPACITY);
        Self {
            inner: Arc::new(AppInner {
                service,
                block_events,
                network,
                active_subscriptions: Arc::new(AtomicUsize::new(0)),
            }),
        }
    }

    /// The underlying service (for direct queries and tests).
    pub fn service(&self) -> &NodeService<K> {
        &self.inner.service
    }

    /// Submits a transaction locally and gossips it to peers on success.
    ///
    /// The transaction is validated and admitted by the service first; only a
    /// newly accepted transaction is broadcast, so a rejected or duplicate
    /// submission never floods the network.
    pub fn submit_transaction(
        &self,
        tx: Transaction,
        now_ms: u64,
    ) -> Result<SubmitReceipt, ApiError> {
        let gossip_copy = tx.clone();
        let receipt = self.inner.service.submit_transaction(tx, now_ms)?;
        if let Some(network) = &self.inner.network {
            // Best-effort: a stopped worker must not fail a valid submission.
            let _ = network.broadcast(NetMessage::Transaction(Box::new(gossip_copy)));
        }
        Ok(receipt)
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
pub(crate) fn now_ms() -> u64 {
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
        // H4: never leak internal error detail (storage paths, chain internals)
        // to the client. For a 5xx, log the real error server-side and return a
        // generic message; 4xx errors describe the client's own request and are
        // safe to return verbatim.
        let error = if status == StatusCode::INTERNAL_SERVER_ERROR {
            eprintln!("internal API error ({kind}): {}", self.0);
            "internal server error".to_string()
        } else {
            self.0.to_string()
        };
        let body = ErrorBody { error, kind };
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

/// Query parameters for the services listing: an optional hex `category` tag plus
/// pagination. `deny_unknown_fields` rejects any stray parameter with a 400 (via the
/// `Query` extractor).
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceListParams {
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
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
        .route("/v1/validators", get(validators::<K>))
        .route("/v1/validators/{address}", get(validator::<K>))
        .route("/v1/supply", get(supply::<K>))
        .route("/v1/objects/{id}", get(object::<K>))
        .route("/v1/tokens/{id}", get(token::<K>))
        .route(
            "/v1/tokens/{id}/balances/{address}",
            get(token_balance::<K>),
        )
        .route("/v1/tokens/{id}/supply", get(token_supply::<K>))
        .route("/v1/nft/collections/{id}", get(nft_collection::<K>))
        .route(
            "/v1/nft/collections/{id}/items/{serial}",
            get(nft_item::<K>),
        )
        .route("/v1/services", get(list_services::<K>))
        .route("/v1/services/{id}", get(service_entry::<K>))
        .route(
            "/v1/governance/instances/{id}",
            get(governance_instance::<K>),
        )
        .route(
            "/v1/governance/proposals/{id}",
            get(governance_proposal::<K>),
        )
        .route("/v1/mandates/{id}", get(mandate::<K>))
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

async fn validators<K: KvStore>(
    State(state): State<AppState<K>>,
) -> Result<Json<ValidatorsResponse>, ApiRejection> {
    Ok(Json(state.service().validators()?))
}

async fn validator<K: KvStore>(
    State(state): State<AppState<K>>,
    Path(address): Path<String>,
) -> Result<Json<ValidatorSummary>, ApiRejection> {
    let address = parse_address(&address)?;
    Ok(Json(state.service().validator(address)?))
}

async fn supply<K: KvStore>(
    State(state): State<AppState<K>>,
) -> Result<Json<webc_chain::SupplyInvariantReport>, ApiRejection> {
    Ok(Json(state.service().supply()?))
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

async fn token<K: KvStore>(
    State(state): State<AppState<K>>,
    Path(id): Path<String>,
) -> Result<Json<webc_chain::TokenRecord>, ApiRejection> {
    let token_id = TokenId::new(parse_hash(&id)?);
    Ok(Json(state.service().token(token_id)?))
}

async fn token_balance<K: KvStore>(
    State(state): State<AppState<K>>,
    Path((id, address)): Path<(String, String)>,
) -> Result<Json<Amount>, ApiRejection> {
    let token_id = TokenId::new(parse_hash(&id)?);
    let holder = parse_address(&address)?;
    Ok(Json(state.service().token_balance(token_id, holder)?))
}

async fn token_supply<K: KvStore>(
    State(state): State<AppState<K>>,
    Path(id): Path<String>,
) -> Result<Json<webc_chain::TokenSupplyReport>, ApiRejection> {
    let token_id = TokenId::new(parse_hash(&id)?);
    Ok(Json(state.service().token_supply(token_id)?))
}

async fn nft_collection<K: KvStore>(
    State(state): State<AppState<K>>,
    Path(id): Path<String>,
) -> Result<Json<webc_chain::NftCollection>, ApiRejection> {
    let collection_id = NftCollectionId::new(parse_hash(&id)?);
    Ok(Json(state.service().nft_collection(collection_id)?))
}

async fn nft_item<K: KvStore>(
    State(state): State<AppState<K>>,
    Path((id, serial)): Path<(String, u64)>,
) -> Result<Json<webc_chain::NftItem>, ApiRejection> {
    let collection_id = NftCollectionId::new(parse_hash(&id)?);
    let nft_id = NftId::new(collection_id, serial);
    Ok(Json(state.service().nft_item(nft_id)?))
}

async fn service_entry<K: KvStore>(
    State(state): State<AppState<K>>,
    Path(id): Path<String>,
) -> Result<Json<webc_chain::ServiceEntry>, ApiRejection> {
    let service_id = ServiceId::new(parse_hash(&id)?);
    Ok(Json(state.service().service_entry(service_id)?))
}

async fn governance_instance<K: KvStore>(
    State(state): State<AppState<K>>,
    Path(id): Path<String>,
) -> Result<Json<webc_chain::GovernanceInstance>, ApiRejection> {
    let instance_id = GovernanceInstanceId::new(parse_hash(&id)?);
    Ok(Json(state.service().governance_instance(instance_id)?))
}

async fn governance_proposal<K: KvStore>(
    State(state): State<AppState<K>>,
    Path(id): Path<String>,
) -> Result<Json<webc_chain::GovernanceProposal>, ApiRejection> {
    let proposal_id = ProposalId::new(parse_hash(&id)?);
    Ok(Json(state.service().governance_proposal(proposal_id)?))
}

async fn mandate<K: KvStore>(
    State(state): State<AppState<K>>,
    Path(id): Path<String>,
) -> Result<Json<webc_chain::Mandate>, ApiRejection> {
    let mandate_id = MandateId::new(parse_hash(&id)?);
    Ok(Json(state.service().mandate(mandate_id)?))
}

async fn list_services<K: KvStore>(
    State(state): State<AppState<K>>,
    Query(params): Query<ServiceListParams>,
) -> Result<Json<ServicesPage>, ApiRejection> {
    let category = match params.category.as_deref() {
        Some(raw) => Some(parse_hash(raw)?),
        None => None,
    };
    Ok(Json(state.service().services(
        category,
        params.cursor.as_deref(),
        params.limit,
    )?))
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
    // Route through AppState so a locally accepted transaction is also gossiped.
    Ok(Json(state.submit_transaction(tx, now_ms())?))
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
    // H3: reserve a subscription slot before upgrading; the guard returns it
    // when the connection ends (or the upgrade never happens).
    if !reserve_slot(&state.inner.active_subscriptions, MAX_WS_SUBSCRIPTIONS) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "subscription limit reached",
        )
            .into_response();
    }
    let guard = SubscriptionGuard(Arc::clone(&state.inner.active_subscriptions));
    let receiver = state.subscribe();
    ws.on_upgrade(move |socket| async move {
        // Hold the slot for the connection's lifetime; dropped when it ends.
        let _guard = guard;
        stream_block_events(socket, receiver).await;
    })
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
    use std::collections::BTreeSet;

    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use futures_util::StreamExt;
    use tower::ServiceExt;
    use webc_chain::{
        Amount, ChainConfig, Epoch, FeeBid, GenesisAccount, GenesisConfig, GovernanceAction,
        GovernanceConfig, MandateCounterpartyPolicy, NftMetadata, Operation, ServicePaymentFlags,
        TokenMetadata,
    };
    use webc_crypto::{Hash256, Keypair};
    use webc_storage::MemoryKvStore;

    use crate::mempool::MempoolConfig;
    use crate::node::Node;

    #[test]
    fn reserve_slot_bounds_concurrent_reservations() {
        // H3: the reservation never exceeds the cap; releasing frees a slot.
        let counter = AtomicUsize::new(0);
        assert!(reserve_slot(&counter, 2));
        assert!(reserve_slot(&counter, 2));
        assert!(!reserve_slot(&counter, 2));
        counter.fetch_sub(1, Ordering::AcqRel); // as SubscriptionGuard would
        assert!(reserve_slot(&counter, 2));
    }

    #[tokio::test]
    async fn internal_errors_do_not_leak_detail_to_clients() {
        // H4: a 5xx returns a generic message; the detail never reaches the wire.
        let rejection = ApiRejection(Box::new(ApiError::Internal(
            "secret /var/lib/webc/chain.redb detail".into(),
        )));
        let response = rejection.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "internal server error");
        assert_eq!(body["kind"], "internal");
        assert!(
            !String::from_utf8_lossy(&bytes).contains("secret"),
            "internal detail must not be exposed"
        );
    }

    #[tokio::test]
    async fn client_errors_still_return_their_detail() {
        // 4xx errors describe the caller's own request and remain informative.
        let rejection = ApiRejection(Box::new(ApiError::InvalidRequest(
            "malformed address".into(),
        )));
        let response = rejection.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("malformed address"));
    }
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

    // ----- native-state (Phase 9/13) read endpoints -----

    /// Fixed transport timestamp for the seeding seals (reads take no clock).
    const SEED_NOW: u64 = 1_000;

    /// The single application namespace all seeded native state is created under.
    fn seed_namespace() -> Hash256 {
        Hash256([0x77; 32])
    }

    /// Lowercase-hex form of a 32-byte id, as the SDK state-key builders emit it.
    fn hash_hex(hash: Hash256) -> String {
        hex::encode(hash.as_bytes())
    }

    /// Ids of the records seeded by [`native_state`], for endpoint assertions.
    struct Seeded {
        creator: Address,
        holder: Address,
        token_id: TokenId,
        collection_id: NftCollectionId,
        serial: u64,
        service_id: ServiceId,
        instance_id: GovernanceInstanceId,
        proposal_id: ProposalId,
        mandate_id: MandateId,
    }

    /// A generous fee bid covering any create operation's required units.
    fn seed_fee() -> FeeBid {
        FeeBid {
            gas_limit: 100_000,
            max_fee_per_unit: 1,
            priority_fee_per_unit: 0,
        }
    }

    /// Commits a prebuilt transaction in its own block via the ordinary
    /// submit-and-seal harness (the same path a real client would drive).
    fn seal_tx(state: &AppState<MemoryKvStore>, tx: Transaction) {
        state
            .service()
            .submit_and_seal(tx, SEED_NOW)
            .expect("operation seals into a block");
    }

    /// Signs `op` from `signer` at `nonce` and commits it in its own block.
    fn seal_op(state: &AppState<MemoryKvStore>, signer: &Keypair, nonce: u64, op: Operation) {
        let tx = Transaction::for_operation(signer, nonce, op, seed_fee())
            .expect("operation transaction signs");
        seal_tx(state, tx);
    }

    /// Builds a service whose committed state holds one of every native record:
    /// a token (1_000 units held by `holder`), an NFT collection with one minted
    /// item, a registered HTTP-402 service, a governance instance with an open
    /// signaling proposal, and a mandate — all created by `creator` through the
    /// real create operations.
    fn native_state() -> (AppState<MemoryKvStore>, Seeded) {
        let creator = Keypair::from_seed([31u8; 32]);
        let holder = Keypair::from_seed([32u8; 32]);
        let agent = Keypair::from_seed([33u8; 32]);
        let namespace = seed_namespace();

        let genesis = GenesisConfig {
            chain: ChainConfig::default(),
            accounts: vec![GenesisAccount {
                address: creator.address(),
                balance: Amount::from_webc(1_000_000),
            }],
            validators: Vec::new(),
        };
        let node = Node::open(MemoryKvStore::new(), &genesis).unwrap();
        let options = NodeServiceOptions {
            mempool: MempoolConfig::default(),
            faucet: None,
            proposer: creator.address(),
        };
        let state = AppState::new(NodeService::new(node, options));

        // 1) Create a token, minting 1_000 base units to the holder.
        seal_op(
            &state,
            &creator,
            0,
            Operation::CreateToken {
                namespace,
                create_nonce: 0,
                metadata: TokenMetadata::new(
                    b"Acme Dollar".to_vec(),
                    b"ACME".to_vec(),
                    6,
                    Hash256([0x1f; 32]),
                )
                .unwrap(),
                mint_authority: Some(creator.address()),
                freeze_authority: Some(creator.address()),
                initial_supply: Amount::from_units(1_000),
                initial_recipient: holder.address(),
            },
        );
        let token_id = TokenId::derive(namespace, creator.address(), 0);

        // 2) Create an NFT collection and 3) mint its first item (serial 0).
        seal_op(
            &state,
            &creator,
            1,
            Operation::CreateNftCollection {
                namespace,
                create_nonce: 0,
                metadata: NftMetadata::new(
                    b"Acme Apes".to_vec(),
                    b"APE".to_vec(),
                    Hash256([0x2f; 32]),
                )
                .unwrap(),
                mint_authority: Some(creator.address()),
                freeze_authority: Some(creator.address()),
                max_supply: None,
                royalty_bps: 0,
            },
        );
        let collection_id = NftCollectionId::derive(namespace, creator.address(), 0);
        seal_op(
            &state,
            &creator,
            2,
            Operation::MintNft {
                collection_id,
                recipient: holder.address(),
                item_metadata_hash: Hash256([0x3f; 32]),
            },
        );
        let serial: u64 = 0;

        // 4) Register a service that accepts HTTP-402 payments (closes the 402 loop).
        seal_op(
            &state,
            &creator,
            3,
            Operation::RegisterService {
                namespace,
                create_nonce: 0,
                categories: BTreeSet::new(),
                title: b"acme-svc".to_vec(),
                endpoint: b"https://acme.example/api".to_vec(),
                interface: Hash256([0x4f; 32]),
                pricing: Vec::new(),
                payment_flags: ServicePaymentFlags {
                    on_chain_direct: false,
                    http_402: true,
                    subscription: false,
                },
            },
        );
        let service_id = ServiceId::derive(namespace, creator.address(), 0);

        // 5) Create a governance instance over the token, 6) open a signaling proposal.
        seal_op(
            &state,
            &creator,
            4,
            Operation::CreateGovernanceInstance {
                namespace,
                create_nonce: 0,
                weight_token: token_id,
                config: GovernanceConfig {
                    voting_period_epochs: 1_000,
                    timelock_epochs: 0,
                    quorum_bps: 0,
                    proposal_threshold: Amount::ZERO,
                    approval_threshold_bps: 5_000,
                },
            },
        );
        let instance_id = GovernanceInstanceId::derive(namespace, creator.address(), 0);
        // OpenProposal reads the proposer's weight-token balance to check the
        // threshold; that balance key is state-derived (the weight token lives on
        // the instance record), so the dedicated builder adds it to the signed
        // access list.
        let open = Transaction::for_open_proposal(
            &creator,
            5,
            instance_id,
            GovernanceAction::Signaling,
            token_id,
            seed_fee(),
        )
        .expect("open-proposal transaction signs");
        seal_tx(&state, open);
        let proposal_id = ProposalId::derive(instance_id, 0);

        // 7) Grant a mandate to the agent key.
        seal_op(
            &state,
            &creator,
            6,
            Operation::GrantMandate {
                agent_key: agent.public_key(),
                grant_nonce: 0,
                budget_total: Amount::from_webc(10),
                expiry_epoch: Epoch::new(1_000_000),
                per_tx_max: Amount::from_webc(1),
                rate_limit_per_day: 0,
                counterparty_policy: MandateCounterpartyPolicy::Open,
            },
        );
        let mandate_id = MandateId::derive(creator.address(), &agent.public_key(), 0);

        (
            state,
            Seeded {
                creator: creator.address(),
                holder: holder.address(),
                token_id,
                collection_id,
                serial,
                service_id,
                instance_id,
                proposal_id,
                mandate_id,
            },
        )
    }

    /// Issues a GET against a cloned router and returns the raw response.
    async fn get_response(app: &Router, uri: String) -> Response {
        app.clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn native_read_endpoints_serve_seeded_records() {
        let (state, seed) = native_state();
        let app = router(state);
        let creator = seed.creator.to_string();
        let holder = seed.holder.to_string();
        let token_hex = hash_hex(seed.token_id.hash());

        // GET /v1/tokens/{id}
        let response = get_response(&app, format!("/v1/tokens/{token_hex}")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_value(response).await;
        assert_eq!(body["creator"], creator.as_str());
        assert_eq!(body["issued_supply"], "1000");
        assert_eq!(body["paused"], false);

        // GET /v1/tokens/{id}/balances/{address} — the holder holds 1_000 units.
        let response =
            get_response(&app, format!("/v1/tokens/{token_hex}/balances/{holder}")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_value(response).await, "1000");

        // GET /v1/tokens/{id}/supply
        let response = get_response(&app, format!("/v1/tokens/{token_hex}/supply")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_value(response).await;
        assert_eq!(body["issued"], "1000");
        assert_eq!(body["held"], "1000");
        assert_eq!(body["balanced"], true);

        // GET /v1/nft/collections/{id}
        let collection_hex = hash_hex(seed.collection_id.hash());
        let response = get_response(&app, format!("/v1/nft/collections/{collection_hex}")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_value(response).await;
        assert_eq!(body["creator"], creator.as_str());
        assert_eq!(body["minted_count"], 1);

        // GET /v1/nft/collections/{id}/items/{serial}
        let response = get_response(
            &app,
            format!("/v1/nft/collections/{collection_hex}/items/{}", seed.serial),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_value(response).await;
        assert_eq!(body["owner"], holder.as_str());
        assert_eq!(body["frozen"], false);

        // GET /v1/services/{id} — the full entry that closes the HTTP-402 loop.
        let response = get_response(
            &app,
            format!("/v1/services/{}", hash_hex(seed.service_id.hash())),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_value(response).await;
        assert_eq!(body["owner"], creator.as_str());
        assert_eq!(body["status"], "Active");
        assert_eq!(body["payment_flags"]["http_402"], true);

        // GET /v1/governance/instances/{id}
        let response = get_response(
            &app,
            format!(
                "/v1/governance/instances/{}",
                hash_hex(seed.instance_id.hash())
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_value(response).await;
        assert_eq!(body["creator"], creator.as_str());
        assert_eq!(body["next_proposal_nonce"], 1);

        // GET /v1/governance/proposals/{id}
        let response = get_response(
            &app,
            format!(
                "/v1/governance/proposals/{}",
                hash_hex(seed.proposal_id.hash())
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_value(response).await;
        assert_eq!(body["status"], "Active");
        assert_eq!(body["proposer"], creator.as_str());

        // GET /v1/mandates/{id}
        let response = get_response(
            &app,
            format!("/v1/mandates/{}", hash_hex(seed.mandate_id.hash())),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_value(response).await;
        assert_eq!(body["principal"], creator.as_str());
        assert_eq!(body["revoked"], false);
        let budget = webc_units(10).to_string();
        assert_eq!(body["budget_total"], budget.as_str());
    }

    #[tokio::test]
    async fn native_read_endpoints_404_for_missing_ids() {
        let (state, seed) = native_state();
        let app = router(state);
        // A syntactically valid 32-byte hex id that names no record.
        let missing = "ab".repeat(32);
        let token_hex = hash_hex(seed.token_id.hash());
        let collection_hex = hash_hex(seed.collection_id.hash());
        // A valid address that holds none of the token.
        let stranger = Keypair::from_seed([222u8; 32]).address().to_string();

        for uri in [
            format!("/v1/tokens/{missing}"),
            format!("/v1/tokens/{missing}/balances/{stranger}"),
            format!("/v1/tokens/{missing}/supply"),
            format!("/v1/nft/collections/{missing}"),
            format!("/v1/nft/collections/{missing}/items/0"),
            // Known collection, unknown serial.
            format!("/v1/nft/collections/{collection_hex}/items/999"),
            format!("/v1/services/{missing}"),
            format!("/v1/governance/instances/{missing}"),
            format!("/v1/governance/proposals/{missing}"),
            format!("/v1/mandates/{missing}"),
        ] {
            let response = get_response(&app, uri.clone()).await;
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "expected 404 for {uri}"
            );
        }

        // A known token with no balance entry for the holder reads back as zero
        // (200), not 404: an absent balance and a zero balance are the same state.
        let response =
            get_response(&app, format!("/v1/tokens/{token_hex}/balances/{stranger}")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_value(response).await, "0");
    }

    #[tokio::test]
    async fn native_read_endpoints_400_for_malformed_ids() {
        let (state, seed) = native_state();
        let app = router(state);
        // Not valid hex (and thus not a 32-byte id).
        let bad = "zz";
        let token_hex = hash_hex(seed.token_id.hash());
        let collection_hex = hash_hex(seed.collection_id.hash());
        let holder = seed.holder.to_string();

        for uri in [
            format!("/v1/tokens/{bad}"),
            format!("/v1/tokens/{bad}/balances/{holder}"),
            // Valid token id, malformed holder address.
            format!("/v1/tokens/{token_hex}/balances/not-an-address"),
            format!("/v1/tokens/{bad}/supply"),
            format!("/v1/nft/collections/{bad}"),
            format!("/v1/nft/collections/{bad}/items/0"),
            // Valid collection id, non-numeric serial (rejected by the extractor).
            format!("/v1/nft/collections/{collection_hex}/items/not-a-number"),
            format!("/v1/services/{bad}"),
            format!("/v1/governance/instances/{bad}"),
            format!("/v1/governance/proposals/{bad}"),
            format!("/v1/mandates/{bad}"),
        ] {
            let response = get_response(&app, uri.clone()).await;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "expected 400 for {uri}"
            );
        }
    }

    // ----- paginated services-by-category discovery endpoint -----

    /// Two disjoint taxonomy tags used to exercise the category filter.
    const CATEGORY_A: Hash256 = Hash256([0xa1; 32]);
    const CATEGORY_B: Hash256 = Hash256([0xb2; 32]);

    /// Builds a service holding `count` registered services under one namespace,
    /// each tagged by `categories_for(i)`, and returns the state, the creator
    /// address, and the derived `ServiceId`s (in creation order). Registrations go
    /// through the real `RegisterService` create op via `submit_and_seal`.
    fn services_state(
        count: usize,
        categories_for: impl Fn(usize) -> BTreeSet<Hash256>,
    ) -> (AppState<MemoryKvStore>, Vec<ServiceId>) {
        let creator = Keypair::from_seed([41u8; 32]);
        let namespace = seed_namespace();
        let genesis = GenesisConfig {
            chain: ChainConfig::default(),
            accounts: vec![GenesisAccount {
                address: creator.address(),
                balance: Amount::from_webc(10_000_000),
            }],
            validators: Vec::new(),
        };
        let node = Node::open(MemoryKvStore::new(), &genesis).unwrap();
        let options = NodeServiceOptions {
            mempool: MempoolConfig::default(),
            faucet: None,
            proposer: creator.address(),
        };
        let state = AppState::new(NodeService::new(node, options));
        let mut ids = Vec::new();
        for i in 0..count {
            seal_op(
                &state,
                &creator,
                i as u64,
                Operation::RegisterService {
                    namespace,
                    create_nonce: i as u64,
                    categories: categories_for(i),
                    title: format!("svc-{i}").into_bytes(),
                    endpoint: b"https://acme.example/api".to_vec(),
                    interface: Hash256([0x4f; 32]),
                    pricing: Vec::new(),
                    payment_flags: ServicePaymentFlags {
                        on_chain_direct: false,
                        http_402: true,
                        subscription: false,
                    },
                },
            );
            ids.push(ServiceId::derive(namespace, creator.address(), i as u64));
        }
        (state, ids)
    }

    /// Walks every page of a services listing (following `next_cursor`), asserting
    /// each page holds at most `limit` items, and returns the concatenated
    /// `service_id`s in the order served. `query` is the query string without a
    /// leading `?` or any `cursor` (e.g. `"limit=3"` or `"category=..&limit=2"`).
    async fn walk_services(app: &Router, query: &str, limit: usize) -> Vec<String> {
        let mut ids = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let uri = match &cursor {
                Some(c) => format!("/v1/services?{query}&cursor={c}"),
                None => format!("/v1/services?{query}"),
            };
            let response = get_response(app, uri).await;
            assert_eq!(response.status(), StatusCode::OK);
            let body = body_value(response).await;
            let page = body["items"].as_array().unwrap();
            assert!(page.len() <= limit, "page exceeded the requested limit");
            for item in page {
                ids.push(item["service_id"].as_str().unwrap().to_string());
            }
            match body["next_cursor"].as_str() {
                Some(c) => cursor = Some(c.to_string()),
                None => break,
            }
            assert!(ids.len() < 100_000, "pagination failed to terminate");
        }
        ids
    }

    #[tokio::test]
    async fn services_list_paginates_ascending_without_overlap() {
        // Seven services, no categories: listing all must walk every one exactly
        // once, in ascending service-id order, across bounded pages.
        let (state, ids) = services_state(7, |_| BTreeSet::new());
        let app = router(state);
        let expected: BTreeSet<String> = ids.iter().map(|id| hash_hex(id.hash())).collect();

        let walked = walk_services(&app, "limit=3", 3).await;
        // Ascending key order and no duplicates.
        let mut sorted = walked.clone();
        sorted.sort();
        assert_eq!(
            walked, sorted,
            "items must be in ascending service-id order"
        );
        let unique: BTreeSet<String> = walked.iter().cloned().collect();
        assert_eq!(unique.len(), walked.len(), "no id may repeat across pages");
        // Exactly the seeded set, nothing missed.
        assert_eq!(unique, expected);

        // The first page is full and carries a cursor; the response also flattens
        // the underlying ServiceEntry (owner/status/payment flags) alongside the id.
        let first = body_value(get_response(&app, "/v1/services?limit=3".to_string()).await).await;
        assert_eq!(first["items"].as_array().unwrap().len(), 3);
        assert!(first["next_cursor"].is_string());
        assert_eq!(first["items"][0]["status"], "Active");
        assert_eq!(first["items"][0]["payment_flags"]["http_402"], true);
    }

    #[tokio::test]
    async fn services_category_filter_returns_only_matches() {
        // i%3==0 -> {A}, i%3==1 -> {B}, i%3==2 -> untagged.
        let (state, ids) = services_state(9, |i| {
            let mut set = BTreeSet::new();
            match i % 3 {
                0 => {
                    set.insert(CATEGORY_A);
                }
                1 => {
                    set.insert(CATEGORY_B);
                }
                _ => {}
            }
            set
        });
        let app = router(state);
        let cat_a_hex = hash_hex(CATEGORY_A);

        let expected_a: BTreeSet<String> = (0..9)
            .filter(|i| i % 3 == 0)
            .map(|i| hash_hex(ids[i].hash()))
            .collect();
        let walked_a = walk_services(&app, &format!("category={cat_a_hex}&limit=2"), 2).await;
        let got_a: BTreeSet<String> = walked_a.iter().cloned().collect();
        assert_eq!(got_a, expected_a, "only category-A services are returned");
        // Ascending order preserved under the filter.
        let mut sorted_a = walked_a.clone();
        sorted_a.sort();
        assert_eq!(walked_a, sorted_a);

        // A category tag no service declares yields an empty, cursor-null page.
        let none_hex = hash_hex(Hash256([0xee; 32]));
        let body =
            body_value(get_response(&app, format!("/v1/services?category={none_hex}")).await).await;
        assert!(body["items"].as_array().unwrap().is_empty());
        assert!(body["next_cursor"].is_null());
    }

    #[tokio::test]
    async fn services_limit_is_clamped_to_the_hard_maximum() {
        // With more services than the hard cap, an over-large limit is clamped: the
        // first page holds exactly MAX_PAGE_LIMIT items and carries a cursor.
        let over = crate::service::MAX_PAGE_LIMIT + 1;
        let (state, _ids) = services_state(over, |_| BTreeSet::new());
        let app = router(state);

        let body =
            body_value(get_response(&app, "/v1/services?limit=100000".to_string()).await).await;
        assert_eq!(
            body["items"].as_array().unwrap().len(),
            crate::service::MAX_PAGE_LIMIT
        );
        assert!(body["next_cursor"].is_string());
    }

    #[tokio::test]
    async fn services_empty_state_returns_empty_page() {
        let (state, _ids) = services_state(0, |_| BTreeSet::new());
        let app = router(state);
        let body = body_value(get_response(&app, "/v1/services".to_string()).await).await;
        assert!(body["items"].as_array().unwrap().is_empty());
        assert!(body["next_cursor"].is_null());
    }

    #[tokio::test]
    async fn services_malformed_params_are_rejected() {
        let (state, _ids) = services_state(1, |_| BTreeSet::new());
        let app = router(state);
        for uri in [
            // Non-hex cursor.
            "/v1/services?cursor=zz",
            // Non-numeric limit (rejected by the Query extractor).
            "/v1/services?limit=abc",
            // Non-hex category tag.
            "/v1/services?category=zz",
            // Unknown query parameter (deny_unknown_fields).
            "/v1/services?bogus=1",
        ] {
            let response = get_response(&app, uri.to_string()).await;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "expected 400 for {uri}"
            );
        }
    }
}
