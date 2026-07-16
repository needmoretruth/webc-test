//! Authenticated TCP transport and flood gossip.
//!
//! This is the concrete implementation behind the transport seam. It reuses
//! mature MIT crates for the commodity plumbing — Tokio for the runtime and
//! sockets, `tokio-util`'s length-delimited codec for framing — and layers the
//! WEBC-owned pieces on top: the authenticated handshake ([`crate::handshake`]),
//! the message envelope ([`crate::wire`]), and a simple flood gossip with loop
//! suppression.
//!
//! Design (actor pattern): a single background worker owns the peer table so no
//! shared state needs locking. Each connection runs its own read/write tasks and
//! reports frames and lifecycle to the worker over one event channel. Callers
//! interact only through the cloneable [`NetworkHandle`] (to broadcast) and an
//! inbound [`InboundMessage`] receiver (to consume gossip).
//!
//! Gossip is best-effort flooding: a broadcast, and every newly-seen inbound
//! frame, is forwarded to all connected peers except the sender. A bounded
//! seen-frame cache drops duplicates so a message does not loop forever. Peer
//! discovery is a static bootstrap list for A-1; richer discovery is later work.

use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use rand_core::{OsRng, RngCore};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use webc_chain::ChainId;
use webc_crypto::Keypair;

use crate::codec;
use crate::error::NetError;
use crate::handshake::{
    accept_hello, build_hello, build_proof, verify_peer_proof, HandshakeHello, HandshakeProof,
    PeerId, CHALLENGE_LEN,
};
use crate::wire::{decode_message, encode_message, message_id, NetMessage, MAX_FRAME_BYTES};

/// Number of recently seen frame IDs retained to suppress gossip loops.
const SEEN_CACHE_CAPACITY: usize = 8192;

/// Per-peer outbound queue depth before slow-peer frames are dropped.
const PEER_SEND_CAPACITY: usize = 256;

/// Reconnect backoff bounds for a configured bootstrap peer, in milliseconds.
const RECONNECT_BACKOFF_START_MS: u64 = 500;
const RECONNECT_BACKOFF_MAX_MS: u64 = 8_000;

/// A gossip message received from an authenticated peer.
#[derive(Clone, Debug)]
pub struct InboundMessage {
    /// Authenticated identity of the peer the frame arrived from.
    pub from: PeerId,
    /// The decoded message.
    pub message: NetMessage,
}

/// Configuration for a node's peer-to-peer network.
pub struct NetworkConfig {
    /// This node's Ed25519 network identity keypair.
    pub identity: Keypair,
    /// Chain this node participates in; peers on other chains are rejected.
    pub chain_id: ChainId,
    /// Address to listen on for inbound peers, or `None` to dial-only.
    pub listen_addr: Option<SocketAddr>,
    /// Peer addresses to dial and keep reconnecting to.
    pub bootstrap_peers: Vec<SocketAddr>,
    /// Inbound message queue depth delivered to the node.
    pub inbound_capacity: usize,
}

impl NetworkConfig {
    /// Builds a config with a sensible default inbound queue depth.
    pub fn new(
        identity: Keypair,
        chain_id: ChainId,
        listen_addr: Option<SocketAddr>,
        bootstrap_peers: Vec<SocketAddr>,
    ) -> Self {
        Self {
            identity,
            chain_id,
            listen_addr,
            bootstrap_peers,
            inbound_capacity: 1024,
        }
    }
}

/// Immutable per-node handshake material shared by every connection task.
struct SharedConfig {
    identity: Keypair,
    chain_id: ChainId,
}

/// Cloneable control handle to a running network worker.
#[derive(Clone)]
pub struct NetworkHandle {
    commands: mpsc::UnboundedSender<Command>,
    local_peer_id: PeerId,
    local_addr: Option<SocketAddr>,
    connected: Arc<AtomicUsize>,
}

impl NetworkHandle {
    /// Floods a message to every connected peer (best-effort).
    ///
    /// Returns [`NetError::WorkerStopped`] only if the worker has shut down.
    pub fn broadcast(&self, message: NetMessage) -> Result<(), NetError> {
        self.commands
            .send(Command::Broadcast(Box::new(message)))
            .map_err(|_| NetError::WorkerStopped)
    }

    /// Sends a message to exactly one peer (best-effort), not the whole mesh.
    ///
    /// Used for point-to-point replies — chiefly state-sync `BlockResponse`s —
    /// so answering one peer's request does not broadcast full blocks to the
    /// entire network (the C7 amplification the flood path would otherwise
    /// cause). If the peer is not currently connected the message is dropped.
    /// Returns [`NetError::WorkerStopped`] only if the worker has shut down.
    pub fn send_to(&self, peer: PeerId, message: NetMessage) -> Result<(), NetError> {
        self.commands
            .send(Command::SendTo(peer, Box::new(message)))
            .map_err(|_| NetError::WorkerStopped)
    }

    /// This node's own authenticated peer identity.
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// The actually-bound listen address, if this node is listening.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Current count of authenticated, connected peers.
    pub fn connected_peers(&self) -> usize {
        self.connected.load(Ordering::Relaxed)
    }
}

/// Commands sent from a [`NetworkHandle`] to the worker.
enum Command {
    Broadcast(Box<NetMessage>),
    SendTo(PeerId, Box<NetMessage>),
}

/// Events sent from connection/listener tasks to the worker.
enum Event {
    Connected {
        peer: PeerId,
        outbound: mpsc::Sender<Arc<Vec<u8>>>,
    },
    Frame {
        from: PeerId,
        bytes: Vec<u8>,
    },
    Disconnected {
        peer: PeerId,
    },
}

/// Starts a network worker and returns its handle plus the inbound stream.
///
/// The listener (if configured) and each bootstrap dialer run as background
/// tasks; the worker owns the peer table. Dropping every [`NetworkHandle`] clone
/// shuts the worker down.
pub async fn spawn_network(
    config: NetworkConfig,
) -> Result<(NetworkHandle, mpsc::Receiver<InboundMessage>), NetError> {
    let local_peer_id = PeerId(config.identity.public_key());
    let shared = Arc::new(SharedConfig {
        identity: config.identity,
        chain_id: config.chain_id,
    });

    let (events_tx, events_rx) = mpsc::channel::<Event>(1024);
    let (commands_tx, commands_rx) = mpsc::unbounded_channel::<Command>();
    let (inbound_tx, inbound_rx) = mpsc::channel::<InboundMessage>(config.inbound_capacity.max(1));
    let connected = Arc::new(AtomicUsize::new(0));

    let local_addr = match config.listen_addr {
        Some(addr) => {
            let listener = TcpListener::bind(addr).await?;
            let bound = listener.local_addr().ok();
            let cfg = shared.clone();
            let ev = events_tx.clone();
            tokio::spawn(accept_loop(listener, cfg, ev));
            bound
        }
        None => None,
    };

    for addr in config.bootstrap_peers {
        tokio::spawn(dial_loop(addr, shared.clone(), events_tx.clone()));
    }

    tokio::spawn(worker(
        events_rx,
        commands_rx,
        inbound_tx,
        connected.clone(),
    ));

    Ok((
        NetworkHandle {
            commands: commands_tx,
            local_peer_id,
            local_addr,
            connected,
        },
        inbound_rx,
    ))
}

/// Accepts inbound TCP peers and hands each to a connection task.
async fn accept_loop(
    listener: TcpListener,
    shared: Arc<SharedConfig>,
    events: mpsc::Sender<Event>,
) {
    // A failed accept means the listener socket itself broke; stop accepting
    // (existing peers persist through their own connection tasks).
    while let Ok((stream, _addr)) = listener.accept().await {
        let cfg = shared.clone();
        let ev = events.clone();
        tokio::spawn(async move {
            let _ = run_connection(stream, cfg, ev).await;
        });
    }
}

/// Dials a bootstrap peer and reconnects with capped exponential backoff.
async fn dial_loop(addr: SocketAddr, shared: Arc<SharedConfig>, events: mpsc::Sender<Event>) {
    let mut backoff = RECONNECT_BACKOFF_START_MS;
    loop {
        if events.is_closed() {
            break;
        }
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                backoff = RECONNECT_BACKOFF_START_MS;
                // Returns when the connection closes; then we reconnect.
                let _ = run_connection(stream, shared.clone(), events.clone()).await;
            }
            Err(_) => {
                backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX_MS);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
    }
}

/// Generates fresh OS randomness for one handshake challenge.
fn random_challenge() -> [u8; CHALLENGE_LEN] {
    let mut challenge = [0u8; CHALLENGE_LEN];
    OsRng.fill_bytes(&mut challenge);
    challenge
}

/// Runs one peer connection: symmetric handshake, then read/write pumps.
///
/// Both inbound and outbound sides run the identical sequence — send hello, read
/// the peer's hello, send a proof over the peer's challenge, read and verify the
/// peer's proof over our challenge — so no role distinction is needed.
async fn run_connection(
    stream: TcpStream,
    shared: Arc<SharedConfig>,
    events: mpsc::Sender<Event>,
) -> Result<(), NetError> {
    let _ = stream.set_nodelay(true);
    let mut framed = LengthDelimitedCodec::builder()
        .max_frame_length(MAX_FRAME_BYTES)
        .new_framed(stream);

    // 1. Announce ourselves with a fresh challenge.
    let our_challenge = random_challenge();
    let hello = build_hello(&shared.identity, &shared.chain_id, our_challenge);
    framed.send(Bytes::from(codec::encode(&hello)?)).await?;

    // 2. Receive and validate the peer's hello.
    let peer_hello_bytes = next_frame(&mut framed).await?;
    let peer_hello: HandshakeHello = codec::decode(&peer_hello_bytes)?;
    let peer_id = accept_hello(&peer_hello, &shared.chain_id)?;
    if peer_id == PeerId(shared.identity.public_key()) {
        // Refuse to peer with ourselves (e.g. a bootstrap list naming us).
        return Err(NetError::MalformedHandshake);
    }

    // 3. Prove possession of our key over the peer's challenge.
    let proof = build_proof(&shared.identity, &shared.chain_id, &peer_hello.challenge);
    framed.send(Bytes::from(codec::encode(&proof)?)).await?;

    // 4. Receive and verify the peer's proof over our challenge.
    let peer_proof_bytes = next_frame(&mut framed).await?;
    let peer_proof: HandshakeProof = codec::decode(&peer_proof_bytes)?;
    verify_peer_proof(peer_id, &shared.chain_id, &our_challenge, &peer_proof)?;

    // Authenticated. Register an outbound queue and start pumping frames.
    let (out_tx, mut out_rx) = mpsc::channel::<Arc<Vec<u8>>>(PEER_SEND_CAPACITY);
    if events
        .send(Event::Connected {
            peer: peer_id,
            outbound: out_tx,
        })
        .await
        .is_err()
    {
        return Ok(());
    }

    let (mut sink, mut stream) = framed.split();
    let writer = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            if sink.send(Bytes::copy_from_slice(&frame)).await.is_err() {
                break;
            }
        }
    });

    while let Some(frame) = stream.next().await {
        match frame {
            Ok(bytes) => {
                if events
                    .send(Event::Frame {
                        from: peer_id,
                        bytes: bytes.to_vec(),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    writer.abort();
    let _ = events.send(Event::Disconnected { peer: peer_id }).await;
    Ok(())
}

/// Reads the next length-delimited frame, mapping closure/short-read to typed errors.
async fn next_frame(
    framed: &mut Framed<TcpStream, LengthDelimitedCodec>,
) -> Result<Vec<u8>, NetError> {
    match framed.next().await {
        Some(Ok(bytes)) => Ok(bytes.to_vec()),
        Some(Err(err)) => Err(NetError::Io(err.to_string())),
        None => Err(NetError::HandshakeClosed),
    }
}

/// The single worker owning the peer table and gossip loop suppression.
async fn worker(
    mut events_rx: mpsc::Receiver<Event>,
    mut commands_rx: mpsc::UnboundedReceiver<Command>,
    inbound_tx: mpsc::Sender<InboundMessage>,
    connected: Arc<AtomicUsize>,
) {
    let mut peers: Vec<(PeerId, mpsc::Sender<Arc<Vec<u8>>>)> = Vec::new();
    let mut seen = SeenCache::new(SEEN_CACHE_CAPACITY);

    loop {
        tokio::select! {
            command = commands_rx.recv() => {
                match command {
                    Some(Command::Broadcast(message)) => {
                        if let Ok(bytes) = encode_message(&message) {
                            // Mark our own message seen so an echo does not reflood.
                            if seen.insert(message_id(&bytes)) {
                                flood(&peers, None, Arc::new(bytes));
                            }
                        }
                    }
                    Some(Command::SendTo(peer, message)) => {
                        // Point-to-point delivery to one peer; never flooded, so a
                        // sync reply does not fan out full blocks to the mesh.
                        if let Ok(bytes) = encode_message(&message) {
                            send_to_peer(&peers, peer, Arc::new(bytes));
                        }
                    }
                    None => break, // every handle dropped → shut down
                }
            }
            event = events_rx.recv() => {
                match event {
                    Some(Event::Connected { peer, outbound }) => {
                        // Replace any stale duplicate connection to the same peer.
                        peers.retain(|(existing, _)| *existing != peer);
                        peers.push((peer, outbound));
                        connected.store(peers.len(), Ordering::Relaxed);
                    }
                    Some(Event::Disconnected { peer }) => {
                        peers.retain(|(existing, _)| *existing != peer);
                        connected.store(peers.len(), Ordering::Relaxed);
                    }
                    Some(Event::Frame { from, bytes }) => {
                        // Suppress loops: only act on the first copy of a frame.
                        if !seen.insert(message_id(&bytes)) {
                            continue;
                        }
                        // A malformed frame from a peer is dropped, not fatal.
                        if let Ok(message) = decode_message(&bytes) {
                            // A state-sync response is a point-to-point reply, not
                            // gossip: deliver it locally but never reflood it, or
                            // one node's directed answer would still fan full
                            // blocks across the whole mesh (C7).
                            let is_directed = matches!(message, NetMessage::BlockResponse(_));
                            let _ = inbound_tx.try_send(InboundMessage { from, message });
                            if !is_directed {
                                // Continue the flood to everyone except the sender.
                                flood(&peers, Some(from), Arc::new(bytes));
                            }
                        }
                    }
                    None => break,
                }
            }
        }
    }
}

/// Sends an encoded frame to every peer except an optional excluded one.
fn flood(
    peers: &[(PeerId, mpsc::Sender<Arc<Vec<u8>>>)],
    except: Option<PeerId>,
    frame: Arc<Vec<u8>>,
) {
    for (peer, outbound) in peers {
        if Some(*peer) == except {
            continue;
        }
        // Best-effort: a full or closed peer queue drops this frame for that peer.
        let _ = outbound.try_send(frame.clone());
    }
}

/// Sends an encoded frame to exactly one peer, if it is connected (best-effort).
fn send_to_peer(
    peers: &[(PeerId, mpsc::Sender<Arc<Vec<u8>>>)],
    target: PeerId,
    frame: Arc<Vec<u8>>,
) {
    if let Some((_, outbound)) = peers.iter().find(|(peer, _)| *peer == target) {
        let _ = outbound.try_send(frame);
    }
}

/// Bounded set of recently seen frame IDs with FIFO eviction.
struct SeenCache {
    capacity: usize,
    order: VecDeque<webc_crypto::Hash256>,
    set: HashSet<webc_crypto::Hash256>,
}

impl SeenCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::with_capacity(capacity.max(1)),
            set: HashSet::with_capacity(capacity.max(1)),
        }
    }

    /// Records an ID, returning `true` only if it was not already present.
    fn insert(&mut self, id: webc_crypto::Hash256) -> bool {
        if !self.set.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.set.remove(&evicted);
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use webc_chain::{Amount, FeeBid, Operation, Transaction};
    use webc_crypto::Hash256;

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    fn sample_tx(seed: u8) -> Transaction {
        let sender = Keypair::from_seed([seed; 32]);
        let recipient = Keypair::from_seed([seed.wrapping_add(1); 32]);
        Transaction::for_operation(
            &sender,
            0,
            Operation::Transfer {
                to: recipient.address(),
                amount: Amount::from_webc(1),
            },
            FeeBid {
                gas_limit: 1_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap()
    }

    /// Spawns a listening node and returns its handle + inbound receiver + addr.
    async fn spawn_listener(
        seed: u8,
        chain: ChainId,
    ) -> (NetworkHandle, mpsc::Receiver<InboundMessage>, SocketAddr) {
        let (handle, rx) = spawn_network(NetworkConfig::new(
            Keypair::from_seed([seed; 32]),
            chain,
            Some(loopback()),
            Vec::new(),
        ))
        .await
        .unwrap();
        let addr = handle.local_addr().expect("listener bound");
        (handle, rx, addr)
    }

    /// Polls until both nodes report a connected peer, or times out.
    async fn await_connected(a: &NetworkHandle, b: &NetworkHandle) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if a.connected_peers() >= 1 && b.connected_peers() >= 1 {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("peers did not connect in time");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn two_nodes_authenticate_and_gossip_a_transaction() {
        let chain = ChainId::devnet();
        let (a_handle, _a_rx, a_addr) = spawn_listener(1, chain.clone()).await;
        let (b_handle, mut b_rx) = spawn_network(NetworkConfig::new(
            Keypair::from_seed([2u8; 32]),
            chain,
            Some(loopback()),
            vec![a_addr],
        ))
        .await
        .unwrap();

        await_connected(&a_handle, &b_handle).await;

        let tx = sample_tx(50);
        let tx_hash = tx.hash().unwrap();
        a_handle
            .broadcast(NetMessage::Transaction(Box::new(tx)))
            .unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), b_rx.recv())
            .await
            .expect("gossip delivered before timeout")
            .expect("inbound channel open");
        assert_eq!(received.from, a_handle.local_peer_id());
        let NetMessage::Transaction(got) = received.message else {
            panic!("expected a transaction message");
        };
        assert_eq!(got.hash().unwrap(), tx_hash);
    }

    #[tokio::test]
    async fn duplicate_broadcast_is_delivered_once() {
        let chain = ChainId::devnet();
        let (a_handle, _a_rx, a_addr) = spawn_listener(3, chain.clone()).await;
        let (b_handle, mut b_rx) = spawn_network(NetworkConfig::new(
            Keypair::from_seed([4u8; 32]),
            chain,
            Some(loopback()),
            vec![a_addr],
        ))
        .await
        .unwrap();
        await_connected(&a_handle, &b_handle).await;

        let tx = sample_tx(60);
        let message = NetMessage::Transaction(Box::new(tx));
        // Broadcast the identical frame twice; the seen-cache must suppress the copy.
        a_handle.broadcast(message.clone()).unwrap();
        a_handle.broadcast(message).unwrap();

        tokio::time::timeout(Duration::from_secs(5), b_rx.recv())
            .await
            .expect("first copy delivered")
            .expect("channel open");
        let second = tokio::time::timeout(Duration::from_millis(600), b_rx.recv()).await;
        assert!(
            second.is_err(),
            "duplicate frame must not be delivered again"
        );
    }

    #[tokio::test]
    async fn send_to_reaches_only_the_named_peer() {
        // A central node connected to two peers must be able to send a message
        // to exactly one of them (directed reply), not both (C7).
        let chain = ChainId::devnet();
        let (hub, mut hub_rx, hub_addr) = spawn_listener(11, chain.clone()).await;
        let (b_handle, mut b_rx) = spawn_network(NetworkConfig::new(
            Keypair::from_seed([12u8; 32]),
            chain.clone(),
            Some(loopback()),
            vec![hub_addr],
        ))
        .await
        .unwrap();
        // `_c_handle` stays bound (not dropped) so C's connection persists.
        let (_c_handle, mut c_rx) = spawn_network(NetworkConfig::new(
            Keypair::from_seed([13u8; 32]),
            chain,
            Some(loopback()),
            vec![hub_addr],
        ))
        .await
        .unwrap();
        // Wait until the hub sees both peers.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while hub.connected_peers() < 2 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "hub did not gain two peers"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // B announces itself so the hub learns B's peer id (from an inbound
        // frame); then the hub sends a message directed only at B.
        b_handle
            .broadcast(NetMessage::Transaction(Box::new(sample_tx(80))))
            .unwrap();
        let from_b = tokio::time::timeout(Duration::from_secs(5), hub_rx.recv())
            .await
            .expect("hub receives B's announcement")
            .expect("channel open");
        let b_peer = from_b.from;
        // Drain any reflood of B's tx that reached C, so the next assertion is clean.
        let _ = tokio::time::timeout(Duration::from_millis(300), c_rx.recv()).await;

        hub.send_to(b_peer, NetMessage::Transaction(Box::new(sample_tx(90))))
            .unwrap();

        // B receives the directed message; C must not.
        let b_got = tokio::time::timeout(Duration::from_secs(5), b_rx.recv())
            .await
            .expect("B receives the directed message")
            .expect("channel open");
        assert!(matches!(b_got.message, NetMessage::Transaction(_)));
        let c_got = tokio::time::timeout(Duration::from_millis(600), c_rx.recv()).await;
        assert!(
            c_got.is_err(),
            "a directed send must not reach a non-target peer"
        );
    }

    #[tokio::test]
    async fn peer_on_a_different_chain_is_not_accepted() {
        let (a_handle, _a_rx, a_addr) = spawn_listener(5, ChainId::devnet()).await;
        // B dials A but is on a different chain; the handshake must fail.
        let (b_handle, mut b_rx) = spawn_network(NetworkConfig::new(
            Keypair::from_seed([6u8; 32]),
            ChainId::new("webc-other-1").unwrap(),
            Some(loopback()),
            vec![a_addr],
        ))
        .await
        .unwrap();

        // Give the dial + failed handshake time to occur.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(a_handle.connected_peers(), 0);
        assert_eq!(b_handle.connected_peers(), 0);

        // A broadcast reaches nobody; B never receives it.
        a_handle
            .broadcast(NetMessage::Transaction(Box::new(sample_tx(70))))
            .unwrap();
        let got = tokio::time::timeout(Duration::from_millis(500), b_rx.recv()).await;
        assert!(got.is_err(), "cross-chain peer must receive nothing");
    }

    #[test]
    fn seen_cache_evicts_oldest_beyond_capacity() {
        let mut cache = SeenCache::new(2);
        let a = Hash256::digest(b"a");
        let b = Hash256::digest(b"b");
        let c = Hash256::digest(b"c");
        assert!(cache.insert(a));
        assert!(cache.insert(b));
        assert!(!cache.insert(a)); // still present
        assert!(cache.insert(c)); // evicts `a` (oldest)
        assert!(cache.insert(a)); // `a` was evicted, so it is new again
    }
}
