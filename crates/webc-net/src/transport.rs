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

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use rand_core::{OsRng, RngCore};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
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

/// Default deadline for completing the full authentication handshake.
///
/// Why 10s (finding N1): the four-step challenge/response is a few small frames
/// over one round trip; even a slow, distant, loaded peer completes it well
/// under a second. Ten seconds is generous enough never to reject an honest
/// peer, yet short enough that a stalled or malicious peer cannot pin a task,
/// socket, and file descriptor for long. A peer that has not authenticated
/// within this window is dropped and its slot freed, which — together with the
/// inbound connection cap (N2) — bounds the slowloris FD-exhaustion surface.
const DEFAULT_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Default cap on concurrent in-flight inbound connections.
///
/// Why 256 (finding N2): every accepted inbound connection costs a task, a
/// socket, and a file descriptor until it authenticates or its handshake
/// deadline (N1) elapses. Capping the total number in flight bounds the
/// resources an inbound flood can pin at once. 256 is far above the handful of
/// peers a healthy devnet node keeps, so honest inbound is never refused; beyond
/// the cap, freshly accepted connections are dropped until a slot frees.
const DEFAULT_MAX_INBOUND_CONNECTIONS: usize = 256;

/// Default cap on concurrent inbound connections from a single source IP.
///
/// Why 8 (finding N2): without a per-source-IP ceiling, one host can consume
/// every global inbound slot and lock every other peer out — a trivial
/// single-box connection-exhaustion DoS and an eclipse aid. Eight lets a
/// legitimately multi-homed or NATed peer open a few connections while keeping
/// any single address to a small share of accept capacity.
const DEFAULT_MAX_INBOUND_PER_IP: usize = 8;

/// Default cap on the number of authenticated peers in the peer table.
///
/// Why 1024 (finding N3): a successful handshake adds one entry to `peers`, and
/// the identity key it is keyed on is an unauthenticated name anyone can mint.
/// Without a cap, a Sybil could inflate the table without bound — growing memory
/// and, worse, multiplying every gossip message through `flood()` (amplification).
/// A deterministic hard cap bounds both. 1024 is far beyond the peer count a
/// healthy devnet node maintains, yet keeps the table and fan-out finite. Beyond
/// the cap, further authenticated connections are rejected (peer scoring and
/// eviction of the least useful peer are later work).
const DEFAULT_MAX_PEERS: usize = 1024;

/// Default per-peer inbound token-bucket burst capacity, in frames.
///
/// Why 512 (finding N4): a peer may legitimately deliver a short burst — a batch
/// of relayed transactions plus a round's worth of consensus proposals/votes —
/// so the bucket must absorb a spike without dropping honest gossip. 512 frames
/// is comfortably above any normal burst.
const DEFAULT_PEER_RATE_CAPACITY: u32 = 512;

/// Default per-peer inbound sustained rate, in frames per second.
///
/// Why 256/s (finding N4): one fast peer must not monopolize the single gossip
/// worker (each inbound frame costs a hash, a decode, and a re-flood) and starve
/// honest peers. 256 frames/s sustained is far above a healthy peer's steady
/// gossip volume at devnet block cadence, yet bounds any single peer's share of
/// the worker; frames beyond the rate are dropped before they cost work and are
/// re-learned from other peers (a fairness bound, not a correctness one).
const DEFAULT_PEER_RATE_PER_SEC: u32 = 256;

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
    /// Deadline for completing the authentication handshake (finding N1).
    ///
    /// A connection that has not finished the mutual challenge/response within
    /// this window is dropped so a stalled peer cannot hold resources forever.
    pub handshake_timeout: std::time::Duration,
    /// Maximum concurrent in-flight inbound connections (finding N2).
    ///
    /// Once this many inbound connections are being handled, freshly accepted
    /// connections are dropped until a slot frees, bounding a connection flood.
    pub max_inbound_connections: usize,
    /// Maximum concurrent inbound connections from any single source IP (N2).
    ///
    /// Keeps one host from consuming every inbound slot and locking others out.
    pub max_inbound_per_ip: usize,
    /// Maximum number of authenticated peers in the peer table (finding N3).
    ///
    /// A deterministic hard cap; connections authenticated beyond it are
    /// rejected so a Sybil cannot inflate the table or gossip fan-out.
    pub max_peers: usize,
    /// Per-peer inbound burst capacity, in frames (finding N4).
    pub peer_rate_capacity: u32,
    /// Per-peer inbound sustained rate, in frames per second (finding N4).
    pub peer_rate_per_sec: u32,
}

impl NetworkConfig {
    /// Builds a config with sensible defaults for the DoS-hardening limits.
    ///
    /// The public constructor keeps a stable four-argument signature so
    /// downstream callers (`webc-node`) are unaffected; the hardening limits use
    /// documented defaults and can be overridden on the returned value in tests.
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
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            max_inbound_connections: DEFAULT_MAX_INBOUND_CONNECTIONS,
            max_inbound_per_ip: DEFAULT_MAX_INBOUND_PER_IP,
            max_peers: DEFAULT_MAX_PEERS,
            peer_rate_capacity: DEFAULT_PEER_RATE_CAPACITY,
            peer_rate_per_sec: DEFAULT_PEER_RATE_PER_SEC,
        }
    }
}

/// Caps concurrent inbound connections per source IP (finding N2).
///
/// The global inbound semaphore alone lets a single host consume every slot; a
/// per-IP ceiling keeps any one address to a small share of accept capacity.
/// Tokio has no keyed semaphore, so this is a small counted map — the standard
/// shape for a per-key connection cap. The `std::sync::Mutex` is held only for
/// the O(1) increment/decrement and never across an `await`, so it cannot block
/// the runtime. A returned [`IpConnectionGuard`] decrements the count on drop,
/// freeing the slot exactly when the connection ends. This is network glue, not
/// consensus state, so a `HashMap` (non-deterministic iteration) is fine.
#[derive(Clone)]
struct IpConnectionLimiter {
    max_per_ip: usize,
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl IpConnectionLimiter {
    /// Builds a limiter allowing at most `max_per_ip` (≥1) connections per IP.
    fn new(max_per_ip: usize) -> Self {
        Self {
            max_per_ip: max_per_ip.max(1),
            counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Reserves a slot for `ip`, or returns `None` if it is already at its cap.
    ///
    /// Fails closed on a poisoned lock (returns `None`) rather than panicking on
    /// a path reachable from network activity.
    fn try_acquire(&self, ip: IpAddr) -> Option<IpConnectionGuard> {
        let mut counts = self.counts.lock().ok()?;
        let entry = counts.entry(ip).or_insert(0);
        if *entry >= self.max_per_ip {
            return None;
        }
        *entry += 1;
        Some(IpConnectionGuard {
            ip,
            counts: self.counts.clone(),
        })
    }
}

/// Frees one per-IP inbound slot when the connection ends.
struct IpConnectionGuard {
    ip: IpAddr,
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl Drop for IpConnectionGuard {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.counts.lock() {
            if let Some(count) = counts.get_mut(&self.ip) {
                *count -= 1;
                if *count == 0 {
                    // Drop empty entries so the map cannot grow unbounded with
                    // one entry per distinct attacker IP.
                    counts.remove(&self.ip);
                }
            }
        }
    }
}

/// Immutable per-node handshake material shared by every connection task.
struct SharedConfig {
    identity: Keypair,
    chain_id: ChainId,
    /// Deadline bounding the authentication handshake (finding N1).
    handshake_timeout: std::time::Duration,
    /// Hard cap on admitted peers (finding N3). A connection acquires one permit
    /// after authenticating and holds it for its lifetime; when none is available
    /// the peer is rejected, so the peer table can never exceed the cap.
    peer_slots: Arc<Semaphore>,
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
        handshake_timeout: config.handshake_timeout,
        // One permit per admissible peer (finding N3), shared by every inbound
        // and outbound connection so the total admitted peer count is bounded.
        peer_slots: Arc::new(Semaphore::new(config.max_peers.max(1))),
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
            // Bound total in-flight inbound connections and per-source-IP
            // concurrency (finding N2) so an inbound flood cannot exhaust
            // tasks/sockets/FDs or let one host monopolize accept capacity.
            let inbound_slots = Arc::new(Semaphore::new(config.max_inbound_connections.max(1)));
            let ip_limiter = IpConnectionLimiter::new(config.max_inbound_per_ip);
            tokio::spawn(accept_loop(listener, cfg, ev, inbound_slots, ip_limiter));
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
        config.peer_rate_capacity,
        config.peer_rate_per_sec,
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

/// Accepts inbound TCP peers and hands each to a connection task, subject to the
/// global and per-IP inbound connection caps (finding N2).
async fn accept_loop(
    listener: TcpListener,
    shared: Arc<SharedConfig>,
    events: mpsc::Sender<Event>,
    inbound_slots: Arc<Semaphore>,
    ip_limiter: IpConnectionLimiter,
) {
    // A failed accept means the listener socket itself broke; stop accepting
    // (existing peers persist through their own connection tasks).
    while let Ok((stream, addr)) = listener.accept().await {
        // Global cap: if every inbound slot is in use, drop this connection now
        // instead of spawning an unbounded handler. The permit is held for the
        // connection's whole lifetime and released when its task ends.
        let Ok(permit) = inbound_slots.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        // Per-IP cap: keep one source IP from consuming every remaining slot.
        let Some(ip_guard) = ip_limiter.try_acquire(addr.ip()) else {
            drop(permit);
            drop(stream);
            continue;
        };
        let cfg = shared.clone();
        let ev = events.clone();
        tokio::spawn(async move {
            // Hold both guards for the connection's lifetime; dropping them when
            // the handler returns frees the global and per-IP slots together.
            let _permit = permit;
            let _ip_guard = ip_guard;
            let _ = run_connection(stream, cfg, ev).await;
        });
    }
}

/// Computes the next reconnect backoff (finding N5).
///
/// The backoff resets to the floor ONLY after an authenticated connection. A
/// bare TCP accept is not enough: a host that accepts TCP but then fails or
/// stalls the handshake would otherwise be redialed every
/// `RECONNECT_BACKOFF_START_MS` forever, since the old code reset on connect.
/// Resetting only on authentication makes a misbehaving host back off like any
/// other unreachable peer.
fn next_reconnect_backoff(previous_ms: u64, authenticated: bool) -> u64 {
    if authenticated {
        RECONNECT_BACKOFF_START_MS
    } else {
        previous_ms.saturating_mul(2).min(RECONNECT_BACKOFF_MAX_MS)
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
                // `run_connection` returns `Ok` only after a successful
                // authenticated handshake (it then runs until the connection
                // closes); a handshake failure/timeout returns `Err`. Reset the
                // backoff only on that authenticated success (N5).
                let authenticated = run_connection(stream, shared.clone(), events.clone())
                    .await
                    .is_ok();
                backoff = next_reconnect_backoff(backoff, authenticated);
            }
            Err(_) => {
                backoff = next_reconnect_backoff(backoff, false);
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

    // Bound the entire authentication handshake with a deadline (finding N1).
    // Without it, a peer that connects and then stalls — never sending its hello
    // or its proof — blocks forever at `next_frame`, pinning this task plus the
    // socket and its file descriptor. Many such half-open connections exhaust the
    // file-descriptor table (a slowloris DoS). `tokio::time::timeout` drops the
    // connection on elapse and frees the slot. The deadline covers only the
    // handshake; once authenticated, the steady-state read loop intentionally has
    // no such deadline, because a healthy peer may sit idle between gossip frames.
    let peer_id = match tokio::time::timeout(
        shared.handshake_timeout,
        perform_handshake(&mut framed, &shared),
    )
    .await
    {
        Ok(result) => result?,
        Err(_elapsed) => return Err(NetError::HandshakeTimedOut),
    };

    // Bound the peer table (finding N3). The peer is now authenticated, but its
    // identity key is an unauthenticated name anyone can mint, so a Sybil could
    // otherwise add unbounded entries to `peers` — inflating memory and, worse,
    // multiplying every gossip message through `flood()`. Admit it only if a peer
    // slot is free; at the cap, reject this connection (it is dropped, freeing its
    // inbound slot) instead of growing the table. The permit is held for the
    // connection's lifetime and released when it ends, freeing the slot. Because
    // the permit is acquired before `Event::Connected` is sent, the worker's
    // `peers` table can never exceed the cap.
    let _peer_slot = match shared.peer_slots.clone().try_acquire_owned() {
        Ok(slot) => slot,
        Err(_) => return Err(NetError::PeerTableFull),
    };

    // Authenticated and admitted. Register an outbound queue and start pumping.
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

/// Runs the four-step mutual challenge/response, returning the authenticated peer.
///
/// This is the exact sequence factored out of [`run_connection`] so the whole of
/// it can be wrapped in a single deadline (finding N1). It performs no
/// registration or pumping; on success the returned [`PeerId`] is authenticated
/// (the peer proved possession of its identity key over our fresh challenge).
async fn perform_handshake(
    framed: &mut Framed<TcpStream, LengthDelimitedCodec>,
    shared: &SharedConfig,
) -> Result<PeerId, NetError> {
    // 1. Announce ourselves with a fresh challenge.
    let our_challenge = random_challenge();
    let hello = build_hello(&shared.identity, &shared.chain_id, our_challenge);
    framed.send(Bytes::from(codec::encode(&hello)?)).await?;

    // 2. Receive and validate the peer's hello.
    let peer_hello_bytes = next_frame(framed).await?;
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
    let peer_proof_bytes = next_frame(framed).await?;
    let peer_proof: HandshakeProof = codec::decode(&peer_proof_bytes)?;
    verify_peer_proof(peer_id, &shared.chain_id, &our_challenge, &peer_proof)?;

    Ok(peer_id)
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
    peer_rate_capacity: u32,
    peer_rate_per_sec: u32,
) {
    let mut peers: Vec<(PeerId, mpsc::Sender<Arc<Vec<u8>>>)> = Vec::new();
    let mut seen = SeenCache::new(SEEN_CACHE_CAPACITY);
    // Per-peer inbound token buckets (finding N4). A bucket's lifetime matches
    // the peer's: created on `Connected`, dropped on `Disconnected`, so the map
    // is bounded by the peer table (itself capped by N3).
    let mut rate_limits: HashMap<PeerId, TokenBucket> = HashMap::new();

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
                        // Start (or reset) this peer's inbound rate budget (N4).
                        rate_limits.insert(
                            peer,
                            TokenBucket::new(
                                peer_rate_capacity,
                                peer_rate_per_sec,
                                tokio::time::Instant::now(),
                            ),
                        );
                        connected.store(peers.len(), Ordering::Relaxed);
                    }
                    Some(Event::Disconnected { peer }) => {
                        peers.retain(|(existing, _)| *existing != peer);
                        rate_limits.remove(&peer);
                        connected.store(peers.len(), Ordering::Relaxed);
                    }
                    Some(Event::Frame { from, bytes }) => {
                        // Per-peer rate limit FIRST (finding N4), before the hash,
                        // decode, and re-flood a frame would otherwise cost: a peer
                        // that exceeds its token bucket has this frame dropped so it
                        // cannot monopolize the shared worker. Dropped gossip is
                        // re-learned from other peers.
                        if let Some(bucket) = rate_limits.get_mut(&from) {
                            if !bucket.try_admit(tokio::time::Instant::now()) {
                                continue;
                            }
                        }
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

/// A per-peer token bucket bounding how many inbound frames one peer may force
/// the shared worker to process (finding N4).
///
/// Standard token bucket: up to `capacity` tokens accrue at `refill_per_sec`,
/// one token is spent per admitted frame, and a frame arriving with the bucket
/// empty is dropped *before* it costs the worker a hash, a decode, or a re-flood.
/// This keeps one fast peer from monopolizing the single gossip worker and
/// starving honest peers — a fairness/throughput bound, not a correctness one:
/// dropped gossip is re-learned from other peers. It lives in the network worker,
/// never in a consensus state transition, so reading `tokio::time::Instant` here
/// is deterministic-irrelevant and allowed. All arithmetic is checked/saturating
/// so hostile timing can never overflow or panic.
struct TokenBucket {
    /// Maximum tokens the bucket can hold (burst size).
    capacity: u64,
    /// Tokens replenished per second.
    refill_per_sec: u64,
    /// Tokens currently available.
    tokens: u64,
    /// Instant the `tokens` count was last brought up to date.
    last_refill: tokio::time::Instant,
}

impl TokenBucket {
    /// Builds a bucket that starts full, so a freshly connected peer may burst
    /// immediately up to `capacity`.
    fn new(capacity: u32, refill_per_sec: u32, now: tokio::time::Instant) -> Self {
        let capacity = u64::from(capacity.max(1));
        Self {
            capacity,
            refill_per_sec: u64::from(refill_per_sec.max(1)),
            tokens: capacity,
            last_refill: now,
        }
    }

    /// Refills for the elapsed time, then spends one token.
    ///
    /// Returns `true` if the frame is admitted, `false` if it must be dropped
    /// because the peer has exceeded its allowance.
    fn try_admit(&mut self, now: tokio::time::Instant) -> bool {
        let elapsed_ms = now.saturating_duration_since(self.last_refill).as_millis();
        // tokens accrued = elapsed_ms * refill_per_sec / 1000 (integer).
        let accrued = elapsed_ms.saturating_mul(u128::from(self.refill_per_sec)) / 1000;
        if accrued >= u128::from(self.capacity) {
            // Enough time elapsed to fully refill; the bucket is full and all of
            // the elapsed time is now accounted for.
            self.tokens = self.capacity;
            self.last_refill = now;
        } else if accrued > 0 {
            let accrued = accrued as u64; // < capacity ≤ u32::MAX, so this fits
            self.tokens = self.tokens.saturating_add(accrued).min(self.capacity);
            // Advance `last_refill` only by the whole-token time credited, so the
            // sub-token remainder is not lost to integer rounding (which would
            // throttle a peer below its configured rate).
            let credited_ms =
                (u128::from(accrued).saturating_mul(1000) / u128::from(self.refill_per_sec)) as u64;
            self.last_refill += std::time::Duration::from_millis(credited_ms);
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
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

    #[test]
    fn backoff_grows_until_authenticated_then_resets() {
        // N5: a bare TCP accept (authenticated = false) keeps growing the
        // backoff; only an authenticated connection resets it to the floor.
        let mut backoff = RECONNECT_BACKOFF_START_MS;
        backoff = next_reconnect_backoff(backoff, false);
        assert_eq!(backoff, RECONNECT_BACKOFF_START_MS * 2);
        backoff = next_reconnect_backoff(backoff, false);
        assert_eq!(backoff, RECONNECT_BACKOFF_START_MS * 4);
        // The growth is capped.
        for _ in 0..20 {
            backoff = next_reconnect_backoff(backoff, false);
        }
        assert_eq!(backoff, RECONNECT_BACKOFF_MAX_MS);
        // An authenticated connection resets to the floor.
        assert_eq!(
            next_reconnect_backoff(backoff, true),
            RECONNECT_BACKOFF_START_MS
        );
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
    async fn a_stalled_handshake_is_dropped_after_the_timeout() {
        use tokio::io::AsyncReadExt;
        // N1 reproduce: a peer that connects and then stalls (never sends its
        // hello or proof) must be dropped once the handshake deadline elapses,
        // freeing the task/socket/FD. Pre-fix the handshake had no deadline, so
        // the server held the half-open connection forever.
        let chain = ChainId::devnet();
        let mut cfg = NetworkConfig::new(
            Keypair::from_seed([21u8; 32]),
            chain,
            Some(loopback()),
            Vec::new(),
        );
        cfg.handshake_timeout = Duration::from_millis(300);
        let (handle, _rx) = spawn_network(cfg).await.unwrap();
        let addr = handle.local_addr().expect("listener bound");

        // Raw client: connect, then never send a hello or proof (a slowloris).
        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();

        // The server must close the connection once the deadline elapses; we see
        // that as EOF (read returns 0) or a reset. A per-read timeout keeps the
        // test from hanging if the server (pre-fix) holds the connection open.
        let mut buf = [0u8; 1024];
        let closed = loop {
            match tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf)).await {
                Ok(Ok(0)) => break true,  // EOF: server dropped the stalled peer
                Ok(Ok(_)) => continue,    // server's own hello bytes; keep reading
                Ok(Err(_)) => break true, // connection reset also means dropped
                Err(_) => break false,    // no close within 2s → still held open
            }
        };
        assert!(
            closed,
            "server must drop a stalled handshake after the deadline"
        );
    }

    #[tokio::test]
    async fn a_flooding_peer_is_rate_limited_before_reflood() {
        // N4 reproduce: a receiver applies a per-peer token bucket to inbound
        // frames, so a peer that floods many distinct frames has the excess
        // dropped before they are delivered or reflooded. Pre-fix every frame
        // was processed, letting one peer monopolize the shared worker.
        let chain = ChainId::devnet();
        // Receiver R with a tiny per-peer budget so the cap is easy to observe.
        let mut r_cfg = NetworkConfig::new(
            Keypair::from_seed([61u8; 32]),
            chain.clone(),
            Some(loopback()),
            Vec::new(),
        );
        r_cfg.peer_rate_capacity = 2;
        r_cfg.peer_rate_per_sec = 1;
        let (r_handle, mut r_rx) = spawn_network(r_cfg).await.unwrap();
        let r_addr = r_handle.local_addr().expect("listener bound");

        // Sender S dials R and then floods.
        let (s_handle, _s_rx) = spawn_network(NetworkConfig::new(
            Keypair::from_seed([62u8; 32]),
            chain,
            None,
            vec![r_addr],
        ))
        .await
        .unwrap();
        await_connected(&r_handle, &s_handle).await;

        // Flood 20 DISTINCT transactions back-to-back (distinct so the seen-cache
        // does not collapse them and each is a genuine inbound frame at R).
        const SENT: u8 = 20;
        for i in 0..SENT {
            s_handle
                .broadcast(NetMessage::Transaction(Box::new(sample_tx(100 + i))))
                .unwrap();
        }

        // Count what R actually delivers in a short window. The refill (1/sec)
        // credits no whole token inside this window, so only the burst capacity
        // gets through.
        let mut delivered = 0usize;
        let window = tokio::time::Instant::now() + Duration::from_millis(700);
        loop {
            let remaining = window.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, r_rx.recv()).await {
                Ok(Some(_)) => delivered += 1,
                Ok(None) => break,
                Err(_) => break,
            }
        }
        assert!(delivered >= 1, "the initial burst must get through");
        assert!(
            delivered <= 6,
            "a flooding peer must be rate-limited (delivered {delivered} of {SENT})"
        );
    }

    /// Drives the N2 caps: two raw connections occupy two inbound slots, then a
    /// real dial-only client must be unable to authenticate until a slot frees.
    /// With `max_conn`/`max_per_ip` chosen so one of the two caps binds at 2, the
    /// third peer is blocked; pre-fix (no caps) it connected immediately.
    async fn assert_inbound_cap_blocks_third(max_conn: usize, max_per_ip: usize, seed: u8) {
        let chain = ChainId::devnet();
        let mut server_cfg = NetworkConfig::new(
            Keypair::from_seed([seed; 32]),
            chain.clone(),
            Some(loopback()),
            Vec::new(),
        );
        server_cfg.max_inbound_connections = max_conn;
        server_cfg.max_inbound_per_ip = max_per_ip;
        // Keep the two stalled slots held for the whole test (no N1 timeout).
        server_cfg.handshake_timeout = Duration::from_secs(30);
        let (server, _server_rx) = spawn_network(server_cfg).await.unwrap();
        let addr = server.local_addr().expect("listener bound");

        // Occupy two inbound slots with raw connections that never authenticate.
        let s1 = tokio::net::TcpStream::connect(addr).await.unwrap();
        let s2 = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Let the server accept both and take both slots.
        tokio::time::sleep(Duration::from_millis(300)).await;

        // A real dial-only client tries to join; it must NOT authenticate while
        // the two slots are held.
        let (client, _client_rx) = spawn_network(NetworkConfig::new(
            Keypair::from_seed([seed.wrapping_add(100); 32]),
            chain,
            None,
            vec![addr],
        ))
        .await
        .unwrap();

        // Give the client several dial attempts; all must be rejected.
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert_eq!(
            server.connected_peers(),
            0,
            "no peer may authenticate while both inbound slots are occupied"
        );

        // Free one slot; the client must now be able to connect.
        drop(s1);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while server.connected_peers() < 1 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "client must connect once an inbound slot frees"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        drop(s2);
        // Keep the client handle alive until the assertions complete.
        drop(client);
    }

    #[tokio::test]
    async fn global_inbound_connection_cap_is_enforced() {
        // Global cap binds (per-IP set high): two in-flight connections fill the
        // two-slot global budget, blocking a third.
        assert_inbound_cap_blocks_third(2, 64, 31).await;
    }

    #[tokio::test]
    async fn per_ip_inbound_connection_cap_is_enforced() {
        // Per-IP cap binds (global set high): two connections from 127.0.0.1 use
        // up the per-IP budget of 2, blocking a third from the same address.
        assert_inbound_cap_blocks_third(64, 2, 41).await;
    }

    #[tokio::test]
    async fn peer_table_size_is_capped() {
        // N3 reproduce: with max_peers = 1, only one authenticated peer is
        // admitted; a second authenticates but is rejected, so the table never
        // exceeds the cap. Pre-fix the table grew one entry per handshake, so a
        // second (or a Sybil flood of) peers would all be admitted.
        let chain = ChainId::devnet();
        let mut server_cfg = NetworkConfig::new(
            Keypair::from_seed([51u8; 32]),
            chain.clone(),
            Some(loopback()),
            Vec::new(),
        );
        server_cfg.max_peers = 1;
        let (server, _server_rx) = spawn_network(server_cfg).await.unwrap();
        let addr = server.local_addr().expect("listener bound");

        // First peer connects and fills the single slot.
        let (peer1, _p1_rx) = spawn_network(NetworkConfig::new(
            Keypair::from_seed([52u8; 32]),
            chain.clone(),
            None,
            vec![addr],
        ))
        .await
        .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while server.connected_peers() < 1 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "first peer must be admitted"
            );
            tokio::time::sleep(Duration::from_millis(30)).await;
        }

        // Second peer dials and authenticates, but the table is full: it must be
        // rejected, keeping the admitted peer count at the cap.
        let (peer2, _p2_rx) = spawn_network(NetworkConfig::new(
            Keypair::from_seed([53u8; 32]),
            chain,
            None,
            vec![addr],
        ))
        .await
        .unwrap();
        // Give the second peer several dial+handshake attempts.
        tokio::time::sleep(Duration::from_millis(1_000)).await;
        assert_eq!(
            server.connected_peers(),
            1,
            "peer table must never exceed max_peers, even under Sybil dialing"
        );

        // Keep both client handles alive through the assertion.
        drop(peer1);
        drop(peer2);
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

    #[tokio::test]
    async fn token_bucket_bounds_burst_then_refills() {
        // N4 mechanism, deterministic (synthetic instants, no real waiting): the
        // bucket admits up to `capacity` at once, denies beyond it, and re-admits
        // exactly as whole tokens refill; a long idle refills only to capacity.
        let t0 = tokio::time::Instant::now();
        let mut bucket = TokenBucket::new(2, 10, t0); // capacity 2, 10 tokens/sec

        assert!(bucket.try_admit(t0), "first burst frame admitted");
        assert!(bucket.try_admit(t0), "second burst frame admitted");
        assert!(!bucket.try_admit(t0), "third frame beyond capacity denied");

        // 50ms at 10/sec is under one whole token → still denied.
        assert!(!bucket.try_admit(t0 + Duration::from_millis(50)));

        // 100ms → exactly one token refilled → one admit, then denied again.
        let t1 = t0 + Duration::from_millis(100);
        assert!(bucket.try_admit(t1), "one refilled token admits one frame");
        assert!(
            !bucket.try_admit(t1),
            "no tokens left after spending the refill"
        );

        // A long idle refills to capacity but never beyond it.
        let t2 = t1 + Duration::from_secs(60);
        assert!(bucket.try_admit(t2));
        assert!(bucket.try_admit(t2));
        assert!(!bucket.try_admit(t2), "refill is clamped to capacity");
    }
}
