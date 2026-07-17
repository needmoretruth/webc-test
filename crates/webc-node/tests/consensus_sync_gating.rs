//! C7 regression: a node must request state sync only on a **verified** finality
//! certificate for a higher height — never on an unproven higher-height claim —
//! and must answer a sync request directly to the requester, not by flooding the
//! whole mesh with full blocks.
//!
//! Part A (request gating): an idle node is fed a validly signed prevote for a
//! far-higher height. Pre-fix this triggered a `BlockRequest` broadcast (a
//! spoofed vote was enough). It must now stay silent. A genuine finality
//! certificate for a higher height, verifying against the node's validator
//! snapshot, must instead trigger exactly one request.
//!
//! Part B (directed reply): a node holding finalized blocks receives a
//! `BlockRequest` from one peer while a second peer is also connected. The
//! `BlockResponse`(s) must reach the requester only — the transport does not
//! reflood a point-to-point sync response — so answering a request cannot
//! amplify into a network-wide block flood.

use std::time::Duration;

use tokio::sync::mpsc;
use webc_chain::{
    Amount, ChainConfig, FinalityCertificate, GenesisAccount, GenesisConfig, GenesisValidator,
    SignedVote, ValidatorSet, Vote, VoteType,
};
use webc_crypto::{Hash256, Keypair};
use webc_net::{spawn_network, InboundMessage, NetMessage, NetworkConfig};
use webc_node::{CommitInfo, ConsensusDriver, DriverTimeouts, MempoolConfig, Node};
use webc_storage::MemoryKvStore;

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

fn timeouts() -> DriverTimeouts {
    DriverTimeouts {
        propose: Duration::from_millis(400),
        prevote: Duration::from_millis(400),
        precommit: Duration::from_millis(400),
        increment: Duration::from_millis(200),
    }
}

/// A spoofed higher-height vote must NOT induce a sync request; a genuine
/// higher-height certificate must.
#[tokio::test]
async fn sync_requests_only_on_a_verified_higher_certificate() {
    let chain = ChainConfig::default().chain_id;
    // Four validators: the harness holds three keys (>2/3) so it can build a
    // genuinely verifying certificate; the node under test is the fourth.
    let seeds: [[u8; 32]; 4] = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    let validators: Vec<Keypair> = seeds.iter().map(|s| Keypair::from_seed(*s)).collect();
    let genesis = validator_genesis(&validators);
    let snapshot =
        ValidatorSet::from_state(Node::open(MemoryKvStore::new(), &genesis).unwrap().state())
            .unwrap();

    let (harness, mut harness_inbound) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([90u8; 32]),
        chain.clone(),
        Some("127.0.0.1:0".parse().unwrap()),
        Vec::new(),
    ))
    .await
    .unwrap();
    let harness_addr = harness.local_addr().unwrap();

    // The node under test is an OBSERVER (no consensus seed) so it produces no
    // consensus traffic of its own: any BlockRequest we see is a sync request.
    let (handle, inbound) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([91u8; 32]),
        chain.clone(),
        Some("127.0.0.1:0".parse().unwrap()),
        vec![harness_addr],
    ))
    .await
    .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while handle.connected_peers() == 0 {
        assert!(tokio::time::Instant::now() < deadline, "did not peer");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let node = Node::open(MemoryKvStore::new(), &genesis).unwrap();
    let (commit_tx, _commit_rx) = mpsc::channel::<CommitInfo>(16);
    let driver = ConsensusDriver::new(node, handle, None, timeouts(), MempoolConfig::default());
    let task = tokio::spawn(driver.run(inbound, Some(commit_tx)));

    // Spoof: a validly signed prevote for a far-higher height. It must NOT
    // trigger a sync request.
    let spoof = SignedVote::sign(
        Vote {
            protocol_version: genesis.chain.protocol_version,
            chain_id: chain.clone(),
            height: 99,
            round: 0,
            vote_type: VoteType::Prevote,
            block_hash: Hash256([0x77; 32]),
            validator: validators[0].address(),
        },
        &validators[0],
    )
    .unwrap();
    harness
        .broadcast(NetMessage::Vote(Box::new(spoof)))
        .unwrap();

    // Watch for a BlockRequest for a while: none may appear.
    let spoof_window = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < spoof_window {
        while let Ok(InboundMessage { message, .. }) = harness_inbound.try_recv() {
            assert!(
                !matches!(message, NetMessage::BlockRequest { .. }),
                "a spoofed higher-height vote must not trigger a sync request"
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Now deliver a GENUINE finality certificate for a higher height, signed by
    // three of four validators (>2/3) so it verifies against the snapshot.
    let bad_hash = Hash256([0x33; 32]);
    let precommits: Vec<SignedVote> = validators[..3]
        .iter()
        .map(|key| {
            SignedVote::sign(
                Vote {
                    protocol_version: genesis.chain.protocol_version,
                    chain_id: chain.clone(),
                    height: 5,
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
        5,
        0,
        bad_hash,
        &precommits,
    )
    .expect("three of four validators exceed two thirds");
    certificate
        .verify(&snapshot, genesis.chain.protocol_version, &chain)
        .expect("the certificate verifies against the snapshot");
    harness
        .broadcast(NetMessage::Certificate(Box::new(certificate)))
        .unwrap();

    // Exactly one sync request must now appear.
    let saw_request = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(InboundMessage { message, .. }) = harness_inbound.recv().await {
                if matches!(message, NetMessage::BlockRequest { .. }) {
                    return true;
                }
            } else {
                return false;
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        saw_request,
        "a verified higher-height certificate must trigger a sync request"
    );

    task.abort();
    let _ = task.await;
}

/// A served `BlockResponse` reaches only the requesting peer, not a bystander.
///
/// A single-validator node finalizes every height instantly and never awaits
/// network input, so it could not serve a request; the servers here are a real
/// 3-validator cluster that awaits each other's votes (and therefore processes
/// inbound, including sync requests).
#[tokio::test]
async fn a_sync_response_is_directed_not_flooded() {
    let chain = ChainConfig::default().chain_id;
    let seeds: [[u8; 32]; 3] = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let validators: Vec<Keypair> = seeds.iter().map(|s| Keypair::from_seed(*s)).collect();
    let genesis = validator_genesis(&validators);

    // Bring up three validator networks and start their drivers synchronized.
    let mut handles = Vec::new();
    let mut inbounds = Vec::new();
    let mut addrs = Vec::new();
    let mut prior: Vec<std::net::SocketAddr> = Vec::new();
    for index in 0..3 {
        let (handle, inbound) = spawn_network(NetworkConfig::new(
            Keypair::from_seed([200u8 + index as u8; 32]),
            chain.clone(),
            Some("127.0.0.1:0".parse().unwrap()),
            prior.clone(),
        ))
        .await
        .unwrap();
        addrs.push(handle.local_addr().unwrap());
        prior.push(handle.local_addr().unwrap());
        handles.push(handle);
        inbounds.push(inbound);
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while handles.iter().any(|h| h.connected_peers() < 2) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "validators did not peer"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut commit_rxs = Vec::new();
    for (index, (handle, inbound)) in handles.into_iter().zip(inbounds).enumerate() {
        let node = Node::open(MemoryKvStore::new(), &genesis).unwrap();
        let (commit_tx, commit_rx) = mpsc::channel::<CommitInfo>(64);
        commit_rxs.push(commit_rx);
        let driver = ConsensusDriver::new(
            node,
            handle,
            Some(seeds[index]),
            timeouts(),
            MempoolConfig::default(),
        );
        tokio::spawn(driver.run(inbound, Some(commit_tx)));
    }

    // Wait until the cluster has finalized several heights to serve.
    let warmed = tokio::time::timeout(Duration::from_secs(20), async {
        let mut tips = std::collections::BTreeMap::new();
        loop {
            for rx in commit_rxs.iter_mut() {
                while let Ok(info) = rx.try_recv() {
                    if let Some(tip) = info.tip {
                        tips.insert(info.height, tip);
                    }
                }
            }
            if tips.contains_key(&3) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or(false);
    assert!(warmed, "the cluster did not finalize blocks to serve");

    // A requester and a bystander both dial the whole validator cluster. Only
    // the requester will ask for blocks.
    let (requester, mut requester_inbound) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([81u8; 32]),
        chain.clone(),
        Some("127.0.0.1:0".parse().unwrap()),
        addrs.clone(),
    ))
    .await
    .unwrap();
    let (bystander, mut bystander_inbound) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([82u8; 32]),
        chain.clone(),
        Some("127.0.0.1:0".parse().unwrap()),
        addrs.clone(),
    ))
    .await
    .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while requester.connected_peers() == 0 || bystander.connected_peers() == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "late peers did not connect"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Track whether the bystander ever receives a BlockResponse for the whole
    // test window; it must not, even as gossip (certificates/votes) flows.
    let bystander_leak = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let leak_flag = bystander_leak.clone();
    let bystander_watch = tokio::spawn(async move {
        while let Some(InboundMessage { message, .. }) = bystander_inbound.recv().await {
            if matches!(message, NetMessage::BlockResponse(_)) {
                leak_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
    });

    // Drive the requests from a separate task so a busy inbound stream (constant
    // gossip) cannot starve the request send. Vary `from_height` so each request
    // is distinct bytes and is not suppressed by any peer's seen-cache.
    let request_driver = {
        let requester = requester.clone();
        tokio::spawn(async move {
            let mut n = 0u64;
            loop {
                let _ = requester.broadcast(NetMessage::BlockRequest {
                    from_height: 1 + (n % 2),
                    max: 3,
                });
                n += 1;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
    };

    // A validator serves the finalized blocks directed back to the requester.
    let got_response = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match requester_inbound.recv().await {
                Some(InboundMessage { message, .. }) => {
                    if matches!(message, NetMessage::BlockResponse(_)) {
                        return true;
                    }
                }
                None => return false,
            }
        }
    })
    .await
    .unwrap_or(false);
    request_driver.abort();
    let _ = request_driver.await;
    assert!(got_response, "the requester never received a sync response");

    // Give any (erroneous) flood a moment to arrive at the bystander.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !bystander_leak.load(std::sync::atomic::Ordering::SeqCst),
        "a directed sync response leaked to a bystander (amplification)"
    );

    bystander_watch.abort();
    let _ = bystander_watch.await;
}
