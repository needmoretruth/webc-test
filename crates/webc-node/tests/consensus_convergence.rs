//! End-to-end A-3 consensus test: three validator nodes running the async
//! consensus driver over the real authenticated TCP transport converge on one
//! finalized chain, committing the same blocks at the same heights.
//!
//! This exercises the full stack composed in Phase 4: `webc-net` transport and
//! gossip (A-1), the signed proposal/vote/certificate wire types and the
//! multi-round `ConsensusMachine` (A-2/A-3), and the async `ConsensusDriver` that
//! runs a machine per height, builds candidate blocks, arms real timers, and
//! commits finalized blocks via `Node::import_block` (A-3).

use std::time::Duration;

use tokio::sync::mpsc;
use webc_chain::{Amount, ChainConfig, GenesisAccount, GenesisConfig, GenesisValidator};
use webc_crypto::{Hash256, Keypair};
use webc_net::{spawn_network, NetworkConfig};
use webc_node::{CommitInfo, ConsensusDriver, DriverTimeouts, Node};
use webc_storage::MemoryKvStore;

/// A genesis with three equally-staked validators, each active from genesis
/// (self-stake comfortably exceeds the activation threshold), so the validator
/// snapshot has real voting power without an epoch transition.
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

#[tokio::test]
async fn three_validators_converge_on_one_finalized_chain() {
    let chain = ChainConfig::default().chain_id;
    // Validator consensus keypairs; the seed doubles as the driver's identity.
    let seeds: [[u8; 32]; 3] = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let validators: Vec<Keypair> = seeds.iter().map(|s| Keypair::from_seed(*s)).collect();
    let genesis = validator_genesis(&validators);

    // Sanity: all three validators are active in the genesis snapshot.
    let probe = Node::open(MemoryKvStore::new(), &genesis).unwrap();
    let snapshot = webc_chain::ValidatorSet::from_state(probe.state()).unwrap();
    assert_eq!(
        snapshot.validators.len(),
        3,
        "validators must be active at genesis"
    );

    // Spawn three networks on loopback: node 0 listens, nodes 1 and 2 dial the
    // earlier ones so the flood-gossip mesh is connected.
    let (h0, in0) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([100u8; 32]),
        chain.clone(),
        Some("127.0.0.1:0".parse().unwrap()),
        Vec::new(),
    ))
    .await
    .unwrap();
    let a0 = h0.local_addr().unwrap();

    let (h1, in1) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([101u8; 32]),
        chain.clone(),
        Some("127.0.0.1:0".parse().unwrap()),
        vec![a0],
    ))
    .await
    .unwrap();
    let a1 = h1.local_addr().unwrap();

    let (h2, in2) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([102u8; 32]),
        chain.clone(),
        Some("127.0.0.1:0".parse().unwrap()),
        vec![a0, a1],
    ))
    .await
    .unwrap();

    // Wait for the authenticated peering to establish across all three.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while h0.connected_peers() < 2 || h1.connected_peers() < 2 || h2.connected_peers() < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "peers did not connect"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Short timeouts so any round change resolves quickly.
    let timeouts = DriverTimeouts {
        propose: Duration::from_millis(400),
        prevote: Duration::from_millis(400),
        precommit: Duration::from_millis(400),
    };

    let handles = [h0, h1, h2];
    let inbounds = [in0, in1, in2];
    let mut commit_rxs = Vec::new();

    for (index, (handle, inbound)) in handles.into_iter().zip(inbounds).enumerate() {
        let node = Node::open(MemoryKvStore::new(), &genesis).unwrap();
        let (commit_tx, commit_rx) = mpsc::channel::<CommitInfo>(64);
        commit_rxs.push(commit_rx);
        let driver = ConsensusDriver::new(node, handle, Some(seeds[index]), timeouts);
        tokio::spawn(driver.run(inbound, Some(commit_tx)));
    }

    // Collect the latest committed (height, tip) from each node until all three
    // have finalized at least two blocks, or a hard timeout trips.
    let target_height = 2u64;
    let mut latest: Vec<Option<CommitInfo>> = vec![None; 3];
    // Record every height's tip per node to assert agreement at each height.
    let mut tips_by_height: Vec<std::collections::BTreeMap<u64, Hash256>> =
        vec![std::collections::BTreeMap::new(); 3];

    let overall = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            for (index, rx) in commit_rxs.iter_mut().enumerate() {
                while let Ok(info) = rx.try_recv() {
                    if let Some(tip) = info.tip {
                        tips_by_height[index].insert(info.height, tip);
                    }
                    latest[index] = Some(info);
                }
            }
            if latest
                .iter()
                .all(|c| c.map(|info| info.height >= target_height).unwrap_or(false))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;

    assert!(
        overall.is_ok(),
        "the three nodes did not all finalize {target_height} blocks in time"
    );

    // Every node finalized the identical block at each height it reported.
    for height in 1..=target_height {
        let tip0 = tips_by_height[0].get(&height).copied();
        let tip1 = tips_by_height[1].get(&height).copied();
        let tip2 = tips_by_height[2].get(&height).copied();
        assert!(
            tip0.is_some() && tip1.is_some() && tip2.is_some(),
            "missing height {height}"
        );
        assert_eq!(tip0, tip1, "node 0 and 1 disagree at height {height}");
        assert_eq!(tip1, tip2, "node 1 and 2 disagree at height {height}");
    }
}
