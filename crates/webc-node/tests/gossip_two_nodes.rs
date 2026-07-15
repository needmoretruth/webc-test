//! End-to-end A-1 gossip test: a transaction submitted to one node reaches the
//! other node's mempool over the real authenticated TCP transport.
//!
//! This exercises the full A-1 path: `AppState::submit_transaction` broadcasts a
//! locally accepted transaction, the transport authenticates the peer and floods
//! the frame, and the receiving node's gossip pump admits it into its mempool.

use std::time::Duration;

use webc_chain::{
    Amount, ChainConfig, FeeBid, GenesisAccount, GenesisConfig, Operation, Transaction,
};
use webc_crypto::Keypair;
use webc_net::{spawn_network, NetworkConfig};
use webc_node::{run_gossip_pump, AppState, MempoolConfig, Node, NodeService, NodeServiceOptions};
use webc_storage::MemoryKvStore;

/// Builds a standalone in-memory node service with `alice` funded in genesis.
fn build_service(alice: &Keypair) -> NodeService<MemoryKvStore> {
    let genesis = GenesisConfig {
        chain: ChainConfig::default(),
        accounts: vec![GenesisAccount {
            address: alice.address(),
            balance: Amount::from_webc(1_000),
        }],
        validators: Vec::new(),
    };
    let node = Node::open(MemoryKvStore::new(), &genesis).unwrap();
    NodeService::new(
        node,
        NodeServiceOptions {
            mempool: MempoolConfig::default(),
            faucet: None,
            proposer: alice.address(),
        },
    )
}

fn transfer(from: &Keypair, to: &Keypair) -> Transaction {
    Transaction::for_operation(
        from,
        0,
        Operation::Transfer {
            to: to.address(),
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

#[tokio::test]
async fn transaction_submitted_to_one_node_reaches_the_others_mempool() {
    let chain = ChainConfig::default().chain_id;
    let alice = Keypair::from_seed([1u8; 32]);
    let bob = Keypair::from_seed([2u8; 32]);

    // Node A listens for peers; node B dials A. Both run a gossip pump.
    let (a_handle, a_inbound) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([100u8; 32]),
        chain.clone(),
        Some("127.0.0.1:0".parse().unwrap()),
        Vec::new(),
    ))
    .await
    .unwrap();
    let a_addr = a_handle.local_addr().unwrap();

    let (b_handle, b_inbound) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([200u8; 32]),
        chain,
        Some("127.0.0.1:0".parse().unwrap()),
        vec![a_addr],
    ))
    .await
    .unwrap();

    let a_state = AppState::with_network(build_service(&alice), Some(a_handle.clone()));
    let b_state = AppState::with_network(build_service(&alice), Some(b_handle.clone()));
    tokio::spawn(run_gossip_pump(a_state.clone(), a_inbound));
    tokio::spawn(run_gossip_pump(b_state.clone(), b_inbound));

    // Wait for the authenticated peering to establish.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while a_handle.connected_peers() == 0 || b_handle.connected_peers() == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "peers did not connect"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Submit to A. It is accepted locally and gossiped to B.
    let receipt = a_state
        .submit_transaction(transfer(&alice, &bob), 1_000)
        .unwrap();
    assert!(receipt.accepted);
    assert_eq!(a_state.service().health().mempool_size, 1);

    // B's mempool receives the gossiped transaction within the timeout.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if b_state.service().health().mempool_size == 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "gossiped transaction never reached node B's mempool"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
