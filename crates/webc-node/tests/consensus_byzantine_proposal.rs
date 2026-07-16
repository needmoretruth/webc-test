//! C1 regression: an honest validator must never prevote (or precommit) a
//! proposal whose block it has not successfully re-executed — Tendermint's
//! `valid(v)` predicate. Without the check, a Byzantine leader can propose a
//! correctly signed but semantically invalid block (here: a forged state
//! root); honest nodes prevote it on signature alone, lock it, precommit it,
//! and the network can assemble a perfectly verifying FinalityCertificate for
//! a block **no node can import** — a certified, unimportable height.
//!
//! Scenario: validator A (never the height-1 round-0 leader) runs a real
//! driver. The harness holds the leader's key and the third validator's key.
//! It signs a proposal for a tampered block (valid body, forged state root)
//! and gossips prevotes for it from both harness validators. The test asserts
//! A signs no prevote or precommit for the tampered block hash; if it does
//! (the pre-fix behavior), the test additionally proves the severity by
//! assembling a full finality certificate for the unimportable block from the
//! three precommits.

use std::time::Duration;

use tokio::sync::mpsc;
use webc_chain::{
    Amount, ChainConfig, FinalityCertificate, GenesisAccount, GenesisConfig, GenesisValidator,
    SignedProposal, SignedVote, ValidatorSet, Vote, VoteType,
};
use webc_crypto::{Hash256, Keypair};
use webc_net::{spawn_network, InboundMessage, NetMessage, NetworkConfig};
use webc_node::{ConsensusDriver, DriverTimeouts, MempoolConfig, Node};
use webc_storage::MemoryKvStore;

/// Three equally-staked genesis validators (active from genesis).
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
async fn an_honest_node_never_votes_for_an_unimportable_block() {
    let chain = ChainConfig::default().chain_id;
    let seeds: [[u8; 32]; 3] = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let validators: Vec<Keypair> = seeds.iter().map(|s| Keypair::from_seed(*s)).collect();
    let genesis = validator_genesis(&validators);

    // The Byzantine leader must be harness-held, so the driver validator is
    // any validator that does NOT lead (height 1, round 0).
    let probe = Node::open(MemoryKvStore::new(), &genesis).unwrap();
    let snapshot = ValidatorSet::from_state(probe.state()).unwrap();
    let leader = snapshot.proposer_for(1, 0).expect("leader scheduled");
    let honest_index = validators
        .iter()
        .position(|keypair| keypair.address() != leader)
        .expect("some validator is not the leader");
    let honest = &validators[honest_index];
    let leader_key = validators
        .iter()
        .find(|keypair| keypair.address() == leader)
        .unwrap();
    let third_key = validators
        .iter()
        .find(|keypair| keypair.address() != leader && keypair.address() != honest.address())
        .unwrap();

    // Craft the Byzantine proposal: a structurally well-formed block whose
    // state root is forged, correctly signed by the scheduled leader. Every
    // signature check passes; only re-execution can reject it.
    let mut bad_block = probe
        .build_candidate(Vec::new(), Vec::new(), leader, 1_700_000_000_000)
        .unwrap();
    bad_block.header.state_root = Hash256([0xAB; 32]);
    let bad_hash = bad_block.hash().unwrap();
    let bad_proposal = SignedProposal::sign(
        genesis.chain.protocol_version,
        chain.clone(),
        1,
        0,
        None,
        bad_block,
        leader,
        leader_key,
    )
    .unwrap();
    // Sanity: the proposal itself is what the wire would accept…
    bad_proposal
        .verify_in_set(&snapshot, genesis.chain.protocol_version, &chain)
        .unwrap();
    // …but the block cannot be imported by any honest node.
    {
        let mut import_probe = Node::open(MemoryKvStore::new(), &genesis).unwrap();
        assert!(import_probe
            .import_block(bad_proposal.block.clone())
            .is_err());
    }

    let sign_vote = |key: &Keypair, vote_type: VoteType| {
        SignedVote::sign(
            Vote {
                protocol_version: genesis.chain.protocol_version,
                chain_id: chain.clone(),
                height: 1,
                round: 0,
                vote_type,
                block_hash: bad_hash,
                validator: key.address(),
            },
            key,
        )
        .unwrap()
    };

    // Harness network node; the honest driver dials it.
    let (harness, mut harness_inbound) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([90u8; 32]),
        chain.clone(),
        Some("127.0.0.1:0".parse().unwrap()),
        Vec::new(),
    ))
    .await
    .unwrap();
    let harness_addr = harness.local_addr().unwrap();

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
        assert!(
            tokio::time::Instant::now() < deadline,
            "driver did not peer with the harness"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Generous propose timeout so the Byzantine proposal always arrives while
    // the honest node is still in (height 1, round 0, Propose).
    let timeouts = DriverTimeouts {
        propose: Duration::from_millis(700),
        prevote: Duration::from_millis(200),
        precommit: Duration::from_millis(200),
    };
    let node = Node::open(MemoryKvStore::new(), &genesis).unwrap();
    let (commit_tx, mut commit_rx) = mpsc::channel(16);
    let driver = ConsensusDriver::new(
        node,
        handle,
        Some(seeds[honest_index]),
        timeouts,
        MempoolConfig::default(),
    );
    let task = tokio::spawn(driver.run(inbound, Some(commit_tx)));

    // Deliver the Byzantine proposal plus supporting prevotes from the two
    // harness validators (with the honest prevote this would form a quorum,
    // pushing a vulnerable node all the way to lock + precommit).
    harness
        .broadcast(NetMessage::Proposal(Box::new(bad_proposal)))
        .unwrap();
    harness
        .broadcast(NetMessage::Vote(Box::new(sign_vote(
            leader_key,
            VoteType::Prevote,
        ))))
        .unwrap();
    harness
        .broadcast(NetMessage::Vote(Box::new(sign_vote(
            third_key,
            VoteType::Prevote,
        ))))
        .unwrap();

    // Observe the honest node's votes for a while.
    let mut honest_votes_for_bad: Vec<SignedVote> = Vec::new();
    let mut honest_nil_round0 = false;
    let collect_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < collect_deadline {
        while let Ok(InboundMessage { message, .. }) = harness_inbound.try_recv() {
            if let NetMessage::Vote(vote) = message {
                if vote.payload.validator == honest.address() && vote.payload.height == 1 {
                    if vote.payload.block_hash == bad_hash {
                        honest_votes_for_bad.push(*vote);
                    } else if vote.payload.round == 0
                        && vote.payload.vote_type == VoteType::Prevote
                        && vote.payload.block_hash == Hash256::ZERO
                    {
                        honest_nil_round0 = true;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    task.abort();
    let _ = task.await;

    // The honest node must never have finalized the unimportable block.
    assert!(
        commit_rx.try_recv().is_err(),
        "the honest node committed a height on an unimportable block"
    );

    // Severity proof for the pre-fix behavior: if the honest node precommitted
    // the bad block, the attacker holds a full, verifying finality certificate
    // for a block no node can import.
    if let Some(honest_precommit) = honest_votes_for_bad
        .iter()
        .find(|vote| vote.payload.vote_type == VoteType::Precommit)
    {
        let pool = vec![
            honest_precommit.clone(),
            sign_vote(leader_key, VoteType::Precommit),
            sign_vote(third_key, VoteType::Precommit),
        ];
        let certificate = FinalityCertificate::build(
            &snapshot,
            genesis.chain.protocol_version,
            chain.clone(),
            1,
            0,
            bad_hash,
            &pool,
        )
        .expect("2f+1 precommits assemble");
        assert!(
            certificate
                .verify(&snapshot, genesis.chain.protocol_version, &chain)
                .is_err(),
            "a verifying finality certificate exists for an unimportable block"
        );
    }
    assert!(
        honest_votes_for_bad.is_empty(),
        "the honest node signed votes for a block it cannot import: {:?}",
        honest_votes_for_bad
            .iter()
            .map(|vote| (vote.payload.round, vote.payload.vote_type))
            .collect::<Vec<_>>()
    );
    // Liveness sanity: the node did react to the round (nil prevote on the
    // propose timeout) rather than going silent.
    assert!(
        honest_nil_round0,
        "the honest node never prevoted nil at round 0 (propose timeout missing?)"
    );
}
