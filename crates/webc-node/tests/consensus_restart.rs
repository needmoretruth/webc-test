//! C4 regression: a validator that crashes and restarts mid-height must never
//! sign a conflicting consensus message for a (height, round, step) it already
//! signed. Two conflicting signed votes are objective `DoubleVoteEvidence`, and
//! since commit `a6197ac` peers turn that evidence into an applied 80% slash
//! plus tombstone — so without a durable vote journal, an ordinary operator
//! restart destroys the validator's stake.
//!
//! The scenario: validator A (the height-1 round-0 proposer) runs alone against
//! two harness-held validators that never vote, so height 1 can never finalize
//! (strict >2/3 of equal-stake 3 needs all three). A proposes and prevotes,
//! then "crashes" (its task is aborted) and restarts over the same durable
//! store. The harness collects every consensus message A signs across both
//! lives and asserts that no two proposals share a round with different block
//! hashes and no two votes share a (round, vote type) with different block
//! hashes. Without the write-ahead journal the restarted node rebuilds a fresh
//! machine, re-proposes with a new timestamp, and re-prevotes the new hash —
//! exactly the self-equivocation this test rejects.

use std::collections::BTreeMap;
use std::time::Duration;

use tokio::sync::mpsc;
use webc_chain::{
    Amount, ChainConfig, DoubleVoteEvidence, GenesisAccount, GenesisConfig, GenesisValidator,
    SlashingEvidence, ValidatorSet, VoteType,
};
use webc_crypto::{Hash256, Keypair};
use webc_net::{spawn_network, InboundMessage, NetMessage, NetworkConfig};
use webc_node::{ConsensusDriver, DriverTimeouts, MempoolConfig, Node};
use webc_storage::RedbKvStore;

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

/// Collected signed consensus messages, grouped for the equivocation check.
#[derive(Default)]
struct SignedLog {
    /// First observed proposal block hash per round at height 1.
    proposals: BTreeMap<u32, Hash256>,
    /// First observed vote block hash per (round, vote type) at height 1.
    votes: BTreeMap<(u32, VoteType), Hash256>,
    /// Conflicting (first, second) pairs observed — must stay empty.
    conflicts: Vec<String>,
    /// Raw signed votes kept so a conflict can be proven as objective evidence.
    raw_votes: Vec<webc_chain::SignedVote>,
}

impl SignedLog {
    fn absorb(&mut self, message: &NetMessage) {
        match message {
            NetMessage::Proposal(proposal) if proposal.payload.height == 1 => {
                let round = proposal.payload.round;
                let hash = proposal.payload.block_hash;
                match self.proposals.get(&round) {
                    Some(first) if *first != hash => self.conflicts.push(format!(
                        "conflicting proposals at round {round}: {first:?} vs {hash:?}"
                    )),
                    Some(_) => {}
                    None => {
                        self.proposals.insert(round, hash);
                    }
                }
            }
            NetMessage::Vote(vote) if vote.payload.height == 1 => {
                let key = (vote.payload.round, vote.payload.vote_type);
                let hash = vote.payload.block_hash;
                self.raw_votes.push((**vote).clone());
                match self.votes.get(&key) {
                    Some(first) if *first != hash => self.conflicts.push(format!(
                        "conflicting votes at {key:?}: {first:?} vs {hash:?}"
                    )),
                    Some(_) => {}
                    None => {
                        self.votes.insert(key, hash);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Drains every currently queued inbound message into the log.
fn drain(inbound: &mut mpsc::Receiver<InboundMessage>, log: &mut SignedLog) {
    while let Ok(message) = inbound.try_recv() {
        log.absorb(&message.message);
    }
}

#[tokio::test]
async fn a_restarted_validator_never_signs_a_conflicting_vote() {
    let chain = ChainConfig::default().chain_id;
    let seeds: [[u8; 32]; 3] = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let validators: Vec<Keypair> = seeds.iter().map(|s| Keypair::from_seed(*s)).collect();
    let genesis = validator_genesis(&validators);

    // Pick the validator scheduled to propose (height 1, round 0) as the node
    // under test, so its first life deterministically signs a proposal and a
    // prevote without needing any peer traffic.
    let probe = Node::open(webc_storage::MemoryKvStore::new(), &genesis).unwrap();
    let snapshot = ValidatorSet::from_state(probe.state()).unwrap();
    let leader = snapshot.proposer_for(1, 0).expect("leader scheduled");
    let leader_index = validators
        .iter()
        .position(|keypair| keypair.address() == leader)
        .expect("leader is a test validator");
    let leader_seed = seeds[leader_index];

    // The harness is a network peer only: it holds the other validator keys but
    // never votes, so height 1 can never finalize and the node under test stays
    // mid-height for the whole test.
    let (harness, mut harness_inbound) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([90u8; 32]),
        chain.clone(),
        Some("127.0.0.1:0".parse().unwrap()),
        Vec::new(),
    ))
    .await
    .unwrap();
    let harness_addr = harness.local_addr().unwrap();

    let temp = tempfile::tempdir().unwrap();
    let store_path = temp.path().join("validator.redb");
    let timeouts = DriverTimeouts {
        propose: Duration::from_millis(200),
        prevote: Duration::from_millis(200),
        precommit: Duration::from_millis(200),
    };

    // First life: run the validator until the harness has observed its round-0
    // proposal and prevote, then abort the task mid-height ("crash").
    let mut log = SignedLog::default();
    {
        let (handle, inbound) = spawn_network(NetworkConfig::new(
            Keypair::from_seed([91u8; 32]),
            chain.clone(),
            Some("127.0.0.1:0".parse().unwrap()),
            vec![harness_addr],
        ))
        .await
        .unwrap();
        // The driver proposes immediately on start, so peer first: a broadcast
        // before the handshake completes reaches nobody.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while handle.connected_peers() == 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "first life did not peer with the harness"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let node = Node::open(RedbKvStore::open(&store_path).unwrap(), &genesis).unwrap();
        let driver = ConsensusDriver::new(
            node,
            handle,
            Some(leader_seed),
            timeouts,
            MempoolConfig::default(),
        );
        let task = tokio::spawn(driver.run(inbound, None));

        let observed = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                drain(&mut harness_inbound, &mut log);
                if log.proposals.contains_key(&0) && log.votes.contains_key(&(0, VoteType::Prevote))
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            observed.is_ok(),
            "the validator's first life never proposed and prevoted round 0"
        );
        task.abort();
        let _ = task.await;
    }

    // A restart is never instantaneous; the gap guarantees a different
    // wall-clock candidate timestamp, so an unjournaled restart would rebuild a
    // *different* block for the same round and re-sign it.
    tokio::time::sleep(Duration::from_millis(25)).await;

    // Second life: same durable store, fresh network identity and driver.
    let (handle, inbound) = spawn_network(NetworkConfig::new(
        Keypair::from_seed([92u8; 32]),
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
            "second life did not peer with the harness"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let node = Node::open(RedbKvStore::open(&store_path).unwrap(), &genesis).unwrap();
    let driver = ConsensusDriver::new(
        node,
        handle,
        Some(leader_seed),
        timeouts,
        MempoolConfig::default(),
    );
    let task = tokio::spawn(driver.run(inbound, None));

    // Collect the restarted life's messages. The restarted node must still
    // participate (it advances to a later round and votes there); silence would
    // hide the bug rather than fix it.
    let mut post_restart_activity = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        while let Ok(message) = harness_inbound.try_recv() {
            match &message.message {
                NetMessage::Proposal(p) if p.payload.height == 1 && p.payload.round > 0 => {
                    post_restart_activity = true;
                }
                NetMessage::Vote(v) if v.payload.height == 1 && v.payload.round > 0 => {
                    post_restart_activity = true;
                }
                _ => {}
            }
            log.absorb(&message.message);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    task.abort();
    let _ = task.await;

    // If a conflicting vote pair exists, prove it is objective slashable
    // evidence — the exact artifact peers would use to destroy this honest
    // validator's stake.
    if !log.conflicts.is_empty() {
        let mut by_key: BTreeMap<(u32, VoteType), webc_chain::SignedVote> = BTreeMap::new();
        for vote in &log.raw_votes {
            let key = (vote.payload.round, vote.payload.vote_type);
            if let Some(first) = by_key.get(&key) {
                if first.payload.block_hash != vote.payload.block_hash {
                    let evidence = SlashingEvidence::DoubleVote(DoubleVoteEvidence {
                        first: first.clone(),
                        second: vote.clone(),
                    });
                    let key_of_leader = validators[leader_index].public_key();
                    assert!(
                        evidence
                            .verify(genesis.chain.protocol_version, &chain, &key_of_leader)
                            .is_ok(),
                        "the conflict is not even verifiable evidence: {:?}",
                        log.conflicts
                    );
                }
            } else {
                by_key.insert(key, vote.clone());
            }
        }
    }
    assert!(
        log.conflicts.is_empty(),
        "restarted validator self-equivocated: {:?}",
        log.conflicts
    );
    assert!(
        post_restart_activity,
        "the restarted validator never participated again (it must keep voting \
         in later rounds without re-signing recorded steps)"
    );
}
