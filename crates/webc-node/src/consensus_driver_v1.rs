//! Protocol-2 async driver for the shared BFT safety machine.
//!
//! Purpose: connect [`webc_chain::ConsensusMachineV1`] to authenticated network
//! frames and the single-owner [`crate::NodeHandle`]. Responsibilities: load and
//! persist the V4 crash WAL, authenticate and replay proposals, build candidates,
//! schedule timeouts, finalize certificates, serve directed state sync, and
//! admit V5 gossip. Non-responsibilities: implement lock/quorum rules, mutate
//! chain state directly, own a second mempool, encode HTTP, or choose validator
//! sets.
//!
//! Data flow: the actor supplies the next height and outgoing authority set. The
//! shared pure machine emits actions; this driver persists every own signed
//! action before gossip, asks the actor for candidate/replay/finality operations,
//! and advances only after the actor's atomic durable commit succeeds. Certified
//! sync replies use the identical finalization path.
//!
//! Security boundary: peer messages, local WAL bytes, timers, and stored sync
//! records are hostile. Cheap height/round/authority/signature checks precede
//! block replay, one authentic proposal per round can consume replay work,
//! higher-height sync requires a verified certificate, replies are directed,
//! and a certified block rejected by deterministic replay stops as an explicit
//! consensus emergency.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

use tokio::sync::mpsc;
use webc_chain::{
    BlockHeight, BuiltBlockV4, ChainError, ConsensusActionV1, ConsensusEventV1, ConsensusMachineV1,
    ConsensusMessageV1, FinalityAuthoritySetV1, FinalityCertificate, SlashingEvidence, TimeoutKind,
    ValidatorIdentity, MAX_BLOCK_SLASHING_EVIDENCE, MAX_FUTURE_ROUNDS,
    TRANSACTION_V5_PROTOCOL_VERSION,
};
use webc_crypto::{Address, Hash256, Keypair};
use webc_net::{CertifiedBlockV4, InboundMessage, NetError, NetMessage, NetworkHandle};
use webc_storage::{LocalTimestampMs, StorageError};
use zeroize::Zeroizing;

use crate::consensus_driver::{
    timestamp_within_future_drift, CommitInfo, DriverTimeouts, SYNC_BATCH,
};
use crate::http::now_ms;
use crate::{NodeError, NodeHandle, NodeRuntimeError};

/// Why the protocol-2 consensus driver stopped.
#[derive(Debug, thiserror::Error)]
pub enum DriverExitV1 {
    /// The authenticated inbound channel closed during normal shutdown.
    #[error("inbound network channel closed; protocol-2 consensus stopped")]
    NetworkClosed,
    /// The network worker stopped while broadcasting a required message.
    #[error("protocol-2 network operation failed: {0}")]
    Network(#[from] NetError),
    /// The single-owner runtime stopped or rejected a local consensus operation.
    #[error("protocol-2 runtime failed at height {height}: {error}")]
    Runtime {
        /// Height being processed when the runtime failed.
        height: u64,
        /// Typed actor/storage/node failure.
        error: NodeRuntimeError,
    },
    /// The pure safety machine failed on locally constructed state.
    #[error("protocol-2 consensus machine failed at height {height}: {error}")]
    Machine {
        /// Height being processed when the machine failed.
        height: u64,
        /// Deterministic consensus failure.
        error: ChainError,
    },
    /// A quorum-certified V4 block failed deterministic local validation.
    #[error("protocol-2 consensus emergency at height {height}: {error}")]
    CertifiedBlockInvalid {
        /// Certified height rejected locally.
        height: u64,
        /// Typed actor/node rejection.
        error: NodeRuntimeError,
    },
    /// Durable storage remained unavailable after bounded retries.
    #[error("protocol-2 storage failed at finalized height {height}: {error}")]
    StorageFailed {
        /// Height whose atomic finalization could not commit.
        height: u64,
        /// Final storage-class error.
        error: NodeRuntimeError,
    },
}

/// In-process protocol-2 validator credentials loaded from a protected file.
///
/// The operator identity and consensus key are deliberately separate: genesis
/// may register a dedicated consensus public key that is not the operator's
/// account key. The seed is never exposed, logged, serialized, cloned, or
/// debug-formatted and is erased when these credentials are dropped.
pub struct ConsensusCredentialsV1 {
    operator: Address,
    consensus_seed: Zeroizing<[u8; 32]>,
}

impl ConsensusCredentialsV1 {
    /// Takes ownership of one validated operator/consensus seed pair.
    pub fn new(operator: Address, consensus_seed: [u8; 32]) -> Self {
        Self {
            operator,
            consensus_seed: Zeroizing::new(consensus_seed),
        }
    }

    /// Public operator address represented by these credentials.
    pub fn operator(&self) -> Address {
        self.operator
    }

    fn identity_for(&self, set: &webc_chain::ValidatorSet) -> Option<ValidatorIdentity> {
        let consensus_key = Keypair::from_seed(*self.consensus_seed);
        if set.consensus_key_of(self.operator)? != consensus_key.public_key() {
            return None;
        }
        Some(ValidatorIdentity {
            address: self.operator,
            consensus_key,
        })
    }
}

/// Protocol-2 consensus/network adapter over the single node actor.
pub struct ConsensusDriverV1 {
    runtime: NodeHandle,
    network: NetworkHandle,
    credentials: Option<ConsensusCredentialsV1>,
    timeouts: DriverTimeouts,
    pending_evidence: BTreeMap<Hash256, SlashingEvidence>,
    checked_proposal_rounds: BTreeSet<u32>,
}

type DecidedV1 = (BuiltBlockV4, FinalityCertificate);

impl ConsensusDriverV1 {
    /// Creates a V4 driver. `None` runs a non-voting observer that still syncs.
    pub fn new(
        runtime: NodeHandle,
        network: NetworkHandle,
        consensus_seed: Option<[u8; 32]>,
        timeouts: DriverTimeouts,
    ) -> Self {
        let credentials = consensus_seed.map(|seed| {
            let operator = Keypair::from_seed(seed).address();
            ConsensusCredentialsV1::new(operator, seed)
        });
        Self::new_with_credentials(runtime, network, credentials, timeouts)
    }

    /// Creates a V4 driver with an explicit operator and dedicated consensus key.
    ///
    /// Use this constructor for operator-loaded credentials. `None` runs a
    /// non-voting observer. At every height the driver confirms that the current
    /// authority set maps `operator` to the seed's public key before it signs.
    pub fn new_with_credentials(
        runtime: NodeHandle,
        network: NetworkHandle,
        credentials: Option<ConsensusCredentialsV1>,
        timeouts: DriverTimeouts,
    ) -> Self {
        Self {
            runtime,
            network,
            credentials,
            timeouts,
            pending_evidence: BTreeMap::new(),
            checked_proposal_rounds: BTreeSet::new(),
        }
    }

    /// Runs height after height until shutdown or a surfaced safety/operational fault.
    pub async fn run(
        mut self,
        mut inbound: mpsc::Receiver<InboundMessage>,
        commit_tx: Option<mpsc::Sender<CommitInfo>>,
    ) -> DriverExitV1 {
        let (timeout_tx, mut timeout_rx) = mpsc::channel::<(TimeoutKind, u32, u64)>(256);

        loop {
            let context = match self.runtime.consensus_context_v1().await {
                Ok(context) => context,
                Err(error) => {
                    return DriverExitV1::Runtime { height: 0, error };
                }
            };
            let height = context.height.get();
            let authority_set = context.current_authority_set;
            let validator_set = match authority_set.to_validator_set() {
                Ok(set) => set,
                Err(_) => {
                    return DriverExitV1::Machine {
                        height,
                        error: ChainError::ConsensusProtocol2ProposalInvalid,
                    };
                }
            };
            self.checked_proposal_rounds.clear();
            let identity = self.identity_for(&validator_set);
            let is_validator = identity.is_some();
            let mut machine = match ConsensusMachineV1::new(authority_set.clone(), height, identity)
            {
                Ok(machine) => machine,
                Err(error) => return DriverExitV1::Machine { height, error },
            };

            if is_validator {
                let journal_safe = match self.runtime.consensus_wal_v1(context.height).await {
                    Ok(None) => true,
                    Ok(Some(record)) => machine.restore(record).is_ok(),
                    Err(_) => false,
                };
                if !journal_safe {
                    machine = match ConsensusMachineV1::new(authority_set.clone(), height, None) {
                        Ok(machine) => machine,
                        Err(error) => return DriverExitV1::Machine { height, error },
                    };
                }
            }

            let mut decided = None;
            let mut sync_requested = false;
            let initial = match machine.start() {
                Ok(actions) => actions,
                Err(error) => return DriverExitV1::Machine { height, error },
            };
            let mut work: VecDeque<ConsensusActionV1> = initial.into();
            if let Err(exit) = self
                .pump(
                    &mut machine,
                    &mut work,
                    context.height,
                    &timeout_tx,
                    &mut decided,
                    is_validator,
                )
                .await
            {
                return exit;
            }
            let mut height_done = match self
                .commit_if_decided(context.height, &mut decided, &commit_tx)
                .await
            {
                Ok(done) => done,
                Err(exit) => return exit,
            };

            while !height_done {
                tokio::select! {
                    inbound_message = inbound.recv() => {
                        let Some(message) = inbound_message else {
                            return DriverExitV1::NetworkClosed;
                        };
                        match self.on_inbound(
                            message,
                            &authority_set,
                            &mut machine,
                            context.height,
                            &timeout_tx,
                            &mut decided,
                            &mut sync_requested,
                            &commit_tx,
                            is_validator,
                        ).await {
                            Ok(done) => height_done |= done,
                            Err(exit) => return exit,
                        }
                    }
                    fired = timeout_rx.recv() => {
                        if let Some((kind, round, event_height)) = fired {
                            if event_height == height {
                                let actions = machine
                                    .on_event(ConsensusEventV1::Timeout { kind, round })
                                    .unwrap_or_default();
                                let mut work: VecDeque<ConsensusActionV1> = actions.into();
                                if let Err(exit) = self.pump(
                                    &mut machine,
                                    &mut work,
                                    context.height,
                                    &timeout_tx,
                                    &mut decided,
                                    is_validator,
                                ).await {
                                    return exit;
                                }
                            }
                        }
                    }
                }
                if !height_done {
                    height_done = match self
                        .commit_if_decided(context.height, &mut decided, &commit_tx)
                        .await
                    {
                        Ok(done) => done,
                        Err(exit) => return exit,
                    };
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn on_inbound(
        &mut self,
        message: InboundMessage,
        authority_set: &FinalityAuthoritySetV1,
        machine: &mut ConsensusMachineV1,
        height: BlockHeight,
        timeout_tx: &mpsc::Sender<(TimeoutKind, u32, u64)>,
        decided: &mut Option<DecidedV1>,
        sync_requested: &mut bool,
        commit_tx: &Option<mpsc::Sender<CommitInfo>>,
        is_validator: bool,
    ) -> Result<bool, DriverExitV1> {
        let from = message.from;
        let event = match message.message {
            NetMessage::TransactionV5(transaction) => {
                let _ = self
                    .runtime
                    .submit(*transaction, LocalTimestampMs::new(now_ms()))
                    .await;
                return Ok(false);
            }
            NetMessage::ProposalV4(proposal) => {
                if !self
                    .validate_proposal(&proposal, authority_set, height, machine.round())
                    .await
                {
                    return Ok(false);
                }
                ConsensusEventV1::Message(ConsensusMessageV1::Proposal(proposal))
            }
            NetMessage::Vote(vote) => ConsensusEventV1::Message(ConsensusMessageV1::Vote(*vote)),
            NetMessage::Certificate(certificate) => {
                self.request_if_certified(
                    from,
                    &certificate,
                    authority_set,
                    height,
                    sync_requested,
                )?;
                return Ok(false);
            }
            NetMessage::BlockRequestV4 { from_height, max } => {
                self.serve_block_request(from, from_height, max).await?;
                return Ok(false);
            }
            NetMessage::BlockResponseV4(response) => {
                return self
                    .apply_synced_block(*response, authority_set, height, commit_tx)
                    .await;
            }
            NetMessage::Transaction(_)
            | NetMessage::Proposal(_)
            | NetMessage::BlockRequest { .. }
            | NetMessage::BlockResponse(_) => return Ok(false),
        };

        let actions = machine.on_event(event).unwrap_or_default();
        let mut work: VecDeque<ConsensusActionV1> = actions.into();
        self.pump(
            machine,
            &mut work,
            height,
            timeout_tx,
            decided,
            is_validator,
        )
        .await?;
        Ok(false)
    }

    async fn validate_proposal(
        &mut self,
        proposal: &webc_chain::SignedProposalV1,
        authority_set: &FinalityAuthoritySetV1,
        height: BlockHeight,
        current_round: u32,
    ) -> bool {
        if proposal.payload.height != height.get()
            || proposal.payload.round > current_round.saturating_add(MAX_FUTURE_ROUNDS)
            || self
                .checked_proposal_rounds
                .contains(&proposal.payload.round)
        {
            return false;
        }
        if proposal.verify_in_authority_set(authority_set).is_err() {
            return false;
        }
        self.checked_proposal_rounds.insert(proposal.payload.round);
        if !timestamp_within_future_drift(proposal.block.header.timestamp_ms, now_ms()) {
            return false;
        }
        self.runtime
            .validate_candidate_v4(proposal.block.clone(), proposal.next_authority_set.clone())
            .await
            .is_ok()
    }

    fn request_if_certified(
        &self,
        _from: webc_net::PeerId,
        certificate: &FinalityCertificate,
        authority_set: &FinalityAuthoritySetV1,
        working_height: BlockHeight,
        requested: &mut bool,
    ) -> Result<(), DriverExitV1> {
        if certificate.height < working_height.get() || *requested {
            return Ok(());
        }
        let Ok(set) = authority_set.to_validator_set() else {
            return Ok(());
        };
        if certificate
            .verify(
                &set,
                TRANSACTION_V5_PROTOCOL_VERSION,
                &authority_set.chain_id,
            )
            .is_err()
        {
            return Ok(());
        }
        *requested = true;
        self.network.broadcast(NetMessage::BlockRequestV4 {
            from_height: working_height,
            max: SYNC_BATCH,
        })?;
        Ok(())
    }

    async fn serve_block_request(
        &self,
        requester: webc_net::PeerId,
        from_height: BlockHeight,
        max: u32,
    ) -> Result<(), DriverExitV1> {
        let count = u64::from(max.min(SYNC_BATCH));
        for offset in 0..count {
            let Some(raw_height) = from_height.get().checked_add(offset) else {
                break;
            };
            let height = BlockHeight::new(raw_height);
            let snapshot = self
                .runtime
                .certified_block_v4(height)
                .await
                .map_err(|error| DriverExitV1::Runtime {
                    height: raw_height,
                    error,
                })?;
            let Some(snapshot) = snapshot else {
                break;
            };
            self.network.send_to(
                requester,
                NetMessage::BlockResponseV4(Box::new(CertifiedBlockV4 {
                    block: snapshot.block,
                    next_authority_set: snapshot.next_authority_set,
                    certificate: snapshot.certificate,
                })),
            )?;
        }
        Ok(())
    }

    async fn apply_synced_block(
        &mut self,
        response: CertifiedBlockV4,
        authority_set: &FinalityAuthoritySetV1,
        working_height: BlockHeight,
        commit_tx: &Option<mpsc::Sender<CommitInfo>>,
    ) -> Result<bool, DriverExitV1> {
        if response.block.header.height != working_height {
            return Ok(false);
        }
        let Ok(block_hash) = response.block.header.hash() else {
            return Ok(false);
        };
        if response.certificate.height != working_height.get()
            || response.certificate.block_hash != block_hash
        {
            return Ok(false);
        }
        let Ok(set) = authority_set.to_validator_set() else {
            return Ok(false);
        };
        if response
            .certificate
            .verify(
                &set,
                TRANSACTION_V5_PROTOCOL_VERSION,
                &authority_set.chain_id,
            )
            .is_err()
        {
            return Ok(false);
        }
        let tx_count = response.block.transactions.len();
        self.finalize_with_retry(
            response.block,
            response.next_authority_set,
            response.certificate,
        )
        .await?;
        self.report_commit(working_height, block_hash, tx_count, commit_tx)
            .await;
        Ok(true)
    }

    async fn commit_if_decided(
        &mut self,
        height: BlockHeight,
        decided: &mut Option<DecidedV1>,
        commit_tx: &Option<mpsc::Sender<CommitInfo>>,
    ) -> Result<bool, DriverExitV1> {
        let Some((built, certificate)) = decided.take() else {
            return Ok(false);
        };
        if built.block.header.height != height {
            return Ok(false);
        }
        let block_hash = built
            .block
            .header
            .hash()
            .map_err(|_| DriverExitV1::Machine {
                height: height.get(),
                error: ChainError::ConsensusProtocol2ProposalInvalid,
            })?;
        let tx_count = built.block.transactions.len();
        let included_evidence = built.block.evidence.clone();
        self.finalize_with_retry(built.block, built.next_authority_set, certificate.clone())
            .await?;
        for evidence in included_evidence {
            if let Ok(hash) = evidence.hash() {
                self.pending_evidence.remove(&hash);
            }
        }
        self.network
            .broadcast(NetMessage::Certificate(Box::new(certificate)))?;
        self.report_commit(height, block_hash, tx_count, commit_tx)
            .await;
        Ok(true)
    }

    async fn finalize_with_retry(
        &self,
        block: webc_chain::BlockV4,
        next_authority_set: FinalityAuthoritySetV1,
        certificate: FinalityCertificate,
    ) -> Result<(), DriverExitV1> {
        const RETRIES: u32 = 3;
        let height = block.header.height.get();
        let mut attempt = 0u32;
        let mut backoff = Duration::from_millis(50);
        loop {
            match self
                .runtime
                .finalize_v4(
                    block.clone(),
                    next_authority_set.clone(),
                    certificate.clone(),
                )
                .await
            {
                Ok(_) => return Ok(()),
                Err(NodeRuntimeError::Node(NodeError::Storage(StorageError::Io(_))))
                    if attempt < RETRIES =>
                {
                    attempt += 1;
                    tokio::time::sleep(backoff).await;
                    backoff = backoff.saturating_mul(2);
                }
                Err(error @ NodeRuntimeError::Node(NodeError::Storage(_))) => {
                    return Err(DriverExitV1::StorageFailed { height, error });
                }
                Err(error @ NodeRuntimeError::Node(_)) => {
                    return Err(DriverExitV1::CertifiedBlockInvalid { height, error });
                }
                Err(error) => return Err(DriverExitV1::Runtime { height, error }),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn pump(
        &mut self,
        machine: &mut ConsensusMachineV1,
        work: &mut VecDeque<ConsensusActionV1>,
        height: BlockHeight,
        timeout_tx: &mpsc::Sender<(TimeoutKind, u32, u64)>,
        decided: &mut Option<DecidedV1>,
        is_validator: bool,
    ) -> Result<(), DriverExitV1> {
        while let Some(action) = work.pop_front() {
            match action {
                ConsensusActionV1::Broadcast(message) => {
                    if is_validator {
                        self.runtime
                            .persist_consensus_wal_v1(machine.wal_record())
                            .await
                            .map_err(|error| DriverExitV1::Runtime {
                                height: height.get(),
                                error,
                            })?;
                    }
                    self.network.broadcast(to_net_message_v1(message))?;
                }
                ConsensusActionV1::ScheduleTimeout { kind, round } => {
                    let sender = timeout_tx.clone();
                    let delay = self.timeouts.for_kind(kind, round);
                    let event_height = height.get();
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        let _ = sender.send((kind, round, event_height)).await;
                    });
                }
                ConsensusActionV1::NeedProposalBlock { round } => {
                    let Some(proposer) = self.credentials.as_ref().map(|value| value.operator)
                    else {
                        continue;
                    };
                    let evidence = self
                        .pending_evidence
                        .values()
                        .take(MAX_BLOCK_SLASHING_EVIDENCE)
                        .cloned()
                        .collect();
                    let built = self
                        .runtime
                        .build_candidate_v4(
                            proposer,
                            now_ms(),
                            LocalTimestampMs::new(now_ms()),
                            evidence,
                        )
                        .await
                        .map_err(|error| DriverExitV1::Runtime {
                            height: height.get(),
                            error,
                        })?;
                    let more = machine.provide_block(round, built).map_err(|error| {
                        DriverExitV1::Machine {
                            height: height.get(),
                            error,
                        }
                    })?;
                    work.extend(more);
                }
                ConsensusActionV1::Commit { block, certificate } => {
                    *decided = Some((*block, *certificate));
                }
                ConsensusActionV1::Equivocation(evidence) => {
                    let evidence = SlashingEvidence::DoubleVote(*evidence);
                    if let Ok(hash) = evidence.hash() {
                        self.pending_evidence.entry(hash).or_insert(evidence);
                    }
                }
            }
        }
        Ok(())
    }

    fn identity_for(&self, set: &webc_chain::ValidatorSet) -> Option<ValidatorIdentity> {
        self.credentials.as_ref()?.identity_for(set)
    }

    async fn report_commit(
        &self,
        height: BlockHeight,
        tip: Hash256,
        tx_count: usize,
        commit_tx: &Option<mpsc::Sender<CommitInfo>>,
    ) {
        if let Some(sender) = commit_tx {
            let _ = sender
                .send(CommitInfo {
                    height: height.get(),
                    tip: Some(tip),
                    tx_count,
                })
                .await;
        }
    }
}

fn to_net_message_v1(message: ConsensusMessageV1) -> NetMessage {
    match message {
        ConsensusMessageV1::Proposal(proposal) => NetMessage::ProposalV4(proposal),
        ConsensusMessageV1::Vote(vote) => NetMessage::Vote(Box::new(vote)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use webc_chain::{Amount, ValidatorPower, ValidatorSet};

    #[test]
    fn dedicated_consensus_key_is_bound_to_the_operator_snapshot() {
        let operator_key = Keypair::from_seed([0x41; 32]);
        let consensus_key = Keypair::from_seed([0x42; 32]);
        let operator = operator_key.address();
        let power = Amount::from_webc(100);
        let set = ValidatorSet {
            validators: BTreeMap::from([(
                operator,
                ValidatorPower {
                    validator: operator,
                    power,
                    consensus_key: consensus_key.public_key(),
                },
            )]),
            total_power: power,
        };

        let credentials = ConsensusCredentialsV1::new(operator, [0x42; 32]);
        let identity = credentials
            .identity_for(&set)
            .expect("registered dedicated key authorizes the operator");
        assert_eq!(identity.address, operator);
        assert_eq!(
            identity.consensus_key.public_key(),
            consensus_key.public_key()
        );

        let wrong = ConsensusCredentialsV1::new(operator, [0x43; 32]);
        assert!(
            wrong.identity_for(&set).is_none(),
            "an unregistered secret must never produce a voting identity"
        );
    }
}
