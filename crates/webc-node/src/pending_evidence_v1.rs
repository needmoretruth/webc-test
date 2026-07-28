//! Bounded protocol-2 slashing-evidence staging.
//!
//! Purpose: retain objective equivocation evidence between detection and block
//! inclusion without allowing Byzantine votes to grow node memory indefinitely.
//! Responsibilities: replay-hash de-duplication, deterministic admission and
//! eviction, bounded candidate selection, and cleanup after durable finalization.
//! Non-responsibilities: verify signatures, decide slashing policy, persist
//! evidence, or execute penalties.
//!
//! Data flow: the consensus machine emits already authenticated evidence; the
//! driver inserts it here, queries the actor for hashes already processed in
//! durable state, and offers a block-sized prefix to candidate construction.
//! Every local or synchronized finalization removes the hashes carried by that
//! block.
//!
//! Security boundary: a Byzantine validator can equivocate at every admitted
//! round. The fixed capacity is therefore mandatory. When full, the pool retains
//! the earliest `(height, round, stage, validator, hash)` evidence so admission
//! is deterministic and cannot be biased solely by grinding a small hash.

use std::collections::{BTreeMap, BTreeSet};

use webc_chain::{ChainError, SlashingEvidence, VoteType, MAX_BLOCK_SLASHING_EVIDENCE};
use webc_crypto::{Address, Hash256};

/// Maximum locally retained objective faults: sixteen full evidence blocks.
///
/// This is an operational memory bound, not a consensus validity rule. A full
/// node can still learn evicted evidence again, while an attacker cannot force
/// this non-durable staging area to grow forever.
pub(crate) const MAX_PENDING_SLASHING_EVIDENCE_V1: usize = MAX_BLOCK_SLASHING_EVIDENCE * 16;

type EvidencePriorityV1 = (u64, u32, VoteType, Address, Hash256);

/// Fixed-capacity, deterministically ordered protocol-2 evidence staging.
pub(crate) struct PendingEvidencePoolV1 {
    entries: BTreeMap<Hash256, SlashingEvidence>,
    capacity: usize,
}

impl Default for PendingEvidencePoolV1 {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity: MAX_PENDING_SLASHING_EVIDENCE_V1,
        }
    }
}

impl PendingEvidencePoolV1 {
    /// Inserts one objective artifact if it is new and wins bounded admission.
    ///
    /// Returns `true` only when the evidence is retained. At capacity the least
    /// urgent retained artifact is replaced only by an earlier deterministic
    /// priority, preventing arrival timing from changing the final pool contents.
    pub(crate) fn insert(&mut self, evidence: SlashingEvidence) -> Result<bool, ChainError> {
        let hash = evidence.hash()?;
        if self.entries.contains_key(&hash) {
            return Ok(false);
        }
        if self.entries.len() < self.capacity {
            self.entries.insert(hash, evidence);
            return Ok(true);
        }
        if self.capacity == 0 {
            return Ok(false);
        }

        let incoming_priority = evidence_priority(&evidence, hash);
        let Some(worst_hash) = self
            .entries
            .iter()
            .max_by_key(|(retained_hash, retained)| evidence_priority(retained, **retained_hash))
            .map(|(retained_hash, _)| *retained_hash)
        else {
            return Ok(false);
        };
        let Some(worst) = self.entries.get(&worst_hash) else {
            return Ok(false);
        };
        if incoming_priority >= evidence_priority(worst, worst_hash) {
            return Ok(false);
        }

        self.entries.remove(&worst_hash);
        self.entries.insert(hash, evidence);
        Ok(true)
    }

    /// Returns at most one block's evidence in stable replay-hash order.
    pub(crate) fn candidate_evidence(&self) -> Vec<SlashingEvidence> {
        self.entries
            .values()
            .take(MAX_BLOCK_SLASHING_EVIDENCE)
            .cloned()
            .collect()
    }

    /// Returns every retained replay hash for one bounded actor membership query.
    pub(crate) fn hashes(&self) -> Vec<Hash256> {
        self.entries.keys().copied().collect()
    }

    /// Computes all valid replay hashes carried by a finalized block.
    pub(crate) fn finalized_hashes(
        evidence: &[SlashingEvidence],
    ) -> Result<Vec<Hash256>, ChainError> {
        evidence.iter().map(SlashingEvidence::hash).collect()
    }

    /// Removes hashes known to be included or already durable in chain state.
    pub(crate) fn remove_hashes(&mut self, hashes: impl IntoIterator<Item = Hash256>) {
        for hash in hashes {
            self.entries.remove(&hash);
        }
    }

    /// Removes all hashes confirmed as processed by the single-owner runtime.
    pub(crate) fn prune_processed(&mut self, processed: &BTreeSet<Hash256>) {
        self.entries.retain(|hash, _| !processed.contains(hash));
    }

    #[cfg(test)]
    fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity,
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    fn contains(&self, hash: &Hash256) -> bool {
        self.entries.contains_key(hash)
    }
}

fn evidence_priority(evidence: &SlashingEvidence, hash: Hash256) -> EvidencePriorityV1 {
    match evidence {
        SlashingEvidence::DoubleVote(double_vote) => {
            let vote = &double_vote.first.payload;
            (
                vote.height,
                vote.round,
                vote.vote_type,
                vote.validator,
                hash,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webc_chain::{
        ChainId, DoubleVoteEvidence, SignedVote, Vote, TRANSACTION_V5_PROTOCOL_VERSION,
    };
    use webc_crypto::Keypair;

    fn double_vote_evidence(round: u32) -> SlashingEvidence {
        let key = Keypair::from_seed([0x51; 32]);
        let vote = |block_hash| Vote {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            height: 7,
            round,
            vote_type: VoteType::Precommit,
            block_hash,
            validator: key.address(),
        };
        SlashingEvidence::DoubleVote(DoubleVoteEvidence {
            first: SignedVote::sign(vote(Hash256::digest(b"first")), &key)
                .expect("first conflicting vote signs"),
            second: SignedVote::sign(vote(Hash256::digest(b"second")), &key)
                .expect("second conflicting vote signs"),
        })
    }

    #[test]
    fn hostile_equivocations_have_a_deterministic_fixed_bound() {
        let mut forward = PendingEvidencePoolV1::with_capacity(3);
        let mut reverse = PendingEvidencePoolV1::with_capacity(3);
        let evidence = (0..5).map(double_vote_evidence).collect::<Vec<_>>();

        for item in &evidence {
            forward.insert(item.clone()).expect("evidence hashes");
        }
        for item in evidence.iter().rev() {
            reverse.insert(item.clone()).expect("evidence hashes");
        }

        assert_eq!(forward.len(), 3);
        assert_eq!(forward.hashes(), reverse.hashes());
        for retained in &evidence[..3] {
            assert!(
                forward.contains(&retained.hash().expect("evidence hashes")),
                "earliest faults win bounded deterministic admission"
            );
        }
    }

    #[test]
    fn finalized_and_processed_evidence_are_pruned() {
        let first = double_vote_evidence(1);
        let second = double_vote_evidence(2);
        let mut pool = PendingEvidencePoolV1::with_capacity(4);
        pool.insert(first.clone()).expect("first evidence hashes");
        pool.insert(second.clone()).expect("second evidence hashes");

        let finalized = PendingEvidencePoolV1::finalized_hashes(std::slice::from_ref(&first))
            .expect("finalized evidence hashes");
        pool.remove_hashes(finalized);
        assert_eq!(pool.len(), 1);

        pool.prune_processed(&BTreeSet::from([second
            .hash()
            .expect("processed evidence hashes")]));
        assert_eq!(pool.len(), 0);
    }
}
