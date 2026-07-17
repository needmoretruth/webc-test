//! Deterministic binary Merkle tree, proofs, and verification.
//!
//! Purpose: commit an ordered list of pre-hashed leaves to a single root and
//! prove inclusion of one leaf. Consensus roots (state subtrees, transaction,
//! receipt, evidence) and browser light-client account proofs use it.
//!
//! Security boundary — hostile proofs. `verify_merkle_proof` runs on
//! attacker-supplied proofs (a light client verifies whatever a full node
//! sends), so it MUST bound work before looping: a proof longer than
//! [`MAX_MERKLE_PROOF_STEPS`] is rejected outright (finding E3) rather than
//! pinning client CPU on an inflated step list.
//!
//! Second-preimage separation. Internal nodes are hashed with the explicit
//! `WEBC_MERKLE_V1` domain (`hash_pair`), a domain no caller uses for a leaf:
//! every leaf handed to [`merkle_root`] is already a digest under its own
//! distinct domain (e.g. `WEBC_ACCOUNT_LEAF_V1`) or a plain payload digest.
//! Because an internal-node hash is computed over `WEBC_MERKLE_V1 || l || r`
//! and no leaf digest is, an internal node cannot be presented as a leaf
//! without a hash collision — the RFC-6962 leaf/internal confusion does not
//! apply here even though `merkle_root` takes leaves pre-hashed.
//!
//! Odd-layer handling. An odd layer duplicates its last node
//! (`right = left`). For WEBC's consensus roots the leaf multiset is fixed by
//! block content, so the classic duplicate-last malleability (two distinct
//! trees, one root) gives an attacker no forgery: they cannot choose the leaf
//! set. Removing the duplication would change every historical root and the
//! cross-language SDK root computation, so it is a deliberately deferred,
//! coordinated root-format change, not a silent one.

use crate::Hash256;
use serde::{Deserialize, Serialize};

/// Maximum inclusion-proof length accepted by [`verify_merkle_proof`].
///
/// A balanced tree of `n` leaves has `ceil(log2(n))` proof steps, so 64 steps
/// already covers `2^64` leaves — more than any real WEBC tree. Bounding the
/// step count before the verification loop stops a hostile full node from
/// handing a browser light client a giant proof to burn its CPU (finding E3).
pub const MAX_MERKLE_PROOF_STEPS: usize = 64;

/// Whether the sibling hash sits to the left or right of the current proof node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MerkleDirection {
    Left,
    Right,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProofStep {
    pub sibling: Hash256,
    pub direction: MerkleDirection,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf: Hash256,
    pub steps: Vec<MerkleProofStep>,
}

/// Computes a deterministic binary Merkle root.
///
/// Odd layers duplicate the final hash. Empty trees use `Hash256::ZERO`, which
/// makes empty state roots explicit and easy for light clients to handle.
pub fn merkle_root(leaves: &[Hash256]) -> Hash256 {
    if leaves.is_empty() {
        return Hash256::ZERO;
    }

    let mut layer = leaves.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            next.push(hash_pair(left, right));
        }
        layer = next;
    }
    layer[0]
}

pub fn merkle_proof(leaves: &[Hash256], index: usize) -> Option<MerkleProof> {
    if leaves.is_empty() || index >= leaves.len() {
        return None;
    }

    let leaf = leaves.get(index).copied()?;
    let mut current_index = index;
    let mut layer = leaves.to_vec();
    let mut steps = Vec::new();

    while layer.len() > 1 {
        let is_right = current_index % 2 == 1;
        let sibling_index = if is_right {
            current_index - 1
        } else {
            current_index + 1
        };
        let sibling = layer
            .get(sibling_index)
            .copied()
            .unwrap_or(layer[current_index]);
        steps.push(MerkleProofStep {
            sibling,
            direction: if is_right {
                MerkleDirection::Left
            } else {
                MerkleDirection::Right
            },
        });

        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            next.push(hash_pair(left, right));
        }
        layer = next;
        current_index /= 2;
    }

    Some(MerkleProof { leaf, steps })
}

pub fn verify_merkle_proof(root: Hash256, proof: &MerkleProof) -> bool {
    // E3: bound work on a hostile proof before looping. A real inclusion proof
    // never exceeds MAX_MERKLE_PROOF_STEPS, so a longer one is malformed and is
    // rejected without hashing its steps.
    if proof.steps.len() > MAX_MERKLE_PROOF_STEPS {
        return false;
    }
    let mut current = proof.leaf;
    for step in &proof.steps {
        current = match step.direction {
            MerkleDirection::Left => hash_pair(step.sibling, current),
            MerkleDirection::Right => hash_pair(current, step.sibling),
        };
    }
    current == root
}

fn hash_pair(left: Hash256, right: Hash256) -> Hash256 {
    let parts: [&[u8]; 3] = [
        b"WEBC_MERKLE_V1".as_slice(),
        left.as_bytes().as_slice(),
        right.as_bytes().as_slice(),
    ];
    Hash256::digest_many(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_proof_verifies() {
        let leaves = [
            Hash256::digest(b"a"),
            Hash256::digest(b"b"),
            Hash256::digest(b"c"),
            Hash256::digest(b"d"),
            Hash256::digest(b"e"),
        ];
        let root = merkle_root(leaves.as_slice());
        let proof = merkle_proof(leaves.as_slice(), 2).unwrap();
        assert!(verify_merkle_proof(root, &proof));
    }

    #[test]
    fn merkle_proof_rejects_wrong_root() {
        let leaves = [Hash256::digest(b"a"), Hash256::digest(b"b")];
        let proof = merkle_proof(leaves.as_slice(), 0).unwrap();
        assert!(!verify_merkle_proof(Hash256::digest(b"wrong"), &proof));
    }

    #[test]
    fn verify_rejects_an_over_length_proof_without_hashing_it() {
        // E3: a hostile proof longer than the bound is rejected outright.
        let leaves = [Hash256::digest(b"a"), Hash256::digest(b"b")];
        let root = merkle_root(leaves.as_slice());
        let mut proof = merkle_proof(leaves.as_slice(), 0).unwrap();
        // Pad far beyond any real tree depth.
        while proof.steps.len() <= MAX_MERKLE_PROOF_STEPS {
            proof.steps.push(MerkleProofStep {
                sibling: Hash256::ZERO,
                direction: MerkleDirection::Right,
            });
        }
        assert!(!verify_merkle_proof(root, &proof));
    }
}
