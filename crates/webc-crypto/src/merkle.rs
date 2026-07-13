use crate::Hash256;
use serde::{Deserialize, Serialize};

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
}
