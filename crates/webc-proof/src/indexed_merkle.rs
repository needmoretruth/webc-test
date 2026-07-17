//! Version-1 indexed inclusion proofs for WEBC's binary Merkle tree.
//!
//! Purpose: prove membership in an ordered, non-empty leaf list without trusting
//! caller-supplied left/right flags. Responsibilities: construct proofs using
//! the legacy root's duplicate-last rule, validate `(leaf_index, leaf_count)`
//! and depth, enforce the 64-sibling resource limit, and verify the expected
//! root. Non-responsibilities: defining transaction/receipt leaf bytes, storing
//! paths, finality certificates, or succinct proofs. Data flow: a builder takes
//! pre-hashed leaves; a verifier takes an expected root and an untrusted proof,
//! validates all structural fields first, then hashes at most 64 parents.
//! Security boundary: malformed counts, impossible depths, non-canonical odd
//! siblings, and oversized paths fail closed with typed errors before expensive
//! or ambiguous verification.

use serde::{Deserialize, Serialize};
use webc_crypto::{merkle_parent, merkle_proof, Hash256};

/// Maximum sibling hashes accepted by an indexed proof.
///
/// A 64-level path covers every non-empty tree whose leaf count fits in a
/// `u64`. The verifier checks this bound before it iterates or hashes any
/// attacker-controlled sibling.
pub const MAX_INDEXED_MERKLE_SIBLINGS: usize = 64;

/// Zero-based position of a leaf in an ordered Merkle tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MerkleLeafIndex(#[serde(with = "canonical_u64")] u64);

impl MerkleLeafIndex {
    /// Creates a zero-based leaf index.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the zero-based index as a `u64`.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Number of leaves committed by a non-empty Merkle root.
///
/// Construction accepts zero so an untrusted decoded proof can be represented;
/// verification rejects it with [`IndexedMerkleProofError::EmptyTree`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MerkleLeafCount(#[serde(with = "canonical_u64")] u64);

impl MerkleLeafCount {
    /// Creates a leaf count. Verification requires the value to be non-zero.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the leaf count as a `u64`.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Version-1 inclusion proof for one leaf in an ordered Merkle tree.
///
/// Invariants enforced by [`verify_indexed_merkle_proof`]: `leaf_count > 0`,
/// `leaf_index < leaf_count`, `siblings.len() == ceil(log2(leaf_count))`, and an
/// unpaired node's sibling equals that node at every odd-width layer. Direction
/// is derived from `leaf_index`; this format deliberately has no direction
/// field. The leaf must already be hashed under the owning tree's leaf domain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedMerkleProofV1 {
    /// Already-domain-separated leaf digest at `leaf_index`.
    pub leaf: Hash256,
    /// Zero-based position of `leaf` in the ordered tree.
    pub leaf_index: MerkleLeafIndex,
    /// Total number of leaves committed by the expected root.
    pub leaf_count: MerkleLeafCount,
    /// Bottom-up sibling digests, one per tree level.
    pub siblings: Vec<Hash256>,
}

impl IndexedMerkleProofV1 {
    /// Schema version represented by this concrete proof type.
    pub const SCHEMA_VERSION: u16 = 1;
}

/// Structural or cryptographic failure while building or verifying a proof.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IndexedMerkleProofError {
    /// An inclusion proof cannot refer to the empty-tree sentinel root.
    #[error("indexed Merkle proof cannot describe an empty tree")]
    EmptyTree,
    /// The leaf position is outside the declared tree.
    #[error("leaf index {index} is outside leaf count {count}")]
    LeafIndexOutOfRange {
        /// Rejected zero-based leaf index.
        index: u64,
        /// Declared number of leaves.
        count: u64,
    },
    /// A platform index could not be represented by the canonical `u64` schema.
    #[error("leaf index or count does not fit the version-1 u64 schema")]
    IndexOrCountOverflow,
    /// The path exceeds the absolute hostile-input resource limit.
    #[error("indexed Merkle proof has {actual} siblings; maximum is {maximum}")]
    TooManySiblings {
        /// Attacker-supplied sibling count.
        actual: usize,
        /// Absolute accepted sibling count.
        maximum: usize,
    },
    /// The supplied path length cannot represent the declared leaf count.
    #[error("indexed Merkle proof depth {actual} does not match required depth {expected}")]
    ImpossibleDepth {
        /// Required path depth for the declared leaf count.
        expected: usize,
        /// Supplied sibling count.
        actual: usize,
    },
    /// An odd-width layer did not duplicate its unpaired final node.
    #[error("odd Merkle layer at proof level {level} has a non-duplicate sibling")]
    InvalidOddDuplicate {
        /// Zero-based proof level, starting at the leaf layer.
        level: usize,
    },
    /// Index/count reduction did not finish at the unique root position.
    #[error("indexed Merkle path left index {index} and count {count} unconsumed")]
    UnconsumedTreePosition {
        /// Remaining index after all sibling levels.
        index: u64,
        /// Remaining node count after all sibling levels.
        count: u64,
    },
    /// Structurally valid proof hashes to a different root.
    #[error("indexed Merkle proof does not match the expected root")]
    RootMismatch,
}

/// Builds a version-1 indexed proof for `leaves[index]`.
///
/// Leaves must be pre-hashed with the owning transaction, receipt, or state-leaf
/// domain. The builder preserves `webc-crypto::merkle_root` semantics exactly,
/// including duplication of an unpaired final node. It returns a typed error for
/// an empty list, an out-of-range index, or a list not representable by the V1
/// `u64` count fields. The operation is pure and consensus-state independent.
pub fn build_indexed_merkle_proof(
    leaves: &[Hash256],
    index: usize,
) -> Result<IndexedMerkleProofV1, IndexedMerkleProofError> {
    let leaf_count =
        u64::try_from(leaves.len()).map_err(|_| IndexedMerkleProofError::IndexOrCountOverflow)?;
    if leaf_count == 0 {
        return Err(IndexedMerkleProofError::EmptyTree);
    }
    let leaf_index =
        u64::try_from(index).map_err(|_| IndexedMerkleProofError::IndexOrCountOverflow)?;
    if leaf_index >= leaf_count {
        return Err(IndexedMerkleProofError::LeafIndexOutOfRange {
            index: leaf_index,
            count: leaf_count,
        });
    }

    let legacy =
        merkle_proof(leaves, index).ok_or(IndexedMerkleProofError::LeafIndexOutOfRange {
            index: leaf_index,
            count: leaf_count,
        })?;
    let siblings = legacy.steps.into_iter().map(|step| step.sibling).collect();
    let proof = IndexedMerkleProofV1 {
        leaf: legacy.leaf,
        leaf_index: MerkleLeafIndex::new(leaf_index),
        leaf_count: MerkleLeafCount::new(leaf_count),
        siblings,
    };

    validate_shape(&proof)?;
    Ok(proof)
}

/// Verifies an untrusted version-1 indexed proof against `expected_root`.
///
/// Structural validation, including the absolute 64-sibling cap, completes
/// before any parent hash is computed. Directions are derived from the index.
/// At an odd-width layer the final unpaired node must explicitly carry itself
/// as the sibling, which binds the proof to the same duplicate-last tree shape
/// as `webc-crypto::merkle_root`. Success mutates no state; every failure is a
/// typed rejection and leaves callers unchanged.
pub fn verify_indexed_merkle_proof(
    expected_root: Hash256,
    proof: &IndexedMerkleProofV1,
) -> Result<(), IndexedMerkleProofError> {
    validate_shape(proof)?;

    let mut current = proof.leaf;
    let mut index = proof.leaf_index.get();
    let mut count = proof.leaf_count.get();

    for (level, sibling) in proof.siblings.iter().copied().enumerate() {
        if index % 2 == 1 {
            current = merkle_parent(sibling, current);
        } else {
            let has_right_sibling = index
                .checked_add(1)
                .is_some_and(|right_index| right_index < count);
            if !has_right_sibling && sibling != current {
                return Err(IndexedMerkleProofError::InvalidOddDuplicate { level });
            }
            current = merkle_parent(current, sibling);
        }

        index /= 2;
        count = half_rounded_up(count);
    }

    if index != 0 || count != 1 {
        return Err(IndexedMerkleProofError::UnconsumedTreePosition { index, count });
    }
    if current != expected_root {
        return Err(IndexedMerkleProofError::RootMismatch);
    }
    Ok(())
}

fn validate_shape(proof: &IndexedMerkleProofV1) -> Result<(), IndexedMerkleProofError> {
    let count = proof.leaf_count.get();
    if count == 0 {
        return Err(IndexedMerkleProofError::EmptyTree);
    }
    let index = proof.leaf_index.get();
    if index >= count {
        return Err(IndexedMerkleProofError::LeafIndexOutOfRange { index, count });
    }
    if proof.siblings.len() > MAX_INDEXED_MERKLE_SIBLINGS {
        return Err(IndexedMerkleProofError::TooManySiblings {
            actual: proof.siblings.len(),
            maximum: MAX_INDEXED_MERKLE_SIBLINGS,
        });
    }

    let expected = required_depth(count);
    if proof.siblings.len() != expected {
        return Err(IndexedMerkleProofError::ImpossibleDepth {
            expected,
            actual: proof.siblings.len(),
        });
    }
    Ok(())
}

fn required_depth(mut count: u64) -> usize {
    let mut depth = 0usize;
    while count > 1 {
        count = half_rounded_up(count);
        depth += 1;
    }
    depth
}

const fn half_rounded_up(value: u64) -> u64 {
    value / 2 + value % 2
}

mod canonical_u64 {
    use serde::{
        de::{Error as DeError, Visitor},
        Deserialize, Deserializer, Serializer,
    };
    use std::fmt;

    pub(super) fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(value)
        } else {
            serializer.serialize_u64(*value)
        }
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(CanonicalU64Visitor)
        } else {
            u64::deserialize(deserializer)
        }
    }

    struct CanonicalU64Visitor;

    impl Visitor<'_> for CanonicalU64Visitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a canonical unsigned decimal u64 string")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            if value.is_empty()
                || value.len() > 20
                || (value.len() > 1 && value.starts_with('0'))
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(E::custom(
                    "expected a canonical unsigned decimal u64 string",
                ));
            }
            value
                .parse()
                .map_err(|_| E::custom("unsigned decimal value exceeds u64"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use webc_crypto::merkle_root;

    fn leaves(count: usize) -> Vec<Hash256> {
        (0..count)
            .map(|index| Hash256::digest(index.to_le_bytes()))
            .collect()
    }

    #[test]
    fn rejects_empty_tree_and_out_of_range_builder_requests() {
        assert_eq!(
            build_indexed_merkle_proof(&[], 0),
            Err(IndexedMerkleProofError::EmptyTree)
        );
        assert_eq!(
            build_indexed_merkle_proof(&leaves(2), 2),
            Err(IndexedMerkleProofError::LeafIndexOutOfRange { index: 2, count: 2 })
        );
    }

    #[test]
    fn single_leaf_vector_has_no_siblings_and_verifies() {
        let values = leaves(1);
        let proof = build_indexed_merkle_proof(&values, 0).unwrap();
        assert_eq!(proof.siblings, Vec::<Hash256>::new());
        assert_eq!(proof.leaf_index, MerkleLeafIndex::new(0));
        assert_eq!(proof.leaf_count, MerkleLeafCount::new(1));
        assert_eq!(
            proof.leaf.to_hex(),
            "af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc"
        );
        assert_eq!(
            verify_indexed_merkle_proof(merkle_root(&values), &proof),
            Ok(())
        );
    }

    #[test]
    fn odd_leaf_vector_duplicates_the_unpaired_node() {
        let values = leaves(5);
        let proof = build_indexed_merkle_proof(&values, 4).unwrap();
        assert_eq!(proof.siblings.len(), 3);
        assert_eq!(proof.siblings[0], proof.leaf);
        assert_eq!(
            proof
                .siblings
                .iter()
                .map(|hash| hash.to_hex())
                .collect::<Vec<_>>(),
            [
                "f0a0278e4372459cca6159cd5e71cfee638302a7b9ca9b05c34181ac0a65ac5d",
                "ca0473f5448c76c98ea2957a866481e76043b4fb3f2776d36df92cbbd7b87efb",
                "dfa4f171b4487f13665b15b05de3244999eb8389ab5238d58f1ab81351a6543e",
            ]
        );
        assert_eq!(
            merkle_root(&values).to_hex(),
            "246b63074bb7074d43cfdf885d112bffe8fa65ea0d00c2e94d5176c821c40b87"
        );
        assert_eq!(
            verify_indexed_merkle_proof(merkle_root(&values), &proof),
            Ok(())
        );
    }

    #[test]
    fn even_tree_boundary_positions_verify() {
        let values = leaves(8);
        for index in [0, values.len() - 1] {
            let proof = build_indexed_merkle_proof(&values, index).unwrap();
            assert_eq!(
                verify_indexed_merkle_proof(merkle_root(&values), &proof),
                Ok(())
            );
        }
    }

    #[test]
    fn verifier_rejects_zero_count_and_out_of_range_before_hashing() {
        let mut proof = IndexedMerkleProofV1 {
            leaf: Hash256::ZERO,
            leaf_index: MerkleLeafIndex::new(0),
            leaf_count: MerkleLeafCount::new(0),
            siblings: Vec::new(),
        };
        assert_eq!(
            verify_indexed_merkle_proof(Hash256::ZERO, &proof),
            Err(IndexedMerkleProofError::EmptyTree)
        );

        proof.leaf_count = MerkleLeafCount::new(1);
        proof.leaf_index = MerkleLeafIndex::new(1);
        assert_eq!(
            verify_indexed_merkle_proof(Hash256::ZERO, &proof),
            Err(IndexedMerkleProofError::LeafIndexOutOfRange { index: 1, count: 1 })
        );
    }

    #[test]
    fn verifier_rejects_impossible_and_excess_depths() {
        let values = leaves(3);
        let mut proof = build_indexed_merkle_proof(&values, 1).unwrap();
        proof.siblings.pop();
        assert_eq!(
            verify_indexed_merkle_proof(merkle_root(&values), &proof),
            Err(IndexedMerkleProofError::ImpossibleDepth {
                expected: 2,
                actual: 1
            })
        );

        proof.siblings = vec![Hash256::ZERO; MAX_INDEXED_MERKLE_SIBLINGS + 1];
        assert_eq!(
            verify_indexed_merkle_proof(merkle_root(&values), &proof),
            Err(IndexedMerkleProofError::TooManySiblings {
                actual: MAX_INDEXED_MERKLE_SIBLINGS + 1,
                maximum: MAX_INDEXED_MERKLE_SIBLINGS,
            })
        );
    }

    #[test]
    fn verifier_rejects_wrong_odd_duplication_and_wrong_leaf_count() {
        let values = leaves(5);
        let root = merkle_root(&values);
        let mut proof = build_indexed_merkle_proof(&values, 4).unwrap();
        proof.siblings[0] = Hash256::digest(b"not-the-duplicated-leaf");
        assert_eq!(
            verify_indexed_merkle_proof(root, &proof),
            Err(IndexedMerkleProofError::InvalidOddDuplicate { level: 0 })
        );

        let mut wrong_count = build_indexed_merkle_proof(&values, 2).unwrap();
        wrong_count.leaf_count = MerkleLeafCount::new(4);
        assert_eq!(
            verify_indexed_merkle_proof(root, &wrong_count),
            Err(IndexedMerkleProofError::ImpossibleDepth {
                expected: 2,
                actual: 3
            })
        );
    }

    #[test]
    fn verifier_rejects_leaf_sibling_and_root_tampering() {
        let values = leaves(6);
        let root = merkle_root(&values);
        let proof = build_indexed_merkle_proof(&values, 2).unwrap();

        let mut leaf_tamper = proof.clone();
        leaf_tamper.leaf = Hash256::digest(b"tampered-leaf");
        assert_eq!(
            verify_indexed_merkle_proof(root, &leaf_tamper),
            Err(IndexedMerkleProofError::RootMismatch)
        );

        let mut sibling_tamper = proof.clone();
        sibling_tamper.siblings[0] = Hash256::digest(b"tampered-sibling");
        assert_eq!(
            verify_indexed_merkle_proof(root, &sibling_tamper),
            Err(IndexedMerkleProofError::RootMismatch)
        );

        assert_eq!(
            verify_indexed_merkle_proof(Hash256::digest(b"wrong-root"), &proof),
            Err(IndexedMerkleProofError::RootMismatch)
        );
    }

    #[test]
    fn human_readable_schema_uses_canonical_decimal_strings() {
        let proof = build_indexed_merkle_proof(&leaves(3), 2).unwrap();
        let encoded = serde_json::to_value(&proof).unwrap();
        assert_eq!(encoded["leaf_index"], "2");
        assert_eq!(encoded["leaf_count"], "3");
        assert_eq!(IndexedMerkleProofV1::SCHEMA_VERSION, 1);

        let mut leading_zero = encoded.clone();
        leading_zero["leaf_count"] = serde_json::Value::String("03".to_owned());
        assert!(serde_json::from_value::<IndexedMerkleProofV1>(leading_zero).is_err());

        let mut numeric = encoded;
        numeric["leaf_index"] = serde_json::Value::Number(2_u64.into());
        assert!(serde_json::from_value::<IndexedMerkleProofV1>(numeric).is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        #[test]
        fn every_generated_position_matches_the_existing_root(
            payloads in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..96), 1..257),
            selected in any::<usize>(),
        ) {
            let values: Vec<Hash256> = payloads.iter().map(Hash256::digest).collect();
            let index = selected % values.len();
            let root = merkle_root(&values);
            let proof = build_indexed_merkle_proof(&values, index).unwrap();

            prop_assert_eq!(
                verify_indexed_merkle_proof(root, &proof),
                Ok(())
            );
            prop_assert_eq!(proof.leaf, values[index]);
            prop_assert_eq!(
                proof.leaf_index,
                MerkleLeafIndex::new(u64::try_from(index).unwrap())
            );
            prop_assert_eq!(
                proof.leaf_count,
                MerkleLeafCount::new(u64::try_from(values.len()).unwrap())
            );
        }
    }
}
