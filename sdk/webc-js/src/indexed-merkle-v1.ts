/**
 * Browser verifier for WEBC V1 indexed Merkle inclusion proofs.
 *
 * Purpose: authenticate an ordered leaf without trusting caller-supplied
 * left/right flags. Responsibilities: exact hostile JSON shape, u64 index/count
 * bounds, the 64-level cap, required tree depth, duplicate-last odd layers, and
 * root comparison. Non-responsibilities: defining transaction/receipt leaves,
 * fetching proof bytes, or deciding finality. Data flow: a pre-hashed leaf and
 * bottom-up siblings are reduced to the expected root. Security boundary: all
 * structural checks complete before the bounded hashing loop.
 */

import { merkleParentV1Hex } from "./receipt-v1.js";
import {
  proofArray,
  proofExactKeys,
  proofHex,
  proofRecord,
  proofU64,
} from "./proof-json-v1.js";

/** Maximum sibling hashes accepted by Rust and browser V1 verifiers. */
export const MAX_INDEXED_MERKLE_SIBLINGS = 64;

/** Exact Rust `IndexedMerkleProofV1` JSON shape. */
export interface IndexedMerkleProofV1Json {
  /** Already-domain-separated leaf digest. */
  leaf: string;
  /** Zero-based leaf position as canonical decimal u64. */
  leaf_index: string;
  /** Non-zero tree leaf count as canonical decimal u64. */
  leaf_count: string;
  /** Bottom-up sibling hashes. */
  siblings: string[];
}

/** Validates shape and verifies `proof` against `expectedRoot`. */
export async function verifyIndexedMerkleProofV1(
  expectedRoot: string,
  proof: IndexedMerkleProofV1Json,
): Promise<void> {
  proofHex(expectedRoot, 32, "expected Merkle root");
  const { index: originalIndex, count: originalCount } = validateIndexedMerkleProofV1(proof);
  let index = originalIndex;
  let count = originalCount;
  let current = proof.leaf;
  // Snapshot the bounded path before the first await so host code cannot change
  // which siblings are hashed while asynchronous WebCrypto work is running.
  const siblings = [...proof.siblings];

  for (let level = 0; level < siblings.length; level += 1) {
    const sibling = siblings[level];
    if ((index & 1n) === 1n) {
      current = await merkleParentV1Hex(sibling, current);
    } else {
      const hasRightSibling = index + 1n < count;
      if (!hasRightSibling && sibling !== current) {
        throw new Error(`indexed Merkle proof has an invalid odd duplicate at level ${level}`);
      }
      current = await merkleParentV1Hex(current, sibling);
    }
    index /= 2n;
    count = halfRoundedUp(count);
  }
  if (index !== 0n || count !== 1n) {
    throw new Error("indexed Merkle proof did not consume its tree position");
  }
  if (current !== expectedRoot) throw new Error("indexed Merkle proof root mismatch");
}

/** Performs all non-cryptographic indexed proof validation. */
export function validateIndexedMerkleProofV1(
  value: unknown,
): { readonly index: bigint; readonly count: bigint } {
  const proof = proofRecord(value, "indexed Merkle proof");
  proofExactKeys(proof, ["leaf", "leaf_index", "leaf_count", "siblings"], "indexed Merkle proof");
  proofHex(proof.leaf, 32, "indexed Merkle leaf");
  const index = proofU64(proof.leaf_index, "indexed Merkle leaf index");
  const count = proofU64(proof.leaf_count, "indexed Merkle leaf count");
  if (count === 0n) throw new Error("indexed Merkle proof cannot describe an empty tree");
  if (index >= count) throw new Error("indexed Merkle proof leaf index is out of range");
  const siblings = proofArray(
    proof.siblings,
    MAX_INDEXED_MERKLE_SIBLINGS,
    "indexed Merkle siblings",
  );
  for (const sibling of siblings) proofHex(sibling, 32, "indexed Merkle sibling");
  if (siblings.length !== requiredDepth(count)) {
    throw new Error("indexed Merkle proof depth does not match its leaf count");
  }
  return { index, count };
}

function requiredDepth(initialCount: bigint): number {
  let count = initialCount;
  let depth = 0;
  while (count > 1n) {
    count = halfRoundedUp(count);
    depth += 1;
  }
  return depth;
}

function halfRoundedUp(value: bigint): bigint {
  return value / 2n + value % 2n;
}
