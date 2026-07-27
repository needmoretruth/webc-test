/** Rust-parity and hostile-shape tests for indexed Merkle V1 verification. */

import { describe, expect, it } from "vitest";
import { verifyIndexedMerkleProofV1, type IndexedMerkleProofV1Json } from "./indexed-merkle-v1";

describe("indexed Merkle proof V1", () => {
  const oddBoundary: IndexedMerkleProofV1Json = {
    leaf: "f0a0278e4372459cca6159cd5e71cfee638302a7b9ca9b05c34181ac0a65ac5d",
    leaf_index: "4",
    leaf_count: "5",
    siblings: [
      "f0a0278e4372459cca6159cd5e71cfee638302a7b9ca9b05c34181ac0a65ac5d",
      "ca0473f5448c76c98ea2957a866481e76043b4fb3f2776d36df92cbbd7b87efb",
      "dfa4f171b4487f13665b15b05de3244999eb8389ab5238d58f1ab81351a6543e",
    ],
  };

  it("verifies the frozen Rust odd-leaf boundary vector", async () => {
    await expect(verifyIndexedMerkleProofV1(
      "246b63074bb7074d43cfdf885d112bffe8fa65ea0d00c2e94d5176c821c40b87",
      oddBoundary,
    )).resolves.toBeUndefined();
  });

  it("rejects odd-duplicate, depth, count, and root tampering", async () => {
    const wrongOdd = structuredClone(oddBoundary);
    wrongOdd.siblings[0] = "00".repeat(32);
    await expect(verifyIndexedMerkleProofV1(
      "246b63074bb7074d43cfdf885d112bffe8fa65ea0d00c2e94d5176c821c40b87",
      wrongOdd,
    )).rejects.toThrow("odd duplicate");

    const wrongDepth = structuredClone(oddBoundary);
    wrongDepth.siblings.pop();
    await expect(verifyIndexedMerkleProofV1("00".repeat(32), wrongDepth))
      .rejects.toThrow("depth");

    const zeroCount = structuredClone(oddBoundary);
    zeroCount.leaf_count = "0";
    await expect(verifyIndexedMerkleProofV1("00".repeat(32), zeroCount))
      .rejects.toThrow("empty tree");

    await expect(verifyIndexedMerkleProofV1("00".repeat(32), oddBoundary))
      .rejects.toThrow("root mismatch");
  });
});
