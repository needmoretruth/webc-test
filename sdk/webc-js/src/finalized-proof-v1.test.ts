/** Shared Rust/browser fixture and adversarial finalized-proof tests. */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  validateCheckpointV1,
  type CheckpointV1Json,
} from "./checkpoint-v1";
import {
  acceptCheckpointQuorumV1,
  acceptExplicitOperatorCheckpointV1,
  type CheckpointSourceObservationV1,
} from "./checkpoint-trust-v1";
import {
  verifyFinalizedTransactionProofV1,
  type FinalizedTransactionProofV1Json,
} from "./finalized-proof-v1";

interface SharedFixture {
  readonly api_version: "v2";
  readonly checkpoint_candidate: CheckpointV1Json;
  readonly proof: FinalizedTransactionProofV1Json;
  readonly requirements: {
    readonly chain_id: string;
    readonly transaction_id: string;
    readonly blocks_per_epoch: string;
  };
  readonly expected: {
    readonly checkpoint_digest: string;
    readonly block_hash: string;
  };
}

const fixture = JSON.parse(readFileSync(
  new URL("../../../fixtures/finalized-transaction-proof-v1.json", import.meta.url),
  "utf8",
)) as SharedFixture;

const checkpointRequirements = {
  chainId: fixture.requirements.chain_id,
  minimumHeight: fixture.checkpoint_candidate.header.height,
  minimumEpoch: fixture.checkpoint_candidate.header.epoch,
} as const;

const proofRequirements = {
  chainId: fixture.requirements.chain_id,
  transactionId: fixture.requirements.transaction_id,
  blocksPerEpoch: fixture.requirements.blocks_per_epoch,
} as const;

describe("finalized transaction proof V1", () => {
  it("verifies the exact frozen Rust checkpoint, transition, signatures, and leaves", async () => {
    const checkpoint = await validateCheckpointV1(
      fixture.checkpoint_candidate,
      checkpointRequirements,
    );
    expect(checkpoint.digest).toBe(fixture.expected.checkpoint_digest);
    const verified = await verifyFinalizedTransactionProofV1(
      fixture.proof,
      checkpoint,
      proofRequirements,
    );
    expect(verified).toEqual({
      transactionId: fixture.requirements.transaction_id,
      position: { height: "11", transaction_index: 0 },
      blockHash: fixture.expected.block_hash,
      checkpointDigest: fixture.expected.checkpoint_digest,
    });
    expect(Object.isFrozen(checkpoint.checkpoint)).toBe(true);
    expect(Object.isFrozen(checkpoint.checkpoint.header)).toBe(true);
  });

  it("uses an owned snapshot while asynchronous signature checks yield", async () => {
    const candidate = structuredClone(fixture.checkpoint_candidate);
    const checkpointPromise = validateCheckpointV1(candidate, checkpointRequirements);
    candidate.certificate.precommits[0].signature = "00".repeat(64);
    const checkpoint = await checkpointPromise;

    const proof = structuredClone(fixture.proof);
    const verification = verifyFinalizedTransactionProofV1(
      proof,
      checkpoint,
      proofRequirements,
    );
    proof.target_certificate.precommits[0].signature = "00".repeat(64);
    proof.receipt.transaction_id = "00".repeat(32);
    await expect(verification).resolves.toMatchObject({
      transactionId: fixture.requirements.transaction_id,
      blockHash: fixture.expected.block_hash,
    });
  });

  it("bounds deep receipt and non-receipt proof data before recursive canonicalization", async () => {
    const checkpoint = await validateCheckpointV1(
      fixture.checkpoint_candidate,
      checkpointRequirements,
    );
    let nested: unknown = null;
    for (let depth = 0; depth < 20_000; depth += 1) nested = { child: nested };

    const deepReceipt = structuredClone(fixture.proof);
    deepReceipt.receipt.events = [{
      version: 1,
      transaction_id: deepReceipt.receipt.transaction_id,
      action_index: 0,
      event_index: 0,
      body: { Transfer: nested },
    }];
    const deepHeader = structuredClone(fixture.proof) as unknown as {
      target_header: { chain_id: unknown };
    };
    deepHeader.target_header.chain_id = nested;

    for (const hostile of [deepReceipt, deepHeader]) {
      try {
        await verifyFinalizedTransactionProofV1(
          hostile,
          checkpoint,
          proofRequirements,
        );
        throw new Error("hostile deep proof unexpectedly verified");
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect(error).not.toBeInstanceOf(RangeError);
        expect((error as Error).message).toMatch(/JSON depth limit/u);
      }
    }
  });

  it("rejects transaction, receipt, path, certificate, and transition tampering", async () => {
    const checkpoint = await validateCheckpointV1(
      fixture.checkpoint_candidate,
      checkpointRequirements,
    );

    const transactionTamper = structuredClone(fixture.proof);
    if (!("Actions" in transactionTamper.transaction.kind)) {
      throw new Error("fixture action program is missing");
    }
    const operation = transactionTamper.transaction.kind.Actions.actions[0];
    if (!("Native" in operation)
      || typeof operation.Native.operation !== "object"
      || operation.Native.operation === null
      || !("Transfer" in operation.Native.operation)) {
      throw new Error("fixture transfer is missing");
    }
    operation.Native.operation.Transfer.amount = "6";
    await expect(verifyFinalizedTransactionProofV1(
      transactionTamper,
      checkpoint,
      proofRequirements,
    )).rejects.toThrow("signature");

    const receiptTamper = structuredClone(fixture.proof);
    receiptTamper.receipt.fee_summary.charged = "31";
    await expect(verifyFinalizedTransactionProofV1(
      receiptTamper,
      checkpoint,
      proofRequirements,
    )).rejects.toThrow("reconcile");

    const leafTamper = structuredClone(fixture.proof);
    leafTamper.transaction_proof.leaf = "00".repeat(32);
    await expect(verifyFinalizedTransactionProofV1(
      leafTamper,
      checkpoint,
      proofRequirements,
    )).rejects.toThrow("leaf mismatch");

    const certificateTamper = structuredClone(fixture.proof);
    certificateTamper.target_certificate.precommits[0].signature = "00".repeat(64);
    await expect(verifyFinalizedTransactionProofV1(
      certificateTamper,
      checkpoint,
      proofRequirements,
    )).rejects.toThrow("signature");

    const transitionTamper = structuredClone(fixture.proof);
    transitionTamper.authority_transitions = [];
    await expect(verifyFinalizedTransactionProofV1(
      transitionTamper,
      checkpoint,
      proofRequirements,
    )).rejects.toThrow("target authority");

    const oversizedPath = structuredClone(fixture.proof);
    oversizedPath.transaction_proof.siblings = Array.from(
      { length: 65 },
      () => "00".repeat(32),
    );
    await expect(verifyFinalizedTransactionProofV1(
      oversizedPath,
      checkpoint,
      proofRequirements,
    )).rejects.toThrow("item limit");
  });

  it("accepts configured agreement and stops on disagreement or invalid input", async () => {
    const agreeing: CheckpointSourceObservationV1[] = [
      { source: "community-a", result: { kind: "candidate", candidate: fixture.checkpoint_candidate } },
      { source: "community-b", result: { kind: "candidate", candidate: fixture.checkpoint_candidate } },
      { source: "official", result: { kind: "unavailable" } },
    ];
    const accepted = await acceptCheckpointQuorumV1(
      ["official", "community-a", "community-b"],
      2,
      agreeing,
      checkpointRequirements,
    );
    expect(accepted.checkpoint.digest).toBe(fixture.expected.checkpoint_digest);
    expect(accepted.trust).toEqual({
      kind: "quorum_agreement_v1",
      requiredAgreements: 2,
      observedAgreements: 2,
    });
    expect(accepted.agreeingSources).toEqual(["community-a", "community-b"]);

    const targetCheckpoint: CheckpointV1Json = {
      version: 1,
      header: fixture.proof.target_header,
      certificate: fixture.proof.target_certificate,
      authority_set: fixture.proof.target_authority_set,
    };
    await expect(acceptCheckpointQuorumV1(
      ["community-a", "community-b"],
      2,
      [
        agreeing[0],
        { source: "community-b", result: { kind: "candidate", candidate: targetCheckpoint } },
      ],
      checkpointRequirements,
    )).rejects.toThrow("disagree");

    const invalid = structuredClone(fixture.checkpoint_candidate);
    invalid.certificate.block_hash = "00".repeat(32);
    await expect(acceptCheckpointQuorumV1(
      ["one", "two", "three"],
      2,
      [
        { source: "one", result: { kind: "candidate", candidate: fixture.checkpoint_candidate } },
        { source: "two", result: { kind: "candidate", candidate: fixture.checkpoint_candidate } },
        { source: "three", result: { kind: "candidate", candidate: invalid } },
      ],
      checkpointRequirements,
    )).rejects.toThrow("block hash");
  });

  it("labels explicit operator trust and rejects wrong-chain or stale candidates", async () => {
    const explicit = await acceptExplicitOperatorCheckpointV1(
      "operator-usb",
      "air-gapped operator input",
      {
        source: "operator-usb",
        result: { kind: "candidate", candidate: fixture.checkpoint_candidate },
      },
      checkpointRequirements,
    );
    expect(explicit.trust).toEqual({
      kind: "explicit_operator_trust_v1",
      label: "air-gapped operator input",
    });

    await expect(validateCheckpointV1(fixture.checkpoint_candidate, {
      ...checkpointRequirements,
      chainId: "webc-other-1",
    })).rejects.toThrow("chain mismatch");
    await expect(validateCheckpointV1(fixture.checkpoint_candidate, {
      ...checkpointRequirements,
      minimumHeight: "10",
    })).rejects.toThrow("height floor");
  });
});
