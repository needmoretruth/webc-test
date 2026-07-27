/**
 * Browser verifier for checkpoint-relative finalized transaction proofs.
 *
 * Purpose: prove that one exact signed V5 transaction and V1 receipt were
 * finalized under a separately accepted checkpoint. Responsibilities: bounded
 * transport/schema checks, authority-transition chaining, target certificate,
 * transaction validity/signature/identity, indexed transaction and receipt
 * membership, and exact receipt/fee binding. Non-responsibilities: trusting the
 * node that served a checkpoint, executing the block, or mutating wallet state.
 * Data flow: an accepted checkpoint anchors zero or more certified authority
 * transitions; the target header commits two indexed leaves. Security boundary:
 * byte/count/depth checks precede signatures and hashes, requested identity is
 * caller-supplied, and every mismatch fails closed.
 */

import { blockHeaderV4HashHex } from "./block.js";
import { canonicalJson } from "./canonical.js";
import {
  checkpointNextAnchorV1,
  equalBlockHeaderV4,
  validateBlockHeaderV4,
  verifyAuthoritySetTransitionV1,
  verifyCertifiedHeaderV1,
  type AuthoritySetTransitionV1Json,
  type CheckpointV1Json,
  type ValidatedCheckpointV1,
} from "./checkpoint-v1.js";
import {
  finalityAuthoritySetV1CommitmentHex,
  MAX_FINALITY_AUTHORITIES_V1,
  validateFinalityAuthoritySetV1,
  type FinalityAuthoritySetV1Json,
} from "./finality-authority.js";
import {
  MAX_INDEXED_MERKLE_SIBLINGS,
  validateIndexedMerkleProofV1,
  verifyIndexedMerkleProofV1,
  type IndexedMerkleProofV1Json,
} from "./indexed-merkle-v1.js";
import {
  receiptV1LeafHex,
  transactionV1LeafHex,
  validateReceiptV1,
  verifyTransactionReceiptPairV1,
  type BlockPositionV1Json,
  type ReceiptV1Json,
} from "./receipt-v1.js";
import {
  proofArray,
  proofChainId,
  proofExactKeys,
  proofHex,
  proofRecord,
  proofU64,
} from "./proof-json-v1.js";
import {
  transactionV5IdHex,
  validateTransactionV5Structure,
  verifySignedTransactionV5,
  type SignedTransactionV5Json,
} from "./transaction-v5.js";
import type { BlockHeaderV4Json } from "./types.js";
import type { FinalityCertificateV1Json } from "./checkpoint-v1.js";

/** Finalized transaction proof schema version. */
export const FINALIZED_TRANSACTION_PROOF_V1 = 1;
/** Maximum authority transitions in one proof. */
export const MAX_AUTHORITY_TRANSITIONS_V1 = 64;
/** Maximum canonical bytes in one proof object. */
export const MAX_FINALIZED_TRANSACTION_PROOF_V1_JSON_BYTES = 16 * 1024 * 1024;
/** Maximum response bytes for the 16 MiB proof plus 8 MiB checkpoint. */
export const MAX_FINALIZED_PROOF_BUNDLE_V1_JSON_BYTES = 24 * 1024 * 1024 + 1024;

/** Exact Rust finalized transaction proof JSON shape. */
export interface FinalizedTransactionProofV1Json {
  version: 1;
  authority_transitions: AuthoritySetTransitionV1Json[];
  target_header: BlockHeaderV4Json;
  target_certificate: FinalityCertificateV1Json;
  target_authority_set: FinalityAuthoritySetV1Json;
  transaction: SignedTransactionV5Json;
  receipt: ReceiptV1Json;
  transaction_proof: IndexedMerkleProofV1Json;
  receipt_proof: IndexedMerkleProofV1Json;
}

/** Node V2 response; the checkpoint remains an untrusted candidate. */
export interface FinalizedTransactionProofBundleV1Json {
  api_version: "v2";
  checkpoint_candidate: CheckpointV1Json;
  proof: FinalizedTransactionProofV1Json;
}

/** Caller-controlled replay, identity, and epoch-boundary requirements. */
export interface FinalizedTransactionProofRequirementsV1 {
  readonly chainId: string;
  readonly transactionId: string;
  readonly blocksPerEpoch: string;
}

/** Authenticated result returned only after every layer verifies. */
export interface VerifiedFinalizedTransactionV1 {
  readonly transactionId: string;
  readonly position: BlockPositionV1Json;
  readonly blockHash: string;
  readonly checkpointDigest: string;
}

/** Parses one bounded V2 node response without trusting its checkpoint. */
export function decodeFinalizedTransactionProofBundleV1(
  bytes: Uint8Array,
): FinalizedTransactionProofBundleV1Json {
  if (bytes.byteLength > MAX_FINALIZED_PROOF_BUNDLE_V1_JSON_BYTES) {
    throw new Error("finalized proof response exceeds its absolute byte limit");
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  return parseFinalizedTransactionProofBundleV1(JSON.parse(text) as unknown);
}

/**
 * Validates an already-decoded V2 proof response.
 *
 * The caller must enforce the transport byte cap before JSON decoding; this
 * function then enforces the exact envelope and every attacker-controlled
 * collection bound needed before cryptographic verification.
 */
export function parseFinalizedTransactionProofBundleV1(
  input: unknown,
): FinalizedTransactionProofBundleV1Json {
  const value = proofRecord(input, "finalized proof response");
  proofExactKeys(value, ["api_version", "checkpoint_candidate", "proof"], "finalized proof response");
  if (value.api_version !== "v2") throw new Error("unsupported finalized proof API version");
  // Full nested cryptographic validation deliberately waits until the caller
  // accepts the checkpoint through an explicit trust policy.
  validateFinalizedProofCollectionBounds(value.proof);
  return value as unknown as FinalizedTransactionProofBundleV1Json;
}

/** Verifies one complete proof relative to a separately accepted checkpoint. */
export async function verifyFinalizedTransactionProofV1(
  value: unknown,
  checkpoint: ValidatedCheckpointV1,
  requirements: FinalizedTransactionProofRequirementsV1,
): Promise<VerifiedFinalizedTransactionV1> {
  validateProofRequirements(requirements);
  validateFinalizedProofCollectionBounds(value);
  const proof = proofRecord(value, "finalized transaction proof");
  proofExactKeys(proof, [
    "version", "authority_transitions", "target_header", "target_certificate",
    "target_authority_set", "transaction", "receipt", "transaction_proof", "receipt_proof",
  ], "finalized transaction proof");
  const canonical = canonicalJson(proof);
  if (new TextEncoder().encode(canonical).byteLength
      > MAX_FINALIZED_TRANSACTION_PROOF_V1_JSON_BYTES) {
    throw new Error("finalized transaction proof exceeds its 16 MiB limit");
  }
  if (proof.version !== FINALIZED_TRANSACTION_PROOF_V1) {
    throw new Error("unsupported finalized transaction proof version");
  }
  const typed = JSON.parse(canonical) as FinalizedTransactionProofV1Json;
  validateBlockHeaderV4(typed.target_header);
  validateFinalityAuthoritySetV1(typed.target_authority_set);
  validateTransactionV5Structure(typed.transaction);
  if (typed.transaction.sender_signature === null) {
    throw new Error("finalized transaction is missing its sender signature");
  }
  validateReceiptV1(typed.receipt);
  validateIndexedMerkleProofV1(typed.transaction_proof);
  validateIndexedMerkleProofV1(typed.receipt_proof);

  if (checkpoint.checkpoint.header.chain_id !== requirements.chainId
    || typed.target_header.chain_id !== requirements.chainId) {
    throw new Error("finalized proof chain mismatch");
  }
  const targetHeight = proofU64(typed.target_header.height, "target height");
  if (targetHeight < proofU64(checkpoint.checkpoint.header.height, "checkpoint height")) {
    throw new Error("finalized proof target predates checkpoint");
  }
  if (typed.receipt.position.height !== typed.target_header.height) {
    throw new Error("receipt position height does not match target");
  }

  await verifyTargetAuthorityV1(typed, checkpoint, requirements.blocksPerEpoch);

  if (!(await verifySignedTransactionV5(typed.transaction, requirements.chainId))) {
    throw new Error("finalized proof transaction signature is invalid");
  }
  const validFrom = proofU64(typed.transaction.validity.valid_from_height, "valid-from height");
  const validUntil = proofU64(typed.transaction.validity.valid_until_height, "valid-until height");
  if (targetHeight < validFrom || targetHeight > validUntil) {
    throw new Error("finalized transaction is outside its signed validity window");
  }
  const transactionId = await transactionV5IdHex(typed.transaction);
  if (transactionId !== requirements.transactionId) {
    throw new Error("finalized proof returned another transaction");
  }
  if (typed.receipt.transaction_id !== transactionId) {
    throw new Error("finalized receipt names another transaction");
  }

  const transactionPath = validateIndexedMerkleProofV1(typed.transaction_proof);
  const receiptPath = validateIndexedMerkleProofV1(typed.receipt_proof);
  const expectedIndex = BigInt(typed.receipt.position.transaction_index);
  if (transactionPath.index !== expectedIndex || receiptPath.index !== expectedIndex
    || transactionPath.count !== receiptPath.count) {
    throw new Error("transaction and receipt Merkle positions do not match");
  }
  const transactionLeaf = await transactionV1LeafHex(typed.receipt.position, transactionId);
  if (typed.transaction_proof.leaf !== transactionLeaf) {
    throw new Error("finalized transaction leaf mismatch");
  }
  await verifyIndexedMerkleProofV1(typed.target_header.tx_root, typed.transaction_proof);

  const receiptLeaf = await receiptV1LeafHex(typed.receipt);
  if (typed.receipt_proof.leaf !== receiptLeaf) {
    throw new Error("finalized receipt leaf mismatch");
  }
  await verifyIndexedMerkleProofV1(typed.target_header.receipt_root, typed.receipt_proof);
  await verifyTransactionReceiptPairV1(typed.transaction, typed.receipt, transactionId);

  return Object.freeze({
    transactionId,
    position: Object.freeze({ ...typed.receipt.position }),
    blockHash: await blockHeaderV4HashHex(typed.target_header),
    checkpointDigest: checkpoint.digest,
  });
}

async function verifyTargetAuthorityV1(
  proof: FinalizedTransactionProofV1Json,
  checkpoint: ValidatedCheckpointV1,
  blocksPerEpoch: string,
): Promise<void> {
  const targetHeight = proofU64(proof.target_header.height, "target height");
  const checkpointHeight = proofU64(checkpoint.checkpoint.header.height, "checkpoint height");
  if (targetHeight === checkpointHeight) {
    if (proof.authority_transitions.length !== 0
      || !equalBlockHeaderV4(proof.target_header, checkpoint.checkpoint.header)) {
      throw new Error("same-height target does not reproduce checkpoint header");
    }
    await verifyTargetAuthoritySetAndCertificate(proof, proof.target_header.epoch);
    return;
  }

  let anchor = checkpointNextAnchorV1(checkpoint, blocksPerEpoch);
  for (const transition of proof.authority_transitions) {
    if (proofU64(transition.header.height, "transition height") >= targetHeight) {
      throw new Error("authority transition is at or after target");
    }
    anchor = await verifyAuthoritySetTransitionV1(transition, anchor);
  }
  if (targetHeight <= proofU64(anchor.minimumHeight, "anchor height")
    || proof.target_header.epoch !== anchor.epoch
    || proof.target_header.finality_authority_set_root !== anchor.authorityRoot) {
    throw new Error("target authority does not follow checkpoint transitions");
  }
  await verifyTargetAuthoritySetAndCertificate(proof, anchor.epoch);
}

async function verifyTargetAuthoritySetAndCertificate(
  proof: FinalizedTransactionProofV1Json,
  expectedEpoch: string,
): Promise<void> {
  validateFinalityAuthoritySetV1(proof.target_authority_set);
  if (proof.target_authority_set.chain_id !== proof.target_header.chain_id
    || proof.target_authority_set.epoch !== expectedEpoch) {
    throw new Error("target authority set domain mismatch");
  }
  if (await finalityAuthoritySetV1CommitmentHex(proof.target_authority_set)
      !== proof.target_header.finality_authority_set_root) {
    throw new Error("target authority commitment mismatch");
  }
  await verifyCertifiedHeaderV1(
    proof.target_header,
    proof.target_certificate,
    proof.target_authority_set,
  );
}

function validateFinalizedProofCollectionBounds(value: unknown): void {
  const proof = proofRecord(value, "finalized transaction proof");
  const transitions = proofArray(
    proof.authority_transitions,
    MAX_AUTHORITY_TRANSITIONS_V1,
    "authority transitions",
  );
  validateAuthorityAndCertificateCounts(
    proof.target_authority_set,
    proof.target_certificate,
    "target",
  );
  for (const [index, rawTransition] of transitions.entries()) {
    const transition = proofRecord(rawTransition, `authority transition ${index}`);
    validateAuthorityAndCertificateCounts(
      transition.outgoing_authority_set,
      transition.certificate,
      `outgoing transition ${index}`,
    );
    const incoming = proofRecord(
      transition.incoming_authority_set,
      `incoming transition authority set ${index}`,
    );
    proofArray(
      incoming.authorities,
      MAX_FINALITY_AUTHORITIES_V1,
      `incoming transition authorities ${index}`,
    );
  }
  for (const field of ["transaction_proof", "receipt_proof"] as const) {
    const merkle = proofRecord(proof[field], field);
    proofArray(merkle.siblings, MAX_INDEXED_MERKLE_SIBLINGS, `${field} siblings`);
  }
}

function validateAuthorityAndCertificateCounts(
  authorityValue: unknown,
  certificateValue: unknown,
  label: string,
): void {
  const authority = proofRecord(authorityValue, `${label} authority set`);
  proofArray(authority.authorities, MAX_FINALITY_AUTHORITIES_V1, `${label} authorities`);
  const certificate = proofRecord(certificateValue, `${label} certificate`);
  proofArray(certificate.precommits, MAX_FINALITY_AUTHORITIES_V1, `${label} certificate votes`);
}

function validateProofRequirements(requirements: FinalizedTransactionProofRequirementsV1): void {
  proofChainId(requirements.chainId, "proof requirement chain ID");
  proofHex(requirements.transactionId, 32, "requested transaction ID");
  if (proofU64(requirements.blocksPerEpoch, "blocks per epoch") === 0n) {
    throw new Error("blocks per epoch must be non-zero");
  }
}
