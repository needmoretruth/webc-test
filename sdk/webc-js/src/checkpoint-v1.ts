/**
 * Browser verification for protocol-2 checkpoints and authority transitions.
 *
 * Purpose: authenticate V4 headers under bounded Ed25519 finality authority
 * sets and advance one trusted authority anchor across exact epoch boundaries.
 * Responsibilities: strict hostile JSON shapes, domains, authority commitments,
 * vote signatures, unique voting power, checkpoint floors, and transition
 * adjacency. Non-responsibilities: fetching sources, choosing a trust policy,
 * replaying blocks, or checking transaction inclusion. Data flow: candidate
 * bytes validate into a checkpoint; each certified boundary consumes one anchor
 * and returns the next. Security boundary: count/byte/shape checks precede the
 * bounded signature loops and every chain, epoch, height, root, and hash is
 * compared to caller-supplied requirements.
 */

import { blockHeaderV4HashHex } from "./block.js";
import { canonicalJson, canonicalJsonBytes, canonicalJsonHashHex } from "./canonical.js";
import {
  finalityAuthoritySetV1CommitmentHex,
  MAX_FINALITY_AUTHORITIES_V1,
  validateFinalityAuthoritySetV1,
  type FinalityAuthoritySetV1Json,
} from "./finality-authority.js";
import { hexToBytes } from "./hex.js";
import {
  proofAddress,
  proofArray,
  proofChainId,
  proofExactKeys,
  proofHex,
  proofRecord,
  proofSafeU64Number,
  proofU32,
  proofU64,
  proofU128,
} from "./proof-json-v1.js";
import type { BlockHeaderV4Json, SignedVoteJson } from "./types.js";
import { verifyEd25519 } from "./wallet.js";

/** Checkpoint wire schema version. */
export const CHECKPOINT_V1 = 1;
/** Checkpoint digest domain shared with Rust. */
export const CHECKPOINT_V1_DOMAIN = "WEBC_CHECKPOINT_V1";
/** Authority transition wire schema version. */
export const AUTHORITY_SET_TRANSITION_V1 = 1;
/** Consensus vote signature domain shared with Rust. */
export const CONSENSUS_VOTE_V1_DOMAIN = "WEBC_CONSENSUS_VOTE_V1";
/** Maximum independently signed votes in one certificate. */
export const MAX_CONSENSUS_VOTES_PER_PROOF = 16_384;
/** Maximum UTF-8 bytes accepted for one checkpoint candidate. */
export const MAX_CHECKPOINT_V1_JSON_BYTES = 8 * 1024 * 1024;
/** Maximum UTF-8 bytes accepted for one standalone authority transition. */
export const MAX_AUTHORITY_SET_TRANSITION_V1_JSON_BYTES = 8 * 1024 * 1024;

/** Exact finality certificate JSON embedded in checkpoint/proof responses. */
export interface FinalityCertificateV1Json {
  protocol_version: 2;
  chain_id: string;
  height: number;
  round: number;
  block_hash: string;
  precommits: SignedVoteJson[];
}

/** Certified V4 weak-subjectivity checkpoint candidate. */
export interface CheckpointV1Json {
  version: 1;
  header: BlockHeaderV4Json;
  certificate: FinalityCertificateV1Json;
  authority_set: FinalityAuthoritySetV1Json;
}

/** Explicit caller-controlled floor for one candidate. */
export interface CheckpointRequirementsV1 {
  readonly chainId: string;
  readonly minimumHeight: string;
  readonly minimumEpoch: string;
}

/** Structurally and cryptographically valid checkpoint, not yet source-trusted. */
export interface ValidatedCheckpointV1 {
  readonly checkpoint: CheckpointV1Json;
  readonly digest: string;
}

/** Certified transition from one outgoing authority set to the next epoch. */
export interface AuthoritySetTransitionV1Json {
  version: 1;
  header: BlockHeaderV4Json;
  certificate: FinalityCertificateV1Json;
  outgoing_authority_set: FinalityAuthoritySetV1Json;
  incoming_authority_set: FinalityAuthoritySetV1Json;
}

/** Trusted root and position consumed by transition verification. */
export interface AuthorityTransitionAnchorV1 {
  readonly chainId: string;
  readonly authorityRoot: string;
  readonly epoch: string;
  readonly minimumHeight: string;
  readonly blocksPerEpoch: string;
}

/** Parses a bounded checkpoint JSON body and fully validates it. */
export async function decodeCheckpointV1(
  bytes: Uint8Array,
  requirements: CheckpointRequirementsV1,
): Promise<ValidatedCheckpointV1> {
  if (bytes.byteLength > MAX_CHECKPOINT_V1_JSON_BYTES) {
    throw new Error("checkpoint exceeds its 8 MiB limit");
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  return validateCheckpointV1(JSON.parse(text) as unknown, requirements);
}

/** Validates a candidate against an exact chain/height/epoch floor. */
export async function validateCheckpointV1(
  value: unknown,
  requirements: CheckpointRequirementsV1,
): Promise<ValidatedCheckpointV1> {
  validateCheckpointRequirements(requirements);
  const checkpoint = proofRecord(value, "V1 checkpoint");
  proofExactKeys(
    checkpoint,
    ["version", "header", "certificate", "authority_set"],
    "V1 checkpoint",
  );
  if (checkpoint.version !== CHECKPOINT_V1) throw new Error("unsupported checkpoint version");
  validateBlockHeaderV4(checkpoint.header);
  validateFinalityCertificateShape(checkpoint.certificate);
  validateFinalityAuthoritySetV1(checkpoint.authority_set);
  const typed = checkpoint as unknown as CheckpointV1Json;
  const canonical = canonicalJson(typed);
  if (new TextEncoder().encode(canonical).byteLength > MAX_CHECKPOINT_V1_JSON_BYTES) {
    throw new Error("checkpoint exceeds its 8 MiB limit");
  }
  // Own the exact checked bytes before any await. Host JavaScript can retain and
  // mutate the original object while WebCrypto yields to the event loop.
  const owned = JSON.parse(canonical) as CheckpointV1Json;
  if (owned.header.chain_id !== requirements.chainId) throw new Error("checkpoint chain mismatch");
  if (proofU64(owned.header.height, "checkpoint height")
      < proofU64(requirements.minimumHeight, "minimum checkpoint height")) {
    throw new Error("checkpoint is below the configured height floor");
  }
  if (proofU64(owned.header.epoch, "checkpoint epoch")
      < proofU64(requirements.minimumEpoch, "minimum checkpoint epoch")) {
    throw new Error("checkpoint is below the configured epoch floor");
  }
  await verifyAuthorityDomainV1(
    owned.authority_set,
    owned.header.chain_id,
    owned.header.epoch,
  );
  if (await finalityAuthoritySetV1CommitmentHex(owned.authority_set)
      !== owned.header.finality_authority_set_root) {
    throw new Error("checkpoint authority commitment mismatch");
  }
  await verifyCertifiedHeaderSnapshotV1(owned.header, owned.certificate, owned.authority_set);
  const digest = await canonicalJsonHashHex({ domain: CHECKPOINT_V1_DOMAIN, checkpoint: owned });
  deepFreeze(owned);
  return Object.freeze({ checkpoint: owned, digest });
}

/** Returns the authority anchor following a validated checkpoint. */
export function checkpointNextAnchorV1(
  checkpoint: ValidatedCheckpointV1,
  blocksPerEpoch: string,
): AuthorityTransitionAnchorV1 {
  const blockCount = proofU64(blocksPerEpoch, "blocks per epoch");
  if (blockCount === 0n) throw new Error("blocks per epoch must be non-zero");
  const header = checkpoint.checkpoint.header;
  const currentEpoch = proofU64(header.epoch, "checkpoint epoch");
  const nextEpoch = header.next_finality_authority_set_root
    === header.finality_authority_set_root ? currentEpoch : checkedNextU64(currentEpoch, "epoch");
  return Object.freeze({
    chainId: header.chain_id,
    authorityRoot: header.next_finality_authority_set_root,
    epoch: nextEpoch.toString(),
    minimumHeight: header.height,
    blocksPerEpoch,
  });
}

/** Verifies one adjacent certified epoch transition and advances the anchor. */
export async function verifyAuthoritySetTransitionV1(
  value: unknown,
  anchor: AuthorityTransitionAnchorV1,
): Promise<AuthorityTransitionAnchorV1> {
  validateAnchor(anchor);
  const transition = proofRecord(value, "V1 authority transition");
  proofExactKeys(
    transition,
    ["version", "header", "certificate", "outgoing_authority_set", "incoming_authority_set"],
    "V1 authority transition",
  );
  if (transition.version !== AUTHORITY_SET_TRANSITION_V1) {
    throw new Error("unsupported authority transition version");
  }
  validateBlockHeaderV4(transition.header);
  validateFinalityCertificateShape(transition.certificate);
  validateFinalityAuthoritySetV1(transition.outgoing_authority_set);
  validateFinalityAuthoritySetV1(transition.incoming_authority_set);
  const typed = transition as unknown as AuthoritySetTransitionV1Json;
  const canonical = canonicalJson(typed);
  if (new TextEncoder().encode(canonical).byteLength
      > MAX_AUTHORITY_SET_TRANSITION_V1_JSON_BYTES) {
    throw new Error("authority transition exceeds its 8 MiB limit");
  }
  const owned = JSON.parse(canonical) as AuthoritySetTransitionV1Json;
  const height = proofU64(owned.header.height, "transition height");
  const minimumHeight = proofU64(anchor.minimumHeight, "anchor minimum height");
  const blocksPerEpoch = proofU64(anchor.blocksPerEpoch, "anchor blocks per epoch");
  if (owned.header.chain_id !== anchor.chainId) throw new Error("transition chain mismatch");
  if (height <= minimumHeight) throw new Error("transition height did not increase");
  if (blocksPerEpoch === 0n || height % blocksPerEpoch !== 0n) {
    throw new Error("transition is not at an epoch boundary");
  }
  if (owned.header.epoch !== anchor.epoch) throw new Error("unexpected transition epoch");
  if (owned.header.finality_authority_set_root !== anchor.authorityRoot) {
    throw new Error("transition outgoing authority root mismatch");
  }
  await verifyAuthorityDomainV1(
    owned.outgoing_authority_set,
    anchor.chainId,
    anchor.epoch,
  );
  if (await finalityAuthoritySetV1CommitmentHex(owned.outgoing_authority_set)
      !== anchor.authorityRoot) {
    throw new Error("transition outgoing authority commitment mismatch");
  }
  const incomingEpoch = checkedNextU64(proofU64(anchor.epoch, "anchor epoch"), "epoch");
  await verifyAuthorityDomainV1(
    owned.incoming_authority_set,
    anchor.chainId,
    incomingEpoch.toString(),
  );
  const incomingRoot = await finalityAuthoritySetV1CommitmentHex(owned.incoming_authority_set);
  if (incomingRoot !== owned.header.next_finality_authority_set_root
      || incomingRoot === anchor.authorityRoot) {
    throw new Error("transition incoming authority commitment mismatch");
  }
  await verifyCertifiedHeaderSnapshotV1(
    owned.header,
    owned.certificate,
    owned.outgoing_authority_set,
  );
  return Object.freeze({
    chainId: anchor.chainId,
    authorityRoot: incomingRoot,
    epoch: incomingEpoch.toString(),
    minimumHeight: owned.header.height,
    blocksPerEpoch: anchor.blocksPerEpoch,
  });
}

/** Validates a V4 header's exact browser JSON representation. */
export function validateBlockHeaderV4(value: unknown): asserts value is BlockHeaderV4Json {
  const header = proofRecord(value, "V4 block header");
  proofExactKeys(header, [
    "protocol_version", "chain_id", "height", "epoch", "previous_hash", "state_root",
    "account_root", "tx_root", "receipt_root", "evidence_root",
    "finality_authority_set_root", "next_finality_authority_set_root", "proposer",
    "timestamp_ms", "base_fee_per_unit",
  ], "V4 block header");
  if (header.protocol_version !== 2) throw new Error("unsupported V4 header protocol version");
  proofChainId(header.chain_id, "V4 header chain ID");
  if (proofU64(header.height, "V4 header height") === 0n) {
    throw new Error("V4 header height must be non-zero");
  }
  proofU64(header.epoch, "V4 header epoch");
  for (const field of [
    "previous_hash", "state_root", "account_root", "tx_root", "receipt_root", "evidence_root",
  ] as const) proofHex(header[field], 32, `V4 header ${field}`);
  proofHex(header.finality_authority_set_root, 32, "current finality root", true);
  proofHex(header.next_finality_authority_set_root, 32, "next finality root", true);
  proofAddress(header.proposer, "V4 header proposer");
  proofU64(header.timestamp_ms, "V4 header timestamp");
  proofU64(header.base_fee_per_unit, "V4 header base fee");
}

/** Verifies a certificate over the exact header under `authoritySet`. */
export async function verifyCertifiedHeaderV1(
  header: BlockHeaderV4Json,
  certificate: FinalityCertificateV1Json,
  authoritySet: FinalityAuthoritySetV1Json,
): Promise<void> {
  validateBlockHeaderV4(header);
  validateFinalityCertificateShape(certificate);
  validateFinalityAuthoritySetV1(authoritySet);
  const snapshot = JSON.parse(canonicalJson({
    header,
    certificate,
    authority_set: authoritySet,
  })) as {
    header: BlockHeaderV4Json;
    certificate: FinalityCertificateV1Json;
    authority_set: FinalityAuthoritySetV1Json;
  };
  await verifyCertifiedHeaderSnapshotV1(
    snapshot.header,
    snapshot.certificate,
    snapshot.authority_set,
  );
}

async function verifyCertifiedHeaderSnapshotV1(
  header: BlockHeaderV4Json,
  certificate: FinalityCertificateV1Json,
  authoritySet: FinalityAuthoritySetV1Json,
): Promise<void> {
  await verifyAuthorityDomainV1(authoritySet, header.chain_id, header.epoch);
  if (await finalityAuthoritySetV1CommitmentHex(authoritySet)
      !== header.finality_authority_set_root) {
    throw new Error("certified header authority commitment mismatch");
  }
  if (certificate.protocol_version !== header.protocol_version
    || certificate.chain_id !== header.chain_id
    || BigInt(certificate.height) !== proofU64(header.height, "header height")) {
    throw new Error("certificate domain does not match header");
  }
  const headerHash = await blockHeaderV4HashHex(header);
  if (certificate.block_hash !== headerHash) throw new Error("certificate block hash mismatch");
  await verifyFinalityCertificateSnapshotV1(certificate, authoritySet);
}

/** Verifies every vote and strictly-over-two-thirds unique voting power. */
export async function verifyFinalityCertificateV1(
  certificate: FinalityCertificateV1Json,
  authoritySet: FinalityAuthoritySetV1Json,
): Promise<void> {
  validateFinalityCertificateShape(certificate);
  validateFinalityAuthoritySetV1(authoritySet);
  const snapshot = JSON.parse(canonicalJson({ certificate, authority_set: authoritySet })) as {
    certificate: FinalityCertificateV1Json;
    authority_set: FinalityAuthoritySetV1Json;
  };
  await verifyFinalityCertificateSnapshotV1(snapshot.certificate, snapshot.authority_set);
}

async function verifyFinalityCertificateSnapshotV1(
  certificate: FinalityCertificateV1Json,
  authoritySet: FinalityAuthoritySetV1Json,
): Promise<void> {
  if (certificate.chain_id !== authoritySet.chain_id
    || certificate.protocol_version !== authoritySet.protocol_version) {
    throw new Error("certificate authority domain mismatch");
  }
  const authorityByValidator = new Map(
    authoritySet.authorities.map((authority) => [authority.validator_id, authority] as const),
  );
  const seen = new Set<string>();
  let power = 0n;
  for (const signedVote of certificate.precommits) {
    const vote = signedVote.payload;
    if (vote.protocol_version !== certificate.protocol_version
      || vote.chain_id !== certificate.chain_id
      || vote.height !== certificate.height
      || vote.round !== certificate.round
      || vote.vote_type !== "Precommit"
      || vote.block_hash !== certificate.block_hash) {
      throw new Error("certificate vote does not match certificate");
    }
    if (seen.has(vote.validator)) throw new Error("certificate repeats a validator");
    const authority = authorityByValidator.get(vote.validator);
    if (authority === undefined) throw new Error("certificate vote is from a non-authority");
    const signingBytes = canonicalJsonBytes({ domain: CONSENSUS_VOTE_V1_DOMAIN, vote });
    if (!(await verifyEd25519(
      hexToBytes(authority.consensus_key),
      signingBytes,
      hexToBytes(signedVote.signature),
    ))) throw new Error("certificate vote signature is invalid");
    seen.add(vote.validator);
    power += proofU128(authority.voting_power, "authority voting power");
  }
  const total = proofU128(authoritySet.total_power, "authority total power");
  const threshold = total / 3n * 2n + (total % 3n * 2n) / 3n;
  if (total === 0n || power <= threshold) {
    throw new Error("certificate does not reach strict two-thirds quorum");
  }
}

function validateFinalityCertificateShape(
  value: unknown,
): asserts value is FinalityCertificateV1Json {
  const certificate = proofRecord(value, "finality certificate");
  proofExactKeys(
    certificate,
    ["protocol_version", "chain_id", "height", "round", "block_hash", "precommits"],
    "finality certificate",
  );
  if (certificate.protocol_version !== 2) throw new Error("unsupported certificate protocol");
  proofChainId(certificate.chain_id, "certificate chain ID");
  proofSafeU64Number(certificate.height, "certificate height");
  proofU32(certificate.round, "certificate round");
  proofHex(certificate.block_hash, 32, "certificate block hash");
  const precommits = proofArray(
    certificate.precommits,
    MAX_CONSENSUS_VOTES_PER_PROOF,
    "certificate precommits",
  );
  for (const rawSignedVote of precommits) {
    const signedVote = proofRecord(rawSignedVote, "signed consensus vote");
    proofExactKeys(signedVote, ["payload", "signature"], "signed consensus vote");
    proofHex(signedVote.signature, 64, "consensus vote signature");
    const vote = proofRecord(signedVote.payload, "consensus vote");
    proofExactKeys(
      vote,
      ["protocol_version", "chain_id", "height", "round", "vote_type", "block_hash", "validator"],
      "consensus vote",
    );
    if (vote.protocol_version !== 2) throw new Error("unsupported consensus vote protocol");
    proofChainId(vote.chain_id, "vote chain ID");
    proofSafeU64Number(vote.height, "vote height");
    proofU32(vote.round, "vote round");
    if (vote.vote_type !== "Prevote" && vote.vote_type !== "Precommit") {
      throw new Error("invalid consensus vote type");
    }
    proofHex(vote.block_hash, 32, "vote block hash");
    proofAddress(vote.validator, "vote validator");
  }
}

async function verifyAuthorityDomainV1(
  authoritySet: FinalityAuthoritySetV1Json,
  chainId: string,
  epoch: string,
): Promise<void> {
  validateFinalityAuthoritySetV1(authoritySet);
  if (authoritySet.chain_id !== chainId || authoritySet.epoch !== epoch) {
    throw new Error("authority set domain mismatch");
  }
  if (authoritySet.authorities.length > MAX_FINALITY_AUTHORITIES_V1) {
    throw new Error("authority set exceeds its item limit");
  }
}

function validateCheckpointRequirements(requirements: CheckpointRequirementsV1): void {
  proofChainId(requirements.chainId, "checkpoint requirement chain ID");
  proofU64(requirements.minimumHeight, "minimum checkpoint height");
  proofU64(requirements.minimumEpoch, "minimum checkpoint epoch");
}

function validateAnchor(anchor: AuthorityTransitionAnchorV1): void {
  proofChainId(anchor.chainId, "authority anchor chain ID");
  proofHex(anchor.authorityRoot, 32, "authority anchor root", true);
  proofU64(anchor.epoch, "authority anchor epoch");
  proofU64(anchor.minimumHeight, "authority anchor height");
  if (proofU64(anchor.blocksPerEpoch, "authority anchor block count") === 0n) {
    throw new Error("authority anchor blocks per epoch must be non-zero");
  }
}

function checkedNextU64(value: bigint, label: string): bigint {
  const next = value + 1n;
  if (next >= (1n << 64n)) throw new Error(`${label} is exhausted`);
  return next;
}

function deepFreeze(value: unknown): void {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return;
  for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  Object.freeze(value);
}

/** Returns exact canonical equality for two validated V4 headers. */
export function equalBlockHeaderV4(left: BlockHeaderV4Json, right: BlockHeaderV4Json): boolean {
  validateBlockHeaderV4(left);
  validateBlockHeaderV4(right);
  return canonicalJson(left) === canonicalJson(right);
}
