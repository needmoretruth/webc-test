/**
 * Replaceable browser trust policies for first checkpoint candidates.
 *
 * Purpose: accept one source-corroborated checkpoint without coupling proof
 * verification to specific URLs or publishers. Responsibilities: configured
 * source identity bounds, explicit availability observations, validation of
 * every candidate, exact digest agreement, and visible explicit-operator trust.
 * Non-responsibilities: HTTP/authentication adapters, source discovery, claims
 * of operational independence, or final transaction proof verification. Data
 * flow: adapters record one result per configured identity; a policy returns a
 * validated checkpoint plus a durable trust label. Security boundary: omitted,
 * duplicated, unconfigured, invalid, stale, wrong-chain, or disagreeing input
 * stops instead of silently lowering trust.
 */

import {
  validateCheckpointV1,
  type CheckpointRequirementsV1,
  type CheckpointV1Json,
  type ValidatedCheckpointV1,
} from "./checkpoint-v1.js";

/** Maximum configured sources/observations, matching Rust. */
export const MAX_CHECKPOINT_SOURCES_V1 = 64;
/** Maximum ASCII bytes in one configured source identity. */
export const MAX_SOURCE_IDENTITY_V1_BYTES = 128;
/** Maximum printable ASCII bytes in one explicit operator label. */
export const MAX_OPERATOR_TRUST_LABEL_V1_BYTES = 128;

/** Candidate or explicit bounded retrieval failure from one configured source. */
export type CheckpointSourceResultV1 =
  | { readonly kind: "candidate"; readonly candidate: CheckpointV1Json }
  | { readonly kind: "unavailable" };

/** One result for one preconfigured source identity. */
export interface CheckpointSourceObservationV1 {
  readonly source: string;
  readonly result: CheckpointSourceResultV1;
}

/** Visible policy output retained with the accepted checkpoint. */
export type CheckpointTrustLabelV1 =
  | {
      readonly kind: "quorum_agreement_v1";
      readonly requiredAgreements: number;
      readonly observedAgreements: number;
    }
  | {
      readonly kind: "explicit_operator_trust_v1";
      readonly label: string;
    };

/** Accepted checkpoint plus deterministic source and trust metadata. */
export interface AcceptedCheckpointV1 {
  readonly checkpoint: ValidatedCheckpointV1;
  readonly trust: CheckpointTrustLabelV1;
  readonly agreeingSources: readonly string[];
}

/** Accepts exact agreement from a threshold of configured distinct sources. */
export async function acceptCheckpointQuorumV1(
  configuredSources: readonly string[],
  requiredAgreements: number,
  observations: readonly CheckpointSourceObservationV1[],
  requirements: CheckpointRequirementsV1,
): Promise<AcceptedCheckpointV1> {
  validateQuorumConfiguration(configuredSources, requiredAgreements);
  if (observations.length > MAX_CHECKPOINT_SOURCES_V1) {
    throw new Error("checkpoint observations exceed their source limit");
  }
  const configured = new Set(configuredSources);
  const observed = new Set<string>();
  for (const observation of observations) {
    validateSourceIdentityV1(observation.source);
    if (!configured.has(observation.source)) throw new Error("unconfigured checkpoint source");
    if (observed.has(observation.source)) throw new Error("duplicate checkpoint source observation");
    observed.add(observation.source);
  }
  for (const source of configuredSources) {
    if (!observed.has(source)) throw new Error(`missing checkpoint source observation: ${source}`);
  }

  let accepted: ValidatedCheckpointV1 | undefined;
  const agreeingSources: string[] = [];
  for (const observation of observations) {
    if (observation.result.kind === "unavailable") continue;
    const validated = await validateCheckpointV1(observation.result.candidate, requirements);
    if (accepted !== undefined && validated.digest !== accepted.digest) {
      throw new Error("configured checkpoint sources disagree");
    }
    accepted ??= validated;
    agreeingSources.push(observation.source);
  }
  if (agreeingSources.length < requiredAgreements || accepted === undefined) {
    throw new Error("insufficient available checkpoint agreement");
  }
  agreeingSources.sort();
  return Object.freeze({
    checkpoint: accepted,
    trust: Object.freeze({
      kind: "quorum_agreement_v1" as const,
      requiredAgreements,
      observedAgreements: agreeingSources.length,
    }),
    agreeingSources: Object.freeze(agreeingSources),
  });
}

/** Accepts one deliberately named operator input and labels it permanently. */
export async function acceptExplicitOperatorCheckpointV1(
  configuredSource: string,
  label: string,
  observation: CheckpointSourceObservationV1,
  requirements: CheckpointRequirementsV1,
): Promise<AcceptedCheckpointV1> {
  validateSourceIdentityV1(configuredSource);
  validateOperatorTrustLabelV1(label);
  validateSourceIdentityV1(observation.source);
  if (observation.source !== configuredSource) throw new Error("unexpected explicit checkpoint source");
  if (observation.result.kind === "unavailable") {
    throw new Error("explicitly trusted checkpoint source is unavailable");
  }
  const checkpoint = await validateCheckpointV1(observation.result.candidate, requirements);
  return Object.freeze({
    checkpoint,
    trust: Object.freeze({ kind: "explicit_operator_trust_v1" as const, label }),
    agreeingSources: Object.freeze([configuredSource]),
  });
}

/** Validates one local source label; discovery never calls this implicitly. */
export function validateSourceIdentityV1(value: string): void {
  if (value.length === 0 || value.length > MAX_SOURCE_IDENTITY_V1_BYTES
    || !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/u.test(value)) {
    throw new Error("invalid checkpoint source identity");
  }
}

/** Validates a trimmed non-empty printable-ASCII operator label. */
export function validateOperatorTrustLabelV1(value: string): void {
  if (value.length === 0 || value.length > MAX_OPERATOR_TRUST_LABEL_V1_BYTES
    || value.trim() !== value || !/^[\x20-\x7e]+$/u.test(value)) {
    throw new Error("invalid explicit operator trust label");
  }
}

function validateQuorumConfiguration(
  configuredSources: readonly string[],
  requiredAgreements: number,
): void {
  if (configuredSources.length < 2 || configuredSources.length > MAX_CHECKPOINT_SOURCES_V1) {
    throw new Error("checkpoint quorum requires 2..=64 configured sources");
  }
  if (!Number.isInteger(requiredAgreements) || requiredAgreements < 2
    || requiredAgreements > configuredSources.length) {
    throw new Error("invalid checkpoint agreement threshold");
  }
  const distinct = new Set<string>();
  for (const source of configuredSources) {
    validateSourceIdentityV1(source);
    if (distinct.has(source)) throw new Error("configured checkpoint sources must be distinct");
    distinct.add(source);
  }
}

