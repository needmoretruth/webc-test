/**
 * Protocol-2 finality-authority commitment shared with Rust.
 *
 * This module owns the browser JSON shape and domain-separated hash only. Full
 * hostile-input validation and certificate verification land in the focused
 * finalized-proof verifier; no network or checkpoint trust is inferred here.
 */

import { canonicalJsonHashHex } from "./canonical.js";
import {
  compareAddressBytes,
  proofAddress,
  proofArray,
  proofChainId,
  proofExactKeys,
  proofHex,
  proofRecord,
  proofU128,
  proofU64,
} from "./proof-json-v1.js";
import type { HexString, WebcAddress } from "./types.js";

/** Schema version of the first finality-authority set. */
export const FINALITY_AUTHORITY_SET_V1 = 1;

/** Independent commitment domain for authority sets. */
export const FINALITY_AUTHORITY_SET_V1_DOMAIN = "WEBC_FINALITY_AUTHORITY_SET_V1";
/** Absolute Rust/browser authority-entry cap. */
export const MAX_FINALITY_AUTHORITIES_V1 = 16_384;

/** One authority entry in strict validator-ID order. */
export interface FinalityAuthorityV1Json {
  /** Stable validator operator identity. */
  validator_id: WebcAddress;
  /** Ed25519 consensus public key as 32-byte lowercase hex. */
  consensus_key: HexString;
  /** Non-zero snapshot voting power in native base units. */
  voting_power: string;
}

/** Exact protocol-2 authority set committed by a V4 header. */
export interface FinalityAuthoritySetV1Json {
  /** Must equal 1. */
  version: 1;
  /** Must equal 2. */
  protocol_version: 2;
  /** Genesis-fixed chain identifier. */
  chain_id: string;
  /** Snapshot epoch as an exact decimal string. */
  epoch: string;
  /** Strictly sorted, unique authorities. */
  authorities: FinalityAuthorityV1Json[];
  /** Checked sum of authority voting power. */
  total_power: string;
}

/** Computes the authority-set commitment placed in V4 headers. */
export function finalityAuthoritySetV1CommitmentHex(
  authoritySet: FinalityAuthoritySetV1Json,
): Promise<HexString> {
  return canonicalJsonHashHex({
    domain: FINALITY_AUTHORITY_SET_V1_DOMAIN,
    authority_set: authoritySet,
  });
}

/** Validates the complete bounded authority set before certificate work. */
export function validateFinalityAuthoritySetV1(
  value: unknown,
): asserts value is FinalityAuthoritySetV1Json {
  const set = proofRecord(value, "V1 finality authority set");
  proofExactKeys(
    set,
    ["version", "protocol_version", "chain_id", "epoch", "authorities", "total_power"],
    "V1 finality authority set",
  );
  if (set.version !== FINALITY_AUTHORITY_SET_V1 || set.protocol_version !== 2) {
    throw new Error("unsupported V1 finality authority set version");
  }
  proofChainId(set.chain_id, "authority chain ID");
  proofU64(set.epoch, "authority epoch");
  const authorities = proofArray(
    set.authorities,
    MAX_FINALITY_AUTHORITIES_V1,
    "finality authorities",
  );
  if (authorities.length === 0) throw new Error("finality authority set must not be empty");

  let previousValidator: string | undefined;
  let total = 0n;
  const consensusKeys = new Set<string>();
  for (const rawAuthority of authorities) {
    const authority = proofRecord(rawAuthority, "V1 finality authority");
    proofExactKeys(
      authority,
      ["validator_id", "consensus_key", "voting_power"],
      "V1 finality authority",
    );
    proofAddress(authority.validator_id, "authority validator ID");
    proofHex(authority.consensus_key, 32, "authority consensus key");
    const power = proofU128(authority.voting_power, "authority voting power");
    if (power === 0n) throw new Error("authority voting power must be non-zero");
    if (previousValidator !== undefined
      && compareAddressBytes(previousValidator, authority.validator_id) >= 0) {
      throw new Error("finality authorities are not strictly sorted");
    }
    previousValidator = authority.validator_id;
    if (consensusKeys.has(authority.consensus_key)) {
      throw new Error("finality authorities reuse a consensus key");
    }
    consensusKeys.add(authority.consensus_key);
    total += power;
    if (total >= (1n << 128n)) throw new Error("finality authority power overflows u128");
  }
  if (total !== proofU128(set.total_power, "authority total power")) {
    throw new Error("finality authority total power mismatch");
  }
}
