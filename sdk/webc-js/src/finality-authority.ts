/**
 * Protocol-2 finality-authority commitment shared with Rust.
 *
 * This module owns the browser JSON shape and domain-separated hash only. Full
 * hostile-input validation and certificate verification land in the focused
 * finalized-proof verifier; no network or checkpoint trust is inferred here.
 */

import { canonicalJsonHashHex } from "./canonical.js";
import type { HexString, WebcAddress } from "./types.js";

/** Schema version of the first finality-authority set. */
export const FINALITY_AUTHORITY_SET_V1 = 1;

/** Independent commitment domain for authority sets. */
export const FINALITY_AUTHORITY_SET_V1_DOMAIN = "WEBC_FINALITY_AUTHORITY_SET_V1";

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
