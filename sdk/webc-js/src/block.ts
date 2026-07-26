/**
 * Versioned browser helpers for authoritative WEBC block headers.
 *
 * This module hashes an already parsed header but does not decide whether its
 * state roots, proposer, timestamp, or finality are valid. Callers must obtain
 * those guarantees from verified consensus data. The wire field names remain
 * snake_case so canonical bytes exactly match Rust serialization.
 */

import { canonicalJsonHashHex } from "./canonical.js";
import type { BlockHeaderJson, BlockHeaderV4Json, HexString } from "./types.js";

/** Domain separator for the PoH-free authoritative block-header schema. */
export const BLOCK_HEADER_DOMAIN = "WEBC_BLOCK_HEADER_V3";

/** Domain separator for protocol-2 V4 block headers. */
export const BLOCK_HEADER_V4_DOMAIN = "WEBC_BLOCK_HEADER_V4";

/**
 * Computes the SHA-256 block identifier committed and signed by validators.
 *
 * The input uses exact Rust wire names and integer units: `height` and `epoch`
 * are consensus counters, `timestamp_ms` is Unix milliseconds supplied by
 * consensus, and `base_fee_per_unit` is native base units per execution unit.
 */
export function blockHeaderHashHex(
  header: BlockHeaderJson,
): Promise<HexString> {
  return canonicalJsonHashHex({ domain: BLOCK_HEADER_DOMAIN, header });
}

/** Computes the exact protocol-2 V4 header identifier verified by Rust. */
export function blockHeaderV4HashHex(
  header: BlockHeaderV4Json,
): Promise<HexString> {
  return canonicalJsonHashHex({ domain: BLOCK_HEADER_V4_DOMAIN, header });
}
