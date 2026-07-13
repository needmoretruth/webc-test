/**
 * Cross-language replay hashes for objective evidence and bridge messages.
 *
 * These helpers reproduce Rust consensus identifiers but do not validate vote
 * signatures, bridge authorization, finality, or asset allowlists. Callers
 * must treat inputs as hostile and rely on the node's verification path before
 * accepting any state transition.
 */

import { canonicalJsonBytes, canonicalJsonHashHex } from "./canonical.js";
import { bytesToHex, concatBytes, toArrayBuffer } from "./hex.js";
import type { BridgeMessageJson, SlashingEvidenceJson } from "./types.js";

const DOUBLE_VOTE_DOMAIN = new TextEncoder().encode(
  "WEBC_DOUBLE_VOTE_EVIDENCE_V1",
);

/** Computes the Rust-compatible replay hash for one bridge message. */
export function bridgeMessageHashHex(
  message: BridgeMessageJson,
): Promise<string> {
  return canonicalJsonHashHex(message);
}

/** Computes the order-independent Rust replay hash for double-vote artifacts. */
export async function slashingEvidenceHashHex(
  evidence: SlashingEvidenceJson,
): Promise<string> {
  const first = canonicalJsonBytes(evidence.DoubleVote.first);
  const second = canonicalJsonBytes(evidence.DoubleVote.second);
  const [lower, upper] = compareBytes(first, second) <= 0
    ? [first, second]
    : [second, first];
  const payload = concatBytes([DOUBLE_VOTE_DOMAIN, lower, upper]);
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", toArrayBuffer(payload)),
  );
  return bytesToHex(digest);
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const common = Math.min(left.length, right.length);
  for (let index = 0; index < common; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.length - right.length;
}
