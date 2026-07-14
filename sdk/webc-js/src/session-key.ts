/**
 * Browser session-subkey helpers.
 *
 * A session key is an ordinary non-extractable Ed25519 keypair the wallet
 * generates and signs constrained transfers with, after the account owner
 * installs it with a post-quantum root signature (see `installSessionKey` in
 * `transaction.ts`). This module only creates the subkey and reports its
 * on-chain id and expiry status. It never holds the account's recovery root and
 * therefore cannot install or revoke a session key by itself — those critical
 * actions require the root signature, which is produced outside this SDK.
 *
 * Responsibilities: subkey generation, id derivation, and epoch-based expiry
 * display. Non-responsibilities: producing the post-quantum root reveal, signing
 * the install/revoke, and deciding constraint policy.
 */

import { bytesToHex } from "./hex.js";
import { deriveSessionKeyIdHex } from "./transaction.js";
import { createWallet, type WebcWallet } from "./wallet.js";

/**
 * Generates a fresh session subkey: a non-extractable Ed25519 wallet whose
 * private key stays in the trusted context. The owner installs its public key
 * (see `sessionSubkeyPublicKeyHex`) with `installSessionKey`; afterwards the
 * subkey signs transfers through the normal `signTransaction` flow.
 */
export async function generateSessionSubkey(): Promise<WebcWallet> {
  return createWallet();
}

/** Lowercase-hex 32-byte public key the owner installs as a session key. */
export function sessionSubkeyPublicKeyHex(subkey: WebcWallet): string {
  return bytesToHex(subkey.publicKey);
}

/**
 * Derives the on-chain session-key id for a subkey. Matches Rust
 * `SessionKeyId::derive`, so the id agrees with the node's state key.
 */
export function sessionSubkeyIdHex(subkey: WebcWallet): Promise<string> {
  return deriveSessionKeyIdHex(bytesToHex(subkey.publicKey));
}

/** Session-key expiry status relative to the current consensus epoch. */
export interface SessionKeyExpiryStatus {
  /** Whether the key can no longer authorize transactions at `currentEpoch`. */
  readonly expired: boolean;
  /** Whole epochs remaining before expiry; 0 when expired or on the last epoch. */
  readonly remainingEpochs: number;
  /** The absolute last epoch the key may be used. */
  readonly expiresAfterEpoch: number;
}

/**
 * Describes a session key's expiry. A key is usable while
 * `currentEpoch <= expiresAfterEpoch`; the node rejects it afterwards and prunes
 * it at the next epoch boundary. Epoch length is an unfixed protocol constant, so
 * this reports epochs and never converts to wall-clock time (which would be a
 * misleading, unmeasured claim).
 */
export function describeSessionKeyExpiry(
  currentEpoch: number,
  expiresAfterEpoch: number,
): SessionKeyExpiryStatus {
  if (!Number.isSafeInteger(currentEpoch) || currentEpoch < 0) {
    throw new Error("currentEpoch must be a non-negative safe integer");
  }
  if (!Number.isSafeInteger(expiresAfterEpoch) || expiresAfterEpoch < 0) {
    throw new Error("expiresAfterEpoch must be a non-negative safe integer");
  }
  const expired = currentEpoch > expiresAfterEpoch;
  const remainingEpochs = expired ? 0 : expiresAfterEpoch - currentEpoch;
  return { expired, remainingEpochs, expiresAfterEpoch };
}
