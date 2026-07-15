/**
 * Shared Argon2id key derivation with a single process-wide serialization gate.
 *
 * This module owns the only call site for noble's async Argon2id in the SDK.
 * noble's `argon2idAsync` uses a shared internal scratch block, so two
 * concurrent derivations can interleave and corrupt each other's output. Every
 * password-hardening consumer (recovery keystore, encrypted permission store)
 * derives through here so all derivations across the whole SDK are serialized by
 * one gate rather than one gate per module — two independent gates would not
 * protect against cross-module concurrency.
 *
 * This module holds no secrets beyond the transient derived key it returns to
 * the caller; it does not log, serialize, or persist any input or output.
 */

import { argon2idAsync } from "@noble/hashes/argon2.js";

/** Exact Argon2id cost profile a consumer must pass for every derivation. */
export interface Argon2idParams {
  /** Memory cost in kibibytes. */
  readonly memoryKib: number;
  /** Time cost in complete passes. */
  readonly iterations: number;
  /** Lane count; consumers use one to avoid device-dependent scheduling. */
  readonly parallelism: number;
  /** Derived-key length in bytes. */
  readonly dkLen: number;
  /** Hard upper bound on memory noble may allocate, in bytes. */
  readonly maxMemoryBytes: number;
}

// One shared gate for the entire module. Each derivation waits for the previous
// one to finish before touching noble's shared scratch block, then releases the
// next waiter in its `finally`. This preserves arrival order and never deadlocks
// because the release runs even if the derivation throws.
let previousDerivation: Promise<void> = Promise.resolve();

/**
 * Derives an Argon2id key, serialized against every other SDK derivation.
 *
 * Inputs are treated as secret: the password bytes are consumed but not copied
 * or retained here, and the caller owns clearing them. The returned key is a
 * fresh buffer the caller must clear after importing it. Uses Argon2 version
 * `0x13` (RFC 9106, decimal 19) with the supplied cost profile.
 */
export async function deriveArgon2idKey(
  password: Uint8Array,
  salt: Uint8Array,
  params: Argon2idParams,
): Promise<Uint8Array> {
  const waitFor = previousDerivation;
  let release: (() => void) | undefined;
  previousDerivation = new Promise<void>((resolve) => {
    release = resolve;
  });
  await waitFor;
  try {
    return await argon2idAsync(password, salt, {
      m: params.memoryKib,
      t: params.iterations,
      p: params.parallelism,
      version: 0x13,
      dkLen: params.dkLen,
      maxmem: params.maxMemoryBytes,
      asyncTick: 10,
    });
  } finally {
    release?.();
  }
}
