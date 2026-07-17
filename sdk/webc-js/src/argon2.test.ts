/** Tests for the shared Argon2id derivation and its purpose separation (S3). */

import { describe, expect, it } from "vitest";
import { deriveArgon2idKey } from "./argon2";

describe("argon2id domain separation", () => {
  const password = new TextEncoder().encode("correct horse battery staple");
  const salt = new Uint8Array(16).fill(7);
  // Small but valid cost profile: this test exercises domain separation, not the
  // production hardening cost.
  const params = {
    memoryKib: 64,
    iterations: 1,
    parallelism: 1,
    dkLen: 32,
    maxMemoryBytes: 1 << 24,
  };
  const domainA = new TextEncoder().encode("webc-keystore-v1-encryption");
  const domainB = new TextEncoder().encode("webc-permission-store-v1-encryption");

  it("derives independent keys per purpose from the same password and salt (S3)", async () => {
    const a = await deriveArgon2idKey(password, salt, params, domainA);
    const b = await deriveArgon2idKey(password, salt, params, domainB);
    const aAgain = await deriveArgon2idKey(password, salt, params, domainA);
    // Different purpose labels must yield different keys, even from the identical
    // password and salt; the same purpose is deterministic.
    expect(a).not.toEqual(b);
    expect(a).toEqual(aAgain);
  });
});
