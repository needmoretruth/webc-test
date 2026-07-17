/** Browser session-subkey generation, id derivation, and expiry display. */

import { describe, expect, it } from "vitest";
import {
  describeSessionKeyExpiry,
  generateSessionSubkey,
  sessionSubkeyIdHex,
  sessionSubkeyPublicKeyHex,
} from "./session-key";
import { deriveSessionKeyIdHex } from "./transaction";

describe("session subkey", () => {
  it("generates a 32-byte subkey and derives its on-chain id", async () => {
    const subkey = await generateSessionSubkey();
    expect(subkey.publicKey).toHaveLength(32);

    const publicHex = sessionSubkeyPublicKeyHex(subkey);
    expect(publicHex).toMatch(/^[0-9a-f]{64}$/u);

    // The convenience id must equal deriving from the raw public key hex.
    expect(await sessionSubkeyIdHex(subkey)).toBe(
      await deriveSessionKeyIdHex(publicHex),
    );
  });

  it("generates distinct subkeys", async () => {
    const a = await generateSessionSubkey();
    const b = await generateSessionSubkey();
    expect(sessionSubkeyPublicKeyHex(a)).not.toBe(sessionSubkeyPublicKeyHex(b));
  });

  it("reports expiry relative to the current epoch", () => {
    // Usable well before expiry.
    expect(describeSessionKeyExpiry(3, 10)).toEqual({
      expired: false,
      remainingEpochs: 7,
      expiresAfterEpoch: 10,
    });
    // The expiry epoch itself is still usable (matches the node's use-time check).
    expect(describeSessionKeyExpiry(10, 10)).toEqual({
      expired: false,
      remainingEpochs: 0,
      expiresAfterEpoch: 10,
    });
    // One epoch past expiry the key is dead.
    expect(describeSessionKeyExpiry(11, 10)).toEqual({
      expired: true,
      remainingEpochs: 0,
      expiresAfterEpoch: 10,
    });
  });

  it("rejects invalid epoch inputs", () => {
    expect(() => describeSessionKeyExpiry(-1, 10)).toThrow();
    expect(() => describeSessionKeyExpiry(1, 1.5)).toThrow();
  });
});
