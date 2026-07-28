/**
 * Rust/browser parity and malformed-input tests for WEBC account addresses.
 *
 * These tests freeze fixed base58 vectors. They do not derive keys or validate
 * account authorization; those responsibilities live in the crypto boundary.
 */

import { describe, expect, it } from "vitest";
import { addressFromBytes, addressToBytes } from "./address";

const PREFIX = "webc1";

describe("WEBC address base58 parity", () => {
  it("round-trips the Rust all-zero address without an extra base58 zero", () => {
    const bytes = new Uint8Array(32);
    const encoded = `${PREFIX}${"1".repeat(32)}`;

    expect(addressFromBytes(bytes)).toBe(encoded);
    expect(addressToBytes(encoded)).toEqual(bytes);
  });

  it("preserves multiple leading zero bytes before a non-zero payload", () => {
    const bytes = new Uint8Array(32);
    bytes[31] = 1;
    const encoded = `${PREFIX}${"1".repeat(31)}2`;

    expect(addressFromBytes(bytes)).toBe(encoded);
    expect(addressToBytes(encoded)).toEqual(bytes);
  });

  it("rejects a non-canonical extra leading base58 zero", () => {
    expect(() => addressToBytes(`${PREFIX}${"1".repeat(33)}`)).toThrow(/32 bytes/u);
  });
});
