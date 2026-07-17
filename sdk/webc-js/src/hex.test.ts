/** Malformed-input tests for shared hexadecimal wire decoding. */

import { describe, expect, it } from "vitest";
import { bytesToHex, hexToBytes } from "./hex";

describe("hex codec", () => {
  it("round-trips valid mixed-case input", () => {
    expect(bytesToHex(hexToBytes("00aAFf"))).toBe("00aaff");
  });

  it("rejects partial and non-hex byte pairs", () => {
    expect(() => hexToBytes("0g")).toThrow("invalid hex");
    expect(() => hexToBytes("-1")).toThrow("invalid hex");
    expect(() => hexToBytes("abc")).toThrow("even length");
  });
});
