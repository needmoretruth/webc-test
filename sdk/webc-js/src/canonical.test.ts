/** Cross-language encoding regression tests for browser-visible values. */

import { describe, expect, it } from "vitest";
import { canonicalJson } from "./canonical";

describe("canonicalJson", () => {
  it("sorts nested object keys without changing array order", () => {
    expect(canonicalJson({ z: [3, 2, 1], a: { y: true, x: "ok" } })).toBe(
      '{"a":{"x":"ok","y":true},"z":[3,2,1]}',
    );
  });

  it("rejects floats, non-finite values, and imprecise integers", () => {
    expect(() => canonicalJson({ invalid: Number.POSITIVE_INFINITY })).toThrow(
      "safe integers",
    );
    expect(() => canonicalJson({ invalid: 1.5 })).toThrow("safe integers");
    expect(() => canonicalJson({ invalid: Number.MAX_SAFE_INTEGER + 1 })).toThrow(
      "safe integers",
    );
  });
});
