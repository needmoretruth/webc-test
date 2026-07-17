/** Cross-language native amount reference vectors. */

import { describe, expect, it } from "vitest";
import { amountFromUnits, amountFromWhole, WEBC_DECIMALS } from "./amount";

describe("native WEBC amounts", () => {
  it("uses the confirmed twelve-decimal precision", () => {
    expect(WEBC_DECIMALS).toBe(12);
    expect(amountFromWhole(1n)).toBe("1000000000000");
    expect(amountFromWhole(10_000_000n)).toBe("10000000000000000000");
  });

  it("rejects non-canonical or negative base-unit strings", () => {
    expect(() => amountFromUnits("01")).toThrow("canonical");
    expect(() => amountFromUnits(-1n)).toThrow("negative");
  });
});
