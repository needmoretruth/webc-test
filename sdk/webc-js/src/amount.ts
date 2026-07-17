/** Exact native WEBC amount helpers using JavaScript `bigint`. */

/** Confirmed number of decimal places in native WEBC. */
export const WEBC_DECIMALS = 12;
/** Exact number of base units in one WEBC. */
export const WEBC_UNIT = 1_000_000_000_000n;

/** Converts a non-negative whole-WEBC count to a wire-format base-unit string. */
export function amountFromWhole(whole: bigint): string {
  if (whole < 0n) throw new Error("WEBC amount cannot be negative");
  return (whole * WEBC_UNIT).toString(10);
}

/** Validates an unsigned decimal base-unit string without precision loss. */
export function amountFromUnits(units: string | bigint): string {
  const value = typeof units === "bigint" ? units : parseUnits(units);
  if (value < 0n) throw new Error("WEBC amount cannot be negative");
  return value.toString(10);
}

function parseUnits(units: string): bigint {
  if (!/^(0|[1-9][0-9]*)$/.test(units)) {
    throw new Error("base units must be a canonical unsigned decimal string");
  }
  return BigInt(units);
}
