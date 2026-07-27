/**
 * Shared hostile-JSON guards for browser transparent-proof modules.
 *
 * Purpose: keep strict object shapes, canonical integers, hashes, chain IDs,
 * and addresses byte-identical across checkpoint, certificate, Merkle, and
 * finalized-proof validation. Responsibilities: cheap synchronous validation
 * only. Non-responsibilities: hashing, signatures, trust policy, networking,
 * or consensus decisions. Data flow: public proof validators call these guards
 * before allocating derived collections or doing cryptographic work. Security
 * boundary: unknown keys, unsafe JS numbers, non-canonical decimal strings,
 * malformed addresses, and oversized integer encodings fail closed.
 */

import { addressToBytes } from "./address.js";
import { hexToBytes } from "./hex.js";

const U64_MAX = (1n << 64n) - 1n;
const U128_MAX = (1n << 128n) - 1n;

export function proofRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

export function proofExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} has an unexpected field set`);
  }
}

export function proofChainId(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || value.length < 3 || value.length > 64
    || !/^[a-z][a-z0-9-]*$/u.test(value)) {
    throw new Error(`${label} is not a canonical chain ID`);
  }
}

export function proofAddress(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string") throw new Error(`${label} must be an address`);
  addressToBytes(value);
}

export function proofHex(
  value: unknown,
  bytes: number,
  label: string,
  nonZero = false,
): asserts value is string {
  if (typeof value !== "string" || value.length !== bytes * 2
    || value !== value.toLowerCase() || !/^[0-9a-f]+$/u.test(value)
    || (nonZero && value === "00".repeat(bytes))) {
    throw new Error(`${label} is not canonical ${bytes}-byte hex`);
  }
  hexToBytes(value);
}

export function proofU64(value: unknown, label: string): bigint {
  return proofUnsignedDecimal(value, 20, U64_MAX, label, "u64");
}

export function proofU128(value: unknown, label: string): bigint {
  return proofUnsignedDecimal(value, 39, U128_MAX, label, "u128");
}

function proofUnsignedDecimal(
  value: unknown,
  maximumDigits: number,
  maximum: bigint,
  label: string,
  typeName: string,
): bigint {
  if (typeof value !== "string" || value.length === 0
    || value.length > maximumDigits || !/^(0|[1-9][0-9]*)$/u.test(value)) {
    throw new Error(`${label} must be a canonical decimal ${typeName} string`);
  }
  const parsed = BigInt(value);
  if (parsed > maximum) throw new Error(`${label} exceeds ${typeName}`);
  return parsed;
}

export function proofSafeU64Number(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be an exact non-negative JavaScript integer`);
  }
  return value;
}

export function proofU32(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value)
    || value < 0 || value > 0xffff_ffff) {
    throw new Error(`${label} must be a u32`);
  }
  return value;
}

export function proofArray(value: unknown, maximum: number, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  if (value.length > maximum) throw new Error(`${label} exceeds its item limit`);
  return value;
}

export function compareAddressBytes(left: string, right: string): number {
  const leftBytes = addressToBytes(left);
  const rightBytes = addressToBytes(right);
  for (let index = 0; index < leftBytes.length; index += 1) {
    const difference = leftBytes[index] - rightBytes[index];
    if (difference !== 0) return difference;
  }
  return 0;
}
