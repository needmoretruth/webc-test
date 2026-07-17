/**
 * Canonical JSON encoder that matches Rust `webc-chain::canonical`.
 *
 * The whole WEBC cross-language story depends on this function: when the
 * browser wants to sign a transaction, it must produce the exact same bytes
 * Rust would. We use a tiny deterministic JSON variant:
 *
 * 1. Object keys are sorted in UTF-8 byte order. The browser SDK only ever
 *    signs ASCII key names (field names from the Rust schema), so JS
 *    `Array.prototype.sort` (UTF-16 code unit order) yields the same order
 *    as Rust's byte comparison. Non-ASCII keys would need a real UTF-8 sort,
 *    but the WEBC signing schema has none.
 * 2. No insignificant whitespace.
 * 3. Strings are encoded per RFC 8259 (handled by `JSON.stringify`).
 * 4. Numbers must be safe integers. Floating point, infinity, and integers
 *    outside JavaScript's exact range are rejected before signing.
 *
 * The Rust side runs the value through `serde_json::to_value` first, which
 * normalizes Rust struct field declaration order. This function sorts keys
 * recursively, so the order of properties on a TS object does not matter.
 *
 * Keep this file small and dependency-free — it is the trust root of the SDK.
 */

/** Recursive canonical stringifier. Sorts keys, no whitespace. */
export function canonicalJson(value: unknown): string {
  return encode(canonicalize(value));
}

/** Canonical JSON bytes (UTF-8 of the canonical string). */
export function canonicalJsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJson(value));
}

/** SHA-256 hex digest of the canonical JSON bytes. */
export async function canonicalJsonHashHex(value: unknown): Promise<string> {
  const bytes = canonicalJsonBytes(value);
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", toArrayBuffer(bytes)),
  );
  return bytesToHex(digest);
}

/** Normalizes a value into a canonical form (sorted keys, ordered arrays). */
function canonicalize(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort(/* by UTF-16 code unit, which is */ undefined);
  const sorted: Record<string, unknown> = {};
  for (const key of keys) {
    sorted[key] = canonicalize(record[key]);
  }
  return sorted;
}

function encode(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value.toString();
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new Error("canonical JSON numbers must be safe integers");
    }
    return Number.prototype.toString.call(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(encode).join(",")}]`;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort(/* same as above */ undefined);
    const parts = keys.map(
      (key) => `${JSON.stringify(key)}:${encode(record[key])}`,
    );
    return `{${parts.join(",")}}`;
  }
  throw new Error(`canonical JSON: unsupported type ${typeof value}`);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
