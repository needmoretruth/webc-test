/** Small hex helpers used across all SDK modules. */

/** Lowercase hex string from raw bytes. */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

/** Raw bytes from a lowercase-or-uppercase hex string. */
export function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.toLowerCase();
  if (normalized.length % 2 !== 0) {
    throw new Error("hex string must have even length");
  }
  if (!/^[0-9a-f]*$/u.test(normalized)) {
    throw new Error("invalid hex string");
  }
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const byte = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
    out[i] = byte;
  }
  return out;
}

/** Big-endian byte arrays for the integer helpers used by proof verification. */
export function u64ToBytes(value: bigint): Uint8Array {
  return unsignedBigIntToBytes(value, 8, "u64");
}

export function u128ToBytes(value: bigint): Uint8Array {
  return unsignedBigIntToBytes(value, 16, "u128");
}

function unsignedBigIntToBytes(
  value: bigint,
  length: number,
  label: string,
): Uint8Array {
  if (value < 0n) throw new Error(`${label} cannot be negative`);
  const out = new Uint8Array(length);
  let remaining = value;
  for (let i = length - 1; i >= 0; i -= 1) {
    out[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) throw new Error(`${label} is too large`);
  return out;
}

/** Concatenates multiple byte arrays into one. */
export function concatBytes(chunks: Uint8Array[]): Uint8Array {
  const length = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/** Returns a fresh ArrayBuffer view sliced from `bytes`. */
export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
}
