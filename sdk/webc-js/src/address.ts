/**
 * Address derivation and base58 helpers shared with Rust `webc-crypto::address`.
 *
 * An address is a 32-byte SHA-256 commitment to a 32-byte Ed25519 public key
 * with a domain tag, rendered as a base58 string with a `webc1` prefix:
 *
 *   `webc1` || base58( SHA-256("WEBC_ADDRESS_V1" || public_key) )
 *
 * The base58 alphabet and prefix must match Rust exactly.
 */

const ADDRESS_PREFIX = "webc1";
const ADDRESS_DOMAIN = new TextEncoder().encode("WEBC_ADDRESS_V1");

/**
 * Derives the WEBC address for a 32-byte Ed25519 public key.
 */
export async function addressFromPublicKey(
  publicKey: Uint8Array,
): Promise<string> {
  if (publicKey.length !== 32) {
    throw new Error("Ed25519 public key must be 32 bytes");
  }
  const bytes = concatBytes(ADDRESS_DOMAIN, publicKey);
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", toArrayBuffer(bytes)),
  );
  return ADDRESS_PREFIX + base58Encode(digest);
}

/**
 * Decodes a `webc1...` address into its 32 raw bytes.
 */
export function addressToBytes(address: string): Uint8Array {
  if (!address.startsWith(ADDRESS_PREFIX)) {
    throw new Error("invalid WEBC address: missing webc1 prefix");
  }
  const encoded = address.slice(ADDRESS_PREFIX.length);
  const bytes = base58Decode(encoded);
  if (bytes.length !== 32) {
    throw new Error("invalid WEBC address: must decode to 32 bytes");
  }
  // A fixed byte string has exactly one base58 representation. Re-encoding
  // rejects alternate spellings before an address enters a signed/hash path.
  if (base58Encode(bytes) !== encoded) {
    throw new Error("invalid WEBC address: non-canonical base58 encoding");
  }
  return bytes;
}

/** Encodes an already-derived 32-byte account identifier as `webc1...`. */
export function addressFromBytes(bytes: Uint8Array): string {
  if (bytes.length !== 32) {
    throw new Error("WEBC address payload must be 32 bytes");
  }
  return ADDRESS_PREFIX + base58Encode(bytes);
}

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros += 1;
  if (zeros === bytes.length) return "1".repeat(zeros);

  const digits: number[] = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i += 1) {
      const value = digits[i] * 256 + carry;
      digits[i] = value % 58;
      carry = Math.floor(value / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  return (
    "1".repeat(zeros) +
    digits
      .reverse()
      .map((digit) => BASE58_ALPHABET[digit])
      .join("")
  );
}

function base58Decode(value: string): Uint8Array {
  let zeros = 0;
  while (zeros < value.length && value[zeros] === "1") zeros += 1;
  if (zeros === value.length) return new Uint8Array(zeros);

  const bytes: number[] = [0];
  for (const char of value) {
    const digit = BASE58_ALPHABET.indexOf(char);
    if (digit === -1) throw new Error("invalid base58 character");
    let carry = digit;
    for (let i = 0; i < bytes.length; i += 1) {
      const current = bytes[i] * 58 + carry;
      bytes[i] = current & 0xff;
      carry = current >> 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  return new Uint8Array([
    ...new Array<number>(zeros).fill(0),
    ...bytes.reverse(),
  ]);
}

function concatBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  const out = new Uint8Array(left.length + right.length);
  out.set(left, 0);
  out.set(right, left.length);
  return out;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
}
