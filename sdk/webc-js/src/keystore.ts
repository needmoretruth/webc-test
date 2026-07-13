/**
 * Authenticated encrypted recovery-keystore v1 for the trusted wallet origin.
 *
 * This module encrypts validated BIP-39 recovery data with AES-256-GCM under an
 * Argon2id-derived key. It does not write browser storage, display passwords,
 * or expose decrypted recovery text from its unlock API. Every untrusted field
 * is bounded and validated before allocation or KDF work; authenticated public
 * metadata is bound as additional data so it cannot be swapped independently.
 */

import { argon2idAsync } from "@noble/hashes/argon2.js";
import { addressToBytes } from "./address.js";
import { canonicalJson, canonicalJsonBytes } from "./canonical.js";
import { bytesToHex, hexToBytes, toArrayBuffer } from "./hex.js";
import {
  MAX_MNEMONIC_PASSPHRASE_BYTES,
  createDevnetWalletFromMnemonic,
  isValidRecoveryMnemonic,
  webcDevnetDerivationPath,
} from "./wallet-derivation.js";
import type { WebcWallet } from "./wallet.js";

/** Exact keystore object version. Unknown versions fail closed. */
export const WEBC_KEYSTORE_VERSION = 1 as const;

/** Domain authenticated with all public keystore metadata. */
export const WEBC_KEYSTORE_AAD_DOMAIN = "WEBC_KEYSTORE_AAD_V1" as const;

/** Argon2id memory cost in KiB: OWASP's 19 MiB interactive profile. */
export const KEYSTORE_ARGON2_MEMORY_KIB = 19_456 as const;

/** Argon2id time cost in complete passes. */
export const KEYSTORE_ARGON2_ITERATIONS = 2 as const;

/** Argon2id lane count; one avoids device-dependent parallel scheduling. */
export const KEYSTORE_ARGON2_PARALLELISM = 1 as const;

/** Maximum UTF-8 password length accepted before KDF work. */
export const MAX_KEYSTORE_PASSWORD_BYTES = 1_024;

/** Minimum UTF-8 password length required when creating a new keystore. */
export const MIN_KEYSTORE_PASSWORD_BYTES = 12;

/** Maximum serialized v1 file length before JSON parsing. */
export const MAX_KEYSTORE_JSON_BYTES = 16_384;

const SALT_BYTES = 16;
const IV_BYTES = 12;
const AES_KEY_BYTES = 32;
const AES_GCM_TAG_BITS = 128;
const MAX_CIPHERTEXT_BYTES = 4_096;
const ARGON2_MAX_MEMORY_BYTES = 32 * 1_024 * 1_024;
const PAYLOAD_VERSION = 1;

/** Stable non-secret failure categories for keystore callers. */
export type KeystoreErrorCode =
  | "INVALID_SCHEMA"
  | "UNSUPPORTED_VERSION"
  | "INVALID_PASSWORD"
  | "AUTHENTICATION_FAILED";

/** Typed keystore error whose message never includes passwords or recovery data. */
export class KeystoreError extends Error {
  /** Machine-readable failure category. */
  readonly code: KeystoreErrorCode;

  constructor(code: KeystoreErrorCode, message: string) {
    super(message);
    this.name = "KeystoreError";
    this.code = code;
  }
}

/** Exact Argon2id parameters accepted by keystore v1. */
export interface KeystoreKdfV1 {
  readonly algorithm: "argon2id";
  /** RFC 9106 Argon2 version, decimal 19 (`0x13`). */
  readonly version: 19;
  /** Memory cost in kibibytes. */
  readonly memory_kib: typeof KEYSTORE_ARGON2_MEMORY_KIB;
  /** Time cost in complete passes. */
  readonly iterations: typeof KEYSTORE_ARGON2_ITERATIONS;
  /** Lane count. */
  readonly parallelism: typeof KEYSTORE_ARGON2_PARALLELISM;
  /** Unique 16-byte random salt encoded as lowercase hex. */
  readonly salt: string;
}

/** Exact authenticated-encryption parameters accepted by keystore v1. */
export interface KeystoreCipherV1 {
  readonly algorithm: "aes-256-gcm";
  /** Unique 12-byte random IV encoded as lowercase hex. */
  readonly iv: string;
  /** Authentication tag length in bits. */
  readonly tag_bits: 128;
  /** Ciphertext with its WebCrypto-appended GCM tag, lowercase hex. */
  readonly ciphertext: string;
}

/** Public derivation metadata authenticated as AES-GCM additional data. */
export interface KeystorePublicV1 {
  /** Expected V1 WEBC address recovered from the encrypted phrase. */
  readonly address: string;
  /** Expected 32-byte Ed25519 public key, lowercase hex. */
  readonly public_key: string;
  /** Named recovery derivation scheme; never inferred from the address. */
  readonly derivation: "bip39-slip10-ed25519-devnet-v1";
  /** Exact hardened path for account/index recovery. */
  readonly path: string;
}

/** Strict JSON-compatible encrypted recovery-keystore schema. */
export interface WebcKeystoreV1 {
  readonly format: "webc-keystore";
  readonly version: typeof WEBC_KEYSTORE_VERSION;
  readonly kdf: KeystoreKdfV1;
  readonly cipher: KeystoreCipherV1;
  readonly public: KeystorePublicV1;
}

/** Options stored inside the encrypted payload and authenticated public path. */
export interface EncryptKeystoreOptions {
  /** Hardened devnet account number in range 0..2^31-1. */
  readonly account?: number;
  /** Hardened devnet address index in range 0..2^31-1. */
  readonly index?: number;
  /** Optional BIP-39 passphrase encrypted inside the keystore. */
  readonly mnemonicPassphrase?: string;
}

interface KeystorePayloadV1 {
  readonly payload_version: 1;
  readonly mnemonic: string;
  readonly mnemonic_passphrase: string;
  readonly account: number;
  readonly index: number;
}

interface KeystoreAadV1 {
  readonly domain: typeof WEBC_KEYSTORE_AAD_DOMAIN;
  readonly format: "webc-keystore";
  readonly version: 1;
  readonly kdf: KeystoreKdfV1;
  readonly cipher: Omit<KeystoreCipherV1, "ciphertext">;
  readonly public: KeystorePublicV1;
}

/**
 * Encrypts recovery material into strict keystore v1.
 *
 * The password must encode to 12..1024 UTF-8 bytes and contain no unpaired
 * UTF-16 surrogate. The mnemonic and optional mnemonic passphrase are encrypted;
 * only the public address/key/path and fixed cryptographic parameters remain
 * visible. Fresh CSPRNG salt and IV values make repeated exports distinct.
 */
export async function encryptMnemonicKeystore(
  mnemonic: string,
  password: string,
  options: EncryptKeystoreOptions = {},
): Promise<WebcKeystoreV1> {
  if (!isValidRecoveryMnemonic(mnemonic)) {
    throw new KeystoreError("INVALID_SCHEMA", "recovery phrase is invalid");
  }
  const passwordBytes = encodePassword(password, true);
  try {
    return await encryptWithPasswordBytes(mnemonic, passwordBytes, options);
  } finally {
    passwordBytes.fill(0);
  }
}

async function encryptWithPasswordBytes(
  mnemonic: string,
  passwordBytes: Uint8Array,
  options: EncryptKeystoreOptions,
): Promise<WebcKeystoreV1> {
  const mnemonicPassphrase = options.mnemonicPassphrase ?? "";
  validateSecretString(
    mnemonicPassphrase,
    MAX_MNEMONIC_PASSPHRASE_BYTES,
    "mnemonic passphrase",
  );
  const account = options.account ?? 0;
  const index = options.index ?? 0;
  const path = webcDevnetDerivationPath(account, index);
  const wallet = await createDevnetWalletFromMnemonic(mnemonic, {
    account,
    index,
    passphrase: mnemonicPassphrase,
  });

  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const kdf = fixedKdf(bytesToHex(salt));
  const publicMetadata: KeystorePublicV1 = {
    address: wallet.address,
    public_key: bytesToHex(wallet.publicKey),
    derivation: "bip39-slip10-ed25519-devnet-v1",
    path,
  };
  const cipherMetadata: Omit<KeystoreCipherV1, "ciphertext"> = {
    algorithm: "aes-256-gcm",
    iv: bytesToHex(iv),
    tag_bits: AES_GCM_TAG_BITS,
  };
  const aad = aadBytes(kdf, cipherMetadata, publicMetadata);
  const payload: KeystorePayloadV1 = {
    payload_version: PAYLOAD_VERSION,
    mnemonic,
    mnemonic_passphrase: mnemonicPassphrase,
    account,
    index,
  };
  const plaintext = new TextEncoder().encode(canonicalJson(payload));

  let derivedKey: Uint8Array | undefined;
  try {
    derivedKey = await deriveEncryptionKey(passwordBytes, salt);
    const aesKey = await importAesKey(derivedKey, ["encrypt"]);
    const encrypted = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: toArrayBuffer(iv),
          additionalData: toArrayBuffer(aad),
          tagLength: AES_GCM_TAG_BITS,
        },
        aesKey,
        toArrayBuffer(plaintext),
      ),
    );
    if (encrypted.length > MAX_CIPHERTEXT_BYTES) {
      throw new KeystoreError(
        "INVALID_SCHEMA",
        "encrypted keystore payload exceeds the v1 limit",
      );
    }
    return {
      format: "webc-keystore",
      version: WEBC_KEYSTORE_VERSION,
      kdf,
      cipher: { ...cipherMetadata, ciphertext: bytesToHex(encrypted) },
      public: publicMetadata,
    };
  } finally {
    plaintext.fill(0);
    derivedKey?.fill(0);
  }
}

/**
 * Decrypts and verifies keystore v1, returning only an in-process wallet.
 *
 * Wrong passwords, ciphertext changes, and authenticated metadata changes share
 * one error code. Resource fields are validated against the exact v1 profile
 * before Argon2 work, preventing a malicious file from requesting unbounded
 * memory or iterations. The recovered public identity must match the metadata.
 */
export async function unlockMnemonicKeystore(
  input: unknown,
  password: string,
): Promise<WebcWallet> {
  const keystore = validateKeystore(input);
  const passwordBytes = encodePassword(password, false);
  try {
    return await unlockWithPasswordBytes(keystore, passwordBytes);
  } finally {
    passwordBytes.fill(0);
  }
}

async function unlockWithPasswordBytes(
  keystore: WebcKeystoreV1,
  passwordBytes: Uint8Array,
): Promise<WebcWallet> {
  const salt = decodeExactHex(keystore.kdf.salt, SALT_BYTES, "salt");
  const iv = decodeExactHex(keystore.cipher.iv, IV_BYTES, "IV");
  const ciphertext = decodeCiphertext(keystore.cipher.ciphertext);
  const cipherMetadata = {
    algorithm: keystore.cipher.algorithm,
    iv: keystore.cipher.iv,
    tag_bits: keystore.cipher.tag_bits,
  };
  const aad = aadBytes(keystore.kdf, cipherMetadata, keystore.public);

  let derivedKey: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    derivedKey = await deriveEncryptionKey(passwordBytes, salt);
    const aesKey = await importAesKey(derivedKey, ["decrypt"]);
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: toArrayBuffer(iv),
          additionalData: toArrayBuffer(aad),
          tagLength: AES_GCM_TAG_BITS,
        },
        aesKey,
        toArrayBuffer(ciphertext),
      ),
    );
    const payload = parsePayload(plaintext);
    const expectedPath = webcDevnetDerivationPath(
      payload.account,
      payload.index,
    );
    if (expectedPath !== keystore.public.path) {
      throw new Error("authenticated derivation path mismatch");
    }
    const wallet = await createDevnetWalletFromMnemonic(payload.mnemonic, {
      account: payload.account,
      index: payload.index,
      passphrase: payload.mnemonic_passphrase,
    });
    if (
      wallet.address !== keystore.public.address ||
      bytesToHex(wallet.publicKey) !== keystore.public.public_key
    ) {
      throw new Error("authenticated public identity mismatch");
    }
    return wallet;
  } catch {
    throw new KeystoreError(
      "AUTHENTICATION_FAILED",
      "wrong password or corrupted keystore",
    );
  } finally {
    ciphertext.fill(0);
    plaintext?.fill(0);
    derivedKey?.fill(0);
  }
}

/** Serializes a validated keystore with deterministic key ordering. */
export function serializeKeystore(keystore: WebcKeystoreV1): string {
  return canonicalJson(validateKeystore(keystore));
}

/** Parses a bounded JSON keystore and rejects unknown or ambiguous fields. */
export function parseKeystore(json: string): WebcKeystoreV1 {
  if (
    json.length > MAX_KEYSTORE_JSON_BYTES ||
    new TextEncoder().encode(json).length > MAX_KEYSTORE_JSON_BYTES
  ) {
    throw new KeystoreError("INVALID_SCHEMA", "keystore JSON is too large");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new KeystoreError("INVALID_SCHEMA", "keystore JSON is malformed");
  }
  return validateKeystore(parsed);
}

function validateKeystore(input: unknown): WebcKeystoreV1 {
  const root = exactRecord(input, ["format", "version", "kdf", "cipher", "public"]);
  if (root.format !== "webc-keystore") invalidSchema();
  if (root.version !== WEBC_KEYSTORE_VERSION) {
    throw new KeystoreError(
      "UNSUPPORTED_VERSION",
      "keystore version is unsupported",
    );
  }
  const kdf = exactRecord(root.kdf, [
    "algorithm",
    "version",
    "memory_kib",
    "iterations",
    "parallelism",
    "salt",
  ]);
  if (
    kdf.algorithm !== "argon2id" ||
    kdf.version !== 19 ||
    kdf.memory_kib !== KEYSTORE_ARGON2_MEMORY_KIB ||
    kdf.iterations !== KEYSTORE_ARGON2_ITERATIONS ||
    kdf.parallelism !== KEYSTORE_ARGON2_PARALLELISM ||
    typeof kdf.salt !== "string"
  ) {
    invalidSchema();
  }
  decodeExactHex(kdf.salt, SALT_BYTES, "salt");

  const cipher = exactRecord(root.cipher, [
    "algorithm",
    "iv",
    "tag_bits",
    "ciphertext",
  ]);
  if (
    cipher.algorithm !== "aes-256-gcm" ||
    cipher.tag_bits !== AES_GCM_TAG_BITS ||
    typeof cipher.iv !== "string" ||
    typeof cipher.ciphertext !== "string"
  ) {
    invalidSchema();
  }
  decodeExactHex(cipher.iv, IV_BYTES, "IV");
  decodeCiphertext(cipher.ciphertext);

  const publicMetadata = exactRecord(root.public, [
    "address",
    "public_key",
    "derivation",
    "path",
  ]);
  if (
    typeof publicMetadata.address !== "string" ||
    typeof publicMetadata.public_key !== "string" ||
    publicMetadata.derivation !== "bip39-slip10-ed25519-devnet-v1" ||
    typeof publicMetadata.path !== "string" ||
    publicMetadata.path.length > 128 ||
    publicMetadata.address.length > 64
  ) {
    invalidSchema();
  }
  decodeExactHex(publicMetadata.public_key, 32, "public key");
  try {
    addressToBytes(publicMetadata.address);
  } catch {
    invalidSchema();
  }
  validatePublicPath(publicMetadata.path);

  return {
    format: "webc-keystore",
    version: WEBC_KEYSTORE_VERSION,
    kdf: {
      algorithm: "argon2id",
      version: 19,
      memory_kib: KEYSTORE_ARGON2_MEMORY_KIB,
      iterations: KEYSTORE_ARGON2_ITERATIONS,
      parallelism: KEYSTORE_ARGON2_PARALLELISM,
      salt: kdf.salt,
    },
    cipher: {
      algorithm: "aes-256-gcm",
      iv: cipher.iv,
      tag_bits: AES_GCM_TAG_BITS,
      ciphertext: cipher.ciphertext,
    },
    public: {
      address: publicMetadata.address,
      public_key: publicMetadata.public_key,
      derivation: "bip39-slip10-ed25519-devnet-v1",
      path: publicMetadata.path,
    },
  };
}

function parsePayload(plaintext: Uint8Array): KeystorePayloadV1 {
  if (plaintext.length > MAX_CIPHERTEXT_BYTES) throw new Error("payload too large");
  const text = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  const record = exactRecord(JSON.parse(text), [
    "payload_version",
    "mnemonic",
    "mnemonic_passphrase",
    "account",
    "index",
  ]);
  if (
    record.payload_version !== PAYLOAD_VERSION ||
    typeof record.mnemonic !== "string" ||
    !isValidRecoveryMnemonic(record.mnemonic) ||
    typeof record.mnemonic_passphrase !== "string" ||
    typeof record.account !== "number" ||
    typeof record.index !== "number"
  ) {
    throw new Error("payload schema mismatch");
  }
  validateSecretString(
    record.mnemonic_passphrase,
    MAX_MNEMONIC_PASSPHRASE_BYTES,
    "mnemonic passphrase",
  );
  webcDevnetDerivationPath(record.account, record.index);
  return {
    payload_version: PAYLOAD_VERSION,
    mnemonic: record.mnemonic,
    mnemonic_passphrase: record.mnemonic_passphrase,
    account: record.account,
    index: record.index,
  };
}

function fixedKdf(salt: string): KeystoreKdfV1 {
  return {
    algorithm: "argon2id",
    version: 19,
    memory_kib: KEYSTORE_ARGON2_MEMORY_KIB,
    iterations: KEYSTORE_ARGON2_ITERATIONS,
    parallelism: KEYSTORE_ARGON2_PARALLELISM,
    salt,
  };
}

function aadBytes(
  kdf: KeystoreKdfV1,
  cipher: Omit<KeystoreCipherV1, "ciphertext">,
  publicMetadata: KeystorePublicV1,
): Uint8Array {
  const aad: KeystoreAadV1 = {
    domain: WEBC_KEYSTORE_AAD_DOMAIN,
    format: "webc-keystore",
    version: WEBC_KEYSTORE_VERSION,
    kdf,
    cipher,
    public: publicMetadata,
  };
  return canonicalJsonBytes(aad);
}

function encodePassword(password: string, creating: boolean): Uint8Array {
  validateSecretString(password, MAX_KEYSTORE_PASSWORD_BYTES, "password");
  const encoded = new TextEncoder().encode(password);
  if (creating && encoded.length < MIN_KEYSTORE_PASSWORD_BYTES) {
    encoded.fill(0);
    throw new KeystoreError(
      "INVALID_PASSWORD",
      "new keystore password must contain at least 12 UTF-8 bytes",
    );
  }
  return encoded;
}

function validateSecretString(value: string, maximum: number, label: string): void {
  if (hasUnpairedSurrogate(value)) {
    throw new KeystoreError(
      "INVALID_PASSWORD",
      `${label} contains invalid Unicode`,
    );
  }
  if (value.length > maximum || new TextEncoder().encode(value).length > maximum) {
    throw new KeystoreError(
      "INVALID_PASSWORD",
      `${label} exceeds the UTF-8 length limit`,
    );
  }
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      if (index + 1 >= value.length) return true;
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

let previousKdf = Promise.resolve();

async function deriveEncryptionKey(
  password: Uint8Array,
  salt: Uint8Array,
): Promise<Uint8Array> {
  // noble's async Argon2 uses a shared scratch block. Serialize calls so two
  // concurrent wallet requests cannot interleave and corrupt derived results.
  const waitFor = previousKdf;
  let release: (() => void) | undefined;
  previousKdf = new Promise<void>((resolve) => {
    release = resolve;
  });
  await waitFor;
  try {
    return await argon2idAsync(password, salt, {
      m: KEYSTORE_ARGON2_MEMORY_KIB,
      t: KEYSTORE_ARGON2_ITERATIONS,
      p: KEYSTORE_ARGON2_PARALLELISM,
      version: 0x13,
      dkLen: AES_KEY_BYTES,
      maxmem: ARGON2_MAX_MEMORY_BYTES,
      asyncTick: 10,
    });
  } finally {
    release?.();
  }
}

async function importAesKey(
  raw: Uint8Array,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    toArrayBuffer(raw),
    { name: "AES-GCM", length: 256 },
    false,
    usages,
  );
}

function decodeExactHex(value: string, bytes: number, label: string): Uint8Array {
  if (value.length !== bytes * 2 || value !== value.toLowerCase()) {
    throw new KeystoreError("INVALID_SCHEMA", `${label} length is invalid`);
  }
  try {
    return hexToBytes(value);
  } catch {
    throw new KeystoreError("INVALID_SCHEMA", `${label} encoding is invalid`);
  }
}

function decodeCiphertext(value: string): Uint8Array {
  if (
    value.length < (AES_GCM_TAG_BITS / 8) * 2 ||
    value.length > MAX_CIPHERTEXT_BYTES * 2 ||
    value !== value.toLowerCase()
  ) {
    throw new KeystoreError("INVALID_SCHEMA", "ciphertext length is invalid");
  }
  try {
    return hexToBytes(value);
  } catch {
    throw new KeystoreError("INVALID_SCHEMA", "ciphertext encoding is invalid");
  }
}

function validatePublicPath(path: string): void {
  const matched = /^m\/44'\/1'\/(0|[1-9]\d*)'\/0'\/(0|[1-9]\d*)'$/u.exec(path);
  if (!matched) invalidSchema();
  const account = Number(matched[1]);
  const index = Number(matched[2]);
  try {
    if (webcDevnetDerivationPath(account, index) !== path) invalidSchema();
  } catch {
    invalidSchema();
  }
}

function exactRecord(
  input: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (
    typeof input !== "object" ||
    input === null ||
    Array.isArray(input) ||
    Object.getPrototypeOf(input) !== Object.prototype
  ) {
    invalidSchema();
  }
  const record = input as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    invalidSchema();
  }
  return record;
}

function invalidSchema(): never {
  throw new KeystoreError("INVALID_SCHEMA", "keystore schema is invalid");
}
