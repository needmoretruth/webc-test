/**
 * Authenticated encrypted permission store v1 for the trusted wallet origin.
 *
 * This module persists the trusted wallet's per-origin authorization grants —
 * the assigned lane, approved scopes, spend limits, and cumulative spent amount —
 * encrypted at rest with AES-256-GCM under an Argon2id-derived key. It is the
 * durable backing for `TrustedWalletService`, whose grants were previously
 * in-memory only and lost on wallet restart.
 *
 * Security boundary and non-responsibilities:
 * - It holds no signing key or recovery phrase; grants are public routing and
 *   budget metadata, not secrets that authorize spending on their own.
 * - It never reads or writes browser storage itself. The caller supplies a
 *   `write` backend (localStorage, IndexedDB, a file) and the already-read
 *   serialized bytes, so this module stays deterministic and testable.
 * - The store is bound to one wallet identity (address + public key) as
 *   authenticated additional data, so one wallet's store cannot be loaded as
 *   another's, and a tampered store fails authentication rather than silently
 *   granting altered limits or lanes.
 * - The cumulative `spent_amount` persists across reconnects. Only an explicit
 *   user-confirmed revoke removes a grant, so a hostile host cannot reset a spend
 *   budget by reconnecting.
 *
 * Every untrusted field is bounded and validated before allocation or KDF work.
 *
 * Known limitation (out of the cross-origin host threat model): this format has
 * no monotonic anti-rollback counter, so an attacker who can overwrite the
 * wallet origin's own storage could restore an older, genuinely authenticated
 * snapshot to reset the spend budget. Defending that requires trusted state
 * outside the store the attacker controls and is deferred; the browser host
 * (dApp) has no path to the wallet origin's storage and cannot do this.
 */

import { deriveArgon2idKey } from "./argon2.js";
import { addressToBytes } from "./address.js";
import { canonicalJson, canonicalJsonBytes } from "./canonical.js";
import { bytesToHex, hexToBytes, toArrayBuffer } from "./hex.js";
import {
  isSecureWalletHostOrigin,
  parseSpendLimits,
  type WalletPermissionScope,
  type WalletSpendLimitsJson,
} from "./wallet-request.js";

/** Exact permission-store object version. Unknown versions fail closed. */
export const WEBC_PERMISSION_STORE_VERSION = 1 as const;

/** Domain authenticated with all public permission-store metadata. */
export const WEBC_PERMISSION_STORE_AAD_DOMAIN =
  "WEBC_PERMISSION_STORE_AAD_V1" as const;

/** Argon2id memory cost in KiB: OWASP's 19 MiB interactive profile. */
export const PERMISSION_STORE_ARGON2_MEMORY_KIB = 19_456 as const;

/** Argon2id time cost in complete passes. */
export const PERMISSION_STORE_ARGON2_ITERATIONS = 2 as const;

/** Argon2id lane count; one avoids device-dependent parallel scheduling. */
export const PERMISSION_STORE_ARGON2_PARALLELISM = 1 as const;

/** Maximum UTF-8 password length accepted before KDF work. */
export const MAX_PERMISSION_STORE_PASSWORD_BYTES = 1_024;

/** Minimum UTF-8 password length required when creating a new store. */
export const MIN_PERMISSION_STORE_PASSWORD_BYTES = 12;

/** Maximum number of per-origin grants a single store may hold. */
export const MAX_PERMISSION_GRANTS = 256;

/** Maximum serialized v1 store length before JSON parsing. */
export const MAX_PERMISSION_STORE_JSON_BYTES = 262_144;

const SALT_BYTES = 16;
const IV_BYTES = 12;
const AES_KEY_BYTES = 32;
const AES_GCM_TAG_BITS = 128;
const MAX_CIPHERTEXT_BYTES = 200_000;
const ARGON2_MAX_MEMORY_BYTES = 32 * 1_024 * 1_024;
const PAYLOAD_VERSION = 1;
const MAX_ORIGIN_BYTES = 2_048;
const U128_MAX = (1n << 128n) - 1n;

/** Stable non-secret failure categories for permission-store callers. */
export type PermissionStoreErrorCode =
  | "INVALID_SCHEMA"
  | "UNSUPPORTED_VERSION"
  | "INVALID_PASSWORD"
  | "IDENTITY_MISMATCH"
  | "AUTHENTICATION_FAILED";

/** Typed permission-store error whose message never includes the password. */
export class PermissionStoreError extends Error {
  /** Machine-readable failure category. */
  readonly code: PermissionStoreErrorCode;

  constructor(code: PermissionStoreErrorCode, message: string) {
    super(message);
    this.name = "PermissionStoreError";
    this.code = code;
  }
}

/** One durable per-origin authorization grant. */
export interface PersistedPermissionGrant {
  /** Exact secure browser origin the grant belongs to. */
  readonly origin: string;
  /** Deterministic wallet-secret-bound lane assigned to this origin, 64-hex. */
  readonly authorization_lane: string;
  /** Approved permission scopes; V1 supports native transfers only. */
  readonly scopes: readonly WalletPermissionScope[];
  /** User-approved spend bounds in WEBC base units. */
  readonly limits: WalletSpendLimitsJson;
  /**
   * Cumulative principal already spent under this grant, base-units decimal.
   * Persisted so a reconnect cannot reset the budget; never exceeds
   * `limits.max_total_amount`.
   */
  readonly spent_amount: string;
}

/** Wallet identity a store is cryptographically bound to. */
export interface PermissionStoreIdentity {
  /** Base58 `webc1...` wallet address. */
  readonly address: string;
  /** 32-byte Ed25519 public key. */
  readonly publicKey: Uint8Array;
}

/** Exact Argon2id parameters accepted by permission-store v1. */
export interface PermissionStoreKdfV1 {
  readonly algorithm: "argon2id";
  /** RFC 9106 Argon2 version, decimal 19 (`0x13`). */
  readonly version: 19;
  readonly memory_kib: typeof PERMISSION_STORE_ARGON2_MEMORY_KIB;
  readonly iterations: typeof PERMISSION_STORE_ARGON2_ITERATIONS;
  readonly parallelism: typeof PERMISSION_STORE_ARGON2_PARALLELISM;
  /** Unique 16-byte random salt encoded as lowercase hex. */
  readonly salt: string;
}

/** Exact authenticated-encryption parameters accepted by permission-store v1. */
export interface PermissionStoreCipherV1 {
  readonly algorithm: "aes-256-gcm";
  /** Unique 12-byte random IV encoded as lowercase hex. */
  readonly iv: string;
  readonly tag_bits: 128;
  /** Ciphertext with its WebCrypto-appended GCM tag, lowercase hex. */
  readonly ciphertext: string;
}

/** Public metadata authenticated as AES-GCM additional data. */
export interface PermissionStorePublicV1 {
  /** Wallet address the encrypted grants belong to. */
  readonly address: string;
  /** Wallet Ed25519 public key, lowercase hex. */
  readonly public_key: string;
  /** Number of grants inside the ciphertext, bounding truncation. */
  readonly grant_count: number;
}

/** Strict JSON-compatible encrypted permission-store schema. */
export interface WebcPermissionStoreV1 {
  readonly format: "webc-permission-store";
  readonly version: typeof WEBC_PERMISSION_STORE_VERSION;
  readonly kdf: PermissionStoreKdfV1;
  readonly cipher: PermissionStoreCipherV1;
  readonly public: PermissionStorePublicV1;
}

interface PermissionStorePayloadV1 {
  readonly payload_version: 1;
  readonly grants: readonly PersistedPermissionGrant[];
}

interface PermissionStoreAadV1 {
  readonly domain: typeof WEBC_PERMISSION_STORE_AAD_DOMAIN;
  readonly format: "webc-permission-store";
  readonly version: 1;
  readonly kdf: PermissionStoreKdfV1;
  readonly cipher: Omit<PermissionStoreCipherV1, "ciphertext">;
  readonly public: PermissionStorePublicV1;
}

/**
 * Persistence port the trusted service calls after each grant change.
 *
 * `save` re-encrypts the full grant set under a cached key and writes it through
 * the caller's backend. It is cheap (only symmetric AES-GCM, no repeated KDF),
 * so persisting after every spend does not run Argon2id per transaction.
 */
export interface PermissionPersistencePort {
  save(records: readonly PersistedPermissionGrant[]): Promise<void>;
}

/**
 * Encrypts a validated grant set into strict permission-store v1.
 *
 * The password must encode to 12..1024 UTF-8 bytes with no unpaired surrogate.
 * Fresh CSPRNG salt and IV make repeated exports distinct. Grants are validated,
 * de-duplicated by origin, and sorted for deterministic output.
 */
export async function encryptPermissionStore(
  records: readonly PersistedPermissionGrant[],
  password: string,
  identity: PermissionStoreIdentity,
): Promise<WebcPermissionStoreV1> {
  const validated = validateGrantSet(records);
  const boundIdentity = validateIdentity(identity);
  const passwordBytes = encodePassword(password, true);
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  try {
    const aesKey = await deriveStoreKey(passwordBytes, salt);
    return await encryptWithKey(aesKey, salt, validated, boundIdentity);
  } finally {
    passwordBytes.fill(0);
  }
}

/**
 * Decrypts and verifies a permission store, returning its grant set.
 *
 * Wrong passwords, ciphertext changes, and authenticated-metadata changes share
 * one `AUTHENTICATION_FAILED` code. A store belonging to a different wallet
 * identity is rejected with `IDENTITY_MISMATCH` before KDF work.
 */
export async function decryptPermissionStore(
  input: unknown,
  password: string,
  identity: PermissionStoreIdentity,
): Promise<PersistedPermissionGrant[]> {
  const store = validateStore(input);
  const boundIdentity = validateIdentity(identity);
  requireMatchingIdentity(store, boundIdentity);
  const passwordBytes = encodePassword(password, false);
  const salt = decodeExactHex(store.kdf.salt, SALT_BYTES, "salt");
  try {
    const aesKey = await deriveStoreKey(passwordBytes, salt);
    return await decryptWithKey(aesKey, store);
  } finally {
    passwordBytes.fill(0);
  }
}

/**
 * Opens a permission store for the trusted service: decrypts existing grants
 * (or starts empty), and returns a save port that re-encrypts cheaply.
 *
 * The Argon2id key is derived exactly once and kept as a non-extractable
 * WebCrypto key for the port's lifetime, so `save` after every spend costs only
 * one AES-GCM encryption with a fresh IV, never another KDF pass. The salt is
 * fixed for the store's lifetime; each save uses a new random IV.
 */
export async function openPermissionStore(options: {
  /** Serialized existing store, or null to start a fresh empty store. */
  readonly serialized: string | null;
  readonly password: string;
  readonly identity: PermissionStoreIdentity;
  /** Backend that durably persists the re-serialized store. */
  readonly write: (serialized: string) => Promise<void>;
}): Promise<{
  records: PersistedPermissionGrant[];
  port: PermissionPersistencePort;
}> {
  if (typeof options.write !== "function") {
    throw new PermissionStoreError(
      "INVALID_SCHEMA",
      "permission store backend write function is required",
    );
  }
  const boundIdentity = validateIdentity(options.identity);
  const existing =
    options.serialized === null ? null : parsePermissionStore(options.serialized);
  if (existing) requireMatchingIdentity(existing, boundIdentity);

  const passwordBytes = encodePassword(options.password, existing === null);
  const salt = existing
    ? decodeExactHex(existing.kdf.salt, SALT_BYTES, "salt")
    : crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  let aesKey: CryptoKey;
  try {
    aesKey = await deriveStoreKey(passwordBytes, salt);
  } finally {
    passwordBytes.fill(0);
  }

  const records = existing
    ? await decryptWithKey(aesKey, existing)
    : [];

  const port: PermissionPersistencePort = {
    async save(next) {
      const validated = validateGrantSet(next);
      const store = await encryptWithKey(aesKey, salt, validated, boundIdentity);
      await options.write(serializePermissionStore(store));
    },
  };
  return { records, port };
}

/**
 * Validates and normalizes an untrusted grant set (bounds, secure origins, valid
 * lane, limits, `spent_amount` within the grant's own cap, no duplicates),
 * returning the grants sorted by origin. Throws `PermissionStoreError` on any
 * violation. Callers that accept grants from anywhere other than
 * `decryptPermissionStore` must run this before trusting them.
 */
export function validatePermissionGrants(
  records: readonly PersistedPermissionGrant[],
): PersistedPermissionGrant[] {
  return validateGrantSet(records);
}

/** Serializes a validated store with deterministic key ordering. */
export function serializePermissionStore(store: WebcPermissionStoreV1): string {
  return canonicalJson(validateStore(store));
}

/** Parses a bounded JSON store and rejects unknown or ambiguous fields. */
export function parsePermissionStore(json: string): WebcPermissionStoreV1 {
  if (
    json.length > MAX_PERMISSION_STORE_JSON_BYTES ||
    new TextEncoder().encode(json).length > MAX_PERMISSION_STORE_JSON_BYTES
  ) {
    throw new PermissionStoreError("INVALID_SCHEMA", "permission store JSON is too large");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new PermissionStoreError("INVALID_SCHEMA", "permission store JSON is malformed");
  }
  return validateStore(parsed);
}

async function encryptWithKey(
  aesKey: CryptoKey,
  salt: Uint8Array,
  grants: readonly PersistedPermissionGrant[],
  identity: BoundIdentity,
): Promise<WebcPermissionStoreV1> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const kdf = fixedKdf(bytesToHex(salt));
  const publicMetadata: PermissionStorePublicV1 = {
    address: identity.address,
    public_key: identity.publicKeyHex,
    grant_count: grants.length,
  };
  const cipherMetadata: Omit<PermissionStoreCipherV1, "ciphertext"> = {
    algorithm: "aes-256-gcm",
    iv: bytesToHex(iv),
    tag_bits: AES_GCM_TAG_BITS,
  };
  const aad = aadBytes(kdf, cipherMetadata, publicMetadata);
  const payload: PermissionStorePayloadV1 = {
    payload_version: PAYLOAD_VERSION,
    grants,
  };
  const plaintext = new TextEncoder().encode(canonicalJson(payload));
  try {
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
      throw new PermissionStoreError(
        "INVALID_SCHEMA",
        "encrypted permission store exceeds the v1 limit",
      );
    }
    return {
      format: "webc-permission-store",
      version: WEBC_PERMISSION_STORE_VERSION,
      kdf,
      cipher: { ...cipherMetadata, ciphertext: bytesToHex(encrypted) },
      public: publicMetadata,
    };
  } finally {
    plaintext.fill(0);
  }
}

async function decryptWithKey(
  aesKey: CryptoKey,
  store: WebcPermissionStoreV1,
): Promise<PersistedPermissionGrant[]> {
  const iv = decodeExactHex(store.cipher.iv, IV_BYTES, "IV");
  const ciphertext = decodeCiphertext(store.cipher.ciphertext);
  const cipherMetadata = {
    algorithm: store.cipher.algorithm,
    iv: store.cipher.iv,
    tag_bits: store.cipher.tag_bits,
  };
  const aad = aadBytes(store.kdf, cipherMetadata, store.public);
  let plaintext: Uint8Array | undefined;
  try {
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
    // parsePayload validates every grant (secure origin, lane, limits, spent
    // bound). The GCM tag already authenticated grant_count via the AAD; re-check
    // so a self-produced store also stays internally consistent.
    const grants = parsePayload(plaintext);
    if (grants.length !== store.public.grant_count) {
      throw new Error("grant count mismatch");
    }
    return grants;
  } catch (error) {
    if (error instanceof PermissionStoreError) throw error;
    throw new PermissionStoreError(
      "AUTHENTICATION_FAILED",
      "wrong password or corrupted permission store",
    );
  } finally {
    ciphertext.fill(0);
    plaintext?.fill(0);
  }
}

/** Purpose label domain-separating permission-store keys from other formats (S3). */
const PERMISSION_STORE_KDF_DOMAIN = new TextEncoder().encode(
  "webc-permission-store-v1-encryption",
);

async function deriveStoreKey(
  passwordBytes: Uint8Array,
  salt: Uint8Array,
): Promise<CryptoKey> {
  let derived: Uint8Array | undefined;
  try {
    // The permission-store purpose label domain-separates this key from the
    // keystore's, so the same password+salt never yields one shared AES key (S3).
    derived = await deriveArgon2idKey(
      passwordBytes,
      salt,
      {
        memoryKib: PERMISSION_STORE_ARGON2_MEMORY_KIB,
        iterations: PERMISSION_STORE_ARGON2_ITERATIONS,
        parallelism: PERMISSION_STORE_ARGON2_PARALLELISM,
        dkLen: AES_KEY_BYTES,
        maxMemoryBytes: ARGON2_MAX_MEMORY_BYTES,
      },
      PERMISSION_STORE_KDF_DOMAIN,
    );
    return await crypto.subtle.importKey(
      "raw",
      toArrayBuffer(derived),
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  } finally {
    derived?.fill(0);
  }
}

interface BoundIdentity {
  readonly address: string;
  readonly publicKeyHex: string;
}

function validateIdentity(identity: PermissionStoreIdentity): BoundIdentity {
  if (
    !identity ||
    typeof identity.address !== "string" ||
    !(identity.publicKey instanceof Uint8Array) ||
    identity.publicKey.length !== 32
  ) {
    throw new PermissionStoreError("INVALID_SCHEMA", "permission store identity is invalid");
  }
  try {
    addressToBytes(identity.address);
  } catch {
    throw new PermissionStoreError("INVALID_SCHEMA", "permission store address is invalid");
  }
  return { address: identity.address, publicKeyHex: bytesToHex(identity.publicKey) };
}

function requireMatchingIdentity(
  store: WebcPermissionStoreV1,
  identity: BoundIdentity,
): void {
  if (
    store.public.address !== identity.address ||
    store.public.public_key !== identity.publicKeyHex
  ) {
    throw new PermissionStoreError(
      "IDENTITY_MISMATCH",
      "permission store belongs to a different wallet identity",
    );
  }
}

function validateGrantSet(
  records: readonly PersistedPermissionGrant[],
): PersistedPermissionGrant[] {
  if (!Array.isArray(records)) {
    throw new PermissionStoreError("INVALID_SCHEMA", "grants must be an array");
  }
  if (records.length > MAX_PERMISSION_GRANTS) {
    throw new PermissionStoreError(
      "INVALID_SCHEMA",
      "permission store exceeds the maximum grant count",
    );
  }
  const seen = new Set<string>();
  const validated = records.map((record) => validateGrant(record));
  for (const grant of validated) {
    if (seen.has(grant.origin)) {
      throw new PermissionStoreError(
        "INVALID_SCHEMA",
        "permission store has duplicate origins",
      );
    }
    seen.add(grant.origin);
  }
  // Deterministic order so identical grant sets serialize identically.
  validated.sort((a, b) => (a.origin < b.origin ? -1 : a.origin > b.origin ? 1 : 0));
  return validated;
}

function validateGrant(input: unknown): PersistedPermissionGrant {
  const record = exactRecord(input, [
    "origin",
    "authorization_lane",
    "scopes",
    "limits",
    "spent_amount",
  ]);
  if (
    typeof record.origin !== "string" ||
    new TextEncoder().encode(record.origin).length > MAX_ORIGIN_BYTES ||
    !isSecureWalletHostOrigin(record.origin) ||
    typeof record.authorization_lane !== "string" ||
    record.authorization_lane.length !== 64 ||
    record.authorization_lane !== record.authorization_lane.toLowerCase() ||
    !Array.isArray(record.scopes) ||
    record.scopes.length !== 1 ||
    record.scopes[0] !== "sign_native_transfer" ||
    typeof record.spent_amount !== "string"
  ) {
    invalidSchema();
  }
  try {
    if (hexToBytes(record.authorization_lane as string).length !== 32) invalidSchema();
  } catch {
    invalidSchema();
  }
  const limits = validateLimits(record.limits);
  const parsedLimits = parseSpendLimits(limits);
  const spent = parseBaseUnits(record.spent_amount as string);
  if (spent > parsedLimits.maxTotalAmount) {
    // A grant can never have spent more than its own cumulative cap.
    invalidSchema();
  }
  return {
    origin: record.origin as string,
    authorization_lane: record.authorization_lane as string,
    scopes: ["sign_native_transfer"],
    limits,
    spent_amount: record.spent_amount as string,
  };
}

function validateLimits(input: unknown): WalletSpendLimitsJson {
  const record = exactRecord(input, [
    "max_amount_per_transaction",
    "max_total_amount",
    "max_fee_per_transaction",
  ]);
  if (
    typeof record.max_amount_per_transaction !== "string" ||
    typeof record.max_total_amount !== "string" ||
    typeof record.max_fee_per_transaction !== "string"
  ) {
    invalidSchema();
  }
  const limits: WalletSpendLimitsJson = {
    max_amount_per_transaction: record.max_amount_per_transaction as string,
    max_total_amount: record.max_total_amount as string,
    max_fee_per_transaction: record.max_fee_per_transaction as string,
  };
  try {
    parseSpendLimits(limits);
  } catch {
    invalidSchema();
  }
  return limits;
}

function validateStore(input: unknown): WebcPermissionStoreV1 {
  const root = exactRecord(input, ["format", "version", "kdf", "cipher", "public"]);
  if (root.format !== "webc-permission-store") invalidSchema();
  if (root.version !== WEBC_PERMISSION_STORE_VERSION) {
    throw new PermissionStoreError(
      "UNSUPPORTED_VERSION",
      "permission store version is unsupported",
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
    kdf.memory_kib !== PERMISSION_STORE_ARGON2_MEMORY_KIB ||
    kdf.iterations !== PERMISSION_STORE_ARGON2_ITERATIONS ||
    kdf.parallelism !== PERMISSION_STORE_ARGON2_PARALLELISM ||
    typeof kdf.salt !== "string"
  ) {
    invalidSchema();
  }
  decodeExactHex(kdf.salt as string, SALT_BYTES, "salt");

  const cipher = exactRecord(root.cipher, ["algorithm", "iv", "tag_bits", "ciphertext"]);
  if (
    cipher.algorithm !== "aes-256-gcm" ||
    cipher.tag_bits !== AES_GCM_TAG_BITS ||
    typeof cipher.iv !== "string" ||
    typeof cipher.ciphertext !== "string"
  ) {
    invalidSchema();
  }
  decodeExactHex(cipher.iv as string, IV_BYTES, "IV");
  decodeCiphertext(cipher.ciphertext as string);

  const publicMetadata = exactRecord(root.public, [
    "address",
    "public_key",
    "grant_count",
  ]);
  if (
    typeof publicMetadata.address !== "string" ||
    publicMetadata.address.length > 64 ||
    typeof publicMetadata.public_key !== "string" ||
    typeof publicMetadata.grant_count !== "number" ||
    !Number.isSafeInteger(publicMetadata.grant_count) ||
    publicMetadata.grant_count < 0 ||
    publicMetadata.grant_count > MAX_PERMISSION_GRANTS
  ) {
    invalidSchema();
  }
  decodeExactHex(publicMetadata.public_key as string, 32, "public key");
  try {
    addressToBytes(publicMetadata.address as string);
  } catch {
    invalidSchema();
  }

  return {
    format: "webc-permission-store",
    version: WEBC_PERMISSION_STORE_VERSION,
    kdf: {
      algorithm: "argon2id",
      version: 19,
      memory_kib: PERMISSION_STORE_ARGON2_MEMORY_KIB,
      iterations: PERMISSION_STORE_ARGON2_ITERATIONS,
      parallelism: PERMISSION_STORE_ARGON2_PARALLELISM,
      salt: kdf.salt as string,
    },
    cipher: {
      algorithm: "aes-256-gcm",
      iv: cipher.iv as string,
      tag_bits: AES_GCM_TAG_BITS,
      ciphertext: cipher.ciphertext as string,
    },
    public: {
      address: publicMetadata.address as string,
      public_key: publicMetadata.public_key as string,
      grant_count: publicMetadata.grant_count as number,
    },
  };
}

function parsePayload(plaintext: Uint8Array): PersistedPermissionGrant[] {
  if (plaintext.length > MAX_CIPHERTEXT_BYTES) throw new Error("payload too large");
  const text = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  const record = exactRecord(JSON.parse(text), ["payload_version", "grants"]);
  if (record.payload_version !== PAYLOAD_VERSION || !Array.isArray(record.grants)) {
    throw new Error("payload schema mismatch");
  }
  return validateGrantSet(record.grants as PersistedPermissionGrant[]);
}

function fixedKdf(salt: string): PermissionStoreKdfV1 {
  return {
    algorithm: "argon2id",
    version: 19,
    memory_kib: PERMISSION_STORE_ARGON2_MEMORY_KIB,
    iterations: PERMISSION_STORE_ARGON2_ITERATIONS,
    parallelism: PERMISSION_STORE_ARGON2_PARALLELISM,
    salt,
  };
}

function aadBytes(
  kdf: PermissionStoreKdfV1,
  cipher: Omit<PermissionStoreCipherV1, "ciphertext">,
  publicMetadata: PermissionStorePublicV1,
): Uint8Array {
  const aad: PermissionStoreAadV1 = {
    domain: WEBC_PERMISSION_STORE_AAD_DOMAIN,
    format: "webc-permission-store",
    version: WEBC_PERMISSION_STORE_VERSION,
    kdf,
    cipher,
    public: publicMetadata,
  };
  return canonicalJsonBytes(aad);
}

function encodePassword(password: string, creating: boolean): Uint8Array {
  if (typeof password !== "string" || hasUnpairedSurrogate(password)) {
    throw new PermissionStoreError("INVALID_PASSWORD", "password contains invalid Unicode");
  }
  if (
    password.length > MAX_PERMISSION_STORE_PASSWORD_BYTES ||
    new TextEncoder().encode(password).length > MAX_PERMISSION_STORE_PASSWORD_BYTES
  ) {
    throw new PermissionStoreError("INVALID_PASSWORD", "password exceeds the UTF-8 length limit");
  }
  const encoded = new TextEncoder().encode(password);
  if (creating && encoded.length < MIN_PERMISSION_STORE_PASSWORD_BYTES) {
    encoded.fill(0);
    throw new PermissionStoreError(
      "INVALID_PASSWORD",
      "new permission store password must contain at least 12 UTF-8 bytes",
    );
  }
  return encoded;
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

function parseBaseUnits(value: string): bigint {
  if (value.length > 39 || !/^(0|[1-9][0-9]*)$/u.test(value)) invalidSchema();
  const parsed = BigInt(value);
  if (parsed > U128_MAX) invalidSchema();
  return parsed;
}

function decodeExactHex(value: string, bytes: number, label: string): Uint8Array {
  if (value.length !== bytes * 2 || value !== value.toLowerCase()) {
    throw new PermissionStoreError("INVALID_SCHEMA", `${label} length is invalid`);
  }
  try {
    return hexToBytes(value);
  } catch {
    throw new PermissionStoreError("INVALID_SCHEMA", `${label} encoding is invalid`);
  }
}

function decodeCiphertext(value: string): Uint8Array {
  if (
    value.length < (AES_GCM_TAG_BITS / 8) * 2 ||
    value.length > MAX_CIPHERTEXT_BYTES * 2 ||
    value !== value.toLowerCase()
  ) {
    throw new PermissionStoreError("INVALID_SCHEMA", "ciphertext length is invalid");
  }
  try {
    return hexToBytes(value);
  } catch {
    throw new PermissionStoreError("INVALID_SCHEMA", "ciphertext encoding is invalid");
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
  throw new PermissionStoreError("INVALID_SCHEMA", "permission store schema is invalid");
}
