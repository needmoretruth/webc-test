/**
 * Browser wallet primitives: Ed25519 key generation, signing, and verification.
 *
 * The wallet intentionally supports both an ephemeral random keypair and a
 * deterministic Ed25519 seed imported by the trusted wallet implementation.
 *
 * Private keys stay as non-extractable `CryptoKey` objects in a module-private
 * weak map. They are not properties of the public wallet object. Persistent
 * wallets must use the reviewed mnemonic and keystore APIs rather than storing
 * a `CryptoKey`; see `docs/security.md` for the threat model.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { addressFromPublicKey } from "./address.js";
import { hexToBytes, toArrayBuffer } from "./hex.js";

const privateKeys = new WeakMap<WebcWallet, CryptoKey>();

/** Public identity of an in-process wallet; it contains no key handle or seed. */
export interface WebcWallet {
  /** Base58 `webc1...` address derived from the public key. */
  readonly address: string;
  /** 32-byte Ed25519 public key as a `Uint8Array`. */
  readonly publicKey: Uint8Array;
}

/**
 * Generates an ephemeral random Ed25519 wallet in the current trusted context.
 *
 * This operation has no recovery material. Persistent wallets should generate
 * a standard recovery mnemonic and derive through `wallet-derivation.ts`.
 */
export async function createWallet(): Promise<WebcWallet> {
  const pair = await crypto.subtle.generateKey(
    { name: "Ed25519" } as Algorithm,
    false,
    ["sign", "verify"],
  );
  if (!("privateKey" in pair) || !("publicKey" in pair)) {
    throw new Error("Ed25519 key generation did not return a key pair");
  }
  const publicKeyBytes = new Uint8Array(
    await crypto.subtle.exportKey("raw", pair.publicKey as CryptoKey),
  );
  const address = await addressFromPublicKey(publicKeyBytes);
  return registerWallet(address, publicKeyBytes, pair.privateKey as CryptoKey);
}

/**
 * Imports a raw 32-byte Ed25519 seed using the WebCrypto PKCS#8 path.
 *
 * Browsers that implement Ed25519 importKey via PKCS#8 (Chrome 113+, recent
 * Firefox and Safari) accept the standard RFC 8410 prefix followed by the raw
 * 32-byte seed. The private key stays non-extractable, and the public key is
 * derived with the reviewed noble Ed25519 implementation before import:
 *
 *   1. Build a 48-byte PKCS#8 with `302e020100300506032b657004220420 || seed`.
 *   2. Import it as a sign-only Ed25519 key.
 *   3. Store the non-extractable key handle only in a module-private weak map.
 *
 * This low-level API is for trusted wallet code and deterministic fixtures. It
 * does not define mnemonic or hierarchical derivation. If WebCrypto lacks
 * Ed25519 PKCS#8 import, it fails closed instead of making the key extractable.
 */
export async function createWalletFromSeed(
  seed: Uint8Array,
): Promise<WebcWallet> {
  if (seed.length !== 32) {
    throw new Error("Ed25519 seed must be 32 bytes");
  }
  const privateSeed = seed.slice();
  const prefix = hexToBytes("302e020100300506032b657004220420");
  const pkcs8 = new Uint8Array(prefix.length + privateSeed.length);
  pkcs8.set(prefix, 0);
  pkcs8.set(privateSeed, prefix.length);

  try {
    const publicKey = ed25519.getPublicKey(privateSeed);
    const privateKey = await crypto.subtle.importKey(
      "pkcs8",
      toArrayBuffer(pkcs8),
      { name: "Ed25519" } as Algorithm,
      false,
      ["sign"],
    );
    const address = await addressFromPublicKey(publicKey);
    return registerWallet(address, publicKey, privateKey);
  } finally {
    // JavaScript cannot erase immutable strings or runtime copies, but these
    // mutable temporary buffers need not retain raw key bytes after import.
    privateSeed.fill(0);
    pkcs8.fill(0);
  }
}

/** Verifier-only identity from a 32-byte raw public key. */
export interface WebcPublicIdentity {
  readonly address: string;
  readonly publicKey: Uint8Array;
}

/** Reconstructs a verifier-only identity from a 32-byte public key. */
export async function walletFromPublic(
  publicKey: Uint8Array,
): Promise<WebcPublicIdentity> {
  if (publicKey.length !== 32) {
    throw new Error("Ed25519 public key must be 32 bytes");
  }
  const address = await addressFromPublicKey(publicKey);
  return { address, publicKey };
}

/** Signs a message blob with the wallet's private key. Returns 64 raw bytes. */
export async function signWithWallet(
  wallet: WebcWallet,
  message: Uint8Array,
): Promise<Uint8Array> {
  const privateKey = privateKeys.get(wallet);
  if (!privateKey) {
    throw new Error("wallet key is unavailable in this trusted context");
  }
  const signature = await crypto.subtle.sign(
    { name: "Ed25519" } as Algorithm,
    privateKey,
    toArrayBuffer(message),
  );
  return new Uint8Array(signature);
}

/** Verifies a 64-byte Ed25519 signature over a message. */
export async function verifyEd25519(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  if (publicKey.length !== 32) throw new Error("public key must be 32 bytes");
  if (signature.length !== 64) throw new Error("signature must be 64 bytes");
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      toArrayBuffer(publicKey),
      { name: "Ed25519" } as Algorithm,
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      { name: "Ed25519" } as Algorithm,
      key,
      toArrayBuffer(signature),
      toArrayBuffer(message),
    );
  } catch {
    return false;
  }
}

function registerWallet(
  address: string,
  publicKey: Uint8Array,
  privateKey: CryptoKey,
): WebcWallet {
  const wallet: WebcWallet = Object.freeze({
    address,
    publicKey: publicKey.slice(),
  });
  privateKeys.set(wallet, privateKey);
  return wallet;
}
