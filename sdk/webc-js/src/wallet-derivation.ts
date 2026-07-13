/**
 * BIP-39 recovery phrases and hardened SLIP-0010 Ed25519 wallet derivation.
 *
 * This module owns deterministic recovery-to-signing-key conversion for the
 * trusted wallet origin. It does not persist phrases, export private keys, or
 * expose secrets to a host site. English 24-word phrases maximize ecosystem
 * interoperability; a devnet-only BIP-44 testnet path prevents claiming an
 * unregistered WEBC mainnet SLIP-44 coin type.
 */

import {
  generateMnemonic,
  mnemonicToSeedWebcrypto,
  validateMnemonic,
} from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { HARDENED_OFFSET, HDKey } from "micro-key-producer/slip10.js";
import { createWalletFromSeed, type WebcWallet } from "./wallet.js";

/** Hardened SLIP-0010 path for account 0/index 0 on all-chain testnets. */
export const WEBC_DEVNET_DERIVATION_PATH_V1 = "m/44'/1'/0'/0'/0'";

/** Maximum UTF-8 mnemonic input accepted before parsing. */
export const MAX_MNEMONIC_BYTES = 512;

/** Maximum UTF-8 optional BIP-39 passphrase input. */
export const MAX_MNEMONIC_PASSPHRASE_BYTES = 1_024;

/** Stable failure categories that reveal no recovery phrase or key material. */
export type WalletDerivationErrorCode =
  | "INPUT_TOO_LARGE"
  | "INVALID_MNEMONIC"
  | "INVALID_ACCOUNT_INDEX"
  | "DERIVATION_FAILED";

/** Typed wallet-derivation failure safe to display without secret contents. */
export class WalletDerivationError extends Error {
  /** Machine-readable failure category. */
  readonly code: WalletDerivationErrorCode;

  constructor(code: WalletDerivationErrorCode, message: string) {
    super(message);
    this.name = "WalletDerivationError";
    this.code = code;
  }
}

/** Account and address index for a devnet hardened derivation path. */
export interface WalletDerivationOptions {
  /** Hardened account number in the inclusive range 0..2^31-1. */
  readonly account?: number;
  /** Hardened address index in the inclusive range 0..2^31-1. */
  readonly index?: number;
  /** Optional BIP-39 passphrase; every value produces a different wallet. */
  readonly passphrase?: string;
}

/** Generates a 24-word English BIP-39 recovery phrase from 256-bit CSPRNG entropy. */
export function generateRecoveryMnemonic(): string {
  return generateMnemonic(wordlist, 256);
}

/** Returns whether text is one canonicalizable English BIP-39 phrase. */
export function isValidRecoveryMnemonic(mnemonic: string): boolean {
  if (mnemonic.length > MAX_MNEMONIC_BYTES) return false;
  if (utf8Length(mnemonic) > MAX_MNEMONIC_BYTES) return false;
  return validateMnemonic(normalizeMnemonic(mnemonic), wordlist);
}

/**
 * Builds the explicit devnet-only SLIP-0010 path for an account and index.
 *
 * Coin type 1 is the registered all-chain testnet value. WEBC mainnet must use
 * a new version after receiving its own SLIP-44 assignment; changing this V1
 * constant would make existing recovery backups derive a different address.
 */
export function webcDevnetDerivationPath(
  account = 0,
  index = 0,
): string {
  validateChildIndex(account);
  validateChildIndex(index);
  return `m/44'/1'/${account}'/0'/${index}'`;
}

/**
 * Recovers one devnet Ed25519 wallet from BIP-39 plus hardened SLIP-0010.
 *
 * Inputs are bounded before PBKDF2. The returned object exposes only address
 * and public key; signing remains tied to the module-private non-extractable
 * WebCrypto key. Mutable seed, chain-code, and child-key buffers are cleared on
 * both success and failure. JavaScript cannot erase the immutable mnemonic
 * string, so callers must keep this function inside the trusted wallet origin.
 */
export async function createDevnetWalletFromMnemonic(
  mnemonic: string,
  options: WalletDerivationOptions = {},
): Promise<WebcWallet> {
  if (
    mnemonic.length > MAX_MNEMONIC_BYTES ||
    utf8Length(mnemonic) > MAX_MNEMONIC_BYTES
  ) {
    throw new WalletDerivationError(
      "INPUT_TOO_LARGE",
      "recovery phrase exceeds the maximum UTF-8 length",
    );
  }
  const normalized = normalizeMnemonic(mnemonic);
  if (!validateMnemonic(normalized, wordlist)) {
    throw new WalletDerivationError(
      "INVALID_MNEMONIC",
      "recovery phrase or checksum is invalid",
    );
  }

  const passphrase = options.passphrase ?? "";
  if (
    passphrase.length > MAX_MNEMONIC_PASSPHRASE_BYTES ||
    utf8Length(passphrase) > MAX_MNEMONIC_PASSPHRASE_BYTES
  ) {
    throw new WalletDerivationError(
      "INPUT_TOO_LARGE",
      "mnemonic passphrase exceeds the maximum UTF-8 length",
    );
  }
  const path = webcDevnetDerivationPath(options.account, options.index);

  let seed: Uint8Array | undefined;
  let master: HDKey | undefined;
  let child: HDKey | undefined;
  try {
    seed = await mnemonicToSeedWebcrypto(normalized, passphrase);
    master = HDKey.fromMasterSeed(seed);
    child = master.derive(path);
    return await createWalletFromSeed(child.privateKey);
  } catch (error) {
    if (error instanceof WalletDerivationError) throw error;
    throw new WalletDerivationError(
      "DERIVATION_FAILED",
      "wallet derivation failed in this runtime",
    );
  } finally {
    seed?.fill(0);
    clearNode(child);
    clearNode(master);
  }
}

function validateChildIndex(value: number | undefined): void {
  const actual = value ?? 0;
  if (
    !Number.isSafeInteger(actual) ||
    actual < 0 ||
    actual >= HARDENED_OFFSET
  ) {
    throw new WalletDerivationError(
      "INVALID_ACCOUNT_INDEX",
      "wallet account and index must be integers in range 0..2^31-1",
    );
  }
}

function normalizeMnemonic(value: string): string {
  return value.trim().split(/\s+/u).join(" ");
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length;
}

function clearNode(node: HDKey | undefined): void {
  node?.privateKey.fill(0);
  node?.chainCode.fill(0);
}
