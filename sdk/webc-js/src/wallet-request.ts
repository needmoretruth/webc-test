/**
 * Strict host-to-wallet postMessage wire schema and hostile-input parsing.
 *
 * This module owns only public request/response data. It does not hold keys,
 * grant permissions, inspect `MessageEvent.origin`, or perform signing. V1
 * intentionally supports native WEBC transfers only so the wallet can derive
 * every confirmation field from the exact transaction it will sign.
 */

import { addressToBytes } from "./address.js";
import { amountFromUnits, WEBC_UNIT } from "./amount.js";
import { hexToBytes } from "./hex.js";
import {
  CURRENT_TRANSACTION_PROTOCOL_VERSION,
  DEFAULT_AUTHORIZATION_LANE,
  validateTransactionContext,
} from "./transaction.js";
import type { FeeBid, SignedTransactionJson } from "./types.js";

/** Stable channel tag for trusted wallet messages. */
export const WALLET_MESSAGE_CHANNEL = "webc-wallet" as const;

/** Exact supported postMessage protocol version. */
export const WALLET_MESSAGE_VERSION = 1 as const;

/** Maximum requests retained for replay detection by one service instance. */
export const MAX_WALLET_REPLAY_IDS = 2_048;

/** Only permission currently safe for automatic wire construction. */
export type WalletPermissionScope = "sign_native_transfer";

/** User-approved native spend bounds, all in WEBC base units. */
export interface WalletSpendLimitsJson {
  /** Maximum principal in one signed transfer. */
  readonly max_amount_per_transaction: string;
  /** Maximum cumulative principal until the grant is replaced or revoked. */
  readonly max_total_amount: string;
  /** Maximum transaction fee bid in one signed transfer. */
  readonly max_fee_per_transaction: string;
}

/** Connect parameters that the trusted UI must show before granting. */
export interface WalletConnectParams {
  readonly scopes: readonly WalletPermissionScope[];
  readonly limits: WalletSpendLimitsJson;
}

/** Exact native transfer parameters; the wallet builds operation/access itself. */
export interface WalletNativeTransferParams {
  /** Wallet-issued connection session preventing replay across grants. */
  readonly session_id: string;
  /** Exact monotonic signing sequence inside the connection session. */
  readonly sequence: number;
  readonly protocol_version: number;
  readonly chain_id: string;
  readonly nonce: number;
  readonly authorization_lane: string;
  /** Installed on-chain policy revision; zero is legacy migration only. */
  readonly authorization_policy_revision: number;
  readonly recipient: string;
  readonly amount: string;
  readonly fee: FeeBid;
}

/** Strict host request union. The origin is never carried inside the message. */
export type WalletRequest =
  | {
      readonly channel: typeof WALLET_MESSAGE_CHANNEL;
      readonly version: typeof WALLET_MESSAGE_VERSION;
      readonly request_id: string;
      readonly method: "connect";
      readonly params: WalletConnectParams;
    }
  | {
      readonly channel: typeof WALLET_MESSAGE_CHANNEL;
      readonly version: typeof WALLET_MESSAGE_VERSION;
      readonly request_id: string;
      readonly method: "sign_native_transfer";
      readonly params: WalletNativeTransferParams;
    }
  | {
      readonly channel: typeof WALLET_MESSAGE_CHANNEL;
      readonly version: typeof WALLET_MESSAGE_VERSION;
      readonly request_id: string;
      readonly method: "revoke";
      readonly params: Record<string, never>;
    };

/** Public account and exact grant returned after user-approved connection. */
export interface WalletConnectionResult {
  readonly address: string;
  readonly public_key: string;
  /** Deterministic wallet-secret-bound lane assigned only to this origin. */
  readonly authorization_lane: string;
  /** Random wallet-issued connection session identifier. */
  readonly session_id: string;
  readonly scopes: readonly WalletPermissionScope[];
  readonly limits: WalletSpendLimitsJson;
}

/** Stable error categories exposed to an untrusted host without secret data. */
export type WalletResponseErrorCode =
  | "INVALID_REQUEST"
  | "UNSUPPORTED_VERSION"
  | "REQUEST_REPLAY"
  | "PERMISSION_REQUIRED"
  | "LIMIT_EXCEEDED"
  | "CHAIN_MISMATCH"
  | "USER_REJECTED"
  | "INTERNAL_ERROR";

/** Strict wallet response union containing only public data. */
export type WalletResponse =
  | {
      readonly channel: typeof WALLET_MESSAGE_CHANNEL;
      readonly version: typeof WALLET_MESSAGE_VERSION;
      readonly request_id: string;
      readonly ok: true;
      readonly result:
        | WalletConnectionResult
        | SignedTransactionJson
        | { readonly revoked: true };
    }
  | {
      readonly channel: typeof WALLET_MESSAGE_CHANNEL;
      readonly version: typeof WALLET_MESSAGE_VERSION;
      readonly request_id: string;
      readonly ok: false;
      readonly error: {
        readonly code: WalletResponseErrorCode;
        readonly message: string;
      };
    };

/** User-visible connection grant derived from event origin and parsed limits. */
export interface WalletConnectionConfirmation {
  readonly kind: "connect";
  readonly origin: string;
  readonly scopes: readonly WalletPermissionScope[];
  readonly limits: WalletSpendLimitsJson;
}

/** User-visible transfer details derived from the exact transaction parameters. */
export interface WalletTransferConfirmation {
  readonly kind: "native_transfer";
  readonly origin: string;
  readonly action: "Send WEBC";
  readonly asset: "WEBC";
  readonly recipient: string;
  readonly amount_base_units: string;
  readonly amount_webc: string;
  readonly maximum_fee_base_units: string;
  readonly chain_id: string;
  readonly authorization_lane: string;
  readonly authorization_policy_revision: number;
}

/** Every trusted UI confirmation shape. */
export type WalletConfirmation =
  | WalletConnectionConfirmation
  | WalletTransferConfirmation;

/** Parsed numeric spend limits used only inside the trusted service. */
export interface ParsedSpendLimits {
  readonly maxAmountPerTransaction: bigint;
  readonly maxTotalAmount: bigint;
  readonly maxFeePerTransaction: bigint;
}

/** Parsed transfer values used for checked limit accounting. */
export interface ParsedNativeTransfer {
  readonly amount: bigint;
  readonly maximumFee: bigint;
}

/** Typed parser failure mapped to a public response by the service. */
export class WalletRequestError extends Error {
  readonly code: WalletResponseErrorCode;

  constructor(code: WalletResponseErrorCode, message: string) {
    super(message);
    this.name = "WalletRequestError";
    this.code = code;
  }
}

/** Parses a cloned postMessage value and rejects unknown fields or variants. */
export function parseWalletRequest(input: unknown): WalletRequest {
  const root = exactRecord(input, [
    "channel",
    "version",
    "request_id",
    "method",
    "params",
  ]);
  if (root.channel !== WALLET_MESSAGE_CHANNEL) invalidRequest();
  if (root.version !== WALLET_MESSAGE_VERSION) {
    throw new WalletRequestError(
      "UNSUPPORTED_VERSION",
      "wallet message version is unsupported",
    );
  }
  if (typeof root.request_id !== "string" || !isRequestId(root.request_id)) {
    invalidRequest();
  }
  if (root.method === "connect") {
    return {
      channel: WALLET_MESSAGE_CHANNEL,
      version: WALLET_MESSAGE_VERSION,
      request_id: root.request_id,
      method: "connect",
      params: parseConnectParams(root.params),
    };
  }
  if (root.method === "sign_native_transfer") {
    return {
      channel: WALLET_MESSAGE_CHANNEL,
      version: WALLET_MESSAGE_VERSION,
      request_id: root.request_id,
      method: "sign_native_transfer",
      params: parseNativeTransferParams(root.params),
    };
  }
  if (root.method === "revoke") {
    exactRecord(root.params, []);
    return {
      channel: WALLET_MESSAGE_CHANNEL,
      version: WALLET_MESSAGE_VERSION,
      request_id: root.request_id,
      method: "revoke",
      params: {},
    };
  }
  invalidRequest();
}

/** Extracts a valid request ID for a correlated malformed-request response. */
export function extractWalletRequestId(input: unknown): string | undefined {
  if (!isPlainRecord(input)) return undefined;
  const value = input.request_id;
  return typeof value === "string" && isRequestId(value) ? value : undefined;
}

/** Parses and checks user-proposed spend limits without floating-point math. */
export function parseSpendLimits(
  limits: WalletSpendLimitsJson,
): ParsedSpendLimits {
  const maxAmountPerTransaction = parseBaseUnits(
    limits.max_amount_per_transaction,
    false,
  );
  const maxTotalAmount = parseBaseUnits(limits.max_total_amount, false);
  const maxFeePerTransaction = parseBaseUnits(
    limits.max_fee_per_transaction,
    false,
  );
  if (maxTotalAmount < maxAmountPerTransaction) invalidRequest();
  return {
    maxAmountPerTransaction,
    maxTotalAmount,
    maxFeePerTransaction,
  };
}

/** Parses amount and checked maximum fee for trusted spend-limit accounting. */
export function parseNativeTransfer(
  params: WalletNativeTransferParams,
): ParsedNativeTransfer {
  const amount = parseBaseUnits(params.amount, false);
  const maximumFee = BigInt(params.fee.gasLimit) * BigInt(params.fee.maxFeePerUnit);
  if (maximumFee > U128_MAX) invalidRequest();
  return { amount, maximumFee };
}

/** Builds user-visible transfer text only from exact parsed signing fields. */
export function nativeTransferConfirmation(
  origin: string,
  params: WalletNativeTransferParams,
): WalletTransferConfirmation {
  const parsed = parseNativeTransfer(params);
  return {
    kind: "native_transfer",
    origin,
    action: "Send WEBC",
    asset: "WEBC",
    recipient: params.recipient,
    amount_base_units: params.amount,
    amount_webc: formatWebc(parsed.amount),
    maximum_fee_base_units: parsed.maximumFee.toString(10),
    chain_id: params.chain_id,
    authorization_lane: params.authorization_lane,
    authorization_policy_revision: params.authorization_policy_revision,
  };
}

/** Creates a fresh lowercase 32-byte request identifier with WebCrypto CSPRNG. */
export function createWalletRequestId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Returns whether a message event origin is safe for wallet authorization. */
export function isSecureWalletHostOrigin(origin: string): boolean {
  if (origin === "null" || origin.length > 2_048) return false;
  try {
    const url = new URL(origin);
    if (url.origin !== origin) return false;
    if (url.protocol === "https:") return true;
    return (
      url.protocol === "http:" &&
      (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]")
    );
  } catch {
    return false;
  }
}

function parseConnectParams(input: unknown): WalletConnectParams {
  const params = exactRecord(input, ["scopes", "limits"]);
  if (
    !Array.isArray(params.scopes) ||
    params.scopes.length !== 1 ||
    params.scopes[0] !== "sign_native_transfer"
  ) {
    invalidRequest();
  }
  const limitsRecord = exactRecord(params.limits, [
    "max_amount_per_transaction",
    "max_total_amount",
    "max_fee_per_transaction",
  ]);
  if (
    typeof limitsRecord.max_amount_per_transaction !== "string" ||
    typeof limitsRecord.max_total_amount !== "string" ||
    typeof limitsRecord.max_fee_per_transaction !== "string"
  ) {
    invalidRequest();
  }
  const limits: WalletSpendLimitsJson = {
    max_amount_per_transaction: limitsRecord.max_amount_per_transaction,
    max_total_amount: limitsRecord.max_total_amount,
    max_fee_per_transaction: limitsRecord.max_fee_per_transaction,
  };
  parseSpendLimits(limits);
  return { scopes: ["sign_native_transfer"], limits };
}

function parseNativeTransferParams(input: unknown): WalletNativeTransferParams {
  const params = exactRecord(input, [
    "session_id",
    "sequence",
    "protocol_version",
    "chain_id",
    "nonce",
    "authorization_lane",
    "authorization_policy_revision",
    "recipient",
    "amount",
    "fee",
  ]);
  if (
    typeof params.protocol_version !== "number" ||
    typeof params.session_id !== "string" ||
    !isRequestId(params.session_id) ||
    typeof params.sequence !== "number" ||
    !Number.isSafeInteger(params.sequence) ||
    params.sequence < 0 ||
    typeof params.chain_id !== "string" ||
    typeof params.nonce !== "number" ||
    !Number.isSafeInteger(params.nonce) ||
    params.nonce < 0 ||
    typeof params.authorization_lane !== "string" ||
    typeof params.authorization_policy_revision !== "number" ||
    !Number.isSafeInteger(params.authorization_policy_revision) ||
    params.authorization_policy_revision < 0 ||
    typeof params.recipient !== "string" ||
    typeof params.amount !== "string"
  ) {
    invalidRequest();
  }
  try {
    validateTransactionContext(params.protocol_version, params.chain_id);
    addressToBytes(params.recipient);
    if (
      params.authorization_lane.length !== 64 ||
      params.authorization_lane !== params.authorization_lane.toLowerCase() ||
      hexToBytes(params.authorization_lane).length !== 32
    ) {
      invalidRequest();
    }
  } catch {
    invalidRequest();
  }
  const fee = parseFee(params.fee);
  const parsed: WalletNativeTransferParams = {
    session_id: params.session_id,
    sequence: params.sequence,
    protocol_version: CURRENT_TRANSACTION_PROTOCOL_VERSION,
    chain_id: params.chain_id,
    nonce: params.nonce,
    authorization_lane: params.authorization_lane,
    authorization_policy_revision: params.authorization_policy_revision,
    recipient: params.recipient,
    amount: amountFromUnits(params.amount),
    fee,
  };
  parseNativeTransfer(parsed);
  return parsed;
}

function parseFee(input: unknown): FeeBid {
  const fee = exactRecord(input, [
    "gasLimit",
    "maxFeePerUnit",
    "priorityFeePerUnit",
  ]);
  const gasLimit = fee.gasLimit;
  const maxFeePerUnit = fee.maxFeePerUnit;
  const priorityFeePerUnit = fee.priorityFeePerUnit;
  for (const value of [gasLimit, maxFeePerUnit, priorityFeePerUnit]) {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
      invalidRequest();
    }
  }
  if (
    typeof gasLimit !== "number" ||
    typeof maxFeePerUnit !== "number" ||
    typeof priorityFeePerUnit !== "number"
  ) {
    invalidRequest();
  }
  if (gasLimit === 0 || maxFeePerUnit === 0) invalidRequest();
  if (priorityFeePerUnit > maxFeePerUnit) invalidRequest();
  return {
    gasLimit,
    maxFeePerUnit,
    priorityFeePerUnit,
  };
}

const U128_MAX = (1n << 128n) - 1n;

function parseBaseUnits(value: string, allowZero: boolean): bigint {
  if (value.length > 39 || !/^(0|[1-9][0-9]*)$/u.test(value)) invalidRequest();
  const parsed = BigInt(value);
  if (parsed > U128_MAX || (!allowZero && parsed === 0n)) invalidRequest();
  return parsed;
}

function formatWebc(units: bigint): string {
  const whole = units / WEBC_UNIT;
  const fractional = (units % WEBC_UNIT)
    .toString(10)
    .padStart(12, "0")
    .replace(/0+$/u, "");
  return fractional.length === 0 ? `${whole} WEBC` : `${whole}.${fractional} WEBC`;
}

function isRequestId(value: string): boolean {
  return /^[0-9a-f]{64}$/u.test(value);
}

function exactRecord(
  input: unknown,
  expectedKeys: readonly string[],
): Record<string, unknown> {
  if (!isPlainRecord(input)) invalidRequest();
  const record = input as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const expected = [...expectedKeys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    invalidRequest();
  }
  return record;
}

function isPlainRecord(input: unknown): input is Record<string, unknown> {
  return (
    typeof input === "object" &&
    input !== null &&
    !Array.isArray(input) &&
    Object.getPrototypeOf(input) === Object.prototype
  );
}

function invalidRequest(): never {
  throw new WalletRequestError("INVALID_REQUEST", "wallet request is invalid");
}

/** Canonical default lane exported here for protocol builders. */
export const WALLET_DEFAULT_AUTHORIZATION_LANE = DEFAULT_AUTHORIZATION_LANE;
