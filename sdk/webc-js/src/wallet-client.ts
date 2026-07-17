/**
 * Host-site client for an isolated trusted wallet frame/window.
 *
 * This module never receives a wallet object, key handle, mnemonic, password,
 * or decrypted keystore. It sends strict public intents to one exact wallet
 * origin, correlates bounded request IDs, validates source/origin on responses,
 * and cryptographically verifies every returned signed transaction.
 */

import { addressFromPublicKey, addressToBytes } from "./address.js";
import { hexToBytes } from "./hex.js";
import { verifySignedTransaction } from "./transaction.js";
import type { SignedTransactionJson } from "./types.js";
import {
  WALLET_MESSAGE_CHANNEL,
  WALLET_MESSAGE_VERSION,
  WalletRequestError,
  createWalletRequestId,
  isSecureWalletHostOrigin,
  parseSpendLimits,
  type WalletConnectParams,
  type WalletConnectionResult,
  type WalletNativeTransferParams,
  type WalletRequest,
  type WalletResponseErrorCode,
  type WalletSpendLimitsJson,
} from "./wallet-request.js";
import type { WalletMessageSource } from "./wallet-service.js";

const DEFAULT_REQUEST_TIMEOUT_MS = 120_000;
const MAX_REQUEST_TIMEOUT_MS = 300_000;
const MAX_PENDING_REQUESTS = 64;

/** Minimal message event supplied by Window or a deterministic test harness. */
export interface WalletHostMessageEvent {
  readonly origin: string;
  readonly source: WalletMessageSource | null;
  readonly data: unknown;
}

/** Minimal event target used by the host client. */
export interface WalletHostEventTarget {
  addEventListener(
    type: "message",
    listener: (event: WalletHostMessageEvent) => void,
  ): void;
  removeEventListener(
    type: "message",
    listener: (event: WalletHostMessageEvent) => void,
  ): void;
}

/** Construction parameters binding the client to one exact wallet window/origin. */
export interface WalletHostClientOptions {
  readonly walletWindow: WalletMessageSource;
  readonly walletOrigin: string;
  readonly eventTarget?: WalletHostEventTarget;
  /** Request timeout in milliseconds, 1..300,000; default 120,000. */
  readonly timeoutMs?: number;
}

/** Public host-side error with no wallet secret contents. */
export class WalletHostError extends Error {
  readonly code: WalletResponseErrorCode | "TIMEOUT" | "CLIENT_CLOSED";

  constructor(
    code: WalletResponseErrorCode | "TIMEOUT" | "CLIENT_CLOSED",
    message: string,
  ) {
    super(message);
    this.name = "WalletHostError";
    this.code = code;
  }
}

interface PendingRequest {
  readonly method: WalletRequest["method"];
  readonly resolve: (value: unknown) => void;
  readonly reject: (error: WalletHostError) => void;
  readonly timer: ReturnType<typeof setTimeout>;
  retryTimer?: ReturnType<typeof setTimeout>;
}

/** Host transfer intent; session replay fields are injected by the client. */
export type WalletNativeTransferIntent = Omit<
  WalletNativeTransferParams,
  "session_id" | "sequence"
>;

/**
 * Exact-origin postMessage client for connection, transfer signing, and revoke.
 *
 * Call `close()` when the frame/window is removed. A client refuses more than
 * 64 concurrent requests and times each one out so a hostile or navigated frame
 * cannot retain unbounded promises.
 */
export class WalletHostClient {
  readonly #walletWindow: WalletMessageSource;
  readonly #walletOrigin: string;
  readonly #eventTarget: WalletHostEventTarget;
  readonly #timeoutMs: number;
  readonly #pending = new Map<string, PendingRequest>();
  readonly #listener: (event: WalletHostMessageEvent) => void;
  #connection: WalletConnectionResult | undefined;
  #nextSequence = 0;
  #closed = false;

  constructor(options: WalletHostClientOptions) {
    if (!isSecureWalletHostOrigin(options.walletOrigin)) {
      throw new WalletHostError(
        "INVALID_REQUEST",
        "wallet origin must be exact HTTPS or localhost",
      );
    }
    const timeoutMs = options.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    if (
      !Number.isSafeInteger(timeoutMs) ||
      timeoutMs < 1 ||
      timeoutMs > MAX_REQUEST_TIMEOUT_MS
    ) {
      throw new WalletHostError("INVALID_REQUEST", "wallet timeout is invalid");
    }
    const eventTarget = options.eventTarget ?? (window as unknown as WalletHostEventTarget);
    this.#walletWindow = options.walletWindow;
    this.#walletOrigin = options.walletOrigin;
    this.#eventTarget = eventTarget;
    this.#timeoutMs = timeoutMs;
    this.#listener = (event) => this.#handleResponse(event);
    this.#eventTarget.addEventListener("message", this.#listener);
  }

  /** Requests a user-approved transfer grant and returns public account data. */
  async connect(limits: WalletSpendLimitsJson): Promise<WalletConnectionResult> {
    const requestedLimits: WalletSpendLimitsJson = {
      max_amount_per_transaction: limits.max_amount_per_transaction,
      max_total_amount: limits.max_total_amount,
      max_fee_per_transaction: limits.max_fee_per_transaction,
    };
    parseSpendLimits(requestedLimits);
    const params: WalletConnectParams = {
      scopes: ["sign_native_transfer"],
      limits: requestedLimits,
    };
    const result = await this.#request("connect", params);
    const connection = parseConnectionResult(result);
    if (
      connection.limits.max_amount_per_transaction !==
        requestedLimits.max_amount_per_transaction ||
      connection.limits.max_total_amount !== requestedLimits.max_total_amount ||
      connection.limits.max_fee_per_transaction !==
        requestedLimits.max_fee_per_transaction ||
      (await addressFromPublicKey(hexToBytes(connection.public_key))) !==
        connection.address
    ) {
      throw new WalletHostError(
        "INTERNAL_ERROR",
        "wallet connection result differs from the approved request",
      );
    }
    this.#connection = connection;
    this.#nextSequence = 0;
    return connection;
  }

  /** Requests one human-confirmed native transfer and verifies the signed result. */
  async signNativeTransfer(
    params: WalletNativeTransferIntent,
  ): Promise<SignedTransactionJson> {
    const connection = this.#connection;
    if (!connection) {
      throw new WalletHostError(
        "PERMISSION_REQUIRED",
        "wallet connection is required before signing",
      );
    }
    if (params.authorization_lane !== connection.authorization_lane) {
      throw new WalletHostError(
        "PERMISSION_REQUIRED",
        "request does not use the origin-assigned lane",
      );
    }
    const wireParams: WalletNativeTransferParams = {
      protocol_version: params.protocol_version,
      chain_id: params.chain_id,
      nonce: params.nonce,
      authorization_lane: params.authorization_lane,
      authorization_policy_revision: params.authorization_policy_revision,
      recipient: params.recipient,
      amount: params.amount,
      fee: {
        gasLimit: params.fee.gasLimit,
        maxFeePerUnit: params.fee.maxFeePerUnit,
        priorityFeePerUnit: params.fee.priorityFeePerUnit,
      },
      session_id: connection.session_id,
      sequence: this.#nextSequence,
    };
    const result = await this.#request("sign_native_transfer", wireParams);
    let transaction: SignedTransactionJson;
    try {
      transaction = parseSignedTransactionResult(result);
      if (!(await verifySignedTransaction(transaction))) {
        throw new Error("invalid signature");
      }
      assertTransactionMatchesRequest(transaction, wireParams, connection);
    } catch {
      throw new WalletHostError(
        "INTERNAL_ERROR",
        "wallet returned an invalid or mismatched signed transaction",
      );
    }
    this.#nextSequence += 1;
    return transaction;
  }

  /** Revokes this origin's in-memory grant and clears the cached connection. */
  async revoke(): Promise<void> {
    const result = await this.#request("revoke", {});
    const record = exactRecord(result, ["revoked"]);
    if (record.revoked !== true) invalidResponse();
    this.#connection = undefined;
    this.#nextSequence = 0;
  }

  /** Rejects pending work and detaches the response listener exactly once. */
  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#eventTarget.removeEventListener("message", this.#listener);
    for (const pending of this.#pending.values()) {
      clearTimeout(pending.timer);
      if (pending.retryTimer) clearTimeout(pending.retryTimer);
      pending.reject(new WalletHostError("CLIENT_CLOSED", "wallet client is closed"));
    }
    this.#pending.clear();
    this.#connection = undefined;
    this.#nextSequence = 0;
  }

  #request(method: WalletRequest["method"], params: unknown): Promise<unknown> {
    if (this.#closed) {
      return Promise.reject(
        new WalletHostError("CLIENT_CLOSED", "wallet client is closed"),
      );
    }
    if (this.#pending.size >= MAX_PENDING_REQUESTS) {
      return Promise.reject(
        new WalletHostError("INVALID_REQUEST", "too many pending wallet requests"),
      );
    }
    let requestId = createWalletRequestId();
    while (this.#pending.has(requestId)) requestId = createWalletRequestId();
    const request = {
      channel: WALLET_MESSAGE_CHANNEL,
      version: WALLET_MESSAGE_VERSION,
      request_id: requestId,
      method,
      params,
    };

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(requestId);
        reject(new WalletHostError("TIMEOUT", "wallet request timed out"));
      }, this.#timeoutMs);
      this.#pending.set(requestId, {
        method,
        resolve,
        reject,
        timer,
      });
      this.#sendWithRetry(requestId, request, 0);
    });
  }

  #sendWithRetry(requestId: string, request: unknown, attempt: number): void {
    const pending = this.#pending.get(requestId);
    if (!pending) return;
    try {
      this.#walletWindow.postMessage(request, this.#walletOrigin);
    } catch {
      // A newly opened or navigating WindowProxy may reject briefly. The main
      // timeout remains authoritative and no fallback target origin is used.
    }
    if (!this.#pending.has(requestId)) return;
    const delay = Math.min(250 * 2 ** Math.min(attempt, 3), 2_000);
    pending.retryTimer = setTimeout(
      () => this.#sendWithRetry(requestId, request, attempt + 1),
      delay,
    );
  }

  #handleResponse(event: WalletHostMessageEvent): void {
    if (
      this.#closed ||
      event.source !== this.#walletWindow ||
      event.origin !== this.#walletOrigin
    ) {
      return;
    }
    let envelope: Record<string, unknown>;
    try {
      envelope = parseResponseEnvelope(event.data);
    } catch {
      return;
    }
    const requestId = envelope.request_id as string;
    const pending = this.#pending.get(requestId);
    if (!pending) return;
    clearTimeout(pending.timer);
    if (pending.retryTimer) clearTimeout(pending.retryTimer);
    this.#pending.delete(requestId);

    if (envelope.ok === false) {
      const error = exactRecord(envelope.error, ["code", "message"]);
      if (
        typeof error.code !== "string" ||
        !isWalletErrorCode(error.code) ||
        typeof error.message !== "string" ||
        error.message.length > 256
      ) {
        pending.reject(new WalletHostError("INVALID_REQUEST", "wallet response is invalid"));
        return;
      }
      pending.reject(
        new WalletHostError(
          error.code,
          error.message,
        ),
      );
      return;
    }
    pending.resolve(envelope.result);
  }
}

function parseResponseEnvelope(input: unknown): Record<string, unknown> {
  const base = isPlainRecord(input) ? input : invalidResponse();
  if (
    base.channel !== WALLET_MESSAGE_CHANNEL ||
    base.version !== WALLET_MESSAGE_VERSION ||
    typeof base.request_id !== "string" ||
    !/^[0-9a-f]{64}$/u.test(base.request_id) ||
    typeof base.ok !== "boolean"
  ) {
    invalidResponse();
  }
  const expected = base.ok
    ? ["channel", "version", "request_id", "ok", "result"]
    : ["channel", "version", "request_id", "ok", "error"];
  return exactRecord(base, expected);
}

function parseConnectionResult(input: unknown): WalletConnectionResult {
  const record = exactRecord(input, [
    "address",
    "public_key",
    "authorization_lane",
    "authorization_policy_revision",
    "session_id",
    "scopes",
    "limits",
  ]);
  if (
    typeof record.address !== "string" ||
    typeof record.public_key !== "string" ||
    typeof record.authorization_lane !== "string" ||
    typeof record.authorization_policy_revision !== "number" ||
    !Number.isSafeInteger(record.authorization_policy_revision) ||
    record.authorization_policy_revision < 0 ||
    typeof record.session_id !== "string" ||
    !/^[0-9a-f]{64}$/u.test(record.session_id) ||
    !Array.isArray(record.scopes) ||
    record.scopes.length !== 1 ||
    record.scopes[0] !== "sign_native_transfer"
  ) {
    invalidResponse();
  }
  try {
    addressToBytes(record.address);
    if (
      record.public_key.length !== 64 ||
      record.public_key !== record.public_key.toLowerCase() ||
      hexToBytes(record.public_key).length !== 32 ||
      record.authorization_lane.length !== 64 ||
      record.authorization_lane !== record.authorization_lane.toLowerCase() ||
      hexToBytes(record.authorization_lane).length !== 32
    ) {
      invalidResponse();
    }
  } catch {
    invalidResponse();
  }
  const limits = parseLimitsResult(record.limits);
  return Object.freeze({
    address: record.address,
    public_key: record.public_key,
    authorization_lane: record.authorization_lane,
    authorization_policy_revision: record.authorization_policy_revision,
    session_id: record.session_id,
    scopes: Object.freeze(["sign_native_transfer"] as const),
    limits: Object.freeze(limits),
  });
}

function parseLimitsResult(input: unknown): WalletSpendLimitsJson {
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
    invalidResponse();
  }
  const limits = {
    max_amount_per_transaction: record.max_amount_per_transaction,
    max_total_amount: record.max_total_amount,
    max_fee_per_transaction: record.max_fee_per_transaction,
  };
  parseSpendLimits(limits);
  return limits;
}

function parseSignedTransactionResult(input: unknown): SignedTransactionJson {
  const record = exactRecord(input, [
    "protocol_version",
    "chain_id",
    "sender",
    "public_key",
    "authorization_lane",
    "authorization_policy_revision",
    "nonce",
    "operation",
    "access_list",
    "fee",
    "signature",
  ]);
  return record as unknown as SignedTransactionJson;
}

function assertTransactionMatchesRequest(
  transaction: SignedTransactionJson,
  params: WalletNativeTransferParams,
  connection: WalletConnectionResult,
): void {
  const operation = transaction.operation;
  const isTransfer =
    typeof operation === "object" &&
    operation !== null &&
    "Transfer" in operation;
  if (
    !isTransfer ||
    operation.Transfer.to !== params.recipient ||
    operation.Transfer.amount !== params.amount ||
    transaction.protocol_version !== params.protocol_version ||
    transaction.chain_id !== params.chain_id ||
    transaction.sender !== connection.address ||
    transaction.public_key !== connection.public_key ||
    transaction.authorization_lane !== params.authorization_lane ||
    transaction.authorization_policy_revision !==
      params.authorization_policy_revision ||
    transaction.nonce !== params.nonce ||
    transaction.fee.gas_limit !== params.fee.gasLimit ||
    transaction.fee.max_fee_per_unit !== params.fee.maxFeePerUnit ||
    transaction.fee.priority_fee_per_unit !== params.fee.priorityFeePerUnit
  ) {
    throw new WalletHostError(
      "INTERNAL_ERROR",
      "signed transaction differs from the confirmed request",
    );
  }
}

function exactRecord(
  input: unknown,
  expectedKeys: readonly string[],
): Record<string, unknown> {
  if (!isPlainRecord(input)) invalidResponse();
  const actual = Object.keys(input).sort();
  const expected = [...expectedKeys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    invalidResponse();
  }
  return input;
}

function isPlainRecord(input: unknown): input is Record<string, unknown> {
  return (
    typeof input === "object" &&
    input !== null &&
    !Array.isArray(input) &&
    Object.getPrototypeOf(input) === Object.prototype
  );
}

function invalidResponse(): never {
  throw new WalletRequestError("INVALID_REQUEST", "wallet response is invalid");
}

function isWalletErrorCode(value: string): value is WalletResponseErrorCode {
  return [
    "INVALID_REQUEST",
    "UNSUPPORTED_VERSION",
    "REQUEST_REPLAY",
    "PERMISSION_REQUIRED",
    "LIMIT_EXCEEDED",
    "CHAIN_MISMATCH",
    "USER_REJECTED",
    "INTERNAL_ERROR",
  ].includes(value);
}
