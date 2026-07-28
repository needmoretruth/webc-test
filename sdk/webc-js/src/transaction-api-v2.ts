/**
 * Protocol-2 transaction HTTP and lifecycle-WebSocket client contracts.
 *
 * Purpose: mirror the bounded `/v2/transactions` Rust transport in browser-safe
 * types and strict parsers. Responsibilities: validate lifecycle, insertion,
 * receipt, and socket-message JSON; bind responses to the requested transaction;
 * and provide an explicit sequence-preserving reconnect handle. Non-
 * responsibilities: signing V5 transactions, deciding lifecycle/finality, or
 * cryptographically verifying finalized proofs. Data flow: `WebcNodeClient`
 * supplies already byte-capped HTTP JSON or a WebSocket constructor, this module
 * validates/project it, then calls host handlers only with bounded typed values.
 * Security boundary: the node and injected transport are hostile; field sets,
 * integer encodings, identities, collection sizes, message bytes, and monotonic
 * sequences all fail closed before application callbacks run.
 */

import {
  MAX_RECEIPT_V1_JSON_BYTES,
  validateReceiptV1,
  type ReceiptV1Json,
} from "./receipt-v1.js";
import type { WebSocketConstructor, WebSocketLike } from "./node-client.js";

/** Stable route family returned by the Rust protocol-2 transaction API. */
export const TRANSACTION_API_VERSION_V2 = "v2" as const;

/** Maximum transaction IDs accepted by one lifecycle subscription. */
export const MAX_TRANSACTION_LIFECYCLE_IDS_V2 = 64;

/** Maximum UTF-8 bytes accepted for one lifecycle WebSocket message. */
export const MAX_TRANSACTION_LIFECYCLE_WS_MESSAGE_BYTES_V2 = 16 * 1024;

/** Maximum successful submit/lifecycle response bytes accepted by the SDK. */
export const MAX_TRANSACTION_API_RESPONSE_BYTES_V2 = 64 * 1024;

/** Receipt response cap shared with the strict V1 receipt schema. */
export const MAX_TRANSACTION_RECEIPT_RESPONSE_BYTES_V2 = MAX_RECEIPT_V1_JSON_BYTES;

const U64_MAX = (1n << 64n) - 1n;
const U32_MAX = 0xffff_ffff;
const MAX_ERROR_CODE_CHARS = 64;
const MAX_ERROR_MESSAGE_CHARS = 256;
const MAX_REQUEST_ID_CHARS = 128;

/** Exact finalized or candidate position returned by a lifecycle snapshot. */
export interface TransactionPositionV2 {
  /** Consensus block height as an exact unsigned 64-bit value. */
  readonly height: bigint;
  /** Zero-based transaction index inside the block. */
  readonly transactionIndex: number;
}

/** Stable reason a node stopped retaining a pending transaction locally. */
export type TransactionDropReasonV2 =
  | "capacity_eviction"
  | "revalidation_failed"
  | "unsupported_protocol_version"
  | "operator_request"
  | "finalized_slot_conflict";

/** Finality-preferred public status returned by lifecycle queries and streams. */
export type TransactionLifecycleStatusV2 =
  | Readonly<{ kind: "unknown" }>
  | Readonly<{ kind: "queued"; observedAtMs: bigint }>
  | Readonly<{
      kind: "replaced";
      replacementId: string;
      observedAtMs: bigint;
    }>
  | Readonly<{
      kind: "dropped";
      reason: TransactionDropReasonV2;
      observedAtMs: bigint;
    }>
  | Readonly<{ kind: "expired"; observedAtMs: bigint }>
  | Readonly<{ kind: "included"; position: TransactionPositionV2 }>
  | Readonly<{ kind: "finalized"; position: TransactionPositionV2 }>;

/** One strict lifecycle projection for an exact V5 transaction identity. */
export interface TransactionLifecycleV2 {
  /** Stable API family; exactly `v2`. */
  readonly apiVersion: typeof TRANSACTION_API_VERSION_V2;
  /** Lowercase domain-separated 32-byte transaction ID. */
  readonly transactionId: string;
  /** Durable global observation order, or `null` only for `unknown`. */
  readonly sequence: bigint | null;
  /** Finality-preferred lifecycle status. */
  readonly status: TransactionLifecycleStatusV2;
}

/** Typed successful mempool insertion classification. */
export type TransactionInsertOutcomeV2 =
  | Readonly<{ kind: "duplicate_known" }>
  | Readonly<{ kind: "added" }>
  | Readonly<{ kind: "replaced"; oldId: string }>
  | Readonly<{ kind: "evicted"; oldId: string }>;

/** Successful durable response from `POST /v2/transactions`. */
export interface TransactionSubmitResponseV2 {
  /** Stable API family; exactly `v2`. */
  readonly apiVersion: typeof TRANSACTION_API_VERSION_V2;
  /** ID of the exact submitted signed V5 transaction. */
  readonly transactionId: string;
  /** Idempotent insertion/replacement result. */
  readonly outcome: TransactionInsertOutcomeV2;
  /** Latest durable lifecycle snapshot for `transactionId`. */
  readonly lifecycle: TransactionLifecycleV2;
  /** Pending transaction count after durable admission. */
  readonly mempoolSize: number;
}

/** Server instruction to reconnect and request an actor-consistent resnapshot. */
export interface TransactionLifecycleResyncV2 {
  /** Highest durable lifecycle sequence safely delivered by the old socket. */
  readonly lastSequence: bigint;
  /** Bounded node-local correlation ID for operator diagnostics. */
  readonly requestId: string;
}

/** Strictly parsed server-to-client lifecycle socket message. */
export type TransactionLifecycleWsMessageV2 =
  | Readonly<{ type: "snapshot"; lifecycle: TransactionLifecycleV2 }>
  | Readonly<{
      type: "resync_required";
      lastSequence: bigint;
      requestId: string;
    }>
  | Readonly<{
      type: "error";
      code: string;
      message: string;
      requestId: string;
    }>;

/** Handlers invoked by a protocol-2 lifecycle subscription. */
export interface TransactionLifecycleSubscriptionHandlersV2 {
  /** Receives each new, validated snapshot; stale known sequences are ignored. */
  readonly onLifecycle: (lifecycle: TransactionLifecycleV2) => void;
  /** Receives a resumable marker after server-side subscriber lag. */
  readonly onResyncRequired: (notice: TransactionLifecycleResyncV2) => void;
  /** Receives transport, parsing, callback, or typed server errors. */
  readonly onError?: (error: unknown) => void;
  /** Runs when the currently active socket reports that it closed. */
  readonly onClose?: () => void;
}

/** Initial cursor for a protocol-2 lifecycle subscription. */
export interface TransactionLifecycleSubscriptionOptionsV2 {
  /** Last durable sequence already applied; the first socket resnapshots after it. */
  readonly afterSequence?: bigint;
}

/** Explicitly controlled, sequence-preserving lifecycle subscription handle. */
export interface TransactionLifecycleSubscriptionV2 {
  /** Highest durable sequence supplied or safely applied, if any. */
  readonly lastSequence: bigint | null;
  /** Reopens the socket and resnapshots strictly after `lastSequence`. */
  reconnect(): void;
  /** Permanently closes the current socket; reconnect then fails closed. */
  close(): void;
}

/** Typed safe error sent by the lifecycle WebSocket server. */
export class TransactionLifecycleSubscriptionError extends Error {
  /** Stable machine-readable server code. */
  readonly code: string;
  /** Bounded correlation ID used to find node-side logs. */
  readonly requestId: string;

  constructor(code: string, message: string, requestId: string) {
    super(message);
    this.name = "TransactionLifecycleSubscriptionError";
    this.code = code;
    this.requestId = requestId;
  }
}

/** Rejects any value that is not a canonical lowercase V5 transaction ID. */
export function validateTransactionIdV2(input: unknown): asserts input is string {
  transactionIdV2(input, "transaction ID");
}

/**
 * Parses one lifecycle query or socket snapshot and optionally binds its ID to
 * the caller's requested transaction.
 */
export function parseTransactionLifecycleV2(
  input: unknown,
  expectedTransactionId?: string,
): TransactionLifecycleV2 {
  const value = exactRecord(
    input,
    ["api_version", "transaction_id", "sequence", "status"],
    "V2 transaction lifecycle",
  );
  if (value.api_version !== TRANSACTION_API_VERSION_V2) {
    throw new Error("unsupported V2 transaction lifecycle API version");
  }
  const transactionId = transactionIdV2(value.transaction_id, "transaction ID");
  if (expectedTransactionId !== undefined) {
    const expected = transactionIdV2(expectedTransactionId, "expected transaction ID");
    if (transactionId !== expected) {
      throw new Error("V2 lifecycle transaction ID does not match the request");
    }
  }
  const status = parseLifecycleStatusV2(value.status);
  const sequence = value.sequence === null
    ? null
    : canonicalU64(value.sequence, "lifecycle sequence");
  if ((status.kind === "unknown") !== (sequence === null)) {
    throw new Error("V2 lifecycle sequence must be null exactly for unknown status");
  }
  return Object.freeze({
    apiVersion: TRANSACTION_API_VERSION_V2,
    transactionId,
    sequence,
    status,
  });
}

/** Parses and identity-binds one successful protocol-2 submission response. */
export function parseTransactionSubmitResponseV2(
  input: unknown,
  expectedTransactionId: string,
): TransactionSubmitResponseV2 {
  const expected = transactionIdV2(expectedTransactionId, "expected transaction ID");
  const value = exactRecord(
    input,
    ["api_version", "transaction_id", "outcome", "lifecycle", "mempool_size"],
    "V2 transaction submission",
  );
  if (value.api_version !== TRANSACTION_API_VERSION_V2) {
    throw new Error("unsupported V2 transaction submission API version");
  }
  const transactionId = transactionIdV2(value.transaction_id, "submitted transaction ID");
  if (transactionId !== expected) {
    throw new Error("V2 submission transaction ID does not match the signed request");
  }
  const lifecycle = parseTransactionLifecycleV2(value.lifecycle, expected);
  return Object.freeze({
    apiVersion: TRANSACTION_API_VERSION_V2,
    transactionId,
    outcome: parseInsertOutcomeV2(value.outcome),
    lifecycle,
    mempoolSize: safeCount(value.mempool_size, "mempool size"),
  });
}

/**
 * Reuses the consensus receipt validator and binds the finalized receipt to the
 * queried transaction ID. Transport code must enforce the exported byte cap.
 */
export function parseFinalizedTransactionReceiptV2(
  input: unknown,
  expectedTransactionId: string,
): ReceiptV1Json {
  const expected = transactionIdV2(expectedTransactionId, "expected transaction ID");
  validateReceiptV1(input);
  if (input.transaction_id !== expected) {
    throw new Error("V2 finalized receipt transaction ID does not match the request");
  }
  return input;
}

/** Parses one already byte-capped server lifecycle WebSocket message. */
export function parseTransactionLifecycleWsMessageV2(
  input: unknown,
): TransactionLifecycleWsMessageV2 {
  const outer = record(input, "V2 lifecycle WebSocket message");
  if (outer.type === "snapshot") {
    exactKeys(outer, ["type", "lifecycle"], "V2 lifecycle snapshot");
    return Object.freeze({
      type: "snapshot",
      lifecycle: parseTransactionLifecycleV2(outer.lifecycle),
    });
  }
  if (outer.type === "resync_required") {
    exactKeys(
      outer,
      ["type", "last_sequence", "request_id"],
      "V2 lifecycle resync message",
    );
    return Object.freeze({
      type: "resync_required",
      lastSequence: canonicalU64(outer.last_sequence, "resync sequence"),
      requestId: boundedRequestId(outer.request_id),
    });
  }
  if (outer.type === "error") {
    exactKeys(
      outer,
      ["type", "code", "message", "request_id"],
      "V2 lifecycle error message",
    );
    return Object.freeze({
      type: "error",
      code: boundedErrorCode(outer.code),
      message: boundedText(
        outer.message,
        "lifecycle error message",
        MAX_ERROR_MESSAGE_CHARS,
      ),
      requestId: boundedRequestId(outer.request_id),
    });
  }
  throw new Error("unknown V2 lifecycle WebSocket message type");
}

/**
 * Opens a bounded lifecycle socket. Reconnection is deliberately explicit: the
 * SDK preserves the server's durable sequence marker but never creates an
 * attacker-triggered infinite reconnect loop or hidden retry timer.
 */
export function openTransactionLifecycleSubscriptionV2(
  url: string,
  webSocket: WebSocketConstructor,
  transactionIds: readonly string[],
  handlers: TransactionLifecycleSubscriptionHandlersV2,
  options: TransactionLifecycleSubscriptionOptionsV2 = {},
): TransactionLifecycleSubscriptionV2 {
  const ids = validateSubscriptionIds(transactionIds);
  const subscribed = new Set(ids);
  let lastSequence = options.afterSequence === undefined
    ? null
    : requireU64BigInt(options.afterSequence, "afterSequence");
  let socket: WebSocketLike | undefined;
  let generation = 0;
  let permanentlyClosed = false;

  const reportError = (error: unknown): void => {
    try {
      handlers.onError?.(error);
    } catch {
      // Application error handlers are outside the transport trust boundary.
    }
  };

  const connect = (): void => {
    if (permanentlyClosed) {
      throw new Error("transaction lifecycle subscription is permanently closed");
    }
    const next = new webSocket(url);
    if (typeof next.send !== "function") {
      next.close();
      throw new Error("WebSocket implementation does not support text send");
    }
    const previous = socket;
    socket = next;
    generation += 1;
    const ownGeneration = generation;
    previous?.close();
    let subscriptionSent = false;

    const isCurrent = (): boolean =>
      !permanentlyClosed && generation === ownGeneration && socket === next;

    next.addEventListener("open", () => {
      if (!isCurrent() || subscriptionSent) return;
      subscriptionSent = true;
      try {
        const request = lastSequence === null
          ? { version: 1, transaction_ids: ids }
          : {
              version: 1,
              transaction_ids: ids,
              after_sequence: lastSequence.toString(),
            };
        const text = JSON.stringify(request);
        if (utf8ByteLength(text) > MAX_TRANSACTION_LIFECYCLE_WS_MESSAGE_BYTES_V2) {
          throw new Error("V2 lifecycle subscription request exceeds its byte limit");
        }
        next.send?.(text);
      } catch (error) {
        reportError(error);
        next.close();
      }
    });

    next.addEventListener("message", (event) => {
      if (!isCurrent()) return;
      try {
        const message = parseTransactionLifecycleWsMessageV2(
          decodeBoundedWsJson(event.data),
        );
        if (message.type === "snapshot") {
          if (!subscribed.has(message.lifecycle.transactionId)) {
            throw new Error("V2 lifecycle snapshot names an unsubscribed transaction ID");
          }
          const sequence = message.lifecycle.sequence;
          if (sequence !== null && lastSequence !== null && sequence <= lastSequence) {
            return;
          }
          if (sequence !== null) lastSequence = sequence;
          handlers.onLifecycle(message.lifecycle);
          return;
        }
        if (message.type === "resync_required") {
          if (lastSequence !== null && message.lastSequence < lastSequence) {
            throw new Error("V2 lifecycle resync marker moves backwards");
          }
          lastSequence = message.lastSequence;
          next.close();
          handlers.onResyncRequired(Object.freeze({
            lastSequence: message.lastSequence,
            requestId: message.requestId,
          }));
          return;
        }
        reportError(new TransactionLifecycleSubscriptionError(
          message.code,
          message.message,
          message.requestId,
        ));
        next.close();
      } catch (error) {
        reportError(error);
        next.close();
      }
    });
    next.addEventListener("error", (event) => {
      if (isCurrent()) reportError(event);
    });
    next.addEventListener("close", () => {
      if (!isCurrent()) return;
      try {
        handlers.onClose?.();
      } catch (error) {
        reportError(error);
      }
    });
  };

  connect();
  return {
    get lastSequence(): bigint | null {
      return lastSequence;
    },
    reconnect(): void {
      connect();
    },
    close(): void {
      if (permanentlyClosed) return;
      permanentlyClosed = true;
      generation += 1;
      socket?.close();
    },
  };
}

function parseLifecycleStatusV2(input: unknown): TransactionLifecycleStatusV2 {
  const value = record(input, "V2 transaction status");
  if (value.kind === "unknown") {
    exactKeys(value, ["kind"], "unknown V2 transaction status");
    return Object.freeze({ kind: "unknown" });
  }
  if (value.kind === "queued" || value.kind === "expired") {
    exactKeys(value, ["kind", "observed_at_ms"], `${value.kind} V2 transaction status`);
    return Object.freeze({
      kind: value.kind,
      observedAtMs: canonicalU64(value.observed_at_ms, "observation timestamp"),
    });
  }
  if (value.kind === "replaced") {
    exactKeys(
      value,
      ["kind", "replacement_id", "observed_at_ms"],
      "replaced V2 transaction status",
    );
    return Object.freeze({
      kind: "replaced",
      replacementId: transactionIdV2(value.replacement_id, "replacement transaction ID"),
      observedAtMs: canonicalU64(value.observed_at_ms, "replacement timestamp"),
    });
  }
  if (value.kind === "dropped") {
    exactKeys(
      value,
      ["kind", "reason", "observed_at_ms"],
      "dropped V2 transaction status",
    );
    return Object.freeze({
      kind: "dropped",
      reason: dropReasonV2(value.reason),
      observedAtMs: canonicalU64(value.observed_at_ms, "drop timestamp"),
    });
  }
  if (value.kind === "included" || value.kind === "finalized") {
    exactKeys(value, ["kind", "position"], `${value.kind} V2 transaction status`);
    return Object.freeze({
      kind: value.kind,
      position: parsePositionV2(value.position),
    });
  }
  throw new Error("unknown V2 transaction status kind");
}

function parsePositionV2(input: unknown): TransactionPositionV2 {
  const value = exactRecord(
    input,
    ["height", "transaction_index"],
    "V2 transaction position",
  );
  return Object.freeze({
    height: canonicalU64(value.height, "block height"),
    transactionIndex: u32(value.transaction_index, "transaction index"),
  });
}

function parseInsertOutcomeV2(input: unknown): TransactionInsertOutcomeV2 {
  const value = record(input, "V2 insertion outcome");
  if (value.kind === "duplicate_known" || value.kind === "added") {
    exactKeys(value, ["kind"], "V2 insertion outcome");
    return Object.freeze({ kind: value.kind });
  }
  if (value.kind === "replaced" || value.kind === "evicted") {
    exactKeys(value, ["kind", "old_id"], "V2 insertion outcome");
    return Object.freeze({
      kind: value.kind,
      oldId: transactionIdV2(value.old_id, "old transaction ID"),
    });
  }
  throw new Error("unknown V2 insertion outcome kind");
}

function dropReasonV2(input: unknown): TransactionDropReasonV2 {
  if (
    input === "capacity_eviction"
    || input === "revalidation_failed"
    || input === "unsupported_protocol_version"
    || input === "operator_request"
    || input === "finalized_slot_conflict"
  ) {
    return input;
  }
  throw new Error("unknown V2 local drop reason");
}

function validateSubscriptionIds(input: readonly string[]): readonly string[] {
  if (!Array.isArray(input) || input.length === 0) {
    throw new Error("V2 lifecycle subscription requires at least one transaction ID");
  }
  if (input.length > MAX_TRANSACTION_LIFECYCLE_IDS_V2) {
    throw new Error(
      `V2 lifecycle subscription accepts at most ${MAX_TRANSACTION_LIFECYCLE_IDS_V2} transaction IDs`,
    );
  }
  const ids = input.map((value, index) =>
    transactionIdV2(value, `transactionIds[${index}]`));
  if (new Set(ids).size !== ids.length) {
    throw new Error("V2 lifecycle subscription transaction IDs must be unique");
  }
  return Object.freeze(ids);
}

function decodeBoundedWsJson(input: unknown): unknown {
  if (typeof input !== "string") {
    throw new Error("expected a text V2 lifecycle WebSocket message");
  }
  if (
    input.length > MAX_TRANSACTION_LIFECYCLE_WS_MESSAGE_BYTES_V2
    || utf8ByteLength(input) > MAX_TRANSACTION_LIFECYCLE_WS_MESSAGE_BYTES_V2
  ) {
    throw new Error("V2 lifecycle WebSocket message exceeds its byte limit");
  }
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("node returned invalid lifecycle WebSocket JSON");
  }
}

function utf8ByteLength(input: string): number {
  return new TextEncoder().encode(input).byteLength;
}

function transactionIdV2(input: unknown, label: string): string {
  if (typeof input !== "string" || !/^[0-9a-f]{64}$/.test(input)) {
    throw new Error(`${label} must be a lowercase 32-byte hex transaction ID`);
  }
  return input;
}

function canonicalU64(input: unknown, label: string): bigint {
  if (
    typeof input !== "string"
    || input.length === 0
    || input.length > 20
    || !/^(0|[1-9][0-9]*)$/.test(input)
  ) {
    throw new Error(`${label} must be a canonical unsigned decimal string`);
  }
  const value = BigInt(input);
  if (value > U64_MAX) throw new Error(`${label} exceeds the unsigned 64-bit range`);
  return value;
}

function requireU64BigInt(input: bigint, label: string): bigint {
  if (typeof input !== "bigint" || input < 0n || input > U64_MAX) {
    throw new Error(`${label} must be an unsigned 64-bit bigint`);
  }
  return input;
}

function u32(input: unknown, label: string): number {
  if (!Number.isInteger(input) || (input as number) < 0 || (input as number) > U32_MAX) {
    throw new Error(`${label} must be an unsigned 32-bit integer`);
  }
  return input as number;
}

function safeCount(input: unknown, label: string): number {
  if (!Number.isSafeInteger(input) || (input as number) < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return input as number;
}

function boundedErrorCode(input: unknown): string {
  const value = boundedText(input, "lifecycle error code", MAX_ERROR_CODE_CHARS);
  if (!/^[a-z][a-z0-9_]*$/.test(value)) {
    throw new Error("lifecycle error code is not a stable snake-case identifier");
  }
  return value;
}

function boundedRequestId(input: unknown): string {
  const value = boundedText(input, "lifecycle request ID", MAX_REQUEST_ID_CHARS);
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("lifecycle request ID contains unsupported characters");
  }
  return value;
}

function boundedText(input: unknown, label: string, maximum: number): string {
  if (typeof input !== "string" || input.length === 0 || input.length > maximum) {
    throw new Error(`${label} must contain between 1 and ${maximum} characters`);
  }
  return input;
}

function record(input: unknown, label: string): Record<string, unknown> {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new Error(`${label} must be an object`);
  }
  return input as Record<string, unknown>;
}

function exactRecord(
  input: unknown,
  expectedKeys: readonly string[],
  label: string,
): Record<string, unknown> {
  const value = record(input, label);
  exactKeys(value, expectedKeys, label);
  return value;
}

function exactKeys(
  input: Record<string, unknown>,
  expectedKeys: readonly string[],
  label: string,
): void {
  const actual = Object.keys(input).sort();
  const expected = [...expectedKeys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(`${label} has an unexpected field set`);
  }
}
