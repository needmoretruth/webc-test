/**
 * Protocol-version-2 receipt, event, and ordered Merkle commitments.
 *
 * This mirrors Rust `webc_chain::receipt_v1`: it validates hostile receipt
 * JSON, reconciles fee arithmetic, binds receipts to signed V5 transactions,
 * and computes the same domain-separated leaves and ordered roots. It does not
 * execute actions, decide finality, or verify a block header/proof.
 */

import { addressToBytes } from "./address.js";
import { canonicalJsonBytes, canonicalJsonHashHex } from "./canonical.js";
import { bytesToHex, hexToBytes } from "./hex.js";
import {
  transactionV5IdHex,
  validateTransactionV5Structure,
  type DecimalU64,
  type SignedTransactionV5Json,
} from "./transaction-v5.js";
import type { WebcAddress } from "./types.js";

export const RECEIPT_V1 = 1;
export const EVENT_V1 = 1;
export const RECEIPT_V1_DOMAIN = "WEBC_RECEIPT_V1";
export const RECEIPT_LEAF_V1_DOMAIN = "WEBC_RECEIPT_LEAF_V1";
export const EVENT_V1_DOMAIN = "WEBC_EVENT_V1";
export const TRANSACTION_LEAF_V1_DOMAIN = "WEBC_TRANSACTION_LEAF_V1";
export const MERKLE_V1_DOMAIN = "WEBC_MERKLE_V1";
/** Maximum events retained or hashed from one untrusted V1 receipt. */
export const MAX_RECEIPT_EVENTS_V1 = 256;

const U64_MAX = (1n << 64n) - 1n;
const U128_MAX = (1n << 128n) - 1n;

export interface BlockPositionV1Json {
  height: DecimalU64;
  transaction_index: number;
}

export interface FeePayerV1Json {
  address: WebcAddress;
  lane: string;
}

export interface FeeSummaryV1Json {
  version: 1;
  payer: FeePayerV1Json;
  gas_limit: DecimalU64;
  units_consumed: DecimalU64;
  base_fee_per_unit: DecimalU64;
  priority_fee_per_unit: DecimalU64;
  max_fee_per_unit: DecimalU64;
  reserved: string;
  base_fee: string;
  priority_fee: string;
  charged: string;
  refund: string;
  burned: string;
  validator_reward: string;
}

export type ExecutionFailureCodeV1 =
  | "InsufficientBalance"
  | "ObjectNotFound"
  | "ObjectOwnerMismatch"
  | "ObjectVersionMismatch"
  | "Precondition";

export type ReceiptStatusV1Json =
  | "Succeeded"
  | { Failed: { code: ExecutionFailureCodeV1; failed_action_index: number | null } };

/** Existing Rust native event enum, retained as an externally tagged object. */
export type NativeEventJson = Readonly<Record<string, unknown>>;

export interface EventV1Json {
  version: 1;
  transaction_id: string;
  action_index: number;
  event_index: number;
  body: NativeEventJson;
}

export interface ReceiptV1Json {
  version: 1;
  position: BlockPositionV1Json;
  transaction_id: string;
  sender: WebcAddress;
  status: ReceiptStatusV1Json;
  fee_summary: FeeSummaryV1Json;
  events: EventV1Json[];
}

export function validateEventV1(value: unknown): asserts value is EventV1Json {
  const event = record(value, "V1 event");
  exactKeys(event, ["version", "transaction_id", "action_index", "event_index", "body"], "V1 event");
  if (event.version !== EVENT_V1) throw new Error("unsupported V1 event version");
  hash256(event.transaction_id, "event transaction ID");
  u32(event.action_index, "event action index");
  u32(event.event_index, "event index");
  const body = record(event.body, "native event body");
  if (Object.keys(body).length !== 1) throw new Error("native event body must have one variant");
  validateCanonicalValue(body, "native event body");
}

export function validateFeeSummaryV1(value: unknown): asserts value is FeeSummaryV1Json {
  const fee = record(value, "V1 fee summary");
  exactKeys(fee, [
    "version", "payer", "gas_limit", "units_consumed", "base_fee_per_unit",
    "priority_fee_per_unit", "max_fee_per_unit", "reserved", "base_fee",
    "priority_fee", "charged", "refund", "burned", "validator_reward",
  ], "V1 fee summary");
  if (fee.version !== 1) throw new Error("unsupported V1 fee-summary version");
  const payer = record(fee.payer, "V1 fee payer");
  exactKeys(payer, ["address", "lane"], "V1 fee payer");
  address(payer.address, "fee payer address");
  hash256(payer.lane, "fee payer lane");

  const gasLimit = u64(fee.gas_limit, "gas limit");
  const consumed = u64(fee.units_consumed, "units consumed");
  const baseRate = u64(fee.base_fee_per_unit, "base fee rate");
  const priorityRate = u64(fee.priority_fee_per_unit, "priority fee rate");
  const maxRate = u64(fee.max_fee_per_unit, "maximum fee rate");
  if (consumed > gasLimit) throw new Error("consumed units exceed gas limit");
  if (maxRate < baseRate) throw new Error("maximum fee rate is below base rate");
  if (priorityRate > maxRate - baseRate) throw new Error("priority fee exceeds available rate");

  const expected = {
    reserved: gasLimit * maxRate,
    base_fee: consumed * baseRate,
    priority_fee: consumed * priorityRate,
  };
  const charged = expected.base_fee + expected.priority_fee;
  const burned = expected.base_fee / 2n;
  const derived: Record<string, bigint> = {
    ...expected,
    charged,
    refund: expected.reserved - charged,
    burned,
    validator_reward: expected.base_fee - burned + expected.priority_fee,
  };
  for (const [field, expectedValue] of Object.entries(derived)) {
    const actual = u128(fee[field], field);
    if (actual !== expectedValue) throw new Error(`V1 fee summary does not reconcile: ${field}`);
  }
}

export function validateReceiptV1(value: unknown): asserts value is ReceiptV1Json {
  const receipt = record(value, "V1 receipt");
  exactKeys(receipt, ["version", "position", "transaction_id", "sender", "status", "fee_summary", "events"], "V1 receipt");
  if (receipt.version !== RECEIPT_V1) throw new Error("unsupported V1 receipt version");
  validatePosition(receipt.position);
  hash256(receipt.transaction_id, "receipt transaction ID");
  address(receipt.sender, "receipt sender");
  const failedIndex = validateStatus(receipt.status);
  validateFeeSummaryV1(receipt.fee_summary);
  if (!Array.isArray(receipt.events)) throw new Error("receipt events must be an array");
  if (receipt.events.length > MAX_RECEIPT_EVENTS_V1) {
    throw new Error("receipt event array exceeds V1 limit");
  }
  if (failedIndex !== undefined && receipt.events.length !== 0) {
    throw new Error("failed receipt must not contain events");
  }
  let previousAction = -1;
  for (let index = 0; index < receipt.events.length; index += 1) {
    const event = receipt.events[index];
    validateEventV1(event);
    if (event.event_index !== index) throw new Error("event index does not match array position");
    if (event.action_index < previousAction) throw new Error("events are not ordered by action index");
    if (event.transaction_id !== receipt.transaction_id) throw new Error("event names another transaction");
    previousAction = event.action_index;
  }
}

export async function eventV1DigestHex(event: EventV1Json): Promise<string> {
  validateEventV1(event);
  return canonicalJsonHashHex({ domain: EVENT_V1_DOMAIN, event });
}

export async function receiptV1DigestHex(receipt: ReceiptV1Json): Promise<string> {
  validateReceiptV1(receipt);
  return canonicalJsonHashHex({ domain: RECEIPT_V1_DOMAIN, receipt });
}

export async function receiptV1LeafHex(receipt: ReceiptV1Json): Promise<string> {
  validateReceiptV1(receipt);
  return canonicalJsonHashHex({ domain: RECEIPT_LEAF_V1_DOMAIN, receipt });
}

export async function transactionV1LeafHex(position: BlockPositionV1Json, transactionId: string): Promise<string> {
  validatePosition(position);
  hash256(transactionId, "transaction ID");
  return canonicalJsonHashHex({ domain: TRANSACTION_LEAF_V1_DOMAIN, position, transaction_id: transactionId });
}

export async function receiptRootV1Hex(receipts: readonly ReceiptV1Json[]): Promise<string> {
  return merkleRootHex(await Promise.all(receipts.map(receiptV1LeafHex)));
}

export async function transactionRootV1Hex(height: DecimalU64, transactions: readonly SignedTransactionV5Json[]): Promise<string> {
  u64(height, "block height");
  const seen = new Set<string>();
  const leaves: string[] = [];
  for (let index = 0; index < transactions.length; index += 1) {
    u32(index, "transaction index");
    validateTransactionV5Structure(transactions[index]);
    const id = await transactionV5IdHex(transactions[index]);
    if (seen.has(id)) throw new Error("duplicate transaction ID");
    seen.add(id);
    leaves.push(await transactionV1LeafHex({ height, transaction_index: index }, id));
  }
  return merkleRootHex(leaves);
}

export async function verifyTransactionReceiptBindingV1(
  height: DecimalU64,
  transactions: readonly SignedTransactionV5Json[],
  receipts: readonly ReceiptV1Json[],
): Promise<void> {
  u64(height, "block height");
  if (transactions.length !== receipts.length) throw new Error("transaction/receipt count mismatch");
  const seen = new Set<string>();
  for (let index = 0; index < transactions.length; index += 1) {
    const transaction = transactions[index];
    const receipt = receipts[index];
    validateTransactionV5Structure(transaction);
    validateReceiptV1(receipt);
    if (receipt.position.height !== height || receipt.position.transaction_index !== index) {
      throw new Error("receipt position mismatch");
    }
    const id = await transactionV5IdHex(transaction);
    if (seen.has(id)) throw new Error("duplicate transaction ID");
    seen.add(id);
    if (receipt.transaction_id !== id) throw new Error("receipt transaction ID mismatch");
    if (receipt.sender !== transaction.sender) throw new Error("receipt sender mismatch");
    validateFeeBinding(transaction, receipt.fee_summary);
    const actionCount = "Actions" in transaction.kind ? transaction.kind.Actions.actions.length : 0;
    for (const event of receipt.events) {
      if (event.action_index >= actionCount) throw new Error("event action index is out of range");
    }
    const failedIndex = validateStatus(receipt.status);
    if (failedIndex !== undefined && failedIndex !== null && failedIndex >= actionCount) {
      throw new Error("failed action index is out of range");
    }
  }
}

async function merkleRootHex(leaves: readonly string[]): Promise<string> {
  if (leaves.length === 0) return "00".repeat(32);
  let layer = leaves.map((leaf) => { hash256(leaf, "Merkle leaf"); return leaf; });
  while (layer.length > 1) {
    const next: string[] = [];
    for (let index = 0; index < layer.length; index += 2) {
      next.push(await merkleParentHex(layer[index], layer[index + 1] ?? layer[index]));
    }
    layer = next;
  }
  return layer[0];
}

async function merkleParentHex(left: string, right: string): Promise<string> {
  const domain = new TextEncoder().encode(MERKLE_V1_DOMAIN);
  const bytes = new Uint8Array(domain.length + 64);
  bytes.set(domain);
  bytes.set(hexToBytes(left), domain.length);
  bytes.set(hexToBytes(right), domain.length + 32);
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

function validateFeeBinding(transaction: SignedTransactionV5Json, fee: FeeSummaryV1Json): void {
  const expected = transaction.fee_payment === "SenderLane"
    ? { address: transaction.sender, lane: transaction.authorization.lane }
    : { address: transaction.fee_payment.Sponsored.grant.sponsor, lane: transaction.fee_payment.Sponsored.grant.payer_lane };
  if (fee.payer.address !== expected.address || fee.payer.lane !== expected.lane) throw new Error("receipt fee payer mismatch");
  const priorityRoom = BigInt(transaction.fee_bid.max_fee_per_unit) - BigInt(fee.base_fee_per_unit);
  if (priorityRoom < 0n
    || fee.gas_limit !== transaction.fee_bid.gas_limit
    || fee.max_fee_per_unit !== transaction.fee_bid.max_fee_per_unit
    || BigInt(fee.priority_fee_per_unit) !== min(BigInt(transaction.fee_bid.priority_fee_per_unit), priorityRoom)) {
    throw new Error("receipt fee bid mismatch");
  }
}

function validatePosition(value: unknown): asserts value is BlockPositionV1Json {
  const position = record(value, "V1 block position");
  exactKeys(position, ["height", "transaction_index"], "V1 block position");
  u64(position.height, "block height");
  u32(position.transaction_index, "transaction index");
}

/** Returns undefined for success, null/index for failure. */
function validateStatus(value: unknown): number | null | undefined {
  if (value === "Succeeded") return undefined;
  const status = record(value, "receipt status");
  exactKeys(status, ["Failed"], "receipt status");
  const failed = record(status.Failed, "failed receipt status");
  exactKeys(failed, ["code", "failed_action_index"], "failed receipt status");
  if (!["InsufficientBalance", "ObjectNotFound", "ObjectOwnerMismatch", "ObjectVersionMismatch", "Precondition"].includes(failed.code as string)) {
    throw new Error("unknown execution failure code");
  }
  if (failed.failed_action_index === null) return null;
  return u32(failed.failed_action_index, "failed action index");
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: string[], label: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} has an unexpected field set`);
  }
}

function address(value: unknown, label: string): asserts value is WebcAddress {
  if (typeof value !== "string") throw new Error(`${label} must be an address`);
  addressToBytes(value);
}

function hash256(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || value.length !== 64 || value !== value.toLowerCase() || !/^[0-9a-f]+$/u.test(value)) {
    throw new Error(`invalid ${label}`);
  }
}

function u32(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 0xffff_ffff) throw new Error(`${label} must be a u32`);
  return value;
}

function u64(value: unknown, label: string): bigint {
  return decimal(value, label, 20, U64_MAX);
}

function u128(value: unknown, label: string): bigint {
  return decimal(value, label, 39, U128_MAX);
}

function decimal(value: unknown, label: string, maxLength: number, maximum: bigint): bigint {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength || !/^(0|[1-9][0-9]*)$/u.test(value)) {
    throw new Error(`${label} must be a canonical decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed > maximum) throw new Error(`${label} is out of range`);
  return parsed;
}

function validateCanonicalValue(value: unknown, label: string): void {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error(`${label} contains an unsafe JSON number`);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) validateCanonicalValue(item, label);
    return;
  }
  if (typeof value === "object") {
    for (const item of Object.values(value as Record<string, unknown>)) validateCanonicalValue(item, label);
    return;
  }
  throw new Error(`${label} contains a non-JSON value`);
}

function min(left: bigint, right: bigint): bigint {
  return left < right ? left : right;
}
