/**
 * Protocol-version-2 receipt, event, and ordered Merkle commitments.
 *
 * This mirrors Rust `webc_chain::receipt_v1`: it validates hostile receipt
 * JSON, reconciles fee arithmetic, binds receipts to signed V5 transactions,
 * and computes the same domain-separated leaves and ordered roots. It does not
 * execute actions, decide finality, or verify a block header/proof.
 */

import { addressToBytes } from "./address.js";
import { boundedJsonSnapshot } from "./bounded-json.js";
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
/** Maximum UTF-8 JSON bytes accepted for one untrusted V1 receipt. */
export const MAX_RECEIPT_V1_JSON_BYTES = 256 * 1024;
/** Maximum object nesting beneath one native event body. */
export const MAX_NATIVE_EVENT_JSON_DEPTH_V1 = 8;
/** Maximum primitive and object nodes traversed beneath one native event body. */
export const MAX_NATIVE_EVENT_JSON_NODES_V1 = 64;

const MAX_RECEIPT_JSON_DEPTH_V1 = 12;
const MAX_RECEIPT_JSON_NODES_V1 = MAX_RECEIPT_EVENTS_V1 * (MAX_NATIVE_EVENT_JSON_NODES_V1 + 6) + 64;

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
  validatedEventSnapshotV1(value);
}

function validateEventSnapshotV1(value: unknown): asserts value is EventV1Json {
  const event = record(value, "V1 event");
  exactKeys(event, ["version", "transaction_id", "action_index", "event_index", "body"], "V1 event");
  if (event.version !== EVENT_V1) throw new Error("unsupported V1 event version");
  hash256(event.transaction_id, "event transaction ID");
  u32(event.action_index, "event action index");
  u32(event.event_index, "event index");
  validateNativeEventBody(event.body);
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
  validatedReceiptSnapshotV1(value);
}

function validateReceiptSnapshotV1(value: unknown): asserts value is ReceiptV1Json {
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
    validateEventSnapshotV1(event);
    if (event.event_index !== index) throw new Error("event index does not match array position");
    if (event.action_index < previousAction) throw new Error("events are not ordered by action index");
    if (event.transaction_id !== receipt.transaction_id) throw new Error("event names another transaction");
    previousAction = event.action_index;
  }
}

/** Copies, validates, and byte-bounds an event before any hash reads it. */
function validatedEventSnapshotV1(value: unknown): EventV1Json {
  const snapshot = boundedJsonSnapshot(value, receiptSnapshotLimits("V1 event"));
  validateEventSnapshotV1(snapshot);
  enforceReceiptJsonByteLimit(snapshot, "V1 event");
  return snapshot;
}

/** Copies, validates, and byte-bounds a receipt before any async or hash use. */
function validatedReceiptSnapshotV1(value: unknown): ReceiptV1Json {
  const snapshot = boundedJsonSnapshot(value, receiptSnapshotLimits("V1 receipt"));
  validateReceiptSnapshotV1(snapshot);
  enforceReceiptJsonByteLimit(snapshot, "V1 receipt");
  return snapshot;
}

function receiptSnapshotLimits(label: string) {
  return {
    label,
    maxDepth: MAX_RECEIPT_JSON_DEPTH_V1,
    maxNodes: MAX_RECEIPT_JSON_NODES_V1,
    maxArrayLength: MAX_RECEIPT_EVENTS_V1,
    maxStringBytes: MAX_RECEIPT_V1_JSON_BYTES,
    stringByteLimitLabel: "256 KiB",
    arrayLimitLabel: "receipt event array",
  } as const;
}

function enforceReceiptJsonByteLimit(value: unknown, label: string): void {
  if (canonicalJsonBytes(value).byteLength > MAX_RECEIPT_V1_JSON_BYTES) {
    throw new Error(`${label} exceeds the 256 KiB V1 limit`);
  }
}

export async function eventV1DigestHex(event: EventV1Json): Promise<string> {
  const snapshot = validatedEventSnapshotV1(event);
  return canonicalJsonHashHex({ domain: EVENT_V1_DOMAIN, event: snapshot });
}

export async function receiptV1DigestHex(receipt: ReceiptV1Json): Promise<string> {
  const snapshot = validatedReceiptSnapshotV1(receipt);
  return canonicalJsonHashHex({ domain: RECEIPT_V1_DOMAIN, receipt: snapshot });
}

export async function receiptV1LeafHex(receipt: ReceiptV1Json): Promise<string> {
  const snapshot = validatedReceiptSnapshotV1(receipt);
  return canonicalJsonHashHex({ domain: RECEIPT_LEAF_V1_DOMAIN, receipt: snapshot });
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
    const receipt = validatedReceiptSnapshotV1(receipts[index]);
    validateTransactionV5Structure(transaction);
    if (receipt.position.height !== height || receipt.position.transaction_index !== index) {
      throw new Error("receipt position mismatch");
    }
    const id = await transactionV5IdHex(transaction);
    if (seen.has(id)) throw new Error("duplicate transaction ID");
    seen.add(id);
    await verifyTransactionReceiptPairSnapshotV1(transaction, receipt, id);
  }
}

/**
 * Verifies one signed V5 transaction and V1 receipt at the receipt's position.
 *
 * The containing block or finalized proof remains responsible for checking the
 * position against its Merkle index and target height.
 */
export async function verifyTransactionReceiptPairV1(
  transaction: SignedTransactionV5Json,
  receipt: ReceiptV1Json,
  knownTransactionId?: string,
): Promise<void> {
  const snapshot = validatedReceiptSnapshotV1(receipt);
  await verifyTransactionReceiptPairSnapshotV1(transaction, snapshot, knownTransactionId);
}

async function verifyTransactionReceiptPairSnapshotV1(
  transaction: SignedTransactionV5Json,
  receipt: ReceiptV1Json,
  knownTransactionId?: string,
): Promise<void> {
  validateTransactionV5Structure(transaction);
  const id = knownTransactionId ?? await transactionV5IdHex(transaction);
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

async function merkleRootHex(leaves: readonly string[]): Promise<string> {
  if (leaves.length === 0) return "00".repeat(32);
  let layer = leaves.map((leaf) => { hash256(leaf, "Merkle leaf"); return leaf; });
  while (layer.length > 1) {
    const next: string[] = [];
    for (let index = 0; index < layer.length; index += 2) {
      next.push(await merkleParentV1Hex(layer[index], layer[index + 1] ?? layer[index]));
    }
    layer = next;
  }
  return layer[0];
}

/** Computes the shared duplicate-last V1 Merkle parent hash. */
export async function merkleParentV1Hex(left: string, right: string): Promise<string> {
  hash256(left, "left Merkle child");
  hash256(right, "right Merkle child");
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

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
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

type JsonFieldValidator = (value: unknown, label: string) => void;
type NativeEventSchema = Readonly<Record<string, JsonFieldValidator>>;

/**
 * Validates the exact externally-tagged JSON schema of Rust `state::Event`.
 *
 * The bounded, iterative pass runs before variant dispatch. This matters even
 * though every current variant is shallow: a hostile node can otherwise place
 * a deeply nested value behind a known field and exhaust the JavaScript stack
 * before the fail-closed field/type check gets a chance to reject it.
 */
function validateNativeEventBody(value: unknown): asserts value is NativeEventJson {
  const body = record(value, "native event body");
  validateBoundedNativeEventJson(body, "native event body");
  const variants = Object.keys(body);
  if (variants.length !== 1) throw new Error("native event body must have one variant");
  const variant = variants[0];
  const schema = NATIVE_EVENT_SCHEMAS.get(variant);
  if (schema === undefined) throw new Error(`unknown native event variant: ${variant}`);
  validateFields(body[variant], schema, `native event ${variant}`);
}

/** Traverses hostile JSON iteratively under explicit depth and node budgets. */
function validateBoundedNativeEventJson(value: unknown, label: string): void {
  const stack: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  let discoveredNodes = 1;
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === undefined) break;
    if (current.depth > MAX_NATIVE_EVENT_JSON_DEPTH_V1) {
      throw new Error(`${label} exceeds the V1 depth limit`);
    }
    if (current.value === null || typeof current.value === "string" || typeof current.value === "boolean") {
      continue;
    }
    if (typeof current.value === "number") {
      if (!Number.isSafeInteger(current.value)) throw new Error(`${label} contains an unsafe JSON number`);
      continue;
    }
    if (Array.isArray(current.value)) {
      // No current Rust Event/BridgeEvent variant contains a sequence. Rejecting
      // it here also avoids walking an attacker-controlled sparse array length.
      throw new Error(`${label} contains an array outside the V1 schema`);
    }
    if (typeof current.value !== "object") throw new Error(`${label} contains a non-JSON value`);

    const object = current.value as Record<string, unknown>;
    for (const key in object) {
      if (!Object.prototype.hasOwnProperty.call(object, key)) continue;
      discoveredNodes += 1;
      if (discoveredNodes > MAX_NATIVE_EVENT_JSON_NODES_V1) {
        throw new Error(`${label} exceeds the V1 node budget`);
      }
      const descriptor = Object.getOwnPropertyDescriptor(object, key);
      if (descriptor === undefined || !("value" in descriptor)) {
        throw new Error(`${label} contains an accessor property`);
      }
      const childDepth = current.depth + 1;
      if (childDepth > MAX_NATIVE_EVENT_JSON_DEPTH_V1) {
        throw new Error(`${label} exceeds the V1 depth limit`);
      }
      stack.push({ value: descriptor.value, depth: childDepth });
    }
  }
}

function validateFields(value: unknown, schema: NativeEventSchema, label: string): void {
  const object = record(value, label);
  const fields = Object.keys(schema);
  exactKeys(object, fields, label);
  for (const field of fields) schema[field](object[field], `${label}.${field}`);
}

function jsonString(value: unknown, label: string): void {
  if (typeof value !== "string") throw new Error(`${label} must be a string`);
}

function jsonBoolean(value: unknown, label: string): void {
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
}

function safeU64Number(value: unknown, label: string): void {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe JSON integer`);
  }
}

function signedI128(value: unknown, label: string): void {
  if (typeof value !== "string" || value.length === 0 || value.length > 40 || !/^(0|-?[1-9][0-9]*)$/u.test(value)) {
    throw new Error(`${label} must be a canonical signed decimal string`);
  }
  const parsed = BigInt(value);
  const minimum = -(1n << 127n);
  const maximum = (1n << 127n) - 1n;
  if (parsed < minimum || parsed > maximum) throw new Error(`${label} is out of range`);
}

function oneOfStrings(value: unknown, choices: readonly string[], label: string): void {
  if (typeof value !== "string" || !choices.includes(value)) throw new Error(`${label} has an unknown enum value`);
}

function nullable(validator: JsonFieldValidator): JsonFieldValidator {
  return (value, label) => {
    if (value !== null) validator(value, label);
  };
}

function validateFeeBreakdown(value: unknown, label: string): void {
  validateFields(value, {
    total: AMOUNT_FIELD,
    burned: AMOUNT_FIELD,
    validator_reward: AMOUNT_FIELD,
  }, label);
}

function validatePostQuantumRoot(value: unknown, label: string): void {
  validateFields(value, {
    scheme: POST_QUANTUM_SCHEME_FIELD,
    public_key_hash: HASH_FIELD,
  }, label);
}

function validateTradingPair(value: unknown, label: string): void {
  validateFields(value, { base: validateAssetId, quote: validateAssetId }, label);
}

function validateNftId(value: unknown, label: string): void {
  validateFields(value, { collection: HASH_FIELD, serial: SAFE_U64_NUMBER_FIELD }, label);
}

function validateSlashingOutcome(value: unknown, label: string): void {
  validateFields(value, {
    validator: ADDRESS_FIELD,
    self_slashed: AMOUNT_FIELD,
    delegated_slashed: AMOUNT_FIELD,
    jailed: BOOLEAN_FIELD,
    tombstoned: BOOLEAN_FIELD,
    reason: STRING_FIELD,
  }, label);
}

function validateAssetId(value: unknown, label: string): void {
  if (value === "NativeWebc") return;
  const tagged = record(value, label);
  const variants = Object.keys(tagged);
  if (variants.length !== 1) throw new Error(`${label} must have one asset variant`);
  switch (variants[0]) {
    case "WrappedWebc":
      validateFields(tagged.WrappedWebc, { origin_chain: EXTERNAL_CHAIN_FIELD }, `${label}.WrappedWebc`);
      return;
    case "External":
      validateFields(tagged.External, {
        origin_chain: EXTERNAL_CHAIN_FIELD,
        symbol: STRING_FIELD,
        contract_or_mint: STRING_FIELD,
      }, `${label}.External`);
      return;
    default:
      throw new Error(`${label} has an unknown asset variant`);
  }
}

function validateBridgeMessage(value: unknown, label: string): void {
  validateFields(value, {
    source_chain: EXTERNAL_CHAIN_FIELD,
    destination_chain: EXTERNAL_CHAIN_FIELD,
    nonce: SAFE_U64_NUMBER_FIELD,
    asset: validateAssetId,
    sender: BRIDGE_ADDRESS_FIELD,
    recipient: BRIDGE_ADDRESS_FIELD,
    amount: AMOUNT_FIELD,
    source_tx: HASH_FIELD,
  }, label);
}

function validateBridgeEvent(value: unknown, label: string): void {
  const tagged = record(value, label);
  const variants = Object.keys(tagged);
  if (variants.length !== 1) throw new Error(`${label} must have one bridge-event variant`);
  const variant = variants[0];
  if (!["Locked", "Minted", "Burned", "Released"].includes(variant)) {
    throw new Error(`${label} has an unknown bridge-event variant`);
  }
  validateFields(tagged[variant], {
    message: validateBridgeMessage,
    message_hash: HASH_FIELD,
  }, `${label}.${variant}`);
}

function boundedBridgeAddress(value: unknown, label: string): void {
  if (typeof value !== "string"
    || value.length > 256
    || value.length % 2 !== 0
    || value !== value.toLowerCase()
    || !/^[0-9a-f]*$/u.test(value)) {
    throw new Error(`${label} must be at most 128 bytes of lowercase hex`);
  }
}

const ADDRESS_FIELD: JsonFieldValidator = (value, label) => { address(value, label); };
const HASH_FIELD: JsonFieldValidator = (value, label) => { hash256(value, label); };
const AMOUNT_FIELD: JsonFieldValidator = (value, label) => { u128(value, label); };
const SAFE_U64_NUMBER_FIELD: JsonFieldValidator = safeU64Number;
const STRING_FIELD: JsonFieldValidator = jsonString;
const BOOLEAN_FIELD: JsonFieldValidator = jsonBoolean;
const BRIDGE_ADDRESS_FIELD: JsonFieldValidator = boundedBridgeAddress;
const FEED_VALUE_FIELD: JsonFieldValidator = signedI128;
const PRICE_FIELD: JsonFieldValidator = AMOUNT_FIELD;
const EXTERNAL_CHAIN_FIELD: JsonFieldValidator = (value, label) => {
  oneOfStrings(value, ["Webc", "Ethereum", "Solana"], label);
};
const ORDER_SIDE_FIELD: JsonFieldValidator = (value, label) => {
  oneOfStrings(value, ["Buy", "Sell"], label);
};
const ORDER_CLOSE_REASON_FIELD: JsonFieldValidator = (value, label) => {
  oneOfStrings(value, ["Cancelled", "FillOrCancel", "Expired"], label);
};
const BUILTIN_CONTRACT_FIELD: JsonFieldValidator = (value, label) => {
  oneOfStrings(value, ["KeyValue"], label);
};
const UNBONDING_KIND_FIELD: JsonFieldValidator = (value, label) => {
  oneOfStrings(value, ["OperatorStake", "Delegation"], label);
};
const POST_QUANTUM_SCHEME_FIELD: JsonFieldValidator = (value, label) => {
  oneOfStrings(value, ["MlDsa65"], label);
};
const SERVICE_STATUS_FIELD: JsonFieldValidator = (value, label) => {
  oneOfStrings(value, ["Active", "Paused", "Retired"], label);
};
const TOKEN_AUTHORITY_FIELD: JsonFieldValidator = (value, label) => {
  oneOfStrings(value, ["Mint", "Freeze"], label);
};
const NFT_AUTHORITY_FIELD: JsonFieldValidator = TOKEN_AUTHORITY_FIELD;
const GOVERNANCE_STATUS_FIELD: JsonFieldValidator = (value, label) => {
  oneOfStrings(value, ["Active", "Defeated", "Passed", "Executed", "Expired"], label);
};
const VOTE_CHOICE_FIELD: JsonFieldValidator = (value, label) => {
  oneOfStrings(value, ["Yes", "No", "Abstain"], label);
};
const NULLABLE_ADDRESS_FIELD = nullable(ADDRESS_FIELD);
const NULLABLE_FEED_VALUE_FIELD = nullable(FEED_VALUE_FIELD);
const NULLABLE_SAFE_U64_NUMBER_FIELD = nullable(SAFE_U64_NUMBER_FIELD);

/**
 * Exact field/type schemas for every current Rust `webc_chain::state::Event`
 * variant. Adding a Rust event without adding its schema here intentionally
 * makes old SDKs reject it until the wire boundary is reviewed and versioned.
 */
const NATIVE_EVENT_SCHEMAS: ReadonlyMap<string, NativeEventSchema> = new Map<string, NativeEventSchema>([
  ["Transfer", { from: ADDRESS_FIELD, to: ADDRESS_FIELD, amount: AMOUNT_FIELD }],
  ["FeePaid", { payer: ADDRESS_FIELD, breakdown: validateFeeBreakdown }],
  ["FeeSponsored", { application: HASH_FIELD, beneficiary: ADDRESS_FIELD, breakdown: validateFeeBreakdown }],
  ["AppSponsorRegistered", {
    application: HASH_FIELD, owner: ADDRESS_FIELD, daily_budget_cap: AMOUNT_FIELD, funded: AMOUNT_FIELD,
  }],
  ["AppSponsorFunded", { application: HASH_FIELD, amount: AMOUNT_FIELD }],
  ["AppSponsorWithdrawn", { application: HASH_FIELD, amount: AMOUNT_FIELD }],
  ["NamespaceRegistered", { namespace: HASH_FIELD, owner: ADDRESS_FIELD }],
  ["NamespaceTransferred", { namespace: HASH_FIELD, from: ADDRESS_FIELD, to: ADDRESS_FIELD }],
  ["FeedCreated", { feed_id: HASH_FIELD, creator: ADDRESS_FIELD, bond: AMOUNT_FIELD, fee_burned: AMOUNT_FIELD }],
  ["ReporterRegistered", { feed_id: HASH_FIELD, reporter: ADDRESS_FIELD, bond: AMOUNT_FIELD }],
  ["ReporterDeregistered", { feed_id: HASH_FIELD, reporter: ADDRESS_FIELD, bond: AMOUNT_FIELD }],
  ["ReportSubmitted", {
    feed_id: HASH_FIELD, reporter: ADDRESS_FIELD, value: FEED_VALUE_FIELD, epoch: SAFE_U64_NUMBER_FIELD,
  }],
  ["FeedReadPaid", { feed_id: HASH_FIELD, payer: ADDRESS_FIELD, amount: AMOUNT_FIELD }],
  ["FeedRevenueSettled", {
    feed_id: HASH_FIELD,
    epoch: SAFE_U64_NUMBER_FIELD,
    median: NULLABLE_FEED_VALUE_FIELD,
    distributed: AMOUNT_FIELD,
    carried: AMOUNT_FIELD,
  }],
  ["OrderSubmitted", {
    order_id: HASH_FIELD,
    owner: ADDRESS_FIELD,
    pair: validateTradingPair,
    side: ORDER_SIDE_FIELD,
    amount: AMOUNT_FIELD,
    limit_price: PRICE_FIELD,
    deadline_height: SAFE_U64_NUMBER_FIELD,
  }],
  ["OrderFilled", {
    order_id: HASH_FIELD,
    pair: validateTradingPair,
    side: ORDER_SIDE_FIELD,
    clearing_price: PRICE_FIELD,
    filled: AMOUNT_FIELD,
    remaining: AMOUNT_FIELD,
    quote: AMOUNT_FIELD,
  }],
  ["OrderClosed", {
    order_id: HASH_FIELD, owner: ADDRESS_FIELD, reason: ORDER_CLOSE_REASON_FIELD, unfilled: AMOUNT_FIELD,
  }],
  ["ContractRegistered", {
    code_id: HASH_FIELD,
    namespace: HASH_FIELD,
    owner: ADDRESS_FIELD,
    builtin: BUILTIN_CONTRACT_FIELD,
    fee_burned: AMOUNT_FIELD,
  }],
  ["ContractInvoked", {
    code_id: HASH_FIELD,
    namespace: HASH_FIELD,
    caller: ADDRESS_FIELD,
    gas_consumed: SAFE_U64_NUMBER_FIELD,
    output_len: SAFE_U64_NUMBER_FIELD,
  }],
  ["WasmContractRegistered", {
    code_id: HASH_FIELD,
    namespace: HASH_FIELD,
    owner: ADDRESS_FIELD,
    code_hash: HASH_FIELD,
    code_len: SAFE_U64_NUMBER_FIELD,
    fee_burned: AMOUNT_FIELD,
  }],
  ["WasmContractInvoked", {
    code_id: HASH_FIELD,
    namespace: HASH_FIELD,
    caller: ADDRESS_FIELD,
    gas_consumed: SAFE_U64_NUMBER_FIELD,
    output_len: SAFE_U64_NUMBER_FIELD,
  }],
  ["ValidatorRegistered", { operator: ADDRESS_FIELD, bootstrap: BOOLEAN_FIELD }],
  ["Delegated", { delegator: ADDRESS_FIELD, validator: ADDRESS_FIELD, amount: AMOUNT_FIELD }],
  ["UnbondingRequested", {
    request_id: SAFE_U64_NUMBER_FIELD,
    delegator: ADDRESS_FIELD,
    validator: ADDRESS_FIELD,
    kind: UNBONDING_KIND_FIELD,
    amount: AMOUNT_FIELD,
  }],
  ["UnbondingAdmitted", {
    request_id: SAFE_U64_NUMBER_FIELD,
    delegator: ADDRESS_FIELD,
    validator: ADDRESS_FIELD,
    kind: UNBONDING_KIND_FIELD,
    amount: AMOUNT_FIELD,
  }],
  ["UnbondingMatured", {
    request_id: SAFE_U64_NUMBER_FIELD,
    delegator: ADDRESS_FIELD,
    validator: ADDRESS_FIELD,
    kind: UNBONDING_KIND_FIELD,
    amount: AMOUNT_FIELD,
  }],
  ["UnbondingClaimed", {
    request_id: SAFE_U64_NUMBER_FIELD, delegator: ADDRESS_FIELD, kind: UNBONDING_KIND_FIELD, amount: AMOUNT_FIELD,
  }],
  ["ValidatorRewardsClaimed", { validator: ADDRESS_FIELD, amount: AMOUNT_FIELD }],
  ["DelegatorRewardsClaimed", { delegator: ADDRESS_FIELD, validator: ADDRESS_FIELD, amount: AMOUNT_FIELD }],
  ["ValidatorRewardsCompounded", { validator: ADDRESS_FIELD, amount: AMOUNT_FIELD }],
  ["DelegatorRewardsCompounded", { delegator: ADDRESS_FIELD, validator: ADDRESS_FIELD, amount: AMOUNT_FIELD }],
  ["Slashed", { outcome: validateSlashingOutcome }],
  ["Bridge", { event: validateBridgeEvent }],
  ["EpochRewardsDistributed", { epoch: SAFE_U64_NUMBER_FIELD, total: AMOUNT_FIELD }],
  ["AuthorizationLaneOpened", { owner: ADDRESS_FIELD, lane: HASH_FIELD, fee_deposit: AMOUNT_FIELD }],
  ["AuthorizationLaneFunded", { owner: ADDRESS_FIELD, lane: HASH_FIELD, fee_deposit: AMOUNT_FIELD }],
  ["AuthorizationPolicyInstalled", {
    owner: ADDRESS_FIELD, revision: SAFE_U64_NUMBER_FIELD, post_quantum_root: validatePostQuantumRoot,
  }],
  ["SessionKeyInstalled", {
    owner: ADDRESS_FIELD, session_key: HASH_FIELD, expires_after_epoch: SAFE_U64_NUMBER_FIELD,
  }],
  ["SessionKeyRevoked", { owner: ADDRESS_FIELD, session_key: HASH_FIELD }],
  ["SessionKeyExpired", { owner: ADDRESS_FIELD, session_key: HASH_FIELD }],
  ["ActiveTransactionKeyRotated", {
    owner: ADDRESS_FIELD, new_revision: SAFE_U64_NUMBER_FIELD, new_active_transaction_key: HASH_FIELD,
  }],
  ["PostQuantumRootRotated", {
    owner: ADDRESS_FIELD, new_revision: SAFE_U64_NUMBER_FIELD, new_post_quantum_root: validatePostQuantumRoot,
  }],
  ["SessionKeyUsed", { owner: ADDRESS_FIELD, session_key: HASH_FIELD, amount: AMOUNT_FIELD }],
  ["ObjectCreated", {
    object_id: HASH_FIELD,
    namespace: HASH_FIELD,
    owner: ADDRESS_FIELD,
    version: SAFE_U64_NUMBER_FIELD,
  }],
  ["ObjectMutated", { object_id: HASH_FIELD, version: SAFE_U64_NUMBER_FIELD }],
  ["ObjectTransferred", {
    object_id: HASH_FIELD,
    from: ADDRESS_FIELD,
    to: ADDRESS_FIELD,
    version: SAFE_U64_NUMBER_FIELD,
  }],
  ["ObjectDeleted", { object_id: HASH_FIELD, owner: ADDRESS_FIELD, refund: AMOUNT_FIELD, burned: AMOUNT_FIELD }],
  ["MandateGranted", {
    mandate_id: HASH_FIELD,
    principal: ADDRESS_FIELD,
    agent_key: HASH_FIELD,
    budget_total: AMOUNT_FIELD,
    expiry_epoch: SAFE_U64_NUMBER_FIELD,
  }],
  ["MandateToppedUp", { mandate_id: HASH_FIELD, amount: AMOUNT_FIELD, budget_total: AMOUNT_FIELD }],
  ["MandateSpent", {
    mandate_id: HASH_FIELD,
    agent_key: HASH_FIELD,
    recipient: ADDRESS_FIELD,
    amount: AMOUNT_FIELD,
    fee: AMOUNT_FIELD,
  }],
  ["MandateRevoked", { mandate_id: HASH_FIELD, principal: ADDRESS_FIELD, refunded: AMOUNT_FIELD }],
  ["ServiceRegistered", { service_id: HASH_FIELD, owner: ADDRESS_FIELD, namespace: HASH_FIELD }],
  ["ServiceUpdated", { service_id: HASH_FIELD, revision: SAFE_U64_NUMBER_FIELD }],
  ["ServiceStatusChanged", {
    service_id: HASH_FIELD, status: SERVICE_STATUS_FIELD, revision: SAFE_U64_NUMBER_FIELD,
  }],
  ["MandateSpentToService", {
    mandate_id: HASH_FIELD,
    service_id: HASH_FIELD,
    agent_key: HASH_FIELD,
    recipient: ADDRESS_FIELD,
    amount: AMOUNT_FIELD,
    fee: AMOUNT_FIELD,
  }],
  ["TokenCreated", {
    token_id: HASH_FIELD,
    creator: ADDRESS_FIELD,
    namespace: HASH_FIELD,
    deposit: AMOUNT_FIELD,
    initial_supply: AMOUNT_FIELD,
  }],
  ["TokenMinted", {
    token_id: HASH_FIELD, recipient: ADDRESS_FIELD, amount: AMOUNT_FIELD, issued_supply: AMOUNT_FIELD,
  }],
  ["TokenBurned", {
    token_id: HASH_FIELD, holder: ADDRESS_FIELD, amount: AMOUNT_FIELD, issued_supply: AMOUNT_FIELD,
  }],
  ["TokenTransferred", { token_id: HASH_FIELD, from: ADDRESS_FIELD, to: ADDRESS_FIELD, amount: AMOUNT_FIELD }],
  ["TokenPausedChanged", { token_id: HASH_FIELD, paused: BOOLEAN_FIELD }],
  ["TokenFreezeChanged", { token_id: HASH_FIELD, account: ADDRESS_FIELD, frozen: BOOLEAN_FIELD }],
  ["TokenAuthorityChanged", {
    token_id: HASH_FIELD, authority_kind: TOKEN_AUTHORITY_FIELD, new_authority: NULLABLE_ADDRESS_FIELD,
  }],
  ["NftCollectionCreated", {
    collection_id: HASH_FIELD, creator: ADDRESS_FIELD, namespace: HASH_FIELD, deposit: AMOUNT_FIELD,
  }],
  ["NftMinted", { nft_id: validateNftId, recipient: ADDRESS_FIELD, item_metadata_hash: HASH_FIELD }],
  ["NftTransferred", { nft_id: validateNftId, from: ADDRESS_FIELD, to: ADDRESS_FIELD }],
  ["NftBurned", { nft_id: validateNftId, owner: ADDRESS_FIELD }],
  ["NftCollectionPausedChanged", { collection_id: HASH_FIELD, paused: BOOLEAN_FIELD }],
  ["NftItemFreezeChanged", { nft_id: validateNftId, frozen: BOOLEAN_FIELD }],
  ["NftAuthorityChanged", {
    collection_id: HASH_FIELD, authority_kind: NFT_AUTHORITY_FIELD, new_authority: NULLABLE_ADDRESS_FIELD,
  }],
  ["GovernanceInstanceCreated", {
    instance_id: HASH_FIELD,
    creator: ADDRESS_FIELD,
    namespace: HASH_FIELD,
    weight_token: HASH_FIELD,
    deposit: AMOUNT_FIELD,
  }],
  ["GovernanceTreasuryFunded", {
    instance_id: HASH_FIELD, funder: ADDRESS_FIELD, amount: AMOUNT_FIELD, treasury: AMOUNT_FIELD,
  }],
  ["GovernanceProposalOpened", {
    proposal_id: HASH_FIELD,
    instance_id: HASH_FIELD,
    proposer: ADDRESS_FIELD,
    voting_ends_epoch: SAFE_U64_NUMBER_FIELD,
  }],
  ["GovernanceVoteCast", {
    proposal_id: HASH_FIELD, voter: ADDRESS_FIELD, choice: VOTE_CHOICE_FIELD, weight: AMOUNT_FIELD,
  }],
  ["GovernanceProposalResolved", {
    proposal_id: HASH_FIELD, status: GOVERNANCE_STATUS_FIELD, eta_epoch: NULLABLE_SAFE_U64_NUMBER_FIELD,
  }],
  ["GovernanceProposalExecuted", { proposal_id: HASH_FIELD, instance_id: HASH_FIELD }],
  ["GovernanceProposalExpired", { proposal_id: HASH_FIELD }],
  ["GovernanceVoteReclaimed", { proposal_id: HASH_FIELD, voter: ADDRESS_FIELD, weight: AMOUNT_FIELD }],
  ["SponsorGrantRevoked", { sponsor: ADDRESS_FIELD, grant_id: HASH_FIELD }],
]);

function min(left: bigint, right: bigint): bigint {
  return left < right ? left : right;
}
