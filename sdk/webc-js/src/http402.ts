/**
 * HTTP-402 agent-payment flow (agent-commerce plan §4, WEBC-DEFINITION §15.5).
 *
 * This module lets an AI agent pay for a resource inside an ordinary web request
 * cycle. The service replies `402 Payment Required` with a machine-readable
 * challenge; the agent validates that challenge AGAINST THE ON-CHAIN REGISTRY
 * ENTRY, pays under its mandate, and retries with an on-chain-verifiable payment
 * reference. The five steps of `docs/agent-commerce.md` §4 map to:
 *
 *   1. `parseChallenge`   — strict, fail-closed decode of the untrusted 402 body.
 *   2. `validateChallenge`— price/pay-to/asset/status/expiry check vs the registry
 *                           entry (the security core; see its doc comment).
 *   3. `buildPayment`     — compose `spendUnderMandateToService` + its
 *                           `accessListForServiceSpend` helper, sign with the
 *                           agent (mandate) key.
 *   4. `makeRetry`        — the `PaymentReference` the agent re-sends so the
 *                           service can verify the spend on-chain.
 *   5. `auditRecord`      — the dispute/audit tuple for record-keeping.
 *
 * The module composes the existing operation builders in `transaction.ts`; it
 * does NOT re-implement the operation or its access list. The registry entry used
 * for validation may be a CALLER-PROVIDED input (`ServiceEntry`) handed in
 * directly, so the whole flow stays unit-testable without a live network. As an
 * additive convenience, `validateChallenge`/`buildPayment` also accept a
 * `ServiceEntrySource` (a `WebcNodeClient` or a `(serviceId) => Promise<ServiceEntry>`
 * fetcher) and obtain the on-chain entry themselves; the same price+pay-to
 * cross-check then runs on the fetched entry, never on the endpoint challenge
 * alone.
 */

import type {
  AssetIdJson,
  AuthorizationLaneIdJson,
  ExternalChainJson,
  FeeBid,
  HexString,
  ServicePaymentFlagsJson,
  ServicePriceJson,
  ServiceStatusJson,
  SignedTransactionJson,
  WebcAddress,
} from "./types.js";
import type { WebcWallet } from "./wallet.js";
import { addressToBytes } from "./address.js";
import {
  accessListForServiceSpend,
  signTransaction,
  spendUnderMandateToService,
  transactionHashHex,
} from "./transaction.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Price quoted by a 402 challenge: an `amount` in base units plus the `asset` it
 * is denominated in. Only `"NativeWebc"` is payable through a mandate spend today
 * — `SpendUnderMandateToService` moves native units and carries no asset field —
 * so `validateChallenge` rejects any other asset (`wrong_asset`).
 */
export interface ChallengePrice {
  /** Amount in native base units, canonical decimal string (Rust `Amount`). */
  amount: string;
  /** Asset the price is denominated in; must be `"NativeWebc"` to be payable. */
  asset: AssetIdJson;
}

/**
 * A parsed `402 Payment Required` challenge. This is UNTRUSTED input from a
 * possibly-hostile endpoint: every field is bounded and canonically validated by
 * `parseChallenge`, and the economic fields are re-checked against the on-chain
 * registry entry by `validateChallenge`.
 *
 * `expiry` is a Unix epoch-SECONDS integer (non-negative, u64 range). We
 * deliberately use an integer deadline rather than an ISO-8601 string: an integer
 * has exactly one canonical representation and no timezone/format ambiguity, which
 * matters for untrusted input, and it mirrors the mandate's numeric `expiry_epoch`
 * (§2). A challenge is expired once wall-clock `now` has REACHED `expiry`
 * (rejected when `now >= expiry`).
 */
export interface PaymentChallenge {
  /** Registered service id, 32-byte lowercase hex. */
  service_id: HexString;
  /** Priced operation discriminant, 32-byte lowercase hex (matches a `ServicePrice.operation`). */
  operation: HexString;
  /** Quoted price (amount + asset). */
  price: ChallengePrice;
  /** Address the service says to pay; must equal the registry `owner`. */
  pay_to: WebcAddress;
  /** Opaque per-invoice nonce, treated as a bounded lowercase-hex token. */
  invoice_nonce: HexString;
  /** Expiry as Unix epoch seconds (see type doc for the boundary rule). */
  expiry: number;
}

/**
 * The on-chain registry entry the challenge is validated against.
 *
 * The registry entry may be CALLER-PROVIDED (fetched however the caller likes) or
 * fetched from a node by the convenience path (see {@link ServiceEntrySource} and
 * {@link WebcNodeClient.getService}), so the validator itself stays pure and
 * network-free. The first five fields are the trust anchors this module reads; the
 * remaining fields carry the full on-chain record the node read endpoint returns
 * and are optional so a minimal caller-supplied entry (just the anchors) keeps
 * validating. The 32-byte-hex `service_id` is NOT part of the serialized on-chain
 * record (it is the map key); `getService` supplies it from the requested id.
 */
export interface ServiceEntry {
  /** Registered service id, 32-byte lowercase hex. */
  service_id: HexString;
  /** Account that controls the entry — the canonical pay-to for its spends. */
  owner: WebcAddress;
  /** Lifecycle status; only `"Active"` may be paid. */
  status: ServiceStatusJson;
  /** Priced operations the service exposes (≤ 16, mirrors the on-chain bound). */
  pricing: ServicePriceJson[];
  /** Accepted payment flows; `http_402` must be set for this flow. */
  payment_flags: ServicePaymentFlagsJson;
  /** Application namespace the entry lives under, 32-byte lowercase hex. */
  namespace?: HexString;
  /** Taxonomy tags a mandate allowlist may reference, 32-byte lowercase hex each (≤ 8). */
  categories?: HexString[];
  /** Short label, LOWERCASE HEX of its UTF-8 bytes (≤ 64 bytes). */
  title?: HexString;
  /** HTTPS URL or on-chain entrypoint reference, LOWERCASE HEX of its bytes (≤ 256 bytes). */
  endpoint?: HexString;
  /** Manifest reference hash (machine-readable interface), 32-byte lowercase hex. */
  interface?: HexString;
  /** Monotonically increasing revision, bumped on every update or status change. */
  revision?: number;
}

/**
 * A function that fetches the on-chain {@link ServiceEntry} for a 32-byte-hex
 * service id. The convenience path accepts one so a caller can plug in any read
 * source (a `WebcNodeClient`, a light-client read, an off-chain mirror).
 */
export type ServiceEntryFetcher = (
  serviceId: HexString,
) => Promise<ServiceEntry>;

/**
 * Structural shape of a node client that can read a {@link ServiceEntry} by id.
 * A `WebcNodeClient` satisfies this via its `getService` method, so it can be
 * passed directly wherever a {@link ServiceEntrySource} is accepted.
 */
export interface ServiceEntryClient {
  getService(serviceId: HexString): Promise<ServiceEntry>;
}

/**
 * Where a {@link ServiceEntry} comes from for validation/payment: an already-held
 * entry (the original caller-supplied path, unchanged), a fetcher function, or a
 * node client. When a fetcher/client is given, the entry is fetched for the
 * challenge's `service_id` and the SAME on-chain price+pay-to cross-check runs on
 * the fetched entry — the endpoint-supplied challenge is never trusted alone.
 */
export type ServiceEntrySource =
  | ServiceEntry
  | ServiceEntryFetcher
  | ServiceEntryClient;

/**
 * The payment reference the agent re-sends on the retry request (step 4). Each
 * field lets the service verify the spend on-chain: it looks up `tx_hash`, checks
 * the operation paid `service_id` under `mandate_id`, and matches `invoice_nonce`
 * to the challenge it issued.
 */
export interface PaymentReference {
  /** Mandate the spend was charged against, 32-byte lowercase hex. */
  mandate_id: HexString;
  /** Service that was paid, 32-byte lowercase hex. */
  service_id: HexString;
  /** Hash of the signed spend transaction, 32-byte lowercase hex. */
  tx_hash: HexString;
  /** The challenge's invoice nonce, echoed back for correlation. */
  invoice_nonce: HexString;
}

/**
 * The dispute/audit tuple (step 5): mandate id + invoice nonce + service id + tx
 * hash. Produced by `auditRecord` for durable record-keeping; a service's
 * non-delivery is provable against this tuple for track-record flags.
 */
export interface AuditRecord {
  mandate_id: HexString;
  invoice_nonce: HexString;
  service_id: HexString;
  tx_hash: HexString;
}

/** Result of `buildPayment`: the signed spend plus the retry reference. */
export interface PaymentResult {
  /** The signed `SpendUnderMandateToService` transaction, agent-key signed. */
  transaction: SignedTransactionJson;
  /** The reference to send on the retry request. */
  reference: PaymentReference;
}

/** Machine-readable reason a challenge was rejected. */
export type ChallengeErrorCode =
  | "malformed"
  | "service_id_mismatch"
  | "http402_not_accepted"
  | "service_paused"
  | "wrong_asset"
  | "unknown_operation"
  | "price_mismatch"
  | "pay_to_mismatch"
  | "expired";

/**
 * Raised whenever an untrusted challenge is malformed or fails validation. The
 * `code` is a stable machine-readable discriminant; the whole flow fails closed by
 * throwing this rather than returning a partial/optimistic result.
 */
export class ChallengeError extends Error {
  readonly code: ChallengeErrorCode;
  constructor(code: ChallengeErrorCode, message: string) {
    super(message);
    this.name = "ChallengeError";
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Strict, fail-closed parsing (mirrors transaction.ts strict-decode discipline)
// ---------------------------------------------------------------------------

/** Largest value Rust's `u128` amount encoding can represent. */
const AMOUNT_U128_MAX = (1n << 128n) - 1n;

/** Maximum invoice-nonce length in bytes (bounds untrusted work before decode). */
const MAX_INVOICE_NONCE_BYTES = 64;

const EXTERNAL_CHAINS: readonly ExternalChainJson[] = ["Webc", "Ethereum", "Solana"];

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function fail(code: ChallengeErrorCode, message: string): never {
  throw new ChallengeError(code, message);
}

/** Rejects any key not in `allowed`, matching strict schema decoding. */
function rejectUnknownKeys(
  obj: Record<string, unknown>,
  allowed: readonly string[],
  ctx: string,
): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) {
      fail("malformed", `${ctx}: unexpected field "${key}"`);
    }
  }
}

/** Requires a 32-byte lowercase-hex string (Rust `hex::encode` of a `Hash256`). */
function parseHash256(value: unknown, ctx: string): HexString {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    fail("malformed", `${ctx}: expected 32-byte lowercase hex`);
  }
  return value;
}

/**
 * Requires a canonical unsigned decimal amount within `u128` — the only form
 * Rust's `Amount` serializer emits (no sign, no leading zero, ≤ `u128::MAX`).
 * Signing a non-canonical string would diverge from Rust on verification, so a
 * non-canonical price fails closed here.
 */
function parseCanonicalAmount(value: unknown, ctx: string): string {
  if (
    typeof value !== "string" ||
    value.length > 39 ||
    !/^(0|[1-9][0-9]*)$/u.test(value)
  ) {
    fail("malformed", `${ctx}: expected canonical u128 amount`);
  }
  if (BigInt(value) > AMOUNT_U128_MAX) {
    fail("malformed", `${ctx}: amount exceeds the u128 range`);
  }
  return value;
}

/** Requires a bounded, non-empty, even-length lowercase-hex opaque token. */
function parseBoundedHex(value: unknown, ctx: string, maxBytes: number): HexString {
  if (typeof value !== "string" || value.length === 0) {
    fail("malformed", `${ctx}: expected non-empty lowercase hex`);
  }
  if (!/^(?:[0-9a-f]{2})+$/u.test(value)) {
    fail("malformed", `${ctx}: expected even-length lowercase hex`);
  }
  if (value.length / 2 > maxBytes) {
    fail("malformed", `${ctx}: exceeds ${maxBytes} bytes`);
  }
  return value;
}

/** Requires a canonical `webc1...` address (decodes to exactly 32 bytes). */
function parseAddress(value: unknown, ctx: string): WebcAddress {
  if (typeof value !== "string") {
    fail("malformed", `${ctx}: expected a webc1 address string`);
  }
  try {
    addressToBytes(value);
  } catch {
    fail("malformed", `${ctx}: not a canonical webc1 address`);
  }
  return value;
}

/** Requires a non-negative safe integer (u64-range epoch second / nonce). */
function parseEpochSeconds(value: unknown, ctx: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    fail("malformed", `${ctx}: expected a non-negative integer epoch second`);
  }
  return value;
}

/** Strictly validates an `AssetId` union (a hostile endpoint may send anything). */
function parseAssetId(value: unknown, ctx: string): AssetIdJson {
  if (value === "NativeWebc") {
    return "NativeWebc";
  }
  if (isObject(value)) {
    if ("WrappedWebc" in value) {
      rejectUnknownKeys(value, ["WrappedWebc"], ctx);
      const inner = value.WrappedWebc;
      if (isObject(inner)) {
        rejectUnknownKeys(inner, ["origin_chain"], `${ctx}.WrappedWebc`);
        const originChain = inner.origin_chain;
        if (isExternalChain(originChain)) {
          return { WrappedWebc: { origin_chain: originChain } };
        }
      }
    } else if ("External" in value) {
      rejectUnknownKeys(value, ["External"], ctx);
      const inner = value.External;
      if (isObject(inner)) {
        rejectUnknownKeys(
          inner,
          ["origin_chain", "symbol", "contract_or_mint"],
          `${ctx}.External`,
        );
        const { origin_chain, symbol, contract_or_mint } = inner;
        if (
          isExternalChain(origin_chain) &&
          typeof symbol === "string" &&
          typeof contract_or_mint === "string"
        ) {
          return { External: { origin_chain, symbol, contract_or_mint } };
        }
      }
    }
  }
  fail("malformed", `${ctx}: unrecognized asset id`);
}

function isExternalChain(value: unknown): value is ExternalChainJson {
  return (
    typeof value === "string" &&
    (EXTERNAL_CHAINS as readonly string[]).includes(value)
  );
}

/**
 * Strictly parses an untrusted 402 challenge body into a `PaymentChallenge`.
 *
 * Fails closed (`ChallengeError` with code `malformed`) on any missing field,
 * unexpected field, wrong type, non-canonical amount, non-lowercase / wrong-length
 * hex, malformed address, or out-of-range expiry. The input is typically
 * `JSON.parse` of the response body, but any `unknown` is accepted so a caller
 * cannot skip validation by pre-shaping the object.
 */
export function parseChallenge(raw: unknown): PaymentChallenge {
  if (!isObject(raw)) {
    fail("malformed", "challenge: expected a JSON object");
  }
  rejectUnknownKeys(
    raw,
    ["service_id", "operation", "price", "pay_to", "invoice_nonce", "expiry"],
    "challenge",
  );
  const priceRaw = raw.price;
  if (!isObject(priceRaw)) {
    fail("malformed", "challenge.price: expected an object");
  }
  rejectUnknownKeys(priceRaw, ["amount", "asset"], "challenge.price");
  return {
    service_id: parseHash256(raw.service_id, "challenge.service_id"),
    operation: parseHash256(raw.operation, "challenge.operation"),
    price: {
      amount: parseCanonicalAmount(priceRaw.amount, "challenge.price.amount"),
      asset: parseAssetId(priceRaw.asset, "challenge.price.asset"),
    },
    pay_to: parseAddress(raw.pay_to, "challenge.pay_to"),
    invoice_nonce: parseBoundedHex(
      raw.invoice_nonce,
      "challenge.invoice_nonce",
      MAX_INVOICE_NONCE_BYTES,
    ),
    expiry: parseEpochSeconds(raw.expiry, "challenge.expiry"),
  };
}

// ---------------------------------------------------------------------------
// Validation against the on-chain registry entry (the security core)
// ---------------------------------------------------------------------------

/** Options for `validateChallenge` / `buildPayment`. */
export interface ValidateOptions {
  /**
   * Wall-clock `now` in Unix epoch seconds used for the expiry check. Defaults to
   * `Date.now() / 1000`. Pass an explicit value for deterministic tests.
   */
  now?: number;
}

/** Validates a caller-supplied `ServiceEntry` shape (fail closed on a bad entry). */
function requireServiceEntry(entry: ServiceEntry): void {
  if (!isObject(entry)) {
    fail("malformed", "service entry: expected an object");
  }
  parseHash256(entry.service_id, "service entry.service_id");
  parseAddress(entry.owner, "service entry.owner");
  if (
    entry.status !== "Active" &&
    entry.status !== "Paused" &&
    entry.status !== "Retired"
  ) {
    fail("malformed", "service entry.status: unrecognized status");
  }
  if (!Array.isArray(entry.pricing)) {
    fail("malformed", "service entry.pricing: expected an array");
  }
  const flags = entry.payment_flags;
  if (
    !isObject(flags) ||
    typeof flags.on_chain_direct !== "boolean" ||
    typeof flags.http_402 !== "boolean" ||
    typeof flags.subscription !== "boolean"
  ) {
    fail("malformed", "service entry.payment_flags: malformed flags");
  }
}

/**
 * Validates a parsed challenge against the on-chain registry entry. Throws a
 * `ChallengeError` (with a machine-readable `code`) on the FIRST failure and
 * returns normally on success.
 *
 * ## Why this defeats a compromised endpoint (agent-commerce §4 step 2)
 *
 * The 402 challenge is issued by the service ENDPOINT, which may be compromised or
 * outright malicious. If the agent paid whatever the endpoint asked, a compromised
 * endpoint could silently (a) DIVERT funds by naming an attacker `pay_to`, or (b)
 * OVERCHARGE by inflating `price`. This function forbids both by cross-checking the
 * two economic fields against the ON-CHAIN registry entry:
 *
 *   - `pay_to` MUST equal the registry `owner`. The spend is built for the
 *     service's registered owner account (`accessListForServiceSpend`), so funds
 *     can only reach the owner the service registered, never an endpoint-supplied
 *     address.
 *   - `price.amount` MUST equal the registered `ServicePrice.price` for the
 *     challenge's `operation`. The endpoint cannot charge more than the price the
 *     owner published on-chain.
 *
 * The registry entry is mutable only by its owner (a signed on-chain op), so an
 * endpoint that lacks the owner key cannot move the goalposts. It also enforces
 * that the service is `Active`, accepts `http_402`, and that the challenge is not
 * expired and is denominated in the only mandate-payable asset (`NativeWebc`). The
 * worst a compromised endpoint can do is DENY service (issue a challenge we
 * reject) — it can never cause an incorrect or diverted payment.
 */
export function validateChallenge(
  challenge: PaymentChallenge,
  entry: ServiceEntry,
  options: ValidateOptions = {},
): void {
  requireServiceEntry(entry);

  if (challenge.service_id !== entry.service_id) {
    fail(
      "service_id_mismatch",
      "challenge names a different service than the registry entry",
    );
  }
  if (entry.payment_flags.http_402 !== true) {
    fail(
      "http402_not_accepted",
      "service does not accept HTTP-402 payment in its registry entry",
    );
  }
  if (entry.status !== "Active") {
    fail("service_paused", `service is not active (status ${entry.status})`);
  }
  // Only native WEBC is payable through a mandate spend; the operation carries no
  // asset field, so a non-native quote can never be satisfied on-chain.
  if (challenge.price.asset !== "NativeWebc") {
    fail("wrong_asset", "challenge price is not denominated in NativeWebc");
  }

  const priced = entry.pricing.find(
    (candidate) => candidate.operation === challenge.operation,
  );
  if (priced === undefined) {
    fail(
      "unknown_operation",
      "registry entry does not price the challenge operation",
    );
  }
  // Both amounts are canonical decimal strings, so string equality is value
  // equality (parse rejected any non-canonical form).
  if (priced.price !== challenge.price.amount) {
    fail(
      "price_mismatch",
      `challenge price ${challenge.price.amount} != registered ${priced.price}`,
    );
  }
  if (challenge.pay_to !== entry.owner) {
    fail(
      "pay_to_mismatch",
      "challenge pay_to does not match the registry owner",
    );
  }

  const now = resolveNow(options.now);
  if (now >= challenge.expiry) {
    fail("expired", `challenge expired at ${challenge.expiry} (now ${now})`);
  }
}

function resolveNow(now: number | undefined): number {
  if (now === undefined) {
    return Math.floor(Date.now() / 1000);
  }
  if (!Number.isFinite(now) || now < 0) {
    fail("malformed", "options.now must be a non-negative epoch second");
  }
  return now;
}

/** Narrows a {@link ServiceEntrySource} to a node client (has `getService`). */
function isServiceEntryClient(
  source: ServiceEntrySource,
): source is ServiceEntryClient {
  return (
    typeof source === "object" &&
    source !== null &&
    "getService" in source &&
    typeof (source as ServiceEntryClient).getService === "function"
  );
}

/**
 * Resolves a {@link ServiceEntrySource} into a concrete {@link ServiceEntry} for
 * the given `serviceId`. A plain entry is returned as-is (the caller-supplied
 * path); a fetcher is called; a node client is asked via `getService`. The
 * returned entry is still cross-checked by {@link validateChallenge}.
 */
export async function resolveServiceEntry(
  source: ServiceEntrySource,
  serviceId: HexString,
): Promise<ServiceEntry> {
  if (typeof source === "function") {
    return source(serviceId);
  }
  if (isServiceEntryClient(source)) {
    return source.getService(serviceId);
  }
  return source;
}

/**
 * Convenience: obtain the on-chain {@link ServiceEntry} from a
 * {@link ServiceEntrySource} (a `WebcNodeClient`, a fetcher, or an already-held
 * entry) and run {@link validateChallenge} against it, returning the resolved
 * entry on success. Fails closed with a {@link ChallengeError} exactly as
 * `validateChallenge` does. The entry is fetched for `challenge.service_id`, so a
 * source that returns a different service still fails the `service_id_mismatch`
 * cross-check.
 */
export async function validateChallengeAgainstSource(
  challenge: PaymentChallenge,
  source: ServiceEntrySource,
  options: ValidateOptions = {},
): Promise<ServiceEntry> {
  const entry = await resolveServiceEntry(source, challenge.service_id);
  validateChallenge(challenge, entry, options);
  return entry;
}

// ---------------------------------------------------------------------------
// Payment + retry (steps 3 and 4)
// ---------------------------------------------------------------------------

/** Inputs to `buildPayment`. */
export interface BuildPaymentArgs {
  /** Agent (mandate) wallet that signs the spend. Its key must match the mandate. */
  agentWallet: WebcWallet;
  /** Mandate to charge against, 32-byte lowercase hex. */
  mandateId: HexString;
  /** The parsed challenge to pay (re-validated here — see below). */
  challenge: PaymentChallenge;
  /**
   * The on-chain registry entry the challenge is validated against. Accepts a
   * {@link ServiceEntrySource}: an already-held `ServiceEntry` (the original
   * caller-supplied path, unchanged), a fetcher function, or a `WebcNodeClient`.
   * When a fetcher/client is given the entry is fetched for the challenge's
   * `service_id` and the on-chain price+pay-to cross-check runs on it.
   */
  serviceEntry: ServiceEntrySource;
  /** Canonical chain id the spend is signed for. */
  chainId: string;
  /** Agent-account nonce for the spend transaction. */
  nonce: number;
  /** Fee bid for the spend. */
  fee: FeeBid;
  /** Non-default authorization lane, if the agent pays from one. */
  authorizationLane?: AuthorizationLaneIdJson;
  /** Authorization-policy revision the agent signs under (default 0). */
  authorizationPolicyRevision?: number;
  /** `now` (epoch seconds) for the expiry check; defaults to wall clock. */
  now?: number;
}

/**
 * Builds and signs the mandate payment for a validated challenge (step 3), then
 * derives the retry reference (step 4). Returns both.
 *
 * `buildPayment` ALWAYS re-runs `validateChallenge` first, so a caller cannot skip
 * the on-chain price/pay-to check by handing an unvalidated challenge straight to
 * the payment builder — the flow fails closed. The transaction is a
 * `SpendUnderMandateToService` composed from the existing `transaction.ts`
 * builders (`spendUnderMandateToService` + `accessListForServiceSpend`), so its
 * operation JSON and access list are byte-identical to what those builders
 * already produce; this module adds no new operation shape.
 *
 * The spend pays the challenge's `service_id` for the challenge's `price.amount`,
 * to the registered `serviceEntry.owner`. It does NOT embed the invoice nonce in
 * the on-chain operation (the operation carries no free field); the nonce travels
 * in the returned `PaymentReference`, which the service correlates to the tx hash
 * on-chain, matching §4.
 */
export async function buildPayment(
  args: BuildPaymentArgs,
): Promise<PaymentResult> {
  // Resolve the entry (from a held entry, a fetcher, or a node client) for the
  // challenge's service id, then run the on-chain cross-check on the resolved
  // entry — a caller can never skip validation, whatever the source.
  const serviceEntry = await resolveServiceEntry(
    args.serviceEntry,
    args.challenge.service_id,
  );
  validateChallenge(args.challenge, serviceEntry, { now: args.now });

  const operation = spendUnderMandateToService(
    args.mandateId,
    args.challenge.service_id,
    args.challenge.price.amount,
  );
  const accessList = accessListForServiceSpend({
    sender: args.agentWallet.address,
    mandateId: args.mandateId,
    serviceId: args.challenge.service_id,
    // The pay-to owner: equal to `challenge.pay_to` (validation just proved it),
    // but sourced from the trusted on-chain entry, never from the endpoint.
    serviceOwner: serviceEntry.owner,
    authorizationLane: args.authorizationLane,
  });
  const transaction = await signTransaction(
    args.agentWallet,
    args.chainId,
    args.nonce,
    operation,
    args.fee,
    accessList,
    args.authorizationLane,
    undefined,
    args.authorizationPolicyRevision ?? 0,
  );
  const txHash = await transactionHashHex(transaction);
  const reference = makeRetry({
    mandateId: args.mandateId,
    serviceId: args.challenge.service_id,
    txHash,
    invoiceNonce: args.challenge.invoice_nonce,
  });
  return { transaction, reference };
}

/**
 * Builds the `PaymentReference` the agent re-sends on the retry request (step 4).
 * Every field is validated (fail closed), so a malformed reference can never be
 * emitted. `buildPayment` calls this for you; it is exported for callers that sign
 * a spend by other means and still want a canonical reference.
 */
export function makeRetry(args: {
  mandateId: HexString;
  serviceId: HexString;
  txHash: HexString;
  invoiceNonce: HexString;
}): PaymentReference {
  return {
    mandate_id: parseHash256(args.mandateId, "reference.mandate_id"),
    service_id: parseHash256(args.serviceId, "reference.service_id"),
    tx_hash: parseHash256(args.txHash, "reference.tx_hash"),
    invoice_nonce: parseBoundedHex(
      args.invoiceNonce,
      "reference.invoice_nonce",
      MAX_INVOICE_NONCE_BYTES,
    ),
  };
}

// ---------------------------------------------------------------------------
// Dispute / audit primitive (step 5)
// ---------------------------------------------------------------------------

/**
 * Produces the dispute/audit tuple for record-keeping (step 5): the mandate id,
 * invoice nonce, service id, and tx hash. Accepts a `PaymentReference` (the object
 * the agent sent on retry) and re-validates each field, so only well-formed tuples
 * enter an audit log. The result is a plain object with a fixed field order,
 * directly serializable (e.g. via `canonicalJson`) for durable storage; a
 * service's non-delivery is provable against this tuple for track-record flags.
 */
export function auditRecord(reference: PaymentReference): AuditRecord {
  return {
    mandate_id: parseHash256(reference.mandate_id, "audit.mandate_id"),
    invoice_nonce: parseBoundedHex(
      reference.invoice_nonce,
      "audit.invoice_nonce",
      MAX_INVOICE_NONCE_BYTES,
    ),
    service_id: parseHash256(reference.service_id, "audit.service_id"),
    tx_hash: parseHash256(reference.tx_hash, "audit.tx_hash"),
  };
}
