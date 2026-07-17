/**
 * Browser-safe client for the WEBC node developer API (`/v1`).
 *
 * Purpose: give a web application a small, typed, defensively-validated way to
 * talk to a `webc-node` HTTP/WebSocket endpoint — read health/fees, query
 * accounts and blocks, submit signed transactions, request devnet faucet funds,
 * and subscribe to new-block events. It is the browser counterpart of the Rust
 * `webc-node` API.
 *
 * Boundaries: this module performs no signing and holds no secrets; callers build
 * and sign transactions with the wallet APIs and pass the canonical JSON here.
 * It only transports and validates.
 *
 * Trust: a node's responses are treated as untrusted input. Every response is
 * parsed through a strict, bounded validator that rejects unexpected shapes,
 * rather than trusting the server's JSON. Network transports (`fetch`,
 * `WebSocket`) are injectable so the client runs in browsers, in Node, and under
 * test without relying on ambient globals.
 */

import { addressToBytes } from "./address.js";
import type { ServiceEntry } from "./http402.js";
import type {
  GovernanceActionJson,
  GovernanceConfigJson,
  GovernanceInstance,
  GovernanceProposal,
  GovProposalStatusJson,
  Mandate,
  MandateCounterpartyJson,
  MandateCounterpartyPolicyJson,
  NftCollection,
  NftItem,
  NftMetadataJson,
  ServicePaymentFlagsJson,
  ServicePriceJson,
  ServiceStatusJson,
  TokenMetadataJson,
  TokenRecord,
  TokenSupplyReport,
} from "./types.js";

/** The API version this client speaks; it must match the node's `/v1` prefix. */
export const NODE_API_VERSION = "v1";

/** Upper bound on a single API response body, to cap hostile payloads. */
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

/** Upper bound on a node-supplied error string surfaced into host UI. */
const MAX_ERROR_STRING_CHARS = 256;

/** Minimal streaming reader (a `ReadableStreamDefaultReader` is compatible). */
interface ByteStreamReader {
  read(): Promise<{ done: boolean; value?: Uint8Array }>;
  cancel(): Promise<void>;
}

/** Minimal readable byte stream (a `fetch` `Response.body` is compatible). */
interface ByteStream {
  getReader(): ByteStreamReader;
}

/** Minimal `fetch` shape the client depends on (browser and Node compatible). */
export type FetchLike = (
  input: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
  },
) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
  /**
   * Optional streamed body. When present (real `fetch`), the client reads it
   * with a running byte cap and aborts early, instead of buffering the whole
   * body before checking its size.
   */
  body?: ByteStream | null;
}>;

/** Minimal event-based `WebSocket` shape the client depends on. */
export interface WebSocketLike {
  addEventListener(type: "message", listener: (event: { data: unknown }) => void): void;
  addEventListener(type: "open", listener: () => void): void;
  addEventListener(type: "close", listener: () => void): void;
  addEventListener(type: "error", listener: (event: unknown) => void): void;
  close(): void;
}

/** Constructor shape for an injectable `WebSocket` implementation. */
export type WebSocketConstructor = new (url: string) => WebSocketLike;

/** A structured API error carrying the HTTP status and the node's error kind. */
export class NodeApiError extends Error {
  readonly status: number;
  readonly kind: string;

  constructor(status: number, kind: string, message: string) {
    super(message);
    this.name = "NodeApiError";
    this.status = status;
    this.kind = kind;
  }
}

/** Node health and identity, as returned by `GET /v1/health`. */
export interface NodeHealth {
  readonly apiVersion: string;
  readonly chainId: string;
  readonly height: number;
  readonly tipHash: string | null;
  readonly stateRoot: string | null;
  readonly mempoolSize: number;
  readonly faucetEnabled: boolean;
}

/** Fee state, as returned by `GET /v1/fees`. */
export interface NodeFees {
  readonly baseFeePerUnit: bigint;
  readonly maxBlockUnits: bigint;
}

/** An account snapshot with its address. Balances are native base units. */
export interface AccountView {
  readonly address: string;
  readonly balance: bigint;
  readonly nonce: number;
}

/** A new-block event from the `subscribe/blocks` WebSocket. */
export interface BlockEvent {
  readonly height: number;
  readonly blockHash: string | null;
  readonly stateRoot: string | null;
}

/** The receipt from submitting a transaction. */
export interface SubmitReceipt {
  readonly txHash: string;
  readonly accepted: boolean;
  readonly mempoolSize: number;
}

/** The receipt from a devnet faucet drip, including the no-value disclaimer. */
export interface FaucetReceipt {
  readonly recipient: string;
  readonly amount: bigint;
  readonly blockHeight: number;
  readonly newBalance: bigint;
  readonly disclaimer: string;
}

/**
 * A validator's eligibility or penalty state, mirroring the Rust
 * `ValidatorStatus` serde enum: the unit variants serialize as bare strings and
 * the data-carrying variants as a single-key tagged object.
 */
export type ValidatorStatus =
  | "Active"
  | "PendingActivation"
  | "Draining"
  | { readonly Jailed: { readonly reason: string } }
  | { readonly Tombstoned: { readonly reason: string } };

/**
 * A validator pool snapshot with its derived total stake, as returned by
 * `GET /v1/validators/{address}` and inside `GET /v1/validators`. All stake and
 * reward amounts are native base units.
 */
export interface ValidatorSummary {
  readonly operator: string;
  readonly consensusKey: string;
  readonly selfStake: bigint;
  readonly delegatedStake: bigint;
  readonly commissionBps: number;
  readonly status: ValidatorStatus;
  readonly bootstrap: boolean;
  readonly accumulatedRewards: bigint;
  readonly totalStake: bigint;
}

/** The public validator set, as returned by `GET /v1/validators`. */
export interface ValidatorsResponse {
  readonly apiVersion: string;
  readonly validators: readonly ValidatorSummary[];
}

/**
 * The deterministic supply-invariant reconciliation, as returned by
 * `GET /v1/supply`. Every bucket is native base units; `balanced` is true when
 * gross issuance exactly equals the accounted buckets.
 */
export interface SupplyInvariantReport {
  readonly issued: bigint;
  readonly liquid: bigint;
  readonly staked: bigint;
  readonly delegated: bigint;
  readonly unbonding: bigint;
  readonly escrowed: bigint;
  readonly laneFees: bigint;
  readonly pendingRewards: bigint;
  readonly feeRewardPool: bigint;
  readonly burned: bigint;
  readonly slashed: bigint;
  readonly accounted: bigint;
  readonly balanced: boolean;
}

/** Handlers for a block subscription. */
export interface BlockSubscriptionHandlers {
  readonly onBlock: (event: BlockEvent) => void;
  readonly onError?: (error: unknown) => void;
  readonly onClose?: () => void;
}

/** A cancelable block subscription. */
export interface BlockSubscription {
  /** Closes the underlying socket. */
  close(): void;
}

/** Options for constructing a {@link WebcNodeClient}. */
export interface WebcNodeClientOptions {
  /** Injected `fetch`; defaults to `globalThis.fetch`. */
  readonly fetchImpl?: FetchLike;
  /** Injected `WebSocket` constructor; defaults to `globalThis.WebSocket`. */
  readonly webSocketImpl?: WebSocketConstructor;
  /**
   * Maximum response body size in BYTES (not UTF-16 units). Defaults to 4 MiB.
   * A streamed body is aborted as soon as the running byte count exceeds this.
   */
  readonly maxResponseBytes?: number;
}

/**
 * A typed, defensively-validated client for one WEBC node endpoint.
 *
 * `baseUrl` is the node origin (e.g. `http://127.0.0.1:8645`); the client appends
 * the `/v1` path itself. All reads and writes reject malformed node responses.
 */
export class WebcNodeClient {
  readonly #baseUrl: string;
  readonly #fetch: FetchLike;
  readonly #webSocket: WebSocketConstructor | undefined;
  readonly #maxResponseBytes: number;

  constructor(baseUrl: string, options: WebcNodeClientOptions = {}) {
    // Normalize away a trailing slash so path joins are unambiguous.
    this.#baseUrl = baseUrl.replace(/\/+$/, "");
    const fetchImpl = options.fetchImpl ?? (globalThis as { fetch?: FetchLike }).fetch;
    if (!fetchImpl) {
      throw new Error("no fetch implementation available; pass options.fetchImpl");
    }
    this.#fetch = fetchImpl;
    this.#webSocket =
      options.webSocketImpl ??
      (globalThis as { WebSocket?: WebSocketConstructor }).WebSocket;
    const maxBytes = options.maxResponseBytes ?? MAX_RESPONSE_BYTES;
    if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
      throw new Error("maxResponseBytes must be a positive integer");
    }
    this.#maxResponseBytes = maxBytes;
  }

  /** Returns node health and identity. */
  async health(): Promise<NodeHealth> {
    return parseHealth(await this.#get("/v1/health"));
  }

  /** Returns the current fee state. */
  async fees(): Promise<NodeFees> {
    return parseFees(await this.#get("/v1/fees"));
  }

  /** Returns an account snapshot, throwing {@link NodeApiError} (404) if absent. */
  async account(address: string): Promise<AccountView> {
    return parseAccount(await this.#get(`/v1/accounts/${encodeURIComponent(address)}`));
  }

  /** Returns every validator with its derived total stake. */
  async getValidators(): Promise<ValidatorsResponse> {
    return parseValidatorsResponse(await this.#get("/v1/validators"));
  }

  /**
   * Returns a single validator by operator address, throwing
   * {@link NodeApiError} (404) if no such validator exists.
   */
  async getValidator(address: string): Promise<ValidatorSummary> {
    return parseValidatorSummary(
      await this.#get(`/v1/validators/${encodeURIComponent(address)}`),
    );
  }

  /** Returns the supply-invariant reconciliation report. */
  async getSupply(): Promise<SupplyInvariantReport> {
    return parseSupplyInvariantReport(await this.#get("/v1/supply"));
  }

  /**
   * Returns a native fungible-token record by 32-byte-hex id, throwing
   * {@link NodeApiError} (404) if no such token exists.
   */
  async getToken(id: string): Promise<TokenRecord> {
    return parseTokenRecord(await this.#get(`/v1/tokens/${encodeURIComponent(id)}`));
  }

  /**
   * Returns a holder's balance of a token as a canonical decimal string of base
   * units. A known token with no balance entry for the holder reads back as
   * `"0"`; only an unknown token id throws {@link NodeApiError} (404).
   */
  async getTokenBalance(id: string, address: string): Promise<string> {
    return parseAmountString(
      await this.#get(
        `/v1/tokens/${encodeURIComponent(id)}/balances/${encodeURIComponent(address)}`,
      ),
      "token balance",
    );
  }

  /**
   * Returns the per-token supply reconciliation for a token, throwing
   * {@link NodeApiError} (404) if no such token exists.
   */
  async getTokenSupply(id: string): Promise<TokenSupplyReport> {
    return parseTokenSupplyReport(
      await this.#get(`/v1/tokens/${encodeURIComponent(id)}/supply`),
    );
  }

  /**
   * Returns an NFT collection record by 32-byte-hex id, throwing
   * {@link NodeApiError} (404) if no such collection exists.
   */
  async getNftCollection(id: string): Promise<NftCollection> {
    return parseNftCollection(
      await this.#get(`/v1/nft/collections/${encodeURIComponent(id)}`),
    );
  }

  /**
   * Returns one NFT item by its collection id and serial, throwing
   * {@link NodeApiError} (404) if no such item exists (or it was burned).
   */
  async getNftItem(id: string, serial: number): Promise<NftItem> {
    return parseNftItem(
      await this.#get(
        `/v1/nft/collections/${encodeURIComponent(id)}/items/${encodeURIComponent(String(serial))}`,
      ),
    );
  }

  /**
   * Returns a service-registry entry by 32-byte-hex id, throwing
   * {@link NodeApiError} (404) if no such service exists. The returned
   * {@link ServiceEntry} carries the requested `service_id` (the on-chain record
   * omits it, since it is the map key) so the result feeds the HTTP-402 flow
   * directly; it can be passed as the `ServiceEntrySource` to `validateChallenge`
   * / `buildPayment`.
   */
  async getService(id: string): Promise<ServiceEntry> {
    return parseServiceEntry(
      await this.#get(`/v1/services/${encodeURIComponent(id)}`),
      id,
    );
  }

  /**
   * Returns a governance instance by 32-byte-hex id, throwing
   * {@link NodeApiError} (404) if no such instance exists.
   */
  async getGovernanceInstance(id: string): Promise<GovernanceInstance> {
    return parseGovernanceInstance(
      await this.#get(`/v1/governance/instances/${encodeURIComponent(id)}`),
    );
  }

  /**
   * Returns a governance proposal by 32-byte-hex id, throwing
   * {@link NodeApiError} (404) if no such proposal exists.
   */
  async getGovernanceProposal(id: string): Promise<GovernanceProposal> {
    return parseGovernanceProposal(
      await this.#get(`/v1/governance/proposals/${encodeURIComponent(id)}`),
    );
  }

  /**
   * Returns an agent-payment mandate by 32-byte-hex id, throwing
   * {@link NodeApiError} (404) if no such mandate exists.
   */
  async getMandate(id: string): Promise<Mandate> {
    return parseMandate(await this.#get(`/v1/mandates/${encodeURIComponent(id)}`));
  }

  /**
   * Returns the raw account-proof JSON for an address. The object is returned
   * as-is (a `record`) so callers can hand it to a proof verifier; its shape is
   * the Rust `AccountStateProof`.
   */
  async accountProof(address: string): Promise<Record<string, unknown>> {
    const value = await this.#get(`/v1/accounts/${encodeURIComponent(address)}/proof`);
    if (!isRecord(value)) {
      throw new Error("node returned a non-object account proof");
    }
    return value;
  }

  /** Returns the finalized block at `height` as raw JSON, or throws on 404. */
  async blockByHeight(height: number): Promise<Record<string, unknown>> {
    const value = await this.#get(`/v1/blocks/height/${encodeURIComponent(String(height))}`);
    if (!isRecord(value)) {
      throw new Error("node returned a non-object block");
    }
    return value;
  }

  /** Returns the finalized block with `hash` (hex) as raw JSON, or throws on 404. */
  async blockByHash(hash: string): Promise<Record<string, unknown>> {
    const value = await this.#get(`/v1/blocks/hash/${encodeURIComponent(hash)}`);
    if (!isRecord(value)) {
      throw new Error("node returned a non-object block");
    }
    return value;
  }

  /**
   * Submits a signed transaction. `transaction` must be the canonical JSON object
   * produced by the wallet/transaction APIs (already signed).
   */
  async submitTransaction(transaction: unknown): Promise<SubmitReceipt> {
    return parseSubmitReceipt(await this.#post("/v1/transactions", transaction));
  }

  /** Requests a devnet faucet drip to `address`. Devnet only; funds are valueless. */
  async requestFaucet(address: string): Promise<FaucetReceipt> {
    return parseFaucetReceipt(
      await this.#post(`/v1/faucet/${encodeURIComponent(address)}`, undefined),
    );
  }

  /**
   * Opens a WebSocket subscription to new-block events. Each validated event is
   * delivered to `handlers.onBlock`. Returns a handle whose `close()` ends the
   * subscription. Throws if no `WebSocket` implementation is available.
   */
  subscribeBlocks(handlers: BlockSubscriptionHandlers): BlockSubscription {
    if (!this.#webSocket) {
      throw new Error("no WebSocket implementation available; pass options.webSocketImpl");
    }
    const url = `${this.#toWebSocketUrl()}/v1/subscribe/blocks`;
    const socket = new this.#webSocket(url);
    socket.addEventListener("message", (event) => {
      try {
        const parsed = parseBlockEvent(decodeJson(asString(event.data)));
        handlers.onBlock(parsed);
      } catch (error) {
        handlers.onError?.(error);
      }
    });
    socket.addEventListener("error", (event) => handlers.onError?.(event));
    socket.addEventListener("close", () => handlers.onClose?.());
    return {
      close: () => socket.close(),
    };
  }

  /** Converts the http(s) base URL to a ws(s) URL for the subscription. */
  #toWebSocketUrl(): string {
    if (this.#baseUrl.startsWith("https://")) {
      return `wss://${this.#baseUrl.slice("https://".length)}`;
    }
    if (this.#baseUrl.startsWith("http://")) {
      return `ws://${this.#baseUrl.slice("http://".length)}`;
    }
    // Assume the caller passed a bare host:port.
    return `ws://${this.#baseUrl}`;
  }

  async #get(path: string): Promise<unknown> {
    const response = await this.#fetch(`${this.#baseUrl}${path}`, { method: "GET" });
    return this.#handle(response);
  }

  async #post(path: string, body: unknown): Promise<unknown> {
    const response = await this.#fetch(`${this.#baseUrl}${path}`, {
      method: "POST",
      headers: body === undefined ? {} : { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return this.#handle(response);
  }

  async #handle(response: {
    ok: boolean;
    status: number;
    text(): Promise<string>;
    body?: ByteStream | null;
  }): Promise<unknown> {
    const text = await this.#readBody(response);
    const value = text.length > 0 ? decodeJson(text) : null;
    if (!response.ok) {
      // The node returns { error, kind } on failure; surface both, but truncate
      // so a hostile node cannot push megabytes of controlled text into host UI.
      const kind =
        isRecord(value) && typeof value.kind === "string"
          ? truncateString(value.kind, MAX_ERROR_STRING_CHARS)
          : "error";
      const message =
        isRecord(value) && typeof value.error === "string"
          ? truncateString(value.error, MAX_ERROR_STRING_CHARS)
          : `request failed with status ${response.status}`;
      throw new NodeApiError(response.status, kind, message);
    }
    return value;
  }

  /**
   * Reads the response body under a strict byte cap. When the transport exposes
   * a stream (real `fetch`), the byte count is enforced WHILE reading and the
   * reader is aborted early. Otherwise the fully-buffered text is measured by
   * UTF-8 bytes (not UTF-16 units) before decoding.
   */
  async #readBody(response: {
    text(): Promise<string>;
    body?: ByteStream | null;
  }): Promise<string> {
    const body = response.body;
    if (body && typeof body.getReader === "function") {
      return this.#readStreamCapped(body);
    }
    const text = await response.text();
    // UTF-8 byte length is always >= UTF-16 unit length, so a unit count over the
    // cap already exceeds it; otherwise measure exact bytes (bounded work).
    if (
      text.length > this.#maxResponseBytes ||
      utf8ByteLength(text) > this.#maxResponseBytes
    ) {
      throw new Error("node response exceeds the maximum allowed size");
    }
    return text;
  }

  async #readStreamCapped(body: ByteStream): Promise<string> {
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value && value.byteLength > 0) {
          total += value.byteLength;
          if (total > this.#maxResponseBytes) {
            throw new Error("node response exceeds the maximum allowed size");
          }
          chunks.push(value);
        }
      }
    } finally {
      // Abort any remaining body (early exit on the cap) and release resources.
      try {
        await reader.cancel();
      } catch {
        // The stream may already be closed/errored; nothing to release.
      }
    }
    return new TextDecoder("utf-8").decode(concatChunks(chunks, total));
  }
}

/** Exact UTF-8 byte length of a string. */
function utf8ByteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

/** Concatenates byte chunks into one buffer of the known total length. */
function concatChunks(chunks: readonly Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/** Bounds a node-controlled string to `max` characters before it reaches UI. */
function truncateString(value: string, max: number): string {
  return value.length > max ? value.slice(0, max) : value;
}

/** Parses a JSON string, rejecting anything unparseable. */
function decodeJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error("node returned invalid JSON");
  }
}

function asString(data: unknown): string {
  if (typeof data === "string") {
    return data;
  }
  throw new Error("expected a text WebSocket message");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Requires a finite, non-negative safe integer. */
function requireCount(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`node response field ${field} is not a valid count`);
  }
  return value;
}

/** Requires a decimal-string amount and returns it as a non-negative bigint. */
function requireAmount(value: unknown, field: string): bigint {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`node response field ${field} is not a valid amount`);
  }
  return BigInt(value);
}

/** Requires a lowercase 32-byte hex string (64 hex chars). */
function requireHex32(value: unknown, field: string): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`node response field ${field} is not a 32-byte hex string`);
  }
  return value;
}

/** Requires a 32-byte hex string, or `null`. */
function requireHashOrNull(value: unknown, field: string): string | null {
  return value === null ? null : requireHex32(value, field);
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`node response field ${field} is not a non-empty string`);
  }
  return value;
}

function requireBool(value: unknown, field: string): boolean {
  if (typeof value !== "boolean") {
    throw new Error(`node response field ${field} is not a boolean`);
  }
  return value;
}

function parseHealth(value: unknown): NodeHealth {
  if (!isRecord(value)) {
    throw new Error("node returned a non-object health response");
  }
  return Object.freeze({
    apiVersion: requireString(value.api_version, "api_version"),
    chainId: requireString(value.chain_id, "chain_id"),
    height: requireCount(value.height, "height"),
    tipHash: requireHashOrNull(value.tip_hash, "tip_hash"),
    stateRoot: requireHashOrNull(value.state_root, "state_root"),
    mempoolSize: requireCount(value.mempool_size, "mempool_size"),
    faucetEnabled: requireBool(value.faucet_enabled, "faucet_enabled"),
  });
}

function requireU64(value: unknown, field: string): bigint {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`node response field ${field} is not a valid unsigned integer`);
  }
  return BigInt(value);
}

function parseFees(value: unknown): NodeFees {
  if (!isRecord(value)) {
    throw new Error("node returned a non-object fees response");
  }
  return Object.freeze({
    baseFeePerUnit: requireU64(value.base_fee_per_unit, "base_fee_per_unit"),
    maxBlockUnits: requireU64(value.max_block_units, "max_block_units"),
  });
}

function parseAccount(value: unknown): AccountView {
  if (!isRecord(value) || !isRecord(value.account)) {
    throw new Error("node returned a malformed account response");
  }
  return Object.freeze({
    address: requireString(value.address, "address"),
    balance: requireAmount(value.account.balance, "account.balance"),
    nonce: requireCount(value.account.nonce, "account.nonce"),
  });
}

/**
 * Parses the serde-tagged `ValidatorStatus` enum. Unit variants arrive as bare
 * strings; the data-carrying variants arrive as a single-key object.
 */
function parseValidatorStatus(value: unknown, field: string): ValidatorStatus {
  if (value === "Active" || value === "PendingActivation" || value === "Draining") {
    return value;
  }
  if (isRecord(value)) {
    if (value.Jailed !== undefined) {
      if (!isRecord(value.Jailed)) {
        throw new Error(`node response field ${field}.Jailed is malformed`);
      }
      return Object.freeze({
        Jailed: Object.freeze({
          reason: requireString(value.Jailed.reason, `${field}.Jailed.reason`),
        }),
      });
    }
    if (value.Tombstoned !== undefined) {
      if (!isRecord(value.Tombstoned)) {
        throw new Error(`node response field ${field}.Tombstoned is malformed`);
      }
      return Object.freeze({
        Tombstoned: Object.freeze({
          reason: requireString(value.Tombstoned.reason, `${field}.Tombstoned.reason`),
        }),
      });
    }
  }
  throw new Error(`node response field ${field} is not a valid validator status`);
}

/** Parses a single validator summary (flattened `Validator` plus total stake). */
function parseValidatorSummary(value: unknown): ValidatorSummary {
  if (!isRecord(value)) {
    throw new Error("node returned a non-object validator");
  }
  return Object.freeze({
    operator: requireString(value.operator, "operator"),
    consensusKey: requireHex32(value.consensus_key, "consensus_key"),
    selfStake: requireAmount(value.self_stake, "self_stake"),
    delegatedStake: requireAmount(value.delegated_stake, "delegated_stake"),
    commissionBps: requireCount(value.commission_bps, "commission_bps"),
    status: parseValidatorStatus(value.status, "status"),
    bootstrap: requireBool(value.bootstrap, "bootstrap"),
    accumulatedRewards: requireAmount(value.accumulated_rewards, "accumulated_rewards"),
    totalStake: requireAmount(value.total_stake, "total_stake"),
  });
}

function parseValidatorsResponse(value: unknown): ValidatorsResponse {
  if (!isRecord(value) || !Array.isArray(value.validators)) {
    throw new Error("node returned a malformed validators response");
  }
  return Object.freeze({
    apiVersion: requireString(value.api_version, "api_version"),
    validators: Object.freeze(
      value.validators.map((validator) => parseValidatorSummary(validator)),
    ),
  });
}

function parseSupplyInvariantReport(value: unknown): SupplyInvariantReport {
  if (!isRecord(value)) {
    throw new Error("node returned a non-object supply report");
  }
  return Object.freeze({
    issued: requireAmount(value.issued, "issued"),
    liquid: requireAmount(value.liquid, "liquid"),
    staked: requireAmount(value.staked, "staked"),
    delegated: requireAmount(value.delegated, "delegated"),
    unbonding: requireAmount(value.unbonding, "unbonding"),
    escrowed: requireAmount(value.escrowed, "escrowed"),
    laneFees: requireAmount(value.lane_fees, "lane_fees"),
    pendingRewards: requireAmount(value.pending_rewards, "pending_rewards"),
    feeRewardPool: requireAmount(value.fee_reward_pool, "fee_reward_pool"),
    burned: requireAmount(value.burned, "burned"),
    slashed: requireAmount(value.slashed, "slashed"),
    accounted: requireAmount(value.accounted, "accounted"),
    balanced: requireBool(value.balanced, "balanced"),
  });
}

/** Parses a block event; exported for testing the WebSocket message path. */
export function parseBlockEvent(value: unknown): BlockEvent {
  if (!isRecord(value)) {
    throw new Error("node returned a non-object block event");
  }
  return Object.freeze({
    height: requireCount(value.height, "height"),
    blockHash: requireHashOrNull(value.block_hash, "block_hash"),
    stateRoot: requireHashOrNull(value.state_root, "state_root"),
  });
}

function parseSubmitReceipt(value: unknown): SubmitReceipt {
  if (!isRecord(value)) {
    throw new Error("node returned a non-object submit receipt");
  }
  return Object.freeze({
    txHash: requireString(value.tx_hash, "tx_hash"),
    accepted: requireBool(value.accepted, "accepted"),
    mempoolSize: requireCount(value.mempool_size, "mempool_size"),
  });
}

function parseFaucetReceipt(value: unknown): FaucetReceipt {
  if (!isRecord(value)) {
    throw new Error("node returned a non-object faucet receipt");
  }
  return Object.freeze({
    recipient: requireString(value.recipient, "recipient"),
    amount: requireAmount(value.amount, "amount"),
    blockHeight: requireCount(value.block_height, "block_height"),
    newBalance: requireAmount(value.new_balance, "new_balance"),
    disclaimer: requireString(value.disclaimer, "disclaimer"),
  });
}

// ---------------------------------------------------------------------------
// Native-state read parsers (Phase 9/13). These decode UNTRUSTED node responses
// into the wire-mirror record types in `types.ts`, failing closed on a missing,
// extra, or wrong-typed field — mirroring Rust's `#[serde(deny_unknown_fields)]`
// on these records and the strict-decode discipline in `http402.ts`.
// ---------------------------------------------------------------------------

/** On-chain byte-length bounds these records enforce (mirrors the Rust consts). */
const MAX_TOKEN_NAME_BYTES = 32;
const MAX_TOKEN_SYMBOL_BYTES = 12;
const MAX_TOKEN_DECIMALS = 18;
const MAX_NFT_NAME_BYTES = 32;
const MAX_NFT_SYMBOL_BYTES = 12;
const MAX_NFT_ROYALTY_BPS = 10_000;
const MAX_SERVICE_TITLE_BYTES = 64;
const MAX_SERVICE_ENDPOINT_BYTES = 256;
const MAX_SERVICE_PRICE_UNIT_BYTES = 32;
const MAX_SERVICE_CATEGORIES = 8;
const MAX_SERVICE_PRICING_ENTRIES = 16;
const MAX_GOVERNANCE_BPS = 10_000;
/** Largest value Rust's `u128` `Amount` can hold. */
const AMOUNT_U128_MAX = (1n << 128n) - 1n;

/** Requires an object, throwing a labeled error otherwise. */
function requireRecord(value: unknown, ctx: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error(`node response ${ctx} is not an object`);
  }
  return value;
}

/** Rejects any key not in `allowed` (fail-closed on an extra field). */
function rejectUnknownKeys(
  obj: Record<string, unknown>,
  allowed: readonly string[],
  ctx: string,
): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) {
      throw new Error(`node response ${ctx} has an unexpected field "${key}"`);
    }
  }
}

/**
 * Requires a canonical unsigned decimal `Amount` within `u128` and returns it as
 * the string (no sign, no leading zero, ≤ `u128::MAX`) — the only form Rust's
 * `Amount` serializer emits.
 */
function requireAmountString(value: unknown, field: string): string {
  if (
    typeof value !== "string" ||
    value.length > 39 ||
    !/^(0|[1-9][0-9]*)$/.test(value)
  ) {
    throw new Error(`node response field ${field} is not a valid amount`);
  }
  if (BigInt(value) > AMOUNT_U128_MAX) {
    throw new Error(`node response field ${field} exceeds the u128 range`);
  }
  return value;
}

/** Requires a canonical `webc1...` address string (decodes to exactly 32 bytes). */
function requireAddress(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new Error(`node response field ${field} is not an address string`);
  }
  try {
    addressToBytes(value);
  } catch {
    throw new Error(`node response field ${field} is not a canonical webc address`);
  }
  return value;
}

/** Requires an address string or `null` (Rust `Option<Address>`). */
function requireAddressOrNull(value: unknown, field: string): string | null {
  return value === null ? null : requireAddress(value, field);
}

/** Requires a non-negative safe-integer count or `null` (Rust `Option<u64>`). */
function requireCountOrNull(value: unknown, field: string): number | null {
  return value === null ? null : requireCount(value, field);
}

/** Requires a count within `[0, max]` (an on-chain range-bounded integer). */
function requireBoundedCount(value: unknown, field: string, max: number): number {
  const count = requireCount(value, field);
  if (count > max) {
    throw new Error(`node response field ${field} exceeds its maximum of ${max}`);
  }
  return count;
}

/**
 * Requires an even-length lowercase-hex byte string within `maxBytes` (the Rust
 * bounded-hex codec form). An empty string is permitted (a zero-length field).
 */
function requireHexBytes(value: unknown, field: string, maxBytes: number): string {
  if (typeof value !== "string" || !/^(?:[0-9a-f]{2})*$/.test(value)) {
    throw new Error(`node response field ${field} is not lowercase byte hex`);
  }
  if (value.length / 2 > maxBytes) {
    throw new Error(`node response field ${field} exceeds ${maxBytes} bytes`);
  }
  return value;
}

function parseTokenMetadata(value: unknown, ctx: string): TokenMetadataJson {
  const obj = requireRecord(value, ctx);
  rejectUnknownKeys(obj, ["name", "symbol", "decimals", "metadata_hash"], ctx);
  return {
    name: requireHexBytes(obj.name, `${ctx}.name`, MAX_TOKEN_NAME_BYTES),
    symbol: requireHexBytes(obj.symbol, `${ctx}.symbol`, MAX_TOKEN_SYMBOL_BYTES),
    decimals: requireBoundedCount(obj.decimals, `${ctx}.decimals`, MAX_TOKEN_DECIMALS),
    metadata_hash: requireHex32(obj.metadata_hash, `${ctx}.metadata_hash`),
  };
}

function parseTokenRecord(value: unknown): TokenRecord {
  const obj = requireRecord(value, "token record");
  rejectUnknownKeys(
    obj,
    ["creator", "metadata", "mint_authority", "freeze_authority", "paused", "issued_supply"],
    "token record",
  );
  return {
    creator: requireAddress(obj.creator, "creator"),
    metadata: parseTokenMetadata(obj.metadata, "metadata"),
    mint_authority: requireAddressOrNull(obj.mint_authority, "mint_authority"),
    freeze_authority: requireAddressOrNull(obj.freeze_authority, "freeze_authority"),
    paused: requireBool(obj.paused, "paused"),
    issued_supply: requireAmountString(obj.issued_supply, "issued_supply"),
  };
}

/** Parses the bare `Amount` string a token-balance endpoint returns. */
function parseAmountString(value: unknown, field: string): string {
  return requireAmountString(value, field);
}

function parseTokenSupplyReport(value: unknown): TokenSupplyReport {
  const obj = requireRecord(value, "token supply report");
  rejectUnknownKeys(obj, ["issued", "held", "balanced"], "token supply report");
  return {
    issued: requireAmountString(obj.issued, "issued"),
    held: requireAmountString(obj.held, "held"),
    balanced: requireBool(obj.balanced, "balanced"),
  };
}

function parseNftMetadata(value: unknown, ctx: string): NftMetadataJson {
  const obj = requireRecord(value, ctx);
  rejectUnknownKeys(obj, ["name", "symbol", "metadata_hash"], ctx);
  return {
    name: requireHexBytes(obj.name, `${ctx}.name`, MAX_NFT_NAME_BYTES),
    symbol: requireHexBytes(obj.symbol, `${ctx}.symbol`, MAX_NFT_SYMBOL_BYTES),
    metadata_hash: requireHex32(obj.metadata_hash, `${ctx}.metadata_hash`),
  };
}

function parseNftCollection(value: unknown): NftCollection {
  const obj = requireRecord(value, "nft collection");
  rejectUnknownKeys(
    obj,
    [
      "creator",
      "metadata",
      "mint_authority",
      "freeze_authority",
      "paused",
      "next_serial",
      "minted_count",
      "burned_count",
      "max_supply",
      "royalty_bps",
    ],
    "nft collection",
  );
  return {
    creator: requireAddress(obj.creator, "creator"),
    metadata: parseNftMetadata(obj.metadata, "metadata"),
    mint_authority: requireAddressOrNull(obj.mint_authority, "mint_authority"),
    freeze_authority: requireAddressOrNull(obj.freeze_authority, "freeze_authority"),
    paused: requireBool(obj.paused, "paused"),
    next_serial: requireCount(obj.next_serial, "next_serial"),
    minted_count: requireCount(obj.minted_count, "minted_count"),
    burned_count: requireCount(obj.burned_count, "burned_count"),
    max_supply: requireCountOrNull(obj.max_supply, "max_supply"),
    royalty_bps: requireBoundedCount(obj.royalty_bps, "royalty_bps", MAX_NFT_ROYALTY_BPS),
  };
}

function parseNftItem(value: unknown): NftItem {
  const obj = requireRecord(value, "nft item");
  rejectUnknownKeys(obj, ["owner", "item_metadata_hash", "frozen"], "nft item");
  return {
    owner: requireAddress(obj.owner, "owner"),
    item_metadata_hash: requireHex32(obj.item_metadata_hash, "item_metadata_hash"),
    frozen: requireBool(obj.frozen, "frozen"),
  };
}

function parseServiceStatus(value: unknown, field: string): ServiceStatusJson {
  if (value === "Active" || value === "Paused" || value === "Retired") {
    return value;
  }
  throw new Error(`node response field ${field} is not a valid service status`);
}

function parseServicePrice(value: unknown, ctx: string): ServicePriceJson {
  const obj = requireRecord(value, ctx);
  rejectUnknownKeys(obj, ["operation", "price", "unit"], ctx);
  return {
    operation: requireHex32(obj.operation, `${ctx}.operation`),
    price: requireAmountString(obj.price, `${ctx}.price`),
    unit: requireHexBytes(obj.unit, `${ctx}.unit`, MAX_SERVICE_PRICE_UNIT_BYTES),
  };
}

function parseServicePaymentFlags(value: unknown, ctx: string): ServicePaymentFlagsJson {
  const obj = requireRecord(value, ctx);
  rejectUnknownKeys(obj, ["on_chain_direct", "http_402", "subscription"], ctx);
  return {
    on_chain_direct: requireBool(obj.on_chain_direct, `${ctx}.on_chain_direct`),
    http_402: requireBool(obj.http_402, `${ctx}.http_402`),
    subscription: requireBool(obj.subscription, `${ctx}.subscription`),
  };
}

/**
 * Parses the on-chain `ServiceEntry` record and returns an `http402` `ServiceEntry`
 * carrying `serviceId` (the record omits the id — it is the map key). The id is
 * re-validated as 32-byte hex so a caller cannot smuggle a malformed id through.
 */
function parseServiceEntry(value: unknown, serviceId: string): ServiceEntry {
  const obj = requireRecord(value, "service entry");
  rejectUnknownKeys(
    obj,
    [
      "owner",
      "namespace",
      "categories",
      "title",
      "endpoint",
      "interface",
      "pricing",
      "payment_flags",
      "status",
      "revision",
    ],
    "service entry",
  );
  if (!Array.isArray(obj.categories)) {
    throw new Error("node response service entry.categories is not an array");
  }
  if (obj.categories.length > MAX_SERVICE_CATEGORIES) {
    throw new Error("node response service entry.categories exceeds its maximum");
  }
  if (!Array.isArray(obj.pricing)) {
    throw new Error("node response service entry.pricing is not an array");
  }
  if (obj.pricing.length > MAX_SERVICE_PRICING_ENTRIES) {
    throw new Error("node response service entry.pricing exceeds its maximum");
  }
  return {
    service_id: requireHex32(serviceId, "service_id"),
    owner: requireAddress(obj.owner, "owner"),
    namespace: requireHex32(obj.namespace, "namespace"),
    categories: obj.categories.map((entry, index) =>
      requireHex32(entry, `categories[${index}]`),
    ),
    title: requireHexBytes(obj.title, "title", MAX_SERVICE_TITLE_BYTES),
    endpoint: requireHexBytes(obj.endpoint, "endpoint", MAX_SERVICE_ENDPOINT_BYTES),
    interface: requireHex32(obj.interface, "interface"),
    pricing: obj.pricing.map((entry, index) =>
      parseServicePrice(entry, `pricing[${index}]`),
    ),
    payment_flags: parseServicePaymentFlags(obj.payment_flags, "payment_flags"),
    status: parseServiceStatus(obj.status, "status"),
    revision: requireCount(obj.revision, "revision"),
  };
}

function parseGovernanceConfig(value: unknown, ctx: string): GovernanceConfigJson {
  const obj = requireRecord(value, ctx);
  rejectUnknownKeys(
    obj,
    [
      "voting_period_epochs",
      "timelock_epochs",
      "quorum_bps",
      "proposal_threshold",
      "approval_threshold_bps",
    ],
    ctx,
  );
  return {
    voting_period_epochs: requireCount(obj.voting_period_epochs, `${ctx}.voting_period_epochs`),
    timelock_epochs: requireCount(obj.timelock_epochs, `${ctx}.timelock_epochs`),
    quorum_bps: requireBoundedCount(obj.quorum_bps, `${ctx}.quorum_bps`, MAX_GOVERNANCE_BPS),
    proposal_threshold: requireAmountString(obj.proposal_threshold, `${ctx}.proposal_threshold`),
    approval_threshold_bps: requireBoundedCount(
      obj.approval_threshold_bps,
      `${ctx}.approval_threshold_bps`,
      MAX_GOVERNANCE_BPS,
    ),
  };
}

function parseGovProposalStatus(value: unknown, field: string): GovProposalStatusJson {
  if (
    value === "Active" ||
    value === "Defeated" ||
    value === "Passed" ||
    value === "Executed" ||
    value === "Expired"
  ) {
    return value;
  }
  throw new Error(`node response field ${field} is not a valid proposal status`);
}

/** Parses the serde-tagged `GovernanceAction` enum (`"Signaling"` or a 1-key object). */
function parseGovernanceAction(value: unknown, field: string): GovernanceActionJson {
  if (value === "Signaling") {
    return "Signaling";
  }
  if (isRecord(value) && value.TreasuryTransfer !== undefined) {
    rejectUnknownKeys(value, ["TreasuryTransfer"], field);
    const inner = requireRecord(value.TreasuryTransfer, `${field}.TreasuryTransfer`);
    rejectUnknownKeys(inner, ["recipient", "amount"], `${field}.TreasuryTransfer`);
    return {
      TreasuryTransfer: {
        recipient: requireAddress(inner.recipient, `${field}.TreasuryTransfer.recipient`),
        amount: requireAmountString(inner.amount, `${field}.TreasuryTransfer.amount`),
      },
    };
  }
  throw new Error(`node response field ${field} is not a valid governance action`);
}

function parseGovernanceInstance(value: unknown): GovernanceInstance {
  const obj = requireRecord(value, "governance instance");
  rejectUnknownKeys(
    obj,
    ["creator", "weight_token", "config", "treasury", "next_proposal_nonce"],
    "governance instance",
  );
  return {
    creator: requireAddress(obj.creator, "creator"),
    weight_token: requireHex32(obj.weight_token, "weight_token"),
    config: parseGovernanceConfig(obj.config, "config"),
    treasury: requireAmountString(obj.treasury, "treasury"),
    next_proposal_nonce: requireCount(obj.next_proposal_nonce, "next_proposal_nonce"),
  };
}

function parseGovernanceProposal(value: unknown): GovernanceProposal {
  const obj = requireRecord(value, "governance proposal");
  rejectUnknownKeys(
    obj,
    [
      "instance_id",
      "proposer",
      "weight_token",
      "config",
      "action",
      "created_epoch",
      "voting_ends_epoch",
      "eta_epoch",
      "status",
      "yes",
      "no",
      "abstain",
    ],
    "governance proposal",
  );
  return {
    instance_id: requireHex32(obj.instance_id, "instance_id"),
    proposer: requireAddress(obj.proposer, "proposer"),
    weight_token: requireHex32(obj.weight_token, "weight_token"),
    config: parseGovernanceConfig(obj.config, "config"),
    action: parseGovernanceAction(obj.action, "action"),
    created_epoch: requireCount(obj.created_epoch, "created_epoch"),
    voting_ends_epoch: requireCount(obj.voting_ends_epoch, "voting_ends_epoch"),
    eta_epoch: requireCountOrNull(obj.eta_epoch, "eta_epoch"),
    status: parseGovProposalStatus(obj.status, "status"),
    yes: requireAmountString(obj.yes, "yes"),
    no: requireAmountString(obj.no, "no"),
    abstain: requireAmountString(obj.abstain, "abstain"),
  };
}

/** Parses one serde-tagged `MandateCounterparty` (`{Category}` or `{Recipient}`). */
function parseMandateCounterparty(value: unknown, ctx: string): MandateCounterpartyJson {
  const obj = requireRecord(value, ctx);
  if (obj.Category !== undefined) {
    rejectUnknownKeys(obj, ["Category"], ctx);
    return { Category: requireHex32(obj.Category, `${ctx}.Category`) };
  }
  if (obj.Recipient !== undefined) {
    rejectUnknownKeys(obj, ["Recipient"], ctx);
    return { Recipient: requireAddress(obj.Recipient, `${ctx}.Recipient`) };
  }
  throw new Error(`node response ${ctx} is not a valid mandate counterparty`);
}

/** Parses the serde-tagged `MandateCounterpartyPolicy` (`"Open"` or `{Allowlist}`). */
function parseMandateCounterpartyPolicy(
  value: unknown,
  field: string,
): MandateCounterpartyPolicyJson {
  if (value === "Open") {
    return "Open";
  }
  if (isRecord(value) && value.Allowlist !== undefined) {
    rejectUnknownKeys(value, ["Allowlist"], field);
    if (!Array.isArray(value.Allowlist)) {
      throw new Error(`node response ${field}.Allowlist is not an array`);
    }
    return {
      Allowlist: value.Allowlist.map((entry, index) =>
        parseMandateCounterparty(entry, `${field}.Allowlist[${index}]`),
      ),
    };
  }
  throw new Error(`node response field ${field} is not a valid counterparty policy`);
}

function parseMandate(value: unknown): Mandate {
  const obj = requireRecord(value, "mandate");
  rejectUnknownKeys(
    obj,
    [
      "principal",
      "agent_key",
      "budget_total",
      "spent",
      "expiry_epoch",
      "per_tx_max",
      "rate_limit_per_day",
      "counterparty_policy",
      "revoked",
      "window_index",
      "spends_in_window",
    ],
    "mandate",
  );
  return {
    principal: requireAddress(obj.principal, "principal"),
    agent_key: requireHex32(obj.agent_key, "agent_key"),
    budget_total: requireAmountString(obj.budget_total, "budget_total"),
    spent: requireAmountString(obj.spent, "spent"),
    expiry_epoch: requireCount(obj.expiry_epoch, "expiry_epoch"),
    per_tx_max: requireAmountString(obj.per_tx_max, "per_tx_max"),
    rate_limit_per_day: requireCount(obj.rate_limit_per_day, "rate_limit_per_day"),
    counterparty_policy: parseMandateCounterpartyPolicy(
      obj.counterparty_policy,
      "counterparty_policy",
    ),
    revoked: requireBool(obj.revoked, "revoked"),
    window_index: requireCount(obj.window_index, "window_index"),
    spends_in_window: requireCount(obj.spends_in_window, "spends_in_window"),
  };
}
