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

/** The API version this client speaks; it must match the node's `/v1` prefix. */
export const NODE_API_VERSION = "v1";

/** Upper bound on a single API response body, to cap hostile payloads. */
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

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
  }): Promise<unknown> {
    const text = await response.text();
    if (text.length > MAX_RESPONSE_BYTES) {
      throw new Error("node response exceeds the maximum allowed size");
    }
    const value = text.length > 0 ? decodeJson(text) : null;
    if (!response.ok) {
      // The node returns { error, kind } on failure; surface both.
      const kind = isRecord(value) && typeof value.kind === "string" ? value.kind : "error";
      const message =
        isRecord(value) && typeof value.error === "string"
          ? value.error
          : `request failed with status ${response.status}`;
      throw new NodeApiError(response.status, kind, message);
    }
    return value;
  }
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

/** Requires a hex string of the given byte length, or `null`. */
function requireHashOrNull(value: unknown, field: string): string | null {
  if (value === null) {
    return null;
  }
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`node response field ${field} is not a 32-byte hex hash`);
  }
  return value;
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
