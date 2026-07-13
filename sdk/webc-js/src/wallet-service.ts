/**
 * Trusted-origin wallet request service, permissions, and spend accounting.
 *
 * This module must run in a wallet-controlled HTTPS frame/window. It derives
 * authority from the browser-provided `MessageEvent.origin` and exact source
 * object, never from host-supplied text. Requests execute serially so cumulative
 * spend limits cannot race. Only fully constructed native transfers are signed;
 * arbitrary bytes and unsupported operations have no service method.
 */

import { bytesToHex, concatBytes, toArrayBuffer } from "./hex.js";
import {
  CURRENT_TRANSACTION_PROTOCOL_VERSION,
  signTransaction,
  transfer,
  validateTransactionContext,
} from "./transaction.js";
import type { SignedTransactionJson } from "./types.js";
import { signWithWallet, type WebcWallet } from "./wallet.js";
import {
  MAX_WALLET_REPLAY_IDS,
  WALLET_MESSAGE_CHANNEL,
  WALLET_MESSAGE_VERSION,
  WalletRequestError,
  createWalletRequestId,
  extractWalletRequestId,
  isSecureWalletHostOrigin,
  nativeTransferConfirmation,
  parseNativeTransfer,
  parseSpendLimits,
  parseWalletRequest,
  type ParsedSpendLimits,
  type WalletConfirmation,
  type WalletConnectionResult,
  type WalletRequest,
  type WalletResponse,
  type WalletResponseErrorCode,
  type WalletSpendLimitsJson,
} from "./wallet-request.js";

const ORIGIN_LANE_DOMAIN = new TextEncoder().encode("WEBC_ORIGIN_LANE_V1\0");

/** Minimum postMessage target surface needed by the trusted service. */
export interface WalletMessageSource {
  /** Sends a public response to one exact browser origin; `*` is never used. */
  postMessage(message: unknown, targetOrigin: string): void;
}

/** Snapshot of browser-authenticated message metadata consumed by the service. */
export interface WalletIncomingMessage {
  readonly origin: string;
  readonly source: WalletMessageSource | null;
  readonly data: unknown;
}

/** User-confirmation callback implemented by trusted wallet UI only. */
export type WalletConfirmationHandler = (
  confirmation: WalletConfirmation,
) => Promise<boolean>;

/** Immutable service construction parameters. */
export interface TrustedWalletServiceOptions {
  /** In-process wallet whose key handle is unavailable to the host. */
  readonly wallet: WebcWallet;
  /** Exact chain accepted for every signed request. */
  readonly chainId: string;
  /** Exact parent/opener window allowed to send requests. */
  readonly expectedSource: WalletMessageSource;
  /** Trusted UI decision invoked for grants and every transaction. */
  readonly confirm: WalletConfirmationHandler;
}

interface PermissionGrant {
  readonly limitsJson: WalletSpendLimitsJson;
  readonly limits: ParsedSpendLimits;
  readonly authorizationLane: string;
  readonly sessionId: string;
  spentAmount: bigint;
  nextSequence: number;
}

/**
 * Stateful trusted wallet service with replay and permission protection.
 *
 * A service instance is bound to one parent/opener window but may grant several
 * HTTPS origins if that source navigates. Grants remain per-origin and in-memory
 * until encrypted permission persistence is designed. Calling `handleMessage`
 * is safe concurrently; requests are queued in arrival order.
 */
export class TrustedWalletService {
  readonly #wallet: WebcWallet;
  readonly #chainId: string;
  readonly #expectedSource: WalletMessageSource;
  readonly #confirm: WalletConfirmationHandler;
  readonly #grants = new Map<string, PermissionGrant>();
  readonly #replayIds = new Map<string, true>();
  #queue: Promise<void> = Promise.resolve();

  constructor(options: TrustedWalletServiceOptions) {
    validateTransactionContext(
      CURRENT_TRANSACTION_PROTOCOL_VERSION,
      options.chainId,
    );
    this.#wallet = options.wallet;
    this.#chainId = options.chainId;
    this.#expectedSource = options.expectedSource;
    this.#confirm = options.confirm;
  }

  /** Enqueues one browser message and posts at most one exact-origin response. */
  handleMessage(event: WalletIncomingMessage): Promise<void> {
    const snapshot: WalletIncomingMessage = {
      origin: event.origin,
      source: event.source,
      data: event.data,
    };
    const task = this.#queue.then(() => this.#process(snapshot));
    this.#queue = task.catch(() => undefined);
    return task;
  }

  async #process(event: WalletIncomingMessage): Promise<void> {
    if (
      event.source !== this.#expectedSource ||
      !event.source ||
      !isSecureWalletHostOrigin(event.origin)
    ) {
      return;
    }

    const requestId = extractWalletRequestId(event.data);
    let request: WalletRequest;
    try {
      request = parseWalletRequest(event.data);
    } catch (error) {
      if (requestId) {
        this.#post(
          event.source,
          event.origin,
          failureResponse(
            requestId,
            error instanceof WalletRequestError ? error.code : "INVALID_REQUEST",
            error instanceof WalletRequestError
              ? error.message
              : "wallet request is invalid",
          ),
        );
      }
      return;
    }

    const replayKey = `${event.origin}\0${request.request_id}`;
    if (this.#replayIds.has(replayKey)) {
      this.#post(
        event.source,
        event.origin,
        failureResponse(
          request.request_id,
          "REQUEST_REPLAY",
          "wallet request ID was already used",
        ),
      );
      return;
    }
    this.#rememberReplay(replayKey);

    try {
      const result = await this.#dispatch(event.origin, request);
      this.#post(
        event.source,
        event.origin,
        successResponse(request.request_id, result),
      );
    } catch (error) {
      const mapped = mapServiceError(error);
      this.#post(
        event.source,
        event.origin,
        failureResponse(request.request_id, mapped.code, mapped.message),
      );
    }
  }

  async #dispatch(
    origin: string,
    request: WalletRequest,
  ): Promise<WalletConnectionResult | SignedTransactionJson | { revoked: true }> {
    if (request.method === "connect") {
      const approved = await this.#confirm({
        kind: "connect",
        origin,
        scopes: request.params.scopes,
        limits: request.params.limits,
      });
      if (!approved) throw serviceError("USER_REJECTED", "user rejected connection");
      const authorizationLane = await deriveOriginAuthorizationLane(this.#wallet, origin);
      const sessionId = createWalletRequestId();
      const grant: PermissionGrant = {
        limitsJson: request.params.limits,
        limits: parseSpendLimits(request.params.limits),
        authorizationLane,
        sessionId,
        spentAmount: 0n,
        nextSequence: 0,
      };
      this.#grants.set(origin, grant);
      return {
        address: this.#wallet.address,
        public_key: bytesToHex(this.#wallet.publicKey),
        authorization_lane: authorizationLane,
        session_id: sessionId,
        scopes: request.params.scopes,
        limits: request.params.limits,
      };
    }

    if (request.method === "revoke") {
      this.#grants.delete(origin);
      return { revoked: true };
    }

    const grant = this.#grants.get(origin);
    if (!grant) {
      throw serviceError("PERMISSION_REQUIRED", "origin has no wallet permission");
    }
    if (request.params.chain_id !== this.#chainId) {
      throw serviceError("CHAIN_MISMATCH", "wallet is connected to another chain");
    }
    if (request.params.authorization_lane !== grant.authorizationLane) {
      throw serviceError(
        "PERMISSION_REQUIRED",
        "transaction lane is not assigned to this origin",
      );
    }
    if (
      request.params.session_id !== grant.sessionId ||
      request.params.sequence !== grant.nextSequence
    ) {
      throw serviceError(
        "REQUEST_REPLAY",
        "transaction session or sequence is stale",
      );
    }

    const parsed = parseNativeTransfer(request.params);
    const nextSpent = grant.spentAmount + parsed.amount;
    if (
      parsed.amount > grant.limits.maxAmountPerTransaction ||
      parsed.maximumFee > grant.limits.maxFeePerTransaction ||
      nextSpent > grant.limits.maxTotalAmount ||
      grant.nextSequence === Number.MAX_SAFE_INTEGER
    ) {
      throw serviceError("LIMIT_EXCEEDED", "transaction exceeds wallet permission limits");
    }

    const approved = await this.#confirm(
      nativeTransferConfirmation(origin, request.params),
    );
    if (!approved) throw serviceError("USER_REJECTED", "user rejected transaction");

    const signed = await signTransaction(
      this.#wallet,
      request.params.chain_id,
      request.params.nonce,
      transfer(request.params.recipient, request.params.amount),
      request.params.fee,
      undefined,
      request.params.authorization_lane,
      request.params.protocol_version,
      request.params.authorization_policy_revision,
    );
    grant.spentAmount = nextSpent;
    grant.nextSequence += 1;
    return signed;
  }

  #rememberReplay(key: string): void {
    this.#replayIds.set(key, true);
    if (this.#replayIds.size > MAX_WALLET_REPLAY_IDS) {
      const oldest = this.#replayIds.keys().next().value as string | undefined;
      if (oldest) this.#replayIds.delete(oldest);
    }
  }

  #post(source: WalletMessageSource, origin: string, response: WalletResponse): void {
    try {
      source.postMessage(response, origin);
    } catch {
      // Navigation can invalidate a WindowProxy between receipt and response.
      // Never retry with `*` because that could disclose the signed transaction.
    }
  }
}

/** Attaches a service to a trusted window and returns a deterministic disposer. */
export function attachTrustedWalletService(
  service: TrustedWalletService,
  target: Window = window,
): () => void {
  const listener = (event: MessageEvent<unknown>) => {
    void service.handleMessage({
      origin: event.origin,
      source: event.source as WalletMessageSource | null,
      data: event.data,
    });
  };
  target.addEventListener("message", listener);
  return () => target.removeEventListener("message", listener);
}

async function deriveOriginAuthorizationLane(
  wallet: WebcWallet,
  origin: string,
): Promise<string> {
  const originBytes = new TextEncoder().encode(origin);
  const message = concatBytes([ORIGIN_LANE_DOMAIN, originBytes]);
  const signature = await signWithWallet(wallet, message);
  try {
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", toArrayBuffer(signature)),
    );
    return bytesToHex(digest);
  } finally {
    signature.fill(0);
    message.fill(0);
  }
}

function successResponse(
  requestId: string,
  result: WalletConnectionResult | SignedTransactionJson | { revoked: true },
): WalletResponse {
  return {
    channel: WALLET_MESSAGE_CHANNEL,
    version: WALLET_MESSAGE_VERSION,
    request_id: requestId,
    ok: true,
    result,
  };
}

function failureResponse(
  requestId: string,
  code: WalletResponseErrorCode,
  message: string,
): WalletResponse {
  return {
    channel: WALLET_MESSAGE_CHANNEL,
    version: WALLET_MESSAGE_VERSION,
    request_id: requestId,
    ok: false,
    error: { code, message },
  };
}

function serviceError(
  code: WalletResponseErrorCode,
  message: string,
): WalletRequestError {
  return new WalletRequestError(code, message);
}

function mapServiceError(error: unknown): {
  code: WalletResponseErrorCode;
  message: string;
} {
  if (error instanceof WalletRequestError) {
    return { code: error.code, message: error.message };
  }
  return {
    code: "INTERNAL_ERROR",
    message: "trusted wallet could not complete the request",
  };
}
