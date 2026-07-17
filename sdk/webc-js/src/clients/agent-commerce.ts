/**
 * `AgentCommerceClient` — the ergonomic entry point for AI-agent commerce on WEBC
 * (agent-commerce plan §2/§4). It COMPOSES the reviewed low-level SDK into the
 * flows an agent (or the principal funding one) actually performs:
 *
 *   - discover priced services (the `/v1/services` list + `getService` hydrate);
 *   - grant / top up / revoke a spending mandate (build -> sign -> submit);
 *   - pay for a resource behind an HTTP-402 challenge (the full `http402.ts` flow);
 *   - read a mandate's live budget/spend status.
 *
 * It introduces no new operation, access list, or wire format: every write goes
 * through a `transaction.ts` builder and `signTransaction`, and the payment path
 * reuses `buildPayment` verbatim, so the on-chain bytes are byte-identical to the
 * low-level API. The client-derived mandate id is computed with the SAME
 * `deriveMandateIdHex` the builder documents.
 *
 * ## Signer roles
 * A mandate GRANT / TOP-UP / REVOKE is signed by the mandate's PRINCIPAL; a
 * `payForResource` spend is signed by the mandate's AGENT key. Construct the
 * client with whichever `signer` matches the flow you are driving (an agent's
 * client pays; the principal's client grants). Both are supported by the same
 * class because both are ordinary signed transactions.
 */

import type { ListServicesOptions } from "../node-client.js";
import type {
  HexString,
  MandateCounterpartyPolicyJson,
} from "../types.js";
import {
  deriveMandateIdHex,
  grantMandate as grantMandateOp,
  revokeMandate as revokeMandateOp,
  topUpMandate as topUpMandateOp,
} from "../transaction.js";
import {
  buildPayment,
  parseChallenge,
} from "../http402.js";
import type {
  PaymentChallenge,
  PaymentReference,
  ServiceEntry,
  ServiceEntrySource,
} from "../http402.js";
import type { SignedTransactionJson } from "../types.js";
import type { SubmitReceipt } from "../node-client.js";
import {
  SigningClient,
  type SubmitOutcome,
  type TxOverrides,
} from "./common.js";

/** Options for {@link AgentCommerceClient.discoverServices}. */
export type DiscoverServicesOptions = ListServicesOptions;

/** A page of discovered, hydrated service registry entries. */
export interface DiscoveredServices {
  /** The full on-chain entries for the ids on this page. */
  readonly services: readonly ServiceEntry[];
  /** Opaque cursor for the next page, or `null` on the last page. */
  readonly nextCursor: string | null;
}

/**
 * Arguments for {@link AgentCommerceClient.grantMandate}. Mirrors the low-level
 * `grantMandate` builder: the signer is the PRINCIPAL, and the mandate id is
 * derived from `(principal, agentKey, grantNonce)`.
 */
export interface GrantMandateArgs {
  /** Agent Ed25519 public key the mandate authorizes, 32-byte lowercase hex. */
  readonly agentKey: HexString;
  /** Principal-chosen grant nonce; disambiguates mandates to the same agent. */
  readonly grantNonce: number;
  /** Total native base units the mandate may spend over its life (decimal string). */
  readonly budgetTotal: string;
  /** Last consensus epoch (inclusive) the mandate may be spent in. */
  readonly expiryEpoch: number;
  /** Maximum native value a single mandate-signed spend may draw (decimal string). */
  readonly perTxMax: string;
  /** Maximum spends per rate-limit window; `0` means unlimited. */
  readonly rateLimitPerDay: number;
  /** Which counterparties the mandate may pay (`"Open"` or an allowlist). */
  readonly counterpartyPolicy: MandateCounterpartyPolicyJson;
}

/** Result of a mandate write: the submit outcome plus the affected mandate id. */
export interface MandateResult extends SubmitOutcome {
  /** The mandate id the write applies to, 32-byte lowercase hex. */
  readonly mandateId: HexString;
}

/**
 * Arguments for {@link AgentCommerceClient.payForResource}. `challenge` is the
 * untrusted 402 body (raw or already parsed); it is re-parsed and re-validated
 * against the on-chain entry before anything is signed.
 */
export interface PayForResourceArgs extends TxOverrides {
  /** The `402 Payment Required` challenge (raw JSON or a parsed challenge). */
  readonly challenge: PaymentChallenge | unknown;
  /** Mandate the spend is charged against, 32-byte lowercase hex. */
  readonly mandateId: HexString;
  /**
   * Where the on-chain {@link ServiceEntry} is read from for the price/pay-to
   * cross-check. Defaults to this client's node (`getService`); pass an explicit
   * entry, fetcher, or client to override. The check ALWAYS runs on this fetched
   * entry, never on the endpoint challenge alone.
   */
  readonly serviceEntry?: ServiceEntrySource;
  /** `now` (epoch seconds) for the expiry check; defaults to wall clock. */
  readonly now?: number;
}

/** Result of a successful {@link AgentCommerceClient.payForResource}. */
export interface PaymentOutcome {
  /** The node's acceptance receipt for the mandate spend. */
  readonly receipt: SubmitReceipt;
  /** The signed `SpendUnderMandateToService` transaction that was submitted. */
  readonly transaction: SignedTransactionJson;
  /** The on-chain-verifiable reference to re-send on the retry request. */
  readonly reference: PaymentReference;
}

/**
 * High-level client for agent commerce: service discovery, mandate lifecycle, and
 * HTTP-402 resource payment. Construct it with a `WebcNodeClient` and a signer;
 * see the module doc for which signer role each method expects.
 */
export class AgentCommerceClient extends SigningClient {
  /**
   * Discovers registered services, returning the full {@link ServiceEntry} for
   * each id on the page. Composes the `/v1/services` list endpoint (optionally
   * filtered by `category` / `namespace`) with a `getService` hydrate per id.
   */
  async discoverServices(
    options: DiscoverServicesOptions = {},
  ): Promise<DiscoveredServices> {
    const page = await this.node.listServices(options);
    const services = await Promise.all(
      page.items.map((serviceId) => this.node.getService(serviceId)),
    );
    return { services, nextCursor: page.nextCursor };
  }

  /**
   * Grants a spending mandate to `agentKey` (signer = PRINCIPAL). Builds
   * `GrantMandate`, lets `signTransaction` derive the default access list, submits,
   * and returns the receipt plus the client-derived mandate id (identical to the
   * id the chain assigns from `(principal, agentKey, grantNonce)`).
   */
  async grantMandate(
    args: GrantMandateArgs,
    overrides: TxOverrides = {},
  ): Promise<MandateResult> {
    const operation = grantMandateOp({
      agentKey: args.agentKey,
      grantNonce: args.grantNonce,
      budgetTotal: args.budgetTotal,
      expiryEpoch: args.expiryEpoch,
      perTxMax: args.perTxMax,
      rateLimitPerDay: args.rateLimitPerDay,
      counterpartyPolicy: args.counterpartyPolicy,
    });
    const mandateId = await deriveMandateIdHex(
      this.signer.address,
      args.agentKey,
      args.grantNonce,
    );
    const outcome = await this.signAndSubmit(operation, undefined, overrides);
    return { ...outcome, mandateId };
  }

  /**
   * Adds native base units to an existing mandate's budget (signer = PRINCIPAL).
   * Builds `TopUpMandate` with the default access list and submits.
   */
  async topUpMandate(
    mandateId: HexString,
    amount: string,
    overrides: TxOverrides = {},
  ): Promise<MandateResult> {
    const operation = topUpMandateOp(mandateId, amount);
    const outcome = await this.signAndSubmit(operation, undefined, overrides);
    return { ...outcome, mandateId };
  }

  /**
   * Revokes a mandate and returns its unspent remainder (signer = PRINCIPAL).
   * Builds `RevokeMandate` with the default access list and submits.
   */
  async revokeMandate(
    mandateId: HexString,
    overrides: TxOverrides = {},
  ): Promise<MandateResult> {
    const operation = revokeMandateOp(mandateId);
    const outcome = await this.signAndSubmit(operation, undefined, overrides);
    return { ...outcome, mandateId };
  }

  /**
   * Pays for a resource behind an HTTP-402 challenge (signer = AGENT) and returns
   * the reference to replay on the retry request. Runs the full `http402.ts` flow:
   * parse the untrusted challenge, fetch the on-chain {@link ServiceEntry} through
   * the node client, and build the `SpendUnderMandateToService` via `buildPayment`.
   *
   * SECURITY: the price and pay-to are re-checked against the FETCHED on-chain
   * entry (not the endpoint challenge) inside `buildPayment`; a mismatched or
   * expired challenge throws a `ChallengeError` and NOTHING is signed or submitted
   * (fail-closed). Funds can only ever reach the service's registered owner for its
   * registered price.
   */
  async payForResource(args: PayForResourceArgs): Promise<PaymentOutcome> {
    // Re-parse the (untrusted) challenge; idempotent on an already-parsed one.
    const challenge = parseChallenge(args.challenge);
    const chainId = await this.resolveChainId(args);
    const fee = this.resolveFee(args);
    const nonce = await this.resolveNonce(args);
    const { transaction, reference } = await buildPayment({
      agentWallet: this.signer,
      mandateId: args.mandateId,
      challenge,
      // Default the entry source to this client's node so the on-chain price and
      // pay-to are cross-checked against `getService`, never the endpoint alone.
      serviceEntry: args.serviceEntry ?? this.node,
      chainId,
      nonce,
      fee,
      authorizationLane: args.authorizationLane,
      authorizationPolicyRevision: args.authorizationPolicyRevision,
      now: args.now,
    });
    const receipt = await this.node.submitTransaction(transaction);
    return { receipt, transaction, reference };
  }

  /**
   * Reads a mandate's live status (budget, spent, expiry, rate-limit window,
   * revocation) by id. Thin wrapper over `getMandate`.
   */
  async getMandateStatus(mandateId: HexString) {
    return this.node.getMandate(mandateId);
  }
}
